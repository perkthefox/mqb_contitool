"""CAN terminal: input parsing, UDS reply decoding, and a live session on a python-can virtual bus."""

from __future__ import annotations

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import can  # noqa: E402
import pytest  # noqa: E402

from contitool.gui.app import create_window  # noqa: E402
from contitool.gui.can_session import describe_uds, parse_hex, parse_id  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402

VIN_REPLY = b"\x62\xf1\x90" + b"WVWZZZ1KZAW000001"


def test_parsing_accepts_common_hex_spellings() -> None:
    assert parse_hex("02 10 03", 8) == b"\x02\x10\x03"
    assert parse_hex("0x22,0xF1,0x90  # VIN", 8) == b"\x22\xf1\x90"
    assert parse_hex("", 8) == b""
    with pytest.raises(ValueError):
        parse_hex("1 2 3", 8)
    with pytest.raises(ValueError):
        parse_hex("00" * 9, 8)
    assert parse_id("710") == (0x710, False)
    assert parse_id("0x18DAF110") == (0x18DAF110, True)
    with pytest.raises(ValueError):
        parse_id("XYZ")


def test_uds_replies_are_explained() -> None:
    set_lang("en")
    assert "requestOutOfRange" in describe_uds(bytes.fromhex("7F2231"))
    assert describe_uds(VIN_REPLY).endswith('"WVWZZZ1KZAW000001"')


def _wait(app, cond, timeout: float = 3.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end and not cond():
        app.processEvents()
        time.sleep(0.01)


def _frame(arb_id: int, hex_data: str | bytes) -> can.Message:
    data = bytes.fromhex(hex_data) if isinstance(hex_data, str) else hex_data
    return can.Message(arbitration_id=arb_id, data=data, is_extended_id=False)


def test_terminal_sends_frames_and_reassembles_uds_replies() -> None:
    set_lang("en")
    app, win = create_window()
    win.set_mode("terminal")
    term = win.terminal
    ecu = can.Bus(interface="virtual", channel="contitool-test")
    bus = can.Bus(interface="virtual", channel="contitool-test")
    try:
        term.connect_bus(bus=bus)
        _wait(app, lambda: term._state == "on")
        assert term.btn_send.isEnabled()

        # raw frame
        term.btn_mode_frame.setChecked(True)
        term.ed_id.setText("123")
        term.cmb_frame.setEditText("DE AD BE EF")
        term._send()
        got = ecu.recv(timeout=2)
        assert got.arbitration_id == 0x123 and bytes(got.data) == bytes.fromhex("DEADBEEF")

        # UDS 22 F1 90: the ECU answers "pending", then sends the VIN as a multi-frame reply
        term.btn_mode_uds.setChecked(True)
        term.cmb_uds.setEditText("22 F1 90")
        term._send()
        req = ecu.recv(timeout=2)
        assert req.arbitration_id == 0x710 and bytes(req.data[:4]) == bytes.fromhex("0322F190")
        ecu.send(_frame(0x77A, "037F2278AAAAAAAA"))
        ecu.send(_frame(0x77A, bytes([0x10, len(VIN_REPLY)]) + VIN_REPLY[:6]))
        fc = ecu.recv(timeout=2)
        assert fc.arbitration_id == 0x710 and fc.data[0] == 0x30
        for seq, off in enumerate(range(6, len(VIN_REPLY), 7), start=1):
            ecu.send(_frame(0x77A, bytes([0x20 | seq]) + VIN_REPLY[off : off + 7]))

        _wait(app, lambda: any(r.kind == "uds-resp" for r in term.model.rows))
        resp = next(r for r in term.model.rows if r.kind == "uds-resp")
        assert resp.data == VIN_REPLY
        assert "WVWZZZ1KZAW000001" in resp.note
        assert "WVWZZZ1KZAW000001" in term.lbl_msg.text()

        # a negative reply is explained and the session stays up
        term.cmb_uds.setEditText("22 12 34")
        term._send()
        ecu.recv(timeout=2)
        ecu.send(_frame(0x77A, "037F2231AAAAAAAA"))
        _wait(app, lambda: "requestOutOfRange" in term.lbl_msg.text())
        assert term.lbl_msg.property("tone") == "warn"
        assert term._state == "on"

        # the filter hides other IDs
        term.ed_filter.setText("123")
        app.processEvents()
        assert term.proxy.rowCount() == 1

        win.set_mode("ecu")  # leaving the terminal frees the adapter
        assert term.session is None
    finally:
        term.disconnect_bus()
        bus.shutdown()
        ecu.shutdown()
        win.close()


def test_terminal_reports_an_adapter_that_cannot_open() -> None:
    set_lang("en")
    app, win = create_window()
    win.conn.port, win.conn.interface = "no-such-port", "no-such-interface"
    win.set_mode("terminal")
    win.terminal.connect_bus()
    _wait(app, lambda: win.terminal.session is None)
    assert win.terminal._state == "err"
    assert win.terminal.lbl_msg.property("tone") == "err"
    win.close()


def test_periodic_gateway_frame_is_hidden_by_default_and_ids_can_be_excluded() -> None:
    from contitool.gui.can_session import TraceRow
    from contitool.gui.screens.terminal import parse_id_filter

    from PySide6.QtCore import QSettings

    assert parse_id_filter("710, 77A -17F00010") == ({0x710, 0x77A}, {0x17F00010})
    QSettings().remove("terminal/filter")  # an earlier test typed its own filter
    app, win = create_window()
    term = win.terminal
    assert term.ed_filter.text() == "-17F00010"
    term.model.append([
        TraceRow(0.0, "rx", 0x17F00010, bytes.fromhex("2010000000000080"), extended=True),
        TraceRow(0.1, "rx", 0x77A, bytes.fromhex("065003003201F4AA")),
        TraceRow(0.2, "error", None, note="bus off"),
    ])
    app.processEvents()
    shown = [term.proxy.mapToSource(term.proxy.index(i, 0)).row() for i in range(term.proxy.rowCount())]
    assert shown == [1, 2]  # the 0.5 s gateway frame is gone, errors stay

    term.table.selectRow(0)
    term._hide_selected_id()
    assert term.ed_filter.text() == "-17F00010, -77A"
    assert term.proxy.rowCount() == 1
    term.ed_filter.setText("")
    assert term.proxy.rowCount() == 3
    win.close()


def test_disconnect_never_destroys_a_running_session(monkeypatch) -> None:
    """A session still stuck in the adapter is kept until its thread ends; until then nothing else may open the adapter."""
    import threading

    from contitool.gui import can_session

    set_lang("en")
    app, win = create_window()
    win.set_mode("terminal")
    term = win.terminal
    release = threading.Event()

    class StuckBus:  # e.g. a VCI that is still updating its firmware
        def recv(self, timeout=None):
            release.wait(5)

        def send(self, msg, timeout=None):
            pass

        def shutdown(self):
            pass

    monkeypatch.setattr(can_session.CanSession, "stop", lambda self: self._stop.set())  # skip the 3 s grace wait
    term.connect_bus(bus=StuckBus())
    _wait(app, lambda: term._state == "on")
    session = term.session
    term.disconnect_bus()
    assert session.isRunning() and term.holds_adapter() and term._state == "off"
    assert "terminal" in win.conn.busy_reason()

    release.set()
    _wait(app, lambda: not term.holds_adapter())
    assert not term.holds_adapter() and win.conn.busy_reason() == ""
    win.close()


def test_a_late_closed_signal_after_disconnect_is_ignored() -> None:
    """`closed` can arrive after disconnect_bus() deleted the session: sender() is then None and must be ignored."""
    set_lang("en")
    app, win = create_window()
    term = win.terminal
    assert term.session is None
    term._on_closed("")  # called with no sender, as a queued signal from an already deleted session arrives
    assert term._state == "off" and term.session is None
    win.close()


def test_can_session_uds_only_uses_uds_session_for_any_ecu_id() -> None:
    """On uds_only D-PDU buses, CanSession._run_command opens link.uds_session() for any (tx_id, rx_id), not just 710/77A."""
    from contextlib import contextmanager

    from contitool.can.transport import J533CanLink
    from contitool.gui.can_session import CanSession

    set_lang("en")
    opened_sessions: list[tuple[int, int]] = []
    sent_payloads: list[bytes] = []

    class FakeDpduBus:
        uds_only = True
        uds_refusal = "unsupported"

        @contextmanager
        def uds_session(self, tx_id: int, rx_id: int, **_kw):  # noqa: ANN003, ANN202
            opened_sessions.append((tx_id, rx_id))
            yield True

        def request_uds(self, payload: bytes, **_kw) -> bytes:  # noqa: ANN003
            sent_payloads.append(payload)
            return b"\x62\xf1\x875NA920740B"

        def recv(self, timeout=None):  # noqa: ANN001, ANN202
            return None

        def shutdown(self) -> None:
            pass

    bus = FakeDpduBus()
    link = J533CanLink("", bus=bus)
    sess = CanSession("VW_PDUAPI", "dpdu", 500_000, bus=bus)
    sess._run_command(link, ("uds", 0x714, 0x77E, bytes.fromhex("22F187"), 2.0))
    assert opened_sessions == [(0x714, 0x77E)]
    assert sent_payloads == [bytes.fromhex("22F187")]
    assert any(r.kind == "uds-resp" and r.arb_id == 0x77E and b"5NA920740B" in r.data for r in sess.rows)


def test_terminal_save_handles_os_error(tmp_path, monkeypatch) -> None:
    from pathlib import Path

    from contitool.gui.can_session import TraceRow
    from contitool.gui.screens import terminal as term_mod

    set_lang("en")
    app, win = create_window()
    term = win.terminal
    term.model.append([TraceRow(0.0, "rx", 0x77A, bytes.fromhex("62F190"))])
    out = tmp_path / "trace.txt"
    warns: list[str] = []
    monkeypatch.setattr(term_mod.QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), ""))
    monkeypatch.setattr(Path, "write_text", lambda *_a, **_k: (_ for _ in ()).throw(OSError("permission denied")))
    monkeypatch.setattr(term_mod.QMessageBox, "warning", lambda _p, _t, msg, *a, **k: warns.append(msg))
    term._save()
    assert warns and "permission denied" in warns[0]
    win.close()
