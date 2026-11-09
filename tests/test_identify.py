"""Before reading an ECU: check the CAN link, show the identification, and only read after the user confirms."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import can  # noqa: E402
import pytest  # noqa: E402

from contitool.can import can_identify  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402

# What a 3Q0907530AA gateway answers
IDENT = {0xF187: b"3Q0907530AA", 0xF191: b"3Q0907530C ", 0xF189: b"5366", 0xF197: b"GW MQB High\x00\x00", 0x0600: bytes.fromhex("030100347f08")}


class FakeGateway:
    """Answers UDS on 0x710 -> 0x77A with ISO-TP framing; unknown identifiers get 7F 22 31."""

    def __init__(self, answers: bool = True) -> None:
        self.answers, self.rx = answers, []

    def _reply(self, payload: bytes) -> None:
        if len(payload) <= 7:
            self.rx.append(bytes([len(payload)]) + payload.ljust(7, b"\xaa"))
            return
        self.rx.append(bytes([0x10 | (len(payload) >> 8), len(payload) & 0xFF]) + payload[:6])
        for seq, off in enumerate(range(6, len(payload), 7), start=1):
            self.rx.append(bytes([0x20 | (seq & 0x0F)]) + payload[off : off + 7].ljust(7, b"\xaa"))

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        data = bytes(msg.data)
        if not self.answers or msg.arbitration_id != 0x710 or data[0] >> 4 != 0:
            return  # flow control frames and silence
        req = data[1 : 1 + (data[0] & 0x0F)]
        if req == b"\x10\x03":
            self._reply(b"\x50\x03\x00\x32\x01\xf4")
        elif req[0] == 0x22:
            did = int.from_bytes(req[1:3], "big")
            self._reply(b"\x62" + req[1:3] + IDENT[did] if did in IDENT else b"\x7f\x22\x31")

    def recv(self, timeout: float | None = None) -> can.Message | None:
        if self.rx:
            return can.Message(arbitration_id=0x77A, data=self.rx.pop(0), is_extended_id=False)
        return None

    def shutdown(self) -> None:
        pass


def test_identification_lists_what_the_ecu_answers() -> None:
    set_lang("en")
    res = can_identify("fake", bus=FakeGateway())
    values = {i["did"]: i["value"] for i in res["ident"]}
    assert res["responding"]
    assert values["F187"] == "3Q0907530AA"
    assert values["F191"] == "3Q0907530C"  # trailing blanks and NULs trimmed
    assert values["F197"] == "GW MQB High"
    assert values["0600"] == "030100347F08"  # binary shown as hex
    assert "F190" not in values and "F18C" not in values  # rejected identifiers are left out


def test_silent_ecu_gets_a_wiring_hint() -> None:
    set_lang("en")
    with pytest.raises(RuntimeError, match="Pin 19"):
        can_identify("fake", bus=FakeGateway(answers=False))


def test_gui_reads_only_after_the_user_confirms(monkeypatch) -> None:
    from PySide6.QtCore import QEventLoop, QTimer

    from contitool.gui import main_window
    from contitool.gui.app import create_window

    set_lang("en")
    app, win = create_window()
    backups: list[str] = []
    monkeypatch.setattr(main_window, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(main_window, "can_identify", lambda *a, **k: {"responding": True, "ident": [
        {"did": "F187", "label_ru": "Номер детали", "label_en": "Part number", "value": "3Q0907530AA"}]})
    monkeypatch.setattr(main_window, "can_backup", lambda *a, **k: backups.append("read") or {})
    monkeypatch.setattr(win.ws, "open_folder", lambda *a, **k: [])
    monkeypatch.setattr(win, "_report_missing", lambda *a, **k: None)  # its message box would block offscreen

    def run(answer: int) -> None:
        monkeypatch.setattr(main_window.EcuFoundDialog, "exec", lambda self: answer)
        loop = QEventLoop()
        win.runner.operation_finished.connect(loop.quit)
        win.read_over_can()
        QTimer.singleShot(5000, loop.quit)
        loop.exec()  # identification finished
        win.runner.operation_finished.disconnect(loop.quit)
        for _ in range(20):
            app.processEvents()
        if win.runner.is_busy:  # the backup started: wait for it as well
            loop2 = QEventLoop()
            win.runner.operation_finished.connect(loop2.quit)
            QTimer.singleShot(5000, loop2.quit)
            loop2.exec()

    run(0)
    assert backups == []
    run(1)
    assert backups == ["read"]
    win.close()


def test_fbl_ecu_warns_and_offers_to_write_backup(monkeypatch) -> None:
    from PySide6.QtCore import QEventLoop, QTimer

    from contitool.can import FoundAdapter
    from contitool.gui import connection, main_window
    from contitool.gui.app import create_window

    set_lang("en")
    app, win = create_window()
    fbl_ident = {
        "responding": True,
        "in_fbl": True,
        "app_valid": False,
        "f1df": "44",
        "ident": [{"did": "F187", "label_ru": "Номер детали", "label_en": "Part number", "value": "3Q0907530AR"}],
    }

    # 1. Link check in ConnectionDialog reports FBL bootloader mode with warning tone
    monkeypatch.setattr(
        connection,
        "discover_adapters",
        lambda: [FoundAdapter("slcan", "/dev/cu.usbmodem1101", "CANable2", "SLCAN")],
    )
    monkeypatch.setattr(connection, "can_identify", lambda port, **k: fbl_ident)
    dlg = connection.ConnectionDialog(win.conn, win)
    while dlg._scan is not None:
        dlg._scan.wait(3000)
        app.processEvents()
    loop = QEventLoop()
    dlg._check_link()
    dlg._check.finished.connect(loop.quit)
    QTimer.singleShot(3000, loop.quit)
    loop.exec()
    for _ in range(5):
        app.processEvents()
    assert dlg.lbl_check.text() == "✓ ECU answers (in FBL bootloader mode): 3Q0907530AR"
    assert dlg.lbl_check.property("tone") == "warn"
    dlg.close()

    # 2. Clicking "Read the ECU" on an FBL unit warns and lets the user jump straight to "Write backup to ECU…"
    actions: list[str] = []
    monkeypatch.setattr(main_window, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(main_window, "can_identify", lambda *a, **k: fbl_ident)
    monkeypatch.setattr(main_window, "can_backup", lambda *a, **k: actions.append("backup") or {})
    monkeypatch.setattr(win, "restore_backup", lambda: actions.append("restore"))

    def choose_restore_in_dialog(self) -> int:
        assert self.windowTitle() == "ECU in bootloader mode (FBL)"
        assert self.btn_ok.text() == "Write backup to ECU…"
        self.btn_ok.click()
        return self.result()

    monkeypatch.setattr(main_window.EcuFoundDialog, "exec", choose_restore_in_dialog)
    loop2 = QEventLoop()
    win.runner.operation_finished.connect(loop2.quit)
    win.read_over_can()
    QTimer.singleShot(5000, loop2.quit)
    loop2.exec()
    win.runner.operation_finished.disconnect(loop2.quit)
    for _ in range(20):
        app.processEvents()
    assert actions == ["restore"]

    # 3. Start screen also exposes "Write backup…" directly
    win.start_screen.btn_restore.click()
    app.processEvents()
    assert actions == ["restore", "restore"]
    win.close()
