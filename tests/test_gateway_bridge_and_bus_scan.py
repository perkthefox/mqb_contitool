"""Tests for J533 RSCAN0 transparent CAN bridge applet, multi-ECU bus scanner, and gateway-routed FPK_E workflows."""

from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Any

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import can  # noqa: E402
import pytest  # noqa: E402

from contitool.can import (  # noqa: E402
    J533_BRIDGE_END_DATA,
    J533_BRIDGE_END_ID,
    J533_BRIDGE_READY_DATA,
    J533_BRIDGE_READY_ID,
    J533_BRIDGE_STOP_DATA,
    J533_BRIDGE_STOP_ID,
    J533_BUS_CHANNELS,
    MAX_LOADER_PACKET_SIZE,
    build_j533_can_bridge_applet,
    build_loader_packet,
    can_scan_bus,
    can_uds_clear_dtc,
    can_uds_read_dtc,
    j533_can_bridge,
)
from contitool.i18n import set_lang  # noqa: E402


class FakeMultiEcuBus:
    """Simulates a CAN bus with optional J533 Gateway (0x710), Kombi FPK_E (0x714), and BCM (0x70E), plus J533 RAM-Bridge."""

    def __init__(
        self,
        *,
        has_j533: bool = True,
        j533_ident: dict[int, bytes] | None = None,
        has_fpke: bool = True,
        fpke_ident: dict[int, bytes] | None = None,
        has_bcm: bool = True,
        bcm_ident: dict[int, bytes] | None = None,
        dtcs_by_tx: dict[int, bytes] | None = None,
    ) -> None:
        self.has_j533 = has_j533
        self.has_fpke = has_fpke
        self.has_bcm = has_bcm
        self.j533_ident = (
            {
                0xF187: b"3Q0907530AR",
                0xF191: b"3Q0907530C ",
                0xF189: b"5388",
                0xF1A3: b"521",
                0xF197: b"GW MQB High",
                0xF19E: b"EV_GatewConti",
                0x0600: bytes.fromhex("030100347F08"),
            }
            if j533_ident is None
            else j533_ident
        )
        self.fpke_ident = (
            {
                0xF187: b"83A920700B ",
                0xF191: b"83A920700B ",
                0xF189: b"0295",
                0xF197: b"Kombi_FPK_E",
                0xF19E: b"EV_DashBoardAU27X",
                0x0600: bytes.fromhex("048400"),
            }
            if fpke_ident is None
            else fpke_ident
        )
        self.bcm_ident = (
            {
                0xF187: b"5Q0937084CG",
                0xF191: b"5Q0937084AN",
                0xF189: b"0253",
                0xF197: b"BCM MQBAB H",
                0xF19E: b"EV_BCMMQB",
            }
            if bcm_ident is None
            else bcm_ident
        )
        self.dtcs_by_tx: dict[int, bytes] = (
            {
                0x710: bytes.fromhex("0010018F"),
                0x714: bytes.fromhex("1000018F"),
                0x70E: bytes.fromhex("0102038F"),
            }
            if dtcs_by_tx is None
            else dict(dtcs_by_tx)
        )
        self.rx: list[tuple[int, bool, bytes]] = []
        self.bridge_active = False
        self.bridge_starts = 0
        self.bridge_stops = 0
        self.cleared_tx_ids: list[int] = []
        self._loader_bytes_remaining = 0

    def _enqueue_isotp(self, rx_id: int, payload: bytes) -> None:
        if len(payload) <= 7:
            self.rx.append((rx_id, False, bytes([len(payload)]) + payload.ljust(7, b"\xaa")))
            return
        self.rx.append((rx_id, False, bytes([0x10 | (len(payload) >> 8), len(payload) & 0xFF]) + payload[:6]))
        for seq, off in enumerate(range(6, len(payload), 7), start=1):
            self.rx.append((rx_id, False, bytes([0x20 | (seq & 0x0F)]) + payload[off : off + 7].ljust(7, b"\xaa")))

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        arb = msg.arbitration_id
        data = bytes(msg.data)

        # J533 Factory RAM-Loader & Bridge control on 0x6F0
        if arb == J533_BRIDGE_STOP_ID:
            if data == J533_BRIDGE_STOP_DATA and self.bridge_active:
                self.bridge_active = False
                self.bridge_stops += 1
                self.rx.append((J533_BRIDGE_END_ID, False, J533_BRIDGE_END_DATA))
                return
            if data == b"\x84\x00\x00\x00\x00":
                self.rx.append((0x6F1, False, b"\x84\x00\x00\x00\x00"))
                self._loader_bytes_remaining = 0
                return
            if b"-END" in data and not self.bridge_active:
                self.bridge_active = True
                self.bridge_starts += 1
                self.rx.append((J533_BRIDGE_READY_ID, False, J533_BRIDGE_READY_DATA))
                return
            return

        # Standard 11-bit UDS queries (0x710->0x77A, 0x714->0x77E, 0x70E->0x778)
        ecu_table: dict[int, tuple[bool, int, dict[int, bytes]]] = {
            0x710: (self.has_j533, 0x77A, self.j533_ident),
            0x714: (self.has_fpke, 0x77E, self.fpke_ident),
            0x70E: (self.has_bcm, 0x778, self.bcm_ident),
        }
        if arb in ecu_table:
            present, rx_id, ident_map = ecu_table[arb]
            if not present or not data or (data[0] >> 4) != 0:
                return
            req = data[1 : 1 + (data[0] & 0x0F)]
            if not req:
                return
            sid = req[0]
            if sid == 0x10:
                self._enqueue_isotp(rx_id, bytes([0x50, req[1] if len(req) > 1 else 0x03, 0x00, 0x32, 0x01, 0xF4]))
            elif sid == 0x22 and len(req) >= 3:
                did = int.from_bytes(req[1:3], "big")
                if did in ident_map:
                    self._enqueue_isotp(rx_id, b"\x62" + req[1:3] + ident_map[did])
                else:
                    self._enqueue_isotp(rx_id, b"\x7f\x22\x31")
            elif sid == 0x19 and req[:2] == b"\x19\x02":
                raw_dtc = self.dtcs_by_tx.get(arb, b"")
                self._enqueue_isotp(rx_id, b"\x59\x02\x8f" + raw_dtc)
            elif sid == 0x14:
                self.dtcs_by_tx[arb] = b""
                self.cleared_tx_ids.append(arb)
                self._enqueue_isotp(rx_id, b"\x54")

    def recv(self, timeout: float | None = None) -> can.Message | None:
        if self.rx:
            arb, ext, payload = self.rx.pop(0)
            return can.Message(arbitration_id=arb, data=payload, is_extended_id=ext)
        return None

    def shutdown(self) -> None:
        pass


def test_j533_can_bridge_applet_builds_for_all_sub_buses() -> None:
    for ch in J533_BUS_CHANNELS:
        blob = build_j533_can_bridge_applet(ch)
        pkt = build_loader_packet(blob)
        assert 900 <= len(blob) <= 1800
        assert len(pkt) <= MAX_LOADER_PACKET_SIZE
        for magic in (J533_BRIDGE_READY_DATA, J533_BRIDGE_STOP_DATA, J533_BRIDGE_END_DATA):
            assert magic[:4] in blob and magic[4:] in blob

    with pytest.raises(ValueError, match="target_channel"):
        build_j533_can_bridge_applet(3)  # ch3 is Diagnosis CAN itself


def test_j533_can_bridge_lifecycle_starts_and_stops_cleanly(monkeypatch) -> None:
    from contitool.can import workflows

    monkeypatch.setattr(
        workflows,
        "enter_ram_loader",
        lambda link, **kw: {"beacon": "CONTITOOL_RAM_OK", "loader_ready": True},
    )
    fake_bus = FakeMultiEcuBus()
    with j533_can_bridge("fake", interface="slcan", target_channel=0, bus=fake_bus) as bridge:
        assert bridge.active is True
        assert bridge.bus is fake_bus
        assert fake_bus.bridge_starts == 1

    assert bridge.active is False
    assert fake_bus.bridge_stops == 1
    assert bridge.stop_info.get("end_ack") is True
    assert bridge.stop_info.get("returned_to_app") is True


def test_j533_can_bridge_rejects_non_native_interface_without_bus() -> None:
    set_lang("en")
    with pytest.raises(RuntimeError, match="native CAN adapter"):
        j533_can_bridge("VAS6154", interface="dpdu")


def test_can_scan_bus_discovers_gateway_and_connected_slaves() -> None:
    set_lang("ru")
    bus = FakeMultiEcuBus(has_j533=True, has_fpke=True, has_bcm=True)
    res = can_scan_bus("fake", interface="slcan", bus=bus)

    assert res.topology == "gateway"
    assert res.gateway_bridge_capable is True
    assert res.gateway is not None
    assert res.gateway.part_number == "3Q0907530AR"
    assert [e.kind for e in res.ecus] == ["j533", "fpke", "bcm"]
    assert [e.diag_addr for e in res.slaves] == ["17", "09"]

    fpke = res.slaves[0]
    assert fpke.part_number == "83A920700B"
    assert fpke.via_gateway is True
    assert fpke.gateway_channel == 0
    assert fpke.bridge_available is True
    assert fpke.memory_access_available is True

    bcm = res.slaves[1]
    assert bcm.part_number == "5Q0937084CG"
    assert bcm.via_gateway is True
    assert bcm.uds_available is True

    # Read and clear DTCs on BCM (0x70E -> 0x778) through the gateway
    dtc_res = can_uds_read_dtc("fake", bcm.uds_tx_id, bcm.uds_rx_id, ecu_kind="bcm", bus=bus)
    assert dtc_res["active_count"] == 1
    clr_res = can_uds_clear_dtc("fake", bcm.uds_tx_id, bcm.uds_rx_id, bus=bus)
    assert clr_res["ok"] is True
    assert 0x70E in bus.cleared_tx_ids
    dtc_after = can_uds_read_dtc("fake", bcm.uds_tx_id, bcm.uds_rx_id, ecu_kind="bcm", bus=bus)
    assert dtc_after["dtcs"] == []


def test_can_scan_bus_direct_connection_when_no_gateway_present() -> None:
    set_lang("en")
    bus = FakeMultiEcuBus(has_j533=False, has_fpke=True, has_bcm=False)
    res = can_scan_bus("fake", interface="slcan", bus=bus)

    assert res.topology == "direct"
    assert res.gateway is None
    assert len(res.ecus) == 1
    fpke = res.ecus[0]
    assert fpke.kind == "fpke"
    assert fpke.via_gateway is False
    assert fpke.memory_access_available is True


def test_fpke_session_via_gateway_uses_j533_ram_bridge_when_level8_not_yet_open(monkeypatch, tmp_path: Path) -> None:
    from contitool.can import fpke as fpke_can
    from test_fpke import FakeFpkeBus

    fake_fpke_bus = FakeFpkeBus()
    dflash = bytes(fake_fpke_bus.dflash)
    bridge_events: list[str] = []

    class DummyBridge:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.bus = fake_fpke_bus

        def __enter__(self) -> DummyBridge:
            bridge_events.append("bridge_enter")
            return self

        def __exit__(self, *a: Any) -> None:
            bridge_events.append("bridge_exit")

    monkeypatch.setattr("contitool.can.bridge.j533_can_bridge", lambda *a, **kw: DummyBridge(*a, **kw))

    # 1. Initially Level 8 is NOT active on fake_fpke_bus -> _managed_fpke_session enters J533CanBridge
    res = fpke_can.can_fpke_full_read(
        "fake",
        interface="slcan",
        session_dir=tmp_path / "gw_fpke_read",
        wake_seconds=0.0,
        via_gateway=True,
        gateway_bridge=True,
        gateway_channel=0,
        bus=fake_fpke_bus,
    )
    assert bridge_events == ["bridge_enter", "bridge_exit"]
    assert res["via_gateway"] is True
    assert res["gateway_bridged"] is True
    assert (tmp_path / "gw_fpke_read" / "Dflash.bin").read_bytes() == dflash

    # 2. Now Level 8 is already unlocked in FPK_E RAM (fake_fpke_bus.current_level == 8):
    #    a subsequent operation over the gateway detects Level 8 via normal UDS 0x23 without starting the bridge!
    bridge_events.clear()
    res2 = fpke_can.can_fpke_read_region(
        "fake",
        mode="dflash",
        interface="slcan",
        session_dir=tmp_path / "gw_fpke_dflash",
        wake_seconds=0.0,
        via_gateway=True,
        gateway_bridge=True,
        gateway_channel=0,
        bus=fake_fpke_bus,
    )
    assert bridge_events == []
    assert res2["via_gateway"] is True
    assert res2["gateway_bridged"] is False


def test_gui_bus_screen_and_multi_ecu_switching(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    from PySide6.QtCore import QEventLoop, QTimer

    from contitool.gui import main_window
    from contitool.gui.app import create_window
    from test_fpke import build_synthetic_extra_area, build_synthetic_fpke_dflash

    set_lang("ru")
    app, win = create_window()
    win.show()

    fake_bus = FakeMultiEcuBus(has_j533=True, has_fpke=True, has_bcm=True)
    real_scan = can_scan_bus

    def _bound_scan(port: str, *, interface: str = "slcan", target_kind: str | None = None, reporter: Any = None):
        return real_scan(port, interface=interface, target_kind=target_kind, bus=fake_bus, reporter=reporter)

    monkeypatch.setattr(main_window, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(main_window, "can_scan_bus", _bound_scan)

    # Direct target cards ("bcm", "j533", "fpke") hide bus topology & scan button, showing primary direct Read button
    for tgt in ("bcm", "j533", "fpke"):
        win.switch_ecu_view("start")
        win.start_screen.set_target_kind(tgt)
        app.processEvents()
        assert win.start_screen.diagram.isVisible() is False
        assert win.start_screen.btn_scan.isVisible() is False
        assert win.start_screen.btn_read.isVisible() is True
        assert win.start_screen.btn_read.isEnabled() is True

    # Gateway+slaves mode ("all") shows bus topology & scan button, and scanning opens BusScreen
    win.switch_ecu_view("start")
    win.start_screen.set_target_kind("all")
    app.processEvents()
    assert win.start_screen.diagram.isVisible() is True
    assert win.start_screen.btn_scan.isVisible() is True
    assert win.start_screen.btn_read.isVisible() is False
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop.quit())
    win.start_screen.btn_scan.click()
    QTimer.singleShot(4000, loop.quit)
    loop.exec()
    for _ in range(10):
        app.processEvents()
    assert win.runner.last_failure is None
    assert win.stack.currentWidget() is win.bus_screen
    assert win.bus_screen.scan_result is not None
    assert [e.kind for e in win.bus_screen.scan_result.ecus] == ["j533", "fpke", "bcm"]

    assert win.tab_bus.isVisible() is True
    assert "3" in win.tab_bus.text()

    # Load both J533 dumps and FPK_E dumps while bus scan is active: both stay open & header switcher appears
    j533_dir = tmp_path / "j533_dumps"
    j533_dir.mkdir()
    (j533_dir / "Cflash.bin").write_bytes(synth_cflash)
    (j533_dir / "Dflash.bin").write_bytes(synth_dflash)
    (j533_dir / "Uflash.bin").write_bytes(synth_uflash)
    win.open_folder(str(j533_dir))
    app.processEvents()
    assert win.ws.is_open is True
    assert win.stack.currentWidget() is win.ecu_screen

    fpke_dir = tmp_path / "fpke_dumps"
    fpke_dir.mkdir()
    (fpke_dir / "Dflash.bin").write_bytes(build_synthetic_fpke_dflash())
    (fpke_dir / "ExtraArea.bin").write_bytes(build_synthetic_extra_area())
    # Historical report with via_gateway=True must NOT force via_gateway when opened from disk
    (fpke_dir / "fpke_report.json").write_text('{"via_gateway": true, "gateway_bridged": true}\n', encoding="utf-8")
    win.open_folder(str(fpke_dir))
    app.processEvents()

    assert win.ws.is_open is True
    assert win.fpke_screen.is_open is True
    assert win.fpke_screen.via_gateway is False
    assert win.ecu_switch_track.isVisible() is True
    assert win.stack.currentWidget() is win.fpke_screen

    # Switch between J533, FPK_E, and CAN Bus topology via header buttons & verify active-ECU action routing
    win.btn_sw_j533.click()
    app.processEvents()
    assert win.stack.currentWidget() is win.ecu_screen
    assert win._is_fpke_active() is False

    # Terminal target must follow active ECU (J533 -> 710/77A, FPK_E -> 714/77E, BCM -> 70E/778)
    win.set_mode("terminal")
    app.processEvents()
    assert win.terminal.ed_tx.text() == "710"
    assert win.terminal.ed_rx.text() == "77A"

    win.btn_sw_fpke.click()
    app.processEvents()
    assert win.stack.currentWidget() is win.fpke_screen
    assert win._is_fpke_active() is True
    win.set_mode("terminal")
    app.processEvents()
    assert win.terminal.ed_tx.text() == "714"
    assert win.terminal.ed_rx.text() == "77E"

    # Opening BCM terminal from BusScreen must keep 70E/778 even when J533 & FPK_E are open
    bcm_ecu = win.bus_screen.scan_result.find("bcm")
    assert bcm_ecu is not None
    win._on_bus_open_terminal(bcm_ecu)
    app.processEvents()
    assert win.modes.currentWidget() is win.terminal
    assert win.terminal.ed_tx.text() == "70E"
    assert win.terminal.ed_rx.text() == "778"

    # Exporting / restoring while viewing J533 must route to J533 (never hijack to FPK_E)
    called: list[str] = []
    monkeypatch.setattr(win.fpke_screen, "export_backup", lambda: called.append("fpke_export"))
    monkeypatch.setattr(win.ecu_screen, "export_backup", lambda: called.append("j533_export"))
    win.switch_ecu_view("j533")
    win.act_export.trigger()
    assert called == ["j533_export"]
    win.switch_ecu_view("fpke")
    win.act_export.trigger()
    assert called == ["j533_export", "fpke_export"]

    # Clicking restore on J533 card in BusScreen must NOT open FPK_E restore even when FPK_E is open
    monkeypatch.setattr(win.fpke_screen, "restore_dflash_from_file", lambda *a, **k: called.append("fpke_restore"))
    monkeypatch.setattr(main_window, "run_dialog", lambda _dlg: False)
    j533_ecu = win.bus_screen.scan_result.find("j533")
    assert j533_ecu is not None
    win._on_bus_restore_ecu(j533_ecu)
    assert "fpke_restore" not in called

    win.tab_bus.click()
    app.processEvents()
    assert win.stack.currentWidget() is win.bus_screen

    win.close()


def test_can_scan_bus_explicit_slave_target_errors_clearly_when_missing() -> None:
    set_lang("ru")
    # J533 present, BCM absent -> targeting "bcm" must raise clear error mentioning J533 + BCM
    bus_no_bcm = FakeMultiEcuBus(has_j533=True, has_fpke=True, has_bcm=False)
    with pytest.raises(RuntimeError, match="BCM"):
        can_scan_bus("fake", interface="slcan", target_kind="bcm", bus=bus_no_bcm)

    # Targeting "j533" directly records scanned_targets=("j533",)
    res_j533 = can_scan_bus("fake", interface="slcan", target_kind="j533", bus=bus_no_bcm)
    assert [e.kind for e in res_j533.ecus] == ["j533"]
    assert res_j533.scanned_targets == ("j533",)


def test_can_fpke_run_level8_action_supports_both_1arg_and_2arg_callbacks(monkeypatch) -> None:
    from contitool.can import fpke as fpke_can
    from test_fpke import FakeFpkeBus

    fake_fpke_bus = FakeFpkeBus()
    bridge_calls: list[str] = []

    class DummyBridge:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.bus = fake_fpke_bus

        def __enter__(self) -> DummyBridge:
            bridge_calls.append("enter")
            return self

        def __exit__(self, *a: Any) -> None:
            bridge_calls.append("exit")

    monkeypatch.setattr("contitool.can.bridge.j533_can_bridge", lambda *a, **kw: DummyBridge(*a, **kw))

    # 2-arg callback (exact signature used by _FpkeCanControlPanel._run_proc and FpkeCoilKeyLearnDialog)
    seen: list[tuple[Any, Any]] = []

    def two_arg(lnk: Any, rep: Any) -> dict[str, Any]:
        seen.append((lnk, rep))
        return {"ok": True, "argc": 2}

    out2 = fpke_can.can_fpke_run_level8_action(
        "fake",
        two_arg,
        interface="slcan",
        via_gateway=True,
        gateway_bridge=True,
        gateway_channel=0,
        bus=fake_fpke_bus,
    )
    assert out2 == {"ok": True, "argc": 2}
    assert len(seen) == 1 and seen[0][0] is not None and seen[0][1] is not None
    assert bridge_calls == ["enter", "exit"]

    # 1-arg callback also works
    out1 = fpke_can.can_fpke_run_level8_action(
        "fake",
        lambda lnk: {"ok": True, "argc": 1, "via_gw": lnk.via_gateway},
        interface="slcan",
        via_gateway=True,
        gateway_bridge=True,
        gateway_channel=0,
        bus=fake_fpke_bus,
    )
    assert out1 == {"ok": True, "argc": 1, "via_gw": False}


def test_ecu_found_dialog_blocks_bcm_and_unbridged_gateway_fpke() -> None:
    from contitool.gui.app import create_window
    from contitool.gui.main_window import EcuFoundDialog

    set_lang("ru")
    _app, win = create_window()
    bus = FakeMultiEcuBus(has_j533=True, has_fpke=True, has_bcm=True)
    scan = can_scan_bus("fake", interface="slcan", bus=bus)

    bcm = scan.find("bcm")
    assert bcm is not None
    assert bcm.bridge_available is True
    assert bcm.memory_access_available is True
    dlg_bcm_bridged = EcuFoundDialog(bcm.to_ident_dict(), win.conn, win)
    assert dlg_bcm_bridged.unsupported == ""
    assert dlg_bcm_bridged.btn_ok is not None
    dlg_bcm_bridged.close()

    bcm_unbridged = bcm.to_ident_dict()
    bcm_unbridged["bridge_available"] = False
    bcm_unbridged["memory_unavailable_reason"] = "Gateway does not support RAM bridge for BCM."
    dlg_bcm = EcuFoundDialog(bcm_unbridged, win.conn, win)
    assert dlg_bcm.unsupported == ""
    assert dlg_bcm.btn_ok is not None
    dlg_bcm.close()

    fpke_ident = scan.find("fpke").to_ident_dict()
    fpke_ident["bridge_available"] = False
    fpke_ident["memory_unavailable_reason"] = "Gateway does not support RAM bridge."
    dlg_unbridged = EcuFoundDialog(fpke_ident, win.conn, win)
    assert dlg_unbridged.unsupported == "Gateway does not support RAM bridge."
    assert dlg_unbridged.btn_ok is None
    dlg_unbridged.close()
    win.close()


def test_fpke_can_control_panel_disables_direct_only_bench_controls_via_gateway() -> None:
    from contitool.gui.app import create_window
    from contitool.gui.screens.fpke import _FpkeCanControlPanel

    set_lang("ru")
    _app, win = create_window()
    panel_gw = _FpkeCanControlPanel(
        win.conn,
        win.runner,
        win,
        via_gateway=True,
        gateway_bridge=True,
        gateway_channel=0,
    )
    assert panel_gw.sw_kl15.isEnabled() is False
    assert panel_gw.sw_drive.isEnabled() is False
    assert panel_gw.sld_speed.isEnabled() is False
    assert panel_gw.sld_rpm.isEnabled() is False
    assert all(not b.isEnabled() for b in panel_gw._mfl_buttons)
    assert all(b.isEnabled() for b in panel_gw._proc_buttons)
    panel_gw.close()

    panel_direct = _FpkeCanControlPanel(win.conn, win.runner, win, via_gateway=False)
    assert panel_direct.sw_kl15.isEnabled() is True
    assert panel_direct.sw_drive.isEnabled() is True
    assert all(b.isEnabled() for b in panel_direct._mfl_buttons)
    panel_direct.close()
    win.close()


def test_cli_can_scan_and_fpke_via_gateway_arg_parsing(monkeypatch, capsys) -> None:
    import importlib

    cli_main = importlib.import_module("contitool.cli.main")

    ap = cli_main.build_arg_parser()
    ns_scan = ap.parse_args(["can", "scan", "--port", "COM4", "--target", "bcm"])
    assert ns_scan.can_action == "scan"
    assert ns_scan.target == "bcm"

    ns_fpke = ap.parse_args(["fpke", "read", "--port", "COM4", "--via-gateway", "--gateway-channel", "0"])
    assert ns_fpke.via_gateway is True
    assert ns_fpke.gateway_channel == 0

    fake_bus = FakeMultiEcuBus(has_j533=True, has_fpke=True, has_bcm=True)
    real_scan = can_scan_bus
    monkeypatch.setattr(
        cli_main,
        "can_scan_bus",
        lambda port, *, interface="slcan", target_kind=None, reporter=None: real_scan(
            port, interface=interface, target_kind=target_kind, bus=fake_bus, reporter=reporter
        ),
    )
    rc = cli_main.cmd_can(ns_scan)
    assert rc == 0
    out = capsys.readouterr().out
    assert "5Q0937084CG" in out
    assert "3Q0907530AR" in out


def test_bcm_direct_identify_and_connection_dialog_check_link(monkeypatch) -> None:
    from PySide6.QtCore import QEventLoop, QTimer

    from contitool.can import FoundAdapter, can_identify
    from contitool.gui import connection
    from contitool.gui.app import create_window

    set_lang("ru")

    # 1. Direct 09 BCM (5Q0937084CG) answers on 0x70E -> 0x778 (no gateway, no FPK_E)
    bcm_bus = FakeMultiEcuBus(has_j533=False, has_fpke=False, has_bcm=True)
    ident = can_identify("fake", interface="slcan", bus=bcm_bus)
    assert ident["responding"] is True
    assert ident["ecu_kind"] == "bcm"
    assert ident["uds_tx_id"] == "0x70E"
    assert ident["uds_rx_id"] == "0x778"
    assert not ident.get("unsupported")
    vals = {it["did"]: it["value"] for it in ident["ident"]}
    assert vals["F187"] == "5Q0937084CG"

    # 2. Direct 09 BCM that rejects 10 03 with NRC 0x22 (KL15 off) but answers 10 01 + 22 F1xx
    class Kl15OffBcmBus(FakeMultiEcuBus):
        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            if msg.arbitration_id == 0x70E and bytes(msg.data)[:3] == b"\x02\x10\x03":
                self._enqueue_isotp(0x778, b"\x7f\x10\x22")
                return
            super().send(msg, timeout=timeout)

    kl15_off_bus = Kl15OffBcmBus(has_j533=False, has_fpke=False, has_bcm=True)
    ident_kl15_off = can_identify("fake", interface="slcan", bus=kl15_off_bus)
    assert ident_kl15_off["ecu_kind"] == "bcm"
    assert any(it["did"] == "F187" and it["value"] == "5Q0937084CG" for it in ident_kl15_off["ident"])

    scan_kl15_off = can_scan_bus("fake", interface="slcan", target_kind="bcm", bus=kl15_off_bus)
    assert scan_kl15_off.topology == "direct"
    assert [e.kind for e in scan_kl15_off.ecus] == ["bcm"]

    # 3. ConnectionDialog Check Link passes cleanly with green "ok" tone for 5Q0937084CG BCM (not flagged as 5Q0 gateway!)
    app, win = create_window()
    monkeypatch.setattr(
        connection,
        "discover_adapters",
        lambda: [FoundAdapter("slcan", "/dev/cu.usbmodem1101", "CANable2", "SLCAN")],
    )
    monkeypatch.setattr(
        connection,
        "can_identify",
        lambda port, *, interface="slcan", reporter=None: can_identify(port, interface=interface, bus=bcm_bus, reporter=reporter),
    )
    dlg = connection.ConnectionDialog(win.conn, win)
    while dlg._scan is not None:
        dlg._scan.wait(3000)
        app.processEvents()
    loop = QEventLoop()
    dlg._check_link()
    dlg._check.finished.connect(loop.quit)
    QTimer.singleShot(3000, loop.quit)
    loop.exec()
    for _ in range(10):
        app.processEvents()
    assert dlg.lbl_check.property("tone") == "ok"
    assert "09 BCM" in dlg.lbl_check.text()
    assert "5Q0937084CG" in dlg.lbl_check.text()
    dlg.close()
    win.close()
