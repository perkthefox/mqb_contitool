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
from contitool.can.hw_applets import J533_BRIDGE_BURST_DATA, J533_BRIDGE_BURST_FAIL, J533_BRIDGE_BURST_OK  # noqa: E402
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
        self.bursts = 0
        self.burst_reply: bytes | None = None  # what the bridge applet answers to BURST-GO (None: silence)

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
            if data == J533_BRIDGE_BURST_DATA and self.bridge_active:
                self.bursts += 1
                if self.burst_reply is not None:
                    self.rx.append((J533_BRIDGE_END_ID, False, self.burst_reply))
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


def test_fire_burst_reports_what_the_gateway_answered(monkeypatch) -> None:
    from contitool.can import workflows

    set_lang("en")
    monkeypatch.setattr(workflows, "enter_ram_loader", lambda link, **kw: {"loader_ready": True})
    frames = [(0x1BFCA2ED, bytes(range(8))), (0x17FA0E14, bytes(8))]
    fake = FakeMultiEcuBus()
    with j533_can_bridge("fake", interface="slcan", bus=fake, burst_frames=frames) as bridge:
        with pytest.raises(RuntimeError, match="differs from the frame table"):
            bridge.fire_burst(frames[:1])
        assert fake.bursts == 0  # nothing triggered for a stream the gateway does not hold
        fake.burst_reply = J533_BRIDGE_BURST_OK
        bridge.fire_burst(frames)
        fake.burst_reply = J533_BRIDGE_BURST_FAIL
        with pytest.raises(RuntimeError, match="got no ACK"):
            bridge.fire_burst(frames)
        fake.burst_reply = None
        with pytest.raises(TimeoutError, match="BURST-OK"):
            bridge.fire_burst(frames, timeout=0.2)
        assert fake.bursts == 3
    with pytest.raises(RuntimeError, match="not running"):
        bridge.fire_burst(frames)

    with j533_can_bridge("fake", interface="slcan", bus=FakeMultiEcuBus()) as plain:
        with pytest.raises(RuntimeError, match="no table was uploaded"):
            plain.fire_burst(frames)


def test_j533_can_bridge_rejects_an_adapter_without_raw_can() -> None:
    set_lang("en")
    with pytest.raises(RuntimeError, match="arbitrary raw CAN"):
        j533_can_bridge("PassThru", interface="j2534")


def test_a_vnci_bridge_serves_the_bcm_and_the_fpke() -> None:
    from contitool.can.ecus import ECU_SPEC_BY_KIND, _build_slave_ecu

    def build(kind: str):
        return _build_slave_ecu(ECU_SPEC_BY_KIND[kind], [], via_gateway=True, gateway_bridge_capable=True,
                                interface="dpdu", bus_injected=False, in_fbl=False)

    for ecu in (build("bcm"), build("fpke")):
        assert ecu.bridge_available and "memory" in ecu.capabilities


def test_a_vnci_that_can_carry_the_bridge_blames_the_gateway_when_memory_is_unavailable() -> None:
    from contitool.can.ecus import ECU_SPEC_BY_KIND, _build_slave_ecu

    set_lang("en")

    def reason(adapter_ok: bool) -> str:
        ecu = _build_slave_ecu(ECU_SPEC_BY_KIND["fpke"], [], via_gateway=True, gateway_bridge_capable=False,
                               interface="dpdu", bus_injected=False, in_fbl=False, bridge_adapter_ok=adapter_ok)
        return str(ecu.memory_unavailable_reason)

    assert "gateway on the bus does not support" in reason(True)
    assert "arbitrary raw CAN" in reason(False)


def test_fpke_memory_pages_check_the_selected_adapter_and_the_gateway_separately() -> None:
    from types import SimpleNamespace

    from contitool.gui.screens.fpke import FpkeScreen

    def blocker(iface: str, via_gateway: bool, gateway_bridge: bool = True) -> str | None:
        screen = SimpleNamespace(conn=SimpleNamespace(interface=iface), via_gateway=via_gateway,
                                 gateway_bridge=gateway_bridge)
        return FpkeScreen._memory_blocker(screen)  # type: ignore[arg-type]

    assert blocker("slcan", False) is None and blocker("dpdu", False) == "adapter"
    assert blocker("dpdu", True) is None and blocker("slcan", True) is None
    assert blocker("j2534", True) == "adapter"  # scanned with a VNCI, then J2534 selected
    assert blocker("slcan", True, gateway_bridge=False) == "gateway"  # SLCAN is fine, the gateway is not


# sha256 of the hardware-verified bridge applet per target channel: the burst variant must never change these
VERIFIED_BRIDGE_APPLETS = {
    0: "2bb48ea7960dde4fc080beac4476cbdc144049063e91143caec726a840c8cfdf",
    1: "c4228e2fde3bb5258fa161790146f2054e6c1ea00ae0b529512ebed03ffa0b0a",
    2: "60154c7c2ba0d9d974be16dc7bacd05cdba9f0a310e764ca7c53f71ad50c4a64",
    4: "d568e5f438a99d24aae07e0bf51b3a352d937e4efe5270a2a285079bb8e49ef1",
    5: "bf579a82525f6b66c694c2f421e3ec0ce6c97ab80bb97a930b4c7bbc3277903c",
}


def test_the_bridge_applet_without_a_burst_stays_byte_identical() -> None:
    import hashlib

    for ch, digest in VERIFIED_BRIDGE_APPLETS.items():
        assert hashlib.sha256(build_j533_can_bridge_applet(ch)).hexdigest() == digest


def test_the_burst_table_rides_at_the_end_of_the_applet_as_tmid_plus_data() -> None:
    import struct

    from contitool.can.hw_applets import J533_BRIDGE_BURST_DATA, J533_BRIDGE_BURST_GAP_MAX_LOOPS

    frames = [(0x1BFCA2ED, bytes(range(8))), (0x17FA0E14, bytes.fromhex("1022800300000000")), (0x6F0, b"ABCDEFGH")]
    blob = build_j533_can_bridge_applet(0, burst_frames=frames)
    table = blob[-12 * len(frames):]
    for i, (can_id, data) in enumerate(frames):
        tmid, = struct.unpack_from("<I", table, 12 * i)
        assert tmid == can_id | 0x80000000  # every burst frame goes out 29-bit, a low id included
        assert table[12 * i + 4 : 12 * i + 12] == data
    for magic in struct.unpack("<II", J533_BRIDGE_BURST_DATA):
        assert struct.pack("<I", magic) in blob  # the trigger compare is compiled in
    assert len(blob) > len(build_j533_can_bridge_applet(0)) + 12 * len(frames)
    for bad in ([], [(0x1BFCA2ED, b"short")], [(0x20000000, bytes(8))]):
        with pytest.raises(ValueError):
            build_j533_can_bridge_applet(0, burst_frames=bad)
    build_j533_can_bridge_applet(0, burst_frames=frames, burst_gap_loops=J533_BRIDGE_BURST_GAP_MAX_LOOPS)
    for gap in (0, J533_BRIDGE_BURST_GAP_MAX_LOOPS + 1):  # the gap loop never kicks the watchdog
        with pytest.raises(ValueError, match="burst_gap_loops"):
            build_j533_can_bridge_applet(0, burst_frames=frames, burst_gap_loops=gap)


def _vnci_behind_a_gateway(monkeypatch, fake, *, on_bridge_start=None) -> dict[str, Any]:
    """A VAS 6154 (`dpdu`) reaching `fake` through a J533 whose bridge is faked; its burst goes out as the applet
    sends it. Returns what the bridge saw: `table` (uploaded with it) and `fired`."""
    from contitool.can import dpdu

    monkeypatch.setattr(dpdu, "open_session", lambda *a, **k: fake)
    monkeypatch.setattr(dpdu, "release_session", lambda *a, **k: None)
    seen: dict[str, Any] = {}

    class GatewayBridge:
        def __init__(self, *a: Any, burst_frames=None, **kw: Any) -> None:
            self.bus = fake
            seen["table"] = burst_frames

        def __enter__(self):
            if on_bridge_start is not None:
                on_bridge_start()
            return self

        def __exit__(self, *a: Any) -> None:
            pass

        def fire_burst(self, frames) -> None:
            assert frames == seen["table"]
            seen["fired"] = True
            for can_id, data in frames:  # what the applet puts on ch0
                fake.send(can.Message(arbitration_id=can_id, data=data, is_extended_id=True))

    monkeypatch.setattr("contitool.can.bridge.j533_can_bridge", lambda *a, **kw: GatewayBridge(*a, **kw))
    return seen


def test_fpke_level8_stream_sent_from_the_gateway_when_the_adapter_is_a_vnci(monkeypatch, tmp_path: Path) -> None:
    """Over a VAS 6154 the gateway gets the level-8 stream with the bridge applet and sends it itself; the host only
    triggers it, and the table matches the profile the cluster reported before the bridge started."""
    from contitool.can import fpke as fpke_can
    from test_fpke import FakeFpkeBus

    fake = FakeFpkeBus()
    seen = _vnci_behind_a_gateway(monkeypatch, fake)
    res = fpke_can.can_fpke_full_read(
        "VAS6154", interface="dpdu", session_dir=tmp_path / "vci", wake_seconds=0.0,
        via_gateway=True, gateway_bridge=True, gateway_channel=0,
    )
    assert seen.get("fired") and res["gateway_bridged"] is True
    assert seen["table"] == fpke_can.fpke_level8_frames(fpke_can.fpke_detect_sw_profile(
        f189=fake.ident_map[0xF189].decode("latin1"), f187=fake.ident_map[0xF187].decode("latin1")))
    assert (tmp_path / "vci" / "Dflash.bin").read_bytes() == bytes(fake.dflash)


def test_no_level8_stream_goes_to_the_gateway_for_a_cluster_that_does_not_identify_itself(
    monkeypatch, tmp_path: Path
) -> None:
    """A sleeping cluster answers neither F189 nor F187: its profile would only be a guess, so no bridge starts."""
    from contitool.can import fpke as fpke_can
    from test_fpke import FakeFpkeBus

    set_lang("en")
    fake = FakeFpkeBus()
    del fake.ident_map[0xF189], fake.ident_map[0xF187]
    seen = _vnci_behind_a_gateway(monkeypatch, fake)
    with pytest.raises(RuntimeError, match="did not report its software version"):
        fpke_can.can_fpke_full_read(
            "VAS6154", interface="dpdu", session_dir=tmp_path / "s", wake_seconds=0.0,
            via_gateway=True, gateway_bridge=True, gateway_channel=0,
        )
    assert "table" not in seen and fake.ed_count == 0


def test_the_gateway_stream_is_not_fired_when_the_cluster_reports_another_profile_after_10_03(
    monkeypatch, tmp_path: Path
) -> None:
    from contitool.can import fpke as fpke_can
    from test_fpke import FakeFpkeBus

    set_lang("en")
    fake = FakeFpkeBus()  # identifies as 83a to the probe before the bridge

    def now_a_1703() -> None:
        fake.ident_map.update({0xF189: b"1703", 0xF187: b"5E0920790A "})

    seen = _vnci_behind_a_gateway(monkeypatch, fake, on_bridge_start=now_a_1703)
    with pytest.raises(RuntimeError, match=r"holds the stream for cluster software 83A.*1703"):
        fpke_can.can_fpke_full_read(
            "VAS6154", interface="dpdu", session_dir=tmp_path / "s", wake_seconds=0.0,
            via_gateway=True, gateway_bridge=True, gateway_channel=0,
        )
    assert seen["table"] == fpke_can.fpke_level8_frames("83a")
    assert "fired" not in seen and fake.ed_count == 0 and fake.vendor_level == 0


def test_a_large_dataflash_rewrite_through_a_vnci_is_refused_before_anything_is_written(monkeypatch, tmp_path: Path) -> None:
    from contitool.can import fpke as fpke_can
    from test_fpke import FakeFpkeBus

    fake = FakeFpkeBus()
    before = bytes(fake.dflash)
    _vnci_behind_a_gateway(monkeypatch, fake)
    blank_checks: list[Any] = []
    monkeypatch.setattr(fpke_can, "fpke_read_dflash_blank_checked", lambda *a, **k: blank_checks.append(k))
    monkeypatch.setattr(fpke_can, "FPKE_SLOW_ADAPTER_MAX_BLOCKS", 8)  # this diff makes 34 block jobs
    cand = bytearray(before)
    for off in range(0x8000, 0x8000 + 64 * 136, 64):
        cand[off] ^= 0x01
    with pytest.raises(RuntimeError, match="VAS 6154"):
        fpke_can.can_fpke_write_dflash(
            "VAS6154", bytes(cand), interface="dpdu", session_dir=tmp_path / "w", wake_seconds=0.0,
            full_rewrite=True, allow_foreign=True, reset_after=False,
            via_gateway=True, gateway_bridge=True, gateway_channel=0,
        )
    assert bytes(fake.dflash) == before
    assert not blank_checks  # refused from the backup read alone, before the 64 KB blank-check
    set_lang("en")
    with pytest.raises(RuntimeError, match="through adapter “j2534”") as other:
        fpke_can._refuse_slow_adapter_write("j2534", 9)
    assert "VAS 6154" not in str(other.value)
    fpke_can._refuse_slow_adapter_write("j2534", 8)
    fpke_can._refuse_slow_adapter_write("slcan", 10_000)


def test_the_level8_frame_list_is_the_stream_the_host_has_always_sent() -> None:
    from contitool.can import fpke as f

    for profile in ("83a", "1703", "1711"):
        ptr = int(f.fpke_get_profile(profile)["pointer_frame"])
        old = [(f.FPKE_BLOCK_ID, f.flood_payload(i, profile=profile)) for i in range(ptr)]
        old += [(f.FPKE_CF_CH9_ID, bytes.fromhex("1022800300000000")),
                (f.FPKE_BLOCK_ID, f.flood_payload(ptr, profile=profile)),
                (f.FPKE_CF_CH9_ID, bytes([0x21, 8, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]))]
        assert f.fpke_level8_frames(profile) == old and len(old) == ptr + 3
        build_loader_packet(build_j533_can_bridge_applet(0, burst_frames=old))  # raises past the FBL buffer limit


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


def test_j533_can_bridge_applet_gafl_whitelist_preserves_default_and_encodes_rules() -> None:
    import hashlib
    import struct

    # Default (no target_rx_filter) must remain 100% byte-identical to hardware-verified applets
    for ch, expected_sha in VERIFIED_BRIDGE_APPLETS.items():
        assert hashlib.sha256(build_j533_can_bridge_applet(ch)).hexdigest() == expected_sha

    # Filtered ch2 (13 MRR: 0x7C1, 0x77E, 0x1BFEBA01) and ch0 (09 BCM / 17 FPK_E) and ch4 (target > diag_ch)
    mrr_filter = ((0x7C1, False), (0x77E, False), (0x1BFEBA01, True))
    blob_mrr = build_j533_can_bridge_applet(2, target_rx_filter=mrr_filter)
    assert len(build_loader_packet(blob_mrr)) <= MAX_LOADER_PACKET_SIZE
    # GAFLCFG0 must encode ch2=3 rules, ch3=1 rule -> (3 << 8) | 1 = 0x00000301
    assert struct.pack("<I", 0x00000301) in blob_mrr
    # Encoded GAFLID / GAFLM words for std 0x7C1, std 0x77E, ext 0x1BFEBA01
    assert struct.pack("<I", 0x000007C1) in blob_mrr
    assert struct.pack("<I", 0xC00007FF) in blob_mrr
    assert struct.pack("<I", 0x1BFEBA01 | 0x80000000) in blob_mrr
    assert struct.pack("<I", 0xDFFFFFFF) in blob_mrr

    # ch4 > ch3: GAFLCFG0 has ch3=1 (0x00000001), GAFLCFG1 has ch4=2 (2 << 24)
    blob_ch4 = build_j533_can_bridge_applet(4, target_rx_filter=((0x773, False), (0x17FE015F, True)))
    assert struct.pack("<I", 0x02000000) in blob_ch4
    assert len(build_loader_packet(blob_ch4)) <= MAX_LOADER_PACKET_SIZE

    with pytest.raises(ValueError, match="1..15"):
        build_j533_can_bridge_applet(0, target_rx_filter=[])
    with pytest.raises(ValueError, match="1..15"):
        build_j533_can_bridge_applet(0, target_rx_filter=[(0x700 + i, False) for i in range(16)])
    with pytest.raises(ValueError, match="Standard filter CAN ID"):
        build_j533_can_bridge_applet(0, target_rx_filter=[(0x800, False)])


def test_j533_can_bridge_close_survives_can_error_and_missed_ready_beacon(monkeypatch) -> None:
    from contitool.can import workflows
    from contitool.progress import OperationReporter

    set_lang("en")
    monkeypatch.setattr(
        workflows,
        "enter_ram_loader",
        lambda link, **kw: {"beacon": "CONTITOOL_RAM_OK", "loader_ready": True},
    )

    # 1. CanOperationError during _wait_beacon in __exit__ must not mask the inner exception
    class DropOnStopBus(FakeMultiEcuBus):
        def recv(self, timeout: float | None = None) -> can.Message | None:
            if self.bridge_stops > 0:
                raise can.CanOperationError("VCI unplugged")
            return super().recv(timeout)

    drop_bus = DropOnStopBus()
    with pytest.raises(ValueError, match="inner-op-error"):
        with j533_can_bridge("fake", interface="slcan", target_channel=0, bus=drop_bus):
            raise ValueError("inner-op-error")

    # 2. Missed J533BRDG ready beacon must still attempt STOPBRDG during error cleanup
    class SilentReadyBus(FakeMultiEcuBus):
        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            if msg.arbitration_id == J533_BRIDGE_STOP_ID and b"-END" in bytes(msg.data) and not self.bridge_active:
                self.bridge_active = True
                self.bridge_starts += 1
                # Deliberately drop J533BRDG beacon
                return
            super().send(msg, timeout=timeout)

    silent_bus = SilentReadyBus()
    warnings: list[str] = []
    rep = OperationReporter(on_log=lambda ev: warnings.append(ev.message) if ev.level == "warning" else None)
    with pytest.raises(TimeoutError, match="J533BRDG"):
        with j533_can_bridge("fake", interface="slcan", target_channel=2, bus=silent_bus, ready_timeout=0.05, reporter=rep):
            pass
    assert silent_bus.bridge_stops == 1


def test_can_scan_bus_reports_nonraw_and_primed_dpdu_slave_limits() -> None:
    set_lang("en")

    class NonRawBus(FakeMultiEcuBus):
        nonraw = {0x710: 1}

    scan_nr = can_scan_bus("fake", interface="dpdu", bus=NonRawBus())
    assert [e.kind for e in scan_nr.ecus] == ["j533"]
    assert any("fixed links" in n for n in scan_nr.scan_notes)

    class PrimedBus(FakeMultiEcuBus):
        _raw_needs_prime = True

    scan_pr = can_scan_bus("fake", interface="dpdu", bus=PrimedBus())
    assert [e.kind for e in scan_pr.ecus] == ["j533"]
    assert any("CAN1 primed" in n for n in scan_pr.scan_notes)


def test_can_scan_bus_warns_about_untested_29bit_dpdu_rawmode_for_bcm_and_mrr() -> None:
    """H4: D-PDU scans discovering 29-bit memory-capable slaves (BCM/MRR) must emit a bilingual warning in scan_notes."""
    bus_en = FakeMultiEcuBus(has_j533=True, has_fpke=False, has_bcm=True)
    set_lang("en")
    scan_en = can_scan_bus("VAS6154", interface="dpdu", targets=("j533", "bcm"), bus=bus_en)
    assert any("29-bit" in n and "untested" in n for n in scan_en.scan_notes)

    bus_ru = FakeMultiEcuBus(has_j533=True, has_fpke=False, has_bcm=True)
    set_lang("ru")
    scan_ru = can_scan_bus("VAS6154", interface="dpdu", targets=("j533", "bcm"), bus=bus_ru)
    assert any("29-битных" in n and "не проверена" in n for n in scan_ru.scan_notes)

    # Native SLCAN must not emit the D-PDU 29-bit warning
    bus_slcan = FakeMultiEcuBus(has_j533=True, has_fpke=False, has_bcm=True)
    set_lang("en")
    scan_slcan = can_scan_bus("COM4", interface="slcan", targets=("j533", "bcm"), bus=bus_slcan)
    assert not any("29-bit" in n for n in scan_slcan.scan_notes)


def test_can_scan_bus_retries_sleeping_slave_behind_gateway_but_not_on_can_error() -> None:
    """M5b: A sleeping slave behind J533 that misses the first 10 03 probe is discovered on the brief 2nd attempt,
    while a failing adapter raising CanError is not retried."""

    class SleepingBcmBus(FakeMultiEcuBus):
        def __init__(self) -> None:
            super().__init__(has_j533=True, has_fpke=False, has_bcm=True)
            self.bcm_1003_seen = 0

        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            if msg.arbitration_id == 0x70E and bytes(msg.data[:3]) == b"\x02\x10\x03":
                self.bcm_1003_seen += 1
                if self.bcm_1003_seen == 1:
                    return  # asleep on first routed probe
            super().send(msg, timeout=timeout)

    sleep_bus = SleepingBcmBus()
    scan = can_scan_bus("fake", interface="slcan", targets=("j533", "bcm"), bus=sleep_bus)
    assert sleep_bus.bcm_1003_seen == 2
    assert [e.kind for e in scan.ecus] == ["j533", "bcm"]

    class FaultingAdapterBus(FakeMultiEcuBus):
        def __init__(self) -> None:
            super().__init__(has_j533=True, has_fpke=False, has_bcm=True)
            self.bcm_attempts = 0

        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            if msg.arbitration_id == 0x70E:
                self.bcm_attempts += 1
                raise can.CanOperationError("TX queue error")
            super().send(msg, timeout=timeout)

    fault_bus = FaultingAdapterBus()
    scan_fault = can_scan_bus("fake", interface="slcan", targets=("j533", "bcm"), bus=fault_bus)
    assert fault_bus.bcm_attempts == 1  # no wasted retry on adapter CanError
    assert [e.kind for e in scan_fault.ecus] == ["j533"]


def test_can_uds_read_dtc_uses_aa_flow_control_padding_for_bcm_and_00_for_j533() -> None:
    """M5b: ISO-TP Flow Control frames to 09 BCM (0x70E/0x778) must be padded with 0xAA, while J533 keeps 0x00."""
    # Two DTCs (11 bytes total response) -> forces multi-frame ISO-TP FirstFrame + FlowControl
    multi_dtcs = bytes.fromhex("0102038F0405068F")

    class RecordingBus(FakeMultiEcuBus):
        def __init__(self) -> None:
            super().__init__(dtcs_by_tx={0x710: multi_dtcs, 0x70E: multi_dtcs})
            self.fc_frames: list[tuple[int, bytes]] = []

        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            raw = bytes(msg.data)
            if raw and (raw[0] >> 4) == 3:
                self.fc_frames.append((msg.arbitration_id, raw))
            super().send(msg, timeout=timeout)

    rec = RecordingBus()
    bcm_res = can_uds_read_dtc("fake", 0x70E, 0x778, ecu_kind="bcm", bus=rec)
    j533_res = can_uds_read_dtc("fake", 0x710, 0x77A, ecu_kind="j533", bus=rec)
    assert bcm_res["active_count"] == 2 and j533_res["active_count"] == 2
    assert (0x70E, bytes.fromhex("300000AAAAAAAAAA")) in rec.fc_frames
    assert (0x710, bytes.fromhex("3000000000000000")) in rec.fc_frames


def test_transport_init_closes_log_file_on_bus_failure_and_formats_rx_id_and_caps_drain_rx(
    tmp_path: Path, monkeypatch
) -> None:
    """M3c + LOW + M5b: J533CanLink closes log_file on init failure, reports actual UDS_RX_ID in ISO-TP errors,
    and caps drain_rx by both frame count and wall-clock time on busy vehicle buses."""
    from contitool.can import transport
    from contitool.can.transport import J533CanLink

    # 1. No fd leak when bus initialization fails after log_path is opened
    opened_files: list[Any] = []
    real_open = Path.open

    def tracking_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        fh = real_open(self, *args, **kwargs)
        if self.name == "fail_init.jsonl":
            opened_files.append(fh)
        return fh

    monkeypatch.setattr(Path, "open", tracking_open)
    monkeypatch.setattr(can.interface, "Bus", lambda **_k: (_ for _ in ()).throw(can.CanInitializationError("no adapter")))
    with pytest.raises(can.CanInitializationError, match="no adapter"):
        J533CanLink("COM99", interface="slcan", log_path=tmp_path / "fail_init.jsonl")
    assert len(opened_files) == 1 and opened_files[0].closed is True
    monkeypatch.undo()

    # 2. ISO-TP error/timeout messages use the active UDS_RX_ID (not hardcoded 0x77A)
    class BadIsoTpBus:
        def __init__(self, frames: list[bytes]) -> None:
            self.frames = list(frames)

        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            pass

        def recv(self, timeout: float | None = None) -> can.Message | None:
            if self.frames:
                return can.Message(arbitration_id=0x778, data=self.frames.pop(0), is_extended_id=False)
            return None

        def shutdown(self) -> None:
            pass

    with J533CanLink("fake", bus=BadIsoTpBus([bytes.fromhex("320000AAAAAAAAAA")])) as link:
        link.UDS_TX_ID, link.UDS_RX_ID = 0x70E, 0x778
        with pytest.raises(RuntimeError, match="from 0x778"):
            link.receive_flow_control(timeout=0.05)

    with J533CanLink("fake", bus=BadIsoTpBus([bytes.fromhex("21AABBCCDDEEFF00")])) as link:
        link.UDS_TX_ID, link.UDS_RX_ID = 0x70E, 0x778
        with pytest.raises(RuntimeError, match="on 0x778"):
            link.receive_uds(timeout=0.05)

    with J533CanLink("fake", bus=BadIsoTpBus([bytes.fromhex("100E62F187355130"), bytes.fromhex("037F221100000000")])) as link:
        link.UDS_TX_ID, link.UDS_RX_ID = 0x70E, 0x778
        with pytest.raises(RuntimeError, match="on 0x778"):
            link.receive_uds(timeout=0.05)

    # 3. drain_rx terminates promptly under a busy vehicle bus (wall-clock cap)
    clock = [10.0]

    class BusyVehicleBus:
        def recv(self, timeout: float | None = None) -> can.Message:
            clock[0] += 0.05
            return can.Message(arbitration_id=0x123, data=bytes(8), is_extended_id=False)

        def shutdown(self) -> None:
            pass

    monkeypatch.setattr(transport.time, "monotonic", lambda: clock[0])
    with J533CanLink("fake", bus=BusyVehicleBus()) as link:
        n = link.drain_rx(max_frames=16_384, max_time=0.2)
    assert 1 <= n <= 5  # stopped by time cap instead of draining 16,384 frames
