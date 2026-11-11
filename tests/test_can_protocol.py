"""Tests for J533 CAN ISO-TP framing, 0x6F0 RAM-loader protocol, SA2, and repository hygiene."""

from __future__ import annotations

from functools import reduce
from pathlib import Path
import re
import can

from contitool.can import (
    BEACON_ASCII,
    DFLASH_READER_STUB,
    J533CanLink,
    LOADER_PASSWORD,
    LOADER_SYNC,
    build_dflash_reader_payload,
    build_loader_packet,
    build_reader_payload,
    build_service_loader_uds_steps,
    build_uflash_one_shot_payload,
    enter_ram_loader,
    fbl_sa2,
    read_memory_bytes,
    verify_payload_self_tests,
)


def test_payload_digests_and_sa2_vectors() -> None:
    verify_payload_self_tests()
    assert fbl_sa2(0x12345678) == 0x7CA16271

    pkt = build_loader_packet(b"\xfe\xff")
    assert len(pkt) == 0x120 + 3
    assert len(DFLASH_READER_STUB) == 652
    assert len(build_dflash_reader_payload(0xFF200000, 4096, calls=16, feed=True)) == 668
    assert pkt[0x110:0x118] == LOADER_PASSWORD
    assert pkt[0x118:0x11A] == b"\xfe\xff"
    assert reduce(lambda a, b: a ^ b, pkt[:-1], 0) == pkt[-1]

    rdr = build_reader_payload(0xFF200000, 4096)
    assert len(rdr) == 28


def test_uflash_one_shot_builder(synth_uflash: bytes) -> None:
    payload, pages = build_uflash_one_shot_payload(synth_uflash)
    assert 1 <= pages <= 122
    assert len(payload) == 436 + pages * 256


class _MockGatewayBus:
    """Deterministic in-memory J533 ECU responder simulating UDS 0x710/0x77A + RAM-Loader 0x6F0/0x6F1."""

    def __init__(self) -> None:
        self.rx_queue: list[can.Message] = []
        self.tx_frames: list[tuple[int, bytes]] = []
        self._in_loader = False
        self._loader_expected = 0
        self._loader_buf = bytearray()
        self._uds_multi_expected = 0
        self._uds_multi_buf = bytearray()

    def recv(self, timeout: float = 0.0):
        if not self.rx_queue:
            return None
        return self.rx_queue.pop(0)

    def _reply(self, arb_id: int, data: bytes) -> None:
        self.rx_queue.append(can.Message(arbitration_id=arb_id, data=data, is_extended_id=False))

    def send(self, message: can.Message, timeout: float = 1.0) -> None:
        arb = message.arbitration_id
        raw = bytes(message.data)
        self.tx_frames.append((arb, raw))

        if arb == 0x710:
            pci = raw[0] >> 4
            if pci == 0:
                req = raw[1 : 1 + (raw[0] & 0x0F)]
                self._handle_uds(req)
            elif pci == 1:
                self._uds_multi_expected = ((raw[0] & 0x0F) << 8) | raw[1]
                self._uds_multi_buf = bytearray(raw[2:])
                self._reply(0x77A, b"\x30\x00\x00\xaa\xaa\xaa\xaa\xaa")
            elif pci == 2:
                self._uds_multi_buf.extend(raw[1:])
                if len(self._uds_multi_buf) >= self._uds_multi_expected:
                    req = bytes(self._uds_multi_buf[: self._uds_multi_expected])
                    self._handle_uds(req)
        elif arb == 0x6F0:
            if raw == LOADER_SYNC:
                self._loader_buf.clear()
                self._loader_expected = 0
                self._reply(0x6F1, LOADER_SYNC)
                return
            if not self._loader_buf:
                sz = raw[0] | ((raw[1] & 0x7F) << 8)
                self._loader_expected = sz + 3
            self._loader_buf.extend(raw)
            if len(self._loader_buf) >= self._loader_expected:
                pkt = bytes(self._loader_buf[: self._loader_expected])
                code = pkt[0x118:-1]
                if BEACON_ASCII in code:
                    self._reply(0x6F1, BEACON_ASCII[:8])
                    self._reply(0x6F1, BEACON_ASCII[8:] + b"\x00" * 5)
                    self._reply(0x6F1, b"\x00\x00")
                elif code.startswith(b"\x26\x06"):
                    ln = int.from_bytes(code[8:12], "little")
                    blob = bytes((i & 0xFF) for i in range(ln))
                    for off in range(0, ln, 8):
                        chunk = blob[off : off + 8].ljust(8, b"\x00")
                        self._reply(0x6F1, chunk)
                    self._reply(0x6F1, b"\x00\x00")

    def _handle_uds(self, req: bytes) -> None:
        stage1, stage2, trigger = build_service_loader_uds_steps()
        if req == b"\x10\x03":
            self._reply(0x77A, b"\x06\x50\x03\x00\x32\x01\xf4\xaa")
        elif req == b"\x27\x03":
            self._reply(0x77A, b"\x06\x67\x03\x11\x22\x33\x44\xaa")
        elif req.startswith(b"\x27\x04"):
            self._reply(0x77A, b"\x02\x67\x04\xaa\xaa\xaa\xaa\xaa")
        elif req == bytes.fromhex("31010203"):
            self._reply(0x77A, b"\x05\x71\x01\x02\x03\x00\xaa\xaa")
        elif req == b"\x10\x02":
            # Emit ResponsePending (7F 10 78) first to verify pending handling!
            self._reply(0x77A, b"\x03\x7f\x10\x78\xaa\xaa\xaa\xaa")
            self._reply(0x77A, b"\x06\x50\x02\x00\x32\x01\xf4\xaa")
        elif req == b"\x27\x11":
            self._reply(0x77A, b"\x06\x67\x11\xde\xad\xbe\xef\xaa")
        elif req.startswith(b"\x2e\x04\x10"):
            self._reply(0x77A, b"\x03\x6e\x04\x10\xaa\xaa\xaa\xaa")
        elif req == stage1:
            resp = b"\x62" + (b"\x00" * 334) + bytes.fromhex("041005")
            assert len(resp) == 338
            self._reply(0x77A, bytes([0x10 | (len(resp) >> 8), len(resp) & 0xFF]) + resp[:6])
            seq = 1
            for off in range(6, len(resp), 7):
                self._reply(0x77A, bytes([0x20 | seq]) + resp[off : off + 7].ljust(7, b"\xaa"))
                seq = (seq + 1) & 0x0F
        elif req == stage2:
            pass  # Suppressed negative response
        elif req == trigger:
            self._in_loader = True
        elif req[:1] == b"\x22":
            # A real gateway answers an identifier it does not keep, so a length measurement never sits on a
            # timeout. Only the staged multi-DID reads above are special.
            self._reply(0x77A, b"\x03\x7f\x22\x31\xaa\xaa\xaa\xaa")


def test_can_link_service_loader_entry_and_native_reader() -> None:
    bus = _MockGatewayBus()
    with J533CanLink("mock", bus=bus) as link:
        info = enter_ram_loader(link)
        assert info["loader_ready"] is True
        # what landed on 0xFEDE0C62..69 goes into the result, as the ECU sent it
        assert info["stage1_overrun"] == "00 00 00 00 00 04 10 05"
        assert info["beacon"] == BEACON_ASCII.decode("ascii")
        sample = read_memory_bytes(link, 0x01000000, 32)
        assert sample == bytes(range(32))


# F15B as a gateway answers it after a 2.0.1d write: the factory record, then date + serial 01..06 + status.
F15B_AFTER_201D = bytes.fromhex("00010100000000000000" "26110901020304050600")


class _SilentStage1(_MockGatewayBus):
    """Stage 1 unanswered, as on a gateway whose last F15B record puts a non-zero byte on the suppress flag."""

    loader = True

    def _handle_uds(self, req: bytes) -> None:
        stage1, _, trigger = build_service_loader_uds_steps()
        if req == stage1 or (req == trigger and not self.loader):
            return
        if req == b"\x22\xf1\x5b":
            resp = b"\x62\xf1\x5b" + F15B_AFTER_201D
            self._reply(0x77A, bytes([0x10, len(resp)]) + resp[:6])
            for seq, off in enumerate(range(6, len(resp), 7), start=1):
                self._reply(0x77A, bytes([0x20 | seq]) + resp[off : off + 7].ljust(7, b"\xaa"))
            return
        super()._handle_uds(req)

    def send(self, message: can.Message, timeout: float = 1.0) -> None:
        if message.arbitration_id == 0x6F0 and not self._in_loader:
            return  # no loader runs: nobody answers on 0x6F1
        super().send(message, timeout)


def test_a_silent_stage1_with_no_loader_after_it_is_named_not_a_bare_timeout() -> None:
    """Issue #1: UDS works but the entry fails after a silent stage 1 — say which step, and carry F15B."""
    import pytest

    from contitool.i18n import set_lang

    set_lang("en")
    bus = _SilentStage1()
    bus.loader = False
    with J533CanLink("mock", bus=bus) as link, pytest.raises(TimeoutError) as err:
        enter_ram_loader(link)
    assert "did not answer stage 1" in str(err.value) and F15B_AFTER_201D.hex(" ") in str(err.value)


def test_every_staged_did_answers_a_length_fixed_in_the_firmware() -> None:
    """The bootloader builds each of these answers with a constant length — its F15B handler copies two 10-byte
    NvM records in a loop that always runs twice — so the staged answer measures the same on every gateway."""
    from contitool.can.payloads import KNOWN_DID_LENGTHS, STAGE1_TOTAL, UNKNOWN_DIDS

    req = build_service_loader_uds_steps()[0]
    dids = [int.from_bytes(req[i : i + 2], "big") for i in range(1, len(req), 2)]
    total = 1 + sum(2 + KNOWN_DID_LENGTHS[d] for d in dids if d not in UNKNOWN_DIDS)
    assert total == STAGE1_TOTAL and dids[-1] == 0x0410


def test_response_pending_waits_p2_star(monkeypatch) -> None:
    """The FBL repeats `7F 31 78` every ~2.5 s during an erase: the link must keep waiting (P2* is 5 s)."""
    from contitool.can import transport

    clock = [0.0]

    class SlowEraseBus:
        def __init__(self) -> None:
            self.schedule: list[tuple[float, can.Message]] = []

        def send(self, message: can.Message, timeout: float = 1.0) -> None:
            t = clock[0]
            for at in (0.025, 2.53, 5.035, 7.54):
                self.schedule.append((t + at, can.Message(arbitration_id=0x77A, data=bytes.fromhex("037f3178aaaaaaaa"))))
            self.schedule.append((t + 9.0, can.Message(arbitration_id=0x77A, data=bytes.fromhex("057101ff0000aaaa"))))

        def recv(self, timeout: float = 0.0):
            if self.schedule and self.schedule[0][0] <= clock[0] + timeout:
                at, msg = self.schedule.pop(0)
                clock[0] = max(clock[0], at)
                return msg
            clock[0] += timeout
            return None

    monkeypatch.setattr(transport.time, "monotonic", lambda: clock[0])
    link = J533CanLink("x", bus=SlowEraseBus())
    assert link.request_uds(bytes.fromhex("3101ff000101"), 0x71, timeout=120.0) == bytes.fromhex("7101ff0000")


def test_a_stream_that_stops_midway_names_the_lost_bytes_and_a_slow_slcan(monkeypatch, tmp_path) -> None:
    """A serial SLCAN clone drops frames of the full-speed memory stream: say so instead of a bare timeout."""
    import pytest

    from contitool.can import workflows
    from contitool.i18n import set_lang

    set_lang("en")
    monkeypatch.setattr(workflows.time, "sleep", lambda _s: None)

    class LossyLink:
        interface, LOADER_RX_ID = "slcan", 0x6F1

        def send_loader_payload(self, payload, **_k):
            self.left = 300  # of the 8192 frames a 64 KB payload streams

        def receive_frame(self, _ident, timeout):
            if self.left:
                self.left -= 1
                return can.Message(arbitration_id=0x6F1, data=bytes(8))
            raise TimeoutError(f"No CAN frame from 0x6F1 within {timeout:.1f}s")

        def drain_rx(self, max_frames=0):
            pass

    errors: list[str] = []

    class Rep:
        def error(self, msg):
            errors.append(msg)

        def __getattr__(self, _name):
            return lambda *a, **k: None

    with pytest.raises(TimeoutError, match="stopped after 2400/65536 bytes"):
        workflows.read_memory_area(LossyLink(), 0, 0x10000, tmp_path / "Cflash.bin", reporter=Rep())
    assert len(errors) == 1 and "loses frames" in errors[0]


def test_a_dpdu_adapter_without_raw_can_is_named_when_the_stream_breaks(tmp_path: Path, monkeypatch) -> None:
    """Issue #17: a VCX that refused RawMode passes on about one frame in five of the memory stream. Say that this
    adapter cannot read memory instead of a bare timeout."""
    import types

    import pytest

    from contitool.can import workflows
    from contitool.i18n import set_lang

    set_lang("en")
    monkeypatch.setattr(workflows.time, "sleep", lambda _s: None)

    class FifthFrameLink:
        interface, LOADER_RX_ID = "dpdu", 0x6F1
        bus = types.SimpleNamespace(nonraw={0x710: 1, 0x6F0: 2})

        def send_loader_payload(self, payload, **_k):
            self.left = 8192 // 5

        def receive_frame(self, _ident, timeout):
            if self.left:
                self.left -= 1
                return can.Message(arbitration_id=0x6F1, data=bytes(8))
            raise TimeoutError("no frame")

        def drain_rx(self, max_frames=0):
            pass

    errors: list[str] = []

    class Rep:
        def error(self, msg):
            errors.append(msg)

        def __getattr__(self, _name):
            return lambda *a, **k: None

    with pytest.raises(TimeoutError, match="stopped after 13104/65536"):
        workflows.read_memory_area(FifthFrameLink(), 0, 0x10000, tmp_path / "Cflash.bin", reporter=Rep())
    assert len(errors) == 1 and "refused raw CAN" in errors[0]


def test_gateway_stuck_in_fbl_after_interrupted_flash_recovers_cleanly(monkeypatch) -> None:
    """After EraseMemory + mid-flash disconnect, the ECU boots into FBL where `10 03` returns `7F 10 7E`.
    Link check, RAM-loader entry, and pre-flash resets must succeed, while strict post-flash check still fails."""
    from contitool.i18n import set_lang

    set_lang("en")  # the messages below are matched in English
    import pytest

    from contitool.can import can_identify, workflows

    monkeypatch.setattr(workflows.time, "sleep", lambda _s: None)

    class FblOnlyGateway(_MockGatewayBus):
        def _handle_uds(self, req: bytes) -> None:
            if req == b"\x10\x03":
                self._reply(0x77A, b"\x03\x7f\x10\x7e\xaa\xaa\xaa\xaa")
                return
            if req in (b"\x27\x03", bytes.fromhex("31010203")) or req.startswith(b"\x27\x04"):
                raise AssertionError(f"Application-only service {req.hex()} must not be sent in FBL")
            if req == b"\x3e\x00":
                self._reply(0x77A, b"\x02\x7e\x00\xaa\xaa\xaa\xaa\xaa")
                return
            if req == b"\x22\xf1\x87":
                resp = b"\x62\xf1\x873Q0907530AR"
                self._reply(0x77A, bytes([0x10, len(resp)]) + resp[:6])
                self._reply(0x77A, b"\x21" + resp[6:13])
                self._reply(0x77A, b"\x22" + resp[13:].ljust(7, b"\xaa"))
                return
            if req == b"\x11\x01":
                self._in_loader = False
                self._reply(0x77A, b"\x02\x51\x01\xaa\xaa\xaa\xaa\xaa")
                return
            super()._handle_uds(req)

        def send(self, message: can.Message, timeout: float = 1.0) -> None:
            if message.arbitration_id == 0x6F0 and not self._in_loader:
                return
            super().send(message, timeout)

    ident = can_identify("mock", bus=FblOnlyGateway())
    assert ident["responding"] is True and ident.get("in_fbl") is True
    assert {i["did"]: i["value"] for i in ident["ident"]}["F187"] == "3Q0907530AR"

    bus = FblOnlyGateway()
    with J533CanLink("mock", bus=bus) as link:
        info = enter_ram_loader(link)
        assert info["loader_ready"] is True
        assert info["stage1_length"] == 338 and info.get("already_in_fbl") is True
        rst = workflows._reset_to_application(link, allow_fbl=True)
        assert rst.get("in_fbl") is True and rst["fbl_session"].startswith("5002")
        # Strict post-flash check (allow_fbl=False) MUST still reject an ECU whose Application failed to boot
        with pytest.raises(RuntimeError, match="Application did not come up"):
            workflows._reset_to_application(link, allow_fbl=False)

        # A write that started from a healthy gateway must not accept FBL as its landing: that is the ECU
        # telling us what we just wrote did not come up, and calling it success hides a dead unit.
        with pytest.raises(RuntimeError, match="Application did not come up"):
            workflows._return_to_application(link, {"session_1003": "5003"})
        # One that was already stuck in FBL before the write cannot be expected to leave it.
        rst = workflows._return_to_application(link, {"already_in_fbl": True})
        assert rst.get("in_fbl") is True
        # Started from a loader an earlier run entered: the start state is unknown, so FBL is not held against it.
        assert workflows._return_to_application(link, None).get("in_fbl") is True


def test_gateway_cold_booted_into_fbl_default_session_after_power_cycle_recovers_cleanly(monkeypatch) -> None:
    """After a power cycle / MCU reset with erased Application (`*(u32*)0xC000 != 0x90482442`), RH850 FBL
    starts in Default Session (`0`): `10 02` directly -> `7F 10 7E`, `10 03` -> `50 03` (Extended `2`),
    `27 03` in Extended -> `7F 27 7F`, `10 02` from Extended -> `50 02` (Programming `1`), `22 F1 DF` -> `0x44`."""
    from contitool.i18n import set_lang

    set_lang("en")  # the messages below are matched in English
    import pytest

    from contitool.can import can_identify, workflows

    monkeypatch.setattr(workflows.time, "sleep", lambda _s: None)

    class ColdBootFblGateway(_MockGatewayBus):
        def __init__(self) -> None:
            super().__init__()
            self.fbl_session = 0  # 0 = Default, 1 = Programming, 2 = Extended (FUN_ram_01003716)

        def _handle_uds(self, req: bytes) -> None:
            if req == b"\x10\x03":
                if self.fbl_session == 1:
                    self._reply(0x77A, b"\x03\x7f\x10\x7e\xaa\xaa\xaa\xaa")
                else:
                    self.fbl_session = 2
                    self._reply(0x77A, b"\x06\x50\x03\x00\x32\x01\xf4\xaa")
                return
            if req == b"\x10\x02":
                if self.fbl_session == 0:
                    self._reply(0x77A, b"\x03\x7f\x10\x7e\xaa\xaa\xaa\xaa")
                else:
                    self.fbl_session = 1
                    self._reply(0x77A, b"\x03\x7f\x10\x78\xaa\xaa\xaa\xaa")
                    self._reply(0x77A, b"\x06\x50\x02\x00\x32\x01\xf4\xaa")
                return
            if req == b"\x27\x03":
                self._reply(0x77A, b"\x03\x7f\x27\x7f\xaa\xaa\xaa\xaa")
                return
            if req.startswith(b"\x27\x04") or req == bytes.fromhex("31010203"):
                raise AssertionError(f"Application precondition {req.hex()} must not follow 7F 27 7F")
            if req == b"\x22\xf1\xdf":
                self._reply(0x77A, b"\x04\x62\xf1\xdf\x44\xaa\xaa\xaa")
                return
            if req == b"\x22\xf1\x87":
                resp = b"\x62\xf1\x873Q0907530AR"
                self._reply(0x77A, bytes([0x10, len(resp)]) + resp[:6])
                self._reply(0x77A, b"\x21" + resp[6:13])
                self._reply(0x77A, b"\x22" + resp[13:].ljust(7, b"\xaa"))
                return
            if req == b"\x11\x01":
                self._in_loader = False
                self.fbl_session = 0
                self._reply(0x77A, b"\x02\x51\x01\xaa\xaa\xaa\xaa\xaa")
                return
            if req == b"\x3e\x00":
                self._reply(0x77A, b"\x02\x7e\x00\xaa\xaa\xaa\xaa\xaa")
                return
            super()._handle_uds(req)

        def send(self, message: can.Message, timeout: float = 1.0) -> None:
            if message.arbitration_id == 0x6F0 and not self._in_loader:
                return
            super().send(message, timeout)

    ident = can_identify("mock", bus=ColdBootFblGateway())
    assert ident["responding"] is True and ident.get("in_fbl") is True
    assert ident.get("app_valid") is False and ident.get("f1df") == "44"
    assert {i["did"]: i["value"] for i in ident["ident"]}["F187"] == "3Q0907530AR"

    bus = ColdBootFblGateway()
    with J533CanLink("mock", bus=bus) as link:
        info = enter_ram_loader(link)
        assert info["loader_ready"] is True and info.get("already_in_fbl") is True
        rst = workflows._reset_to_application(link, allow_fbl=True)
        assert rst.get("in_fbl") is True and rst["fbl_session"].startswith("5003")
        bus.fbl_session = 0
        workflows._enter_fbl_uds_programming(link, workflows.NULL_REPORTER)
        assert bus.fbl_session == 1
        with pytest.raises(RuntimeError, match="F197/0600 did not"):
            workflows._reset_to_application(link, allow_fbl=False)


def test_loader_payload_deadline_pacing_skips_sleep_when_send_already_took_longer(monkeypatch) -> None:
    from contitool.can import transport

    clock = [0.0]
    sleeps: list[float] = []

    class SlowSyncAdapter(_MockGatewayBus):
        def send(self, message: can.Message, timeout: float = 1.0) -> None:
            super().send(message, timeout)
            if message.arbitration_id == 0x6F0 and bytes(message.data) != LOADER_SYNC:
                clock[0] += 0.005  # VNCI RawMode takes ~5 ms synchronously per frame

    monkeypatch.setattr(transport.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(transport.time, "sleep", lambda dt: sleeps.append(dt))
    with J533CanLink("mock", bus=SlowSyncAdapter()) as link:
        link.send_loader_payload(b"\xfe\xff", inter_frame_delay=0.003)
    assert sleeps == []  # 5 ms per send already exceeds 3 ms spacing; zero extra sleep wasted


def test_a_drain_on_an_idle_slcan_port_does_not_wait_out_the_serial_timeout() -> None:
    import queue
    import types

    class SlcanLike:
        """python-can's slcan: recv(timeout=0) with no byte waiting still blocks for the port timeout (0.1 s)."""

        def __init__(self, waiting: int) -> None:
            self.serialPortOrig = types.SimpleNamespace(in_waiting=waiting)
            self._queue: queue.Queue = queue.Queue()
            self.recvs = 0

        def recv(self, timeout: float = 0.0) -> can.Message | None:
            self.recvs += 1
            if not self.serialPortOrig.in_waiting:
                return None
            self.serialPortOrig.in_waiting = 0
            return can.Message(arbitration_id=0x77A, data=b"\x02\x7e\x00", is_extended_id=False)

        def shutdown(self) -> None:
            pass

    idle, stale = SlcanLike(0), SlcanLike(22)
    J533CanLink("mock", bus=idle).drain_rx(quick=True)
    assert idle.recvs == 0  # nothing waiting: no 0.1 s read per UDS request
    J533CanLink("mock", bus=idle).drain_rx()
    assert idle.recvs == 1  # the RAM-loader packets keep the read their slcan pacing was verified with
    link = J533CanLink("mock", bus=stale)
    link.drain_rx(quick=True)
    assert (stale.recvs, link.rx_frames) == (1, 1)  # a late frame is still thrown away


def test_after_a_write_only_f197_proves_the_application_runs() -> None:
    """10 03 -> 50 03 is answered by a cold FBL too, and F1DF bit 2 comes from a check outside the dump: a FBL
    that clears it must still not pass for a running application once something has been written."""
    from contitool.i18n import set_lang

    set_lang("en")  # the messages below are matched in English
    import pytest

    from contitool.can import workflows

    class ColdFblLink:
        def request_uds(self, req: bytes, expected: int, timeout: float, allow_pending: bool = False) -> bytes:
            if req == b"\x10\x03":
                return b"\x50\x03\x00\x32\x01\xf4"
            if req == b"\x22\xf1\xdf":
                return b"\x62\xf1\xdf\x40"  # bit 2 clear
            raise TimeoutError("no answer")  # F197: the bootloader does not know it

    with pytest.raises(RuntimeError, match="F197/0600 did not"):
        workflows._probe_app_or_fbl(ColdFblLink(), attempts=2, allow_fbl=False)
    # where FBL is an acceptable landing, the clear bit still reads as "application" — the cheaper mistake there
    assert workflows._probe_app_or_fbl(ColdFblLink(), attempts=1, allow_fbl=True)[1] is False


def test_a_request_the_adapter_iso_tp_drops_goes_again_on_the_software_path() -> None:
    """Mid-flash the application may already be erased: a transport failure on the adapter's ISO-TP must not end
    the operation. The same request goes again on the verified software path, and the user is told."""
    import contextlib

    import pytest

    from contitool.can import J533CanLink
    from test_identify import FakeGateway

    class HwThenSoftware(FakeGateway):
        hw_calls = ended = 0

        @contextlib.contextmanager
        def uds_session(self, tx_id: int, rx_id: int):
            yield True

        def request_uds(self, req: bytes, *, timeout: float, allow_pending: bool) -> bytes:
            self.hw_calls += 1
            raise can.CanOperationError("D-PDU: the frame never went out")

        def end_uds_session(self) -> None:
            self.ended += 1

    bus = HwThenSoftware()
    told: list[str] = []
    with J533CanLink("mock", bus=bus) as link, link.uds_session() as hw:
        assert hw is True
        link.on_hw_fallback = told.append
        assert link.request_uds(b"\x10\x03", 0x50).startswith(b"\x50\x03")  # answered on the software path
        assert bus.hw_calls == 1 and bus.ended == 1 and told and told[0].startswith("10 03")
        assert link.request_uds(b"\x10\x03", 0x50).startswith(b"\x50\x03")  # and it stays there
        assert bus.hw_calls == 1

    # A reset is expected to go unanswered: a hardware failure on it is not a reason to send it twice.
    bus = HwThenSoftware()
    with J533CanLink("mock", bus=bus) as link, link.uds_session():
        with pytest.raises(can.CanOperationError):
            link.request_uds(b"\x11\x01", 0x51, resend=False)
        assert bus.ended == 0


def test_a_refused_precondition_does_not_stop_the_fbl_entry_the_10_02_answer_decides(monkeypatch) -> None:
    """2.0.1c behaviour, verified on hardware: 27 03 answering 7F 27 37 (delay) used to fall through to 10 02."""
    from contitool.can import workflows
    from contitool.can.transport import UdsNegativeResponse
    from contitool.progress import NULL_REPORTER

    sent: list[bytes] = []

    class DelayedLink:
        def request_uds(self, req: bytes, expected: int, timeout: float, allow_pending: bool = False) -> bytes:
            sent.append(req)
            if req == b"\x10\x03":
                return b"\x50\x03\x00\x32\x01\xf4"
            if req == b"\x27\x03":
                raise UdsNegativeResponse(0x27, 0x37, b"\x7f\x27\x37")
            if req == b"\x10\x02":
                return b"\x50\x02\x00\x32\x01\xf4"
            raise AssertionError(req.hex())

    monkeypatch.setattr(workflows.time, "sleep", lambda _s: None)
    workflows._enter_fbl_uds_programming(DelayedLink(), NULL_REPORTER)
    assert sent[-1] == b"\x10\x02"


def test_a_silent_stage1_never_spends_a_securityaccess_attempt_on_the_trigger() -> None:
    """The trigger is a `27 12` with a deliberately wrong key: it only works because the staged overrun diverts
    the bootloader before the key is checked, and the attempt is recorded first. After three the bootloader locks
    SecurityAccess behind its timer (NRC 0x37, handler 0x01002F08, NvM-backed counter at 0xFEDE0AEE), which an
    `11 01` reset does not clear. 2.0.1e sent the trigger even when stage 1 stayed silent — i.e. when there is no
    evidence the overrun landed — and locked a user's gateway out. So: no answer to stage 1, no trigger."""
    import pytest

    from contitool.i18n import set_lang

    set_lang("en")
    _, _, trigger = build_service_loader_uds_steps()

    class CountingSilentStage1(_SilentStage1):
        def __init__(self) -> None:
            super().__init__()
            self.loader = False
            self.triggers = 0

        def _handle_uds(self, req: bytes) -> None:
            if req == trigger:
                self.triggers += 1
            super()._handle_uds(req)

    bus = CountingSilentStage1()
    with J533CanLink("mock", bus=bus) as link, pytest.raises(TimeoutError) as err:
        enter_ram_loader(link)
    assert "did not answer stage 1" in str(err.value)
    assert bus.triggers == 0, "a silent stage 1 must not spend a key attempt on the trigger"


def test_cancel_waits_for_a_write_and_a_cancelled_read_hands_the_gateway_back(monkeypatch, tmp_path) -> None:
    """A cancel during a flash write takes effect once the write is done; after a cancelled read the gateway is
    reset to its application instead of being left in the RAM-loader."""
    import contextlib

    import pytest

    from contitool.can import workflows
    from contitool.progress import OperationCancelledError, OperationReporter

    rep = OperationReporter()
    done: list[str] = []
    with pytest.raises(OperationCancelledError), rep.uninterruptible():
        rep.cancel()
        rep.progress(1, 2)  # a checkpoint inside the write: must not stop it
        done.append("write finished")
    assert done == ["write finished"]

    resets: list[str] = []

    def cancelled_read(*_a, **_k):
        raise OperationCancelledError("cancelled")

    monkeypatch.setattr(workflows, "J533CanLink", lambda *a, **k: contextlib.nullcontext())
    monkeypatch.setattr(workflows, "enter_ram_loader", lambda *a, **k: {})
    monkeypatch.setattr(workflows, "read_memory_area", cancelled_read)
    monkeypatch.setattr(workflows, "_reset_to_application", lambda *a, **k: resets.append("reset") or {})
    with pytest.raises(OperationCancelledError):
        workflows.can_backup("fake", session_dir=tmp_path, areas=("dflash",))
    assert resets == ["reset"]


def test_a_switched_off_ecu_does_not_take_the_adapter_off_its_hardware_isotp(monkeypatch) -> None:
    """Issue #18: while waiting for the power cycle (NRC 0x37) every request goes unanswered. Those requests must
    not move the link to the frame-by-frame path (resend=False), or the VNCI gives up halfway through the write."""
    import can

    from contitool.can import workflows
    from contitool.can.transport import UdsNegativeResponse

    monkeypatch.setattr(workflows.time, "sleep", lambda _s: None)
    calls: list[tuple[str, bool]] = []
    state = {"phase": "locked", "off_polls": 0}

    class Link:
        def request_uds(self, req, sid=None, *, timeout=2.0, allow_pending=True, resend=True):
            calls.append((bytes(req[:2]).hex(), resend))
            if req[:2] == b"\x27\x11":
                if state["phase"] == "locked":
                    raise UdsNegativeResponse(0x27, 0x37, b"\x7f\x27\x37")
                if state["phase"] == "off":
                    raise can.CanOperationError("D-PDU UDS protocol error (0x105)")
                return b"\x67\x11\x00\x00\x12\x34"
            if req[:1] == b"\x11":
                return b"\x51\x01"
            if state["phase"] == "off":
                state["off_polls"] += 1
                if state["off_polls"] > 3:
                    state["phase"] = "on"
                raise can.CanOperationError("D-PDU UDS protocol error (0x105)")
            return b"\x50\x02" if req[:1] == b"\x10" else b"\x67\x04" if req[:1] == b"\x27" else b"\x71\x01\x02\x03"

    class Rep(workflows.NULL_REPORTER.__class__):
        def warning(self, msg):
            state["phase"] = "off"  # the user switches the ECU off when asked
            state["prompt_at"] = len(calls)

    seed = workflows._fbl_seed(Link(), Rep())
    assert seed == b"\x67\x11\x00\x00\x12\x34"
    after_prompt = calls[state["prompt_at"] :]
    assert state["off_polls"] > 3 and after_prompt and all(not resend for _req, resend in after_prompt)
