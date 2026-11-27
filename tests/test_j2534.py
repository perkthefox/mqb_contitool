"""J2534 PassThru bus: PASSTHRU_MSG encoding, echo skipping, pass filters, and a UDS identification through it."""

from __future__ import annotations

import ctypes

import can
import pytest

from contitool.can import can_identify
from contitool.can.j2534 import CAN_29BIT_ID, CAN_ID_BOTH, TX_INDICATION, J2534Bus, PassThruMsg, dll_bits
from contitool.i18n import set_lang
from test_identify import FakeGateway


class FakePassThru:
    """The DLL side of J2534 in Python: frames go to / come from a FakeGateway; byref() args are unwrapped via _obj."""

    def __init__(self, gw: FakeGateway, id_both: bool = True) -> None:
        self.gw, self.id_both = gw, id_both
        self.filters: list[int] = []
        self.rx: list[PassThruMsg] = [PassThruMsg(5, TX_INDICATION, 0, 0, 4)]  # must be skipped
        self.closed = False

    def PassThruOpen(self, _name, dev) -> int:  # noqa: N802 (J2534 names)
        dev._obj.value = 1
        return 0

    def PassThruConnect(self, _dev, proto, flags, baud, chan) -> int:  # noqa: N802
        assert proto == 5 and baud == 500_000
        if flags & CAN_ID_BOTH and not self.id_both:
            return 0x06  # ERR_INVALID_FLAGS
        chan._obj.value = 7
        return 0

    def PassThruStartMsgFilter(self, chan, ftype, mask, pattern, flow, fid) -> int:  # noqa: N802
        assert chan == 7 and ftype == 1 and flow is None and mask._obj.DataSize == 4
        self.filters.append(pattern._obj.TxFlags)
        return 0

    def PassThruWriteMsgs(self, chan, msg, n, _timeout) -> int:  # noqa: N802
        m = msg._obj
        raw = bytes(m.Data[: m.DataSize])
        self.gw.send(can.Message(arbitration_id=int.from_bytes(raw[:4], "big"), data=raw[4:],
                                 is_extended_id=bool(m.TxFlags & CAN_29BIT_ID)))
        return 0

    def PassThruReadMsgs(self, chan, buf, n, _timeout) -> int:  # noqa: N802
        while (m := self.gw.recv()) is not None:
            out = PassThruMsg(5, 0, 0, 0, 4 + len(m.data))
            out.Data[: out.DataSize] = list(m.arbitration_id.to_bytes(4, "big") + bytes(m.data))
            self.rx.append(out)
        count = min(n._obj.value, len(self.rx))
        for i in range(count):
            ctypes.memmove(ctypes.byref(buf._obj[i]), ctypes.byref(self.rx.pop(0)), ctypes.sizeof(PassThruMsg))
        n._obj.value = count
        return 0 if count else 0x10  # ERR_BUFFER_EMPTY

    def PassThruGetLastError(self, _text) -> int:  # noqa: N802
        return 0

    def PassThruDisconnect(self, _chan) -> int:  # noqa: N802
        return 0

    def PassThruClose(self, _dev) -> int:  # noqa: N802
        self.closed = True
        return 0


def test_identification_runs_over_a_j2534_device() -> None:
    set_lang("en")
    dll = FakePassThru(FakeGateway())
    bus = J2534Bus("fake.dll", dll=dll)
    assert dll.filters == [0, CAN_29BIT_ID]  # 11- and 29-bit pass-all filters
    res = can_identify("fake.dll", bus=bus)
    assert {i["did"]: i["value"] for i in res["ident"]}["F187"] == "3Q0907530AA"
    bus.shutdown()
    bus.shutdown()  # second call is a no-op
    assert dll.closed


def test_device_without_mixed_ids_connects_11_bit_and_29_bit_frames_keep_their_flag() -> None:
    dll = FakePassThru(FakeGateway(), id_both=False)
    bus = J2534Bus("fake.dll", dll=dll)
    frame = PassThruMsg(5, CAN_29BIT_ID, 0, 0, 12)
    frame.Data[:12] = list(bytes.fromhex("17F00010 2010000000000080"))
    dll.rx.append(frame)
    msg = bus.recv(0)
    assert msg.is_extended_id and msg.arbitration_id == 0x17F00010 and msg.data == bytes.fromhex("2010000000000080")
    assert bus.recv(0) is None
    bus.shutdown()


def test_failed_open_reports_the_driver_error() -> None:
    dll = FakePassThru(FakeGateway())
    dll.PassThruOpen = lambda *_a: 0x08  # ERR_DEVICE_NOT_CONNECTED
    with pytest.raises(can.CanOperationError, match="PassThruOpen: J2534 error 0x08"):
        J2534Bus("fake.dll", dll=dll)


def test_dll_bitness_comes_from_the_pe_header(tmp_path) -> None:
    def pe(machine: int) -> bytes:
        head = bytearray(0x100)
        head[:2], head[0x3C:0x40] = b"MZ", (0x80).to_bytes(4, "little")
        head[0x80:0x86] = b"PE\0\0" + machine.to_bytes(2, "little")
        return bytes(head)

    (tmp_path / "x86.dll").write_bytes(pe(0x014C))
    (tmp_path / "x64.dll").write_bytes(pe(0x8664))
    (tmp_path / "junk.dll").write_bytes(b"not a dll")
    assert dll_bits(str(tmp_path / "x86.dll")) == 32
    assert dll_bits(str(tmp_path / "x64.dll")) == 64
    assert dll_bits(str(tmp_path / "junk.dll")) is None
    assert dll_bits(str(tmp_path / "missing.dll")) is None


def test_j2534_hardware_iso15765_session_handles_514b_blocks_start_of_message_and_78_pending() -> None:
    from contitool.can import J533CanLink
    from contitool.can.j2534 import FLOW_CONTROL_FILTER, ISO15765_FRAME_PAD, PROTOCOL_ISO15765, START_OF_MESSAGE

    class IsoTpPassThru(FakePassThru):
        def __init__(self) -> None:
            super().__init__(FakeGateway())
            self.iso_rx: list[PassThruMsg] = []
            self.iso_writes: list[bytes] = []

        def PassThruConnect(self, _dev, proto, flags, baud, chan) -> int:  # noqa: N802
            if proto == PROTOCOL_ISO15765:
                assert baud == 500_000 and flags == 0
                chan._obj.value = 9
                return 0
            return super().PassThruConnect(_dev, proto, flags, baud, chan)

        def PassThruStartMsgFilter(self, chan, ftype, mask, pattern, flow, fid) -> int:  # noqa: N802
            if chan == 9:
                assert ftype == FLOW_CONTROL_FILTER
                assert bytes(pattern._obj.Data[:4]) == (0x77A).to_bytes(4, "big")
                assert bytes(flow._obj.Data[:4]) == (0x710).to_bytes(4, "big")
                return 0
            return super().PassThruStartMsgFilter(chan, ftype, mask, pattern, flow, fid)

        def PassThruWriteMsgs(self, chan, msg, n, _timeout) -> int:  # noqa: N802
            if chan == 9:
                m = msg._obj
                assert m.ProtocolID == PROTOCOL_ISO15765 and (m.TxFlags & ISO15765_FRAME_PAD)
                raw = bytes(m.Data[: m.DataSize])
                assert int.from_bytes(raw[:4], "big") == 0x710
                req = raw[4:]
                self.iso_writes.append(req)
                # Real J2534 drivers emit START_OF_MESSAGE (4-byte ID only) before the reassembled response
                som = PassThruMsg(PROTOCOL_ISO15765, START_OF_MESSAGE, 0, 0, 4)
                som.Data[:4] = list((0x77A).to_bytes(4, "big"))
                self.iso_rx.append(som)
                if req == b"\x3e\x00":
                    self._push_iso(b"\x7e\x00")
                elif req[0] == 0x36:
                    self._push_iso(b"\x7f\x36\x78")
                    self._push_iso(bytes([0x76, req[1]]))
                return 0
            return super().PassThruWriteMsgs(chan, msg, n, _timeout)

        def _push_iso(self, uds: bytes) -> None:
            raw = (0x77A).to_bytes(4, "big") + uds
            out = PassThruMsg(PROTOCOL_ISO15765, 0, 0, 0, len(raw))
            out.Data[: len(raw)] = list(raw)
            self.iso_rx.append(out)

        def PassThruReadMsgs(self, chan, buf, n, _timeout) -> int:  # noqa: N802
            if chan == 9:
                count = min(n._obj.value, len(self.iso_rx))
                for i in range(count):
                    ctypes.memmove(ctypes.byref(buf._obj[i]), ctypes.byref(self.iso_rx.pop(0)), ctypes.sizeof(PassThruMsg))
                n._obj.value = count
                return 0 if count else 0x10
            return super().PassThruReadMsgs(chan, buf, n, _timeout)

    dll = IsoTpPassThru()
    bus = J2534Bus("fake.dll", dll=dll)
    block = bytes([0x36, 0x01]) + bytes(range(256)) * 2  # 514-byte TransferData PDU
    with J533CanLink("fake.dll", bus=bus) as link:
        with link.uds_session() as active:
            assert active is True
            assert link.request_uds(block, 0x76, timeout=5.0) == b"\x76\x01"
        assert dll.iso_writes == [b"\x3e\x00", block]
        # Raw CAN channel (0x710/0x77A + 0x6F0/0x6F1) is reconnected immediately on exit
        res = can_identify("fake.dll", bus=bus)
        assert {i["did"]: i["value"] for i in res["ident"]}["F187"] == "3Q0907530AA"
    bus.shutdown()


def test_a_late_answer_to_an_earlier_request_is_never_returned_as_this_one() -> None:
    """A `11 02` that timed out leaves its `51 02` queued. The next request must not take that for its answer,
    or a reset is reported as a session change and the flow carries on with a wrong idea of the ECU's state."""
    from contitool.can import J533CanLink
    from contitool.can.j2534 import ISO15765_FRAME_PAD, PROTOCOL_ISO15765

    class StaleRxPassThru(FakePassThru):
        def __init__(self) -> None:
            super().__init__(FakeGateway())
            self.iso_rx: list[PassThruMsg] = []
            self.stale_pending = True

        def PassThruConnect(self, _dev, proto, flags, baud, chan) -> int:  # noqa: N802
            if proto == PROTOCOL_ISO15765:
                chan._obj.value = 9
                return 0
            return super().PassThruConnect(_dev, proto, flags, baud, chan)

        def PassThruStartMsgFilter(self, chan, ftype, mask, pattern, flow, fid) -> int:  # noqa: N802
            return 0 if chan == 9 else super().PassThruStartMsgFilter(chan, ftype, mask, pattern, flow, fid)

        def _push(self, uds: bytes) -> None:
            raw = (0x77A).to_bytes(4, "big") + uds
            out = PassThruMsg(PROTOCOL_ISO15765, 0, 0, 0, len(raw))
            out.Data[: len(raw)] = list(raw)
            self.iso_rx.append(out)

        def PassThruWriteMsgs(self, chan, msg, n, _timeout) -> int:  # noqa: N802
            if chan != 9:
                return super().PassThruWriteMsgs(chan, msg, n, _timeout)
            m = msg._obj
            assert m.TxFlags & ISO15765_FRAME_PAD
            req = bytes(m.Data[: m.DataSize])[4:]
            if req == b"\x3e\x00":
                if self.stale_pending:  # the orphan from a request that had already timed out
                    self.stale_pending = False
                    self._push(b"\x51\x02")
                self._push(b"\x7e\x00")
            elif req == b"\x10\x03":
                self._push(b"\x50\x03\x00\x32\x01\xf4")
            elif req[:2] == b"\x36\x02":  # block 1's answer came late: it sits in front of block 2's
                self._push(b"\x76\x01")
                self._push(b"\x76\x02")
            return 0

        def PassThruReadMsgs(self, chan, buf, n, _timeout) -> int:  # noqa: N802
            if chan != 9:
                return super().PassThruReadMsgs(chan, buf, n, _timeout)
            count = min(n._obj.value, len(self.iso_rx))
            for i in range(count):
                ctypes.memmove(ctypes.byref(buf._obj[i]), ctypes.byref(self.iso_rx.pop(0)), ctypes.sizeof(PassThruMsg))
            n._obj.value = count
            return 0 if count else 0x10

    dll = StaleRxPassThru()
    bus = J2534Bus("fake.dll", dll=dll)
    with J533CanLink("fake.dll", bus=bus) as link, link.uds_session() as active:
        assert active is True
        assert link.request_uds(b"\x10\x03", 0x50, timeout=2.0).startswith(b"\x50\x03")
        assert link.request_uds(b"\x36\x02" + bytes(512), 0x76, timeout=2.0) == b"\x76\x02"  # not 76 01
    bus.shutdown()


def test_j2534_fallback_and_send_batch_with_partial_driver_writes() -> None:
    from contitool.can import J533CanLink

    class BatchPassThru(FakePassThru):
        def __init__(self) -> None:
            super().__init__(FakeGateway())
            self.batch_sizes: list[int] = []
            self.reassembled = bytearray()
            self._expected = 0
            self._cf_in_block = 0

        def PassThruWriteMsgs(self, chan, msg, n, _timeout) -> int:  # noqa: N802
            obj = msg._obj
            items = [obj] if isinstance(obj, PassThruMsg) else list(obj[: n._obj.value])
            # Simulate a driver that accepts at most 8 frames per PassThruWriteMsgs call when given a 15-frame burst
            accepted = min(len(items), 8)
            self.batch_sizes.append(accepted)
            for m in items[:accepted]:
                raw = bytes(m.Data[: m.DataSize])
                arb, data = int.from_bytes(raw[:4], "big"), raw[4:]
                assert arb == 0x710
                pci = data[0] >> 4
                if pci == 1:
                    self._expected = ((data[0] & 0x0F) << 8) | data[1]
                    self.reassembled = bytearray(data[2:8])
                    self._cf_in_block = 0
                    self._push_can(0x77A, b"\x30\x0f\x00\xaa\xaa\xaa\xaa\xaa")
                elif pci == 2:
                    self.reassembled.extend(data[1:8])
                    self._cf_in_block += 1
                    if len(self.reassembled) >= self._expected:
                        self.reassembled = self.reassembled[: self._expected]
                        self._push_can(0x77A, bytes([0x02, 0x76, self.reassembled[1], 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]))
                    elif self._cf_in_block == 15:
                        self._cf_in_block = 0
                        self._push_can(0x77A, b"\x30\x0f\x00\xaa\xaa\xaa\xaa\xaa")
            n._obj.value = accepted
            return 0

        def _push_can(self, arb: int, data: bytes) -> None:
            out = PassThruMsg(5, 0, 0, 0, 4 + len(data))
            out.Data[: 4 + len(data)] = list(arb.to_bytes(4, "big") + data)
            self.rx.append(out)

    dll = BatchPassThru()
    bus = J2534Bus("fake.dll", dll=dll)
    block = bytes([0x36, 0x2A]) + bytes((i & 0xFF) for i in range(512))
    with J533CanLink("fake.dll", bus=bus) as link:
        with link.uds_session() as active:
            assert active is False  # FakePassThru refuses PROTOCOL_ISO15765 -> automatic fallback to raw CAN + batch
            assert link.request_uds(block, 0x76, timeout=5.0) == b"\x76\x2a"
    assert bytes(dll.reassembled) == block
    # 1 FirstFrame + four 15-frame blocks (split 8+7) + final 13-frame block (split 8+5) = 11 calls instead of 74!
    assert dll.batch_sizes == [1, 8, 7, 8, 7, 8, 7, 8, 7, 8, 5]
    bus.shutdown()


def test_j2534_buffer_overflow_clears_rx_and_steps_down_read_burst(monkeypatch, tmp_path) -> None:
    """Issue #45: Scanmatik SM2 USB returned ERR_BUFFER_OVERFLOW (0x12) during 64 KB bursts and again inside
    `read_memory_area`'s retry `drain_rx`. J2534 must default to 16 KB bursts, clear the RX queue via
    CLEAR_RX_BUFFER on 0x12, survive 0x12 during retry drain, and step down to 4 KB bursts to finish cleanly."""
    from contitool.can import J533CanLink, transport, workflows
    from contitool.can.j2534 import ERR_BUFFER_OVERFLOW, IOCTL_CLEAR_RX_BUFFER, J2534BufferOverflowError

    class OverflowPassThru(FakePassThru):
        def __init__(self) -> None:
            super().__init__(FakeGateway())
            self.ioctls: list[tuple[int, int]] = []
            self.overflow_reads = 0

        def PassThruIoctl(self, chan, ioctl_id, _p_in, _p_out) -> int:  # noqa: N802
            self.ioctls.append((chan, ioctl_id))
            if ioctl_id == IOCTL_CLEAR_RX_BUFFER:
                self.rx.clear()
            return 0

        def PassThruReadMsgs(self, chan, buf, n, timeout) -> int:  # noqa: N802
            if self.overflow_reads > 0:
                self.overflow_reads -= 1
                n._obj.value = 0
                return ERR_BUFFER_OVERFLOW
            return super().PassThruReadMsgs(chan, buf, n, timeout)

    set_lang("en")
    monkeypatch.setattr(workflows.time, "sleep", lambda _s: None)
    monkeypatch.setattr(transport.time, "sleep", lambda _s: None)
    dll = OverflowPassThru()
    bus = J2534Bus("fake.dll", dll=dll)

    # 1. Direct read raises J2534BufferOverflowError (keeps message & error code); drain_rx clears and recovers
    dll.overflow_reads = 1
    with pytest.raises(J2534BufferOverflowError, match="PassThruReadMsgs: J2534 error 0x12"):
        bus.recv(0)
    dll.overflow_reads = 2
    with J533CanLink("fake.dll", interface="j2534", bus=bus) as link:
        assert link.drain_rx(max_frames=32) == 2
        assert (7, IOCTL_CLEAR_RX_BUFFER) in dll.ioctls

        # 2. read_memory_area starts at 16 KB on J2534, survives 0x12 inside retry drain, and steps down to 4 KB
        expected = bytes((i * 73 + 5) & 0xFF for i in range(65_536))
        seen_sizes: list[int] = []
        dll.ioctls.clear()

        def fake_stream(_link, _payload, addr, size, **_kw) -> bytes:
            seen_sizes.append(size)
            if len(seen_sizes) == 1:
                dll.overflow_reads = 2  # retry cleanup's drain_rx also hits 0x12 — must not abort retry
                raise J2534BufferOverflowError("PassThruReadMsgs: J2534 error 0x12", error_code=ERR_BUFFER_OVERFLOW)
            return expected[addr : addr + size]

        monkeypatch.setattr(workflows, "_stream_loader_read_payload", fake_stream)
        out = tmp_path / "Cflash.bin"
        res = workflows.read_memory_area(link, 0, 65_536, out, label="Cflash.bin")

    assert res["complete"] is True
    assert out.read_bytes() == expected
    assert seen_sizes[0] == workflows.J2534_FED_READS_PER_PAYLOAD * workflows.READ_CHUNK_BYTES  # 16 KB initial burst
    assert seen_sizes[1:] == [4096] * 16  # stepped down to 4 KB after 0x12
    assert (7, IOCTL_CLEAR_RX_BUFFER) in dll.ioctls
    bus.shutdown()


def test_j2534_request_uds_reads_one_pdu_and_nested_uds_session_checks_ids() -> None:
    from contitool.can import J533CanLink
    from contitool.can.j2534 import PROTOCOL_ISO15765

    class CheckingIsoTpPassThru(FakePassThru):
        def __init__(self) -> None:
            super().__init__(FakeGateway())
            self.iso_rx: list[PassThruMsg] = []
            self.iso_read_counts: list[int] = []
            self.disconnected: list[int] = []
            self.fail_raw_filter = False

        def PassThruConnect(self, _dev, proto, flags, baud, chan) -> int:  # noqa: N802
            if proto == PROTOCOL_ISO15765:
                chan._obj.value = 9
                return 0
            return super().PassThruConnect(_dev, proto, flags, baud, chan)

        def PassThruDisconnect(self, chan) -> int:  # noqa: N802
            self.disconnected.append(chan)
            return super().PassThruDisconnect(chan)

        def PassThruStartMsgFilter(self, chan, ftype, mask, pattern, flow, fid) -> int:  # noqa: N802
            if chan == 9:
                return 0
            if self.fail_raw_filter:
                return 0x08
            return super().PassThruStartMsgFilter(chan, ftype, mask, pattern, flow, fid)

        def PassThruWriteMsgs(self, chan, msg, n, _timeout) -> int:  # noqa: N802
            if chan != 9:
                return super().PassThruWriteMsgs(chan, msg, n, _timeout)
            m = msg._obj
            req = bytes(m.Data[: m.DataSize])[4:]
            resp = b"\x7e\x00" if req == b"\x3e\x00" else b"\x50\x03\x00\x32\x01\xf4"
            raw = (0x77A).to_bytes(4, "big") + resp
            out = PassThruMsg(PROTOCOL_ISO15765, 0, 0, 0, len(raw))
            out.Data[: len(raw)] = list(raw)
            self.iso_rx.append(out)
            return 0

        def PassThruReadMsgs(self, chan, buf, n, timeout) -> int:  # noqa: N802
            if chan != 9:
                return super().PassThruReadMsgs(chan, buf, n, timeout)
            if timeout > 0:
                self.iso_read_counts.append(n._obj.value)
            count = min(n._obj.value, len(self.iso_rx))
            for i in range(count):
                ctypes.memmove(ctypes.byref(buf._obj[i]), ctypes.byref(self.iso_rx.pop(0)), ctypes.sizeof(PassThruMsg))
            n._obj.value = count
            return 0 if count else 0x10

    dll = CheckingIsoTpPassThru()
    bus = J2534Bus("fake.dll", dll=dll)
    with J533CanLink("fake.dll", bus=bus) as link, link.uds_session() as active:
        assert active is True
        assert link.request_uds(b"\x10\x03", 0x50, timeout=1.0).startswith(b"\x50\x03")
        # Same IDs re-entry succeeds; mismatched IDs must yield False and report refusal rather than talking to wrong ECU
        with bus.uds_session(tx_id=0x710, rx_id=0x77A) as same_ok:
            assert same_ok is True
        with bus.uds_session(tx_id=0x714, rx_id=0x77E) as diff_ok:
            assert diff_ok is False
        assert "0x710/0x77A" in bus.uds_refusal
    assert dll.iso_read_counts and all(c == 1 for c in dll.iso_read_counts)
    bus.shutdown()

    # Partial raw CAN connect must disconnect its channel if PassThruStartMsgFilter fails
    dll2 = CheckingIsoTpPassThru()
    dll2.fail_raw_filter = True
    with pytest.raises(can.CanOperationError, match="PassThruStartMsgFilter"):
        J2534Bus("fake.dll", dll=dll2)
    assert 7 in dll2.disconnected

