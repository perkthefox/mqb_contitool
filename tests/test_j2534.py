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
