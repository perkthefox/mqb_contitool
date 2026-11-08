"""VAS 6154 / VNCI over the VW D-PDU API: monitor link for receiving, RawMode link for sending."""

from __future__ import annotations

import ctypes as C

import can
import pytest

from contitool.can import can_identify
from contitool.can.dpdu import (
    COPT_SENDRECV,
    COPT_STARTCOMM,
    IT_ERROR,
    IT_RESULT,
    IT_STATUS,
    MAX_TX_IN_FLIGHT,
    RAWCAN_OBD6_14,
    DPduBus,
    EventItem,
    FlagData,
    ModuleData,
    ModuleItem,
    ResultData,
)
from contitool.i18n import set_lang
from test_identify import FakeGateway

U8 = C.c_uint8


class FakePduApi:
    """PDUAPI_VW.dll as a real VCI behaves: the monitor link gets every bus frame, our own ones flagged 00 00 00 01."""

    def __init__(self) -> None:
        self.gw = FakeGateway()
        self.links: dict[int, tuple[int, ...]] = {}
        self.params: dict[int, dict[int, int]] = {}
        self.events: dict[int, list] = {}
        self.keep: list = []
        self.monitor = 0
        self.monitor_started = False
        self.extra_rx: list[tuple[int, bytes, bytes]] = []  # (id, data, flags) injected by a test
        self.destructed = False
        self.next_cop = 1
        self.tx_open: list[int] = []  # send primitives the "VCI" has not finished yet
        self.max_open = 0
        self.fail_next_send = False

    def PDUConstruct(self, *_a) -> int:  # noqa: N802 (D-PDU names)
        return 0

    def PDUGetModuleIds(self, out) -> int:  # noqa: N802
        md = (ModuleData * 1)(ModuleData(14, 0x10000001, b"VAS6154A", b"", 0x8063))
        item = ModuleItem(0x1600, 1, C.cast(md, C.POINTER(ModuleData)))
        self.keep += [md, item]
        out._obj.contents = item
        return 0

    def PDUDestroyItem(self, _item) -> int:  # noqa: N802
        return 0

    def PDUModuleConnect(self, hmod) -> int:  # noqa: N802
        assert hmod == 0x10000001
        return 0

    def PDUCreateComLogicalLink(self, _hmod, rsc, resource, _tag, phcll, flag) -> int:  # noqa: N802
        assert rsc is None and resource == RAWCAN_OBD6_14 and flag._obj.NumFlagBytes == 4
        h = 0x20010000 + len(self.links)
        self.links[h] = tuple(flag._obj.pFlagData[i] for i in range(4))
        self.params[h], self.events[h] = {}, []
        if self.links[h] == (0x80, 0, 0, 1):
            self.monitor = h
        phcll._obj.value = h
        return 0

    def PDUSetComParam(self, _hmod, hcll, item) -> int:  # noqa: N802
        p = item._obj
        self.params[hcll][p.ComParamId] = C.cast(p.pComParamData, C.POINTER(C.c_uint32)).contents.value
        return 0

    def PDUConnect(self, *_a) -> int:  # noqa: N802
        return 0

    def PDUStartComPrimitive(self, _hmod, hcll, cop, size, data, ctrl, _tag, hcop) -> int:  # noqa: N802
        c = ctrl._obj
        assert c.TxFlag.NumFlagBytes == 4
        if hcll == self.monitor:
            assert cop == COPT_SENDRECV and (c.NumSendCycles, c.NumReceiveCycles) == (0, -1)
            assert c.NumPossibleExpectedResponses >= 1  # the exported API refuses an empty list
            self.monitor_started = True
        elif cop == COPT_STARTCOMM:
            assert (c.NumSendCycles, c.NumReceiveCycles) == (0, 0)  # 1 makes the VCI send an empty frame
        else:
            hcop._obj.value = self.next_cop
            self.tx_open.append(self.next_cop)
            self.max_open = max(self.max_open, len(self.tx_open))
            self.next_cop += 1
            raw = bytes(data[:size])
            self._result(raw, b"\x00\x00\x00\x01")  # echo of our own frame
            self.gw.send(can.Message(arbitration_id=int.from_bytes(raw[:4], "big"), data=raw[4:], is_extended_id=False))
            while (m := self.gw.recv()) is not None:
                self._result(m.arbitration_id.to_bytes(4, "big") + bytes(m.data), b"\x00\x00\x00\x00")
            return 0
        hcop._obj.value = 0
        return 0

    def _result(self, raw: bytes, flags: bytes) -> None:
        data, fl = (U8 * len(raw)).from_buffer_copy(raw), (U8 * 4).from_buffer_copy(flags)
        r = ResultData(FlagData(4, fl), 0, 1, FlagData(0, None), 0, 0, None, len(raw), C.cast(data, C.POINTER(U8)))
        ev = EventItem(IT_RESULT, 1, None, 0, C.cast(C.pointer(r), C.c_void_p))
        self.keep += [data, fl, r, ev]
        self.events[self.monitor].append(ev)

    def PDUGetEventItem(self, _hmod, hcll, out) -> int:  # noqa: N802
        if hcll != self.monitor and self.tx_open and not self.events[hcll]:
            # the VCI finishes one send primitive per poll (it really takes ~3.5 ms each)
            cop = self.tx_open.pop(0)
            if self.fail_next_send:
                self.fail_next_send = False
                self.events[hcll].append(EventItem(IT_ERROR, cop, None, 0, None))
            else:
                st = C.c_uint32(0x8012)  # COPST_FINISHED
                self.keep.append(st)
                self.events[hcll].append(EventItem(IT_STATUS, cop, None, 0, C.cast(C.pointer(st), C.c_void_p)))
        for cid, data, flags in self.extra_rx:
            self._result(cid.to_bytes(4, "big") + data, flags)
        self.extra_rx.clear()
        if not self.events[hcll]:
            return 0x71
        out._obj.contents = self.events[hcll].pop(0)
        return 0

    def PDUDisconnect(self, *_a) -> int:  # noqa: N802
        return 0

    def PDUDestroyComLogicalLink(self, *_a) -> int:  # noqa: N802
        return 0

    def PDUModuleDisconnect(self, *_a) -> int:  # noqa: N802
        return 0

    def PDUDestruct(self) -> int:  # noqa: N802
        self.destructed = True
        return 0


def test_identification_runs_over_the_vas6154_monitor_and_rawmode_links() -> None:
    set_lang("en")
    api = FakePduApi()
    bus = DPduBus("VW_D_PDU_API_OE", dll=api)
    assert api.monitor_started
    assert sorted(api.links.values()) == [(0x80, 0, 0, 0), (0x80, 0, 0, 1)]
    assert api.params[api.monitor] == {165: 1, 163: 2300, 164: 10, 126: 500_000}
    res = can_identify("VW_D_PDU_API_OE", bus=bus)  # ISO-TP is ours; echoes of our frames must not confuse it
    assert {i["did"]: i["value"] for i in res["ident"]}["F187"] == "3Q0907530AA"
    bus.shutdown()
    assert api.destructed


def test_monitor_frames_keep_their_29_bit_flag_and_own_echoes_are_dropped() -> None:
    api = FakePduApi()
    bus = DPduBus(dll=api)
    api.extra_rx += [(0x710, bytes(8), b"\x00\x00\x00\x01"),
                     (0x17F00010, bytes.fromhex("2010000000000080"), b"\x00\x00\x01\x00")]
    msg = bus.recv(0.1)
    assert (msg.arbitration_id, msg.is_extended_id, bytes(msg.data)) == (0x17F00010, True, bytes.fromhex("2010000000000080"))
    assert bus.recv(0.01) is None
    bus.shutdown()


def test_full_send_queue_is_waited_out() -> None:
    api = FakePduApi()
    bus = DPduBus(dll=api)
    real, calls = api.PDUStartComPrimitive, []

    def busy_twice(*args):
        calls.append(1)
        return 0x70 if len(calls) <= 2 else real(*args)  # PDU_ERR_TX_QUEUE_FULL

    api.PDUStartComPrimitive = busy_twice
    bus.send(can.Message(arbitration_id=0x6F0, data=bytes(8), is_extended_id=False))
    assert len(calls) == 3
    bus.shutdown()


def test_bursts_are_paced_to_the_vci_queue_and_a_lost_frame_fails_at_once() -> None:
    api = FakePduApi()
    bus = DPduBus(dll=api)
    for _ in range(80):  # a RAM-loader payload once overflowed the VCI queue with 52 waiting
        bus.send(can.Message(arbitration_id=0x6F0, data=bytes(8), is_extended_id=False))
    assert api.max_open <= MAX_TX_IN_FLIGHT
    api.fail_next_send = True
    with pytest.raises(can.CanOperationError):
        for _ in range(MAX_TX_IN_FLIGHT + 2):
            bus.send(can.Message(arbitration_id=0x6F0, data=bytes(8), is_extended_id=False))
    bus.shutdown()


def test_short_frames_keep_their_length_and_a_packed_result_is_an_error() -> None:
    """The loader's 2-byte closing frame must arrive as 2 bytes; a result longer than one frame is never guess-split."""
    set_lang("en")
    api = FakePduApi()
    bus = DPduBus(dll=api)
    api._result((0x6F1).to_bytes(4, "big") + b"\x00\x00", b"\x00\x00\x00\x00")
    msg = bus.recv(0.1)
    assert (msg.arbitration_id, bytes(msg.data)) == (0x6F1, b"\x00\x00")
    api._result((0x6F1).to_bytes(4, "big") + bytes(5) + (0x6F1).to_bytes(4, "big") + b"\x00\x00", b"\x00\x00\x00\x00")
    with pytest.raises(can.CanOperationError, match="more than one CAN frame"):
        bus.recv(0.1)
    bus.shutdown()
