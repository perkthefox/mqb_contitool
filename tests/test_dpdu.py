"""VAS 6154 / VNCI over the VW D-PDU API: monitor link for receiving, RawMode link for sending."""

from __future__ import annotations

import ctypes as C
import threading
import time

import can
import pytest

from contitool.can import can_identify
from contitool.can import dpdu
from contitool.can.dpdu import (
    COPT_SENDRECV,
    COPT_STARTCOMM,
    COPT_STOPCOMM,
    IT_ERROR,
    IT_RESULT,
    IT_STATUS,
    MAX_TX_IN_FLIGHT,
    RAWCAN_OBD6_14,
    DPduBus,
    EcuUniqueRespData,
    EventItem,
    FlagData,
    ModuleData,
    ModuleItem,
    ParamItem,
    ResultData,
    UridTable,
)
from contitool.i18n import set_lang
from test_identify import FakeGateway

U8 = C.c_uint8


@pytest.fixture(autouse=True)
def _no_kept_link():
    """A kept-open D-PDU link is process-wide: never let one leak from a failed test into the next."""
    dpdu.close_session()
    yield
    dpdu.close_session()


class FakePduApi:
    """PDUAPI_VW.dll as a real VCI behaves: the monitor link gets every bus frame, our own ones flagged 00 00 00 01."""

    def __init__(self) -> None:
        self._lock = threading.RLock()  # the real DLL is called from the receive thread and the caller's at once
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
        self.fail_connects = 0  # PDUConnect calls that answer PDU_ERR_COMM_PC_TO_VCI_FAILED
        self.calls: list[tuple] = []
        # (ModuleTypeId, hMod, VendorModuleName) as PDUGetModuleIds reports them; 14 is a VW VCI, 12 a J2534 driver
        self.modules = [(14, 0x10000001, b"VendorName='Volkswagen AG' ModuleName='VAS6154A' IP='192.168.13.69'")]
        self.connect_ok = {0x10000001}
        self.connect_rc: dict[int, int] = {}  # per-module PDUModuleConnect result other than 0 / 0x01
        self.connected: list[int] = []
        self.create_rc = 0  # what PDUCreateComLogicalLink answers (0x50: the module has no such resource)
        self.create_rc_for: dict[int, int] = {}  # per-module refusal, keyed by hMod
        self.rawmode_ok = True  # False: the adapter refuses RawMode, as the VCI of issue #12 does
        self.nonraw_ok = True  # False: it refuses the ODIS-style link as well
        self.nonraw_silent = False  # True: the links open but carry nothing — the guess was wrong
        self.nonraw_links: dict[int, dict[str, int]] = {}  # link -> ids written into its URID table
        self.objects = {"ISO_11898_2_DWCAN": 0x10, "ISO_11898_RAW": 0x11, "HI": 0x20, "LOW": 0x21,
                        "CP_CanPhysReqId": 0x1A, "CP_CanRespUUDTId": 0x1B}

    def PDUConstruct(self, *_a) -> int:  # noqa: N802 (D-PDU names)
        return 0

    def PDUGetModuleIds(self, out) -> int:  # noqa: N802
        md = (ModuleData * len(self.modules))(*(ModuleData(t, h, n, b"", 0x8063) for t, h, n in self.modules))
        item = ModuleItem(0x1600, len(self.modules), C.cast(md, C.POINTER(ModuleData)))
        self.keep += [md, item]
        out._obj.contents = item
        return 0

    def PDUDestroyItem(self, _item) -> int:  # noqa: N802
        return 0

    def PDUModuleConnect(self, hmod) -> int:  # noqa: N802
        self.connected.append(hmod)
        if hmod in self.connect_rc:
            return self.connect_rc[hmod]
        return 0 if hmod in self.connect_ok else 0x01  # PDU_ERR_FCT_FAILED, as a driver whose service is down

    # ---- the ODIS-style fallback an adapter without RawMode has to offer
    def PDUGetObjectId(self, _kind, name, out) -> int:  # noqa: N802
        oid = self.objects.get(name.decode(), 0)
        out._obj.value = oid
        return 0 if oid else 0x62  # PDU_ERR_ID_NOT_SUPPORTED

    def PDUGetUniqueRespIdTable(self, _hmod, hcll, out) -> int:  # noqa: N802
        vals = (C.c_uint32 * 2)(0, 0)
        params = (ParamItem * 2)(  # indexing a ctypes array yields an int, so address the slots, not the values
            ParamItem(0x1200, 0x1A, 0x105, 1, C.cast(vals, C.c_void_p)),
            ParamItem(0x1200, 0x1B, 0x105, 1, C.cast(C.byref(vals, C.sizeof(C.c_uint32)), C.c_void_p)),
        )
        entry = (EcuUniqueRespData * 1)(EcuUniqueRespData(0, 2, C.cast(params, C.POINTER(ParamItem))))
        table = UridTable(0x1700, 1, C.cast(entry, C.POINTER(EcuUniqueRespData)))
        self.keep += [vals, params, entry, table, hcll]
        out._obj.contents = table
        return 0

    def PDUSetUniqueRespIdTable(self, _hmod, hcll, table) -> int:  # noqa: N802
        t = table._obj if hasattr(table, "_obj") else table.contents
        entry = t.pUniqueData[0]
        ids = {entry.pParams[i].ComParamId: C.cast(entry.pParams[i].pComParamData, C.POINTER(C.c_uint32)).contents.value
               for i in range(entry.NumParamItems)}
        self.nonraw_links[hcll] = {"phys": ids.get(0x1A, 0), "resp": ids.get(0x1B, 0)}
        return 0

    def PDUCreateComLogicalLink(self, _hmod, rsc, resource, _tag, phcll, flag) -> int:  # noqa: N802
        if _hmod in self.create_rc_for:
            return self.create_rc_for[_hmod]
        if self.create_rc:
            return self.create_rc
        if rsc is not None:  # RscData path: bus + protocol + pins, resource PDU_ID_UNDEF
            if not self.nonraw_ok:
                return 0x01
            assert resource == 0xFFFFFFFE and rsc._obj.ProtocolId == self.objects["ISO_11898_RAW"]
            h = 0x20010000 + len(self.links)
            self.links[h] = tuple(flag._obj.pFlagData[i] for i in range(4))
            self.params[h], self.events[h] = {}, []
            self.nonraw_links[h] = {"phys": 0, "resp": 0}
            phcll._obj.value = h
            return 0
        if not self.rawmode_ok:
            return 0x01  # PDU_ERR_FCT_FAILED, exactly as the issue #12 adapter answers
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

    def PDUConnect(self, _hmod, hcll) -> int:  # noqa: N802
        if self.fail_connects:
            self.fail_connects -= 1
            return 0x11
        self.calls.append(("connect", hcll))
        return 0

    def PDUStartComPrimitive(self, *args) -> int:  # noqa: N802
        with self._lock:
            return self._start_cop(*args)

    def _start_cop(self, _hmod, hcll, cop, size, data, ctrl, _tag, hcop) -> int:
        c = ctrl._obj
        assert c.TxFlag.NumFlagBytes == 4
        if hcll in self.nonraw_links:  # fixed-id link: the payload travels alone, the ids come from its URID table
            hcop._obj.value = self.next_cop
            self.next_cop += 1
            if cop != COPT_SENDRECV or not size:
                return 0  # STARTCOMM/STOPCOMM and the receive-only primitive
            self.tx_open.append(hcop._obj.value)
            if self.nonraw_silent:
                return 0
            ids = self.nonraw_links[hcll]
            self.gw.send(can.Message(arbitration_id=ids["phys"], data=bytes(data[:size]), is_extended_id=False))
            while (m := self.gw.recv()) is not None:
                if m.arbitration_id == ids["resp"]:
                    self._result(bytes(m.data), b"\x00\x00\x00\x00", link=hcll)
            return 0
        if hcll == self.monitor:
            assert cop == COPT_SENDRECV and (c.NumSendCycles, c.NumReceiveCycles) == (0, -1)
            assert c.NumPossibleExpectedResponses >= 1  # the exported API refuses an empty list
            self.monitor_started = True
            hcop._obj.value = 0x01
            return 0
        elif cop in (COPT_STARTCOMM, COPT_STOPCOMM):
            assert (c.NumSendCycles, c.NumReceiveCycles) == (0, 0)  # 1 makes the VCI send an empty frame
            self.calls.append(("stopcomm" if cop == COPT_STOPCOMM else "startcomm", hcll))
            if cop == COPT_STOPCOMM:
                hcop._obj.value = self.next_cop
                self.tx_open.append(self.next_cop)
                self.next_cop += 1
                return 0
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

    def _result(self, raw: bytes, flags: bytes, link: int | None = None) -> None:
        with self._lock:
            data, fl = (U8 * len(raw)).from_buffer_copy(raw), (U8 * 4).from_buffer_copy(flags)
            r = ResultData(FlagData(4, fl), 0, 1, FlagData(0, None), 0, 0, None, len(raw), C.cast(data, C.POINTER(U8)))
            ev = EventItem(IT_RESULT, 1, None, 0, C.cast(C.pointer(r), C.c_void_p))
            self.keep += [data, fl, r, ev]
            self.events[self.monitor if link is None else link].append(ev)

    def PDUGetEventItem(self, *args) -> int:  # noqa: N802
        with self._lock:
            return self._get_event(*args)

    def _get_event(self, _hmod, hcll, out) -> int:
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

    def PDUCancelComPrimitive(self, _hmod, hcll, hcop) -> int:  # noqa: N802
        self.calls.append(("cancel", hcll, hcop))
        return 0

    def PDUDisconnect(self, _hmod, hcll) -> int:  # noqa: N802
        self.calls.append(("disconnect", hcll))
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
        bus.recv(1.0)
    # read_memory_area retries exactly this error, so the link has to stay alive for the retry to have a chance
    api._result((0x6F1).to_bytes(4, "big") + b"\x11\x22", b"\x00\x00\x00\x00")
    assert bytes(bus.recv(1.0).data) == b"\x11\x22" and not bus.spent
    bus.shutdown()


def test_close_stops_the_send_link_and_cancels_the_monitor_before_disconnecting() -> None:
    """Driver 30.x: without STOPCOMM / cancel the next session's monitor PDUConnect dropped the VCI every second time."""
    api = FakePduApi()
    bus = DPduBus(dll=api)
    tx = next(h for h, f in api.links.items() if f == (0x80, 0, 0, 0))
    api.calls.clear()
    bus.shutdown()
    assert api.calls == [("stopcomm", tx), ("cancel", api.monitor, 0x01), ("disconnect", api.monitor), ("disconnect", tx)]
    assert api.destructed


def test_a_vci_that_drops_on_connect_is_retried_once(monkeypatch) -> None:
    monkeypatch.setattr(dpdu, "VCI_RESTART_WAIT", 0)
    api = FakePduApi()
    api.fail_connects = 1
    bus = DPduBus(dll=api)
    assert api.monitor_started
    api.extra_rx += [(0x17F00010, bytes(8), b"\x00\x00\x00\x00")]
    assert bus.recv(1.0) is not None  # the retry must come up fully alive, receive thread included
    assert not bus.spent  # and be keepable: attempt 1's error must not condemn the link that worked
    bus.shutdown()
    api = FakePduApi()
    api.fail_connects = 2
    with pytest.raises(can.CanError):  # an initialization failure now: no module produced a usable link
        DPduBus(dll=api)
    assert api.destructed


def test_only_known_driver_versions_run_without_confirmation(monkeypatch) -> None:
    set_lang("en")
    monkeypatch.setattr(dpdu, "accepted_drivers", set())
    for ok in ("27.2.0", "31.0.0", "31.1.2"):
        dpdu.check_driver(ok)
    for bad in ("30.3.0", "34.0.0", ""):
        with pytest.raises(can.CanInitializationError, match="not verified"):
            dpdu.check_driver(bad)
    dpdu.accepted_drivers.add("30.3.0")
    dpdu.check_driver("30.3.0")


XHORSE = (12, 0x10000007, b"VendorName='XHorse ELECTRONICS Co.,Ltd.' ModuleName='XHorse - MVCI - 1.4.8'")
DENSO = (12, 0x10000002, b"VendorName='DENSO CORPORATION' ModuleName='TIS Techstream VIM'")
VAS6154 = (14, 0x10000001, b"VendorName='Volkswagen AG' ModuleName='VAS6154A' SerialNumber='6003982'")
SOFTING = (12, 0x10000004, b"VendorName='Softing' ModuleName='VAS5054A#083600808'")


def test_the_vw_vci_is_picked_out_of_every_j2534_driver_installed_on_the_pc() -> None:
    """PDUGetModuleIds lists every D-PDU and J2534 driver on the PC, in an order that changes between calls.

    Taking the first entry connected a foreign driver, whose own service refused on 127.0.0.1:4500 (0x01), and the
    same PC then worked or failed depending on that order."""
    api = FakePduApi()
    api.modules = [XHORSE, DENSO, VAS6154, SOFTING]
    bus = DPduBus(dll=api)
    assert api.connected == [0x10000001]  # the foreign drivers are never even connected
    assert bus.module_label == "VAS6154A"
    bus.shutdown()


def test_every_module_tried_is_named_when_none_of_them_connects() -> None:
    set_lang("en")
    api = FakePduApi()
    api.modules = [VAS6154, (14, 0x10000009, b"VendorName='Volkswagen AG' ModuleName='VAS6154A-WLAN'")]
    api.connect_ok = set()
    with pytest.raises(can.CanError, match="VAS6154A, VAS6154A-WLAN"):
        DPduBus(dll=api)
    assert api.connected == [0x10000001, 0x10000009] and api.destructed


def test_a_module_without_the_raw_can_resource_says_so() -> None:
    """A real VAS 5054A connects and then has no 0x30030003 resource: name that, don't just report error 0x50."""
    set_lang("en")
    api = FakePduApi()
    api.modules = [SOFTING]  # no VW VCI on this PC at all, so the J2534 module is the only candidate
    api.connect_ok = {0x10000004}
    api.create_rc = 0x50
    with pytest.raises(can.CanError, match="VAS5054A#083600808.*raw CAN"):
        DPduBus(dll=api)
    assert api.destructed


def test_one_link_serves_every_operation_and_only_one_at_a_time(monkeypatch) -> None:
    """Reopening asks for the module list again, so the link is opened once and handed back, not closed."""
    api = FakePduApi()
    monkeypatch.setattr(dpdu, "DPduBus", lambda channel, bitrate: DPduBus(channel, bitrate, dll=api))
    first = dpdu.open_session("VW_D_PDU_API_OE")
    dpdu.release_session(first)
    assert dpdu.open_session("VW_D_PDU_API_OE") is first and api.connected == [0x10000001]
    assert not api.destructed
    with pytest.raises(can.CanError, match="busy"):  # two operations at once would interleave their frames
        dpdu.open_session("VW_D_PDU_API_OE")
    dpdu.release_session(first)  # closing while an operation holds it is a separate test
    dpdu.close_session()
    assert api.destructed


def _fake_dll(path, machine: int = 0x8664) -> None:
    """Just enough of a PE header for the bit-width check (0x8664 = x64, 0x14C = x86)."""
    buf = bytearray(0x80)
    buf[:2] = b"MZ"
    buf[0x3C:0x40] = (0x40).to_bytes(4, "little")
    buf[0x40:0x44] = b"PE\0\0"
    buf[0x44:0x46] = machine.to_bytes(2, "little")
    path.write_bytes(bytes(buf))


def test_a_driver_copied_next_to_contitool_is_offered_first_and_only_64_bit(monkeypatch, tmp_path) -> None:
    """A PC without the driver installed (no registry key) can still use a copy put in `dpdu/`.

    The VW package ships both builds; a 32-bit DLL cannot load into our process and must not shadow a working one."""
    monkeypatch.setattr(dpdu.sys, "platform", "win32")  # the registry read then fails on its own
    monkeypatch.setattr(dpdu, "bundled_dpdu_dir", lambda: tmp_path / "dpdu")
    (tmp_path / "dpdu/VW_PDUAPI_OE").mkdir(parents=True)
    (tmp_path / "dpdu/VW_PDUAPI_x86").mkdir(parents=True)
    _fake_dll(tmp_path / "dpdu/VW_PDUAPI_OE/PDUAPI_VW.dll")
    _fake_dll(tmp_path / "dpdu/VW_PDUAPI_x86/PDUAPI_VW.dll", machine=0x14C)

    found = dpdu.discover_dpdu()
    assert [a["name"] for a in found] == ["ContiTool · VW_PDUAPI_OE"]
    assert found[0]["dll"].endswith("PDUAPI_VW.dll")


def test_the_driver_the_user_picked_wins_over_a_longer_name_containing_it(monkeypatch) -> None:
    api = FakePduApi()
    loaded: list[str] = []
    monkeypatch.setattr(dpdu, "discover_dpdu", lambda: [
        {"name": "VW_D_PDU_API_OE_2", "dll": "b.dll", "version": "31.1.0"},
        {"name": "VW_D_PDU_API_OE", "dll": "a.dll", "version": "31.1.0"},
    ])
    monkeypatch.setattr(dpdu.C, "WinDLL", lambda path: (loaded.append(path), api)[1], raising=False)
    bus = DPduBus("VW_D_PDU_API_OE")
    assert loaded == ["a.dll"] and bus.channel_key == "VW_D_PDU_API_OE"
    bus.shutdown()


def test_the_monitor_link_stays_drained_while_no_operation_runs(monkeypatch) -> None:
    """The link is held open like ODIS holds it, so somebody has to keep taking the driver's events: a quiet spell
    must not leave a backlog for the next operation to chew through before it sees its own answer."""
    api = FakePduApi()
    monkeypatch.setattr(dpdu, "DPduBus", lambda channel, bitrate: DPduBus(channel, bitrate, dll=api))
    bus = dpdu.open_session("")
    dpdu.release_session(bus)  # idle, as between two operations

    api.extra_rx += [(0x17F00010, bytes(8), b"\x00\x00\x00\x00")] * 3
    end = time.monotonic() + 2.0
    while len(bus._pending) < 3 and time.monotonic() < end:
        time.sleep(0.005)
    assert len(bus._pending) == 3 and not api.events[api.monitor]  # taken with nobody polling

    assert dpdu.open_session("") is bus and not bus._pending  # and the next operation starts on a clean queue
    dpdu.close_session()


def test_a_module_failing_in_an_unexpected_way_does_not_hide_the_vci_behind_it() -> None:
    """Only 0x01 was tolerated before, so any other answer aborted the search at the first module."""
    set_lang("en")
    api = FakePduApi()
    api.modules = [(14, 0x10000009, b"VendorName='Volkswagen AG' ModuleName='VAS6154A-WLAN'"), VAS6154]
    api.connect_ok = {0x10000001}
    api.connect_rc = {0x10000009: 0xA3}  # PDU_ERR_MODULE_NOT_CONNECTED, not the 0x01 we had expected
    bus = DPduBus(dll=api)
    assert api.connected == [0x10000009, 0x10000001]
    assert bus.module_label == "VAS6154A" and not bus.spent
    bus.shutdown()


def test_a_module_that_connects_but_gives_no_raw_can_is_not_the_one_we_keep() -> None:
    """Issue #12: connecting proves nothing — a foreign driver accepts the connect and only then refuses the
    raw-CAN resource, which reached users as a bare `PDUCreateComLogicalLink: D-PDU error 0x01`."""
    set_lang("en")
    api = FakePduApi()
    api.modules = [(14, 0x10000009, b"VendorName='Volkswagen AG' ModuleName='VAS6154A-STALE'"), VAS6154]
    api.connect_ok = {0x10000009, 0x10000001}  # both connect happily
    api.create_rc_for = {0x10000009: 0x01}  # but only the second one has a raw CAN channel

    bus = DPduBus(dll=api)
    assert api.connected == [0x10000009, 0x10000001]
    assert bus.module_label == "VAS6154A" and bus.hmod == 0x10000001 and not bus.spent
    bus.shutdown()


def test_the_last_module_refusing_raw_can_is_reported_in_words() -> None:
    set_lang("en")
    api = FakePduApi()
    api.modules = [SOFTING]  # no VW VCI on this PC at all
    api.connect_ok = {0x10000004}
    api.create_rc = 0x01  # not only 0x50: another vendor's driver answers 0x01 here
    with pytest.raises(can.CanError, match="VAS5054A#083600808.*raw CAN"):
        DPduBus(dll=api)
    assert api.destructed


def test_an_adapter_without_rawmode_falls_back_to_fixed_id_links() -> None:
    """Issue #12: a genuine VAS6154A refuses RawMode on every driver. Try the ODIS-style link instead, and only
    keep it when it actually carries a 10 03 — a wrong guess must end as "not supported", not half working."""
    set_lang("en")
    api = FakePduApi()
    api.rawmode_ok = False

    bus = DPduBus(dll=api)
    assert bus.nonraw and sorted(bus.nonraw) == [0x6F0, 0x710]  # both pairs opened
    assert {v["phys"] for v in api.nonraw_links.values()} >= {0x710, 0x6F0}  # ids really written to the URID table
    res = can_identify("", bus=bus)  # the whole UDS stack now runs over the fallback
    assert {i["did"]: i["value"] for i in res["ident"]}["F187"] == "3Q0907530AA"
    bus.shutdown()


def test_a_frame_to_an_id_the_fallback_has_no_link_for_is_refused() -> None:
    set_lang("en")
    api = FakePduApi()
    api.rawmode_ok = False
    bus = DPduBus(dll=api)
    with pytest.raises(can.CanError, match="only on identifiers"):
        bus.send(can.Message(arbitration_id=0x123, data=bytes(8), is_extended_id=False))
    bus.shutdown()


def test_a_fallback_link_that_opens_but_carries_nothing_is_refused(monkeypatch) -> None:
    """Opening proves nothing. If 10 03 brings nothing back, the adapter is reported unsupported rather than
    left half working — that is the whole point of verifying instead of guessing."""
    set_lang("en")
    monkeypatch.setattr(dpdu, "NONRAW_VERIFY_WAIT", 0.2)
    api = FakePduApi()
    api.rawmode_ok = False
    api.nonraw_silent = True
    with pytest.raises(can.CanError, match="no raw CAN channel"):
        DPduBus(dll=api)
    assert api.destructed


def test_an_adapter_that_gives_neither_rawmode_nor_the_fallback_reports_the_refusal() -> None:
    set_lang("en")
    api = FakePduApi()
    api.rawmode_ok = api.nonraw_ok = False
    with pytest.raises(can.CanError, match="no raw CAN channel"):
        DPduBus(dll=api)
    assert api.destructed


def test_closing_never_pulls_the_handles_out_from_under_a_running_operation(monkeypatch) -> None:
    """Quitting mid-write: PDUDisconnect/PDUDestruct while a worker sits in a ctypes call takes the driver down."""
    api = FakePduApi()
    monkeypatch.setattr(dpdu, "CLOSE_WAIT", 0.1)
    monkeypatch.setattr(dpdu, "DPduBus", lambda channel, bitrate: DPduBus(channel, bitrate, dll=api))
    bus = dpdu.open_session("")  # claimed, as by a running operation

    dpdu.close_session()
    assert not api.destructed  # left alone…
    assert bus.spent  # …but never handed to anyone again

    dpdu.release_session(bus)
    bus.shutdown()
    assert api.destructed


def test_a_link_that_saw_a_vci_error_is_not_handed_out_again(monkeypatch) -> None:
    api = FakePduApi()
    monkeypatch.setattr(dpdu, "DPduBus", lambda channel, bitrate: DPduBus(channel, bitrate, dll=api))
    bus = dpdu.open_session("")
    bus.spent = True  # set wherever the VCI drops a link or refuses a frame
    dpdu.release_session(bus)
    assert dpdu.open_session("") is not bus
    dpdu.close_session()
