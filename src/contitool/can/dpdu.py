"""VAS 6154 / VNCI 6154A through the VW D-PDU API (ISO 22900-2) as a python-can bus. Windows only.

Verified with a VNCI 6154A and the 64-bit PDUAPI_VW.dll: a plain raw-CAN link sends but never receives.
What works is two links on the raw-CAN resource of pins 6/14:
  * TX link: CllCreateFlag 80 00 00 00 (RawMode), STARTCOMM with 0 send cycles, then one SENDRECV per frame
    (1 send, 0 receives) whose data is the 4-byte big-endian CAN ID followed by the payload;
  * RX link: CllCreateFlag 80 00 00 01 (RawMode + monitor, as the driver's own CAN trace opens it),
    CP_MonitoredChannels/CP_DataPacketSize/CP_CollectTimeout/CP_Baudrate, then a SENDRECV with 0 sends and -1
    receives. The exported API needs at least one expected response there; an accept-anything one is enough.
    Every bus frame arrives as a result: 4-byte ID + data; RxFlag byte 3 bit 0 = our own frame, byte 2 bit 0 = 29-bit.
Note: PDUModuleConnect lets the VW driver update the VCI firmware when its version differs (about 30 s, once).
"""

from __future__ import annotations

import collections
import ctypes as C
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import can

from contitool.i18n import tr

U32, S32, U8 = C.c_uint32, C.c_int32, C.c_uint8

RAWCAN_OBD6_14 = 0x30030003  # MDF_VW resource VAS6154_RAWCAN_CAN1_HS_OBD6_14 (VAS6154 and VAS6154A)
COPT_STARTCOMM, COPT_STOPCOMM, COPT_SENDRECV = 0x8001, 0x8002, 0x8004
IT_RESULT, IT_STATUS, IT_ERROR, IT_PARAM = 0x1300, 0x1301, 0x1302, 0x1200
PT_UNUM32 = 0x105
ERR_EVENT_QUEUE_EMPTY = 0x71
ERR_TX_QUEUE_FULL = 0x70
CLLST_OFFLINE = 0x8050
COPST_DONE = (0x8012, 0x8013)  # FINISHED, CANCELLED
# One frame at a time. Every frame is a primitive the VCI runs about every 4 ms. When its firmware queue overflows
# ("Rx Firmware Cop-Queue full", seen with ~50 queued and also at a depth of only 14 while frames streamed in) the
# driver re-sends that frame later, out of order (0x2f8 went out 107 ms after 0x2f9), which broke the RAM-loader
# payload and the ECU reset. Waiting for each FINISHED keeps the order; it costs ~10 % on a read.
# Raise to 2-4 only after reads at that setting give byte-identical dumps.
MAX_TX_IN_FLIGHT = 1
MODULE_READY = (0x8060, 0x8063)  # MODST_READY, MODST_AVAIL
# Monitor ComParams (id, class, value) exactly as PDUAPI_VW.dll's CMonitor2Logfile sets them, except the collect time:
# 1000 ms suits a log file; 10 ms hands every frame over right away (the gateway answers ~0.6 ms after a request).
MONITOR_PARAMS = ((165, 2, 1), (163, 3, 2300), (164, 1, 10))  # CP_MonitoredChannels=CAN1, CP_DataPacketSize, CP_CollectTimeout
CP_BAUDRATE = 126


class FlagData(C.Structure):
    _fields_ = [("NumFlagBytes", U32), ("pFlagData", C.POINTER(U8))]


class ModuleData(C.Structure):
    _fields_ = [("ModuleTypeId", U32), ("hMod", U32), ("pVendorModuleName", C.c_char_p),
                ("pVendorAdditionalInfo", C.c_char_p), ("ModuleStatus", U32)]


class ModuleItem(C.Structure):
    _fields_ = [("ItemType", U32), ("NumEntries", U32), ("pModuleData", C.POINTER(ModuleData))]


class ParamItem(C.Structure):
    _fields_ = [("ItemType", U32), ("ComParamId", U32), ("ComParamDataType", U32), ("ComParamClass", U32),
                ("pComParamData", C.c_void_p)]


class ExpResp(C.Structure):
    _fields_ = [("ResponseType", U32), ("AcceptanceId", U32), ("NumMaskPatternBytes", U32),
                ("pMaskData", C.POINTER(U8)), ("pPatternData", C.POINTER(U8)), ("NumUniqueRespIds", U32),
                ("pUniqueRespIds", C.POINTER(U32))]


class CopCtrl(C.Structure):
    _fields_ = [("Time", U32), ("NumSendCycles", S32), ("NumReceiveCycles", S32), ("TempParamUpdate", U32),
                ("TxFlag", FlagData), ("NumPossibleExpectedResponses", U32),
                ("pExpectedResponseArray", C.POINTER(ExpResp))]


class EventItem(C.Structure):
    _fields_ = [("ItemType", U32), ("hCop", U32), ("pCoPTag", C.c_void_p), ("Timestamp", U32), ("pData", C.c_void_p)]


class ResultData(C.Structure):
    _fields_ = [("RxFlag", FlagData), ("UniqueRespIdentifier", U32), ("AcceptanceId", U32),
                ("TimestampFlags", FlagData), ("TxMsgDoneTimestamp", U32), ("StartMsgTimestamp", U32),
                ("pExtraInfo", C.c_void_p), ("NumDataBytes", U32), ("pDataBytes", C.POINTER(U8))]


def discover_dpdu() -> list[dict[str, str]]:
    """64-bit D-PDU APIs from the root file named in HKLM\\SOFTWARE\\D-PDU API ("Root File"); ODIS-E's first."""
    if sys.platform != "win32":
        return []
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\D-PDU API", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            root_file = str(winreg.QueryValueEx(key, "Root File")[0])
        root = ET.parse(root_file).getroot()
    except (OSError, ET.ParseError):
        return []
    apis = []
    for node in root.iter("MVCI_PDU_API"):
        lib = node.find("LIBRARY_FILE")
        dll = (lib.get("URI", "") if lib is not None else "").replace("file:///", "").replace("file:/", "")
        dll = dll.replace("%20", " ")
        if dll and Path(dll).exists():
            apis.append({"name": node.findtext("SHORT_NAME", ""), "dll": dll})
    return sorted(apis, key=lambda a: not a["name"].upper().endswith("_OE"))


class DPduBus(can.BusABC):
    """Raw CAN on CAN1 (OBD pins 6/14) of a VAS 6154 / VNCI. `channel` picks a D-PDU API by (part of) its name."""

    def __init__(self, channel: str = "", bitrate: int = 500_000, *, dll: Any = None, module_wait: float = 15.0,
                 **kwargs: Any) -> None:
        if dll is None:
            apis = [a for a in discover_dpdu() if not channel or channel.upper() in a["name"].upper()]
            if not apis:
                raise RuntimeError(tr("D-PDU API (VAS 6154 / VNCI) не найден: установите драйвер VAS 6154 из ODIS.",
                                      "No D-PDU API (VAS 6154 / VNCI) found: install the VAS 6154 driver from ODIS."))
            channel = apis[0]["name"]
            dll = C.WinDLL(apis[0]["dll"])  # type: ignore[attr-defined]
        self._dll = dll
        self._pending: collections.deque[can.Message] = collections.deque()
        self._tx_in_flight: set[int] = set()
        self.hmod = self.h_rx = self.h_tx = 0
        self._call("PDUConstruct", None, None)
        try:
            self.hmod = self._find_module(module_wait)
            self._call("PDUModuleConnect", self.hmod)
            self.h_rx = self._open_monitor(bitrate)
            self.h_tx = self._create((0x80, 0, 0, 0))
            self._call("PDUConnect", self.hmod, self.h_tx)
            self._start(self.h_tx, COPT_STARTCOMM, b"", 0, 0)
        except Exception:
            self._teardown()
            raise
        self.channel_info = f"D-PDU {channel}"
        super().__init__(channel=channel, **kwargs)

    # ------------------------------------------------------------------ driver calls
    def _call(self, fn: str, *args: Any, also_ok: tuple[int, ...] = ()) -> int:
        rc = getattr(self._dll, fn)(*args)
        if rc not in (0, ERR_EVENT_QUEUE_EMPTY, *also_ok):
            raise can.CanOperationError(f"{fn}: D-PDU error 0x{rc:02X}")
        return rc

    def _find_module(self, wait: float) -> int:
        end = time.monotonic() + wait
        while True:
            items = C.POINTER(ModuleItem)()
            self._call("PDUGetModuleIds", C.byref(items))
            ready = []
            if items:
                ready = [items.contents.pModuleData[i].hMod for i in range(items.contents.NumEntries)
                         if items.contents.pModuleData[i].ModuleStatus in MODULE_READY]
                self._dll.PDUDestroyItem(items)
            if ready:
                return ready[0]
            if time.monotonic() > end:
                raise can.CanInitializationError(tr("VAS 6154 / VNCI не найден: подключён ли он и закрыт ли ODIS?",
                                                    "VAS 6154 / VNCI not found: is it plugged in and ODIS closed?"))
            time.sleep(0.5)

    def _create(self, flags: tuple[int, int, int, int]) -> int:
        h, fl = U32(0), (U8 * 4)(*flags)
        self._call("PDUCreateComLogicalLink", self.hmod, None, RAWCAN_OBD6_14, None, C.byref(h), C.byref(FlagData(4, fl)))
        return h.value

    def _set_u32(self, hcll: int, param_id: int, cls: int, value: int) -> None:
        v = U32(value)
        item = ParamItem(IT_PARAM, param_id, PT_UNUM32, cls, C.cast(C.pointer(v), C.c_void_p))
        self._call("PDUSetComParam", self.hmod, hcll, C.byref(item))

    def _open_monitor(self, bitrate: int) -> int:
        h = self._create((0x80, 0, 0, 0x01))
        for param_id, cls, value in MONITOR_PARAMS:
            self._set_u32(h, param_id, cls, value)
        self._set_u32(h, CP_BAUDRATE, 5, bitrate)
        self._call("PDUConnect", self.hmod, h)
        self._start(h, COPT_SENDRECV, b"", 0, -1, accept_any=True)
        return h

    def _start(self, hcll: int, cop: int, data: bytes, send: int, recv: int, *, accept_any: bool = False,
               tx_flag: tuple[int, int, int, int] = (0, 0, 0, 0), also_ok: tuple[int, ...] = ()) -> tuple[int, int]:
        tx = (U8 * 4)(*tx_flag)
        ctrl = CopCtrl(0, send, recv, 0, FlagData(4, tx))
        mask = pattern = resp = None
        if accept_any:
            mask, pattern = (U8 * 1)(0), (U8 * 1)(0)
            resp = ExpResp(0, 1, 1, mask, pattern, 0, None)
            ctrl.NumPossibleExpectedResponses, ctrl.pExpectedResponseArray = 1, C.pointer(resp)
        buf = (U8 * len(data)).from_buffer_copy(data) if data else None
        hcop = U32(0)
        rc = self._call("PDUStartComPrimitive", self.hmod, hcll, cop, len(data), buf, C.byref(ctrl), None,
                        C.byref(hcop), also_ok=also_ok)
        return rc, hcop.value

    # ------------------------------------------------------------------ events
    def _drain(self, hcll: int) -> bool:
        """Take every queued event of one link; results of the monitor link become messages. True if any arrived."""
        got = False
        while True:
            item = C.POINTER(EventItem)()
            rc = self._call("PDUGetEventItem", self.hmod, hcll, C.byref(item))
            if rc == ERR_EVENT_QUEUE_EMPTY or not item:
                return got
            got = True
            try:
                ev = item.contents
                if ev.ItemType == IT_STATUS and ev.pData and C.cast(ev.pData, C.POINTER(U32)).contents.value == CLLST_OFFLINE:
                    raise can.CanOperationError(tr("VCI закрыл канал D-PDU", "The VCI closed the D-PDU link"))
                if hcll == self.h_rx and ev.ItemType == IT_RESULT and ev.pData:
                    self._take_result(C.cast(ev.pData, C.POINTER(ResultData)).contents)
                elif hcll == self.h_tx and ev.ItemType == IT_STATUS and ev.pData:
                    if C.cast(ev.pData, C.POINTER(U32)).contents.value in COPST_DONE:
                        self._tx_in_flight.discard(ev.hCop)
                elif hcll == self.h_tx and ev.ItemType == IT_ERROR:
                    # a frame the VCI could not send (e.g. its queue overflowed): fail now, not by a later timeout
                    self._tx_in_flight.discard(ev.hCop)
                    raise can.CanOperationError(tr("VCI не смог отправить кадр", "The VCI could not send a frame"))
            finally:
                self._dll.PDUDestroyItem(item)

    def _take_result(self, r: ResultData) -> None:
        raw = bytes(r.pDataBytes[: min(r.NumDataBytes, 4128)]) if r.NumDataBytes else b""
        flags = bytes(r.RxFlag.pFlagData[: r.RxFlag.NumFlagBytes]) if r.RxFlag.NumFlagBytes else b""
        if len(flags) >= 4 and flags[3] & 0x01:
            return  # the VCI's echo of a frame we sent
        # One result = one frame: 4-byte BE ID + payload, with no length field. Frames of different
        # lengths (the loader also sends 2..5-byte frames) could not be packed unambiguously, so anything longer
        # than one classic frame is an error to retry, never something to guess-split into wrong data.
        if len(raw) < 4:
            return
        if len(raw) > 12:
            raise can.CanOperationError(
                tr(f"D-PDU: неожиданный результат {len(raw)} Б (больше одного кадра CAN)",
                   f"D-PDU: unexpected {len(raw)}-byte result (more than one CAN frame)")
            )
        self._pending.append(can.Message(
            timestamp=time.time(),
            arbitration_id=int.from_bytes(raw[:4], "big") & 0x1FFFFFFF,
            is_extended_id=len(flags) >= 3 and bool(flags[2] & 0x01),
            data=raw[4:],
        ))

    def _recv_internal(self, timeout: float | None) -> tuple[can.Message | None, bool]:
        end = None if timeout is None else time.monotonic() + timeout
        while not self._pending:
            self._drain(self.h_tx)  # keeps the send link's status events from piling up
            if self._drain(self.h_rx) or self._pending:
                continue
            if end is not None and time.monotonic() >= end:
                return None, False
            time.sleep(0.0005)
        return self._pending.popleft(), False

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        payload = msg.arbitration_id.to_bytes(4, "big") + bytes(msg.data)
        # 29-bit sending mirrors the RxFlag layout (byte 2 bit 0); only 11-bit sending is verified on hardware
        flag = (0, 0, 1 if msg.is_extended_id else 0, 0)
        end = time.monotonic() + (2.0 if timeout is None else timeout)
        while True:
            self._drain(self.h_tx)
            if len(self._tx_in_flight) < MAX_TX_IN_FLIGHT:
                rc, hcop = self._start(self.h_tx, COPT_SENDRECV, payload, 1, 0, tx_flag=flag,
                                       also_ok=(ERR_TX_QUEUE_FULL,))
                if rc == 0:
                    self._tx_in_flight.add(hcop)
                    return
            if time.monotonic() > end:
                raise can.CanOperationError(tr("D-PDU: очередь отправки VCI переполнена", "D-PDU: the VCI send queue is full"))
            time.sleep(0.0005)

    def _teardown(self) -> None:
        for h in (self.h_rx, self.h_tx):
            if h:
                for fn, args in (("PDUDisconnect", (self.hmod, h)), ("PDUDestroyComLogicalLink", (self.hmod, h))):
                    try:
                        getattr(self._dll, fn)(*args)
                    except Exception:  # noqa: BLE001 - closing must not raise over the original error
                        pass
        if self.hmod:
            self._dll.PDUModuleDisconnect(self.hmod)
        self._dll.PDUDestruct()
        self.hmod = self.h_rx = self.h_tx = 0

    def shutdown(self) -> None:
        if self._is_shutdown:
            return
        super().shutdown()
        self._teardown()
