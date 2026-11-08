"""VAS 6154 / VNCI 6154A through the VW D-PDU API (ISO 22900-2) as a python-can bus. Windows only.

Verified with a VNCI 6154A and the 64-bit PDUAPI_VW.dll: a plain raw-CAN link sends but never receives.
What works is two links on the raw-CAN resource of pins 6/14:
  * TX link: CllCreateFlag 80 00 00 00 (RawMode), STARTCOMM with 0 send cycles, then one SENDRECV per frame
    (1 send, 0 receives) whose data is the 4-byte big-endian CAN ID followed by the payload;
  * RX link: CllCreateFlag 80 00 00 01 (RawMode + monitor, as the driver's own CAN trace opens it),
    CP_MonitoredChannels/CP_DataPacketSize/CP_CollectTimeout/CP_Baudrate, then a SENDRECV with 0 sends and -1
    receives. The exported API needs at least one expected response there; an accept-anything one is enough.
    Every bus frame arrives as a result: 4-byte ID + data; RxFlag byte 3 bit 0 = our own frame, byte 2 bit 0 = 29-bit.
Closing follows the driver's own CAN trace (CMonitor2Logfile, 27.2 and 31.0): cancel the monitor primitive, then
disconnect and destroy; the send link gets STOPCOMM first, as ODIS does. Without that, drivers 30.x left the VCI with
a stale monitor and every second session died 2 s after the monitor PDUConnect (PDU_ERR_COMM_PC_TO_VCI_FAILED).
Note: PDUModuleConnect lets the VW driver reflash the VCI to its own version (about 30 s), so the driver version is
checked before that: only versions known to work run without an explicit confirmation.
"""

from __future__ import annotations

import atexit
import collections
import ctypes as C
import sys
import threading
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
ERR_COMM_PC_TO_VCI_FAILED = 0x11  # the VCI dropped the connection (it restarts its service in ~3 s)
ERR_EVENT_QUEUE_EMPTY = 0x71
ERR_TX_QUEUE_FULL = 0x70
ERR_FCT_FAILED = 0x01  # "the call failed": from PDUModuleConnect it is a module whose own service did not answer
ERR_INVALID_PARAMETERS = 0x50
VW_MODULE_TYPE_ID = 14  # a Volkswagen VCI (VAS 6154 / 6154A); 12 is some other vendor's J2534 driver
VCI_RESTART_WAIT = 4.0
# Driver versions (major.minor) that run without asking: 27.2 is verified on hardware (backup + write);
# 31.0/31.1 is what ODIS installs today. Others reflash the VCI and need the user's explicit go-ahead.
SUPPORTED_DRIVERS = ("27.2", "31.0", "31.1")
accepted_drivers: set[str] = set()  # other versions the user confirmed in this run
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
# The receive thread polls this fast while frames keep coming, and backs off to the second value when the bus is
# quiet. CP_CollectTimeout above already batches for 10 ms, so a 2 ms idle poll costs nothing in latency.
RX_POLL, RX_IDLE_POLL = 0.0005, 0.002
# Frames waiting to be handed to a caller. A full 500 kbit/s bus is ~4000 frames/s and the largest burst we ever
# read is one 4 KB loader chunk (512 frames), so this only ever matters if nobody reads for seconds — an idle link
# kept open between operations. Same bound as the terminal's own trace.
RX_QUEUE_MAX = 50_000


CLOSE_WAIT = 3.0  # how long close_session waits for a running operation to hand the link back


class FrameError(can.CanOperationError):
    """A result we refuse to interpret. The read is retried (`read_memory_area` does); the link itself is fine."""


def _is_x64_dll(path: Path) -> bool:
    """PE machine type: the VW package ships both builds, and only a 64-bit one loads into our process."""
    try:
        with path.open("rb") as fh:
            if fh.read(2) != b"MZ":
                return False
            fh.seek(0x3C)
            fh.seek(int.from_bytes(fh.read(4), "little"))
            if fh.read(4) != b"PE\0\0":
                return False
            return int.from_bytes(fh.read(2), "little") in (0x8664, 0xAA64)  # IMAGE_FILE_MACHINE_AMD64 / ARM64
    except OSError:
        return False


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


def dll_version(path: str) -> str:
    """File version of a DLL ("31.0.0"), or "" if Windows does not report one."""
    try:
        ver = C.windll.version  # type: ignore[attr-defined]
        size = ver.GetFileVersionInfoSizeW(path, None)
        buf = C.create_string_buffer(size)
        info, n = C.c_void_p(), C.c_uint()
        if not size or not ver.GetFileVersionInfoW(path, 0, size, buf) or not ver.VerQueryValueW(buf, "\\", C.byref(info), C.byref(n)):
            return ""
        fixed = C.cast(info, C.POINTER(U32 * 4)).contents  # VS_FIXEDFILEINFO: signature, struc version, MS, LS
        return f"{fixed[2] >> 16}.{fixed[2] & 0xFFFF}.{fixed[3] >> 16}"
    except (AttributeError, OSError):
        return ""


def driver_supported(version: str) -> bool:
    return ".".join(version.split(".")[:2]) in SUPPORTED_DRIVERS or version in accepted_drivers


def check_driver(version: str) -> None:
    """Refuse a driver version nobody confirmed before PDUModuleConnect gets the chance to reflash the VCI."""
    if not driver_supported(version):
        shown = version or "?"
        raise can.CanInitializationError(tr(
            f"Драйвер D-PDU {shown} не проверен с ContiTool (проверены {', '.join(SUPPORTED_DRIVERS)}). При подключении он "
            "перепрошьёт VCI под свою версию. Установите поддерживаемую версию или подтвердите этот драйвер в окне «Подключение».",
            f"D-PDU driver {shown} is not verified with ContiTool (verified: {', '.join(SUPPORTED_DRIVERS)}). On connect it "
            "reflashes the VCI to its own version. Install a supported version or confirm this driver in the Connection dialog.",
        ))


def bundled_dpdu_dir() -> Path:
    """`dpdu/` next to the ContiTool executable (the repo root when run from source).

    A D-PDU driver folder copied in there is used as it is, with no installer run and no registry entry — for a PC
    where the driver is not installed, or where the installed one does not talk to this adapter. ContiTool ships no
    driver itself: the files are Volkswagen's, so the user puts their own copy there."""
    root = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[3]
    return root / "dpdu"


def discover_dpdu() -> list[dict[str, str]]:
    """64-bit D-PDU APIs: whatever sits in `dpdu/` next to ContiTool first, then the installed ones from the root
    file named in HKLM\\SOFTWARE\\D-PDU API ("Root File"), ODIS-E's first."""
    if sys.platform != "win32":
        return []
    folder = bundled_dpdu_dir()
    found: list[dict[str, str]] = []
    for dll in sorted(folder.rglob("PDUAPI*.dll")) if folder.is_dir() else []:
        if not _is_x64_dll(dll):
            continue  # the 32-bit build of the same package must not shadow a working 64-bit driver
        name = f"ContiTool · {dll.parent.name}"
        if any(a["name"] == name for a in found):  # several DLLs in one folder still need separate rows
            name = f"{name}/{dll.stem}"
        found.append({"name": name, "dll": str(dll), "version": dll_version(str(dll))})
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\D-PDU API", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            root_file = str(winreg.QueryValueEx(key, "Root File")[0])
        root = ET.parse(root_file).getroot()
    except (OSError, ImportError, ET.ParseError):
        return found
    apis = []
    for node in root.iter("MVCI_PDU_API"):
        lib = node.find("LIBRARY_FILE")
        dll = (lib.get("URI", "") if lib is not None else "").replace("file:///", "").replace("file:/", "")
        dll = dll.replace("%20", " ")
        if dll and Path(dll).exists():
            apis.append({"name": node.findtext("SHORT_NAME", ""), "dll": dll, "version": dll_version(dll)})
    return found + sorted(apis, key=lambda a: not a["name"].upper().endswith("_OE"))


class DPduBus(can.BusABC):
    """Raw CAN on CAN1 (OBD pins 6/14) of a VAS 6154 / VNCI. `channel` picks a D-PDU API by (part of) its name."""

    def __init__(self, channel: str = "", bitrate: int = 500_000, *, dll: Any = None, module_wait: float = 15.0,
                 **kwargs: Any) -> None:
        self.channel_key, self.bitrate = channel, bitrate  # what open_session matches a kept-open link against
        self.spent = False  # a VCI or link error happened: this link must not be handed to the next operation
        self.claimed = False
        self.module_label = ""
        if dll is None:
            apis = [a for a in discover_dpdu() if not channel or channel.upper() in a["name"].upper()]
            # The driver the user picked wins over one whose name merely contains it (…_OE vs …_OE_2).
            apis = [a for a in apis if a["name"].upper() == channel.upper()] or apis
            if not apis:
                raise RuntimeError(tr(
                    "D-PDU API (VAS 6154 / VNCI) не найден. Поставьте драйвер «VW D-PDU API» (отдельный пакет, "
                    "ODIS для него не нужен) или положите свою копию его папки в dpdu/ рядом с ContiTool.",
                    "No D-PDU API (VAS 6154 / VNCI) found. Install the \"VW D-PDU API\" driver (a standalone package, "
                    "it does not need ODIS) or copy your own copy of its folder into dpdu/ next to ContiTool.",
                ))
            channel = apis[0]["name"]
            check_driver(apis[0]["version"])
            try:
                dll = C.WinDLL(apis[0]["dll"])  # type: ignore[attr-defined]
            except OSError as exc:  # a 32-bit driver gives a bare "[WinError 193] not a valid Win32 application"
                raise can.CanInitializationError(tr(
                    f"Драйвер D-PDU не загрузился: {apis[0]['dll']} ({exc}). Нужна 64-разрядная версия "
                    "(VW_D-PDU_API_Win_x64), 32-разрядная не подходит.",
                    f"The D-PDU driver did not load: {apis[0]['dll']} ({exc}). It must be the 64-bit build "
                    "(VW_D-PDU_API_Win_x64); a 32-bit one cannot be used.",
                )) from exc
        self._dll = dll
        self._pending: collections.deque[can.Message] = collections.deque(maxlen=RX_QUEUE_MAX)
        self._tx_in_flight: set[int] = set()
        self.hmod = self.h_rx = self.h_tx = self._mon_cop = 0
        self._tx_started = False
        self._stop = threading.Event()
        self._rx_thread: threading.Thread | None = None
        self._rx_error: BaseException | None = None
        for attempt in (1, 2):
            self._call("PDUConstruct", None, None)
            try:
                self._open(bitrate, module_wait)
                self.spent = False  # a failed first attempt set it; this link is healthy and may be kept
                break
            except can.CanError as exc:
                self._teardown()
                if attempt == 2 or exc.error_code != ERR_COMM_PC_TO_VCI_FAILED:
                    raise
                time.sleep(VCI_RESTART_WAIT)  # the session after a dropped one always connected in the logs
            except Exception:
                self._teardown()
                raise
        self.channel_info = f"D-PDU {channel}"
        super().__init__(channel=channel, **kwargs)
        self._stop.clear()  # a first attempt that failed went through _teardown, which sets it
        self._rx_thread = threading.Thread(target=self._rx_loop, name="dpdu-rx", daemon=True)
        self._rx_thread.start()

    def _open(self, bitrate: int, module_wait: float) -> None:
        self._connect_module(module_wait)
        self.h_rx = self._open_monitor(bitrate)
        self.h_tx = self._create((0x80, 0, 0, 0))
        self._call("PDUConnect", self.hmod, self.h_tx)
        self._start(self.h_tx, COPT_STARTCOMM, b"", 0, 0)
        self._tx_started = True

    # ------------------------------------------------------------------ receiving
    def _rx_loop(self) -> None:
        """Keep the monitor link drained for as long as the link is open.

        The driver queues every frame as an event on the logical link and waits for its owner to take it — ODIS
        hands it a callback for this, which is why its own log complains that ours is NULL. Draining only while an
        operation runs was fine while the link was closed in between; with the link kept open, a quiet period let
        the queue grow and the next operation had to chew through stale frames before its own answer. This thread
        owns the monitor link; the send link stays with the calling thread, which waits for each frame itself."""
        while not self._stop.is_set():
            try:
                busy = self._drain(self.h_rx)
            except FrameError as exc:
                # One result we would not interpret. The caller retries the read, so the link must stay up.
                self._rx_error, busy = exc, True
            except BaseException as exc:  # noqa: BLE001 - the link died; whoever asks next gets told
                self._rx_error = exc
                self.spent = True
                return
            self._stop.wait(RX_POLL if busy else RX_IDLE_POLL)

    def _check_rx(self) -> None:
        """Re-raise, in the caller's thread, whatever ended the receive thread."""
        if self._rx_error is not None:
            err, self._rx_error = self._rx_error, None
            raise err

    # ------------------------------------------------------------------ driver calls
    def _call(self, fn: str, *args: Any, also_ok: tuple[int, ...] = ()) -> int:
        rc = getattr(self._dll, fn)(*args)
        if rc not in (0, ERR_EVENT_QUEUE_EMPTY, *also_ok):
            self.spent = True
            raise can.CanOperationError(f"{fn}: D-PDU error 0x{rc:02X}", error_code=rc)
        return rc

    @staticmethod
    def _label(vendor_module_name: bytes | None) -> str:
        """`VendorName='X' ModuleName='Y' SerialNumber=…` → "Y", whatever the driver puts around it."""
        raw = (vendor_module_name or b"").decode("latin-1", "replace")
        _, mark, tail = raw.partition("ModuleName='")
        return tail.split("'", 1)[0] if mark else (raw.strip() or "?")

    def _modules(self, wait: float) -> list[tuple[int, str]]:
        """Ready modules as (hMod, name), VW VCIs first — never just the one the driver happens to list first.

        PDUGetModuleIds returns every D-PDU and J2534 driver installed on the PC, in an order that changes between
        calls: a user with 8 modules got them back as 7,5,2,3,1,4,6,8 with the VAS6154A fifth. Connecting the first
        one reached another vendor's J2534 service on 127.0.0.1:4500, which refused it (PDU_ERR_FCT_FAILED), so the
        same PC worked or failed depending on the order. Modules of other vendors are tried only when no VW VCI is
        there at all: our raw-CAN resource is a VAS 6154 one, so for them a clear error is the best outcome."""
        end = time.monotonic() + wait
        while True:
            items = C.POINTER(ModuleItem)()
            self._call("PDUGetModuleIds", C.byref(items))
            vw: list[tuple[int, str]] = []
            other: list[tuple[int, str]] = []
            if items:
                for i in range(items.contents.NumEntries):
                    m = items.contents.pModuleData[i]
                    if m.ModuleStatus not in MODULE_READY:
                        continue
                    raw = (m.pVendorModuleName or b"").decode("latin-1", "replace")
                    entry = (m.hMod, self._label(m.pVendorModuleName))
                    (vw if m.ModuleTypeId == VW_MODULE_TYPE_ID or "Volkswagen" in raw else other).append(entry)
                self._dll.PDUDestroyItem(items)
            if vw or other:
                return vw or other
            if time.monotonic() > end:
                raise can.CanInitializationError(tr("VAS 6154 / VNCI не найден: подключён ли он и закрыт ли ODIS?",
                                                    "VAS 6154 / VNCI not found: is it plugged in and ODIS closed?"))
            time.sleep(0.5)

    def _connect_module(self, wait: float) -> None:
        """Connect the first module that accepts it, so one unreachable driver cannot hide the VCI behind itself."""
        tried: list[str] = []
        failure = ERR_FCT_FAILED
        for hmod, name in self._modules(wait):
            self.hmod = hmod
            try:
                if self._call("PDUModuleConnect", hmod, also_ok=(ERR_FCT_FAILED,)) == 0:
                    self.module_label = name
                    return
            except can.CanError as exc:
                # Whatever this module answered, the next one still gets its turn — otherwise one driver that
                # fails in an unexpected way keeps hiding the VCI listed behind it.
                failure = exc.error_code or failure
                self.spent = False
            self._dll.PDUModuleDisconnect(hmod)  # the API holds the failed attempt open otherwise
            self.hmod = 0
            tried.append(name)
        raise can.CanInitializationError(
            tr(
                f"Ни один модуль D-PDU не принял подключение (пробовали: {', '.join(tried)}). Включите VCI и "
                "закройте ODIS; если в списке адаптеров есть другой драйвер D-PDU, выберите его.",
                f"No D-PDU module accepted the connection (tried: {', '.join(tried)}). Switch the VCI on and close "
                "ODIS; if the adapter list offers another D-PDU driver, pick that one.",
            ),
            error_code=failure,  # a VCI that dropped the link (0x11) still gets the one retry __init__ does
        )

    def _create(self, flags: tuple[int, int, int, int]) -> int:
        h, fl = U32(0), (U8 * 4)(*flags)
        if self._call("PDUCreateComLogicalLink", self.hmod, None, RAWCAN_OBD6_14, None, C.byref(h),
                      C.byref(FlagData(4, fl)), also_ok=(ERR_INVALID_PARAMETERS,)):
            raise can.CanInitializationError(
                tr(
                    f"Модуль «{self.module_label}» не даёт сырой канал CAN: ресурс 0x{RAWCAN_OBD6_14:08X} есть "
                    "только у VAS 6154 / VNCI. Для другого адаптера выберите в списке J2534.",
                    f"Module “{self.module_label}” gives no raw CAN channel: resource 0x{RAWCAN_OBD6_14:08X} exists "
                    "only on a VAS 6154 / VNCI. For another adapter pick J2534 in the list instead.",
                ),
                error_code=ERR_INVALID_PARAMETERS,
            )
        return h.value

    def _set_u32(self, hcll: int, param_id: int, cls: int, value: int) -> None:
        v = U32(value)
        item = ParamItem(IT_PARAM, param_id, PT_UNUM32, cls, C.cast(C.pointer(v), C.c_void_p))
        self._call("PDUSetComParam", self.hmod, hcll, C.byref(item))

    def _open_monitor(self, bitrate: int) -> int:
        h = self.h_rx = self._create((0x80, 0, 0, 0x01))  # set at once: a failure from here on still closes it
        for param_id, cls, value in MONITOR_PARAMS:
            self._set_u32(h, param_id, cls, value)
        self._set_u32(h, CP_BAUDRATE, 5, bitrate)
        self._call("PDUConnect", self.hmod, h)
        _, self._mon_cop = self._start(h, COPT_SENDRECV, b"", 0, -1, accept_any=True)
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
                    self.spent = True
                    raise can.CanOperationError(tr("VCI закрыл канал D-PDU", "The VCI closed the D-PDU link"))
                if hcll == self.h_rx and ev.ItemType == IT_RESULT and ev.pData:
                    self._take_result(C.cast(ev.pData, C.POINTER(ResultData)).contents)
                elif hcll == self.h_tx and ev.ItemType == IT_STATUS and ev.pData:
                    if C.cast(ev.pData, C.POINTER(U32)).contents.value in COPST_DONE:
                        self._tx_in_flight.discard(ev.hCop)
                elif hcll == self.h_tx and ev.ItemType == IT_ERROR:
                    # a frame the VCI could not send (e.g. its queue overflowed): fail now, not by a later timeout
                    self._tx_in_flight.discard(ev.hCop)
                    self.spent = True
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
            raise FrameError(
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
            self._check_rx()  # the receive thread fills the queue; it only stops on a dead link
            if end is not None and time.monotonic() >= end:
                return None, False
            time.sleep(RX_POLL)
        return self._pending.popleft(), False

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        payload = msg.arbitration_id.to_bytes(4, "big") + bytes(msg.data)
        # 29-bit sending mirrors the RxFlag layout (byte 2 bit 0); only 11-bit sending is verified on hardware
        flag = (0, 0, 1 if msg.is_extended_id else 0, 0)
        end = time.monotonic() + (2.0 if timeout is None else timeout)
        while True:
            self._check_rx()
            self._drain(self.h_tx)
            if len(self._tx_in_flight) < MAX_TX_IN_FLIGHT:
                rc, hcop = self._start(self.h_tx, COPT_SENDRECV, payload, 1, 0, tx_flag=flag,
                                       also_ok=(ERR_TX_QUEUE_FULL,))
                if rc == 0:
                    self._tx_in_flight.add(hcop)
                    return
            if time.monotonic() > end:
                self.spent = True
                raise can.CanOperationError(tr("D-PDU: очередь отправки VCI переполнена", "D-PDU: the VCI send queue is full"))
            time.sleep(0.0005)

    def _stop_links(self) -> None:
        """STOPCOMM on the send link (waiting for it like ODIS does), then cancel the monitor primitive."""
        if self._tx_started:
            self._tx_started = False
            try:
                _, cop = self._start(self.h_tx, COPT_STOPCOMM, b"", 0, 0)
                self._tx_in_flight.add(cop)
                end = time.monotonic() + 1.0
                while cop in self._tx_in_flight and time.monotonic() < end:
                    self._drain(self.h_tx)
                    time.sleep(0.001)
            except Exception:  # noqa: BLE001 - closing goes on whatever the VCI says
                pass
        if self._mon_cop:
            try:
                self._dll.PDUCancelComPrimitive(self.hmod, self.h_rx, self._mon_cop)
            except Exception:  # noqa: BLE001
                pass
            self._mon_cop = 0

    def _teardown(self) -> None:
        self._stop.set()  # before the links go: the receive thread must not poll a handle that is being destroyed
        if self._rx_thread is not None:
            self._rx_thread.join(timeout=2.0)
            self._rx_thread = None
        self._stop_links()
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
        self._tx_in_flight.clear()

    def claim(self) -> None:
        """Take the kept-open link for one operation: two at once would interleave their frames."""
        if self.claimed:
            raise can.CanOperationError(tr("Адаптер D-PDU занят другой операцией",
                                           "The D-PDU adapter is busy with another operation"))
        self.claimed = True
        try:
            self._check_rx()  # the link may have died while no operation was using it
        except BaseException:  # noqa: BLE001 - `spent` is set, so open_session opens a fresh link instead
            pass
        self._pending.clear()  # bus traffic recorded while nobody was asking for it

    def shutdown(self) -> None:
        if self._is_shutdown:
            return
        super().shutdown()
        self._teardown()


# ------------------------------------------------------------------ the one kept-open link of this process
_session: DPduBus | None = None


def open_session(channel: str = "", bitrate: int = 500_000) -> DPduBus:
    """The process's D-PDU link, opened once and kept open between operations.

    Opening asks the driver for its module list again, and that list comes back in a different order every time, so
    closing the link after each operation re-rolled which module gets connected — hence reports of "works only
    after a restart" and "works only while the CAN monitor is open". The driver also spends seconds enumerating its
    own log files on each PDUConstruct. `release_session()` hands the link back, `close_session()` really closes it."""
    global _session
    live = _session
    if live is not None and not live.spent and (live.channel_key, live.bitrate) == (channel, bitrate):
        live.claim()  # which also notices a link that died while it was idle
        if not live.spent:
            return live
    close_session()
    bus = DPduBus(channel, bitrate)
    bus.claim()
    _session = bus
    return bus


def release_session(bus: DPduBus) -> None:
    """An operation finished with the link it borrowed; the next one reuses it."""
    bus.claimed = False


def close_session() -> None:
    """Really close the kept link: the adapter changed, or the program is quitting.

    An operation can still hold the link — the user may quit in the middle of a flash write. Destroying the
    driver's handles under a worker thread that sits inside a ctypes call takes the driver down with it, so wait
    for the operation and, if it will not let go, leave its handles alone and let the process exit drop them."""
    global _session
    bus, _session = _session, None
    if bus is None:
        return
    end = time.monotonic() + CLOSE_WAIT
    while bus.claimed and time.monotonic() < end:
        time.sleep(0.05)
    if bus.claimed:
        bus.spent = True  # nobody may hand this link out again, but nobody pulls it out from under the operation
        return
    bus.shutdown()


atexit.register(close_session)  # a CLI run or a crash must not leave the VCI with a live monitor primitive
