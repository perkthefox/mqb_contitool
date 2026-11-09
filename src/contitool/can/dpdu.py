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
from collections.abc import Iterator
import contextlib
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
PDU_ID_UNDEF = 0xFFFFFFFE
OBJT_PROTOCOL, OBJT_BUSTYPE, OBJT_COMPARAM, OBJT_PINTYPE = 0x8021, 0x8022, 0x8024, 0x8025
# Fallback for adapters whose firmware refuses RawMode: one link per request/response id pair, described the way
# ODIS describes its own (bus + protocol + pins, resource PDU_ID_UNDEF) with the ids set in the URID table.
NONRAW_PAIRS = ((0x710, 0x77A), (0x6F0, 0x6F1))  # diagnostics, then the factory RAM-loader
NONRAW_BUS, NONRAW_PROTOCOL = "ISO_11898_2_DWCAN", "ISO_11898_RAW"
NONRAW_PINS = ((6, "HI"), (14, "LOW"))
NONRAW_VERIFY_WAIT = 2.0  # the gateway answers 10 03 in under a millisecond; this only has to outlast the driver
UDS_PROTOCOLS = ("ISO_15765_3_on_ISO_15765_2", "ISO_14229_3_on_ISO_15765_2", "ISO_OBD_on_ISO_15765_2")
ERR_EVT_RX_TIMEOUT = 0x00000103
ERR_EVT_LOST_COMM_TO_VCI = 0x00000106
ERR_EVT_VCI_HARDWARE_FAULT = 0x00000107
# In #113.log the VNCI's internal TCP service restarted after ~125,000 un-freed RawMode send primitives on one link.
# Recycling the RawMode TX link periodically keeps the VCI's primitive table bounded while the monitor stays up.
MAX_RAW_TX_COPS_BEFORE_RECYCLE = 20_000
RAW_TX_IDLE_RECYCLE_THRESHOLD = 5_000


class RawModeUnavailable(can.CanInitializationError):
    """This adapter will not give a RawMode link. Only this refusal may start the fixed-id fallback — a VCI that
    merely dropped the connection must keep its own retry instead."""


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


class PinData(C.Structure):
    _fields_ = [("DLCPinNumber", U32), ("DLCPinTypeId", U32)]


class RscData(C.Structure):
    _fields_ = [("BusTypeId", U32), ("ProtocolId", U32), ("NumPinData", U32), ("pDLCPinData", C.POINTER(PinData))]


class RscIdItemData(C.Structure):
    _fields_ = [("hMod", U32), ("NumIds", U32), ("pResourceIdArray", C.POINTER(U32))]


class RscIdItem(C.Structure):
    _fields_ = [("ItemType", U32), ("NumModules", U32), ("pResourceIdDataArray", C.POINTER(RscIdItemData))]


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


class EcuUniqueRespData(C.Structure):
    _fields_ = [("UniqueRespIdentifier", U32), ("NumParamItems", U32), ("pParams", C.POINTER(ParamItem))]


class UridTable(C.Structure):
    _fields_ = [("ItemType", U32), ("NumEntries", U32), ("pUniqueData", C.POINTER(EcuUniqueRespData))]


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


class ErrorData(C.Structure):
    _fields_ = [("ErrorCodeId", U32), ("ExtraErrorInfoId", U32)]


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
        # cop -> the logical link it was started on: a fixed-id adapter has one link per CAN id, and a stuck
        # primitive can only be cancelled on its own link
        self._tx_in_flight: dict[int, int] = {}
        self._tx_cop_count = 0
        self.hmod = self.h_rx = self.h_tx = self._mon_cop = self._uds_link = 0
        self.uds_refusal = ""  # why the last uds_session() stayed on RawMode: goes into the flash result
        self._nonraw_verified = False  # the fixed-id fallback answered a 10 03 on this module
        self._tx_started = False
        self.nonraw: dict[int, int] = {}  # CAN id we send on -> its link, when the adapter refused RawMode
        self._rx_id: dict[int, int] = {}  # link -> the CAN id its results carry (RawMode puts it in the data)
        self._links: list[int] = []  # every logical link opened, for teardown
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
        """Take the first module that actually gives a raw CAN link.

        Accepting a connection proves nothing: a foreign J2534 driver connects happily and only then refuses the
        raw-CAN resource, which reached users as a bare `PDUCreateComLogicalLink: D-PDU error 0x01`. So the links
        are opened inside the candidate loop and a module counts as the right one only once they are up."""
        tried: list[str] = []
        failure = ERR_FCT_FAILED
        last: BaseException | None = None
        for hmod, name in self._modules(module_wait):
            self.hmod, self.module_label = hmod, name
            try:
                if self._call("PDUModuleConnect", hmod, also_ok=(ERR_FCT_FAILED,)) != 0:
                    raise can.CanOperationError(f"PDUModuleConnect: D-PDU error 0x{ERR_FCT_FAILED:02X}",
                                                error_code=ERR_FCT_FAILED)
                self._open_links(bitrate)
                return
            except can.CanError as exc:
                # Whatever this module answered, the next candidate still gets its turn.
                failure = exc.error_code or failure
                last = exc
                self.spent = False
                tried.append(name)
                self._drop_module()
        if len(tried) == 1 and last is not None:
            raise last  # with one candidate its own reason says more than any summary of it
        raise can.CanInitializationError(
            tr(
                f"Ни один модуль D-PDU не дал канал к блоку (пробовали: {', '.join(tried)}). Включите VCI и "
                f"закройте ODIS; если в списке адаптеров есть другой драйвер D-PDU, выберите его. Последняя "
                f"ошибка: {last}",
                f"No D-PDU module provided a link to the ECU (tried: {', '.join(tried)}). Switch the VCI on and "
                f"close ODIS; if the adapter list offers another D-PDU driver, pick that one. Last error: {last}",
            ),
            error_code=failure,  # a VCI that dropped the link (0x11) still gets the one retry __init__ does
        )

    def _open_links(self, bitrate: int, *, verify: bool = True) -> None:
        """RawMode first — the verified path — and the ODIS-style fallback only if the adapter refuses it.

        These links are new, so nothing about them is spent yet: whatever marked the old ones dead must not make
        `send()` refuse the very first frame of the fallback's own check. `verify=False` reopens a fallback this
        module has already proven, without asking an ECU that may be rebooting right now."""
        self.spent = False
        try:
            self.h_rx = self._open_monitor(bitrate)
            self.h_tx = self._create((0x80, 0, 0, 0))
            self._call("PDUConnect", self.hmod, self.h_tx)
            self._start(self.h_tx, COPT_STARTCOMM, b"", 0, 0)
            self._tx_started = True
        except RawModeUnavailable as refused:
            self._close_links()
            if not self._open_nonraw(bitrate, verify=verify):
                raise refused  # the adapter gives neither, so its own refusal is the useful message
            self.spent = False

    def _drop_module(self) -> None:
        """Release everything one candidate opened, so the next one starts clean (the API is left constructed)."""
        self._close_links()
        if self.hmod:
            self._try("PDUModuleDisconnect", self.hmod)
        self.hmod = 0
        self.module_label = ""
        self._nonraw_verified = False

    # ------------------------------------------------------------------ fallback for adapters without RawMode
    def _try(self, fn: str, *args: Any) -> int:
        """A call whose failure is an answer, not a fault: it marks nothing spent and raises nothing."""
        try:
            return int(getattr(self._dll, fn)(*args))
        except Exception:  # noqa: BLE001 - a missing export is simply "this driver cannot do it"
            return -1

    def _object_id(self, kind: int, name: str) -> int | None:
        """Ask the driver for an object id by name — the numbers differ between MDFs, so never hardcode them.

        None means this MDF does not know the name. It must not be 0: the VW MDF numbers `ISO_11898_2_DWCAN` and
        the `HI` pin 0, and reading those as "unknown" kept the hardware ISO-TP link from ever being created."""
        out = U32(0)
        return out.value if self._try("PDUGetObjectId", kind, name.encode(), C.byref(out)) == 0 else None

    def _patch_urid(self, hcll: int, want: dict[str, int]) -> None:
        """Ids live in the unique-response table: read it, set the named UNUM32 params, write it back."""
        # A param this MDF does not know is left out; one whose id is 0 is not, 0 being a valid ComParam id.
        by_id = {pid: value for name, value in want.items() if (pid := self._object_id(OBJT_COMPARAM, name)) is not None}
        table = C.POINTER(UridTable)()
        if not by_id or self._try("PDUGetUniqueRespIdTable", self.hmod, hcll, C.byref(table)) != 0 or not table:
            return
        t = table.contents
        for e in range(t.NumEntries):
            entry = t.pUniqueData[e]
            for i in range(entry.NumParamItems):
                item = entry.pParams[i]
                if item.ComParamId in by_id and item.ComParamDataType == PT_UNUM32 and item.pComParamData:
                    C.cast(item.pComParamData, C.POINTER(U32)).contents.value = by_id[item.ComParamId]
        self._try("PDUSetUniqueRespIdTable", self.hmod, hcll, table)
        self._try("PDUDestroyItem", table)

    def _set_urid(self, hcll: int, phys: int, resp: int) -> None:
        """A fixed-id link: requests on `phys`, unsegmented responses on `resp`."""
        self._patch_urid(hcll, {"CP_CanPhysReqId": phys, "CP_CanRespUUDTId": resp})

    def _open_nonraw(self, bitrate: int, *, verify: bool = True) -> bool:
        """One ODIS-style link per id pair, for an adapter whose firmware refuses RawMode.

        None of this is bench-verified, so the links must prove themselves: `_verify_nonraw` sends one `10 03` and
        requires an answer. A wrong guess therefore ends as a clear "this adapter is not supported", never as a
        session that half works. The diagnostic pair is required; without the loader pair everything except
        reading and writing memory still runs."""
        bus, proto = self._object_id(OBJT_BUSTYPE, NONRAW_BUS), self._object_id(OBJT_PROTOCOL, NONRAW_PROTOCOL)
        pin_ids = [self._object_id(OBJT_PINTYPE, t) for _, t in NONRAW_PINS]
        if bus is None or proto is None or any(p is None for p in pin_ids):
            return False
        pins = (PinData * len(NONRAW_PINS))(*(PinData(n, pid) for (n, _), pid in zip(NONRAW_PINS, pin_ids)))
        for phys, resp in NONRAW_PAIRS:
            rsc = RscData(bus, proto, len(pins), C.cast(pins, C.POINTER(PinData)))
            h, flag = U32(0), (U8 * 4)(0, 0, 0, 0)  # no 0x80: this link is exactly what RawMode is not
            if self._try("PDUCreateComLogicalLink", self.hmod, C.byref(rsc), PDU_ID_UNDEF, None, C.byref(h),
                         C.byref(FlagData(4, flag))) != 0 or not h.value:
                continue
            self._links.append(h.value)
            self._set_u32(h.value, CP_BAUDRATE, 5, bitrate)
            self._set_urid(h.value, phys, resp)
            if self._try("PDUConnect", self.hmod, h.value) != 0:
                continue
            tolerated = (ERR_FCT_FAILED, ERR_INVALID_PARAMETERS)  # a refusal here only rules this pair out
            self._start(h.value, COPT_STARTCOMM, b"", 0, 0, also_ok=tolerated)
            if self._start(h.value, COPT_SENDRECV, b"", 0, -1, accept_any=True, also_ok=tolerated)[0] != 0:
                continue
            self.nonraw[phys], self._rx_id[h.value] = h.value, resp
        if NONRAW_PAIRS[0][0] not in self.nonraw:
            return False
        self._tx_started = True
        if not verify:
            return True
        self._nonraw_verified = self._verify_nonraw()
        return self._nonraw_verified

    def _verify_nonraw(self) -> bool:
        """One `10 03` through the fallback. Nothing back means the guess was wrong, and the adapter is refused."""
        self._pending.clear()
        try:
            self.send(can.Message(arbitration_id=NONRAW_PAIRS[0][0], is_extended_id=False,
                                  data=bytes.fromhex("021003AAAAAAAAAA")))
            end = time.monotonic() + NONRAW_VERIFY_WAIT
            while time.monotonic() < end:
                self._drain_rx_links()
                if self._pending:
                    self._pending.clear()
                    return True
                time.sleep(RX_POLL)
        except can.CanError:
            return False
        return False

    def _close_links(self) -> None:
        """Release the links of one attempt, leaving the module connected for the next."""
        self._stop_links()
        for h in self._links:
            self._try("PDUDisconnect", self.hmod, h)
            self._try("PDUDestroyComLogicalLink", self.hmod, h)
        self._links.clear()
        self.h_rx = self.h_tx = self._mon_cop = self._uds_link = 0
        self._tx_cop_count = 0
        self.nonraw.clear()
        self._rx_id.clear()
        self._tx_in_flight.clear()

    # ------------------------------------------------------------------ hardware ISO-TP / UDS link for fast flashing
    def _set_named_u32(self, hcll: int, name: str, value: int, cls: int = 2) -> bool:
        """Set a named UNUM32 ComParam via PDUGetComParam -> PDUSetComParam so MDF class/type always match."""
        pid = self._object_id(OBJT_COMPARAM, name)
        if pid is None:
            return False
        item = C.POINTER(ParamItem)()
        if self._try("PDUGetComParam", self.hmod, hcll, pid, C.byref(item)) == 0 and item:
            try:
                p = item.contents
                if p.ComParamDataType == PT_UNUM32 and p.pComParamData:
                    C.cast(p.pComParamData, C.POINTER(U32)).contents.value = value
                    return self._try("PDUSetComParam", self.hmod, hcll, item) == 0
                return False
            finally:
                self._try("PDUDestroyItem", item)
        v = U32(value)
        raw = ParamItem(IT_PARAM, pid, PT_UNUM32, cls, C.cast(C.pointer(v), C.c_void_p))
        return self._try("PDUSetComParam", self.hmod, hcll, C.byref(raw)) == 0

    def _set_uds_urid(self, hcll: int, phys: int, resp: int) -> None:
        """Physical request (0x710) and segmented response (0x77A) ids in the UDS link's URID table — nothing else.

        Exactly what read `22 F187` through a VNCI on the bench (probe v6, 2026-11-08): the driver's own defaults
        for the rest (both formats 5, UUDT id 0xFFFFFFFF) stay as they are."""
        self._patch_urid(hcll, {"CP_CanPhysReqId": phys, "CP_CanRespUSDTId": resp})

    def _find_resource_id(self, rsc: RscData) -> int:
        """Resolve a module-specific ResourceId via PDUGetResourceIds when PDU_ID_UNDEF is not accepted."""
        items = C.POINTER(RscIdItem)()
        if self._try("PDUGetResourceIds", self.hmod, C.byref(rsc), C.byref(items)) != 0 or not items:
            return 0
        try:
            top = items.contents
            for i in range(top.NumModules):
                mod_entry = top.pResourceIdDataArray[i]
                if mod_entry.hMod == self.hmod and mod_entry.NumIds and mod_entry.pResourceIdArray:
                    return int(mod_entry.pResourceIdArray[0])
            return 0
        finally:
            self._try("PDUDestroyItem", items)

    def _uds_control(self, hcll: int, cop_type: int, timeout: float) -> None:
        """STARTCOMM / STOPCOMM on the UDS link, then poll its own events until that primitive finishes.

        Not `_start` + `_drain`: those treat a refusal or an error event as a dead adapter, while here it only
        means this link variant does not work and the caller moves on."""
        ctrl = CopCtrl(0, 0, 0, 0, FlagData(4, (U8 * 4)(0, 0, 0, 0)))
        cop = U32(0)
        if self._try("PDUStartComPrimitive", self.hmod, hcll, cop_type, 0, None, C.byref(ctrl), None,
                     C.byref(cop)) != 0 or not cop.value:
            return
        hcop, end = cop.value, time.monotonic() + timeout
        while time.monotonic() < end:
            item = C.POINTER(EventItem)()
            if self._try("PDUGetEventItem", self.hmod, hcll, C.byref(item)) != 0 or not item:
                time.sleep(0.001)
                continue
            ev = item.contents
            done = (ev.ItemType == IT_STATUS and bool(ev.pData) and ev.hCop == hcop
                    and C.cast(ev.pData, C.POINTER(U32)).contents.value in COPST_DONE)
            self._try("PDUDestroyItem", item)
            if done:
                return

    def _close_uds_link(self) -> None:
        hcll = self._uds_link
        if not hcll:
            return
        self._uds_link = 0
        try:
            self._uds_control(hcll, COPT_STOPCOMM, 0.5)
        except Exception:  # noqa: BLE001 - closing goes on whatever the VCI says
            pass
        self._try("PDUDisconnect", self.hmod, hcll)
        self._try("PDUDestroyComLogicalLink", self.hmod, hcll)
        if hcll in self._links:
            self._links.remove(hcll)

    def _pause_raw(self) -> None:
        self._stop.set()
        if self._rx_thread is not None:
            self._rx_thread.join(timeout=2.0)
            self._rx_thread = None
        self._close_links()
        self._pending.clear()

    def _resume_raw(self) -> None:
        """Reopen the links `_pause_raw` closed. If that fails the bus has no links and no receive thread, so it is
        marked spent before the error goes up — the kept-open session must never hand it out again."""
        self._rx_error = None
        try:
            try:
                # a reset usually follows the UDS session, so a fallback already proven here is not asked again
                self._open_links(self.bitrate, verify=not self._nonraw_verified)
            except can.CanError as exc:
                if exc.error_code != ERR_COMM_PC_TO_VCI_FAILED:
                    raise
                self._drop_module()
                time.sleep(VCI_RESTART_WAIT)
                self._open(self.bitrate, 15.0)
        except BaseException:
            self.spent = True
            raise
        self.spent = False
        self._stop.clear()
        self._rx_thread = threading.Thread(target=self._rx_loop, name="dpdu-rx", daemon=True)
        self._rx_thread.start()

    def _open_uds_link(self, bus: int, protos: list[int], hi: int, low: int, tx_id: int, rx_id: int) -> bool:
        """Open and live-verify (`3E 00`) an ISO 15765-2/3 link so VCI firmware segments 514-byte `0x36` blocks."""
        pins = (PinData * 2)(PinData(6, hi), PinData(14, low))
        for proto in protos:
            rsc = RscData(bus, proto, 2, C.cast(pins, C.POINTER(PinData)))
            # 0x40 (ChecksumMode, RawMode off) is what ODIS-E creates this very link with on this VCI — see the
            # driver log of its own session (PDUAPI_VW_#42, CllCreateFlag=0x40 0x00 0x00 0x00). The raw links keep
            # their hardware-verified 0x80 / 0x80000001.
            h, flag = U32(0), (U8 * 4)(0x40, 0, 0, 0)
            rc = self._try("PDUCreateComLogicalLink", self.hmod, C.byref(rsc), PDU_ID_UNDEF, None, C.byref(h),
                           C.byref(FlagData(4, flag)))
            if rc != 0 or not h.value:
                rid = self._find_resource_id(rsc)
                if not rid:
                    self.uds_refusal = f"PDUCreateComLogicalLink 0x{rc:X}, no resource id"
                    continue
                rc = self._try("PDUCreateComLogicalLink", self.hmod, None, rid, None, C.byref(h),
                               C.byref(FlagData(4, flag)))
                if rc != 0 or not h.value:
                    self.uds_refusal = f"PDUCreateComLogicalLink by resource id 0x{rc:X}"
                    continue
            hcll = h.value
            self._links.append(hcll)
            self._uds_link = hcll
            if not self._set_named_u32(hcll, "CP_Baudrate", self.bitrate, cls=5):
                v = U32(self.bitrate)
                p = ParamItem(IT_PARAM, CP_BAUDRATE, PT_UNUM32, 5, C.cast(C.pointer(v), C.c_void_p))
                self._try("PDUSetComParam", self.hmod, hcll, C.byref(p))
            self._set_named_u32(hcll, "CP_CanFillerByteHandling", 1)
            self._set_named_u32(hcll, "CP_CanFillerByte", 0x00)  # as send_uds pads ConsecutiveFrames
            self._set_named_u32(hcll, "CP_TesterPresentHandling", 0)
            self._set_named_u32(hcll, "CP_BlockSize", 0)
            self._set_named_u32(hcll, "CP_StMin", 0)
            # Without CP_ModifyTiming the VCI keeps the MDF's own P2/P2*, whatever we set below. ODIS-E sets it
            # to 1 on this link before its own timing (same driver log), so our 2.5 s / 6 s really take effect.
            self._set_named_u32(hcll, "CP_ModifyTiming", 1)
            self._set_named_u32(hcll, "CP_CanMaxNumWaitFrames", 0x0F)  # as ODIS-E; the default 0xFF never ends
            if not self._set_named_u32(hcll, "CP_P2Max", 2_500_000):
                self._set_named_u32(hcll, "CP_P2Max", 500_000)
            if not self._set_named_u32(hcll, "CP_P2Star", 6_000_000):
                self._set_named_u32(hcll, "CP_P2Star", 5_000_000)
            if not self._set_named_u32(hcll, "CP_RC78CompletionTimeout", 150_000_000):
                self._set_named_u32(hcll, "CP_RC78CompletionTimeout", 30_000_000)
            if not self._set_named_u32(hcll, "CP_RC78Handling", 2):
                self._set_named_u32(hcll, "CP_RC78Handling", 1)
            self._set_uds_urid(hcll, tx_id, rx_id)
            if (rc := self._try("PDUConnect", self.hmod, hcll)) != 0:
                self.uds_refusal = f"PDUConnect 0x{rc:X}"
                self._close_uds_link()
                continue
            self._uds_control(hcll, COPT_STARTCOMM, 1.0)
            try:
                probe = self.request_uds(b"\x3e\x00", timeout=1.5, allow_pending=True)
                if probe and (probe[0] == 0x7E or (len(probe) >= 3 and probe[:2] == b"\x7f\x3e")):
                    self.uds_refusal = ""
                    return True
                self.uds_refusal = f"3E 00 answered {(probe or b'').hex(' ')}"
            except (can.CanError, TimeoutError) as exc:
                self.uds_refusal = f"3E 00: {exc}"
            self.spent = False
            self._close_uds_link()
        return False

    @contextlib.contextmanager
    def uds_session(self, tx_id: int = 0x710, rx_id: int = 0x77A) -> Iterator[bool]:
        """Temporarily switch CAN1 from RawMode to hardware ISO 15765-2/3 for bulk UDS transfers (`0x34/0x36/0x37`).

        On a VNCI 6154A each RawMode primitive takes ~5 ms over TCP, turning 2,975 x 74 frames into 27 minutes and
        overflowing the VCI's primitive table at ~125k primitives. Hardware ISO-TP sends one 514-byte primitive per
        block (2,975 total) and handles `30 0F 00` FlowControls locally inside the VCI firmware. If the driver or
        adapter refuses or fails the live `3E 00` probe, RawMode is restored transparently."""
        if self._uds_link:
            yield True
            return
        if not self.hmod:
            self.uds_refusal = "no D-PDU module"
            yield False
            return
        bus = self._object_id(OBJT_BUSTYPE, NONRAW_BUS)
        hi, low = self._object_id(OBJT_PINTYPE, "HI"), self._object_id(OBJT_PINTYPE, "LOW")
        protos = [p for name in UDS_PROTOCOLS if (p := self._object_id(OBJT_PROTOCOL, name)) is not None]
        missing = [n for n, v in ((NONRAW_BUS, bus), ("pin HI", hi), ("pin LOW", low)) if v is None]
        if missing or not protos:
            self.uds_refusal = "driver lacks " + ", ".join(missing or [" / ".join(UDS_PROTOCOLS)])
            yield False
            return
        self._pause_raw()
        opened = False
        try:
            opened = self._open_uds_link(bus, protos, hi, low, tx_id, rx_id)
        except Exception as exc:  # noqa: BLE001
            self.uds_refusal = f"{type(exc).__name__}: {exc}"
            self.spent = False
            self._close_uds_link()
            opened = False
        if not opened:
            # One refusal is not proof the adapter can never do it — a busy or rebooting ECU fails the probe too,
            # and sticking would silently condemn every later flash in this process to the slow RawMode path.
            self._resume_raw()
            yield False
            return
        try:
            yield True
        finally:
            self.end_uds_session()

    def end_uds_session(self) -> None:
        """Leave the hardware ISO-TP link and bring RawMode back. Idempotent: the caller may already have done it.

        Whatever happens here must not replace the error that brought us here, and must never leave the bus
        looking healthy while it has no links — the kept-open session would hand that out to the next operation."""
        if not self._uds_link:
            return
        self._close_uds_link()
        try:
            self._resume_raw()
        except BaseException:  # noqa: BLE001 - the flash error, if any, is the one worth reporting
            self.spent = True

    def _drain_uds_leftovers(self, hcll: int) -> None:
        while True:
            item = C.POINTER(EventItem)()
            if self._try("PDUGetEventItem", self.hmod, hcll, C.byref(item)) != 0 or not item:
                return
            try:
                ev = item.contents
                if ev.ItemType == IT_STATUS and ev.pData and C.cast(ev.pData, C.POINTER(U32)).contents.value == CLLST_OFFLINE:
                    self.spent = True
                    raise can.CanOperationError(tr("VCI закрыл канал D-PDU", "The VCI closed the D-PDU link"))
            finally:
                self._try("PDUDestroyItem", item)

    def request_uds(self, req: bytes, *, timeout: float = 2.0, allow_pending: bool = True) -> bytes:
        """Send one full UDS PDU through the active ISO 15765 link and return the reassembled UDS response."""
        hcll = self._uds_link
        if not hcll:
            raise can.CanOperationError("D-PDU hardware UDS link is not active")
        payload = bytes(req)
        if not payload:
            raise ValueError("Empty UDS payload")
        req_sid = payload[0]
        self._drain_uds_leftovers(hcll)

        pos_mask, pos_pat = (U8 * 1)(0xFF), (U8 * 1)((req_sid + 0x40) & 0xFF)
        neg_mask, neg_pat = (U8 * 2)(0xFF, 0xFF), (U8 * 2)(0x7F, req_sid)
        exps = (ExpResp * 2)(
            ExpResp(0, 1, 1, pos_mask, pos_pat, 0, None),
            ExpResp(1, 2, 2, neg_mask, neg_pat, 0, None),
        )
        tx = (U8 * 4)(0, 0, 0, 0)
        deadline = time.monotonic() + timeout

        def start_primitive(send_cycles: int, tx_bytes: bytes) -> int:
            ctrl = CopCtrl(0, send_cycles, 1, 0, FlagData(4, tx), 2, C.cast(exps, C.POINTER(ExpResp)))
            buf = (U8 * len(tx_bytes)).from_buffer_copy(tx_bytes) if tx_bytes else None
            hcop_out = U32(0)
            self._call("PDUStartComPrimitive", self.hmod, hcll, COPT_SENDRECV, len(tx_bytes), buf, C.byref(ctrl),
                       None, C.byref(hcop_out))
            return hcop_out.value

        hcop = start_primitive(1, payload)
        cop_done = hcop == 0
        result_bytes: bytes | None = None
        seen_pending_78 = False

        while True:
            while True:
                item = C.POINTER(EventItem)()
                rc = self._call("PDUGetEventItem", self.hmod, hcll, C.byref(item))
                if rc == ERR_EVENT_QUEUE_EMPTY or not item:
                    break
                try:
                    ev = item.contents
                    if ev.ItemType == IT_STATUS and ev.pData:
                        st = C.cast(ev.pData, C.POINTER(U32)).contents.value
                        if st == CLLST_OFFLINE:
                            self.spent = True
                            raise can.CanOperationError(tr("VCI закрыл канал D-PDU", "The VCI closed the D-PDU link"))
                        if ev.hCop == hcop and st in COPST_DONE:
                            cop_done = True
                    elif ev.ItemType == IT_RESULT and ev.pData and (ev.hCop == hcop or hcop == 0):
                        r = C.cast(ev.pData, C.POINTER(ResultData)).contents
                        flags = bytes(r.RxFlag.pFlagData[: r.RxFlag.NumFlagBytes]) if r.RxFlag.NumFlagBytes else b""
                        if len(flags) >= 4 and flags[3] & 0x01:
                            continue
                        raw = bytes(r.pDataBytes[: min(r.NumDataBytes, 4128)]) if r.NumDataBytes else b""
                        if allow_pending and len(raw) >= 3 and raw[0] == 0x7F and raw[1] == req_sid and raw[2] == 0x78:
                            seen_pending_78 = True
                        elif raw:
                            result_bytes = raw
                    elif ev.ItemType == IT_ERROR and (ev.hCop == hcop or hcop == 0):
                        err_code = C.cast(ev.pData, C.POINTER(ErrorData)).contents.ErrorCodeId if ev.pData else 0
                        self._drain_uds_leftovers(hcll)
                        if err_code == ERR_EVT_RX_TIMEOUT:
                            raise TimeoutError(f"UDS response timeout ({timeout:.1f}s) for {payload[:8].hex()}")
                        if err_code in (ERR_EVT_LOST_COMM_TO_VCI, ERR_EVT_VCI_HARDWARE_FAULT, 0):
                            self.spent = True
                            raise can.CanOperationError(tr(
                                "Потеряна связь с VCI по каналу D-PDU",
                                "Lost communication with VCI on D-PDU link",
                            ))
                        raise can.CanOperationError(tr(
                            f"Ошибка протокола UDS D-PDU (0x{err_code:X})",
                            f"D-PDU UDS protocol error (0x{err_code:X})",
                        ))
                finally:
                    self._dll.PDUDestroyItem(item)

            if cop_done:
                if result_bytes is not None:
                    return result_bytes
                if seen_pending_78 and time.monotonic() < deadline:
                    # Fallback if a driver ignores CP_RC78Handling and finishes the primitive on 7F xx 78
                    seen_pending_78 = False
                    hcop = start_primitive(0, b"")
                    cop_done = hcop == 0
                    continue
                raise TimeoutError(f"UDS response timeout ({timeout:.1f}s) for {payload[:8].hex()}")

            if time.monotonic() >= deadline:
                if hcop:
                    self._try("PDUCancelComPrimitive", self.hmod, hcll, hcop)
                    cancel_end = time.monotonic() + 0.2
                    while time.monotonic() < cancel_end:
                        item = C.POINTER(EventItem)()
                        if self._try("PDUGetEventItem", self.hmod, hcll, C.byref(item)) != 0 or not item:
                            break
                        self._try("PDUDestroyItem", item)
                raise TimeoutError(f"UDS response timeout ({timeout:.1f}s) for {payload[:8].hex()}")
            time.sleep(RX_POLL)

    # ------------------------------------------------------------------ receiving
    def _drain_rx_links(self) -> bool:
        """Take events from whichever links deliver frames: the monitor in RawMode, the id pairs otherwise."""
        busy = False
        for h in ([self.h_rx] if self.h_rx else list(self._rx_id)):
            busy = self._drain(h) or busy
        return busy

    def _rx_loop(self) -> None:
        """Keep the monitor link drained for as long as the link is open.

        The driver queues every frame as an event on the logical link and waits for its owner to take it — ODIS
        hands it a callback for this, which is why its own log complains that ours is NULL. Draining only while an
        operation runs was fine while the link was closed in between; with the link kept open, a quiet period let
        the queue grow and the next operation had to chew through stale frames before its own answer. This thread
        owns the monitor link; the send link stays with the calling thread, which waits for each frame itself."""
        while not self._stop.is_set():
            try:
                busy = self._drain_rx_links()
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

    def _create(self, flags: tuple[int, int, int, int]) -> int:
        h, fl = U32(0), (U8 * 4)(*flags)
        # Any refusal means the same thing — this module has no raw CAN on OBD pins 6/14 — so say that instead of
        # the bare code. Seen as 0x50 from a VAS 5054A and as 0x01 from another vendor's driver.
        rc = self._call("PDUCreateComLogicalLink", self.hmod, None, RAWCAN_OBD6_14, None, C.byref(h),
                        C.byref(FlagData(4, fl)), also_ok=(ERR_INVALID_PARAMETERS, ERR_FCT_FAILED))
        if rc:
            raise RawModeUnavailable(
                tr(
                    f"Адаптер «{self.module_label}» не даёт сырой канал CAN (ошибка 0x{rc:02X}). ContiTool "
                    "работает только через RawMode на контактах 6/14; его не дают ни чужие драйверы J2534, ни "
                    "часть клонов VNCI — отказ приходит от самого адаптера. Попробуйте другой драйвер D-PDU в "
                    "окне «Подключение»; если и там отказ, этот адаптер не подойдёт.",
                    f"Adapter “{self.module_label}” provides no raw CAN channel (error 0x{rc:02X}). ContiTool "
                    "works only through RawMode on pins 6/14, which neither other vendors' J2534 drivers nor some "
                    "VNCI clones provide — the refusal comes from the adapter itself. Try another D-PDU driver in "
                    "the Connection window; if that is refused too, this adapter cannot be used.",
                ),
                error_code=rc,
            )
        self._links.append(h.value)
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
                if ev.ItemType == IT_RESULT and ev.pData and (hcll == self.h_rx or hcll in self._rx_id):
                    self._take_result(C.cast(ev.pData, C.POINTER(ResultData)).contents, self._rx_id.get(hcll))
                elif ev.ItemType == IT_STATUS and ev.pData and hcll != self.h_rx:
                    if C.cast(ev.pData, C.POINTER(U32)).contents.value in COPST_DONE:
                        self._tx_in_flight.pop(ev.hCop, None)
                elif ev.ItemType == IT_ERROR and hcll != self.h_rx:
                    # a frame the VCI could not send (e.g. its queue overflowed): fail now, not by a later timeout
                    self._tx_in_flight.pop(ev.hCop, None)
                    self.spent = True
                    raise can.CanOperationError(tr("VCI не смог отправить кадр", "The VCI could not send a frame"))
            finally:
                self._dll.PDUDestroyItem(item)

    def _take_result(self, r: ResultData, rx_id: int | None = None) -> None:
        raw = bytes(r.pDataBytes[: min(r.NumDataBytes, 4128)]) if r.NumDataBytes else b""
        flags = bytes(r.RxFlag.pFlagData[: r.RxFlag.NumFlagBytes]) if r.RxFlag.NumFlagBytes else b""
        if len(flags) >= 4 and flags[3] & 0x01:
            return  # the VCI's echo of a frame we sent
        if rx_id is not None:
            # A link with fixed ids carries the payload alone; the id is the one its URID table was set to.
            if raw:
                self._pending.append(can.Message(timestamp=time.time(), arbitration_id=rx_id,
                                                 is_extended_id=False, data=raw[:8]))
            return
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

    def maybe_recycle_tx(self, threshold: int | None = None) -> None:
        """Recycle the RawMode TX link if it is due — call only between packets, never inside one.

        Recycling costs a STOPCOMM wait of up to a second plus several VCI round trips. In the middle of a
        RAM-loader packet or an ISO-TP block that gap outlives the receiver's tolerance and breaks the transfer,
        so the decision belongs at a boundary where a pause is harmless."""
        if self.spent or self.nonraw or not self.h_tx:
            return
        if self._tx_cop_count < (MAX_RAW_TX_COPS_BEFORE_RECYCLE if threshold is None else threshold):
            return
        end = time.monotonic() + 0.25  # let the last frames of the stream finish; they are already on the wire
        while self._tx_in_flight and time.monotonic() < end:
            self._drain(self.h_tx)
            time.sleep(0.001)
        if self._tx_in_flight:
            return  # still busy: the next boundary tries again, and there are thousands of them before the limit
        self._recycle_raw_tx()

    def _recycle_raw_tx(self) -> None:
        """Reopen the RawMode TX link while keeping the RX monitor running so VCI primitive tables never overflow."""
        if not self.h_tx or self.nonraw or self._tx_in_flight:
            return
        old_tx = self.h_tx
        if self._tx_started:
            self._tx_started = False
            self._stopcomm(old_tx)
        self._try("PDUDisconnect", self.hmod, old_tx)
        self._try("PDUDestroyComLogicalLink", self.hmod, old_tx)
        if old_tx in self._links:
            self._links.remove(old_tx)
        self.h_tx = 0
        self._tx_cop_count = 0
        self.h_tx = self._create((0x80, 0, 0, 0))
        self._call("PDUConnect", self.hmod, self.h_tx)
        self._start(self.h_tx, COPT_STARTCOMM, b"", 0, 0)
        self._tx_started = True

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        if self.spent:
            # A dead link costs the full timeout on every frame otherwise, and a retry loop around a reset
            # turns that into minutes of waiting for an answer that can no longer come.
            self._check_rx()
            raise can.CanOperationError(tr("D-PDU: канал больше не работает",
                                           "D-PDU: this link no longer works"))
        if self.nonraw:  # fixed-id links: the id is the link's, the payload goes on its own
            link = self.nonraw.get(msg.arbitration_id)
            if link is None:
                ids = ", ".join(f"0x{i:03X}" for i in sorted(self.nonraw))
                raise can.CanOperationError(tr(
                    f"Этот адаптер не даёт сырой CAN и работает только на идентификаторах {ids}; "
                    f"отправить кадр 0x{msg.arbitration_id:03X} через него нельзя.",
                    f"This adapter has no raw CAN and works only on identifiers {ids}; "
                    f"a frame to 0x{msg.arbitration_id:03X} cannot be sent through it.",
                ))
            payload, tx_link, flag = bytes(msg.data), link, (0, 0, 0, 0)
        else:
            payload, tx_link = msg.arbitration_id.to_bytes(4, "big") + bytes(msg.data), self.h_tx
            # 29-bit sending mirrors the RxFlag layout (byte 2 bit 0); only 11-bit sending is verified on hardware
            flag = (0, 0, 1 if msg.is_extended_id else 0, 0)
        end = time.monotonic() + (5.0 if timeout is None else timeout)
        saw_queue_full = False
        while True:
            self._check_rx()
            self._drain(tx_link)
            if len(self._tx_in_flight) < MAX_TX_IN_FLIGHT:
                rc, hcop = self._start(tx_link, COPT_SENDRECV, payload, 1, 0, tx_flag=flag,
                                       also_ok=(ERR_TX_QUEUE_FULL,))
                if rc == 0:
                    self._tx_in_flight[hcop] = tx_link
                    self._tx_cop_count += 1
                    return
                saw_queue_full = True
            if time.monotonic() > end:
                # Mark the link unusable first: _check_rx re-raises whatever killed the receive thread, and if it
                # does, `spent` must already be set or the kept-open session hands this dead bus out again.
                self.spent = True
                stuck_links = set()
                for stuck, stuck_link in list(self._tx_in_flight.items()):
                    self._try("PDUCancelComPrimitive", self.hmod, stuck_link, stuck)
                    stuck_links.add(stuck_link)
                for link in stuck_links | {tx_link}:
                    self._drain(link)
                self._check_rx()
                if saw_queue_full:
                    raise can.CanOperationError(tr(
                        "D-PDU: очередь отправки VCI переполнена",
                        "D-PDU: the VCI send queue is full",
                    ))
                # The previous frame never finished. From the PC side two causes look the same: nothing on the bus
                # acknowledges it (no ECU power, wiring, termination), or the VCI's own service hung (#113.log). The
                # empty event queue the driver keeps returning is answered by the DLL locally, so it proves neither.
                raise can.CanOperationError(tr(
                    "D-PDU: кадр так и не ушёл. Либо его никто не подтверждает на шине (питание блока, "
                    "провода CAN-H/CAN-L, терминатор 120 Ом), либо завис сам VCI (переподключите адаптер).",
                    "D-PDU: the frame never went out. Either nothing on the bus acknowledges it (ECU power, "
                    "CAN-H/CAN-L wiring, 120 Ohm terminator) or the VCI itself hung (reconnect the adapter).",
                ))
            time.sleep(0.0005)

    def _stopcomm(self, link: int) -> None:
        """STOPCOMM on a send link, waiting up to a second for it like ODIS does. Whatever the VCI answers,
        nothing started on this link is in flight any more afterwards."""
        try:
            _, cop = self._start(link, COPT_STOPCOMM, b"", 0, 0)
            if cop:
                self._tx_in_flight[cop] = link
                end = time.monotonic() + 1.0
                while cop in self._tx_in_flight and time.monotonic() < end:
                    self._drain(link)
                    time.sleep(0.001)
        except Exception:  # noqa: BLE001 - closing goes on whatever the VCI says
            pass
        for cop in [c for c, owner in self._tx_in_flight.items() if owner == link]:
            del self._tx_in_flight[cop]

    def _stop_links(self) -> None:
        """STOPCOMM on the send link (waiting for it like ODIS does), then cancel the monitor primitive."""
        if self._tx_started:
            self._tx_started = False
            for link in [self.h_tx] if self.h_tx else list(self.nonraw.values()):
                self._stopcomm(link)
        if self._uds_link:
            self._close_uds_link()
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
        self._drop_module()
        self._dll.PDUDestruct()

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
    try:  # between operations nothing is streaming, so a worn link can go earlier than mid-run
        bus.maybe_recycle_tx(RAW_TX_IDLE_RECYCLE_THRESHOLD)
    except Exception:  # noqa: BLE001
        bus.spent = True
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
