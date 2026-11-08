"""SAE J2534 PassThru (04.04) adapters as a python-can bus: VAS 6154A / VNCI, Tactrix, Mongoose, Scanmatik…

Windows only: J2534 drivers are DLLs registered under HKLM\\SOFTWARE\\PassThruSupport.04.04. The bus uses the raw
CAN protocol (not ISO15765) because the RAM loader on 0x6F0/0x6F1 is not ISO-TP; ISO-TP stays in our transport.
"""

from __future__ import annotations

import collections
import ctypes
import dataclasses
import struct
import sys
import time
from typing import Any

import can

from contitool.i18n import tr

PROTOCOL_CAN = 5
CAN_29BIT_ID = 0x100  # connect flag, tx flag and rx status bit
CAN_ID_BOTH = 0x800  # connect flag: receive 11- and 29-bit frames (optional in 04.04)
PASS_FILTER = 1
TX_MSG_TYPE = 0x01  # rx status: echo of our own frame
TX_INDICATION = 0x08  # rx status: "your frame went out"
ERR_TIMEOUT = 0x09
ERR_BUFFER_EMPTY = 0x10
_RX_BATCH = 64


class PassThruMsg(ctypes.Structure):
    # `unsigned long` in the J2534 header is 32-bit on Windows, also in 64-bit drivers
    _fields_ = [
        ("ProtocolID", ctypes.c_uint32),
        ("RxStatus", ctypes.c_uint32),
        ("TxFlags", ctypes.c_uint32),
        ("Timestamp", ctypes.c_uint32),
        ("DataSize", ctypes.c_uint32),
        ("ExtraDataIndex", ctypes.c_uint32),
        ("Data", ctypes.c_ubyte * 4128),
    ]


@dataclasses.dataclass(frozen=True)
class J2534Device:
    name: str
    vendor: str
    dll: str
    bits: int | None  # 32 / 64 from the DLL header, None if unreadable

    @property
    def usable(self) -> bool:
        return self.bits in (None, _PY_BITS)


_PY_BITS = struct.calcsize("P") * 8


def dll_bits(path: str) -> int | None:
    """32 or 64 from the PE header; None if the file is not a readable Windows DLL."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
        pe = struct.unpack_from("<I", head, 0x3C)[0]
        if head[pe : pe + 4] != b"PE\0\0":
            return None
        machine = struct.unpack_from("<H", head, pe + 4)[0]
    except (OSError, struct.error):
        return None
    return {0x014C: 32, 0x8664: 64, 0xAA64: 64}.get(machine)


def discover_j2534() -> list[J2534Device]:
    """Installed J2534 drivers that support CAN, from both registry views (32- and 64-bit)."""
    if sys.platform != "win32":
        return []
    import winreg

    found: dict[str, J2534Device] = {}
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\PassThruSupport.04.04", 0, winreg.KEY_READ | view)
        except OSError:
            continue
        with root:
            for i in range(256):
                try:
                    sub = winreg.EnumKey(root, i)
                except OSError:
                    break
                with winreg.OpenKey(root, sub) as key:
                    vals: dict[str, Any] = {}
                    for name in ("Name", "Vendor", "FunctionLibrary", "CAN"):
                        try:
                            vals[name] = winreg.QueryValueEx(key, name)[0]
                        except OSError:
                            pass
                dll = str(vals.get("FunctionLibrary") or "")
                if not dll or vals.get("CAN") == 0 or dll.lower() in found:
                    continue
                found[dll.lower()] = J2534Device(str(vals.get("Name") or sub), str(vals.get("Vendor") or ""), dll, dll_bits(dll))
    return list(found.values())


def resolve_device(port: str) -> str:
    """DLL path for `port`: a .dll path, a device name (or part of it), or empty for the only usable device."""
    if port.lower().endswith(".dll"):
        return port
    devices = [d for d in discover_j2534() if not port or port.lower() in d.name.lower()]
    devices.sort(key=lambda d: d.name.lower() != port.lower())  # an exact name wins over a partial one
    usable = [d for d in devices if d.usable]
    if usable:
        return usable[0].dll
    if devices:
        raise RuntimeError(_bitness_message(devices[0]))
    raise RuntimeError(
        tr(
            "J2534-адаптер не найден. Установите драйвер PassThru от производителя адаптера.",
            "No J2534 adapter found. Install the PassThru driver from the adapter vendor.",
        )
    )


def _bitness_message(dev: J2534Device) -> str:
    return tr(
        f"Драйвер «{dev.name}» {dev.bits}-битный, а ContiTool {_PY_BITS}-битный — Windows не загружает такой драйвер "
        "в программу. Нужен драйвер PassThru той же разрядности от производителя адаптера.",
        f"The “{dev.name}” driver is {dev.bits}-bit and ContiTool is {_PY_BITS}-bit — Windows cannot load it. "
        "Get a PassThru driver of the same bitness from the adapter vendor.",
    )


class J2534Bus(can.BusABC):
    """Raw CAN over a J2534 PassThru device. `channel` is the driver DLL path (or a device name, see resolve_device)."""

    def __init__(self, channel: str = "", bitrate: int = 500_000, *, dll: Any = None, **kwargs: Any) -> None:
        path = channel if dll is not None else resolve_device(channel or "")
        if dll is None:
            bits = dll_bits(path)
            if bits not in (None, _PY_BITS):
                raise RuntimeError(_bitness_message(J2534Device(path, "", path, bits)))
            dll = ctypes.WinDLL(path)  # type: ignore[attr-defined]  # J2534 functions are __stdcall
        self._dll = dll
        self._rx_buf = (PassThruMsg * _RX_BATCH)()
        self._pending: collections.deque[can.Message] = collections.deque()
        self._dev = ctypes.c_uint32()
        self._chan = ctypes.c_uint32()
        self._call("PassThruOpen", None, ctypes.byref(self._dev))
        try:
            # Both ID widths if the device can (the gateway's 0x17F00010 is 29-bit); our work needs only 11-bit
            try:
                self._call("PassThruConnect", self._dev.value, PROTOCOL_CAN, CAN_ID_BOTH, bitrate, ctypes.byref(self._chan))
            except can.CanError:
                self._call("PassThruConnect", self._dev.value, PROTOCOL_CAN, 0, bitrate, ctypes.byref(self._chan))
            for flags in (0, CAN_29BIT_ID):  # J2534 drops every frame until a pass filter is set
                mask, pattern = PassThruMsg(PROTOCOL_CAN, 0, flags, 0, 4), PassThruMsg(PROTOCOL_CAN, 0, flags, 0, 4)
                try:
                    self._call("PassThruStartMsgFilter", self._chan.value, PASS_FILTER, ctypes.byref(mask),
                               ctypes.byref(pattern), None, ctypes.byref(ctypes.c_uint32()))
                except can.CanError:
                    if not flags:
                        raise
        except Exception:
            self._dll.PassThruClose(self._dev.value)
            raise
        self.channel_info = f"J2534 {path}"
        super().__init__(channel=path, **kwargs)

    def _call(self, fn: str, *args: Any) -> int:
        rc = getattr(self._dll, fn)(*args)
        if rc not in (0, ERR_TIMEOUT, ERR_BUFFER_EMPTY):
            text = ctypes.create_string_buffer(80)
            try:
                self._dll.PassThruGetLastError(text)
            except Exception:
                pass
            detail = text.value.decode("latin-1", "replace").strip()
            raise can.CanOperationError(f"{fn}: J2534 error 0x{rc:02X}" + (f" ({detail})" if detail else ""))
        return rc

    def _read(self, timeout_ms: int, count: int) -> None:
        n = ctypes.c_uint32(count)
        self._call("PassThruReadMsgs", self._chan.value, ctypes.byref(self._rx_buf), ctypes.byref(n), timeout_ms)
        now = time.time()
        for m in self._rx_buf[: n.value]:
            if m.RxStatus & (TX_MSG_TYPE | TX_INDICATION) or m.DataSize < 4:
                continue
            raw = bytes(m.Data[: m.DataSize])
            self._pending.append(
                can.Message(
                    timestamp=now,
                    arbitration_id=int.from_bytes(raw[:4], "big"),
                    is_extended_id=bool(m.RxStatus & CAN_29BIT_ID),
                    data=raw[4:],
                )
            )

    def _recv_internal(self, timeout: float | None) -> tuple[can.Message | None, bool]:
        if not self._pending:
            self._read(0, _RX_BATCH)  # whatever is buffered, without waiting
        if not self._pending and timeout != 0:
            # ReadMsgs waits for *all* requested frames, so ask for one to return as soon as it arrives
            self._read(1000 if timeout is None else max(1, int(timeout * 1000)), 1)
        return (self._pending.popleft() if self._pending else None), False

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        out = PassThruMsg(PROTOCOL_CAN, 0, CAN_29BIT_ID if msg.is_extended_id else 0, 0, 4 + msg.dlc)
        out.Data[: 4 + msg.dlc] = list(msg.arbitration_id.to_bytes(4, "big") + bytes(msg.data))
        n = ctypes.c_uint32(1)
        self._call("PassThruWriteMsgs", self._chan.value, ctypes.byref(out), ctypes.byref(n),
                   100 if timeout is None else int(timeout * 1000))
        if n.value != 1:
            raise can.CanOperationError(tr("J2534: кадр не отправлен", "J2534: frame not sent"))

    def shutdown(self) -> None:
        if self._is_shutdown:
            return
        super().shutdown()
        try:
            self._dll.PassThruDisconnect(self._chan.value)
        finally:
            self._dll.PassThruClose(self._dev.value)
