"""SAE J2534 PassThru (04.04) adapters as a python-can bus: VAS 6154A / VNCI, Tactrix, Mongoose, Scanmatik…

Windows only: J2534 drivers are DLLs registered under HKLM\\SOFTWARE\\PassThruSupport.04.04. The bus uses the raw
CAN protocol (not ISO15765) because the RAM loader on 0x6F0/0x6F1 is not ISO-TP; ISO-TP stays in our transport.
"""

from __future__ import annotations

import collections
from collections.abc import Iterator
import contextlib
import ctypes
import dataclasses
import struct
import sys
import time
from typing import Any

import can

from contitool.can.transport import positive_prefix
from contitool.i18n import tr

PROTOCOL_CAN = 5
PROTOCOL_ISO15765 = 6
CAN_29BIT_ID = 0x100  # connect flag, tx flag and rx status bit
CAN_ID_BOTH = 0x800  # connect flag: receive 11- and 29-bit frames (optional in 04.04)
PASS_FILTER = 1
FLOW_CONTROL_FILTER = 3
TX_MSG_TYPE = 0x01  # rx status: echo of our own frame
START_OF_MESSAGE = 0x02  # ISO15765 rx status: FirstFrame seen; wait for the reassembled PDU
TX_INDICATION = 0x08  # rx status: "your frame went out"
ISO15765_FRAME_PAD = 0x40  # ISO15765 tx/filter flag: pad CAN frames to 8 bytes
ERR_TIMEOUT = 0x09
ERR_BUFFER_EMPTY = 0x10
_RX_BATCH = 64
_P2_WAIT = 2.5  # P2server before the first response byte; the FBL repeats `7F xx 78` about this often
_P2_STAR_WAIT = 6.0  # P2*server 5.0 s + 1 s for adapter latency, matching the software ISO-TP path


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
        self._bitrate = bitrate
        self._rx_buf = (PassThruMsg * _RX_BATCH)()
        self._pending: collections.deque[can.Message] = collections.deque()
        self._dev = ctypes.c_uint32()
        self._chan = ctypes.c_uint32()
        self._uds_chan = 0
        self._uds_tx_id = 0x710
        self._uds_rx_id = 0x77A
        self._call("PassThruOpen", None, ctypes.byref(self._dev))
        try:
            self._connect_raw_can()
        except Exception:
            self._dll.PassThruClose(self._dev.value)
            raise
        self.channel_info = f"J2534 {path}"
        super().__init__(channel=path, **kwargs)

    def _connect_raw_can(self) -> None:
        # Both ID widths if the device can (the gateway's 0x17F00010 is 29-bit); our work needs only 11-bit
        try:
            self._call("PassThruConnect", self._dev.value, PROTOCOL_CAN, CAN_ID_BOTH, self._bitrate, ctypes.byref(self._chan))
        except can.CanError:
            self._call("PassThruConnect", self._dev.value, PROTOCOL_CAN, 0, self._bitrate, ctypes.byref(self._chan))
        for flags in (0, CAN_29BIT_ID):  # J2534 drops every frame until a pass filter is set
            mask, pattern = PassThruMsg(PROTOCOL_CAN, 0, flags, 0, 4), PassThruMsg(PROTOCOL_CAN, 0, flags, 0, 4)
            try:
                self._call("PassThruStartMsgFilter", self._chan.value, PASS_FILTER, ctypes.byref(mask),
                           ctypes.byref(pattern), None, ctypes.byref(ctypes.c_uint32()))
            except can.CanError:
                if not flags:
                    raise

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

    def send_batch(self, msgs: list[can.Message], timeout: float | None = None) -> None:
        """Write a whole block of ConsecutiveFrames in one PassThruWriteMsgs call instead of one USB/TCP call each."""
        if not msgs:
            return
        if len(msgs) == 1:
            self.send(msgs[0], timeout=timeout)
            return
        timeout_ms = 500 if timeout is None else max(100, int(timeout * 1000))
        idx = 0
        total = len(msgs)
        while idx < total:
            rem = total - idx
            arr = (PassThruMsg * rem)()
            for i, msg in enumerate(msgs[idx:]):
                raw = msg.arbitration_id.to_bytes(4, "big") + bytes(msg.data)
                arr[i].ProtocolID = PROTOCOL_CAN
                arr[i].TxFlags = CAN_29BIT_ID if msg.is_extended_id else 0
                arr[i].DataSize = len(raw)
                arr[i].Data[: len(raw)] = list(raw)
            n = ctypes.c_uint32(rem)
            self._call("PassThruWriteMsgs", self._chan.value, ctypes.byref(arr), ctypes.byref(n), timeout_ms)
            if n.value == 0:
                raise can.CanOperationError(tr("J2534: кадр не отправлен", "J2534: frame not sent"))
            idx += n.value

    @contextlib.contextmanager
    def uds_session(self, tx_id: int = 0x710, rx_id: int = 0x77A) -> Iterator[bool]:
        """Temporarily switch the PassThru device to hardware PROTOCOL_ISO15765 for bulk UDS flashing."""
        if self._uds_chan:
            yield True
            return
        if self._chan.value:
            self._dll.PassThruDisconnect(self._chan.value)
            self._chan.value = 0
        self._pending.clear()
        chan = ctypes.c_uint32()
        opened = False
        try:
            self._call("PassThruConnect", self._dev.value, PROTOCOL_ISO15765, 0, self._bitrate, ctypes.byref(chan))
            mask = PassThruMsg(PROTOCOL_ISO15765, 0, ISO15765_FRAME_PAD, 0, 4)
            pattern = PassThruMsg(PROTOCOL_ISO15765, 0, ISO15765_FRAME_PAD, 0, 4)
            flow = PassThruMsg(PROTOCOL_ISO15765, 0, ISO15765_FRAME_PAD, 0, 4)
            mask.Data[:4] = [0xFF, 0xFF, 0xFF, 0xFF]
            pattern.Data[:4] = list(rx_id.to_bytes(4, "big"))
            flow.Data[:4] = list(tx_id.to_bytes(4, "big"))
            self._call("PassThruStartMsgFilter", chan.value, FLOW_CONTROL_FILTER, ctypes.byref(mask),
                       ctypes.byref(pattern), ctypes.byref(flow), ctypes.byref(ctypes.c_uint32()))
            self._uds_chan, self._uds_tx_id, self._uds_rx_id = chan.value, tx_id, rx_id
            probe = self.request_uds(b"\x3e\x00", timeout=1.5, allow_pending=True)
            opened = bool(probe and (probe[0] == 0x7E or (len(probe) >= 3 and probe[:2] == b"\x7f\x3e")))
            self.uds_refusal = "" if opened else f"3E 00 answered {(probe or b'').hex(' ')}"
        except Exception as exc:  # noqa: BLE001 - any driver refusal or mock assertion falls back to raw CAN + send_batch
            self.uds_refusal = f"{type(exc).__name__}: {exc}"
            opened = False
        if not opened:
            bad = self._uds_chan or chan.value
            self._uds_chan = 0
            if bad:
                try:
                    self._dll.PassThruDisconnect(bad)
                except Exception:  # noqa: BLE001
                    pass
            # Not sticky: a busy or rebooting ECU fails the probe too, and remembering that would condemn every
            # later flash in this process to the slow frame-by-frame path.
            self._connect_raw_can()
            yield False
            return
        try:
            yield True
        finally:
            self.end_uds_session()

    def end_uds_session(self) -> None:
        """Leave the hardware ISO15765 channel and bring raw CAN back. Idempotent."""
        chan_id, self._uds_chan = self._uds_chan, 0
        if not chan_id:
            return
        try:
            self._dll.PassThruDisconnect(chan_id)
        except Exception:  # noqa: BLE001 - whatever sent us here is the error worth reporting
            pass
        self._pending.clear()
        try:
            self._connect_raw_can()
        except Exception:  # noqa: BLE001 - this runs while an error unwinds; that error is the one to report
            self._chan.value = 0  # no raw channel: the next send fails on its own, with its own message

    def request_uds(self, req: bytes, *, timeout: float = 2.0, allow_pending: bool = True) -> bytes:
        """Send one full UDS PDU (up to 4,095 B) over J2534 PROTOCOL_ISO15765 and return the reassembled response."""
        if not self._uds_chan:
            raise can.CanOperationError("J2534 ISO15765 channel is not active")
        payload = bytes(req)
        if not payload:
            raise ValueError("Empty UDS payload")
        req_sid, want = payload[0], positive_prefix(payload)
        self._drain_uds_rx()  # a late answer to an earlier request must not be read as the answer to this one
        raw_tx = self._uds_tx_id.to_bytes(4, "big") + payload
        out = PassThruMsg(PROTOCOL_ISO15765, 0, ISO15765_FRAME_PAD, 0, len(raw_tx))
        out.Data[: len(raw_tx)] = list(raw_tx)
        n = ctypes.c_uint32(1)
        self._call("PassThruWriteMsgs", self._uds_chan, ctypes.byref(out), ctypes.byref(n),
                   max(2000, int(timeout * 1000)))
        if n.value != 1:
            raise can.CanOperationError(tr("J2534: запрос UDS не отправлен", "J2534: UDS request not sent"))

        # P2 bounds the wait for the first byte; after a `7F xx 78` the ECU gets P2* for the next one. Without
        # this a dead ECU held the caller for the whole operation timeout — 120 s for an erase.
        deadline = time.monotonic() + timeout
        slice_end = min(deadline, time.monotonic() + _P2_WAIT)
        while True:
            now = time.monotonic()
            if now >= deadline or now >= slice_end:
                raise TimeoutError(f"UDS response timeout ({timeout:.1f}s) for {payload[:8].hex()}")
            n_rx = ctypes.c_uint32(_RX_BATCH)
            self._call("PassThruReadMsgs", self._uds_chan, ctypes.byref(self._rx_buf), ctypes.byref(n_rx),
                       max(1, int(min(slice_end - now, 0.25) * 1000)))
            for m in self._rx_buf[: n_rx.value]:
                if m.RxStatus & (TX_MSG_TYPE | TX_INDICATION | START_OF_MESSAGE) or m.DataSize <= 4:
                    continue
                if int.from_bytes(bytes(m.Data[:4]), "big") != self._uds_rx_id:
                    continue
                resp = bytes(m.Data[4 : m.DataSize])
                if not resp:
                    continue
                if len(resp) >= 2 and resp[0] == 0x7F and resp[1] != req_sid:
                    continue  # a refusal of some earlier request
                if resp[0] != 0x7F and not resp.startswith(want):
                    continue  # an answer to some earlier request (a 76 of the previous block, say)
                if allow_pending and len(resp) >= 3 and resp[0] == 0x7F and resp[2] == 0x78:
                    slice_end = min(deadline, time.monotonic() + _P2_STAR_WAIT)
                    continue
                return resp

    def _drain_uds_rx(self) -> None:
        """Throw away anything already queued on the ISO15765 channel before sending a new request."""
        for _ in range(16):
            n_rx = ctypes.c_uint32(_RX_BATCH)
            self._call("PassThruReadMsgs", self._uds_chan, ctypes.byref(self._rx_buf), ctypes.byref(n_rx), 0)
            if n_rx.value == 0:
                return

    def shutdown(self) -> None:
        if self._is_shutdown:
            return
        super().shutdown()
        try:
            if self._uds_chan:
                self._dll.PassThruDisconnect(self._uds_chan)
                self._uds_chan = 0
            if self._chan.value:
                self._dll.PassThruDisconnect(self._chan.value)
                self._chan.value = 0
        finally:
            self._dll.PassThruClose(self._dev.value)
