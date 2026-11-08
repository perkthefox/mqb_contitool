"""Raw CAN / UDS session for the terminal: one thread owns the bus, the GUI polls what it saw."""

from __future__ import annotations

import collections
import dataclasses
import queue
import re
import threading
import time
from typing import Any

from PySide6.QtCore import QThread, Signal

from contitool.can import J533CanLink
from contitool.can.transport import P2_STAR_WAIT
from contitool.i18n import tr

# ISO 14229-1 negative response codes
NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "responsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}


def parse_hex(text: str, max_len: int) -> bytes:
    """`02 10 03`, `021003`, `0x02,0x10` → bytes. Anything after `#` is a comment."""
    s = re.sub(r"(?i)0x|[\s,;:_\-]", "", text.split("#", 1)[0])
    if len(s) % 2 or not re.fullmatch(r"[0-9A-Fa-f]*", s):
        raise ValueError(tr("Данные — байты в hex, например: 22 F1 90", "Data must be hex bytes, e.g. 22 F1 90"))
    data = bytes.fromhex(s)
    if len(data) > max_len:
        raise ValueError(tr(f"Не больше {max_len} байт", f"At most {max_len} bytes"))
    return data


def parse_id(text: str) -> tuple[int, bool]:
    """Hex CAN identifier → (id, extended). More than 3 hex digits or above 0x7FF means a 29-bit ID."""
    s = text.strip().lower().removeprefix("0x")
    try:
        value = int(s, 16)
    except ValueError:
        raise ValueError(tr("ID — число в hex, например 710", "The ID must be hex, e.g. 710")) from None
    if value > 0x1FFFFFFF:
        raise ValueError(tr("ID больше 0x1FFFFFFF", "The ID is above 0x1FFFFFFF"))
    return value, value > 0x7FF or len(s) > 3


def ascii_preview(data: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data)


def describe_uds(resp: bytes) -> str:
    """One-line meaning of a UDS response."""
    if len(resp) >= 3 and resp[0] == 0x7F:
        name = NRC.get(resp[2], "")
        return tr(
            f"Отказ: сервис 0x{resp[1]:02X}, NRC 0x{resp[2]:02X} {name}",
            f"Negative: service 0x{resp[1]:02X}, NRC 0x{resp[2]:02X} {name}",
        ).rstrip()
    text = tr(f"Положительный ответ 0x{resp[0]:02X}", f"Positive response 0x{resp[0]:02X}") if resp else ""
    tail = resp[3:] if resp[:1] == b"\x62" else resp[1:]  # 62 = ReadDataByIdentifier: skip the DID
    if len(tail) >= 4 and sum(0x20 <= b < 0x7F for b in tail) >= 0.8 * len(tail):
        text += f'  "{ascii_preview(tail).strip(".")}"'
    return text


@dataclasses.dataclass(frozen=True)
class TraceRow:
    """One line of the terminal trace. `t` is seconds since the session opened."""

    t: float
    kind: str  # rx | tx | uds-req | uds-resp | error
    arb_id: int | None
    data: bytes = b""
    note: str = ""
    extended: bool = False


class _Tap:
    """Wraps a python-can bus so every frame sent or received — ISO-TP included — is recorded."""

    def __init__(self, bus: Any, record: Any) -> None:
        self._bus, self._record = bus, record

    def send(self, msg: Any, timeout: float | None = None) -> None:
        self._bus.send(msg, timeout=timeout)
        self._record("tx", msg)

    def recv(self, timeout: float | None = None) -> Any:
        msg = self._bus.recv(timeout=timeout)
        if msg is not None:
            self._record("rx", msg)
        return msg

    def shutdown(self) -> None:
        self._bus.shutdown()


class CanSession(QThread):
    """Opens the adapter, keeps receiving, and runs queued sends between reads. Never blocks the GUI."""

    opened = Signal()
    closed = Signal(str)  # "" on a normal stop, otherwise the error that ended the session

    def __init__(self, port: str, interface: str, bitrate: int, bus: Any | None = None, parent: Any = None) -> None:
        super().__init__(parent)
        self._port, self._interface, self._bitrate, self._bus = port, interface, bitrate, bus
        self._cmds: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self._stop = threading.Event()
        self._t0 = time.monotonic()
        self.rows: collections.deque[TraceRow] = collections.deque(maxlen=50_000)  # drained by the GUI

    # ── called from the GUI thread ──
    def send_frame(self, arb_id: int, data: bytes, extended: bool = False) -> None:
        self._cmds.put(("frame", arb_id, data, extended))

    def send_uds(self, tx_id: int, rx_id: int, payload: bytes, timeout: float = 2.0) -> None:
        self._cmds.put(("uds", tx_id, rx_id, payload, timeout))

    def stop(self) -> None:
        self._stop.set()
        self.wait(3000)

    # ── session thread ──
    def _push(self, kind: str, arb_id: int | None, data: bytes = b"", note: str = "", extended: bool = False) -> None:
        self.rows.append(TraceRow(time.monotonic() - self._t0, kind, arb_id, bytes(data), note, extended))

    def _record(self, kind: str, msg: Any) -> None:
        if getattr(msg, "is_error_frame", False):
            self._push("error", None, note=tr("Кадр ошибки на шине", "Error frame on the bus"))
            return
        self._push(kind, msg.arbitration_id, bytes(msg.data), ascii_preview(bytes(msg.data)), msg.is_extended_id)

    def run(self) -> None:
        try:
            link = J533CanLink(self._port, interface=self._interface, bitrate=self._bitrate, bus=self._bus)
        except Exception as exc:  # adapter missing, port busy, driver not installed…
            self.closed.emit(str(exc) or type(exc).__name__)
            return
        link.bus = _Tap(link.bus, self._record)
        self._t0 = time.monotonic()
        self.opened.emit()
        error = ""
        try:
            while not self._stop.is_set():
                try:
                    cmd = self._cmds.get_nowait()
                except queue.Empty:
                    link.bus.recv(timeout=0.02)  # the tap records it
                    continue
                try:
                    self._run_command(link, cmd)
                except Exception as exc:  # one bad request must not end the session
                    self._push("error", None, note=str(exc) or type(exc).__name__)
        except Exception as exc:  # the bus itself failed (adapter unplugged)
            error = str(exc) or type(exc).__name__
        finally:
            link.close()
        self.closed.emit(error)

    def _run_command(self, link: J533CanLink, cmd: tuple[Any, ...]) -> None:
        if cmd[0] == "frame":
            import can

            _, arb_id, data, extended = cmd
            link.bus.send(can.Message(arbitration_id=arb_id, data=data, is_extended_id=extended), timeout=1.0)
            return

        _, tx_id, rx_id, payload, timeout = cmd
        link.UDS_TX_ID, link.UDS_RX_ID = tx_id, rx_id
        link.drain_rx()
        self._push("uds-req", tx_id, payload)
        link.send_uds(payload)
        deadline = time.monotonic() + timeout
        while not self._stop.is_set():  # a 7F xx 78 chain must not keep a disconnect waiting
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(tr(f"Нет ответа от 0x{rx_id:X} за {timeout:g} с", f"No reply from 0x{rx_id:X} within {timeout:g} s"))
            try:
                resp = link.receive_uds(timeout=left)
            except TimeoutError:
                continue  # reported above with a readable message
            if len(resp) >= 3 and resp[0] == 0x7F and resp[2] == 0x78:
                deadline = time.monotonic() + P2_STAR_WAIT  # a 7F xx 78 extends the wait by P2*
                continue
            self._push("uds-resp", rx_id, resp, describe_uds(resp))
            return
