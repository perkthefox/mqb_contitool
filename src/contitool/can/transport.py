"""ISO-TP UDS (0x710/0x77A) and Factory RAM-Loader (0x6F0/0x6F1) CAN transport layer."""

from __future__ import annotations

from collections.abc import Iterator
import contextlib
import ctypes
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any

import can

from contitool.can.payloads import LOADER_SYNC, build_loader_packet
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationReporter

P2_STAR_WAIT = 6.0  # P2*server 5.0 s + 1 s for adapter latency
# Handing one classic frame to the adapter: 0.25 ms on the wire at 500 kbit/s plus USB/TCP latency. A second is
# fifty times the worst latency we have measured, so anything slower is a fault, and waiting longer only delays
# saying so — a retry loop around an ECU reset multiplies this wait by every frame it tries.
FRAME_SEND_TIMEOUT = 1.0
BLOCK_SEND_TIMEOUT = 5.0  # a whole ISO-TP block in one adapter call, so up to 0x20 frames at once
TRANSPORT_ERRORS = (TimeoutError, can.CanError)  # the link failed — as opposed to the ECU answering "no"


class UdsNegativeResponse(RuntimeError):
    """The ECU answered `7F <sid> <nrc>`: it heard the request and refused it. Never a transport failure."""

    def __init__(self, sid: int, nrc: int, resp: bytes) -> None:
        super().__init__(f"UDS negative response for 0x{sid:02X}: {resp.hex()}")
        self.sid, self.nrc, self.resp = sid, nrc, bytes(resp)


class UnexpectedUdsResponse(RuntimeError):
    """An answer arrived, but not to this request (wrong SID) — e.g. a late reply to an earlier one."""


ECHO_BYTES = {0x22: 2, 0x2E: 2, 0x31: 3, 0x36: 1}  # DID, DID, sub-function + routine id, block sequence counter


def positive_prefix(req: bytes) -> bytes:
    """What a positive answer to `req` starts with: SID + 0x40 and the bytes it echoes back.

    The adapters' own ISO-TP paths match on this, as ODIS does on the same VCI (its flash, PDUAPI_VW_#48:
    `76 <seq>`, `71 01 FF 00`, `6E F1 5A`, `62 <DID>`), so a late answer to an earlier request — a `76` for the
    previous block — is never taken for this one."""
    return bytes([(req[0] + 0x40) & 0xFF]) + bytes(req[1 : 1 + ECHO_BYTES.get(req[0], 0)])


def _checked_response(req_sid: int, resp: bytes, expected_sid: int | None) -> bytes:
    if len(resp) >= 3 and resp[0] == 0x7F and resp[1] == req_sid:
        raise UdsNegativeResponse(req_sid, resp[2], resp)
    if resp and resp[0] == 0x7F:  # a refusal, but of some other request
        raise UnexpectedUdsResponse(f"Unexpected UDS response for 0x{req_sid:02X}: {resp.hex()}")
    if expected_sid is not None and (not resp or resp[0] != expected_sid):
        raise UnexpectedUdsResponse(
            f"Unexpected UDS response for 0x{req_sid:02X} (expected 0x{expected_sid:02X}): {resp.hex()}"
        )
    return resp

_win_timer_lock = threading.Lock()
_win_timer_refs = 0


def _acquire_win_timer() -> bool:
    """Request 1 ms OS timer resolution on Windows so sub-millisecond CAN polls do not quantize to 15.6 ms."""
    global _win_timer_refs
    if sys.platform != "win32":
        return False
    with _win_timer_lock:
        if _win_timer_refs == 0:
            try:
                ctypes.windll.winmm.timeBeginPeriod(1)  # type: ignore[attr-defined]
            except Exception:
                return False
        _win_timer_refs += 1
        return True


def _release_win_timer() -> None:
    global _win_timer_refs
    if sys.platform != "win32":
        return
    with _win_timer_lock:
        if _win_timer_refs > 0:
            _win_timer_refs -= 1
            if _win_timer_refs == 0:
                try:
                    ctypes.windll.winmm.timeEndPeriod(1)  # type: ignore[attr-defined]
                except Exception:
                    pass


SLCAN_RX_BUFFER = 262_144  # 256 KB (>11,900 SLCAN frames = >93 KB of flash): keeps Windows usbser.sys from NAKing Bulk IN
SLCAN_TX_BUFFER = 65_536


def _pop_slcan_line(buf: bytearray) -> str | None:
    """Pop one complete `\\r`- or `\\x07`-terminated SLCAN line from `buf`, leaving any partial tail intact."""
    cr = buf.find(13)  # b"\r" (_OK / frame terminator)
    bel = buf.find(7)  # b"\x07" (_ERROR)
    if cr < 0 and bel < 0:
        return None
    cut = cr if bel < 0 else (bel if cr < 0 else min(cr, bel))
    line = bytes(buf[: cut + 1]).decode("ascii", errors="replace")
    del buf[: cut + 1]
    return line


def _tune_slcan_bus(bus: Any) -> None:
    """Replace python-can's byte-by-byte `serialPortOrig.read(1)` loop and enlarge Windows `usbser.sys` RX FIFO.

    `python-can`'s `slcanBus._read` calls `serialPortOrig.read(1)` once per ASCII byte — 22 Win32 overlapped `ReadFile`
    + `ClearCommError` + `GetOverlappedResult` kernel calls per 8-byte CAN frame (~70,000 IRPs/s during a 500 kbit/s
    RAM-Loader stream), capping Windows throughput around ~1,530 fps (~30 KB of a 64 KB block) and overflowing
    `usbser.sys`'s default 4 KB RX buffer even on a native USB-CDC CANable (`0x16D0:0x117E`). Reading `in_waiting`
    bytes in one bulk `ReadFile` and enlarging `SetupComm` to 256 KB cuts Win32 syscalls >100x so 64 KB bursts arrive
    with zero frame loss.
    """
    ser = getattr(bus, "serialPortOrig", None)
    buf = getattr(bus, "_buffer", None)
    if ser is None or not callable(getattr(ser, "read", None)) or not isinstance(buf, bytearray):
        return
    set_buf = getattr(ser, "set_buffer_size", None)
    if callable(set_buf):
        with contextlib.suppress(Exception):
            set_buf(rx_size=SLCAN_RX_BUFFER, tx_size=SLCAN_TX_BUFFER)

    from can.interfaces.slcan import error_check

    def _bulk_read(timeout: float | None) -> str | None:
        line = _pop_slcan_line(buf)
        if line is not None:
            return line
        deadline = None if timeout is None else (time.monotonic() + max(0.0, timeout))
        with error_check("Could not read from serial device"):
            while True:
                waiting = ser.in_waiting
                chunk = ser.read(waiting if waiting > 0 else 1)
                if chunk:
                    buf.extend(chunk)
                    if waiting == 0:
                        more = ser.in_waiting
                        if more > 0:
                            buf.extend(ser.read(more))
                    line = _pop_slcan_line(buf)
                    if line is not None:
                        return line
                if deadline is not None and time.monotonic() >= deadline:
                    return None

    bus._read = _bulk_read


class J533CanLink:
    """Clean, logged CAN bus link for Continental J533 Diagnosis CAN (500 kbit/s)."""

    UDS_TX_ID = 0x710
    UDS_RX_ID = 0x77A
    LOADER_TX_ID = 0x6F0
    LOADER_RX_ID = 0x6F1

    def __init__(
        self,
        port: str,
        *,
        interface: str = "slcan",
        bitrate: int = 500_000,
        tty_baudrate: int = 115_200,
        listen_only: bool = False,
        log_path: Path | None = None,
        bus: Any | None = None,
    ) -> None:
        self.port = port
        self.interface = interface
        self.tx_frames = 0
        self.rx_frames = 0
        self._hw_uds = False
        self._timer_held = False
        self._log_file = None
        self._borrowed: Any = None  # a kept-open bus this link only borrows, handed back in close()
        self.on_hw_fallback: Any = None  # called with a short reason when hardware ISO-TP gives way to software
        self._recycle_held = 0  # >0 inside a window where no TX link reopen may pause the stream
        self._rx_trace_suspended = 0  # >0 while streaming 200k 0x6F1 memory frames so json.dumps never starves RX
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = log_path.open("a", encoding="utf-8", buffering=1)

        if bus is not None:
            self.bus = bus
            self._owns_bus = False
        elif interface == "dpdu":
            from contitool.can import dpdu

            # Kept open between operations: reopening re-rolls which D-PDU module the driver hands out.
            self._borrowed = dpdu.open_session(port or "", bitrate)
            self.bus = self._borrowed
            self._owns_bus = False
        elif interface == "j2534":
            from contitool.can.j2534 import J2534Bus

            self.bus = J2534Bus(port, bitrate)
            self._owns_bus = True
        else:
            import can

            kwargs: dict[str, Any] = {
                "interface": interface,
                "channel": port,
                "bitrate": bitrate,
                "timeout": 0.1,
            }
            if interface == "slcan":
                kwargs["tty_baudrate"] = tty_baudrate
                kwargs["listen_only"] = listen_only
            self.bus = can.interface.Bus(**kwargs)
            if interface == "slcan":
                _tune_slcan_bus(self.bus)
            self._owns_bus = True
        self._timer_held = _acquire_win_timer()

    def close(self) -> None:
        if getattr(self, "_timer_held", False):
            _release_win_timer()
            self._timer_held = False
        if getattr(self, "_owns_bus", False) and getattr(self, "bus", None) is not None:
            try:
                self.bus.shutdown()
            except Exception:
                pass
            self._owns_bus = False
        if getattr(self, "_borrowed", None) is not None:
            from contitool.can import dpdu

            dpdu.release_session(self._borrowed)
            self._borrowed = None
        if self._log_file is not None:
            try:
                self._log_file.close()
            except Exception:
                pass
            self._log_file = None

    def __enter__(self) -> J533CanLink:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _write_trace(self, direction: str, arb_id: int, dlc: int, data: bytes) -> None:
        if self._log_file is not None and not (direction == "rx" and self._rx_trace_suspended):
            self._log_file.write(
                json.dumps(
                    {
                        "time": time.time(),
                        "direction": direction,
                        "id": f"0x{arb_id:x}",
                        "dlc": dlc,
                        "data": data.hex(),
                    }
                )
                + "\n"
            )

    @contextlib.contextmanager
    def suspend_rx_trace(self) -> Iterator[None]:
        """Skip per-frame JSONL writes during 200k-frame memory streams so disk I/O / GIL never starves VCI RX (#28)."""
        self._rx_trace_suspended += 1
        try:
            yield
        finally:
            self._rx_trace_suspended -= 1

    def write_stream_summary(self, address: int, expected: int, received: int, frames: int) -> None:
        """Record one compact summary line in `can.jsonl` for a streamed `0x6F1` memory burst."""
        if self._log_file is not None:
            self._log_file.write(
                json.dumps(
                    {
                        "time": time.time(),
                        "direction": "rx_stream",
                        "id": f"0x{self.LOADER_RX_ID:x}",
                        "address": f"0x{address:08x}",
                        "expected_bytes": expected,
                        "received_bytes": received,
                        "frames": frames,
                    }
                )
                + "\n"
            )

    def drain_rx(self, max_frames: int = 64, *, quick: bool = False) -> int:
        """Drain any stale buffered frames before starting a fresh handshake.

        `quick`: return at once when an slcan port has nothing waiting. python-can's slcan answers recv(timeout=0)
        only after one read at the serial port's own timeout (0.1 s) then; before every UDS request that was 0.1 s
        per `36` block (3.9 KB/s). The RAM-loader packets keep that read: their pacing on slcan was verified with it."""
        port = getattr(self.bus, "serialPortOrig", None) if quick else None
        parsed = getattr(self.bus, "_queue", None)  # slcan: lines already read from the port
        raw_buf = getattr(self.bus, "_buffer", None)
        drained = 0
        for _ in range(max_frames):
            has_buf_line = isinstance(raw_buf, bytearray) and (13 in raw_buf or 7 in raw_buf)
            if port is not None and not port.in_waiting and not (parsed and parsed.qsize()) and not has_buf_line:
                break
            try:
                msg = self.bus.recv(timeout=0.0)
            except can.CanOperationError as exc:
                from contitool.can.dpdu import FrameError

                if not isinstance(exc, FrameError):
                    raise
                drained += 1
                continue  # a result of the stale stream the bus could not interpret: thrown away with the rest
            if msg is None:
                if isinstance(raw_buf, bytearray) and (13 in raw_buf or 7 in raw_buf):
                    continue  # e.g. an slcan TX ack (`z\r` / `\r`) sat ahead of a real buffered frame
                break
            raw = bytes(msg.data)
            self.rx_frames += 1
            drained += 1
            if drained <= 32:
                self._write_trace("rx", msg.arbitration_id, msg.dlc, raw)
        return drained

    def drain_until_quiet(
        self,
        identifier: int | None = None,
        *,
        quiet_window: float = 0.08,
        max_wait: float = 2.5,
    ) -> int:
        """Drain frames until `identifier` (or the whole bus) stays silent for `quiet_window` seconds."""
        deadline = time.monotonic() + max_wait
        quiet_since = time.monotonic()
        discarded = 0
        while time.monotonic() < deadline:
            rem_quiet = quiet_window - (time.monotonic() - quiet_since)
            if rem_quiet <= 0:
                break
            wait = min(0.02, max(0.002, rem_quiet), max(0.001, deadline - time.monotonic()))
            try:
                msg = self.bus.recv(timeout=wait)
            except can.CanOperationError as exc:
                from contitool.can.dpdu import FrameError

                if not isinstance(exc, FrameError):
                    raise
                discarded += 1
                quiet_since = time.monotonic()
                continue
            if msg is None:
                continue
            self.rx_frames += 1
            if identifier is None or msg.arbitration_id == identifier:
                discarded += 1
                quiet_since = time.monotonic()
        return discarded

    def send_frame(self, identifier: int, data: bytes | bytearray, pad: int | None = None) -> None:
        import can

        raw = bytes(data)
        if pad is not None and len(raw) < 8:
            raw += bytes([pad]) * (8 - len(raw))
        message = can.Message(arbitration_id=identifier, data=raw, is_extended_id=False)
        self._write_trace("tx", identifier, message.dlc, raw)
        self.bus.send(message, timeout=FRAME_SEND_TIMEOUT)
        self.tx_frames += 1

    def receive_frame(self, identifier: int | None = None, timeout: float = 2.0) -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = self.bus.recv(timeout=min(0.1, max(0.005, deadline - time.monotonic())))
            if msg is None:
                continue
            raw = bytes(msg.data)
            self.rx_frames += 1
            self._write_trace("rx", msg.arbitration_id, msg.dlc, raw)
            if identifier is None or msg.arbitration_id == identifier:
                return msg
        target = f"0x{identifier:X}" if identifier is not None else "any ID"
        raise TimeoutError(f"No CAN frame from {target} within {timeout:.1f}s")

    def receive_flow_control(self, timeout: float = 2.0) -> tuple[int, int]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = self.receive_frame(self.UDS_RX_ID, timeout=max(0.05, deadline - time.monotonic()))
            pci_type = msg.data[0] >> 4
            fc_status = msg.data[0] & 0x0F
            if pci_type == 3:
                if fc_status == 0:
                    return msg.data[1], msg.data[2]
                if fc_status == 1:
                    continue  # FC.Wait
                raise RuntimeError(f"ISO-TP FlowControl Overflow/Abort from 0x77A: {bytes(msg.data).hex()}")
        raise TimeoutError("Timed out waiting for ISO-TP FlowControl from 0x77A")

    @staticmethod
    def _st_min_seconds(st_min: int) -> float:
        if 0x01 <= st_min <= 0x7F:
            return st_min / 1000.0
        if 0xF1 <= st_min <= 0xF9:
            return (st_min - 0xF0) / 10_000.0
        return 0.0

    def _maybe_recycle_tx(self) -> None:
        """Let the bus reopen a worn-out TX link, but only here: between whole requests or packets.

        Reopening costs a stop-communication wait plus several adapter round trips. In the middle of
        an ISO-TP block or a RAM-loader packet that gap outlives the receiver's tolerance, so the
        bus never recycles on its own - it waits to be asked at a boundary like this one.
        """
        if self._recycle_held:
            return
        recycle = getattr(self.bus, "maybe_recycle_tx", None)
        if callable(recycle):
            recycle()

    @contextlib.contextmanager
    def no_link_recycle(self) -> Iterator[None]:
        """A window where even a short pause breaks the protocol — the RAM-loader entry from `27 11` to the beacon.
        A reopen that falls due inside it waits for the next boundary after it."""
        self._recycle_held += 1
        try:
            yield
        finally:
            self._recycle_held -= 1

    def send_uds(self, uds_payload: bytes) -> None:
        """Send pure UDS service payload `[SID, ...]` using exact SingleFrame / MultiFrame framing."""
        payload = bytes(uds_payload)
        if not payload:
            raise ValueError("Empty UDS payload")
        self._maybe_recycle_tx()
        length = len(payload)
        if length <= 7:
            self.send_frame(self.UDS_TX_ID, bytes([length]) + payload, pad=0xAA)
            return
        self.send_frame(
            self.UDS_TX_ID,
            bytes([0x10 | (length >> 8), length & 0xFF]) + payload[:6],
        )
        block_size, st_min = self.receive_flow_control()
        seq = 1
        offset = 6
        sent = 0
        delay = self._st_min_seconds(st_min)
        while offset < length:
            if delay == 0 and hasattr(self.bus, "send_batch"):
                limit = (block_size - (sent % block_size)) if block_size else ((length - offset + 6) // 7)
                batch: list[Any] = []
                while offset < length and len(batch) < limit:
                    chunk = payload[offset : offset + 7]
                    raw = bytes([0x20 | seq]) + chunk
                    if len(raw) < 8:
                        raw += b"\x00" * (8 - len(raw))
                    msg = can.Message(arbitration_id=self.UDS_TX_ID, data=raw, is_extended_id=False)
                    self._write_trace("tx", self.UDS_TX_ID, msg.dlc, raw)
                    batch.append(msg)
                    seq = (seq + 1) & 0x0F
                    offset += len(chunk)
                    sent += 1
                self.bus.send_batch(batch, timeout=BLOCK_SEND_TIMEOUT)
                self.tx_frames += len(batch)
            else:
                chunk = payload[offset : offset + 7]
                self.send_frame(self.UDS_TX_ID, bytes([0x20 | seq]) + chunk, pad=0x00)
                seq = (seq + 1) & 0x0F
                offset += len(chunk)
                sent += 1
                if delay > 0:
                    time.sleep(delay)
            if block_size and sent % block_size == 0 and offset < length:
                block_size, st_min = self.receive_flow_control()
                delay = self._st_min_seconds(st_min)

    def receive_uds(self, timeout: float = 2.0) -> bytes:
        first = self.receive_frame(self.UDS_RX_ID, timeout=timeout)
        raw0 = bytes(first.data)
        kind = raw0[0] >> 4
        if kind == 0:
            sf_len = raw0[0] & 0x0F
            return raw0[1 : 1 + sf_len]
        if kind != 1:
            raise RuntimeError(f"Unexpected ISO-TP frame on 0x77A: {raw0.hex()}")
        length = ((raw0[0] & 0x0F) << 8) | raw0[1]
        output = bytearray(raw0[2:])
        self.send_frame(self.UDS_TX_ID, b"\x30\x00\x00", pad=0x00)
        while len(output) < length:
            msg = self.receive_frame(self.UDS_RX_ID, timeout=timeout)
            cf = bytes(msg.data)
            if (cf[0] >> 4) != 2:
                raise RuntimeError(f"Expected ISO-TP ConsecutiveFrame on 0x77A, got: {cf.hex()}")
            output.extend(cf[1:])
        return bytes(output[:length])

    @contextlib.contextmanager
    def uds_session(self) -> Iterator[bool]:
        """Use hardware ISO-TP (D-PDU ISO_15765 / J2534 ISO15765) for bulk UDS when the adapter supports it."""
        if self._hw_uds:
            yield True
            return
        bus_ctx = getattr(self.bus, "uds_session", None)
        if not callable(bus_ctx):
            yield False
            return
        with bus_ctx(self.UDS_TX_ID, self.UDS_RX_ID) as active:
            self._hw_uds = bool(active)
            try:
                yield self._hw_uds
            finally:
                self._hw_uds = False

    def drop_hw_uds(self) -> bool:
        """Leave the hardware ISO-TP path mid-transfer and finish on the verified software one.

        The adapter only proves it can segment once a real multi-block transfer runs, and by then the application
        is already erased — so a failure there must be recoverable, not fatal. Returns True if it was active."""
        if getattr(self.bus, "uds_only", False) or not self._hw_uds:
            return False
        self._hw_uds = False
        end = getattr(self.bus, "end_uds_session", None)
        if callable(end):
            end()
        return True

    def request_uds(
        self,
        uds_payload: bytes,
        expected_sid: int | None = None,
        *,
        timeout: float = 2.0,
        allow_pending: bool = True,
        resend: bool = True,
    ) -> bytes:
        """Send pure UDS request `[SID, ...]` and wait for response, handling `7F <SID> 78`.

        `resend=False` is for a request whose silence is a normal outcome (an ECU reset): a failure on the
        hardware path is raised as is instead of sending the request a second time on the software path."""
        req = bytes(uds_payload)
        if not req:
            raise ValueError("Empty UDS payload")
        req_sid = req[0]
        uds_only = bool(getattr(self.bus, "uds_only", False)) and (self.UDS_TX_ID, self.UDS_RX_ID) == (0x710, 0x77A)
        if self._hw_uds or uds_only:
            self._write_trace("uds_tx", self.UDS_TX_ID, len(req), req[:16])
            self.tx_frames += 1
            try:
                resp = self.bus.request_uds(req, timeout=timeout, allow_pending=allow_pending)
            except TRANSPORT_ERRORS as exc:
                if not resend:
                    raise
                # The adapter's ISO-TP failed. Mid-flash the application may already be erased, so this request
                # goes again on the verified software path instead of ending the operation. The ECU refusing
                # (a 7F answer) is not caught here: that is its answer, and no transport would change it.
                self.drop_hw_uds()
                if not uds_only:
                    self._write_trace("uds_hw_fallback", self.UDS_TX_ID, len(req), req[:16])
                if getattr(self.bus, "spent", False):
                    # The VCI itself is gone (it reboots, #19-#22): the software path would only fail on the next
                    # frame with "this link no longer works", after promising to carry on.
                    from contitool.can.dpdu import driver_unstable

                    # On a 30+ driver the same flash stops at the same place again: the way out is the 27.2 one.
                    again = tr(
                        "затем подключитесь через драйвер D-PDU 27.2 (идёт вместе с ContiTool) и запустите ту же "
                        "прошивку заново: на драйверах 30 и новее обрыв повторится.",
                        "then connect through D-PDU driver 27.2 (it comes with ContiTool) and run the same flash "
                        "again: on drivers 30 and newer it breaks off again.",
                    ) if driver_unstable(getattr(self.bus, "driver_version", "")) else tr(
                        "затем запустите ту же прошивку заново.", "then run the same flash again.")
                    raise can.CanOperationError(tr(
                        f"Связь с VCI потеряна посреди передачи ({req[:3].hex(' ').upper()}: {exc}): адаптер "
                        "перезагрузился или отключился, продолжить на этом соединении нельзя. Если шла прошивка, блок "
                        "остался в загрузчике FBL без приложения — это поправимо: выключите и включите питание блока и "
                        f"VCI, {again}",
                        f"Lost the VCI mid-transfer ({req[:3].hex(' ').upper()}: {exc}): the adapter rebooted or "
                        "disconnected, and this connection cannot go on. If a flash was running, the ECU stays in its "
                        "FBL bootloader without an application — which can be fixed: power-cycle the ECU and the VCI, "
                        f"{again}",
                    )) from exc
                if uds_only:
                    raise
                if self.on_hw_fallback is not None:
                    self.on_hw_fallback(f"{req[:3].hex(' ').upper()}: {exc}")
            else:
                self._write_trace("uds_rx", self.UDS_RX_ID, len(resp), resp[:16])
                self.rx_frames += 1
                return _checked_response(req_sid, resp, expected_sid)
        try:
            self.drain_rx(quick=True)  # a late answer to an earlier request must not be read as the answer to this one
            self.send_uds(req)
            deadline = time.monotonic() + timeout
            wait = 2.5
            while True:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError(f"UDS response timeout ({timeout:.1f}s) for {req[:8].hex()}")
                resp = self.receive_uds(timeout=min(wait, rem))
                if (
                    allow_pending
                    and len(resp) >= 3
                    and resp[0] == 0x7F
                    and resp[1] == req_sid
                    and resp[2] == 0x78
                ):
                    # After 78 the ECU has P2* (5000 ms, from `50 xx 00 32 01 F4`) for the next frame; the FBL repeats
                    # 78 every ~2.5 s, so waiting only 2.5 s raced it and broke an erase over a slower adapter.
                    wait = P2_STAR_WAIT
                    continue
                return _checked_response(req_sid, resp, expected_sid)
        except TimeoutError:
            fb = (
                getattr(self.bus, "fallback_from_silent_raw", None)
                if (resend and not self._recycle_held and (self.UDS_TX_ID, self.UDS_RX_ID) == (0x710, 0x77A))
                else None
            )
            if callable(fb) and fb():
                return self.request_uds(
                    req,
                    expected_sid,
                    timeout=timeout,
                    allow_pending=allow_pending,
                    resend=False,
                )
            raise

    def send_loader_payload(
        self,
        payload: bytes,
        *,
        inter_frame_delay: float = 0.003,
        reporter: OperationReporter = NULL_REPORTER,
        progress_label: str = "",
    ) -> int:
        """Synchronize (`84 00 00 00 00`) and stream a framed RAM-loader packet over 0x6F0."""
        packet = build_loader_packet(payload)
        self._maybe_recycle_tx()
        if self.drain_rx(max_frames=16_384):
            self.drain_until_quiet(self.LOADER_RX_ID, quiet_window=0.06, max_wait=2.0)
        self.send_frame(self.LOADER_TX_ID, LOADER_SYNC)
        sync_deadline = time.monotonic() + 2.0
        sync_rx = bytes(self.receive_frame(self.LOADER_RX_ID, timeout=2.0).data)
        while sync_rx != LOADER_SYNC:
            rem = min(0.15, sync_deadline - time.monotonic())
            if rem <= 0:
                break
            try:
                sync_rx = bytes(self.receive_frame(self.LOADER_RX_ID, timeout=rem).data)
            except TimeoutError:
                break
        if sync_rx != LOADER_SYNC:
            raise RuntimeError(f"Factory loader sync failed: got {sync_rx.hex()}")
        total = len(packet)
        for idx, offset in enumerate(range(0, total, 8)):
            t_frame = time.monotonic()
            self.send_frame(self.LOADER_TX_ID, packet[offset : offset + 8])
            if inter_frame_delay > 0:
                rem = inter_frame_delay - (time.monotonic() - t_frame)
                if rem > 0:
                    time.sleep(rem)
            if total > 1024 and (idx % 64 == 0 or offset + 8 >= total):
                reporter.progress(
                    min(offset + 8, total),
                    total,
                    unit="B",
                    detail=progress_label,
                )
        return total
