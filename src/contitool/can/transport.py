"""ISO-TP UDS (0x710/0x77A) and Factory RAM-Loader (0x6F0/0x6F1) CAN transport layer."""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any

from contitool.can.payloads import LOADER_SYNC, build_loader_packet
from contitool.progress import NULL_REPORTER, OperationReporter

P2_STAR_WAIT = 6.0  # P2*server 5.0 s + 1 s for adapter latency


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
        self._log_file = None
        self._borrowed: Any = None  # a kept-open bus this link only borrows, handed back in close()
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
            self._owns_bus = True

    def close(self) -> None:
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
        if self._log_file is not None:
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

    def drain_rx(self, max_frames: int = 64) -> None:
        """Drain any stale buffered frames before starting a fresh handshake."""
        for _ in range(max_frames):
            msg = self.bus.recv(timeout=0.0)
            if msg is None:
                break
            raw = bytes(msg.data)
            self.rx_frames += 1
            self._write_trace("rx", msg.arbitration_id, msg.dlc, raw)

    def send_frame(self, identifier: int, data: bytes | bytearray, pad: int | None = None) -> None:
        import can

        raw = bytes(data)
        if pad is not None and len(raw) < 8:
            raw += bytes([pad]) * (8 - len(raw))
        message = can.Message(arbitration_id=identifier, data=raw, is_extended_id=False)
        self._write_trace("tx", identifier, message.dlc, raw)
        self.bus.send(message, timeout=1.0)
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

    def send_uds(self, uds_payload: bytes) -> None:
        """Send pure UDS service payload `[SID, ...]` using exact SingleFrame / MultiFrame framing."""
        payload = bytes(uds_payload)
        if not payload:
            raise ValueError("Empty UDS payload")
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

    def request_uds(
        self,
        uds_payload: bytes,
        expected_sid: int | None = None,
        *,
        timeout: float = 2.0,
        allow_pending: bool = True,
    ) -> bytes:
        """Send pure UDS request `[SID, ...]` and wait for response, handling `7F <SID> 78`."""
        req = bytes(uds_payload)
        req_sid = req[0]
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
            if resp and resp[0] == 0x7F:
                raise RuntimeError(f"UDS negative response for 0x{req_sid:02X}: {resp.hex()}")
            if expected_sid is not None and (not resp or resp[0] != expected_sid):
                raise RuntimeError(
                    f"Unexpected UDS response for 0x{req_sid:02X} (expected 0x{expected_sid:02X}): {resp.hex()}"
                )
            return resp

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
        self.drain_rx()
        self.send_frame(self.LOADER_TX_ID, LOADER_SYNC)
        sync_rx = bytes(self.receive_frame(self.LOADER_RX_ID, timeout=2.0).data)
        if sync_rx != LOADER_SYNC:
            raise RuntimeError(f"Factory loader sync failed: got {sync_rx.hex()}")
        total = len(packet)
        for idx, offset in enumerate(range(0, total, 8)):
            self.send_frame(self.LOADER_TX_ID, packet[offset : offset + 8])
            if inter_frame_delay > 0:
                time.sleep(inter_frame_delay)
            if total > 1024 and (idx % 64 == 0 or offset + 8 >= total):
                reporter.progress(
                    min(offset + 8, total),
                    total,
                    unit="B",
                    detail=progress_label,
                )
        return total
