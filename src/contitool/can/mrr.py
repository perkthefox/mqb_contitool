"""VAG MQB 13 ACC Radar / J428 (Bosch MRR1Plus 3Q0 & MRRevo14F 5Q0/3QF) live CAN/UDS/XCP workflows."""

from __future__ import annotations

from collections.abc import Iterator
import contextlib
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any

import can

from contitool.can.bridge import j533_can_bridge
from contitool.can.transport import (
    FRAME_SEND_TIMEOUT,
    TRANSPORT_ERRORS,
    J533CanLink,
    UdsNegativeResponse,
    UnexpectedUdsResponse,
)
from contitool.core import dtc as _dtc_mod
from contitool.core.mrr import (
    C90FL_SECTORS_5674K,
    C90FL_SECTORS_5675K,
    MRR_APP_BASE,
    MRR_BOOT_BASE,
    MRR_BOOT_SIZE,
    MRR_CP_KEY_TYPE_GFA,
    MRR_CP_KEY_TYPE_IKA,
    MRR_DEV_ADDEND_0192,
    MRR_DFLASH_ADDR,
    MRR_DFLASH_SIZE,
    MRR_DRIVER_ADDRESS,
    MRR_DRIVER_CONTROL,
    MRR_DRIVER_CONTROL_SAVE_SIZE,
    MRR_FAST_CAN_CHUNK_SIZE,
    MRR_FAST_CAN_ID,
    MRR_FAST_CAN_TIMEOUT_LOOPS,
    MRR_FAST_WRITE_CHUNK_BYTES,
    MRR_FLASH_DRIVER_ADDRESS,
    MRR_FLASH_DRIVER_HALF_SIZE,
    MRR_FLASH_DRIVER_SIZE,
    MRR_FLASH_DRIVER_UPPER_PHYS,
    MRR_FLASH_SECTOR_DRIVER_ADDR,
    MRR_FLASH_STAGE_BUFFER,
    MRR_FLASH_STREAM_BATCH_BYTES,
    MRR_FLASH_STREAM_TIMEOUT_LOOPS,
    MRR_GEN1_SWAP_PACKAGES,
    MRR_LOGIN_XCP_GATE,
    MRR_SRAM_ADDR,
    MRR_SWAP_RSA_KEY_DID,
    MRR_SWAP_STATUS_ACTIVE,
    MRR_SWAP_STATUS_DID,
    MRR_SWAP_VCRN_DID,
    MRR_UDS_RX_ID,
    MRR_UDS_TX_ID,
    MRR_XCP_RX_ID,
    MRR_XCP_TX_ID,
    MrrFrfBlock,
    MrrFrfImage,
    mrr_apply_cp_disable_patch,
    mrr_apply_swap_patch,
    mrr_apply_swap_sites,
    mrr_build_cp_key_container,
    mrr_build_fast_read_control_block,
    mrr_build_fast_read_ram_driver,
    mrr_build_fast_write_ram_driver,
    mrr_build_flash_sector_write_driver,
    mrr_build_gen2_swap_group_stub,
    mrr_build_tlb1_0b_descriptor,
    mrr_decode_status_dids,
    mrr_describe_gen2_swap_groups,
    mrr_detect_profile,
    mrr_extract_cp_affected_sectors,
    mrr_extract_swap_affected_sectors,
    mrr_fblv_compute_key,
    mrr_frf_compatibility,
    mrr_get_eraserouti_driver,
    mrr_get_profile,
    mrr_inspect_cflash_cp_state,
    mrr_inspect_cflash_swap_state,
    mrr_inspect_swap_sites,
    mrr_is_virgin_ika,
    mrr_parse_dflash_fee,
    mrr_parse_swap_uds_response,
    mrr_read_frf,
    mrr_sum32_be,
    mrr_support_info,
    mrr_xcp_compute_key,
)
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationReporter

# Exact RX IDs from 13 ACC Radar on Extended CAN (ch2) -> J533 bridge hardware GAFL filter
MRR_BRIDGE_RX_FILTER: tuple[tuple[int, bool], ...] = (
    (MRR_UDS_RX_ID, False),
    (MRR_FAST_CAN_ID, False),
    (MRR_XCP_RX_ID, True),
)
# Elevated bridge idle_limit during silent 256 KiB C90FL sector erase + blank check (first_ready_timeout=20s)
MRR_BRIDGE_FLASH_IDLE_LIMIT = 160_000_000

MRR_PASSPORT_DIDS: tuple[tuple[str, int], ...] = (
    ("part_number", 0xF187),
    ("sw_version", 0xF189),
    ("hw_part_number", 0xF191),
    ("hw_version", 0xF1A3),
    ("fazit", 0xF17C),
    ("system_name", 0xF197),
    ("asam_odx", 0xF19E),
    ("odx_version", 0xF1A2),
    ("vin", 0xF190),
    ("coding", 0x0600),
)

MRR_STATUS_DIDS: tuple[int, ...] = (
    0x03DE,  # Component Protection counter / state (2 B)
    0x0440,  # KS info & virgin IKA / GFA missing flags (7 B)
    0x043F,  # KS 16-bit options mask (2 B)
    0x02E0,  # KS active challenge nonce (4 B)
    0x02F9,  # KS VCRN / FAZIT IEEE CRC-32 (5 B)
    0x0902,  # Adaptation channel including bit 3 XcpGate (1 B)
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


class MrrCanLink(J533CanLink):
    """CAN link for 13 ACC Radar (J428): 11-bit UDS `0x757/0x7C1`, 29-bit XCP `0x1BFEBA00/01`, 11-bit Fast CAN `0x77E`."""

    UDS_TX_ID = MRR_UDS_TX_ID
    UDS_RX_ID = MRR_UDS_RX_ID

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
        self.sw_profile = sw_profile.strip().upper() if sw_profile else None
        self._detected_sw: str | None = None
        self.xcp_tx_id = MRR_XCP_TX_ID
        self.xcp_rx_id = MRR_XCP_RX_ID
        self.fast_can_id = MRR_FAST_CAN_ID
        self.last_wd_kick_count = 0
        self.last_wd_challenge = 0
        self.last_read_used_fast = False

    def send_frame(self, identifier: int, data: bytes | bytearray, pad: int | None = 0xAA) -> None:
        raw = bytes(data)
        if len(raw) > 8:
            raise ValueError(f"Classic CAN frame cannot exceed 8 bytes (got {len(raw)})")
        if pad is not None and len(raw) < 8:
            raw = raw + bytes([pad & 0xFF]) * (8 - len(raw))
        is_ext = identifier > 0x7FF
        msg = can.Message(arbitration_id=identifier, is_extended_id=is_ext, data=raw)
        self._write_trace("tx", identifier, msg.dlc, raw)
        self.bus.send(msg, timeout=FRAME_SEND_TIMEOUT)
        self.tx_frames += 1

    def _should_use_hw_uds(self) -> bool:
        """Return True when the underlying bus requires hardware ISO-TP (`uds_only` / `nonraw` D-PDU)."""
        if self._hw_uds:
            return False
        bus_ctx = getattr(self.bus, "uds_session", None)
        if not callable(bus_ctx):
            return False
        return bool(getattr(self.bus, "uds_only", False)) or bool(getattr(self.bus, "nonraw", None))

    def request_uds(
        self,
        uds_payload: bytes,
        expected_sid: int | None = None,
        *,
        timeout: float = 2.0,
        allow_pending: bool = True,
        resend: bool = True,
    ) -> bytes:
        """Send UDS request on `0x757/0x7C1`, routing via `uds_session` on `uds_only`/`nonraw` D-PDU buses."""
        if self._should_use_hw_uds():
            with self.uds_session() as active:
                if not active and getattr(self.bus, "uds_only", False):
                    refusal = str(getattr(self.bus, "uds_refusal", "") or "").strip()
                    detail = f" ({refusal})" if refusal else ""
                    raise TimeoutError(
                        tr(
                            f"Адаптер D-PDU не смог открыть аппаратный канал UDS ISO-TP для 13 ACC Radar "
                            f"(0x{self.UDS_TX_ID:03X} → 0x{self.UDS_RX_ID:03X}){detail}.",
                            f"D-PDU adapter could not open a hardware UDS ISO-TP link for 13 ACC Radar "
                            f"(0x{self.UDS_TX_ID:03X} → 0x{self.UDS_RX_ID:03X}){detail}.",
                        )
                    )
                return super().request_uds(
                    uds_payload,
                    expected_sid,
                    timeout=timeout,
                    allow_pending=allow_pending,
                    resend=resend,
                )
        return super().request_uds(
            uds_payload,
            expected_sid,
            timeout=timeout,
            allow_pending=allow_pending,
            resend=resend,
        )

    def _recv_matching(self, identifiers: set[int], timeout: float) -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = self.bus.recv(timeout=min(0.05, max(0.002, deadline - time.monotonic())))
            if msg is None:
                continue
            raw = bytes(msg.data)
            self.rx_frames += 1
            self._write_trace("rx", msg.arbitration_id, msg.dlc, raw)
            if msg.arbitration_id in identifiers:
                return msg
        return None

    def read_did(self, did: int, *, timeout: float = 1.5) -> bytes:
        hi = (did >> 8) & 0xFF
        lo = did & 0xFF
        resp = self.request_uds(bytes([0x22, hi, lo]), 0x62, timeout=timeout)
        if len(resp) < 3 or resp[1] != hi or resp[2] != lo:
            raise UnexpectedUdsResponse(f"Unexpected ReadDataByIdentifier response for 0x{did:04X}: {resp.hex()}")
        return resp[3:]

    def read_passport(self) -> dict[str, Any]:
        passport: dict[str, Any] = {}
        raw_dids: dict[str, str] = {}
        for field_name, did in MRR_PASSPORT_DIDS:
            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                val = self.read_did(did, timeout=1.0)
                raw_dids[f"{did:04X}"] = val.hex()
                if field_name == "coding":
                    passport[field_name] = val.hex()
                else:
                    passport[field_name] = _clean_ascii(val)
        if not raw_dids:
            raise RuntimeError(
                tr(
                    "Радар 13 ACC (0x757 → 0x7C1) не ответил ни на один диагностический DID паспорта UDS. "
                    "Проверьте питание +12 В, массу, шину Extended CAN и терминатор 120 Ом.",
                    "13 ACC Radar (0x757 → 0x7C1) did not answer any UDS passport DID. "
                    "Check +12 V power, ground, Extended CAN wiring, and 120 Ω termination.",
                )
            )
        passport["raw_dids"] = raw_dids
        self._detected_sw = str(passport.get("sw_version") or "").strip().upper() or None
        profile = mrr_detect_profile(passport, sw_version=self.sw_profile or "")
        passport["detected_profile"] = profile["sw"]
        passport["profile_verified"] = bool(profile.get("verified", False))
        passport["family"] = profile["family"]
        passport["mcu"] = profile["mcu"]
        return passport

    def read_status_dids(self) -> dict[str, Any]:
        raw_dids: dict[str, str] = {}
        for did in MRR_STATUS_DIDS:
            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                val = self.read_did(did, timeout=1.0)
                raw_dids[f"{did:04X}"] = val.hex()
        decoded = mrr_decode_status_dids(raw_dids)
        decoded["raw_status_dids"] = raw_dids
        return decoded

    def read_swap_status_uds(
        self,
        *,
        include_metadata: bool = True,
        coding_raw: bytes | None = None,
        generation: int | None = None,
    ) -> dict[str, Any]:
        """Read standard UDS SWaP / FeC status (`22 3C 00`) plus optional metadata (`3C0A` VCRN, `3C05` RSA key, `0600` coding)."""
        with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            self.request_uds(b"\x10\x03", 0x50, timeout=1.5)
        fake_bus = getattr(self.bus, "__class__", None).__module__.startswith("tests")
        raw_3c00 = b""
        for attempt in range(3):
            raw_3c00 = self.read_did(MRR_SWAP_STATUS_DID, timeout=2.0)
            if len(raw_3c00) % 5 != 0:
                raise UnexpectedUdsResponse(
                    f"Unexpected UDS 22 3C 00 payload length ({len(raw_3c00)} B): {raw_3c00.hex()}"
                )
            checking = False
            for off in range(0, len(raw_3c00), 5):
                if raw_3c00[off : off + 4] in (b"\x00\x00\x00\x00", b"\xff\xff\xff\xff"):
                    continue
                st = raw_3c00[off + 4]
                if (st & 0x01) and (st & MRR_SWAP_STATUS_ACTIVE) != MRR_SWAP_STATUS_ACTIVE:
                    checking = True
                    break
            if not checking or attempt == 2:
                break
            time.sleep(0.02 if fake_bus else 0.6)

        raw_3c0a: bytes | None = None
        raw_3c05: bytes | None = None
        raw_0600: bytes | None = bytes(coding_raw) if coding_raw is not None else None
        if include_metadata:
            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                raw_3c0a = self.read_did(MRR_SWAP_VCRN_DID, timeout=1.2)
            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                raw_3c05 = self.read_did(MRR_SWAP_RSA_KEY_DID, timeout=2.0)
            if raw_0600 is None:
                with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                    raw_0600 = self.read_did(0x0600, timeout=1.2)

        return mrr_parse_swap_uds_response(
            raw_3c00,
            raw_3c0a=raw_3c0a,
            raw_3c05=raw_3c05,
            raw_0600=raw_0600,
            generation=generation,
        )

    def read_dtcs(self) -> list[dict[str, Any]]:
        """Read and decode 13 ACC Radar fault codes (`UDS 19 02 FF`) on the currently open link."""
        with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            self.request_uds(b"\x10\x03", 0x50, timeout=1.2)
        resp = self.request_uds(b"\x19\x02\xff", 0x59, timeout=3.0)
        active_dtcs: list[dict[str, Any]] = []
        stored_dtcs: list[dict[str, Any]] = []
        for off in range(3, len(resp) - 3, 4):
            code = int.from_bytes(resp[off:off + 3], "big")
            status = resp[off + 3]
            grp = _dtc_mod.group(status)
            if grp == "untested":
                continue
            disp, desc = _dtc_mod.describe_mrr(code)
            entry = {
                "code": f"0x{code:06X}",
                "code_int": code,
                "display": disp,
                "description": desc,
                "status": f"0x{status:02X}",
                "status_text": _dtc_mod.status_text(status),
                "group": grp,
                "active": grp == "active",
            }
            if grp == "active":
                active_dtcs.append(entry)
            else:
                stored_dtcs.append(entry)
        return active_dtcs + stored_dtcs

    # ── XCP on CAN (0x1BFEBA00 -> 0x1BFEBA01) ────────────────────────────────
    def xcp_request(self, payload: bytes, *, timeout: float = 0.6) -> bytes:
        raw = bytes(payload)
        if len(raw) > 8:
            raise ValueError(f"XCP CTO payload cannot exceed 8 bytes, got {len(raw)}")
        self.send_frame(self.xcp_tx_id, raw, pad=0x00)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rem = max(0.005, deadline - time.monotonic())
            msg = self._recv_matching({self.xcp_rx_id}, rem)
            if msg is None:
                continue
            data = bytes(msg.data)
            if not data:
                continue
            if data[0] == 0xFE:
                err_code = data[1] if len(data) > 1 else 0x00
                raise RuntimeError(f"XCP command {raw.hex()} returned ERR 0x{err_code:02X}")
            if data[0] == 0xFF:
                return data
        raise TimeoutError(f"Timed out waiting for XCP DTO 0x{self.xcp_rx_id:08X} on {raw.hex()}")

    def xcp_request_with_burst(
        self,
        payload: bytes,
        *,
        burst_id: int = MRR_FAST_CAN_ID,
        expected_frames: int = 0,
        timeout: float = 2.5,
    ) -> tuple[bytes, list[bytes]]:
        raw = bytes(payload)
        self.send_frame(self.xcp_tx_id, raw, pad=0x00)
        deadline = time.monotonic() + timeout
        burst: list[bytes] = []
        dto: bytes | None = None
        watch_ids = {self.xcp_rx_id, burst_id}
        while time.monotonic() < deadline:
            rem = max(0.002, deadline - time.monotonic())
            msg = self._recv_matching(watch_ids, rem)
            if msg is None:
                continue
            data = bytes(msg.data)
            if msg.arbitration_id == burst_id:
                if len(data) != 8:
                    raise RuntimeError(
                        f"Malformed burst frame on 0x{burst_id:03X}: expected 8 bytes, got {len(data)}"
                    )
                burst.append(data)
                if dto is not None and len(burst) >= expected_frames:
                    if len(burst) != expected_frames:
                        raise RuntimeError(
                            f"Burst frame count mismatch on 0x{burst_id:03X}: got {len(burst)}, expected {expected_frames}"
                        )
                    return dto, burst
                continue
            if msg.arbitration_id == self.xcp_rx_id and data:
                if data[0] == 0xFE:
                    code = data[1] if len(data) > 1 else 0
                    raise RuntimeError(f"XCP {raw.hex()} returned ERR 0x{code:02X}")
                if data[0] == 0xFF:
                    dto = data
                    if dto[:2] != b"\xFF\x00":
                        return dto, burst
                    if len(burst) >= expected_frames:
                        if len(burst) != expected_frames:
                            raise RuntimeError(
                                f"Burst frame count mismatch on 0x{burst_id:03X}: got {len(burst)}, expected {expected_frames}"
                            )
                        return dto, burst
        raise TimeoutError(
            f"XCP burst timeout on {raw.hex()} (got {len(burst)}/{expected_frames} frames)"
        )

    def xcp_connect_and_unlock(self, *, timeout: float = 0.6) -> bytes:
        fake_bus = getattr(self.bus, "__class__", None).__module__.startswith("tests")
        disconnect_timed_out = False
        try:
            self.xcp_request(b"\xFE\x00", timeout=0.15)
        except TimeoutError:
            disconnect_timed_out = True
        except Exception:
            pass
        self.drain_rx(max_frames=64, quick=True)
        if disconnect_timed_out and not fake_bus:
            self.drain_until_quiet(self.xcp_rx_id, quiet_window=0.05, max_wait=0.25)

        # Send CONNECT (0xFF 0x00) and discard any late/stale DISCONNECT ACK (`FF 00 00 00 00 00 00 00`)
        # so subsequent GET_SEED / UNLOCK responses never desynchronize.
        self.send_frame(self.xcp_tx_id, b"\xFF\x00", pad=0x00)
        deadline = time.monotonic() + timeout
        conn_resp: bytes | None = None
        while time.monotonic() < deadline:
            rem = max(0.005, deadline - time.monotonic())
            msg = self._recv_matching({self.xcp_rx_id}, rem)
            if msg is None:
                continue
            data = bytes(msg.data)
            if not data:
                continue
            if data[0] == 0xFE:
                err_code = data[1] if len(data) > 1 else 0x00
                raise RuntimeError(f"XCP command ff00 returned ERR 0x{err_code:02X}")
            if data[0] == 0xFF:
                if len(data) >= 4 and all(b == 0 for b in data[1:]):
                    continue  # stale/late DISCONNECT positive response (`FF 00 00 00 00 00 00 00`)
                conn_resp = data
                break
        if conn_resp is None:
            raise TimeoutError(f"Timed out waiting for XCP CONNECT DTO 0x{self.xcp_rx_id:08X}")

        for resource in (0x01, 0x04):
            seed_resp = self.xcp_request(bytes([0xF8, 0x00, resource]), timeout=timeout)
            if len(seed_resp) >= 6 and seed_resp[1] == 4:
                seed = int.from_bytes(seed_resp[2:6], "big")
                if seed != 0:
                    key = mrr_xcp_compute_key(seed)
                    self.xcp_request(bytes([0xF7, 0x04]) + key.to_bytes(4, "little"), timeout=timeout)
        self.drain_rx(max_frames=32, quick=True)
        return conn_resp

    def enable_xcp_gate_uds(self, *, reporter: OperationReporter = NULL_REPORTER) -> dict[str, Any]:
        """Enable persistent XcpGate (DID 0x0902 = 0x08) over UDS 10 03 -> 27 03/04 -> 2E F198 -> 2E 0902 08."""
        reporter.info(
            tr(
                "Активация XcpGate (DID 0x0902 = 0x08) через UDS (Login 24085)…",
                "Enabling XcpGate (DID 0x0902 = 0x08) over UDS (Login 24085)…",
            )
        )
        self.request_uds(b"\x10\x03", 0x50, timeout=1.5)
        live_sw = (self._detected_sw or self.sw_profile or "").strip().upper()
        if not live_sw:
            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                live_sw = _clean_ascii(self.read_did(0xF189, timeout=1.0)).strip().upper()

        unlocked = False
        used_addend = MRR_LOGIN_XCP_GATE
        last_nrc_35: UdsNegativeResponse | None = None
        last_err: Exception | None = None
        entered_4f = False

        for session_id, addend in ((0x03, MRR_LOGIN_XCP_GATE), (0x4F, MRR_DEV_ADDEND_0192)):
            if session_id == 0x4F and last_nrc_35 is not None and live_sw != "0192":
                break
            try:
                if session_id != 0x03:
                    self.request_uds(bytes([0x10, session_id]), 0x50, timeout=1.2)
                    entered_4f = True
                seed_resp = self.request_uds(b"\x27\x03", 0x67, timeout=1.2)
                if len(seed_resp) >= 6:
                    seed = int.from_bytes(seed_resp[2:6], "big")
                    if seed == 0:
                        unlocked = True
                        used_addend = addend
                        break
                    key = (seed + addend) & 0xFFFFFFFF
                    self.request_uds(b"\x27\x04" + key.to_bytes(4, "big"), 0x67, timeout=1.2)
                    unlocked = True
                    used_addend = addend
                    break
            except UdsNegativeResponse as exc:
                last_err = exc
                if exc.nrc in (0x36, 0x37):
                    if entered_4f:
                        with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                            self.request_uds(b"\x10\x03", 0x50, timeout=1.2)
                    nrc_name = "exceededNumberOfAttempts" if exc.nrc == 0x36 else "requiredTimeDelayNotExpired"
                    raise RuntimeError(
                        tr(
                            f"Доступ SecurityAccess (27 03/04) для активации XcpGate заблокирован таймером "
                            f"(NRC 0x{exc.nrc:02X} {nrc_name}): подождите ~10 минут при включённом питании "
                            "радара (не выключая +12 В) и повторите попытку.",
                            f"SecurityAccess (27 03/04) for XcpGate activation is locked out by time delay "
                            f"(NRC 0x{exc.nrc:02X} {nrc_name}): wait ~10 minutes with radar power ON "
                            "(do not cycle +12 V) and retry.",
                        )
                    ) from exc
                if exc.nrc == 0x35:
                    last_nrc_35 = exc
                    continue
                continue
            except (*TRANSPORT_ERRORS, UnexpectedUdsResponse) as exc:
                last_err = exc
                continue

        if entered_4f and not unlocked:
            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                self.request_uds(b"\x10\x03", 0x50, timeout=1.2)

        if not unlocked:
            if last_nrc_35 is not None:
                raise RuntimeError(
                    tr(
                        "Радар 13 ACC отклонил ключ SecurityAccess (27 04, NRC 0x35 invalidKey) при активации XcpGate: "
                        "логин доступа не принят текущей версией ПО (повторные неверные попытки включат блокировку NRC 0x36/0x37).",
                        "13 ACC Radar rejected the SecurityAccess key (27 04, NRC 0x35 invalidKey) while enabling XcpGate: "
                        "the login key was not accepted by this firmware (repeated failed attempts will trigger NRC 0x36/0x37 lockout).",
                    )
                ) from last_nrc_35
            detail = f": {last_err}" if last_err is not None else ""
            raise RuntimeError(
                tr(
                    f"Не удалось разблокировать SecurityAccess (27 03/04) радара 13 ACC перед записью XcpGate (DID 0x0902){detail}.",
                    f"Failed to unlock 13 ACC Radar SecurityAccess (27 03/04) before writing XcpGate (DID 0x0902){detail}.",
                )
            ) from last_err

        orig_0902 = 0x00
        with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            prev = self.read_did(0x0902, timeout=1.0)
            if prev:
                orig_0902 = prev[0]
        target_0902 = orig_0902 | 0x08

        with contextlib.suppress(Exception):
            self.request_uds(b"\x2E\xF1\x98" + bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]), 0x6E, timeout=1.2)

        self.request_uds(bytes([0x2E, 0x09, 0x02, target_0902]), 0x6E, timeout=1.5)
        readback = self.read_did(0x0902, timeout=1.2)
        return {
            "unlocked": unlocked,
            "addend": f"0x{used_addend:X}",
            "did_0902_hex": readback.hex(),
            "xcp_gate_enabled": bool(readback and (readback[0] & 0x08)),
        }

    def ensure_xcp_enabled(self, *, reporter: OperationReporter = NULL_REPORTER) -> dict[str, Any]:
        """Connect and unlock XCP; if XcpGate is closed, enable it over UDS first."""
        try:
            dto = self.xcp_connect_and_unlock(timeout=0.5)
            return {"connected": True, "auto_enabled_gate": False, "connect_dto": dto.hex()}
        except (TimeoutError, RuntimeError):
            gate_info = self.enable_xcp_gate_uds(reporter=reporter)
            dto = self.xcp_connect_and_unlock(timeout=1.0)
            return {
                "connected": True,
                "auto_enabled_gate": True,
                "connect_dto": dto.hex(),
                "gate_info": gate_info,
            }

    def xcp_set_mta(self, address: int, *, timeout: float = 0.6) -> None:
        self.xcp_request(bytes([0xF6, 0x00, 0x00, 0x00]) + (address & 0xFFFFFFFF).to_bytes(4, "big"), timeout=timeout)

    def xcp_build_checksum(self, address: int, length: int, *, timeout: float = 1.0) -> int:
        self.xcp_set_mta(address, timeout=timeout)
        resp = self.xcp_request(bytes([0xF3, 0x00, 0x00, 0x00]) + (length & 0xFFFFFFFF).to_bytes(4, "big"), timeout=timeout)
        if len(resp) < 8:
            raise RuntimeError(f"Short XCP BUILD_CHECKSUM response at 0x{address:08X}: {resp.hex()}")
        return int.from_bytes(resp[4:8], "big")

    def verify_region_checksum(
        self,
        address: int,
        data: bytes,
        *,
        block_size: int = 0x0400,
        timeout: float = 1.5,
    ) -> None:
        """Verify `data` against live ECU memory via XCP `BUILD_CHECKSUM` (`0xF3`, `ADD_44`).

        Bosch MRR XCP firmware enforces a hard maximum `BUILD_CHECKSUM` block size of `0x0400` (1024 B,
        returning `ERR_OUT_OF_RANGE 0x22` for larger blocks) and post-increments MTA by `block_size`.
        """
        if len(data) % 4 != 0:
            raise ValueError(f"Region length for BUILD_CHECKSUM must be 4-byte aligned, got {len(data)}")
        step = min(max(4, int(block_size) & ~3), 0x0400)
        if not data:
            return
        self.xcp_set_mta(address, timeout=timeout)
        for off in range(0, len(data), step):
            chunk = data[off : off + step]
            expected = mrr_sum32_be(chunk)
            resp = self.xcp_request(
                bytes([0xF3, 0x00, 0x00, 0x00]) + len(chunk).to_bytes(4, "big"),
                timeout=timeout,
            )
            if len(resp) < 8:
                raise RuntimeError(f"Short XCP BUILD_CHECKSUM response at 0x{address + off:08X}: {resp.hex()}")
            actual = int.from_bytes(resp[4:8], "big")
            if actual != expected:
                raise RuntimeError(
                    tr(
                        f"Ошибка проверки контрольной суммы XCP BUILD_CHECKSUM по адресу 0x{address + off:08X} "
                        f"({len(chunk)} Б): получено 0x{actual:08X}, ожидалось 0x{expected:08X}. "
                        "Стирание Code Flash отменено — повторите чтение сектора.",
                        f"XCP BUILD_CHECKSUM mismatch at 0x{address + off:08X} ({len(chunk)} B): "
                        f"got 0x{actual:08X}, expected 0x{expected:08X}. "
                        "Code Flash erase aborted — re-read the sector.",
                    )
                )

    def xcp_read_memory(
        self,
        address: int,
        length: int,
        *,
        timeout: float = 0.6,
        use_checksum_skip: bool = False,
        reporter: OperationReporter = NULL_REPORTER,
        label: str = "",
    ) -> bytes:
        """Read memory over standard XCP SHORT_UPLOAD (0xF4), optionally skipping 1 KiB 0xFF flash blocks via ADD_44."""
        if address < 0 or length < 0 or address + length > 0x100000000:
            raise ValueError(f"Invalid XCP read range: 0x{address:08X} + 0x{length:X}")
        output = bytearray()
        started = time.monotonic()
        if use_checksum_skip:
            reporter.warning(
                tr(
                    "Включён эвристический пропуск пустых блоков (use_checksum_skip, ADD_44): для критических "
                    "бэкапов и прошивки секторов рекомендуется полное чтение без пропуска.",
                    "Heuristic blank-block skipping (use_checksum_skip, ADD_44) is enabled: full reads without "
                    "skipping are recommended for critical backups and flash programming.",
                )
            )

        while len(output) < length:
            reporter.check_cancelled()
            current = address + len(output)
            rem = length - len(output)
            if use_checksum_skip and (current % 1024 == 0) and rem >= 1024:
                with contextlib.suppress(Exception):
                    # Require 4 independent 256 B ADD_44 sub-checksums (0xFFFFFFC0 each) PLUS head/mid/tail
                    # SHORT_UPLOAD probes so a single 32-bit ADD_44 collision across 1 KiB cannot skip non-0xFF bytes.
                    if (
                        self.xcp_build_checksum(current, 1024, timeout=timeout) == 0xFFFFFF00
                        and all(
                            self.xcp_build_checksum(current + q_off, 256, timeout=timeout) == 0xFFFFFFC0
                            for q_off in (0, 256, 512, 768)
                        )
                        and all(
                            self.xcp_read_memory(current + p_off, 7, timeout=timeout, use_checksum_skip=False)
                            == b"\xFF" * 7
                            for p_off in (0, 512, 1017)
                        )
                    ):
                        output.extend(b"\xFF" * 1024)
                        continue
            size = min(7, rem)
            resp = self.xcp_request(
                bytes([0xF4, size, 0x00, 0x00]) + current.to_bytes(4, "big"),
                timeout=timeout,
            )
            if len(resp) < size + 1:
                raise RuntimeError(f"Short XCP SHORT_UPLOAD response at 0x{current:08X}: {resp.hex()}")
            output.extend(resp[1:size + 1])
            if label and length >= 4096 and (len(output) % 2048 < 7 or len(output) == length):
                dt = max(time.monotonic() - started, 1e-6)
                reporter.progress(
                    len(output),
                    length,
                    unit="B",
                    detail=f"{label}: {len(output) // 1024}/{length // 1024} KiB ({len(output) / dt:.0f} B/s)",
                )
        return bytes(output)

    def xcp_write_ram_unchecked(
        self,
        address: int,
        data: bytes,
        *,
        ram_end: int = 0x4005E000,
        timeout: float = 0.6,
    ) -> None:
        if address < MRR_SRAM_ADDR or address + len(data) > ram_end:
            raise ValueError(
                f"RAM writes are restricted to 0x{MRR_SRAM_ADDR:08X}..0x{ram_end - 1:08X}"
            )
        self.xcp_set_mta(address, timeout=timeout)
        for offset in range(0, len(data), 6):
            chunk = data[offset:offset + 6]
            self.xcp_request(bytes([0xF0, len(chunk)]) + chunk, timeout=timeout)

    def xcp_write_ram(
        self,
        address: int,
        data: bytes,
        *,
        verify: bool = True,
        ram_end: int = 0x4005E000,
        timeout: float = 0.6,
    ) -> bytes:
        self.xcp_write_ram_unchecked(address, data, ram_end=ram_end, timeout=timeout)
        if not verify:
            return data
        readback = self.xcp_read_memory(address, len(data), timeout=timeout)
        if readback != data:
            raise RuntimeError(
                f"XCP RAM readback mismatch at 0x{address:08X}: expected {data.hex()}, got {readback.hex()}"
            )
        return readback

    def xcp_inspect_live_cp_patch_state(
        self,
        *,
        profile: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Read the 7 CP patch sites directly from Code Flash over XCP (<25 ms) and classify stock vs cp_disabled."""
        prof = profile or mrr_get_profile(self.sw_profile or "0192")
        points: list[dict[str, Any]] = []
        stock_count = 0
        patched_count = 0
        for name, address, expected_hex, replacement_hex in prof["patches"]:
            expected = bytes.fromhex(expected_hex)
            replacement = bytes.fromhex(replacement_hex)
            actual = self.xcp_read_memory(int(address), len(expected))
            if actual == expected:
                state = "stock"
                stock_count += 1
            elif actual == replacement:
                state = "cp_disabled"
                patched_count += 1
            else:
                state = "unknown"
            points.append({
                "name": name,
                "physical_address": f"0x{int(address):08X}",
                "stock_hex": expected_hex,
                "patched_hex": replacement_hex,
                "actual_hex": actual.hex(),
                "state": state,
            })
        total = len(points)
        if patched_count == total:
            overall = "cp_disabled"
        elif stock_count == total:
            overall = "stock"
        elif patched_count > 0 and stock_count > 0:
            overall = "partial"
        else:
            overall = "unknown"
        return {
            "unit": prof["unit"],
            "sw": prof["sw"],
            "cp_patch_state": overall,
            "stock_points": stock_count,
            "patched_points": patched_count,
            "total_points": total,
            "points": points,
        }

    def xcp_inspect_live_swap_patch_state(
        self,
        *,
        profile: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Read the SWaP / FSC + UDS 22 3C 00 patch sites directly from Code Flash over XCP and classify state."""
        prof = profile or mrr_get_profile(self.sw_profile or "0192")
        return mrr_inspect_swap_sites(prof, self.xcp_read_memory)

    def xcp_configure_sram_exec(
        self,
        executable: bool = True,
        *,
        profile: dict[str, Any] | None = None,
    ) -> None:
        """Return-safe TLB1[0x0B / 0x14] SX configuration via MMU_DISPATCH_WRAPPER -> MMU_LOAD_SINGLE_ENTRY."""
        prof = profile or mrr_get_profile(self.sw_profile or "0192")
        r3_arg_state = int(prof["xcp_r3_arg_state"])
        synch_slot = int(prof["xcp_synch_slot"])
        mmu_wrapper = int(prof["mmu_dispatch_wrapper"])
        mmu_entry = int(prof["mmu_load_single_entry"])
        ram_end = int(prof["ram_safe_end"])
        tlb1_entry = int(prof.get("tlb1_sram_entry") or 0x0B)
        mmu_mode = str(prof.get("mmu_dispatch_mode") or "direct")

        arg_state = (0).to_bytes(4, "big") + (MRR_DRIVER_CONTROL + 8).to_bytes(4, "big")
        self.xcp_write_ram(r3_arg_state, arg_state, ram_end=ram_end)
        self.xcp_write_ram(
            MRR_DRIVER_CONTROL + 8,
            mrr_build_tlb1_0b_descriptor(
                executable,
                mmu_load_single_entry=mmu_entry,
                tlb1_entry=tlb1_entry,
                mmu_dispatch_mode=mmu_mode,
            ),
            ram_end=ram_end,
        )
        saved_ptr_48: bytes | None = None
        if tlb1_entry != 0x0B:
            saved_ptr_48 = self.xcp_read_memory(0x40000048, 4)
            self.xcp_write_ram(0x40000048, (MRR_DRIVER_CONTROL + 0x14).to_bytes(4, "big"), ram_end=ram_end)
        try:
            self.xcp_write_ram(synch_slot, mmu_wrapper.to_bytes(4, "big"), ram_end=ram_end)
            self.xcp_request(b"\xFC\x00", timeout=1.0)
        finally:
            if saved_ptr_48 is not None:
                with contextlib.suppress(Exception):
                    self.xcp_write_ram(0x40000048, saved_ptr_48, ram_end=ram_end)

    def xcp_read_fast_regions(
        self,
        regions: list[tuple[str, int, int]],
        *,
        profile: dict[str, Any] | None = None,
        timeout_loops: int = MRR_FAST_CAN_TIMEOUT_LOOPS,
        reporter: OperationReporter = NULL_REPORTER,
    ) -> list[tuple[str, bytes, int, float]]:
        """Read one or more memory regions using the 25 KiB/s 0x77E burst RAM driver (with automatic XCP fallback)."""
        prof = profile or mrr_get_profile(self.sw_profile or "0192")
        self.last_read_used_fast = False
        non_empty = [(name, addr, size) for name, addr, size in regions if size > 0]
        if not non_empty:
            return [(name, b"", 0, 0.0) for name, _, _ in regions]

        can_use_fast = (
            bool(prof.get("verified", True))
            and bool(prof.get("fast_driver_supported"))
            and all((addr & 3) == 0 and (size & 7) == 0 for _, addr, size in non_empty)
        )
        synch_slot = int(prof.get("xcp_synch_slot") or 0)
        synch_default = int(prof.get("xcp_synch_default") or 0).to_bytes(4, "big")
        r3_arg_state = int(prof.get("xcp_r3_arg_state") or 0)
        ram_end = int(prof.get("ram_safe_end") or 0x4005E000)

        original_slot = b""
        if can_use_fast and synch_slot:
            original_slot = self.xcp_read_memory(synch_slot, 4)
            if original_slot != synch_default:
                can_use_fast = False

        if not can_use_fast:
            results: list[tuple[str, bytes, int, float]] = []
            for name, reg_addr, reg_len in regions:
                reporter.check_cancelled()
                if reg_len == 0:
                    results.append((name, b"", 0, 0.0))
                    continue
                t0 = time.monotonic()
                data = self.xcp_read_memory(
                    reg_addr,
                    reg_len,
                    use_checksum_skip=False,
                    reporter=reporter,
                    label=name,
                )
                elapsed = time.monotonic() - t0
                results.append((name, data, (reg_len + 6) // 7, elapsed))
            return results

        dto_buf = int(prof.get("xcp_dto_buffer") or 0x4003A26C)
        driver_code = mrr_build_fast_read_ram_driver(dto_buffer_addr=dto_buf)
        ctrl_save_size = 0x70 if int(prof.get("tlb1_sram_entry") or 0x0B) != 0x0B else 0x3C
        original_arg_state = self.xcp_read_memory(r3_arg_state, 8)
        original_control = self.xcp_read_memory(MRR_DRIVER_CONTROL, ctrl_save_size)
        original_payload = self.xcp_read_memory(MRR_DRIVER_ADDRESS, len(driver_code))
        self.last_read_used_fast = True
        try:
            self.xcp_configure_sram_exec(True, profile=prof)
            self.xcp_write_ram(MRR_DRIVER_ADDRESS, driver_code, ram_end=ram_end)
            first_addr, first_len = non_empty[0][1], non_empty[0][2]
            initial_frames = min(64, (first_len + 7) // 8)
            initial_ctrl = mrr_build_fast_read_control_block(
                first_addr,
                initial_frames * 8,
                timeout_loops=timeout_loops,
            )
            self.xcp_write_ram(MRR_DRIVER_CONTROL, initial_ctrl, ram_end=ram_end)
            self.xcp_write_ram(synch_slot, MRR_DRIVER_ADDRESS.to_bytes(4, "big"), ram_end=ram_end)
            self.drain_rx(max_frames=64, quick=True)
            state = {
                "expected_addr": first_addr,
                "last_frames": initial_frames,
            }
            results = []
            with self.suspend_rx_trace():
                for name, reg_addr, reg_len in regions:
                    if reg_len == 0:
                        results.append((name, b"", 0, 0.0))
                        continue
                    reg_started = time.monotonic()
                    output = bytearray()
                    calls = 0
                    while len(output) < reg_len:
                        reporter.check_cancelled()
                        chunk_addr = reg_addr + len(output)
                        chunk_len = min(MRR_FAST_CAN_CHUNK_SIZE, reg_len - len(output))
                        n_frames = (chunk_len + 7) // 8
                        chunk_data: bytes | None = None
                        last_chunk_err: Exception | None = None
                        for chunk_try in range(3):
                            if chunk_try > 0 or chunk_addr != state["expected_addr"] or n_frames != state["last_frames"]:
                                if chunk_try > 0:
                                    self.drain_rx(max_frames=128, quick=True)
                                if chunk_try == 0 and n_frames == state["last_frames"]:
                                    self.xcp_write_ram_unchecked(
                                        MRR_DRIVER_CONTROL,
                                        chunk_addr.to_bytes(4, "big"),
                                        ram_end=ram_end,
                                    )
                                else:
                                    self.xcp_write_ram_unchecked(
                                        MRR_DRIVER_CONTROL,
                                        chunk_addr.to_bytes(4, "big") + n_frames.to_bytes(4, "big"),
                                        ram_end=ram_end,
                                    )
                                    state["last_frames"] = n_frames
                            try:
                                dto, frames = self.xcp_request_with_burst(
                                    b"\xFC\x00",
                                    burst_id=self.fast_can_id,
                                    expected_frames=n_frames,
                                    timeout=2.5,
                                )
                            except (TimeoutError, RuntimeError) as exc:
                                last_chunk_err = exc
                                state["expected_addr"] = -1
                                continue
                            if dto[:2] != b"\xFF\x00":
                                raise RuntimeError(f"Fast RAM reader error at 0x{chunk_addr:08X}: {dto.hex()}")
                            joined = b"".join(frames)
                            if len(frames) != n_frames or len(joined) < chunk_len:
                                last_chunk_err = RuntimeError(
                                    f"Incomplete burst at 0x{chunk_addr:08X}: {len(frames)}/{n_frames} frames ({len(joined)} B)"
                                )
                                state["expected_addr"] = -1
                                continue
                            chunk_data = joined[:chunk_len]
                            break
                        if chunk_data is None:
                            assert last_chunk_err is not None
                            raise last_chunk_err
                        state["expected_addr"] = (chunk_addr + n_frames * 8) & 0xFFFFFFFF
                        output.extend(chunk_data)
                        calls += 1
                        if reg_len >= 8192 and (len(output) % 16384 == 0 or len(output) == reg_len):
                            dt = max(time.monotonic() - reg_started, 1e-6)
                            reporter.progress(
                                len(output),
                                reg_len,
                                unit="B",
                                detail=f"{name}: {len(output) // 1024}/{reg_len // 1024} KiB ({len(output) / dt:.0f} B/s)",
                            )
                    results.append((name, bytes(output), calls, time.monotonic() - reg_started))
            return results
        finally:
            had_exc = sys.exc_info()[0] is not None
            cleanup_err: Exception | None = None
            for step_name, fn in (
                ("restore_synch_pre", lambda: self.xcp_write_ram(synch_slot, original_slot, ram_end=ram_end)),
                ("disable_sram_exec", lambda: self.xcp_configure_sram_exec(False, profile=prof)),
                ("restore_synch_post", lambda: self.xcp_write_ram(synch_slot, original_slot, ram_end=ram_end)),
                ("restore_arg_state", lambda: self.xcp_write_ram(r3_arg_state, original_arg_state, ram_end=ram_end)),
                ("restore_ctrl", lambda: self.xcp_write_ram(MRR_DRIVER_CONTROL, original_control, ram_end=ram_end)),
                ("restore_payload", lambda: self.xcp_write_ram(MRR_DRIVER_ADDRESS, original_payload, ram_end=ram_end)),
            ):
                try:
                    fn()
                except Exception as exc:  # noqa: BLE001
                    if cleanup_err is None:
                        cleanup_err = exc
                    reporter.warning(
                        tr(
                            f"Предупреждение при очистке SRAM после Fast-чтения ({step_name}): {exc}",
                            f"SRAM cleanup warning after Fast read ({step_name}): {exc}",
                        )
                    )
            if cleanup_err is not None and not had_exc:
                raise cleanup_err

    def _stream_on_ready(
        self,
        data: bytes,
        start_addr: int,
        *,
        count_in_bytes: bool = False,
        first_ready_timeout: float = 20.0,
        batch_timeout: float = 5.0,
        label: str = "stream",
        reporter: OperationReporter = NULL_REPORTER,
    ) -> tuple[bytes, int, float]:
        if not data or (len(data) % 8) != 0:
            raise ValueError("Stream payload length must be a positive multiple of 8")
        if count_in_bytes and (len(data) % MRR_FLASH_STREAM_BATCH_BYTES) != 0:
            raise ValueError("Flash stream payload length must be a multiple of 64")
        self.drain_rx(max_frames=64, quick=True)
        self.send_frame(self.xcp_tx_id, b"\xFC\x00", pad=0x00)
        started = time.monotonic()
        total = len(data)
        batches = 0
        next_offset = 0
        last_sent_offset: int | None = None
        watch_ids = {self.fast_can_id, self.xcp_rx_id}

        while True:
            wait_sec = first_ready_timeout if next_offset == 0 else batch_timeout
            deadline = time.monotonic() + wait_sec
            got_event = False
            while time.monotonic() < deadline:
                rem = max(0.002, deadline - time.monotonic())
                msg = self._recv_matching(watch_ids, rem)
                if msg is None:
                    continue
                can_id = msg.arbitration_id
                fdata = bytes(msg.data)
                if can_id == self.fast_can_id and len(fdata) == 8:
                    ready_addr = int.from_bytes(fdata[0:4], "big")
                    ready_rem = int.from_bytes(fdata[4:8], "big")
                    offset = (ready_addr - start_addr) & 0xFFFFFFFF
                    if offset not in (next_offset, last_sent_offset) or offset >= total:
                        exp_addr = (start_addr + min(next_offset, total)) & 0xFFFFFFFF
                        exp_rem = (
                            (total - min(next_offset, total))
                            if count_in_bytes
                            else ((total - min(next_offset, total)) // 8)
                        )
                        raise RuntimeError(
                            f"{label} READY mismatch at +0x{next_offset:X}: "
                            f"got (0x{ready_addr:08X}, 0x{ready_rem:X}), "
                            f"expected (0x{exp_addr:08X}, 0x{exp_rem:X})"
                        )
                    exp_rem = (total - offset) if count_in_bytes else ((total - offset) // 8)
                    if ready_rem != exp_rem:
                        raise RuntimeError(
                            f"{label} READY remaining count mismatch at +0x{offset:X}: "
                            f"got 0x{ready_rem:X}, expected 0x{exp_rem:X}"
                        )
                    batch = data[offset:offset + MRR_FLASH_STREAM_BATCH_BYTES]
                    for f_off in range(0, len(batch), 8):
                        self.send_frame(self.xcp_tx_id, batch[f_off:f_off + 8], pad=0x00)
                    last_sent_offset = offset
                    if offset == next_offset:
                        batches += 1
                        next_offset = offset + len(batch)
                        if total >= 8192 and (next_offset % 16384 == 0 or next_offset == total):
                            dt = max(time.monotonic() - started, 1e-6)
                            reporter.progress(
                                next_offset,
                                total,
                                unit="B",
                                detail=f"{label}: {next_offset // 1024}/{total // 1024} KiB ({next_offset / dt:.0f} B/s)",
                            )
                    got_event = True
                    break
                if can_id == self.xcp_rx_id and fdata:
                    if fdata[0] == 0xFE:
                        code = fdata[1] if len(fdata) > 1 else 0
                        raise RuntimeError(f"{label} returned XCP ERR 0x{code:02X}")
                    if fdata[0] == 0xFF:
                        if next_offset < total:
                            raise RuntimeError(
                                f"{label} terminated early at +0x{next_offset:X}: DTO {fdata.hex()}"
                            )
                        return fdata, batches, time.monotonic() - started
            if not got_event:
                if next_offset < total:
                    raise TimeoutError(f"{label} timeout waiting for 0x77E READY at +0x{next_offset:X}")
                raise TimeoutError(f"{label} timeout waiting for final XCP DTO")

    def _write_fast_ram_raw(
        self,
        regions: list[tuple[str, int, bytes]],
        *,
        profile: dict[str, Any],
        timeout_loops: int = MRR_FLASH_STREAM_TIMEOUT_LOOPS,
        reporter: OperationReporter = NULL_REPORTER,
    ) -> list[tuple[str, int, float]]:
        synch_slot = int(profile["xcp_synch_slot"])
        ram_end = int(profile["ram_safe_end"])
        sbc_tb = int(profile.get("sbc_last_tb_addr") or 0x40025E28)
        dto_buf = int(profile.get("xcp_dto_buffer") or 0x4003A26C)
        fast_wr_drv = mrr_build_fast_write_ram_driver(sbc_last_tb_addr=sbc_tb, dto_buffer_addr=dto_buf)
        self.xcp_write_ram(MRR_DRIVER_ADDRESS, fast_wr_drv, ram_end=ram_end)
        self.xcp_write_ram(synch_slot, MRR_DRIVER_ADDRESS.to_bytes(4, "big"), ram_end=ram_end)
        self.xcp_write_ram(MRR_DRIVER_CONTROL + 0x0C, timeout_loops.to_bytes(4, "big"), ram_end=ram_end)
        self.xcp_write_ram(MRR_DRIVER_CONTROL + 0x60, b"\x00" * 8, ram_end=ram_end)
        results: list[tuple[str, int, float]] = []

        for name, address, data in regions:
            if not data:
                results.append((name, 0, 0.0))
                continue
            aligned_len = (len(data) // 8) * 8
            batches = 0
            stream_sec = 0.0
            if aligned_len > 0:
                chunk_offset = 0
                last_n_frames: int | None = None
                while chunk_offset < aligned_len:
                    chunk_bytes = min(MRR_FAST_WRITE_CHUNK_BYTES, aligned_len - chunk_offset)
                    n_frames = chunk_bytes // 8
                    if chunk_offset == 0:
                        self.xcp_write_ram_unchecked(
                            MRR_DRIVER_CONTROL,
                            (address + chunk_offset).to_bytes(4, "big") + n_frames.to_bytes(4, "big"),
                            ram_end=ram_end,
                        )
                        last_n_frames = n_frames
                    elif n_frames != last_n_frames:
                        self.xcp_write_ram_unchecked(
                            MRR_DRIVER_CONTROL + 4,
                            n_frames.to_bytes(4, "big"),
                            ram_end=ram_end,
                        )
                        last_n_frames = n_frames
                    dto, c_batches, c_sec = self._stream_on_ready(
                        data[chunk_offset:chunk_offset + chunk_bytes],
                        address + chunk_offset,
                        count_in_bytes=False,
                        first_ready_timeout=5.0,
                        batch_timeout=5.0,
                        label=name,
                        reporter=reporter,
                    )
                    if dto[:2] != b"\xFF\x00":
                        raise RuntimeError(
                            f"Fast RAM write error on {name} (0x{address + chunk_offset:08X}): {dto.hex()}"
                        )
                    batches += c_batches
                    stream_sec += c_sec
                    chunk_offset += chunk_bytes
            if aligned_len < len(data):
                t0 = time.monotonic()
                self.xcp_write_ram(address + aligned_len, data[aligned_len:], ram_end=ram_end)
                stream_sec += time.monotonic() - t0
            results.append((name, batches, stream_sec))

        wd_words = self.xcp_read_memory(MRR_DRIVER_CONTROL + 0x60, 8)
        self.last_wd_kick_count = int.from_bytes(wd_words[0:4], "big")
        self.last_wd_challenge = int.from_bytes(wd_words[4:8], "big")
        return results

    def xcp_flash_write_sectors(
        self,
        sectors: list[tuple[int, bytes]],
        *,
        driver_image: bytes | None = None,
        profile: dict[str, Any] | None = None,
        skip_unchanged: bool = True,
        backup_dir: Path | None = None,
        timeout_loops: int = MRR_FLASH_STREAM_TIMEOUT_LOOPS,
        reporter: OperationReporter = NULL_REPORTER,
    ) -> dict[str, Any]:
        """Erase and program C90FL Code Flash sectors via XCP + DB_99ERASEROUTI.bin with Bosch SBC watchdog service."""
        prof = profile or mrr_get_profile(self.sw_profile or "0192")
        if not prof.get("verified", True) or not prof.get("flash_write_supported"):
            raise RuntimeError(
                tr(
                    f"Прямая запись секторов Code Flash по XCP поддерживается только для проверенных профилей "
                    f"(0130, 0192, 0194, 0196, 0682, X720, 0771, 0780; текущий: {prof['sw']}).",
                    f"Direct XCP Code Flash sector programming is supported only for verified profiles "
                    f"(0130, 0192, 0194, 0196, 0682, X720, 0771, 0780; got {prof['sw']}).",
                )
            )
        drv_bytes = driver_image if driver_image is not None else mrr_get_eraserouti_driver(prof["sw"])
        if len(drv_bytes) != MRR_FLASH_DRIVER_SIZE:
            raise ValueError(f"HIS Flash Driver must be {MRR_FLASH_DRIVER_SIZE} bytes")
        if hashlib.sha256(drv_bytes).hexdigest() != prof["eraserouti_sha256"]:
            raise ValueError("HIS Flash Driver SHA-256 does not match verified profile driver")

        valid_geometries = dict(
            C90FL_SECTORS_5674K if prof["mcu"] == "MPC5674K" else C90FL_SECTORS_5675K
        )
        for sector_addr, sector_data in sectors:
            expected_size = valid_geometries.get(sector_addr)
            if expected_size is None or len(sector_data) != expected_size:
                raise ValueError(
                    f"Invalid C90FL sector geometry (addr=0x{sector_addr:08X}, len=0x{len(sector_data):X})"
                )

        pre_specs = [(f"pre_0x{addr:06X}", addr, len(data)) for addr, data in sectors]
        pre_reads = self.xcp_read_fast_regions(pre_specs, profile=prof, reporter=reporter)
        to_write: list[tuple[int, bytes, dict[str, Any]]] = []
        sector_reports: list[dict[str, Any]] = []

        for (addr, data), (_, pre_data, _, _) in zip(sectors, pre_reads):
            self.verify_region_checksum(addr, pre_data)
            if backup_dir is not None:
                bkp_dir = Path(backup_dir)
                bkp_dir.mkdir(parents=True, exist_ok=True)
                bkp_file = bkp_dir / f"backup_sector_0x{addr:06X}.bin"
                if not bkp_file.exists():
                    bkp_file.write_bytes(pre_data)
            pre_sha = hashlib.sha256(pre_data).hexdigest()
            target_sha = hashlib.sha256(data).hexdigest()
            unchanged = pre_data == data
            entry: dict[str, Any] = {
                "sector_address": f"0x{addr:08X}",
                "sector_size": len(data),
                "pre_sha256": pre_sha,
                "target_sha256": target_sha,
                "skipped_unchanged": bool(skip_unchanged and unchanged),
                "erased_and_written": False,
            }
            sector_reports.append(entry)
            if not (skip_unchanged and unchanged):
                to_write.append((addr, data, entry))

        synch_slot = int(prof["xcp_synch_slot"])
        synch_default = int(prof["xcp_synch_default"]).to_bytes(4, "big")
        r3_arg_state = int(prof["xcp_r3_arg_state"])
        ram_end = int(prof["ram_safe_end"])
        canary_addr = int(prof["user_stack_canary_addr"])
        sbc_tb = int(prof.get("sbc_last_tb_addr") or 0x40025E28)
        dto_buf = int(prof.get("xcp_dto_buffer") or 0x4003A26C)
        flash_drv_low_addr = int(prof.get("flash_driver_addr") or MRR_FLASH_DRIVER_ADDRESS)
        flash_drv_high_addr = int(prof.get("flash_driver_upper_phys") or MRR_FLASH_DRIVER_UPPER_PHYS)

        canary_before = self.xcp_read_memory(canary_addr, 8)
        if to_write:
            reporter.check_cancelled()
            original_slot = self.xcp_read_memory(synch_slot, 4)
            if original_slot != synch_default:
                raise RuntimeError(f"Unexpected XCP SYNCH handler: {original_slot.hex()}")
            ctrl_save_size = max(MRR_DRIVER_CONTROL_SAVE_SIZE, 0x70)
            original_arg_state = self.xcp_read_memory(r3_arg_state, 8)
            original_control = self.xcp_read_memory(MRR_DRIVER_CONTROL, ctrl_save_size)
            sector_drv_addr = MRR_FLASH_SECTOR_DRIVER_ADDR
            sector_drv_code = mrr_build_flash_sector_write_driver(
                mcu=prof["mcu"],
                sbc_last_tb_addr=sbc_tb,
                dto_buffer_addr=dto_buf,
            )
            padded_sector_drv = sector_drv_code + b"\x00" * ((-len(sector_drv_code)) % 8)
            fast_wr_drv = mrr_build_fast_write_ram_driver(sbc_last_tb_addr=sbc_tb, dto_buffer_addr=dto_buf)
            # Save all SRAM areas that will be overwritten (critical on MPC5675K where 0x4007C000 overlaps live KS/IKA/GFA/NvM SRAM!)
            saved_flash_ram = self.xcp_read_fast_regions(
                [
                    ("orig_drv_low", flash_drv_low_addr, MRR_FLASH_DRIVER_HALF_SIZE),
                    ("orig_drv_high", flash_drv_high_addr, MRR_FLASH_DRIVER_HALF_SIZE),
                    ("orig_sector_drv", sector_drv_addr, len(padded_sector_drv)),
                    ("orig_stage", MRR_FLASH_STAGE_BUFFER, MRR_FLASH_STREAM_BATCH_BYTES),
                ],
                profile=prof,
                reporter=reporter,
            )
            orig_drv_low = saved_flash_ram[0][1]
            orig_drv_high = saved_flash_ram[1][1]
            orig_sector_drv = saved_flash_ram[2][1]
            orig_stage = saved_flash_ram[3][1]
            original_payload = self.xcp_read_memory(MRR_DRIVER_ADDRESS, len(fast_wr_drv))
            reporter.check_cancelled()
            sram_written = False
            with reporter.uninterruptible():
                try:
                    self.xcp_configure_sram_exec(True, profile=prof)
                    sram_written = True
                    with self.suspend_rx_trace():
                        self._write_fast_ram_raw(
                            [
                                ("flash_drv_low", flash_drv_low_addr, drv_bytes[:MRR_FLASH_DRIVER_HALF_SIZE]),
                                (
                                    "flash_drv_high",
                                    flash_drv_high_addr,
                                    drv_bytes[MRR_FLASH_DRIVER_HALF_SIZE:MRR_FLASH_DRIVER_SIZE],
                                ),
                                ("flash_sector_drv", sector_drv_addr, padded_sector_drv),
                            ],
                            profile=prof,
                            timeout_loops=timeout_loops,
                            reporter=reporter,
                        )
                    self.xcp_write_ram(synch_slot, sector_drv_addr.to_bytes(4, "big"), ram_end=ram_end)
                    for addr, data, entry in to_write:
                        reporter.info(
                            tr(
                                f"Стирание и прошивка сектора Code Flash 0x{addr:08X} ({len(data) // 1024} КиБ)…",
                                f"Erasing and programming Code Flash sector 0x{addr:08X} ({len(data) // 1024} KiB)…",
                            )
                        )
                        ctrl_params = (
                            addr.to_bytes(4, "big")
                            + len(data).to_bytes(4, "big")
                            + (0xFFFFFFFF).to_bytes(4, "big")
                            + (0).to_bytes(4, "big")
                            + timeout_loops.to_bytes(4, "big")
                        )
                        self.xcp_write_ram(MRR_DRIVER_CONTROL + 0x28, ctrl_params, ram_end=ram_end)
                        self.xcp_write_ram(MRR_DRIVER_CONTROL + 0x60, b"\x00" * 8, ram_end=ram_end)
                        with self.suspend_rx_trace():
                            dto, batches, stream_sec = self._stream_on_ready(
                                data,
                                addr,
                                count_in_bytes=True,
                                first_ready_timeout=20.0,
                                batch_timeout=5.0,
                                label=f"flash_0x{addr:06X}",
                                reporter=reporter,
                            )
                        status_words = self.xcp_read_memory(MRR_DRIVER_CONTROL + 0x30, 8)
                        wd_words = self.xcp_read_memory(MRR_DRIVER_CONTROL + 0x60, 8)
                        drv_status = int.from_bytes(status_words[0:4], "big")
                        drv_detail = int.from_bytes(status_words[4:8], "big")
                        wd_kicks = int.from_bytes(wd_words[0:4], "big")
                        wd_challenge = int.from_bytes(wd_words[4:8], "big")
                        entry["dto"] = dto.hex()
                        entry["driver_status"] = drv_status
                        entry["driver_detail"] = f"0x{drv_detail:08X}"
                        entry["wd_kick_count"] = wd_kicks
                        entry["last_wd_challenge"] = f"0x{wd_challenge:08X}"
                        entry["batches"] = batches
                        entry["stream_elapsed_sec"] = round(stream_sec, 3)
                        entry["stream_bytes_per_sec"] = round(len(data) / stream_sec) if stream_sec else 0
                        if dto[:2] != b"\xFF\x00" or drv_status != 0:
                            raise RuntimeError(
                                f"Flash sector write failed at 0x{addr:08X}: "
                                f"dto={dto.hex()} status=0x{drv_status:X} detail=0x{drv_detail:08X}"
                            )
                        entry["erased_and_written"] = True
                finally:
                    had_exc = sys.exc_info()[0] is not None
                    cleanup_err: Exception | None = None
                    cleanup_steps: list[tuple[str, Any]] = [
                        ("restore_synch_pre", lambda: self.xcp_write_ram(synch_slot, original_slot, ram_end=ram_end)),
                    ]
                    if sram_written:
                        def _restore_driver_sram() -> None:
                            with self.suspend_rx_trace():
                                self._write_fast_ram_raw(
                                    [
                                        ("restore_sector_drv", sector_drv_addr, orig_sector_drv),
                                        ("restore_stage", MRR_FLASH_STAGE_BUFFER, orig_stage),
                                        ("restore_drv_high", flash_drv_high_addr, orig_drv_high),
                                        ("restore_drv_low", flash_drv_low_addr, orig_drv_low),
                                    ],
                                    profile=prof,
                                    timeout_loops=timeout_loops,
                                    reporter=reporter,
                                )

                        cleanup_steps.append(("restore_flash_drv_sram", _restore_driver_sram))
                    cleanup_steps.extend(
                        [
                            ("restore_synch_mid", lambda: self.xcp_write_ram(synch_slot, original_slot, ram_end=ram_end)),
                            ("disable_sram_exec", lambda: self.xcp_configure_sram_exec(False, profile=prof)),
                            ("restore_synch_post", lambda: self.xcp_write_ram(synch_slot, original_slot, ram_end=ram_end)),
                            ("restore_arg_state", lambda: self.xcp_write_ram(r3_arg_state, original_arg_state, ram_end=ram_end)),
                            ("restore_ctrl", lambda: self.xcp_write_ram(MRR_DRIVER_CONTROL, original_control, ram_end=ram_end)),
                            ("restore_payload", lambda: self.xcp_write_ram(MRR_DRIVER_ADDRESS, original_payload, ram_end=ram_end)),
                        ]
                    )
                    for step_name, fn in cleanup_steps:
                        try:
                            fn()
                        except Exception as exc:  # noqa: BLE001
                            if cleanup_err is None:
                                cleanup_err = exc
                            reporter.warning(
                                tr(
                                    f"Предупреждение при очистке SRAM после записи Flash ({step_name}): {exc}",
                                    f"SRAM cleanup warning after Flash write ({step_name}): {exc}",
                                )
                            )
                    if cleanup_err is not None and not had_exc:
                        raise cleanup_err

        canary_after = self.xcp_read_memory(canary_addr, 8)
        if canary_after != canary_before:
            raise RuntimeError(
                f"User stack canary corrupted: {canary_before.hex()} -> {canary_after.hex()}"
            )
        post_specs = [(f"post_0x{addr:06X}", addr, len(data)) for addr, data in sectors]
        post_reads = self.xcp_read_fast_regions(post_specs, profile=prof, reporter=reporter)
        for (addr, data), entry, (_, post_data, _, _) in zip(sectors, sector_reports, post_reads):
            self.verify_region_checksum(addr, post_data)
            post_sha = hashlib.sha256(post_data).hexdigest()
            entry["post_sha256"] = post_sha
            entry["verified"] = post_data == data
            if post_data != data:
                raise RuntimeError(
                    f"Flash readback verification failed at 0x{addr:08X}: "
                    f"expected {entry['target_sha256']}, got {post_sha}"
                )
        return {
            "user_stack_canary_before": canary_before.hex(),
            "user_stack_canary_after": canary_after.hex(),
            "sectors": sector_reports,
        }


def _warn_dpdu_29bit_mrr(reporter: OperationReporter) -> None:
    reporter.warning(
        tr(
            "29-битный режим D-PDU RawMode для XCP (0x1BFEBA00/01) радара 13 ACC не проверен на реальном "
            "оборудовании; рекомендуется нативный CAN-адаптер (CANable / gs_usb / PCAN / SocketCAN).",
            "29-bit D-PDU RawMode for 13 ACC Radar XCP (0x1BFEBA00/01) is unverified on hardware; "
            "a native CAN adapter (CANable / gs_usb / PCAN / SocketCAN) is recommended.",
        )
    )


def _require_matching_mrr_sw_profile(
    passport: dict[str, Any],
    sw_profile: str | None,
    *,
    force: bool = False,
) -> None:
    """Refuse dangerous RAM/Flash writes when a manual `sw_profile` override conflicts with the live ECU SW version."""
    override = (sw_profile or "").strip().upper()
    if not override or force:
        return
    live_sw = str(passport.get("sw_version") or "").strip().upper()
    if not live_sw:
        return
    if live_sw != override:
        raise RuntimeError(
            tr(
                f"Выбранный вручную профиль ПО MRR ({override}) не совпадает с версией ПО подключённого радара "
                f"({live_sw}, деталь {passport.get('part_number') or '—'}). "
                "Опасная запись в SRAM / Code Flash отменена, чтобы не повредить неверные адреса "
                "(укажите точный профиль ПО или передайте force=True).",
                f"Manual MRR SW profile override ({override}) does not match live radar SW version "
                f"({live_sw}, part {passport.get('part_number') or '—'}). "
                "Refusing SRAM / Code Flash write to prevent corrupting wrong addresses "
                "(select the matching SW profile or pass force=True).",
            )
        )


# ── Managed Session Context (Direct or J533 Gateway Bridge Ch 2) ────────────
@contextlib.contextmanager
def _managed_mrr_session(
    port: str,
    *,
    interface: str = "slcan",
    log_path: Path | None = None,
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    needs_raw_extended_can: bool = False,
    idle_limit: int = 40_000_000,
    sw_profile: str | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> Iterator[tuple[MrrCanLink, bool]]:
    """Open MrrCanLink, activating J533 RSCAN0 ch3<->ch2 (Extended CAN) bridge when needed for XCP/0x77E."""
    if via_gateway and needs_raw_extended_can:
        if not gateway_bridge:
            raise RuntimeError(
                tr(
                    "Операции по 29-битному XCP (чтение памяти, IKA/GFA, патч Code Flash) через шлюз требуют "
                    "шлюз Continental 3Q0 907 530 и адаптер с произвольным raw CAN для RAM-моста ch3 ↔ ch2.",
                    "29-bit XCP operations (memory read, IKA/GFA extraction, Code Flash patching) through a gateway "
                    "require a Continental 3Q0 907 530 gateway and an arbitrary raw-CAN adapter for the ch3 ↔ ch2 RAM bridge.",
                )
            )
        if interface == "dpdu":
            _warn_dpdu_29bit_mrr(reporter)
        with j533_can_bridge(
            port,
            interface=interface,
            target_channel=gateway_channel,
            bus=bus,
            idle_limit=idle_limit,
            target_rx_filter=MRR_BRIDGE_RX_FILTER,
            log_path=None,
            reporter=reporter,
        ) as bridge:
            with MrrCanLink(
                port,
                interface=interface,
                log_path=log_path,
                bus=bridge.bus,
                via_gateway=False,
                sw_profile=sw_profile,
            ) as link:
                yield link, True
        return

    if needs_raw_extended_can and interface == "dpdu":
        _warn_dpdu_29bit_mrr(reporter)

    with MrrCanLink(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        sw_profile=sw_profile,
    ) as link:
        if not needs_raw_extended_can and link._should_use_hw_uds():
            with link.uds_session() as active:
                if not active and getattr(link.bus, "uds_only", False):
                    refusal = str(getattr(link.bus, "uds_refusal", "") or "").strip()
                    detail = f" ({refusal})" if refusal else ""
                    raise TimeoutError(
                        tr(
                            f"Адаптер D-PDU не смог открыть аппаратный канал UDS ISO-TP для 13 ACC Radar "
                            f"(0x{link.UDS_TX_ID:03X} → 0x{link.UDS_RX_ID:03X}){detail}.",
                            f"D-PDU adapter could not open a hardware UDS ISO-TP link for 13 ACC Radar "
                            f"(0x{link.UDS_TX_ID:03X} → 0x{link.UDS_RX_ID:03X}){detail}.",
                        )
                    )
                yield link, False
            return
        yield link, False


def _reset_and_wait_mrr(
    link: MrrCanLink,
    *,
    reset_subfn: int = 0x02,
    timeout: float = 6.0,
) -> bool:
    sent = False
    for attempt in range(2):
        try:
            link.request_uds(bytes([0x11, reset_subfn & 0xFF]), 0x51, timeout=1.5)
            sent = True
            break
        except UdsNegativeResponse as exc:
            if attempt == 0 and exc.nrc in (0x7F, 0x22):
                with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                    link.request_uds(b"\x10\x03", 0x50, timeout=1.2)
                continue
            return False
        except (*TRANSPORT_ERRORS, UnexpectedUdsResponse):
            # ECU may drop off bus before replying 0x51; treat transport loss on first try as possibly sent
            sent = True
            break
    if not sent:
        return False
    fake_bus = getattr(link.bus, "__class__", None).__module__.startswith("tests")
    if not fake_bus:
        time.sleep(0.9)
        link.drain_rx(max_frames=128, quick=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            link.request_uds(b"\x10\x01", 0x50, timeout=0.6)
            return True
        except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            time.sleep(0.01 if fake_bus else 0.12)
    return False


# ── High-Level MRR Workflows ────────────────────────────────────────────────
def can_mrr_status(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read 13 ACC Radar UDS passport, Component Protection status DIDs, SWaP/FeC status (22 3C 00), and XcpGate state."""
    with _managed_mrr_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_extended_can=False,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        reporter.step(
            1,
            2,
            tr("Чтение паспорта 13 ACC Radar (J428)…", "Reading 13 ACC Radar (J428) passport…"),
        )
        passport = link.read_passport()
        prof = mrr_detect_profile(passport, sw_version=sw_profile or "")
        sup = mrr_support_info(passport, sw_version=sw_profile or "")
        if sup["warning"]:
            reporter.warning(sup["warning"])
        gen = 1 if prof["mcu"] == "MPC5674K" else 2
        coding_raw = bytes.fromhex(str(passport["coding"])) if passport.get("coding") else None
        reporter.step(
            2,
            2,
            tr("Чтение статуса защиты компонентов (KS), SWaP (3C00), XcpGate и ошибок DTC…", "Reading Component Protection (KS), SWaP (3C00), XcpGate & DTCs…"),
        )
        status = link.read_status_dids()
        swap_uds: dict[str, Any] | None = None
        try:
            swap_uds = link.read_swap_status_uds(
                include_metadata=True,
                coding_raw=coding_raw,
                generation=gen,
            )
        except Exception as exc:  # noqa: BLE001
            reporter.warning(tr(f"Не удалось считать состояние SWaP (22 3C 00): {exc}", f"Could not read SWaP status (22 3C 00): {exc}"))
        dtcs: list[dict[str, Any]] | None = None
        try:
            dtcs = link.read_dtcs()
        except Exception as exc:  # noqa: BLE001
            reporter.warning(tr(f"Не удалось считать ошибки DTC: {exc}", f"Could not read DTCs: {exc}"))
        return {
            "ecu": "13_MRR",
            "ecu_kind": "mrr",
            "via_gateway": via_gateway,
            "gateway_bridged": bridged,
            "passport": passport,
            "status": status,
            "swap_uds": swap_uds,
            "dtcs": dtcs,
            "officially_supported": bool(sup["verified"]),
            "support_warning": sup["warning"],
            "support_warning_tone": sup["tone"],
        }


def can_mrr_swap_status(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    include_metadata: bool = True,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read standard UDS SWaP / FeC status (`22 3C 00`, plus optional `3C0A` VCRN, `3C05` RSA key, `0600` coding) from 13 ACC Radar.

    Read-only standard UDS operation (no Security Access, no XCP, no gateway RAM-bridge required).
    Works identically on Generation 1 (`3Q0 907 572 B/C`) and Generation 2 (`5Q0 907 572 M/R/S`, `3QF 907 561 D`).
    """
    with _managed_mrr_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_extended_can=False,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        reporter.step(
            1,
            2,
            tr("Чтение паспорта 13 ACC Radar (J428)…", "Reading 13 ACC Radar (J428) passport…"),
        )
        passport = link.read_passport()
        prof = mrr_detect_profile(passport, sw_version=sw_profile or "")
        gen = 1 if prof["mcu"] == "MPC5674K" else 2
        coding_raw = bytes.fromhex(str(passport["coding"])) if passport.get("coding") else None
        reporter.step(
            2,
            2,
            tr(
                "Чтение состояния SWaP / FeC по UDS (22 3C 00 / 3C 0A / 3C 05)…",
                "Reading SWaP / FeC status over UDS (22 3C 00 / 3C 0A / 3C 05)…",
            ),
        )
        swap_uds = link.read_swap_status_uds(
            include_metadata=include_metadata,
            coding_raw=coding_raw,
            generation=gen,
        )
        for feat in swap_uds.get("features") or []:
            reporter.info(
                f"FS-ID 0x{feat['fsid_hex']}: {feat['status_hex']} "
                f"({tr(feat['label_ru'], feat['label_en'])}) — {tr(feat['name_ru'], feat['name_en'])}"
            )
        if not swap_uds.get("features"):
            reporter.info(
                tr(
                    "В DID 0x3C00 нет установленных сертификатов SWaP/FeC (пустой ответ 00 00 00 00 00).",
                    "No installed SWaP/FeC certificates reported in DID 0x3C00 (empty 00 00 00 00 00).",
                )
            )
        return {
            "ecu": "13_MRR",
            "ecu_kind": "mrr",
            "profile": prof["sw"],
            "profile_verified": bool(prof.get("verified", False)),
            "unit": prof["unit"],
            "family": prof["family"],
            "mcu": prof["mcu"],
            "generation": gen,
            "via_gateway": via_gateway,
            "gateway_bridged": bridged,
            "passport": passport,
            "swap_uds": swap_uds,
        }


def can_mrr_read_keys(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    session_dir: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Extract IKA, GFA, ECU_BOOT_SUM, and KS_META from 13 ACC Radar over XCP (DFLASH0 Fee + live SRAM mirrors)."""
    with _managed_mrr_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_extended_can=True,
        idle_limit=MRR_BRIDGE_FLASH_IDLE_LIMIT,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        reporter.step(1, 3, tr("Чтение паспорта и статуса 13 ACC Radar…", "Reading 13 ACC Radar passport & status…"))
        passport = link.read_passport()
        status = link.read_status_dids()
        prof = mrr_detect_profile(passport, sw_version=sw_profile or "")
        sup = mrr_support_info(passport, sw_version=sw_profile or "")
        if sup["warning"]:
            reporter.warning(sup["warning"])

        reporter.step(2, 3, tr("Подключение и разблокировка XCP (0x1BFEBA00)…", "Connecting and unlocking XCP (0x1BFEBA00)…"))
        xcp_info = link.ensure_xcp_enabled(reporter=reporter)

        reporter.step(
            3,
            3,
            tr(
                "Проверка точек патча CP и SWaP/FSC в Code Flash, вычитывание DFLASH0 (64 КиБ) и зеркал IKA / GFA в SRAM…",
                "Inspecting Code Flash CP & SWaP/FSC patch sites, reading DFLASH0 (64 KiB) & live SRAM IKA / GFA mirrors…",
            ),
        )
        if prof.get("verified") and prof.get("patches"):
            cflash_cp = link.xcp_inspect_live_cp_patch_state(profile=prof)
        else:
            cflash_cp = {
                "unit": prof["unit"],
                "sw": prof["sw"],
                "verified": False,
                "cp_patch_state": "unsupported_sw",
                "stock_points": 0,
                "patched_points": 0,
                "total_points": 0,
                "points": [],
            }
        if prof.get("verified") and prof.get("swap_config"):
            cflash_swap = link.xcp_inspect_live_swap_patch_state(profile=prof)
        else:
            cflash_swap = {
                "unit": prof["unit"],
                "sw": prof["sw"],
                "verified": False,
                "generation": 1 if prof["mcu"] == "MPC5674K" else 2,
                "swap_patch_state": "unsupported_sw",
                "stock_points": 0,
                "patched_points": 0,
                "total_points": 0,
                "points": [],
            }
        dflash_res = link.xcp_read_fast_regions(
            [("dflash0", MRR_DFLASH_ADDR, MRR_DFLASH_SIZE)],
            profile=prof,
            reporter=reporter,
        )
        _, dflash_bytes, _, dflash_sec = dflash_res[0]
        fee_info = mrr_parse_dflash_fee(dflash_bytes)

        sram_mirrors: dict[str, Any] = {}
        if prof.get("verified"):
            for key_name, addr_field, length in (
                ("sram_ika_hex", "sram_ika_addr", 16),
                ("sram_ika_inv_hex", "sram_ika_inv_addr", 16),
                ("sram_gfa_hex", "sram_gfa_addr", 16),
                ("sram_ks_meta_hex", "sram_ks_meta_addr", 16),
                ("sram_ecu_boot_sum_hex", "sram_ecu_boot_sum_addr", 16),
                ("sram_cp_active_byte", "sram_cp_active_addr", 1),
                ("sram_cp_counter_u16", "sram_cp_counter_addr", 2),
            ):
                addr = prof.get(addr_field)
                if addr:
                    with contextlib.suppress(Exception):
                        raw = link.xcp_read_memory(int(addr), length)
                        if length == 1:
                            sram_mirrors[key_name] = raw[0]
                        elif length == 2:
                            sram_mirrors[key_name] = int.from_bytes(raw, "big")
                        else:
                            sram_mirrors[key_name] = raw.hex()

        dtcs: list[dict[str, Any]] | None = None
        try:
            dtcs = link.read_dtcs()
        except Exception as exc:  # noqa: BLE001
            reporter.warning(tr(f"Не удалось считать ошибки DTC: {exc}", f"Could not read DTCs: {exc}"))

        swap_uds: dict[str, Any] | None = None
        try:
            gen = 1 if prof["mcu"] == "MPC5674K" else 2
            coding_raw = bytes.fromhex(str(passport["coding"])) if passport.get("coding") else None
            swap_uds = link.read_swap_status_uds(
                include_metadata=True,
                coding_raw=coding_raw,
                generation=gen,
            )
        except Exception as exc:  # noqa: BLE001
            reporter.warning(tr(f"Не удалось считать состояние SWaP (22 3C 00): {exc}", f"Could not read SWaP status (22 3C 00): {exc}"))

        ika_hex = fee_info.get("ika_hex") or sram_mirrors.get("sram_ika_hex")
        gfa_hex = fee_info.get("gfa_hex") or sram_mirrors.get("sram_gfa_hex")
        ecu_boot_sum_hex = fee_info.get("ecu_boot_sum_hex") or sram_mirrors.get("sram_ecu_boot_sum_hex")

        saved_files: dict[str, str] = {}
        if session_dir is not None:
            session_dir = Path(session_dir)
            session_dir.mkdir(parents=True, exist_ok=True)
            df_path = session_dir / "Dflash.bin"
            df_path.write_bytes(dflash_bytes)
            saved_files["dflash"] = str(df_path)
            keys_path = session_dir / "mrr_keys.json"
            saved_files["keys_json"] = str(keys_path)

        result = {
            "ecu": "13_MRR",
            "ecu_kind": "mrr",
            "profile": prof["sw"],
            "profile_verified": bool(prof.get("verified", False)),
            "officially_supported": bool(sup["verified"]),
            "support_warning": sup["warning"],
            "support_warning_tone": sup["tone"],
            "unit": prof["unit"],
            "family": prof["family"],
            "mcu": prof["mcu"],
            "via_gateway": via_gateway,
            "gateway_bridged": bridged,
            "passport": passport,
            "status": status,
            "swap_uds": swap_uds,
            "dtcs": dtcs,
            "xcp": xcp_info,
            "ika_hex": ika_hex,
            "gfa_hex": gfa_hex,
            "ecu_boot_sum_hex": ecu_boot_sum_hex,
            "ika_virgin": fee_info.get("ika_virgin"),
            "ika_personalized": fee_info.get("ika_personalized"),
            "gfa_learned": fee_info.get("gfa_learned"),
            "cp_counter": sram_mirrors.get("sram_cp_counter_u16", fee_info.get("cp_counter")),
            "cp_active": (
                bool(sram_mirrors["sram_cp_active_byte"])
                if "sram_cp_active_byte" in sram_mirrors
                else fee_info.get("cp_active")
            ),
            "ks_options_hex": fee_info.get("ks_options_hex"),
            "cp_patch_state": cflash_cp["cp_patch_state"],
            "cflash_cp": cflash_cp,
            "swap_patch_state": cflash_swap["swap_patch_state"],
            "cflash_swap": cflash_swap,
            "dflash_fee": fee_info,
            "sram_mirrors": sram_mirrors,
            "dflash_read_sec": round(dflash_sec, 3),
            "session_dir": str(session_dir) if session_dir is not None else None,
            "saved_files": saved_files,
        }
        if session_dir is not None:
            (session_dir / "mrr_keys.json").write_text(
                json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )

        if ika_hex:
            reporter.info(
                tr(
                    f"Ключи радара считаны: IKA={ika_hex.upper()} | GFA={(gfa_hex or '—').upper()}",
                    f"Radar keys extracted: IKA={ika_hex.upper()} | GFA={(gfa_hex or '—').upper()}",
                )
            )
        return result


def can_mrr_read_all(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    session_dir: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read passport, status DIDs, IKA/GFA keys, and 64 KiB DFLASH0 from 13 ACC Radar in one session."""
    return can_mrr_read_keys(
        port,
        interface=interface,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        sw_profile=sw_profile,
        session_dir=session_dir,
        log_path=log_path,
        reporter=reporter,
    )


def can_mrr_write_keys(
    port: str,
    *,
    current_ika: bytes | str | None = None,
    new_ika: bytes | str | None = None,
    new_gfa: bytes | str | None = None,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    force: bool = False,
    reset_after: bool = True,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Write personalized IKA (UDS 2E 00BE) and/or vehicle group key GFA (UDS 2E 00BD) to 13 ACC Radar.

    Because UDS 2E 00BE (IKA) erases GFA (FF*16) and immediately switches the active encryption key to `new_ika`,
    `00BE` is always written first under `current_ika` and `00BD` (GFA) is written second under the active IKA.
    If `current_ika` is omitted, it is automatically read from the radar via XCP first.
    """
    if new_ika is None and new_gfa is None:
        raise ValueError("At least one of new_ika or new_gfa must be provided")

    new_ika_bytes = _norm_key_16b(new_ika, "new_ika") if new_ika is not None else None
    new_gfa_bytes = _norm_key_16b(new_gfa, "new_gfa") if new_gfa is not None else None
    if new_ika_bytes is not None and mrr_is_virgin_ika(new_ika_bytes):
        raise ValueError("Refusing to write factory virgin IKA test key to 00BE")

    needs_xcp = current_ika is None
    if via_gateway and gateway_bridge and not needs_xcp:
        # Probe DID 0x03DE over pure UDS first: if radar is in CP lockout (>= 0x23), upgrade to J533 bridge to clear it via XCP
        with _managed_mrr_session(
            port,
            interface=interface,
            log_path=log_path,
            bus=bus,
            via_gateway=True,
            gateway_bridge=False,
            gateway_channel=gateway_channel,
            needs_raw_extended_can=False,
            sw_profile=sw_profile,
            reporter=reporter,
        ) as (probe_link, _):
            with contextlib.suppress(Exception):
                probe_st = probe_link.read_status_dids()
                if (probe_st.get("cp_counter") or 0) >= 0x23:
                    needs_xcp = True
        if bus is None and interface != "dpdu":
            time.sleep(0.15)

    with _managed_mrr_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_extended_can=needs_xcp,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        passport = link.read_passport()
        status_before = link.read_status_dids()
        prof = mrr_detect_profile(passport, sw_version=sw_profile or "")

        if current_ika is not None:
            active_ika = _norm_key_16b(current_ika, "current_ika")
        else:
            reporter.info(
                tr(
                    "Текущий IKA не указан — автоматическое чтение текущего IKA по XCP…",
                    "Current IKA not provided — automatically reading current IKA via XCP…",
                )
            )
            link.ensure_xcp_enabled(reporter=reporter)
            df_res = link.xcp_read_fast_regions(
                [("dflash0", MRR_DFLASH_ADDR, MRR_DFLASH_SIZE)],
                profile=prof,
                reporter=reporter,
            )
            fee_info = mrr_parse_dflash_fee(df_res[0][1])
            auto_ika_hex = fee_info.get("ika_hex")
            if not auto_ika_hex and prof.get("verified") and prof.get("sram_ika_addr"):
                with contextlib.suppress(Exception):
                    auto_ika_hex = link.xcp_read_memory(int(prof["sram_ika_addr"]), 16).hex()
            if not auto_ika_hex:
                raise RuntimeError(
                    tr("Не удалось определить текущий IKA из DFLASH0 / SRAM", "Could not determine current IKA from DFLASH0 / SRAM")
                )
            active_ika = bytes.fromhex(auto_ika_hex)

        # If cp_counter is in lockout state (0x23 / 0x25), clear it via XCP AuthSuccess trigger first
        cp_cnt_before = status_before.get("cp_counter", 0) or 0
        xcp_reachable = (not via_gateway) or bridged
        if cp_cnt_before >= 0x23 and xcp_reachable:
            _require_matching_mrr_sw_profile(passport, sw_profile, force=force)
        if (
            cp_cnt_before >= 0x23
            and xcp_reachable
            and prof.get("verified")
            and prof.get("sram_auth_success_trigger_addr")
        ):
            with contextlib.suppress(Exception):
                link.ensure_xcp_enabled(reporter=reporter)
                link.xcp_write_ram(
                    int(prof["sram_auth_success_trigger_addr"]),
                    (1).to_bytes(4, "big"),
                    verify=False,
                    ram_end=int(prof["ram_safe_end"]),
                )
                fake_bus = getattr(link.bus, "__class__", None).__module__.startswith("tests")
                cnt_addr = prof.get("sram_cp_counter_addr")
                for _ in range(10):
                    time.sleep(0.01 if fake_bus else 0.06)
                    if cnt_addr:
                        raw_c = link.xcp_read_memory(int(cnt_addr), 2)
                        if int.from_bytes(raw_c, "big") == 0:
                            break

        link.request_uds(b"\x10\x03", 0x50, timeout=1.5)
        written: dict[str, Any] = {}

        if new_ika_bytes is not None:
            reporter.info(
                tr(
                    f"Запись нового IKA (2E 00BE): {new_ika_bytes.hex().upper()}…",
                    f"Writing new IKA (2E 00BE): {new_ika_bytes.hex().upper()}…",
                )
            )
            container_00be = mrr_build_cp_key_container(active_ika, new_ika_bytes, MRR_CP_KEY_TYPE_IKA)
            resp_be = link.request_uds(b"\x2E\x00\xBE" + container_00be, 0x6E, timeout=3.0)
            written["00BE"] = {
                "encrypted_under_ika_hex": active_ika.hex(),
                "new_ika_hex": new_ika_bytes.hex(),
                "container_hex": container_00be.hex(),
                "uds_response_hex": resp_be.hex(),
            }
            active_ika = new_ika_bytes

        if new_gfa_bytes is not None:
            reporter.info(
                tr(
                    f"Запись группового ключа GFA (2E 00BD): {new_gfa_bytes.hex().upper()}…",
                    f"Writing vehicle group key GFA (2E 00BD): {new_gfa_bytes.hex().upper()}…",
                )
            )
            container_00bd = mrr_build_cp_key_container(active_ika, new_gfa_bytes, MRR_CP_KEY_TYPE_GFA)
            try:
                resp_bd = link.request_uds(b"\x2E\x00\xBD" + container_00bd, 0x6E, timeout=3.0)
            except Exception as exc:
                if "00BE" in written:
                    raise RuntimeError(
                        tr(
                            f"Внимание: новый IKA (2E 00BE) УЖЕ записан в радар ({active_ika.hex().upper()}), "
                            f"но последующая запись GFA (2E 00BD) завершилась ошибкой: {exc}. "
                            "Для повторной записи GFA используйте этот новый IKA как текущий.",
                            f"Warning: new IKA (2E 00BE) was ALREADY written to the radar ({active_ika.hex().upper()}), "
                            f"but the subsequent GFA write (2E 00BD) failed: {exc}. "
                            "Use this new IKA as the current IKA when retrying GFA.",
                        )
                    ) from exc
                raise
            written["00BD"] = {
                "encrypted_under_ika_hex": active_ika.hex(),
                "new_gfa_hex": new_gfa_bytes.hex(),
                "container_hex": container_00bd.hex(),
                "uds_response_hex": resp_bd.hex(),
            }

        with contextlib.suppress(Exception):
            link.request_uds(b"\x14\xFF\xFF\xFF", 0x54, timeout=2.0)

        reset_confirmed = True
        if reset_after:
            reset_confirmed = _reset_and_wait_mrr(link, reset_subfn=0x02)
            if not reset_confirmed:
                reporter.warning(
                    tr(
                        "Радар не ответил на UDS 10 01 после сброса 11 02 — проверьте питание и повторите опрос статуса.",
                        "Radar did not answer UDS 10 01 after 11 02 reset — verify power and poll status again.",
                    )
                )

        status_after = link.read_status_dids()
        dtcs_after: list[dict[str, Any]] | None = None
        with contextlib.suppress(Exception):
            dtcs_after = link.read_dtcs()
        return {
            "ecu": "13_MRR",
            "profile": prof["sw"],
            "via_gateway": via_gateway,
            "gateway_bridged": bridged,
            "written": written,
            "active_ika_hex": active_ika.hex(),
            "active_gfa_hex": new_gfa_bytes.hex() if new_gfa_bytes is not None else None,
            "gfa_cleared": bool("00BE" in written and "00BD" not in written),
            "reset_confirmed": reset_confirmed,
            "status_before": status_before,
            "status_after": status_after,
            "dtcs": dtcs_after,
        }


def can_mrr_reset_cp_counter(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    force: bool = False,
    reset_after: bool = True,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Reset MRR Component Protection counter (`DID 0x03DE`) to `0x0000` in DFLASH0 Fee 0x2C2C and clear CP DTCs."""
    with _managed_mrr_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_extended_can=True,
        idle_limit=MRR_BRIDGE_FLASH_IDLE_LIMIT,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        passport = link.read_passport()
        status_before = link.read_status_dids()
        _require_matching_mrr_sw_profile(passport, sw_profile, force=force)
        prof = mrr_detect_profile(passport, sw_version=sw_profile or "")
        trigger_addr = prof.get("sram_auth_success_trigger_addr")
        counter_addr = prof.get("sram_cp_counter_addr")
        ram_end = int(prof.get("ram_safe_end") or 0x4005E000)

        if not prof.get("verified") or not trigger_addr:
            raise RuntimeError(
                tr(
                    f"Сброс счётчика CP в SRAM недоступен для непроверенной версии ПО ({prof['sw']}).",
                    f"SRAM CP counter reset is not available for unverified SW version ({prof['sw']}).",
                )
            )

        reporter.step(
            1,
            3,
            tr(
                f"Активация KS_State_AuthSuccess @ 0x{int(trigger_addr):08X} для сброса счётчика CP в DFLASH0…",
                f"Triggering KS_State_AuthSuccess @ 0x{int(trigger_addr):08X} to reset CP counter in DFLASH0…",
            ),
        )
        link.ensure_xcp_enabled(reporter=reporter)
        link.xcp_write_ram(int(trigger_addr), (1).to_bytes(4, "big"), verify=False, ram_end=ram_end)

        fake_bus = getattr(link.bus, "__class__", None).__module__.startswith("tests")
        sram_counter_after: int | None = None
        for _ in range(12):
            time.sleep(0.01 if fake_bus else 0.08)
            if counter_addr:
                with contextlib.suppress(Exception):
                    raw_cnt = link.xcp_read_memory(int(counter_addr), 2)
                    sram_counter_after = int.from_bytes(raw_cnt, "big")
                    if sram_counter_after == 0:
                        break

        reporter.step(2, 3, tr("Очистка DTC (UDS 14 FF FF FF)…", "Clearing DTCs (UDS 14 FF FF FF)…"))
        with contextlib.suppress(Exception):
            link.request_uds(b"\x10\x03", 0x50, timeout=1.2)
            link.request_uds(b"\x14\xFF\xFF\xFF", 0x54, timeout=2.0)

        reset_confirmed = True
        if reset_after:
            reporter.step(3, 3, tr("Перезагрузка радара (UDS 11 02 KeyOffOnReset)…", "Rebooting radar (UDS 11 02 KeyOffOnReset)…"))
            reset_confirmed = _reset_and_wait_mrr(link, reset_subfn=0x02)
            if not reset_confirmed:
                reporter.warning(
                    tr(
                        "Радар не ответил на UDS 10 01 после сброса 11 02.",
                        "Radar did not respond to UDS 10 01 after 11 02 reset.",
                    )
                )
            with contextlib.suppress(Exception):
                link.request_uds(b"\x10\x03", 0x50, timeout=1.2)
                link.request_uds(b"\x14\xFF\xFF\xFF", 0x54, timeout=2.0)

        status_after = link.read_status_dids()
        dtcs_after: list[dict[str, Any]] | None = None
        with contextlib.suppress(Exception):
            dtcs_after = link.read_dtcs()
        return {
            "ecu": "13_MRR",
            "profile": prof["sw"],
            "via_gateway": via_gateway,
            "gateway_bridged": bridged,
            "trigger_address": f"0x{int(trigger_addr):08X}",
            "sram_counter_after": sram_counter_after,
            "reset_confirmed": reset_confirmed,
            "status_before": status_before,
            "status_after": status_after,
            "dtcs": dtcs_after,
        }


def can_mrr_read_memory(
    port: str,
    *,
    region: str = "dflash",
    address: int | None = None,
    length: int | None = None,
    fast: bool = True,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    session_dir: Path | None = None,
    output_path: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read DFLASH0 (64 KiB), Bootloader (192 KiB), Application, full CodeFlash, SRAM, or custom address range."""
    with _managed_mrr_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_extended_can=True,
        idle_limit=MRR_BRIDGE_FLASH_IDLE_LIMIT,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        passport = link.read_passport()
        prof = mrr_detect_profile(passport, sw_version=sw_profile or "")
        sup = mrr_support_info(passport, sw_version=sw_profile or "")
        if sup["warning"]:
            reporter.warning(sup["warning"])
        link.ensure_xcp_enabled(reporter=reporter)

        reg_key = (region or "dflash").strip().lower()
        if (address is None) != (length is None):
            raise ValueError("Both address and length must be provided together for custom memory reads")
        specs: list[tuple[str, int, int, str]] = []
        if address is not None and length is not None:
            specs.append(("custom", int(address), int(length), f"mrr_0x{int(address):08X}_0x{int(length):X}.bin"))
        elif reg_key in ("dflash", "dflash0"):
            specs.append(("dflash0", MRR_DFLASH_ADDR, MRR_DFLASH_SIZE, "Dflash.bin"))
        elif reg_key in ("boot", "bootloader"):
            specs.append(("bootloader", MRR_BOOT_BASE, MRR_BOOT_SIZE, "Bootloader.bin"))
        elif reg_key in ("app", "application"):
            specs.append(("application", MRR_APP_BASE, int(prof["app_size"]), "Application.bin"))
        elif reg_key in ("cflash", "flash"):
            specs.append(("cflash", MRR_BOOT_BASE, int(prof["cflash_size"]), "Cflash.bin"))
        elif reg_key in ("sram", "ram"):
            specs.append(("sram", MRR_SRAM_ADDR, int(prof["sram_size"]), "Sram.bin"))
        elif reg_key == "all":
            specs.extend([
                ("cflash", MRR_BOOT_BASE, int(prof["cflash_size"]), "Cflash.bin"),
                ("dflash0", MRR_DFLASH_ADDR, MRR_DFLASH_SIZE, "Dflash.bin"),
                ("sram", MRR_SRAM_ADDR, int(prof["sram_size"]), "Sram.bin"),
            ])
        else:
            raise ValueError(f"Unknown MRR memory region: {region!r}")

        req_tuples = [(name, addr, sz) for name, addr, sz, _ in specs]
        started = time.monotonic()
        if fast:
            read_results = link.xcp_read_fast_regions(req_tuples, profile=prof, reporter=reporter)
            mode = "xcp-fast-can-burst" if link.last_read_used_fast else "xcp-short-upload"
        else:
            read_results = []
            for name, addr, sz in req_tuples:
                t0 = time.monotonic()
                data = link.xcp_read_memory(addr, sz, reporter=reporter, label=name)
                read_results.append((name, data, (sz + 6) // 7, time.monotonic() - t0))
            mode = "xcp-short-upload"

        total_elapsed = time.monotonic() - started
        regions_report: list[dict[str, Any]] = []
        dflash_analysis: dict[str, Any] | None = None
        cflash_analysis: dict[str, Any] | None = None
        cflash_swap_analysis: dict[str, Any] | None = None
        cflash_bytes_ref: bytes | None = None

        for (name, addr, sz, default_fname), (_, data, calls, burst_sec) in zip(specs, read_results):
            if name in ("cflash", "bootloader"):
                cflash_bytes_ref = data

        for (name, addr, sz, default_fname), (_, data, calls, burst_sec) in zip(specs, read_results):
            file_path: Path | None = None
            if output_path is not None and len(specs) == 1:
                file_path = Path(output_path)
            elif session_dir is not None:
                file_path = Path(session_dir) / default_fname
            if file_path is not None:
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_bytes(data)

            entry: dict[str, Any] = {
                "name": name,
                "address": f"0x{addr:08X}",
                "length": len(data),
                "chunks": calls,
                "sha256": hashlib.sha256(data).hexdigest(),
                "elapsed_sec": round(burst_sec, 3),
                "bytes_per_sec": round(len(data) / burst_sec) if burst_sec else 0,
                "file": str(file_path) if file_path else None,
            }
            if name == "dflash0" and len(data) == MRR_DFLASH_SIZE:
                dflash_analysis = mrr_parse_dflash_fee(data, cflash_or_boot_bytes=cflash_bytes_ref)
                entry["fee_analysis"] = dflash_analysis
            if name in ("cflash", "application") and len(data) in (prof["cflash_size"], prof["app_size"]):
                with contextlib.suppress(Exception):
                    cflash_analysis = mrr_inspect_cflash_cp_state(
                        data, profile=prof["sw"] if prof.get("verified") else None
                    )
                    entry["cp_state"] = cflash_analysis
                with contextlib.suppress(Exception):
                    cflash_swap_analysis = mrr_inspect_cflash_swap_state(
                        data, profile=prof["sw"] if prof.get("verified") else None
                    )
                    entry["swap_state"] = cflash_swap_analysis
            regions_report.append(entry)

        report_out = {
            "ecu": "13_MRR",
            "ecu_kind": "mrr",
            "profile": prof["sw"],
            "profile_verified": bool(prof.get("verified", False)),
            "officially_supported": bool(sup["verified"]),
            "support_warning": sup["warning"],
            "support_warning_tone": sup["tone"],
            "unit": prof["unit"],
            "family": prof["family"],
            "mcu": prof["mcu"],
            "mode": mode,
            "via_gateway": via_gateway,
            "gateway_bridged": bridged,
            "passport": passport,
            "total_elapsed_sec": round(total_elapsed, 3),
            "session_dir": str(session_dir) if session_dir is not None else None,
            "regions": regions_report,
            "dflash_fee": dflash_analysis,
            "cflash_cp": cflash_analysis,
            "cflash_swap": cflash_swap_analysis,
        }
        if dflash_analysis:
            if dflash_analysis.get("ika_hex"):
                report_out["ika_hex"] = dflash_analysis["ika_hex"]
            if dflash_analysis.get("gfa_hex"):
                report_out["gfa_hex"] = dflash_analysis["gfa_hex"]
            if dflash_analysis.get("ecu_boot_sum_hex"):
                report_out["ecu_boot_sum_hex"] = dflash_analysis["ecu_boot_sum_hex"]
        if session_dir is not None:
            s_path = Path(session_dir)
            s_path.mkdir(parents=True, exist_ok=True)
            (s_path / "mrr_read_report.json").write_text(
                json.dumps(report_out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        return report_out


def _flash_mrr_cp_mode(
    port: str,
    *,
    restore_stock: bool = False,
    app_image: bytes | Path | None = None,
    driver_image: bytes | Path | None = None,
    force: bool = False,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    session_dir: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Apply or revert the 7-point Code Flash CP-disable patch on a live MRR radar + reset CP counter + clear DTCs."""
    with _managed_mrr_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_extended_can=True,
        idle_limit=MRR_BRIDGE_FLASH_IDLE_LIMIT,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        reporter.step(1, 5, tr("Чтение паспорта и статуса 13 ACC Radar…", "Reading 13 ACC Radar passport & status…"))
        passport = link.read_passport()
        status_before = link.read_status_dids()
        _require_matching_mrr_sw_profile(passport, sw_profile, force=force)
        prof = mrr_detect_profile(passport, sw_version=sw_profile or "")

        if not prof.get("verified") or not prof.get("flash_write_supported"):
            raise RuntimeError(
                tr(
                    f"Прямая прошивка секторов Code Flash по XCP поддерживается только для проверенных профилей "
                    f"(0130, 0192, 0194, 0196, 0682, X720, 0771, 0780; обнаружено ПО: {prof['sw']}).",
                    f"Live XCP Code Flash sector flashing is supported only for verified profiles "
                    f"(0130, 0192, 0194, 0196, 0682, X720, 0771, 0780; detected SW: {prof['sw']}).",
                )
            )

        reporter.step(2, 5, tr("Подключение и разблокировка XCP…", "Connecting and unlocking XCP…"))
        link.ensure_xcp_enabled(reporter=reporter)

        drv_bytes: bytes | None = None
        if isinstance(driver_image, (bytes, bytearray, memoryview)):
            drv_bytes = bytes(driver_image)
        elif isinstance(driver_image, Path):
            drv_bytes = driver_image.read_bytes()

        if app_image is not None:
            raw_img = app_image.read_bytes() if isinstance(app_image, Path) else bytes(app_image)
            patched_img, patch_manifest = mrr_apply_cp_disable_patch(
                raw_img,
                restore_stock=restore_stock,
                profile=prof["sw"],
            )
            sectors = mrr_extract_cp_affected_sectors(patched_img, profile=prof["sw"])
        else:
            # Read only the affected C90FL sectors directly from the live radar, patch the 7 sites in place!
            reporter.info(
                tr(
                    "Чтение целевых секторов Code Flash из радара для патча CP…",
                    "Reading target Code Flash sectors from radar for in-place CP patching…",
                )
            )
            sector_specs = [(f"sec_0x{addr:06X}", addr, sz) for addr, sz in prof["cp_affected_sectors"]]
            sec_reads = link.xcp_read_fast_regions(sector_specs, profile=prof, reporter=reporter)
            sector_map: dict[int, bytearray] = {}
            for (addr, sz), (_, sec_data, _, _) in zip(prof["cp_affected_sectors"], sec_reads):
                link.verify_region_checksum(addr, sec_data)
                sector_map[addr] = bytearray(sec_data)
                if session_dir is not None:
                    bkp_dir = Path(session_dir)
                    bkp_dir.mkdir(parents=True, exist_ok=True)
                    (bkp_dir / f"backup_sector_0x{addr:06X}.bin").write_bytes(sec_data)

            records: list[dict[str, Any]] = []
            for name, address, stock_hex, patched_hex in prof["patches"]:
                stock_b = bytes.fromhex(stock_hex)
                patched_b = bytes.fromhex(patched_hex)
                target_b = stock_b if restore_stock else patched_b
                hit_sec = None
                for sec_addr, sec_buf in sector_map.items():
                    if sec_addr <= address and address + len(stock_b) <= sec_addr + len(sec_buf):
                        hit_sec = (sec_addr, sec_buf)
                        break
                if hit_sec is None:
                    raise RuntimeError(f"Patch address 0x{address:08X} does not lie in affected sectors")
                sec_addr, sec_buf = hit_sec
                rel_off = address - sec_addr
                actual_b = bytes(sec_buf[rel_off:rel_off + len(stock_b)])
                if actual_b not in (stock_b, patched_b):
                    raise ValueError(
                        f"Unexpected bytes at 0x{address:08X}: got {actual_b.hex()}, "
                        f"expected {stock_hex} or {patched_hex}"
                    )
                sec_buf[rel_off:rel_off + len(target_b)] = target_b
                records.append({
                    "name": name,
                    "physical_address": f"0x{address:08X}",
                    "before": actual_b.hex(),
                    "after": target_b.hex(),
                    "changed": actual_b != target_b,
                })
            sectors = [(addr, bytes(buf)) for addr, buf in sector_map.items()]
            patch_manifest = {
                "unit": prof["unit"],
                "sw": prof["sw"],
                "mode": "restore_stock" if restore_stock else "cp_disable",
                "patch_count": len(records),
                "patches": records,
            }

        reporter.step(
            3,
            5,
            tr(
                "Прошивка модифицированных секторов Code Flash через XCP + DB_99ERASEROUTI…",
                "Flashing modified Code Flash sectors via XCP + DB_99ERASEROUTI…",
            ),
        )
        flash_result = link.xcp_flash_write_sectors(
            sectors,
            driver_image=drv_bytes,
            profile=prof,
            skip_unchanged=not force,
            backup_dir=Path(session_dir) if session_dir is not None else None,
            reporter=reporter,
        )

        reporter.step(
            4,
            5,
            tr(
                "Сброс счётчика CP (DID 0x03DE -> 0x0000) в DFLASH0 и очистка DTC…",
                "Resetting CP counter (DID 0x03DE -> 0x0000) in DFLASH0 and clearing DTCs…",
            ),
        )
        trigger_addr = prof.get("sram_auth_success_trigger_addr")
        counter_addr = prof.get("sram_cp_counter_addr")
        ram_end = int(prof.get("ram_safe_end") or 0x4005E000)
        if trigger_addr:
            with contextlib.suppress(Exception):
                link.xcp_write_ram(int(trigger_addr), (1).to_bytes(4, "big"), verify=False, ram_end=ram_end)
                fake_bus = getattr(link.bus, "__class__", None).__module__.startswith("tests")
                if counter_addr:
                    for _ in range(12):
                        time.sleep(0.01 if fake_bus else 0.08)
                        raw_cnt = link.xcp_read_memory(int(counter_addr), 2)
                        if int.from_bytes(raw_cnt, "big") == 0:
                            break
                elif not fake_bus:
                    time.sleep(0.15)

        with contextlib.suppress(Exception):
            link.request_uds(b"\x10\x03", 0x50, timeout=1.2)
            link.request_uds(b"\x14\xFF\xFF\xFF", 0x54, timeout=2.0)

        reporter.step(
            5,
            5,
            tr("Холодный сброс радара (UDS 11 02) и проверка статуса CP…", "Cold reset of radar (UDS 11 02) & verifying CP status…"),
        )
        reset_ok = _reset_and_wait_mrr(link, reset_subfn=0x02)
        if not reset_ok:
            raise RuntimeError(
                tr(
                    "Секторы Code Flash записаны и проверены по SHA-256, но радар не ответил на UDS 10 01 после сброса 11 02. "
                    "Переподключите питание +12 В на стенде и проверьте связь.",
                    "Code Flash sectors were programmed and verified by SHA-256, but the radar did not respond to UDS 10 01 "
                    "after 11 02 reset. Cycle +12 V bench power and verify link.",
                )
            )
        with contextlib.suppress(Exception):
            link.request_uds(b"\x10\x03", 0x50, timeout=1.2)
            link.request_uds(b"\x14\xFF\xFF\xFF", 0x54, timeout=2.0)

        target_state = "stock" if restore_stock else "cp_disabled"
        cflash_cp_after: dict[str, Any] = {
            "unit": prof["unit"],
            "sw": prof["sw"],
            "cp_patch_state": target_state,
            "stock_points": len(prof["patches"]) if restore_stock else 0,
            "patched_points": 0 if restore_stock else len(prof["patches"]),
            "total_points": len(prof["patches"]),
            "points": [
                {
                    "name": rec["name"],
                    "physical_address": rec["physical_address"],
                    "actual_hex": rec["after"],
                    "state": target_state,
                }
                for rec in patch_manifest.get("patches", [])
            ],
        }
        status_after = link.read_status_dids()
        dtcs_after: list[dict[str, Any]] | None = None
        with contextlib.suppress(Exception):
            dtcs_after = link.read_dtcs()
        return {
            "ecu": "13_MRR",
            "profile": prof["sw"],
            "unit": prof["unit"],
            "mode": "restore_cp_stock" if restore_stock else "apply_cp_disable",
            "via_gateway": via_gateway,
            "gateway_bridged": bridged,
            "reset_confirmed": reset_ok,
            "cp_patch_state": target_state,
            "cflash_cp": cflash_cp_after,
            "patch_manifest": patch_manifest,
            "flash_result": flash_result,
            "status_before": status_before,
            "status_after": status_after,
            "dtcs": dtcs_after,
            "session_dir": str(session_dir) if session_dir is not None else None,
        }


def can_mrr_deactivate_cp(
    port: str,
    *,
    app_image: bytes | Path | None = None,
    driver_image: bytes | Path | None = None,
    force: bool = False,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    session_dir: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Deactivate Component Protection on a live 13 ACC Radar (7-point Code Flash patch + CP counter reset + DTC clear)."""
    return _flash_mrr_cp_mode(
        port,
        restore_stock=False,
        app_image=app_image,
        driver_image=driver_image,
        force=force,
        interface=interface,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        sw_profile=sw_profile,
        session_dir=session_dir,
        log_path=log_path,
        reporter=reporter,
    )


def can_mrr_restore_cp_stock(
    port: str,
    *,
    app_image: bytes | Path | None = None,
    driver_image: bytes | Path | None = None,
    force: bool = False,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    session_dir: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Restore stock Component Protection logic on a live 13 ACC Radar."""
    return _flash_mrr_cp_mode(
        port,
        restore_stock=True,
        app_image=app_image,
        driver_image=driver_image,
        force=force,
        interface=interface,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        sw_profile=sw_profile,
        session_dir=session_dir,
        log_path=log_path,
        reporter=reporter,
    )


def _flash_mrr_swap_mode(
    port: str,
    *,
    restore_stock: bool = False,
    package_index: int = 6,
    groups: tuple[int, int, int, int] = (8, 3, 4, 7),
    app_image: bytes | Path | None = None,
    driver_image: bytes | Path | None = None,
    force: bool = False,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    session_dir: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Apply or revert the direct Code Flash SWaP / FSC activation patch on a live MRR radar + clear DTCs + reboot."""
    with _managed_mrr_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_extended_can=True,
        idle_limit=MRR_BRIDGE_FLASH_IDLE_LIMIT,
        sw_profile=sw_profile,
        reporter=reporter,
    ) as (link, bridged):
        reporter.step(1, 5, tr("Чтение паспорта и статуса 13 ACC Radar…", "Reading 13 ACC Radar passport & status…"))
        passport = link.read_passport()
        status_before = link.read_status_dids()
        _require_matching_mrr_sw_profile(passport, sw_profile, force=force)
        prof = mrr_detect_profile(passport, sw_version=sw_profile or "")
        swap_cfg = prof.get("swap_config")

        if not prof.get("verified") or not prof.get("flash_write_supported") or not swap_cfg:
            raise RuntimeError(
                tr(
                    f"Прямая прошивка патча SWaP/FSC в Code Flash по XCP поддерживается только для проверенных профилей "
                    f"(0130, 0192, 0194, 0196, 0682, X720, 0771, 0780; обнаружено ПО: {prof['sw']}).",
                    f"Live XCP Code Flash SWaP/FSC sector flashing is supported only for verified profiles "
                    f"(0130, 0192, 0194, 0196, 0682, X720, 0771, 0780; detected SW: {prof['sw']}).",
                )
            )

        gen = int(swap_cfg["generation"])
        if gen == 1 and not restore_stock and (package_index not in MRR_GEN1_SWAP_PACKAGES or package_index == 3):
            raise ValueError(
                f"Invalid Gen 1 SWaP package index {package_index}; allowed values: 0, 1, 2, 4, 5, 6"
            )
        if gen == 2 and not restore_stock:
            mrr_build_gen2_swap_group_stub(int(groups[0]), int(groups[1]), int(groups[2]), int(groups[3]))

        reporter.step(2, 5, tr("Подключение и разблокировка XCP…", "Connecting and unlocking XCP…"))
        link.ensure_xcp_enabled(reporter=reporter)

        drv_bytes: bytes | None = None
        if isinstance(driver_image, (bytes, bytearray, memoryview)):
            drv_bytes = bytes(driver_image)
        elif isinstance(driver_image, Path):
            drv_bytes = driver_image.read_bytes()

        if app_image is not None:
            raw_img = app_image.read_bytes() if isinstance(app_image, Path) else bytes(app_image)
            patched_img, patch_manifest = mrr_apply_swap_patch(
                raw_img,
                restore_stock=restore_stock,
                profile=prof["sw"],
                package_index=package_index,
                groups=groups,
            )
            sectors = mrr_extract_swap_affected_sectors(patched_img, profile=prof["sw"])
        else:
            reporter.info(
                tr(
                    "Чтение целевого сектора Code Flash из радара для патча SWaP/FSC…",
                    "Reading target Code Flash sector from radar for in-place SWaP/FSC patching…",
                )
            )
            sector_specs = [(f"sec_0x{addr:06X}", addr, sz) for addr, sz in prof["swap_affected_sectors"]]
            sec_reads = link.xcp_read_fast_regions(sector_specs, profile=prof, reporter=reporter)
            sector_map: dict[int, bytearray] = {}
            for (addr, sz), (_, sec_data, _, _) in zip(prof["swap_affected_sectors"], sec_reads):
                link.verify_region_checksum(addr, sec_data)
                sector_map[addr] = bytearray(sec_data)
                if session_dir is not None:
                    bkp_dir = Path(session_dir)
                    bkp_dir.mkdir(parents=True, exist_ok=True)
                    (bkp_dir / f"backup_sector_0x{addr:06X}.bin").write_bytes(sec_data)

            def _read_sector_bytes(address: int, length: int) -> bytes:
                for sec_addr, sec_buf in sector_map.items():
                    if sec_addr <= address and address + length <= sec_addr + len(sec_buf):
                        rel_off = address - sec_addr
                        return bytes(sec_buf[rel_off:rel_off + length])
                raise RuntimeError(f"SWaP patch address 0x{address:08X} does not lie in affected sectors")

            def _write_sector_bytes(address: int, payload: bytes) -> None:
                for sec_addr, sec_buf in sector_map.items():
                    if sec_addr <= address and address + len(payload) <= sec_addr + len(sec_buf):
                        rel_off = address - sec_addr
                        sec_buf[rel_off:rel_off + len(payload)] = payload
                        return
                raise RuntimeError(f"SWaP patch address 0x{address:08X} does not lie in affected sectors")

            patch_manifest = mrr_apply_swap_sites(
                prof,
                _read_sector_bytes,
                _write_sector_bytes,
                restore_stock=restore_stock,
                package_index=package_index,
                groups=groups,
            )
            sectors = [(addr, bytes(buf)) for addr, buf in sector_map.items()]

        reporter.step(
            3,
            5,
            tr(
                "Прошивка модифицированного сектора Code Flash через XCP + DB_99ERASEROUTI…",
                "Flashing modified Code Flash sector via XCP + DB_99ERASEROUTI…",
            ),
        )
        flash_result = link.xcp_flash_write_sectors(
            sectors,
            driver_image=drv_bytes,
            profile=prof,
            skip_unchanged=not force,
            backup_dir=Path(session_dir) if session_dir is not None else None,
            reporter=reporter,
        )

        reporter.step(
            4,
            5,
            tr("Очистка DTC (UDS 14 FF FF FF)…", "Clearing DTCs (UDS 14 FF FF FF)…"),
        )
        with contextlib.suppress(Exception):
            link.request_uds(b"\x10\x03", 0x50, timeout=1.2)
            link.request_uds(b"\x14\xFF\xFF\xFF", 0x54, timeout=2.0)

        reporter.step(
            5,
            5,
            tr("Холодный сброс радара (UDS 11 02) и проверка статуса SWaP/FSC…", "Cold reset of radar (UDS 11 02) & verifying SWaP/FSC status…"),
        )
        reset_ok = _reset_and_wait_mrr(link, reset_subfn=0x02)
        if not reset_ok:
            raise RuntimeError(
                tr(
                    "Сектор Code Flash записан и проверен по SHA-256, но радар не ответил на UDS 10 01 после сброса 11 02. "
                    "Переподключите питание +12 В на стенде и проверьте связь.",
                    "Code Flash sector was programmed and verified by SHA-256, but the radar did not respond to UDS 10 01 "
                    "after 11 02 reset. Cycle +12 V bench power and verify link.",
                )
            )
        with contextlib.suppress(Exception):
            link.request_uds(b"\x10\x03", 0x50, timeout=1.2)
            link.request_uds(b"\x14\xFF\xFF\xFF", 0x54, timeout=2.0)

        target_state = "stock" if restore_stock else "swap_activated"
        total_pts = len(patch_manifest.get("patches", []))
        cflash_swap_after: dict[str, Any] = {
            "unit": prof["unit"],
            "sw": prof["sw"],
            "verified": True,
            "generation": gen,
            "swap_patch_state": target_state,
            "stock_points": total_pts if restore_stock else 0,
            "patched_points": 0 if restore_stock else total_pts,
            "total_points": total_pts,
            "package_index": patch_manifest.get("package_index"),
            "feature_level": patch_manifest.get("feature_level"),
            "groups": patch_manifest.get("groups"),
            "coding_byte12_13_hex": patch_manifest.get("coding_byte12_13_hex"),
            "active_fsids": patch_manifest.get("active_fsids", []),
            "points": [
                {
                    "name": rec["name"],
                    "physical_address": rec["physical_address"],
                    "actual_hex": rec["after"],
                    "state": target_state,
                }
                for rec in patch_manifest.get("patches", [])
            ],
        }
        if gen == 1 and not restore_stock and package_index in MRR_GEN1_SWAP_PACKAGES:
            pkg_meta = MRR_GEN1_SWAP_PACKAGES[package_index]
            cflash_swap_after["package_title_ru"] = pkg_meta["title_ru"]
            cflash_swap_after["package_title_en"] = pkg_meta["title_en"]
        elif gen == 2 and not restore_stock:
            g_tuple = (int(groups[0]), int(groups[1]), int(groups[2]), int(groups[3]))
            cflash_swap_after["group_details"] = mrr_describe_gen2_swap_groups(g_tuple)["group_details"]

        status_after = link.read_status_dids()
        swap_uds_after: dict[str, Any] | None = None
        with contextlib.suppress(Exception):
            coding_raw = bytes.fromhex(str(passport["coding"])) if passport.get("coding") else None
            swap_uds_after = link.read_swap_status_uds(
                include_metadata=True,
                coding_raw=coding_raw,
                generation=gen,
            )
        dtcs_after: list[dict[str, Any]] | None = None
        with contextlib.suppress(Exception):
            dtcs_after = link.read_dtcs()
        return {
            "ecu": "13_MRR",
            "ecu_kind": "mrr",
            "profile": prof["sw"],
            "unit": prof["unit"],
            "generation": gen,
            "mode": "restore_swap_stock" if restore_stock else "apply_swap_activate",
            "via_gateway": via_gateway,
            "gateway_bridged": bridged,
            "reset_confirmed": reset_ok,
            "swap_patch_state": target_state,
            "cflash_swap": cflash_swap_after,
            "swap_uds": swap_uds_after,
            "patch_manifest": patch_manifest,
            "flash_result": flash_result,
            "status_before": status_before,
            "status_after": status_after,
            "dtcs": dtcs_after,
            "session_dir": str(session_dir) if session_dir is not None else None,
        }


def can_mrr_activate_swap(
    port: str,
    *,
    package_index: int = 6,
    groups: tuple[int, int, int, int] = (8, 3, 4, 7),
    app_image: bytes | Path | None = None,
    driver_image: bytes | Path | None = None,
    force: bool = False,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    session_dir: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Activate SWaP / FSC feature package (Gen 1) or 4-group set (Gen 2) directly in Code Flash on a live 13 ACC Radar."""
    return _flash_mrr_swap_mode(
        port,
        restore_stock=False,
        package_index=package_index,
        groups=groups,
        app_image=app_image,
        driver_image=driver_image,
        force=force,
        interface=interface,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        sw_profile=sw_profile,
        session_dir=session_dir,
        log_path=log_path,
        reporter=reporter,
    )


def can_mrr_restore_swap_stock(
    port: str,
    *,
    app_image: bytes | Path | None = None,
    driver_image: bytes | Path | None = None,
    force: bool = False,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 2,
    sw_profile: str | None = None,
    session_dir: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Restore stock SWaP / FSC evaluation logic in Code Flash on a live 13 ACC Radar."""
    return _flash_mrr_swap_mode(
        port,
        restore_stock=True,
        app_image=app_image,
        driver_image=driver_image,
        force=force,
        interface=interface,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        sw_profile=sw_profile,
        session_dir=session_dir,
        log_path=log_path,
        reporter=reporter,
    )


def _mrr_parse_download_max_block(resp: bytes) -> int:
    if len(resp) < 3 or resp[0] != 0x74:
        raise UnexpectedUdsResponse(f"Unexpected RequestDownload response: {resp.hex()}")
    lfid = resp[1]
    if lfid & 0x0F:
        raise UnexpectedUdsResponse(f"Invalid RequestDownload lengthFormatIdentifier: {resp.hex()}")
    n_bytes = lfid >> 4
    if not (1 <= n_bytes <= 4) or len(resp) != 2 + n_bytes:
        raise UnexpectedUdsResponse(f"Invalid maxNumberOfBlockLength encoding: {resp.hex()}")
    max_len = int.from_bytes(resp[2:], "big")
    if max_len < 3:
        raise UnexpectedUdsResponse(f"Advertised TransferData block length too small: {max_len}")
    return max_len


def _mrr_require_routine_ok(resp: bytes, routine_id: int, label: str) -> None:
    expected_prefix = bytes([0x71, 0x01, (routine_id >> 8) & 0xFF, routine_id & 0xFF])
    if len(resp) < 5 or not resp.startswith(expected_prefix):
        raise UnexpectedUdsResponse(f"{label}: unexpected RoutineControl response {resp.hex()}")
    if resp[4] != 0x00:
        raise RuntimeError(
            tr(
                f"{label}: загрузчик FBLv вернул код отказа 0x{resp[4]:02X} ({resp.hex()})",
                f"{label}: FBLv bootloader returned failure code 0x{resp[4]:02X} ({resp.hex()})",
            )
        )


def _mrr_upload_fblv_block(
    link: MrrCanLink,
    block: MrrFrfBlock,
    *,
    reporter: OperationReporter = NULL_REPORTER,
    progress_label: str = "",
) -> dict[str, Any]:
    req_dl = bytes([0x34, block.data_format & 0xFF, 0x41, block.block_id & 0xFF]) + block.uncompressed_size.to_bytes(4, "big")
    dl_resp = link.request_uds(req_dl, 0x74, timeout=10.0)
    advertised = _mrr_parse_download_max_block(dl_resp)
    eff_max = min(advertised, 0xFFF)
    payload_sz = eff_max - 2
    stream = block.stream
    total_len = len(stream)
    total_blocks = (total_len + payload_sz - 1) // payload_sz
    started = time.monotonic()

    sent = 0
    for idx, off in enumerate(range(0, total_len, payload_sz)):
        seq = (idx + 1) & 0xFF
        chunk = stream[off : off + payload_sz]
        resp = link.request_uds(bytes([0x36, seq]) + chunk, 0x76, timeout=30.0)
        if len(resp) < 2 or resp[1] != seq:
            raise UnexpectedUdsResponse(f"Unexpected TransferData response for seq 0x{seq:02X}: {resp.hex()}")
        sent += len(chunk)
        if idx == 0 or (idx + 1) % 4 == 0 or (idx + 1) == total_blocks:
            reporter.progress(
                sent,
                total_len,
                unit="B",
                detail=f"{progress_label} ({idx + 1}/{total_blocks})" if progress_label else f"{idx + 1}/{total_blocks}",
            )

    link.request_uds(b"\x37", 0x77, timeout=30.0)
    elapsed = max(0.001, time.monotonic() - started)
    return {
        "name": block.name,
        "block_id": f"0x{block.block_id:02X}",
        "data_format": f"0x{block.data_format:02X}",
        "request_download_response": dl_resp.hex(),
        "advertised_max_block_length": advertised,
        "transfer_payload_per_block": payload_sz,
        "transfer_blocks": total_blocks,
        "stream_bytes": total_len,
        "elapsed_sec": round(elapsed, 3),
        "bytes_per_sec": round(total_len / elapsed),
    }


def can_mrr_flash_frf(
    port: str,
    frf: MrrFrfImage | Path | bytes,
    *,
    allow_mismatch: bool = False,
    recovery_mode: bool = False,
    clear_dtcs: bool = True,
    interface: str = "slcan",
    bus: Any | None = None,
    via_gateway: bool = False,
    sw_profile: str | None = None,
    session_dir: Path | None = None,
    log_path: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Flash a factory-signed ODIS FRF / ODX-F container onto a 13 ACC Radar (3Q0 / 5Q0 / 3QF) over pure UDS 10 02.

    Works both on direct Extended CAN and through the J533 gateway UDS routing (no 29-bit XCP or RAM-bridge needed).
    Verifies RSA-1024 signatures, LZSS 0xA0 decompression, CRC-32, and MCU generation BEFORE erasing Code Flash.
    """
    if isinstance(frf, MrrFrfImage):
        img = frf
    elif isinstance(frf, Path):
        img = mrr_read_frf(frf.read_bytes(), frf.name)
    elif isinstance(frf, (bytes, bytearray, memoryview)):
        img = mrr_read_frf(bytes(frf))
    else:
        raise TypeError(f"Unsupported frf input type: {type(frf).__name__}")

    if session_dir is not None:
        session_dir.mkdir(parents=True, exist_ok=True)
        if log_path is None:
            log_path = session_dir / "can.jsonl"

    result: dict[str, Any] = {
        "ecu": "13_MRR",
        "ecu_kind": "mrr",
        "mode": "flash_frf",
        "frf": img.summary(),
        "via_gateway": via_gateway,
        "recovery_mode": recovery_mode,
        "complete": False,
        "session_dir": str(session_dir) if session_dir is not None else None,
    }

    try:
        with _managed_mrr_session(
            port,
            interface=interface,
            log_path=log_path,
            bus=bus,
            via_gateway=via_gateway,
            gateway_bridge=False,
            needs_raw_extended_can=False,
            sw_profile=sw_profile,
            reporter=reporter,
        ) as (link, _bridged):
            # Step 1: Identify target & verify MCU / signature compatibility BEFORE touching flash
            reporter.step(
                1,
                6,
                tr(
                    f"Проверка совместимости {img.kind} ({img.part_number} · {img.sw_version} · {img.mcu})…",
                    f"Verifying {img.kind} compatibility ({img.part_number} · {img.sw_version} · {img.mcu})…",
                ),
            )
            passport_before: dict[str, Any] = {}
            try:
                passport_before = link.read_passport()
            except Exception as exc:  # noqa: BLE001
                if not recovery_mode:
                    raise RuntimeError(
                        tr(
                            f"Не удалось прочитать паспорт радара ({exc}). Если радар уже в загрузчике FBLv, "
                            "включите «Режим восстановления из загрузчика (FBLv)».",
                            f"Could not read radar passport ({exc}). If the radar is already stuck in FBLv bootloader, "
                            "enable 'Bootloader recovery mode (FBLv)'.",
                        )
                    ) from exc
                reporter.warning(
                    tr(
                        f"Паспорт приложения не прочитан ({exc}) — продолжаем в режиме восстановления FBLv.",
                        f"Application passport unavailable ({exc}) — continuing in FBLv recovery mode.",
                    )
                )
            result["passport_before"] = passport_before

            hard_errs, soft_warns = mrr_frf_compatibility(img, passport_before, recovery_mode=recovery_mode)
            result["compatibility"] = {"hard_errors": hard_errs, "warnings": soft_warns}
            if hard_errs:
                raise RuntimeError("; ".join(hard_errs))
            if soft_warns and not allow_mismatch and not recovery_mode:
                raise RuntimeError(
                    tr("Предупреждение совместимости (подтвердите кросс-прошивку): ", "Compatibility warning (confirm cross-flash): ")
                    + "; ".join(soft_warns)
                )
            for w in soft_warns:
                reporter.warning(w)

            in_programming_session = False
            flash_erased = False
            try:
                # Step 2: Enter Programming Session (10 02), unlock FBLv (27 11/12), write fingerprint (2E F1 5A)
                reporter.step(
                    2,
                    6,
                    tr(
                        "Вход в сессию программирования FBLv (10 02 → 27 11/12 → 2E F1 5A)…",
                        "Entering FBLv Programming Session (10 02 → 27 11/12 → 2E F1 5A)…",
                    ),
                )
                if recovery_mode:
                    with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                        link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
                else:
                    link.request_uds(b"\x10\x03", 0x50, timeout=3.0)
                link.request_uds(b"\x10\x02", 0x50, timeout=30.0)
                in_programming_session = True

                seed_resp = link.request_uds(b"\x27\x11", 0x67, timeout=5.0)
                if len(seed_resp) != 6 or seed_resp[1] != 0x11:
                    raise UnexpectedUdsResponse(f"Unexpected FBLv SecurityAccess seed response: {seed_resp.hex()}")
                seed = int.from_bytes(seed_resp[2:6], "big")
                if seed != 0:
                    key = mrr_fblv_compute_key(seed)
                    link.request_uds(b"\x27\x12" + key.to_bytes(4, "big"), 0x67, timeout=5.0)
                result["fblv_security_access"] = {"seed": f"0x{seed:08X}", "accepted": True}

                fp_resp = link.request_uds(b"\x2E\xF1\x5A" + bytes(9), 0x6E, timeout=5.0)
                if fp_resp != b"\x6E\xF1\x5A":
                    raise UnexpectedUdsResponse(f"Unexpected WriteFingerprint response: {fp_resp.hex()}")
                result["fingerprint_written"] = True

                # Step 3: Upload RAM Flash Driver DB_99ERASEROUTI & verify CheckMemory
                reporter.step(
                    3,
                    6,
                    tr(
                        "Загрузка flash-драйвера DB_99ERASEROUTI в SRAM (16 КиБ) и проверка RSA…",
                        "Uploading DB_99ERASEROUTI flash driver into SRAM (16 KiB) & verifying RSA…",
                    ),
                )
                result["driver_upload"] = _mrr_upload_fblv_block(
                    link,
                    img.driver,
                    reporter=reporter,
                    progress_label="DB_99ERASEROUTI",
                )
                drv_chk = link.request_uds(b"\x31\x01\x02\x02" + img.driver.signature, 0x71, timeout=60.0)
                _mrr_require_routine_ok(drv_chk, 0x0202, "DB_99ERASEROUTI CheckMemory")
                result["driver_check_memory_response"] = drv_chk.hex()

                # Step 4: Erase logical block 0x10 (Code Flash application)
                reporter.step(
                    4,
                    6,
                    tr(
                        "Стирание Code Flash приложения (31 01 FF 00 01 10) — НЕ ОТКЛЮЧАЙТЕ ПИТАНИЕ!",
                        "Erasing Code Flash application (31 01 FF 00 01 10) — DO NOT CUT POWER!",
                    ),
                )
                reporter.check_cancelled()
                with reporter.uninterruptible():
                    flash_erased = True
                    erase_resp = link.request_uds(b"\x31\x01\xFF\x00\x01\x10", 0x71, timeout=180.0)
                    _mrr_require_routine_ok(erase_resp, 0xFF00, "EraseMemory (block 0x10)")
                    result["erase_response"] = erase_resp.hex()

                    # Step 5: Stream DB_10FLASHDATA, verify RSA-1024 + CRC-32 & ProgrammingDependencies
                    reporter.step(
                        5,
                        6,
                        tr(
                            f"Запись приложения {img.part_number} {img.sw_version} "
                            f"({len(img.app.stream) // 1024} КиБ поток → {img.app.uncompressed_size // 1024} КиБ) — НЕ ОТКЛЮЧАЙТЕ ПИТАНИЕ!",
                            f"Programming application {img.part_number} {img.sw_version} "
                            f"({len(img.app.stream) // 1024} KiB stream → {img.app.uncompressed_size // 1024} KiB) — DO NOT CUT POWER!",
                        ),
                    )
                    result["application_upload"] = _mrr_upload_fblv_block(
                        link,
                        img.app,
                        reporter=reporter,
                        progress_label=f"DB_10FLASHDATA ({img.sw_version})",
                    )

                    app_chk_req = b"\x31\x01\x02\x02" + img.app.signature + img.app.crc32.to_bytes(4, "big")
                    app_chk = link.request_uds(app_chk_req, 0x71, timeout=180.0)
                    result["application_check_memory_response"] = app_chk.hex()
                    _mrr_require_routine_ok(app_chk, 0x0202, "DB_10FLASHDATA CheckMemory (RSA-1024 + CRC-32)")
                    result["application_rsa_accepted"] = True

                    dep_resp = link.request_uds(b"\x31\x01\xFF\x01", 0x71, timeout=60.0)
                    _mrr_require_routine_ok(dep_resp, 0xFF01, "CheckProgrammingDependencies")
                    result["programming_dependencies_response"] = dep_resp.hex()

                    # Step 6: Hard Reset (11 01), wait for Application boot, clear DTCs & re-read passport/status
                    reporter.step(
                        6,
                        6,
                        tr(
                            "Перезагрузка радара (11 01), проверка запуска ПО и опрос статуса…",
                            "Resetting radar (11 01), verifying application boot & reading status…",
                        ),
                    )
                    reset_resp_hex = ""
                    try:
                        r_resp = link.request_uds(b"\x11\x01", 0x51, timeout=5.0, resend=False)
                        reset_resp_hex = r_resp.hex()
                    except (*TRANSPORT_ERRORS, UnexpectedUdsResponse):
                        reset_resp_hex = "sent_no_reply"
                    in_programming_session = False
                    result["ecu_reset_response"] = reset_resp_hex
            finally:
                if in_programming_session and not flash_erased and not recovery_mode:
                    with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                        link.request_uds(b"\x11\x01", 0x51, timeout=3.0, resend=False)

            fake_bus = getattr(link.bus, "__class__", None).__module__.startswith("tests")
            if not fake_bus:
                time.sleep(1.5)
                link.drain_rx(max_frames=128, quick=True)
            booted = False
            deadline = time.monotonic() + (2.0 if fake_bus else 15.0)
            while time.monotonic() < deadline:
                try:
                    link.request_uds(b"\x10\x01", 0x50, timeout=0.8)
                    booted = True
                    break
                except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                    time.sleep(0.01 if fake_bus else 0.25)
            result["reset_confirmed"] = booted
            if not booted:
                raise RuntimeError(
                    tr(
                        "Прошивка принята загрузчиком FBLv (RSA OK), но радар не ответил на 10 01 после сброса 11 01. "
                        "Переподключите питание +12 В и выполните опрос блока.",
                        "Firmware was accepted by FBLv (RSA OK), but radar did not respond to 10 01 after 11 01 reset. "
                        "Cycle +12 V power and re-poll the radar.",
                    )
                )

            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                sess = link.read_did(0xF186, timeout=1.0)
                if sess == b"\x02":
                    raise RuntimeError(
                        tr(
                            "После сброса радар остался в загрузчике FBLv (DID F186 = 0x02).",
                            "After reset, radar stayed in FBLv bootloader (DID F186 = 0x02).",
                        )
                    )

            if clear_dtcs:
                with contextlib.suppress(Exception):
                    link.request_uds(b"\x10\x03", 0x50, timeout=1.5)
                    link.request_uds(b"\x14\xFF\xFF\xFF", 0x54, timeout=3.0)
                    link.request_uds(b"\x10\x01", 0x50, timeout=1.5)

            passport_after = link.read_passport()
            status_after = link.read_status_dids()
            swap_uds_after: dict[str, Any] | None = None
            with contextlib.suppress(Exception):
                coding_raw = bytes.fromhex(str(passport_after["coding"])) if passport_after.get("coding") else None
                swap_uds_after = link.read_swap_status_uds(
                    include_metadata=True,
                    coding_raw=coding_raw,
                    generation=img.generation,
                )
            dtcs_after: list[dict[str, Any]] | None = None
            with contextlib.suppress(Exception):
                dtcs_after = link.read_dtcs()

            result["passport_after"] = passport_after
            result["status_after"] = status_after
            result["swap_uds"] = swap_uds_after
            result["dtcs"] = dtcs_after
            result["complete"] = True

            old_sw = passport_before.get("sw_version") or "—"
            new_sw = passport_after.get("sw_version") or img.sw_version
            reporter.success(
                tr(
                    f"{img.kind} прошит успешно: {passport_after.get('part_number') or img.part_number} "
                    f"(ПО {old_sw} → {new_sw}, RSA-1024 OK, приложение запущено).",
                    f"{img.kind} flashed successfully: {passport_after.get('part_number') or img.part_number} "
                    f"(SW {old_sw} → {new_sw}, RSA-1024 OK, application running).",
                )
            )
            return result
    except Exception as exc:
        result["error"] = str(exc)
        raise
    finally:
        if session_dir is not None:
            with contextlib.suppress(OSError):
                (session_dir / "mrr_frf_result.json").write_text(
                    json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
