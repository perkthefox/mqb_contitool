"""Continental VAG MQB 17 Kombi VDD (`EV_DashBoardVDDMQBAB`, V850E2/Dx4 `uPD70F3526`) live CAN & Supplier Level 7 handler.

Unlike `FPK_E` (RH850/D1L + R-Car D1 virtual cockpit, which uses 29-bit `0x1BFCA2EC/ED` block-stream and RH850 SX RAM applets),
`Kombi VDD` (`5NA 920 740 B` `SW 0310`) operates entirely over standard 11-bit ISO-TP UDS (`0x714 -> 0x77E`):
  1. Stages `NVM Block 0x5C` (`60` bytes of `EEL 0x0063 +0x02..+0x3D`) into `0xFEDD5508..0xFEDD5543` via `10 60 -> 2E FD 11 08 00`.
  2. Unlocks `SA1` (`10 4F -> 27 03 / 27 04`, `key = (seed + 0xB80B) mod 2^32`). `NVM Block 0x18` overwrites only the first
     `27` bytes (`0xFEDD5508..0xFEDD5522`), leaving the 16-byte `FD11 Supplier Level 7 Key` + 4-byte `CRC-32` untouched at
     `0xFEDD5530..0xFEDD5543`, where it is read via `23 44 FE DD 55 30 00 00 00 14`.
  3. Authenticates to `FD11 Supplier Level 7` (`SL 7`) in `10 60` via `2E FD 11 03 <T16><T8> 07` + `2E FD 11 04 <proof>`,
     verified by `2E FD 11 01 -> 6E FD 11 07`.
  4. At `SL 7` in `10 60`, stages and reads all `EEL 0x0063` & `0x0064` sub-blocks from `0xFEDD5508` (including the 16-byte
     `FD11 Level 6 Key` at `0x006316`), reads the live physical offset table at `0xFEDC7BF0..0xFEDC7D07`, and reads/writes all
     132 EEL DataFlash blocks (`0x0001..0x0084`, including all WFS5 / Immo / Transponder / SHE / Component Protection records
     `0x0065..0x006F`) via `UDS 0x23` (`0xEF00BB00`) and `UDS 0x3D` (`0xEF00BB02`).
"""

from __future__ import annotations

from collections.abc import Iterator
import contextlib
from datetime import datetime, timezone
import hashlib
import inspect
import json
from pathlib import Path
import struct
import time
from typing import Any
import zlib

from contitool.can.fpke import (
    FpkeCanLink,
    atomic_write,
    build_fpke_drive_frame,
    close_active_fpke_link,
    fpke_coil_poll_transponder,
    fpke_read_memory_0x23,
    fpke_run_procedure,
    fpke_write_memory_0x3d,
    get_active_fpke_link,
    open_or_reuse_fpke_link,
    partition_chunks,
)
from contitool.can.transport import UdsNegativeResponse
from contitool.core.fpke import (
    build_fpke_02e1_request,
    fpke_s0_s1_from_slots,
    fpke_slots_from_s0_s1,
    fpke_verify_s0_s1,
)
from contitool.core.kombi import (
    EEL_KOMBI_0310_IDS,
    EEL_KOMBI_2220_IDS,
    KOMBI_2220_FDE3_AFFECTED_EEL_IDS,
    KOMBI_2220_RAM_FD11_STATE_ADDR,
    KOMBI_ALIGN4_EEL_IDS,
    KOMBI_CFLASH_ADDR,
    KOMBI_CFLASH_SIZE,
    KOMBI_DFLASH_BASE_ADDR,
    KOMBI_DFLASH_POOL_SIZE,
    KOMBI_DFLASH_SYNTH_SIZE,
    KOMBI_EEL_IMMO_MODE_VADDR,
    KOMBI_EEL_LOGICAL_SIZE,
    KOMBI_EEL_VIRTUAL_BASE,
    KOMBI_FD11_STAGED_SUBBLOCKS,
    KOMBI_NVM_BLOCK_CODING,
    KOMBI_NVM_BLOCK_IMMO,
    KOMBI_NVM_BLOCK_ODO,
    KOMBI_NVM_BLOCK_ODO_REPAIR,
    KOMBI_NVM_STAGED_EEL_MAP,
    KOMBI_RAM_EEL_PHYS_TABLE_ADDR,
    KOMBI_RAM_EEL_STATE_ADDR,
    KOMBI_RAM_IMMO_MODE_ADDR,
    KOMBI_RAM_LEVEL_ADDR,
    KOMBI_RAM_ODO_DPOOL_ADDR,
    KOMBI_RAM_ODO_METERS_ADDR,
    KOMBI_RAM_SL7_KEY_ADDR,
    KOMBI_RAM_STAGING_ADDR,
    KOMBI_REQUIRED_SL,
    KOMBI_RETAIN_ODO_DPOOL_ADDR,
    KOMBI_SA1_DELTA,
    KOMBI_SA1_LOCKOUT_RESET_DELTA,
    KOMBI_UDS_RX_ID,
    KOMBI_UDS_TX_ID,
    KOMBI_WR_PRIVILEGED_EEL_IDS,
    analyze_kombi_dflash,
    build_fd11_proof,
    build_kombi_eel_dflash,
    eel_read_record_any,
    extract_kombi_eel_updates,
    extract_kombi_immo_passport,
    get_kombi_sw_profile,
    is_kombi_dflash,
    kombi_crc16_ccitt,
    kombi_eel_layout,
    kombi_support_info,
    normalize_kombi_dflash_input,
    summarize_kombi_dflash_changes,
)
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationCancelledError, OperationReporter

KombiCanLink = FpkeCanLink


@contextlib.contextmanager
def _managed_kombi_session(
    port: str,
    *,
    interface: str = "slcan",
    log_path: Path | None = None,
    bus: Any | None = None,
    keep_open: bool = False,
    via_gateway: bool = False,
) -> Iterator[FpkeCanLink]:
    """Open or reuse a `0x714/0x77E` CAN link for `17 Kombi VDD` (works both directly and behind a J533 gateway over 11-bit UDS)."""
    active = get_active_fpke_link(port, interface, ecu_kind="kombi")
    reused = (
        active is not None
        and active.via_gateway == bool(via_gateway)
        and (bus is None or getattr(active, "bus", None) is bus)
    )
    if keep_open or reused:
        yield open_or_reuse_fpke_link(
            port,
            interface=interface,
            log_path=log_path,
            bus=bus,
            via_gateway=via_gateway,
            ecu_kind="kombi",
        )
    else:
        with FpkeCanLink(
            port,
            interface=interface,
            log_path=log_path,
            bus=bus,
            via_gateway=via_gateway,
            ecu_kind="kombi",
        ) as link:
            yield link


def _read_chunked_0x23(link: FpkeCanLink, address: int, size: int, *, chunk_size: int = 128, timeout: float = 3.0) -> bytes:
    out = bytearray()
    off = 0
    while off < size:
        cur = min(chunk_size, size - off)
        out.extend(fpke_read_memory_0x23(link, (address + off) & 0xFFFFFFFF, cur, timeout=timeout))
        off += cur
    return bytes(out)


def _get_link_kombi_profile(
    link: FpkeCanLink,
    *,
    ident: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    cached = getattr(link, "_kombi_sw_profile", None)
    if isinstance(cached, dict) and not ident:
        return cached
    f189_str = getattr(link, "_last_ident_sw", "")
    f187_str = getattr(link, "_last_ident_pn", "")
    if ident:
        vals = {str(it.get("did", "")).upper(): str(it.get("value", "")).strip() for it in ident}
        f189_str = vals.get("F189") or f189_str
        f187_str = vals.get("F187") or vals.get("F191") or f187_str
    if not f189_str and not f187_str:
        with contextlib.suppress(Exception):
            r89 = link.request_uds(b"\x22\xf1\x89", 0x62, timeout=0.8)
            f189_str = r89[3:].decode("latin1", errors="ignore").strip("\x00 ")
        with contextlib.suppress(Exception):
            r87 = link.request_uds(b"\x22\xf1\x87", 0x62, timeout=0.8)
            f187_str = r87[3:].decode("latin1", errors="ignore").strip("\x00 ")
    if f189_str:
        link._last_ident_sw = f189_str
    if f187_str:
        link._last_ident_pn = f187_str
    prof = get_kombi_sw_profile(sw_version=f189_str, part_number=f187_str)
    if f189_str or f187_str:
        link._kombi_sw_profile = prof
    return prof


def _check_kombi_link_support(
    link: FpkeCanLink,
    *,
    ident: list[dict[str, str]] | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    _get_link_kombi_profile(link, ident=ident)
    if not ident:
        f189_str = getattr(link, "_last_ident_sw", "")
        f187_str = getattr(link, "_last_ident_pn", "")
        sup = kombi_support_info(f189=f189_str, f187=f187_str)
    else:
        sup = kombi_support_info(ident)
    if sup["warning"] and not getattr(link, "_kombi_support_warned", False):
        link._kombi_support_warned = True
        reporter.warning(sup["warning"])
    return sup


# ────────────────────────────── Supplier Level 7 (SL 7) Extraction & Auth ──────────────────────────────


def kombi_check_sl7(link: FpkeCanLink, *, timeout: float = 1.0) -> bool:
    """Check whether `FD11 Supplier Level 7` (`6E FD 11 07`) is currently active in session `10 60`."""
    try:
        link.request_uds(b"\x10\x60", 0x50, timeout=timeout)
        resp = link.request_uds(b"\x2e\xfd\x11\x01", 0x6E, timeout=timeout)
        if len(resp) >= 4 and resp[:4] == b"\x6e\xfd\x11\x07":
            link.level8_active = True
            return True
    except Exception:
        pass
    link.level8_active = False
    return False


def _wait_fd11_timer_ready(
    link: FpkeCanLink,
    *,
    max_wait_s: float = 15.0,
    reporter: OperationReporter = NULL_REPORTER,
) -> None:
    """Poll `2E FD 11 0E` in session `10 60` until the timer reports `6E FD 11 00 00 00`."""
    deadline = time.monotonic() + max_wait_s
    logged = False
    while time.monotonic() < deadline:
        reporter.check_cancelled()
        try:
            st = link.request_uds(b"\x2e\xfd\x11\x0e", 0x6E, timeout=2.0)
        except Exception:
            break
        if len(st) >= 6 and st[3] == 0x00:
            return
        if not logged:
            logged = True
            reporter.can_log(
                tr(
                    "Ожидание готовности таймера FD11 (2E FD11 0E → 00 00 00)…",
                    "Waiting for FD11 timer readiness (2E FD11 0E → 00 00 00)…",
                )
            )
        time.sleep(0.5)


def _sleep_cancelable(seconds: float, reporter: OperationReporter = NULL_REPORTER) -> None:
    end = time.monotonic() + max(0.0, float(seconds))
    while time.monotonic() < end:
        reporter.check_cancelled()
        time.sleep(min(0.1, max(0.01, end - time.monotonic())))


def kombi_clear_sa1_delay_timer(
    link: FpkeCanLink,
    *,
    reset_delta: int = KOMBI_SA1_LOCKOUT_RESET_DELTA,
    s3_wait_s: float = 5.5,
    ecu_reset_wait_s: float = 2.0,
    allow_session_reset: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Reset the UDS 0x27 delay timer (`7F 27 37`) on V850E2 Kombi VDD (`+0x62EF` in `0x00180B5C` / `0x001A0584`)."""
    reset_payload = (int(reset_delta) & 0xFFFFFFFF).to_bytes(4, "big")
    reporter.can_log(
        tr(
            f"Сброс таймера задержки 0x27 (7F 27 37) штатной командой 27 04 {reset_payload.hex().upper()}…",
            f"Resetting 0x27 delay timer (7F 27 37) via built-in 27 04 {reset_payload.hex().upper()}…",
        )
    )
    try:
        link.request_uds(b"\x27\x04" + reset_payload, 0x67, timeout=2.0)
        return {"cleared": True, "stage": "direct", "needs_restage": False}
    except UdsNegativeResponse as exc:
        if not allow_session_reset or exc.sid != 0x27 or exc.nrc not in (0x24, 0x35, 0x36, 0x37):
            raise

    if s3_wait_s > 0:
        reporter.can_log(
            tr(
                f"Ожидание S3-таймаута ({s3_wait_s:.1f} с) для обнуления seed и сброса таймера 0x27…",
                f"Waiting for S3 timeout ({s3_wait_s:.1f} s) to zero seed and reset 0x27 timer…",
            )
        )
        _sleep_cancelable(s3_wait_s, reporter=reporter)
    try:
        link.request_uds(b"\x10\x4f", 0x50, timeout=2.0)
        link.request_uds(b"\x27\x04" + reset_payload, 0x67, timeout=2.0)
        return {"cleared": True, "stage": "s3_timeout", "needs_restage": True}
    except UdsNegativeResponse as exc:
        if exc.sid != 0x27 or exc.nrc not in (0x24, 0x35, 0x36, 0x37):
            raise

    reporter.can_log(
        tr(
            "Мягкий перезапуск 11 02 для обнуления seed и сброса таймера 0x27…",
            "Warm reset 11 02 to zero seed and reset 0x27 timer…",
        )
    )
    link.request_uds(b"\x11\x02", 0x51, timeout=2.5)
    if ecu_reset_wait_s > 0:
        _sleep_cancelable(ecu_reset_wait_s, reporter=reporter)
    link.request_uds(b"\x10\x4f", 0x50, timeout=2.5)
    link.request_uds(b"\x27\x04" + reset_payload, 0x67, timeout=2.0)
    return {"cleared": True, "stage": "ecu_reset_1102", "needs_restage": True}


def kombi_extract_sl7_key(
    link: FpkeCanLink,
    *,
    s3_wait_s: float = 5.5,
    ecu_reset_wait_s: float = 2.0,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, dict[str, Any]]:
    """Read the 16-byte `FD11 Supplier Level 7` record from the NvM staging buffer (`0xFEDD5530` on `0310`, `0xFEDD2480` on `2220`)."""
    prof = _get_link_kombi_profile(link)
    sa1_delta = int(prof["sa1_delta"])
    reset_delta = int(prof.get("sa1_lockout_reset_delta", KOMBI_SA1_LOCKOUT_RESET_DELTA))
    staging_addr = int(prof["ram_staging_addr"])
    sl7_key_addr = int(prof["ram_sl7_key_addr"])
    timer_reset_info: dict[str, Any] | None = None

    def _stage_eel63() -> None:
        t16 = bytes(range(16))
        t8 = bytes(range(0x10, 0x18))
        reporter.can_log(
            tr(
                f"Подгрузка EEL 0x0063 в буфер 0x{staging_addr:08X} (10 60 → 2E FD11 03/04)…",
                f"Staging EEL 0x0063 into 0x{staging_addr:08X} buffer (10 60 → 2E FD11 03/04)…",
            )
        )
        link.request_uds(b"\x10\x60", 0x50, timeout=2.0)
        _wait_fd11_timer_ready(link, reporter=reporter)
        with contextlib.suppress(UdsNegativeResponse, Exception):
            ch = link.request_uds(b"\x2e\xfd\x11\x03" + t16 + t8 + bytes([KOMBI_REQUIRED_SL]), 0x6E, timeout=2.5)
            if len(ch) == 26 and ch[:3] == b"\x6e\xfd\x11":
                link._kombi_fd11_id_15b = bytes(ch[11:26])
        with contextlib.suppress(UdsNegativeResponse, Exception):
            link.request_uds(b"\x2e\xfd\x11\x04" + bytes(32), 0x6E, timeout=2.5)

    def _unlock_sa1(*, allow_session_reset: bool = True, clear_delay_timer: bool = True) -> bool:
        nonlocal timer_reset_info
        link.request_uds(b"\x10\x4f", 0x50, timeout=2.0)
        needs_restage = False
        try:
            seed_resp = link.request_uds(b"\x27\x03", 0x67, timeout=2.0)
        except UdsNegativeResponse as exc:
            if not clear_delay_timer or exc.sid != 0x27 or exc.nrc not in (0x36, 0x37):
                raise
            try:
                timer_reset_info = kombi_clear_sa1_delay_timer(
                    link,
                    reset_delta=reset_delta,
                    s3_wait_s=s3_wait_s,
                    ecu_reset_wait_s=ecu_reset_wait_s,
                    allow_session_reset=allow_session_reset,
                    reporter=reporter,
                )
                needs_restage = bool(timer_reset_info.get("needs_restage"))
                seed_resp = link.request_uds(b"\x27\x03", 0x67, timeout=2.0)
            except Exception:
                raise exc from None
        if len(seed_resp) != 6:
            raise RuntimeError(f"Unexpected SecurityAccess 27 03 response: {seed_resp.hex()}")
        seed_int = int.from_bytes(seed_resp[2:6], "big")
        if seed_int != 0:
            sa1_key = ((seed_int + sa1_delta) & 0xFFFFFFFF).to_bytes(4, "big")
            link.request_uds(b"\x27\x04" + sa1_key, 0x67, timeout=2.0)
        return needs_restage

    def _unlock_sa1_and_read_20(
        *,
        allow_session_reset: bool = True,
        restage_on_reset: bool = False,
        clear_delay_timer: bool = True,
    ) -> tuple[bytes, int, int]:
        needs_restage = _unlock_sa1(
            allow_session_reset=allow_session_reset,
            clear_delay_timer=clear_delay_timer,
        )
        if needs_restage and restage_on_reset:
            _stage_eel63()
            _unlock_sa1(allow_session_reset=False, clear_delay_timer=False)
        staged_20 = fpke_read_memory_0x23(link, sl7_key_addr, 20, timeout=2.0)
        k16 = bytes(staged_20[:16])
        c_stored = int.from_bytes(staged_20[16:20], "little")
        c_calc = zlib.crc32(k16) & 0xFFFFFFFF
        return k16, c_stored, c_calc

    # On SW 2220 (8V0 920 860 E), check 0xFEDD2480 in 10 4F + SA1 first in case EEL 0x0063 is already staged in RAM
    if prof["sw_profile"] == "2220":
        try:
            k16_pre, c_st_pre, c_ca_pre = _unlock_sa1_and_read_20(
                allow_session_reset=False,
                restage_on_reset=False,
                clear_delay_timer=False,
            )
            if c_st_pre == c_ca_pre and k16_pre not in (b"\xff" * 16, b"\x00" * 16):
                meta_pre: dict[str, Any] = {
                    "staging_addr": f"0x{sl7_key_addr:08X}",
                    "key_hex": k16_pre.hex(),
                    "crc32_le": f"0x{c_st_pre:08X}",
                    "crc32_valid": True,
                }
                if timer_reset_info is not None:
                    meta_pre["sa1_delay_timer_reset"] = timer_reset_info
                return k16_pre, meta_pre
        except OperationCancelledError:
            raise
        except Exception:
            pass

    _stage_eel63()

    reporter.can_log(
        tr(
            f"Переход в 10 4F + SA1 (27 03/04, +0x{sa1_delta:04X}) и чтение записи SL 7 из 0x{sl7_key_addr:08X}…",
            f"Entering 10 4F + SA1 (27 03/04, +0x{sa1_delta:04X}) and reading SL 7 record from 0x{sl7_key_addr:08X}…",
        )
    )
    key_16b, crc_stored, crc_calc = _unlock_sa1_and_read_20(allow_session_reset=True, restage_on_reset=True)
    if crc_stored != crc_calc or key_16b in (b"\xff" * 16, b"\x00" * 16):
        raise RuntimeError(
            tr(
                f"Не удалось извлечь валидный ключ FD11 Level 7 из 0x{sl7_key_addr:08X}: "
                f"CRC32=0x{crc_stored:08X} (ожидался 0x{crc_calc:08X}).",
                f"Failed to extract a valid FD11 Level 7 key from 0x{sl7_key_addr:08X}: "
                f"CRC32=0x{crc_stored:08X} (expected 0x{crc_calc:08X}).",
            )
        )
    meta: dict[str, Any] = {
        "staging_addr": f"0x{sl7_key_addr:08X}",
        "key_hex": key_16b.hex(),
        "crc32_le": f"0x{crc_stored:08X}",
        "crc32_valid": True,
    }
    if timer_reset_info is not None:
        meta["sa1_delay_timer_reset"] = timer_reset_info
    return key_16b, meta


def kombi_authenticate_fd11(
    link: FpkeCanLink,
    key_16b: bytes,
    *,
    level: int = KOMBI_REQUIRED_SL,
    expected_id_hex: str | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> str:
    """Authenticate `FD11 Supplier Level` (`6` or `7`) via `10 60 -> 2E FD11 0E -> 2E FD11 03 / 04 / 01`."""
    if len(key_16b) != 16:
        raise ValueError("FD11 key must contain exactly 16 bytes")
    if level not in (6, 7):
        raise ValueError(f"Unsupported FD11 supplier level: {level} (expected 6 or 7)")
    t16 = bytes(range(16))
    t8 = bytes(range(0x10, 0x18))
    link.request_uds(b"\x10\x60", 0x50, timeout=3.0)
    _wait_fd11_timer_ready(link, reporter=reporter)
    challenge = link.request_uds(b"\x2e\xfd\x11\x03" + t16 + t8 + bytes([level]), 0x6E, timeout=3.0)
    if len(challenge) != 26 or challenge[:3] != b"\x6e\xfd\x11":
        raise RuntimeError(f"Unexpected FD11 challenge response: {challenge.hex()}")
    id_15b = bytes(challenge[11:26])
    identifier = id_15b.hex()
    if expected_id_hex is not None and identifier.lower() != expected_id_hex.lower():
        raise RuntimeError(f"FD11 challenge identifier mismatch: {identifier} != {expected_id_hex}")
    proof = build_fd11_proof(challenge, key_16b, t16=t16, t8=t8)
    resp04 = link.request_uds(b"\x2e\xfd\x11\x04" + proof, 0x6E, timeout=3.0)
    if resp04 != b"\x6e\xfd\x11":
        raise RuntimeError(f"FD11 04 rejected: {resp04.hex()}")
    resp01 = link.request_uds(b"\x2e\xfd\x11\x01", 0x6E, timeout=2.0)
    if len(resp01) < 4 or resp01[:3] != b"\x6e\xfd\x11" or resp01[3] != level:
        raise RuntimeError(f"FD11 level verification failed: got {resp01.hex()}, expected 6efd11{level:02x}")
    link.level8_active = level >= KOMBI_REQUIRED_SL
    link._kombi_fd11_id_15b = id_15b
    link._kombi_sl7_key = key_16b if level == 7 else getattr(link, "_kombi_sl7_key", None)
    reporter.can_log(
        tr(
            f"Авторизация FD11 Supplier Level {level} подтверждена (6E FD 11 {level:02X}, ID={identifier})",
            f"FD11 Supplier Level {level} authentication confirmed (6E FD 11 {level:02X}, ID={identifier})",
        )
    )
    return identifier


def _normalize_sl7_key_bytes(sl7_key: bytes | str | None) -> bytes | None:
    if sl7_key is None:
        return None
    if isinstance(sl7_key, (bytes, bytearray, memoryview)):
        raw = bytes(sl7_key)
    else:
        cleaned = "".join(str(sl7_key).split()).replace("0x", "").replace("0X", "")
        if len(cleaned) != 32:
            return None
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError:
            return None
    if len(raw) != 16 or raw in (b"\x00" * 16, b"\xff" * 16):
        return None
    return raw


def _extract_sl7_key_from_dflash(dflash_bytes: bytes | None) -> tuple[bytes | None, str | None]:
    if not dflash_bytes:
        return None, None
    with contextlib.suppress(Exception):
        info = analyze_kombi_dflash(dflash_bytes)
        fd11_id = str(info.get("fd11_identifier") or "").strip().lower() or None
        for item in info.get("items", []):
            if item.get("key_id") == "fd11_l7" and item.get("crc_valid", True):
                raw = _normalize_sl7_key_bytes(item.get("hex"))
                if raw is not None:
                    return raw, fd11_id
    return None, None


def _find_saved_kombi_sl7_key_for_fd11_id(fd11_id_hex: str) -> tuple[bytes, str] | None:
    """Search saved `ContiTool` Kombi session reports for a previously extracted 16-byte `FD11 SL 7` key matching `fd11_id_hex`."""
    want = "".join(fd11_id_hex.split()).lower()
    if len(want) != 30:
        return None
    roots: list[Path] = []
    seen_roots: set[Path] = set()
    try:
        from contitool.storage import runs_root

        cand_roots = [
            runs_root(),
            Path.home() / "Documents" / "ContiTool" / "contitool_runs",
            Path.cwd() / "contitool_runs",
        ]
    except Exception:
        cand_roots = [Path.home() / "Documents" / "ContiTool" / "contitool_runs", Path.cwd() / "contitool_runs"]
    for root in cand_roots:
        with contextlib.suppress(OSError):
            if root.is_dir():
                res = root.resolve()
                if res not in seen_roots:
                    seen_roots.add(res)
                    roots.append(res)

    report_files: list[Path] = []
    for root in roots:
        for pat in ("**/kombi_report.json", "**/kombi_write_report.json"):
            with contextlib.suppress(OSError):
                report_files.extend(root.glob(pat))
    report_files.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0.0, reverse=True)

    for rep_path in report_files[:64]:
        with contextlib.suppress(Exception):
            doc = json.loads(rep_path.read_text(encoding="utf-8"))
            acc = doc.get("access") if isinstance(doc, dict) else None
            sec = doc.get("secrets") if isinstance(doc, dict) else None
            rep_ids = {
                str((acc or {}).get("fd11_identifier") or "").strip().lower(),
                str((sec or {}).get("fd11_identifier") or "").strip().lower(),
            }
            if want not in rep_ids:
                continue
            for cand_hex in (
                (acc or {}).get("key_hex"),
                (acc or {}).get("sl7_key_hex"),
            ):
                raw = _normalize_sl7_key_bytes(cand_hex)
                if raw is not None:
                    return raw, str(rep_path)
            for item in (sec or {}).get("items", []):
                if isinstance(item, dict) and item.get("key_id") == "fd11_l7":
                    raw = _normalize_sl7_key_bytes(item.get("hex"))
                    if raw is not None:
                        return raw, str(rep_path)
    return None


def _authenticate_fd11_from_saved_sessions(
    link: FpkeCanLink,
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[str, bytes, str] | None:
    """Probe the cluster's 15-byte `FD11 ID` via `10 60 -> 2E FD 11 03` (no `0x27`) and authenticate with a saved `SL 7` key if present."""
    t16 = bytes(range(16))
    t8 = bytes(range(0x10, 0x18))
    link.request_uds(b"\x10\x60", 0x50, timeout=3.0)
    _wait_fd11_timer_ready(link, reporter=reporter)
    challenge = link.request_uds(b"\x2e\xfd\x11\x03" + t16 + t8 + bytes([KOMBI_REQUIRED_SL]), 0x6E, timeout=3.0)
    if len(challenge) != 26 or challenge[:3] != b"\x6e\xfd\x11":
        return None
    id_15b = bytes(challenge[11:26])
    identifier = id_15b.hex()
    found = _find_saved_kombi_sl7_key_for_fd11_id(identifier)
    if found is None:
        return None
    key_16b, src_path = found
    proof = build_fd11_proof(challenge, key_16b, t16=t16, t8=t8)
    resp04 = link.request_uds(b"\x2e\xfd\x11\x04" + proof, 0x6E, timeout=3.0)
    if resp04 != b"\x6e\xfd\x11":
        return None
    resp01 = link.request_uds(b"\x2e\xfd\x11\x01", 0x6E, timeout=2.0)
    if len(resp01) < 4 or resp01[:3] != b"\x6e\xfd\x11" or resp01[3] != KOMBI_REQUIRED_SL:
        return None
    link.level8_active = True
    link._kombi_fd11_id_15b = id_15b
    link._kombi_sl7_key = key_16b
    return identifier, key_16b, src_path


def kombi_ensure_sl7(
    link: FpkeCanLink,
    *,
    sl7_key: bytes | str | None = None,
    expected_fd11_id: str | None = None,
    wake_seconds: float = 1.5,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Ensure `FD11 Supplier Level 7` (`SL 7`) is active on `link`, using a known SL 7 key directly or extracting via NvM staging RAM."""
    if not link.via_gateway:
        link.start_keepalive()
    if kombi_check_sl7(link):
        prof = _get_link_kombi_profile(link)
        sl7_addr = int(prof["ram_sl7_key_addr"])
        method_name = f"fd11_sl7_staging_0x{sl7_addr:08x}"
        cached_key = getattr(link, "_kombi_sl7_key", None)
        cached_id = getattr(link, "_kombi_fd11_id_15b", None)
        reporter.info(
            tr(
                "Доступ FD11 Supplier Level 7 (SL 7) уже активен в открытой сессии",
                "FD11 Supplier Level 7 (SL 7) is already active in the open session",
            )
        )
        return {
            "method": method_name,
            "supplier_level": KOMBI_REQUIRED_SL,
            "reused_session": True,
            "fd11_identifier": cached_id.hex() if isinstance(cached_id, bytes) else None,
            "sl7_key_hex": cached_key.hex() if isinstance(cached_key, bytes) else None,
        }

    if wake_seconds > 0 and not link.via_gateway:
        end_w = time.monotonic() + min(wake_seconds, 2.0)
        while time.monotonic() < end_w:
            reporter.check_cancelled()
            time.sleep(min(0.1, max(0.01, end_w - time.monotonic())))

    prof = _get_link_kombi_profile(link)
    sl7_addr = int(prof["ram_sl7_key_addr"])
    method_name = f"fd11_sl7_staging_0x{sl7_addr:08x}"

    t0 = time.monotonic()
    # Direct FD11 SL 7 auth (bypasses UDS 0x27 and any 7F 27 37 lockout timer) when caller/session already knows the SL 7 key
    known_key = _normalize_sl7_key_bytes(sl7_key) or _normalize_sl7_key_bytes(getattr(link, "_kombi_sl7_key", None))
    if known_key is not None:
        with contextlib.suppress(Exception):
            fd11_id = kombi_authenticate_fd11(
                link,
                known_key,
                level=KOMBI_REQUIRED_SL,
                expected_id_hex=expected_fd11_id,
                reporter=reporter,
            )
            elapsed = round(time.monotonic() - t0, 3)
            reporter.info(
                tr(
                    f"Доступ FD11 Supplier Level 7 (SL 7) открыт напрямую по известному ключу FD11 за {elapsed:.2f} с (без 0x27)",
                    f"FD11 Supplier Level 7 (SL 7) unlocked directly with known FD11 key in {elapsed:.2f} s (bypassing 0x27)",
                )
            )
            return {
                "method": "fd11_sl7_known_key",
                "supplier_level": KOMBI_REQUIRED_SL,
                "reused_session": False,
                "elapsed_s": elapsed,
                "fd11_identifier": fd11_id,
                "key_hex": known_key.hex(),
                "sl7_key_hex": known_key.hex(),
                "crc32_valid": True,
            }

    try:
        extracted_key, key_meta = kombi_extract_sl7_key(link, reporter=reporter)
    except UdsNegativeResponse as exc:
        if exc.sid == 0x27 and exc.nrc in (0x36, 0x37):
            saved = None
            with contextlib.suppress(Exception):
                saved = _authenticate_fd11_from_saved_sessions(link, reporter=reporter)
            if saved is not None:
                fd11_id, saved_key, src_path = saved
                elapsed = round(time.monotonic() - t0, 3)
                reporter.info(
                    tr(
                        f"Таймер SecurityAccess (7F 27 {exc.nrc:02X}) обойдён: доступ FD11 SL 7 открыт по сохранённому ключу для ID {fd11_id} за {elapsed:.2f} с.",
                        f"Bypassed SecurityAccess lockout (7F 27 {exc.nrc:02X}): unlocked FD11 SL 7 using saved key for ID {fd11_id} in {elapsed:.2f} s.",
                    )
                )
                return {
                    "method": "fd11_sl7_saved_cache",
                    "supplier_level": KOMBI_REQUIRED_SL,
                    "reused_session": False,
                    "elapsed_s": elapsed,
                    "fd11_identifier": fd11_id,
                    "key_hex": saved_key.hex(),
                    "sl7_key_hex": saved_key.hex(),
                    "saved_key_source": src_path,
                    "crc32_valid": True,
                }
            raise RuntimeError(
                tr(
                    f"Блок временно заблокировал SecurityAccess (7F 27 {exc.nrc:02X} — таймер задержки 10 мин после неверных попыток 27 04). "
                    "Оставьте приборку с включённым зажиганием (KL15) на 10 минут без снятия питания, либо откройте ранее считанный дамп этой приборки "
                    "из «Недавних блоков» — тогда ContiTool войдёт в SL 7 напрямую по ключу FD11 без 0x27.",
                    f"Cluster SecurityAccess is locked by delay timer (7F 27 {exc.nrc:02X} — 10 min lockout after invalid 27 04 attempts). "
                    "Leave the cluster powered with ignition (KL15) ON for 10 minutes, or open a previously saved dump of this cluster from "
                    "Recent units — ContiTool will unlock SL 7 directly with the FD11 key without 0x27.",
                )
            ) from exc
        raise

    fd11_id = kombi_authenticate_fd11(link, extracted_key, level=KOMBI_REQUIRED_SL, reporter=reporter)
    elapsed = round(time.monotonic() - t0, 3)
    reporter.info(
        tr(
            f"Доступ FD11 Supplier Level 7 (SL 7) получен за {elapsed:.2f} с",
            f"FD11 Supplier Level 7 (SL 7) established in {elapsed:.2f} s",
        )
    )
    return {
        "method": method_name,
        "supplier_level": KOMBI_REQUIRED_SL,
        "reused_session": False,
        "elapsed_s": elapsed,
        "fd11_identifier": fd11_id,
        **key_meta,
    }


def can_kombi_run_sl7_action(
    port: str,
    action: Any,
    *,
    interface: str = "slcan",
    via_gateway: bool = False,
    gateway_bridge: bool = False,  # noqa: ARG001 - Kombi SL 7 uses standard 11-bit UDS (no 29-bit RAM bridge needed)
    gateway_channel: int = 0,  # noqa: ARG001
    keep_open: bool = True,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> Any:
    """Run a Kombi callback `action(link)` or `action(link, reporter)` in an open session."""
    accepts_reporter = False
    try:
        sig = inspect.signature(action)
        pos_params = [
            p
            for p in sig.parameters.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in sig.parameters.values())
        accepts_reporter = has_varargs or len(pos_params) >= 2
    except (TypeError, ValueError):
        accepts_reporter = False

    with _managed_kombi_session(
        port,
        interface=interface,
        bus=bus,
        keep_open=keep_open and not via_gateway,
        via_gateway=via_gateway,
    ) as link:
        if accepts_reporter:
            return action(link, reporter)
        return action(link)


# ────────────────────────────── Full EEL DataFlash Reader & Writer ──────────────────────────────


def kombi_read_raw_physical_dflash_in_session(
    link: FpkeCanLink,
    *,
    state_out: dict[str, Any] | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, dict[int, bytes]]:
    """Read the full `32 KiB` (`32,768` B) raw physical DataFlash (`0x02000000..0x02007FFF`, `RD_tbl0[5]`) and full
    direct `EEL 0x0063` / `EEL 0x0064` (`RD_tbl0[12]`) under `kombi_temporary_immo_mode0(link)`.
    """
    prof = _get_link_kombi_profile(link)
    eel_ids = prof["eel_ids"]
    direct_eel: dict[int, bytes] = {}
    phys_data = bytearray()
    with kombi_temporary_immo_mode0(link, reporter=reporter) as mode0_state:
        if state_out is not None:
            state_out.update(mode0_state)
        # 1. Read full EEL 0x0063 and EEL 0x0064 directly via 0xEF006300 / 0xEF006400 (RD_tbl0[12])
        for eid in (0x0063, 0x0064):
            reporter.check_cancelled()
            esz = eel_ids[eid]
            vaddr0 = KOMBI_EEL_VIRTUAL_BASE | (eid << 8) | 0x00
            try:
                raw_rec = _read_chunked_0x23(link, vaddr0, esz, chunk_size=128)
            except Exception:
                vaddr2 = KOMBI_EEL_VIRTUAL_BASE | (eid << 8) | 0x02
                payload = _read_chunked_0x23(link, vaddr2, esz - 2, chunk_size=128)
                raw_rec = struct.pack("<H", esz) + payload
            if len(raw_rec) == esz:
                direct_eel[eid] = struct.pack("<H", esz) + raw_rec[2:]

        # 2. Restore 0xEF00684B in DataFlash before reading 0x02000000..0x02007FFF (without reloading RAM yet)
        if mode0_state.get("switched") and not mode0_state.get("eel68_written"):
            restore_val = int(mode0_state.get("restore_mode", 0x01)) & 0xFF
            fpke_write_memory_0x3d(link, KOMBI_EEL_IMMO_MODE_VADDR, bytes([restore_val]), timeout=4.0)
            mode0_state["eel68_written"] = True
            if state_out is not None:
                state_out.update(mode0_state)

        # 3. Read all 32,768 bytes of physical DataFlash (0x02000000..0x02007FFF, RD_tbl0[5]) in 500-byte chunks
        chunks = partition_chunks(KOMBI_DFLASH_POOL_SIZE, 500)
        reporter.reset_stage_timer()
        for idx, sz in enumerate(chunks):
            reporter.check_cancelled()
            addr = KOMBI_DFLASH_BASE_ADDR + idx * 500
            phys_data.extend(fpke_read_memory_0x23(link, addr, sz, timeout=3.0))
            reporter.progress(
                len(phys_data),
                KOMBI_DFLASH_POOL_SIZE,
                unit="B",
                detail=f"Physical DataFlash @ 0x{addr:08X}",
            )
            if idx % 24 == 0 and idx > 0:
                with contextlib.suppress(Exception):
                    link.request_uds(b"\x3e\x00", 0x7E, timeout=1.0)

    return bytes(phys_data), direct_eel


def kombi_read_all_eel_in_session(
    link: FpkeCanLink,
    *,
    read_physical_dflash: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, bytes, dict[str, Any]]:
    """Read all EEL DataFlash records (`132` records / `9,533` B on `0310`, `130` records / `8,334` B on `2220`) at `SL 7`.

    Returns `(dflash_64k_eel_t01, eel_logical_bytes, meta)`.
    """
    if not kombi_check_sl7(link):
        kombi_ensure_sl7(link, wake_seconds=0.5, reporter=reporter)

    prof = _get_link_kombi_profile(link)
    eel_ids: dict[int, int] = dict(prof["eel_ids"])
    n_blocks = len(eel_ids)
    logical_total = int(prof["eel_logical_size"])
    staging_addr = int(prof["ram_staging_addr"])
    phys_table_addr = int(prof["ram_eel_phys_table_addr"])

    reporter.reset_stage_timer()
    reporter.progress(0, logical_total, unit="B", detail=f"EEL DataFlash ({n_blocks} blocks)")

    # 1. Reconstruct EEL 0x0063 (126 B) and EEL 0x0064 (146 B on 0310 / 42 B on 2220) via staging RAM
    eel_0063 = bytearray(b"\xff" * eel_ids[0x0063])
    eel_0064 = bytearray(b"\xff" * eel_ids[0x0064])
    struct.pack_into("<H", eel_0063, 0, eel_ids[0x0063])
    struct.pack_into("<H", eel_0064, 0, eel_ids[0x0064])

    subblocks_meta: dict[str, Any] = {}
    id_15b = getattr(link, "_kombi_fd11_id_15b", None)
    if not isinstance(id_15b, bytes) or len(id_15b) != 15:
        sl7_key = getattr(link, "_kombi_sl7_key", None)
        if isinstance(sl7_key, bytes) and len(sl7_key) == 16:
            kombi_authenticate_fd11(link, sl7_key, level=KOMBI_REQUIRED_SL, reporter=reporter)
            id_15b = getattr(link, "_kombi_fd11_id_15b", None)
        else:
            with contextlib.suppress(UdsNegativeResponse, Exception):
                link.request_uds(b"\x2e\xfd\x11\x08\x00", 0x6E, timeout=1.5)
            raw_id20 = fpke_read_memory_0x23(link, staging_addr, 20, timeout=2.0)
            id_15b = bytes(raw_id20[:15])
            link._kombi_fd11_id_15b = id_15b

    id_payload_16 = bytes(id_15b) + b"\xff"
    id_crc32 = zlib.crc32(id_payload_16) & 0xFFFFFFFF
    id_raw_20 = id_payload_16 + struct.pack("<I", id_crc32)
    eel_0063[0x02:0x16] = id_raw_20
    subblocks_meta["0x006302_fd11_id"] = {
        "eel_id": "0x0063",
        "offset": "0x02",
        "size": 20,
        "payload_hex": id_payload_16.hex(),
        "crc32_le": f"0x{id_crc32:08X}",
        "crc32_ok": True,
    }

    for name, cmd, sz, eid, eoff in KOMBI_FD11_STAGED_SUBBLOCKS:
        reporter.check_cancelled()
        with contextlib.suppress(UdsNegativeResponse, Exception):
            link.request_uds(cmd, 0x6E, timeout=2.0)
        staged = fpke_read_memory_0x23(link, staging_addr, sz, timeout=2.0)
        payload = staged[:-4]
        crc_stored = int.from_bytes(staged[-4:], "little")
        crc_calc = zlib.crc32(payload) & 0xFFFFFFFF
        subblocks_meta[name] = {
            "cmd": cmd.hex(),
            "eel_id": f"0x{eid:04X}",
            "offset": f"0x{eoff:02X}",
            "size": sz,
            "payload_hex": payload.hex(),
            "crc32_le": f"0x{crc_stored:08X}",
            "crc32_ok": crc_stored == crc_calc,
        }
        if eid == 0x0063:
            eel_0063[eoff : eoff + sz] = staged
        elif eid == 0x0064 and eoff + sz <= len(eel_0064):
            eel_0064[eoff : eoff + sz] = staged

    if eel_ids[0x0064] > 0x2A:
        tail_sz = eel_ids[0x0064] - 0x2A
        tail_64 = _read_chunked_0x23(link, KOMBI_EEL_VIRTUAL_BASE | (0x0064 << 8) | 0x2A, tail_sz, chunk_size=tail_sz)
        eel_0064[0x2A : 0x2A + tail_sz] = tail_64

    # 2. Read live EEL physical word-offset table in RAM (n_blocks x 2 bytes)
    phys_word_offsets: tuple[int, ...] = (0,) * n_blocks
    phys_tbl_bytes = n_blocks * 2
    with contextlib.suppress(Exception):
        idx_raw = _read_chunked_0x23(link, phys_table_addr, phys_tbl_bytes, chunk_size=132)
        if len(idx_raw) == phys_tbl_bytes:
            phys_word_offsets = struct.unpack(f"<{n_blocks}H", idx_raw)

    # 3. Read all EEL records (1..132 on 0310, 1..130 on 2220)
    records: dict[int, bytes] = {}
    logical_concat = bytearray()
    phys_map: dict[str, dict[str, Any]] = {}
    bytes_done = 0

    for idx, (eel_id, eel_size) in enumerate(sorted(eel_ids.items())):
        reporter.check_cancelled()
        w_off = phys_word_offsets[idx] if idx < len(phys_word_offsets) else 0
        phys_addr = (KOMBI_DFLASH_BASE_ADDR + w_off * 4) if w_off != 0 else None
        phys_map[f"0x{eel_id:04X}"] = {
            "size": eel_size,
            "word_offset": f"0x{w_off:04X}",
            "phys_addr": f"0x{phys_addr:08X}" if phys_addr else None,
        }

        if eel_id == 0x0063:
            raw_rec = bytes(eel_0063)
        elif eel_id == 0x0064:
            raw_rec = bytes(eel_0064)
        else:
            vaddr0 = KOMBI_EEL_VIRTUAL_BASE | (eel_id << 8) | 0x00
            try:
                raw_rec = _read_chunked_0x23(link, vaddr0, eel_size, chunk_size=128)
            except Exception:
                vaddr2 = KOMBI_EEL_VIRTUAL_BASE | (eel_id << 8) | 0x02
                try:
                    payload = _read_chunked_0x23(link, vaddr2, eel_size - 2, chunk_size=128)
                    raw_rec = struct.pack("<H", eel_size) + payload
                except Exception:
                    if eel_id not in KOMBI_NVM_STAGED_EEL_MAP:
                        raise
                    # On SW 2220 (when immo_mode != 0), RD_tbl0[12..13] blocks direct 0xEF006500..0xEF006FFF reads at SL 7;
                    # reload NvM block 0x4A..0x54 via 2E FD 3A into the unwiped 0xFEDD2458 staging buffer and read it via 0x23!
                    nvm_blk, nvm_len = KOMBI_NVM_STAGED_EEL_MAP[eel_id]
                    kombi_nvm_reload_block(link, nvm_blk)
                    staged_payload = _read_chunked_0x23(link, staging_addr, nvm_len, chunk_size=128)
                    padded_payload = bytes(staged_payload).ljust(eel_size - 2, b"\xff")[: eel_size - 2]
                    raw_rec = struct.pack("<H", eel_size) + padded_payload

        records[eel_id] = raw_rec
        logical_concat.extend(raw_rec)
        bytes_done += len(raw_rec)
        reporter.progress(bytes_done, logical_total, unit="B", detail=f"EEL 0x{eel_id:04X} ({eel_size} B)")
        if idx % 24 == 0 and idx > 0:
            with contextlib.suppress(Exception):
                link.request_uds(b"\x3e\x00", 0x7E, timeout=1.0)

    physical_dflash_bytes: bytes | None = None
    eel_0063_0064_direct = False
    mode0_switched = False
    if read_physical_dflash:
        r68_cur = records.get(0x0068, b"")
        cur_immo_mode = r68_cur[0x4B] if len(r68_cur) > 0x4B else 0x01
        unlock_method = prof.get("immo_mode0_unlock_method", "direct_0x3d_ef00684b")
        can_read_phys = (
            bool(prof["can_switch_immo_mode0_at_sl7"]) and unlock_method == "direct_0x3d_ef00684b"
        ) or cur_immo_mode == 0x00
        if can_read_phys:
            phys_mode0_state: dict[str, Any] = {}
            try:
                phys_raw, direct_63_64 = kombi_read_raw_physical_dflash_in_session(
                    link,
                    state_out=phys_mode0_state,
                    reporter=reporter,
                )
                mode0_switched = bool(phys_mode0_state.get("switched"))
                if len(phys_raw) == KOMBI_DFLASH_POOL_SIZE:
                    physical_dflash_bytes = phys_raw
                if direct_63_64:
                    for eid, d_rec in direct_63_64.items():
                        if len(d_rec) == eel_ids[eid]:
                            records[eid] = d_rec
                    eel_0063_0064_direct = True
                    logical_concat = bytearray()
                    for eid in sorted(eel_ids):
                        logical_concat.extend(records[eid])
            except Exception as exc:
                mode0_switched = bool(phys_mode0_state.get("switched"))
                reporter.warning(
                    tr(
                        f"Чтение сырого физического DataFlash 0x02000000..0x02007FFF пропущено ({exc}); используются {n_blocks} бл. EEL.",
                        f"Raw physical DataFlash 0x02000000..0x02007FFF read skipped ({exc}); using {n_blocks} logical EEL blocks.",
                    )
                )
        else:
            reporter.can_log(
                tr(
                    f"ПО {prof['sw_profile']} (immo_mode=0x{cur_immo_mode:02X}): все {n_blocks} блоков EEL (включая 0x0063..0x006F) считаны через SL 7 и буфер 0x{staging_addr:08X}.",
                    f"SW {prof['sw_profile']} (immo_mode=0x{cur_immo_mode:02X}): all {n_blocks} EEL blocks (including 0x0063..0x006F) read via SL 7 and 0x{staging_addr:08X} staging buffer.",
                )
            )

    eel_logical_bytes = bytes(logical_concat)
    dflash_64k = build_kombi_eel_dflash(records, eel_ids=eel_ids)
    meta: dict[str, Any] = {
        "mode": "eel_sl7_0x23_and_phys_32k" if physical_dflash_bytes is not None else "eel_sl7_0x23",
        "protocol": (
            "uds_0x23_ef00xxxx_and_02000000_mode0"
            if physical_dflash_bytes is not None
            else f"uds_0x23_ef00xxxx_and_{staging_addr:08x}"
        ),
        "eel_blocks_read": len(records),
        "eel_0063_0064_direct": eel_0063_0064_direct,
        "logical_size": len(eel_logical_bytes),
        "logical_sha256": hashlib.sha256(eel_logical_bytes).hexdigest(),
        "size": len(dflash_64k),
        "sha256": hashlib.sha256(dflash_64k).hexdigest(),
        "fd11_subblocks": subblocks_meta,
        "eel_phys_offsets": phys_map,
        "flash_writes": bool(mode0_switched),
    }
    if physical_dflash_bytes is not None:
        meta["physical_dflash_bytes"] = physical_dflash_bytes
        meta["physical_source"] = f"0x{KOMBI_DFLASH_BASE_ADDR:08X}..0x{KOMBI_DFLASH_BASE_ADDR + KOMBI_DFLASH_POOL_SIZE - 1:08X}"
        meta["physical_size"] = len(physical_dflash_bytes)
        meta["physical_sha256"] = hashlib.sha256(physical_dflash_bytes).hexdigest()
    return dflash_64k, eel_logical_bytes, meta


def can_kombi_full_read(
    port: str,
    *,
    interface: str = "slcan",
    session_dir: Path | None = None,
    wake_seconds: float = 2.0,
    read_cflash: bool = False,
    read_physical_dflash: bool = False,
    cflash_bytes: bytes | None = None,
    ident: list[dict[str, str]] | None = None,
    keep_open: bool = False,
    via_gateway: bool = False,
    gateway_bridge: bool = False,  # noqa: ARG001 - Kombi SL 7 uses standard 11-bit UDS (no 29-bit RAM bridge needed)
    gateway_channel: int = 0,  # noqa: ARG001
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Complete single-session keyless read of Continental V850E2 `17 Kombi VDD` (`5NA 920 740 B` `SW 0310` / `8V0 920 860 E` `SW 2220`)."""
    from contitool.can.workflows import default_session_dir

    out_dir = session_dir or default_session_dir(None, "kombi_read")
    out_dir.mkdir(parents=True, exist_ok=True)

    dflash_path = out_dir / "Dflash.bin"
    phys_dflash_path = out_dir / "DflashPhysical.bin"
    logical_path = out_dir / "EelLogical.bin"
    report_path = out_dir / "kombi_report.json"
    can_log_path = out_dir / "kombi.can.log"

    total_steps = 3 + int(read_cflash)
    step_no = 1
    started = time.monotonic()

    with _managed_kombi_session(
        port,
        interface=interface,
        log_path=out_dir / "can.jsonl",
        bus=bus,
        keep_open=keep_open and not via_gateway,
        via_gateway=via_gateway,
    ) as link:
        try:
            sup = _check_kombi_link_support(link, ident=ident, reporter=reporter)
            prof = _get_link_kombi_profile(link, ident=ident)
            n_eel = len(prof["eel_ids"])
            reporter.step(
                step_no,
                total_steps,
                tr("Получение доступа FD11 Supplier Level 7 (SL 7)", "Establishing FD11 Supplier Level 7 (SL 7)"),
            )
            sl7_info = kombi_ensure_sl7(link, wake_seconds=wake_seconds, reporter=reporter)
            if not ident:
                sup = _check_kombi_link_support(link, reporter=reporter)
                prof = _get_link_kombi_profile(link)
                n_eel = len(prof["eel_ids"])

            step_no += 1
            reporter.step(
                step_no,
                total_steps,
                tr(
                    f"Чтение {n_eel} блоков EEL DataFlash (SL 7)",
                    f"Reading {n_eel} EEL DataFlash blocks (SL 7)",
                ),
            )
            dflash_bytes, eel_logical_bytes, dflash_meta = kombi_read_all_eel_in_session(
                link,
                read_physical_dflash=read_physical_dflash,
                reporter=reporter,
            )
            phys_raw_bytes = dflash_meta.pop("physical_dflash_bytes", None)
            atomic_write(dflash_path, dflash_bytes)
            atomic_write(logical_path, eel_logical_bytes)
            if isinstance(phys_raw_bytes, (bytes, bytearray)) and len(phys_raw_bytes) == KOMBI_DFLASH_POOL_SIZE:
                atomic_write(phys_dflash_path, bytes(phys_raw_bytes))
                dflash_meta["physical_first_16"] = bytes(phys_raw_bytes[:16]).hex()
                dflash_meta["physical_last_16"] = bytes(phys_raw_bytes[-16:]).hex()
                dflash_meta["physical_output"] = str(phys_dflash_path)

            opt_results: dict[str, Any] = {}
            if read_cflash:
                step_no += 1
                reporter.step(step_no, total_steps, tr("Чтение CodeFlash (3 МБ)", "Reading CodeFlash (3 MB)"))
                cf_data = bytearray()
                chunks = partition_chunks(KOMBI_CFLASH_SIZE, 500)
                reporter.reset_stage_timer()
                for idx, sz in enumerate(chunks):
                    reporter.check_cancelled()
                    addr = KOMBI_CFLASH_ADDR + idx * 500
                    cf_data.extend(fpke_read_memory_0x23(link, addr, sz))
                    reporter.progress(len(cf_data), KOMBI_CFLASH_SIZE, unit="B", detail=f"CodeFlash @ 0x{addr:08X}")
                cflash_bytes = bytes(cf_data)
                cf_path = out_dir / "Cflash.bin"
                atomic_write(cf_path, cflash_bytes)
                opt_results["cflash"] = {
                    "mode": "direct",
                    "protocol": "uds_0x23",
                    "source": f"0x{KOMBI_CFLASH_ADDR:08X}",
                    "size": len(cflash_bytes),
                    "sha256": hashlib.sha256(cflash_bytes).hexdigest(),
                    "output": str(cf_path),
                }

            step_no += 1
            reporter.step(
                step_no,
                total_steps,
                tr("Разбор данных DataFlash Kombi", "Analyzing Kombi DataFlash records"),
            )
            secrets = analyze_kombi_dflash(dflash_bytes, cflash_bytes)
            immo_passport = extract_kombi_immo_passport(dflash_bytes, cflash_bytes)
            immo_passport_path = out_dir / "immo_passport.json"
            atomic_write(
                immo_passport_path,
                (json.dumps(immo_passport, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
            )

            report: dict[str, Any] = {
                "ecu_kind": "kombi",
                "target": prof["target_label"],
                "sw_profile": prof["sw_profile"],
                "officially_supported": bool(sup["verified"]),
                "support_warning": sup["warning"],
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "port": port,
                "interface": interface,
                "via_gateway": bool(via_gateway),
                "gateway_bridged": False,
                "can_only": True,
                "target_keys_used": False,
                "flash_writes": bool(dflash_meta.get("flash_writes", False)),
                "ident": list(ident) if ident else [],
                "access": sl7_info,
                "dflash": {
                    **dflash_meta,
                    "first_16": dflash_bytes[:16].hex(),
                    "last_16": dflash_bytes[-16:].hex(),
                    "output": str(dflash_path),
                    "logical_output": str(logical_path),
                },
                "secrets": secrets,
                **opt_results,
                "wall_s": round(time.monotonic() - started, 3),
                "session_dir": str(out_dir),
                "report_path": str(report_path),
                "immo_passport_path": str(immo_passport_path),
                "can_log": str(can_log_path),
            }
            atomic_write(report_path, (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            reporter.success(
                tr(
                    f"DataFlash Kombi ({n_eel} бл. EEL) считан на SL 7 за {report['wall_s']:.1f} с. Папка: {out_dir}",
                    f"Kombi DataFlash ({n_eel} EEL blocks) read at SL 7 in {report['wall_s']:.1f} s. Folder: {out_dir}",
                )
            )
            return report
        finally:
            link.save_can_log(can_log_path)


def kombi_nvm_reload_block(
    link: FpkeCanLink,
    nvm_block_id: int,
    *,
    retries: int = 5,
    timeout: float = 2.0,
    strict: bool = False,
) -> bool:
    """Reload an NVM block from EEL DataFlash into its RAM mirror via `2E FD 3A <block_id:2BE>` (`op = 3`)."""
    cmd = bytes([0x2E, 0xFD, 0x3A, (nvm_block_id >> 8) & 0xFF, nvm_block_id & 0xFF])
    for attempt in range(max(1, retries)):
        resp = link.request_uds(cmd, 0x6E, timeout=timeout)
        if len(resp) >= 4 and resp[:3] == b"\x6e\xfd\x3a" and resp[3] != 0x00:
            return True
        if attempt + 1 < retries:
            time.sleep(0.05)
    if strict:
        raise RuntimeError(
            tr(
                f"Не удалось перезагрузить блок NvM 0x{nvm_block_id:04X} (2E FD 3A вернул 0x00 после {max(1, retries)} попыток).",
                f"Failed to reload NvM block 0x{nvm_block_id:04X} (2E FD 3A returned 0x00 after {max(1, retries)} attempt(s)).",
            )
        )
    return False


def _poll_ram_immo_mode_zero(
    link: FpkeCanLink,
    *,
    timeout_s: float = 2.5,
) -> int:
    """Poll `ram_immo_mode_addr` until `2E FD 3A 00 4D` reloads `0x00` into RAM."""
    prof = _get_link_kombi_profile(link)
    ram_immo_addr = int(prof["ram_immo_mode_addr"])
    deadline = time.monotonic() + timeout_s
    last_val = -1
    while True:
        try:
            raw = fpke_read_memory_0x23(link, ram_immo_addr, 1, timeout=1.5)
            if raw:
                last_val = raw[0]
                if last_val == 0x00:
                    return 0x00
        except UdsNegativeResponse as exc:
            if exc.nrc != 0x33:
                raise
        except Exception:
            pass
        if time.monotonic() >= deadline:
            return last_val
        time.sleep(0.05)


def _poll_ram_immo_mode_restored(
    link: FpkeCanLink,
    expected: int,
    *,
    timeout_s: float = 2.5,
) -> int:
    """Wait until `2E FD 3A 00 4D` reloads non-zero `immo_mode` into `ram_immo_mode_addr`."""
    exp = expected & 0xFF
    if exp == 0x00:
        return _poll_ram_immo_mode_zero(link, timeout_s=timeout_s)
    prof = _get_link_kombi_profile(link)
    ram_immo_addr = int(prof["ram_immo_mode_addr"])
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            raw = fpke_read_memory_0x23(link, ram_immo_addr, 1, timeout=1.5)
            if raw and raw[0] == exp:
                return exp
        except UdsNegativeResponse as exc:
            if exc.nrc == 0x33:
                return exp
            raise
        except Exception:
            pass
        if time.monotonic() >= deadline:
            return exp
        time.sleep(0.05)


_KOMBI_EEL63_CRC_SUBBLOCKS: tuple[tuple[int, int, str], ...] = (
    (0x02, 20, "FD11 ID (+0x02)"),
    (0x16, 20, "SL 0..6 key (+0x16)"),
    (0x2A, 20, "SL 7 key (+0x2A)"),
    (0x3E, 20, "slot 3 key (+0x3E)"),
    (0x76, 8, "FD11 flags (+0x76)"),
)


def _validate_eel63_subblock_crcs(rec_63: bytes) -> None:
    """Verify CRC-32 checksums on all required `EEL 0x0063` sub-blocks (`+0x02`, `+0x16`, `+0x2A`, `+0x3E`, `+0x76`)."""
    for off, sz, label in _KOMBI_EEL63_CRC_SUBBLOCKS:
        if len(rec_63) < off + sz:
            raise RuntimeError(
                tr(
                    f"Невозможно безопасно выполнить 2E FD E3: запись EEL 0x0063 слишком коротка для {label}.",
                    f"Cannot safely execute 2E FD E3: EEL 0x0063 record is too short for {label}.",
                )
            )
        sub = rec_63[off : off + sz]
        crc_stored = int.from_bytes(sub[-4:], "little")
        crc_calc = zlib.crc32(sub[:-4]) & 0xFFFFFFFF
        if crc_stored != crc_calc:
            raise RuntimeError(
                tr(
                    f"Невозможно безопасно выполнить 2E FD E3: ошибка CRC-32 в подблоке EEL 0x0063 {label} "
                    f"(0x{crc_stored:08X} != 0x{crc_calc:08X}).",
                    f"Cannot safely execute 2E FD E3: CRC-32 mismatch in EEL 0x0063 sub-block {label} "
                    f"(0x{crc_stored:08X} != 0x{crc_calc:08X}).",
                )
            )
    sl7_k16 = rec_63[0x2A:0x3A]
    if sl7_k16 in (b"\xff" * 16, b"\x00" * 16):
        raise RuntimeError(
            tr(
                "Невозможно безопасно выполнить 2E FD E3: ключ SL 7 в резервной копии EEL 0x0063 пуст.",
                "Cannot safely execute 2E FD E3: SL 7 key in backup EEL 0x0063 is empty.",
            )
        )


def _read_fde3_affected_records_in_session(
    link: FpkeCanLink,
    prof: dict[str, Any],
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[int, bytes]:
    """Fast staged read of the 8 EEL records (`0x0063`, `0x0065..0x006B`) affected by `2E FD E3` on SW 2220."""
    eel_ids: dict[int, int] = dict(prof["eel_ids"])
    staging_addr = int(prof["ram_staging_addr"])
    eel_0063 = bytearray(b"\xff" * eel_ids[0x0063])
    struct.pack_into("<H", eel_0063, 0, eel_ids[0x0063])

    id_15b = getattr(link, "_kombi_fd11_id_15b", None)
    if not isinstance(id_15b, bytes) or len(id_15b) != 15:
        sl7_key = getattr(link, "_kombi_sl7_key", None)
        if isinstance(sl7_key, bytes) and len(sl7_key) == 16:
            kombi_authenticate_fd11(link, sl7_key, level=KOMBI_REQUIRED_SL, reporter=reporter)
            id_15b = getattr(link, "_kombi_fd11_id_15b", None)
    if isinstance(id_15b, bytes) and len(id_15b) == 15:
        id_payload_16 = bytes(id_15b) + b"\xff"
        id_crc32 = zlib.crc32(id_payload_16) & 0xFFFFFFFF
        eel_0063[0x02:0x16] = id_payload_16 + struct.pack("<I", id_crc32)
    else:
        link.request_uds(b"\x2e\xfd\x11\x08\x00", 0x6E, timeout=1.5)
        raw_id20 = fpke_read_memory_0x23(link, staging_addr, 20, timeout=2.0)
        id_crc_stored = int.from_bytes(raw_id20[16:20], "little")
        id_crc_calc = zlib.crc32(raw_id20[:16]) & 0xFFFFFFFF
        if id_crc_stored != id_crc_calc:
            raise RuntimeError(
                tr(
                    f"Некорректный CRC-32 в буфере RAM для EEL 0x0063+0x02 (FD11 ID): "
                    f"0x{id_crc_stored:08X} != 0x{id_crc_calc:08X}.",
                    f"Invalid RAM staging CRC-32 for EEL 0x0063+0x02 (FD11 ID): "
                    f"0x{id_crc_stored:08X} != 0x{id_crc_calc:08X}.",
                )
            )
        link._kombi_fd11_id_15b = bytes(raw_id20[:15])
        eel_0063[0x02:0x16] = bytes(raw_id20)

    for _name, cmd, sz, eid, eoff in KOMBI_FD11_STAGED_SUBBLOCKS:
        if eid != 0x0063:
            continue
        reporter.check_cancelled()
        link.request_uds(cmd, 0x6E, timeout=2.0)
        staged = fpke_read_memory_0x23(link, staging_addr, sz, timeout=2.0)
        eel_0063[eoff : eoff + sz] = staged

    _validate_eel63_subblock_crcs(bytes(eel_0063))

    records: dict[int, bytes] = {0x0063: bytes(eel_0063)}
    for afeid in KOMBI_2220_FDE3_AFFECTED_EEL_IDS:
        if afeid == 0x0063:
            continue
        reporter.check_cancelled()
        eel_size = int(eel_ids[afeid])
        vaddr0 = KOMBI_EEL_VIRTUAL_BASE | (afeid << 8) | 0x00
        try:
            raw_rec = _read_chunked_0x23(link, vaddr0, eel_size, chunk_size=128)
        except Exception:
            vaddr2 = KOMBI_EEL_VIRTUAL_BASE | (afeid << 8) | 0x02
            try:
                payload = _read_chunked_0x23(link, vaddr2, eel_size - 2, chunk_size=128)
                raw_rec = struct.pack("<H", eel_size) + payload
            except Exception:
                nvm_blk, nvm_len = KOMBI_NVM_STAGED_EEL_MAP[afeid]
                kombi_nvm_reload_block(link, nvm_blk, strict=True)
                staged_payload = _read_chunked_0x23(link, staging_addr, nvm_len, chunk_size=128)
                padded_payload = bytes(staged_payload).ljust(eel_size - 2, b"\xff")[: eel_size - 2]
                raw_rec = struct.pack("<H", eel_size) + padded_payload
        records[afeid] = raw_rec
    return records


@contextlib.contextmanager
def kombi_temporary_immo_mode0(
    link: FpkeCanLink,
    *,
    restore_mode: int | None = None,
    backup_dflash: bytes | None = None,
    skip_restore_eids: set[int] | frozenset[int] = frozenset(),
    reporter: OperationReporter = NULL_REPORTER,
) -> Iterator[dict[str, Any]]:
    """Temporarily switch `immo_mode` (`EEL 0x0068+0x4B` / RAM mirror) to `0x00` at `SL 7` and restore on exit."""
    prof = _get_link_kombi_profile(link)
    ram_immo_addr = int(prof["ram_immo_mode_addr"])
    staging_addr = int(prof["ram_staging_addr"])
    unlock_method = str(prof.get("immo_mode0_unlock_method", "direct_0x3d_ef00684b"))
    orig_mode: int | None = None
    if unlock_method == "fde3_sl7_restore":
        with contextlib.suppress(Exception):
            raw_ram = fpke_read_memory_0x23(link, ram_immo_addr, 1, timeout=2.0)
            if raw_ram:
                orig_mode = raw_ram[0]
        if orig_mode is None and backup_dflash is not None:
            with contextlib.suppress(Exception):
                lay_init = kombi_eel_layout(backup_dflash)
                r68_init, _ = eel_read_record_any(lay_init, backup_dflash, 0x0068)
                if r68_init is not None and len(r68_init) > 0x4B:
                    orig_mode = r68_init[0x4B]
    if orig_mode is None:
        try:
            orig_raw = fpke_read_memory_0x23(link, KOMBI_EEL_IMMO_MODE_VADDR, 1, timeout=2.0)
            orig_mode = orig_raw[0] if orig_raw else 0x01
        except Exception:
            kombi_nvm_reload_block(link, KOMBI_NVM_BLOCK_IMMO)
            staged_68 = fpke_read_memory_0x23(link, staging_addr, 75, timeout=2.0)
            orig_mode = staged_68[0x49] if len(staged_68) > 0x49 else 0x01

    target_restore = orig_mode if restore_mode is None else (int(restore_mode) & 0xFF)
    pending_fde3_restore: set[int] = set()
    saved_fde3_records: dict[int, bytes] = {}
    state: dict[str, Any] = {
        "orig_mode": orig_mode,
        "restore_mode": target_restore,
        "switched": False,
        "eel68_written": False,
        "pending_fde3_restore": pending_fde3_restore,
    }

    def _restore_fde3_block(afeid: int) -> None:
        rec_orig = saved_fde3_records.get(afeid)
        if rec_orig is None:
            return
        if afeid in KOMBI_NVM_STAGED_EEL_MAP:
            nvm_len = KOMBI_NVM_STAGED_EEL_MAP[afeid][1]
            payload = bytes(rec_orig[2 : 2 + nvm_len])
        else:
            payload = bytes(rec_orig[2:])
        vaddr = KOMBI_EEL_VIRTUAL_BASE | (afeid << 8) | 0x02
        fpke_write_memory_0x3d(link, vaddr, payload, timeout=6.0)
        pending_fde3_restore.discard(afeid)
        if afeid == 0x0065:
            kombi_nvm_reload_block(link, 0x004A)
            fd11_state_addr = int(prof.get("ram_fd11_state_addr") or KOMBI_2220_RAM_FD11_STATE_ADDR)
            if len(rec_orig) >= 14:
                fpke_write_memory_0x3d(link, fd11_state_addr, bytes(rec_orig[2:14]), timeout=3.0)
        elif afeid == 0x0068:
            state["eel68_written"] = True
            cur_ram = _poll_ram_immo_mode_zero(link, timeout_s=1.0)
            if cur_ram != 0x00:
                fpke_write_memory_0x3d(link, ram_immo_addr, b"\x00", timeout=2.0)
        elif afeid in KOMBI_NVM_STAGED_EEL_MAP:
            kombi_nvm_reload_block(link, KOMBI_NVM_STAGED_EEL_MAP[afeid][0])

    if orig_mode != 0x00:
        if not prof["can_switch_immo_mode0_at_sl7"]:
            raise RuntimeError(
                tr(
                    f"На панели {prof['target_label']} при immo_mode=0x{orig_mode:02X} область WR_tbl0[25..29] "
                    "(EEL 0x0060 пробег / 0x0066..0x006E иммо) требует Level 8 или неадаптированный режим (immo_mode=0).",
                    f"On {prof['target_label']} with immo_mode=0x{orig_mode:02X}, WR_tbl0[25..29] "
                    "(EEL 0x0060 odometer / 0x0066..0x006E immo) requires Level 8 or virgin state (immo_mode=0).",
                )
            )
        if unlock_method == "fde3_sl7_restore":
            eel_ids = prof["eel_ids"]
            if backup_dflash is not None:
                lay_b = kombi_eel_layout(backup_dflash)
                raw_affected: dict[int, bytes | None] = {
                    afeid: eel_read_record_any(lay_b, backup_dflash, afeid)[0]
                    for afeid in KOMBI_2220_FDE3_AFFECTED_EEL_IDS
                }
            else:
                raw_affected = _read_fde3_affected_records_in_session(link, prof, reporter=reporter)
            for afeid in KOMBI_2220_FDE3_AFFECTED_EEL_IDS:
                rec_b = raw_affected.get(afeid)
                exp_len = int(eel_ids[afeid])
                if rec_b is None or len(rec_b) != exp_len:
                    raise RuntimeError(
                        tr(
                            f"Невозможно безопасно выполнить 2E FD E3: в резервной копии отсутствует блок EEL 0x{afeid:04X}.",
                            f"Cannot safely execute 2E FD E3: backup is missing EEL block 0x{afeid:04X}.",
                        )
                    )
                if afeid == 0x0068 and len(rec_b) > 0x4B:
                    r68_mut = bytearray(rec_b)
                    r68_mut[0x4B] = target_restore
                    saved_fde3_records[afeid] = bytes(r68_mut)
                else:
                    saved_fde3_records[afeid] = bytes(rec_b)
            _validate_eel63_subblock_crcs(saved_fde3_records[0x0063])

    entered_yield = False
    try:
        if orig_mode != 0x00:
            if unlock_method == "fde3_sl7_restore":
                reporter.can_log(
                    tr(
                        f"Временное открытие WR_tbl0 на SL 7 (ПО 2220): 2E FD E3 (immo_mode 0x{orig_mode:02X} → 0x00) с восстановлением EEL 0x0063/0x0065..0x006B…",
                        f"Temporarily unlocking WR_tbl0 at SL 7 (SW 2220): 2E FD E3 (immo_mode 0x{orig_mode:02X} → 0x00) with immediate EEL 0x0063/0x0065..0x006B restore…",
                    )
                )
                link.request_uds(b"\x2e\xfd\xe3", 0x6E, timeout=12.0)
                state["switched"] = True
                pending_fde3_restore.update(KOMBI_2220_FDE3_AFFECTED_EEL_IDS)
                cur_val = _poll_ram_immo_mode_zero(link, timeout_s=2.5)
                if cur_val != 0x00:
                    raise RuntimeError(
                        tr(
                            f"Не удалось переключить RAM 0x{ram_immo_addr:08X} в 0x00 через 2E FD E3 (ответ: 0x{cur_val & 0xFF:02X}).",
                            f"Failed to switch RAM 0x{ram_immo_addr:08X} to 0x00 via 2E FD E3 (got: 0x{cur_val & 0xFF:02X}).",
                        )
                    )
                for afeid in KOMBI_2220_FDE3_AFFECTED_EEL_IDS:
                    if afeid not in skip_restore_eids:
                        _restore_fde3_block(afeid)
            else:
                reporter.can_log(
                    tr(
                        f"Временное открытие WR_tbl0 на SL 7: 0xEF00684B ← 0x00 + 2E FD 3A 00 4D (immo_mode 0x{orig_mode:02X} → 0x00)…",
                        f"Temporarily unlocking WR_tbl0 at SL 7: 0xEF00684B ← 0x00 + 2E FD 3A 00 4D (immo_mode 0x{orig_mode:02X} → 0x00)…",
                    )
                )
                fpke_write_memory_0x3d(link, KOMBI_EEL_IMMO_MODE_VADDR, b"\x00", timeout=4.0)
                state["switched"] = True
                kombi_nvm_reload_block(link, KOMBI_NVM_BLOCK_IMMO)
                cur_val = _poll_ram_immo_mode_zero(link, timeout_s=2.5)
                if cur_val != 0x00:
                    raise RuntimeError(
                        tr(
                            f"Не удалось переключить RAM 0x{ram_immo_addr:08X} в 0x00 через 2E FD 3A 00 4D (ответ: 0x{cur_val & 0xFF:02X}).",
                            f"Failed to switch RAM 0x{ram_immo_addr:08X} to 0x00 via 2E FD 3A 00 4D (got: 0x{cur_val & 0xFF:02X}).",
                        )
                    )
        entered_yield = True
        yield state
    finally:
        restore_val_eff = target_restore if entered_yield else orig_mode
        failed_fde3: list[int] = []
        if pending_fde3_restore:
            for afeid in list(KOMBI_2220_FDE3_AFFECTED_EEL_IDS):
                if afeid not in pending_fde3_restore:
                    continue
                if afeid == 0x0068 and not entered_yield and afeid in saved_fde3_records and len(saved_fde3_records[afeid]) > 0x4B:
                    r68_orig_m = bytearray(saved_fde3_records[afeid])
                    r68_orig_m[0x4B] = orig_mode
                    saved_fde3_records[afeid] = bytes(r68_orig_m)
                restored_ok = False
                for attempt in range(3):
                    try:
                        _restore_fde3_block(afeid)
                        restored_ok = True
                        break
                    except Exception as exc:
                        if attempt + 1 < 3:
                            time.sleep(0.1)
                        else:
                            reporter.warning(
                                tr(
                                    f"Не удалось восстановить блок безопасности EEL 0x{afeid:04X} после 3 попыток: {exc}",
                                    f"Failed to restore security block EEL 0x{afeid:04X} after 3 attempts: {exc}",
                                )
                            )
                if not restored_ok:
                    failed_fde3.append(afeid)
        if failed_fde3:
            ids_hex = ", ".join(f"0x{eid:04X}" for eid in failed_fde3)
            raise RuntimeError(
                tr(
                    f"Критическая ошибка восстановления после 2E FD E3: не удалось восстановить блоки EEL {ids_hex}!",
                    f"Critical restore failure after 2E FD E3: failed to restore EEL security block(s) {ids_hex}!",
                )
            )
        if state["switched"] or state["eel68_written"] or (target_restore != 0x00 and prof["can_switch_immo_mode0_at_sl7"]):
            if not state["eel68_written"] and 0x0068 not in pending_fde3_restore:
                fpke_write_memory_0x3d(link, KOMBI_EEL_IMMO_MODE_VADDR, bytes([restore_val_eff]), timeout=4.0)
            kombi_nvm_reload_block(link, KOMBI_NVM_BLOCK_IMMO)
            restored_val = _poll_ram_immo_mode_restored(link, restore_val_eff, timeout_s=2.5)
            reporter.can_log(
                tr(
                    f"Статус immo_mode восстановлен: EEL 0x0068+0x4B / RAM 0x{ram_immo_addr:08X} = 0x{restored_val:02X}",
                    f"Restored immo_mode: EEL 0x0068+0x4B / RAM 0x{ram_immo_addr:08X} = 0x{restored_val:02X}",
                )
            )


def can_kombi_write_dflash(
    port: str,
    candidate_dflash: bytes | Path,
    *,
    interface: str = "slcan",
    base_dflash: bytes | Path | None = None,
    cflash_bytes: bytes | None = None,  # noqa: ARG001
    session_dir: Path | None = None,
    wake_seconds: float = 1.5,
    allow_foreign: bool = False,
    reset_after: bool = True,
    keep_open: bool = True,
    via_gateway: bool = False,
    gateway_bridge: bool = False,  # noqa: ARG001 - Kombi SL 7 uses standard 11-bit UDS (no 29-bit RAM bridge needed)
    gateway_channel: int = 0,  # noqa: ARG001
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Write modified EEL records to Continental V850E2 `17 Kombi VDD` at `Supplier Level 7` (`SL 7`) via `UDS 0x3D`."""
    from contitool.can.workflows import default_session_dir

    raw_cand = Path(candidate_dflash).read_bytes() if isinstance(candidate_dflash, (str, Path)) else bytes(candidate_dflash)
    if not is_kombi_dflash(raw_cand):
        raise ValueError(
            tr(
                f"Некорректный образ DataFlash Kombi ({len(raw_cand)} Б): требуется валидный дамп 65 536 Б (EEL T01) или 9 533 / 8 334 Б (EelLogical.bin).",
                f"Invalid Kombi DataFlash image ({len(raw_cand)} B): expected a valid 65,536-byte EEL T01 or 9,533 / 8,334-byte logical EEL dump.",
            )
        )
    cand_bytes = normalize_kombi_dflash_input(raw_cand)
    base_bytes = (
        normalize_kombi_dflash_input(
            Path(base_dflash).read_bytes() if isinstance(base_dflash, (str, Path)) else bytes(base_dflash)
        )
        if base_dflash is not None
        else None
    )

    out_dir = session_dir or default_session_dir(None, "kombi_write")
    out_dir.mkdir(parents=True, exist_ok=True)
    before_path = out_dir / "Dflash_before.bin"
    readback_path = out_dir / "Dflash_readback.bin"
    dflash_path = out_dir / "Dflash.bin"
    logical_path = out_dir / "EelLogical.bin"
    report_path = out_dir / "kombi_write_report.json"
    can_log_path = out_dir / "kombi.can.log"

    total_steps = 5 if reset_after else 4
    started = time.monotonic()

    with _managed_kombi_session(
        port,
        interface=interface,
        log_path=out_dir / "can.jsonl",
        bus=bus,
        keep_open=keep_open and not via_gateway,
        via_gateway=via_gateway,
    ) as link:
        try:
            reporter.step(
                1,
                total_steps,
                tr("Получение доступа FD11 Supplier Level 7 (SL 7)", "Establishing FD11 Supplier Level 7 (SL 7)"),
            )
            dump_sl7_key, dump_fd11_id = _extract_sl7_key_from_dflash(base_bytes or cand_bytes)
            access_info = kombi_ensure_sl7(
                link,
                sl7_key=dump_sl7_key,
                expected_fd11_id=dump_fd11_id,
                wake_seconds=wake_seconds,
                reporter=reporter,
            )
            _check_kombi_link_support(link, reporter=reporter)
            prof = _get_link_kombi_profile(link)
            n_eel = len(prof["eel_ids"])

            reporter.step(
                2,
                total_steps,
                tr(
                    f"Резервное чтение текущего DataFlash ({n_eel} бл. EEL)",
                    f"Backing up live DataFlash ({n_eel} EEL blocks)",
                ),
            )
            dflash_before, logical_before, before_meta = kombi_read_all_eel_in_session(link, reporter=reporter)
            atomic_write(before_path, dflash_before)

            before_info = analyze_kombi_dflash(dflash_before)
            cand_info = analyze_kombi_dflash(cand_bytes)
            live_fd11 = before_info.get("fd11_identifier")
            cand_fd11 = cand_info.get("fd11_identifier")
            if live_fd11 and cand_fd11 and live_fd11 != cand_fd11 and not allow_foreign:
                raise RuntimeError(
                    tr(
                        f"Отказано в прямой записи чужого дампа DataFlash Kombi: идентификатор FD11 в дампе ({cand_fd11}) "
                        f"не совпадает с подключённой панелью ({live_fd11}). "
                        "Для переноса иммо, ключей и CP используйте вкладку «Перенос из донора».",
                        f"Refusing to write a foreign Kombi DataFlash dump directly: candidate FD11 ({cand_fd11}) "
                        f"does not match connected cluster ({live_fd11}). "
                        "Use the “Donor transfer” tab to transfer immo, keys, and CP safely.",
                    )
                )

            ref_base = base_bytes if base_bytes is not None else dflash_before
            change_summary = summarize_kombi_dflash_changes(ref_base, cand_bytes)
            eel_updates = dict(extract_kombi_eel_updates(ref_base, cand_bytes))

            # Ensure EEL 0x0030 carries a valid big-endian CRC-16/CCITT-FALSE at rec[-2:] on SW 0310
            if 0x0030 in eel_updates and len(eel_updates[0x0030]) == 43 and prof["sw_profile"] != "2220":
                r30_mut = bytearray(eel_updates[0x0030])
                struct.pack_into(">H", r30_mut, 41, kombi_crc16_ccitt(bytes(r30_mut[2:41])))
                eel_updates[0x0030] = bytes(r30_mut)

            priv_set = prof.get("wr_privileged_eel_ids", KOMBI_WR_PRIVILEGED_EEL_IDS)
            needs_mode0 = any(eid in priv_set for eid in eel_updates)
            final_immo_mode: int | None = None
            if 0x0068 in eel_updates and len(eel_updates[0x0068]) > 0x4B:
                final_immo_mode = eel_updates[0x0068][0x4B]

            reporter.step(
                3,
                total_steps,
                tr(
                    f"Запись изменённых блоков EEL через UDS 0x3D ({len(eel_updates)} бл.)",
                    f"Writing modified EEL blocks via UDS 0x3D ({len(eel_updates)} block(s))",
                ),
            )
            reporter.reset_stage_timer()
            written_ids: list[str] = []
            words_cnt = 0
            odometer_sync_meta: dict[str, Any] | None = None

            def _write_eel_record(idx: int, eid: int, rec_bytes: bytes) -> None:
                nonlocal words_cnt
                if eid in KOMBI_ALIGN4_EEL_IDS and rec_bytes[2:4] == b"\xff\xff":
                    payload = bytes(rec_bytes[4:])
                    vaddr = KOMBI_EEL_VIRTUAL_BASE | (eid << 8) | 0x04
                elif prof["sw_profile"] == "2220" and eid in KOMBI_NVM_STAGED_EEL_MAP:
                    nvm_len = KOMBI_NVM_STAGED_EEL_MAP[eid][1]
                    payload = bytes(rec_bytes[2 : 2 + nvm_len])
                    vaddr = KOMBI_EEL_VIRTUAL_BASE | (eid << 8) | 0x02
                else:
                    payload = bytes(rec_bytes[2:])
                    vaddr = KOMBI_EEL_VIRTUAL_BASE | (eid << 8) | 0x02
                fpke_write_memory_0x3d(link, vaddr, payload, timeout=6.0)
                written_ids.append(f"0x{eid:02X}")
                words_cnt += (len(payload) + 3) // 4
                reporter.progress(idx + 1, len(eel_updates), unit="blk", detail=f"EEL 0x{eid:04X} ({len(payload)} B)")

            if eel_updates:
                with reporter.uninterruptible():
                    ordered_eids = [eid for eid in sorted(eel_updates) if eid != 0x0068]
                    if 0x0068 in eel_updates:
                        ordered_eids.append(0x0068)

                    ctx = (
                        kombi_temporary_immo_mode0(
                            link,
                            restore_mode=final_immo_mode,
                            backup_dflash=dflash_before,
                            skip_restore_eids=frozenset(eel_updates),
                            reporter=reporter,
                        )
                        if needs_mode0
                        else contextlib.nullcontext({"switched": False, "eel68_written": False})
                    )
                    with ctx as mode_state:
                        pending_fde3 = mode_state.get("pending_fde3_restore")
                        for idx, eid in enumerate(ordered_eids):
                            rec_bytes = eel_updates[eid]
                            _write_eel_record(idx, eid, rec_bytes)
                            if isinstance(pending_fde3, set):
                                pending_fde3.discard(eid)
                            if eid == 0x0068:
                                mode_state["eel68_written"] = True
                                if not needs_mode0:
                                    kombi_nvm_reload_block(link, KOMBI_NVM_BLOCK_IMMO)
                            elif eid == 0x0065:
                                kombi_nvm_reload_block(link, 0x004A)
                                fd11_state_addr = prof.get("ram_fd11_state_addr")
                                if fd11_state_addr and len(rec_bytes) >= 14:
                                    fpke_write_memory_0x3d(link, int(fd11_state_addr), bytes(rec_bytes[2:14]), timeout=3.0)
                            elif eid in KOMBI_NVM_STAGED_EEL_MAP:
                                kombi_nvm_reload_block(link, KOMBI_NVM_STAGED_EEL_MAP[eid][0])

                        if 0x0060 in eel_updates:
                            target_km = (cand_info.get("odometer") or {}).get("odometer_km")
                            if target_km is not None:
                                target_meters = int(target_km) * 1000
                                m_bytes = struct.pack("<I", target_meters)
                                ram_meters_addr = int(prof["ram_odo_meters_addr"])
                                ram_dpool_addr = int(prof["ram_odo_dpool_addr"])
                                retain_dpool_addr = int(prof["retain_odo_dpool_addr"])
                                kombi_nvm_reload_block(link, KOMBI_NVM_BLOCK_ODO)
                                if 0x0035 in eel_updates:
                                    kombi_nvm_reload_block(link, KOMBI_NVM_BLOCK_ODO_REPAIR)
                                fpke_write_memory_0x3d(link, ram_meters_addr, m_bytes, timeout=3.0)
                                fpke_write_memory_0x3d(link, ram_dpool_addr, m_bytes, timeout=3.0)
                                fpke_write_memory_0x3d(link, retain_dpool_addr, m_bytes, timeout=3.0)
                                odometer_sync_meta = {
                                    "target_km": int(target_km),
                                    "target_meters": target_meters,
                                    "ram_meters_addr": f"0x{ram_meters_addr:08X}",
                                    "dpool_ram_addr": f"0x{ram_dpool_addr:08X}",
                                    "retention_ram_addr": f"0x{retain_dpool_addr:08X}",
                                }
                                reporter.can_log(
                                    tr(
                                        f"Синхронизирован пробег в RAM (0x{ram_meters_addr:08X}, 0x{ram_dpool_addr:08X}) и Retention RAM (0x{retain_dpool_addr:08X}): {target_km} км ({target_meters} м)",
                                        f"Synchronized odometer in RAM (0x{ram_meters_addr:08X}, 0x{ram_dpool_addr:08X}) and Retention RAM (0x{retain_dpool_addr:08X}): {target_km} km ({target_meters} m)",
                                    )
                                )

                        if 0x0030 in eel_updates:
                            kombi_nvm_reload_block(link, KOMBI_NVM_BLOCK_CODING)

            reporter.step(
                4,
                total_steps,
                tr("Контрольное чтение и верификация DataFlash", "Readback & DataFlash verification"),
            )
            dflash_readback, logical_readback, readback_meta = kombi_read_all_eel_in_session(link, reporter=reporter)
            atomic_write(readback_path, dflash_readback)
            atomic_write(dflash_path, dflash_readback)
            atomic_write(logical_path, logical_readback)

            lay_rb = kombi_eel_layout(dflash_readback)
            for eid, expected_rec in eel_updates.items():
                got_rec, got_src = eel_read_record_any(lay_rb, dflash_readback, eid)
                if (
                    prof["sw_profile"] == "2220"
                    and eid in KOMBI_NVM_STAGED_EEL_MAP
                    and not readback_meta.get("eel_0063_0064_direct")
                ):
                    cmp_len = 2 + KOMBI_NVM_STAGED_EEL_MAP[eid][1]
                    rec_match = got_rec[:cmp_len] == expected_rec[:cmp_len]
                else:
                    rec_match = got_rec == expected_rec
                if got_src.get("generation") != "current" or not rec_match:
                    raise RuntimeError(
                        tr(
                            f"Контрольная проверка записи EEL 0x{eid:02X} после чтения DataFlash не пройдена!",
                            f"Post-write verification failed for EEL record 0x{eid:02X} in DataFlash readback!",
                        )
                    )

            reset_info: dict[str, Any] | None = None
            if reset_after and eel_updates:
                reporter.step(
                    5,
                    total_steps,
                    tr("Перезапуск панели приборов (UDS 11 02)", "Restarting instrument cluster (UDS 11 02)"),
                )
                with contextlib.suppress(Exception):
                    link.request_uds(b"\x11\x02", 0x51, timeout=2.0)
                link.level8_active = False
                if wake_seconds > 0:
                    time.sleep(min(1.5, max(0.2, wake_seconds * 0.6)))
                post_odo_km: int | None = None
                if 0x0060 in eel_updates:
                    with contextlib.suppress(Exception):
                        r_odo = link.request_uds(b"\x22\x22\x03", 0x62, timeout=1.5)
                        if len(r_odo) >= 6 and r_odo[:3] == b"\x62\x22\x03":
                            val24 = int.from_bytes(r_odo[3:6], "big")
                            if val24 != 0xFFFFFF:
                                post_odo_km = val24
                reset_info = {"method": "uds_11_02", "odometer_2203_km": post_odo_km}

            readback_secrets = analyze_kombi_dflash(dflash_readback)
            elapsed_s = round(time.monotonic() - started, 3)
            report: dict[str, Any] = {
                "ok": True,
                "ecu_kind": "kombi",
                "target": prof["target_label"],
                "sw_profile": prof["sw_profile"],
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "port": port,
                "interface": interface,
                "via_gateway": bool(via_gateway),
                "gateway_bridged": False,
                "mode": "uds_0x3d_eel_sl7_mode0_unlock" if needs_mode0 else "uds_0x3d_eel_sl7",
                "elapsed_s": elapsed_s,
                "blocks_written": len(eel_updates),
                "blocks_erased": 0,
                "words_programmed": words_cnt,
                "changed_eel_ids": change_summary["changed_eel_ids"],
                "written_eel_ids": written_ids,
                "short_summary": change_summary["short_summary"],
                "summary_lines": change_summary["lines"],
                "odometer_ram_sync": odometer_sync_meta,
                "dflash_before_sha256": hashlib.sha256(dflash_before).hexdigest(),
                "dflash_readback_sha256": hashlib.sha256(dflash_readback).hexdigest(),
                "dflash_before_path": str(before_path),
                "dflash_readback_path": str(readback_path),
                "dflash_path": str(dflash_path),
                "logical_path": str(logical_path),
                "session_dir": str(out_dir),
                "access": access_info,
                "before_read": before_meta,
                "readback_read": readback_meta,
                "secrets": readback_secrets,
                "reset": reset_info,
            }
            atomic_write(report_path, (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
            reporter.success(
                tr(
                    f"Запись DataFlash Kombi (SL 7) завершена и проверена ({len(eel_updates)} бл. EEL, {elapsed_s:.1f} с).",
                    f"Kombi DataFlash write (SL 7) completed and verified ({len(eel_updates)} EEL block(s), {elapsed_s:.1f} s).",
                )
            )
            return report
        finally:
            with contextlib.suppress(Exception):
                link.save_can_log(can_log_path)


def _trigger_kombi_coil_slot_poll(
    link: FpkeCanLink,
    *,
    do_reset: bool = False,
    wait_seconds: float = 1.6,
    reporter: OperationReporter = NULL_REPORTER,
) -> None:
    """Trigger WFS5 LF coil `Slot A / Slot B` read & decryption via `0x3C0` byte-2 bit-7 (`0x83`) edge and optional `11 02` warm reset."""
    if do_reset:
        reporter.can_log(
            tr(
                "Перезапуск опроса штатной катушки LF (UDS 11 02 + 0x3C0 KL15/WFS) для расшифровки слотов A/B рабочего ключа…",
                "Triggering fresh LF coil poll (UDS 11 02 + 0x3C0 KL15/WFS) to decrypt working key Slots A/B…",
            )
        )
        with contextlib.suppress(Exception):
            link.request_uds(b"\x11\x02", 0x51, timeout=2.0)
        link.level8_active = False

    if link.via_gateway or wait_seconds <= 0:
        return

    has_send = hasattr(link, "send_frame")
    deadline = time.monotonic() + wait_seconds
    cnt = 0
    phase = 0
    while time.monotonic() < deadline:
        reporter.check_cancelled()
        if has_send:
            # Toggle 0x3C0 byte 2 between 0x03 (KL_S|KL_15) and 0x83 (KL_S|KL_15|WFS_Freigabe_Anf bit 7 -> event 0x905/0x975 -> FUN_ram_0017cd38(1))
            b2 = 0x83 if (phase >= 2 and phase % 4 != 0) else 0x03
            frame_3c0 = bytearray(build_fpke_drive_frame(0x3C0, cnt, kl15=True))
            frame_3c0[2] = b2
            from contitool.can.fpke import fpke_e2e_crc

            frame_3c0[0] = fpke_e2e_crc(0x3C0, frame_3c0)
            with contextlib.suppress(Exception):
                link.send_frame(0x3C0, bytes(frame_3c0), extended=False)
            cnt = (cnt + 1) & 0x0F
            phase += 1
        rem = deadline - time.monotonic()
        if rem <= 0:
            break
        time.sleep(min(0.08, max(0.01, rem)))


def kombi_extract_live_s0_s1_from_coil(
    link: FpkeCanLink,
    *,
    expected_crc_a_le: bytes | str | None = None,
    expected_crc_b_le: bytes | str | None = None,
    sl7_key: bytes | str | None = None,
    expected_fd11_id: str | None = None,
    wake_seconds: float = 1.5,
    poll_timeout: float = 4.0,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Extract live 32-byte `S0 || S1` (`Slot A / Slot B`) from V850E2 `17 Kombi VDD` RAM at `SL 7` when a working key is in the coil.

    Checks both the raw decrypted `Slot A / Slot B` buffers (`0xFEDC8E30` & `0xFEDC8E50` on SW 2220, which survive `2E FD E3`
    untouched; `0xFEDC82FC` & `0xFEDC831C` on SW 0310), the interleaved `S0 || S1` buffer (`0xFEDC8EE0` on SW 2220 /
    `0xFEDC83C4` on SW 0310), and the `EEL 0x0069` RAM mirror (`0xFEDC8B00` on SW 2220 / `0xFEDC7F90` on SW 0310),
    verifying `CRC-32(Slot A)` and `CRC-32(Slot B)` against `EEL 0x0068`.
    """
    if not link.via_gateway:
        link.start_keepalive()

    coil_key_id: str | None = None
    with contextlib.suppress(Exception):
        link.request_uds(b"\x10\x03", 0x50, timeout=1.5)
        r_02e4 = link.request_uds(b"\x22\x02\xe4", 0x62, timeout=2.5)
        if len(r_02e4) >= 7 and r_02e4[3:7] not in (b"\x00" * 4, b"\xff" * 4):
            coil_key_id = r_02e4[3:7].hex().upper()

    if not link.via_gateway and poll_timeout > 0:
        _trigger_kombi_coil_slot_poll(link, do_reset=False, wait_seconds=min(0.4, poll_timeout * 0.2), reporter=reporter)

    kombi_ensure_sl7(
        link,
        sl7_key=sl7_key,
        expected_fd11_id=expected_fd11_id,
        wake_seconds=wake_seconds,
        reporter=reporter,
    )
    _check_kombi_link_support(link, reporter=reporter)
    prof = _get_link_kombi_profile(link)
    sw_label = f"SW {prof['sw_profile']}"
    staging_addr = int(prof["ram_staging_addr"])
    s0_addr = int(prof["ram_s0_addr"])
    flag_addr = int(prof["ram_slots_flag_addr"])
    recog_addr = int(prof["ram_recog_state_addr"])
    id_addr = prof.get("ram_last_key_id_addr")
    slot_a_addr = int(prof["ram_slot_a_addr"])
    slot_b_addr = int(prof["ram_slot_b_addr"])
    eel69_addr = int(prof["ram_eel69_addr"])
    scan_start, scan_end = prof["secdata_scan_range"]

    last_recog_state: int | None = None
    last_slots_flag: int | None = None

    def _finish_hit(ver: dict[str, Any], src_label: str, addr_int: int) -> dict[str, Any]:
        msg = tr(
            f"Секрет S0/S1 считан из {src_label} и подтверждён по CRC-32 (A={ver['crc_a_le_hex']}, B={ver['crc_b_le_hex']}).",
            f"Secret S0/S1 extracted from {src_label} and verified by CRC-32 (A={ver['crc_a_le_hex']}, B={ver['crc_b_le_hex']}).",
        )
        reporter.success(msg)
        return {
            "ok": True,
            "summary": msg,
            **ver,
            "source": src_label,
            "source_addr": f"0x{addr_int:08X}",
            "coil_key_id": coil_key_id,
            "slots_flag": last_slots_flag,
            "recog_state": last_recog_state,
        }

    # Fast check 0: Check EEL 0x0069 via NvM 0x4E staging reload before touching immo_mode
    with contextlib.suppress(Exception):
        kombi_nvm_reload_block(link, 0x004E)
        staged_69 = fpke_read_memory_0x23(link, staging_addr, 32, timeout=2.0)
        if len(staged_69) == 32:
            ver_69 = fpke_verify_s0_s1(staged_69[:16], staged_69[16:32], expected_crc_a_le, expected_crc_b_le)
            if ver_69["valid"] and expected_crc_a_le is not None:
                return _finish_hit(ver_69, f"{sw_label} NvM 0x4E / EEL 0x0069 (0x{staging_addr:08X})", staging_addr)

    def _probe_slots_under_mode0(*, allow_scan: bool) -> dict[str, Any] | None:
        nonlocal coil_key_id, last_recog_state, last_slots_flag
        with kombi_temporary_immo_mode0(link, reporter=reporter):
            with contextlib.suppress(Exception):
                last_slots_flag = fpke_read_memory_0x23(link, flag_addr, 1)[0]
            with contextlib.suppress(Exception):
                last_recog_state = fpke_read_memory_0x23(link, recog_addr, 1)[0]
            if id_addr is not None and not coil_key_id:
                with contextlib.suppress(Exception):
                    raw_kid = fpke_read_memory_0x23(link, int(id_addr), 4)
                    if raw_kid not in (b"\x00" * 4, b"\xff" * 4):
                        coil_key_id = raw_kid[::-1].hex().upper()

            # 1. Raw decrypted Slot A (16 B) + Slot B (16 B) buffers (unwiped by 2E FD E3 on SW 2220!)
            with contextlib.suppress(Exception):
                raw_slot_a = fpke_read_memory_0x23(link, slot_a_addr, 16)
                raw_slot_b = fpke_read_memory_0x23(link, slot_b_addr, 16)
                if len(raw_slot_a) == 16 and len(raw_slot_b) == 16:
                    s0_ab, s1_ab = fpke_s0_s1_from_slots(raw_slot_a, raw_slot_b)
                    ver_ab = fpke_verify_s0_s1(s0_ab, s1_ab, expected_crc_a_le, expected_crc_b_le)
                    if ver_ab["valid"] and (expected_crc_a_le is not None or last_slots_flag == 0x03):
                        return _finish_hit(
                            ver_ab,
                            f"{sw_label} Slot A/B RAM (0x{slot_a_addr:08X}/0x{slot_b_addr:08X})",
                            slot_a_addr,
                        )

            # 2. Interleaved S0 || S1 Slot RAM buffer (32 B)
            with contextlib.suppress(Exception):
                raw_32 = fpke_read_memory_0x23(link, s0_addr, 32)
                if len(raw_32) == 32:
                    ver_s0 = fpke_verify_s0_s1(raw_32[:16], raw_32[16:32], expected_crc_a_le, expected_crc_b_le)
                    if ver_s0["valid"] and (expected_crc_a_le is not None or last_slots_flag == 0x03):
                        return _finish_hit(ver_s0, f"{sw_label} Slot RAM (0x{s0_addr:08X})", s0_addr)

            # 3. EEL 0x0069 RAM mirror (32 B)
            with contextlib.suppress(Exception):
                raw_69 = fpke_read_memory_0x23(link, eel69_addr, 32)
                if len(raw_69) == 32:
                    ver_e69 = fpke_verify_s0_s1(raw_69[:16], raw_69[16:32], expected_crc_a_le, expected_crc_b_le)
                    if ver_e69["valid"]:
                        return _finish_hit(ver_e69, f"{sw_label} EEL 0x69 RAM (0x{eel69_addr:08X})", eel69_addr)

            # 4. Fallback scan of .secdata RAM if expected CRC-32(A/B) are known
            if allow_scan and expected_crc_a_le and expected_crc_b_le:
                for page_addr in range(int(scan_start), int(scan_end), 0x80):
                    reporter.check_cancelled()
                    read_len = min(0xB0, int(scan_end) + 0x30 - page_addr)
                    if read_len < 32:
                        break
                    with contextlib.suppress(Exception):
                        chunk = fpke_read_memory_0x23(link, page_addr, read_len)
                        for off in range(0, len(chunk) - 32, 4):
                            c0, c1 = chunk[off : off + 16], chunk[off + 16 : off + 32]
                            ver_inter = fpke_verify_s0_s1(c0, c1, expected_crc_a_le, expected_crc_b_le)
                            if ver_inter["valid"]:
                                hit_addr = page_addr + off
                                return _finish_hit(ver_inter, f"{sw_label} RAM scan (0x{hit_addr:08X})", hit_addr)
                            s0_c, s1_c = fpke_s0_s1_from_slots(c0, c1)
                            ver_slots = fpke_verify_s0_s1(s0_c, s1_c, expected_crc_a_le, expected_crc_b_le)
                            if ver_slots["valid"]:
                                hit_addr = page_addr + off
                                return _finish_hit(ver_slots, f"{sw_label} Slot RAM scan (0x{hit_addr:08X})", hit_addr)
                            if off + 48 <= len(chunk):
                                c2 = chunk[off + 32 : off + 48]
                                s0_s, s1_s = fpke_s0_s1_from_slots(c0, c2)
                                ver_stride = fpke_verify_s0_s1(s0_s, s1_s, expected_crc_a_le, expected_crc_b_le)
                                if ver_stride["valid"]:
                                    hit_addr = page_addr + off
                                    return _finish_hit(
                                        ver_stride,
                                        f"{sw_label} Slot A/B RAM scan (0x{hit_addr:08X}/0x{hit_addr + 0x20:08X})",
                                        hit_addr,
                                    )
        return None

    hit = _probe_slots_under_mode0(allow_scan=False)
    if hit is not None:
        return hit

    # Pass 2: if key was placed in the coil after initial boot (or RAM slots were cleared), trigger a fresh boot/KL15 coil poll
    if poll_timeout > 0:
        _trigger_kombi_coil_slot_poll(
            link,
            do_reset=True,
            wait_seconds=min(2.4, max(0.8, poll_timeout * 0.55)),
            reporter=reporter,
        )
        with contextlib.suppress(Exception):
            link.request_uds(b"\x10\x03", 0x50, timeout=1.5)
            r_02e4 = link.request_uds(b"\x22\x02\xe4", 0x62, timeout=2.5)
            if len(r_02e4) >= 7 and r_02e4[3:7] not in (b"\x00" * 4, b"\xff" * 4):
                coil_key_id = r_02e4[3:7].hex().upper()
        kombi_ensure_sl7(
            link,
            sl7_key=sl7_key,
            expected_fd11_id=expected_fd11_id,
            wake_seconds=0.2,
            reporter=reporter,
        )
        hit = _probe_slots_under_mode0(allow_scan=True)
        if hit is not None:
            return hit

    raise RuntimeError(
        tr(
            f"Слоты A/B ещё не загружены в ОЗУ панели приборов {prof['target_label']} (флаг слотов={last_slots_flag}, состояние={last_recog_state}). "
            "Приложите рабочий ключ от этой приборки к штатной катушке (T18 пин 8 и 9) при включённом зажигании, подождите 1–2 с и повторите.",
            f"Slots A/B are not loaded in {prof['target_label']} RAM yet (slots_flag={last_slots_flag}, recog_state={last_recog_state}). "
            "Hold a working key for this cluster against the stock LF coil (T18 pins 8 & 9) with ignition ON, wait 1–2 s, and retry.",
        )
    )


def kombi_prepare_additive_coil_learning(
    link: FpkeCanLink,
    *,
    s0_hex: str,
    s1_hex: str,
    kc_hex: str = "",  # noqa: ARG001
    allowed_keys: int = 3,
    existing_key_display_ids: list[str] | None = None,
    expected_crc_a_le: bytes | str | None = None,
    expected_crc_b_le: bytes | str | None = None,
    sl7_key: bytes | str | None = None,
    expected_fd11_id: str | None = None,
    wake_seconds: float = 1.5,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Method A (non-destructive): enter LF coil key-addition mode (`immo_mode = 5`) on V850E2 `17 Kombi VDD` at `SL 7` without `2E 02F7`.

    Preserves all existing learned key IDs in `EEL 0x0067` (`NvM 0x4C`), writes `S0 || S1` to `EEL 0x0069` (`NvM 0x4E`) and
    the live `Slot A / Slot B` RAM buffers, sets `immo_flags` bit 0 (`S0/S1` valid), clears any lockout timers and KESSY
    `key_over_can` bit 7 (`+0x3F` on SW 2220 / `+0x4B` on SW 0310), and switches `immo_mode = 5` (`+0x49`).
    """
    s0 = bytes.fromhex("".join(s0_hex.split()))
    s1 = bytes.fromhex("".join(s1_hex.split()))
    ver = fpke_verify_s0_s1(s0, s1, expected_crc_a_le, expected_crc_b_le)
    if not ver["valid"]:
        raise RuntimeError(
            tr(
                f"Проверка S0/S1 не пройдена: CRC-32(A)={ver['crc_a_le_hex']} (ожидался {ver['expected_crc_a_le_hex']}), "
                f"CRC-32(B)={ver['crc_b_le_hex']} (ожидался {ver['expected_crc_b_le_hex']}). Подготовка режима дообучения заблокирована.",
                f"S0/S1 verification failed: CRC-32(A)={ver['crc_a_le_hex']} (expected {ver['expected_crc_a_le_hex']}), "
                f"CRC-32(B)={ver['crc_b_le_hex']} (expected {ver['expected_crc_b_le_hex']}). Refusing to enter additive mode.",
            )
        )
    slot_a, slot_b = fpke_slots_from_s0_s1(s0, s1)

    if not link.via_gateway:
        link.start_keepalive()

    pre_poll = fpke_coil_poll_transponder(link, reporter=reporter)
    cur_learned = int(pre_poll.get("learned_keys") or 0)
    live_ids = list(pre_poll.get("learned_key_ids") or [])
    if not live_ids and existing_key_display_ids:
        live_ids = [k.strip().upper() for k in existing_key_display_ids if k and k.strip().upper() != "FFFFFFFF"]
        if cur_learned == 0:
            cur_learned = len(live_ids)

    target_allowed = max(cur_learned + 1, min(8, int(allowed_keys)))
    if target_allowed > 8:
        raise RuntimeError(tr("Все 8 слотов ключей уже заняты.", "All 8 key slots are already full."))

    kombi_ensure_sl7(
        link,
        sl7_key=sl7_key,
        expected_fd11_id=expected_fd11_id,
        wake_seconds=wake_seconds,
        reporter=reporter,
    )
    _check_kombi_link_support(link, reporter=reporter)
    prof = _get_link_kombi_profile(link)
    eel_ids: dict[int, int] = dict(prof["eel_ids"])
    r67_base = int(prof["ram_eel67_addr"])
    r68_base = int(prof["ram_eel68_addr"])
    r69_base = int(prof["ram_eel69_addr"])
    s0_addr = int(prof["ram_s0_addr"])
    flag_addr = int(prof["ram_slots_flag_addr"])
    slot_a_addr = int(prof["ram_slot_a_addr"])
    slot_b_addr = int(prof["ram_slot_b_addr"])
    kessy_off = int(prof["eel68_kessy_payload_offset"])

    affected = _read_fde3_affected_records_in_session(link, prof, reporter=reporter)
    rec_67_orig = affected[0x0067]
    rec_68_orig = affected[0x0068]

    r67_payload = bytearray(rec_67_orig[2:39])
    if len(r67_payload) != 37 or r67_payload == bytearray(b"\xaa" * 37) or r67_payload == bytearray(b"\x00" * 37):
        r67_payload = bytearray(b"\xff" * 32 + bytes([target_allowed, cur_learned & 0x0F, 0, 0, 0]))
        for idx, disp_id in enumerate(live_ids[:cur_learned]):
            if len(disp_id) == 8:
                r67_payload[idx * 4 : (idx + 1) * 4] = bytes.fromhex(disp_id)[::-1]
    else:
        ram_learned = r67_payload[0x21] & 0x0F
        if 0 < ram_learned <= 8:
            cur_learned = ram_learned
            target_allowed = max(cur_learned + 1, min(8, int(allowed_keys)))
            if target_allowed > 8:
                raise RuntimeError(tr("Все 8 слотов ключей уже заняты.", "All 8 key slots are already full."))
        for slot in range(cur_learned, 8):
            r67_payload[slot * 4 : (slot + 1) * 4] = b"\xff\xff\xff\xff"
        r67_payload[0x20] = target_allowed
        r67_payload[0x21] = (r67_payload[0x21] & 0xF0) | (cur_learned & 0x0F)

    r68_payload_len = KOMBI_NVM_STAGED_EEL_MAP[0x0068][1] if prof["sw_profile"] == "2220" else (eel_ids[0x0068] - 2)
    r68_payload = bytearray(rec_68_orig[2 : 2 + r68_payload_len])
    if r68_payload[0x42] == 0xFF:
        r68_payload[0x42] = 0x01
    else:
        r68_payload[0x42] |= 0x01  # immo_flags bit 0 := 1 (S0/S1 present in EEL 0x0069)
    r68_payload[0x43:0x49] = b"\x00" * 6  # clear any lockout counters
    r68_payload[0x49] = 0x05  # immo_mode := 5 (additive key learning mode 5)

    kessy_saved = False
    if kessy_off < len(r68_payload):
        orig_kessy = r68_payload[kessy_off]
        if orig_kessy == 0xFF:
            r68_payload[kessy_off] = 0x00
            link._saved_coil_key_flags = None
        else:
            if orig_kessy & 0x80:
                link._saved_coil_key_flags = (r68_base + kessy_off, orig_kessy)
                kessy_saved = True
            else:
                link._saved_coil_key_flags = None
            r68_payload[kessy_off] = orig_kessy & ~0x80
    else:
        link._saved_coil_key_flags = None

    full_records = dict(affected)
    for eid, sz in eel_ids.items():
        if eid not in full_records:
            full_records[eid] = struct.pack("<H", sz) + (b"\xff" * (sz - 2))
    backup_df = build_kombi_eel_dflash(full_records, eel_ids=eel_ids)

    with kombi_temporary_immo_mode0(
        link,
        restore_mode=5,
        backup_dflash=backup_df,
        skip_restore_eids=frozenset({0x0067, 0x0068, 0x0069}),
        reporter=reporter,
    ) as mode_state:
        pending_fde3 = mode_state.get("pending_fde3_restore")
        fpke_write_memory_0x3d(link, KOMBI_EEL_VIRTUAL_BASE | (0x0069 << 8) | 0x02, s0 + s1, timeout=6.0)
        kombi_nvm_reload_block(link, 0x004E)
        if isinstance(pending_fde3, set):
            pending_fde3.discard(0x0069)

        fpke_write_memory_0x3d(link, KOMBI_EEL_VIRTUAL_BASE | (0x0067 << 8) | 0x02, bytes(r67_payload), timeout=6.0)
        kombi_nvm_reload_block(link, 0x004C)
        if isinstance(pending_fde3, set):
            pending_fde3.discard(0x0067)

        # Populate live RAM mirrors & Slot A/B buffers while immo_mode == 0 in RAM
        with contextlib.suppress(Exception):
            fpke_write_memory_0x3d(link, r69_base, s0 + s1, timeout=3.0)
            fpke_write_memory_0x3d(link, r67_base, bytes(r67_payload), timeout=3.0)
            fpke_write_memory_0x3d(link, slot_a_addr, slot_a, timeout=3.0)
            fpke_write_memory_0x3d(link, slot_b_addr, slot_b, timeout=3.0)
            fpke_write_memory_0x3d(link, s0_addr, s0 + s1, timeout=3.0)
            fpke_write_memory_0x3d(link, flag_addr, b"\x03", timeout=3.0)

        fpke_write_memory_0x3d(link, KOMBI_EEL_VIRTUAL_BASE | (0x0068 << 8) | 0x02, bytes(r68_payload), timeout=6.0)
        mode_state["eel68_written"] = True
        if isinstance(pending_fde3, set):
            pending_fde3.discard(0x0068)

    poll = fpke_coil_poll_transponder(link, reporter=reporter)
    free_slots = max(0, target_allowed - cur_learned)
    msg = tr(
        f"Режим дообучения (режим 5, Способ А) активирован на {prof['target_label']} без удаления старых ключей: "
        f"сохранено {cur_learned} кл., открыто для добавления: {free_slots} (разрешено: {target_allowed}). "
        "Приложите только новую болванку к катушке и нажмите «2. Обучить ключ в катушке (40 00)».",
        f"Additive learning mode (mode 5, Method A) activated on {prof['target_label']} without erasing old keys: "
        f"preserved {cur_learned} key(s), open for addition: {free_slots} (allowed: {target_allowed}). "
        "Place only the new blank key on the coil and click “2. Learn key in coil (40 00)”.",
    )
    reporter.success(msg)
    return {
        "ok": True,
        "method": "kombi_additive_sl7_mode5",
        "immo_mode": 5,
        "kessy_preserved": kessy_saved,
        "summary": msg,
        "preserved_keys": cur_learned,
        "allowed_keys": target_allowed,
        "r67_ram_addr": f"0x{r67_base:08X}",
        "r68_ram_addr": f"0x{r68_base:08X}",
        "r69_ram_addr": f"0x{r69_base:08X}",
        "poll": poll,
    }


def kombi_finish_coil_key_learning(
    link: FpkeCanLink,
    *,
    sync_channel3: bool = False,
    restore_key_flags: int | None = None,
    sl7_key: bytes | str | None = None,
    expected_fd11_id: str | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Step 3 of LF coil key learning on V850E2 `17 Kombi VDD`: send `2E 02E1 00 00 80 00` (or `80 01`) to exit learning mode (`mode -> 1`)."""
    if not link.via_gateway:
        link.start_keepalive()

    saved_pair = getattr(link, "_saved_coil_key_flags", None)
    eff_restore_flags = restore_key_flags if restore_key_flags is not None else (saved_pair[1] if saved_pair else None)

    link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
    param = 0x01 if sync_channel3 else 0x00
    req = build_fpke_02e1_request(0x80, param)
    used_fallback_80_00 = False
    promoted_mode2 = False

    def _promote_mode2_if_needed(exc: Exception) -> bool:
        nonlocal promoted_mode2
        if promoted_mode2 or not isinstance(exc, UdsNegativeResponse) or exc.nrc not in (0x7F, 0x22):
            return False
        with contextlib.suppress(Exception):
            kombi_ensure_sl7(
                link,
                sl7_key=sl7_key,
                expected_fd11_id=expected_fd11_id,
                wake_seconds=0.5,
                reporter=reporter,
            )
            prof = _get_link_kombi_profile(link)
            with kombi_temporary_immo_mode0(link, restore_mode=5, reporter=reporter) as mode_state:
                if prof["sw_profile"] != "2220":
                    fpke_write_memory_0x3d(link, KOMBI_EEL_IMMO_MODE_VADDR, b"\x05", timeout=4.0)
                    mode_state["eel68_written"] = True
            link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
            promoted_mode2 = True
            return True
        return False

    try:
        link.request_uds(req, 0x6E, timeout=20.0 if sync_channel3 else 8.0)
    except Exception as exc:
        if _promote_mode2_if_needed(exc):
            try:
                link.request_uds(req, 0x6E, timeout=20.0 if sync_channel3 else 8.0)
            except Exception:
                if not sync_channel3:
                    raise
                link.request_uds(build_fpke_02e1_request(0x80, 0x00), 0x6E, timeout=8.0)
                used_fallback_80_00 = True
        else:
            if not sync_channel3:
                raise
            reporter.info(
                tr(
                    "Узел 0x0E (BCM 09) не ответил по каналу 3 (работа на стенде) — завершение обучения командой 80 00…",
                    "Node 0x0E (BCM 09) did not answer on channel 3 (bench mode) — finishing with 80 00…",
                )
            )
            link.request_uds(build_fpke_02e1_request(0x80, 0x00), 0x6E, timeout=8.0)
            used_fallback_80_00 = True

    kessy_restored = False
    needs_kessy_restore = eff_restore_flags is not None and bool(eff_restore_flags & 0x80)
    if needs_kessy_restore:
        with contextlib.suppress(Exception):
            kombi_ensure_sl7(
                link,
                sl7_key=sl7_key,
                expected_fd11_id=expected_fd11_id,
                wake_seconds=0.5,
                reporter=reporter,
            )
            prof = _get_link_kombi_profile(link)
            kessy_off = int(prof["eel68_kessy_payload_offset"])
            affected = _read_fde3_affected_records_in_session(link, prof, reporter=reporter)
            rec_68 = bytearray(affected[0x0068])
            if 2 + kessy_off < len(rec_68):
                cur_b = rec_68[2 + kessy_off]
                restore_mask = 0x80 if prof["sw_profile"] == "2220" else 0xC0
                base_b = 0x00 if cur_b in (0xAA, 0xFF) else (cur_b & ~restore_mask)
                rec_68[2 + kessy_off] = base_b | (eff_restore_flags & restore_mask)
                if len(rec_68) > 0x4B:
                    rec_68[0x4B] = 0x01
                r68_plen = KOMBI_NVM_STAGED_EEL_MAP[0x0068][1] if prof["sw_profile"] == "2220" else (len(rec_68) - 2)
                with kombi_temporary_immo_mode0(
                    link,
                    restore_mode=1,
                    skip_restore_eids=frozenset({0x0068}),
                    reporter=reporter,
                ) as mode_state:
                    fpke_write_memory_0x3d(
                        link,
                        KOMBI_EEL_VIRTUAL_BASE | (0x0068 << 8) | 0x02,
                        bytes(rec_68[2 : 2 + r68_plen]),
                        timeout=6.0,
                    )
                    mode_state["eel68_written"] = True
                    pending_fde3 = mode_state.get("pending_fde3_restore")
                    if isinstance(pending_fde3, set):
                        pending_fde3.discard(0x0068)
                kessy_restored = True
        if kessy_restored:
            link._saved_coil_key_flags = None
    else:
        link._saved_coil_key_flags = None

    poll = fpke_coil_poll_transponder(link, reporter=reporter)
    learned = poll["learned_keys"]
    ids_str = ", ".join(poll["learned_key_ids"]) if poll["learned_key_ids"] else "—"
    msg = tr(
        f"Обучение ключей завершено (режим 1, S0/S1 стёрты из 0x69)! Всего обучено: {learned} • ID: {ids_str}",
        f"Key learning completed (mode 1, S0/S1 erased from 0x69)! Total learned: {learned} • ID: {ids_str}",
    )
    reporter.success(msg)
    return {
        "ok": True,
        "summary": msg,
        "learned_keys": learned,
        "learned_key_ids": poll["learned_key_ids"],
        "mode_family": poll["mode_family"],
        "sync_channel3_requested": sync_channel3,
        "used_fallback_80_00": used_fallback_80_00,
        "promoted_mode2_to_mode5": promoted_mode2,
        "kessy_restored": kessy_restored,
        "poll": poll,
    }


def kombi_run_procedure(
    link: FpkeCanLink,
    proc_id: str,
    *,
    wake_seconds: float = 1.5,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Execute a diagnostic or bench procedure on a `17 Kombi VDD` cluster."""
    if not link.via_gateway:
        link.start_keepalive()
    if proc_id in ("ensure_sl7", "ensure_level8"):
        info = kombi_ensure_sl7(link, wake_seconds=wake_seconds, reporter=reporter)
        reused = bool(info.get("reused_session"))
        msg = (
            tr("Доступ FD11 Supplier Level 7 (SL 7) уже открыт.", "FD11 Supplier Level 7 (SL 7) is already unlocked.")
            if reused
            else tr("Доступ FD11 Supplier Level 7 (SL 7) успешно открыт.", "FD11 Supplier Level 7 (SL 7) unlocked.")
        )
        reporter.success(msg)
        return {"procedure": proc_id, "ok": True, "summary": msg, "details": info}
    return fpke_run_procedure(link, proc_id, wake_seconds=wake_seconds, reporter=reporter)


__all__ = [
    "KombiCanLink",
    "can_kombi_full_read",
    "can_kombi_run_sl7_action",
    "can_kombi_write_dflash",
    "close_active_fpke_link",
    "get_active_fpke_link",
    "kombi_authenticate_fd11",
    "kombi_check_sl7",
    "kombi_clear_sa1_delay_timer",
    "kombi_ensure_sl7",
    "kombi_extract_live_s0_s1_from_coil",
    "kombi_extract_sl7_key",
    "kombi_finish_coil_key_learning",
    "kombi_nvm_reload_block",
    "kombi_prepare_additive_coil_learning",
    "kombi_read_all_eel_in_session",
    "kombi_run_procedure",
    "kombi_temporary_immo_mode0",
    "open_or_reuse_fpke_link",
]
