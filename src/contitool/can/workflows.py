"""End-to-end Continental J533 live Diagnosis CAN bench workflows with real-time progress.

Provides complete bench-programmer replacement over Diagnosis CAN (500 kbit/s):
0x6F0 service RAM-loader entry, arbitrary memory reader, live RSA-1024 probe,
FACI Uflash (32 KB), FACI DataFlash (64 KB), FACI CodeFlash boot/raw blocks + UDS FD_0DATA (1.5 MB),
and gateway health/DTC diagnostics.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
import time
from typing import Any

import can

from contitool.can.payloads import (
    BEACON_ASCII,
    BEACON_PAYLOAD,
    DFLASH_BLOCK_SIZE,
    DFLASH_ICUS_RESERVED_OFFSET,
    EXPECTED_BEACON_SHA256,
    EXPECTED_RSA_PROBE_SHA256,
    LOADER_RESET_PAYLOAD,
    RSA_PROBE_PAYLOAD,
    build_cflash_faci_block_payloads,
    build_dflash_faci_payloads,
    build_dflash_reader_payload,
    build_fed_reader_payload,
    build_reader_payload,
    build_service_loader_uds_steps,
    build_uflash_faci_payloads,
    cflash_block_ranges,
    fbl_sa2,
    verify_payload_self_tests,
)
from contitool.can.transport import J533CanLink
from contitool.core.analyzer import (
    analyze_cflash,
    analyze_dflash_swap,
    fbl_app_valid,
    analyze_uflash,
    split_cflash_or_app,
    validate_dflash_bytes,
    validate_uflash_bytes,
)
from contitool.core.checksums import app_crc
from contitool.core.constants import (
    APP_BASE,
    APP_SIZE,
    CFLASH_ADDR_START,
    CFLASH_SIZE,
    DFLASH_ADDR_START,
    DFLASH_SIZE,
    DFLASH_SWAP_NVM_OFF,
    FBL_PRESENCE_MAGIC,
    UFLASH_ADDR_START,
    UFLASH_RSA_CMP_OFFSET,
    UFLASH_SIZE,
    ZDC_DATASET_SPECS,
    ZDC_UDS_UPLOAD_MAP,
)
from contitool.core.patcher import apply_engineering_patch, apply_uflash_rsa_patch, write_dflash_slots
from contitool.core.zdc import MFL_KEYCODE_PRESETS, export_zdc_block, parse_zdc_passport, zdc_crc32_le
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationReporter

# One native-reader request streams without returning to the loader, and the loader kicks the watchdog only
# before it runs a payload, so a request must finish inside the WDTA window. The FBL (identical Uflash on the
# 3Q0907530C, E and G seen so far) sets WDTA0/1 MD = 0x77: 2^16 counts, 100 % open window. A 16 KB request
# reset the ECU after 269.6 ms of streaming: 2^16 / 240 kHz = 0.273 s. At ~0.25 ms per
# 8-byte frame, 4 KB streams for ~0.13 s. Do not raise this without kicking the watchdog inside the payload
# (the FBL's own service routine is at 0x01000EF0).
READ_CHUNK_BYTES = 4096
# What a flaky link raises: our own timeouts / protocol errors, and python-can errors from the D-PDU and J2534 buses
# (can.CanOperationError is not a RuntimeError). Every retry and recovery path catches all of them.
LINK_ERRORS = (TimeoutError, RuntimeError, can.CanError)
FED_READS_PER_PAYLOAD = 16  # 64 KB per upload outside DataFlash; verified: full CodeFlash over a CANable2, 0 retries
AREA_READ_RETRIES = 2
SELFID_OFFSET = 0x0000AB00
SELFID_SIZE = 16
FBL_META_START = 0x0000C000  # FBL logistic block up to APP_BASE: presence magic, programming data
FAZIT_OFFSET = 0x0000A240  # CodeFlash boot area: the same string the ECU answers on UDS 22 F17C
FAZIT_SIZE = 23

DTC_STATUS_NAMES: tuple[str, ...] = (
    "testFailed",
    "testFailedThisOperationCycle",
    "pendingDTC",
    "confirmedDTC",
    "testNotCompletedSinceLastClear",
    "testFailedSinceLastClear",
    "testNotCompletedThisOperationCycle",
    "warningIndicatorRequested",
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def default_session_dir(base_dir: Path | None, prefix: str) -> Path:
    """Create a fresh timestamped session folder so runs never overwrite or mix evidence."""
    root = base_dir if base_dir is not None else (Path.cwd() / "contitool_runs")
    stamp = time.strftime("%Y%m%d_%H%M%S")
    cand = root / f"{prefix}_{stamp}"
    idx = 1
    while cand.exists() and any(cand.iterdir()):
        idx += 1
        cand = root / f"{prefix}_{stamp}_{idx}"
    cand.mkdir(parents=True, exist_ok=True)
    return cand


def _consume_loader_end_frame(
    link: J533CanLink,
    *,
    timeout: float = 1.5,
    label: str = "RAM-loader",
) -> bytes:
    """Consume the mandatory 2-byte `00 00` status frame emitted by `0x0100120E` after every RAM applet."""
    resp = bytes(link.receive_frame(link.LOADER_RX_ID, timeout=timeout).data)
    if resp[:2] != b"\x00\x00":
        raise RuntimeError(f"Unexpected {label} closing frame on 0x6F1: {resp.hex()}")
    return resp


def _probe_beacon_in_loader(link: J533CanLink, reporter: OperationReporter) -> str:
    """Send 35-byte readiness beacon to an active 0x6F0 RAM-loader, verify reply, and consume closing `00 00`."""
    link.send_loader_payload(BEACON_PAYLOAD, reporter=reporter)
    received = bytearray()
    deadline = time.monotonic() + 5.0
    while len(received) < len(BEACON_ASCII) and time.monotonic() < deadline:
        frame = link.receive_frame(link.LOADER_RX_ID, timeout=1.0)
        received.extend(bytes(frame.data))
    beacon_bytes = bytes(received[: len(BEACON_ASCII)])
    if beacon_bytes != BEACON_ASCII:
        raise RuntimeError(f"Unexpected RAM-loader beacon reply: {received.hex()}")
    _consume_loader_end_frame(link, timeout=1.5, label="beacon")
    return beacon_bytes.decode("ascii")


def _enter_ram_loader_once(link: J533CanLink, reporter: OperationReporter) -> dict[str, Any]:
    """Execute the verified multi-DID UDS staging sequence to enter the 0x6F0 RAM-loader."""
    stage1, stage2, trigger = build_service_loader_uds_steps()
    info: dict[str, Any] = {
        "payload_sha256": EXPECTED_BEACON_SHA256,
        "flash_commands_sent": False,
    }
    reporter.can_log(tr("UDS 10 03 -> Расширенная диагностическая сессия", "UDS 10 03 -> Extended Diagnostic Session"))
    info["session_1003"] = link.request_uds(b"\x10\x03", 0x50, timeout=2.0).hex()

    reporter.can_log(tr("UDS 27 03 / 27 04 -> Разблокировка предпосылок программирования", "UDS 27 03 / 27 04 -> Precondition SecurityAccess"))
    info["security_2703"] = link.request_uds(b"\x27\x03", 0x67, timeout=2.0).hex()
    info["security_2704"] = link.request_uds(bytes.fromhex("2704caffe012"), 0x67, timeout=2.0).hex()
    info["preconditions"] = link.request_uds(bytes.fromhex("31010203"), 0x71, timeout=2.0).hex()

    reporter.can_log(tr("UDS 10 02 -> Переход в загрузчик FBL (Programming Session)", "UDS 10 02 -> Entering FBL Programming Session"))
    info["session_1002"] = link.request_uds(b"\x10\x02", 0x50, timeout=5.0, allow_pending=True).hex()
    time.sleep(1.0)

    reporter.can_log(tr("UDS 27 11 + multi-DID 0x22 Stage 1/2 -> Подготовка дескриптора 0x0100120E", "UDS 27 11 + multi-DID 0x22 Stage 1/2 -> Staging descriptor 0x0100120E"))
    info["seed"] = link.request_uds(b"\x27\x11", 0x67, timeout=2.0).hex()
    info["write_0410_05"] = link.request_uds(bytes.fromhex("2e041005"), 0x6E, timeout=2.0).hex()
    resp1 = link.request_uds(stage1, 0x62, timeout=3.0)
    if len(resp1) != 338 or resp1[-3:] != bytes.fromhex("041005"):
        raise RuntimeError(f"Unexpected multi-DID stage 1 response ({len(resp1)} bytes)")
    info["stage1_length"] = len(resp1)
    info["write_0410_48"] = link.request_uds(bytes.fromhex("2e041048"), 0x6E, timeout=2.0).hex()

    link.send_uds(stage2)
    try:
        info["stage2_response"] = link.receive_uds(timeout=0.2).hex()
    except TimeoutError:
        info["stage2_response"] = "suppressed"

    reporter.can_log(tr("UDS 27 12 Trigger -> Передача управления в заводской RAM-Loader (0x6F0/0x6F1)", "UDS 27 12 Trigger -> Jumping to factory RAM-Loader (0x6F0/0x6F1)"))
    link.send_uds(trigger)
    try:
        trig_resp = link.receive_uds(timeout=0.2)
        if trig_resp and trig_resp[0] == 0x7F:
            raise RuntimeError(f"Service loader trigger rejected with NRC: {trig_resp.hex()}")
        info["trigger_response"] = trig_resp.hex()
    except TimeoutError:
        info["trigger_response"] = "loader"

    beacon = _probe_beacon_in_loader(link, reporter)
    info["beacon"] = beacon
    info["loader_ready"] = True
    reporter.success(
        tr(
            f"Сервисный RAM-Loader активен и подтверждён маяком: {beacon} (0x6F1)",
            f"Service RAM-Loader active and confirmed by beacon: {beacon} (0x6F1)",
        )
    )
    return info


def enter_ram_loader(
    link: J533CanLink,
    *,
    allow_already_active: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Enter factory 0x6F0 RAM-loader over UDS, automatically recovering if already inside loader."""
    try:
        return _enter_ram_loader_once(link, reporter)
    except LINK_ERRORS as first_err:
        if allow_already_active:
            try:
                reporter.info(
                    tr(
                        "Шлюз не ответил на 10 03 — проверяем, не активен ли уже заводской RAM-Loader (0x6F0)…",
                        "No UDS 10 03 reply — checking if factory RAM-Loader (0x6F0) is already active…",
                    )
                )
                beacon = _probe_beacon_in_loader(link, reporter)
                reporter.success(
                    tr(
                        f"Заводской RAM-Loader уже активен ({beacon})",
                        f"Factory RAM-Loader is already active ({beacon})",
                    )
                )
                return {
                    "payload_sha256": EXPECTED_BEACON_SHA256,
                    "flash_commands_sent": False,
                    "already_in_loader": True,
                    "beacon": beacon,
                    "loader_ready": True,
                }
            except Exception:
                pass
        reporter.warning(
            tr(
                f"Первая попытка входа не удалась ({first_err}) — выполняем мягкий сброс шлюза и повтор…",
                f"Initial entry failed ({first_err}) — resetting gateway back to Application and retrying…",
            )
        )
        _reset_to_application(link, reporter=reporter)
        return _enter_ram_loader_once(link, reporter)


def _stream_loader_read_payload(
    link: J533CanLink,
    payload: bytes,
    address: int,
    length: int,
    *,
    frame_timeout: float = 1.5,
) -> bytes:
    """Execute one reader RAM applet, collect `length` data bytes from 0x6F1, and consume closing `00 00`."""
    link.send_loader_payload(payload)
    data = bytearray()
    deadline = time.monotonic() + max(10.0, length / 1000.0, frame_timeout + 1.0)
    while len(data) < length and time.monotonic() < deadline:
        try:
            frame = link.receive_frame(link.LOADER_RX_ID, timeout=frame_timeout)
        except TimeoutError:
            if not data:
                raise
            # the ECU streams at full bus speed; an adapter that cannot keep up drops frames and the stream "stops"
            raise TimeoutError(
                f"Stream from 0x6F1 at 0x{address:08X} stopped after {len(data)}/{length} bytes (frames lost by the adapter?)"
            ) from None
        data.extend(bytes(frame.data))
    out = bytes(data[:length])
    if len(out) != length:
        raise RuntimeError(f"Short memory read at 0x{address:08X}: got {len(out)}/{length} bytes")
    _consume_loader_end_frame(link, timeout=frame_timeout, label=f"reader @ 0x{address:08X}")
    return out


def _read_dflash_bytes(link: J533CanLink, address: int, length: int, frame_timeout: float) -> bytes:
    aligned_start = address & ~0x3
    aligned_end = (address + length + 3) & ~0x3
    collected = bytearray()
    cur = aligned_start
    while cur < aligned_end:
        step = min(READ_CHUNK_BYTES, aligned_end - cur)
        payload = build_dflash_reader_payload(cur, step, calls=1, feed=True)
        collected.extend(_stream_loader_read_payload(link, payload, cur, step, frame_timeout=frame_timeout))
        cur += step
    head = address - aligned_start
    return bytes(collected[head : head + length])


def read_memory_bytes(
    link: J533CanLink,
    address: int,
    length: int,
    *,
    frame_timeout: float = 1.5,
) -> bytes:
    """Read `length` bytes (1..65535) from `address`, using FACI Blank Check (`0x71`) for DataFlash.

    The range is cut at the DataFlash limits and into 4 KB requests: the stock reader 0x010010F0 does not kick
    the 0.273 s watchdog while it streams (a single 16 KB request resets the ECU)."""
    if not 1 <= length <= 0xFFFF:
        raise ValueError(f"Memory read length must be 1..65535, got {length}")
    dflash_end = DFLASH_ADDR_START + DFLASH_SIZE
    out = bytearray()
    cur, end = address, address + length
    while cur < end:
        in_dflash = DFLASH_ADDR_START <= cur < dflash_end
        limit = dflash_end if in_dflash else (DFLASH_ADDR_START if cur < DFLASH_ADDR_START else end)
        step = min(READ_CHUNK_BYTES, end - cur, limit - cur)
        if in_dflash:
            out += _read_dflash_bytes(link, cur, step, frame_timeout)
        else:
            out += _stream_loader_read_payload(link, build_reader_payload(cur, step), cur, step, frame_timeout=frame_timeout)
        cur += step
    return bytes(out)


SLOW_ADAPTER_HINT = (  # (ru, en): the language can change while the app runs
    "Адаптер теряет кадры, когда блок передаёт память на полной скорости шины. Так ведут себя SLCAN-клоны с "
    "последовательным портом (CH340 и т. п. на 115200 бод): для UDS их хватает, для чтения памяти — нет. "
    "Нужен адаптер с прямым USB (CANable, candleLight) или VAS 6154 / VNCI.",
    "The adapter loses frames while the ECU streams memory at full bus speed. Serial SLCAN clones (CH340 etc. at "
    "115200 baud) behave like this: fine for UDS, too slow for memory reads. Use a native USB adapter "
    "(CANable, candleLight) or VAS 6154 / VNCI.",
)


def read_memory_area(
    link: J533CanLink,
    start: int,
    end: int,
    output_path: Path,
    *,
    label: str = "",
    reference: bytes | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Stream a whole region with live KB/s & ETA: DataFlash through the blank-check reader (4 KB per payload),
    everything else through the watchdog-fed reader (16 x 4 KB per payload). A failed payload is retried."""
    if start % 256 or end % 256 or end <= start or (end - start) % READ_CHUNK_BYTES:
        raise ValueError(f"Invalid aligned area range: 0x{start:08X}..0x{end:08X}")
    total = end - start
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()

    reporter.reset_stage_timer()
    reporter.progress(0, total, unit="B", detail=label)
    collected = bytearray()
    offset = 0
    in_dflash = start < DFLASH_ADDR_START + DFLASH_SIZE and end > DFLASH_ADDR_START
    while offset < total:
        reporter.check_cancelled()
        addr = start + offset
        reads = 1 if in_dflash else min(FED_READS_PER_PAYLOAD, (total - offset) // READ_CHUNK_BYTES)
        size = reads * READ_CHUNK_BYTES
        for attempt in range(AREA_READ_RETRIES + 1):
            try:
                if in_dflash:  # FACI blank-check reader: erased words come back as FF
                    chunk = read_memory_bytes(link, addr, size)
                else:
                    payload = build_fed_reader_payload(addr, READ_CHUNK_BYTES, reads)
                    chunk = _stream_loader_read_payload(link, payload, addr, size)
                break
            except LINK_ERRORS as exc:
                if attempt == AREA_READ_RETRIES:
                    if link.interface == "slcan" and "stopped after" in str(exc):
                        reporter.error(tr(*SLOW_ADAPTER_HINT))
                    raise
                reporter.warning(
                    tr(
                        f"{label}: сбой чтения @ 0x{addr:08X} ({exc}) — повтор {attempt + 1}/{AREA_READ_RETRIES}",
                        f"{label}: read failed @ 0x{addr:08X} ({exc}) — retry {attempt + 1}/{AREA_READ_RETRIES}",
                    )
                )
                time.sleep(2.5)  # a 64 KB stream lasts ~2.1 s: let a broken one run out before the next sync
                link.drain_rx(max_frames=100_000)
        if len(chunk) != size:
            raise RuntimeError(f"Short chunk at 0x{addr:08X}: {len(chunk)}")
        with output_path.open("ab") as fh:
            fh.write(chunk)
        collected.extend(chunk)
        offset += len(chunk)
        reporter.progress(
            offset,
            total,
            unit="B",
            detail=f"{label} @ 0x{addr:08X}",
        )
        if offset % (64 * 1024) == 0 or offset == total:
            reporter.can_log(
                tr(
                    f"{label}: прочитано {offset:,} / {total:,} байт ({offset * 100.0 / total:.1f}%)",
                    f"{label}: read {offset:,} / {total:,} bytes ({offset * 100.0 / total:.1f}%)",
                )
            )

    raw = bytes(collected)
    sha = _digest(raw)
    result: dict[str, Any] = {
        "start": start,
        "end": end,
        "bytes": len(raw),
        "complete": len(raw) == total,
        "sha256": sha,
        "output_file": str(output_path),
        "flash_commands_sent": False,
    }
    if reference is not None:
        mismatch = next((i for i, (a, b) in enumerate(zip(raw, reference)) if a != b), None)
        result["reference_sha256"] = _digest(reference)
        result["reference_match"] = raw == reference
        result["first_mismatch"] = mismatch
        result["first_mismatch_address"] = (start + mismatch) if mismatch is not None else None
    reporter.success(
        tr(
            f"{label}: чтение завершено ({len(raw):,} Б, SHA-256: {sha[:16]}…)",
            f"{label}: read complete ({len(raw):,} B, SHA-256: {sha[:16]}…)",
        )
    )
    return result


def run_rsa_probe(link: J533CanLink, *, reporter: OperationReporter = NULL_REPORTER) -> dict[str, Any]:
    """Execute live 92-byte RSA probe in RAM-loader (`0` = Engineering RSA-Free FBL, `2` = Stock RSA)."""
    reporter.can_log(
        tr(
            "Запуск RSA-пробника (вызов 0x010033FC на 128 байтах 0xFF)…",
            "Running live RSA probe (calling 0x010033FC on 128 bytes of 0xFF)…",
        )
    )
    link.send_loader_payload(RSA_PROBE_PAYLOAD, reporter=reporter)
    _consume_loader_end_frame(link, timeout=5.0, label="RSA probe")
    status_bytes = read_memory_bytes(link, 0xFEDE9000, 4)
    rsa_status = int.from_bytes(status_bytes, "little")
    return {
        "complete": True,
        "payload_sha256": EXPECTED_RSA_PROBE_SHA256,
        "rsa_status": rsa_status,
        "engineering_active": rsa_status == 0,
        "flash_commands_sent": False,
    }


def _loader_reset_command(link: J533CanLink) -> str:
    try:
        link.send_loader_payload(LOADER_RESET_PAYLOAD)
    except LINK_ERRORS as exc:
        return f"sync-error:{exc}"
    try:
        return bytes(link.receive_frame(link.LOADER_RX_ID, timeout=1.0).data).hex()
    except TimeoutError:
        return "no response after reset"


def _request_with_retries(link: J533CanLink, uds_payload: bytes, expected_sid: int, attempts: int = 10) -> bytes:
    last_err: Exception | None = None
    for _ in range(attempts):
        try:
            return link.request_uds(uds_payload, expected_sid, timeout=1.2, allow_pending=True)
        except LINK_ERRORS as exc:
            last_err = exc
            time.sleep(0.5)
    raise RuntimeError(f"Application did not answer {uds_payload.hex()}: {last_err}")


def _reset_to_application(link: J533CanLink, *, reporter: OperationReporter = NULL_REPORTER) -> dict[str, Any]:
    info: dict[str, Any] = {}
    try:
        info["uds_reset"] = link.request_uds(b"\x11\x01", 0x51, timeout=1.2, allow_pending=True).hex()
        info["reset_method"] = "uds"
    except LINK_ERRORS as exc:
        info["uds_reset_error"] = str(exc)
    time.sleep(2.0)
    try:
        info["application_session"] = _request_with_retries(link, b"\x10\x03", 0x50, attempts=2).hex()
        info["reset_method"] = info.get("reset_method", "uds")
    except LINK_ERRORS:
        reporter.can_log(
            tr(
                "Отправка команды сброса FE FF через заводской RAM-Loader (0x6F0)…",
                "Sending FE FF MCU reset via factory RAM-Loader (0x6F0)…",
            )
        )
        info["loader_reset"] = _loader_reset_command(link)
        info["reset_method"] = "factory-loader"
        time.sleep(2.0)
        info["application_session"] = _request_with_retries(link, b"\x10\x03", 0x50, attempts=10).hex()
    return info


# Identification the gateway answers in the extended session (checked on 3Q0907530AA / HW 3Q0907530C / SW 5366)
ECU_IDENT_DIDS: tuple[tuple[int, str, str], ...] = (
    (0xF187, "Номер детали", "Part number"),
    (0xF191, "Номер оборудования", "Hardware number"),
    (0xF189, "Версия ПО", "Software version"),
    (0xF1A3, "Версия оборудования", "Hardware version"),
    (0xF197, "Система", "System name"),
    (0xF18C, "Серийный номер", "Serial number"),
    (0xF17C, "FAZIT", "FAZIT"),
    (0xF19E, "Вариант ODX", "ODX variant"),
    (0xF1A2, "Версия ODX", "ODX version"),
    (0x0600, "Кодирование", "Coding"),
)


def can_identify(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Check that the gateway answers on Diagnosis CAN and read its identification (UDS 10 03 + 22 xx xx).

    Read-only: no reset, no RAM-Loader. Identifiers the ECU rejects are left out. `bus` is for tests."""
    result: dict[str, Any] = {"responding": False, "ident": []}
    with J533CanLink(port, interface=interface, bus=bus) as link:
        reporter.step(1, 2, tr("Проверка связи с блоком (UDS 10 03)", "Checking the link to the ECU (UDS 10 03)"))
        try:
            link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        except LINK_ERRORS as exc:
            raise RuntimeError(
                tr(
                    f"Блок не отвечает по CAN ({exc}). Проверьте питание +12 В (Pin 1 и Pin 14), массу (Pin 11), "
                    "CAN-H на Pin 19, CAN-L на Pin 9 и что включён CAN-терминатор (или стоит резистор 120 Ом между ними).",
                    f"The ECU does not answer on CAN ({exc}). Check +12 V (Pin 1 and Pin 14), ground (Pin 11), "
                    "CAN-H on Pin 19, CAN-L on Pin 9 and that CAN termination is on (or a 120 Ω resistor between them).",
                )
            ) from exc
        result["responding"] = True
        reporter.step(2, 2, tr("Чтение идентификации блока", "Reading the ECU identification"))
        for did, ru, en in ECU_IDENT_DIDS:
            try:
                raw = link.request_uds(bytes([0x22, did >> 8, did & 0xFF]), 0x62, timeout=2.0)[3:]
            except LINK_ERRORS:
                continue  # this ECU variant does not support the identifier
            text = raw.rstrip(b"\x00 ").decode("latin-1")
            value = text.strip() if text and all(32 <= ord(ch) < 127 for ch in text) else raw.hex().upper()
            result["ident"].append({"did": f"{did:04X}", "label_ru": ru, "label_en": en, "value": value})
            reporter.info(f"{did:04X} {tr(ru, en)}: {value}")
    return result


# "Status_of_all_existing_FS-IDs_in_the_ECU" (ODIS): [FS-ID 4 B big-endian, status bits] per feature. In the
# 3Q0907530AR SW 5504 DID table @ 0x1FE7C with at most 75 bytes = 15 features.
SWAP_STATUS_DID = 0x3C00
SWAP_STATUS_ACTIVE = 0x7F  # bits 0..6 = certificate, not cancelled, VCRN, validity, configuration, function, signature


def can_swap_status(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Which SWaP features the gateway itself reports as active (UDS 22 3C 00). Read-only."""
    with J533CanLink(port, interface=interface, bus=bus) as link:
        reporter.step(1, 1, tr("Чтение состояния функций SWaP (UDS 22 3C 00)", "Reading SWaP feature states (UDS 22 3C 00)"))
        link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        for attempt in range(3):
            raw = link.request_uds(bytes([0x22, SWAP_STATUS_DID >> 8, SWAP_STATUS_DID & 0xFF]), 0x62, timeout=2.0)[3:]
            if len(raw) % 5:
                raise RuntimeError(
                    tr(f"Неожиданный ответ 22 3C 00: {raw.hex().upper()}", f"Unexpected 22 3C 00 answer: {raw.hex().upper()}")
                )
            features = [
                {"fsid": int.from_bytes(raw[i : i + 4], "big"), "status": raw[i + 4]}
                for i in range(0, len(raw), 5)
                if raw[i : i + 4] not in (b"\x00" * 4, b"\xff" * 4)
            ]
            checking = [f for f in features if f["status"] & 1 and f["status"] & SWAP_STATUS_ACTIVE != SWAP_STATUS_ACTIVE]
            if not checking or attempt == 2:
                break
            time.sleep(1.0)  # right after a reset the gateway may still be checking its certificates
    for f in features:
        reporter.info(f"FS-ID {f['fsid']:08X}: {f['status']:02X}")
    return {"features": features}


def can_health_check(
    port: str,
    *,
    interface: str = "slcan",
    session_dir: Path | None = None,
    clear_dtc: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Reset gateway into normal Application mode, verify UDS 10 03 & TesterPresent, and read/clear DTCs."""
    verify_payload_self_tests()
    out_dir = session_dir or default_session_dir(None, "health")
    out_dir.mkdir(parents=True, exist_ok=True)
    total_steps = 4 if clear_dtc else 3
    result: dict[str, Any] = {
        "complete": False,
        "session_dir": str(out_dir),
        "flash_commands_sent": False,
        "clear_dtc_requested": clear_dtc,
    }
    with J533CanLink(port, interface=interface, log_path=out_dir / "can.jsonl") as link:
        try:
            reporter.step(1, total_steps, tr("Перевод шлюза в штатный режим и сессию 10 03", "Resetting gateway into normal Application mode (10 03)"))
            reporter.progress(15, 100)
            result.update(_reset_to_application(link, reporter=reporter))

            reporter.step(2, total_steps, tr("Проверка связи с приложением (TesterPresent 3E 00)", "Verifying Application communication (TesterPresent 3E 00)"))
            result["tester_present"] = link.request_uds(b"\x3e\x00", 0x7E, timeout=2.0).hex()
            result["application_communication_ok"] = True
            reporter.progress(50, 100)
            reporter.success(tr("Штатное приложение шлюза J533 на связи (50 03 / 7E 00)!", "Gateway Application is alive and responding (50 03 / 7E 00)!"))

            step_idx = 3
            if clear_dtc:
                reporter.step(3, total_steps, tr("Очистка регистра ошибок DTC (UDS 14 FF FF FF)", "Clearing Diagnostic Trouble Codes (UDS 14 FF FF FF)"))
                result["clear_dtc_response"] = link.request_uds(
                    bytes.fromhex("14ffffff"), 0x54, timeout=5.0, allow_pending=True
                ).hex()
                time.sleep(0.5)
                reporter.info(tr("Команда очистки DTC выполнена успешно (0x54)", "ClearDiagnosticInformation accepted (0x54)"))
                step_idx = 4

            reporter.step(step_idx, total_steps, tr("Чтение регистра ошибок DTC (UDS 19 02 FF)", "Reading Diagnostic Trouble Codes (UDS 19 02 FF)"))
            try:
                resp = link.request_uds(bytes.fromhex("1902ff"), 0x59, timeout=3.0)
                result["dtc_supported"] = True
                result["dtc_response"] = resp.hex()
                if len(resp) < 3 or resp[1] != 0x02 or (len(resp) - 3) % 4 != 0:
                    raise RuntimeError(f"Malformed UDS 19 02 response: {resp.hex()}")
                result["dtc_status_availability_mask"] = f"{resp[2]:02x}"
                records_raw = resp[3:]
                dtc_list: list[dict[str, Any]] = []
                for idx in range(0, len(records_raw), 4):
                    code_hex = records_raw[idx : idx + 3].hex().upper()
                    st_byte = records_raw[idx + 3]
                    flags = [name for bit, name in enumerate(DTC_STATUS_NAMES) if st_byte & (1 << bit)]
                    dtc_list.append({"dtc": code_hex, "status": f"{st_byte:02X}", "flags": flags})
                result["dtc_records"] = dtc_list
                result["dtc_record_count"] = len(dtc_list)
                active_cnt = sum(1 for r in dtc_list if int(r["status"], 16) & 0x09)
                reporter.success(
                    tr(
                        f"Прочитано записей DTC: {len(dtc_list)} (активных/подтверждённых: {active_cnt})",
                        f"Read {len(dtc_list)} DTC records (active/confirmed: {active_cnt})",
                    )
                )
            except RuntimeError as dtc_err:
                result["dtc_supported"] = False
                result["dtc_error"] = str(dtc_err)
                reporter.warning(f"DTC read warning: {dtc_err}")

            result["complete"] = True
            reporter.progress(100, 100)
            return result
        except Exception as exc:
            result["error"] = str(exc)
            raise
        finally:
            _write_json(out_dir / "health_result.json", result)


def can_verify(
    port: str,
    *,
    interface: str = "slcan",
    session_dir: Path | None = None,
    no_enter: bool = False,
    return_to_app: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Enter 0x6F0 RAM-loader (read-only), dump 32 KB Uflash, inspect RSA state, and run live RSA-1024 probe."""
    verify_payload_self_tests()
    out_dir = session_dir or default_session_dir(None, "verify")
    out_dir.mkdir(parents=True, exist_ok=True)
    total_steps = 4 if return_to_app else 3
    report: dict[str, Any] = {
        "complete": False,
        "session_dir": str(out_dir),
        "flash_commands_sent": False,
    }
    with J533CanLink(port, interface=interface, log_path=out_dir / "can.jsonl") as link:
        try:
            if not no_enter:
                reporter.step(1, total_steps, tr("Вход в заводской RAM-Loader по Diagnosis CAN (без стирания/записи)", "Entering factory RAM-Loader over Diagnosis CAN (read-only)"))
                report["loader_session"] = enter_ram_loader(link, reporter=reporter)
            else:
                reporter.step(1, total_steps, tr("Проверка активного заводского RAM-Loader (0x6F0)", "Checking active factory RAM-Loader (0x6F0)"))
                report["beacon"] = _probe_beacon_in_loader(link, reporter)

            reporter.step(2, total_steps, tr("Вычитывание загрузчика Uflash (32 КБ @ 0x01000000)", "Reading Uflash bootloader (32 KB @ 0x01000000)"))
            uf_path = out_dir / "Uflash.bin"
            uf_read = read_memory_area(
                link,
                UFLASH_ADDR_START,
                UFLASH_ADDR_START + UFLASH_SIZE,
                uf_path,
                label="Uflash (32 KB)",
                reporter=reporter,
            )
            uf_bytes = uf_path.read_bytes()
            uf_info = analyze_uflash(uf_bytes)
            report["uflash_read"] = uf_read
            report["physical_uflash_sha256"] = uf_info.sha256
            report["uflash_signature_found"] = uf_info.signature_found
            report["uflash_rsa_bypassed"] = uf_info.rsa_bypassed

            reporter.step(3, total_steps, tr("Запуск живого RSA-пробника в RAM (0x010033FC)", "Running live RSA verification probe in RAM (0x010033FC)"))
            rsa_res = run_rsa_probe(link, reporter=reporter)
            report["rsa_probe"] = rsa_res
            report["rsa_status"] = rsa_res["rsa_status"]
            if rsa_res["rsa_status"] == 0:
                reporter.success(
                    tr(
                        "Статус загрузчика: ИНЖЕНЕРНЫЙ RSA-FREE FBL АКТИВЕН (rsa_status = 0)",
                        "Bootloader status: ENGINEERING RSA-FREE FBL ACTIVE (rsa_status = 0)",
                    )
                )
            else:
                reporter.info(
                    tr(
                        f"Статус загрузчика: Заводская проверка RSA-1024 АКТИВНА (rsa_status = {rsa_res['rsa_status']})",
                        f"Bootloader status: Stock RSA-1024 check is ACTIVE (rsa_status = {rsa_res['rsa_status']})",
                    )
                )

            if return_to_app:
                reporter.step(4, total_steps, tr("Возврат шлюза в штатный рабочий режим (10 03)", "Returning gateway to normal Application mode (10 03)"))
                report["return_to_app"] = _reset_to_application(link, reporter=reporter)

            report["complete"] = True
            reporter.progress(100, 100)
            return report
        except Exception as exc:
            report["error"] = str(exc)
            raise
        finally:
            _write_json(out_dir / "verification.json", report)


def can_backup(
    port: str,
    *,
    interface: str = "slcan",
    session_dir: Path | None = None,
    areas: tuple[str, ...] = ("cflash", "uflash", "dflash"),
    no_enter: bool = False,
    return_to_app: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read full Cflash (1.5 MB), Uflash (32 KB), and Dflash (64 KB) over CAN into `session_dir`."""
    verify_payload_self_tests()
    out_dir = session_dir or default_session_dir(None, "backup")
    out_dir.mkdir(parents=True, exist_ok=True)
    area_map: dict[str, tuple[str, int, int]] = {
        "cflash": ("Cflash.bin", CFLASH_ADDR_START, CFLASH_ADDR_START + CFLASH_SIZE),
        "uflash": ("Uflash.bin", UFLASH_ADDR_START, UFLASH_ADDR_START + UFLASH_SIZE),
        "dflash": ("Dflash.bin", DFLASH_ADDR_START, DFLASH_ADDR_START + DFLASH_SIZE),
    }
    selected = [a.lower() for a in areas]
    for a in selected:
        if a not in area_map:
            raise ValueError(f"Unknown backup area: {a}")

    total_steps = 1 + len(selected) + (1 if return_to_app else 0)
    manifest: dict[str, Any] = {
        "complete": False,
        "session_dir": str(out_dir),
        "flash_commands_sent": False,
        "areas": {},
    }
    with J533CanLink(port, interface=interface, log_path=out_dir / "can.jsonl") as link:
        try:
            if not no_enter:
                reporter.step(1, total_steps, tr("Вход в заводской RAM-Loader по CAN (режим только чтение)", "Entering factory RAM-Loader over CAN (read-only mode)"))
                manifest["loader_session"] = enter_ram_loader(link, reporter=reporter)
            else:
                reporter.step(1, total_steps, tr("Проверка активного RAM-Loader (0x6F0)", "Checking active RAM-Loader (0x6F0)"))
                manifest["beacon"] = _probe_beacon_in_loader(link, reporter)

            for idx, area_key in enumerate(selected, start=2):
                fname, start_addr, end_addr = area_map[area_key]
                size_kb = (end_addr - start_addr) // 1024
                reporter.step(
                    idx,
                    total_steps,
                    tr(
                        f"Чтение {fname} ({size_kb:,} КБ: 0x{start_addr:08X}..0x{end_addr - 1:08X})",
                        f"Reading {fname} ({size_kb:,} KB: 0x{start_addr:08X}..0x{end_addr - 1:08X})",
                    ),
                )
                file_path = out_dir / fname
                res = read_memory_area(
                    link,
                    start_addr,
                    end_addr,
                    file_path,
                    label=fname,
                    reporter=reporter,
                )
                manifest["areas"][area_key] = res

            if "cflash" in manifest["areas"]:
                cf_info = analyze_cflash((out_dir / "Cflash.bin").read_bytes())
                manifest["gateway_identity"] = {
                    "hw_pn": cf_info.hw_pn,
                    "hw_ver": cf_info.hw_ver,
                    "fazit": cf_info.fazit,
                    "crc_ok": cf_info.crc_ok,
                    "cp_mode": cf_info.hook_mode,
                }

            if return_to_app:
                reporter.step(total_steps, total_steps, tr("Возврат шлюза в штатный режим после бэкапа", "Returning gateway to normal Application mode"))
                manifest["return_to_app"] = _reset_to_application(link, reporter=reporter)

            manifest["complete"] = True
            reporter.progress(100, 100)
            reporter.success(
                tr(
                    f"Полный бэкап сохранён в папку: {out_dir}",
                    f"Full backup saved to folder: {out_dir}",
                )
            )
            return manifest
        except Exception as exc:
            manifest["error"] = str(exc)
            raise
        finally:
            _write_json(out_dir / "manifest.json", manifest)


def can_read_memory(
    port: str,
    address: int,
    length: int,
    output_file: Path,
    *,
    interface: str = "slcan",
    session_dir: Path | None = None,
    no_enter: bool = False,
    return_to_app: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read an arbitrary memory range (`address .. address + length - 1`) over the 0x6F0 RAM-loader."""
    verify_payload_self_tests()
    if length <= 0 or length > 0x01000000:
        raise ValueError(f"Memory read length must be between 1 and 16,777,216 bytes, got {length}")
    if address < 0 or address > 0xFFFFFFFF or (address + length) > 0x100000000:
        raise ValueError(f"Invalid 32-bit address range: start=0x{address:08X}, length={length}")

    out_dir = session_dir or default_session_dir(None, "read_mem")
    out_dir.mkdir(parents=True, exist_ok=True)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    total_steps = 3 if return_to_app else 2
    report: dict[str, Any] = {
        "complete": False,
        "session_dir": str(out_dir),
        "address": address,
        "length": length,
        "output_file": str(output_file),
        "flash_commands_sent": False,
    }
    with J533CanLink(port, interface=interface, log_path=out_dir / "can.jsonl") as link:
        try:
            if not no_enter:
                reporter.step(1, total_steps, tr("Вход в заводской RAM-Loader по CAN (чтение памяти)", "Entering factory RAM-Loader over CAN (memory read)"))
                report["loader_session"] = enter_ram_loader(link, reporter=reporter)
            else:
                reporter.step(1, total_steps, tr("Проверка активного RAM-Loader (0x6F0)", "Checking active RAM-Loader (0x6F0)"))
                report["beacon"] = _probe_beacon_in_loader(link, reporter)

            reporter.step(
                2,
                total_steps,
                tr(
                    f"Чтение памяти 0x{address:08X}..0x{address + length - 1:08X} ({length:,} Б)",
                    f"Reading memory 0x{address:08X}..0x{address + length - 1:08X} ({length:,} B)",
                ),
            )
            if output_file.exists():
                output_file.unlink()
            reporter.reset_stage_timer()
            reporter.progress(0, length, unit="B", detail=f"0x{address:08X}")
            collected = bytearray()
            offset = 0
            while offset < length:
                reporter.check_cancelled()
                cur_addr = address + offset
                step = min(READ_CHUNK_BYTES, length - offset)
                chunk = read_memory_bytes(link, cur_addr, step)
                with output_file.open("ab") as fh:
                    fh.write(chunk)
                collected.extend(chunk)
                offset += len(chunk)
                reporter.progress(offset, length, unit="B", detail=f"0x{cur_addr:08X}")

            raw = bytes(collected)
            report["bytes"] = len(raw)
            report["sha256"] = _digest(raw)
            reporter.success(
                tr(
                    f"Прочитано {len(raw):,} Б -> {output_file} (SHA-256: {report['sha256'][:16]}…)",
                    f"Read {len(raw):,} B -> {output_file} (SHA-256: {report['sha256'][:16]}…)",
                )
            )

            if return_to_app:
                reporter.step(3, total_steps, tr("Возврат шлюза в штатный режим (10 03)", "Returning gateway to normal Application mode (10 03)"))
                report["return_to_app"] = _reset_to_application(link, reporter=reporter)

            report["complete"] = True
            reporter.progress(100, 100)
            return report
        except Exception as exc:
            report["error"] = str(exc)
            raise
        finally:
            _write_json(out_dir / "read_mem_result.json", report)


def _execute_faci_payloads(
    link: J533CanLink,
    payloads: list[bytes],
    *,
    label: str,
    status_words: int = 3,
    reporter: OperationReporter = NULL_REPORTER,
) -> list[dict[str, Any]]:
    """Send 1..N FACI RAM-loader packets, verify 00 00 reply and FSTATR status at 0xFEDE9000."""
    packets_log: list[dict[str, Any]] = []
    total = len(payloads)
    for idx, payload in enumerate(payloads, start=1):
        reporter.check_cancelled()
        pkt_label = f"{label} ({idx}/{total})" if total > 1 else label
        link.send_loader_payload(payload, reporter=reporter, progress_label=pkt_label)
        resp_frame = bytes(link.receive_frame(link.LOADER_RX_ID, timeout=60.0).data)
        if resp_frame[:2] != b"\x00\x00":
            raise RuntimeError(f"{pkt_label} returned loader error frame: {resp_frame.hex()}")

        status_raw = read_memory_bytes(link, 0xFEDE9000, status_words * 4)
        marker = int.from_bytes(status_raw[0:4], "little")
        fstatr = int.from_bytes(status_raw[4:8], "little")
        last_offset = int.from_bytes(status_raw[8:12], "little") if status_words >= 3 else 0
        entry = {
            "packet_index": idx,
            "payload_bytes": len(payload),
            "payload_sha256": _digest(payload),
            "loader_response": resp_frame.hex(),
            "marker": marker,
            "fstatr": fstatr,
            "last_offset": last_offset,
        }
        packets_log.append(entry)
        if marker != 1 or (fstatr & 0x7000) != 0:
            raise RuntimeError(
                tr(
                    f"{pkt_label}: ошибка FACI: marker={marker}, FSTATR=0x{fstatr:08X}, last_offset=0x{last_offset:08X}",
                    f"{pkt_label} FACI status error: marker={marker}, FSTATR=0x{fstatr:08X}, last_offset=0x{last_offset:08X}",
                )
            )
    return packets_log


def can_write_uflash(
    port: str,
    *,
    input_uflash: bytes | Path | None = None,
    restore_stock: bool = False,
    raw_image: bool = False,
    interface: str = "slcan",
    session_dir: Path | None = None,
    skip_full_backup: bool = False,
    return_to_app: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Safely back up gateway, patch (or validate) 32 KB Uflash, program via FACI RAM payload, and verify."""
    verify_payload_self_tests()
    out_dir = session_dir or default_session_dir(None, "write_uflash")
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "complete": False,
        "session_dir": str(out_dir),
        "write_performed": False,
        "flash_commands_sent": False,
    }
    total_steps = 6 if return_to_app else 5

    with J533CanLink(port, interface=interface, log_path=out_dir / "can.jsonl") as link:
        try:
            reporter.step(1, total_steps, tr("Вход в заводской RAM-Loader по Diagnosis CAN", "Entering factory RAM-Loader over Diagnosis CAN"))
            result["loader_session"] = enter_ram_loader(link, reporter=reporter)

            reporter.step(2, total_steps, tr("Чтение текущего загрузчика Uflash из блока (32 КБ)", "Reading current physical Uflash from gateway (32 KB)"))
            backup_dir = out_dir / "backup"
            backup_dir.mkdir(parents=True, exist_ok=True)
            cur_uf_path = backup_dir / "Uflash_before.bin"
            read_memory_area(
                link,
                UFLASH_ADDR_START,
                UFLASH_ADDR_START + UFLASH_SIZE,
                cur_uf_path,
                label="Uflash (before)",
                reporter=reporter,
            )
            current_uf = cur_uf_path.read_bytes()
            validate_uflash_bytes(current_uf)
            result["before_uflash_sha256"] = _digest(current_uf)

            if input_uflash is None:
                source_uf = current_uf
            elif isinstance(input_uflash, Path):
                source_uf = input_uflash.read_bytes()
            else:
                source_uf = bytes(input_uflash)

            if raw_image:
                validate_uflash_bytes(source_uf)
                candidate = source_uf
                mod_desc = "raw validated Uflash image"
            else:
                candidate, mod_desc = apply_uflash_rsa_patch(source_uf, restore_stock=restore_stock)

            # Safety guard: unless raw_image is explicitly requested, candidate and physical Uflash
            # may ONLY differ in the 4-byte RSA comparison instruction at +0x342A..+0x342D!
            diffs = [i for i in range(UFLASH_SIZE) if current_uf[i] != candidate[i]]
            if not raw_image and any(not (UFLASH_RSA_CMP_OFFSET <= i < UFLASH_RSA_CMP_OFFSET + 4) for i in diffs):
                raise RuntimeError(
                    tr(
                        "Входной файл Uflash не принадлежит этому шлюзу (отличается за пределами +0x342A)! Запись заблокирована.",
                        "Input Uflash does not match physical Uflash outside +0x342A! Write refused for safety.",
                    )
                )

            cand_path = out_dir / ("Uflash_stock_candidate.bin" if restore_stock else "Uflash_engineering_candidate.bin")
            cand_path.write_bytes(candidate)
            result["candidate_path"] = str(cand_path)
            result["candidate_sha256"] = _digest(candidate)
            result["modification"] = mod_desc

            if current_uf == candidate:
                reporter.success(
                    tr(
                        "Нужная версия Uflash уже прошита в блоке — повторное стирание не требуется!",
                        "Target Uflash image is already programmed in gateway — skipping erase/write!",
                    )
                )
                result["already_matching"] = True
                result["step3_skipped_backup"] = True
            else:
                if not skip_full_backup:
                    reporter.step(3, total_steps, tr("Обязательный полный бэкап Cflash + Dflash перед стиранием Uflash", "Mandatory full Cflash + Dflash backup before erasing Uflash"))
                    read_memory_area(
                        link,
                        CFLASH_ADDR_START,
                        CFLASH_ADDR_START + CFLASH_SIZE,
                        backup_dir / "Cflash_before.bin",
                        label="Cflash Backup (1.5 MB)",
                        reporter=reporter,
                    )
                    read_memory_area(
                        link,
                        DFLASH_ADDR_START,
                        DFLASH_ADDR_START + DFLASH_SIZE,
                        backup_dir / "Dflash_before.bin",
                        label="Dflash Backup (64 KB)",
                        reporter=reporter,
                    )
                else:
                    reporter.step(3, total_steps, tr("Используется ранее созданный полный бэкап сессии", "Using existing full backup in session"))

                payloads, pages = build_uflash_faci_payloads(candidate)
                result["payload_sha256"] = _digest(payloads[0])
                result["pages_written"] = pages
                result["packet_count"] = len(payloads)

                reporter.step(
                    4,
                    total_steps,
                    tr(
                        f"Запись Uflash через FACI в RAM ({pages} стр. = {pages * 256:,} Б) — НЕ ОТКЛЮЧАЙТЕ ПИТАНИЕ!",
                        f"FACI Uflash programming in RAM ({pages} pages = {pages * 256:,} B) — DO NOT CUT POWER!",
                    ),
                )
                result["flash_commands_sent"] = True
                pkt_logs = _execute_faci_payloads(
                    link,
                    payloads,
                    label="FACI Uflash Packet",
                    status_words=2 if len(payloads) == 1 and pages <= 122 else 3,
                    reporter=reporter,
                )
                result["packets"] = pkt_logs
                result["loader_response"] = pkt_logs[-1]["loader_response"]
                result["marker"] = pkt_logs[-1]["marker"]
                result["fstatr"] = pkt_logs[-1]["fstatr"]
                result["write_performed"] = True
                reporter.success(
                    tr(
                        f"Запись FACI завершена штатно (marker=1, FSTATR=0x{result['fstatr']:04X})",
                        f"FACI programming completed cleanly (marker=1, FSTATR=0x{result['fstatr']:04X})",
                    )
                )

            reporter.step(5, total_steps, tr("Контрольное побайтовое вычитывание Uflash (32 КБ) и RSA-пробник", "Full 32 KB Uflash readback verification & RSA probe"))
            rb_path = out_dir / "Uflash_readback.bin"
            rb = read_memory_area(
                link,
                UFLASH_ADDR_START,
                UFLASH_ADDR_START + UFLASH_SIZE,
                rb_path,
                label="Uflash Readback",
                reference=candidate,
                reporter=reporter,
            )
            result["readback"] = rb
            if not rb.get("reference_match"):
                raise RuntimeError(f"Uflash readback mismatch at {rb.get('first_mismatch_address')!r}")

            rsa_res = run_rsa_probe(link, reporter=reporter)
            result["rsa_probe"] = rsa_res
            cand_bypassed = analyze_uflash(candidate).rsa_bypassed
            if cand_bypassed and rsa_res["rsa_status"] != 0:
                raise RuntimeError(f"Engineering RSA bypass did not activate: {rsa_res}")
            if not cand_bypassed and rsa_res["rsa_status"] == 0:
                raise RuntimeError("Stock RSA verification was requested, but rsa_status is still 0")

            if return_to_app:
                reporter.step(6, total_steps, tr("Перезапуск шлюза и проверка штатного режима (10 03 / 3E 00)", "Resetting gateway & verifying normal Application communication"))
                result["return_to_app"] = _reset_to_application(link, reporter=reporter)
                result["tester_present"] = link.request_uds(b"\x3e\x00", 0x7E, timeout=2.0).hex()

            result["complete"] = True
            reporter.progress(100, 100)
            reporter.success(
                tr(
                    "Загрузчик Uflash успешно прошит и побайтово верифицирован!",
                    "Uflash bootloader successfully programmed and verified byte-for-byte!",
                )
            )
            return result
        except Exception as exc:
            result["error"] = str(exc)
            raise
        finally:
            _write_json(out_dir / "uflash_write_result.json", result)


def _validate_dflash_candidate_blank_state(raw_cand: bytes) -> None:
    """Reject legacy un-blank-checked DataFlash dumps containing RV40F floating-gate read noise."""
    noisy_cp_slots = 0
    for off in range(0xC000, 0xCC00, 0x80):
        slot = raw_cand[off : off + 0x80]
        if slot != b"\xff" * 0x80 and slot[:4] != b"\x55\x55\x55\x55":
            noisy_cp_slots += 1
    if noisy_cp_slots >= 2:
        raise ValueError(
            tr(
                "Образ DataFlash содержит шум стёртых ячеек RV40F вместо FF..FF (старый дамп, вычитанный по шине CPU "
                "без аппаратного Blank Check 0x71). Снимите свежий бэкап DataFlash перед записью!",
                "Candidate DataFlash contains RV40F erased-cell read noise instead of FF..FF (legacy CPU-bus dump "
                "captured without hardware Blank Check 0x71). Read a fresh DataFlash backup before writing!",
            )
        )


def can_write_dflash(
    port: str,
    candidate_dflash: bytes | Path,
    *,
    expected_before_dflash: bytes | None = None,
    full_rewrite: bool = False,
    allow_icus_tail: bool = False,
    interface: str = "slcan",
    session_dir: Path | None = None,
    skip_full_backup: bool = False,
    no_enter: bool = False,
    return_to_app: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Program 64 KB DataFlash (`0xFF200000..0xFF20FFFF`) over CAN via RH850 FACI DataFlash P/E stub and verify."""
    verify_payload_self_tests()
    out_dir = session_dir or default_session_dir(None, "write_dflash")
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_cand = candidate_dflash.read_bytes() if isinstance(candidate_dflash, Path) else bytes(candidate_dflash)
    if len(raw_cand) != DFLASH_SIZE:
        raise ValueError(
            tr(
                f"Ожидается полный 64-КБ образ DataFlash ({DFLASH_SIZE:,} байт), получено {len(raw_cand):,} байт",
                f"Expected full 64 KB DataFlash image ({DFLASH_SIZE:,} bytes), got {len(raw_cand):,} bytes",
            )
        )
    if not allow_icus_tail and raw_cand[DFLASH_ICUS_RESERVED_OFFSET:] != b"\xff" * (DFLASH_SIZE - DFLASH_ICUS_RESERVED_OFFSET):
        raise ValueError(
            tr(
                f"Хвостовая область DataFlash 0x{DFLASH_ICUS_RESERVED_OFFSET:04X}..0xFFFF защищена аппаратно под ключи ICUSB и должна оставаться FF..FF",
                f"DataFlash tail 0x{DFLASH_ICUS_RESERVED_OFFSET:04X}..0xFFFF is hardware-guarded for ICUSB keys and must remain FF..FF",
            )
        )
    _validate_dflash_candidate_blank_state(raw_cand)

    result: dict[str, Any] = {
        "complete": False,
        "session_dir": str(out_dir),
        "write_performed": False,
        "flash_commands_sent": False,
        "full_rewrite": full_rewrite,
    }
    total_steps = 6 if return_to_app else 5

    with J533CanLink(port, interface=interface, log_path=out_dir / "can.jsonl") as link:
        try:
            if not no_enter:
                reporter.step(1, total_steps, tr("Вход в заводской RAM-Loader по Diagnosis CAN", "Entering factory RAM-Loader over Diagnosis CAN"))
                result["loader_session"] = enter_ram_loader(link, reporter=reporter)
            else:
                reporter.step(1, total_steps, tr("Проверка активного RAM-Loader (0x6F0)", "Checking active RAM-Loader (0x6F0)"))
                result["beacon"] = _probe_beacon_in_loader(link, reporter)

            reporter.step(2, total_steps, tr("Чтение текущего образа DataFlash из блока (64 КБ)", "Reading current physical DataFlash from gateway (64 KB)"))
            backup_dir = out_dir / "backup"
            backup_dir.mkdir(parents=True, exist_ok=True)
            cur_df_path = backup_dir / "Dflash_before.bin"
            read_memory_area(
                link,
                DFLASH_ADDR_START,
                DFLASH_ADDR_START + DFLASH_SIZE,
                cur_df_path,
                label="Dflash (before)",
                reporter=reporter,
            )
            current_df = cur_df_path.read_bytes()
            result["before_dflash_sha256"] = _digest(current_df)
            if expected_before_dflash is not None and current_df != expected_before_dflash:
                raise RuntimeError(
                    tr(
                        "Исходный файл DataFlash не совпадает с фактическим дампом в шлюзе! Запись остановлена для защиты данных.",
                        "Input base DataFlash differs from physical gateway DataFlash! Write refused for safety.",
                    )
                )

            tail = slice(DFLASH_ICUS_RESERVED_OFFSET, DFLASH_SIZE)
            if not allow_icus_tail and current_df[tail] != raw_cand[tail]:
                # Never programmed by us, but verified: a unit holding ICU-S data there would fail the readback after
                # every block was written. Read with the blank-check reader the tail is FF on every unit read so far.
                raise RuntimeError(
                    tr(
                        f"В защищённой области DataFlash 0x{DFLASH_ICUS_RESERVED_OFFSET:04X}..0xFFFF этого блока есть данные "
                        "(ключи ICU-S), а образ ожидает там FF. Запись остановлена до первой команды стирания.",
                        f"This ECU holds data (ICU-S keys) in the protected DataFlash area 0x{DFLASH_ICUS_RESERVED_OFFSET:04X}..0xFFFF "
                        "while the image expects FF there. Write stopped before any erase command.",
                    )
                )

            cand_path = out_dir / "Dflash_candidate.bin"
            cand_path.write_bytes(raw_cand)
            result["candidate_path"] = str(cand_path)
            result["candidate_sha256"] = _digest(raw_cand)

            limit = DFLASH_SIZE if allow_icus_tail else DFLASH_ICUS_RESERVED_OFFSET
            blocks_to_write: list[tuple[int, bytes]] = []
            for off in range(0, limit, DFLASH_BLOCK_SIZE):
                cand_blk = raw_cand[off : off + DFLASH_BLOCK_SIZE]
                if full_rewrite or current_df[off : off + DFLASH_BLOCK_SIZE] != cand_blk:
                    blocks_to_write.append((off, cand_blk))

            result["blocks_changed"] = len(blocks_to_write)
            result["block_offsets"] = [f"0x{off:04X}" for off, _ in blocks_to_write]

            if not blocks_to_write:
                reporter.success(
                    tr(
                        "Целевой образ DataFlash уже полностью совпадает с памятью шлюза — перезапись не требуется!",
                        "Candidate DataFlash already matches physical gateway memory — skipping erase/write!",
                    )
                )
                result["already_matching"] = True
            else:
                if not skip_full_backup:
                    reporter.step(3, total_steps, tr("Обязательный полный бэкап Cflash + Uflash перед записью DataFlash", "Mandatory full Cflash + Uflash backup before writing DataFlash"))
                    read_memory_area(
                        link,
                        CFLASH_ADDR_START,
                        CFLASH_ADDR_START + CFLASH_SIZE,
                        backup_dir / "Cflash_before.bin",
                        label="Cflash Backup (1.5 MB)",
                        reporter=reporter,
                    )
                    read_memory_area(
                        link,
                        UFLASH_ADDR_START,
                        UFLASH_ADDR_START + UFLASH_SIZE,
                        backup_dir / "Uflash_before.bin",
                        label="Uflash Backup (32 KB)",
                        reporter=reporter,
                    )
                else:
                    reporter.step(3, total_steps, tr("Используется ранее созданный полный бэкап сессии", "Using existing full backup in session"))

                selfid_16b = read_memory_bytes(link, SELFID_OFFSET, SELFID_SIZE)
                payloads = build_dflash_faci_payloads(
                    blocks_to_write,
                    flid_16b=selfid_16b,
                    allow_icus_tail=allow_icus_tail,
                )
                result["packet_count"] = len(payloads)

                reporter.step(
                    4,
                    total_steps,
                    tr(
                        f"Запись DataFlash через FACI ({len(blocks_to_write)} бл. × 64 Б = {len(blocks_to_write) * 64:,} Б) — НЕ ОТКЛЮЧАЙТЕ ПИТАНИЕ!",
                        f"Programming DataFlash via FACI ({len(blocks_to_write)} × 64 B = {len(blocks_to_write) * 64:,} B) — DO NOT CUT POWER!",
                    ),
                )
                result["flash_commands_sent"] = True
                pkt_logs = _execute_faci_payloads(
                    link,
                    payloads,
                    label="FACI DataFlash Packet",
                    status_words=3,
                    reporter=reporter,
                )
                result["packets"] = pkt_logs
                result["marker"] = pkt_logs[-1]["marker"]
                result["fstatr"] = pkt_logs[-1]["fstatr"]
                result["write_performed"] = True
                reporter.success(
                    tr(
                        f"Блоки DataFlash успешно записаны через FACI ({len(blocks_to_write)} бл., FSTATR=0x{result['fstatr']:04X})",
                        f"DataFlash blocks programmed cleanly via FACI ({len(blocks_to_write)} blocks, FSTATR=0x{result['fstatr']:04X})",
                    )
                )

            reporter.step(5, total_steps, tr("Контрольное побайтовое вычитывание всех 64 КБ DataFlash", "Full 64 KB DataFlash readback verification"))
            rb_path = out_dir / "Dflash_readback.bin"
            rb = read_memory_area(
                link,
                DFLASH_ADDR_START,
                DFLASH_ADDR_START + DFLASH_SIZE,
                rb_path,
                label="Dflash Readback (64 KB)",
                reference=raw_cand,
                reporter=reporter,
            )
            result["readback"] = rb
            if not rb.get("reference_match"):
                raise RuntimeError(
                    tr(
                        f"Сверка DataFlash не совпала по адресу {rb.get('first_mismatch_address')!r}",
                        f"DataFlash readback mismatch at {rb.get('first_mismatch_address')!r}",
                    )
                )

            if return_to_app:
                reporter.step(6, total_steps, tr("Перезапуск шлюза и проверка штатного режима (10 03 / 3E 00)", "Resetting gateway & verifying normal Application communication"))
                result["return_to_app"] = _reset_to_application(link, reporter=reporter)
                result["tester_present"] = link.request_uds(b"\x3e\x00", 0x7E, timeout=2.0).hex()

            result["complete"] = True
            reporter.progress(100, 100)
            reporter.success(
                tr(
                    "DataFlash (64 КБ) успешно записан по CAN и побайтово верифицирован!",
                    "DataFlash (64 KB) successfully programmed over CAN and verified byte-for-byte!",
                )
            )
            return result
        except Exception as exc:
            result["error"] = str(exc)
            raise
        finally:
            _write_json(out_dir / "dflash_write_result.json", result)


def _enter_fbl_uds_programming(link: J533CanLink, reporter: OperationReporter) -> None:
    """Enter FBL Programming Session (`10 02`) cleanly whether starting from Application or FBL."""
    try:
        link.request_uds(b"\x10\x03", 0x50, timeout=1.5)
        link.request_uds(b"\x27\x03", 0x67, timeout=2.0)
        link.request_uds(bytes.fromhex("2704caffe012"), 0x67, timeout=2.0)
        link.request_uds(bytes.fromhex("31010203"), 0x71, timeout=2.0)
    except RuntimeError:
        # Already in FBL Programming Session (where 10 03 returns NRC 0x7E)
        pass
    link.request_uds(b"\x10\x02", 0x50, timeout=5.0, allow_pending=True)
    time.sleep(1.0)


def _routine_ok(resp: bytes, label: str) -> None:
    if len(resp) < 4 or resp[0] != 0x71 or resp[1] != 0x01 or resp[-1] != 0x00:
        raise RuntimeError(f"{label} failed with routine response: {resp.hex()}")


def _bcd_byte(val: int) -> int:
    return ((val // 10) << 4) | (val % 10)


def _program_application_uds(
    link: J533CanLink,
    app_bytes: bytes,
    *,
    signature_128b: bytes | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Program 1,523,200-byte FD_0DATA (`0x0000C200..0x0017FFFF`) via standard VAG FBL UDS."""
    if len(app_bytes) != APP_SIZE:
        raise ValueError(f"Expected {APP_SIZE:,} bytes of Application data, got {len(app_bytes):,}")

    info: dict[str, Any] = {
        "security_unlocked": False,
        "fingerprint_written": False,
        "erase_completed": False,
        "download_accepted": False,
        "bytes_transferred": 0,
    }
    reporter.can_log(tr("Вход в сессию программирования FBL (10 02) и авторизация SA2 (27 11/12)…", "Entering FBL Programming Session (10 02) & unlocking SA2 (27 11/12)…"))
    _enter_fbl_uds_programming(link, reporter)
    seed_resp = link.request_uds(b"\x27\x11", 0x67, timeout=3.0)
    if len(seed_resp) != 6:
        raise RuntimeError(f"Unexpected FBL 27 11 seed response: {seed_resp.hex()}")
    seed = int.from_bytes(seed_resp[2:6], "big")
    if seed != 0:
        key = fbl_sa2(seed)
        link.request_uds(b"\x27\x12" + key.to_bytes(4, "big"), 0x67, timeout=3.0)
    info["security_unlocked"] = True

    # Write mandatory 9-byte VAG Fingerprint (DID 0xF15A: BCD YY MM DD + 6-byte tester serial)
    now = datetime.datetime.now(datetime.timezone.utc)
    fp = bytes([
        _bcd_byte(now.year % 100),
        _bcd_byte(now.month),
        _bcd_byte(now.day),
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    ])
    link.request_uds(b"\x2e\xf1\x5a" + fp, 0x6E, timeout=3.0)
    info["fingerprint_written"] = True

    reporter.can_log(
        tr(
            "Стирание прикладной области CodeFlash (31 01 FF 00 01 01: 0x0000C000..0x0017FFFF)…",
            "Erasing Application CodeFlash block (31 01 FF 00 01 01: 0x0000C000..0x0017FFFF)…",
        )
    )
    erase_resp = link.request_uds(bytes.fromhex("3101ff000101"), 0x71, timeout=120.0, allow_pending=True)
    _routine_ok(erase_resp, "EraseMemory (FF00)")
    info["erase_completed"] = True
    info["erase_response"] = erase_resp.hex()

    req_dl = b"\x34\x00\x44" + APP_BASE.to_bytes(4, "big") + APP_SIZE.to_bytes(4, "big")
    dl_resp = link.request_uds(req_dl, 0x74, timeout=5.0)
    len_bytes = dl_resp[1] >> 4
    if not (1 <= len_bytes <= 4) or len(dl_resp) < 2 + len_bytes:
        raise RuntimeError(f"Malformed RequestDownload response: {dl_resp.hex()}")
    max_block_len = int.from_bytes(dl_resp[2 : 2 + len_bytes], "big")
    # FBL ISO-TP RX buffer cap is 0x202 (514 bytes = 2-byte `36 <seq>` header + 512 payload bytes)
    chunk_size = min(512, ((max_block_len - 2) // 256) * 256)
    if chunk_size < 256:
        raise RuntimeError(f"FBL reported invalid maxNumberOfBlockLength={max_block_len}")
    info["download_accepted"] = True
    info["max_block_length"] = max_block_len
    info["chunk_size"] = chunk_size

    reporter.reset_stage_timer()
    reporter.progress(0, APP_SIZE, unit="B", detail="UDS TransferData (0x36)")
    total_blocks = (APP_SIZE + chunk_size - 1) // chunk_size
    for blk_idx, offset in enumerate(range(0, APP_SIZE, chunk_size)):
        reporter.check_cancelled()
        chunk = app_bytes[offset : offset + chunk_size]
        seq = (blk_idx + 1) & 0xFF
        link.request_uds(bytes([0x36, seq]) + chunk, 0x76, timeout=30.0, allow_pending=True)
        done = offset + len(chunk)
        info["bytes_transferred"] = done
        if blk_idx % 8 == 0 or done == APP_SIZE:
            reporter.progress(
                done,
                APP_SIZE,
                unit="B",
                detail=f"Block {blk_idx + 1}/{total_blocks} (seq 0x{seq:02X})",
            )
        if (blk_idx + 1) % 250 == 0 or done == APP_SIZE:
            reporter.can_log(
                tr(
                    f"TransferData: передано {done:,} / {APP_SIZE:,} Б (блок {blk_idx + 1}/{total_blocks})",
                    f"TransferData: sent {done:,} / {APP_SIZE:,} B (block {blk_idx + 1}/{total_blocks})",
                )
            )

    link.request_uds(b"\x37", 0x77, timeout=5.0)
    info["transfer_exit_ok"] = True
    info["blocks"] = total_blocks

    sig = signature_128b if (signature_128b and len(signature_128b) == 128) else (b"\x00" * 128)
    chk_mem_req = (
        bytes.fromhex("3101020244")
        + APP_BASE.to_bytes(4, "big")
        + APP_SIZE.to_bytes(4, "big")
        + (128).to_bytes(2, "big")
        + sig
    )
    reporter.can_log(tr("Проверка контрольной суммы и подписи в FBL (31 01 02 02)…", "Running FBL CheckMemory (31 01 02 02)…"))
    chk_resp = link.request_uds(chk_mem_req, 0x71, timeout=120.0, allow_pending=True)
    _routine_ok(chk_resp, "CheckMemory (0202)")
    info["check_memory_response"] = chk_resp.hex()

    reporter.can_log(tr("Проверка зависимостей и запись маркера присутствия (31 01 FF 01)…", "Running CheckProgrammingDependencies (31 01 FF 01)…"))
    dep_resp = link.request_uds(bytes.fromhex("3101ff01"), 0x71, timeout=60.0, allow_pending=True)
    _routine_ok(dep_resp, "CheckProgrammingDependencies (FF01)")
    info["dependencies_response"] = dep_resp.hex()

    try:
        info["reset_response"] = link.request_uds(b"\x11\x01", 0x51, timeout=2.0).hex()
    except TimeoutError:
        info["reset_response"] = "no response after reset"
    time.sleep(2.0)
    return info


def _program_cflash_blocks_in_loader(
    link: J533CanLink,
    expected_full: bytes,
    block_indices: list[int],
    *,
    flid_16b: bytes,
    reporter: OperationReporter = NULL_REPORTER,
) -> list[dict[str, Any]]:
    """Erase and program selected physical CodeFlash blocks directly in the 0x6F0 RAM-loader via FACI."""
    ranges = cflash_block_ranges()
    logs: list[dict[str, Any]] = []
    total = len(block_indices)
    for pos, blk_idx in enumerate(block_indices, start=1):
        _, start, end = ranges[blk_idx]
        block_bytes = expected_full[start:end]
        payloads = build_cflash_faci_block_payloads(start, block_bytes, flid_16b=flid_16b)
        size_kb = (end - start) // 1024
        reporter.can_log(
            tr(
                f"FACI CodeFlash блок #{blk_idx} ({pos}/{total}): 0x{start:06X}..0x{end - 1:06X} ({size_kb} КБ, пакетов: {len(payloads)})",
                f"FACI CodeFlash block #{blk_idx} ({pos}/{total}): 0x{start:06X}..0x{end - 1:06X} ({size_kb} KB, packets: {len(payloads)})",
            )
        )
        pkt_logs = _execute_faci_payloads(
            link,
            payloads,
            label=f"FACI CodeFlash Block #{blk_idx} (0x{start:06X})",
            status_words=3,
            reporter=reporter,
        )
        logs.append(
            {
                "block_index": blk_idx,
                "start": start,
                "end": end,
                "bytes": end - start,
                "packets": pkt_logs,
            }
        )
    return logs


FBL_VALIDITY_WORDS = (slice(0xC000, 0xC004), slice(0xC100, 0xC104))  # read by the FBL @ 0x1C32, written by it


def _same_but_validity_words(a: bytes, b: bytes) -> bool:
    a, b = bytearray(a), bytearray(b)
    for w in FBL_VALIDITY_WORDS:
        a[w] = b[w] = b"\xff" * 4
    return a == b


def _cflash_block_differs(physical: bytes, expected: bytes, start: int, end: int) -> bool:
    """Block 6 holds the FBL's validity words: they count only through the FBL's own rule, not byte for byte."""
    if start <= FBL_META_START < end:
        return not (fbl_app_valid(physical) and _same_but_validity_words(physical[start:end].rjust(end, b"\xff"),
                                                                          expected[start:end].rjust(end, b"\xff")))
    return physical[start:end] != expected[start:end]


def can_write_cflash(
    port: str,
    candidate_cflash: bytes | Path,
    *,
    expected_before_cflash: bytes | None = None,
    ignore_input_crc: bool = False,
    signature_128b: bytes | None = None,
    raw_faci: bool = False,
    preserve_selfid: bool = True,
    interface: str = "slcan",
    session_dir: Path | None = None,
    skip_backup: bool = False,
    return_to_app: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Back up gateway, program CodeFlash (including boot blocks 0x000000..0x00BFFF via FACI + FD_0DATA via UDS or raw FACI), and verify."""
    verify_payload_self_tests()
    out_dir = session_dir or default_session_dir(None, "write_cflash")
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_cand = candidate_cflash.read_bytes() if isinstance(candidate_cflash, Path) else bytes(candidate_cflash)
    prefix, app = split_cflash_or_app(raw_cand)
    stored_crc, calc_crc = app_crc(app)
    if not ignore_input_crc and stored_crc != calc_crc:
        raise RuntimeError(
            tr(
                f"Не совпадает App CRC-16 @ 0x0000C21C (в файле 0x{stored_crc:04X}, расчёт 0x{calc_crc:04X})! Прошивка отменена.",
                f"Application CRC-16 mismatch @ 0x0000C21C (stored 0x{stored_crc:04X}, calculated 0x{calc_crc:04X})! Flash aborted.",
            )
        )

    result: dict[str, Any] = {
        "complete": False,
        "session_dir": str(out_dir),
        "flash_commands_sent": False,
        "raw_faci": raw_faci,
    }
    total_steps = 6 if return_to_app else 5

    with J533CanLink(port, interface=interface, log_path=out_dir / "can.jsonl") as link:
        try:
            reporter.step(1, total_steps, tr("Вход в RAM-Loader и проверка загрузчика (RSA Probe)", "Entering RAM-Loader & probing bootloader state"))
            enter_ram_loader(link, reporter=reporter)
            rsa_res = run_rsa_probe(link, reporter=reporter)
            result["rsa_precheck"] = rsa_res

            backup_dir = out_dir / "backup"
            backup_dir.mkdir(parents=True, exist_ok=True)
            if not skip_backup or not prefix or not expected_before_cflash:
                reporter.step(2, total_steps, tr("Обязательный полный бэкап Cflash + Uflash + Dflash перед прошивкой", "Mandatory full Cflash + Uflash + Dflash backup before flashing"))
                cf_before_path = backup_dir / "Cflash_before.bin"
                read_memory_area(
                    link,
                    CFLASH_ADDR_START,
                    CFLASH_ADDR_START + CFLASH_SIZE,
                    cf_before_path,
                    label="Cflash Backup (1.5 MB)",
                    reporter=reporter,
                )
                if not skip_backup:
                    read_memory_area(
                        link,
                        UFLASH_ADDR_START,
                        UFLASH_ADDR_START + UFLASH_SIZE,
                        backup_dir / "Uflash_before.bin",
                        label="Uflash Backup (32 KB)",
                        reporter=reporter,
                    )
                    read_memory_area(
                        link,
                        DFLASH_ADDR_START,
                        DFLASH_ADDR_START + DFLASH_SIZE,
                        backup_dir / "Dflash_before.bin",
                        label="Dflash Backup (64 KB)",
                        reporter=reporter,
                    )
                physical_before = cf_before_path.read_bytes()
                if expected_before_cflash is not None and physical_before != expected_before_cflash:
                    raise RuntimeError(
                        tr(
                            "Исходный файл CodeFlash не совпадает с фактическим дампом в шлюзе! Запись остановлена для защиты блока.",
                            "Input base CodeFlash differs from physical gateway CodeFlash! Write refused for safety.",
                        )
                    )
                if not prefix:
                    prefix = physical_before[:APP_BASE]
            else:
                reporter.step(2, total_steps, tr("Проверка бэкапа текущей сессии", "Checking current session backup"))
                physical_before = expected_before_cflash

            live_selfid = physical_before[SELFID_OFFSET : SELFID_OFFSET + SELFID_SIZE]
            expected_full = bytearray(prefix + bytes(app))
            expected_full[0xC000:0xC004] = FBL_PRESENCE_MAGIC.to_bytes(4, "little")
            expected_full[0xC100:0xC104] = b"\xff\xff\xff\xff"
            if preserve_selfid and expected_full[SELFID_OFFSET : SELFID_OFFSET + SELFID_SIZE] != live_selfid:
                reporter.warning(
                    tr(
                        "В образе отличался 16-байтный SELFID @ 0x0000AB00 — автоматически сохранён родной SELFID процессора.",
                        "Candidate had a different 16-byte SELFID @ 0x0000AB00 — automatically preserved target MCU's native SELFID.",
                    )
                )
                expected_full[SELFID_OFFSET : SELFID_OFFSET + SELFID_SIZE] = live_selfid
                result["selfid_preserved"] = True

            cand_out = out_dir / "Cflash_candidate.bin"
            cand_out.write_bytes(expected_full)
            result["candidate_sha256"] = _digest(bytes(expected_full))

            ranges = cflash_block_ranges()
            changed_blocks = [
                idx for idx, start, end in ranges if _cflash_block_differs(physical_before, bytes(expected_full), start, end)
            ]
            boot_blocks = [idx for idx in changed_blocks if idx < 6]   # 0x000000..0x00BFFF (6 x 8 KB)
            app_blocks = [idx for idx in changed_blocks if idx >= 6]   # 0x00C000..0x17FFFF
            result["changed_blocks"] = changed_blocks
            result["changed_boot_blocks"] = boot_blocks
            result["changed_app_blocks"] = app_blocks

            if not changed_blocks:
                reporter.success(
                    tr(
                        "Подготовленный образ CodeFlash уже идентичен прошивке в шлюзе — перезапись не требуется!",
                        "Candidate CodeFlash already matches physical gateway firmware — skipping flash!",
                    )
                )
                result["already_matching"] = True
            elif raw_faci:
                reporter.step(
                    3,
                    total_steps,
                    tr(
                        f"Прямая запись изменённых блоков CodeFlash через FACI ({len(changed_blocks)} бл.) — НЕ ОТКЛЮЧАЙТЕ ПИТАНИЕ!",
                        f"Direct FACI programming of changed CodeFlash blocks ({len(changed_blocks)} blocks) — DO NOT CUT POWER!",
                    ),
                )
                result["flash_commands_sent"] = True
                result["faci_blocks"] = _program_cflash_blocks_in_loader(
                    link,
                    bytes(expected_full),
                    changed_blocks,
                    flid_16b=live_selfid,
                    reporter=reporter,
                )
                reporter.step(4, total_steps, tr("Прямая запись FACI завершена — переход к верификации", "Direct FACI write complete — proceeding to readback"))
                reporter.step(5, total_steps, tr("Побайтовая сверка всех 1.5 МБ CodeFlash", "Verifying full 1.5 MB CodeFlash readback"))
                rb_path = out_dir / "Cflash_readback.bin"
                rb = read_memory_area(
                    link,
                    CFLASH_ADDR_START,
                    CFLASH_ADDR_START + CFLASH_SIZE,
                    rb_path,
                    label="Cflash Readback (1.5 MB)",
                    reference=bytes(expected_full),
                    reporter=reporter,
                )
                result["readback"] = rb
                if not rb.get("reference_match"):
                    raise RuntimeError(f"CodeFlash readback mismatch at {rb.get('first_mismatch_address')!r}")
            else:
                if app_blocks and rsa_res["rsa_status"] != 0 and signature_128b is None:
                    raise RuntimeError(
                        tr(
                            "В загрузчике Uflash активна заводская проверка RSA-1024 (rsa_status != 0)! "
                            "Сначала активируйте инженерный Uflash, подпишите прошивку или укажите --raw-faci.",
                            "Stock RSA-1024 check is active in Uflash (rsa_status != 0)! "
                            "Unlock Engineering Uflash first, provide a valid signature, or use --raw-faci.",
                        )
                    )

                if boot_blocks:
                    reporter.step(
                        3,
                        total_steps,
                        tr(
                            f"Запись области загрузчика CodeFlash через FACI (блоки {boot_blocks}) — НЕ ОТКЛЮЧАЙТЕ ПИТАНИЕ!",
                            f"Programming CodeFlash boot blocks via FACI (blocks {boot_blocks}) — DO NOT CUT POWER!",
                        ),
                    )
                    result["flash_commands_sent"] = True
                    result["boot_faci_blocks"] = _program_cflash_blocks_in_loader(
                        link,
                        bytes(expected_full),
                        boot_blocks,
                        flid_16b=live_selfid,
                        reporter=reporter,
                    )
                else:
                    reporter.step(3, total_steps, tr("Область загрузчика 0x000000..0x00BFFF без изменений", "Boot region 0x000000..0x00BFFF unchanged"))

                if app_blocks:
                    _reset_to_application(link, reporter=reporter)
                    reporter.step(
                        4,
                        total_steps,
                        tr(
                            "Прошивка прикладной области CodeFlash (1 523 200 Б) по штатному UDS — НЕ ОТКЛЮЧАЙТЕ ПИТАНИЕ!",
                            "Programming Application CodeFlash (1,523,200 B) via UDS — DO NOT DISCONNECT POWER!",
                        ),
                    )
                    result["flash_commands_sent"] = True
                    result["uds_programming"] = _program_application_uds(
                        link,
                        bytes(app),
                        signature_128b=signature_128b,
                        reporter=reporter,
                    )
                    reporter.step(5, total_steps, tr("Повторный вход в RAM-Loader и побайтовая сверка всех 1.5 МБ CodeFlash", "Re-entering RAM-Loader & verifying full 1.5 MB CodeFlash readback"))
                    enter_ram_loader(link, reporter=reporter)
                else:
                    reporter.step(4, total_steps, tr("Прикладная область 0x00C200..0x17FFFF без изменений — UDS перезапись не требуется", "Application area 0x00C200..0x17FFFF unchanged — skipping UDS reflash"))
                    reporter.step(5, total_steps, tr("Побайтовая сверка всех 1.5 МБ CodeFlash", "Verifying full 1.5 MB CodeFlash readback"))

                rb_path = out_dir / "Cflash_readback.bin"
                rb = read_memory_area(
                    link,
                    CFLASH_ADDR_START,
                    CFLASH_ADDR_START + CFLASH_SIZE,
                    rb_path,
                    label="Cflash Readback (1.5 MB)",
                    reference=bytes(expected_full),
                    reporter=reporter,
                )
                result["readback"] = rb
                if not rb.get("reference_match"):
                    actual = rb_path.read_bytes()
                    # The FBL sets its own validity words (0xC000 / 0xC100) during 34/36/37: accept a difference only
                    # there, and only if the FBL's own rule then calls the application valid.
                    if not (app_blocks and _same_but_validity_words(actual, bytes(expected_full)) and fbl_app_valid(actual)):
                        raise RuntimeError(f"CodeFlash readback mismatch at {rb.get('first_mismatch_address')!r}")
                    result["fbl_validity_words"] = actual[FBL_META_START : FBL_META_START + 4].hex() + "/" + actual[0xC100:0xC104].hex()
                    reporter.info(
                        tr(
                            "Загрузчик сам выставил флаг действительности приложения (0xC000/0xC100) — остальное совпало побайтово",
                            "The bootloader set its own application-valid flag (0xC000/0xC100) — everything else matches byte for byte",
                        )
                    )

            if return_to_app:
                reporter.step(6, total_steps, tr("Запуск шлюза и финальная диагностика приложения (10 03 / 3E 00)", "Restarting gateway & running post-flash Application health check"))
                result["post_health"] = _reset_to_application(link, reporter=reporter)
                result["tester_present"] = link.request_uds(b"\x3e\x00", 0x7E, timeout=2.0).hex()

            result["complete"] = True
            reporter.progress(100, 100)
            reporter.success(
                tr(
                    "CodeFlash успешно прошит и побайтово верифицирован по всем 1.5 МБ!",
                    "CodeFlash programmed and verified byte-for-byte across all 1.5 MB!",
                )
            )
            return result
        except Exception as exc:
            result["error"] = str(exc)
            raise
        finally:
            _write_json(out_dir / "cflash_write_result.json", result)


def _fazit(raw: bytes) -> str:
    return raw.decode("ascii").strip() if all(0x20 <= b < 0x7F for b in raw) else ""


def _vcrn(df: bytes) -> str:
    vcrn = analyze_dflash_swap(df).vcrn
    return vcrn.hex().upper() if vcrn not in (b"", b"\x00" * 5, b"\xff" * 5) else ""


def backup_identity(cflash: bytes | None, dflash: bytes | None) -> dict[str, str | None]:
    """FAZIT (CodeFlash 0xA240) and VCRN (DataFlash NvM 0x7C) of a backup: None = not in it, "" = blank."""
    fazit = vcrn = None
    if cflash is not None:
        prefix, _app = split_cflash_or_app(cflash)
        fazit = _fazit(prefix[FAZIT_OFFSET : FAZIT_OFFSET + FAZIT_SIZE]) if prefix else None  # an app-only image keeps the ECU's
    if dflash is not None:
        vcrn = _vcrn(dflash)
    return {"fazit": fazit, "vcrn": vcrn}


def backup_owner_problems(ecu: dict[str, str], backup: dict[str, str | None], writes: set[str]) -> list[str]:
    """Why this backup must not go into this ECU; empty when at least one of FAZIT/VCRN matches and nothing differs."""
    problems: list[str] = []
    matched = False
    for name, key, kind in (("FAZIT", "fazit", "cflash"), ("VCRN", "vcrn", "dflash")):
        mine, theirs = ecu[key], backup[key]
        if mine and theirs:
            if mine == theirs:
                matched = True
            else:
                problems.append(
                    tr(
                        f"{name} в бэкапе {theirs}, а в блоке {mine} — бэкап снят с другого блока",
                        f"the backup has {name} {theirs} but the ECU has {mine} — it was taken from another ECU",
                    )
                )
        elif mine and theirs == "" and kind in writes:
            problems.append(
                tr(
                    f"в бэкапе нет {name}, а в блоке он есть ({mine}) — запись стёрла бы его",
                    f"the backup has no {name} but the ECU has one ({mine}) — writing it would erase it",
                )
            )
    if not matched and not problems:
        problems.append(
            tr(
                "нельзя убедиться, что бэкап снят с этого блока: ни FAZIT, ни VCRN не с чем сравнить",
                "cannot confirm the backup was taken from this ECU: neither FAZIT nor VCRN can be compared",
            )
        )
    return problems


def can_restore_backup(
    port: str,
    files: dict[str, Path],
    writes: list[str],
    *,
    interface: str = "slcan",
    session_dir: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Write `writes` (cflash/dflash/uflash) of a backup of this very ECU back into it.

    `files` is the whole backup (its CodeFlash and DataFlash carry FAZIT and VCRN even when not written). Before any
    write command the ECU's own FAZIT and VCRN are read through the RAM-Loader; a backup of another ECU is refused.
    The writes are the same as "Write to ECU": each takes its backup, programs only differing blocks and verifies.
    CodeFlash goes in through the engineering bootloader; afterwards the backup's bootloader is written, or, when
    Uflash is not restored, the one the ECU had — so the ECU never keeps a bootloader the user did not choose."""
    verify_payload_self_tests()
    out_dir = session_dir or default_session_dir(None, "restore")
    own_dir = out_dir / "owner"
    own_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_identity(
        files["cflash"].read_bytes() if "cflash" in files else None,
        files["dflash"].read_bytes() if "dflash" in files else None,
    )
    cf_chunk = FAZIT_OFFSET & ~(READ_CHUNK_BYTES - 1)
    df_chunk = DFLASH_SWAP_NVM_OFF & ~(READ_CHUNK_BYTES - 1)
    with J533CanLink(port, interface=interface, log_path=own_dir / "can.jsonl") as link:
        reporter.step(1, 1, tr("Проверка, что бэкап снят с этого блока (FAZIT и VCRN)", "Checking the backup was taken from this ECU (FAZIT and VCRN)"))
        enter_ram_loader(link, reporter=reporter)
        cf_path, df_path = own_dir / "Cflash_fazit.bin", own_dir / "Dflash_vcrn.bin"
        read_memory_area(link, CFLASH_ADDR_START + cf_chunk, CFLASH_ADDR_START + cf_chunk + READ_CHUNK_BYTES, cf_path, label="FAZIT", reporter=reporter)
        read_memory_area(link, DFLASH_ADDR_START + df_chunk, DFLASH_ADDR_START + df_chunk + READ_CHUNK_BYTES, df_path, label="VCRN", reporter=reporter)
        _reset_to_application(link, reporter=reporter)
    at = FAZIT_OFFSET - cf_chunk
    df = bytearray(b"\xff" * DFLASH_SIZE)
    df[df_chunk : df_chunk + READ_CHUNK_BYTES] = df_path.read_bytes()
    ecu = {"fazit": _fazit(cf_path.read_bytes()[at : at + FAZIT_SIZE]), "vcrn": _vcrn(bytes(df))}
    result: dict[str, Any] = {"session_dir": str(out_dir), "ecu": ecu, "backup": backup, "writes": list(writes)}
    _write_json(own_dir / "owner.json", result)
    reporter.info(f"FAZIT: {ecu['fazit'] or '—'} / {backup['fazit'] or '—'}   VCRN: {ecu['vcrn'] or '—'} / {backup['vcrn'] or '—'}")
    problems = backup_owner_problems(ecu, backup, set(writes))
    if problems:
        raise RuntimeError(tr("Бэкап не записан: ", "The backup was not written: ") + "; ".join(problems))
    reporter.success(tr("Бэкап снят с этого блока — записываем", "The backup belongs to this ECU — writing it"))

    did_backup = False
    try:
        if "cflash" in writes:
            result["uflash_engineering"] = can_write_uflash(
                port, restore_stock=False, interface=interface, session_dir=out_dir / "uflash_eng", reporter=reporter
            )
            result["cflash"] = can_write_cflash(
                port, files["cflash"], interface=interface, session_dir=out_dir / "cflash", reporter=reporter
            )
            did_backup = True
        if "dflash" in writes:
            result["dflash"] = can_write_dflash(
                port, files["dflash"], interface=interface, session_dir=out_dir / "dflash", skip_full_backup=did_backup, reporter=reporter
            )
            did_backup = True
    except Exception:
        if result.get("uflash_engineering", {}).get("write_performed"):
            # Deliberately not put back: with the factory bootloader a half-written application could not be
            # programmed again over UDS. The engineering one lets the user simply repeat the restore.
            reporter.warning(
                tr(
                    "В блоке оставлен инженерный загрузчик: с ним заливку можно повторить. После удачной заливки "
                    "вернётся прежний загрузчик.",
                    "The engineering bootloader stays in the ECU so the restore can be repeated. A successful restore "
                    "puts the previous bootloader back.",
                )
            )
        _write_json(own_dir / "owner.json", result)
        raise
    # The bootloader goes last: the backup's own, or the one the ECU had if CodeFlash needed the engineering one.
    eng = result.get("uflash_engineering", {})
    uflash = files.get("uflash") if "uflash" in writes else None
    if uflash is None and eng.get("write_performed"):
        uflash = out_dir / "uflash_eng" / "backup" / "Uflash_before.bin"
        reporter.info(tr("Возвращаем загрузчик, который был в блоке до заливки", "Putting back the bootloader the ECU had before"))
    if uflash is not None:
        result["uflash"] = can_write_uflash(
            port,
            input_uflash=uflash,
            raw_image=True,
            interface=interface,
            session_dir=out_dir / "uflash",
            skip_full_backup=did_backup,
            reporter=reporter,
        )
    _write_json(own_dir / "owner.json", result)
    return result


def can_turnkey_read_patch_flash(
    port: str,
    *,
    patch_cp_hybrid: bool = True,
    bypass_eeprom_mask: bool = False,
    patch_engineering_cflash: bool = True,
    unlock_engineering_uflash: bool = True,
    cp_updates: list[tuple[Any, bytes]] | None = None,
    clear_dtc_after: bool = True,
    interface: str = "slcan",
    session_dir: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Foolproof 1-Click CAN Turnkey Wizard:
    1. Reads complete backup (`Cflash.bin` 1.5 MB + `Uflash.bin` 32 KB + `Dflash.bin` 64 KB).
    2. Unlocks Engineering RSA-Free `Uflash` if needed.
    3. Optionally writes 16-byte plaintext IKA keys into `DataFlash` over CAN via FACI.
    4. Applies selected ContiTool patches (`Hybrid CP` / `95640 mask` / `Engineering Mode`) to `Cflash` & flashes via CAN!
    5. Runs post-flash Gateway Health Check & optional Clear DTC.
    """
    from contitool.core.patcher import apply_cflash_patch

    out_dir = session_dir or default_session_dir(None, "turnkey_can")
    out_dir.mkdir(parents=True, exist_ok=True)
    backup_dir = out_dir / "01_full_backup"

    summary: dict[str, Any] = {
        "complete": False,
        "session_dir": str(out_dir),
        "backup_dir": str(backup_dir),
    }

    reporter.info(
        tr(
            "═══ ШАГ A: ПОЛНЫЙ БЭКАП ШЛЮЗА (Cflash + Uflash + Dflash) ═══",
            "═══ PHASE A: FULL GATEWAY BACKUP (Cflash + Uflash + Dflash) ═══",
        )
    )
    bkp = can_backup(
        port,
        interface=interface,
        session_dir=backup_dir,
        return_to_app=False,
        reporter=reporter,
    )
    summary["backup"] = bkp

    orig_cf = (backup_dir / "Cflash.bin").read_bytes()
    orig_uf = (backup_dir / "Uflash.bin").read_bytes()
    orig_df = (backup_dir / "Dflash.bin").read_bytes()

    need_cflash = bool(patch_cp_hybrid or patch_engineering_cflash or cp_updates)
    if unlock_engineering_uflash or need_cflash:
        reporter.info(
            tr(
                "═══ ШАГ B: РАЗБЛОКИРОВКА ИНЖЕНЕРНОГО ЗАГРУЗЧИКА UFLASH ═══",
                "═══ PHASE B: UNLOCKING ENGINEERING RSA-FREE UFLASH ═══",
            )
        )
        uf_res = can_write_uflash(
            port,
            input_uflash=orig_uf,
            restore_stock=False,
            interface=interface,
            session_dir=out_dir / "02_uflash_unlock",
            skip_full_backup=True,
            return_to_app=not bool(cp_updates),
            reporter=reporter,
        )
        summary["uflash_unlock"] = uf_res

    if cp_updates:
        reporter.info(
            tr(
                "═══ ШАГ B2: ЗАПИСЬ КЛЮЧЕЙ IKA В DATAFLASH ЧЕРЕЗ FACI ═══",
                "═══ PHASE B2: WRITING IKA KEYS TO DATAFLASH VIA FACI ═══",
            )
        )
        mod_df, _ = write_dflash_slots(orig_df, cp_updates, reporter=reporter)
        patched_df_path = out_dir / "Dflash_patched.bin"
        patched_df_path.write_bytes(mod_df)
        summary["patched_dflash_path"] = str(patched_df_path)
        df_res = can_write_dflash(
            port,
            mod_df,
            expected_before_dflash=orig_df,
            interface=interface,
            session_dir=out_dir / "02b_dflash_flash",
            skip_full_backup=True,
            return_to_app=True,
            reporter=reporter,
        )
        summary["dflash_flash"] = df_res

    if need_cflash:
        reporter.info(
            tr(
                "═══ ШАГ C: ПАТЧИНГ И ПРОШИВКА CODEFLASH ПО CAN ═══",
                "═══ PHASE C: PATCHING & FLASHING CODEFLASH OVER CAN ═══",
            )
        )
        mod_cf = orig_cf
        applied_descriptions: list[str] = []
        if patch_cp_hybrid or cp_updates:
            mod_cf, desc_cp, _ = apply_cflash_patch(
                mod_cf,
                mode="hybrid",
                bypass_eeprom_mask=bypass_eeprom_mask,
                preserve_existing_mask_bypass=True,
            )
            applied_descriptions.append(desc_cp)
        if patch_engineering_cflash:
            mod_cf, desc_eng, _ = apply_engineering_patch(mod_cf)
            applied_descriptions.append(desc_eng)

        patched_path = out_dir / "Cflash_patched.bin"
        patched_path.write_bytes(mod_cf)
        summary["patched_cflash_path"] = str(patched_path)
        summary["applied_patches"] = applied_descriptions

        cf_res = can_write_cflash(
            port,
            mod_cf,
            expected_before_cflash=orig_cf,
            interface=interface,
            session_dir=out_dir / "03_cflash_flash",
            skip_backup=True,
            reporter=reporter,
        )
        summary["cflash_flash"] = cf_res

    reporter.info(
        tr(
            "═══ ШАГ D: ФИНАЛЬНАЯ ПРОВЕРКА ШЛЮЗА И ОШИБОК DTC ═══",
            "═══ PHASE D: FINAL GATEWAY HEALTH & DTC CHECK ═══",
        )
    )
    hlth = can_health_check(
        port,
        interface=interface,
        session_dir=out_dir / "04_health",
        clear_dtc=clear_dtc_after,
        reporter=reporter,
    )
    summary["health"] = hlth
    summary["complete"] = True
    _write_json(out_dir / "turnkey_summary.json", summary)
    return summary


# ═══════════════════════════════════════════════════════════════════════════════
# Live OBD / Bench ZDC Dataset Upload, MFL Button Learn & Gateway Coding (0x0600)
# ═══════════════════════════════════════════════════════════════════════════════

ZDC_SECURITY_ACCESS_PIN = 20103
ZDC_UPLOAD_CHUNK_SIZE = 0xF0


def _transfer_chunk(dl_resp: bytes, preferred: int) -> int:
    """TransferData payload size for a 74 reply: ISO 14229 maxNumberOfBlockLength counts the 36 SID + sequence byte.
    Same parsing as the hardware-verified FBL path in _program_application_uds; never more than `preferred`."""
    len_bytes = dl_resp[1] >> 4 if len(dl_resp) >= 2 else 0
    if not (1 <= len_bytes <= 4) or len(dl_resp) < 2 + len_bytes:
        raise RuntimeError(f"Malformed RequestDownload response: {dl_resp.hex()}")
    max_block_len = int.from_bytes(dl_resp[2 : 2 + len_bytes], "big")
    if max_block_len < 3:
        raise RuntimeError(f"ECU reported invalid maxNumberOfBlockLength={max_block_len}")
    return min(preferred, max_block_len - 2)


def _uds_security_20103(link: J533CanLink, *, reporter: OperationReporter = NULL_REPORTER) -> None:
    """Unlock Application SecurityAccess Level 1 (`27 01/02`, code `20103`: `key = (seed + 20103) & 0xFFFFFFFF`)."""
    resp = link.request_uds(b"\x27\x01", 0x67, timeout=3.0)
    if len(resp) < 6:
        raise RuntimeError(f"Malformed 27 01 response: {resp.hex()}")
    seed = int.from_bytes(resp[2:6], "big")
    if seed != 0:
        key = (seed + ZDC_SECURITY_ACCESS_PIN) & 0xFFFFFFFF
        link.request_uds(b"\x27\x02" + key.to_bytes(4, "big"), 0x67, timeout=3.0)
    reporter.can_log(tr("Доступ безопасности 20103 открыт (0x67)", "SecurityAccess 20103 unlocked (0x67)"))


def _uds_write_workshop_fingerprint(link: J533CanLink) -> None:
    """Write standard 6-byte tester fingerprint (`F198`) and 3-byte BCD date (`F199`) before DataFlash writes."""
    link.request_uds(bytes.fromhex("2EF198010203040506"), 0x6E, timeout=3.0, allow_pending=True)
    now = datetime.datetime.now(datetime.timezone.utc)  # one clock read (UTC, as F15A): never an impossible date
    date = bytes(_bcd_byte(v) for v in (now.year % 100, now.month, now.day))
    link.request_uds(bytes([0x2E, 0xF1, 0x99]) + date, 0x6E, timeout=3.0, allow_pending=True)


def can_upload_zdc_datasets(
    port: str,
    dflash_bytes: bytes,
    *,
    blocks: tuple[int, ...] | list[int] | None = None,
    write_passport: bool = True,
    reset_after: bool = True,
    interface: str = "slcan",
    bus: Any | None = None,
    session_dir: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Upload ZDC dataset blocks directly over standard Application UDS (`10 40` + `27 01/02` `20103` + `34/36/37` + `02EF`).

    No boot mode, no RAM-loader, and no RSA signature required — verified directly by trailing LE CRC-32 per block."""
    validate_dflash_bytes(dflash_bytes)
    spec_names = {s[0]: s[1] for s in ZDC_DATASET_SPECS}
    cand_blocks = [0, 1, 2, 3, 4, 5, 6] if blocks is None else sorted({int(b) for b in blocks})

    to_upload: list[tuple[int, str, int, int, bytes]] = []
    for idx in cand_blocks:
        if idx not in ZDC_UDS_UPLOAD_MAP:
            raise ValueError(f"Unsupported ZDC block index: {idx}")
        uds_addr, uds_len = ZDC_UDS_UPLOAD_MAP[idx]
        payload = export_zdc_block(dflash_bytes, idx)
        if all(b == 0xFF for b in payload):
            continue
        crc_st = int.from_bytes(payload[-4:], "little")
        crc_ca = zdc_crc32_le(payload[:-4])
        if crc_st != crc_ca:
            raise ValueError(
                tr(
                    f"Блок ZDC #{idx} ({spec_names.get(idx, '')}) имеет неверный CRC-32 (0x{crc_st:08X} != 0x{crc_ca:08X}).",
                    f"ZDC #{idx} ({spec_names.get(idx, '')}) has invalid CRC-32 (0x{crc_st:08X} != 0x{crc_ca:08X}).",
                )
            )
        to_upload.append((idx, spec_names.get(idx, f"ZDC{idx}"), uds_addr, uds_len, payload))

    if not to_upload:
        raise ValueError(
            tr(
                "В открытом дампе нет заполненных блоков ZDC для загрузки по CAN.",
                "No populated ZDC blocks found in the loaded DataFlash to upload over CAN.",
            )
        )

    out_dir = session_dir or (default_session_dir(None, "zdc_upload") if bus is None else None)
    log_path = (out_dir / "can.jsonl") if out_dir is not None else None
    total_steps = len(to_upload) + (3 if write_passport else 2)

    result: dict[str, Any] = {
        "complete": False,
        "uploaded_blocks": [],
        "passport_written": False,
    }
    if out_dir is not None:
        result["session_dir"] = str(out_dir)

    with J533CanLink(port, interface=interface, bus=bus, log_path=log_path) as link:
        reporter.step(1, total_steps, tr("Вход в EOL-сессию (UDS 10 40) и авторизация 20103", "Entering EOLSession (UDS 10 40) & SecurityAccess 20103"))
        link.request_uds(b"\x10\x40", 0x50, timeout=3.0)
        _uds_security_20103(link, reporter=reporter)
        _uds_write_workshop_fingerprint(link)
        reporter.progress(12, 100)

        for pos, (idx, code, uds_addr, uds_len, payload) in enumerate(to_upload, start=2):
            reporter.step(
                pos,
                total_steps,
                tr(
                    f"Передача и проверка CRC-32 ZDC #{idx} ({code}, {uds_len} Б -> 0x{uds_addr:08X})",
                    f"Uploading & verifying CRC-32 for ZDC #{idx} ({code}, {uds_len} B -> 0x{uds_addr:08X})",
                ),
            )
            req34 = b"\x34\x00\x44" + uds_addr.to_bytes(4, "big") + uds_len.to_bytes(4, "big")
            dl_resp = link.request_uds(req34, 0x74, timeout=3.0, allow_pending=True)
            chunk_size = _transfer_chunk(dl_resp, ZDC_UPLOAD_CHUNK_SIZE)
            seq = 1
            for off in range(0, len(payload), chunk_size):
                chunk = payload[off : off + chunk_size]
                link.request_uds(bytes([0x36, seq & 0xFF]) + chunk, 0x76, timeout=5.0, allow_pending=True)
                seq = (seq + 1) & 0xFF
            link.request_uds(b"\x37", 0x77, timeout=5.0, allow_pending=True)

            # Continental J533 requires per-block CheckMemory (0x02EF) right after each 0x37:
            # clears transfer-complete latch (preventing NRC 0x22 on next 0x34) and validates block CRC-32.
            # On real hardware: 71 03 02 EF 02 FF FF = CRC PASS; 71 03 02 EF 02 00 00 = CRC FAIL.
            link.request_uds(bytes.fromhex("310102EF031000"), 0x71, timeout=5.0, allow_pending=True)
            for _ in range(25):
                r_poll = link.request_uds(bytes.fromhex("310302EF"), 0x71, timeout=3.0, allow_pending=True)
                if len(r_poll) < 5:
                    raise RuntimeError(f"Malformed 31 03 02 EF response: {r_poll.hex()}")
                if r_poll[4] == 0x01:
                    if bus is None:
                        time.sleep(0.05)
                    continue
                if r_poll[4] == 0x02:
                    if len(r_poll) < 7 or r_poll[5:7] != b"\xff\xff":
                        err_hex = r_poll[5:7].hex().upper() if len(r_poll) >= 7 else r_poll.hex().upper()
                        raise RuntimeError(
                            tr(
                                f"Шлюз отклонил CRC-32 блока ZDC #{idx} ({code}) при проверке 02EF (статус {err_hex})",
                                f"Gateway CheckMemory 02EF rejected CRC-32 for ZDC #{idx} ({code}) (status {err_hex})",
                            )
                        )
                    break
                raise RuntimeError(f"Unexpected 31 03 02 EF status: {r_poll.hex()}")
            else:
                raise TimeoutError(f"CheckMemory routine 0x02EF timed out in status 0x01 for ZDC #{idx}")

            result["uploaded_blocks"].append({"idx": idx, "code": code, "uds_addr": f"0x{uds_addr:08X}", "size": uds_len})
            reporter.info(tr(f"ZDC #{idx} ({code}) принят, проверен 02EF (FFFF) и сохранён в DataFlash", f"ZDC #{idx} ({code}) accepted, verified by 02EF (FFFF), and committed to DataFlash"))
            reporter.progress(12 + int(76 * (pos - 1) / len(to_upload)), 100)

        if write_passport:
            pp = parse_zdc_passport(dflash_bytes)
            pn_str = (pp.dataset_pn or "V03935256AA")[:11]
            ver_str = pp.dataset_ver if (len(pp.dataset_ver) == 4 and pp.dataset_ver != "0000") else "0001"
            eq_12 = pp.equip_bytes if len(pp.equip_bytes) == 12 else (b"\xff" * 12)

            reporter.step(
                len(to_upload) + 2,
                total_steps,
                tr(f"Фиксация паспорта датасета F1A0={pn_str} / F1A1={ver_str}", f"Sealing dataset passport F1A0={pn_str} / F1A1={ver_str}"),
            )
            link.request_uds(b"\x2E\xF1\xA0" + pn_str.encode("ascii").ljust(11, b" "), 0x6E, timeout=5.0, allow_pending=True)
            link.request_uds(b"\x2E\xF1\xA1" + ver_str.encode("ascii"), 0x6E, timeout=5.0, allow_pending=True)
            link.request_uds(b"\x2E\xF1\xA4" + eq_12, 0x6E, timeout=5.0, allow_pending=True)
            result["passport_written"] = True
            result["dataset_pn"] = pn_str
            result["dataset_ver"] = ver_str

        if reset_after:
            reporter.step(total_steps, total_steps, tr("Перезагрузка шлюза для применения датасета (UDS 11 02)", "Resetting gateway to reload dataset tables (UDS 11 02)"))
            try:
                link.request_uds(b"\x11\x02", 0x51, timeout=2.0, allow_pending=True)
            except LINK_ERRORS:
                try:
                    link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
                except LINK_ERRORS:
                    pass
            if bus is None:
                time.sleep(1.2)

        result["complete"] = True
        reporter.progress(100, 100)
        reporter.success(
            tr(
                f"Параметрия ZDC успешно загружена по CAN (блоков: {len(to_upload)})!",
                f"ZDC parameterization uploaded over CAN ({len(to_upload)} block(s))!",
            )
        )
    if out_dir is not None:
        _write_json(out_dir / "zdc_upload_result.json", result)
    return result


def _gra_button_signature(data8: bytes) -> bytes:
    """Mask out `GRA_Neu` E2E CRC (`byte 0`) and 4-bit rolling counter `BZ` (`byte 1 bits 0..3`)."""
    if len(data8) < 2:
        return b""
    return bytes([data8[1] & 0xF0]) + data8[2:]


def can_learn_mfl_button(
    port: str,
    *,
    timeout_s: float = 12.0,
    interface: str = "slcan",
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Poll live steering-wheel LIN frames (`DID 0x1F07` `MFL_01` & `DID 0x1F19` `GRA_Neu`) to capture a button press."""
    preset_labels = {code: (ru, en) for code, ru, en in MFL_KEYCODE_PRESETS}
    with J533CanLink(port, interface=interface, bus=bus) as link:
        reporter.step(
            1,
            2,
            tr(
                "Опрос шины LIN рулевого колеса (DID 0x1F07 / 0x1F19)…",
                "Connecting to steering-wheel LIN monitor (DID 0x1F07 / 0x1F19)…",
            ),
        )
        link.request_uds(b"\x10\x03", 0x50, timeout=2.0)

        base_mfl = link.request_uds(b"\x22\x1F\x07", 0x62, timeout=2.0)[3:]
        if len(base_mfl) < 4:
            raise RuntimeError(f"Unexpected 22 1F 07 payload length: {base_mfl.hex()}")

        gra_base_sig: bytes | None = None
        try:
            base_gra = link.request_uds(b"\x22\x1F\x19", 0x62, timeout=1.5)[3:]
            if len(base_gra) >= 4:
                gra_base_sig = _gra_button_signature(base_gra)
        except LINK_ERRORS:
            gra_base_sig = None

        reporter.step(
            2,
            2,
            tr(
                "Нажмите желаемую кнопку на руле в течение 12 секунд…",
                "Press the desired steering-wheel button within 12 seconds…",
            ),
        )

        # If a button was already held at startup, wait briefly for release first
        released = (base_mfl[1] == 0 and base_mfl[2] == 0)
        deadline = time.monotonic() + max(0.5, float(timeout_s))

        while time.monotonic() < deadline:
            mfl = link.request_uds(b"\x22\x1F\x07", 0x62, timeout=2.0)[3:]
            kc1 = mfl[1] if len(mfl) > 1 else 0
            kc2 = mfl[2] if len(mfl) > 2 else 0
            ev = mfl[3] if len(mfl) > 3 else 0

            if not released:
                if kc1 == 0 and kc2 == 0:
                    released = True
            elif kc1 != 0 or kc2 != 0:
                code = kc1 if kc1 != 0 else kc2
                ru, en = preset_labels.get(code, (f"Кнопка MFL 0x{code:02X}", f"MFL key 0x{code:02X}"))
                reporter.success(
                    tr(
                        f"Поймана кнопка руля: 0x{code:02X} ({ru})",
                        f"Captured steering-wheel button: 0x{code:02X} ({en})",
                    )
                )
                return {
                    "captured": True,
                    "keycode": code,
                    "event_byte": ev,
                    "label_ru": ru,
                    "label_en": en,
                    "raw_1f07": mfl.hex().upper(),
                    "gra_button_detected": False,
                    "timed_out": False,
                }

            if gra_base_sig is not None:
                try:
                    gra = link.request_uds(b"\x22\x1F\x19", 0x62, timeout=1.5)[3:]
                    if len(gra) >= 4 and _gra_button_signature(gra) != gra_base_sig:
                        reporter.warning(
                            tr(
                                "Обнаружено нажатие кнопки круиз-контроля / Travel Assist (кадр GRA_Neu LIN 0x0F). "
                                "Эта линия не передаёт MFL_Tastencode в координатор профилей FPA — выберите мультимедийную/функциональную кнопку (Голос, VIEW, Ассистенты, Обогрев).",
                                "Detected a cruise-control / Travel Assist button press (GRA_Neu LIN 0x0F). "
                                "This line does not send an MFL_Tastencode to the FPA profile coordinator — choose a media/function key (Voice, VIEW, Assistants, Heater).",
                            )
                        )
                        return {
                            "captured": False,
                            "keycode": None,
                            "raw_1f19": gra.hex().upper(),
                            "gra_button_detected": True,
                            "timed_out": False,
                        }
                except LINK_ERRORS:
                    gra_base_sig = None

            if bus is None:
                time.sleep(0.06)

    reporter.warning(tr("Время ожидания нажатия кнопки на руле истекло.", "Timed out waiting for a steering-wheel button press."))
    return {
        "captured": False,
        "keycode": None,
        "gra_button_detected": False,
        "timed_out": True,
    }


def can_read_gateway_coding(
    port: str,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read 30-byte Gateway Long Coding (`UDS 22 06 00`)."""
    with J533CanLink(port, interface=interface, bus=bus) as link:
        reporter.step(1, 1, tr("Чтение кодировки шлюза (UDS 22 06 00)", "Reading gateway coding (UDS 22 06 00)"))
        link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        raw = link.request_uds(b"\x22\x06\x00", 0x62, timeout=2.0)[3:]
        if len(raw) != 30:
            raise RuntimeError(f"Expected 30-byte 0x0600 coding, got {len(raw)} B: {raw.hex().upper()}")
        reporter.info(f"0600 ({len(raw)} B): {raw.hex().upper()}")
        return {"coding": raw, "coding_hex": raw.hex().upper()}


def can_write_gateway_coding(
    port: str,
    coding30: bytes,
    *,
    interface: str = "slcan",
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Write and verify 30-byte Gateway Long Coding (`UDS 2E 06 00`) with workshop fingerprint (`F198`/`F199`)."""
    if len(coding30) != 30:
        raise ValueError(tr(f"Кодировка 0x0600 должна содержать 30 байт, получено {len(coding30)} Б", f"Gateway coding 0x0600 must be 30 bytes, got {len(coding30)} B"))
    with J533CanLink(port, interface=interface, bus=bus) as link:
        reporter.step(1, 2, tr("Запись кодировки шлюза (UDS 2E 06 00)", "Writing gateway coding (UDS 2E 06 00)"))
        link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        _uds_write_workshop_fingerprint(link)
        link.request_uds(b"\x2E\x06\x00" + bytes(coding30), 0x6E, timeout=5.0, allow_pending=True)
        reporter.step(2, 2, tr("Контрольное чтение кодировки (UDS 22 06 00)", "Verifying gateway coding (UDS 22 06 00)"))
        verify = link.request_uds(b"\x22\x06\x00", 0x62, timeout=2.0)[3:]
        if verify != bytes(coding30):
            raise RuntimeError(
                tr(
                    f"Проверка кодировки 0x0600 не совпала: {verify.hex().upper()}",
                    f"Coding 0x0600 readback mismatch: {verify.hex().upper()}",
                )
            )
        reporter.success(tr("Кодировка шлюза 0x0600 записана и проверена!", "Gateway coding 0x0600 written and verified!"))
        return {"coding": verify, "coding_hex": verify.hex().upper()}
