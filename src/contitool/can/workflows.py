"""End-to-end Continental J533 live Diagnosis CAN bench workflows with real-time progress.

Provides complete bench-programmer replacement over Diagnosis CAN (500 kbit/s):
0x6F0 service RAM-loader entry, arbitrary memory reader, live RSA-1024 probe,
FACI Uflash (32 KB), FACI DataFlash (64 KB), FACI CodeFlash boot/raw blocks + UDS FD_0DATA (1.5 MB),
and gateway health/DTC diagnostics.
"""

from __future__ import annotations

import contextlib
import datetime
import functools
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
    FBL_TESTER_SERIAL,
    STAGE1_OVERRUN,
    STAGE1_TOTAL,
    build_cflash_faci_block_payloads,
    build_dflash_faci_payloads,
    dflash_needs_full_program,
    build_dflash_reader_payload,
    build_fed_reader_payload,
    build_reader_payload,
    build_service_loader_uds_steps,
    build_uflash_faci_payloads,
    cflash_block_ranges,
    fbl_sa2,
    verify_payload_self_tests,
)
from contitool.can.transport import TRANSPORT_ERRORS, J533CanLink, UdsNegativeResponse
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
from contitool.core.frf import FrfImage, frf_ident_problems, frf_signature_problem
from contitool.core.patcher import (
    apply_dflash_swap_fecs,
    apply_engineering_patch,
    apply_uflash_rsa_patch,
    write_dflash_slots,
)
from contitool.core.zdc import (
    MFL_KEYCODE_PRESETS,
    export_zdc_block,
    parse_zdc_passport,
    sync_gateway_coding_for_zdc,
    zdc_crc32_le,
    zdc_ver_ok,
)
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationCancelledError, OperationReporter

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


def _uninterruptible(fn):  # noqa: ANN001, ANN202
    """A flash write: a cancel request waits until it is done (OperationReporter.uninterruptible)."""

    @functools.wraps(fn)
    def run(*args: Any, reporter: OperationReporter = NULL_REPORTER, **kwargs: Any) -> Any:
        with reporter.uninterruptible():
            return fn(*args, reporter=reporter, **kwargs)

    return run
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
    from contitool.storage import runs_root  # noqa: PLC0415 - the folder next to the program

    root = base_dir if base_dir is not None else runs_root()
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


STAGE1_SILENT = (  # (ru, en): the language can change while the app runs
    "Блок не ответил на этапе 1 входа в заводской RAM-Loader (multi-DID), хотя на предыдущие запросы отвечал. "
    "Без этого ответа вход не срабатывает, поэтому ключ не отправлялся. Так молчат блоки, в последнем отпечатке "
    "программирования которых (F15B) ненулевой серийник тестера: прошитые ContiTool до 2.0.1e (01..06) или "
    "тестером со своим серийником — в том числе ODIS, так что перепрошивка через ODIS этого не лечит. Лечится "
    "одной перепрошивкой приложения по UDS с нулевым серийником из файла CodeFlash этого блока — ContiTool "
    "предложит её сам. Если серийник в F15B (ниже) нулевой — сообщите о проблеме и приложите отчёт.",
    "The ECU did not answer stage 1 of the factory RAM-Loader entry (multi-DID), though it answered the requests "
    "before it. The entry does not work without that answer, so no key was sent. Gateways whose last programming "
    "fingerprint (F15B) carries a non-zero tester serial go silent this way: flashed by ContiTool before 2.0.1e "
    "(01..06) or by a tester with a serial of its own — ODIS included, so a reflash through ODIS does not cure "
    "it. One reflash of the application over UDS with a zero serial, from this ECU's CodeFlash file, does — "
    "ContiTool offers it. If the serial in the F15B below is zero, please report it with the archive.",
)


def _note_silent_stage1(link: J533CanLink, reporter: OperationReporter, info: dict[str, Any]) -> None:
    """Stage 1 went unanswered; the entry stops there (Stage1SilentError). F15B is read for the report: its last
    record is what decides the answer.

    The read sits between `27 11` and the trigger. That is safe: the seed state (0xFEDE0AF3 = 3) is written only
    by the 27 handler itself and by the attempt-delay timer, which only moves 1 -> 2 — a 22 never touches it and
    it does not expire (bench AA Uflash 0x01002F08..0x010031B4). Its short answer stays inside the buffer."""
    info["stage1_response"] = "suppressed"
    reporter.info(tr(
        "Блок не ответил на этап 1 — так бывает, если в отпечатке программирования (F15B) записан ненулевой "
        "серийник тестера. Читаем F15B для отчёта…",
        "The ECU did not answer stage 1 — this happens when the programming fingerprint (F15B) carries a non-zero "
        "tester serial. Reading F15B for the report…",
    ))
    try:
        resp = link.request_uds(b"\x22\xf1\x5b", 0x62, timeout=1.0)
    except LINK_ERRORS:
        return
    if resp[1:3] == b"\xf1\x5b":  # a late stage-1 answer also starts with 62
        info["f15b"] = resp[3:].hex(" ")


def _hand_back_after_cancel(link: J533CanLink, reporter: OperationReporter) -> None:
    """Cancelled outside a write (a read, a backup, before the first erase): do not leave the gateway in the
    RAM-loader with no application running. NULL_REPORTER: the user's cancel must not stop this reset too."""
    reporter.info(tr("Операция отменена — возвращаем шлюз в штатный режим", "Cancelled — returning the gateway to its application"))
    with contextlib.suppress(*LINK_ERRORS):
        _reset_to_application(link, allow_fbl=True)


def _is_fbl_session_nrc(exc: BaseException) -> bool:
    """True when `10 03` returned NRC 0x7E / 0x12 because the gateway is in FBL Programming Session."""
    return isinstance(exc, UdsNegativeResponse) and exc.sid == 0x10 and exc.nrc in (0x7E, 0x12)


def _is_fbl_precondition_nrc(exc: BaseException) -> bool:
    """True when `27 03` returned NRC 0x7F / 0x12 after `10 03` succeeded in cold-boot FBL Extended Session."""
    return isinstance(exc, UdsNegativeResponse) and exc.sid == 0x27 and exc.nrc in (0x7F, 0x12)


POWER_CYCLE_WAIT = 300.0  # how long a refused key may wait for the user to switch the ECU off and on again


class FblKeyLockedError(RuntimeError):
    """The FBL kept refusing `27 11` (NRC 0x37) even through a reset and the wait for a power cycle."""


class FblRejectedAppError(RuntimeError):
    """`31 01 02 02` did not pass: the factory bootloader wants a signature we do not have."""


class Stage1SilentError(TimeoutError):
    """Stage 1 of the RAM-loader entry went unanswered, so the entry stopped before its key (STAGE1_SILENT).
    A retry would be just as silent; can_cure_fbl_fingerprint is the cure."""


def _is_sa_delay_nrc(exc: BaseException) -> bool:
    """True when SecurityAccess answered NRC 0x37 `requiredTimeDelayNotExpired`."""
    return isinstance(exc, UdsNegativeResponse) and exc.sid == 0x27 and exc.nrc == 0x37


def _fbl_seed(link: J533CanLink, reporter: OperationReporter) -> bytes:
    """`27 11` in the FBL Programming Session; on NRC 0x37 one reset, then a power cycle.

    Seen on a gateway stuck in its bootloader (2026-11-09): after a RAM-loader session and its `FE FF` reset
    the FBL refused every `27 11` with 0x37 — through `11 01` resets too — until the ECU's power was switched
    off; the first request after power-on got its seed. A gateway with a running application never shows it:
    it reaches the FBL through `10 02` from the application. So: answer 0x37 with one reset, and if that does not
    help, ask for the power cycle and carry on by ourselves once the ECU is back."""
    try:
        return link.request_uds(b"\x27\x11", 0x67, timeout=2.0)
    except RuntimeError as exc:
        if not _is_sa_delay_nrc(exc):
            raise
    reporter.info(tr("Загрузчик не выдаёт ключ (NRC 0x37) — сбрасываем блок и пробуем ещё раз…",
                     "The bootloader refuses the seed (NRC 0x37) — resetting the ECU and trying again…"))
    with contextlib.suppress(*LINK_ERRORS):
        link.request_uds(b"\x11\x01", 0x51, timeout=1.5, allow_pending=True)
    time.sleep(2.5)
    try:
        _enter_fbl_uds_programming(link, reporter)
        return link.request_uds(b"\x27\x11", 0x67, timeout=2.0)
    except RuntimeError as exc:
        if not _is_sa_delay_nrc(exc):
            raise
    reporter.warning(
        tr(
            "Загрузчик держит доступ закрытым до выключения питания (NRC 0x37). Выключите питание блока на "
            "10 секунд и включите снова — операция продолжится сама.",
            "The bootloader keeps access closed until power is removed (NRC 0x37). Switch the ECU off for "
            "10 seconds and on again — the operation carries on by itself.",
        )
    )
    deadline = time.monotonic() + POWER_CYCLE_WAIT
    while time.monotonic() < deadline:
        reporter.check_cancelled()
        time.sleep(2.0)
        try:
            # the ECU is off for a while here: its silence must not take the adapter off its hardware ISO-TP,
            # or the whole 1.5 MB then goes frame by frame (issue #18: the VNCI gave up at block ~1650)
            _enter_fbl_uds_programming(link, reporter, resend=False)
            seed = link.request_uds(b"\x27\x11", 0x67, timeout=2.0, resend=False)
        except (TimeoutError, can.CanError):
            continue  # the ECU is off or still starting
        except RuntimeError as exc:
            if isinstance(exc, UdsNegativeResponse) and exc.sid in (0x10, 0x27):
                continue  # not switched off yet, or caught while it starts up
            raise
        reporter.success(tr("Блок снова выдаёт ключ — продолжаем", "The ECU gives a seed again — carrying on"))
        return seed
    raise FblKeyLockedError(
        tr(
            "Загрузчик так и не выдал ключ (NRC 0x37). Выключите питание блока на 10 секунд, включите и повторите "
            "операцию.",
            "The bootloader never gave a seed (NRC 0x37). Switch the ECU off for 10 seconds, on again, and repeat "
            "the operation.",
        )
    )


def _enter_ram_loader_once(link: J533CanLink, reporter: OperationReporter) -> dict[str, Any]:
    """Execute the verified multi-DID UDS staging sequence to enter the 0x6F0 RAM-loader."""
    stage1, stage2, trigger = build_service_loader_uds_steps()
    info: dict[str, Any] = {
        "payload_sha256": EXPECTED_BEACON_SHA256,
        "flash_commands_sent": False,
    }
    reporter.can_log(tr("UDS 10 03 -> Расширенная диагностическая сессия", "UDS 10 03 -> Extended Diagnostic Session"))
    try:
        info["session_1003"] = link.request_uds(b"\x10\x03", 0x50, timeout=2.0).hex()
    except RuntimeError as exc:
        if not _is_fbl_session_nrc(exc):
            raise
        info["already_in_fbl"] = True
        reporter.can_log(
            tr(
                "Шлюз уже находится в загрузчике FBL (NRC 0x7E на 10 03) — прямой переход к 10 02",
                "Gateway is already in FBL bootloader (NRC 0x7E on 10 03) — proceeding directly to 10 02",
            )
        )
    else:
        reporter.can_log(tr("UDS 27 03 / 27 04 -> Разблокировка предпосылок программирования", "UDS 27 03 / 27 04 -> Precondition SecurityAccess"))
        try:
            info["security_2703"] = link.request_uds(b"\x27\x03", 0x67, timeout=2.0).hex()
        except RuntimeError as exc:
            if not _is_fbl_precondition_nrc(exc):
                raise
            info["already_in_fbl"] = True
            reporter.can_log(
                tr(
                    "Шлюз находится в загрузчике FBL после сброса (NRC на 27 03) — прямой переход к 10 02",
                    "Gateway is in FBL bootloader after reset (NRC on 27 03) — proceeding directly to 10 02",
                )
            )
        else:
            info["security_2704"] = link.request_uds(bytes.fromhex("2704caffe012"), 0x67, timeout=2.0).hex()
            info["preconditions"] = link.request_uds(bytes.fromhex("31010203"), 0x71, timeout=2.0).hex()

    reporter.can_log(tr("UDS 10 02 -> Переход в загрузчик FBL (Programming Session)", "UDS 10 02 -> Entering FBL Programming Session"))
    info["session_1002"] = link.request_uds(b"\x10\x02", 0x50, timeout=5.0, allow_pending=True).hex()
    time.sleep(1.0)

    reporter.can_log(tr("UDS 27 11 + multi-DID 0x22 Stage 1/2 -> Подготовка дескриптора 0x0100120E", "UDS 27 11 + multi-DID 0x22 Stage 1/2 -> Staging descriptor 0x0100120E"))
    with link.no_link_recycle():  # from here to the beacon the entry must not pause for a TX link reopen
        return _stage_and_trigger_loader(link, reporter, info, stage1, stage2, trigger)


def _stage_and_trigger_loader(
    link: J533CanLink,
    reporter: OperationReporter,
    info: dict[str, Any],
    stage1: bytes,
    stage2: bytes,
    trigger: bytes,
) -> dict[str, Any]:
    """`27 11`, both staged DID reads and the trigger, then the beacon: the timing-critical half of the entry."""
    info["seed"] = _fbl_seed(link, reporter).hex()
    info["write_0410_05"] = link.request_uds(bytes.fromhex("2e041005"), 0x6E, timeout=2.0).hex()
    try:
        resp1 = link.request_uds(stage1, 0x62, timeout=1.0)  # the answer starts within 60 ms on every log
    except TimeoutError:
        # Stop here, and do not send the trigger. The trigger is a `27 12` whose key is deliberately wrong: it
        # only works because the staged overrun diverts the bootloader before the key is ever checked. On a
        # gateway that did not answer stage 1 there is no evidence the overrun landed, and if it did not, the
        # bootloader takes it as a wrong key and answers 0x37 to `27 11` from then on (see _fbl_seed).
        _note_silent_stage1(link, reporter, info)
        f15b = f" F15B: {info['f15b']}." if "f15b" in info else ""
        raise Stage1SilentError(tr(*STAGE1_SILENT) + f15b) from None
    if len(resp1) != STAGE1_TOTAL or resp1[-3:] != bytes.fromhex("041005"):
        raise RuntimeError(f"Unexpected multi-DID stage 1 response ({len(resp1)} bytes)")
    info["stage1_length"] = len(resp1)
    info["stage1_overrun"] = resp1[STAGE1_OVERRUN:].hex(" ")  # 0xFEDE0C62..69 as sent (0C63 reads 0C by then)
    beacon = _stage2_and_trigger(link, reporter, info, stage2, trigger)
    info["beacon"] = beacon
    info["loader_ready"] = True
    reporter.success(
        tr(
            f"Сервисный RAM-Loader активен и подтверждён маяком: {beacon} (0x6F1)",
            f"Service RAM-Loader active and confirmed by beacon: {beacon} (0x6F1)",
        )
    )
    return info


def _stage2_and_trigger(
    link: J533CanLink, reporter: OperationReporter, info: dict[str, Any], stage2: bytes, trigger: bytes
) -> str:
    """`2E 0410 48`, stage 2 (never answered: it lands FAZIT digits on the suppress flag), the trigger, the beacon."""
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
    return _probe_beacon_in_loader(link, reporter)


def _j2534_wrapper_bus(link: Any) -> Any:
    """The D-PDU bus when it runs on another vendor's J2534 driver through the VW driver without raw CAN, else None."""
    bus = getattr(link, "bus", None)
    wrapped = getattr(link, "interface", "") == "dpdu" and getattr(bus, "j2534_wrapper", False)
    return bus if wrapped and getattr(bus, "nonraw", None) else None


def _j2534_wrapper_problem(bus: Any) -> str:
    """Why memory cannot be read this way, and what to pick instead. Only 64-bit J2534 drivers load into ContiTool."""
    from contitool.can.j2534 import discover_j2534

    keys = {k.lower() for k in (bus.module_vendor, bus.module_label) if len(k) >= 3}
    dev = next((d for d in discover_j2534()
                if any(k in f"{d.name} {d.vendor} {Path(d.dll).stem}".lower() for k in keys)), None)
    head = tr(
        f"Адаптер «{bus.module_label}» ({bus.module_vendor or '?'}) — не VAS 6154: это драйвер J2534 другого "
        "производителя, подключённый через драйвер VW D-PDU. Raw CAN через него нет, а из потока памяти доходит "
        "примерно каждый пятый кадр, поэтому читать и писать память через RAM-Loader так нельзя. Запросы UDS "
        "через него проходят.",
        f"Adapter “{bus.module_label}” ({bus.module_vendor or '?'}) is not a VAS 6154: it is another vendor's J2534 "
        "driver connected through the VW D-PDU driver. It gives no raw CAN, and only about every fifth frame of a "
        "memory stream gets through, so memory cannot be read or written through the RAM-Loader this way. UDS "
        "requests do get through.",
    )
    if dev is not None and dev.usable:
        tail = tr(f" Выберите в окне «Подключение» адаптер J2534 «{dev.name}» напрямую, без драйвера VW.",
                  f" Pick the J2534 adapter “{dev.name}” directly in the Connection window, without the VW driver.")
    elif dev is not None:
        tail = tr(f" Его драйвер J2534 «{dev.name}» {dev.bits}-разрядный, а ContiTool работает только с 64-разрядными.",
                  f" Its J2534 driver “{dev.name}” is {dev.bits}-bit, and ContiTool works only with 64-bit ones.")
    else:
        tail = ""
    return head + tail + tr(" Для чтения памяти подойдёт CANable, candleLight или VAS 6154 / VNCI с raw CAN.",
                            " A CANable, candleLight or a VAS 6154 / VNCI with raw CAN can read memory.")


def _refuse_memory_via_j2534_wrapper(link: Any) -> None:
    """Before the RAM-Loader: a read through such a link fails after ~20 s of retries and tells the user nothing."""
    bus = _j2534_wrapper_bus(link)
    if bus is not None:
        raise RuntimeError(_j2534_wrapper_problem(bus))


def enter_ram_loader(
    link: J533CanLink,
    *,
    allow_already_active: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Enter factory 0x6F0 RAM-loader over UDS, automatically recovering if already inside loader."""
    _refuse_memory_via_j2534_wrapper(link)
    try:
        return _enter_ram_loader_once(link, reporter)
    except LINK_ERRORS as first_err:
        if isinstance(first_err, (FblKeyLockedError, Stage1SilentError)):
            raise  # a retry would only stage another entry: another key attempt, or the same silence
        if allow_already_active:
            try:
                reporter.info(
                    tr(
                        "Проверяем, не активен ли уже заводской RAM-Loader (0x6F0)…",
                        "Checking whether the factory RAM-Loader (0x6F0) is already active…",
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
        _reset_to_application(link, reporter=reporter, allow_fbl=True)
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


NONRAW_ADAPTER_HINT = (
    # A VCI without RawMode. Through a wrapped J2534 driver (issue #17) every fifth frame arrived, evenly over the
    # whole stream, so a shorter read loses the same share; such a link is refused before the RAM-Loader. How a VW
    # VCI's own plain link copes is not known yet: only that the stream did not come through.
    "Адаптер не дал raw CAN (RawMode), а через обычный канал D-PDU поток памяти от блока дошёл не целиком. "
    "Прочитать память этим адаптером не получится. Нужен CANable, candleLight или VAS 6154 / VNCI с raw CAN.",
    "The adapter refused raw CAN (RawMode), and through the plain D-PDU link the memory stream from the ECU did not "
    "arrive in full. Memory cannot be read with this adapter. Use a CANable, candleLight or a VAS 6154 / VNCI with "
    "raw CAN.",
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
                    if "stopped after" in str(exc):
                        if link.interface == "slcan":
                            reporter.error(tr(*SLOW_ADAPTER_HINT))
                        elif getattr(getattr(link, "bus", None), "nonraw", None):
                            reporter.error(tr(*NONRAW_ADAPTER_HINT))
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


# In the application's DID tables and absent from the bootloader's read table (bench AA CodeFlash 0x1B24..0x1BC3),
# so an answer to either can only come from a running application. Both answer on every build in the reports
# (5366, 5388, 5502, 5504).
APP_ONLY_DIDS = (0xF197, 0x0600)


def _application_answers(link: J533CanLink) -> BaseException | None:
    """None if the running application answered one of APP_ONLY_DIDS, otherwise the last failure."""
    last: BaseException | None = None
    for did in APP_ONLY_DIDS:
        try:
            link.request_uds(bytes([0x22, did >> 8, did & 0xFF]), 0x62, timeout=1.0)
            return None
        except LINK_ERRORS as exc:
            last = exc
    return last


def _probe_app_or_fbl(link: J533CanLink, *, attempts: int, allow_fbl: bool) -> tuple[str, bool]:
    last_err: Exception | None = None
    for _ in range(attempts):
        try:
            sess = link.request_uds(b"\x10\x03", 0x50, timeout=1.2, allow_pending=True).hex()
        except LINK_ERRORS as exc:
            if allow_fbl and _is_fbl_session_nrc(exc):
                try:
                    return link.request_uds(b"\x10\x02", 0x50, timeout=2.5, allow_pending=True).hex(), True
                except LINK_ERRORS as fbl_exc:
                    last_err = fbl_exc
            else:
                last_err = exc
            time.sleep(0.5)
            continue

        # Cold-boot FBL Default Session also accepts `10 03 -> 50 03` when Application is erased/invalid, so a
        # positive 10 03 alone does not prove the application runs. An application-only DID does.
        exc = _application_answers(link)
        if exc is None:
            return sess, False
        if not allow_fbl:
            # Where FBL is no acceptable landing nothing short of that proof counts: F1DF bit 2 is only the result
            # of a check whose code lies outside the dump, and a clear bit is no evidence the application started.
            last_err = RuntimeError(tr(f"на 10 03 ответ есть, а на F197/0600 нет — работа приложения не подтверждена ({exc})",
                                       f"10 03 answered but F197/0600 did not, so the Application is not proven ({exc})"))
            time.sleep(0.5)
            continue
        # Where landing in FBL is acceptable, a running application mistaken for FBL is the costlier error (the
        # entry then skips its preconditions), so a clear "application invalid" bit keeps treating it as one.
        f1df_val: int | None = None
        try:
            f1df = link.request_uds(b"\x22\xf1\xdf", 0x62, timeout=1.0)
            if len(f1df) >= 4:
                f1df_val = f1df[3]
        except LINK_ERRORS:
            pass
        return sess, f1df_val is not None and bool(f1df_val & 0x04)
    raise RuntimeError(tr(f"Приложение шлюза не запустилось: {last_err}", f"Application did not come up: {last_err}"))


def _return_to_application(
    link: J533CanLink,
    session: dict[str, Any] | None,
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Bring the gateway back to its Application at the end of an operation, and refuse to call it done if not.

    A gateway that was already stuck in FBL when we started cannot be expected to leave it, so for that one FBL is
    an acceptable landing — and so it is when the start is unknown (`session` None: the loader was entered by an
    earlier run). For every other gateway staying in FBL means the operation left it without a running
    application, and reporting that as "done" is how a user learns about it only when the car will not start."""
    started_in_fbl = session is None or bool(session.get("already_in_fbl"))
    info = _reset_to_application(link, reporter=reporter, allow_fbl=started_in_fbl)
    if info.get("in_fbl"):
        reporter.warning(
            tr(
                "Шлюз был в загрузчике FBL ещё до операции и остаётся в нём: приложение нужно восстановить "
                "(заливка бэкапа или прошивка через ODIS).",
                "The gateway was already in its FBL bootloader before this operation and is still there: its "
                "application has to be restored (write a backup back, or an ODIS flash).",
            )
        )
    return info


def _reset_to_application(
    link: J533CanLink,
    *,
    reporter: OperationReporter = NULL_REPORTER,
    allow_fbl: bool = False,
) -> dict[str, Any]:
    info: dict[str, Any] = {}
    try:
        info["uds_reset"] = link.request_uds(b"\x11\x01", 0x51, timeout=1.2, allow_pending=True).hex()
        info["reset_method"] = "uds"
    except LINK_ERRORS as exc:
        info["uds_reset_error"] = str(exc)
    time.sleep(2.0)
    try:
        sess, in_fbl = _probe_app_or_fbl(link, attempts=2, allow_fbl=allow_fbl)
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
        sess, in_fbl = _probe_app_or_fbl(link, attempts=10, allow_fbl=allow_fbl)
    if in_fbl:
        info["fbl_session"] = sess
        info["in_fbl"] = True
    else:
        info["application_session"] = sess
    return info


# Identification the gateway answers in the extended session (checked on 3Q0907530AA / HW 3Q0907530C / SW 5366)
ECU_IDENT_DIDS: tuple[tuple[int, str, str], ...] = (
    (0xF187, "Номер детали", "Part number"),
    (0xF191, "Номер оборудования", "Hardware number"),
    (0xF189, "Версия ПО", "Software version"),
    # Boot software (FBL) identification: the RAM-loader entry is staged inside the FBL, so this is the version
    # that decides whether it works. An ODIS recovery flash can change it without touching F189.
    (0xF180, "Версия загрузчика", "Boot software version"),
    (0xF1A3, "Версия оборудования", "Hardware version"),
    (0xF197, "Система", "System name"),
    (0xF18C, "Серийный номер", "Serial number"),
    (0xF17C, "FAZIT", "FAZIT"),
    (0xF19E, "Вариант ODX", "ODX variant"),
    (0xF1A2, "Версия ODX", "ODX version"),
    (0x0600, "Кодирование", "Coding"),
)


def _is_vag_part_number(value: str) -> bool:
    return 9 <= len(value) <= 12 and value.isalnum() and any(c.isalpha() for c in value[:3]) and value[3:9].isdigit()


def unsupported_ecu_reason(ident: list[dict[str, str]]) -> str | None:
    """Explain why an identified gateway is not a supported Continental 3Q0 RH850/F1L unit, or None if supported."""
    vals = {item["did"]: item["value"].strip() for item in ident}
    part = "".join(vals.get("F187", "").split()).upper()
    hw_part = "".join(vals.get("F191", "").split()).upper()
    sw_ver = vals.get("F189", "").strip().upper()
    hw_ver = vals.get("F1A3", "").strip().upper()
    fazit = vals.get("F17C", "").strip().upper()
    odx_var = vals.get("F19E", "").strip()

    # 1. Lear MQB Gen 1 (5Q0, MPC5607B) & Gen 2 (3Q0, MPC5748G) — shares 3Q0907530* part numbers with Continental!
    is_lear = (
        "lear" in odx_var.lower()
        or fazit.startswith(("LG", "LCE"))
        or (len(hw_ver) == 3 and hw_ver.isdigit() and hw_ver[0] in ("1", "4"))
        or hw_ver.startswith(("X2", "H4"))
        or (len(sw_ver) == 4 and ((sw_ver.isdigit() and sw_ver[0] in ("1", "4")) or sw_ver.startswith(("1A", "1B", "91"))))
    )
    if is_lear:
        return tr(
            "Это шлюз производства Lear на процессоре NXP PowerPC (MPC5607B / MPC5748G). "
            "ContiTool поддерживает только шлюзы Continental 3Q0 907 530 на базе Renesas RH850/F1L (HW 5xx / SW 5xxx).",
            "This is a Lear gateway based on NXP PowerPC (MPC5607B / MPC5748G). "
            "ContiTool only supports Continental 3Q0 907 530 gateways based on Renesas RH850/F1L (HW 5xx / SW 5xxx).",
        )

    # 2. First-generation MQB gateways (5Q0 / 8V0 / 5QE / 8S0, or early HW 2xx / SW 2xxx) on NXP MPC5607B PowerPC
    is_conti_gen1 = (
        "conti" in odx_var.lower()
        or fazit.startswith("SJ8")
        or (len(hw_ver) == 3 and hw_ver.isdigit() and hw_ver.startswith("2"))
        or (len(sw_ver) == 4 and sw_ver.isdigit() and sw_ver.startswith("2"))
    )
    is_gen1_part = any(p.startswith(("5Q0", "8V0", "5QE", "8S0")) for p in (part, hw_part) if p)
    if is_gen1_part or (len(hw_ver) == 3 and hw_ver.isdigit() and hw_ver.startswith("2")) or (
        len(sw_ver) == 4 and sw_ver.isdigit() and sw_ver.startswith("2")
    ):
        if is_conti_gen1:
            return tr(
                "Это ранний шлюз Continental поколения 5Q0 (HW 2xx / SW 2xxx) на процессоре NXP PowerPC (MPC5607B), "
                "а не Renesas RH850/F1L. ContiTool поддерживает только поколение 3Q0 907 530 на базе Renesas RH850/F1L (HW 5xx / SW 5xxx).",
                "This is a first-generation Continental 5Q0 gateway (HW 2xx / SW 2xxx) based on NXP PowerPC (MPC5607B), "
                "not Renesas RH850/F1L. ContiTool only supports 3Q0 907 530 gateways based on Renesas RH850/F1L (HW 5xx / SW 5xxx).",
            )
        return tr(
            "Это шлюз первого поколения MQB (5Q0 / 8V0) на процессоре NXP PowerPC (MPC5607B), а не Renesas RH850/F1L. "
            "ContiTool поддерживает только шлюзы Continental 3Q0 907 530 на базе Renesas RH850/F1L (HW 5xx / SW 5xxx).",
            "This is a first-generation MQB gateway (5Q0 / 8V0) based on NXP PowerPC (MPC5607B), not Renesas RH850/F1L. "
            "ContiTool only supports Continental 3Q0 907 530 gateways based on Renesas RH850/F1L (HW 5xx / SW 5xxx).",
        )

    # 3. Other VAG gateway/ECU families (e.g. MQB-A0 2Q0 907 530, MQB-Evo 5WA 907 530)
    if any(_is_vag_part_number(p) and not p.startswith(("3Q0", "V03")) for p in (part, hw_part) if p):
        return tr(
            "Этот блок не относится к линейке Continental 3Q0 907 530 на процессоре Renesas RH850/F1L и не поддерживается программой.",
            "This ECU is not a Continental 3Q0 907 530 gateway based on Renesas RH850/F1L and is not supported.",
        )

    return None


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
    in_fbl = False
    with J533CanLink(port, interface=interface, bus=bus) as link:
        if link.interface == "dpdu" and callable(getattr(link.bus, "describe", None)):
            reporter.info(tr("Модуль D-PDU: ", "D-PDU module: ") + link.bus.describe())
            if (wrapped := _j2534_wrapper_bus(link)) is not None:
                result["adapter_warning"] = _j2534_wrapper_problem(wrapped)
                reporter.warning(result["adapter_warning"])
        reporter.step(1, 2, tr("Проверка связи с блоком (UDS 10 03)", "Checking the link to the ECU (UDS 10 03)"))
        try:
            link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        except LINK_ERRORS as exc:
            if _is_fbl_session_nrc(exc):
                in_fbl = True
            else:
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

        # Cold-boot FBL Default Session answers `10 03 -> 50 03`, omits Application-only DIDs (`F197`, `0600`),
        # and reports bit 2 (`0x04`, e.g. `0x44`) in `22 F1 DF` when the Application is erased or invalid.
        answered = {item["did"] for item in result["ident"]}
        if in_fbl or not ({f"{did:04X}" for did in APP_ONLY_DIDS} & answered):
            try:
                raw_df = link.request_uds(b"\x22\xf1\xdf", 0x62, timeout=1.0)
                if len(raw_df) >= 4:
                    f1df_val = raw_df[3]
                    result["f1df"] = f"{f1df_val:02X}"
                    if f1df_val & 0x04:
                        in_fbl = True
                        result["app_valid"] = False
            except LINK_ERRORS:
                pass
        unsupported = unsupported_ecu_reason(result["ident"])
        if unsupported:
            result["unsupported"] = unsupported
            reporter.warning(unsupported)
        if in_fbl:
            result["in_fbl"] = True
            reporter.warning(
                tr(
                    "Блок отвечает из загрузчика FBL — основная прошивка сейчас не запущена.",
                    "The ECU answered from the FBL bootloader — the main application is not running.",
                )
            )
    return result


# "Status_of_all_existing_FS-IDs_in_the_ECU" (ODIS): [FS-ID 4 B big-endian, status bits] per feature. In the
# 3Q0907530AR SW 5504 DID table @ 0x1FE7C with at most 75 bytes = 15 features.
SWAP_STATUS_DID = 0x3C00
# The gateway's own rule (IsFecActive, 5388 0x7A2E0 / 5504 0x7BA62): bits 0, 1, 2, 3 and 6 = certificate, not
# cancelled, VCRN, validity, signature. Bits 4/5 (configuration, function) do not take part.
SWAP_STATUS_ACTIVE = 0x4F


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
                report["return_to_app"] = _return_to_application(link, report.get("loader_session"), reporter=reporter)

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
                manifest["return_to_app"] = _return_to_application(link, manifest.get("loader_session"), reporter=reporter)

            manifest["complete"] = True
            reporter.progress(100, 100)
            reporter.success(
                tr(
                    f"Полный бэкап сохранён в папку: {out_dir}",
                    f"Full backup saved to folder: {out_dir}",
                )
            )
            return manifest
        except OperationCancelledError:
            _hand_back_after_cancel(link, reporter)
            raise
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
                report["return_to_app"] = _return_to_application(link, report.get("loader_session"), reporter=reporter)

            report["complete"] = True
            reporter.progress(100, 100)
            return report
        except OperationCancelledError:
            _hand_back_after_cancel(link, reporter)
            raise
        except Exception as exc:
            report["error"] = str(exc)
            raise
        finally:
            _write_json(out_dir / "read_mem_result.json", report)


@_uninterruptible
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
                    reporter.step(3, total_steps, tr("Полное чтение блока уже есть — остальные области не читаются", "A complete read of this ECU is on file — the other areas are not read again"))

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
                with reporter.uninterruptible():  # a cancel held back by the write must not skip its record
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
                result["return_to_app"] = _return_to_application(
                    link, result.get("loader_session"), reporter=reporter
                )
                result["tester_present"] = link.request_uds(b"\x3e\x00", 0x7E, timeout=2.0).hex()

            result["complete"] = True
            reporter.progress(100, 100)
            if result.get("already_matching"):
                reporter.success(tr("Загрузчик Uflash не менялся: в блоке уже нужная версия, сверка совпала",
                                    "Uflash bootloader left as is: the gateway already had this version, readback matches"))
            else:
                reporter.success(tr("Загрузчик Uflash успешно прошит и побайтово верифицирован!",
                                    "Uflash bootloader successfully programmed and verified byte-for-byte!"))
            return result
        except OperationCancelledError:
            _hand_back_after_cancel(link, reporter)
            raise
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


def merge_dflash_edits(current: bytes, base: bytes, edited: bytes) -> tuple[bytes, list[int], list[int]]:
    """Put only the blocks the user changed (`edited` vs the `base` backup they were made on) onto what the ECU holds now.

    The gateway keeps some DataFlash records up to date itself (seen: 0xF040/0xF080 changed between a backup and a
    write 12 minutes later). Writing the whole edited copy rolled those back to the backup's state.
    Returns (image to write, blocks the ECU changed itself and that stay as they are, blocks both changed)."""
    out = bytearray(current)
    kept: list[int] = []
    conflicts: list[int] = []
    for off in range(0, DFLASH_SIZE, DFLASH_BLOCK_SIZE):
        blk = slice(off, off + DFLASH_BLOCK_SIZE)
        user, ecu = edited[blk] != base[blk], current[blk] != base[blk]
        if user and ecu and edited[blk] != current[blk]:
            conflicts.append(off)
        elif user:
            out[blk] = edited[blk]
        elif ecu:
            kept.append(off)
    return bytes(out), kept, conflicts


def can_write_dflash(
    port: str,
    candidate_dflash: bytes | Path,
    *,
    expected_before_dflash: bytes | None = None,
    base_dflash: bytes | None = None,
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

            if base_dflash is not None:  # an edited copy of a backup: write the edits, keep what the ECU changed since
                raw_cand, kept, conflicts = merge_dflash_edits(current_df, base_dflash, raw_cand)
                result["kept_ecu_blocks"] = [f"0x{off:04X}" for off in kept]
                if conflicts:
                    raise RuntimeError(tr(
                        "После бэкапа блок сам изменил те же блоки DataFlash, что и вы: "
                        f"{', '.join(f'0x{o:04X}' for o in conflicts)}. Запись остановлена до первой команды стирания: "
                        "снимите свежий бэкап и внесите правки в него.",
                        "Since the backup the ECU itself changed the same DataFlash blocks you edited: "
                        f"{', '.join(f'0x{o:04X}' for o in conflicts)}. Write stopped before any erase command: "
                        "take a fresh backup and make your edits on it.",
                    ))
                if kept:
                    reporter.info(tr(
                        f"Блок сам изменил после бэкапа {', '.join(result['kept_ecu_blocks'])} — эти блоки остаются как в блоке.",
                        f"The ECU changed {', '.join(result['kept_ecu_blocks'])} itself since the backup — these stay as the ECU has them.",
                    ))

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
                # A ZDC block whose trailing FF words an earlier write left blank reads FF here (blank-check reader)
                # but noise in the gateway: rewrite it whole even when it looks unchanged.
                if (full_rewrite or current_df[off : off + DFLASH_BLOCK_SIZE] != cand_blk
                        or dflash_needs_full_program(cand_blk, off)):
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
                    reporter.step(3, total_steps, tr("Полное чтение блока уже есть — остальные области не читаются", "A complete read of this ECU is on file — the other areas are not read again"))

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
                with reporter.uninterruptible():  # a cancel held back by the write must not skip its record
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

            # The caller syncs the coding itself when the application is not started here (can_sync_zdc_coding)
            written = [idx for idx, _c, off, sz, *_ in ZDC_DATASET_SPECS if current_df[off : off + sz] != raw_cand[off : off + sz]]
            result["zdc_blocks_written"] = written
            if return_to_app:
                reporter.step(6, total_steps, tr("Перезапуск шлюза и проверка штатного режима (10 03 / 3E 00)", "Resetting gateway & verifying normal Application communication"))
                result["return_to_app"] = _return_to_application(
                    link, result.get("loader_session"), reporter=reporter
                )
                result["tester_present"] = link.request_uds(b"\x3e\x00", 0x7E, timeout=2.0).hex()
                if written and not result["return_to_app"].get("in_fbl"):
                    result["auto_coding"] = _sync_coding_for_zdc(link, raw_cand, written, reporter)

            result["complete"] = True
            reporter.progress(100, 100)
            reporter.success(
                tr(
                    "DataFlash (64 КБ) успешно записан по CAN и побайтово верифицирован!",
                    "DataFlash (64 KB) successfully programmed over CAN and verified byte-for-byte!",
                )
            )
            return result
        except OperationCancelledError:
            _hand_back_after_cancel(link, reporter)
            raise
        except Exception as exc:
            result["error"] = str(exc)
            raise
        finally:
            _write_json(out_dir / "dflash_write_result.json", result)


def can_sync_zdc_coding(
    port: str,
    dflash: bytes,
    blocks: list[int],
    *,
    interface: str = "slcan",
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Coding 0x0600 for ZDC blocks written earlier without a return to the application (DataFlash + CodeFlash in
    one write: the coding can only be written once the application runs again)."""
    with J533CanLink(port, interface=interface) as link:
        return _sync_coding_for_zdc(link, dflash, blocks, reporter)


def _sync_coding_for_zdc(link: J533CanLink, written_df: bytes, blocks: list[int], reporter: OperationReporter) -> dict[str, Any]:
    """Set the long-coding enable bits (DID 0x0600) of the ZDC blocks just written, so the gateway uses them.

    A dataset whose bit is clear is never loaded (see sync_gateway_coding_for_zdc); auto-parameterization used to
    leave it so. Only the bits of `blocks` change. The gateway reads coding and datasets at start-up, so it is
    restarted afterwards. A refusal leaves DataFlash written and says exactly which coding change is still due."""
    info: dict[str, Any] = {"blocks": blocks}
    link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
    coding = link.request_uds(b"\x22\x06\x00", 0x62, timeout=2.0)[3:]
    want = sync_gateway_coding_for_zdc(written_df, coding, blocks=blocks)
    info["before"] = coding.hex().upper()
    if want == coding:
        reporter.info(tr("Кодировка 0x0600 уже согласована с записанными датасетами",
                         "Coding 0x0600 already matches the written datasets"))
        return info
    changes = ", ".join(
        f"байт {i}: {coding[i]:02X} -> {want[i]:02X}" for i in range(len(want)) if want[i] != coding[i]
    )
    changes_en = ", ".join(
        f"byte {i}: {coding[i]:02X} -> {want[i]:02X}" for i in range(len(want)) if want[i] != coding[i]
    )
    try:
        _uds_write_workshop_fingerprint(link)
        link.request_uds(b"\x2E\x06\x00" + want, 0x6E, timeout=5.0, allow_pending=True)
        verify = link.request_uds(b"\x22\x06\x00", 0x62, timeout=2.0)[3:]
        if verify != want:
            raise RuntimeError(f"0x0600 readback {verify.hex().upper()}")
    except LINK_ERRORS as exc:
        info["error"] = str(exc)
        reporter.warning(tr(
            f"DataFlash записан, но кодировку 0x0600 записать не удалось ({exc}). Без неё датасеты не используются — "
            f"измените кодировку вручную: {changes}.",
            f"DataFlash is written, but coding 0x0600 could not be written ({exc}). Without it the datasets are not "
            f"used — change the coding by hand: {changes_en}.",
        ))
        return info
    info["after"] = want.hex().upper()
    reporter.success(tr(f"Кодировка 0x0600 согласована с датасетами ({changes})",
                        f"Coding 0x0600 aligned with the datasets ({changes_en})"))
    info["restart"] = _reset_to_application(link, reporter=reporter)
    return info


def _enter_fbl_uds_programming(link: J533CanLink, reporter: OperationReporter, *, resend: bool = True) -> None:
    """Enter FBL Programming Session (`10 02`) cleanly whether starting from Application or FBL.

    `resend=False` while the ECU may be switched off: a request it does not answer must not move the link off the
    adapter's hardware ISO-TP (see J533CanLink.request_uds)."""
    kw = {} if resend else {"resend": False}
    try:
        link.request_uds(b"\x10\x03", 0x50, timeout=1.5, **kw)
        link.request_uds(b"\x27\x03", 0x67, timeout=2.0, **kw)
        link.request_uds(bytes.fromhex("2704caffe012"), 0x67, timeout=2.0, **kw)
        link.request_uds(bytes.fromhex("31010203"), 0x71, timeout=2.0, **kw)
    except RuntimeError as exc:
        # The preconditions are best effort, as in the hardware-verified 2.0.1c: in FBL they are refused by design
        # (7F 10 7E, 7F 27 7F/12), and in the application a 27 03 delay (7F 27 37) or a refused 31 01 0203 does not
        # have to stop the entry. Whether programming may start is the answer to `10 02` below. Transport errors
        # are not RuntimeError and still end the operation.
        if not (_is_fbl_session_nrc(exc) or _is_fbl_precondition_nrc(exc)):
            reporter.can_log(tr(f"Предусловие отклонено ({exc}) — пробуем 10 02", f"Precondition refused ({exc}) — trying 10 02"))
    link.request_uds(b"\x10\x02", 0x50, timeout=5.0, allow_pending=True, **kw)
    time.sleep(1.0)


def _routine_ok(resp: bytes, label: str) -> None:
    if len(resp) < 4 or resp[0] != 0x71 or resp[1] != 0x01 or resp[-1] != 0x00:
        raise RuntimeError(f"{label} failed with routine response: {resp.hex()}")


def _bcd_byte(val: int) -> int:
    return ((val // 10) << 4) | (val % 10)


def _dpdu_frame_by_frame(link: Any) -> bool:
    """A VAS 6154 / VNCI link that would send UDS frame by frame (no hardware ISO-TP, or it has given way)."""
    on_dpdu = getattr(link, "interface", "") == "dpdu" or type(getattr(link, "bus", None)).__name__ == "DPduBus"
    return on_dpdu and not getattr(link, "_hw_uds", False)


def _uds_session(link: Any) -> Any:
    uds_ctx = getattr(link, "uds_session", None)
    return uds_ctx() if callable(uds_ctx) else contextlib.nullcontext(False)


def _note_hw_fallback(link: Any, info: dict[str, Any], reporter: OperationReporter) -> None:
    """Have the link tell the user, and the result, when its hardware ISO-TP gives way to the software path."""
    def note(where: str) -> None:
        info["hardware_isotp"] = False
        info["hardware_isotp_fell_back_at"] = where
        reporter.warning(tr(
            f"Аппаратный ISO-TP адаптера отказал ({where}) — продолжаем проверенным программным путём "
            "(медленнее, но надёжно)",
            f"The adapter's hardware ISO-TP failed ({where}) — continuing on the verified software path "
            "(slower, but reliable)",
        ))
    link.on_hw_fallback = note


@_uninterruptible
def _program_application_uds(
    link: J533CanLink,
    app_bytes: bytes,
    *,
    signature_128b: bytes | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Program 1,523,200-byte FD_0DATA (`0x0000C200..0x0017FFFF`) via standard VAG FBL UDS.

    Over an adapter with its own ISO-TP (VNCI through D-PDU, J2534) the whole programming session runs on one
    link, as ODIS does: one primitive per request instead of one per CAN frame. The adapter's ISO-TP is proven
    by ODIS; our settings of it are proven by the steps before the erase, every time: `10 02` always answers
    `7F 10 78` first, and `2E F15A` is a multi-frame request. Should it fail on any request anyway, the link sends
    that request again on the verified software path (`J533CanLink.request_uds`) rather than leave the gateway
    without its application. The erase and both routines are idempotent, and a `36` resent with the same
    sequence counter is a repeated block that ISO 14229 accepts without writing twice; a `34` or `37` the ECU had
    already acted on comes back refused, and that refusal is reported, never assumed away."""
    if len(app_bytes) != APP_SIZE:
        raise ValueError(f"Expected {APP_SIZE:,} bytes of Application data, got {len(app_bytes):,}")

    info: dict[str, Any] = {
        "security_unlocked": False,
        "fingerprint_written": False,
        "erase_completed": False,
        "download_accepted": False,
        "bytes_transferred": 0,
    }
    _note_hw_fallback(link, info, reporter)
    with _uds_session(link) as hw_uds:
        info["hardware_isotp"] = bool(hw_uds)
        if not hw_uds and (why := getattr(getattr(link, "bus", None), "uds_refusal", "")):
            info["hardware_isotp_refused"] = why
            reporter.info(tr(f"Аппаратный ISO-TP адаптера не включился ({why}) — передача идёт программным путём",
                             f"The adapter's hardware ISO-TP did not come up ({why}) — transferring on the software path"))
        reporter.can_log(tr("Вход в сессию программирования FBL (10 02) и авторизация SA2 (27 11/12)…", "Entering FBL Programming Session (10 02) & unlocking SA2 (27 11/12)…"))
        _enter_fbl_uds_programming(link, reporter)
        seed_resp = _fbl_seed(link, reporter)
        if len(seed_resp) != 6:
            raise RuntimeError(f"Unexpected FBL 27 11 seed response: {seed_resp.hex()}")
        seed = int.from_bytes(seed_resp[2:6], "big")
        if seed != 0:
            key = fbl_sa2(seed)
            link.request_uds(b"\x27\x12" + key.to_bytes(4, "big"), 0x67, timeout=3.0)
        info["security_unlocked"] = True

        # Mandatory 9-byte VAG fingerprint (DID 0xF15A: BCD YY MM DD + 6-byte tester serial). The bootloader keeps
        # it as the last F15B record, which the RAM-loader entry's stage 1 overruns: see FBL_TESTER_SERIAL.
        now = datetime.datetime.now(datetime.timezone.utc)
        fp = bytes(_bcd_byte(v) for v in (now.year % 100, now.month, now.day)) + FBL_TESTER_SERIAL
        link.request_uds(b"\x2e\xf1\x5a" + fp, 0x6E, timeout=3.0)
        info["fingerprint_written"] = True

        if _dpdu_frame_by_frame(link):
            # Before the erase, not at 50%: frame by frame a 1.5 MB application is ~220,000 network requests, and
            # every VNCI log so far (three users, issue #18 among them) stops finishing them at ~125,000 and the
            # adapter restarts its service. Reopening the link does not help: the VCI counts per module.
            raise RuntimeError(tr(
                "Аппаратный ISO-TP адаптера VAS 6154 / VNCI не работает, а без него запись CodeFlash обрывается на "
                "середине: адаптер перестаёт отправлять примерно на 125-тысячном кадре. Стирание не начиналось. "
                "Переподключите адаптер и повторите; если ISO-TP так и не заработает, обновите драйвер D-PDU или "
                "запишите блок другим адаптером.",
                "The VAS 6154 / VNCI hardware ISO-TP is not working, and without it a CodeFlash write breaks off "
                "halfway: the adapter stops sending at around the 125,000th frame. The erase has not started. "
                "Reconnect the adapter and try again; if ISO-TP still does not work, update the D-PDU driver or "
                "write the ECU with another adapter.",
            ))
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
        try:
            _routine_ok(chk_resp, "CheckMemory (0202)")
        except RuntimeError as exc:
            # With the engineering bootloader this always passes; the factory one checks the RSA signature, and
            # ContiTool has none to give. The application is now invalid, so the ECU stays in its bootloader.
            raise FblRejectedAppError(
                tr(
                    f"Загрузчик не принял приложение ({chk_resp.hex()}): в блоке заводской загрузчик, ему нужна "
                    "подпись. Сначала нужен инженерный загрузчик.",
                    f"The bootloader rejected the application ({chk_resp.hex()}): the ECU has the factory "
                    "bootloader, which wants a signature. The engineering bootloader is needed first.",
                )
            ) from exc
        info["check_memory_response"] = chk_resp.hex()

        reporter.can_log(tr("Проверка зависимостей и запись маркера присутствия (31 01 FF 01)…", "Running CheckProgrammingDependencies (31 01 FF 01)…"))
        dep_resp = link.request_uds(bytes.fromhex("3101ff01"), 0x71, timeout=60.0, allow_pending=True)
        _routine_ok(dep_resp, "CheckProgrammingDependencies (FF01)")
        info["dependencies_response"] = dep_resp.hex()

        try:
            info["reset_response"] = link.request_uds(b"\x11\x01", 0x51, timeout=2.0, resend=False).hex()
        except TRANSPORT_ERRORS:
            # the ECU is rebooting: on a hardware link that can surface as an error event, not only as silence
            info["reset_response"] = "no response after reset"
    return info


@_uninterruptible
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


FBL_RECORD_BLOCK = 4  # CodeFlash 0x8000..0x9FFF: the FBL's programming record ("NIGB"), then erased to 0x9FFF
FBL_RECORD_STATUS = 0x8023  # 0x00 after a completed download; 0xFF while one is unfinished (application invalid)


def _fbl_record_writable(image: bytes, reporter: OperationReporter) -> bool:
    """Whether the image's own FBL programming record may go into the ECU.

    A record taken while a download was unfinished carries status 0xFF: written back, the bootloader would treat
    the application as half-written and stay in FBL. Then the record the download just made is kept instead."""
    if image[FBL_RECORD_STATUS] == 0x00:
        return True
    reporter.warning(tr(
        f"В образе запись загрузчика о программировании отмечена как незавершённая (0x{FBL_RECORD_STATUS:04X} = "
        f"0x{image[FBL_RECORD_STATUS]:02X}) — её не пишем, иначе блок останется в загрузчике. Остаётся запись, "
        "которую сделал загрузчик при этой прошивке.",
        f"The image's FBL programming record is marked unfinished (0x{FBL_RECORD_STATUS:04X} = "
        f"0x{image[FBL_RECORD_STATUS]:02X}) — not written, or the ECU would stay in its bootloader. The record the "
        "bootloader made during this download stays.",
    ))
    return False


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

    if not raw_faci and _ecu_stuck_in_fbl(port, interface, out_dir):
        # Its application does not run, so there is nothing in it worth a backup yet, and a RAM-loader entry now
        # would cost the `27 11` the programming needs (see _fbl_seed). The FBL takes the application over UDS
        # first; with it running, the regular path below writes the rest (boot area, the FBL's record in block 4)
        # through the RAM-loader and reads everything back — entered from a live application, which is safe.
        reporter.warning(tr(
            "Блок в загрузчике FBL, приложение не работает: сначала прошиваем приложение по UDS, затем, когда оно "
            "заработает, — загрузочную область через RAM-Loader и сверку.",
            "The ECU is in its FBL bootloader with no running application: the application goes in over UDS "
            "first; once it runs, the boot area through the RAM-loader, then the readback.",
        ))
        result["flash_commands_sent"] = True
        result["uds_first"] = _restore_app_over_uds(port, raw_cand, interface, out_dir / "uds_first", reporter)

    with J533CanLink(port, interface=interface, log_path=out_dir / "can.jsonl") as link:
        try:
            reporter.step(1, total_steps, tr("Вход в RAM-Loader и проверка загрузчика (RSA Probe)", "Entering RAM-Loader & probing bootloader state"))
            enter_ram_loader(link, reporter=reporter)
            rsa_res = run_rsa_probe(link, reporter=reporter)
            result["rsa_precheck"] = rsa_res

            backup_dir = out_dir / "backup"
            backup_dir.mkdir(parents=True, exist_ok=True)
            if not skip_backup or not prefix or not expected_before_cflash:
                if skip_backup:  # the full backup is taken already; CodeFlash is still read to compare against
                    reporter.step(2, total_steps, tr("Чтение текущего CodeFlash (1.5 МБ) для сравнения", "Reading the current CodeFlash (1.5 MB) to compare"))
                else:
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
                with reporter.uninterruptible():  # a cancel held back by the write must not skip its record
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
                actual = rb_path.read_bytes()
                # validity words of a block 6 not written here stay as the FBL set them; written here, it must match
                if not rb.get("reference_match") and not (
                    6 not in changed_blocks
                    and _same_but_validity_words(actual, bytes(expected_full)) and fbl_app_valid(actual)
                ):
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

                # Block 4 holds the FBL's own programming record (counter 0x800C, date 0x801A, status 0x8023, checksum
                # 0x82FA), and every UDS download rewrites it. Written before the download it is overwritten at once,
                # so with an application to program it goes in afterwards, in the verify session.
                with reporter.uninterruptible():  # boot blocks, application, block 4: one write
                    record_after = bool(app_blocks) and _fbl_record_writable(bytes(expected_full), reporter)
                    boot_now = [b for b in boot_blocks if not (app_blocks and b == FBL_RECORD_BLOCK)]
                    if boot_now:
                        reporter.step(
                            3,
                            total_steps,
                            tr(
                                f"Запись области загрузчика CodeFlash через FACI (блоки {boot_now}) — НЕ ОТКЛЮЧАЙТЕ ПИТАНИЕ!",
                                f"Programming CodeFlash boot blocks via FACI (blocks {boot_now}) — DO NOT CUT POWER!",
                            ),
                        )
                        result["flash_commands_sent"] = True
                        result["boot_faci_blocks"] = _program_cflash_blocks_in_loader(
                            link,
                            bytes(expected_full),
                            boot_now,
                            flid_16b=live_selfid,
                            reporter=reporter,
                        )
                    else:
                        reporter.step(3, total_steps, tr("Область загрузчика 0x000000..0x00BFFF без изменений", "Boot region 0x000000..0x00BFFF unchanged"))

                    if app_blocks:
                        _reset_to_application(link, reporter=reporter, allow_fbl=True)
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
                        if record_after:
                            reporter.can_log(tr("Запись загрузчика о программировании (блок 4) — из образа, после UDS",
                                                "The FBL's programming record (block 4) — from the image, after UDS"))
                            result["fbl_record_faci"] = _program_cflash_blocks_in_loader(
                                link, bytes(expected_full), [FBL_RECORD_BLOCK], flid_16b=live_selfid, reporter=reporter
                            )
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
                    expected_cmp = bytearray(expected_full)
                    if app_blocks and not record_after:
                        # The image's record was deliberately not written (unfinished download): the one this
                        # download made stays, and is what we read back.
                        expected_cmp[0x8000:0xA000] = actual[0x8000:0xA000]
                    # The FBL sets its own validity words (0xC000 / 0xC100) during 34/36/37, or did so long ago when
                    # no application is written now: accept a difference only there, and only if the FBL's own rule
                    # then calls the application valid.
                    if actual != bytes(expected_cmp) and not (
                        _same_but_validity_words(actual, bytes(expected_cmp)) and fbl_app_valid(actual)
                    ):
                        at = next(i for i in range(len(actual)) if actual[i] != expected_cmp[i])
                        raise RuntimeError(
                            f"CodeFlash readback mismatch at 0x{at:06X}: wrote 0x{expected_cmp[at]:02X}, read 0x{actual[at]:02X}"
                        )
                    if actual != bytes(expected_cmp):
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
            if result.get("already_matching"):
                reporter.success(tr("CodeFlash не менялся: в блоке уже этот образ", "CodeFlash left as is: the ECU already holds this image"))
            else:
                reporter.success(tr("CodeFlash успешно прошит и побайтово верифицирован по всем 1.5 МБ!",
                                    "CodeFlash programmed and verified byte-for-byte across all 1.5 MB!"))
            return result
        except OperationCancelledError:
            _hand_back_after_cancel(link, reporter)
            raise
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


def _ecu_fazit_over_uds(link: J533CanLink) -> tuple[str, bool]:
    """The ECU's FAZIT as it answers `22 F17C`, and whether it sits in its FBL bootloader."""
    _sess, in_fbl = _probe_app_or_fbl(link, attempts=2, allow_fbl=True)
    resp = link.request_uds(b"\x22\xf1\x7c", 0x62, timeout=2.0)
    return (_fazit(resp[3:]) if resp[1:3] == b"\xf1\x7c" else ""), in_fbl


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
    factory_fbl: bool = False,
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
        # FAZIT comes over UDS: `22 F17C` is in the bootloader's own DID table too, so this works on a gateway
        # stuck in FBL — without a RAM-loader entry, after which such a gateway refuses `27 11` (see _fbl_seed).
        # A gateway restored *because* it is stuck there has no application until CodeFlash is written, and
        # nothing in the chain may ask for one before that.
        ecu = {"fazit": "", "vcrn": ""}
        app_was_down = True
        try:
            ecu["fazit"], app_was_down = _ecu_fazit_over_uds(link)
        except LINK_ERRORS:
            pass  # no UDS answer (left in the RAM-loader, say): the loader reads it below
        # VCRN lives in DataFlash and no bootloader DID carries it, so only the RAM-loader can read it. It is
        # needed when FAZIT did not answer, when the backup has no FAZIT but a VCRN (DataFlash alone), and when
        # DataFlash is written from a backup with a blank VCRN: the ECU's own must not be erased by it.
        in_loader = (not ecu["fazit"] or (not backup["fazit"] and bool(backup["vcrn"]))
                     or ("dflash" in writes and backup["vcrn"] == ""))
        if in_loader:
            entry = enter_ram_loader(link, reporter=reporter)
            if not entry.get("already_in_loader"):
                app_was_down = bool(entry.get("already_in_fbl"))
            cf_path, df_path = own_dir / "Cflash_fazit.bin", own_dir / "Dflash_vcrn.bin"
            read_memory_area(link, CFLASH_ADDR_START + cf_chunk, CFLASH_ADDR_START + cf_chunk + READ_CHUNK_BYTES, cf_path, label="FAZIT", reporter=reporter)
            read_memory_area(link, DFLASH_ADDR_START + df_chunk, DFLASH_ADDR_START + df_chunk + READ_CHUNK_BYTES, df_path, label="VCRN", reporter=reporter)
            at = FAZIT_OFFSET - cf_chunk
            df = bytearray(b"\xff" * DFLASH_SIZE)
            df[df_chunk : df_chunk + READ_CHUNK_BYTES] = df_path.read_bytes()
            ecu = {"fazit": _fazit(cf_path.read_bytes()[at : at + FAZIT_SIZE]), "vcrn": _vcrn(bytes(df))}
        result = {"session_dir": str(out_dir), "ecu": ecu, "backup": backup, "writes": list(writes),
                  "app_was_down": app_was_down}
        _write_json(own_dir / "owner.json", result)
        reporter.info(f"FAZIT: {ecu['fazit'] or '—'} / {backup['fazit'] or '—'}   VCRN: {ecu['vcrn'] or '—'} / {backup['vcrn'] or '—'}")
        problems = backup_owner_problems(ecu, backup, set(writes))
        if problems:
            if in_loader:  # nothing follows, so hand the gateway back rather than leave it in the RAM-loader
                with contextlib.suppress(*LINK_ERRORS):
                    _reset_to_application(link, reporter=reporter, allow_fbl=True)
            raise RuntimeError(tr("Бэкап не записан: ", "The backup was not written: ") + "; ".join(problems))
        # If the RAM-loader had to be entered, it is deliberately left running: the write that follows recognises
        # it by its beacon instead of staging another entry and its `27 11`.
    reporter.success(tr("Бэкап снят с этого блока — записываем", "The backup belongs to this ECU — writing it"))

    did_backup = False
    try:
        if "cflash" in writes and app_was_down:
            # Stuck in its bootloader: program the application over UDS straight away, as the FBL itself
            # expects, with no RAM-loader entry first. Only a factory bootloader, which wants a signature,
            # needs the engineering one — the one case that has to go through the RAM-loader.
            # can_write_cflash sees the ECU stuck and programs the application over UDS first; then the boot
            # area and the readback go through the RAM-loader, entered from the running application.
            # No full backup of a gateway whose application does not run: the backup being written is the copy.
            # The bootloader it had is still saved by can_write_uflash (Uflash_before.bin) and put back below.
            refused = factory_fbl  # the caller saw the factory FBL refuse it already: do not erase it again for that
            if not refused:
                try:
                    result["cflash"] = can_write_cflash(
                        port, files["cflash"], interface=interface, session_dir=out_dir / "cflash",
                        skip_backup=True, return_to_app=False, reporter=reporter,
                    )
                except FblRejectedAppError as exc:
                    reporter.warning(str(exc))
                    refused = True
            if refused:
                result["uflash_engineering"] = can_write_uflash(
                    port, restore_stock=False, interface=interface, session_dir=out_dir / "uflash_eng",
                    skip_full_backup=True, return_to_app=False, reporter=reporter,
                )
                result["cflash"] = can_write_cflash(
                    port, files["cflash"], interface=interface, session_dir=out_dir / "cflash_retry",
                    skip_backup=True, return_to_app=False, reporter=reporter,
                )
            did_backup = True
        elif "cflash" in writes:
            # the CodeFlash write right after reads CodeFlash, DataFlash and the bootloader itself: no copy here
            result["uflash_engineering"] = can_write_uflash(
                port, restore_stock=False, interface=interface, session_dir=out_dir / "uflash_eng",
                skip_full_backup=True, return_to_app=False, reporter=reporter,
            )
            result["cflash"] = can_write_cflash(
                port, files["cflash"], interface=interface, session_dir=out_dir / "cflash",
                return_to_app=False, reporter=reporter,
            )
            did_backup = True
        if "dflash" in writes:
            result["dflash"] = can_write_dflash(
                port, files["dflash"], interface=interface, session_dir=out_dir / "dflash", skip_full_backup=did_backup,
                return_to_app=False, reporter=reporter,
            )
            did_backup = True
    except (Exception, OperationCancelledError):  # a cancel leaves the same ECU behind as a failure
        eng_record = out_dir / "uflash_eng" / "uflash_write_result.json"
        if "uflash_engineering" not in result and eng_record.is_file():  # the write itself raised: its own record
            with contextlib.suppress(OSError, ValueError):  # what is re-raised below stays the cancel or the error
                result["uflash_engineering"] = json.loads(eng_record.read_text(encoding="utf-8"))
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
            return_to_app=False,
            reporter=reporter,
        )
    result["return_to_app"] = _finish_restore(port, interface, out_dir, writes, app_was_down, reporter)
    _write_json(own_dir / "owner.json", result)
    return result


def _ecu_stuck_in_fbl(port: str, interface: str, out_dir: Path) -> bool:
    """True when the ECU answers UDS from its FBL without a running application. UDS only, no RAM-loader."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with J533CanLink(port, interface=interface, log_path=out_dir / "state.jsonl") as link:
        try:
            return _probe_app_or_fbl(link, attempts=2, allow_fbl=True)[1]
        except LINK_ERRORS:
            return False  # e.g. a RAM-loader left running by the step before: the regular path picks it up


def _restore_app_over_uds(
    port: str, cflash_file: Path | bytes, interface: str, out_dir: Path, reporter: OperationReporter
) -> dict[str, Any]:
    """Program the backup's application through the FBL's own UDS download — no RAM-loader involved.

    Restores a gateway stuck in its bootloader the way the bootloader expects to be fed, and as was done by hand
    on 2026-11-09: `10 02`, real SA2 key, fingerprint, erase, 2,975 blocks, the two checks, reset. The boot area
    0x0000..0xBFFF is not written: UDS cannot reach it, and a backup of this very ECU carries the same."""
    image = cflash_file.read_bytes() if isinstance(cflash_file, Path) else bytes(cflash_file)
    _prefix, app = split_cflash_or_app(image)
    stored, calc = app_crc(app)
    if stored != calc:
        raise RuntimeError(tr(f"В бэкапе повреждено приложение: CRC-16 0x{stored:04X} != 0x{calc:04X}",
                              f"The backup's application is damaged: CRC-16 0x{stored:04X} != 0x{calc:04X}"))
    out_dir.mkdir(parents=True, exist_ok=True)
    reporter.step(1, 1, tr("Прошивка приложения CodeFlash по UDS через загрузчик FBL — НЕ ОТКЛЮЧАЙТЕ ПИТАНИЕ!",
                           "Programming the CodeFlash application over UDS through the FBL — DO NOT CUT POWER!"))
    with J533CanLink(port, interface=interface, log_path=out_dir / "can.jsonl") as link:
        try:
            _probe_app_or_fbl(link, attempts=1, allow_fbl=True)
        except LINK_ERRORS:
            # A RAM-loader left running (after the engineering bootloader went in) does not speak UDS: leave it.
            _reset_to_application(link, reporter=reporter, allow_fbl=True)
        return _program_application_uds(link, bytes(app), reporter=reporter)


def can_cure_fbl_fingerprint(
    port: str,
    cflash_file: Path,
    *,
    interface: str = "slcan",
    session_dir: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Open the RAM-loader entry again on a gateway ContiTool <= 2.0.1d flashed (Stage1SilentError).

    Its last fingerprint record carries tester serial 01..06, and only the FBL's own erase of the application
    rewrites that record (see FBL_TESTER_SERIAL). So this ECU's application is programmed once more over UDS, as
    ODIS would, with no RAM-loader. The engineering bootloader those gateways got with that write takes it; a
    factory one refuses the unsigned application, but by then the record is rewritten, so the restore of a
    gateway stuck in its bootloader takes over. Bench 2026-11-09: silent with serial 01..06, answered after this."""
    out_dir = session_dir or default_session_dir(None, "fingerprint")
    out_dir.mkdir(parents=True, exist_ok=True)
    reporter.step(1, 1, tr("Проверка, что CodeFlash снят с этого блока (FAZIT)", "Checking the CodeFlash was taken from this ECU (FAZIT)"))
    with J533CanLink(port, interface=interface, log_path=out_dir / "owner.jsonl") as link:
        fazit, _in_fbl = _ecu_fazit_over_uds(link)
    backup = backup_identity(cflash_file.read_bytes(), None)
    problems = backup_owner_problems({"fazit": fazit, "vcrn": ""}, backup, {"cflash"})
    if problems:
        raise RuntimeError(tr("Приложение не записано: ", "The application was not written: ") + "; ".join(problems))
    result: dict[str, Any] = {"session_dir": str(out_dir), "fazit": fazit}
    try:
        result["uds"] = _restore_app_over_uds(port, cflash_file, interface, out_dir / "uds", reporter)
    except FblRejectedAppError:
        reporter.warning(tr(
            "В блоке заводской загрузчик: приложение без подписи он не принял. Отпечаток уже исправлен, и вход в "
            "RAM-Loader снова работает — восстанавливаем блок через инженерный загрузчик.",
            "The ECU has the factory bootloader, which refused the unsigned application. The fingerprint is fixed "
            "already and the RAM-Loader entry works again — restoring the ECU through the engineering bootloader.",
        ))
        result["restore"] = can_restore_backup(port, {"cflash": cflash_file}, ["cflash"], interface=interface,
                                               session_dir=out_dir / "restore", factory_fbl=True, reporter=reporter)
        return result
    time.sleep(3.0)  # the reset that ends the programming
    with J533CanLink(port, interface=interface, log_path=out_dir / "after.jsonl") as link:
        _sess, in_fbl = _probe_app_or_fbl(link, attempts=5, allow_fbl=True)
        if in_fbl:
            raise RuntimeError(tr("Приложение записано, но блок остался в загрузчике FBL",
                                  "The application is written, but the ECU stayed in its FBL bootloader"))
        link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        result["f15b"] = link.request_uds(b"\x22\xf1\x5b", 0x62, timeout=2.0)[3:].hex(" ").upper()
    reporter.success(tr(f"Отпечаток исправлен (F15B: {result['f15b']}) — вход в RAM-Loader снова доступен",
                        f"Fingerprint fixed (F15B: {result['f15b']}) — the RAM-Loader entry is available again"))
    return result


FRF_IDENT_DIDS = ("F187", "F189", "F191", "F1A3")


def _read_ident_dids(link: J533CanLink) -> dict[str, str]:
    """F187 / F189 / F191 / F1A3 as text, from the application or the bootloader; what does not answer is left out."""
    _probe_app_or_fbl(link, attempts=2, allow_fbl=True)
    out: dict[str, str] = {}
    for did in FRF_IDENT_DIDS:
        try:
            raw = link.request_uds(b"\x22" + bytes.fromhex(did), 0x62, timeout=2.0)[3:]
        except LINK_ERRORS:
            continue
        out[did] = raw.rstrip(b"\x00 ").decode("latin-1").strip()
    return out


def can_flash_frf(
    port: str,
    frf: FrfImage,
    *,
    interface: str = "slcan",
    session_dir: Path | None = None,
    allow_unlisted: bool = False,
    fbl_modulus: bytes | None = None,
    fbl_open: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Flash an ODIS FRF over UDS the way ODIS does: the application with the FRF's own signature, so the factory
    bootloader takes it, with no RAM-loader and no engineering bootloader. The tester serial in the fingerprint is
    zero (FBL_TESTER_SERIAL), so this also opens a RAM-loader entry that an ODIS flash closed.

    The FRF's EXPECTED-IDENTs are checked first: other hardware is refused; a part number or software version
    ODIS would not flash it onto needs `allow_unlisted`. The signature is checked before anything else against the
    ECU's bootloader key (`fbl_modulus` from a read of its CodeFlash, the factory key without one; none with the
    engineering bootloader, `fbl_open`): a signature the bootloader would refuse never reaches the erase."""
    why = frf_signature_problem(frf, fbl_modulus=fbl_modulus, fbl_open=fbl_open)
    if why:
        raise RuntimeError(why)
    out_dir = session_dir or default_session_dir(None, "frf")
    result: dict[str, Any] = {"session_dir": str(out_dir), "frf": frf.name, "frf_version": frf.sw_version}
    try:
        with J533CanLink(port, interface=interface, log_path=out_dir / "can.jsonl") as link:
            reporter.step(1, 3, tr("Идентификация блока (F187 / F189 / F191 / F1A3)", "Identifying the ECU (F187 / F189 / F191 / F1A3)"))
            result["before"] = ecu = _read_ident_dids(link)
            hard, soft = frf_ident_problems(frf, ecu)
            result["ident_problems"] = hard + soft
            if hard or (soft and not allow_unlisted):
                raise RuntimeError(tr(f"{frf.kind} не для этого блока: ", f"The {frf.kind} is not for this ECU: ") + "; ".join(hard + soft))
            reporter.step(2, 3, tr(f"Прошивка {frf.name} по UDS — НЕ ОТКЛЮЧАЙТЕ ПИТАНИЕ!",
                                   f"Flashing {frf.name} over UDS — DO NOT CUT POWER!"))
            try:
                result["uds"] = _program_application_uds(link, frf.app, signature_128b=frf.signature, reporter=reporter)
            except FblRejectedAppError as exc:
                raise FblRejectedAppError(tr(
                    f"Загрузчик не принял приложение из {frf.kind} с его подписью. Приложение стёрто, блок остался в "
                    "загрузчике FBL — восстановите его «Залить бэкап…» (CodeFlash этого блока) или прошейте подходящий "
                    "FRF / ODX.",
                    f"The bootloader refused the {frf.kind} application with its signature. The application is erased and "
                    "the ECU stays in its FBL bootloader — restore it with \"Write backup…\" (this ECU's CodeFlash) or "
                    "flash a matching FRF / ODX.",
                )) from exc
        time.sleep(3.0)  # the reset that ends the programming
        with J533CanLink(port, interface=interface, log_path=out_dir / "after.jsonl") as link:
            reporter.step(3, 3, tr("Проверка: приложение запущено, новая версия", "Checking: application running, new version"))
            _s, in_fbl = _probe_app_or_fbl(link, attempts=5, allow_fbl=True)
            if in_fbl:
                raise RuntimeError(tr(f"{frf.kind} записан, но блок остался в загрузчике FBL",
                                      f"The {frf.kind} is written, but the ECU stayed in its FBL bootloader"))
            result["after"] = after = _read_ident_dids(link)
        old_v, new_v = ecu.get("F189", "?"), after.get("F189", frf.sw_version)
        reporter.success(tr(f"{frf.kind} записан: ПО {old_v} → {new_v}, приложение запущено",
                            f"{frf.kind} written: software {old_v} → {new_v}, application running"))
        if old_v != new_v:
            reporter.warning(tr(
                "Версия ПО сменилась: параметрия ZDC должна соответствовать новой прошивке, иначе возможна ошибка "
                "000601 «недостоверный блок данных». Загрузите датасет под эту версию («Импорт файла ODIS» → "
                "«Записать параметрию по CAN»).",
                "The software version changed: the ZDC datasets must suit the new firmware, or DTC 000601 "
                "(implausible dataset) may follow. Upload the dataset for this version (\"Import ODIS file\" → "
                "\"Write datasets over CAN\").",
            ))
        result["complete"] = True
        return result
    except Exception as exc:
        result["error"] = str(exc)
        raise
    finally:
        _write_json(out_dir / "frf_result.json", result)


def _finish_restore(
    port: str,
    interface: str,
    out_dir: Path,
    writes: list[str],
    app_was_down: bool,
    reporter: OperationReporter,
) -> dict[str, Any]:
    """The one place the restore chain leaves the RAM-loader and looks at the application.

    Every step before this stays in the loader rather than reset out of it and enter again. The application
    must come up only if this restore wrote
    CodeFlash, or if it was running before; a gateway that was stuck in its bootloader and got no CodeFlash
    cannot, and landing in the bootloader is then the expected end, not an error."""
    must_run = "cflash" in writes or not app_was_down
    reporter.step(1, 1, tr("Перезапуск шлюза после заливки", "Restarting the gateway after the restore"))
    (out_dir / "finish").mkdir(parents=True, exist_ok=True)
    with J533CanLink(port, interface=interface, log_path=out_dir / "finish" / "can.jsonl") as link:
        info = _reset_to_application(link, reporter=reporter, allow_fbl=not must_run)
    if info.get("in_fbl"):
        reporter.warning(
            tr(
                "Блок остался в загрузчике FBL: CodeFlash в этой заливке не записывался, а приложения в блоке нет. "
                "Чтобы блок запустился, залейте CodeFlash.",
                "The ECU stays in its FBL bootloader: this restore did not write CodeFlash and the ECU has no "
                "application. Restore CodeFlash for it to start.",
            )
        )
    return info


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


def _transfer_chunk(dl_resp: bytes) -> int:
    """TransferData payload size for a 74 reply: ISO 14229 maxNumberOfBlockLength counts the 36 SID + sequence byte.
    Same parsing as the hardware-verified FBL path in _program_application_uds."""
    len_bytes = dl_resp[1] >> 4 if len(dl_resp) >= 2 else 0
    if not (1 <= len_bytes <= 4) or len(dl_resp) < 2 + len_bytes:
        raise RuntimeError(f"Malformed RequestDownload response: {dl_resp.hex()}")
    max_block_len = int.from_bytes(dl_resp[2 : 2 + len_bytes], "big")
    if max_block_len < 3:
        raise RuntimeError(f"ECU reported invalid maxNumberOfBlockLength={max_block_len}")
    return max_block_len - 2


def _uds_security_20103(link: J533CanLink, *, reporter: OperationReporter = NULL_REPORTER) -> None:
    """Log in with code `20103`: SecurityAccess level 3 (`27 03` seed, `27 04` key = `(seed + 20103) & 0xFFFFFFFF`).

    Level 3, as ODIS does it: in its own driver logs every `27 04` key is the seed plus the login code (156 of them,
    2026-11). Level 1 (`27 01`), used before 2.0.1e, does not exist on the gateway: `7F 27 12`."""
    resp = link.request_uds(b"\x27\x03", 0x67, timeout=3.0)
    if len(resp) < 6:
        raise RuntimeError(f"Malformed 27 03 response: {resp.hex()}")
    seed = int.from_bytes(resp[2:6], "big")
    if seed != 0:
        key = (seed + ZDC_SECURITY_ACCESS_PIN) & 0xFFFFFFFF
        link.request_uds(b"\x27\x04" + key.to_bytes(4, "big"), 0x67, timeout=3.0)
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
    """Upload ZDC dataset blocks directly over standard Application UDS (`10 40` + `27 03/04` `20103` + `34/36/37` + `02EF`).

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

    with J533CanLink(port, interface=interface, bus=bus, log_path=log_path) as link, _uds_session(link):
        _note_hw_fallback(link, result, reporter)
        reporter.step(1, total_steps, tr("Вход в EOL-сессию (UDS 10 40) и авторизация 20103", "Entering EOLSession (UDS 10 40) & SecurityAccess 20103"))
        link.request_uds(b"\x10\x40", 0x50, timeout=3.0)
        _uds_security_20103(link, reporter=reporter)
        _uds_write_workshop_fingerprint(link)
        reporter.progress(12, 100)

        with reporter.uninterruptible():  # a dataset left half-uploaded stays erased
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
                # Full-size blocks, as ODIS sends them (1022 + 1022 + 794 after `74 20 04 00`): the gateway answered a
                # 240-byte block after `74 10 FE` with 7F 36 31 and left the dataset half erased (bench 2026-11-09).
                chunk_size = _transfer_chunk(dl_resp)
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
            ver_str = pp.dataset_ver if zdc_ver_ok(pp.dataset_ver) else "0001"
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

        # Each uploaded block is used only with its enable bit in 0x0600 set; a coding change restarts the gateway.
        result["auto_coding"] = _sync_coding_for_zdc(link, dflash_bytes, [u[0] for u in to_upload], reporter)
        if reset_after and "after" not in result["auto_coding"]:
            reporter.step(total_steps, total_steps, tr("Перезагрузка шлюза для применения датасета (UDS 11 02)", "Resetting gateway to reload dataset tables (UDS 11 02)"))
            try:
                link.request_uds(b"\x11\x02", 0x51, timeout=2.0, allow_pending=True, resend=False)
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


def can_activate_swap(
    port: str,
    fecs: list[int],
    *,
    interface: str = "slcan",
    session_dir: Path | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Switch SWaP features on in the ECU itself. The gateway has no UDS service for that without a signed
    certificate, so its own DataFlash is read through the RAM-loader, only the Multi-FSC records are patched
    (apply_dflash_swap_fecs, the VIN as the records already carry it) and written back; the datasets and the rest
    of DataFlash stay exactly as the ECU has them. The read DataFlash is the backup of the only area written."""
    out_dir = session_dir or default_session_dir(None, "swap")
    read = can_backup(port, interface=interface, session_dir=out_dir / "read", areas=("dflash",),
                      return_to_app=False, reporter=reporter)
    before = Path(read["areas"]["dflash"]["output_file"]).read_bytes()
    patched, summary = apply_dflash_swap_fecs(before, enable_fecs=fecs, reporter=reporter)
    write = can_write_dflash(port, patched, expected_before_dflash=before, interface=interface,
                             session_dir=out_dir / "write", skip_full_backup=True, return_to_app=True, reporter=reporter)
    return {"session_dir": str(out_dir), "swap": summary, "write": write}


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
