"""Binary firmware & DataFlash patchers, CP slot writers, key parsers, and safety guardrails."""

from __future__ import annotations

from collections.abc import Iterable
import re
import struct
import time
from typing import Any
import zlib

from contitool.core.analyzer import (
    analyze_dflash,
    analyze_dflash_datasets,
    analyze_dflash_swap,
    build_hybrid_cave,
    check_fec_dataset_support,
    decode_jr_disp22,
    encode_jr_disp22,
    find_ccp_blacklist_sites,
    find_eeprom_mask_branch_sites,
    find_eng_feature_gate_sites,
    find_kschutz_hook_sites,
    find_ramloader_a167_sites,
    find_swap_rsa_modulus_sites,
    split_cflash_or_app,
    validate_dflash_bytes,
    validate_uflash_bytes,
)
from contitool.core.checksums import app_crc
from contitool.core.constants import (
    ALL_SLOTS,
    APP_BASE,
    CAVE_SIZE,
    DEFAULT_CAVE_VADDR,
    DFLASH_FSC_BASE_OFF,
    DFLASH_FSC_PAY_SIZE,
    DFLASH_FSC_STRIDE,
    DFLASH_SWAP_CRC_OFF,
    DFLASH_SWAP_NVM_OFF,
    DFLASH_SWAP_PAY_SIZE,
    FBL_EXP_OFFSET,
    FBL_MOD_OFFSET,
    GATEWAY_SWAP_SLOT_ORDER,
    KNOWN_GATEWAY_FECS,
    MASTER_SLOT,
    OTP_ENG_FLAG_OFFSET,
    PATCH_A167_NOP,
    PATCH_CCP_BLACKLIST_NOP,
    PATCH_ENG_GATE_HEAD,
    PATCH_MOVEA_0X10,
    PATCH_UFLASH_RSA_OK,
    SHE_M1_RAMKEY_KEY2,
    SLAVE_SLOTS,
    STOCK_A167_BE,
    STOCK_CCP_BLACKLIST_CMOV,
    STOCK_ENG_GATE_HEAD,
    STOCK_MOVEA_0X40,
    STOCK_UFLASH_RSA_CMOV,
    SlotSpec,
    UFLASH_RSA_CMP_OFFSET,
    UNSUPPORTED_DATASET_RU,
    UNSUPPORTED_DATASET_WARNING,
)
from contitool.i18n import get_lang, tr
from contitool.progress import NULL_REPORTER, OperationReporter


def apply_engineering_patch(
    raw: bytes,
    *,
    restore_stock: bool = False,
    ignore_input_crc: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, str, int]:
    """Enable (or restore stock) Engineering Mode in CodeFlash.bin / FD_0DATA and update CRC-16 @ 0xC21C."""
    reporter.step(1, 3, tr("Проверка входного образа CodeFlash и CRC-16", "Validating input CodeFlash & CRC-16"))
    prefix, app = split_cflash_or_app(raw)
    prefix_mut = bytearray(prefix)

    _, range_cnt = struct.unpack_from("<HH", app, 0x1C)
    if range_cnt == 0:
        struct.pack_into("<H", app, 0x1E, 1)
    elif not ignore_input_crc:
        stored_crc, calc_crc = app_crc(app)
        if stored_crc != calc_crc:
            raise RuntimeError(
                tr(
                    f"Не совпадает входной CRC-16 @ 0x0000C21C (в файле 0x{stored_crc:04X}, расчёт 0x{calc_crc:04X}).",
                    f"Input Application CRC-16 mismatch @ 0x0000C21C (stored 0x{stored_crc:04X}, calculated 0x{calc_crc:04X}).",
                )
            )
    reporter.progress(33, 100)

    reporter.step(2, 3, tr("Поиск сигнатур Feature Gate, CCP и 0xA167 RAM-Loader", "Locating Feature Gate, CCP & 0xA167 sites"))
    app_ro = bytes(app)
    eng_hits = find_eng_feature_gate_sites(app_ro)
    ccp_bl_hits = find_ccp_blacklist_sites(app_ro)
    a167_hits = find_ramloader_a167_sites(app_ro)
    if len(eng_hits) != 1:
        raise RuntimeError(
            tr(
                f"Ожидалась ровно 1 точка Feature 0x80/0x81/0x83 gate, найдено: {len(eng_hits)}",
                f"Expected exactly 1 Feature 0x80/0x81/0x83 gate site, found: {len(eng_hits)}",
            )
        )
    if len(ccp_bl_hits) != 1:
        raise RuntimeError(
            tr(
                f"Ожидалась ровно 1 точка фильтра адресов CCP_CheckAddr, найдено: {len(ccp_bl_hits)}",
                f"Expected exactly 1 CCP_CheckAddr blacklist site, found: {len(ccp_bl_hits)}",
            )
        )
    if len(a167_hits) != 1:
        raise RuntimeError(
            tr(
                f"Ожидалась ровно 1 точка проверки 0xA167 CAN RAM-Loader, найдено: {len(a167_hits)}",
                f"Expected exactly 1 0xA167 CAN RAM-Loader check site, found: {len(a167_hits)}",
            )
        )

    eoff = eng_hits[0]
    boff = ccp_bl_hits[0]
    aoff = a167_hits[0]
    evaddr = APP_BASE + eoff
    bvaddr = APP_BASE + boff
    avaddr = APP_BASE + aoff

    if restore_stock:
        app[eoff : eoff + 4] = STOCK_ENG_GATE_HEAD
        app[boff : boff + 4] = STOCK_CCP_BLACKLIST_CMOV
        app[aoff : aoff + 2] = STOCK_A167_BE
        if prefix_mut:
            prefix_mut[OTP_ENG_FLAG_OFFSET] = 0xFF
        desc = tr(
            f"возврат заводской защиты Feature 0x80/0x81/0x83 @ 0x{evaddr:06X} + фильтра CCP @ 0x{bvaddr:06X} + закрытие 0xA167 @ 0x{avaddr:06X}",
            f"restored stock Feature 0x80/0x81/0x83 gate @ 0x{evaddr:06X} + CCP filter @ 0x{bvaddr:06X} + locked 0xA167 @ 0x{avaddr:06X}",
        )
    else:
        app[eoff : eoff + 4] = PATCH_ENG_GATE_HEAD
        app[boff : boff + 4] = PATCH_CCP_BLACKLIST_NOP
        app[aoff : aoff + 2] = PATCH_A167_NOP
        if prefix_mut:
            prefix_mut[OTP_ENG_FLAG_OFFSET] = 0x00
        otp_note = tr(" + OTP [0x0000A167]=0x00", " + OTP [0x0000A167]=0x00") if prefix_mut else ""
        desc = tr(
            f"инженерный режим ВКЛЮЧЕН: Feature 0x80/0x81/0x83 @ 0x{evaddr:06X} + полный CCP Flash/RAM @ 0x{bvaddr:06X} "
            f"+ 0x07FC80FE RAM-Loader @ 0x{avaddr:06X}{otp_note}",
            f"Engineering Mode ENABLED: Feature 0x80/0x81/0x83 @ 0x{evaddr:06X} + full CCP Flash/RAM @ 0x{bvaddr:06X} "
            f"+ 0x07FC80FE RAM-Loader @ 0x{avaddr:06X}{otp_note}",
        )
    reporter.progress(70, 100)

    reporter.step(3, 3, tr("Пересчёт Application CRC-16/MODBUS @ 0x0000C21C", "Recalculating Application CRC-16/MODBUS @ 0x0000C21C"))
    _, new_crc = app_crc(app)
    struct.pack_into("<H", app, 0x001C, new_crc)
    reporter.progress(100, 100)
    reporter.success(f"{desc} | CRC-16 = 0x{new_crc:04X}")
    return bytes(prefix_mut) + bytes(app), desc, new_crc


def apply_uflash_rsa_patch(
    uf_raw: bytes,
    *,
    restore_stock: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, str]:
    """Patch (or restore) Uflash.bin (+0x342A) so FBL CheckMemory (31 01 02 02) accepts unsigned .odx."""
    reporter.step(1, 2, tr("Проверка сигнатуры бутлодера Uflash @ +0x342A", "Validating Uflash FBL signature @ +0x342A"))
    validate_uflash_bytes(uf_raw)
    reporter.progress(50, 100)
    reporter.step(2, 2, tr("Модификация инструкции проверки RSA @ 0x0100342A", "Updating RSA verification instruction @ 0x0100342A"))
    uf = bytearray(uf_raw)
    if restore_stock:
        uf[UFLASH_RSA_CMP_OFFSET : UFLASH_RSA_CMP_OFFSET + 4] = STOCK_UFLASH_RSA_CMOV
        desc = tr(
            "возврат штатной проверки RSA-1024 в Uflash.bin @ 0x0100342A (e2 57 14 eb)",
            "restored stock RSA-1024 verification in Uflash.bin @ 0x0100342A (e2 57 14 eb)",
        )
    else:
        uf[UFLASH_RSA_CMP_OFFSET : UFLASH_RSA_CMP_OFFSET + 4] = PATCH_UFLASH_RSA_OK
        desc = tr(
            "инженерный RSA-Free загрузчик в Uflash.bin @ 0x0100342A (00 ea 00 00: приём любых .odx по UDS без RSA)",
            "Engineering RSA-Free FBL in Uflash.bin @ 0x0100342A (00 ea 00 00: accepts any .odx over UDS without RSA)",
        )
    reporter.progress(100, 100)
    reporter.success(desc)
    return bytes(uf), desc


def apply_cflash_rsa_modulus(
    raw: bytes,
    modulus_128b: bytes,
    *,
    patch_swap: bool = True,
    patch_fbl: bool = False,
    ignore_input_crc: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, list[str], int]:
    """Replace 128-byte RSA-1024 modulus (e=3) in Cflash (SWaP and/or FBL Sector 5) and update CRC-16."""
    if len(modulus_128b) != 128 or (modulus_128b[0] & 0x80) == 0:
        raise ValueError(
            tr(
                "Модуль RSA-1024 должен быть 128 байт со старшим битом 1.",
                "RSA-1024 modulus must be 128 bytes with MSB=1.",
            )
        )
    reporter.step(1, 2, tr("Замена модуля RSA-1024 в CodeFlash", "Updating RSA-1024 modulus in CodeFlash"))
    prefix, app = split_cflash_or_app(raw)
    prefix_mut = bytearray(prefix)

    _, range_cnt = struct.unpack_from("<HH", app, 0x1C)
    if range_cnt == 0:
        if ignore_input_crc:
            struct.pack_into("<H", app, 0x1E, 1)
        else:
            raise RuntimeError(
                tr(
                    "Поле [0x0000C21E] == 0 (счётчик диапазонов CRC-16 занулён). Включите автоисправление CRC.",
                    "Header field [0x0000C21E] == 0 (CRC-16 range count zeroed). Enable ignore/repair input CRC.",
                )
            )
    else:
        stored_crc, calc_crc = app_crc(app)
        if stored_crc != calc_crc and not ignore_input_crc:
            raise RuntimeError(
                tr(
                    f"Не совпадает входной CRC-16 @ 0x0000C21C (в файле 0x{stored_crc:04X}, расчёт 0x{calc_crc:04X}).",
                    f"Input Application CRC-16 mismatch @ 0x0000C21C (stored 0x{stored_crc:04X}, calculated 0x{calc_crc:04X}).",
                )
            )

    notes: list[str] = []
    if patch_swap:
        swap_hits = find_swap_rsa_modulus_sites(bytes(app))
        if len(swap_hits) != 1:
            raise RuntimeError(
                tr(
                    f"Не найден уникальный ключ SWaP RSA-1024 в CodeFlash (совпадений: {len(swap_hits)})",
                    f"Unique SWaP RSA-1024 key not found in CodeFlash (matches: {len(swap_hits)})",
                )
            )
        soff = swap_hits[0]
        app[soff : soff + 128] = modulus_128b
        notes.append(
            tr(
                f"SWaP RSA-1024 N в CodeFlash @ 0x{APP_BASE + soff:06X} ({modulus_128b[:8].hex()}…)",
                f"SWaP RSA-1024 N in CodeFlash @ 0x{APP_BASE + soff:06X} ({modulus_128b[:8].hex()}…)",
            )
        )

    if patch_fbl:
        if not prefix_mut:
            raise ValueError(
                tr(
                    "Ключ FBL RSA-1024 лежит в Sector 5 @ 0x0000A2F7 — нужен полный 1.5 МБ CodeFlash.bin (не FD_0DATA)!",
                    "FBL RSA-1024 key resides in Sector 5 @ 0x0000A2F7 — full 1.5 MB CodeFlash.bin is required (not FD_0DATA)!",
                )
            )
        prefix_mut[FBL_EXP_OFFSET : FBL_EXP_OFFSET + 128] = (b"\x00" * 127) + b"\x03"
        prefix_mut[FBL_MOD_OFFSET : FBL_MOD_OFFSET + 128] = modulus_128b
        notes.append(
            tr(
                f"FBL (ODX) RSA-1024 N в Sector 5 @ 0x{FBL_MOD_OFFSET:06X} ({modulus_128b[:8].hex()}…)",
                f"FBL (ODX) RSA-1024 N in Sector 5 @ 0x{FBL_MOD_OFFSET:06X} ({modulus_128b[:8].hex()}…)",
            )
        )

    reporter.progress(60, 100)
    reporter.step(2, 2, tr("Пересчёт Application CRC-16 @ 0x0000C21C", "Recalculating Application CRC-16 @ 0x0000C21C"))
    _, new_crc = app_crc(app)
    struct.pack_into("<H", app, 0x001C, new_crc)
    reporter.progress(100, 100)
    for n in notes:
        reporter.success(n)
    return bytes(prefix_mut) + bytes(app), notes, new_crc


def apply_dflash_swap_rsa_modulus(
    df_raw: bytes,
    modulus_128b: bytes,
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, int, bytes]:
    """Update cached SWaP RSA-1024 modulus in Dflash NvM 0x7C @ 0xDB04..0xDB83 and recalculate CRC-32 @ 0xDCE4."""
    validate_dflash_bytes(df_raw)
    if len(modulus_128b) != 128 or (modulus_128b[0] & 0x80) == 0:
        raise ValueError(
            tr(
                "Модуль RSA-1024 должен быть 128 байт со старшим битом 1.",
                "RSA-1024 modulus must be 128 bytes with MSB=1.",
            )
        )
    df = bytearray(df_raw)
    magic, = struct.unpack_from("<I", df, DFLASH_SWAP_NVM_OFF)
    if magic != 0x55555555:
        reporter.warning(
            tr(
                "Блок NvM 0x7C @ 0xDB00 пуст (Virgin) — шлюз сам скопирует ключ из CodeFlash при первом старте.",
                "NvM 0x7C @ 0xDB00 is uninitialized (Virgin) — gateway will populate it from CodeFlash on first boot.",
            )
        )
        return bytes(df), 0, b""

    pay_start = DFLASH_SWAP_NVM_OFF + 4
    df[pay_start : pay_start + 128] = modulus_128b
    df[pay_start + 0x80 : pay_start + 0x100] = (b"\x00" * 127) + b"\x03"
    vcrn_5b = bytes(df[pay_start + 0x108 : pay_start + 0x10D])
    if df[pay_start + 0x10D] == 0:
        df[pay_start + 0x10D] = 1
    new_crc32 = zlib.crc32(df[pay_start : pay_start + DFLASH_SWAP_PAY_SIZE]) & 0xFFFFFFFF
    struct.pack_into("<I", df, DFLASH_SWAP_CRC_OFF, new_crc32)
    reporter.success(
        tr(
            f"Кэш SWaP RSA в DataFlash NvM 0x7C @ 0xDB04 обновлён (CRC-32=0x{new_crc32:08X}, VCRN={vcrn_5b.hex().upper()})",
            f"Updated SWaP RSA cache in DataFlash NvM 0x7C @ 0xDB04 (CRC-32=0x{new_crc32:08X}, VCRN={vcrn_5b.hex().upper()})",
        )
    )
    return bytes(df), new_crc32, vcrn_5b


def parse_fec_code(raw: str | int) -> int:
    """Parse a 32-bit VAG SWaP FeC / FS-ID code (e.g. '10000100', '0x10000300', or int)."""
    if isinstance(raw, int):
        val = raw
    else:
        tok = str(raw).strip()
        if tok.lower().startswith("0x"):
            tok = tok[2:]
        if not tok or len(tok) > 8 or not re.fullmatch(r"[0-9a-fA-F]+", tok):
            raise ValueError(
                tr(
                    f"Неверный формат кода FeC '{raw}' — ожидается 8 hex-символов (напр. 10000100)",
                    f"Invalid FeC code '{raw}' — expected up to 8 hex characters (e.g. 10000100)",
                )
            )
        val = int(tok, 16)
    if not (0 < val <= 0xFFFFFFFF):
        raise ValueError(tr(f"Код FeC вне диапазона: 0x{val:X}", f"FeC code out of range: 0x{val:X}"))
    return val


def parse_fec_list(tokens: Iterable[str | int]) -> list[int]:
    """Parse and deduplicate a sequence of FeC codes (accepts space/comma-separated strings or ints)."""
    out: list[int] = []
    seen: set[int] = set()
    for item in tokens:
        if isinstance(item, int):
            codes = [parse_fec_code(item)]
        else:
            parts = [p for p in re.split(r"[,;\s]+", str(item).strip()) if p]
            codes = [parse_fec_code(p) for p in parts]
        for c in codes:
            if c not in seen:
                seen.add(c)
                out.append(c)
    return out


def build_factory_multi_fsc_slot(
    fec_code: int,
    vcrn_5b: bytes,
    vin_str: str = "",
    *,
    timestamp_unix: int | None = None,
) -> tuple[bytes, bytes, int]:
    """Build a 192-byte (0xC0) factory Multi-FSC DataFlash slot record + 14-byte NvM 0x7C header entry.

    Uses the native Continental J533 EOL split Multi-FSC layout (171-byte FSC v2 payload with
    128 zero signature bytes, 1 zero alignment pad byte at +0xAF, LE CRC-32 at +0xB0..+0xB3,
    12 erased 0xFF bytes at +0xB4..+0xBF, and NvM 0x7C header flag 0xFF 0x01).
    """
    if len(vcrn_5b) != 5:
        raise ValueError(
            tr("VCRN должен иметь длину ровно 5 байт (10 hex-символов)", "VCRN must be exactly 5 bytes (10 hex chars)")
        )
    vin_clean = vin_str.strip().upper()
    if vin_clean:
        if len(vin_clean) != 17 or not all(0x20 <= ord(ch) <= 0x7E for ch in vin_clean):
            raise ValueError(
                tr("VIN должен содержать ровно 17 ASCII-символов", "VIN must be exactly 17 ASCII characters")
            )
        vin_field = vin_clean.encode("ascii") + b"\x00"
    else:
        vin_field = b"\x00" * 18

    fec_u32 = parse_fec_code(fec_code)
    ts = int(time.time()) if timestamp_unix is None else int(timestamp_unix)
    if not 0 <= ts <= 0xFFFFFFFF:  # the slot holds it in 32 bits: refuse, never cut to fit
        raise ValueError(tr(f"Время вне диапазона 0..0xFFFFFFFF: {ts}", f"Timestamp out of range 0..0xFFFFFFFF: {ts}"))
    ts_u32 = max(1, ts & 0xFFFFFFFF)

    spay = (
        b"\x11\x02"
        + struct.pack(">I", fec_u32)
        + b"\x03"
        + bytes(vcrn_5b)
        + vin_field
        + struct.pack(">I", ts_u32)
        + (b"\x00" * 9)
        + (b"\x00" * 128)
    )
    assert len(spay) == DFLASH_FSC_PAY_SIZE
    slot_crc = zlib.crc32(spay) & 0xFFFFFFFF
    slot_record = (
        struct.pack("<I", 0x55555555)
        + spay
        + b"\x00"
        + struct.pack("<I", slot_crc)
        + (b"\xff" * 12)
    )
    assert len(slot_record) == DFLASH_FSC_STRIDE
    ent_header = b"\x00\x00\x00\x00" + struct.pack(">II", fec_u32, ts_u32) + b"\xff\x01"
    assert len(ent_header) == 14
    return slot_record, ent_header, slot_crc


def apply_dflash_swap_fecs(
    df_raw: bytes,
    *,
    enable_fecs: Iterable[str | int] = (),
    disable_fecs: Iterable[str | int] = (),
    vin: str | None = None,
    timestamp_unix: int | None = None,
    preserve_existing_active: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, dict[str, Any]]:
    """Directly activate/deactivate SWaP FeC codes in DataFlash (Multi-FSC) without RSA keys or CodeFlash edits.

    Validates each requested FeC against the ZDC parameterization datasets currently flashed in DataFlash
    (0x0000..0x303F). If a selected FeC is not supported by the current dataset, activation STILL proceeds
    and emits the warning `"Unsupported Dataset: Selected FEC not supported by current dataset"`.
    """
    reporter.step(
        1,
        3,
        tr(
            "Проверка кэша SWaP (NvM 0x7C) и текущих датасетов ZDC в DataFlash",
            "Validating SWaP cache (NvM 0x7C) & current ZDC datasets in DataFlash",
        ),
    )
    validate_dflash_bytes(df_raw)
    sw_before = analyze_dflash_swap(df_raw)
    if not sw_before.magic_ok or not sw_before.initialized or sw_before.vcrn in (b"", b"\x00" * 5, b"\xff" * 5):
        raise ValueError(
            tr(
                "Область SWaP NvM 0x7C (0xDB00) пуста или не инициализирована (нет аппаратного VCRN). "
                "Один раз запустите шлюз на столе и вычитайте инициализированный DataFlash.",
                "SWaP NvM 0x7C (0xDB00) is empty or uninitialized (missing hardware VCRN). "
                "Boot the gateway once on bench and read back the initialized DataFlash.",
            )
        )

    enable_list = parse_fec_list(enable_fecs)
    disable_list = parse_fec_list(disable_fecs)
    enable_set = set(enable_list)

    disable_list = [c for c in disable_list if c not in enable_set]  # enabling wins: never erase a kept certificate
    if not preserve_existing_active:
        for active_slot in sw_before.active_fscs:
            if active_slot.fec_code not in enable_set and active_slot.fec_code not in disable_list:
                disable_list.append(active_slot.fec_code)

    effective_vin = sw_before.vin if vin is None else vin.strip().upper()
    if effective_vin and (len(effective_vin) != 17 or not all(0x20 <= ord(ch) <= 0x7E for ch in effective_vin)):
        raise ValueError(
            tr("VIN должен содержать ровно 17 ASCII-символов", "VIN must be exactly 17 ASCII characters")
        )

    ds_summary = analyze_dflash_datasets(df_raw)
    unsupported_fecs: list[int] = []
    warnings: list[str] = []
    for fec in enable_list:
        sup = check_fec_dataset_support(ds_summary, fec, raw_df=df_raw)
        if not sup.supported:
            unsupported_fecs.append(fec)
            msg = f"{tr(UNSUPPORTED_DATASET_RU, UNSUPPORTED_DATASET_WARNING)} (0x{fec:08X} — {sup.reason})"
            warnings.append(msg)
            reporter.warning(msg)

    reporter.progress(35, 100)
    reporter.step(
        2,
        3,
        tr(
            "Запись слотов Multi-FSC (0xDD00..0xE83F) без модификации RSA-ключей",
            "Writing Multi-FSC slots (0xDD00..0xE83F) without modifying RSA keys",
        ),
    )

    df = bytearray(df_raw)
    pay_start = DFLASH_SWAP_NVM_OFF + 4
    pay = bytearray(df[pay_start : pay_start + DFLASH_SWAP_PAY_SIZE])
    vcrn_5b = bytes(pay[0x108:0x10D])

    # Map existing FeC -> slot index
    fec_to_slot: dict[int, int] = {}
    used_slots: set[int] = set()
    for slot in range(15):
        ent = bytes(pay[0x10E + slot * 14 : 0x10E + (slot + 1) * 14])
        fec_meta, _ = struct.unpack_from(">II", ent, 4)
        off = DFLASH_FSC_BASE_OFF + slot * DFLASH_FSC_STRIDE
        smagic, = struct.unpack_from("<I", df, off)
        fec_rec = 0
        if smagic == 0x55555555 and df[off + 4 : off + 6] == b"\x11\x02":
            fec_rec, = struct.unpack_from(">I", df, off + 6)
        fec_here = fec_rec or fec_meta
        if fec_here != 0 and fec_here not in fec_to_slot:
            fec_to_slot[fec_here] = slot
            used_slots.add(slot)

    # Ensure canonical slots 0..12 are reserved/initialized for the 13 Gateway FeCs when blank
    for canon_slot, canon_fec in enumerate(GATEWAY_SWAP_SLOT_ORDER):
        ent_slice = slice(0x10E + canon_slot * 14, 0x10E + (canon_slot + 1) * 14)
        if canon_fec not in fec_to_slot and canon_slot not in used_slots:
            fec_to_slot[canon_fec] = canon_slot
            used_slots.add(canon_slot)
            if bytes(pay[ent_slice]) == b"\x00" * 14:
                pay[ent_slice] = b"\x00\x00\x00\x00" + struct.pack(">II", canon_fec, 0) + b"\xb0\x02"

    def _allocate_slot(fec_val: int) -> int:
        if fec_val in fec_to_slot:
            return fec_to_slot[fec_val]
        for s in range(15):
            if s not in used_slots:
                fec_to_slot[fec_val] = s
                used_slots.add(s)
                return s
        raise ValueError(
            tr(
                f"Нет свободных слотов FSC (все 15 слотов заняты) для FeC 0x{fec_val:08X}",
                f"No free FSC slots available (all 15 slots occupied) for FeC 0x{fec_val:08X}",
            )
        )

    existing_active_by_fec = {f.fec_code: f for f in sw_before.active_fscs}
    erased_slot = b"\xff" * DFLASH_FSC_STRIDE
    disabled_applied: list[int] = []

    for fec in disable_list:
        if fec not in fec_to_slot:
            continue
        slot = fec_to_slot[fec]
        off = DFLASH_FSC_BASE_OFF + slot * DFLASH_FSC_STRIDE
        df[off : off + DFLASH_FSC_STRIDE] = erased_slot
        ent_slice = slice(0x10E + slot * 14, 0x10E + (slot + 1) * 14)
        if slot < len(GATEWAY_SWAP_SLOT_ORDER) and GATEWAY_SWAP_SLOT_ORDER[slot] == fec:
            pay[ent_slice] = b"\x00\x00\x00\x00" + struct.pack(">II", fec, 0) + b"\xb0\x02"
        else:
            pay[ent_slice] = b"\x00" * 14
            used_slots.discard(slot)
            fec_to_slot.pop(fec, None)
        disabled_applied.append(fec)
        reporter.info(
            tr(
                f"Деактивирован FeC 0x{fec:08X} (слот #{slot:02d} @ 0x{off:04X} -> FF..FF)",
                f"Deactivated FeC 0x{fec:08X} (slot #{slot:02d} @ 0x{off:04X} -> FF..FF)",
            )
        )

    base_ts = int(time.time()) if timestamp_unix is None else int(timestamp_unix)
    enabled_applied: list[int] = []

    for fec in enable_list:
        slot = _allocate_slot(fec)
        off = DFLASH_FSC_BASE_OFF + slot * DFLASH_FSC_STRIDE
        ent_slice = slice(0x10E + slot * 14, 0x10E + (slot + 1) * 14)
        cur_active = existing_active_by_fec.get(fec)
        if (
            cur_active is not None
            and cur_active.slot_idx == slot
            and cur_active.crc_ok
            and (vin is None or cur_active.vin == effective_vin)
            and timestamp_unix is None
        ):
            # A valid certificate stays byte for byte: rebuilding a VAG-signed one would drop its signature.
            if pay[ent_slice][12] != 0xFF:
                pay[ent_slice] = b"\x00\x00\x00\x00" + struct.pack(">II", fec, cur_active.timestamp) + b"\xff\x01"
            enabled_applied.append(fec)
            continue
        if cur_active is not None and cur_active.crc_ok and not cur_active.factory_eol:
            reporter.warning(
                tr(
                    f"Подписанный сертификат 0x{fec:08X} заменяется записью без подписи (другой VIN или время) — "
                    "подпись VAG останется только в исходном бэкапе",
                    f"The signed certificate 0x{fec:08X} is replaced by an unsigned record (other VIN or time) — "
                    "the VAG signature stays only in the original backup",
                )
            )

        prev_ts = sw_before.slot_timestamps.get(fec, 0)
        ts_use = max(base_ts, prev_ts) if timestamp_unix is None else base_ts
        slot_rec, ent_hdr, slot_crc = build_factory_multi_fsc_slot(
            fec,
            vcrn_5b,
            effective_vin,
            timestamp_unix=ts_use,
        )
        df[off : off + DFLASH_FSC_STRIDE] = slot_rec
        pay[ent_slice] = ent_hdr
        enabled_applied.append(fec)
        fec_names = KNOWN_GATEWAY_FECS.get(fec)
        desc = (fec_names[1] if get_lang() == "en" else fec_names[0]) if fec_names else f"0x{fec:08X}"
        reporter.success(
            tr(
                f"Активирован Multi-FSC слот #{slot:02d} @ 0x{off:04X}: {desc} (CRC-32=0x{slot_crc:08X})",
                f"Activated Multi-FSC slot #{slot:02d} @ 0x{off:04X}: {desc} (CRC-32=0x{slot_crc:08X})",
            )
        )

    reporter.progress(80, 100)
    reporter.step(
        3,
        3,
        tr(
            "Пересчёт контрольной суммы NvM 0x7C CRC-32 @ 0xDCE4",
            "Recalculating NvM 0x7C CRC-32 @ 0xDCE4",
        ),
    )
    df[pay_start : pay_start + DFLASH_SWAP_PAY_SIZE] = pay
    nvm7c_crc = zlib.crc32(pay) & 0xFFFFFFFF
    struct.pack_into("<I", df, DFLASH_SWAP_CRC_OFF, nvm7c_crc)

    out_bytes = bytes(df)
    sw_after = analyze_dflash_swap(out_bytes)
    reporter.progress(100, 100)
    reporter.success(
        tr(
            f"DataFlash SWaP обновлён: активных функций {len(sw_after.active_fscs)}, NvM 0x7C CRC-32=0x{nvm7c_crc:08X}",
            f"DataFlash SWaP updated: {len(sw_after.active_fscs)} active feature(s), NvM 0x7C CRC-32=0x{nvm7c_crc:08X}",
        )
    )
    summary: dict[str, Any] = {
        "vcrn": vcrn_5b.hex().upper(),
        "vin": effective_vin,
        "nvm_7c_crc32": nvm7c_crc,
        "enabled_fecs": [f"0x{c:08X}" for c in enabled_applied],
        "disabled_fecs": [f"0x{c:08X}" for c in disabled_applied],
        "active_fecs": [f"0x{f.fec_code:08X}" for f in sw_after.active_fscs],
        "unsupported_fecs": [f"0x{c:08X}" for c in unsupported_fecs],
        "warnings": warnings,
    }
    return out_bytes, summary


def apply_cflash_patch(
    raw: bytes,
    *,
    mode: str = "hybrid",
    bypass_eeprom_mask: bool = False,
    preserve_existing_mask_bypass: bool = False,
    cave_vaddr: int = DEFAULT_CAVE_VADDR,
    ignore_input_crc: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, str, int]:
    """Patch or restore KSCHUTZ CP callback in Cflash/FD_0DATA and return (out_bytes, description, new_crc16)."""
    reporter.step(1, 3, tr("Проверка входного CodeFlash и заголовка @ 0x0000C200", "Checking input CodeFlash & header @ 0x0000C200"))
    prefix, app = split_cflash_or_app(raw)
    _, range_cnt = struct.unpack_from("<HH", app, 0x1C)
    if range_cnt == 0:
        if ignore_input_crc or mode == "restore_stock":
            struct.pack_into("<H", app, 0x1E, 1)
        else:
            raise RuntimeError(
                tr(
                    "Поле [0x0000C21E] == 0 (счётчик диапазонов CRC-16 занулён — FBL FF 01 отвергает такой образ). "
                    "Включите игнорирование/ремонт входного CRC-16.",
                    "Header field [0x0000C21E] == 0 (CRC-16 range count zeroed — rejected by FBL FF 01). "
                    "Enable ignore/repair input CRC-16.",
                )
            )
    else:
        stored_crc, calc_crc = app_crc(app)
        if stored_crc != calc_crc and not ignore_input_crc:
            raise RuntimeError(
                tr(
                    f"Не совпадает входной CRC-16 приложения @ 0x0000C21C "
                    f"(в файле 0x{stored_crc:04X}, расчёт 0x{calc_crc:04X}).",
                    f"Input Application CRC-16 mismatch @ 0x0000C21C "
                    f"(stored 0x{stored_crc:04X}, calculated 0x{calc_crc:04X}).",
                )
            )
    reporter.progress(30, 100)

    reporter.step(2, 3, tr("Установка патча KSCHUTZ и проверка области трамплина", "Applying KSCHUTZ patch & verifying trampoline cave"))
    hits = find_kschutz_hook_sites(bytes(app))
    if len(hits) != 1:
        raise RuntimeError(
            tr(
                f"Ожидалась ровно 1 точка KSCHUTZ callback, найдено: {len(hits)}",
                f"Expected exactly 1 KSCHUTZ callback site, found: {len(hits)}",
            )
        )
    hook_off = hits[0]
    hook_vaddr = APP_BASE + hook_off
    old_insn = bytes(app[hook_off : hook_off + 4])
    old_jr = decode_jr_disp22(hook_vaddr, old_insn)

    cave_off = cave_vaddr - APP_BASE
    if not (0x0040 <= cave_off <= len(app) - CAVE_SIZE) or (cave_vaddr & 3) != 0:
        raise ValueError(
            tr(
                f"Некорректный адрес трамплина cave_vaddr: 0x{cave_vaddr:06X}",
                f"Invalid trampoline address cave_vaddr: 0x{cave_vaddr:06X}",
            )
        )

    if old_jr is not None:
        prev_off = old_jr - APP_BASE
        expected_prev = build_hybrid_cave(old_jr, hook_vaddr + 4)
        if 0 <= prev_off <= len(app) - CAVE_SIZE and bytes(app[prev_off : prev_off + CAVE_SIZE]) == expected_prev:
            app[prev_off : prev_off + CAVE_SIZE] = b"\xff" * CAVE_SIZE

    mask_hits = find_eeprom_mask_branch_sites(bytes(app))

    if mode == "restore_stock":
        app[hook_off : hook_off + 4] = STOCK_MOVEA_0X40
        for moff in mask_hits:
            app[moff : moff + 2] = b"\x82\x3d"
        desc = tr(
            f"возврат заводского кода movea 0x40 @ 0x{hook_vaddr:06X} + восстановление проверки 95640",
            f"restored stock movea 0x40 @ 0x{hook_vaddr:06X} + restored 95640 mask check",
        )
    elif mode == "global_plain":
        app[hook_off : hook_off + 4] = PATCH_MOVEA_0X10
        desc = tr(
            f"глобальный стендовый режим movea 0x10 @ 0x{hook_vaddr:06X}",
            f"global bench mode movea 0x10 @ 0x{hook_vaddr:06X}",
        )
    elif mode == "hybrid":
        cave_slice = bytes(app[cave_off : cave_off + CAVE_SIZE])
        expected_cave = build_hybrid_cave(cave_vaddr, hook_vaddr + 4)
        if cave_slice != (b"\xff" * CAVE_SIZE) and cave_slice != expected_cave:
            raise RuntimeError(
                tr(
                    f"Область под трамплин @ 0x{cave_vaddr:06X} не пуста (не 0xFF): {cave_slice.hex()}",
                    f"Trampoline cave region @ 0x{cave_vaddr:06X} is not empty (not 0xFF): {cave_slice.hex()}",
                )
            )
        app[cave_off : cave_off + CAVE_SIZE] = expected_cave
        app[hook_off : hook_off + 4] = encode_jr_disp22(hook_vaddr, cave_vaddr)
        desc = tr(
            f"гибридный трамплин jr 0x{cave_vaddr:06X} @ 0x{hook_vaddr:06X} "
            f"({CAVE_SIZE} Б -> возврат 0x{hook_vaddr + 4:06X})",
            f"hybrid trampoline jr 0x{cave_vaddr:06X} @ 0x{hook_vaddr:06X} "
            f"({CAVE_SIZE} B -> return 0x{hook_vaddr + 4:06X})",
        )
    else:
        raise ValueError(tr(f"Неизвестный режим патча: {mode}", f"Unknown patch mode: {mode}"))

    if mode != "restore_stock":
        if bypass_eeprom_mask:
            if len(mask_hits) != 1:
                raise RuntimeError(
                    tr(
                        f"Ожидалась ровно 1 точка проверки маски 95640, найдено: {len(mask_hits)}",
                        f"Expected exactly 1 95640 EEPROM mask check site, found: {len(mask_hits)}",
                    )
                )
            app[mask_hits[0] : mask_hits[0] + 2] = b"\x00\x00"
            desc += tr(
                f" + обход маски 95640 @ 0x{APP_BASE + mask_hits[0]:06X}",
                f" + 95640 mask bypass @ 0x{APP_BASE + mask_hits[0]:06X}",
            )
        elif not preserve_existing_mask_bypass and len(mask_hits) == 1:
            app[mask_hits[0] : mask_hits[0] + 2] = b"\x82\x3d"

    reporter.progress(70, 100)
    reporter.step(3, 3, tr("Пересчёт Application CRC-16 @ 0x0000C21C", "Recalculating Application CRC-16 @ 0x0000C21C"))
    _, new_crc = app_crc(app)
    struct.pack_into("<H", app, 0x001C, new_crc)
    reporter.progress(100, 100)
    reporter.success(f"{desc} | CRC-16 = 0x{new_crc:04X}")
    return prefix + bytes(app), desc, new_crc


def build_plaintext_dflash_record(spec: SlotSpec, key_bytes: bytes) -> tuple[bytes, int]:
    """Build 128-byte Dflash record (0x55555555 + plaintext 16B key + zero tail + trailer + CRC-32)."""
    if len(key_bytes) != 16:
        raise ValueError(
            tr(
                f"Ключ CP должен быть ровно 16 байт (32 hex-символа), получено {len(key_bytes)} Б",
                f"CP key must be exactly 16 bytes (32 hex chars), got {len(key_bytes)} B",
            )
        )
    payload = bytearray(spec.rec_size)
    payload[0:16] = key_bytes
    if spec.rec_size == 0x42:
        payload[0x40:0x42] = b"\x2d\xdb"
    crc = zlib.crc32(payload) & 0xFFFFFFFF

    rec = bytearray(b"\xff" * 0x80)
    rec[0x00:0x04] = b"\x55\x55\x55\x55"
    rec[0x04 : 0x04 + spec.rec_size] = payload
    if spec.rec_size == 0x42:
        rec[0x46:0x48] = b"\x18\x92"
        struct.pack_into("<I", rec, 0x48, crc)
    else:
        struct.pack_into("<I", rec, 0x44, crc)
    return bytes(rec), crc


def write_dflash_slots(
    df_raw: bytes,
    updates: list[tuple[SlotSpec, bytes]],
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, list[tuple[SlotSpec, int]]]:
    """Write one or more 16-byte plaintext keys into primary & mirror Dflash slots."""
    validate_dflash_bytes(df_raw)
    df = bytearray(df_raw)
    written: list[tuple[SlotSpec, int]] = []
    total = max(1, len(updates))
    for idx, (spec, key_bytes) in enumerate(updates, start=1):
        rec, crc = build_plaintext_dflash_record(spec, key_bytes)
        df[spec.off1 : spec.off1 + 0x80] = rec
        df[spec.off2 : spec.off2 + 0x80] = rec
        written.append((spec, crc))
        reporter.progress(idx, total)
        reporter.success(
            tr(
                f"Записан Банк #{spec.slot} (ЭБУ {spec.ecu_addr} — {spec.short}) @ 0x{spec.off1:04X}/0x{spec.off2:04X}, CRC-32=0x{crc:08X}",
                f"Wrote Bank #{spec.slot} (ECU {spec.ecu_addr} — {spec.short}) @ 0x{spec.off1:04X}/0x{spec.off2:04X}, CRC-32=0x{crc:08X}",
            )
        )
    return bytes(df), written


def clear_dflash_slots(
    df_raw: bytes,
    specs: list[SlotSpec],
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Erase one or more Dflash CP banks (primary + mirror = 256 bytes) back to 0xFF."""
    validate_dflash_bytes(df_raw)
    df = bytearray(df_raw)
    erased = b"\xff" * 0x80
    total = max(1, len(specs))
    for idx, spec in enumerate(specs, start=1):
        df[spec.off1 : spec.off1 + 0x80] = erased
        df[spec.off2 : spec.off2 + 0x80] = erased
        reporter.progress(idx, total)
        reporter.info(
            tr(
                f"Очищен Банк #{spec.slot} (ЭБУ {spec.ecu_addr}) @ 0x{spec.off1:04X}/0x{spec.off2:04X} -> FF..FF",
                f"Cleared Bank #{spec.slot} (ECU {spec.ecu_addr}) @ 0x{spec.off1:04X}/0x{spec.off2:04X} -> FF..FF",
            )
        )
    return bytes(df)


def bind_cp_turnkey(
    cflash_raw: bytes,
    dflash_raw: bytes,
    updates: list[tuple[SlotSpec, bytes]],
    *,
    auto_bypass_empty_banks: bool = True,
    force_bypass_eeprom_mask: bool = False,
    ignore_input_crc: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, bytes, dict]:
    """Turnkey offline CP binding: analyzes empty banks, patches Cflash (hybrid + auto 95640 mask), writes Dflash."""
    reporter.step(1, 3, tr("Анализ существующих банков CP в DataFlash (64 КБ)", "Analyzing existing CP banks in DataFlash (64 KB)"))
    before_states = {st.spec.slot: st for st in analyze_dflash(dflash_raw)}
    empty_retrofits = [
        spec for spec, _ in updates if spec.slot > 0 and before_states[spec.slot].empty
    ]
    need_mask_bypass = force_bypass_eeprom_mask or (auto_bypass_empty_banks and bool(empty_retrofits))
    if empty_retrofits and need_mask_bypass:
        names = ", ".join(f"#{s.slot} ({s.ecu_addr})" for s in empty_retrofits)
        reporter.info(
            tr(
                f"Обнаружено дооснащение в ранее пустые банки [{names}] — автоматически включён обход маски 95640 SPI EEPROM.",
                f"Detected retrofit into previously empty banks [{names}] — automatically enabling 95640 SPI EEPROM mask bypass.",
            )
        )
    reporter.progress(30, 100)

    reporter.step(2, 3, tr("Установка гибридного патча KSCHUTZ в CodeFlash", "Installing hybrid KSCHUTZ patch in CodeFlash"))
    patched_cf, cf_desc, new_crc = apply_cflash_patch(
        cflash_raw,
        mode="hybrid",
        bypass_eeprom_mask=need_mask_bypass,
        preserve_existing_mask_bypass=True,
        ignore_input_crc=ignore_input_crc,
    )
    reporter.info(f"{cf_desc} (CRC-16: 0x{new_crc:04X})")
    reporter.progress(65, 100)

    reporter.step(3, 3, tr("Запись 16-байтных ключей IKA и пересчёт CRC-32 в DataFlash", "Writing 16-byte IKA keys & CRC-32 into DataFlash"))
    patched_df, written_crcs = write_dflash_slots(dflash_raw, updates, reporter=reporter)
    reporter.progress(100, 100)
    summary = {
        "cflash_description": cf_desc,
        "cflash_crc16": new_crc,
        "eeprom_mask_bypassed": need_mask_bypass,
        "empty_retrofits": [s.ecu_addr for s in empty_retrofits],
        "written_banks": [{"slot": s.slot, "ecu": s.ecu_addr, "crc32": f"0x{c:08X}"} for s, c in written_crcs],
    }
    return patched_cf, patched_df, summary


def parse_slot_selector(token: str, *, allow_master: bool = False) -> SlotSpec:
    """Resolve bank number ('1'..'12', 'bank7', 'slot5') OR VAG ECU code ('17', '09', '5F', '47', 'A5', ...)."""
    t = token.strip().lower()
    if not t:
        raise ValueError(tr("Пустой идентификатор банка/блока", "Empty bank/ECU selector"))

    for pfx in ("bank", "slot", "банк", "слот", "b"):
        if t.startswith(pfx) and t[len(pfx):].strip().isdigit():
            num = int(t[len(pfx):].strip(), 10)
            for s in ALL_SLOTS:
                if s.slot == num:
                    if s.slot == 0 and not allow_master:
                        raise ValueError(
                            tr(
                                "Банк 0 (мастер-ключ самого шлюза 19) защищён от случайной перезаписи.",
                                "Bank 0 (Gateway 19 own master key) is protected from accidental overwrite.",
                            )
                        )
                    return s
            raise ValueError(
                tr(
                    f"Неизвестный номер банка: {num} (доступны банки 1..12)",
                    f"Unknown bank number: {num} (valid slave banks are 1..12)",
                )
            )

    if t in ("09", "0x09", "ecu09", "stg09"):
        return SLAVE_SLOTS[1]

    if t.isdigit():
        num = int(t, 10)
        if 1 <= num <= 12:
            return SLAVE_SLOTS[num - 1]
        if num == 0:
            if not allow_master:
                raise ValueError(
                    tr(
                        "Банк 0 — это собственный мастер-ключ шлюза 19 (NvM 0x7B). "
                        "Для привязки ведомых блоков выбирайте банки 1..12 (либо флаг --force-master).",
                        "Bank 0 is Gateway 19's own master key (NvM 0x7B). "
                        "Select slave banks 1..12 when binding ECUs (or pass --force-master).",
                    )
                )
            return MASTER_SLOT

    t_clean = t[2:] if t.startswith("0x") else t
    for pfx in ("ecu", "stg", "блок"):
        if t_clean.startswith(pfx) and len(t_clean) > len(pfx):
            t_clean = t_clean[len(pfx):].strip(":-_ ")

    for s in ALL_SLOTS:
        if t_clean == s.ecu_addr.lower() or t in s.aliases or t_clean in s.aliases:
            if s.slot == 0 and not allow_master:
                raise ValueError(
                    tr(
                        "Блок 19 (мастер-ключ самого шлюза) трогать при привязке блоков не нужно!",
                        "Module 19 (Gateway own master key) must not be modified when binding slave ECUs!",
                    )
                )
            return s

    bank_word = tr("банк", "bank")
    valid_ecus = ", ".join(f"{s.ecu_addr} ({bank_word} {s.slot})" for s in SLAVE_SLOTS)
    raise ValueError(
        tr(
            f"Не удалось распознать банк или адрес ЭБУ '{token}'. "
            f"Укажите номер банка 1..12 или адрес блока VAG: {valid_ecus}",
            f"Could not recognize bank or VAG ECU address '{token}'. "
            f"Specify bank number 1..12 or VAG ECU code: {valid_ecus}",
        )
    )


def parse_slot_list(raw: str, *, allow_master: bool = False) -> list[SlotSpec]:
    parts = [p for p in re.split(r"[,;\s]+", raw.strip()) if p]
    if not parts:
        raise ValueError(tr("Не указан ни один банк", "No bank specified"))
    seen: set[int] = set()
    result: list[SlotSpec] = []
    for p in parts:
        spec = parse_slot_selector(p, allow_master=allow_master)
        if spec.slot not in seen:
            seen.add(spec.slot)
            result.append(spec)
    return result


def parse_hex_key(raw: str) -> bytes:
    """Parse 16-byte hex key in any common format (spaces, colons, dashes, commas, 0x prefixes)."""
    cleaned = re.sub(r"0x", "", raw.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"[\s:,\-_]+", "", cleaned)
    if not cleaned or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise ValueError(
            tr(
                "Ключ должен состоять только из шестнадцатеричных символов (0-9, A-F).",
                "Key must contain hexadecimal characters only (0-9, A-F).",
            )
        )
    if len(cleaned) != 32:
        raise ValueError(
            tr(
                f"Ключ CP должен иметь длину ровно 16 байт (32 hex-символа), вы ввели {len(cleaned)} симв.",
                f"CP key must be exactly 16 bytes (32 hex characters); you entered {len(cleaned)} chars.",
            )
        )
    return bytes.fromhex(cleaned)


def check_key_warnings(key_bytes: bytes) -> list[tuple[str, str]]:
    """Return list of (severity 'STOP'|'WARN', localized_message) for suspicious 16-byte keys."""
    warnings: list[tuple[str, str]] = []
    if key_bytes == SHE_M1_RAMKEY_KEY2:
        warnings.append((
            "STOP",
            tr(
                "Вы ввели '000000000000000000000000000000E5' — это НЕ ключ блока, а заголовок M1 "
                "зашифрованного контейнера SHE из самого гейтвея! Настоящий 16-байтный рабочий ключ IKA "
                "нужно вычитать из привязываемого ЭБУ (или задать одинаковый кастомный ключ с обеих сторон).",
                "You entered '000000000000000000000000000000E5' — that is NOT an ECU key, it is the SHE M1 "
                "container header from the gateway itself! Read the real 16-byte active IKA key from the "
                "target slave ECU (or program the same custom key into both sides).",
            ),
        ))
    elif key_bytes == b"\x00" * 16:
        warnings.append((
            "STOP",
            tr(
                "Вы ввели 16 нулевых байтов (00..00). Запись нулей в гейтвей НЕ отключает CP: "
                "блокировку включает САМ ведомый ЭБУ у себя внутри, сверяя ответ шлюза со своим ключом IKA (00 BE)! "
                "Ключ 00..00 сработает ТОЛЬКО если 00..00 также записаны в слот IKA самого блока.",
                "You entered 16 zero bytes (00..00). Writing zeros in the gateway NEVER bypasses CP: functional "
                "locks are enforced INSIDE the slave ECU against its own IKA (00 BE)! "
                "00..00 works ONLY if 00..00 is also written into the slave ECU's own IKA slot.",
            ),
        ))
    elif key_bytes == b"\xff" * 16:
        warnings.append((
            "WARN",
            tr(
                "Вы ввели 16 байтов FF..FF (транспортный ключ нового Virgin-блока). Это сработает только "
                "если в самом привязываемом блоке рабочий слот IKA содержит 16x0xFF.",
                "You entered 16 bytes of FF..FF (Virgin transport key). This works ONLY if the slave ECU's "
                "active IKA slot actually holds 16x0xFF.",
            ),
        ))
    elif len(set(key_bytes)) == 1:
        warnings.append((
            "WARN",
            tr(
                f"Все 16 байт ключа одинаковы (0x{key_bytes[0]:02X}). Убедитесь, что это действительно рабочий ключ IKA вашего блока.",
                f"All 16 bytes of the key are identical (0x{key_bytes[0]:02X}). Make sure this is really your ECU's active IKA key.",
            ),
        ))
    return warnings
