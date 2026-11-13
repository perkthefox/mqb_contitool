"""Decoders for Renesas RH850/F1L Option Bytes (OPBT) and external ST M95640 8 KB SPI EEPROM."""

from __future__ import annotations

import dataclasses
import struct

from contitool.core.constants import (
    EEPROM_SIZE,
    EXTRA_AREA_SIZE,
    OPBT_LEGACY_SIZE,
    OPBT_SIZE,
    SLAVE_SLOTS,
    SlotSpec,
)
from contitool.i18n import tr

# RH850/F1L User's Manual: Hardware (Table 35.34) — OPBT0 reserved bits that must be 1 on a programmed device
OPBT0_REQUIRED_ONES_MASK = 0x9A20FECF
OPBT_EXTRA_AREA_OFFSET = 0x70


def crc16_ccitt_false(data: bytes) -> int:
    """Standard CRC-16/CCITT-FALSE (poly=0x1021, init=0xFFFF, refin=False, xorout=0x0000) used by M95640 NvM blocks."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


@dataclasses.dataclass(frozen=True)
class OpbtField:
    bits: str
    name: str
    raw_value: int
    value_ru: str
    value_en: str

    @property
    def value_text(self) -> str:
        return tr(self.value_ru, self.value_en)


@dataclasses.dataclass
class OpbtSummary:
    size_bytes: int
    from_extra_area: bool
    words: tuple[int, ...]  # OPBT0..OPBT7 (8 words) or OPBT0..OPBT8 (9 words)
    opbt0: int
    opbt8: int | None
    reserved_bits_ok: bool
    blank: bool
    jtag_mode: int
    jtag_enabled: bool
    wdta0_enabled: bool
    wdta0_auto_start: bool
    wdta0_var_code: bool
    wdta1_enabled: bool
    wdta1_auto_start: bool
    wdta1_var_code: bool
    wdt_overflow_exp: int  # 2**(9 + val) / WDTATCKI -> wait: Table 35.34: 0..7 -> 2^9 .. 2^16
    memcdiv_div4: bool
    cvm_high_enabled: bool
    cvm_low_enabled: bool
    icus_activated: bool | None  # None when OPBT8 is absent (32-byte legacy dump)
    fields: tuple[OpbtField, ...]


def is_plausible_opbt_bytes(raw: bytes) -> bool:
    """Heuristic check so arbitrary 32/36/256-byte files are not misclassified as RH850 Option Bytes."""
    if len(raw) == EXTRA_AREA_SIZE:
        opbt_slice = raw[OPBT_EXTRA_AREA_OFFSET : OPBT_EXTRA_AREA_OFFSET + OPBT_SIZE]
    elif len(raw) in (OPBT_LEGACY_SIZE, OPBT_SIZE):
        opbt_slice = raw
    else:
        return False
    if all(b == 0xFF for b in opbt_slice):
        return True
    words = struct.unpack(f"<{len(opbt_slice) // 4}I", opbt_slice)
    if (words[0] & OPBT0_REQUIRED_ONES_MASK) != OPBT0_REQUIRED_ONES_MASK:
        return False
    # OPBT1 configures RH850/F1L PLL/clock/reset (e.g. 0xFEFFFBDB on J533); OPBT2..OPBT7 are unused/reserved.
    return all(w in (0x00000000, 0xFFFFFFFF) for w in words[2:8])


def analyze_opbt(raw: bytes) -> OpbtSummary:
    """Decode 32-byte (OPBT0..7), 36-byte (OPBT0..8), or 256-byte Extra Area dumps per RH850/F1L Table 35.34."""
    from_extra = False
    if len(raw) == EXTRA_AREA_SIZE:
        from_extra = True
        opbt_bytes = raw[OPBT_EXTRA_AREA_OFFSET : OPBT_EXTRA_AREA_OFFSET + OPBT_SIZE]
    elif len(raw) in (OPBT_LEGACY_SIZE, OPBT_SIZE):
        opbt_bytes = raw
    else:
        raise ValueError(
            tr(
                f"Ожидался дамп OPBT размером 32, 36 или 256 байт, получено: {len(raw)} Б",
                f"Expected a 32, 36, or 256-byte OPBT dump, got {len(raw)} B",
            )
        )

    n_words = len(opbt_bytes) // 4
    words = struct.unpack(f"<{n_words}I", opbt_bytes)
    opbt0 = words[0]
    opbt8 = words[8] if n_words >= 9 else None
    blank = all(w == 0xFFFFFFFF for w in words)
    reserved_ok = (opbt0 & OPBT0_REQUIRED_ONES_MASK) == OPBT0_REQUIRED_ONES_MASK

    jtag_mode = (opbt0 >> 29) & 0x3
    jtag_map = {
        0: (
            "Порт общего назначения JP0 (отладочный интерфейс JTAG/LPD отключён)",
            "General-purpose port JP0 (JTAG/LPD debug interface disabled)",
        ),
        1: ("1-проводной интерфейс LPD (1-pin LPD)", "1-pin LPD debug interface"),
        2: ("4-проводной интерфейс LPD (4-pin LPD)", "4-pin LPD debug interface"),
        3: ("Интерфейс отладки JTAG / Nexus", "JTAG / Nexus debug interface"),
    }

    wdt1_var = bool((opbt0 >> 26) & 1)
    wdt1_auto = bool((opbt0 >> 24) & 1)
    wdt1_en = bool((opbt0 >> 23) & 1)

    wdt0_var = bool((opbt0 >> 22) & 1)
    wdt0_auto = bool((opbt0 >> 20) & 1)
    wdt0_en = bool((opbt0 >> 19) & 1)

    wdt_sel = (opbt0 >> 16) & 0x7
    wdt_exp = 9 + wdt_sel  # 0 -> 2^9, ..., 7 -> 2^16 / WDTATCKI

    memcdiv_div4 = bool((opbt0 >> 8) & 1)
    cvm_hd = bool((opbt0 >> 5) & 1)
    cvm_ld = bool((opbt0 >> 4) & 1)

    icus_active: bool | None = None
    if opbt8 is not None:
        icus_active = opbt8 != 0xFFFFFFFF

    fields: list[OpbtField] = [
        OpbtField("30..29", "OPJTAG[1:0]", jtag_mode, *jtag_map[jtag_mode]),
        OpbtField(
            "26",
            "WDT1_3",
            int(wdt1_var),
            "Переменный код активации WDTA1" if wdt1_var else "Фиксированный код активации WDTA1 (0xAC)",
            "Variable WDTA1 activation code" if wdt1_var else "Fixed WDTA1 activation code (0xAC)",
        ),
        OpbtField(
            "24",
            "WDT1_1",
            int(wdt1_auto),
            "Автозапуск WDTA1 сразу после сброса" if wdt1_auto else "Запуск WDTA1 программным триггером",
            "WDTA1 starts automatically after reset" if wdt1_auto else "WDTA1 starts on software trigger",
        ),
        OpbtField(
            "23",
            "WDT1_0",
            int(wdt1_en),
            "WDTA1 включён" if wdt1_en else "WDTA1 выключен",
            "WDTA1 enabled" if wdt1_en else "WDTA1 disabled",
        ),
        OpbtField(
            "22",
            "WDT0_3",
            int(wdt0_var),
            "Переменный код активации WDTA0" if wdt0_var else "Фиксированный код активации WDTA0 (0xAC)",
            "Variable WDTA0 activation code" if wdt0_var else "Fixed WDTA0 activation code (0xAC)",
        ),
        OpbtField(
            "20",
            "WDT0_1",
            int(wdt0_auto),
            "Автозапуск WDTA0 сразу после сброса" if wdt0_auto else "Запуск WDTA0 программным триггером",
            "WDTA0 starts automatically after reset" if wdt0_auto else "WDTA0 starts on software trigger",
        ),
        OpbtField(
            "19",
            "WDT0_0",
            int(wdt0_en),
            "WDTA0 включён" if wdt0_en else "WDTA0 выключен",
            "WDTA0 enabled" if wdt0_en else "WDTA0 disabled",
        ),
        OpbtField(
            "18..16",
            "WDT_[2:0]",
            wdt_sel,
            f"Период переполнения 2^{wdt_exp} / WDTATCKI",
            f"Overflow interval 2^{wdt_exp} / WDTATCKI",
        ),
        OpbtField(
            "8",
            "MEMCDIV",
            int(memcdiv_div4),
            "Тактирование контроллера памяти CPUCLK/4 (штатно для 96 МГц)" if memcdiv_div4 else "Тактирование CPUCLK/2",
            "Memory controller clock CPUCLK/4 (standard for 96 MHz)" if memcdiv_div4 else "Memory controller clock CPUCLK/2",
        ),
        OpbtField(
            "5",
            "CVM_HD_EN",
            int(cvm_hd),
            "Монитор повышенного напряжения ядра включён" if cvm_hd else "Монитор повышенного напряжения выключен",
            "High core voltage monitor enabled" if cvm_hd else "High core voltage monitor disabled",
        ),
        OpbtField(
            "4",
            "CVM_LD_EN",
            int(cvm_ld),
            "Монитор пониженного напряжения ядра включён" if cvm_ld else "Монитор пониженного напряжения выключен",
            "Low core voltage monitor enabled" if cvm_ld else "Low core voltage monitor disabled",
        ),
    ]

    return OpbtSummary(
        size_bytes=len(raw),
        from_extra_area=from_extra,
        words=words,
        opbt0=opbt0,
        opbt8=opbt8,
        reserved_bits_ok=reserved_ok,
        blank=blank,
        jtag_mode=jtag_mode,
        jtag_enabled=(jtag_mode != 0),
        wdta0_enabled=wdt0_en,
        wdta0_auto_start=wdt0_auto,
        wdta0_var_code=wdt0_var,
        wdta1_enabled=wdt1_en,
        wdta1_auto_start=wdt1_auto,
        wdta1_var_code=wdt1_var,
        wdt_overflow_exp=wdt_exp,
        memcdiv_div4=memcdiv_div4,
        cvm_high_enabled=cvm_hd,
        cvm_low_enabled=cvm_ld,
        icus_activated=icus_active,
        fields=tuple(fields),
    )


@dataclasses.dataclass(frozen=True)
class EepromNvmRecord:
    nvm_id: int | None
    offset: int
    length: int
    crc_stored: int | None
    crc_calc: int | None
    crc_ok: bool | None  # None for headerless NvM 0x00/0x01 or erased records
    erased: bool
    mirrored: bool
    payload: bytes


@dataclasses.dataclass(frozen=True)
class EepromRdsrInfo:
    raw: int
    srwd: bool
    bp_bits: int
    wel: bool
    wip: bool
    protected_range_ru: str
    protected_range_en: str

    @property
    def protected_range(self) -> str:
        return tr(self.protected_range_ru, self.protected_range_en)


def decode_m95640_rdsr(rdsr: int) -> EepromRdsrInfo:
    """Decode ST M95640 Status Register (RDSR 0x05)."""
    v = rdsr & 0xFF
    bp = (v >> 2) & 0x3
    ranges = {
        0: ("Нет аппаратной защиты секторов (вся память открыта)", "None (entire array unprotected)"),
        1: ("Верхняя 1/4 памяти (0x1800..0x1FFF)", "Upper quarter (0x1800..0x1FFF)"),
        2: ("Верхняя 1/2 памяти (0x1000..0x1FFF)", "Upper half (0x1000..0x1FFF)"),
        3: ("Вся микросхема 8 КБ (0x0000..0x1FFF)", "Whole 8 KB memory (0x0000..0x1FFF)"),
    }
    return EepromRdsrInfo(
        raw=v,
        srwd=bool((v >> 7) & 1),
        bp_bits=bp,
        wel=bool((v >> 1) & 1),
        wip=bool(v & 1),
        protected_range_ru=ranges[bp][0],
        protected_range_en=ranges[bp][1],
    )


@dataclasses.dataclass
class EepromSummary:
    size_bytes: int
    blank: bool
    nonzero_bytes: int
    non_ff_bytes: int
    rdsr: EepromRdsrInfo | None
    # NvM 0x00 boot/ODX passport
    part_number: str
    sw_version: str
    asam_id: str
    odx_version: str
    # Vehicle / coding / workshop records
    vin: str
    prog_date: str       # YYYY-MM-DD from BCD NvM 0x08 if valid
    prog_counter: int | None
    workshop_hex: str    # F198 6-byte fingerprint
    long_coding: bytes   # DID 0x0600 (30 bytes)
    verbauliste: bytes   # DID 0x04A3 (32 bytes)
    transport_mode_raw: bytes  # NvM 0x0E (6 bytes)
    # BEM battery
    bem_capacity_ah: int | None
    bem_vendor: str
    bem_serial: str
    bem_history_serial: str
    # Stored DTCs (NvM 0x31 / 0x32)
    stored_dtcs: tuple[tuple[int, int], ...]  # (dtc_24bit, status_byte)
    # Security & Component Protection state (NvM 0x5E @ 0x1324, CMAC-protected)
    nvm_5e_present: bool
    nvm_5e_crc_ok: bool
    learned_cp_mask: int | None
    learned_cp_slots: tuple[SlotSpec, ...]
    master_cp_learned: bool | None
    showroom_mode_active: bool | None
    showroom_counter: int | None
    eng_disable_mask: int | None
    feat_80_enabled: bool | None
    feat_81_enabled: bool | None
    feat_83_enabled: bool | None
    nvm_5f_present: bool
    nvm_5f_crc_ok: bool
    # Overall NvM record inventory
    from_cflash_table: bool
    records: tuple[EepromNvmRecord, ...]
    crc_ok_count: int
    crc_bad_count: int
    erased_count: int


def _clean_ascii(buf: bytes) -> str:
    s = buf.split(b"\x00", 1)[0]
    chars = [chr(b) for b in s if 32 <= b < 127]
    return "".join(chars).strip()


def parse_cflash_eeprom_nvm_table(cflash_bytes: bytes | None) -> list[tuple[int, int, int, bool]]:
    """Locate the 96-entry (NvM 0x00..0x5F) 16-byte external EEPROM descriptor table in Cflash.bin.

    Returns `[(nvm_id, eeprom_offset, payload_len, mirrored), ...]`, or `[]` if unavailable.
    Anchored on NvM 0x00 (`offset=0x0000, size=94`) followed by NvM 0x01 (`offset=0x0064, size=2`) and
    NvM 0x5E (`size=18`) + NvM 0x5F (`size=55`).
    """
    if not cflash_bytes or len(cflash_bytes) < 0x30000:
        return []
    anchor = struct.pack("<HH", 0x0000, 94)
    start = 0x10000
    end = min(len(cflash_bytes) - 0x60 * 16, 0x48000)
    while True:
        idx = cflash_bytes.find(anchor, start, end)
        if idx < 0:
            return []
        off1, sz1 = struct.unpack_from("<HH", cflash_bytes, idx + 16)
        _, sz5e = struct.unpack_from("<HH", cflash_bytes, idx + 0x5E * 16)
        _, sz5f = struct.unpack_from("<HH", cflash_bytes, idx + 0x5F * 16)
        if (off1, sz1) == (0x0064, 2) and sz5e == 18 and sz5f == 55:
            out: list[tuple[int, int, int, bool]] = []
            valid = True
            for nvm_id in range(0x60):
                off, sz, copies, _b5, _w6, _rom, _w12, drv, _flg = struct.unpack_from(
                    "<HHBBHIHBB", cflash_bytes, idx + nvm_id * 16
                )
                if drv != 0 or sz == 0 or off + sz > EEPROM_SIZE:
                    valid = False
                    break
                out.append((nvm_id, off, sz, copies == 0))
            if valid:
                return out
        start = idx + 2


def _walk_standalone_tlv_records(raw: bytes) -> list[EepromNvmRecord]:
    """Walk self-describing 6-byte TLV records (`tag == pos - 0x20`, `len`, `CRC-16/CCITT-FALSE`) in M95640."""
    records: list[EepromNvmRecord] = []
    # NvM 0x00 (0x0000..0x005D) and NvM 0x01 (0x0064..0x0065) have no 6-byte TLV prefix
    p0 = raw[0x0000:0x005E]
    records.append(
        EepromNvmRecord(
            nvm_id=0x00,
            offset=0x0000,
            length=94,
            crc_stored=None,
            crc_calc=None,
            crc_ok=None,
            erased=all(b == 0xFF for b in p0),
            mirrored=False,
            payload=p0,
        )
    )
    pos = 0x006C
    while pos + 6 <= EEPROM_SIZE:
        tag, rlen, rcrc = struct.unpack_from("<HHH", raw, pos)
        if tag == pos - 0x0020 and 1 <= rlen <= 600 and pos + 6 + rlen <= EEPROM_SIZE:
            pay = raw[pos + 6 : pos + 6 + rlen]
            calc = crc16_ccitt_false(pay)
            records.append(
                EepromNvmRecord(
                    nvm_id=None,
                    offset=pos,
                    length=rlen,
                    crc_stored=rcrc,
                    crc_calc=calc,
                    crc_ok=(rcrc == calc),
                    erased=False,
                    mirrored=False,
                    payload=pay,
                )
            )
            pos += 6 + rlen
        else:
            pos += 1
    return records


def is_plausible_eeprom_bytes(raw: bytes, *, filename: str = "") -> bool:
    """True when an 8 KB file looks like a Continental J533 ST M95640 dump (or an erased 8 KB EEPROM named accordingly)."""
    if len(raw) != EEPROM_SIZE:
        return False
    fname = filename.lower()
    if any(k in fname for k in ("eeprom", "m95640", "95640")):
        return True
    if b"EV_Gatew" in raw[:0x80] or b"3Q0907530" in raw[:0x80] or b"5Q0907530" in raw[:0x80]:
        return True
    tlv = [r for r in _walk_standalone_tlv_records(raw) if r.nvm_id is None and r.crc_ok]
    return len(tlv) >= 3


def analyze_eeprom(
    raw: bytes,
    cflash_bytes: bytes | None = None,
    *,
    rdsr: int | None = None,
) -> EepromSummary:
    """Decode an 8,192-byte Continental J533 external SPI EEPROM (`ST M95640`) image."""
    if len(raw) != EEPROM_SIZE:
        raise ValueError(
            tr(
                f"Ожидался дамп внешней EEPROM M95640 размером 8192 байта (8 КБ), получено: {len(raw)} Б",
                f"Expected an 8,192-byte (8 KB) M95640 external EEPROM dump, got {len(raw)} B",
            )
        )

    blank = all(b == 0xFF for b in raw)
    nonzero = sum(b != 0x00 for b in raw)
    non_ff = sum(b != 0xFF for b in raw)
    rdsr_info = decode_m95640_rdsr(rdsr) if rdsr is not None else None

    cf_table = parse_cflash_eeprom_nvm_table(cflash_bytes)
    from_cf = bool(cf_table)
    records: list[EepromNvmRecord] = []
    by_nvm: dict[int, EepromNvmRecord] = {}

    if cf_table:
        for nvm_id, off, sz, mirrored in cf_table:
            if nvm_id < 2:
                pay = raw[off : off + sz]
                rec = EepromNvmRecord(
                    nvm_id=nvm_id,
                    offset=off,
                    length=sz,
                    crc_stored=None,
                    crc_calc=None,
                    crc_ok=None,
                    erased=all(b == 0xFF for b in pay),
                    mirrored=mirrored,
                    payload=pay,
                )
            else:
                hdr = raw[off : off + 6]
                pay = raw[off + 6 : off + 6 + sz]
                if all(b == 0xFF for b in hdr + pay):
                    rec = EepromNvmRecord(
                        nvm_id=nvm_id,
                        offset=off,
                        length=sz,
                        crc_stored=None,
                        crc_calc=None,
                        crc_ok=None,
                        erased=True,
                        mirrored=mirrored,
                        payload=pay,
                    )
                else:
                    tag, rlen, rcrc = struct.unpack("<HHH", hdr)
                    calc = crc16_ccitt_false(pay)
                    ok = tag == (off - 0x0020) and rlen == sz and rcrc == calc
                    # If primary copy is corrupt and mirrored copy exists right after it, inspect mirror too
                    if not ok and mirrored and off + 2 * (6 + sz) <= EEPROM_SIZE:
                        m_off = off + 6 + sz
                        m_tag, m_len, m_crc = struct.unpack_from("<HHH", raw, m_off)
                        m_pay = raw[m_off + 6 : m_off + 6 + sz]
                        m_calc = crc16_ccitt_false(m_pay)
                        if m_tag == (m_off - 0x0020) and m_len == sz and m_crc == m_calc:
                            pay, rcrc, calc, ok = m_pay, m_crc, m_calc, True
                    rec = EepromNvmRecord(
                        nvm_id=nvm_id,
                        offset=off,
                        length=sz,
                        crc_stored=rcrc,
                        crc_calc=calc,
                        crc_ok=ok,
                        erased=False,
                        mirrored=mirrored,
                        payload=pay,
                    )
            records.append(rec)
            by_nvm[nvm_id] = rec
    else:
        records = _walk_standalone_tlv_records(raw)
        if records and records[0].nvm_id == 0x00:
            by_nvm[0x00] = records[0]

    def _find_record(nvm_id: int, *, approx_off: tuple[int, int], length: int) -> EepromNvmRecord | None:
        if nvm_id in by_nvm:
            return by_nvm[nvm_id]
        lo, hi = approx_off
        for r in records:
            if r.length == length and lo <= r.offset <= hi and r.crc_ok:
                return r
        return None

    # 1. Boot / ODX passport in NvM 0x00 (0x0000..0x005D)
    sw_ver = _clean_ascii(raw[0x001C:0x0020])
    part_no = _clean_ascii(raw[0x0020:0x002C])
    asam_id = _clean_ascii(raw[0x002C:0x0046])
    odx_raw = _clean_ascii(raw[0x0046:0x0054])
    odx_ver = f"{odx_raw[:6]} ({odx_raw[6:]})" if len(odx_raw) > 6 and odx_raw[:6].isdigit() else odx_raw

    # 2. Programming date & counter (NvM 0x08, 5 bytes @ ~0x00F2..0x00F8)
    prog_date = ""
    prog_counter: int | None = None
    rec_08 = _find_record(0x08, approx_off=(0x00E8, 0x0104), length=5)
    if rec_08 is not None and not rec_08.erased and len(rec_08.payload) == 5:
        yy, mm, dd = rec_08.payload[0], rec_08.payload[1], rec_08.payload[2]
        prog_counter = int.from_bytes(rec_08.payload[3:5], "big")
        if all(((b >> 4) <= 9 and (b & 0xF) <= 9) for b in (yy, mm, dd)) and (yy or mm or dd):
            y_dec = (yy >> 4) * 10 + (yy & 0xF)
            m_dec = (mm >> 4) * 10 + (mm & 0xF)
            d_dec = (dd >> 4) * 10 + (dd & 0xF)
            if 1 <= m_dec <= 12 and 1 <= d_dec <= 31:
                prog_date = f"20{y_dec:02d}-{m_dec:02d}-{d_dec:02d}"

    # 3. Verbauliste / Installation List (DID 0x04A3, NvM 0x09, 32 bytes @ ~0x00FA..0x0110)
    rec_09 = _find_record(0x09, approx_off=(0x00F4, 0x0118), length=32)
    verbauliste = rec_09.payload if (rec_09 is not None and not rec_09.erased) else b""

    # 4. Gateway Long Coding (DID 0x0600, NvM 0x0D, 30 bytes @ ~0x03D0..0x03F0)
    rec_0d = _find_record(0x0D, approx_off=(0x03C8, 0x03F8), length=30)
    long_coding = rec_0d.payload if (rec_0d is not None and not rec_0d.erased) else b""

    # 5. Transport / Production Mode flags (NvM 0x0E, 6 bytes @ ~0x0418..0x0435)
    rec_0e = _find_record(0x0E, approx_off=(0x0415, 0x0438), length=6)
    transport_raw = rec_0e.payload if (rec_0e is not None and not rec_0e.erased) else b""

    # 6. VIN (check NvM 0x0F or any 17-char ASCII WMI/VIN across EEPROM)
    vin = ""
    rec_0f = by_nvm.get(0x0F)
    if rec_0f is not None and not rec_0f.erased:
        cand = _clean_ascii(rec_0f.payload)
        if len(cand) >= 11 and cand.isalnum():
            vin = cand
    if not vin:
        # Search for standard 17-character alphanumeric VIN if stored in another vehicle ID block
        for r in records:
            if r.length >= 17 and not r.erased:
                txt = _clean_ascii(r.payload)
                if len(txt) == 17 and txt.isalnum() and not txt.startswith(("3Q0", "5Q0", "EV_", "JCB")):
                    vin = txt
                    break

    # 7. Workshop / Tester fingerprint F198 (NvM 0x21, 6 bytes @ ~0x0800..0x0830)
    rec_21 = _find_record(0x21, approx_off=(0x0800, 0x0830), length=6)
    workshop_hex = rec_21.payload.hex().upper() if (rec_21 is not None and not rec_21.erased) else ""

    # 8. BEM Battery adaptation (NvM 0x27, 42 bytes @ ~0x0848..0x0878) & History (NvM 0x3C, 84 bytes @ ~0x0C10..0x0C48)
    bem_ah: int | None = None
    bem_vendor = ""
    bem_serial = ""
    rec_27 = _find_record(0x27, approx_off=(0x0848, 0x0878), length=42)
    if rec_27 is not None and not rec_27.erased and len(rec_27.payload) >= 15:
        p27 = rec_27.payload
        if 1 <= p27[0] <= 250:
            bem_ah = p27[0]
        bem_vendor = _clean_ascii(p27[2:5])
        bem_serial = _clean_ascii(p27[5:15])

    bem_hist = ""
    rec_3c = _find_record(0x3C, approx_off=(0x0C10, 0x0C48), length=84)
    if rec_3c is not None and not rec_3c.erased and len(rec_3c.payload) >= 18:
        bem_hist = _clean_ascii(rec_3c.payload[4:18])

    # 9. Stored DTC entries in NvM 0x31 / 0x32 (30 bytes = 5 x 6-byte slots @ ~0x0A35..0x0A85)
    dtcs: list[tuple[int, int]] = []
    for nvm_id, rng in ((0x31, (0x0A30, 0x0A58)), (0x32, (0x0A55, 0x0A80))):
        r_dtc = _find_record(nvm_id, approx_off=rng, length=30)
        if r_dtc is not None and not r_dtc.erased:
            for off_slot in range(0, 30, 6):
                entry = r_dtc.payload[off_slot : off_slot + 6]
                if len(entry) == 6 and entry != b"\xff" * 6 and entry != b"\x00" * 6:
                    st_byte = entry[0]
                    dtc_code = (entry[3] << 16) | (entry[4] << 8) | entry[5]
                    if dtc_code not in (0x000000, 0xFFFFFF):
                        dtcs.append((dtc_code, st_byte))

    # 10. KSCHUTZ / Component Protection & Engineering Feature state (NvM 0x5E @ 0x1324, 18 bytes)
    rec_5e = _find_record(0x5E, approx_off=(0x1300, 0x1340), length=18)
    nvm_5e_present = rec_5e is not None and not rec_5e.erased
    nvm_5e_crc_ok = bool(rec_5e and rec_5e.crc_ok)
    cp_mask: int | None = None
    cp_slots: list[SlotSpec] = []
    master_cp: bool | None = None
    showroom_active: bool | None = None
    showroom_cnt: int | None = None
    eng_mask: int | None = None
    f80: bool | None = None
    f81: bool | None = None
    f83: bool | None = None

    if nvm_5e_present and rec_5e is not None and len(rec_5e.payload) == 18:
        p5e = rec_5e.payload
        showroom_cnt = p5e[4]
        cp_mask = struct.unpack_from("<H", p5e, 5)[0] & 0x0FFF
        for slot in SLAVE_SLOTS:
            if slot.mask_bit is not None and (cp_mask & (1 << slot.mask_bit)):
                cp_slots.append(slot)
        master_cp = bool(p5e[11] & 0x01)
        showroom_active = bool(p5e[11] & 0x02)
        eng_mask = struct.unpack_from("<H", p5e, 12)[0]
        # In FUN_0008fa06: feature is enabled when its corresponding bit in (fedfc989..8a) is 0!
        f80 = (eng_mask & (1 << 0)) == 0
        f81 = (eng_mask & (1 << 1)) == 0
        f83 = (eng_mask & (1 << 3)) == 0

    rec_5f = _find_record(0x5F, approx_off=(0x1328, 0x1360), length=55)
    nvm_5f_present = rec_5f is not None and not rec_5f.erased
    nvm_5f_crc_ok = bool(rec_5f and rec_5f.crc_ok)

    crc_ok_cnt = sum(1 for r in records if r.crc_ok is True)
    crc_bad_cnt = sum(1 for r in records if r.crc_ok is False)
    erased_cnt = sum(1 for r in records if r.erased)

    return EepromSummary(
        size_bytes=len(raw),
        blank=blank,
        nonzero_bytes=nonzero,
        non_ff_bytes=non_ff,
        rdsr=rdsr_info,
        part_number=part_no,
        sw_version=sw_ver,
        asam_id=asam_id,
        odx_version=odx_ver,
        vin=vin,
        prog_date=prog_date,
        prog_counter=prog_counter,
        workshop_hex=workshop_hex,
        long_coding=long_coding,
        verbauliste=verbauliste,
        transport_mode_raw=transport_raw,
        bem_capacity_ah=bem_ah,
        bem_vendor=bem_vendor,
        bem_serial=bem_serial,
        bem_history_serial=bem_hist,
        stored_dtcs=tuple(dtcs),
        nvm_5e_present=nvm_5e_present,
        nvm_5e_crc_ok=nvm_5e_crc_ok,
        learned_cp_mask=cp_mask,
        learned_cp_slots=tuple(cp_slots),
        master_cp_learned=master_cp,
        showroom_mode_active=showroom_active,
        showroom_counter=showroom_cnt,
        eng_disable_mask=eng_mask,
        feat_80_enabled=f80,
        feat_81_enabled=f81,
        feat_83_enabled=f83,
        nvm_5f_present=nvm_5f_present,
        nvm_5f_crc_ok=nvm_5f_crc_ok,
        from_cflash_table=from_cf,
        records=tuple(records),
        crc_ok_count=crc_ok_cnt,
        crc_bad_count=crc_bad_cnt,
        erased_count=erased_cnt,
    )
