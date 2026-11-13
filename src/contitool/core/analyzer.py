"""Binary dump validation, RH850 signature scanners, and rich Cflash/Dflash/Uflash analyzers."""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
import re
import struct
import zlib

from contitool.core.checksums import app_crc
from contitool.core.constants import (
    ALL_SLOTS,
    APP_BASE,
    APP_SIZE,
    CAVE_SIZE,
    CFLASH_SIZE,
    DFLASH_FSC_BASE_OFF,
    DFLASH_FSC_PAY_SIZE,
    DFLASH_FSC_STRIDE,
    DFLASH_SIZE,
    DFLASH_SWAP_CRC_OFF,
    DFLASH_SWAP_NVM_OFF,
    DFLASH_SWAP_PAY_SIZE,
    EEPROM_SIZE,
    EXTRA_AREA_SIZE,
    FBL_EXP_OFFSET,
    FBL_MOD_OFFSET,
    FBL_PRESENCE_MAGIC,
    FSC_SIGNED_BODY_SIZE,
    GATEWAY_SWAP_SLOT_ORDER,
    OPBT_LEGACY_SIZE,
    OPBT_SIZE,
    OTP_ENG_FLAG_OFFSET,
    PATCH_A167_NOP,
    PATCH_CCP_BLACKLIST_NOP,
    PATCH_ENG_GATE_HEAD,
    PATCH_MOVEA_0X10,
    PATCH_UFLASH_RSA_OK,
    STOCK_MOVEA_0X40,
    STOCK_UFLASH_RSA_CMOV,
    SWAP_KEY_HDR,
    SlotSpec,
    UFLASH_RSA_CMP_OFFSET,
    UFLASH_SIZE,
    ZDC_DATASET_SPECS,
    ZDC_MAINGW_FPA_INST1_MAP_OFF,
    ZDC_MAINGW_FPA_MAP_OFF,
    ZDC_MAINGW_FPA_MASK_OFF,
    ZDC_PASSPORT_EQUIP_OFF,
    ZDC_PASSPORT_PN_OFF,
    ZDC_PASSPORT_VER_OFF,
)
from contitool.core.hw_extra import (
    EepromSummary,
    OpbtSummary,
    analyze_eeprom,
    analyze_opbt,
    is_plausible_eeprom_bytes,
    is_plausible_opbt_bytes,
)
from contitool.i18n import get_lang, tr


def encode_jr_disp22(pc: int, target: int) -> bytes:
    """Encode RH850 Format V 32-bit `jr disp22` (unconditional jump, no link)."""
    disp = target - pc
    if (disp & 1) != 0 or not (-0x200000 <= disp <= 0x1FFFFE):
        raise ValueError(
            tr(
                f"jr disp22 вне диапазона: pc=0x{pc:06X} -> target=0x{target:06X}",
                f"jr disp22 out of range: pc=0x{pc:06X} -> target=0x{target:06X}",
            )
        )
    u22 = disp & 0x3FFFFF
    hw0 = 0x0780 | ((u22 >> 16) & 0x3F)
    hw1 = u22 & 0xFFFF
    return struct.pack("<HH", hw0, hw1)


def decode_jr_disp22(pc: int, insn4: bytes) -> int | None:
    """Decode RH850 `jr disp22` target address, or return None if not `jr disp22`."""
    if len(insn4) != 4:
        return None
    hw0, hw1 = struct.unpack("<HH", insn4)
    if (hw0 & 0xFFC0) != 0x0780 or (hw1 & 1) != 0:
        return None
    u22 = ((hw0 & 0x3F) << 16) | hw1
    if u22 & 0x200000:
        u22 -= 0x400000
    return pc + u22


def build_hybrid_cave(cave_vaddr: int, return_vaddr: int) -> bytes:
    """Build 38-byte RH850 hybrid key-length selector cave."""
    body = (
        b"\x21\x7f\x2d\x00"  # +0x00: ld.w  44[r1], r15   (buf[19..22] in M2)
        b"\x21\x87\x31\x00"  # +0x04: ld.w  48[r1], r16   (buf[23..26] in M2)
        b"\x10\x79"          # +0x08: or    r16, r15
        b"\x21\x87\x4d\x00"  # +0x0A: ld.w  76[r1], r16   (buf[51..54] in M3)
        b"\x10\x79"          # +0x0E: or    r16, r15
        b"\x21\x87\x51\x00"  # +0x10: ld.w  80[r1], r16   (buf[55..58] in M3)
        b"\x10\x79"          # +0x14: or    r16, r15
        b"\xca\x05"          # +0x16: bne   +8            (-> +0x1E if SHE M1..M3)
        b"\x20\x7e\x10\x00"  # +0x18: movea 0x10, r0, r15 (CMD_LOAD_PLAIN_KEY)
        b"\xb5\x05"          # +0x1C: br    +6            (-> +0x22)
        b"\x20\x7e\x40\x00"  # +0x1E: movea 0x40, r0, r15 (CMD_LOAD_KEY)
    )
    ret_jr = encode_jr_disp22(cave_vaddr + len(body), return_vaddr)
    cave = body + ret_jr
    assert len(cave) == CAVE_SIZE
    return cave


def find_kschutz_hook_sites(app_bytes: bytes) -> list[int]:
    """Locate the 4-byte instruction slot (+0x10) in KSCHUTZ NvM key-load callback."""
    pattern = re.compile(
        rb"\x21\x06..\xdf\xfe\x01\x87\x11\x00\x62\x82\xda\x0d\x01\xf0"
        rb"(....)"
        rb"\x30\x06..\x08\x00\x8c\x7b",
        re.DOTALL,
    )
    return [m.start(1) for m in pattern.finditer(app_bytes)]


def find_eeprom_mask_branch_sites(app_bytes: bytes) -> list[int]:
    """Locate the 2-byte `be +0x70` (`82 3d` or NOPed `00 00`) learned-mask check."""
    pattern = re.compile(
        rb"\x83\xf7\x03\x00\x21\x06..\xdf\xfe\xc1\xf1\xa3\x0f\x03\x00\x60\x80\x50\x09"
        rb"(\x82\x3d|\x00\x00)"
        rb"\x40\x36\xe0\xfe",
        re.DOTALL,
    )
    return [m.start(1) for m in pattern.finditer(app_bytes)]


def find_eng_feature_gate_sites(app_bytes: bytes) -> list[int]:
    """Locate System Engineering Feature Gate (`Feature 0x80/0x81/0x83`)."""
    pattern = re.compile(
        rb"(\x40\x0e\xe0\xfe|\x00\x52\x7f\x00)"
        rb"\x81\x0f.."
        rb"\xe0\x09\xba\x05\x02\x52\x7f\x00\x86\x00\x06\x0e\x80\xff\x01\x06\xf0\xff\xa1\x1d\x01\x82",
        re.DOTALL,
    )
    return [m.start(1) for m in pattern.finditer(app_bytes)]


def find_ramloader_a167_sites(app_bytes: bytes) -> list[int]:
    """Locate the 2-byte `be +26` (`d2 0d` or NOPed `00 00`) checking OTP byte [0x0000A167]."""
    pattern = re.compile(
        rb"\x40\x0e\x01\x00\x81\x0f\x67\xa1\x01\x06\x01\xff"
        rb"(\xd2\x0d|\x00\x00)",
        re.DOTALL,
    )
    return [m.start(1) for m in pattern.finditer(app_bytes)]


def find_ccp_blacklist_sites(app_bytes: bytes) -> list[int]:
    """Locate the 4-byte `cmov nh, 0, r28, r28` (`e0 e7 06 e3`) inside CCP_CheckAddr."""
    pattern = re.compile(
        rb"\xc1\xf1\x00\x85\x02\x0d\xf0\xd1\xc1\x05\xe1\xd9"
        rb"(\xe0\xe7\x06\xe3|\x00\x00\x00\x00)"
        rb"\x41\xea\x9d\x00",
        re.DOTALL,
    )
    return [m.start(1) for m in pattern.finditer(app_bytes)]


def find_swap_rsa_modulus_sites(app_bytes: bytes) -> list[int]:
    """Locate the 128-byte SWaP RSA-1024 modulus in FD_0DATA via its unique 38-byte header+exp."""
    sites: list[int] = []
    pos = 0
    hdr_len = len(SWAP_KEY_HDR)
    while True:
        idx = app_bytes.find(SWAP_KEY_HDR, pos)
        if idx == -1:
            break
        if idx + hdr_len + 128 <= len(app_bytes):
            sites.append(idx + hdr_len)
        pos = idx + 1
    return sites


def split_cflash_or_app(raw: bytes) -> tuple[bytes, bytearray]:
    """Return (prefix_before_C200, mutable_app_bytes_from_C200)."""
    if len(raw) == UFLASH_SIZE:
        raise ValueError(
            tr(
                "Указан файл размером 32 768 байт — это Uflash.bin (загрузчик FBL), а не CodeFlash.bin (1.5 МБ)!",
                "32,768-byte file provided — this is Uflash.bin (Extended User Area FBL), not CodeFlash.bin (1.5 MB)!",
            )
        )
    if len(raw) == DFLASH_SIZE:
        raise ValueError(
            tr(
                "Указан файл размером 65 536 байт — это DataFlash.bin (ключи CP), а не CodeFlash.bin (1.5 МБ)!",
                "65,536-byte file provided — this is DataFlash.bin (CP keys), not CodeFlash.bin (1.5 MB)!",
            )
        )
    if len(raw) == CFLASH_SIZE:
        return raw[:APP_BASE], bytearray(raw[APP_BASE:])
    if len(raw) == APP_SIZE:
        return b"", bytearray(raw)
    raise ValueError(
        tr(
            f"Ожидался CodeFlash/Cflash.bin ({CFLASH_SIZE:,} Б) или FD_0DATA ({APP_SIZE:,} Б), получен файл {len(raw):,} Б",
            f"Expected CodeFlash/Cflash.bin ({CFLASH_SIZE:,} B) or FD_0DATA ({APP_SIZE:,} B), got {len(raw):,} B",
        )
    )


def validate_uflash_bytes(uf: bytes) -> None:
    if len(uf) != UFLASH_SIZE:
        raise ValueError(
            tr(
                f"Ожидался Uflash.bin размером 32 768 байт (32 КБ), получен {len(uf):,} Б",
                f"Expected Uflash.bin of 32,768 bytes (32 KB), got {len(uf):,} B",
            )
        )
    anchor_pre = uf[UFLASH_RSA_CMP_OFFSET - 6 : UFLASH_RSA_CMP_OFFSET]
    anchor_post = uf[UFLASH_RSA_CMP_OFFSET + 4 : UFLASH_RSA_CMP_OFFSET + 10]
    mid = uf[UFLASH_RSA_CMP_OFFSET : UFLASH_RSA_CMP_OFFSET + 4]
    if (
        anchor_pre != bytes.fromhex("80ff38158051")
        or anchor_post != bytes.fromhex("1d504006ff00")
        or mid not in (STOCK_UFLASH_RSA_CMOV, PATCH_UFLASH_RSA_OK)
    ):
        raise ValueError(
            tr(
                "Не найдена сигнатура проверки RSA @ Uflash+0x342A — этот файл не является Uflash загрузчика J533 "
                "(возможно, это обрезанный 32 КБ D-Flash от профиля R7F7010343AFP)!",
                "RSA check signature @ Uflash+0x342A not found — this file is not a J533 FBL Uflash "
                "(it may be a truncated 32 KB D-Flash read using R7F7010343AFP)!",
            )
        )


def validate_dflash_bytes(df: bytes) -> None:
    if len(df) == UFLASH_SIZE:
        # Distinguish genuine Uflash from truncated 32 KB Dflash for maximum clarity
        try:
            validate_uflash_bytes(df)
            is_uflash = True
        except ValueError:
            is_uflash = False
        if is_uflash:
            raise ValueError(
                tr(
                    "Указан файл размером 32 768 байт — это Uflash.bin (загрузчик FBL), а не DataFlash.bin (65 536 Б)!",
                    "32,768-byte file provided — this is Uflash.bin (FBL bootloader), not DataFlash.bin (65,536 B)!",
                )
            )
        raise ValueError(
            tr(
                "Получен обрезанный файл 32 768 Б (32 КБ) вместо полных 65 536 Б (64 КБ)! "
                "При чтении был выбран профиль R7F7010343AFP (32 КБ D-Flash), отрезавший область 0xC000..0xFFFF "
                "со ВСЕМИ ключами CP и SWaP. Перечитайте полные 64 КБ профилем 3Q0907530 или чипа R7F7010543 / R7F7010563!",
                "Got a truncated 32,768-byte (32 KB) file instead of the full 65,536-byte (64 KB) DataFlash! "
                "R7F7010343AFP (32 KB D-Flash) was selected, cutting off 0xC000..0xFFFF where ALL CP keys and SWaP "
                "reside. Re-read full 64 KB using the 3Q0907530 preset or R7F7010543 / R7F7010563!",
            )
        )
    if len(df) in (CFLASH_SIZE, APP_SIZE):
        raise ValueError(
            tr(
                f"Указан файл прошивки CodeFlash ({len(df):,} Б) вместо DataFlash.bin (65 536 Б)!",
                f"CodeFlash firmware file ({len(df):,} B) provided instead of DataFlash.bin (65,536 B)!",
            )
        )
    if len(df) != DFLASH_SIZE:
        raise ValueError(
            tr(
                f"Ожидался DataFlash/Dflash.bin размером 65 536 байт (64 КБ), получен {len(df):,} Б",
                f"Expected DataFlash/Dflash.bin of 65,536 bytes (64 KB), got {len(df):,} B",
            )
        )


def classify_dflash_record(payload: bytes) -> str:
    """Return 'PLAIN' or 'SHE' matching the 4 words checked by the RH850 hybrid trampoline."""
    w0, w1 = struct.unpack_from("<II", payload, 19)
    w2, w3 = struct.unpack_from("<II", payload, 51)
    return "PLAIN" if (w0 | w1 | w2 | w3) == 0 else "SHE"


@dataclasses.dataclass
class SlotState:
    spec: SlotSpec
    empty: bool
    kind: str               # "EMPTY", "SHE", "PLAIN", "PARTIAL"
    crc_stored: int = 0
    crc_calc: int = 0
    crc_ok: bool = True
    mirrored: bool = True
    first16_hex: str = ""


@dataclasses.dataclass
class CflashSummary:
    size: int
    sha256: str
    has_prefix: bool
    fazit: str = ""
    hw_pn: str = ""
    hw_ver: str = ""
    sw_pn: str = ""  # F187 VW Spare Part Number (e.g. 3Q0907530AA / AC / AR)
    sw_ver: str = ""  # F189 as the application answers it
    system_name: str = ""  # F19E System Name (e.g. GW MQB High / GW MQB EV)
    hw_variant: int | None = None  # OTP 0x0000A600 hardware tier index (0..6)
    fbl_c000: int = 0
    fbl_c100: int = 0
    fbl_ok: bool = True
    crc_stored: int = 0
    crc_calc: int = 0
    crc_ok: bool = False
    crc_range_count: int = 1  # 0: no usable CRC range table (application erased or its header damaged)
    hook_vaddr: int | None = None
    hook_mode: str = "NOT_FOUND"
    cave_target: int | None = None
    mask_vaddr: int | None = None
    mask_bypassed: bool = False
    eng_gate_vaddr: int | None = None
    eng_gate_unlocked: bool = False
    ccp_blacklist_vaddr: int | None = None
    ccp_blacklist_bypassed: bool = False
    a167_otp_byte: int | None = None
    a167_branch_vaddr: int | None = None
    a167_branch_bypassed: bool = False
    swap_rsa_vaddr: int | None = None
    swap_rsa_mod: bytes = b""
    fbl_rsa_mod: bytes = b""
    fbl_rsa_exp_ok: bool = True


@dataclasses.dataclass
class FscSlotInfo:
    slot_idx: int
    dflash_off: int
    fec_code: int
    vcrn_hex: str
    vin: str
    timestamp: int
    crc_ok: bool
    factory_eol: bool


@dataclasses.dataclass
class DflashSwapSummary:
    initialized: bool
    magic_ok: bool
    crc_stored: int = 0
    crc_calc: int = 0
    crc_ok: bool = False
    vcrn: bytes = b""
    init_flag: int = 0
    swap_rsa_mod: bytes = b""
    swap_rsa_exp_ok: bool = False
    vin: str = ""
    active_fscs: list[FscSlotInfo] = dataclasses.field(default_factory=list)
    inactive_fecs: list[int] = dataclasses.field(default_factory=list)
    free_slots: int = 0
    slot_timestamps: dict[int, int] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ZdcBlockInfo:
    idx: int
    code: str
    offset: int
    size: int
    name_ru: str
    name_en: str
    empty: bool
    crc_stored: int = 0
    crc_calc: int = 0
    crc_ok: bool = False
    header_tag: str = ""

    @property
    def name(self) -> str:
        return self.name_en if get_lang() == "en" else self.name_ru

    @property
    def label(self) -> str:
        return self.name

    @property
    def version_tag(self) -> str:
        return self.header_tag


@dataclasses.dataclass
class FecDatasetSupport:
    fec_code: int
    supported: bool
    reason_ru: str
    reason_en: str

    @property
    def reason(self) -> str:
        return self.reason_en if get_lang() == "en" else self.reason_ru


@dataclasses.dataclass
class DflashDatasetSummary:
    dataset_pn: str = ""
    dataset_ver: str = ""
    dataset_equip: str = ""
    passport_crc_ok: bool = False
    maingw_tag: str = ""
    fpa_selectable_mask: int = 0
    blocks: list[ZdcBlockInfo] = dataclasses.field(default_factory=list)
    fpa_profile_map: dict[int, int] = dataclasses.field(default_factory=dict)
    supported_fecs: list[int] = dataclasses.field(default_factory=list)
    fec_support: dict[int, FecDatasetSupport] = dataclasses.field(default_factory=dict)

    @property
    def has_any_valid_dataset(self) -> bool:
        return any(b.crc_ok for b in self.blocks)


@dataclasses.dataclass
class UflashSummary:
    size: int
    sha256: str
    signature_found: bool
    rsa_bypassed: bool = False
    raw_insn_hex: str = ""


def fbl_app_valid(cflash: bytes) -> bool:
    """The FBL's own "application valid" test (3Q0907530AR SW 5504 FBL @ 0x00001C32, table @ 0x1460 -> 0xC000):
    the word at 0xC100 decides when it is not FFFFFFFF, otherwise the word at 0xC000; valid = 0x90482442."""
    c000, = struct.unpack_from("<I", cflash, 0xC000)
    c100, = struct.unpack_from("<I", cflash, 0xC100)
    return (c100 if c100 != 0xFFFFFFFF else c000) == FBL_PRESENCE_MAGIC


def analyze_cflash(raw: bytes) -> CflashSummary:
    prefix, app = split_cflash_or_app(raw)
    sha = hashlib.sha256(raw).hexdigest()
    stored_word, range_cnt = struct.unpack_from("<HH", app, 0x1C)
    try:
        stored_crc, calc_crc = app_crc(app)
        crc_valid = stored_crc == calc_crc
    except ValueError:  # no usable range table: erased (unit in its bootloader) or damaged application header
        stored_crc, calc_crc, crc_valid, range_cnt = stored_word, stored_word, False, 0

    res = CflashSummary(
        size=len(raw),
        sha256=sha,
        has_prefix=bool(prefix),
        crc_stored=stored_crc,
        crc_calc=calc_crc,
        crc_ok=crc_valid,
        crc_range_count=range_cnt,
    )
    hw_variant: int | None = None
    if prefix:
        m_c000, = struct.unpack_from("<I", prefix, 0xC000)
        m_c100, = struct.unpack_from("<I", prefix, 0xC100)
        res.fbl_c000 = m_c000
        res.fbl_c100 = m_c100
        res.fbl_ok = fbl_app_valid(prefix)
        res.fazit = _clean_printable_ascii(prefix[0xA240:0xA257])
        res.hw_ver = _clean_printable_ascii(prefix[0xA257:0xA25A])
        res.hw_pn = _clean_printable_ascii(prefix[0xA25A:0xA265])
        raw_var, = struct.unpack_from("<I", prefix, HW_VARIANT_OFFSET)
        if raw_var < 7:
            hw_variant = raw_var
        res.hw_variant = hw_variant
        res.a167_otp_byte = prefix[OTP_ENG_FLAG_OFFSET]
        res.fbl_rsa_mod = bytes(prefix[FBL_MOD_OFFSET : FBL_MOD_OFFSET + 128])
        res.fbl_rsa_exp_ok = bytes(prefix[FBL_EXP_OFFSET : FBL_EXP_OFFSET + 128]) == ((b"\x00" * 127) + b"\x03")

    app_ro = bytes(app)
    res.sw_ver = app_sw_version(app_ro)
    res.sw_pn, res.system_name = app_sw_identity(app_ro, hw_variant=hw_variant, hw_pn=res.hw_pn)
    hits = find_kschutz_hook_sites(app_ro)
    if len(hits) == 1:
        off = hits[0]
        vaddr = APP_BASE + off
        res.hook_vaddr = vaddr
        insn4 = app_ro[off : off + 4]
        jr_target = decode_jr_disp22(vaddr, insn4)
        if insn4 == STOCK_MOVEA_0X40:
            res.hook_mode = "STOCK"
        elif insn4 == PATCH_MOVEA_0X10:
            res.hook_mode = "GLOBAL_PLAIN"
        elif jr_target is not None:
            res.cave_target = jr_target
            cave_off = jr_target - APP_BASE
            expected_cave = build_hybrid_cave(jr_target, vaddr + 4)
            cave_ok = (
                0 <= cave_off <= len(app) - CAVE_SIZE
                and app_ro[cave_off : cave_off + CAVE_SIZE] == expected_cave
            )
            res.hook_mode = "HYBRID" if cave_ok else "HYBRID_BAD"
        else:
            res.hook_mode = f"UNKNOWN({insn4.hex()})"

    mask_hits = find_eeprom_mask_branch_sites(app_ro)
    if len(mask_hits) == 1:
        moff = mask_hits[0]
        res.mask_vaddr = APP_BASE + moff
        res.mask_bypassed = app_ro[moff : moff + 2] == b"\x00\x00"

    eng_hits = find_eng_feature_gate_sites(app_ro)
    if len(eng_hits) == 1:
        eoff = eng_hits[0]
        res.eng_gate_vaddr = APP_BASE + eoff
        res.eng_gate_unlocked = app_ro[eoff : eoff + 4] == PATCH_ENG_GATE_HEAD

    ccp_bl_hits = find_ccp_blacklist_sites(app_ro)
    if len(ccp_bl_hits) == 1:
        boff = ccp_bl_hits[0]
        res.ccp_blacklist_vaddr = APP_BASE + boff
        res.ccp_blacklist_bypassed = app_ro[boff : boff + 4] == PATCH_CCP_BLACKLIST_NOP

    a167_hits = find_ramloader_a167_sites(app_ro)
    if len(a167_hits) == 1:
        aoff = a167_hits[0]
        res.a167_branch_vaddr = APP_BASE + aoff
        res.a167_branch_bypassed = app_ro[aoff : aoff + 2] == PATCH_A167_NOP

    swap_hits = find_swap_rsa_modulus_sites(app_ro)
    if len(swap_hits) == 1:
        soff = swap_hits[0]
        res.swap_rsa_vaddr = APP_BASE + soff
        res.swap_rsa_mod = app_ro[soff : soff + 128]

    return res


def analyze_dflash_swap(df: bytes) -> DflashSwapSummary:
    """Inspect NvM 0x7C (0xDB00..0xDCE7: cached SWaP RSA-1024 key + VCRN) & FSC slots 0xDD00..0xE780."""
    validate_dflash_bytes(df)
    magic, = struct.unpack_from("<I", df, DFLASH_SWAP_NVM_OFF)
    if magic != 0x55555555:
        return DflashSwapSummary(initialized=False, magic_ok=False)

    payload = df[DFLASH_SWAP_NVM_OFF + 4 : DFLASH_SWAP_NVM_OFF + 4 + DFLASH_SWAP_PAY_SIZE]
    crc_calc = zlib.crc32(payload) & 0xFFFFFFFF
    crc_st, = struct.unpack_from("<I", df, DFLASH_SWAP_CRC_OFF)
    mod = payload[0x000:0x080]
    exp_ok = payload[0x080:0x100] == ((b"\x00" * 127) + b"\x03")
    vcrn = payload[0x108:0x10D]
    init_flag = payload[0x10D]

    inactive_fecs: list[int] = []
    free_slots = 0
    slot_timestamps: dict[int, int] = {}
    for slot in range(15):
        ent = payload[0x10E + slot * 14 : 0x10E + (slot + 1) * 14]
        fec_meta, ts_meta = struct.unpack_from(">II", ent, 4)
        st_byte = ent[12]
        if fec_meta != 0:
            slot_timestamps[fec_meta] = max(slot_timestamps.get(fec_meta, 0), ts_meta)
            if st_byte == 0xB0:
                inactive_fecs.append(fec_meta)
        elif ent == b"\x00" * 14:
            free_slots += 1

    fscs: list[FscSlotInfo] = []
    detected_vin = ""
    for slot in range(15):
        off = DFLASH_FSC_BASE_OFF + slot * DFLASH_FSC_STRIDE
        smagic, = struct.unpack_from("<I", df, off)
        if smagic != 0x55555555:
            continue
        spay = df[off + 4 : off + 4 + DFLASH_FSC_PAY_SIZE]
        scrc_calc = zlib.crc32(spay) & 0xFFFFFFFF
        scrc_st, = struct.unpack_from("<I", df, off + 0xB0)
        if spay[0:2] == b"\x11\x02" and spay[6] == 0x03:
            fec_u32, = struct.unpack_from(">I", spay, 2)
            svcrn = spay[7:12].hex()
            raw_vin = spay[12:29].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
            if raw_vin and not detected_vin:
                detected_vin = raw_vin
            ts_u32, = struct.unpack_from(">I", spay, 30)
            slot_timestamps[fec_u32] = max(slot_timestamps.get(fec_u32, 0), ts_u32)
            factory_eol = not any(spay[FSC_SIGNED_BODY_SIZE:])
            fscs.append(
                FscSlotInfo(
                    slot_idx=slot,
                    dflash_off=off,
                    fec_code=fec_u32,
                    vcrn_hex=svcrn,
                    vin=raw_vin,
                    timestamp=ts_u32,
                    crc_ok=(scrc_calc == scrc_st),
                    factory_eol=factory_eol,
                )
            )

    return DflashSwapSummary(
        initialized=(init_flag != 0),
        magic_ok=True,
        crc_stored=crc_st,
        crc_calc=crc_calc,
        crc_ok=(crc_calc == crc_st),
        vcrn=vcrn,
        init_flag=init_flag,
        swap_rsa_mod=mod,
        swap_rsa_exp_ok=exp_ok,
        vin=detected_vin,
        active_fscs=fscs,
        inactive_fecs=inactive_fecs,
        free_slots=free_slots,
        slot_timestamps=slot_timestamps,
    )


def _clean_printable_ascii(raw: bytes) -> str:
    chars = []
    for b in raw:
        if b in (0x00, 0xFF):
            break
        if 0x20 <= b <= 0x7E:
            chars.append(chr(b))
        else:
            return ""
    return "".join(chars).strip()


def analyze_dflash_datasets(df: bytes) -> DflashDatasetSummary:
    """Inspect linear ZDC parameterization datasets in DataFlash (0x0000..0x303F) & per-FeC support."""
    validate_dflash_bytes(df)
    ds_pn = _clean_printable_ascii(df[ZDC_PASSPORT_PN_OFF : ZDC_PASSPORT_PN_OFF + 11])
    ds_ver = _clean_printable_ascii(df[ZDC_PASSPORT_VER_OFF : ZDC_PASSPORT_VER_OFF + 4])
    ds_equip = _clean_printable_ascii(df[ZDC_PASSPORT_EQUIP_OFF : ZDC_PASSPORT_EQUIP_OFF + 12])
    pass_erased = all(b == 0xFF for b in df[0x0000:0x0080])
    pass_crc_st, = struct.unpack_from("<I", df, 0x0000)
    pass_crc_ca = zlib.crc32(df[0x0004:0x0080]) & 0xFFFFFFFF
    pass_crc_ok = (not pass_erased) and (pass_crc_st == pass_crc_ca)

    blocks: list[ZdcBlockInfo] = []
    by_idx: dict[int, ZdcBlockInfo] = {}
    for idx, code, off, sz, name_ru, name_en in ZDC_DATASET_SPECS:
        blk = df[off : off + sz]
        empty = all(b == 0xFF for b in blk)
        if empty:
            info = ZdcBlockInfo(idx=idx, code=code, offset=off, size=sz, name_ru=name_ru, name_en=name_en, empty=True)
        else:
            crc_st, = struct.unpack_from("<I", blk, sz - 4)
            crc_ca = zlib.crc32(blk[:-4]) & 0xFFFFFFFF
            tag = _clean_printable_ascii(blk[:4])
            info = ZdcBlockInfo(
                idx=idx,
                code=code,
                offset=off,
                size=sz,
                name_ru=name_ru,
                name_en=name_en,
                empty=False,
                crc_stored=crc_st,
                crc_calc=crc_ca,
                crc_ok=(crc_st == crc_ca),
                header_tag=tag,
            )
        blocks.append(info)
        by_idx[idx] = info

    zdc4 = by_idx[4]
    gw_blk = df[zdc4.offset : zdc4.offset + zdc4.size]
    maingw_tag = zdc4.header_tag if zdc4.crc_ok else ""

    fpa_map: dict[int, int] = {}
    fpa_mask = 0
    if zdc4.crc_ok:
        for k in range(1, 10):
            fpa_map[k] = gw_blk[ZDC_MAINGW_FPA_MAP_OFF + k]
        for k in (10, 11):
            fpa_map[k] = gw_blk[ZDC_MAINGW_FPA_INST1_MAP_OFF + (k - 9)]
        fpa_mask, = struct.unpack_from(">H", gw_blk, ZDC_MAINGW_FPA_MASK_OFF)

    summary = DflashDatasetSummary(
        dataset_pn=ds_pn,
        dataset_ver=ds_ver,
        dataset_equip=ds_equip,
        passport_crc_ok=pass_crc_ok,
        maingw_tag=maingw_tag,
        fpa_selectable_mask=fpa_mask,
        blocks=blocks,
        fpa_profile_map=fpa_map,
    )

    for fec in GATEWAY_SWAP_SLOT_ORDER:
        sup = check_fec_dataset_support(summary, fec, raw_df=df)
        summary.fec_support[fec] = sup
        if sup.supported:
            summary.supported_fecs.append(fec)

    return summary


def check_fec_dataset_support(
    df_or_summary: bytes | DflashDatasetSummary,
    fec_code: int,
    *,
    raw_df: bytes | None = None,
) -> FecDatasetSupport:
    """Return whether `fec_code` is supported by the currently flashed ZDC dataset in DataFlash."""
    if isinstance(df_or_summary, DflashDatasetSummary):
        summary = df_or_summary
    else:
        raw_df = df_or_summary
        summary = analyze_dflash_datasets(df_or_summary)

    fec_u32 = fec_code & 0xFFFFFFFF
    if fec_u32 in summary.fec_support:
        return summary.fec_support[fec_u32]

    by_idx = {b.idx: b for b in summary.blocks}
    zdc1 = by_idx.get(1)
    zdc4 = by_idx.get(4)
    ds_label = summary.dataset_pn or summary.maingw_tag or "ZDC"

    if fec_u32 == 0x10000300:
        mke_non_zero = True
        if raw_df is not None and zdc1 is not None:
            mke_non_zero = raw_df[zdc1.offset : zdc1.offset + 4] != b"\x00\x00\x00\x00"
        if zdc1 is not None and zdc1.crc_ok and mke_non_zero:
            return FecDatasetSupport(
                fec_code=fec_u32,
                supported=True,
                reason_ru="Датасет MKE (ZDC #1 @ 0x0100) записан и корректен",
                reason_en="MKE dataset (ZDC #1 @ 0x0100) is present and valid",
            )
        return FecDatasetSupport(
            fec_code=fec_u32,
            supported=False,
            reason_ru="Датасет MKE (ZDC #1 @ 0x0100) пуст или имеет неверный CRC-32",
            reason_en="MKE dataset (ZDC #1 @ 0x0100) is empty or has invalid CRC-32",
        )

    if fec_u32 == 0x10000100:
        if zdc4 is not None and zdc4.crc_ok:
            return FecDatasetSupport(
                fec_code=fec_u32,
                supported=True,
                reason_ru=f"Основной датасет шлюза ({ds_label}) записан и корректен",
                reason_en=f"Main Gateway dataset ({ds_label}) is present and valid",
            )
        return FecDatasetSupport(
            fec_code=fec_u32,
            supported=False,
            reason_ru="Основной датасет шлюза (ZDC #4 @ 0x1340) пуст или не записан",
            reason_en="Main Gateway dataset (ZDC #4 @ 0x1340) is empty or missing",
        )

    if (fec_u32 & 0xFFFFF0FF) == 0x10001000:
        prof_idx = (fec_u32 - 0x10001000) >> 8
        if 1 <= prof_idx <= 11:
            if zdc4 is None or not zdc4.crc_ok:
                return FecDatasetSupport(
                    fec_code=fec_u32,
                    supported=False,
                    reason_ru="Датасет MainGW / FPA (ZDC #4 @ 0x1340) пуст или не записан",
                    reason_en="MainGW / FPA dataset (ZDC #4 @ 0x1340) is empty or missing",
                )
            mapped = summary.fpa_profile_map.get(prof_idx, 0)
            if prof_idx <= 9:
                # the head unit is offered slot n when S028[n] holds an ID 1..0x13 (and the FeC is active)
                slot_ok = 1 <= mapped <= 0x13
            else:
                slot_ok = 1 <= mapped <= 0x3F
            if slot_ok:
                return FecDatasetSupport(
                    fec_code=fec_u32,
                    supported=True,
                    reason_ru=f"Поддерживается датасетом {ds_label} (профиль FPA #{prof_idx} -> ID {mapped})",
                    reason_en=f"Supported by dataset {ds_label} (FPA profile #{prof_idx} -> ID {mapped})",
                )
            return FecDatasetSupport(
                fec_code=fec_u32,
                supported=False,
                reason_ru=f"Профиль FPA #{prof_idx} отключён в текущем датасете {ds_label} (код 0x{mapped:02X})",
                reason_en=f"FPA profile #{prof_idx} is disabled in current dataset {ds_label} (value 0x{mapped:02X})",
            )

    return FecDatasetSupport(
        fec_code=fec_u32,
        supported=False,
        reason_ru=f"Код FeC 0x{fec_u32:08X} отсутствует в таблице функций датасета {ds_label}",
        reason_en=f"FeC 0x{fec_u32:08X} is not configured in dataset {ds_label}",
    )


FBL_LIBRARY_ID = b"SH850T01"  # Renesas flash library ID string inside every J533 bootloader build seen
HW_VARIANT_OFFSET = 0xA600  # uint32 hardware tier index (0..6) read by DID 0xF187/0xF19E in FD_0DATA


def app_sw_version(app: bytes) -> str:
    """F189 of the application: its DID table holds `89 F1 | flags | length 4 | pointer` (little-endian, absolute)."""
    for m in re.finditer(rb"\x89\xf1..\x04\x00\x00\x00", app, re.DOTALL):
        ptr = int.from_bytes(app[m.end() : m.end() + 4], "little") - APP_BASE
        val = app[ptr : ptr + 4] if 0 <= ptr <= len(app) - 4 else b""
        if val.isdigit():
            return val.decode()
    return ""


def app_sw_identity(app: bytes, *, hw_variant: int | None = None, hw_pn: str = "") -> tuple[str, str]:
    """Return `(sw_pn, system_name)` (`F187`, `F19E`) from the FD_0DATA header and 8-tier variant table.

    In Continental J533 RH850 builds, `app + 0x44` points to the 4-digit `F189` version string, followed at
    `+0x14` by 8 pointers to 11-byte `F187` part numbers and at `+0x34` by 8 pointers to 13-byte `F19E` names.
    The UDS `0x22 F187` / `0x22 F19E` handler indexes those tables with `*(uint32_t *)0x0000A600` (`0..6`).
    """
    if len(app) < 0x60:
        return "", ""
    _, p_sw = struct.unpack_from("<II", app, 0x40)
    sw_off = p_sw - APP_BASE
    if not (0 <= sw_off <= len(app) - 0x54) or not app[sw_off : sw_off + 4].isdigit():
        return "", ""
    sw_ptrs = struct.unpack_from("<8I", app, sw_off + 0x14)
    nm_ptrs = struct.unpack_from("<8I", app, sw_off + 0x34)
    pns: list[str] = []
    for ptr in sw_ptrs[:7]:
        off = ptr - APP_BASE
        if not (0 <= off <= len(app) - 11):
            return "", ""
        raw_pn = app[off : off + 11]
        if not all(0x20 <= b <= 0x7E for b in raw_pn):
            return "", ""
        pns.append(raw_pn.decode("ascii").strip())

    if hw_variant is not None and 0 <= hw_variant < 7:
        idx = hw_variant
    else:
        hp = hw_pn.strip()
        if hp and hp in pns:
            idx = pns.index(hp)
        elif hp.startswith("8S0907468"):
            idx = 5
        elif hp.startswith(("81D907468", "8V1907468")):
            idx = 6
        elif hp in ("3Q0907530B", "3Q0907530D", "3Q0907530F", "3Q0907530H"):
            idx = 4
        else:
            idx = 3  # GW MQB High (3Q0907530AA / AC / AG / AL / AR / ...)

    nm = ""
    nm_off = nm_ptrs[idx] - APP_BASE
    if 0 <= nm_off <= len(app) - 13:
        raw_nm = app[nm_off : nm_off + 13]
        if all(0x20 <= b <= 0x7E for b in raw_nm):
            nm = raw_nm.decode("ascii").strip()
    return pns[idx], nm


def analyze_uflash(uf: bytes) -> UflashSummary:
    if len(uf) != UFLASH_SIZE:
        raise ValueError(
            tr(
                f"Ожидался Uflash.bin размером 32 768 байт, получен {len(uf):,} Б",
                f"Expected 32,768-byte Uflash.bin, got {len(uf):,} B",
            )
        )
    sha = hashlib.sha256(uf).hexdigest()
    mid = uf[UFLASH_RSA_CMP_OFFSET : UFLASH_RSA_CMP_OFFSET + 4]
    anchor_ok = (
        uf[UFLASH_RSA_CMP_OFFSET - 6 : UFLASH_RSA_CMP_OFFSET] == bytes.fromhex("80ff38158051")
        and uf[UFLASH_RSA_CMP_OFFSET + 4 : UFLASH_RSA_CMP_OFFSET + 10] == bytes.fromhex("1d504006ff00")
        and mid in (STOCK_UFLASH_RSA_CMOV, PATCH_UFLASH_RSA_OK)
    )
    return UflashSummary(
        size=len(uf),
        sha256=sha,
        signature_found=anchor_ok,
        rsa_bypassed=(anchor_ok and mid == PATCH_UFLASH_RSA_OK),
        raw_insn_hex=mid.hex(),
    )


def analyze_dflash(df: bytes) -> list[SlotState]:
    validate_dflash_bytes(df)
    states: list[SlotState] = []
    for spec in ALL_SLOTS:
        m1, = struct.unpack_from("<I", df, spec.off1)
        m2, = struct.unpack_from("<I", df, spec.off2)
        if m1 == 0xFFFFFFFF and m2 == 0xFFFFFFFF:
            states.append(SlotState(spec=spec, empty=True, kind="EMPTY"))
            continue
        base = spec.off1 if m1 == 0x55555555 else spec.off2
        c_stored, = struct.unpack_from("<I", df, base + spec.crc_off)
        payload = df[base + 4 : base + 4 + spec.rec_size]
        c_calc = zlib.crc32(payload) & 0xFFFFFFFF
        rec_len = spec.crc_off + 4
        mirrored = df[spec.off1 : spec.off1 + rec_len] == df[spec.off2 : spec.off2 + rec_len]
        kind = classify_dflash_record(payload) if m1 == 0x55555555 or m2 == 0x55555555 else "PARTIAL"
        states.append(
            SlotState(
                spec=spec,
                empty=False,
                kind=kind,
                crc_stored=c_stored,
                crc_calc=c_calc,
                crc_ok=(c_stored == c_calc and (m1 == 0x55555555 or m2 == 0x55555555)),
                mirrored=mirrored,
                first16_hex=payload[:16].hex(),
            )
        )
    return states


@dataclasses.dataclass
class DetectedDumpFile:
    """Auto-detected metadata for foolproof Drag & Drop file inputs in GUI."""

    path: Path
    kind: str  # "cflash", "fd_0data", "dflash", "uflash", "eeprom", "opbt", "truncated_dflash", "rsa_key", "unknown"
    valid: bool
    summary_text: str
    cflash_info: CflashSummary | None = None
    dflash_slots: list[SlotState] | None = None
    dflash_swap: DflashSwapSummary | None = None
    dflash_datasets: DflashDatasetSummary | None = None
    uflash_info: UflashSummary | None = None
    eeprom_info: EepromSummary | None = None
    opbt_info: OpbtSummary | None = None


def detect_dump_file(path: Path) -> DetectedDumpFile:
    """Auto-classify any file dropped by the user and build a friendly status badge."""
    if not path.is_file():
        return DetectedDumpFile(
            path=path,
            kind="unknown",
            valid=False,
            summary_text=tr("Файл не найден", "File not found"),
        )
    raw = path.read_bytes()
    sz = len(raw)
    if sz in (CFLASH_SIZE, APP_SIZE):
        try:
            info = analyze_cflash(raw)
            kind = "cflash" if sz == CFLASH_SIZE else "fd_0data"
            pn_main = info.sw_pn or info.hw_pn
            sw_tag = f" ({info.sw_ver})" if info.sw_ver else ""
            pn_lbl = f" • {pn_main}{sw_tag}" if pn_main else (f" • SW {info.sw_ver}" if info.sw_ver else "")
            crc_lbl = "CRC OK" if info.crc_ok else "CRC ERR!"
            mode_lbl = info.hook_mode
            eng_lbl = " • ENG" if (info.eng_gate_unlocked and info.a167_branch_bypassed) else ""
            label = (
                f"{'CodeFlash 1.5 MB' if kind == 'cflash' else 'FD_0DATA 1.45 MB'}"
                f"{pn_lbl} • {crc_lbl} • CP:{mode_lbl}{eng_lbl}"
            )
            return DetectedDumpFile(path=path, kind=kind, valid=True, summary_text=label, cflash_info=info)
        except Exception as exc:
            return DetectedDumpFile(path=path, kind="cflash", valid=False, summary_text=str(exc))
    if sz == DFLASH_SIZE:
        try:
            slots = analyze_dflash(raw)
            swap = analyze_dflash_swap(raw)
            datasets = analyze_dflash_datasets(raw)
            active_cnt = sum(1 for s in slots if s.spec.slot > 0 and not s.empty)
            vin = f" • VIN: {swap.vin}" if swap.vin else ""
            vcrn = f" • VCRN: {swap.vcrn.hex().upper()}" if swap.vcrn else ""
            label = tr(
                f"DataFlash 64 КБ • Активных банков CP: {active_cnt}/12{vin}{vcrn}",
                f"DataFlash 64 KB • Active CP banks: {active_cnt}/12{vin}{vcrn}",
            )
            return DetectedDumpFile(
                path=path,
                kind="dflash",
                valid=True,
                summary_text=label,
                dflash_slots=slots,
                dflash_swap=swap,
                dflash_datasets=datasets,
            )
        except Exception as exc:
            return DetectedDumpFile(path=path, kind="dflash", valid=False, summary_text=str(exc))
    if sz == UFLASH_SIZE:
        uinfo = analyze_uflash(raw)
        # Every FBL build carries the Renesas flash library's ID; only the builds we know have the RSA check at
        # UFLASH_RSA_CMP_OFFSET. Another build (HW 518, say) is still a bootloader, not a cut DataFlash.
        if uinfo.signature_found or FBL_LIBRARY_ID in raw:
            state = (
                tr("сборка не распознана", "unrecognised build") if not uinfo.signature_found
                else tr("Инженерный RSA-Free", "Engineering RSA-Free") if uinfo.rsa_bypassed
                else tr("Заводской RSA", "Stock RSA")
            )
            return DetectedDumpFile(
                path=path,
                kind="uflash",
                valid=True,
                summary_text=f"Uflash 32 KB (FBL) • {state}",
                uflash_info=uinfo,
            )
        return DetectedDumpFile(
            path=path,
            kind="truncated_dflash",
            valid=False,
            summary_text=tr(
                "ОШИБКА: Обрезанный 32 КБ дамп (вероятно R7F7010343AFP вместо 64 КБ R7F7010543)!",
                "ERROR: Truncated 32 KB dump (likely R7F7010343AFP instead of 64 KB R7F7010543)!",
            ),
        )
    if sz == EEPROM_SIZE and is_plausible_eeprom_bytes(raw, filename=path.name):
        try:
            einfo = analyze_eeprom(raw)
            pn = f" • {einfo.part_number}" if einfo.part_number else ""
            sw = f" SW {einfo.sw_version}" if einfo.sw_version else ""
            cp_lbl = (
                f" • CP mask 0x{einfo.learned_cp_mask:03X}"
                if einfo.learned_cp_mask is not None
                else ""
            )
            label = tr(
                f"EEPROM M95640 8 КБ{pn}{sw}{cp_lbl}",
                f"EEPROM M95640 8 KB{pn}{sw}{cp_lbl}",
            )
            return DetectedDumpFile(
                path=path,
                kind="eeprom",
                valid=True,
                summary_text=label,
                eeprom_info=einfo,
            )
        except Exception as exc:
            return DetectedDumpFile(path=path, kind="eeprom", valid=False, summary_text=str(exc))
    if sz in (OPBT_LEGACY_SIZE, OPBT_SIZE, EXTRA_AREA_SIZE) and is_plausible_opbt_bytes(raw):
        try:
            oinfo = analyze_opbt(raw)
            jtag = "JTAG ON" if oinfo.jtag_enabled else "JTAG OFF"
            icus = (
                ""
                if oinfo.icus_activated is None
                else (" • ICU-S ON" if oinfo.icus_activated else " • ICU-S OFF")
            )
            label = f"OPBT ({sz} B) • OPBT0=0x{oinfo.opbt0:08X} • {jtag}{icus}"
            return DetectedDumpFile(
                path=path,
                kind="opbt",
                valid=True,
                summary_text=label,
                opbt_info=oinfo,
            )
        except Exception as exc:
            return DetectedDumpFile(path=path, kind="opbt", valid=False, summary_text=str(exc))
    if path.suffix.lower() in (".json", ".pem") or sz == 128:
        return DetectedDumpFile(
            path=path,
            kind="rsa_key",
            valid=True,
            summary_text=tr(f"Ключ RSA ({path.name}, {sz:,} Б)", f"RSA Key ({path.name}, {sz:,} B)"),
        )
    return DetectedDumpFile(
        path=path,
        kind="unknown",
        valid=False,
        summary_text=tr(
            f"Неизвестный размер файла ({sz:,} Б) — ожидался 1.5 МБ CodeFlash, 64 КБ DataFlash или 32 КБ Uflash",
            f"Unrecognized file size ({sz:,} B) — expected 1.5 MB CodeFlash, 64 KB DataFlash, or 32 KB Uflash",
        ),
    )
