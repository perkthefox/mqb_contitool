"""Continental VAG MQB 17 Kombi VDD (`EV_DashBoardVDDMQBAB`, V850E2/Dx4 `uPD70F3526`) offline & protocol core.

Strictly separated from `FPK_E` (RH850/D1L + R-Car D1 virtual cockpit):
  - Single-MCU NEC/Renesas V850E2/Dx4 (`uPD70F3526`, verified on `5NA 920 740 B`, `SW 0310`).
  - Physical DataFlash: `32 KiB` at `0x02000000..0x02007FFF` (`16 x 2 KiB` physical blocks), blank-check status alias
    at `0x02100000..0x02107FFF`, and `132` EEL records (`0x0001..0x0084`, `9,533` bytes total defined at `0x00015320`)
    with live physical word-offset index table at `0xFEDC7BF0..0xFEDC7D07`.
  - Key firmware-verified layout differences vs RH850 `FPK_E`:
      * `EEL 0x0030` (`43 B`, `NVM 0x1C`): Long Coding (`+0x0B..+0x1E`, 20 B) protected by big-endian CRC-16/CCITT-FALSE
        at `+0x29..+0x2A` (`r30[-2:]` over `r30[2:-2]`), checked periodically by the background CRC-16 task (`0x001F3CF0`).
      * `EEL 0x0045` (`95 B`, `NVM 0x2D`): SW (`+2..+6`), ASAM (`+6..+12`), ODX (`+12..+37`), PN (`+37..+49`), HW PN (`+64..+76`).
      * `EEL 0x0060` (`16 B`, `NVM 0x47`, `eel_off = 4, plen = 12`): bytes `+2..+3` are `0xFF 0xFF` alignment padding,
        `+4..+15` are `3 x uint32 LE` of `km // 2`. Live RAM accumulator is at `0xFEDC8A48` (`meters`), DPOOL `0x260` at
        `0xFEDC1338`, and Retention RAM `0x140` at `0xFF7605DC`.
      * `EEL 0x0063` (`126 B`) / `0x0064` (`146 B`): FD11 identifier (`+0x02`, 15 B + pad + CRC32), SL 0..6 key (`+0x16`),
        SL 7 key (`+0x2A`), slot 3 (`+0x3E`), 32-byte key (`+0x52`), flags (`+0x76`), and `0x0064` slots (`+0x02`, `+0x16`).
      * `EEL 0x006B` (`50 B`, `NVM 0x50`, `0xFEDC7FB0..0xFEDC7FDF`):
          - `+0x02..+0x11` (`0xFEDC7FB0`): CP `/4` master VIN tail (`VIN[3..16]` + 2 B pad)
          - `+0x12..+0x21` (`0xFEDC7FC0`): CP `/1` GFA key (`DID 0x00BD`, 16 B)
          - `+0x22..+0x31` (`0xFEDC7FD0`): CP `/3` IKA key (`DID 0x00BE`, 16 B)
      * `EEL 0x006D` (`18 B`, `NVM 0x52`): CP `/2` status (`+2..+3` error counter, `+4..+7` J533 ref, `+8..+A` VIN prefix, `+B` adapted).
      * `WR_tbl0` (`0x001D8A6C`, checked by `0x001A046E`): uses `levels[3]` (`0x08` for `0x0060`, `0x0061..0x0064`, `0x0030+0x0E`,
        RAM, Retention RAM) when `DAT_ram_fedc8075` (`immo_mode`, `NVM 0x4D` / `EEL 0x0068+0x4B`) is non-zero, and switches to
        `levels[2]` (`0x06`/`0x07 <= SL 7`) when `DAT_ram_fedc8075 == 0x00` (reloaded live via `2E FD 3A 00 4D`).
"""

from __future__ import annotations

import contextlib
import hashlib
from pathlib import Path
import struct
from typing import Any
import zlib

from contitool.core.fpke import (
    EEL_MARK,
    FPKE_DFLASH_SIZE,
    FPKE_IMMO_PARTNERS,
    _clean_ascii,
    _crc32_le_ok,
    _eel_record_bytes,
    _parse_exact_hex,
    _partner_mac_map,
    build_fd11_proof,
    compare_fpke_immo_passports,
    eel_append_records,
    eel_cs24,
    eel_parse_pool,
    eel_read_record_any,
    format_fpke_immo_comparison,
    fpke_crc16_ccitt,
    fpke_derive_k_ffb,
    fpke_verify_s0_s1,
    is_fpke_dflash,
    parse_fpke_immo_config,
    parse_fpke_transponders,
    vote_fpke_odometer,
)
from contitool.i18n import tr

# ────────────────────────────── CAN IDs & V850E2 Memory Constants ──────────────────────────────

KOMBI_UDS_TX_ID = 0x714
KOMBI_UDS_RX_ID = 0x77E

KOMBI_CFLASH_ADDR = 0x00000000
KOMBI_CFLASH_SIZE = 0x00300000  # 3 MiB V850E2/Dx4 CodeFlash (0x00000000..0x002FFFFF)
KOMBI_DFLASH_BASE_ADDR = 0x02000000
KOMBI_DFLASH_POOL_SIZE = 0x00008000  # 32 KiB physical DataFlash pool (16 x 2 KiB blocks)
KOMBI_DFLASH_BC_ALIAS_ADDR = 0x02100000
KOMBI_DFLASH_SYNTH_SIZE = FPKE_DFLASH_SIZE  # 64 KiB EEL T01 container for offline editing/backup

KOMBI_EEL_VIRTUAL_BASE = 0xEF000000
KOMBI_RAM_STAGING_ADDR = 0xFEDD5508  # 252-byte shared NVM staging buffer (flg_e = 0x24)
KOMBI_RAM_SL7_KEY_ADDR = 0xFEDD5530  # 20 B: 16B FD11 Level 7 key + 4B CRC32 (offset +40 in NVM Block 0x5C)
KOMBI_RAM_EEL_PHYS_TABLE_ADDR = 0xFEDC7BF0  # 132 x u16 physical word offsets in 0x02000000..0x02007FFF
KOMBI_RAM_EEL_STATE_ADDR = 0xFEDC7CF8
KOMBI_RAM_LEVEL_ADDR = 0xFEDC8793

# Verified V850E2 SW 0310 NVM / RAM / Retention RAM addresses (from 5na-740b-clean.elf)
KOMBI_EEL_IMMO_MODE_VADDR = 0xEF00684B  # EEL 0x0068 + 0x4B (writable at SL 7 via WR_tbl0[30])
KOMBI_RAM_IMMO_MODE_ADDR = 0xFEDC8075  # RAM mirror of NVM 0x4D (EEL 0x0068 + 0x4B), checked by FUN_ram_000844ac
KOMBI_RAM_ODO_MIRROR_ADDR = 0xFEDC8000  # RAM mirror of NVM 0x47 (EEL 0x0060 + 0x04..0x0F)
KOMBI_RAM_ODO_METERS_ADDR = 0xFEDC8A48  # DAT_ram_fedc8a44[1], live odometer in meters (LE32)
KOMBI_RAM_ODO_DPOOL_ADDR = 0xFEDC1338  # DPOOL 0x260 meters (LE32), read by 22 2203 and saved to Retention RAM on sleep
KOMBI_RETAIN_ODO_DPOOL_ADDR = 0xFF7605DC  # Retention RAM DPOOL 0x140 meters (LE32), restored on warm reset (11 02 / 11 01)
KOMBI_RAM_S0_ADDR = 0xFEDC83C4  # 32 B: S0 (16 B) || S1 (16 B) packed by 0x00199D90 on SW 0310
KOMBI_RAM_SLOTS_FLAG_ADDR = 0xFEDC83FA  # 1 B: bit 0 = Slot A loaded, bit 1 = Slot B loaded (0x03 = both)
KOMBI_RAM_RECOG_STATE_ADDR = 0xFEDC8361  # 1 B: transponder recognition state
KOMBI_RAM_SLOT_A_ADDR = 0xFEDC82FC  # 16 B: raw decrypted Slot A plaintext (0x0019655A)
KOMBI_RAM_SLOT_B_ADDR = 0xFEDC831C  # 16 B: raw decrypted Slot B plaintext (0x0019655A)
KOMBI_RAM_EEL67_ADDR = 0xFEDC8007  # 37 B: RAM mirror of NVM 0x4C / EEL 0x0067 (key IDs + allowed/learned)
KOMBI_RAM_EEL68_ADDR = 0xFEDC802C  # 76 B: RAM mirror of NVM 0x4D / EEL 0x0068 (VIN, K_c, flags, immo_mode)
KOMBI_RAM_EEL69_ADDR = 0xFEDC7F90  # 32 B: RAM mirror of NVM 0x4E / EEL 0x0069 (S0 || S1)
KOMBI_SECDATA_SCAN_RANGE: tuple[int, int] = (0xFEDC7E88, 0xFEDC87A0)

KOMBI_NVM_BLOCK_CODING = 0x001C  # EEL 0x0030 (43 B)
KOMBI_NVM_BLOCK_ODO_REPAIR = 0x0021  # EEL 0x0035 (4 B)
KOMBI_NVM_BLOCK_ODO = 0x0047  # EEL 0x0060 (16 B)
KOMBI_NVM_BLOCK_IMMO = 0x004D  # EEL 0x0068 (128 B)

KOMBI_SA1_DELTA = 0xB80B  # *(uint16_t *)(0x00253ADE + 15 * 2) = 0xB80B
KOMBI_SA1_LOCKOUT_RESET_DELTA = 0x62EF  # Built-in SA1 lockout clear key (25327): 0x001A0584 (SW 0310) & 0x00180B5C (SW 2220)
KOMBI_REQUIRED_SL = 7

# EEL blocks protected by big-endian CRC-16/CCITT-FALSE at rec[-2:] over rec[2:-2] (table @ 0x001F3CF0)
KOMBI_CRC16_EEL_IDS: frozenset[int] = frozenset({0x0030, 0x0038, 0x003E, 0x0043})

# EEL blocks with eel_off = 4 (bytes +2..+3 are 0xFF 0xFF alignment padding, payload starts at +4)
KOMBI_ALIGN4_EEL_IDS: frozenset[int] = frozenset({0x0060, 0x0061, 0x0062})

# EEL blocks whose WR_tbl0 entry has levels[3] == 0x08 when immo_mode != 0, and levels[2] <= 0x07 when immo_mode == 0
KOMBI_WR_PRIVILEGED_EEL_IDS: frozenset[int] = frozenset(
    {0x0008, 0x002C, 0x0030, 0x003A, 0x003E, 0x0060, 0x0061, 0x0062, 0x0063, 0x0064}
)
KOMBI_2220_WR_PRIVILEGED_EEL_IDS: frozenset[int] = frozenset(
    {
        0x0008,
        0x002C,
        0x0030,
        0x003A,
        0x003E,
        0x0060,
        0x0061,
        0x0062,
        0x0063,
        0x0064,
        0x0065,
        0x0066,
        0x0067,
        0x0068,
        0x0069,
        0x006A,
        0x006B,
        0x006C,
        0x006D,
        0x006E,
        0x006F,
        0x0070,
    }
)
# EEL records touched by 2E FD E3 (FUN_ram_00060798 @ 0x00060798) during temporary immo_mode=0 unlock on SW 2220
KOMBI_2220_FDE3_AFFECTED_EEL_IDS: tuple[int, ...] = (
    0x0063,
    0x0065,
    0x0066,
    0x0067,
    0x0068,
    0x0069,
    0x006A,
    0x006B,
)
KOMBI_2220_RAM_FD11_STATE_ADDR = 0xFEDC9299  # 12 B RAM mirror of EEL 0x0065+0x02..0x0D (saved_level @ +3, 'Z' @ +4, flags @ +5, CRC32 @ +8)

# 132-entry EEL block size table @ 0x00015320 on 5NA 920 740 B (SW 0310, total = 9,533 bytes)
EEL_KOMBI_0310_IDS: dict[int, int] = {
    1: 5, 2: 130, 3: 249, 4: 85, 5: 90, 6: 172, 7: 126, 8: 246, 9: 246, 10: 248,
    11: 242, 12: 202, 13: 113, 14: 248, 15: 186, 16: 248, 17: 186, 18: 248, 19: 186, 20: 248,
    21: 186, 22: 248, 23: 186, 24: 248, 25: 186, 26: 248, 27: 186, 28: 248, 29: 186, 30: 128,
    31: 4, 32: 158, 33: 4, 34: 48, 35: 6, 36: 22, 37: 26, 38: 14, 39: 4, 40: 19,
    41: 3, 42: 8, 43: 14, 44: 29, 45: 23, 46: 33, 47: 23, 48: 43, 49: 62, 50: 14,
    51: 22, 52: 8, 53: 4, 54: 50, 55: 9, 56: 55, 57: 4, 58: 79, 59: 151, 60: 95,
    61: 161, 62: 196, 63: 137, 64: 62, 65: 32, 66: 17, 67: 14, 68: 56, 69: 95, 70: 136,
    71: 12, 72: 12, 73: 12, 74: 12, 75: 12, 76: 12, 77: 12, 78: 12, 79: 12, 80: 12,
    81: 12, 82: 12, 83: 12, 84: 12, 85: 12, 86: 12, 87: 12, 88: 12, 89: 12, 90: 12,
    91: 12, 92: 12, 93: 12, 94: 12, 95: 4, 96: 16, 97: 132, 98: 132, 99: 126, 100: 146,
    101: 14, 102: 22, 103: 39, 104: 128, 105: 34, 106: 121, 107: 50, 108: 18, 109: 18, 110: 4,
    111: 5, 112: 4, 113: 86, 114: 5, 115: 22, 116: 22, 117: 22, 118: 22, 119: 22, 120: 22,
    121: 22, 122: 22, 123: 22, 124: 22, 125: 22, 126: 22, 127: 22, 128: 22, 129: 22, 130: 22,
    131: 50, 132: 45,
}
KOMBI_EEL_LOGICAL_SIZE = sum(EEL_KOMBI_0310_IDS.values())  # 9,533 bytes

# 130-entry EEL block size table @ 0x00015320 on 8V0 920 860 E (SW 2220, total = 8,334 bytes)
EEL_KOMBI_2220_IDS: dict[int, int] = {
    1: 5, 2: 130, 3: 174, 4: 85, 5: 49, 6: 172, 7: 100, 8: 246, 9: 246, 10: 248,
    11: 250, 12: 170, 13: 113, 14: 248, 15: 100, 16: 248, 17: 100, 18: 248, 19: 100, 20: 248,
    21: 100, 22: 248, 23: 100, 24: 248, 25: 100, 26: 248, 27: 100, 28: 248, 29: 100, 30: 74,
    31: 4, 32: 168, 33: 4, 34: 48, 35: 6, 36: 22, 37: 25, 38: 14, 39: 4, 40: 19,
    41: 3, 42: 8, 43: 13, 44: 20, 45: 6, 46: 3, 47: 24, 48: 43, 49: 63, 50: 14,
    51: 22, 52: 8, 53: 4, 54: 50, 55: 9, 56: 52, 57: 4, 58: 65, 59: 124, 60: 93,
    61: 156, 62: 188, 63: 137, 64: 62, 65: 32, 66: 17, 67: 14, 68: 56, 69: 95, 70: 136,
    71: 12, 72: 12, 73: 12, 74: 12, 75: 12, 76: 12, 77: 12, 78: 12, 79: 12, 80: 12,
    81: 12, 82: 12, 83: 12, 84: 12, 85: 12, 86: 12, 87: 12, 88: 12, 89: 12, 90: 12,
    91: 12, 92: 12, 93: 12, 94: 12, 95: 4, 96: 16, 97: 132, 98: 132, 99: 126, 100: 42,
    101: 14, 102: 17, 103: 39, 104: 128, 105: 34, 106: 121, 107: 50, 108: 18, 109: 18, 110: 4,
    111: 5, 112: 4, 113: 87, 114: 6, 115: 23, 116: 23, 117: 23, 118: 23, 119: 23, 120: 23,
    121: 23, 122: 23, 123: 23, 124: 23, 125: 23, 126: 23, 127: 23, 128: 23, 129: 23, 130: 23,
}
KOMBI_EEL_2220_LOGICAL_SIZE = sum(EEL_KOMBI_2220_IDS.values())  # 8,334 bytes
KOMBI_EEL_LOGICAL_SIZES: frozenset[int] = frozenset({KOMBI_EEL_LOGICAL_SIZE, KOMBI_EEL_2220_LOGICAL_SIZE})

# Verified V850E2 SW 2220 (8V0 920 860 E) NVM / RAM / Retention RAM addresses (from 8v0-860e-app.elf)
KOMBI_2220_SA1_DELTA = 0x4E87  # FUN_ram_00180b44 @ 0x00180B44: key = (seed + 0x4E87) mod 2^32
KOMBI_2220_RAM_STAGING_ADDR = 0xFEDD2458  # 256-byte NvM internal staging buffer (FUN_ram_000ba21a @ 0x000BA21A, NOT wiped)
KOMBI_2220_RAM_SL7_KEY_ADDR = 0xFEDD2480  # 20 B: 16B FD11 Level 7 key + 4B CRC32 (offset +0x28 in 0xFEDD2458)
KOMBI_2220_RAM_EEL_PHYS_TABLE_ADDR = 0xFEDFDE90  # 130 x u16 physical word offsets in 0x02000000..0x02007FFF
KOMBI_2220_RAM_LEVEL_ADDR = 0xFEDC9287  # Current FD11 supplier level byte (FUN_ram_00180ed2 @ 0x00180ED2)
KOMBI_2220_RAM_IMMO_MODE_ADDR = 0xFEDC8C07  # RAM mirror of NVM 0x4D (EEL 0x0068 + 0x4B), checked by FUN_ram_00089088
KOMBI_2220_RAM_ODO_MIRROR_ADDR = 0xFEDC8B70  # RAM mirror of NVM 0x47 (EEL 0x0060 + 0x04..0x0F)
KOMBI_2220_RAM_ODO_METERS_ADDR = 0xFEDC9560  # (&DAT_ram_fedc955c)[1], live odometer in meters (LE32)
KOMBI_2220_RAM_ODO_DPOOL_ADDR = 0xFEDC10EC  # DPOOL 0x226 meters (LE32), read by 22 2203
KOMBI_2220_RETAIN_ODO_DPOOL_ADDR = 0xFF760678  # Retention RAM DPOOL 0x125 meters (LE32)
KOMBI_2220_RAM_S0_ADDR = 0xFEDC8EE0  # 32 B: S0 (16 B) || S1 (16 B) packed by FUN_ram_0017a69a @ 0x0017A69A
KOMBI_2220_RAM_SLOTS_FLAG_ADDR = 0xFEDC8F15  # 1 B: bit 0 = Slot A loaded, bit 1 = Slot B loaded (0x03 = both)
KOMBI_2220_RAM_RECOG_STATE_ADDR = 0xFEDC8E94  # 1 B: transponder recognition state
KOMBI_2220_RAM_LAST_KEY_ID_ADDR = 0xFEDC8D08  # 4 B: last transponder ID read by LF coil (22 02E4)
KOMBI_2220_RAM_SLOT_A_ADDR = 0xFEDC8E30  # 16 B: raw decrypted Slot A plaintext (FUN_ram_00177048, unwiped by 2E FDE3)
KOMBI_2220_RAM_SLOT_B_ADDR = 0xFEDC8E50  # 16 B: raw decrypted Slot B plaintext (FUN_ram_00177048, unwiped by 2E FDE3)
KOMBI_2220_RAM_EEL67_ADDR = 0xFEDC8B99  # 37 B: RAM mirror of NVM 0x4C / EEL 0x0067 (key IDs + allowed/learned)
KOMBI_2220_RAM_EEL68_ADDR = 0xFEDC8BBE  # 75 B: RAM mirror of NVM 0x4D / EEL 0x0068 (VIN, K_c, flags, immo_mode)
KOMBI_2220_RAM_EEL69_ADDR = 0xFEDC8B00  # 32 B: RAM mirror of NVM 0x4E / EEL 0x0069 (S0 || S1)
KOMBI_2220_SECDATA_SCAN_RANGE: tuple[int, int] = (0xFEDC89F8, 0xFEDC92B0)

# Protected EEL blocks 0x0065..0x006F mapped to (nvm_block_id, payload_len) for 2E FD 3A -> ram_staging_addr reload at SL 7
KOMBI_NVM_STAGED_EEL_MAP: dict[int, tuple[int, int]] = {
    0x0065: (0x004A, 12),
    0x0066: (0x004B, 15),
    0x0067: (0x004C, 37),
    0x0068: (0x004D, 75),
    0x0069: (0x004E, 32),
    0x006A: (0x004F, 119),
    0x006B: (0x0050, 48),
    0x006C: (0x0051, 16),
    0x006D: (0x0052, 16),
    0x006E: (0x0053, 2),
    0x006F: (0x0054, 3),
}

# Staged sub-blocks of EEL 0x0063 (126 B) and EEL 0x0064 (146 B on 0310 / 42 B on 2220) loaded into staging RAM at SL 7
KOMBI_FD11_STAGED_SUBBLOCKS: tuple[tuple[str, bytes, int, int, int], ...] = (
    ("0x006316_level6_key", bytes.fromhex("2efd110a01"), 20, 0x0063, 0x16),
    ("0x00632A_level7_key", bytes.fromhex("2efd110a02"), 20, 0x0063, 0x2A),
    ("0x00633E_slot3_key", bytes.fromhex("2efd110a03"), 20, 0x0063, 0x3E),
    ("0x006352_32b_key", bytes.fromhex("2efd1106"), 36, 0x0063, 0x52),
    ("0x006376_flags", bytes.fromhex("2efd110a04"), 8, 0x0063, 0x76),
    ("0x006402_slot5_key", bytes.fromhex("2efd110a05"), 20, 0x0064, 0x02),
    ("0x006416_slot6_key", bytes.fromhex("2efd110a06"), 20, 0x0064, 0x16),
)

KOMBI_VERIFIED_SW_VERSIONS: tuple[str, ...] = ("0310", "2220")
KOMBI_VERIFIED_PART_NUMBERS: tuple[str, ...] = ("5NA920740B", "8V0920860E")


def get_kombi_sw_profile(
    sw_version: str | None = None,
    part_number: str | None = None,
) -> dict[str, Any]:
    """Return the verified V850E2 Kombi firmware profile (`0310` for `5NA 920 740 B` or `2220` for `8V0 920 860 E`)."""
    sw_norm = "".join((sw_version or "").split()).upper()
    pn_norm = "".join((part_number or "").split()).upper()
    if sw_norm == "2220" or pn_norm.startswith("8V0920860"):
        return {
            "sw_profile": "2220",
            "platform": "V850E2-KOMBI-2220",
            "target_label": "Audi Kombi MQB V850E2 SW 2220 (8V0920860E)",
            "sa1_delta": KOMBI_2220_SA1_DELTA,
            "sa1_lockout_reset_delta": KOMBI_SA1_LOCKOUT_RESET_DELTA,
            "ram_staging_addr": KOMBI_2220_RAM_STAGING_ADDR,
            "ram_sl7_key_addr": KOMBI_2220_RAM_SL7_KEY_ADDR,
            "ram_eel_phys_table_addr": KOMBI_2220_RAM_EEL_PHYS_TABLE_ADDR,
            "ram_level_addr": KOMBI_2220_RAM_LEVEL_ADDR,
            "ram_immo_mode_addr": KOMBI_2220_RAM_IMMO_MODE_ADDR,
            "ram_odo_mirror_addr": KOMBI_2220_RAM_ODO_MIRROR_ADDR,
            "ram_odo_meters_addr": KOMBI_2220_RAM_ODO_METERS_ADDR,
            "ram_odo_dpool_addr": KOMBI_2220_RAM_ODO_DPOOL_ADDR,
            "retain_odo_dpool_addr": KOMBI_2220_RETAIN_ODO_DPOOL_ADDR,
            "eel_ids": EEL_KOMBI_2220_IDS,
            "eel_logical_size": KOMBI_EEL_2220_LOGICAL_SIZE,
            "can_switch_immo_mode0_at_sl7": True,
            "immo_mode0_unlock_method": "fde3_sl7_restore",
            "ram_fd11_state_addr": KOMBI_2220_RAM_FD11_STATE_ADDR,
            "wr_privileged_eel_ids": KOMBI_2220_WR_PRIVILEGED_EEL_IDS,
            "ram_s0_addr": KOMBI_2220_RAM_S0_ADDR,
            "ram_slots_flag_addr": KOMBI_2220_RAM_SLOTS_FLAG_ADDR,
            "ram_recog_state_addr": KOMBI_2220_RAM_RECOG_STATE_ADDR,
            "ram_last_key_id_addr": KOMBI_2220_RAM_LAST_KEY_ID_ADDR,
            "ram_slot_a_addr": KOMBI_2220_RAM_SLOT_A_ADDR,
            "ram_slot_b_addr": KOMBI_2220_RAM_SLOT_B_ADDR,
            "ram_eel67_addr": KOMBI_2220_RAM_EEL67_ADDR,
            "ram_eel68_addr": KOMBI_2220_RAM_EEL68_ADDR,
            "ram_eel69_addr": KOMBI_2220_RAM_EEL69_ADDR,
            "eel68_kessy_payload_offset": 0x3F,
            "secdata_scan_range": KOMBI_2220_SECDATA_SCAN_RANGE,
        }
    return {
        "sw_profile": "0310",
        "platform": "V850E2-KOMBI-0310",
        "target_label": "VW Kombi MQB V850E2 SW 0310 (5NA920740B)",
        "sa1_delta": KOMBI_SA1_DELTA,
        "sa1_lockout_reset_delta": KOMBI_SA1_LOCKOUT_RESET_DELTA,
        "ram_staging_addr": KOMBI_RAM_STAGING_ADDR,
        "ram_sl7_key_addr": KOMBI_RAM_SL7_KEY_ADDR,
        "ram_eel_phys_table_addr": KOMBI_RAM_EEL_PHYS_TABLE_ADDR,
        "ram_level_addr": KOMBI_RAM_LEVEL_ADDR,
        "ram_immo_mode_addr": KOMBI_RAM_IMMO_MODE_ADDR,
        "ram_odo_mirror_addr": KOMBI_RAM_ODO_MIRROR_ADDR,
        "ram_odo_meters_addr": KOMBI_RAM_ODO_METERS_ADDR,
        "ram_odo_dpool_addr": KOMBI_RAM_ODO_DPOOL_ADDR,
        "retain_odo_dpool_addr": KOMBI_RETAIN_ODO_DPOOL_ADDR,
        "eel_ids": EEL_KOMBI_0310_IDS,
        "eel_logical_size": KOMBI_EEL_LOGICAL_SIZE,
        "can_switch_immo_mode0_at_sl7": True,
        "immo_mode0_unlock_method": "direct_0x3d_ef00684b",
        "ram_fd11_state_addr": None,
        "wr_privileged_eel_ids": KOMBI_WR_PRIVILEGED_EEL_IDS,
        "ram_s0_addr": KOMBI_RAM_S0_ADDR,
        "ram_slots_flag_addr": KOMBI_RAM_SLOTS_FLAG_ADDR,
        "ram_recog_state_addr": KOMBI_RAM_RECOG_STATE_ADDR,
        "ram_last_key_id_addr": None,
        "ram_slot_a_addr": KOMBI_RAM_SLOT_A_ADDR,
        "ram_slot_b_addr": KOMBI_RAM_SLOT_B_ADDR,
        "ram_eel67_addr": KOMBI_RAM_EEL67_ADDR,
        "ram_eel68_addr": KOMBI_RAM_EEL68_ADDR,
        "ram_eel69_addr": KOMBI_RAM_EEL69_ADDR,
        "eel68_kessy_payload_offset": 0x4B,
        "secdata_scan_range": KOMBI_SECDATA_SCAN_RANGE,
    }


# ────────────────────────────── Checksums & Identification Helpers ──────────────────────────────


def kombi_crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE (`poly=0x1021, init=0xFFFF`, big-endian in `EEL 0x0030 / 0x0038 / 0x003E / 0x0043`)."""
    return fpke_crc16_ccitt(data)


def _kombi_crc32_ok(payload: bytes, expected_4: bytes) -> bool:
    if len(expected_4) != 4:
        return False
    return (zlib.crc32(payload) & 0xFFFFFFFF) == int.from_bytes(expected_4, "little")


def is_kombi_ident(ident: list[dict[str, str]] | dict[str, Any] | None) -> bool:
    """True when UDS identification DIDs belong to a Continental V850E2 MQB `17 Kombi VDD` (not `FPK_E`)."""
    vals: dict[str, str] = {}
    if isinstance(ident, list):
        vals = {str(item.get("did", "")).upper(): str(item.get("value", "")).strip() for item in ident}
    elif isinstance(ident, dict):
        vals = {
            "F187": str(ident.get("part_number") or ident.get("F187") or "").strip(),
            "F189": str(ident.get("sw_version") or ident.get("F189") or "").strip(),
            "F191": str(ident.get("hw_part_number") or ident.get("F191") or "").strip(),
            "F197": str(ident.get("system_name") or ident.get("F197") or "").strip(),
            "F19E": str(ident.get("asam_odx") or ident.get("F19E") or "").strip(),
            "F17C": str(ident.get("fazit") or ident.get("F17C") or "").strip(),
        }
    if not vals:
        return False
    odx = vals.get("F19E", "").upper()
    sys_name = vals.get("F197", "").upper()
    sw = "".join(vals.get("F189", "").split()).upper()
    pn = "".join((vals.get("F187") or vals.get("F191") or "").split()).upper()
    if "FPK" in odx or "FPK" in sys_name:
        return False
    if "VDDMQB" in odx or "EV_DASHBOARDVDD" in odx:
        return True
    if pn in KOMBI_VERIFIED_PART_NUMBERS or pn.startswith(("5NA920740", "8V0920860")):
        return True
    if len(pn) >= 9 and pn[3:6] == "920" and sw in KOMBI_VERIFIED_SW_VERSIONS:
        return True
    return False


def kombi_support_info(
    ident: list[dict[str, str]] | dict[str, Any] | None = None,
    *,
    f189: str | None = None,
    f187: str | None = None,
    f191: str | None = None,
    f197: str | None = None,
    f19e: str | None = None,
    f17c: str | None = None,
) -> dict[str, Any]:
    """Return official support status and a clear `(PN + SW)` warning for a `17 Kombi VDD` cluster."""
    vals: dict[str, str] = {}
    if isinstance(ident, list):
        vals = {str(it.get("did", "")).upper(): str(it.get("value", "")).strip() for it in ident}
    elif isinstance(ident, dict):
        vals = {
            "F187": str(ident.get("part_number") or ident.get("F187") or "").strip(),
            "F189": str(ident.get("sw_version") or ident.get("F189") or "").strip(),
            "F191": str(ident.get("hw_part_number") or ident.get("F191") or "").strip(),
            "F197": str(ident.get("system_name") or ident.get("F197") or "").strip(),
            "F19E": str(ident.get("asam_odx") or ident.get("F19E") or "").strip(),
            "F17C": str(ident.get("fazit") or ident.get("F17C") or "").strip(),
        }

    pn = (f187 if f187 is not None else (vals.get("F187") or vals.get("F191") or (f191 or ""))).strip()
    sw = (f189 if f189 is not None else vals.get("F189", "")).strip()
    sys_name = (f197 if f197 is not None else vals.get("F197", "")).strip().upper()
    odx = (f19e if f19e is not None else vals.get("F19E", "")).strip().upper()
    fazit = (f17c if f17c is not None else vals.get("F17C", "")).strip().upper()

    if not pn and not sw:
        return {
            "verified": True,
            "part_number": "",
            "sw_version": "",
            "warning": None,
            "tone": "ok",
        }

    pn_norm = "".join(pn.split()).upper()
    sw_norm = "".join(sw.split()).upper()
    meta_upper = f"{sys_name} {odx} {fazit}"
    non_conti = any(tok in meta_upper for tok in ("VISTEON", "BOSCH", "JCI", "JOHNSON", "MARELLI"))

    if non_conti:
        verified = False
    elif sw_norm:
        verified = sw_norm in KOMBI_VERIFIED_SW_VERSIONS
    else:
        verified = pn_norm in KOMBI_VERIFIED_PART_NUMBERS

    warning: str | None = None
    if not verified:
        unit_id_ru = f"{pn} (ПО {sw})" if (pn and sw) else (pn or f"ПО {sw}")
        unit_id_en = f"{pn} (SW {sw})" if (pn and sw) else (pn or f"SW {sw}")
        warning = tr(
            f"Блок Kombi {unit_id_ru} официально не проверен (эталоны: Continental 5NA 920 740 B ПО 0310, 8V0 920 860 E ПО 2220, V850E2). "
            "Доступно чтение по UDS / Supplier Level 7; перед записью в DataFlash проверьте адреса RAM.",
            f"Kombi unit {unit_id_en} is not officially verified (references: Continental 5NA 920 740 B SW 0310, 8V0 920 860 E SW 2220, V850E2). "
            "UDS / Supplier Level 7 reading is available; verify RAM addresses before writing DataFlash.",
        )

    return {
        "verified": verified,
        "part_number": pn,
        "sw_version": sw,
        "warning": warning,
        "tone": "ok" if verified else "warn",
    }


# ────────────────────────────── EEL Container Builders & Parsers ──────────────────────────────


def kombi_eel_layout(
    dflash: bytes | None = None,
    *,
    ids: dict[int, int] | None = None,
) -> dict[str, Any]:
    """Return the 28-VB EEL T01 container layout descriptor for Kombi V850E2 (`0310` 132-record or `2220` 130-record)."""
    chosen_ids = ids
    if chosen_ids is None and dflash is not None and len(dflash) == KOMBI_DFLASH_SYNTH_SIZE:
        lay_0310 = {"vb": 0x800, "n_vb": 28, "base": 0, "threshold": 8, "ids": EEL_KOMBI_0310_IDS}
        lay_2220 = {"vb": 0x800, "n_vb": 28, "base": 0, "threshold": 8, "ids": EEL_KOMBI_2220_IDS}
        _, lat_0310 = eel_parse_pool(lay_0310, dflash)
        _, lat_2220 = eel_parse_pool(lay_2220, dflash)
        has_high_id = any(ident > 130 for ident in lat_0310)
        if not has_high_id and lat_2220:
            ok_0310 = sum(
                1
                for ident, (_vb, top, _ref) in lat_0310.items()
                if int.from_bytes(dflash[top : top + 2], "little") == EEL_KOMBI_0310_IDS.get(ident, -1)
            )
            ok_2220 = sum(
                1
                for ident, (_vb, top, _ref) in lat_2220.items()
                if int.from_bytes(dflash[top : top + 2], "little") == EEL_KOMBI_2220_IDS.get(ident, -1)
            )
            if ok_2220 > ok_0310:
                chosen_ids = EEL_KOMBI_2220_IDS
    if chosen_ids is None:
        chosen_ids = EEL_KOMBI_0310_IDS
    return {
        "vb": 0x800,
        "n_vb": 28,
        "base": 0,
        "threshold": 8,
        "ids": dict(chosen_ids),
    }


def _choose_kombi_eel_ids_for_records(
    records: dict[int, bytes],
    eel_ids: dict[int, int] | None = None,
) -> dict[int, int]:
    if eel_ids is not None:
        return dict(eel_ids)
    if 131 not in records and 132 not in records:
        r64 = records.get(0x64)
        r66 = records.get(0x66)
        r03 = records.get(0x03)
        if (
            (r64 is not None and len(r64) in (42, 40))
            or (r66 is not None and len(r66) in (17, 15))
            or (r03 is not None and len(r03) in (174, 172))
            or len(records) == len(EEL_KOMBI_2220_IDS)
        ):
            return dict(EEL_KOMBI_2220_IDS)
    return dict(EEL_KOMBI_0310_IDS)


def _build_empty_eel_t01_pool(first_rec_1: bytes, n_vb: int = 28, vb_size: int = 0x800) -> bytes:
    """Create a clean 64 KiB EEL T01 pool with VB 0 active (`EC = 1`, seeded with record `0x0001`) and VBs `1..n_vb-1` prepared."""
    df = bytearray(b"\xff" * KOMBI_DFLASH_SYNTH_SIZE)
    ec_word = eel_cs24(1)
    struct.pack_into("<5I", df, 0, 0xFFFFFFFF, EEL_MARK, EEL_MARK, EEL_MARK, ec_word)
    sz1 = EEL_KOMBI_0310_IDS[1]
    padded1 = (sz1 + 3) & ~3
    rec1 = (struct.pack("<H", sz1) + bytes(first_rec_1[2:sz1])).ljust(padded1, b"\xff")
    top1 = vb_size - 8
    for i in range(0, padded1, 4):
        df[top1 - i : top1 - i + 4] = rec1[i : i + 4]
    drp1 = 1 | (top1 << 16)
    struct.pack_into("<4I", df, 0x18, EEL_MARK, EEL_MARK, EEL_MARK, drp1)
    for vb in range(1, n_vb):
        base = vb * vb_size
        struct.pack_into("<5I", df, base, 0xFFFFFFFF, EEL_MARK, 0xFFFFFFFF, 0xFFFFFFFF, ec_word)
    return bytes(df)


def build_kombi_eel_dflash(
    records: dict[int, bytes],
    *,
    eel_ids: dict[int, int] | None = None,
) -> bytes:
    """Pack `{eel_id: raw_record}` (`132` records on `0310` or `130` records on `2220`) into a valid 64 KiB EEL T01 image.

    Each value in `records` may be either `size` bytes (with the 2-byte `<H` size prefix) or `size - 2` bytes
    (payload only, in which case `struct.pack('<H', size)` is prepended automatically).
    """
    target_ids = _choose_kombi_eel_ids_for_records(records, eel_ids)
    lay = kombi_eel_layout(ids=target_ids)
    norm_updates: dict[int, bytes] = {}
    for ident, exp_size in sorted(target_ids.items()):
        raw = records.get(ident)
        if raw is None:
            norm_updates[ident] = struct.pack("<H", exp_size) + (b"\xff" * (exp_size - 2))
        elif len(raw) == exp_size:
            norm_updates[ident] = struct.pack("<H", exp_size) + bytes(raw[2:])
        elif len(raw) == exp_size - 2:
            norm_updates[ident] = struct.pack("<H", exp_size) + bytes(raw)
        else:
            raise ValueError(
                f"Kombi EEL 0x{ident:04X} record length mismatch: got {len(raw)} B, expected {exp_size} B (or {exp_size - 2} B payload)"
            )
    empty_pool = _build_empty_eel_t01_pool(norm_updates[1])
    return eel_append_records(empty_pool, norm_updates, layout=lay)


def unpack_kombi_logical_eel(blob: bytes) -> dict[int, bytes]:
    """Unpack a contiguous `9,533`-byte (`SW 0310`) or `8,334`-byte (`SW 2220`) logical EEL dump into `{eel_id: raw}`."""
    if len(blob) == KOMBI_EEL_LOGICAL_SIZE:
        target_ids = EEL_KOMBI_0310_IDS
    elif len(blob) == KOMBI_EEL_2220_LOGICAL_SIZE:
        target_ids = EEL_KOMBI_2220_IDS
    else:
        raise ValueError(
            f"Expected {KOMBI_EEL_LOGICAL_SIZE}-byte (SW 0310) or {KOMBI_EEL_2220_LOGICAL_SIZE}-byte (SW 2220) logical EEL image, got {len(blob)} bytes"
        )
    records: dict[int, bytes] = {}
    off = 0
    for ident, sz in sorted(target_ids.items()):
        rec = bytes(blob[off : off + sz])
        records[ident] = struct.pack("<H", sz) + rec[2:]
        off += sz
    return records


def unpack_kombi_physical_dflash(raw_32k: bytes) -> dict[int, bytes]:
    """Parse a raw `32,768`-byte (`0x02000000..0x02007FFF`) V850E2 physical DataFlash image into `{eel_id: raw_record}`."""
    if len(raw_32k) != KOMBI_DFLASH_POOL_SIZE:
        raise ValueError(f"Expected {KOMBI_DFLASH_POOL_SIZE}-byte physical V850E2 DataFlash, got {len(raw_32k)} bytes")

    vb_size = 0x800
    n_vb = KOMBI_DFLASH_POOL_SIZE // vb_size
    block_order: list[tuple[int, int]] = []
    for blk in range(n_vb):
        base = blk * vb_size
        w0 = int.from_bytes(raw_32k[base : base + 4], "little")
        ec_raw = int.from_bytes(raw_32k[base + 0x1C : base + 0x20], "little")
        if w0 == 0xFFFFFFFF and ec_raw == 0xFFFFFFFF:
            continue
        ec = ec_raw & 0x00FFFFFF
        if ec == 0x00FFFFFF:
            ec = 0
        block_order.append((ec, blk))
    block_order.sort()

    def _extract_payload(top_word_off: int, exp_size: int) -> tuple[bytes, int] | None:
        top_off = top_word_off * 4
        if top_off < 0x20 or top_off + 4 > KOMBI_DFLASH_POOL_SIZE:
            return None
        padded = (exp_size + 3) & ~3
        out = bytearray()
        cur_off = top_off
        cur_blk = cur_off // vb_size
        for _ in range(padded // 4):
            if cur_off < cur_blk * vb_size + 0x20:
                cur_blk = (cur_blk - 1) % n_vb
                cur_off = (cur_blk + 1) * vb_size - 4
            if cur_off < 0 or cur_off + 4 > KOMBI_DFLASH_POOL_SIZE:
                return None
            out.extend(raw_32k[cur_off : cur_off + 4])
            cur_off -= 4
        rec = bytes(out[:exp_size])
        raw_hdr = int.from_bytes(rec[:2], "little") if len(rec) >= 2 else -1
        return struct.pack("<H", exp_size) + rec[2:], raw_hdr

    def _parse_with_table(id_table: dict[int, int]) -> tuple[dict[int, bytes], int, bool]:
        recs: dict[int, bytes] = {}
        hdr_matches = 0
        has_high = False
        for _ec, blk in block_order:
            base = blk * vb_size
            drp_off = base + 0x20
            while drp_off + 8 <= base + vb_size - 4:
                w0, w1 = struct.unpack_from("<II", raw_32k, drp_off)
                if w0 == 0xFFFFFFFF and w1 == 0xFFFFFFFF:
                    break
                ident = w0 & 0xFFFF
                top_w = (w0 >> 16) & 0xFFFF
                if ident not in id_table and (w1 & 0xFFFF) in id_table:
                    ident = w1 & 0xFFFF
                    top_w = (w1 >> 16) & 0xFFFF
                if ident > 130 and ident <= 132:
                    has_high = True
                exp_sz = id_table.get(ident)
                if exp_sz is not None and 0 < top_w < (KOMBI_DFLASH_POOL_SIZE // 4):
                    ext = _extract_payload(top_w, exp_sz)
                    if ext is not None:
                        rec, raw_hdr = ext
                        recs[ident] = rec
                        if raw_hdr == exp_sz:
                            hdr_matches += 1
                drp_off += 8
        return recs, hdr_matches, has_high

    recs_0310, ok_0310, has_high = _parse_with_table(EEL_KOMBI_0310_IDS)
    if not has_high:
        recs_2220, ok_2220, _ = _parse_with_table(EEL_KOMBI_2220_IDS)
        if ok_2220 > ok_0310:
            return recs_2220
    return recs_0310


def normalize_kombi_dflash_input(data: bytes) -> bytes:
    """Convert a 32 KiB physical DataFlash dump, 9,533 B / 8,334 B logical EEL dump, or 64 KiB EEL T01 `Dflash.bin` into a 64 KiB EEL T01 image."""
    if len(data) in KOMBI_EEL_LOGICAL_SIZES:
        return build_kombi_eel_dflash(unpack_kombi_logical_eel(data))
    if len(data) == KOMBI_DFLASH_POOL_SIZE and is_kombi_dflash(data):
        return build_kombi_eel_dflash(unpack_kombi_physical_dflash(data))
    if len(data) == KOMBI_DFLASH_SYNTH_SIZE and is_kombi_dflash(data):
        return bytes(data)
    raise ValueError(
        tr(
            f"Некорректный дамп DataFlash Kombi ({len(data)} Б): ожидается 32 768 Б (физический DataFlash), 65 536 Б (Dflash.bin) или 9 533 / 8 334 Б (EelLogical.bin).",
            f"Invalid Kombi DataFlash dump ({len(data)} B): expected 32,768 B (physical DataFlash), 65,536 B (Dflash.bin), or 9,533 / 8,334 B (EelLogical.bin).",
        )
    )


def is_kombi_dflash(data: bytes) -> bool:
    """True when `data` is a valid Kombi V850E2 DataFlash dump (`32 KiB` physical, `9,533 B` / `8,334 B` logical EEL, or `64 KiB` EEL T01)."""
    if len(data) in KOMBI_EEL_LOGICAL_SIZES:
        target_ids = EEL_KOMBI_2220_IDS if len(data) == KOMBI_EEL_2220_LOGICAL_SIZE else EEL_KOMBI_0310_IDS
        off = 0
        valid_headers = 0
        for _ident, sz in sorted(target_ids.items()):
            hdr = int.from_bytes(data[off : off + 2], "little")
            if hdr == sz:
                valid_headers += 1
            off += sz
        return valid_headers >= 115
    if len(data) == KOMBI_DFLASH_POOL_SIZE:
        try:
            recs = unpack_kombi_physical_dflash(data)
            return len(recs) >= 60
        except Exception:
            return False
    if len(data) == KOMBI_DFLASH_SYNTH_SIZE and is_fpke_dflash(data):
        lay = kombi_eel_layout(data)
        _blocks, latest = eel_parse_pool(lay, data)
        if not latest or any(ident > 132 for ident in latest):
            return False
        ok_cnt = sum(
            1
            for ident, (_vb, top, _ref) in latest.items()
            if int.from_bytes(data[top : top + 2], "little") == lay["ids"].get(ident, -1)
        )
        return ok_cnt >= 100
    return False


def detect_kombi_files(paths: list[Path]) -> dict[str, Path]:
    """Classify loose files or a directory's contents into `{'dflash', 'eel_logical', 'cflash', 'report'}` for Kombi."""
    found: dict[str, Path] = {}
    candidates: list[Path] = []
    for p in paths:
        if p.is_dir():
            candidates.extend(sorted(c for c in p.iterdir() if c.is_file()))
        elif p.is_file():
            candidates.append(p)
    for p in candidates:
        low = p.name.lower()
        if low.endswith(".json") and ("kombi" in low or "dflash" in low):
            found.setdefault("report", p)
            continue
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if sz == KOMBI_DFLASH_SYNTH_SIZE:
            raw = p.read_bytes()
            if is_kombi_dflash(raw):
                found["dflash"] = p
        elif sz == KOMBI_DFLASH_POOL_SIZE:
            raw = p.read_bytes()
            if is_kombi_dflash(raw):
                found.setdefault("physical_dflash", p)
                found.setdefault("dflash", p)
        elif sz in KOMBI_EEL_LOGICAL_SIZES:
            raw = p.read_bytes()
            if is_kombi_dflash(raw):
                found.setdefault("eel_logical", p)
                found.setdefault("dflash", p)
        elif sz == KOMBI_CFLASH_SIZE:
            found.setdefault("cflash", p)
    return found


# ────────────────────────────── Kombi V850E2 DataFlash Analysis ──────────────────────────────


def analyze_kombi_dflash(dflash: bytes, cflash: bytes | None = None) -> dict[str, Any]:  # noqa: ARG001
    """Parse a Kombi V850E2 DataFlash image (`64 KiB` EEL T01 or `9,533 B` / `8,334 B` logical EEL) natively without RH850 assumptions."""
    norm_df = normalize_kombi_dflash_input(dflash)
    lay = kombi_eel_layout(norm_df)
    blocks, latest = eel_parse_pool(lay, norm_df)
    state_counts: dict[str, int] = {"active": 0, "prepared": 0, "invalid": 0, "inconsistent": 0}
    for b in blocks:
        state_counts[b["state"]] = state_counts.get(b["state"], 0) + 1

    records: dict[int, bytes] = {}
    sources: dict[str, dict[str, Any]] = {}
    missing_ids: list[str] = []
    for ident in (
        0x30, 0x35, 0x38, 0x3E, 0x43, 0x45, 0x46,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
    ):
        if ident not in lay["ids"]:
            continue
        try:
            rec, src = eel_read_record_any(lay, norm_df, ident)
            records[ident] = rec
            sources[f"0x{ident:02X}"] = src
        except KeyError:
            if ident in (0x63, 0x64, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D):
                missing_ids.append(f"0x{ident:02X}")

    items: list[dict[str, Any]] = []
    fd11_id = ""
    if 0x63 in records and len(records[0x63]) >= 0x76:
        r63 = records[0x63]
        fd11_id = r63[0x02:0x11].hex()
        items.append(
            {
                "key_id": "fd11_l0_6",
                "name": "FD11 vendor levels 0..6",
                "hex": r63[0x16:0x26].hex(),
                "role": "FD11 AES-128 key (levels 0..6, EEL 0x63+0x16)",
                "crc_valid": _crc32_le_ok(r63[0x16:0x26], r63[0x26:0x2A]),
            }
        )
        items.append(
            {
                "key_id": "fd11_l7",
                "name": "FD11 vendor level 7",
                "hex": r63[0x2A:0x3A].hex(),
                "role": "FD11 AES-128 key (level 7, EEL 0x63+0x2A)",
                "crc_valid": _crc32_le_ok(r63[0x2A:0x3A], r63[0x3A:0x3E]),
            }
        )
        items.append(
            {
                "key_id": "aux_63_3e",
                "name": "FD11 slot 3 key (0x63+0x3E)",
                "hex": r63[0x3E:0x4E].hex(),
                "role": "FD11 slot 3 auxiliary key (EEL 0x63+0x3E)",
                "crc_valid": _crc32_le_ok(r63[0x3E:0x4E], r63[0x4E:0x52]),
            }
        )
        if r63[0x52:0x72] != b"\xff" * 32:
            items.append(
                {
                    "key_id": "fd11_32b_key",
                    "name": "FD11 32-byte key (0x63+0x52)",
                    "hex": r63[0x52:0x72].hex(),
                    "role": "FD11 32-byte key (EEL 0x63+0x52, 2E FD 11 06)",
                    "crc_valid": _kombi_crc32_ok(r63[0x52:0x72], r63[0x72:0x76]),
                }
            )
    if 0x64 in records and len(records[0x64]) >= 0x2A:
        r64 = records[0x64]
        items.append(
            {
                "key_id": "aux_64_02",
                "name": "FD11 slot 5 key (0x64+0x02)",
                "hex": r64[0x02:0x12].hex(),
                "role": "FD11 slot 5 auxiliary key (EEL 0x64+0x02)",
                "crc_valid": _crc32_le_ok(r64[0x02:0x12], r64[0x12:0x16]),
            }
        )
        if r64[0x16:0x26] != b"\xff" * 16:
            items.append(
                {
                    "key_id": "aux_64_16",
                    "name": "FD11 slot 6 key (0x64+0x16)",
                    "hex": r64[0x16:0x26].hex(),
                    "role": "FD11 slot 6 auxiliary key (EEL 0x64+0x16)",
                    "crc_valid": _crc32_le_ok(r64[0x16:0x26], r64[0x26:0x2A]),
                }
            )
    if 0x68 in records and len(records[0x68]) >= 0x40:
        r68 = records[0x68]
        items.append(
            {
                "key_id": "kc",
                "name": "K_c",
                "hex": r68[0x28:0x38].hex(),
                "role": "Immobilizer master key (EEL 0x68+0x28)",
                "crc_valid": None,
            }
        )
    if 0x6B in records and len(records[0x6B]) == 0x32:
        # V850E2 Kombi (50 B record, 48 B payload):
        #   +0x02..+0x11: CP /4 master VIN[3..16] (14 B + 2 B pad)
        #   +0x12..+0x21: CP /1 GFA (DID 0x00BD, 16 B)
        #   +0x22..+0x31: CP /3 IKA (DID 0x00BE, 16 B)
        r6b = records[0x6B]
        items.append(
            {
                "key_id": "ika_cp3",
                "name": "IKA / CP working key /3",
                "hex": r6b[0x22:0x32].hex(),
                "role": "Component protection individual working key (EEL 0x6B+0x22, UDS 00BE)",
                "crc_valid": None,
            }
        )
        items.append(
            {
                "key_id": "cp1_bank_0",
                "name": "CP /1 bank 0 (GFA)",
                "hex": r6b[0x12:0x22].hex(),
                "role": "Component protection slot 1 / GFA key (EEL 0x6B+0x12, UDS 00BD)",
                "crc_valid": None,
            }
        )
        items.append(
            {
                "key_id": "cp4_vin_tail",
                "name": "CP /4 master VIN[3..16]",
                "hex": r6b[0x02:0x12].hex(),
                "role": "Component protection slot 4 master VIN tail (EEL 0x6B+0x02)",
                "crc_valid": None,
            }
        )

    known_hex = {it["hex"] for it in items}
    crc_fields: list[dict[str, Any]] = []
    for ident in sorted(latest):
        try:
            vb, top, _ref = latest[ident]
            size = lay["ids"][ident]
            if top - ((size + 3) & ~3) + 4 < lay["base"] + vb * lay["vb"] + 0x18:
                continue
            rec = _eel_record_bytes(lay, norm_df, ident, top)
        except Exception:
            continue
        for off in range(2, len(rec) - 19):
            raw = rec[off : off + 16]
            if raw != b"\xff" * 16 and _crc32_le_ok(raw, rec[off + 16 : off + 20]) and raw.hex() not in known_hex:
                known_hex.add(raw.hex())
                crc_fields.append(
                    {
                        "name": f"EEL 0x{ident:02X}+0x{off:02X}",
                        "hex": raw.hex(),
                        "role": "CRC-valid 16-byte field",
                        "crc_valid": True,
                    }
                )

    r68_opt = records.get(0x68, b"")
    r69_opt = records.get(0x69, b"")
    r6c_opt = records.get(0x6C, b"")
    r6d_opt = records.get(0x6D, b"")
    slot_secrets = {
        "S0": r69_opt[0x02:0x12].hex() if len(r69_opt) >= 0x12 else "",
        "S1": r69_opt[0x12:0x22].hex() if len(r69_opt) >= 0x22 else "",
        "A_crc32_le": r68_opt[0x38:0x3C].hex() if len(r68_opt) >= 0x3C else "",
        "B_crc32_le": r68_opt[0x3C:0x40].hex() if len(r68_opt) >= 0x40 else "",
    }
    cp_err_cnt = int.from_bytes(r6d_opt[0x02:0x04], "little") if len(r6d_opt) >= 0x04 else None
    cp_adapted = (r6d_opt[0x0B] == 1) if len(r6d_opt) >= 0x0C else None
    cp_vin_prefix = _clean_ascii(r6d_opt[0x08:0x0B]) if len(r6d_opt) >= 0x0B else ""
    cp_state = {
        "prng_0": r6c_opt[0x02:0x12].hex() if len(r6c_opt) >= 0x12 else "",
        "record_2_first_10": r6d_opt[0x02:0x0C].hex() if len(r6d_opt) >= 0x0C else "",
        "error_counter": cp_err_cnt if cp_err_cnt != 0xFFFF else None,
        "active": bool(cp_err_cnt is not None and cp_err_cnt != 0xFFFF and cp_err_cnt >= 0x1F),
        "adapted": cp_adapted,
        "vin_prefix": cp_vin_prefix,
        "j533_ref_hex": r6d_opt[0x04:0x08].hex().upper() if len(r6d_opt) >= 0x08 else "",
    }

    r66_raw = records.get(0x66)
    r66_for_immo = r66_raw.ljust(0x16, b"\xff") if (r66_raw is not None and 0x11 <= len(r66_raw) < 0x16) else r66_raw
    immo_cfg = parse_fpke_immo_config(r66_for_immo, records.get(0x68), records.get(0x6E))
    odo_info = vote_fpke_odometer(records.get(0x60), records.get(0x35))

    meta: dict[str, Any] = {}
    if 0x68 in records and len(records[0x68]) >= 0x28:
        vin_raw = records[0x68][0x17:0x28]
        if vin_raw not in (b"\x00" * 17, b"\xff" * 17, b"-" * 17):
            vin_str = _clean_ascii(vin_raw)
            if len(vin_str) >= 11 and vin_str.strip("-") != "":
                meta["vin"] = vin_str
    if immo_cfg["immo_mode"] is not None:
        meta["immo_mode"] = immo_cfg["immo_mode"]
    if immo_cfg["power_class"] is not None:
        meta["power_class"] = immo_cfg["power_class_hex"]
        meta["power_class_int"] = immo_cfg["power_class"]
    if immo_cfg["EEL_0x68_present"]:
        meta["partners_mask"] = immo_cfg["partners_mask_hex"]
        meta["adapted_partners"] = immo_cfg["adapted_partner_codes"]
    if 0x45 in records and len(records[0x45]) >= 76:
        r45 = records[0x45]
        sw_tag = _clean_ascii(r45[2:6])
        if sw_tag.isdigit():
            meta["sw_version_eel"] = sw_tag
        odx_str = _clean_ascii(r45[12:37])
        if odx_str:
            meta["asam_odx"] = odx_str
        pn = _clean_ascii(r45[37:49])
        if pn:
            meta["part_number"] = pn
        hw_pn = _clean_ascii(r45[64:76])
        if hw_pn:
            meta["hw_part_number"] = hw_pn
    if 0x46 in records and len(records[0x46]) >= 23:
        ds_pn = _clean_ascii(records[0x46][11:22])
        if ds_pn:
            meta["dataset_pn"] = ds_pn
    is_2220 = len(lay["ids"]) == len(EEL_KOMBI_2220_IDS) or meta.get("sw_version_eel") == "2220"
    if 0x30 in records and len(records[0x30]) == 43:
        r30 = records[0x30]
        meta["coding_hex"] = r30[11:31].hex().upper()
        crc_stored = int.from_bytes(r30[-2:], "big")
        crc_calc = kombi_crc16_ccitt(r30[2:-2])
        if not (is_2220 and crc_stored == 0x0000):
            meta["coding_crc16_hex"] = f"{crc_stored:04X}"
            meta["coding_crc16_valid"] = crc_stored == crc_calc
    if odo_info["odometer_km"] is not None:
        meta["odometer_km"] = odo_info["odometer_km"]
        meta["odometer_unanimous"] = odo_info["unanimous"]
        meta["odometer_repair_count"] = odo_info["repair_count"]

    crc16_ids = frozenset({0x003E}) if is_2220 else KOMBI_CRC16_EEL_IDS
    crc16_checks: dict[str, dict[str, Any]] = {}
    for cid in sorted(crc16_ids):
        rec = records.get(cid)
        if rec is not None and len(rec) >= 6:
            c_stored = int.from_bytes(rec[-2:], "big")
            c_calc = kombi_crc16_ccitt(rec[2:-2])
            crc16_checks[f"0x{cid:02X}"] = {
                "stored": f"{c_stored:04X}",
                "calculated": f"{c_calc:04X}",
                "valid": c_stored == c_calc,
            }

    secret_sources = {k: v for k, v in sources.items() if int(k, 16) >= 0x63}
    return {
        "platform": "V850E2-KOMBI-2220" if is_2220 else "V850E2-KOMBI-0310",
        "mcu": "Renesas/NEC V850E2/Dx4 (uPD70F3526)",
        "access_method": (
            "uds_0x23_fd11_sl7_staging_0xfedd2480"
            if is_2220
            else "uds_0x23_fd11_sl7_staging_0xfedd5530"
        ),
        "sha256": hashlib.sha256(norm_df).hexdigest(),
        "pool": {
            "virtual_blocks": lay["n_vb"],
            "vb_size": lay["vb"],
            "states": state_counts,
            "active_ids": len(latest),
            "total_ids": len(lay["ids"]),
        },
        "metadata": meta,
        "crc16_checks": crc16_checks,
        "immo_config": immo_cfg,
        "odometer": odo_info,
        "fd11_identifier": fd11_id,
        "record_sources": secret_sources,
        "missing_secret_records": missing_ids,
        "items": items,
        "crc_fields": crc_fields,
        "slot_secrets": slot_secrets,
        "component_protection_state": cp_state,
        "transponder_records": parse_fpke_transponders(records.get(0x67), records.get(0x6A)),
    }


def extract_kombi_immo_passport(dflash: bytes, cflash: bytes | None = None) -> dict[str, Any]:
    """Build the read-only ContiTool Immo / WFS5 JSON passport for a Continental V850E2 Kombi (`5NA 920 740 B` / `8V0 920 860 E`)."""
    norm_df = normalize_kombi_dflash_input(dflash)
    info = analyze_kombi_dflash(norm_df, cflash)
    lay = kombi_eel_layout(norm_df)

    raw_recs: dict[int, bytes] = {}
    rec_sources: dict[str, dict[str, Any]] = {}
    for ident in (0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E):
        if ident not in lay["ids"]:
            continue
        with contextlib.suppress(KeyError):
            rec, src = eel_read_record_any(lay, norm_df, ident)
            raw_recs[ident] = rec
            rec_sources[f"0x{ident:02X}"] = src

    r68 = raw_recs.get(0x68)
    r69 = raw_recs.get(0x69)
    r6a = raw_recs.get(0x6A)

    vin_val: str | None = None
    vin_state = "missing"
    if r68 is not None and len(r68) >= 0x28:
        vin_bytes = r68[0x17:0x28]
        if vin_bytes in (b"\xff" * 17, b"\x00" * 17, b"-" * 17):
            vin_state = "empty"
        elif all((48 <= b <= 57) or (65 <= b <= 90) for b in vin_bytes):
            vin_val = vin_bytes.decode("ascii")
            vin_state = "present"
        else:
            vin_state = "corrupted"

    cs_val: str | None = None
    cs_state = "missing"
    if r68 is not None and len(r68) >= 0x38:
        cs_bytes = r68[0x28:0x38]
        if cs_bytes == b"\xff" * 16:
            cs_state = "empty"
        else:
            cs_val = cs_bytes.hex().upper()
            cs_state = "present"

    vdo_cs_plus: str | None = None
    crc_a_le: str | None = None
    crc_b_le: str | None = None
    vdo_state = "missing"
    if r68 is not None and len(r68) >= 0x40:
        vdo_bytes = r68[0x38:0x40]
        if vdo_bytes == b"\xff" * 8:
            vdo_state = "empty"
        else:
            vdo_cs_plus = vdo_bytes.hex().upper()
            crc_a_le = vdo_bytes[:4].hex().upper()
            crc_b_le = vdo_bytes[4:8].hex().upper()
            vdo_state = "present"

    immo_cfg = info["immo_config"]
    tp = info["transponder_records"]

    s0_hex = r69[0x02:0x12].hex().upper() if (r69 is not None and len(r69) >= 0x12) else None
    s1_hex = r69[0x12:0x22].hex().upper() if (r69 is not None and len(r69) >= 0x22) else None
    if r69 is None:
        s0_s1_state = "missing"
    elif s0_hex == "FF" * 16 and s1_hex == "FF" * 16:
        s0_s1_state = "empty_expected_in_mode_1" if immo_cfg.get("immo_mode") == 1 else "empty"
    else:
        s0_s1_state = "present"

    return {
        "schema": "contitool.kombi.immo_passport.v1",
        "read_only": True,
        "platform": info.get("platform", "V850E2-KOMBI-0310"),
        "eel_total_ids": len(lay["ids"]),
        "dflash_sha256": info["sha256"],
        "cflash_sha256": hashlib.sha256(cflash).hexdigest() if cflash is not None else None,
        "record_sources": rec_sources,
        "immo": {
            "personalized": cs_state == "present",
            "vin": vin_val,
            "vin_state": vin_state,
            "cs": cs_val,
            "kc": cs_val,
            "k_ffb": immo_cfg.get("k_ffb_hex") or None,
            "cs_state": cs_state,
            "vdo_cs_plus": vdo_cs_plus,
            "crc32_a_le": crc_a_le,
            "crc32_b_le": crc_b_le,
            "vdo_cs_plus_state": vdo_state,
            "power_class": immo_cfg.get("power_class_byte"),
            "power_class_hex": immo_cfg.get("power_class_hex"),
            "power_class_int": immo_cfg.get("power_class"),
            "status": immo_cfg.get("status_5b") or None,
            "mac_fields": dict(immo_cfg.get("mac_fields") or {}),
            "mac4": immo_cfg.get("mac4") or None,
            "keys": list(tp.get("display_ids") or []),
            "key_slots": list(tp.get("key_ids") or []),
            "counts": {
                "allowed_keys": tp.get("allowed_keys", 0),
                "learned_keys": tp.get("learned_keys", 0),
                "session_xor_flags": tp.get("session_xor_flags", 0),
                "queue_count": tp.get("queue_count", 0),
                "queue_pending_mask": tp.get("queue_pending_mask", 0),
                "queue_flags": tp.get("queue_flags", 0),
            },
            "mode_and_flags": {
                "immo_mode": immo_cfg.get("immo_mode"),
                "identity_counter": immo_cfg.get("identity_counter"),
                "partners_mask": immo_cfg.get("partners_mask"),
                "partners_mask_hex": immo_cfg.get("partners_mask_hex"),
                "adapted_partner_codes": list(immo_cfg.get("adapted_partner_codes") or []),
                "learning_partners_mask": immo_cfg.get("learning_partners_mask", 0),
                "lf_reader_config": immo_cfg.get("lf_reader_config"),
                "immo_flags": immo_cfg.get("immo_flags"),
                "s0_s1_stored_in_0x69": immo_cfg.get("s0_s1_stored_in_0x69", False),
                "cp_deferred": immo_cfg.get("cp_deferred", False),
                "key_transport_raw": immo_cfg.get("key_transport_raw"),
                "key_over_can": immo_cfg.get("key_over_can", False),
                "restart_window_disabled": immo_cfg.get("restart_window_disabled", False),
                "lockout_counters": list(immo_cfg.get("lockout_counters") or []),
                "lock_mode_0x6e": immo_cfg.get("lock_mode_0x6e") or None,
            },
            "partners": list(immo_cfg.get("partners") or []),
            "s0_s1": {
                "state": s0_s1_state,
                "S0": None if s0_hex == "FF" * 16 else s0_hex,
                "S1": None if s1_hex == "FF" * 16 else s1_hex,
            },
            "key_queue_0x6a": {
                "present": r6a is not None,
                "usable_key_data": tp.get("usable_key_data", False),
                "entries": list(tp.get("entries") or []),
            },
        },
        "component_protection_separate": {
            "ika_cp3": next((it["hex"].upper() for it in info["items"] if it["key_id"] == "ika_cp3"), None),
            "cp1_gfa": next((it["hex"].upper() for it in info["items"] if it["key_id"] == "cp1_bank_0"), None),
            "cp4_vin_tail": next((it["hex"].upper() for it in info["items"] if it["key_id"] == "cp4_vin_tail"), None),
            **info["component_protection_state"],
        },
        "cluster_metadata": dict(info["metadata"]),
    }


# ────────────────────────────── Kombi V850E2 Semantic Editor ──────────────────────────────


def apply_kombi_dflash_edits(
    dflash: bytes,
    *,
    vin: str | None = None,
    cs_hex: str | None = None,
    crc_a_hex: str | None = None,
    crc_b_hex: str | None = None,
    slot_s0_hex: str | None = None,
    slot_s1_hex: str | None = None,
    power_class: int | str | None = None,
    immo_mode: int | None = None,
    key_over_can: bool | None = None,
    partners_mask: int | None = None,
    clear_lockouts: bool = False,
    mac_dash_hex: str | None = None,
    partner_macs: dict[str, str] | None = None,
    key_display_ids: list[str | None] | None = None,
    allowed_keys: int | None = None,
    learned_keys: int | None = None,
    session_xor_flags: int | None = None,
    ika_key_hex: str | None = None,
    gfa_key_hex: str | None = None,
    reset_cp_counter: bool = False,
    odometer_km: int | None = None,
    coding_hex: str | None = None,
    cflash: bytes | None = None,  # noqa: ARG001 - kept for signature compatibility
) -> bytes:
    """Selectively update semantic fields in a Kombi V850E2 DataFlash image via EEL T01 append.

    Honors every verified V850E2 `SW 0310` / `SW 2220` firmware invariant:
      - `EEL 0x006B` (`50 B`): `IKA (/3)` at `+0x22..+0x31`, `GFA (/1)` at `+0x12..+0x21`, preserves `CP /4` VIN tail at `+0x02..+0x11`.
      - `EEL 0x0060` (`16 B`): preserves `0xFF 0xFF` alignment pad at `+2..+3` (`eel_off = 4`) and packs `3 x uint32 LE (km // 2)` at `+4..+15`.
      - `EEL 0x0030` (`43 B`): updates 20-byte Long Coding at `+11..+31` and recalculates big-endian CRC-16/CCITT-FALSE at `+41..+42`.
    """
    norm_df = normalize_kombi_dflash_input(dflash)
    lay = kombi_eel_layout(norm_df)

    def _base_record(ident: int) -> bytearray:
        size = lay["ids"][ident]
        with contextlib.suppress(KeyError):
            rec, _src = eel_read_record_any(lay, norm_df, ident)
            return bytearray(rec)
        buf = bytearray(b"\xff" * size)
        buf[:2] = struct.pack("<H", size)
        return buf

    updates: dict[int, bytes] = {}

    # 1. EEL 0x68 (128 B): VIN, CS/Kc, VDO CS+ A/B, PowerClass, partners_mask, immo_mode, key_over_can
    if any(
        x is not None
        for x in (vin, cs_hex, crc_a_hex, crc_b_hex, power_class, immo_mode, key_over_can, partners_mask)
    ) or clear_lockouts:
        r68 = _base_record(0x68)
        if vin is not None:
            v_clean = vin.strip().upper()
            if not v_clean or v_clean in ("—", "-" * 17, "FF" * 17):
                r68[0x17:0x28] = b"\xff" * 17
            else:
                if len(v_clean) != 17 or not all(("0" <= c <= "9") or ("A" <= c <= "Z") for c in v_clean):
                    raise ValueError(
                        tr(
                            "VIN должен содержать ровно 17 латинских букв и цифр (A–Z, 0–9).",
                            "VIN must be exactly 17 ASCII alphanumeric characters (A–Z, 0–9).",
                        )
                    )
                r68[0x17:0x28] = v_clean.encode("ascii")
        if cs_hex is not None:
            r68[0x28:0x38] = _parse_exact_hex(cs_hex, 16, "CS / Kc")
        if crc_a_hex is not None:
            r68[0x38:0x3C] = _parse_exact_hex(crc_a_hex, 4, "VDO CS+ (Slot A)")
        if crc_b_hex is not None:
            r68[0x3C:0x40] = _parse_exact_hex(crc_b_hex, 4, "VDO CS+ (Slot B)")
        if power_class is not None:
            if isinstance(power_class, str):
                pc_s = power_class.strip().replace("0x", "").replace("0X", "")
                if not pc_s or pc_s in ("—", "-"):
                    pc_val = 0xFF
                else:
                    try:
                        pc_val = int(pc_s, 16)
                    except ValueError as exc:
                        raise ValueError(
                            tr(
                                f"PowerClass: некорректное HEX-значение «{power_class}».",
                                f"PowerClass: invalid hex value '{power_class}'.",
                            )
                        ) from exc
            else:
                pc_val = int(power_class)
            if not (0 <= pc_val <= 0xFF):
                raise ValueError(
                    tr(
                        "PowerClass должен быть в диапазоне 0x00..0xFF.",
                        "PowerClass must be in range 0x00..0xFF.",
                    )
                )
            r68[0x40] = pc_val
        if partners_mask is not None:
            r68[0x41] = int(partners_mask) & 0xFF
        if clear_lockouts:
            r68[0x45:0x4B] = b"\x00" * 6
        if immo_mode is not None:
            r68[0x4B] = int(immo_mode) & 0xFF
            if r68[0x4C] == 0xFF:
                r68[0x4C] = 1
        if key_over_can is not None:
            cur_kt = 0x00 if r68[0x4D] == 0xFF else r68[0x4D]
            r68[0x4D] = (cur_kt | 0x80) if key_over_can else (cur_kt & ~0x80)
        updates[0x68] = bytes(r68)

    # 2. EEL 0x66 (22 B on 0310 / 17 B on 2220): Cluster WFS MAC + Partner MAC IDs
    if mac_dash_hex is not None or partner_macs is not None:
        r66 = _base_record(0x66)
        if mac_dash_hex is not None:
            r66[0x02:0x04] = _parse_exact_hex(mac_dash_hex, 2, "MAC DASH")
        if partner_macs is not None:
            alias_map = {"ECU": "MSG_1", "TCU": "GSG", "ELV": "ELV"}
            off_by_code = {code: r66_off for _idx, code, r66_off, *_rest in FPKE_IMMO_PARTNERS}
            for k_code, hex_val in partner_macs.items():
                norm_code = alias_map.get(k_code.upper(), k_code.upper())
                if norm_code not in off_by_code:
                    continue
                off = off_by_code[norm_code]
                if off + 2 <= len(r66) and not (len(r66) == 17 and off >= 0x10):
                    r66[off : off + 2] = _parse_exact_hex(hex_val, 2, f"MAC {norm_code}")
        updates[0x66] = bytes(r66)

    # 3. EEL 0x67 (39 B): Transponder key table & counters
    if any(x is not None for x in (key_display_ids, allowed_keys, learned_keys, session_xor_flags)):
        r67 = _base_record(0x67)
        if key_display_ids is not None:
            if len(key_display_ids) > 8:
                raise ValueError(
                    tr(
                        "Поддерживается не более 8 слотов транспондеров (ключей).",
                        "Up to 8 transponder key slots are supported.",
                    )
                )
            parsed_slots: list[bytes] = []
            for slot in range(8):
                disp = key_display_ids[slot] if slot < len(key_display_ids) else None
                cleaned = (disp or "").strip().replace(" ", "").replace("0x", "").replace("0X", "").upper()
                if not cleaned or cleaned in ("—", "-", "FFFFFFFF"):
                    continue
                if len(cleaned) != 8:
                    raise ValueError(
                        tr(
                            f"Ключ {slot + 1}: требуется 8 HEX-символов (4 байта).",
                            f"Key {slot + 1}: expected 8 hex digits (4 bytes).",
                        )
                    )
                try:
                    val_u32 = int(cleaned, 16)
                except ValueError as exc:
                    raise ValueError(
                        tr(
                            f"Ключ {slot + 1}: некорректное HEX-значение «{disp}».",
                            f"Key {slot + 1}: invalid hex '{disp}'.",
                        )
                    ) from exc
                parsed_slots.append(val_u32.to_bytes(4, "little"))
            for slot in range(8):
                r67[2 + slot * 4 : 6 + slot * 4] = (
                    parsed_slots[slot] if slot < len(parsed_slots) else b"\xff\xff\xff\xff"
                )
            present_count = len(parsed_slots)
        else:
            present_count = 0
            for slot in range(8):
                if r67[2 + slot * 4 : 6 + slot * 4] != b"\xff\xff\xff\xff":
                    present_count += 1
                else:
                    break

        cur_lf = 0x20 if r67[0x23] == 0xFF else r67[0x23]
        cur_learned = present_count if key_display_ids is not None else (cur_lf & 0x0F)
        cur_xor = (cur_lf >> 4) & 0x0F
        if learned_keys is not None:
            cur_learned = max(0, min(8, int(learned_keys)))
        cur_learned = min(cur_learned, present_count)
        for slot in range(cur_learned, 8):
            r67[2 + slot * 4 : 6 + slot * 4] = b"\xff\xff\xff\xff"
        if allowed_keys is not None:
            r67[0x22] = max(0, min(8, int(allowed_keys)))
        elif r67[0x22] == 0xFF or r67[0x22] < cur_learned:
            r67[0x22] = cur_learned
        if session_xor_flags is not None:
            cur_xor = int(session_xor_flags) & 0x0F
        r67[0x23] = (cur_xor << 4) | cur_learned
        if r67[0x24] == 0xFF:
            r67[0x24] = 0
        if r67[0x25] == 0xFF:
            r67[0x25] = 0
        if r67[0x26] == 0xFF:
            r67[0x26] = 0
        updates[0x67] = bytes(r67)

    # 3b. EEL 0x69 (34 B): Temporary slot secret S0 / S1 and synchronized EEL 0x68[0x44] bit 0 flag
    if slot_s0_hex is not None or slot_s1_hex is not None:
        r69 = _base_record(0x69)
        if slot_s0_hex is not None:
            r69[0x02:0x12] = _parse_exact_hex(slot_s0_hex, 16, "Slot S0 (0x69)")
        if slot_s1_hex is not None:
            r69[0x12:0x22] = _parse_exact_hex(slot_s1_hex, 16, "Slot S1 (0x69)")
        updates[0x69] = bytes(r69)
        s0_s1_present = r69[0x02:0x12] != b"\xff" * 16 or r69[0x12:0x22] != b"\xff" * 16
        r68_sync = bytearray(updates[0x68]) if 0x68 in updates else _base_record(0x68)
        cur_flags = 0x00 if r68_sync[0x44] == 0xFF else r68_sync[0x44]
        new_flags = (cur_flags | 0x01) if s0_s1_present else (cur_flags & ~0x01)
        if r68_sync[0x44] != new_flags or 0x68 in updates:
            r68_sync[0x44] = new_flags
            updates[0x68] = bytes(r68_sync)

    # 4. EEL 0x6B (50 B) & 0x6D (18 B): V850E2 Component Protection keys & status
    #    EEL 0x6B: +0x02..+0x11 CP /4 VIN tail, +0x12..+0x21 CP /1 GFA (00BD), +0x22..+0x31 CP /3 IKA (00BE)
    if ika_key_hex is not None or gfa_key_hex is not None:
        r6b = _base_record(0x6B)
        if ika_key_hex is not None:
            r6b[0x22:0x32] = _parse_exact_hex(ika_key_hex, 16, "IKA (/3)")
        if gfa_key_hex is not None:
            r6b[0x12:0x22] = _parse_exact_hex(gfa_key_hex, 16, "GFA (/1)")
        updates[0x6B] = bytes(r6b)

    if reset_cp_counter:
        r6d = _base_record(0x6D)
        r6d[0x02:0x04] = b"\x00\x00"
        if len(r6d) >= 0x0C:
            r6d[0x0B] = 0x01
        updates[0x6D] = bytes(r6d)

    # 5. EEL 0x60 (16 B, eel_off = 4 -> preserve +2..+3 padding) & EEL 0x35 (4 B)
    if odometer_km is not None:
        km = int(odometer_km)
        if not (0 <= km <= 999_998):
            raise ValueError(
                tr(
                    "Пробег должен быть в диапазоне от 0 до 999 998 км.",
                    "Odometer must be between 0 and 999,998 km.",
                )
            )
        if km % 2 != 0:
            raise ValueError(
                tr(
                    f"Пробег в EEL 0x60 хранится с шагом 2 км — укажите чётное значение (получено {km} км).",
                    f"EEL 0x60 stores odometer in 2 km units — enter an even value (got {km} km).",
                )
            )
        half = km // 2
        r60 = _base_record(0x60)
        struct.pack_into("<3I", r60, 4, half, half, half)
        updates[0x60] = bytes(r60)
        r35 = _base_record(0x35)
        if r35[2:4] != b"\x00\x00":
            r35[2:4] = b"\x00\x00"
            updates[0x35] = bytes(r35)

    # 6. EEL 0x30 (43 B): Long Coding (+ big-endian CRC-16/CCITT-FALSE at r30[41:43] on SW 0310; 0x0000 pad on SW 2220)
    if coding_hex is not None:
        r30 = _base_record(0x30)
        new_cod_20 = _parse_exact_hex(coding_hex, 20, "Coding (0x30)", allow_empty=False)
        if bytes(r30[11:31]) != new_cod_20:
            is_2220_pool = len(lay["ids"]) == len(EEL_KOMBI_2220_IDS)
            has_crc16_30 = not (is_2220_pool and bytes(r30[-2:]) == b"\x00\x00")
            r30[11:31] = new_cod_20
            if has_crc16_30:
                crc16 = kombi_crc16_ccitt(bytes(r30[2:-2]))
                struct.pack_into(">H", r30, len(r30) - 2, crc16)
            updates[0x30] = bytes(r30)

    changed_updates = {
        ident: rec_bytes
        for ident, rec_bytes in updates.items()
        if rec_bytes != bytes(_base_record(ident))
    }
    if not changed_updates:
        return norm_df
    return eel_append_records(norm_df, changed_updates, layout=lay)


# ────────────────────────────── Kombi Diffs, Transfer Plan & Reports ──────────────────────────────


def extract_kombi_eel_updates(before_dflash: bytes, after_dflash: bytes) -> dict[int, bytes]:
    """Return `{ident: record_bytes}` for every active EEL ID modified between `before_dflash` and `after_dflash`."""
    norm_before = normalize_kombi_dflash_input(before_dflash)
    norm_after = normalize_kombi_dflash_input(after_dflash)
    lay_before = kombi_eel_layout(norm_before)
    lay_after = kombi_eel_layout(norm_after)
    updates: dict[int, bytes] = {}
    for ident in sorted(lay_after["ids"]):
        try:
            rec_after, src_after = eel_read_record_any(lay_after, norm_after, ident)
        except KeyError:
            continue
        if src_after.get("generation") != "current":
            continue
        rec_before: bytes | None = None
        if ident in lay_before["ids"]:
            with contextlib.suppress(KeyError):
                cand, src_before = eel_read_record_any(lay_before, norm_before, ident)
                if src_before.get("generation") == "current":
                    rec_before = cand
        if rec_before != rec_after:
            updates[ident] = rec_after
    return updates


def summarize_kombi_dflash_changes(before_dflash: bytes, after_dflash: bytes) -> dict[str, Any]:
    """Build a human-readable bilingual summary of semantic and EEL changes between two Kombi DataFlash images."""
    norm_before = normalize_kombi_dflash_input(before_dflash)
    norm_after = normalize_kombi_dflash_input(after_dflash)
    updates = extract_kombi_eel_updates(norm_before, norm_after)
    if not updates:
        return {
            "changed": False,
            "is_pure_eel_update": False,
            "eel_pool_append_only": False,
            "changed_eel_ids": [],
            "raw_diff_blocks": 0,
            "lines": [],
            "short_summary": tr("Изменений нет", "No changes"),
        }

    p1 = extract_kombi_immo_passport(norm_before)
    p2 = extract_kombi_immo_passport(norm_after)
    im1, im2 = p1["immo"], p2["immo"]
    m1, m2 = p1.get("cluster_metadata") or {}, p2.get("cluster_metadata") or {}
    cp1, cp2 = p1.get("component_protection_separate") or {}, p2.get("component_protection_separate") or {}

    lines: list[str] = []
    short_tags: list[str] = []

    if im1.get("vin") != im2.get("vin"):
        lines.append(f"VIN: {im1.get('vin') or '—'} → {im2.get('vin') or '—'}")
        short_tags.append(f"VIN → {im2.get('vin') or '—'}")

    if im1.get("cs") != im2.get("cs"):
        c_old = (im1.get("cs") or "—")[:8]
        c_new = (im2.get("cs") or "—")[:8]
        lines.append(f"CS / Kc: {c_old}… → {c_new}…")
        short_tags.append("CS/Kc")

    if (im1.get("crc32_a_le"), im1.get("crc32_b_le")) != (im2.get("crc32_a_le"), im2.get("crc32_b_le")):
        lines.append(
            f"VDO CS+: {im1.get('crc32_a_le') or '—'}/{im1.get('crc32_b_le') or '—'} → "
            f"{im2.get('crc32_a_le') or '—'}/{im2.get('crc32_b_le') or '—'}"
        )
        short_tags.append("VDO CS+")

    if 0x69 in updates:
        lines.append(tr("Слоты S0 / S1 (EEL 0x69): обновлены", "Slots S0 / S1 (EEL 0x69): updated"))
        short_tags.append("S0/S1")

    if im1.get("power_class_hex") != im2.get("power_class_hex"):
        lines.append(f"PowerClass: {im1.get('power_class_hex') or '—'} → {im2.get('power_class_hex') or '—'}")
        short_tags.append(f"PC → {im2.get('power_class_hex') or '—'}")

    mf1, mf2 = im1.get("mode_and_flags") or {}, im2.get("mode_and_flags") or {}
    if (
        mf1.get("immo_mode") != mf2.get("immo_mode")
        or mf1.get("key_over_can") != mf2.get("key_over_can")
        or mf1.get("partners_mask") != mf2.get("partners_mask")
    ):
        lines.append(
            tr(
                f"Режим и флаги иммо: mode={mf2.get('immo_mode')}, партнёры={mf2.get('partners_mask_hex')}",
                f"Immo mode & flags: mode={mf2.get('immo_mode')}, partners={mf2.get('partners_mask_hex')}",
            )
        )
        short_tags.append(tr("режим иммо", "immo mode"))

    if im1.get("mac_fields") != im2.get("mac_fields") or _partner_mac_map(im1) != _partner_mac_map(im2):
        lines.append(f"MAC IDs (EEL 0x66): MAC4={im1.get('mac4') or '—'} → {im2.get('mac4') or '—'}")
        short_tags.append("MAC")

    cnt1, cnt2 = im1.get("counts") or {}, im2.get("counts") or {}
    if im1.get("keys") != im2.get("keys") or cnt1 != cnt2:
        k_sum = f"{cnt2.get('learned_keys', 0)}/{cnt2.get('allowed_keys', 0)}"
        lines.append(
            tr(
                f"Ключи и транспондеры (EEL 0x67): обучено {cnt1.get('learned_keys', 0)}/{cnt1.get('allowed_keys', 0)} → {k_sum}",
                f"Keys & transponders (EEL 0x67): learned {cnt1.get('learned_keys', 0)}/{cnt1.get('allowed_keys', 0)} → {k_sum}",
            )
        )
        short_tags.append(tr(f"ключи ({k_sum})", f"keys ({k_sum})"))

    odo1, odo2 = m1.get("odometer_km"), m2.get("odometer_km")
    if odo1 != odo2 or 0x60 in updates:
        o1_s = f"{odo1:,}".replace(",", " ") if odo1 is not None else "—"
        o2_s = f"{odo2:,}".replace(",", " ") if odo2 is not None else "—"
        lines.append(tr(f"Пробег (EEL 0x60): {o1_s} км → {o2_s} км", f"Odometer (EEL 0x60): {o1_s} km → {o2_s} km"))
        short_tags.append(tr(f"пробег → {o2_s} км", f"odo → {o2_s} km"))

    if cp1 != cp2 or 0x6B in updates or 0x6D in updates:
        lines.append(
            tr(
                "Защита компонентов (EEL 0x6B / 0x6D): ключи IKA/GFA или статус SAFE CP обновлены",
                "Component Protection (EEL 0x6B / 0x6D): IKA/GFA keys or SAFE CP status updated",
            )
        )
        short_tags.append("CP/IKA")

    if m1.get("coding_hex") != m2.get("coding_hex") or 0x30 in updates:
        lines.append(
            tr(
                f"Кодировка (EEL 0x30, CRC-16={m2.get('coding_crc16_hex', '—')}): {(m2.get('coding_hex') or '—')[:16]}…",
                f"Coding (EEL 0x30, CRC-16={m2.get('coding_crc16_hex', '—')}): {(m2.get('coding_hex') or '—')[:16]}…",
            )
        )
        short_tags.append(tr("кодировка", "coding"))

    covered_ids = {0x68, 0x69, 0x66, 0x67, 0x60, 0x35, 0x6B, 0x6D, 0x30}
    extra_ids = [f"0x{i:02X}" for i in sorted(updates) if i not in covered_ids]
    if extra_ids or not lines:
        if extra_ids:
            lines.append(
                tr(
                    f"Дополнительные записи EEL: {', '.join(extra_ids)}",
                    f"Additional EEL records: {', '.join(extra_ids)}",
                )
            )
            short_tags.append(f"EEL {', '.join(extra_ids[:3])}")

    short_summary = ", ".join(short_tags[:4])
    if len(short_tags) > 4:
        short_summary += f" (+{len(short_tags) - 4})"

    return {
        "changed": True,
        "is_pure_eel_update": True,
        "eel_pool_append_only": True,
        "changed_eel_ids": [f"0x{i:02X}" for i in sorted(updates)],
        "raw_diff_blocks": len(updates),
        "lines": lines,
        "short_summary": short_summary,
    }


def _extract_donor_passport_any(donor: bytes | dict[str, Any], donor_cflash: bytes | None = None) -> dict[str, Any]:
    """Accept a Kombi DataFlash (`64 KiB` or `9,533 B`), an FPK_E DataFlash (`64 KiB`), or an already-parsed Immo JSON passport."""
    if isinstance(donor, dict):
        return donor
    raw = bytes(donor)
    if is_kombi_dflash(raw):
        return extract_kombi_immo_passport(raw, donor_cflash)
    if is_fpke_dflash(raw):
        from contitool.core.fpke import extract_fpke_immo_passport

        return extract_fpke_immo_passport(raw, donor_cflash)
    raise ValueError(
        tr(
            f"Неподдерживаемый формат файла донора ({len(raw)} Б): ожидается дамп Kombi/FPK_E или immo_passport.json.",
            f"Unsupported donor file format ({len(raw)} B): expected a Kombi/FPK_E DataFlash dump or immo_passport.json.",
        )
    )


def plan_kombi_a_to_b_transfer(
    donor_passport: dict[str, Any],
    recipient_passport: dict[str, Any],
) -> dict[str, Any]:
    """Build a Kombi V850E2 A -> B Immo/CP/Odometer migration plan (supports Kombi or FPK_E donor into Kombi recipient)."""
    im_a = donor_passport.get("immo") or {}
    im_b = recipient_passport.get("immo") or {}
    meta_a = donor_passport.get("cluster_metadata") or {}
    meta_b = recipient_passport.get("cluster_metadata") or {}

    warnings: list[str] = []
    if not im_a.get("personalized"):
        warnings.append(
            tr(
                "Донор A не персонализирован (CS/K_c = FF…): перенос иммо не требуется или источник пуст.",
                "Donor A is not personalized (CS/K_c = FF…): immo source appears blank.",
            )
        )
    if donor_passport.get("platform") != recipient_passport.get("platform"):
        warnings.append(
            tr(
                f"Межплатформенный перенос ({donor_passport.get('platform')} → {recipient_passport.get('platform')}): "
                "переносятся только семантические поля WFS5/CP/пробега с пересчётом форматов V850E2 Kombi (EEL 0x6B 50 Б, 0x6D 18 Б).",
                f"Cross-platform transfer ({donor_passport.get('platform')} → {recipient_passport.get('platform')}): "
                "only semantic WFS5/CP/odometer fields are mapped into native V850E2 Kombi EEL formats (0x6B 50 B, 0x6D 18 B).",
            )
        )
    warnings.append(
        tr(
            "Записи оборудования (0x45), датасета (0x46), кодировки (0x30) и ключей FD11 (0x63/0x64) панели B сохраняются.",
            "Recipient B hardware metadata (0x45), dataset (0x46), coding (0x30), and FD11 keys (0x63/0x64) are preserved.",
        )
    )

    mf_a = im_a.get("mode_and_flags") or {}
    return {
        "schema": "contitool.kombi.transfer_plan.v1",
        "read_only": True,
        "donor_a": {
            "dflash_sha256": donor_passport.get("dflash_sha256"),
            "platform": donor_passport.get("platform"),
            "part_number": meta_a.get("part_number"),
            "personalized": bool(im_a.get("personalized")),
        },
        "recipient_b": {
            "dflash_sha256": recipient_passport.get("dflash_sha256"),
            "platform": recipient_passport.get("platform"),
            "part_number": meta_b.get("part_number"),
            "personalized": bool(im_b.get("personalized")),
            "current_kc_on_b": im_b.get("cs"),
        },
        "transfer_from_a": {
            "vin": im_a.get("vin"),
            "cs": im_a.get("cs"),
            "k_ffb": im_a.get("k_ffb"),
            "vdo_cs_plus": im_a.get("vdo_cs_plus"),
            "crc32_a_le": im_a.get("crc32_a_le"),
            "crc32_b_le": im_a.get("crc32_b_le"),
            "power_class": im_a.get("power_class"),
            "power_class_hex": im_a.get("power_class_hex"),
            "mac_fields": dict(im_a.get("mac_fields") or {}),
            "mac4": im_a.get("mac4"),
            "keys": list(im_a.get("keys") or []),
            "counts": dict(im_a.get("counts") or {}),
            "partners_mask_hex": mf_a.get("partners_mask_hex"),
            "adapted_partner_codes": list(mf_a.get("adapted_partner_codes") or []),
            "immo_mode": mf_a.get("immo_mode"),
            "key_over_can": mf_a.get("key_over_can"),
            "lf_reader_config": mf_a.get("lf_reader_config"),
        },
        "preserve_on_b": {
            "part_number": meta_b.get("part_number"),
            "sw_version_eel": meta_b.get("sw_version_eel"),
            "dataset_pn": meta_b.get("dataset_pn"),
            "coding_hex": meta_b.get("coding_hex"),
            "odometer_km_on_b": meta_b.get("odometer_km"),
            "current_kc_on_b": im_b.get("cs"),
        },
        "odometer_sync": {
            "donor_a_km": meta_a.get("odometer_km"),
            "recipient_b_km": meta_b.get("odometer_km"),
            "eel_id": "0x60",
        },
        "component_protection_separate": {
            "donor_a": donor_passport.get("component_protection_separate") or {},
            "recipient_b": recipient_passport.get("component_protection_separate") or {},
        },
        "s0_s1_and_0x6a_policy": {
            "donor_s0_s1_state": (im_a.get("s0_s1") or {}).get("state"),
            "donor_0x6a_usable": (im_a.get("key_queue_0x6a") or {}).get("usable_key_data", False),
            "allow_02f7_with_stub_s0_s1": False,
        },
        "warnings": warnings,
    }


def format_kombi_transfer_plan(plan: dict[str, Any]) -> str:
    """Format a human-readable RU/EN A -> B migration plan for Kombi VDD (V850E2/Dx4)."""
    da = plan.get("donor_a") or {}
    rb = plan.get("recipient_b") or {}
    tx = plan.get("transfer_from_a") or {}
    pr = plan.get("preserve_on_b") or {}
    od = plan.get("odometer_sync") or {}
    cp = plan.get("component_protection_separate") or {}
    pol = plan.get("s0_s1_and_0x6a_policy") or {}

    lines = [
        "═" * 72,
        tr(
            "ПЛАН ПЕРЕНОСА ДАННЫХ A → B ДЛЯ KOMBI VDD (V850E2/Dx4, SL 7)",
            "DATA MIGRATION PLAN A → B FOR KOMBI VDD (V850E2/Dx4, SL 7)",
        ),
        "═" * 72,
        f"  {tr('Донор A', 'Donor A'):<26}: {da.get('part_number') or '—'} ({da.get('platform') or '—'})",
        f"  {tr('Приёмник B (Kombi)', 'Recipient B (Kombi)'):<26}: {rb.get('part_number') or '—'} ({rb.get('platform') or '—'})",
        "",
        tr("── 1. Переносится из донора A в панель B ──", "── 1. Transferred from Donor A to Recipient B ──"),
        f"  VIN (EEL 0x68)            : {tx.get('vin') or '—'}",
        f"  CS / K_c (EEL 0x68)       : {tx.get('cs') or '—'}",
        f"  K_ffb (FFB)               : {tx.get('k_ffb') or '—'}",
        f"  VDO CS+ (A / B)           : {tx.get('crc32_a_le') or '—'} / {tx.get('crc32_b_le') or '—'}",
        f"  PowerClass                : {tx.get('power_class_hex') or '—'}",
        f"  MAC4 (DASH + ECU)         : {tx.get('mac4') or '—'}",
        f"  {tr('Партнёры WFS5', 'WFS5 Partners'):<26}: {tx.get('partners_mask_hex') or '—'} ({', '.join(tx.get('adapted_partner_codes') or []) or 'none'})",
        f"  {tr('Ключи (EEL 0x67)', 'Keys (EEL 0x67)'):<26}: {', '.join(str(k) for k in (tx.get('keys') or []) if k) or '—'}",
        "",
        tr("── 2. Сохраняется от панели B ──", "── 2. Preserved from Recipient B ──"),
        f"  Part Number / SW (0x45)   : {pr.get('part_number') or '—'} / {pr.get('sw_version_eel') or '—'}",
        f"  Dataset (0x46)            : {pr.get('dataset_pn') or '—'}",
        f"  Coding (0x30)             : {pr.get('coding_hex') or '—'}",
        "",
        tr("── 3. Пробег и Защита компонентов (отдельные области) ──", "── 3. Odometer & Component Protection (separate areas) ──"),
        (
            f"  {tr('Пробег A → B (EEL 0x60)', 'Odometer A → B (EEL 0x60)'):<26}: "
            f"{od.get('donor_a_km')} km  →  {tr('текущий на B', 'current on B')}: {od.get('recipient_b_km')} km"
        ),
        f"  Donor A IKA /3            : {(cp.get('donor_a') or {}).get('ika_cp3') or '—'}",
        f"  Recipient B IKA /3 (0x6B) : {(cp.get('recipient_b') or {}).get('ika_cp3') or '—'}",
        f"  S0/S1 (0x69)              : {pol.get('donor_s0_s1_state')}",
    ]
    if plan.get("warnings"):
        lines.append("")
        lines.append(tr("── Примечания и ограничения ──", "── Notes & Safeguards ──"))
        for w in plan["warnings"]:
            lines.append(f"  • {w}")
    return "\n".join(lines)


def transfer_kombi_donor_to_target(
    donor: bytes | dict[str, Any],
    target_dflash: bytes,
    *,
    copy_immo: bool = True,
    copy_keys: bool = True,
    copy_odometer: bool = True,
    copy_cp: bool = False,
    donor_cflash: bytes | None = None,
    target_cflash: bytes | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Transfer selected identity blocks from Donor A (Kombi dump, FPK_E dump, or Immo JSON) into Target B Kombi DataFlash."""
    donor_passport = _extract_donor_passport_any(donor, donor_cflash)
    norm_target = normalize_kombi_dflash_input(target_dflash)

    im_a = donor_passport.get("immo") or {}
    cnt_a = im_a.get("counts") or {}
    mf_a = im_a.get("mode_and_flags") or {}
    cp_a = donor_passport.get("component_protection_separate") or {}
    meta_a = donor_passport.get("cluster_metadata") or {}

    partner_macs: dict[str, str] = {}
    for p in im_a.get("partners") or []:
        if isinstance(p, dict) and p.get("code"):
            partner_macs[str(p["code"])] = str(p["mac_id_hex"]) if p.get("mac_id_hex") else "FFFF"
    if not partner_macs and isinstance(im_a.get("mac_fields"), dict):
        mf_dict = im_a["mac_fields"]
        if any(mf_dict.get(k) for k in ("ecu", "tcu", "elv")):
            for p_code, mf_key in (("MSG_1", "ecu"), ("GSG", "tcu"), ("ELV", "elv")):
                if mf_key in mf_dict:
                    val = mf_dict.get(mf_key)
                    partner_macs[p_code] = str(val) if val else "FFFF"

    raw_mac_dash = (im_a.get("mac_fields") or {}).get("dash")
    mac_dash = str(raw_mac_dash) if raw_mac_dash else None
    donor_pc = im_a.get("power_class_int")
    if donor_pc is None and im_a.get("power_class"):
        donor_pc = str(im_a["power_class"])

    donor_vin = im_a.get("vin") or None
    donor_cs = im_a.get("cs") or None
    donor_crc_a = im_a.get("crc32_a_le") or None
    donor_crc_b = im_a.get("crc32_b_le") or None
    donor_immo_mode = mf_a.get("immo_mode")
    donor_kessy = mf_a.get("key_over_can")
    donor_partners_mask = mf_a.get("partners_mask")
    has_donor_immo = any(
        v is not None
        for v in (donor_vin, donor_cs, donor_crc_a, donor_crc_b, donor_pc, donor_immo_mode, donor_kessy, donor_partners_mask, mac_dash)
    ) or bool(partner_macs)

    raw_keys = im_a.get("keys")
    donor_keys = list(raw_keys) if (isinstance(raw_keys, list) and any(k for k in raw_keys)) else None
    donor_allowed = cnt_a.get("allowed_keys") if donor_keys is not None else None
    donor_learned = cnt_a.get("learned_keys") if donor_keys is not None else None
    donor_xor_flags = cnt_a.get("session_xor_flags") if donor_keys is not None else None
    has_donor_keys = donor_keys is not None

    donor_ika = cp_a.get("ika_cp3") or None
    donor_gfa = cp_a.get("cp1_gfa") or None
    has_donor_cp = bool(donor_ika or donor_gfa)

    donor_odo = meta_a.get("odometer_km")
    if donor_odo is not None:
        donor_odo = int(donor_odo) & ~1  # EEL 0x60 stores 2-km steps

    updated_df = apply_kombi_dflash_edits(
        norm_target,
        vin=donor_vin if copy_immo else None,
        cs_hex=donor_cs if copy_immo else None,
        crc_a_hex=donor_crc_a if copy_immo else None,
        crc_b_hex=donor_crc_b if copy_immo else None,
        power_class=donor_pc if copy_immo else None,
        immo_mode=donor_immo_mode if copy_immo else None,
        key_over_can=(bool(donor_kessy) if donor_kessy is not None else None) if copy_immo else None,
        partners_mask=donor_partners_mask if copy_immo else None,
        clear_lockouts=bool(copy_immo and has_donor_immo),
        mac_dash_hex=mac_dash if copy_immo else None,
        partner_macs=(partner_macs or None) if copy_immo else None,
        key_display_ids=donor_keys if copy_keys else None,
        allowed_keys=donor_allowed if copy_keys else None,
        learned_keys=donor_learned if copy_keys else None,
        session_xor_flags=donor_xor_flags if copy_keys else None,
        odometer_km=donor_odo if (copy_odometer and donor_odo is not None) else None,
        ika_key_hex=donor_ika if copy_cp else None,
        gfa_key_hex=donor_gfa if copy_cp else None,
        reset_cp_counter=bool(copy_cp and has_donor_cp),
        cflash=target_cflash,
    )

    after_passport = extract_kombi_immo_passport(updated_df, target_cflash)
    summary = {
        "copied_sections": {
            "immo": bool(copy_immo and has_donor_immo),
            "keys": bool(copy_keys and has_donor_keys),
            "odometer": copy_odometer and (donor_odo is not None),
            "cp": bool(copy_cp and has_donor_cp),
        },
        "donor_part_number": meta_a.get("part_number"),
        "target_part_number": (after_passport.get("cluster_metadata") or {}).get("part_number"),
        "vin": after_passport["immo"]["vin"],
        "power_class_hex": after_passport["immo"]["power_class_hex"],
        "learned_keys": after_passport["immo"]["counts"]["learned_keys"],
        "odometer_km": (after_passport.get("cluster_metadata") or {}).get("odometer_km"),
    }
    return updated_df, summary


def format_kombi_report(
    *,
    dflash_info: dict[str, Any] | None = None,
    ident: list[dict[str, str]] | None = None,
) -> str:
    """Format a human-readable RU/EN report specifically for Continental VAG Kombi VDD (V850E2/Dx4, SL 7)."""
    lines: list[str] = []
    lines.append("═" * 72)
    lines.append(
        tr(
            "ОТЧЁТ ПО ПРИБОРНОЙ ПАНЕЛИ VAG KOMBI VDD (V850E2/Dx4, uPD70F3526)",
            "VAG KOMBI VDD INSTRUMENT CLUSTER REPORT (V850E2/Dx4, uPD70F3526)",
        )
    )
    lines.append("═" * 72)

    if ident:
        lines.append("")
        lines.append(tr("── Идентификация UDS (0x714 / 0x77E) ──", "── UDS Identification (0x714 / 0x77E) ──"))
        for item in ident:
            lbl = tr(item.get("label_ru", item["did"]), item.get("label_en", item["did"]))
            lines.append(f"  {item['did']}  {lbl:<24} : {item['value']}")

    if dflash_info:
        pool = dflash_info.get("pool") or {}
        meta = dflash_info.get("metadata") or {}
        tot_ids = int(pool.get("total_ids", 132) or 132)
        log_sz = KOMBI_EEL_2220_LOGICAL_SIZE if tot_ids == len(EEL_KOMBI_2220_IDS) else KOMBI_EEL_LOGICAL_SIZE
        lines.append("")
        lines.append(
            tr(
                f"── DataFlash Kombi V850E2 ({tot_ids} бл. EEL, Supplier Level 7) ──",
                f"── Kombi V850E2 DataFlash ({tot_ids} EEL blocks, Supplier Level 7) ──",
            )
        )
        lines.append(f"  SHA-256                  : {dflash_info.get('sha256', '—')}")
        lines.append(
            tr(
                f"  Записи EEL (0x0001..0x{tot_ids:02X}): {pool.get('active_ids', 0)} / {tot_ids} "
                f"(логический размер {log_sz} Б)",
                f"  EEL records (0x0001..0x{tot_ids:02X}): {pool.get('active_ids', 0)} / {tot_ids} "
                f"(logical size {log_sz} B)",
            )
        )
        if meta.get("vin"):
            lines.append(f"  VIN (EEL 0x68 / F190)    : {meta['vin']}")
        if meta.get("part_number"):
            sw_s = f" (SW {meta['sw_version_eel']})" if meta.get("sw_version_eel") else ""
            lines.append(f"  Part Number (EEL 0x45)   : {meta['part_number']}{sw_s}")
        if meta.get("asam_odx"):
            lines.append(f"  ASAM / ODX (EEL 0x45)    : {meta['asam_odx']}")
        if meta.get("dataset_pn"):
            lines.append(f"  Dataset (EEL 0x46)       : {meta['dataset_pn']}")
        if meta.get("coding_hex"):
            crc_ok = meta.get("coding_crc16_valid")
            crc_tag = (
                f"  [CRC-16={meta.get('coding_crc16_hex')}: {'OK' if crc_ok else 'FAIL'}]"
                if crc_ok is not None
                else ""
            )
            lines.append(f"  Coding (EEL 0x30)        : {meta['coding_hex']}{crc_tag}")
        if meta.get("power_class"):
            lines.append(f"  PowerClass (EEL 0x68+40) : {meta['power_class']}")
        if "odometer_km" in meta:
            lines.append(
                f"  Odometer (EEL 0x60)      : {meta['odometer_km']} km "
                f"(unanimous={meta.get('odometer_unanimous')}, repair_cnt={meta.get('odometer_repair_count', 0)})"
            )

        by_id = {it["key_id"]: it for it in dflash_info.get("items", [])}
        immo_cfg = dflash_info.get("immo_config") or {}
        slots = dflash_info.get("slot_secrets") or {}
        tp = dflash_info.get("transponder_records") or {}

        lines.append("")
        lines.append(
            tr(
                "── Паспорт иммобилайзера WFS5 (EEL 0x66 / 0x67 / 0x68 / 0x69) ──",
                "── Immobilizer WFS5 Passport (EEL 0x66 / 0x67 / 0x68 / 0x69) ──",
            )
        )
        if "kc" in by_id:
            lines.append(f"  {'CS / K_c (0x68+0x28)':<28} : {by_id['kc']['hex'].upper()}")
        if immo_cfg.get("k_ffb_hex"):
            lines.append(f"  {'K_ffb (AES_Kc(C16), FFB)':<28} : {immo_cfg['k_ffb_hex']}")
        if slots.get("A_crc32_le") or slots.get("B_crc32_le"):
            lines.append(
                f"  {'VDO CS+ (Slot A / B)':<28} : {slots.get('A_crc32_le', '').upper()} / {slots.get('B_crc32_le', '').upper()}"
            )
        if immo_cfg.get("power_class_hex"):
            lines.append(f"  {'PowerClass (P_class)':<28} : {immo_cfg['power_class_hex']}")
        if immo_cfg.get("immo_mode") is not None:
            lines.append(f"  {'Immo Mode (0x68+0x4B)':<28} : {immo_cfg['immo_mode']}")
        if immo_cfg.get("mac4"):
            lines.append(f"  {'MAC4 (DASH + ECU)':<28} : {immo_cfg['mac4']}")
        if immo_cfg.get("EEL_0x68_present") or immo_cfg.get("EEL_0x66_present"):
            if immo_cfg.get("cluster_mac_id"):
                lines.append(f"  {'Cluster MAC ID (DASH)':<28} : {immo_cfg['cluster_mac_id']}")
            lines.append(
                f"  {'Adapted Partners Mask':<28} : {immo_cfg.get('partners_mask_hex', '0x00')} "
                f"({', '.join(immo_cfg.get('adapted_partner_codes') or []) or 'none'})"
            )
            for p in immo_cfg.get("partners", []):
                if p.get("adapted") or p.get("mac_id_hex"):
                    st_lbl = tr("адаптирован", "adapted") if p.get("adapted") else tr("не активен", "inactive")
                    lines.append(
                        f"    Partner {p['index']} ({p['code']:<5})          : ID={p['mac_id_hex'] or '----'} ({st_lbl}, {tr(p['label_ru'], p['label_en'])})"
                    )
        if tp:
            keys_list = [str(k) for k in (tp.get("display_ids") or []) if k]
            lines.append(
                f"  {'Keys (EEL 0x67)':<28} : {tp.get('learned_keys', 0)}/{tp.get('allowed_keys', 0)}"
                + (f" ({', '.join(keys_list)})" if keys_list else "")
            )
        if slots.get("S0") or slots.get("S1"):
            s0 = tr("стёрто (FF×16)", "erased (FF×16)") if slots.get("S0") == "ff" * 16 else slots.get("S0", "").upper()
            s1 = tr("стёрто (FF×16)", "erased (FF×16)") if slots.get("S1") == "ff" * 16 else slots.get("S1", "").upper()
            lines.append(f"  {'Slot S0 / S1 (0x69)':<28} : {s0} / {s1}")

        lines.append("")
        lines.append(
            tr(
                "── Защита компонентов IKA / CP (EEL 0x6B 50 Б / 0x6C / 0x6D 18 Б) ──",
                "── Component Protection IKA / CP (EEL 0x6B 50 B / 0x6C / 0x6D 18 B) ──",
            )
        )
        for item in dflash_info.get("items", []):
            if item["key_id"].startswith(("ika_", "cp1_", "cp4_")):
                lines.append(f"  {item['name']:<28} : {item['hex'].upper()}")
        cp_st = dflash_info.get("component_protection_state") or {}
        if cp_st.get("error_counter") is not None:
            lines.append(f"  {'CP Error Counter (0x6D)':<28} : {cp_st['error_counter']} (adapted={cp_st.get('adapted')})")
        if cp_st.get("prng_0"):
            lines.append(f"  {'CP PRNG /0 (EEL 0x6C)':<28} : {cp_st['prng_0'].upper()}")
        if cp_st.get("record_2_first_10"):
            lines.append(f"  {'CP /2 [0..9] (EEL 0x6D)':<28} : {cp_st['record_2_first_10'].upper()}")

        lines.append("")
        lines.append(
            tr(
                "── Доступ поставщика Continental FD11 (EEL 0x63 / 0x64, SL 7) ──",
                "── Continental Vendor Access FD11 (EEL 0x63 / 0x64, SL 7) ──",
            )
        )
        if dflash_info.get("fd11_identifier"):
            lines.append(f"  {'FD11 Identifier':<28} : {dflash_info['fd11_identifier'].upper()}")
        for item in dflash_info.get("items", []):
            if item["key_id"].startswith(("fd11_", "aux_")):
                crc_tag = f"  [CRC-32: {'OK' if item['crc_valid'] else 'FAIL'}]" if item["crc_valid"] is not None else ""
                lines.append(f"  {item['name']:<28} : {item['hex'].upper()}{crc_tag}")

    return "\n".join(lines)


__all__ = [
    "EEL_KOMBI_0310_IDS",
    "EEL_KOMBI_2220_IDS",
    "KOMBI_2220_FDE3_AFFECTED_EEL_IDS",
    "KOMBI_2220_RAM_EEL_PHYS_TABLE_ADDR",
    "KOMBI_2220_RAM_EEL_STATE_ADDR",
    "KOMBI_2220_RAM_FD11_STATE_ADDR",
    "KOMBI_2220_RAM_IMMO_MODE_ADDR",
    "KOMBI_2220_RAM_LEVEL_ADDR",
    "KOMBI_2220_RAM_ODO_DPOOL_ADDR",
    "KOMBI_2220_RAM_ODO_METERS_ADDR",
    "KOMBI_2220_RAM_ODO_MIRROR_ADDR",
    "KOMBI_2220_RAM_SL7_KEY_ADDR",
    "KOMBI_2220_RAM_STAGING_ADDR",
    "KOMBI_2220_RETAIN_ODO_DPOOL_ADDR",
    "KOMBI_2220_SA1_DELTA",
    "KOMBI_2220_WR_PRIVILEGED_EEL_IDS",
    "KOMBI_ALIGN4_EEL_IDS",
    "KOMBI_CFLASH_ADDR",
    "KOMBI_CFLASH_SIZE",
    "KOMBI_CRC16_EEL_IDS",
    "KOMBI_DFLASH_BASE_ADDR",
    "KOMBI_2220_RAM_EEL67_ADDR",
    "KOMBI_2220_RAM_EEL68_ADDR",
    "KOMBI_2220_RAM_EEL69_ADDR",
    "KOMBI_2220_RAM_LAST_KEY_ID_ADDR",
    "KOMBI_2220_RAM_RECOG_STATE_ADDR",
    "KOMBI_2220_RAM_S0_ADDR",
    "KOMBI_2220_RAM_SLOTS_FLAG_ADDR",
    "KOMBI_2220_RAM_SLOT_A_ADDR",
    "KOMBI_2220_RAM_SLOT_B_ADDR",
    "KOMBI_2220_SECDATA_SCAN_RANGE",
    "KOMBI_DFLASH_BC_ALIAS_ADDR",
    "KOMBI_DFLASH_POOL_SIZE",
    "KOMBI_DFLASH_SYNTH_SIZE",
    "KOMBI_EEL_2220_LOGICAL_SIZE",
    "KOMBI_EEL_IMMO_MODE_VADDR",
    "KOMBI_EEL_LOGICAL_SIZE",
    "KOMBI_EEL_LOGICAL_SIZES",
    "KOMBI_EEL_VIRTUAL_BASE",
    "KOMBI_FD11_STAGED_SUBBLOCKS",
    "KOMBI_NVM_BLOCK_CODING",
    "KOMBI_NVM_BLOCK_IMMO",
    "KOMBI_NVM_BLOCK_ODO",
    "KOMBI_NVM_BLOCK_ODO_REPAIR",
    "KOMBI_NVM_STAGED_EEL_MAP",
    "KOMBI_RAM_EEL67_ADDR",
    "KOMBI_RAM_EEL68_ADDR",
    "KOMBI_RAM_EEL69_ADDR",
    "KOMBI_RAM_EEL_PHYS_TABLE_ADDR",
    "KOMBI_RAM_EEL_STATE_ADDR",
    "KOMBI_RAM_IMMO_MODE_ADDR",
    "KOMBI_RAM_LEVEL_ADDR",
    "KOMBI_RAM_ODO_DPOOL_ADDR",
    "KOMBI_RAM_ODO_METERS_ADDR",
    "KOMBI_RAM_ODO_MIRROR_ADDR",
    "KOMBI_RAM_RECOG_STATE_ADDR",
    "KOMBI_RAM_S0_ADDR",
    "KOMBI_RAM_SL7_KEY_ADDR",
    "KOMBI_RAM_SLOTS_FLAG_ADDR",
    "KOMBI_RAM_SLOT_A_ADDR",
    "KOMBI_RAM_SLOT_B_ADDR",
    "KOMBI_RAM_STAGING_ADDR",
    "KOMBI_REQUIRED_SL",
    "KOMBI_RETAIN_ODO_DPOOL_ADDR",
    "KOMBI_SA1_DELTA",
    "KOMBI_SECDATA_SCAN_RANGE",
    "KOMBI_UDS_RX_ID",
    "KOMBI_UDS_TX_ID",
    "KOMBI_VERIFIED_PART_NUMBERS",
    "KOMBI_VERIFIED_SW_VERSIONS",
    "KOMBI_WR_PRIVILEGED_EEL_IDS",
    "analyze_kombi_dflash",
    "apply_kombi_dflash_edits",
    "build_fd11_proof",
    "build_kombi_eel_dflash",
    "compare_fpke_immo_passports",
    "detect_kombi_files",
    "eel_read_record_any",
    "extract_kombi_eel_updates",
    "extract_kombi_immo_passport",
    "format_fpke_immo_comparison",
    "format_kombi_report",
    "format_kombi_transfer_plan",
    "fpke_derive_k_ffb",
    "fpke_verify_s0_s1",
    "get_kombi_sw_profile",
    "is_kombi_dflash",
    "is_kombi_ident",
    "kombi_crc16_ccitt",
    "kombi_eel_layout",
    "kombi_support_info",
    "normalize_kombi_dflash_input",
    "plan_kombi_a_to_b_transfer",
    "summarize_kombi_dflash_changes",
    "transfer_kombi_donor_to_target",
    "unpack_kombi_logical_eel",
    "unpack_kombi_physical_dflash",
]
