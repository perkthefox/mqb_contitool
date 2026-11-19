"""Offline analysis, EEL T01 record parser, Extra Area decoder, and AES-128-CBC FD11 helpers for VAG FPK_E (Kombi)."""

from __future__ import annotations

import contextlib
import hashlib
from pathlib import Path
import struct
from typing import Any
import zlib

from contitool.i18n import tr

FPKE_CFLASH_ADDR = 0x00000000
FPKE_CFLASH_SIZE = 0x00200000  # 2 MiB RH850/D1L Code Flash
FPKE_BFLASH_ADDR = 0x00000000
FPKE_BFLASH_SIZE = 0x00018000  # 96 KiB BootRV40F / BFlash
FPKE_UFLASH_ADDR = 0x01000000
FPKE_UFLASH_SIZE = 0x00008000  # 32 KiB Extended User Area
FPKE_DFLASH_ADDR = 0xFF200000
FPKE_DFLASH_SIZE = 0x00010000  # 64 KiB Data Flash (EEL pool 0x0000..0xDFFF)
FPKE_EXTRA_ADDR = 0xFF300000
FPKE_EXTRA_SIZE = 0x00000100   # 256 B Extra Area (Security / IDCODE / OPBT)

FPKE_CFLASH_CONTROL_PREFIX = bytes.fromhex("8007f010")
EEL_MARK = 0x55555555
FDL_POOL_MAGIC = struct.pack("<HHHH", 8, 64, 0, 0x0380)  # legacy synthetic FDL descriptor
FDL_POOL_MAGIC_120MHZ = struct.pack("<HHHH", 120, 992, 0, 0x0380)  # real RH850/D1L 120 MHz, 992 FDL blks, 0..0x380 EEL

# ID-L table for Audi FPK_E SW 83A (83A920700E, SW 6170/6181, EEL descriptor @ 0x19F150: 235 IDs)
EEL_83A_IDS: dict[int, int] = {
    1: 252, 2: 132, 3: 252, 4: 116, 5: 92, 6: 244, 7: 128, 8: 228, 9: 248, 10: 248,
    11: 252, 12: 254, 13: 132, 14: 164, 15: 248, 16: 200, 17: 248, 18: 200, 19: 248, 20: 200,
    21: 248, 22: 200, 23: 248, 24: 200, 25: 248, 26: 200, 27: 248, 28: 200, 29: 248, 30: 200,
    31: 4, 32: 208, 33: 4, 34: 64, 35: 8, 36: 24, 37: 28, 38: 16, 39: 4, 40: 40,
    41: 4, 42: 8, 43: 16, 44: 201, 45: 240, 46: 90, 47: 24, 48: 44, 49: 208, 50: 26,
    51: 24, 52: 8, 53: 4, 54: 52, 55: 12, 56: 184, 57: 184, 58: 90, 59: 156, 60: 96,
    61: 224, 62: 214, 63: 140, 64: 64, 65: 32, 66: 20, 67: 16, 68: 56, 69: 96, 70: 136,
    71: 12, 72: 12, 73: 12, 74: 12, 75: 12, 76: 12, 77: 12, 78: 12, 79: 12, 80: 12,
    81: 12, 82: 12, 83: 12, 84: 12, 85: 12, 86: 12, 87: 12, 88: 12, 89: 12, 90: 12,
    91: 12, 92: 12, 93: 12, 94: 12, 95: 4, 96: 16, 97: 132, 98: 132, 99: 128, 100: 148,
    101: 36, 102: 24, 103: 40, 104: 128, 105: 36, 106: 124, 107: 84, 108: 20, 109: 100, 110: 4,
    111: 8, 112: 36, 113: 20, 114: 84, 115: 68, 116: 132, 117: 36, 118: 180, 119: 164, 120: 164,
    121: 164, 122: 164, 123: 164, 124: 164, 125: 164, 126: 164, 127: 84, 128: 44, 129: 44, 130: 44,
    131: 44, 132: 44, 133: 44, 134: 44, 135: 44, 136: 44, 137: 44, 138: 44, 139: 44, 140: 44,
    141: 44, 142: 44, 143: 44, 144: 32, 145: 52, 146: 36, 147: 20, 148: 4, 149: 88, 150: 8,
    151: 24, 152: 24, 153: 24, 154: 24, 155: 24, 156: 24, 157: 24, 158: 24, 159: 24, 160: 24,
    161: 24, 162: 24, 163: 24, 164: 24, 165: 24, 166: 24, 167: 52, 168: 200, 169: 84, 170: 218,
    171: 244, 172: 4, 173: 12, 174: 12, 175: 12, 176: 12, 177: 12, 178: 16, 179: 200, 180: 200,
    181: 200, 182: 196, 183: 124, 184: 12, 185: 7, 186: 187, 187: 204, 188: 248, 189: 200, 190: 248,
    191: 200, 192: 248, 193: 200, 194: 248, 195: 200, 196: 248, 197: 200, 198: 248, 199: 200, 200: 248,
    201: 200, 202: 248, 203: 200, 204: 248, 205: 200, 206: 248, 207: 200, 208: 248, 209: 200, 210: 248,
    211: 200, 212: 248, 213: 200, 214: 248, 215: 200, 216: 248, 217: 200, 218: 248, 219: 200, 220: 248,
    221: 200, 222: 248, 223: 200, 224: 248, 225: 200, 226: 248, 227: 200, 228: 248, 229: 200, 230: 248,
    231: 200, 232: 248, 233: 200, 234: 248, 235: 201,
}

# ID-L table for VW / Skoda FPK_E SW 1703/1711 (5E0920790A, EEL descriptor @ 0x1B87C0: 162 IDs)
EEL_1703_IDS: dict[int, int] = {
    1: 252, 2: 132, 3: 252, 4: 116, 5: 92, 6: 244, 7: 128, 8: 228, 9: 248, 10: 248,
    11: 252, 12: 254, 13: 132, 14: 248, 15: 200, 16: 248, 17: 200, 18: 248, 19: 200, 20: 248,
    21: 200, 22: 248, 23: 200, 24: 248, 25: 200, 26: 248, 27: 200, 28: 248, 29: 200, 30: 164,
    31: 4, 32: 208, 33: 4, 34: 48, 35: 8, 36: 24, 37: 28, 38: 16, 39: 4, 40: 40,
    41: 4, 42: 8, 43: 16, 44: 196, 45: 24, 46: 68, 47: 24, 48: 44, 49: 208, 50: 26,
    51: 24, 52: 8, 53: 4, 54: 52, 55: 12, 56: 134, 57: 184, 58: 84, 59: 156, 60: 96,
    61: 247, 62: 210, 63: 140, 64: 64, 65: 32, 66: 20, 67: 16, 68: 56, 69: 96, 70: 136,
    71: 12, 72: 12, 73: 12, 74: 12, 75: 12, 76: 12, 77: 12, 78: 12, 79: 12, 80: 12,
    81: 12, 82: 12, 83: 12, 84: 12, 85: 12, 86: 12, 87: 12, 88: 12, 89: 12, 90: 12,
    91: 12, 92: 12, 93: 12, 94: 12, 95: 4, 96: 16, 97: 132, 98: 132, 99: 128, 100: 148,
    101: 36, 102: 24, 103: 40, 104: 128, 105: 36, 106: 124, 107: 84, 108: 20, 109: 100, 110: 4,
    111: 8, 112: 36, 113: 20, 114: 84, 115: 68, 116: 132, 117: 36, 118: 180, 119: 164, 120: 164,
    121: 164, 122: 164, 123: 164, 124: 164, 125: 164, 126: 164, 127: 84, 128: 4, 129: 88, 130: 8,
    131: 24, 132: 24, 133: 24, 134: 24, 135: 24, 136: 24, 137: 24, 138: 24, 139: 24, 140: 24,
    141: 24, 142: 24, 143: 24, 144: 24, 145: 24, 146: 24, 147: 52, 148: 48, 149: 84, 150: 218,
    151: 244, 152: 4, 153: 12, 154: 12, 155: 12, 156: 12, 157: 12, 158: 16, 159: 200, 160: 200,
    161: 200, 162: 200,
}

# Immobilizer partner table (ODIS-E STRUC_DataRecorTheftProteDataStateOfImmobSlave + ac-immo-she.md §3.3/§4.1):
# (partner_idx, code, r66_off, did_02ee_off, can_rx, can_tx, group, label_ru, label_en)
FPKE_IMMO_PARTNERS: tuple[tuple[int, str, int, int, int, int, str, str, str], ...] = (
    (0, "MSG_1", 0x04, 2, 0x010, 0x011, "B", "ECU 1 (Двигатель)", "ECU 1 (Engine)"),
    (1, "GSG",   0x0E, 6, 0x012, 0x013, "B", "TCU (Коробка передач)", "TCU (Gearbox)"),
    (2, "MSG_2", 0x06, 3, 0x014, 0x015, "B", "ECU 2 / Инвертор", "ECU 2 / Inverter"),
    (3, "MSG_3", 0x08, 4, 0x016, 0x017, "B", "ECU 3", "ECU 3"),
    (4, "MSG_4", 0x0A, 5, 0x018, 0x019, "B", "ECU 4", "ECU 4"),
    (5, "ELV",   0x0C, 7, 0x01A, 0x01B, "A", "ELV (Блокиратор руля)", "ELV (Steering lock)"),
    (6, "OCU",   0x14, 8, 0x01C, 0x01D, "A", "OCU (Телематика)", "OCU (Telematics)"),
    (7, "VTS",   0x12, 9, 0x01E, 0x01F, "A", "VTS (Охранная система)", "VTS (Vehicle tracking)"),
)


# ────────────────────────────── Pure-Python AES-128-CBC ──────────────────────────────

_AES_SBOX: tuple[int, ...] = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _aes128_expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    w = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = [_AES_SBOX[temp[1]] ^ _RCON[i // 4], _AES_SBOX[temp[2]], _AES_SBOX[temp[3]], _AES_SBOX[temp[0]]]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    return [sum(w[r * 4 : (r + 1) * 4], []) for r in range(11)]


def _aes128_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    s = [block[i] ^ round_keys[0][i] for i in range(16)]
    for r in range(1, 10):
        s = [_AES_SBOX[b] for b in s]
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        out = [0] * 16
        for c in range(4):
            i = c * 4
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            t = a0 ^ a1 ^ a2 ^ a3
            out[i] = a0 ^ t ^ _xtime(a0 ^ a1)
            out[i + 1] = a1 ^ t ^ _xtime(a1 ^ a2)
            out[i + 2] = a2 ^ t ^ _xtime(a2 ^ a3)
            out[i + 3] = a3 ^ t ^ _xtime(a3 ^ a0)
        rk = round_keys[r]
        s = [out[i] ^ rk[i] for i in range(16)]
    s = [_AES_SBOX[b] for b in s]
    s = [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]
    rk = round_keys[10]
    return bytes(s[i] ^ rk[i] for i in range(16))


def aes128_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt `plaintext` (multiple of 16 bytes) with AES-128-CBC (no padding)."""
    if len(iv) != 16:
        raise ValueError(f"AES-128-CBC IV must be 16 bytes, got {len(iv)}")
    if len(plaintext) % 16 != 0:
        raise ValueError(f"AES-128-CBC plaintext must be a multiple of 16 bytes, got {len(plaintext)}")
    rks = _aes128_expand_key(key)
    prev = iv
    out = bytearray()
    for off in range(0, len(plaintext), 16):
        xored = bytes(plaintext[off + i] ^ prev[i] for i in range(16))
        prev = _aes128_encrypt_block(xored, rks)
        out.extend(prev)
    return bytes(out)


def aes128_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt `plaintext` (multiple of 16 bytes) with AES-128-ECB (no padding)."""
    if len(plaintext) % 16 != 0:
        raise ValueError(f"AES-128-ECB plaintext must be a multiple of 16 bytes, got {len(plaintext)}")
    rks = _aes128_expand_key(key)
    out = bytearray()
    for off in range(0, len(plaintext), 16):
        out.extend(_aes128_encrypt_block(plaintext[off : off + 16], rks))
    return bytes(out)


# 10-byte ROM constant for `2E 02E1` MAC block (SW 1703 `0x19D1D8`, SW 83A `0x196E68`)
FPKE_02E1_C10 = bytes.fromhex("01020304050607080910")

# 16-byte ROM constant C16 (FPK_E `0x19DA90`) for FFB radio channel secret: `K_ffb = AES128_ECB_ENC(K_c, C16)`
FPKE_FFB_C16 = bytes.fromhex("e7ad3585e2f937e81c75df6e47f11a71")


def fpke_derive_k_ffb(kc: bytes | str) -> bytes:
    """Derive 16-byte FFB remote key radio-channel secret `K_ffb = AES128_ECB_ENC(K_c, C16)` (`FPK_E` ROM `0x19DA90`)."""
    if isinstance(kc, (bytes, bytearray, memoryview)):
        raw = bytes(kc)
    else:
        cleaned = "".join(str(kc).split()).replace("0x", "").replace("0X", "")
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"K_c must be 32 hex digits (16 bytes), got {kc!r}") from exc
    if len(raw) != 16:
        raise ValueError(f"K_c must be 16 bytes (32 hex digits), got {len(raw)} bytes")
    return aes128_ecb_encrypt(raw, FPKE_FFB_C16)


def fpke_crc16_ccitt(data: bytes) -> int:
    """Compute firmware CRC-16/CCITT (`0x13F4A2`: polynomial `0x1021`, init `0xFFFF`)."""
    c = 0xFFFF
    for b in data:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if (c & 0x8000) else (c << 1) & 0xFFFF
    return c


def fpke_compute_02e1_mac(kc: bytes, challenge_r: bytes, cmd: int, param: int) -> bytes:
    """Compute 2-byte big-endian MAC for `2E 02E1 <M0> <M1> <C> <P>` (`ac-immo-diag.md` §4.2).

    Commands `0x40` and `0x80` (`P in {0, 1, 2}`) do not use MAC (`00 00`).
    Commands `0x01`, `0x02`, `0x04`, `0x10` use `CRC16_CCITT(AES128_ECB_Kc(C || P || R[0..3] || C10))`.
    """
    c_byte = cmd & 0xFF
    p_byte = param & 0xFF
    if c_byte in (0x40, 0x80):
        return b"\x00\x00"
    if len(kc) != 16:
        raise ValueError(f"K_c must be 16 bytes, got {len(kc)}")
    if len(challenge_r) != 4:
        raise ValueError(f"Challenge R (DID 0x02E0) must be 4 bytes, got {len(challenge_r)}")
    blk = bytes([c_byte, p_byte]) + challenge_r + FPKE_02E1_C10
    crc = fpke_crc16_ccitt(aes128_ecb_encrypt(kc, blk))
    return bytes([(crc >> 8) & 0xFF, crc & 0xFF])


def build_fpke_02e1_request(
    cmd: int,
    param: int,
    *,
    kc: bytes | None = None,
    challenge_r: bytes | None = None,
) -> bytes:
    """Build 7-byte UDS request `2E 02 E1 <M0> <M1> <C> <P>`."""
    c_byte = cmd & 0xFF
    p_byte = param & 0xFF
    if c_byte in (0x40, 0x80):
        mac = b"\x00\x00"
    else:
        if kc is None or challenge_r is None:
            raise ValueError(f"Command 0x{c_byte:02X} requires 16-byte K_c and 4-byte challenge R (0x02E0)")
        mac = fpke_compute_02e1_mac(kc, challenge_r, c_byte, p_byte)
    return bytes([0x2E, 0x02, 0xE1, mac[0], mac[1], c_byte, p_byte])


def fpke_slots_from_s0_s1(s0: bytes, s1: bytes) -> tuple[bytes, bytes]:
    """Reconstruct 16-byte `(slot_a, slot_b)` from `EEL 0x69` `(s0, s1)` (`0x13FC24`, `ac-immo-she.md` §3.3)."""
    if len(s0) != 16 or len(s1) != 16:
        raise ValueError("S0 and S1 must each be 16 bytes")
    slot_a = bytes(s0[0:4]) + bytes(s1[4:12]) + bytes(s0[12:16])
    slot_b = bytes(s1[0:4]) + bytes(s0[4:12]) + bytes(s1[12:16])
    return slot_a, slot_b


def fpke_s0_s1_from_slots(slot_a: bytes, slot_b: bytes) -> tuple[bytes, bytes]:
    """Pack 16-byte `(slot_a, slot_b)` into `EEL 0x69` / `02F7` `(s0, s1)` layout (involutory permutation)."""
    if len(slot_a) != 16 or len(slot_b) != 16:
        raise ValueError("Slot A and Slot B must each be 16 bytes")
    return fpke_slots_from_s0_s1(slot_a, slot_b)


def fpke_verify_s0_s1(
    s0: bytes,
    s1: bytes,
    expected_crc_a_le: bytes | str | None = None,
    expected_crc_b_le: bytes | str | None = None,
) -> dict[str, Any]:
    """Verify `S0 / S1` (`EEL 0x69` / RAM `0xFEDF2D44`) against `EEL 0x68` `CRC-32(A)` and `CRC-32(B)` (`VDO CS+`)."""
    if len(s0) != 16 or len(s1) != 16:
        raise ValueError("S0 and S1 must each be 16 bytes")
    slot_a, slot_b = fpke_slots_from_s0_s1(s0, s1)
    crc_a_le = struct.pack("<I", zlib.crc32(slot_a))
    crc_b_le = struct.pack("<I", zlib.crc32(slot_b))

    def _norm_crc(val: bytes | str | None) -> bytes | None:
        if val is None:
            return None
        if isinstance(val, str):
            cleaned = "".join(val.split()).replace("0x", "").replace("0X", "")
            return bytes.fromhex(cleaned) if len(cleaned) == 8 else None
        return bytes(val) if len(val) == 4 else None

    exp_a = _norm_crc(expected_crc_a_le)
    exp_b = _norm_crc(expected_crc_b_le)
    not_blank = (
        s0 not in (b"\xff" * 16, b"\x00" * 16, b"\xaa" * 16)
        and s1 not in (b"\xff" * 16, b"\x00" * 16, b"\xaa" * 16)
    )
    crc_a_ok = True if exp_a is None else (crc_a_le == exp_a)
    crc_b_ok = True if exp_b is None else (crc_b_le == exp_b)
    return {
        "valid": bool(not_blank and crc_a_ok and crc_b_ok),
        "not_blank": not_blank,
        "crc_a_ok": crc_a_ok,
        "crc_b_ok": crc_b_ok,
        "s0_hex": s0.hex().upper(),
        "s1_hex": s1.hex().upper(),
        "slot_a_hex": slot_a.hex().upper(),
        "slot_b_hex": slot_b.hex().upper(),
        "crc_a_le_hex": crc_a_le.hex().upper(),
        "crc_b_le_hex": crc_b_le.hex().upper(),
        "expected_crc_a_le_hex": exp_a.hex().upper() if exp_a else None,
        "expected_crc_b_le_hex": exp_b.hex().upper() if exp_b else None,
    }


def encode_fpke_02f7_config(
    allowed_keys: int,
    partner_mask: int = 0x01,
    key_flags: int = 0x00,
    *,
    force_local_coil: bool = True,
) -> tuple[int, int]:
    """Encode `P[0x42]` and `P[0x43]` of `2E 02F7` as exact inverse of `0x13A99C` (`ac-immo-data.md` §2.4)."""
    if not (1 <= allowed_keys <= 8):
        raise ValueError(f"allowed_keys must be in 1..8, got {allowed_keys}")
    eff_flags = (key_flags & ~0x80) if force_local_coil else (key_flags & 0xFF)
    b42 = allowed_keys & 0x0F
    if partner_mask & 0x80:  # partner 7 -> b42 bit 6
        b42 |= 0x40
    if partner_mask & 0x40:  # partner 6 -> b42 bit 7
        b42 |= 0x80

    b43 = 0
    if eff_flags & 0x80:     # 0x5303 bit 7 (key over CAN) -> b43 bit 0
        b43 |= 0x01
    if eff_flags & 0x40:     # 0x5303 bit 6 (restart window off) -> b43 bit 1
        b43 |= 0x02
    if partner_mask & 0x20:  # partner 5 -> b43 bit 2
        b43 |= 0x04
    if partner_mask & 0x02:  # partner 1 -> b43 bit 3
        b43 |= 0x08
    if partner_mask & 0x01:  # partner 0 (ECU) -> b43 bit 4
        b43 |= 0x10
    if partner_mask & 0x04:  # partner 2 (TCU) -> b43 bit 5
        b43 |= 0x20
    if partner_mask & 0x08:  # partner 3 (ELV) -> b43 bit 6
        b43 |= 0x40
    if partner_mask & 0x10:  # partner 4 -> b43 bit 7
        b43 |= 0x80
    return b42, b43


def build_fpke_02f7_payload(
    *,
    vin: str,
    s0: bytes,
    s1: bytes,
    current_kc: bytes,
    new_kc: bytes | None = None,
    power_class: int,
    allowed_keys: int,
    partner_mask: int = 0x01,
    key_flags: int = 0x00,
    status_5302: int = 0x00,
    force_local_coil: bool = True,
) -> tuple[bytes, bytes]:
    """Build 87-byte `2E 02F7` UDS request (`2E 02 F7 || AES128_ECB_Kc(P[80]) || CRC32_BE(P)`) and 80-byte plaintext."""
    vin_clean = vin.strip().upper()
    if len(vin_clean) != 17 or not all(0x20 <= ord(c) < 0x7F for c in vin_clean):
        raise ValueError(f"VIN must be 17 ASCII characters, got {vin!r}")
    if len(s0) != 16 or len(s1) != 16:
        raise ValueError("S0 and S1 must each be 16 bytes")
    if s0 in (b"\xff" * 16, b"\x00" * 16) or s1 in (b"\xff" * 16, b"\x00" * 16):
        raise ValueError("Refusing to build 02F7 with blank/erased S0/S1")
    if len(current_kc) != 16:
        raise ValueError("current_kc must be 16 bytes")
    eff_new_kc = current_kc if new_kc is None else new_kc
    if len(eff_new_kc) != 16:
        raise ValueError("new_kc must be 16 bytes")

    p = bytearray(80)
    p[0x00:0x11] = vin_clean.encode("ascii")
    p[0x11:0x21] = s0
    p[0x21:0x31] = s1
    p[0x31:0x41] = eff_new_kc
    p[0x41] = power_class & 0xFF
    b42, b43 = encode_fpke_02f7_config(
        allowed_keys,
        partner_mask,
        key_flags,
        force_local_coil=force_local_coil,
    )
    p[0x42] = b42
    p[0x43] = b43
    p[0x44] = status_5302 & 0xFF

    plain = bytes(p)
    encrypted = aes128_ecb_encrypt(current_kc, plain)
    crc_be = zlib.crc32(plain).to_bytes(4, "big")
    return b"\x2e\x02\xf7" + encrypted + crc_be, plain


def build_fd11_proof(
    challenge_resp: bytes,
    key: bytes,
    *,
    t16: bytes = bytes(range(16)),
    t8: bytes = bytes(range(0x10, 0x18)),
) -> bytes:
    """Compute the 32-byte AES-128-CBC proof for `2E FD11 04` from a 26-byte `6E FD11 <C8:8><ID:15>` reply."""
    if len(challenge_resp) != 26 or challenge_resp[:3] != b"\x6e\xfd\x11":
        raise ValueError(f"Malformed FD11 challenge response ({len(challenge_resp)} B): {challenge_resp.hex()}")
    if len(t16) != 16 or len(t8) != 8:
        raise ValueError("FD11 t16 must be 16 B and t8 must be 8 B")
    c8_and_id = challenge_resp[3:26]  # 23 bytes: C8 (8 B) || ID (15 B)
    plain = c8_and_id + t8 + b"\x01"  # 32 bytes
    return aes128_cbc_encrypt(key, t16, plain)


# ────────────────────────────── Detection Helpers ──────────────────────────────


def is_fpke_ident(ident: list[dict[str, str]]) -> bool:
    """True when UDS identification DIDs belong to a VAG Kombi / FPK_E instrument cluster."""
    vals = {item.get("did", ""): item.get("value", "").strip() for item in ident or []}
    odx = vals.get("F19E", "").upper()
    sys_name = vals.get("F197", "").upper()
    if "DASHBOARD" in odx or "FPK" in odx or "KOMBI" in sys_name or "FPK" in sys_name:
        return True
    for key in ("F187", "F191"):
        pn = "".join(vals.get(key, "").split()).upper()
        if len(pn) >= 9 and pn[3:6] == "920":
            return True
    return False


def is_fpke_cflash(data: bytes) -> bool:
    """True for a 2 MiB FPK_E RH850/D1L CodeFlash image."""
    if len(data) != FPKE_CFLASH_SIZE:
        return False
    if data[:4] == FPKE_CFLASH_CONTROL_PREFIX:
        return True
    return b"EV_DashBoard" in data[:0x60000] or b"FPKE" in data[:0x60000]


def eel_cs24(value: int) -> int:
    """24-bit EEL value with its inverted byte-sum check in bits 31..24."""
    v = value & 0xFFFFFF
    chk = (~((v & 0xFF) + ((v >> 8) & 0xFF) + ((v >> 16) & 0xFF))) & 0xFF
    return v | (chk << 24)


def is_fpke_dflash(data: bytes) -> bool:
    """True for a 64 KiB FPK_E DataFlash image containing a Renesas EEL T01 pool (28 x 2 KiB VBs)."""
    if len(data) != FPKE_DFLASH_SIZE:
        return False
    valid_vbs = 0
    active_or_prep = 0
    for vb in range(28):
        base = vb * 0x800
        i0, p, a0, _a1, ec = struct.unpack_from("<5I", data, base)
        i1 = struct.unpack_from("<I", data, base + 0x7FC)[0]
        if i0 == EEL_MARK and i1 == EEL_MARK:
            valid_vbs += 1
            continue
        if (a0 == EEL_MARK or p == EEL_MARK) and ec != 0xFFFFFFFF and eel_cs24(ec) == ec:
            valid_vbs += 1
            active_or_prep += 1
    return valid_vbs >= 20 and active_or_prep >= 1


def is_fpke_extra_area(data: bytes) -> bool:
    """True for a valid 256-byte RH850 Extra Area dump (`0xFF300000..0xFF3000FF`)."""
    if len(data) != FPKE_EXTRA_SIZE:
        return False
    try:
        validate_fpke_extra_area(data)
        return True
    except RuntimeError:
        return False


def detect_fpke_files(paths: list[Path]) -> dict[str, Path]:
    """Classify loose files or a directory's contents into `{'dflash', 'extra', 'cflash', 'uflash', 'bflash', 'report'}`."""
    found: dict[str, Path] = {}
    uflash_cand: Path | None = None
    candidates: list[Path] = []
    for p in paths:
        if p.is_dir():
            candidates.extend(sorted(c for c in p.iterdir() if c.is_file()))
        elif p.is_file():
            candidates.append(p)
    for p in candidates:
        low = p.name.lower()
        if low.endswith(".json") and "fpke" in low:
            found.setdefault("report", p)
            continue
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if sz == FPKE_EXTRA_SIZE:
            raw = p.read_bytes()
            if is_fpke_extra_area(raw):
                found.setdefault("extra", p)
        elif sz == FPKE_DFLASH_SIZE:
            raw = p.read_bytes()
            if is_fpke_dflash(raw):
                found.setdefault("dflash", p)
        elif sz == FPKE_CFLASH_SIZE:
            raw = p.read_bytes()
            if is_fpke_cflash(raw):
                found.setdefault("cflash", p)
        elif sz == FPKE_BFLASH_SIZE and "bflash" in low:
            found.setdefault("bflash", p)
        elif sz == FPKE_UFLASH_SIZE and "uflash" in low:
            uflash_cand = uflash_cand or p
    if found and uflash_cand is not None:
        found.setdefault("uflash", uflash_cand)
    return found


# ────────────────────────────── Extra Area Analysis ──────────────────────────────


def validate_fpke_extra_area(data: bytes) -> None:
    """Enforce structural postconditions on an RH850 Extra Area read (`0xFF300000`)."""
    if len(data) < 0x80:
        raise RuntimeError(f"Extra Area too short: {len(data)} bytes (expected >= 128)")
    invalid_words = {b"\x00" * 4, b"\xff" * 4, b"\x55" * 4}
    if data[:0x40] != b"\xff" * 0x40:
        raise RuntimeError("Extra Area structural check failed: reserved prefix 0x00..0x3F is not erased")
    if bytes(data[0x40:0x44]) in invalid_words or bytes(data[0x70:0x74]) in invalid_words:
        raise RuntimeError("Extra Area structural check failed: invalid security or OPBT0 word")


def analyze_fpke_extra_area(data: bytes) -> dict[str, Any]:
    """Decode RH850/D1L Extra Area (`0xFF300000`, 256 bytes): security flags, IDCODE, reset vector, OPBT0."""
    validate_fpke_extra_area(data)
    security = int.from_bytes(data[0x40:0x44], "little")
    opbt0 = int.from_bytes(data[0x70:0x74], "little")
    icu_bound = int.from_bytes(data[0x9C:0xA0], "little") if len(data) >= 0xA0 else None
    idcode = bytes(data[0x50:0x60])
    reset_vec = bytes(data[0x60:0x70])
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "security_raw": f"0x{security:08X}",
        "security_bytes": bytes(data[0x40:0x50]).hex(),
        "protection_mode": "Command Protection" if (security & (1 << 24)) else "ID Code Protection",
        "serial_programming_enabled": bool(security & (1 << 27)),
        "command_erase_enabled": bool(security & (1 << 29)),
        "command_write_enabled": bool(security & (1 << 30)),
        "command_read_enabled": bool(security & (1 << 31)),
        "idcode": idcode.hex(),
        "idcode_spaced": " ".join(f"{b:02X}" for b in idcode),
        "idcode_is_blank_ff": idcode == b"\xff" * 16,
        "reset_vector": reset_vec.hex(),
        "opbt0": f"0x{opbt0:08X}",
        "option_bytes": bytes(data[0x70:0x80]).hex(),
        "icu_bound": f"0x{icu_bound:08X}" if icu_bound is not None else None,
    }


# ────────────────────────────── EEL T01 & Secret Extraction ──────────────────────────────


def fpke_eel_layout(cflash: bytes | None = None, dflash: bytes | None = None) -> dict[str, Any]:
    """Return EEL pool geometry & ID-L map, parsed from `cflash` or auto-detected from `dflash` (83A vs 1703)."""
    if cflash is not None and len(cflash) >= FPKE_CFLASH_SIZE:
        for known_off in (0x19F150, 0x1B87C0):
            if known_off + 0x18 <= len(cflash) and cflash[known_off + 0x10 : known_off + 0x18] in (
                FDL_POOL_MAGIC_120MHZ,
                FDL_POOL_MAGIC,
            ):
                return _parse_eel_desc(cflash, known_off)
        for magic in (FDL_POOL_MAGIC_120MHZ, FDL_POOL_MAGIC):
            at = cflash.find(magic)
            while at >= 0x10:
                vblk, _thr, idl, _ram, n_ids = struct.unpack_from("<HHIIH", cflash, at - 0x10)
                if 0 < vblk < 64 and 0 < n_ids < 512 and (idl & 0xFFFFFF) + 4 * n_ids <= len(cflash):
                    return _parse_eel_desc(cflash, at - 0x10)
                at = cflash.find(magic, at + 1)

    chosen_ids = EEL_83A_IDS
    if dflash is not None and len(dflash) == FPKE_DFLASH_SIZE:
        lay_83a = {"vb": 0x800, "n_vb": 28, "base": 0, "threshold": 8, "ids": EEL_83A_IDS}
        lay_1703 = {"vb": 0x800, "n_vb": 28, "base": 0, "threshold": 8, "ids": EEL_1703_IDS}
        _, lat_83a = eel_parse_pool(lay_83a, dflash)
        _, lat_1703 = eel_parse_pool(lay_1703, dflash)
        has_high_id = any(ident > 162 for ident in lat_83a)
        if not has_high_id and lat_1703:
            ok_83a = sum(
                1 for ident, (_vb, top, _ref) in lat_83a.items()
                if int.from_bytes(dflash[top : top + 2], "little") == EEL_83A_IDS[ident]
            )
            ok_1703 = sum(
                1 for ident, (_vb, top, _ref) in lat_1703.items()
                if int.from_bytes(dflash[top : top + 2], "little") == EEL_1703_IDS[ident]
            )
            if ok_1703 > ok_83a:
                chosen_ids = EEL_1703_IDS

    return {
        "vb": 0x800,
        "n_vb": 28,
        "base": 0,
        "threshold": 8,
        "ids": dict(chosen_ids),
    }


def _parse_eel_desc(cflash: bytes, eel_desc: int) -> dict[str, Any]:
    vblk_blocks, threshold, idl, _ram, n_ids = struct.unpack_from("<HHIIH", cflash, eel_desc)
    _mhz, _fdl_blocks, eel_start, eel_blocks = struct.unpack_from("<HHHH", cflash, eel_desc + 0x10)
    idl_off = idl & 0xFFFFFF
    ids = dict(struct.unpack_from("<HH", cflash, idl_off + 4 * i) for i in range(n_ids))
    vb = vblk_blocks * 64
    return {
        "vb": vb,
        "n_vb": (eel_blocks * 64) // vb,
        "base": eel_start * 64,
        "threshold": threshold,
        "ids": ids,
    }


def eel_remask(lay: dict[str, Any], df: bytes) -> bytearray:
    """Rebuild written-word mask for a 64 KiB DataFlash image from its EEL virtual block headers and DRPs."""
    mask = bytearray(FPKE_DFLASH_SIZE)

    def word(addr: int) -> int:
        return struct.unpack_from("<I", df, addr)[0]

    def put(addr: int) -> None:
        if 0 <= addr <= FPKE_DFLASH_SIZE - 4:
            mask[addr : addr + 4] = b"\xff\xff\xff\xff"

    for n in range(lay["n_vb"]):
        b = lay["base"] + n * lay["vb"]
        for o in (0, 4, 8, 0xC, 0x10, 0x14, lay["vb"] - 4):
            if word(b + o) != 0xFFFFFFFF:
                put(b + o)
        if word(b + 8) != EEL_MARK:
            continue
        a = b + 0x18
        while a + 0x10 <= b + lay["vb"] - 4 and word(a) == EEL_MARK:
            for o in (0, 4, 8):
                if word(a + o) != 0xFFFFFFFF:
                    put(a + o)
            put(a + 0xC)
            drp = word(a + 0xC)
            top = b + ((drp >> 16) & 0x7FFF)
            rec_len = (lay["ids"].get(drp & 0xFFFF, 0) + 3) & ~3 if top > b else 0
            for i in range(0, rec_len, 4):
                if top - i >= b + 0x18:
                    put(top - i)
            a += 0x10
    return mask


def eel_faci_word_mask(lay: dict[str, Any], df: bytes) -> bytearray:
    """Return exact 65,536-byte programmed-word mask (`0xFF*4` = `BCST 1`, `0x00*4` = blank `BCST 0`) for RV40F FACI.

    Handles both blank-checked dumps and raw CPU-read (`UDS 0x23`) dumps where erased RV40F DataFlash cells
    contain floating-gate residue (including ghost `0x55555555` words from prior EEL cycles):
      - `active` VB: marks `P/A0/A1/EC/RWP`, active DRPs up to true separator, and all referenced data words, while
        keeping `I0 (+0x00)`, `[separator .. next_top]`, and `I1 (+vb-4)` genuinely blank (`BCST 0`).
      - `prepared` VB: marks only `P (+0x04)` and valid `EC (+0x10)`, keeping `I0`, `A0`, `A1`, `RWP`, body, and `I1` blank.
      - `invalid` VB: marks valid header/footer markers (`I0`, `I1`, `P`, `A0`, `A1`, `EC`, `RWP`) and historical DRPs/records.
      - Non-EEL tail (`pool_end .. 0xFFFF`): marks words `!= 0xFFFFFFFF`.
    """
    mask = bytearray(FPKE_DFLASH_SIZE)
    vb_sz = lay["vb"]
    n_vb = lay["n_vb"]

    def word(addr: int) -> int:
        return struct.unpack_from("<I", df, addr)[0]

    def put(addr: int) -> None:
        if 0 <= addr <= FPKE_DFLASH_SIZE - 4:
            mask[addr : addr + 4] = b"\xff\xff\xff\xff"

    def _scan_drps(b: int, limit_addr: int, strict_packed: bool) -> tuple[int, list[tuple[int, int, int]]]:
        a = b + 0x18
        exp_widx = vb_sz - 8
        entries: list[tuple[int, int, int]] = []
        while a + 0x10 <= limit_addr and word(a) == EEL_MARK:
            if not (word(a + 4) == EEL_MARK or word(a + 8) == EEL_MARK):
                break
            drp = word(a + 0xC)
            ident, widx = drp & 0xFFFF, (drp >> 16) & 0x7FFF
            rec_sz = lay["ids"].get(ident, 0)
            if strict_packed:
                if not rec_sz or (widx & 3) != 0 or not (0x18 <= widx <= exp_widx):
                    break
                if struct.unpack_from("<H", df, b + widx)[0] != rec_sz:
                    break
                exp_widx = widx - ((rec_sz + 3) & ~3)
            entries.append((a, b + widx, (rec_sz + 3) & ~3 if rec_sz and widx > 0 else 0))
            a += 0x10
        return a, entries

    def _emit_entries(b: int, entries: list[tuple[int, int, int]]) -> None:
        for drp_addr, top, rec_len in entries:
            for o in (0, 4, 8, 0xC):
                put(drp_addr + o)
            for i in range(0, rec_len, 4):
                if b + 0x18 <= top - i <= b + vb_sz - 8:
                    put(top - i)

    has_fg_noise = False
    vb_meta: list[dict[str, Any]] = []
    for n in range(n_vb):
        b = lay["base"] + n * vb_sz
        w_i0, w_p, w_a0, w_a1, w_ec, w_rwp = struct.unpack_from("<6I", df, b)
        w_i1 = word(b + vb_sz - 4)
        if any(v not in (0xFFFFFFFF, EEL_MARK) for v in (w_i0, w_p, w_a0, w_a1, w_i1)):
            has_fg_noise = True
        ec_ok = w_ec != 0xFFFFFFFF and eel_cs24(w_ec) == w_ec
        rwp_ok = w_rwp != 0xFFFFFFFF and eel_cs24(w_rwp) == w_rwp
        vb_meta.append(
            {
                "b": b,
                "i0": w_i0 == EEL_MARK,
                "i1": w_i1 == EEL_MARK,
                "p": w_p == EEL_MARK,
                "a0": w_a0 == EEL_MARK,
                "a1": w_a1 == EEL_MARK,
                "ec_ok": ec_ok,
                "ec": (w_ec & 0xFFFFFF) if ec_ok else None,
                "rwp_ok": rwp_ok,
                "rwp": (w_rwp & 0xFFFFFF) if rwp_ok else None,
            }
        )

    if has_fg_noise:
        # Reconstruct exact active RWP-linked chain so ghost 0x55555555 words in prepared/erased cells are ignored
        succ: dict[int, int] = {}
        pred: dict[int, int] = {}
        for n in range(n_vb):
            cur = vb_meta[n]
            nxt_idx = (n + 1) % n_vb
            nxt = vb_meta[nxt_idx]
            if not (cur["p"] and cur["a0"] and cur["ec_ok"] and nxt["p"] and nxt["a0"] and nxt["ec_ok"] and nxt["rwp_ok"]):
                continue
            exp_ec = cur["ec"] + (1 if nxt_idx == 0 else 0)
            rwp_val = nxt["rwp"]
            if nxt["ec"] == exp_ec and cur["b"] + 0x18 <= rwp_val <= cur["b"] + vb_sz - 4:
                sep_end, _ = _scan_drps(cur["b"], rwp_val, True)
                if sep_end == rwp_val:
                    succ[n] = nxt_idx
                    pred[nxt_idx] = n

        best_chain: list[int] = []
        for start in range(n_vb):
            if start in pred or not (vb_meta[start]["p"] and vb_meta[start]["a0"] and vb_meta[start]["ec_ok"]):
                continue
            chain = [start]
            cur_idx = start
            while cur_idx in succ and succ[cur_idx] not in chain:
                cur_idx = succ[cur_idx]
                chain.append(cur_idx)
            # Validate single-block candidate if no RWP chain exists
            if len(chain) == 1:
                if not vb_meta[start]["rwp_ok"] or (vb_meta[start]["i0"] and vb_meta[start]["i1"]):
                    continue
                _sep, ents = _scan_drps(vb_meta[start]["b"], vb_meta[start]["b"] + vb_sz - 4, True)
                if not ents:
                    continue
            # Trim invalidated tail predecessor(s) at the start of the chain (e.g. VB 15 before active VB 16)
            while len(chain) > 1 and vb_meta[chain[0]]["i0"] and vb_meta[chain[0]]["i1"]:
                chain.pop(0)
            if len(chain) > len(best_chain) or (
                len(chain) == len(best_chain)
                and best_chain
                and (vb_meta[chain[-1]]["ec"] or 0) > (vb_meta[best_chain[-1]]["ec"] or 0)
            ):
                best_chain = chain

        active_set = set(best_chain)
        if len(best_chain) <= 1:
            for n, m in enumerate(vb_meta):
                if m["p"] and m["a0"] and m["ec_ok"] and m["rwp_ok"] and not (m["i0"] and m["i1"]):
                    _sep, ents = _scan_drps(m["b"], m["b"] + vb_sz - 4, True)
                    if ents:
                        active_set.add(n)
        for n, m in enumerate(vb_meta):
            b = m["b"]
            if n in active_set:
                if m["p"]:
                    put(b + 4)
                put(b + 8)
                if m["a1"]:
                    put(b + 0xC)
                if m["ec_ok"]:
                    put(b + 0x10)
                if m["rwp_ok"]:
                    put(b + 0x14)
                limit = vb_meta[succ[n]]["rwp"] if (n in succ and succ[n] in active_set) else (b + vb_sz - 4)
                _sep, ents = _scan_drps(b, limit, True)
                _emit_entries(b, ents)
            elif m["i0"] and m["i1"] and (n in succ or (m["ec"] is not None and best_chain and m["ec"] < (vb_meta[best_chain[-1]]["ec"] or 0))):
                put(b)
                put(b + vb_sz - 4)
                if m["p"]:
                    put(b + 4)
                if m["a0"]:
                    put(b + 8)
                    limit = vb_meta[succ[n]]["rwp"] if n in succ else (b + vb_sz - 4)
                    _sep, ents = _scan_drps(b, limit, True)
                    _emit_entries(b, ents)
                if m["a1"]:
                    put(b + 0xC)
                if m["ec_ok"]:
                    put(b + 0x10)
                if m["rwp_ok"]:
                    put(b + 0x14)
            elif m["p"]:
                put(b + 4)
                if m["ec_ok"]:
                    put(b + 0x10)
    else:
        for n, m in enumerate(vb_meta):
            b = m["b"]
            if m["i0"] and m["i1"]:
                put(b)
                put(b + vb_sz - 4)
                if m["p"]:
                    put(b + 4)
                if m["a0"]:
                    put(b + 8)
                    _sep, ents = _scan_drps(b, b + vb_sz - 4, False)
                    _emit_entries(b, ents)
                if m["a1"]:
                    put(b + 0xC)
                if m["ec_ok"]:
                    put(b + 0x10)
                if m["rwp_ok"]:
                    put(b + 0x14)
            elif m["a0"]:
                if m["p"]:
                    put(b + 4)
                put(b + 8)
                if m["a1"]:
                    put(b + 0xC)
                if m["ec_ok"]:
                    put(b + 0x10)
                if m["rwp_ok"]:
                    put(b + 0x14)
                _sep, ents = _scan_drps(b, b + vb_sz - 4, False)
                _emit_entries(b, ents)
            elif m["p"]:
                put(b + 4)
                if m["ec_ok"]:
                    put(b + 0x10)

    pool_end = lay["base"] + n_vb * vb_sz
    for off in range(pool_end, FPKE_DFLASH_SIZE, 4):
        if word(off) != 0xFFFFFFFF:
            put(off)
    return mask


def normalize_fpke_dflash_for_faci(
    dflash: bytes,
    cflash: bytes | None = None,
) -> tuple[bytes, bytearray]:
    """Strip CPU-read floating-gate noise from erased EEL cells and return `(clean_dflash, faci_word_mask)`."""
    if len(dflash) != FPKE_DFLASH_SIZE:
        raise ValueError(f"Expected 65,536-byte FPK_E DataFlash, got {len(dflash)} bytes")
    lay = fpke_eel_layout(cflash, dflash)
    mask = eel_faci_word_mask(lay, dflash)
    clean = bytearray(dflash)
    for off in range(0, FPKE_DFLASH_SIZE, 4):
        if not any(mask[off : off + 4]):
            clean[off : off + 4] = b"\xff\xff\xff\xff"
    return bytes(clean), mask


def eel_parse_pool(
    lay: dict[str, Any],
    df: bytes,
    mask: bytearray | bytes | None = None,
) -> tuple[list[dict[str, Any]], dict[int, tuple[int, int, int]]]:
    """Parse EEL T01 virtual blocks and return `(blocks, latest_active_refs)`."""
    if mask is None:
        mask = eel_faci_word_mask(lay, df)

    def word(addr: int) -> int:
        return struct.unpack_from("<I", df, addr)[0]

    def written(addr: int) -> bool:
        return any(mask[addr : addr + 4])

    def mark(addr: int) -> bool:
        return written(addr) and word(addr) == EEL_MARK

    blocks: list[dict[str, Any]] = []
    block_refs: dict[int, list[tuple[int, int, int]]] = {}
    for n in range(lay["n_vb"]):
        b = lay["base"] + n * lay["vb"]
        i0, i1 = mark(b), mark(b + lay["vb"] - 4)
        ec = word(b + 0x10) if written(b + 0x10) else None
        state = (
            "invalid"
            if (i0 and i1)
            else "active"
            if mark(b + 8)
            else "prepared"
            if mark(b + 4)
            else "inconsistent"
        )
        if ec is not None and eel_cs24(ec) != ec:
            state = "inconsistent"
        rec: dict[str, Any] = {
            "vb": n,
            "state": state,
            "ec": None if ec is None else (ec & 0xFFFFFF),
            "refs": 0,
        }
        if state == "active":
            rwp = word(b + 0x14)
            rwp_ok = written(b + 0x14) and eel_cs24(rwp) == rwp
            rec["rwp_ok"] = rwp_ok
            rec["rwp"] = (rwp & 0xFFFFFF) if rwp_ok else None
            a = b + 0x18
            min_bottom = b + lay["vb"] - 4
            refs_in_block: list[tuple[int, int, int]] = []
            while a + 0x10 <= b + lay["vb"] - 4 and written(a):
                drp = word(a + 0x0C)
                if not (mark(a + 8) or mark(a + 4)):
                    break
                ident, widx = drp & 0xFFFF, (drp >> 16) & 0x7FFF
                if ident in lay["ids"] and widx > 0 and widx + 4 <= lay["vb"] - 4:
                    refs_in_block.append((ident, b + widx, a))
                    padded = (lay["ids"][ident] + 3) & ~3
                    bottom = b + widx - padded + 4
                    if bottom >= b + 0x18 and bottom < min_bottom:
                        min_bottom = bottom
                rec["refs"] += 1
                a += 0x10
            rec["separator"] = a - b
            rec["next_top"] = min_bottom - 4
            block_refs[n] = refs_in_block
        blocks.append(rec)

    active_nums = {b["vb"] for b in blocks if b["state"] == "active"}
    ring_start = 0
    if 0 in active_nums and (lay["n_vb"] - 1) in active_nums and len(active_nums) < lay["n_vb"]:
        for cand in sorted(active_nums):
            if ((cand - 1) % lay["n_vb"]) not in active_nums:
                ring_start = cand
                break

    def _active_order(blk: dict[str, Any]) -> tuple[int, int]:
        return (blk["ec"] or 0, (blk["vb"] - ring_start) % lay["n_vb"])

    latest: dict[int, tuple[int, int, int]] = {}
    for blk in sorted((b for b in blocks if b["state"] == "active"), key=_active_order):
        for ident, top_addr, ref_addr in block_refs.get(blk["vb"], ()):
            latest[ident] = (blk["vb"], top_addr, ref_addr)
    return blocks, latest


def _eel_record_bytes(lay: dict[str, Any], df: bytes, ident: int, top: int) -> bytes:
    size = lay["ids"][ident]
    padded = (size + 3) & ~3
    return b"".join(df[top - i : top - i + 4] for i in range(0, padded, 4))[:size]


def eel_read_record_any(lay: dict[str, Any], df: bytes, ident: int) -> tuple[bytes, dict[str, Any]]:
    """Read the latest FEE-size-valid instance of EEL `ident`, scanning historical VBs if needed."""
    blocks, latest = eel_parse_pool(lay, df)
    rejected_current: dict[str, Any] | None = None
    size = lay["ids"][ident]
    if ident in latest:
        vb, top, ref = latest[ident]
        padded = (size + 3) & ~3
        if top - padded + 4 >= lay["base"] + vb * lay["vb"] + 0x18:
            record = _eel_record_bytes(lay, df, ident, top)
            fee_ok = int.from_bytes(record[:2], "little") == size
            source: dict[str, Any] = {
                "generation": "current",
                "vb": vb,
                "top": top,
                "ref": ref,
                "state": blocks[vb]["state"],
                "ec": blocks[vb]["ec"],
                "fee_size_valid": fee_ok,
                "sha256": hashlib.sha256(record).hexdigest(),
            }
            if fee_ok:
                return record, source
            rejected_current = source

    active = [b for b in blocks if b["state"] == "active"]
    head = max(active, key=lambda b: (b["ec"] or 0, b["vb"]))["vb"] if active else 0
    padded = (size + 3) & ~3
    candidates: list[tuple[int, int, dict[str, Any], bytes]] = []
    for vb in range(lay["n_vb"]):
        base = lay["base"] + vb * lay["vb"]
        if int.from_bytes(df[base + 8 : base + 12], "little") != EEL_MARK:
            continue
        for ref in range(base + 0x18, base + lay["vb"] - 0x10, 0x10):
            drp = int.from_bytes(df[ref + 0x0C : ref + 0x10], "little")
            if (drp & 0xFFFF) != ident:
                continue
            top = base + ((drp >> 16) & 0x7FFF)
            bottom = top - padded + 4
            if top == base or top + 4 > base + lay["vb"] - 4:
                continue
            if bottom < base + 0x18 or ref + 0x10 > bottom:
                continue
            marker_errors = [
                (int.from_bytes(df[ref + off : ref + off + 4], "little") ^ EEL_MARK).bit_count()
                for off in (0, 4, 8)
            ]
            if marker_errors[0] > 4 or min(marker_errors[1:]) > 4:
                continue
            record = _eel_record_bytes(lay, df, ident, top)
            if int.from_bytes(record[:2], "little") != size:
                continue
            cand_src: dict[str, Any] = {
                "generation": "historical",
                "vb": vb,
                "top": top,
                "ref": ref,
                "state": blocks[vb]["state"],
                "ec": blocks[vb]["ec"],
                "fee_size_valid": True,
                "marker_bit_errors": marker_errors,
                "sha256": hashlib.sha256(record).hexdigest(),
            }
            candidates.append(((head - vb) % lay["n_vb"], -ref, cand_src, record))
    if not candidates:
        raise KeyError(ident)
    _rank, _neg_ref, chosen_src, chosen_rec = min(candidates, key=lambda c: c[:2])
    if rejected_current is not None:
        chosen_src["rejected_current"] = rejected_current
    return chosen_rec, chosen_src


def parse_fpke_transponders(r67: bytes | None, r6a: bytes | None) -> dict[str, Any]:
    """Decode transponder slots (`EEL 0x67`) and key queue (`EEL 0x6A`) per `audi-83a-immo-transfer.md` §4.3."""
    if r67 is None or len(r67) < 0x27:
        return {
            "EEL_0x67_present": False,
            "EEL_0x6A_present": r6a is not None,
            "allowed_keys": 0,
            "learned_keys": 0,
            "session_xor_flags": 0,
            "queue_count": 0,
            "queue_pending_mask": 0,
            "queue_flags": 0,
            "key_ids": [],
            "display_ids": [],
            "entries": [],
            "usable_key_data": False,
        }
    allowed = r67[0x22]
    learned_flags = r67[0x23]
    learned = learned_flags & 0x0F
    queue_count = r67[0x24]
    key_ids = []
    display_ids: list[str | None] = []
    for slot in range(8):
        raw = r67[2 + slot * 4 : 6 + slot * 4]
        present = raw != b"\xff" * 4
        within = slot < learned
        disp_u32 = f"{int.from_bytes(raw, 'little'):08X}" if present else None
        display_ids.append(disp_u32)
        state = "active" if (present and within) else ("outside_learned_count" if present else "empty")
        key_ids.append(
            {
                "slot": slot,
                "hex": raw.hex(),
                "display_id": disp_u32,
                "present": present,
                "within_learned_count": within,
                "state": state,
            }
        )
    entries = []
    if r6a is not None and len(r6a) >= 2 + 7 * 17:
        for slot in range(7):
            offset = 2 + slot * 17
            number = r6a[offset]
            raw = r6a[offset + 1 : offset + 17]
            valid_number = 1 <= number <= 8
            entries.append(
                {
                    "slot": slot,
                    "key_number": number,
                    "hex": raw.hex(),
                    "valid_key_number": valid_number,
                    "usable": valid_number and raw not in (b"\xff" * 16, b"\xaa" * 16),
                    "within_queue": slot < queue_count,
                }
            )
    return {
        "EEL_0x67_present": True,
        "EEL_0x6A_present": r6a is not None,
        "allowed_keys": allowed,
        "learned_keys": learned,
        "session_xor_flags": learned_flags >> 4,
        "queue_count": queue_count,
        "queue_pending_mask": r67[0x25],
        "queue_flags": r67[0x26],
        "key_ids": key_ids,
        "display_ids": display_ids,
        "entries": entries,
        "usable_key_data": any(e["usable"] for e in entries),
    }


def parse_fpke_immo_config(
    r66: bytes | None,
    r68: bytes | None,
    r6e: bytes | None = None,
) -> dict[str, Any]:
    """Decode immobilizer configuration, PowerClass (`r68[0x40]`), MAC4 (`r66[0x02:0x06]`), and 8 partner slots."""
    has_68 = r68 is not None and len(r68) >= 0x4E
    has_66 = r66 is not None and len(r66) >= 0x16
    cs_raw = r68[0x28:0x38] if (r68 is not None and len(r68) >= 0x38) else None
    cs_personalized = cs_raw is not None and cs_raw != b"\xff" * 16
    k_ffb_hex = fpke_derive_k_ffb(cs_raw).hex().upper() if (cs_personalized and cs_raw is not None) else ""
    power_class = r68[0x40] if (r68 is not None and len(r68) > 0x40) else None
    partners_mask = r68[0x41] if (r68 is not None and len(r68) > 0x41 and r68[0x41] != 0xFF) else 0
    lf_cfg = r68[0x42] if (r68 is not None and len(r68) > 0x42) else None
    immo_flags = r68[0x44] if (r68 is not None and len(r68) > 0x44) else None
    lockouts = list(r68[0x45:0x4B]) if (r68 is not None and len(r68) >= 0x4B) else []
    immo_mode = r68[0x4B] if (r68 is not None and len(r68) > 0x4B and r68[0x4B] != 0xFF) else None
    identity_cnt = r68[0x4C] if (r68 is not None and len(r68) > 0x4C and r68[0x4C] != 0xFF) else None
    key_transport = r68[0x4D] if (r68 is not None and len(r68) > 0x4D and r68[0x4D] != 0xFF) else None
    status_5b = (
        bytes([r68[4], r68[3], r68[2], r68[0x40], r68[5]]).hex().upper()
        if (r68 is not None and len(r68) > 0x40)
        else ""
    )

    def _pair_hex(buf: bytes | None, off: int) -> str:
        if buf is None or len(buf) < off + 2:
            return ""
        raw_p = buf[off : off + 2]
        return "" if raw_p == b"\xff\xff" else raw_p.hex().upper()

    cluster_mac_id = _pair_hex(r66, 0x02)
    mac_ecu = _pair_hex(r66, 0x04)
    mac_elv = _pair_hex(r66, 0x0C)
    mac_tcu = _pair_hex(r66, 0x0E)
    mac4 = (
        r66[0x02:0x06].hex().upper()
        if (r66 is not None and len(r66) >= 0x06 and r66[0x02:0x06] != b"\xff\xff\xff\xff")
        else ""
    )
    learning_mask = r66[0x10] if (has_66 and r66[0x10] != 0xFF) else 0

    partners: list[dict[str, Any]] = []
    adapted_codes: list[str] = []
    for p_idx, code, r66_off, did_off, can_rx, can_tx, grp, lbl_ru, lbl_en in FPKE_IMMO_PARTNERS:
        adapted = bool(partners_mask & (1 << p_idx))
        learning = bool(learning_mask & (1 << p_idx))
        id_hex = _pair_hex(r66, r66_off)
        if adapted:
            adapted_codes.append(code)
        partners.append(
            {
                "index": p_idx,
                "code": code,
                "label_ru": lbl_ru,
                "label_en": lbl_en,
                "adapted": adapted,
                "learning": learning,
                "mac_id_hex": id_hex,
                "r66_offset": r66_off,
                "did_02ee_offset": did_off,
                "can_rx": f"0x{can_rx:03X}",
                "can_tx": f"0x{can_tx:03X}",
                "group": grp,
            }
        )

    pc_valid = power_class is not None and (power_class != 0xFF or cs_personalized or immo_mode is not None)
    return {
        "EEL_0x68_present": has_68,
        "EEL_0x66_present": has_66,
        "personalized": cs_personalized,
        "k_ffb_hex": k_ffb_hex,
        "power_class": power_class if pc_valid else None,
        "power_class_hex": f"0x{power_class:02X}" if pc_valid and power_class is not None else None,
        "power_class_byte": f"{power_class:02X}" if pc_valid and power_class is not None else None,
        "status_5b": status_5b,
        "brand_id": 0x03,
        "immo_mode": immo_mode,
        "identity_counter": identity_cnt,
        "key_transport_raw": key_transport,
        "key_over_can": bool(key_transport & 0x80) if key_transport is not None else False,
        "restart_window_disabled": bool(key_transport & 0x40) if key_transport is not None else False,
        "lf_reader_config": lf_cfg if (lf_cfg is not None and lf_cfg != 0xFF) else None,
        "immo_flags": immo_flags if (immo_flags is not None and immo_flags != 0xFF) else None,
        "s0_s1_stored_in_0x69": bool(immo_flags & 0x01) if (immo_flags is not None and immo_flags != 0xFF) else False,
        "cp_deferred": bool(immo_flags & 0x02) if (immo_flags is not None and immo_flags != 0xFF) else False,
        "lockout_counters": lockouts,
        "lock_mode_0x6e": r6e[0x02:0x04].hex().upper() if (r6e is not None and len(r6e) >= 4) else "",
        "cluster_mac_id": cluster_mac_id,
        "mac4": mac4,
        "mac_fields": {
            "dash": cluster_mac_id or None,
            "ecu": mac_ecu or None,
            "elv": mac_elv or None,
            "tcu": mac_tcu or None,
        },
        "partners_mask": partners_mask,
        "partners_mask_hex": f"0x{partners_mask:02X}",
        "learning_partners_mask": learning_mask,
        "adapted_partner_codes": adapted_codes,
        "partners": partners,
    }


def decode_fpke_02ed(raw: bytes) -> dict[str, Any]:
    """Decode UDS `DID 0x02ED` (`MAS00077 State of Immobilizer`, 10 bytes, `STRUC_DataRecorImmobDataStateOfImmob`)."""
    life_state = raw[0] if len(raw) > 0 else 0
    identity_cnt = raw[1] if len(raw) > 1 else 0
    brand_id = raw[2] if len(raw) > 2 else 0
    power_class = raw[3] if len(raw) > 3 else None
    learned = raw[4] if len(raw) > 4 else 0
    rem_dl = raw[5] if len(raw) > 5 else 0
    rem_alt = raw[6] if len(raw) > 6 else 0
    cfg_status = raw[8] if len(raw) > 8 else 0
    return {
        "raw_hex": raw.hex().upper(),
        "life_state": life_state,
        "identity_counter": identity_cnt,
        "brand_id": brand_id,
        "power_class": power_class,
        "power_class_hex": f"0x{power_class:02X}" if power_class is not None else None,
        "learned_keys": learned,
        "remaining_keys": rem_dl if rem_dl else rem_alt,
        "config_status": cfg_status,
        "keyless_coded": bool(cfg_status & 0x01),
        "restart_window_disabled": bool(cfg_status & 0x02),
    }


def decode_fpke_02ee(raw: bytes) -> dict[str, Any]:
    """Decode UDS `DID 0x02EE` (`MAS06788 State of Immobilizer Slaves`, 10 bytes)."""
    partners: list[dict[str, Any]] = []
    for p_idx, code, _r66_off, did_off, _rx, _tx, _grp, lbl_ru, lbl_en in FPKE_IMMO_PARTNERS:
        val = raw[did_off] if len(raw) > did_off else 0
        partners.append(
            {
                "index": p_idx,
                "code": code,
                "label_ru": lbl_ru,
                "label_en": lbl_en,
                "status_byte": val,
                "id_known": bool(val & 0x01),
                "adapted": bool(val & 0x02),
                "mac_verified": bool(val & 0x04),
                "response_sent": bool(val & 0x08),
            }
        )
    return {
        "raw_hex": raw.hex().upper(),
        "s0_s1_present": raw[0] if len(raw) > 0 else 0,
        "slots_a_b_loaded": raw[1] if len(raw) > 1 else 0,
        "partners": partners,
    }


def vote_fpke_odometer(r60: bytes | None, r35: bytes | None = None) -> dict[str, Any]:
    """Decode `EEL 0x60` (`3 x u32` of `km // 2`, 2-of-3 vote @ `0x0D3376`/`0xDDA12`) and `EEL 0x35` status."""
    err_code = r35[2] if (r35 is not None and len(r35) >= 4 and r35[2] != 0xFF) else 0
    repairs = r35[3] if (r35 is not None and len(r35) >= 4 and r35[3] != 0xFF) else 0
    if r60 is None or len(r60) < 16:
        return {
            "present": False,
            "odometer_km": None,
            "copies_km": [],
            "unanimous": False,
            "error_code": err_code,
            "repair_count": repairs,
        }
    c0, c1, c2 = struct.unpack_from("<3I", r60, 4)
    copies_km = [c * 2 if c < 500_000 else None for c in (c0, c1, c2)]
    voted_half: int | None = None
    unanimous = False
    if c0 == c1 == c2 and c0 < 500_000:
        voted_half = c0
        unanimous = True
    elif c0 == c1 and c0 < 500_000:
        voted_half = c0
    elif c0 == c2 and c0 < 500_000:
        voted_half = c0
    elif c1 == c2 and c1 < 500_000:
        voted_half = c1
    else:
        valid = [c for c in (c0, c1, c2) if c < 500_000]
        if valid:
            voted_half = valid[0]
    return {
        "present": voted_half is not None,
        "odometer_km": voted_half * 2 if voted_half is not None else None,
        "copies_km": copies_km,
        "unanimous": unanimous,
        "error_code": err_code,
        "repair_count": repairs,
    }


def _crc32_le_ok(data_16: bytes, expected_4: bytes) -> bool:
    return struct.pack("<I", zlib.crc32(data_16) & 0xFFFFFFFF) == expected_4


def _clean_ascii(raw: bytes) -> str:
    txt = "".join(chr(b) for b in raw if 32 <= b < 127).strip()
    return txt


def analyze_fpke_dflash(dflash: bytes, cflash: bytes | None = None) -> dict[str, Any]:
    """Parse FPK_E 64 KiB DataFlash: EEL pool statistics, cluster metadata, PowerClass, CP/IKA, K_c, FD11, and keys."""
    if len(dflash) != FPKE_DFLASH_SIZE:
        raise ValueError(f"Expected 65,536-byte FPK_E DataFlash, got {len(dflash)} bytes")
    lay = fpke_eel_layout(cflash, dflash)
    blocks, latest = eel_parse_pool(lay, dflash)
    state_counts: dict[str, int] = {"active": 0, "prepared": 0, "invalid": 0, "inconsistent": 0}
    for b in blocks:
        state_counts[b["state"]] = state_counts.get(b["state"], 0) + 1

    records: dict[int, bytes] = {}
    sources: dict[str, dict[str, Any]] = {}
    missing_ids: list[str] = []
    for ident in (0x30, 0x31, 0x35, 0x45, 0x46, 0x60, 0x61, 0x62, 0x63, 0x64, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E):
        if ident not in lay["ids"]:
            continue
        try:
            rec, src = eel_read_record_any(lay, dflash, ident)
            records[ident] = rec
            sources[f"0x{ident:02X}"] = src
        except KeyError:
            if ident in (0x63, 0x64, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D):
                missing_ids.append(f"0x{ident:02X}")

    items: list[dict[str, Any]] = []
    fd11_id = ""
    if 0x63 in records and len(records[0x63]) >= 0x52:
        r63 = records[0x63]
        fd11_id = r63[2:17].hex()
        items.append(
            {
                "key_id": "fd11_l0_6",
                "name": "FD11 vendor levels 0..6",
                "hex": r63[0x16:0x26].hex(),
                "role": "FD11 AES-128 key (levels 0..6)",
                "crc_valid": _crc32_le_ok(r63[0x16:0x26], r63[0x26:0x2A]),
            }
        )
        items.append(
            {
                "key_id": "fd11_l7",
                "name": "FD11 vendor level 7",
                "hex": r63[0x2A:0x3A].hex(),
                "role": "FD11 AES-128 key (level 7)",
                "crc_valid": _crc32_le_ok(r63[0x2A:0x3A], r63[0x3A:0x3E]),
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
    if 0x6B in records and len(records[0x6B]) >= 0x52:
        r6b = records[0x6B]
        items.append(
            {
                "key_id": "ika_cp3",
                "name": "IKA / CP working key /3",
                "hex": r6b[0x02:0x12].hex(),
                "role": "Component protection individual working key (EEL 0x6B+0x02)",
                "crc_valid": None,
            }
        )
        for idx in range(4):
            raw = r6b[0x12 + idx * 16 : 0x22 + idx * 16]
            role = (
                "Component protection slot 1 / channel 3 node 0x0E"
                if idx == 0
                else "Additional CP key-bank material"
            )
            items.append(
                {
                    "key_id": f"cp1_bank_{idx}",
                    "name": f"CP /1 bank {idx}",
                    "hex": raw.hex(),
                    "role": role,
                    "crc_valid": None,
                }
            )
    if 0x63 in records and len(records[0x63]) >= 0x52:
        r63 = records[0x63]
        items.append(
            {
                "key_id": "aux_63_3e",
                "name": "FD11 auxiliary field 0x63+0x3E",
                "hex": r63[0x3E:0x4E].hex(),
                "role": "CRC-valid auxiliary field",
                "crc_valid": _crc32_le_ok(r63[0x3E:0x4E], r63[0x4E:0x52]),
            }
        )
    if 0x64 in records and len(records[0x64]) >= 0x16:
        r64 = records[0x64]
        items.append(
            {
                "key_id": "aux_64_02",
                "name": "CRC-valid field 0x64+0x02",
                "hex": r64[0x02:0x12].hex(),
                "role": "CRC-valid auxiliary field",
                "crc_valid": _crc32_le_ok(r64[0x02:0x12], r64[0x12:0x16]),
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
            rec = _eel_record_bytes(lay, dflash, ident, top)
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

    immo_cfg = parse_fpke_immo_config(records.get(0x66), records.get(0x68), records.get(0x6E))
    odo_info = vote_fpke_odometer(records.get(0x60), records.get(0x35))

    # Metadata from EEL 0x30 (coding), 0x45 (part number), 0x46 (dataset), 0x60 (odometer backup), 0x68 (VIN, PowerClass & immo mode)
    meta: dict[str, Any] = {}
    if 0x68 in records and len(records[0x68]) >= 0x28:
        vin_raw = records[0x68][0x17:0x28]  # 17 bytes @ 0xFEDF52CD (DID 0xF190)
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
    if 0x45 in records and len(records[0x45]) >= 49:
        pn = _clean_ascii(records[0x45][37:49])
        if pn:
            meta["part_number"] = pn
        sw_tag = _clean_ascii(records[0x45][2:6])
        if sw_tag.isdigit():
            meta["sw_version_eel"] = sw_tag
    if 0x46 in records and len(records[0x46]) >= 23:
        ds_pn = _clean_ascii(records[0x46][11:22])
        if ds_pn:
            meta["dataset_pn"] = ds_pn
    if 0x30 in records and len(records[0x30]) >= 31:
        meta["coding_hex"] = records[0x30][11:31].hex().upper()
    if odo_info["odometer_km"] is not None:
        meta["odometer_km"] = odo_info["odometer_km"]
        meta["odometer_unanimous"] = odo_info["unanimous"]
        meta["odometer_repair_count"] = odo_info["repair_count"]

    secret_sources = {k: v for k, v in sources.items() if int(k, 16) >= 0x63}
    return {
        "sha256": hashlib.sha256(dflash).hexdigest(),
        "pool": {
            "virtual_blocks": lay["n_vb"],
            "vb_size": lay["vb"],
            "states": state_counts,
            "active_ids": len(latest),
            "total_ids": len(lay["ids"]),
        },
        "metadata": meta,
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


# ─────────────── Read-Only Immo 4.0 Exporter, Comparator & A->B Planner ───────────────


def extract_fpke_immo_passport(
    dflash: bytes,
    cflash: bytes | None = None,
) -> dict[str, Any]:
    """Build the verified read-only ContiTool Immo 4.0 JSON container (`audi-83a-immo-transfer.md` §4, §5, §8, §9, §11).

    - Uses `eel_read_record_any()` with FEE-size validation and historical VB fallback.
    - Preserves `record_sources` and SHA-256 of each logical EEL record (`0x66`, `0x67`, `0x68`, `0x69`, `0x6A`, `0x6E`).
    - Explicitly distinguishes `present`, `empty` (`FF…`), `missing`, and `corrupted` values.
    - Keeps Component Protection (`0x6B..0x6D`) and Odometer (`0x60`, `0x35`) strictly separate from the Immo form.
    - Performs zero write operations.
    """
    info = analyze_fpke_dflash(dflash, cflash)
    lay = fpke_eel_layout(cflash, dflash)

    raw_recs: dict[int, bytes] = {}
    rec_sources: dict[str, dict[str, Any]] = {}
    for ident in (0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E):
        if ident not in lay["ids"]:
            continue
        with contextlib.suppress(KeyError):
            rec, src = eel_read_record_any(lay, dflash, ident)
            raw_recs[ident] = rec
            rec_sources[f"0x{ident:02X}"] = src

    r66 = raw_recs.get(0x66)
    r67 = raw_recs.get(0x67)
    r68 = raw_recs.get(0x68)
    r69 = raw_recs.get(0x69)
    r6a = raw_recs.get(0x6A)
    r6e = raw_recs.get(0x6E)

    # VIN classification: present (valid 17-char ASCII [A-Z0-9]), empty (FF/00/'-'), corrupted, or missing
    vin_val: str | None = None
    vin_state = "missing"
    if r68 is not None and len(r68) >= 0x28:
        vin_bytes = r68[0x17:0x28]
        if vin_bytes in (b"\xff" * 17, b"\x00" * 17, b"-" * 17):
            vin_state = "empty"
        else:
            ascii_ok = all((48 <= b <= 57) or (65 <= b <= 90) for b in vin_bytes)
            if ascii_ok:
                vin_val = vin_bytes.decode("ascii")
                vin_state = "present"
            else:
                vin_state = "corrupted"

    # CS / K_c classification
    cs_val: str | None = None
    cs_state = "missing"
    if r68 is not None and len(r68) >= 0x38:
        cs_bytes = r68[0x28:0x38]
        if cs_bytes == b"\xff" * 16:
            cs_state = "empty"
        else:
            cs_val = cs_bytes.hex().upper()
            cs_state = "present"

    # VDO CS+ (CRC32_A_LE || CRC32_B_LE)
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

    # S0/S1 state (§8: S0/S1=FF... is normal in mode 1; only populated during key learning)
    s0_hex = r69[0x02:0x12].hex().upper() if (r69 is not None and len(r69) >= 0x12) else None
    s1_hex = r69[0x12:0x22].hex().upper() if (r69 is not None and len(r69) >= 0x22) else None
    if r69 is None:
        s0_s1_state = "missing"
    elif s0_hex == "FF" * 16 and s1_hex == "FF" * 16:
        s0_s1_state = "empty_expected_in_mode_1" if immo_cfg.get("immo_mode") == 1 else "empty"
    else:
        s0_s1_state = "present"

    platform = "RH850-FPKE-83A" if len(lay["ids"]) > 162 else "RH850-FPKE-1703"
    return {
        "schema": "contitool.fpke.immo_passport.v1",
        "read_only": True,
        "platform": platform,
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
            **info["component_protection_state"],
        },
        "cluster_metadata": dict(info["metadata"]),
    }


def compare_fpke_immo_passports(
    first: dict[str, Any] | bytes,
    second: dict[str, Any] | bytes,
    *,
    cflash_first: bytes | None = None,
    cflash_second: bytes | None = None,
) -> dict[str, Any]:
    """Compare two DFlash dumps or exported Immo passports by semantic Immo fields (`audi-83a-immo-transfer.md` §6.3, §11).

    Does NOT require the full raw 64 KiB DFlash images or physical EEL `vb/top/ref` offsets to be equal.
    """
    p1 = extract_fpke_immo_passport(first, cflash_first) if isinstance(first, (bytes, bytearray)) else first
    p2 = extract_fpke_immo_passport(second, cflash_second) if isinstance(second, (bytes, bytearray)) else second
    im1, im2 = p1["immo"], p2["immo"]
    c1, c2 = im1["counts"], im2["counts"]
    mf1, mf2 = im1["mode_and_flags"], im2["mode_and_flags"]

    checks: dict[str, bool] = {
        "vin": im1["vin"] == im2["vin"] and im1["vin_state"] == im2["vin_state"],
        "cs": im1["cs"] == im2["cs"] and im1["cs_state"] == im2["cs_state"],
        "vdo_cs_plus": im1["vdo_cs_plus"] == im2["vdo_cs_plus"],
        "power_class": im1["power_class"] == im2["power_class"],
        "mac_fields": im1["mac_fields"] == im2["mac_fields"],
        "mac4": im1["mac4"] == im2["mac4"],
        "keys": im1["keys"] == im2["keys"],
        "allowed_keys": c1["allowed_keys"] == c2["allowed_keys"],
        "learned_keys": c1["learned_keys"] == c2["learned_keys"],
        "session_xor_flags": c1["session_xor_flags"] == c2["session_xor_flags"],
        "immo_mode": mf1["immo_mode"] == mf2["immo_mode"],
        "partners_mask": mf1["partners_mask"] == mf2["partners_mask"],
        "key_over_can": mf1["key_over_can"] == mf2["key_over_can"],
    }
    src1_68 = (p1.get("record_sources") or {}).get("0x68") or {}
    src2_68 = (p2.get("record_sources") or {}).get("0x68") or {}
    r68_sha_equal = bool(src1_68.get("sha256") and src1_68.get("sha256") == src2_68.get("sha256"))
    mismatches = [k for k, ok in checks.items() if not ok]
    return {
        "semantic_match": len(mismatches) == 0,
        "mismatched_fields": mismatches,
        "field_checks": checks,
        "r68_sha256_equal": r68_sha_equal,
        "dflash_sha256_equal": p1.get("dflash_sha256") == p2.get("dflash_sha256"),
        "physical_vb_differs": (src1_68.get("vb"), src1_68.get("top")) != (src2_68.get("vb"), src2_68.get("top")),
    }


def plan_fpke_a_to_b_transfer(
    donor_dflash: bytes,
    recipient_dflash: bytes,
    *,
    donor_cflash: bytes | None = None,
    recipient_cflash: bytes | None = None,
) -> dict[str, Any]:
    """Build a static, read-only Donor A -> Recipient B transfer plan per `audi-83a-immo-transfer.md` §7–§12.

    Separates:
    - `transfer_from_a`: semantic Immo fields (`VIN`, `CS`/`K_c`, `CRC A/B`, `PowerClass`, `MAC DASH/ECU/ELV/TCU`, 8 key IDs & counters);
    - `preserve_on_b`: Recipient B's own coding (`0x30`), hardware/part number (`0x45`), dataset (`0x46`), current `K_c` on B, and FD11 keys (`0x63`);
    - `component_protection`: separate CP assessment (`0x6B..0x6D`) per §9;
    - `odometer`: Donor A vs Recipient B mileage (`0x60`, `0x35`).
    Performs zero writes and never clones raw DFlash.
    """
    donor = extract_fpke_immo_passport(donor_dflash, donor_cflash)
    recipient = extract_fpke_immo_passport(recipient_dflash, recipient_cflash)
    im_a = donor["immo"]
    im_b = recipient["immo"]
    meta_a = donor["cluster_metadata"]
    meta_b = recipient["cluster_metadata"]

    warnings: list[str] = []
    if not im_a["personalized"]:
        warnings.append("Donor A is not personalized (CS is empty FF*16)")
    if im_a["vin_state"] != "present":
        warnings.append(f"Donor A VIN state is {im_a['vin_state']}")
    if im_a["s0_s1"]["state"] != "present":
        warnings.append(
            "Donor A S0/S1 (0x69) is empty (normal in mode 1): do not invoke UDS 02F7 with stub/FF S0/S1"
        )

    return {
        "schema": "contitool.fpke.transfer_plan.v1",
        "read_only": True,
        "raw_dflash_clone_prohibited": True,
        "donor_a": {
            "dflash_sha256": donor["dflash_sha256"],
            "platform": donor["platform"],
            "part_number": meta_a.get("part_number"),
            "personalized": im_a["personalized"],
        },
        "recipient_b": {
            "dflash_sha256": recipient["dflash_sha256"],
            "platform": recipient["platform"],
            "part_number": meta_b.get("part_number"),
            "personalized": im_b["personalized"],
            "current_kc_on_b": im_b["cs"],
        },
        "transfer_from_a": {
            "vin": im_a["vin"],
            "cs": im_a["cs"],
            "k_ffb": im_a["k_ffb"],
            "vdo_cs_plus": im_a["vdo_cs_plus"],
            "crc32_a_le": im_a["crc32_a_le"],
            "crc32_b_le": im_a["crc32_b_le"],
            "power_class": im_a["power_class"],
            "power_class_hex": im_a["power_class_hex"],
            "mac_fields": dict(im_a["mac_fields"]),
            "mac4": im_a["mac4"],
            "keys": list(im_a["keys"]),
            "counts": dict(im_a["counts"]),
            "partners_mask_hex": im_a["mode_and_flags"]["partners_mask_hex"],
            "adapted_partner_codes": list(im_a["mode_and_flags"]["adapted_partner_codes"]),
            "immo_mode": im_a["mode_and_flags"]["immo_mode"],
            "key_over_can": im_a["mode_and_flags"]["key_over_can"],
            "lf_reader_config": im_a["mode_and_flags"]["lf_reader_config"],
        },
        "preserve_on_b": {
            "part_number": meta_b.get("part_number"),
            "sw_version_eel": meta_b.get("sw_version_eel"),
            "dataset_pn": meta_b.get("dataset_pn"),
            "coding_hex": meta_b.get("coding_hex"),
            "odometer_km_on_b": meta_b.get("odometer_km"),
            "current_kc_on_b": im_b["cs"],
        },
        "odometer_sync": {
            "donor_a_km": meta_a.get("odometer_km"),
            "recipient_b_km": meta_b.get("odometer_km"),
            "eel_id": "0x60",
        },
        "component_protection_separate": {
            "donor_a": donor["component_protection_separate"],
            "recipient_b": recipient["component_protection_separate"],
        },
        "s0_s1_and_0x6a_policy": {
            "donor_s0_s1_state": im_a["s0_s1"]["state"],
            "donor_0x6a_usable": im_a["key_queue_0x6a"]["usable_key_data"],
            "allow_02f7_with_stub_s0_s1": False,
        },
        "warnings": warnings,
    }


# ─────────────── EEL T01 Journaled Record Writer & Non-Destructive Dump Editor ───────────────


def _parse_exact_hex(val: str, byte_len: int, field_name: str, *, allow_empty: bool = True) -> bytes:
    cleaned = "".join(val.split()).replace("0x", "").replace("0X", "")
    if not cleaned or cleaned in ("—", "-"):
        if allow_empty:
            return b"\xff" * byte_len
        raise ValueError(f"{field_name}: expected {byte_len * 2} hex digits")
    if len(cleaned) != byte_len * 2:
        raise ValueError(f"{field_name}: expected {byte_len * 2} hex digits ({byte_len} bytes), got {len(cleaned)}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{field_name}: invalid hex string '{val}'") from exc


def eel_append_records(
    dflash: bytes,
    updates: dict[int, bytes],
    cflash: bytes | None = None,
) -> bytes:
    """Append updated EEL T01 records into a 64 KiB FPK_E DataFlash image (`ac-eel.md` §2.3–2.4).

    - Writes only changed logical records into the active head virtual block (or activates the next
      virtual block in ring order when the head VB is full).
    - Enforces the 2-byte FEE length header `struct.pack('<H', size)` at `rec[0:2]`.
    - Verifies that every written record reads back as `generation == 'current'` via `eel_read_record_any()`.
    """
    if len(dflash) != FPKE_DFLASH_SIZE:
        raise ValueError(f"Expected 65,536-byte FPK_E DataFlash, got {len(dflash)} bytes")
    if not updates:
        return bytes(dflash)

    lay = fpke_eel_layout(cflash, dflash)
    df = bytearray(dflash)
    pending: list[tuple[int, bytes]] = []
    for ident, raw_rec in updates.items():
        if ident not in lay["ids"]:
            raise KeyError(f"EEL ID 0x{ident:02X} is not defined in layout")
        size = lay["ids"][ident]
        if len(raw_rec) != size:
            raise ValueError(f"EEL 0x{ident:02X} record must be {size} bytes, got {len(raw_rec)}")
        norm_rec = struct.pack("<H", size) + bytes(raw_rec[2:])
        with contextlib.suppress(KeyError):
            cur_rec, cur_src = eel_read_record_any(lay, bytes(df), ident)
            if cur_src.get("generation") == "current" and cur_rec == norm_rec:
                continue
        pending.append((ident, norm_rec))

    if not pending:
        return bytes(df)

    for ident, rec in pending:
        size = lay["ids"][ident]
        padded = (size + 3) & ~3
        faci_mask = eel_faci_word_mask(lay, bytes(df))
        blocks, _ = eel_parse_pool(lay, bytes(df), faci_mask)
        active_nums = {b["vb"] for b in blocks if b["state"] == "active"}
        ring_start = 0
        if 0 in active_nums and (lay["n_vb"] - 1) in active_nums and len(active_nums) < lay["n_vb"]:
            for cand in sorted(active_nums):
                if ((cand - 1) % lay["n_vb"]) not in active_nums:
                    ring_start = cand
                    break

        active_sorted = sorted(
            (b for b in blocks if b["state"] == "active"),
            key=lambda blk: (blk["ec"] or 0, (blk["vb"] - ring_start) % lay["n_vb"]),
        )
        if not active_sorted:
            raise RuntimeError("No active EEL virtual blocks found in DataFlash pool")
        head = active_sorted[-1]
        b_addr = lay["base"] + head["vb"] * lay["vb"]
        ref_addr = b_addr + int(head.get("separator", 0x18))
        next_top = int(head.get("next_top", b_addr + lay["vb"] - 8))

        # Leave at least one clean 4-byte separator word (`ref_addr + 0x10 .. ref_addr + 0x13`) between refs and data.
        # Check `faci_mask` rather than raw `0xFF` bytes so CPU-read (`UDS 0x23`) dumps with floating-gate residue in
        # erased RV40F DataFlash cells still append inside `VB_head` without false rollover.
        fits = (
            ref_addr + 0x14 <= next_top - padded + 4
            and not any(faci_mask[ref_addr : ref_addr + 0x14])
            and not any(faci_mask[next_top - padded + 4 : next_top + 4])
        )
        if not fits:
            next_vb = (head["vb"] + 1) % lay["n_vb"]
            if blocks[next_vb]["state"] == "active":
                raise RuntimeError(f"EEL pool full: next virtual block VB {next_vb} is already active")
            remaining_free = sum(
                1 for blk in blocks if blk["vb"] != next_vb and blk["state"] in ("prepared", "invalid")
            )
            if remaining_free < 1:
                raise RuntimeError(
                    "EEL pool exhausted: at least one prepared/invalidated virtual block must remain free for R_EEL_Startup"
                )
            nb = lay["base"] + next_vb * lay["vb"]
            old_sep = ref_addr  # full DataFlash pool byte offset of previous head's separator (`0x14D10A`)
            df[old_sep : old_sep + 4] = b"\xff\xff\xff\xff"
            expected_ec = (head["ec"] or 1) + (1 if next_vb == 0 else 0)
            if (
                blocks[next_vb]["state"] == "prepared"
                and (blocks[next_vb]["ec"] or 0) == expected_ec
                and not any(faci_mask[nb + 0x18 : nb + lay["vb"] - 4])
            ):
                df[nb] = 0xFF
                df[nb : nb + 4] = b"\xff\xff\xff\xff"
                df[nb + 0x18 : nb + lay["vb"]] = b"\xff" * (lay["vb"] - 0x18)
                struct.pack_into("<I", df, nb + 0x08, EEL_MARK)
                struct.pack_into("<I", df, nb + 0x14, eel_cs24(old_sep))
                struct.pack_into("<I", df, nb + 0x0C, EEL_MARK)
            else:
                df[nb : nb + lay["vb"]] = b"\xff" * lay["vb"]
                struct.pack_into(
                    "<5I",
                    df,
                    nb,
                    0xFFFFFFFF,
                    EEL_MARK,
                    EEL_MARK,
                    EEL_MARK,
                    eel_cs24(expected_ec),
                )
                struct.pack_into("<I", df, nb + 0x14, eel_cs24(old_sep))
            b_addr = nb
            ref_addr = nb + 0x18
            next_top = nb + lay["vb"] - 8

        padded_bytes = rec + b"\xff" * (padded - size)
        for i in range(0, padded, 4):
            df[next_top - i : next_top - i + 4] = padded_bytes[i : i + 4]
        widx = next_top - b_addr
        drp = (ident & 0xFFFF) | ((widx & 0x7FFF) << 16)
        struct.pack_into("<4I", df, ref_addr, EEL_MARK, EEL_MARK, EEL_MARK, drp)
        df[ref_addr + 0x10 : ref_addr + 0x14] = b"\xff\xff\xff\xff"

    out_bytes = bytes(df)
    for ident, expected_rec in pending:
        read_back, src = eel_read_record_any(lay, out_bytes, ident)
        if src.get("generation") != "current" or read_back != expected_rec:
            raise RuntimeError(f"Post-write verification failed for EEL 0x{ident:02X}")
    return out_bytes


def apply_fpke_dflash_edits(
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
    cflash: bytes | None = None,
) -> bytes:
    """Selectively update semantic fields in a 64 KiB FPK_E DataFlash image via EEL T01 append.

    Never overwrites unrelated bytes inside `EEL 0x68`, `0x66`, `0x67`, `0x6B`, `0x6D`, `0x60`, or `0x30`.
    """
    lay = fpke_eel_layout(cflash, dflash)

    def _base_record(ident: int) -> bytearray:
        size = lay["ids"][ident]
        with contextlib.suppress(KeyError):
            rec, _src = eel_read_record_any(lay, dflash, ident)
            return bytearray(rec)
        buf = bytearray(b"\xff" * size)
        buf[:2] = struct.pack("<H", size)
        return buf

    updates: dict[int, bytes] = {}

    # 1. EEL 0x68 (VIN, CS/Kc, CRC A/B, PowerClass, partners_mask, immo_mode, key_over_can)
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
                pc_val = 0xFF if not pc_s or pc_s == "—" else int(pc_s, 16)
            else:
                pc_val = int(power_class)
            if not (0 <= pc_val <= 0xFF):
                raise ValueError("PowerClass must be in range 0x00..0xFF")
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

    # 2. EEL 0x66 (Cluster WFS MAC + Partner MAC IDs)
    if mac_dash_hex is not None or partner_macs is not None:
        r66 = _base_record(0x66)
        if mac_dash_hex is not None:
            r66[0x02:0x04] = _parse_exact_hex(mac_dash_hex, 2, "MAC DASH")
        if partner_macs is not None:
            alias_map = {
                "ECU": "MSG_1",
                "TCU": "GSG",
                "ELV": "ELV",
            }
            off_by_code = {code: r66_off for _idx, code, r66_off, *_rest in FPKE_IMMO_PARTNERS}
            for k_code, hex_val in partner_macs.items():
                norm_code = alias_map.get(k_code.upper(), k_code.upper())
                if norm_code not in off_by_code:
                    continue
                off = off_by_code[norm_code]
                r66[off : off + 2] = _parse_exact_hex(hex_val, 2, f"MAC {norm_code}")
        if r66[0x10:0x12] == b"\xff\xff":
            r66[0x10:0x12] = b"\x00\x00"
        updates[0x66] = bytes(r66)

    # 3. EEL 0x67 (Transponder key table & counters)
    if any(x is not None for x in (key_display_ids, allowed_keys, learned_keys, session_xor_flags)):
        r67 = _base_record(0x67)
        if key_display_ids is not None:
            if len(key_display_ids) > 8:
                raise ValueError("Up to 8 transponder key slots are supported")
            for slot in range(8):
                disp = key_display_ids[slot] if slot < len(key_display_ids) else None
                cleaned = (disp or "").strip().replace(" ", "").replace("0x", "").replace("0X", "").upper()
                if not cleaned or cleaned in ("—", "-", "FFFFFFFF"):
                    r67[2 + slot * 4 : 6 + slot * 4] = b"\xff\xff\xff\xff"
                else:
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
                        raise ValueError(f"Key {slot + 1}: invalid hex '{disp}'") from exc
                    r67[2 + slot * 4 : 6 + slot * 4] = val_u32.to_bytes(4, "little")
        if allowed_keys is not None:
            r67[0x22] = max(0, min(8, int(allowed_keys)))
        cur_lf = 0x20 if r67[0x23] == 0xFF else r67[0x23]
        cur_learned = cur_lf & 0x0F
        cur_xor = (cur_lf >> 4) & 0x0F
        if learned_keys is not None:
            cur_learned = max(0, min(8, int(learned_keys)))
        if session_xor_flags is not None:
            cur_xor = int(session_xor_flags) & 0x0F
        r67[0x23] = (cur_xor << 4) | cur_learned
        if r67[0x24] == 0xFF:
            r67[0x24] = cur_learned
        updates[0x67] = bytes(r67)

    # 3b. EEL 0x69 (Temporary slot secret S0 / S1)
    if slot_s0_hex is not None or slot_s1_hex is not None:
        r69 = _base_record(0x69)
        if slot_s0_hex is not None:
            r69[0x02:0x12] = _parse_exact_hex(slot_s0_hex, 16, "Slot S0 (0x69)")
        if slot_s1_hex is not None:
            r69[0x12:0x22] = _parse_exact_hex(slot_s1_hex, 16, "Slot S1 (0x69)")
        updates[0x69] = bytes(r69)

    # 4. EEL 0x6B & 0x6D (Component Protection keys & adaptation status)
    if ika_key_hex is not None or gfa_key_hex is not None:
        r6b = _base_record(0x6B)
        if ika_key_hex is not None:
            r6b[0x02:0x12] = _parse_exact_hex(ika_key_hex, 16, "IKA (/3)")
        if gfa_key_hex is not None:
            r6b[0x12:0x22] = _parse_exact_hex(gfa_key_hex, 16, "GFA (/1)")
        updates[0x6B] = bytes(r6b)

    if reset_cp_counter:
        r6d = _base_record(0x6D)
        r6d[0x02:0x04] = b"\x00\x00"
        if len(r6d) >= 0x0C:
            r6d[0x0B] = 0x01
        updates[0x6D] = bytes(r6d)

    # 5. EEL 0x60 / 0x35 (Odometer) and EEL 0x30 (Long coding)
    if odometer_km is not None:
        km = int(odometer_km)
        if not (0 <= km <= 999_998):
            raise ValueError("Odometer must be between 0 and 999,998 km")
        half = km // 2
        r60 = _base_record(0x60)
        if r60[2:4] == b"\xff\xff":
            r60[2:4] = b"\x00\x00"
        struct.pack_into("<3I", r60, 4, half, half, half)
        updates[0x60] = bytes(r60)
        if 0x35 in lay["ids"]:
            r35 = _base_record(0x35)
            r35[2:4] = b"\x00\x00"
            updates[0x35] = bytes(r35)

    if coding_hex is not None:
        r30 = _base_record(0x30)
        r30[11:31] = _parse_exact_hex(coding_hex, 20, "Coding (0x30)", allow_empty=False)
        updates[0x30] = bytes(r30)

    return eel_append_records(dflash, updates, cflash)


def transfer_fpke_donor_to_target(
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
    """Transfer selected identity blocks from Donor A (64 KiB DFlash or Immo JSON) into Target B DFlash via EEL T01 append.

    Always preserves Target B's hardware records (`0x45` part number/SW, `0x46` dataset, `0x30` coding, `0x63` FD11 keys,
    and calibration records `0x01..0x2F`).
    """
    donor_passport = (
        extract_fpke_immo_passport(donor, donor_cflash)
        if isinstance(donor, (bytes, bytearray))
        else donor
    )
    im_a = donor_passport.get("immo") or {}
    cnt_a = im_a.get("counts") or {}
    mf_a = im_a.get("mode_and_flags") or {}
    cp_a = donor_passport.get("component_protection_separate") or {}
    meta_a = donor_passport.get("cluster_metadata") or {}

    partner_macs: dict[str, str] = {}
    for p in im_a.get("partners") or []:
        if isinstance(p, dict) and p.get("code"):
            partner_macs[str(p["code"])] = str(p.get("mac_id_hex") or "")
    if not partner_macs and isinstance(im_a.get("mac_fields"), dict):
        mf_dict = im_a["mac_fields"]
        partner_macs = {
            "MSG_1": str(mf_dict.get("ecu") or ""),
            "GSG": str(mf_dict.get("tcu") or ""),
            "ELV": str(mf_dict.get("elv") or ""),
        }

    mac_dash = str((im_a.get("mac_fields") or {}).get("dash") or "")
    donor_pc = im_a.get("power_class_int")
    if donor_pc is None and im_a.get("power_class"):
        donor_pc = str(im_a["power_class"])

    updated_df = apply_fpke_dflash_edits(
        target_dflash,
        vin=(im_a.get("vin") or "") if copy_immo else None,
        cs_hex=(im_a.get("cs") or "") if copy_immo else None,
        crc_a_hex=(im_a.get("crc32_a_le") or "") if copy_immo else None,
        crc_b_hex=(im_a.get("crc32_b_le") or "") if copy_immo else None,
        power_class=donor_pc if copy_immo else None,
        immo_mode=(mf_a.get("immo_mode") if mf_a.get("immo_mode") is not None else 1) if copy_immo else None,
        key_over_can=bool(mf_a.get("key_over_can")) if copy_immo else None,
        partners_mask=(mf_a.get("partners_mask") if mf_a.get("partners_mask") is not None else 0) if copy_immo else None,
        clear_lockouts=bool(copy_immo),
        mac_dash_hex=mac_dash if copy_immo else None,
        partner_macs=partner_macs if copy_immo else None,
        key_display_ids=list(im_a.get("keys") or []) if copy_keys else None,
        allowed_keys=cnt_a.get("allowed_keys", 8) if copy_keys else None,
        learned_keys=cnt_a.get("learned_keys", 0) if copy_keys else None,
        session_xor_flags=cnt_a.get("session_xor_flags", 0) if copy_keys else None,
        odometer_km=meta_a.get("odometer_km") if (copy_odometer and meta_a.get("odometer_km") is not None) else None,
        ika_key_hex=(cp_a.get("ika_cp3") or "") if copy_cp else None,
        gfa_key_hex=(cp_a.get("cp1_gfa") or "") if copy_cp else None,
        reset_cp_counter=bool(copy_cp),
        cflash=target_cflash,
    )

    after_passport = extract_fpke_immo_passport(updated_df, target_cflash)
    summary = {
        "copied_sections": {
            "immo": copy_immo,
            "keys": copy_keys,
            "odometer": copy_odometer and (meta_a.get("odometer_km") is not None),
            "cp": copy_cp,
        },
        "donor_part_number": meta_a.get("part_number"),
        "target_part_number": (after_passport.get("cluster_metadata") or {}).get("part_number"),
        "vin": after_passport["immo"]["vin"],
        "power_class_hex": after_passport["immo"]["power_class_hex"],
        "learned_keys": after_passport["immo"]["counts"]["learned_keys"],
        "odometer_km": (after_passport.get("cluster_metadata") or {}).get("odometer_km"),
    }
    return updated_df, summary


def extract_fpke_eel_updates(
    before_dflash: bytes,
    after_dflash: bytes,
    cflash: bytes | None = None,
) -> dict[int, bytes]:
    """Return `{ident: record_bytes}` for every active EEL ID added or modified in `after_dflash` vs `before_dflash`."""
    lay_before = fpke_eel_layout(cflash, before_dflash)
    lay_after = fpke_eel_layout(cflash, after_dflash)
    updates: dict[int, bytes] = {}
    for ident in sorted(lay_after["ids"]):
        try:
            rec_after, src_after = eel_read_record_any(lay_after, after_dflash, ident)
        except KeyError:
            continue
        if src_after.get("generation") != "current":
            continue
        rec_before: bytes | None = None
        if ident in lay_before["ids"]:
            with contextlib.suppress(KeyError):
                cand, src_before = eel_read_record_any(lay_before, before_dflash, ident)
                if src_before.get("generation") == "current":
                    rec_before = cand
        if rec_before != rec_after:
            updates[ident] = rec_after
    return updates


def summarize_fpke_dflash_changes(
    before_dflash: bytes,
    after_dflash: bytes,
    cflash: bytes | None = None,
) -> dict[str, Any]:
    """Build a human-readable bilingual summary of semantic and EEL changes between two 64 KiB FPK_E DataFlash images."""
    norm_before, mask_before = normalize_fpke_dflash_for_faci(before_dflash, cflash)
    norm_after, mask_after = normalize_fpke_dflash_for_faci(after_dflash, cflash)
    updates = extract_fpke_eel_updates(norm_before, norm_after, cflash)

    is_pure_eel_update = False
    if updates:
        with contextlib.suppress(Exception):
            lay_chk = fpke_eel_layout(cflash, norm_after)
            pool_end = lay_chk["base"] + lay_chk["n_vb"] * lay_chk["vb"]
            replayed, mask_replayed = normalize_fpke_dflash_for_faci(
                eel_append_records(norm_before, updates, cflash),
                cflash,
            )
            if (norm_after == replayed) and (mask_after == mask_replayed):
                is_pure_eel_update = True
            elif (
                norm_before[pool_end:] == norm_after[pool_end:]
                and mask_before[pool_end:] == mask_after[pool_end:]
                and all(
                    any(mask_after[off : off + 4]) and norm_before[off : off + 4] == norm_after[off : off + 4]
                    for off in range(0, pool_end, 4)
                    if any(mask_before[off : off + 4])
                )
            ):
                is_pure_eel_update = True

    raw_diff_blocks = sum(
        1
        for blk_off in range(0, FPKE_DFLASH_SIZE, 64)
        if norm_before[blk_off : blk_off + 64] != norm_after[blk_off : blk_off + 64]
        or mask_before[blk_off : blk_off + 64] != mask_after[blk_off : blk_off + 64]
    )
    changed = bool(updates) or raw_diff_blocks > 0
    if not changed:
        return {
            "changed": False,
            "is_pure_eel_update": False,
            "changed_eel_ids": [],
            "raw_diff_blocks": 0,
            "lines": [],
            "short_summary": tr("Изменений нет", "No changes"),
        }

    p1 = extract_fpke_immo_passport(norm_before, cflash)
    p2 = extract_fpke_immo_passport(norm_after, cflash)
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

    if im1.get("mac_fields") != im2.get("mac_fields"):
        lines.append(f"MAC IDs (EEL 0x66): MAC4={im1.get('mac4') or '—'} → {im2.get('mac4') or '—'}")
        short_tags.append("MAC")

    cnt1, cnt2 = im1.get("counts") or {}, im2.get("counts") or {}
    if im1.get("keys") != im2.get("keys") or cnt1 != cnt2:
        k_Summary = f"{cnt2.get('learned_keys', 0)}/{cnt2.get('allowed_keys', 0)}"
        lines.append(
            tr(
                f"Ключи и транспондеры (EEL 0x67): обучено {cnt1.get('learned_keys', 0)}/{cnt1.get('allowed_keys', 0)} → {k_Summary}",
                f"Keys & transponders (EEL 0x67): learned {cnt1.get('learned_keys', 0)}/{cnt1.get('allowed_keys', 0)} → {k_Summary}",
            )
        )
        short_tags.append(tr(f"ключи ({k_Summary})", f"keys ({k_Summary})"))

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
                f"Кодировка (EEL 0x30): {(m2.get('coding_hex') or '—')[:16]}…",
                f"Coding (EEL 0x30): {(m2.get('coding_hex') or '—')[:16]}…",
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
        elif raw_diff_blocks:
            lines.append(
                tr(
                    f"Прямые изменения образа DataFlash: {raw_diff_blocks} бл. по 64 Б",
                    f"Direct DataFlash image changes: {raw_diff_blocks} × 64 B blocks",
                )
            )
            short_tags.append(tr(f"{raw_diff_blocks} бл. DataFlash", f"{raw_diff_blocks} DataFlash blocks"))

    short_summary = ", ".join(short_tags[:4])
    if len(short_tags) > 4:
        short_summary += f" (+{len(short_tags) - 4})"

    return {
        "changed": True,
        "is_pure_eel_update": is_pure_eel_update,
        "changed_eel_ids": [f"0x{i:02X}" for i in sorted(updates)],
        "raw_diff_blocks": raw_diff_blocks,
        "lines": lines,
        "short_summary": short_summary,
    }


# ────────────────────────────── Bilingual Text Reports ──────────────────────────────


def format_fpke_immo_comparison(
    cmp_res: dict[str, Any],
    passport_a: dict[str, Any],
    passport_b: dict[str, Any],
) -> str:
    """Format a clear RU/EN semantic comparison report for two FPK_E DataFlash dumps."""
    lines: list[str] = []
    lines.append("═" * 72)
    lines.append(tr("СВЕРКА ПАСПОРТА ИММОБИЛАЙЗЕРА FPK_E (A ↔ B)", "FPK_E IMMOBILIZER PASSPORT COMPARISON (A ↔ B)"))
    lines.append("═" * 72)
    verdict = (
        tr("СМЫСЛОВЫЕ ПОЛЯ ПОЛНОСТЬЮ СОВПАДАЮТ", "SEMANTIC IMMO FIELDS MATCH")
        if cmp_res["semantic_match"]
        else tr(
            f"ОБНАРУЖЕНЫ ОТЛИЧИЯ: {', '.join(cmp_res['mismatched_fields'])}",
            f"DIFFERENCES FOUND: {', '.join(cmp_res['mismatched_fields'])}",
        )
    )
    lines.append(f"  {tr('Итог сверки', 'Verdict'):<26}: {verdict}")
    lines.append(f"  DFlash A SHA-256          : {passport_a.get('dflash_sha256', '—')}")
    lines.append(f"  DFlash B SHA-256          : {passport_b.get('dflash_sha256', '—')}")
    lines.append(
        f"  EEL 0x68 SHA-256          : "
        f"{tr('совпадает', 'identical') if cmp_res['r68_sha256_equal'] else tr('различается', 'different')}"
    )
    if cmp_res.get("physical_vb_differs"):
        lines.append(
            tr(
                "  Физическое смещение EEL   : различается (нормально для журналируемого пула EEL T01)",
                "  Physical EEL VB/offset    : differs (expected for journaled EEL T01 pool)",
            )
        )
    lines.append("")
    lines.append(tr("── Построчная проверка полей ──", "── Field-by-Field Verification ──"))
    im1, im2 = passport_a["immo"], passport_b["immo"]
    rows = (
        ("VIN", im1["vin"] or f"<{im1['vin_state']}>", im2["vin"] or f"<{im2['vin_state']}>", cmp_res["field_checks"]["vin"]),
        ("CS / Kc", im1["cs"] or f"<{im1['cs_state']}>", im2["cs"] or f"<{im2['cs_state']}>", cmp_res["field_checks"]["cs"]),
        ("VDO CS+ (CRC A/B)", im1["vdo_cs_plus"] or "—", im2["vdo_cs_plus"] or "—", cmp_res["field_checks"]["vdo_cs_plus"]),
        ("PowerClass", im1["power_class_hex"] or "—", im2["power_class_hex"] or "—", cmp_res["field_checks"]["power_class"]),
        ("MAC4 (DASH+ECU)", im1["mac4"] or "—", im2["mac4"] or "—", cmp_res["field_checks"]["mac4"]),
        (
            "Keys (learned/allowed)",
            f"{im1['counts']['learned_keys']}/{im1['counts']['allowed_keys']} {im1['keys']}",
            f"{im2['counts']['learned_keys']}/{im2['counts']['allowed_keys']} {im2['keys']}",
            cmp_res["field_checks"]["keys"]
            and cmp_res["field_checks"]["learned_keys"]
            and cmp_res["field_checks"]["allowed_keys"],
        ),
        (
            "Partners mask",
            im1["mode_and_flags"]["partners_mask_hex"],
            im2["mode_and_flags"]["partners_mask_hex"],
            cmp_res["field_checks"]["partners_mask"],
        ),
    )
    for label, v1, v2, ok in rows:
        mark = "OK" if ok else "DIFF"
        lines.append(f"  [{mark:<4}] {label:<22}: {v1}" + ("" if ok else f"  !=  {v2}"))
    return "\n".join(lines)


def format_fpke_transfer_plan(plan: dict[str, Any]) -> str:
    """Format a human-readable RU/EN static Donor A -> Recipient B transfer plan."""
    da = plan["donor_a"]
    rb = plan["recipient_b"]
    ta = plan["transfer_from_a"]
    pb = plan["preserve_on_b"]
    od = plan["odometer_sync"]
    cp = plan["component_protection_separate"]
    pol = plan["s0_s1_and_0x6a_policy"]

    lines: list[str] = []
    lines.append("═" * 72)
    lines.append(tr("СТАТИЧЕСКИЙ ПЛАН ПЕРЕНОСА FPK_E (ДОНОР A → РЕЦИПИЕНТ B)", "STATIC FPK_E TRANSFER PLAN (DONOR A → RECIPIENT B)"))
    lines.append("═" * 72)
    lines.append(
        f"  {tr('Донор A (родной блок)', 'Donor A (source)'):<26}: "
        f"{da.get('part_number') or '—'} ({da['platform']}, SHA-256 {da['dflash_sha256'][:16]}…)"
    )
    lines.append(
        f"  {tr('Реципиент B (замена)', 'Recipient B (target)'):<26}: "
        f"{rb.get('part_number') or '—'} ({rb['platform']}, SHA-256 {rb['dflash_sha256'][:16]}…)"
    )

    lines.append("")
    lines.append(tr("── 1. Переносится из Донора A (паспорт автомобиля) ──", "── 1. Transferred from Donor A (vehicle identity) ──"))
    lines.append(f"  VIN (EEL 0x68+0x17)       : {ta.get('vin') or '—'}")
    lines.append(f"  CS / Kc (EEL 0x68+0x28)   : {ta.get('cs') or '—'}")
    lines.append(f"  VDO CS+ (CRC-32 A / B)    : {ta.get('crc32_a_le') or '—'} / {ta.get('crc32_b_le') or '—'}")
    lines.append(f"  PowerClass (EEL 0x68+40)  : {ta.get('power_class_hex') or '—'}")
    mf = ta.get("mac_fields") or {}
    lines.append(
        f"  MAC IDs (EEL 0x66)        : DASH={mf.get('dash') or '—'}  ECU={mf.get('ecu') or '—'}  "
        f"TCU={mf.get('tcu') or '—'}  ELV={mf.get('elv') or '—'}  (MAC4={ta.get('mac4') or '—'})"
    )
    lines.append(
        f"  {tr('Партнёры иммо', 'Adapted partners'):<26}: {ta.get('partners_mask_hex')} "
        f"({', '.join(ta.get('adapted_partner_codes') or []) or 'none'})"
    )
    cnt = ta.get("counts") or {}
    active_keys = [f"K{i + 1}:{k}" for i, k in enumerate(ta.get("keys") or []) if k]
    lines.append(
        f"  {tr('Транспондеры (EEL 0x67)', 'Transponders (EEL 0x67)'):<26}: "
        f"learned={cnt.get('learned_keys', 0)}, allowed={cnt.get('allowed_keys', 0)}, "
        f"XOR=0x{cnt.get('session_xor_flags', 0):X}  [{', '.join(active_keys) or 'empty'}]"
    )

    lines.append("")
    lines.append(tr("── 2. Сохраняется на Реципиенте B (аппаратная часть B) ──", "── 2. Preserved on Recipient B (hardware/calibration) ──"))
    lines.append(f"  Part Number / SW (0x45)   : {pb.get('part_number') or '—'} / {pb.get('sw_version_eel') or '—'}")
    lines.append(f"  Dataset (EEL 0x46)        : {pb.get('dataset_pn') or '—'}")
    lines.append(f"  Coding (EEL 0x30)         : {pb.get('coding_hex') or '—'}")
    lines.append(f"  Current Kc on B           : {pb.get('current_kc_on_b') or '—'}")

    lines.append("")
    lines.append(tr("── 3. Пробег и Защита компонентов (отдельные области) ──", "── 3. Odometer & Component Protection (separate areas) ──"))
    lines.append(
        f"  {tr('Пробег A → B (EEL 0x60)', 'Odometer A → B (EEL 0x60)'):<26}: "
        f"{od.get('donor_a_km')} km  →  {tr('текущий на B', 'current on B')}: {od.get('recipient_b_km')} km"
    )
    lines.append(f"  Donor A IKA /3 (0x6B)     : {(cp.get('donor_a') or {}).get('ika_cp3') or '—'}")
    lines.append(f"  Recipient B IKA /3 (0x6B) : {(cp.get('recipient_b') or {}).get('ika_cp3') or '—'}")
    lines.append(
        f"  S0/S1 (0x69)              : {pol.get('donor_s0_s1_state')} | "
        f"02F7 stub S0/S1 allowed={pol.get('allow_02f7_with_stub_s0_s1')}"
    )

    if plan.get("warnings"):
        lines.append("")
        lines.append(tr("── Примечания и ограничения ──", "── Notes & Safeguards ──"))
        for w in plan["warnings"]:
            lines.append(f"  • {w}")
    return "\n".join(lines)


def format_fpke_report(
    *,
    dflash_info: dict[str, Any] | None = None,
    extra_info: dict[str, Any] | None = None,
    ident: list[dict[str, str]] | None = None,
    idauth_info: dict[str, Any] | None = None,
) -> str:
    """Format a human-readable RU/EN report for FPK_E DataFlash EEL secrets and Extra Area."""
    lines: list[str] = []
    lines.append("═" * 72)
    lines.append(tr("ОТЧЁТ ПО ПРИБОРНОЙ ПАНЕЛИ VAG FPK_E (RH850/D1L)", "VAG FPK_E INSTRUMENT CLUSTER REPORT (RH850/D1L)"))
    lines.append("═" * 72)

    if ident:
        lines.append("")
        lines.append(tr("── Идентификация UDS (0x714 / 0x77E) ──", "── UDS Identification (0x714 / 0x77E) ──"))
        for item in ident:
            lbl = tr(item.get("label_ru", item["did"]), item.get("label_en", item["did"]))
            lines.append(f"  {item['did']}  {lbl:<24} : {item['value']}")

    if extra_info:
        lines.append("")
        lines.append(tr("── Extra Area / Конфигурация RH850 (0xFF300000) ──", "── Extra Area / RH850 Configuration (0xFF300000) ──"))
        lines.append(f"  SHA-256                  : {extra_info['sha256']}")
        lines.append(f"  Security word            : {extra_info['security_raw']} ({extra_info['protection_mode']})")
        lines.append(
            f"  Serial Programming       : {'enabled' if extra_info['serial_programming_enabled'] else 'disabled'} | "
            f"Erase={'on' if extra_info['command_erase_enabled'] else 'off'} "
            f"Write={'on' if extra_info['command_write_enabled'] else 'off'} "
            f"Read={'on' if extra_info['command_read_enabled'] else 'off'}"
        )
        lines.append(f"  IDCODE (0xFF300050)      : {extra_info['idcode_spaced']}")
        lines.append(f"  OPBT0  (0xFF300070)      : {extra_info['opbt0']}")
        if extra_info.get("icu_bound"):
            lines.append(f"  ICU bound (0xFF30009C)   : {extra_info['icu_bound']}")
        if idauth_info and idauth_info.get("idst_after_idcode") is not None:
            accepted = idauth_info["idst_after_idcode"] == "00000000"
            verdict = tr("ПРИНЯТ (00000000)", "ACCEPTED (00000000)") if accepted else tr("ОТКЛОНЁН", "REJECTED")
            lines.append(
                f"  IDAUTH                   : {verdict} "
                f"({idauth_info.get('idst_before')} -> {idauth_info.get('idst_after_idcode')} -> relock {idauth_info.get('idst_after_relock')})"
            )

    if dflash_info:
        pool = dflash_info["pool"]
        st = pool["states"]
        lines.append("")
        lines.append(tr("── Пул Renesas EEL T01 в DataFlash (64 КБ) ──", "── Renesas EEL T01 Pool in DataFlash (64 KB) ──"))
        lines.append(f"  SHA-256                  : {dflash_info['sha256']}")
        lines.append(
            tr(
                f"  Виртуальные блоки (28)   : активных={st.get('active', 0)}, подготовленных={st.get('prepared', 0)}, "
                f"аннулированных={st.get('invalid', 0)}, ошибок={st.get('inconsistent', 0)}",
                f"  Virtual blocks (28)      : active={st.get('active', 0)}, prepared={st.get('prepared', 0)}, "
                f"invalid={st.get('invalid', 0)}, inconsistent={st.get('inconsistent', 0)}",
            )
        )
        lines.append(
            tr(
                f"  Активных записей ID-L    : {pool['active_ids']} / {pool['total_ids']}",
                f"  Active ID-L records      : {pool['active_ids']} / {pool['total_ids']}",
            )
        )
        meta = dflash_info.get("metadata") or {}
        if meta.get("vin"):
            lines.append(f"  VIN (EEL 0x68 / F190)    : {meta['vin']}")
        if meta.get("part_number"):
            lines.append(f"  Part Number (EEL 0x45)   : {meta['part_number']}")
        if meta.get("dataset_pn"):
            lines.append(f"  Dataset (EEL 0x46)       : {meta['dataset_pn']}")
        if meta.get("coding_hex"):
            lines.append(f"  Coding (EEL 0x30)        : {meta['coding_hex']}")
        if meta.get("power_class"):
            lines.append(f"  PowerClass (EEL 0x68+40) : {meta['power_class']}")
        if "odometer_km" in meta:
            lines.append(f"  Odometer (EEL 0x60)      : {meta['odometer_km']} km")

        by_id = {it["key_id"]: it for it in dflash_info.get("items", [])}
        immo_cfg = dflash_info.get("immo_config") or {}
        slots = dflash_info.get("slot_secrets") or {}

        lines.append("")
        lines.append(tr("── Паспорт иммобилайзера Immo 4.0 (EEL 0x66 / 0x68 / 0x69) ──", "── Immobilizer Immo 4.0 Passport (EEL 0x66 / 0x68 / 0x69) ──"))
        if "kc" in by_id:
            lines.append(f"  {'CS / K_c (0x68+0x28)':<28} : {by_id['kc']['hex'].upper()}")
        if immo_cfg.get("k_ffb_hex"):
            lines.append(f"  {'K_ffb (AES_Kc(C16), FFB)':<28} : {immo_cfg['k_ffb_hex']}")
        if slots.get("A_crc32_le") or slots.get("B_crc32_le"):
            lines.append(
                f"  {'VDO CS+ (CRC-32 A / B)':<28} : {slots.get('A_crc32_le', '').upper()} / {slots.get('B_crc32_le', '').upper()}"
            )
        if immo_cfg.get("power_class_hex"):
            lines.append(f"  {'PowerClass (P_class)':<28} : {immo_cfg['power_class_hex']}")
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
        if slots.get("S0") or slots.get("S1"):
            s0 = tr("стёрто (FF×16)", "erased (FF×16)") if slots.get("S0") == "ff" * 16 else slots.get("S0", "").upper()
            s1 = tr("стёрто (FF×16)", "erased (FF×16)") if slots.get("S1") == "ff" * 16 else slots.get("S1", "").upper()
            lines.append(f"  {'Slot S0 / S1 (0x69)':<28} : {s0} / {s1}")

        lines.append("")
        lines.append(tr("── Защита компонентов IKA / CP (EEL 0x6B / 0x6C / 0x6D) ──", "── Component Protection IKA / CP (EEL 0x6B / 0x6C / 0x6D) ──"))
        for item in dflash_info.get("items", []):
            if item["key_id"].startswith(("ika_", "cp1_")):
                lines.append(f"  {item['name']:<28} : {item['hex'].upper()}")
        cp_st = dflash_info.get("component_protection_state") or {}
        if cp_st.get("error_counter") is not None:
            lines.append(f"  {'CP Error Counter (0x6D)':<28} : {cp_st['error_counter']} (adapted={cp_st.get('adapted')})")
        if cp_st.get("prng_0"):
            lines.append(f"  {'CP PRNG /0 (EEL 0x6C)':<28} : {cp_st['prng_0'].upper()}")
        if cp_st.get("record_2_first_10"):
            lines.append(f"  {'CP /2 [0..9] (EEL 0x6D)':<28} : {cp_st['record_2_first_10'].upper()}")

        lines.append("")
        lines.append(tr("── Доступ поставщика Continental FD11 (EEL 0x63 / 0x64) ──", "── Continental Vendor Access FD11 (EEL 0x63 / 0x64) ──"))
        if dflash_info.get("fd11_identifier"):
            lines.append(f"  {'FD11 Identifier':<28} : {dflash_info['fd11_identifier']}")
        for item in dflash_info.get("items", []):
            if item["key_id"].startswith(("fd11_", "aux_")):
                crc_tag = f"  [CRC-32: {'OK' if item['crc_valid'] else 'FAIL'}]" if item["crc_valid"] is not None else ""
                lines.append(f"  {item['name']:<28} : {item['hex'].upper()}{crc_tag}")

        if dflash_info.get("record_sources"):
            lines.append("")
            lines.append(tr("── Источники записей EEL ──", "── EEL Record Sources ──"))
            for ident_hex, src in dflash_info["record_sources"].items():
                gen = tr("активная", "active") if src["generation"] == "current" else tr("историческая", "historical")
                lines.append(
                    f"  {ident_hex}: {gen:<12} | VB {src['vb']:2d} | top=0x{src['top']:04X} | "
                    f"state={src['state']:<8} | EC={src['ec']} | FEE={'OK' if src['fee_size_valid'] else 'FAIL'}"
                )

        tp = dflash_info.get("transponder_records") or {}
        if tp.get("EEL_0x67_present"):
            lines.append("")
            lines.append(tr("── Транспондеры и ключи (EEL 0x67 / 0x6A) ──", "── Transponders & Keys (EEL 0x67 / 0x6A) ──"))
            lines.append(
                tr(
                    f"  Разрешено: {tp['allowed_keys']} | Обучено: {tp['learned_keys']} | Session-XOR: 0x{tp['session_xor_flags']:X}",
                    f"  Allowed: {tp['allowed_keys']} | Learned: {tp['learned_keys']} | Session-XOR: 0x{tp['session_xor_flags']:X}",
                )
            )
            for k in tp.get("key_ids", []):
                if k["present"] or k["within_learned_count"]:
                    tag = tr("обучен", "learned") if k["within_learned_count"] else tr("вне счётчика", "outside learned count")
                    disp = k.get("display_id") or k["hex"].upper()
                    lines.append(f"    Key {k['slot'] + 1}: {disp}  (raw: {k['hex'].upper()}, {tag})")

    return "\n".join(lines)
