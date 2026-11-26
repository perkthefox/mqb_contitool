"""VAG MQB 2B ELV / ESCL / J764 (Marquardt 3Q0 905 861, EV_ELVMarquMQBB) offline & protocol core.

Pure-Python implementation derived from Renesas V850ES/FJ3 uPD70F3624 (3Q0 905 861 SW 0032):
  - EEELib Data Flash parser & record rebuilder supporting both 32 KiB compact dumps
    (`0xFCFF8000..0xFCFFFFFF`, Pool 0 & Pool 1 auto-selection) and 64 KiB programmer dumps
    (`4 B data + 4 B slot status marker`).
  - Marquardt EEH 48-bit nonlinear LFSR per-vaddr AES-128 key derivation (`FUN_ram_000183de`),
    AES-128-ECB, IEEE 802.3 CRC-32 (`FUN_ram_0001b482`), CRC-16/CCITT-FALSE (`FUN_ram_0001b442`),
    and AUTOSAR CRC-8 H2F (`FUN_ram_0001b40c`, poly `0x2F`).
  - Offline DFLASH Virginizer (`Mode 2 -> Mode 1`) and Vehicle Adapter (`VIN`, `K_5 / Slot A`,
    `PowerClass`, optional `IDac` or auto-learn `0x00`).
  - Online UDS & CAN protocol helpers:
      * `22 02F9` read-only cryptographic verification of `K_5 / Slot A` (`FUN_ram_00028058`).
      * `2E 02E1` 4-byte command builder (`cmd=0x04, arg=0x80` reset learned `IDac`; `cmd=0x08, arg=0x00`).
      * `2E 02E2` 52-byte payload builder for Vehicle Adaptation and Virgin Reset (`FUN_ram_00027bc2` / `00027ad0`).
      * `0x01A <-> 0x01B` WFS5 CAN MAC (Little-Endian CRC-32 per `FUN_ram_00026f94` / `000272aa`).
      * `0x3DC Gateway_71` engine-stopped frame & `0x3C0 Klemmen_Status_01` E2E Profile 2 frame.
      * Bootloader SecurityAccess `27 11 / 27 12` key derivation (`FUN_ram_00003e48`).
  - Cross-ECU material extractor from Continental `17 FPK_E` instrument cluster Data Flash dumps.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import struct
from typing import Any
import zlib

from contitool.core.dtc import describe_elv
from contitool.core.dtc_elv import ELV_DTC_ORDER
from contitool.core.fpke import analyze_fpke_dflash, fpke_verify_s0_s1
from contitool.i18n import tr

# ────────────────────────────── CAN IDs & Memory Constants ──────────────────────────────

ELV_UDS_TX_ID = 0x731
ELV_UDS_RX_ID = 0x79B
ELV_UDS_FUNC_ID = 0x700

ELV_UDS_EXT_TX_ID = 0x17FC0231
ELV_UDS_EXT_RX_ID = 0x17FE0231
ELV_UDS_EXT_FUNC_ID = 0x17FD0409

ELV_DEV_MEM_TX_ID = 0x1BFD8A0B
ELV_DEV_MEM_RX_ID = 0x1BFD8A0A
ELV_DEV_CTRL_TX_ID = 0x1BFD8A05
ELV_DEV_MEM_MAGIC = b"42B"  # 0x34 0x32 0x42

ELV_NM_WAKE_ID = 0x1B000010
ELV_NM_WAKE_PAYLOAD = bytes.fromhex("1040ffffffffffff")
ELV_NM_OWN_ID = 0x1B000031
ELV_KN_STATUS_ID = 0x17F00031

ELV_WFS_ELV_CAN_ID = 0x01A
ELV_WFS_KOMBI_CAN_ID = 0x01B

ELV_GATEWAY_71_CAN_ID = 0x3DC
ELV_GATEWAY_71_ENGINE_STOPPED = bytes.fromhex("010000000000")

ELV_KL_STATUS_CAN_ID = 0x3C0
ELV_KL_STATUS_KENNUNG = 0xC3  # ROM[0x100FA..0x10109] = 0xC3 * 16

ELV_DFLASH_BASE_ADDR = 0xFCFF8000
ELV_DFLASH_COMPACT_SIZE = 32_768
ELV_DFLASH_RAW64K_SIZE = 65_536
ELV_DFLASH_POOL_SIZE = 16_384
ELV_EEELIB_DIR_COUNT = 47
ELV_EEELIB_ACTIVE_MARKER = 0x55555555

# ────────────────────────────── ROM Cryptographic Constants ──────────────────────────────

# Marquardt EEH nonlinear LFSR S-Box tables @ 0x0001089D (16B), 0x000108AD (16B), 0x000108BD (32B)
_SBOX_1089D = bytes.fromhex("01000001010101000000010100010000")
_SBOX_108AD = bytes.fromhex("01000000010101000001010000010100")
_SBOX_108BD = bytes.fromhex(
    "0100000001010100000101000001010000000000000000000000000000000000"
)

ELV_EEH_DEFAULT_SEED10 = bytes([0x17] * 10)  # Derived from PFLASH 0x0003FC00..0x0003FFFF (0x17)

ELV_WFS5_PREFIX = bytes.fromhex("9cf7feb7")
ELV_WFS5_CASC = b"casc"  # 0x63 0x61 0x73 0x63
ELV_WFS5_SUFFIX_01B_REPLY = bytes([0x0C, 0x0D, 0x0E])  # Kombi -> ELV reply to 0x01A Type 1
ELV_WFS5_SUFFIX_01A_TYPE2 = bytes([0x05, 0x06, 0x07])  # ELV -> Kombi Type 2 response
ELV_WFS5_SUFFIX_01B_CASC = bytes([0x0F, 0x10, 0x11])   # Kombi -> ELV autonomous 'casc' request
ELV_WFS5_SUFFIX_01A_TYPE3 = bytes([0x11, 0x12, 0x13])  # ROM[0x11EC0..0x11EC6] = "casc" + 11 12 13

ELV_02E1_CONST10 = bytes.fromhex("01020304050607080910")      # ROM[0x11EC7..0x11ED0]
ELV_02F9_CONST12 = bytes.fromhex("0cc348950d3089a23f47e658")  # ROM[0x11ED1..0x11EDC]

ELV_CMD_RESET_IDAC = (0x04, 0x80)
ELV_CMD_DIAG_TEST = (0x08, 0x00)

# Standard AES-128 tables (matching 0x000112B6 / 0x000113B6 in 3Q0 905 861 PFLASH)
_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)
_AES_ISBOX = bytes(_AES_SBOX.index(i) for i in range(256))
_AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

# Triple-copy block groups: (block_name, (vaddr_0, vaddr_1, vaddr_2))
ELV_TRIPLE_COPY_GROUPS: tuple[tuple[str, tuple[int, int, int]], ...] = (
    ("block00_identity", (0x0001, 0x0069, 0x00D1)),
    ("block02_counters", (0x0181, 0x0199, 0x01B1)),
    ("block04_partner", (0x0201, 0x0219, 0x0231)),
    ("block07_serial", (0x0279, 0x02B1, 0x02E9)),
    ("block08_coding", (0x0321, 0x0369, 0x03B1)),
    ("block34_immo", (0x07D1, 0x0809, 0x0841)),
)

ELV_MODE_LABELS: dict[int, tuple[str, str]] = {
    0x01: ("Virgin (новый, Mode 1)", "Virgin (Mode 1)"),
    0x02: ("Адаптирован (Mode 2)", "Adapted (Mode 2)"),
    0xFF: ("Заводской (Plant, Mode 0xFF)", "Plant (Mode 0xFF)"),
}

ELV_IDAC_STATE_LABELS: dict[int, tuple[str, str]] = {
    0x00: ("Не обучен (автообучение)", "Unlearned (auto-learn)"),
    0x55: ("Первое подтверждение (0x55)", "First challenge seen (0x55)"),
    0xAA: ("Привязан к приборке (0xAA)", "Locked to cluster (0xAA)"),
}

ELV_BOLT_STATE_LABELS: dict[int, tuple[str, str]] = {
    0xC3: ("Открыт / разблокирован (0xC3)", "Unlocked (0xC3)"),
    0x5A: ("Закрыт / заблокирован (0x5A)", "Locked (0x5A)"),
}


# ────────────────────────────── Helpers & Validation ──────────────────────────────


def _clean_ascii(raw: bytes) -> str:
    return "".join(chr(b) for b in raw if 0x20 <= b < 0x7F).strip()


def _norm_hex_bytes(val: bytes | bytearray | memoryview | str, expected_len: int, label: str) -> bytes:
    if isinstance(val, (bytes, bytearray, memoryview)):
        raw = bytes(val)
    else:
        cleaned = "".join(str(val).split()).replace("0x", "").replace("0X", "")
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"{label} must be {expected_len * 2} hex digits ({expected_len} bytes), got {val!r}") from exc
    if len(raw) != expected_len:
        raise ValueError(f"{label} must be {expected_len} bytes ({expected_len * 2} hex digits), got {len(raw)} bytes")
    return raw


def _validate_u8(val: int, label: str) -> int:
    if isinstance(val, bool) or not isinstance(val, int) or not (0 <= val <= 0xFF):
        raise ValueError(
            tr(
                f"Параметр {label} должен быть целым числом в диапазоне 0x00..0xFF, получено {val!r}",
                f"{label} must be an integer in range 0x00..0xFF, got {val!r}",
            )
        )
    return val


def _validate_u32(val: int, label: str) -> int:
    if isinstance(val, bool) or not isinstance(val, int) or not (0 <= val <= 0xFFFFFFFF):
        raise ValueError(
            tr(
                f"Параметр {label} должен быть целым числом в диапазоне 0x00000000..0xFFFFFFFF, получено {val!r}",
                f"{label} must be an integer in range 0x00000000..0xFFFFFFFF, got {val!r}",
            )
        )
    return val


def _norm_vin17(vin: str | bytes) -> bytes:
    if isinstance(vin, (bytes, bytearray, memoryview)):
        raw = bytes(vin)
        if len(raw) != 17:
            raise ValueError(
                tr(
                    f"VIN должен состоять ровно из 17 ASCII-символов, получено {len(raw)} ({raw!r})",
                    f"VIN must be exactly 17 ASCII characters, got {len(raw)} ({raw!r})",
                )
            )
        if any(b < 0x20 or b > 0x7E for b in raw):
            raise ValueError(
                tr(
                    f"VIN содержит недопустимые управляющие или не-ASCII байты: {raw!r}",
                    f"VIN contains invalid control or non-ASCII bytes: {raw!r}",
                )
            )
        return raw.decode("ascii").upper().encode("ascii")

    text = str(vin)
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in text):
        raise ValueError(
            tr(
                f"VIN содержит недопустимые управляющие или не-ASCII символы: {vin!r}",
                f"VIN contains invalid control or non-ASCII characters: {vin!r}",
            )
        )
    cleaned = text.strip(" ")
    raw = cleaned.encode("ascii", errors="strict")
    if len(raw) != 17:
        raise ValueError(
            tr(
                f"VIN должен состоять ровно из 17 ASCII-символов, получено {len(raw)} ({raw!r})",
                f"VIN must be exactly 17 ASCII characters, got {len(raw)} ({raw!r})",
            )
        )
    return cleaned.upper().encode("ascii")


def elv_mode_label(mode: int | None) -> str:
    if mode is None:
        return tr("Неизвестно", "Unknown")
    pair = ELV_MODE_LABELS.get(mode & 0xFF)
    if pair is None:
        return tr(f"Неизвестно (0x{mode & 0xFF:02X})", f"Unknown (0x{mode & 0xFF:02X})")
    return tr(pair[0], pair[1])


def elv_idac_state_label(state: int | None) -> str:
    if state is None:
        return tr("Неизвестно", "Unknown")
    pair = ELV_IDAC_STATE_LABELS.get(state & 0xFF)
    if pair is None:
        return tr(f"Неизвестно (0x{state & 0xFF:02X})", f"Unknown (0x{state & 0xFF:02X})")
    return tr(pair[0], pair[1])


def elv_bolt_state_label(state: int | None) -> str:
    if state is None:
        return tr("Неизвестно", "Unknown")
    pair = ELV_BOLT_STATE_LABELS.get(state & 0xFF)
    if pair is None:
        return tr(f"Неизвестно (0x{state & 0xFF:02X})", f"Unknown (0x{state & 0xFF:02X})")
    return tr(pair[0], pair[1])


# ────────────────────────────── Crypto & Checksums ──────────────────────────────


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _aes_expand_key(key: bytes) -> list[list[int]]:
    rk = [list(key)]
    for r in range(10):
        prev = rk[-1]
        t = [
            _AES_SBOX[prev[13]] ^ _AES_RCON[r],
            _AES_SBOX[prev[14]],
            _AES_SBOX[prev[15]],
            _AES_SBOX[prev[12]],
        ]
        nxt = [0] * 16
        for i in range(4):
            nxt[i] = prev[i] ^ t[i]
        for i in range(4, 16):
            nxt[i] = prev[i] ^ nxt[i - 4]
        rk.append(nxt)
    return rk


def _aes128_encrypt_block(rk: list[list[int]], block: bytes) -> bytes:
    st = [block[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, 11):
        st = [_AES_SBOX[x] for x in st]
        st = [
            st[0], st[5], st[10], st[15],
            st[4], st[9], st[14], st[3],
            st[8], st[13], st[2], st[7],
            st[12], st[1], st[6], st[11],
        ]
        if r < 10:
            ns = [0] * 16
            for c in range(4):
                i = c * 4
                s0, s1, s2, s3 = st[i], st[i + 1], st[i + 2], st[i + 3]
                ns[i] = _gmul(s0, 2) ^ _gmul(s1, 3) ^ s2 ^ s3
                ns[i + 1] = s0 ^ _gmul(s1, 2) ^ _gmul(s2, 3) ^ s3
                ns[i + 2] = s0 ^ s1 ^ _gmul(s2, 2) ^ _gmul(s3, 3)
                ns[i + 3] = _gmul(s0, 3) ^ s1 ^ s2 ^ _gmul(s3, 2)
            st = ns
        st = [st[i] ^ rk[r][i] for i in range(16)]
    return bytes(st)


def _aes128_decrypt_block(rk: list[list[int]], block: bytes) -> bytes:
    st = [block[i] ^ rk[10][i] for i in range(16)]
    for r in range(9, -1, -1):
        st = [
            st[0], st[13], st[10], st[7],
            st[4], st[1], st[14], st[11],
            st[8], st[5], st[2], st[15],
            st[12], st[9], st[6], st[3],
        ]
        st = [_AES_ISBOX[x] for x in st]
        st = [st[i] ^ rk[r][i] for i in range(16)]
        if r > 0:
            ns = [0] * 16
            for c in range(4):
                i = c * 4
                s0, s1, s2, s3 = st[i], st[i + 1], st[i + 2], st[i + 3]
                ns[i] = _gmul(s0, 0x0E) ^ _gmul(s1, 0x0B) ^ _gmul(s2, 0x0D) ^ _gmul(s3, 0x09)
                ns[i + 1] = _gmul(s0, 0x09) ^ _gmul(s1, 0x0E) ^ _gmul(s2, 0x0B) ^ _gmul(s3, 0x0D)
                ns[i + 2] = _gmul(s0, 0x0D) ^ _gmul(s1, 0x09) ^ _gmul(s2, 0x0E) ^ _gmul(s3, 0x0B)
                ns[i + 3] = _gmul(s0, 0x0B) ^ _gmul(s1, 0x0D) ^ _gmul(s2, 0x09) ^ _gmul(s3, 0x0E)
            st = ns
    return bytes(st)


def elv_aes128_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """Pure-Python AES-128-ECB encryption (matching `FUN_ram_000185f2` / `FUN_ram_0001b07a`)."""
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    if not data or len(data) % 16 != 0:
        raise ValueError(f"AES-128-ECB input must be a non-empty multiple of 16 bytes, got {len(data)}")
    rk = _aes_expand_key(key)
    return b"".join(_aes128_encrypt_block(rk, data[i : i + 16]) for i in range(0, len(data), 16))


def elv_aes128_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    """Pure-Python AES-128-ECB decryption (matching `FUN_ram_0001863e` / `FUN_ram_0001b1ea`)."""
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    if not data or len(data) % 16 != 0:
        raise ValueError(f"AES-128-ECB input must be a non-empty multiple of 16 bytes, got {len(data)}")
    rk = _aes_expand_key(key)
    return b"".join(_aes128_decrypt_block(rk, data[i : i + 16]) for i in range(0, len(data), 16))


def elv_crc32(data: bytes) -> int:
    """IEEE 802.3 CRC-32 matching `FUN_ram_0001b482` (init `0xFFFFFFFF`, reflected poly `0xEDB88320`, final `~crc`)."""
    return zlib.crc32(data) & 0xFFFFFFFF


def elv_crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE matching `FUN_ram_0001b442` (init `0xFFFF`, poly `0x1021`, no final XOR)."""
    crc = 0xFFFF
    for b in data:
        crc = b ^ ((crc >> 8) | ((crc & 0xFF) << 8))
        crc ^= (crc & 0xFF) >> 4
        crc ^= (crc << 12) & 0xFFFF
        crc = (crc & 0xFFFF) ^ ((crc & 0xFF) << 5)
    return crc & 0xFFFF


def elv_crc8_autosar(data: bytes) -> int:
    """AUTOSAR E2E Profile 2 CRC-8 H2F matching `FUN_ram_0001b40c` (poly `0x2F`, init `0xFF`, final XOR `0xFF`)."""
    crc = 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x2F) & 0xFF if (crc & 0x80) else (crc << 1)
    return (crc ^ 0xFF) & 0xFF


def elv_derive_eeprom_key(vaddr: int, seed10: bytes = ELV_EEH_DEFAULT_SEED10) -> bytes:
    """Derive the per-`vaddr` 16-byte AES-128 key for Marquardt EEH Data Flash (`FUN_ram_00018304` + `000183de`)."""
    if len(seed10) != 10:
        raise ValueError(f"seed10 must be 10 bytes, got {len(seed10)}")
    u5 = (vaddr >> 8) & 0xFF
    p1 = vaddr & 0xFF
    u8 = u5
    u10 = p1
    u7 = seed10[0]
    u9 = seed10[1]
    c55f = seed10[2:6]
    c563 = seed10[6:10]
    out_key = bytearray()
    for _ in range(4):
        for u6 in range(4):
            for u26 in range(7, -1, -1):
                u1 = u5 >> 5
                u2 = u5 >> 4
                u3 = u5 >> 2
                u4 = u5 >> 1
                u25 = p1 >> 7
                u19 = p1 >> 3
                u20 = p1 >> 1
                u21 = p1 & 1
                u11 = u8 >> 6
                u12 = u8 >> 2
                u13 = u8 & 1
                u14 = u10 >> 5
                u15 = u10 >> 3
                u16 = u10 >> 2
                u17 = u10 & 1
                u18 = u7 >> 6
                u22 = u7 >> 5

                u5 = ((u5 << 1) | u25) & 0xFF
                p1 = ((u8 >> 7) | ((p1 & 0x7F) << 1)) & 0xFF
                u8 = ((u10 >> 7) | ((u8 & 0x7F) << 1)) & 0xFF
                u10 = ((u7 >> 7) | ((u10 & 0x7F) << 1)) & 0xFF
                u7 = ((u9 >> 7) | ((u7 & 0x7F) << 1)) & 0xFF

                idx_a = ((((u22 & 1) << 1 | ((u9 >> 4) & 1)) << 1 | ((u9 >> 3) & 1)) << 1) | ((u9 >> 1) & 1)
                idx_b = ((((u11 & 1) << 1 | (u12 & 1)) << 1 | u13) << 1) | (u14 & 1)
                idx_c = (((u25 << 1 | (u19 & 1)) << 1 | (u20 & 1)) << 1) | u21
                idx_d = ((((u1 & 1) << 1 | (u2 & 1)) << 1 | (u3 & 1)) << 1) | (u4 & 1)
                idx_e = ((((u15 & 1) << 1 | (u16 & 1)) << 1 | u17) << 1) | (u18 & 1)

                t_inner = (
                    (
                        (
                            _SBOX_108AD[idx_b]
                            | ((_SBOX_108AD[idx_c] | (_SBOX_1089D[idx_d] << 1)) << 1)
                        )
                        << 1
                    )
                    | _SBOX_108AD[idx_e]
                ) & 0x7F
                idx_outer = _SBOX_1089D[idx_a] | (t_inner << 1)
                fb_bit = (((c55f[u6] >> u26) ^ (c563[u6] >> u26)) & 1) ^ _SBOX_108BD[idx_outer]
                u9 = (fb_bit | ((u9 & 0x7F) << 1)) & 0xFF
        out_key.extend((u5, p1, u8, u10))
    return bytes(out_key)


def elv_decrypt_eeh_payload(
    vaddr: int,
    raw_payload: bytes,
    *,
    seed10: bytes = ELV_EEH_DEFAULT_SEED10,
) -> tuple[bytes, int, int, int, bool]:
    """Decrypt an EEELib record payload (if `flags & 0x02`) and verify its Big-Endian IEEE CRC-32."""
    vlen = len(raw_payload)
    if vlen < 24 or (vlen - 8) % 16 != 0:
        raise ValueError(f"Invalid EEH payload length {vlen} for vaddr 0x{vaddr:04X}")
    data_len = vlen - 8
    meta = raw_payload[data_len:]
    flags = meta[0]
    stored_crc = struct.unpack_from(">I", meta, 1)[0]
    enc_data = raw_payload[:data_len]
    if flags & 0x02:
        key = elv_derive_eeprom_key(vaddr, seed10=seed10)
        dec_data = elv_aes128_ecb_decrypt(key, enc_data)
    else:
        dec_data = enc_data
    calc_crc = elv_crc32(dec_data + bytes([flags]))
    return dec_data, flags, stored_crc, calc_crc, (stored_crc == calc_crc)


def elv_build_eeh_payload(
    vaddr: int,
    dec_data: bytes,
    flags: int,
    tail3: bytes = b"\xff\xff\xff",
    *,
    seed10: bytes = ELV_EEH_DEFAULT_SEED10,
) -> bytes:
    """Compute Big-Endian IEEE CRC-32 over `(dec_data || flags)` and encrypt `dec_data` if `flags & 0x02`."""
    if not dec_data or len(dec_data) % 16 != 0:
        raise ValueError(f"EEH decrypted payload must be a non-empty multiple of 16 bytes, got {len(dec_data)}")
    flags_u8 = _validate_u8(flags, "flags")
    crc = elv_crc32(dec_data + bytes([flags_u8]))
    meta = bytes([flags_u8]) + struct.pack(">I", crc) + bytes(tail3[:3]).ljust(3, b"\xff")
    if flags_u8 & 0x02:
        key = elv_derive_eeprom_key(vaddr, seed10=seed10)
        enc_data = elv_aes128_ecb_encrypt(key, dec_data)
    else:
        enc_data = bytes(dec_data)
    return enc_data + meta


def elv_bootloader_seed_to_key(seed: int) -> int:
    """Exact Bootloader SecurityAccess (`27 11 / 27 12`) algorithm (`FUN_ram_00003e48`)."""
    val = (seed ^ 0x271AF9C4) & 0xFFFFFFFF
    for _ in range(9):
        lsb = val & 1
        val = (val >> 1) | (0x80000000 if lsb else 0)
        if lsb:
            val ^= 0xB45FD715
        val = (val + 0x6CA71259) & 0xFFFFFFFF
    return val


# ────────────────────────────── EEELib Data Flash Parser & Rebuilder ──────────────────────────────


def elv_raw64k_to_compact32k(raw64k: bytes) -> tuple[bytearray, list[int]]:
    """Unpack a 64 KiB programmer DFLASH dump (`4B data + 4B marker`) into 32 KiB compact + 8192 markers."""
    if len(raw64k) != ELV_DFLASH_RAW64K_SIZE:
        raise ValueError(f"Expected 65536-byte programmer DFLASH dump, got {len(raw64k)} bytes")
    compact = bytearray(ELV_DFLASH_COMPACT_SIZE)
    markers: list[int] = [0] * (ELV_DFLASH_COMPACT_SIZE // 4)
    for i in range(ELV_DFLASH_COMPACT_SIZE // 4):
        off = i * 8
        compact[i * 4 : i * 4 + 4] = raw64k[off : off + 4]
        markers[i] = struct.unpack_from("<I", raw64k, off + 4)[0]
    return compact, markers


def elv_compact32k_to_raw64k(compact: bytes | bytearray, markers: list[int]) -> bytes:
    """Repack a 32 KiB compact DFLASH image and 8192 slot markers into a 64 KiB programmer dump."""
    if len(compact) != ELV_DFLASH_COMPACT_SIZE:
        raise ValueError(f"Expected 32768-byte compact DFLASH, got {len(compact)} bytes")
    if len(markers) != ELV_DFLASH_COMPACT_SIZE // 4:
        raise ValueError(f"Expected 8192 slot markers, got {len(markers)}")
    out = bytearray(ELV_DFLASH_RAW64K_SIZE)
    for i in range(ELV_DFLASH_COMPACT_SIZE // 4):
        out[i * 8 : i * 8 + 4] = compact[i * 4 : i * 4 + 4]
        struct.pack_into("<I", out, i * 8 + 4, markers[i] & 0xFFFFFFFF)
    return bytes(out)


def _unpack_dflash_input(raw: bytes) -> tuple[bytearray, list[int] | None, str]:
    if len(raw) == ELV_DFLASH_RAW64K_SIZE:
        compact, markers = elv_raw64k_to_compact32k(raw)
        return compact, markers, "programmer_64k"
    if len(raw) == ELV_DFLASH_COMPACT_SIZE:
        return bytearray(raw), None, "compact_32k"
    raise ValueError(
        f"Unsupported ELV Data Flash size: {len(raw)} bytes "
        f"(expected {ELV_DFLASH_COMPACT_SIZE} for CAN compact dump or {ELV_DFLASH_RAW64K_SIZE} for programmer dump)"
    )


def _scan_eeelib_pool(
    compact: bytes | bytearray,
    markers: list[int] | None,
    pool_index: int,
    *,
    seed10: bytes = ELV_EEH_DEFAULT_SEED10,
) -> dict[str, Any]:
    """Scan one 16 KiB EEELib pool (`Pool 0`: `0x0000..0x3FFF`, `Pool 1`: `0x4000..0x7FFF`)."""
    base = pool_index * ELV_DFLASH_POOL_SIZE
    end = base + ELV_DFLASH_POOL_SIZE
    active_marker = struct.unpack_from("<I", compact, end - 8)[0]
    cnt_val, cnt_inv = struct.unpack_from("<HH", compact, end - 4)
    counter_valid = ((cnt_val ^ cnt_inv) & 0xFFFF) == 0xFFFF

    dir_entries: list[tuple[int, int, int]] = []
    dir_map: dict[int, int] = {}
    valid_dir_count = 0
    for idx in range(ELV_EEELIB_DIR_COUNT):
        va, vl = struct.unpack_from("<HH", compact, base + idx * 4)
        dir_entries.append((idx, va, vl))
        if 0 < va < 0x2000 and 24 <= vl <= 0x400 and (vl - 8) % 16 == 0:
            dir_map[va] = vl
            valid_dir_count += 1

    active_records: dict[int, tuple[int, int, bytes]] = {}
    active_crc_ok: dict[int, bool] = {}
    all_instances: list[tuple[int, int, int, bytes]] = []
    if valid_dir_count >= 16:
        pos = base + ELV_EEELIB_DIR_COUNT * 4
        limit = end - 16
        while pos < limit:
            slot = pos // 4
            if markers is not None and markers[slot] != 0x00000000:
                pos += 4
                continue
            va, vl = struct.unpack_from("<HH", compact, pos)
            if dir_map.get(va) == vl and pos + vl + 8 <= end - 8:
                t_va, t_vl = struct.unpack_from("<HH", compact, pos + 4 + vl)
                if (t_va, t_vl) == (va, vl):
                    payload = bytes(compact[pos + 4 : pos + 4 + vl])
                    all_instances.append((pos, va, vl, payload))
                    try:
                        _, _, _, _, ok = elv_decrypt_eeh_payload(va, payload, seed10=seed10)
                    except ValueError:
                        ok = False
                    # Records grow downward from end-16 toward 0x00BC: lowest offset is newest committed copy.
                    # Prefer the newest CRC-valid instance so a torn newest copy never shadows an intact prior copy.
                    if va not in active_records or (not active_crc_ok[va] and ok):
                        active_records[va] = (pos, vl, payload)
                        active_crc_ok[va] = ok
                    pos += vl + 8
                    continue
            pos += 4

    return {
        "pool_index": pool_index,
        "base": base,
        "active_marker": active_marker,
        "has_active_marker": active_marker == ELV_EEELIB_ACTIVE_MARKER,
        "counter": cnt_val if counter_valid else None,
        "counter_hex": f"0x{cnt_val:04X}" if counter_valid else None,
        "valid_dir_count": valid_dir_count,
        "dir_entries": dir_entries,
        "active_records": active_records,
        "all_instances": all_instances,
    }


def _select_active_pool(
    compact: bytes | bytearray,
    markers: list[int] | None,
    *,
    seed10: bytes = ELV_EEH_DEFAULT_SEED10,
) -> tuple[dict[str, Any], dict[int, dict[str, Any]]]:
    p0 = _scan_eeelib_pool(compact, markers, 0, seed10=seed10)
    p1 = _scan_eeelib_pool(compact, markers, 1, seed10=seed10)

    def _score(p: dict[str, Any]) -> tuple[int, int, int, int]:
        return (
            1 if (p["valid_dir_count"] == ELV_EEELIB_DIR_COUNT and len(p["active_records"]) >= 30) else 0,
            1 if p["has_active_marker"] else 0,
            len(p["active_records"]),
            p["valid_dir_count"],
        )

    s0, s1 = _score(p0), _score(p1)
    if s1 > s0:
        chosen = p1
    elif s0 > s1:
        chosen = p0
    else:
        c0, c1 = p0["counter"], p1["counter"]
        if c0 is not None and c1 is not None:
            chosen = p1 if (c1 != c0 and ((c1 - c0) & 0xFFFF) < 0x8000) else p0
        elif c1 is not None:
            chosen = p1
        else:
            chosen = p0
    if chosen["valid_dir_count"] < 16 or not chosen["active_records"]:
        raise ValueError("No valid Marquardt ELV EEELib pool found in Data Flash dump")
    return chosen, {0: p0, 1: p1}


def _select_valid_triple_copy(
    vaddrs: tuple[int, ...],
    active: dict[int, tuple[int, int, bytes]],
    seed10: bytes = ELV_EEH_DEFAULT_SEED10,
) -> bytes | None:
    """Select decrypted payload from a triple-copy block using CRC-32 verified 2-of-3 majority voting."""
    valid_copies: list[bytes] = []
    for va in vaddrs:
        rec = active.get(va)
        if rec is None:
            continue
        try:
            dec, _, _, _, ok = elv_decrypt_eeh_payload(va, rec[2], seed10=seed10)
        except ValueError:
            continue
        if ok:
            valid_copies.append(dec)
    if not valid_copies:
        return None
    for cand in valid_copies:
        if valid_copies.count(cand) >= 2:
            return cand
    return valid_copies[0]


def elv_is_dflash_bytes(raw: bytes) -> bool:
    """Fast structural detector for 32 KiB CAN compact or 64 KiB programmer Marquardt ELV Data Flash dumps."""
    if len(raw) not in (ELV_DFLASH_COMPACT_SIZE, ELV_DFLASH_RAW64K_SIZE):
        return False
    try:
        compact, markers, _ = _unpack_dflash_input(raw)
        chosen, _ = _select_active_pool(compact, markers)
        active = chosen["active_records"]
        dec0 = _select_valid_triple_copy((0x0001, 0x0069, 0x00D1), active)
        dec34 = _select_valid_triple_copy((0x07D1, 0x0809, 0x0841), active)
        return dec0 is not None and dec34 is not None
    except Exception:
        return False


def elv_parse_dflash(raw: bytes, *, seed10: bytes = ELV_EEH_DEFAULT_SEED10) -> dict[str, Any]:
    """Decode and verify all 47 EEELib records of a 32 KiB or 64 KiB Marquardt 3Q0 905 861 Data Flash dump."""
    compact, markers, fmt = _unpack_dflash_input(raw)
    chosen, pools = _select_active_pool(compact, markers, seed10=seed10)
    active = chosen["active_records"]
    dir_entries: list[tuple[int, int, int]] = chosen["dir_entries"]

    records_out: list[dict[str, Any]] = []
    decrypted_by_vaddr: dict[int, bytes] = {}
    crc_ok_by_vaddr: dict[int, bool] = {}
    crc_valid_count = 0

    for idx, va, vl in dir_entries:
        if va not in active:
            records_out.append(
                {
                    "id": idx,
                    "vaddr": va,
                    "vaddr_hex": f"0x{va:04X}",
                    "vlen": vl,
                    "present": False,
                    "crc_ok": False,
                }
            )
            continue
        pos, _, payload = active[va]
        dec, flags, scrc, ccrc, ok = elv_decrypt_eeh_payload(va, payload, seed10=seed10)
        if ok:
            crc_valid_count += 1
        decrypted_by_vaddr[va] = dec
        crc_ok_by_vaddr[va] = ok
        flag_names = []
        if flags & 0x01:
            flag_names.append("CRC")
        if flags & 0x02:
            flag_names.append("AES")
        if flags & 0x08:
            flag_names.append("TRIPLE")
        records_out.append(
            {
                "id": idx,
                "vaddr": va,
                "vaddr_hex": f"0x{va:04X}",
                "vlen": vl,
                "compact_offset": pos,
                "compact_offset_hex": f"0x{pos:04X}",
                "raw64k_offset_hex": f"0x{pos * 2:05X}",
                "present": True,
                "flags": flags,
                "flags_hex": f"0x{flags:02X}",
                "flags_label": "+".join(flag_names) if flag_names else "RAW",
                "stored_crc": scrc,
                "calc_crc": ccrc,
                "crc_hex": f"0x{scrc:08X}",
                "crc_ok": ok,
                "data_hex": dec.hex().upper(),
            }
        )

    triple_checks: dict[str, bool] = {}
    for gname, vaddrs in ELV_TRIPLE_COPY_GROUPS:
        copies = [decrypted_by_vaddr.get(v) for v in vaddrs]
        triple_checks[gname] = (
            all(c is not None and crc_ok_by_vaddr.get(v, False) for v, c in zip(vaddrs, copies))
            and copies[0] == copies[1] == copies[2]
        )

    def _best_block(vaddrs: tuple[int, ...]) -> bytes:
        voted = _select_valid_triple_copy(vaddrs, active, seed10)
        if voted is not None:
            return voted
        for v in vaddrs:
            if v in decrypted_by_vaddr:
                return decrypted_by_vaddr[v]
        return b""

    dec0 = _best_block((0x0001, 0x0069, 0x00D1))
    dec1 = _best_block((0x0139,))
    dec2 = _best_block((0x0181, 0x0199, 0x01B1))
    dec4 = _best_block((0x0201, 0x0219, 0x0231))
    dec7 = _best_block((0x0279, 0x02B1, 0x02E9))
    dec8 = _best_block((0x0321, 0x0369, 0x03B1))
    dec31 = _best_block((0x0759,))
    dec32 = _best_block((0x0771,))
    dec34 = _best_block((0x07D1, 0x0809, 0x0841))

    part_number = _clean_ascii(dec0[0:11]) if len(dec0) >= 11 else ""
    hw_part_number = _clean_ascii(dec0[25:36]) if len(dec0) >= 36 else ""
    hw_version = _clean_ascii(dec0[36:39]) if len(dec0) >= 39 else ""
    asam_odx = _clean_ascii(dec0[39:55].split(b"\x00", 1)[0]) if len(dec0) >= 55 else ""
    asam_version = _clean_ascii(dec0[55:61]) if len(dec0) >= 61 else ""
    fazit = _clean_ascii(dec0[66:89]) if len(dec0) >= 89 else ""

    sw_version = ""
    app_valid_byte: int | None = None
    reprog_flag_byte: int | None = None
    if len(dec1) >= 24:
        reprog_flag_byte = dec1[1]
        app_valid_byte = dec1[2]
        # Block 1 holds bootloader/app/dataset 4-digit ASCII versions; offset 10..14 is the primary app SW slot.
        cand_app = dec1[10:14]
        if cand_app.isdigit() and cand_app != b"0000":
            sw_version = cand_app.decode("ascii")
        if not sw_version:
            for off in range(0, len(dec1) - 3):
                cand = dec1[off : off + 4]
                prev_digit = off > 0 and 0x30 <= dec1[off - 1] <= 0x39
                next_digit = (off + 4) < len(dec1) and 0x30 <= dec1[off + 4] <= 0x39
                if not prev_digit and not next_digit and cand.isdigit() and cand != b"0000":
                    sw_version = cand.decode("ascii")
                    break
        if not sw_version:
            for off in range(0, len(dec1) - 3):
                cand = dec1[off : off + 4]
                if cand.isdigit() and cand != b"0000":
                    sw_version = cand.decode("ascii")
                    break

    serial = _clean_ascii(dec7[16:30]) if len(dec7) >= 30 else ""
    coding_hex = dec8[0:8].hex().upper() if len(dec8) >= 8 else ""
    coding_date = dec8[8:11].hex().upper() if len(dec8) >= 11 else ""
    wsc_hex = dec8[11:17].hex().upper() if len(dec8) >= 17 else ""
    dataset_pn = _clean_ascii(dec8[17:28]) if len(dec8) >= 28 else ""

    vin_raw = dec34[0:17] if len(dec34) >= 17 else b""
    vin = _clean_ascii(vin_raw) if vin_raw else ""
    slot_a_bytes = dec34[17:33] if len(dec34) >= 33 else b""
    power_class = dec34[33] if len(dec34) >= 34 else None
    cfg_byte = dec34[34] if len(dec34) >= 35 else None
    brand_byte = dec34[35] if len(dec34) >= 36 else None
    mode = dec34[36] if len(dec34) >= 37 else None

    idp_bytes = dec4[1:3] if len(dec4) >= 3 else b""
    idac_bytes = dec4[3:5] if len(dec4) >= 5 else b""
    idac_state = dec4[5] if len(dec4) >= 6 else None
    last_r_bytes = dec4[6:10] if len(dec4) >= 10 else b""

    lockout_timers_hex = dec2[0:3].hex().upper() if len(dec2) >= 3 else ""
    error_counters_hex = dec2[3:6].hex().upper() if len(dec2) >= 6 else ""
    virgin_opens_left = struct.unpack_from(">H", dec2, 6)[0] if len(dec2) >= 8 else None

    bolt_state = dec31[1] if len(dec31) >= 2 else None
    lock_cycles = struct.unpack_from(">H", dec31, 4)[0] if len(dec31) >= 6 else None

    reset_counter = dec32[0] if len(dec32) >= 1 else None
    dem_fault_mask_hex = dec32[1:9].hex().upper() if len(dec32) >= 9 else ""

    # Decode stored DTC slots (IDs 19..38, vaddr 0x03F9..0x06F1)
    stored_dtcs: list[dict[str, Any]] = []
    for slot_i in range(20):
        rec_id = 19 + slot_i
        if rec_id >= len(dir_entries):
            break
        _, va, _ = dir_entries[rec_id]
        dec_slot = decrypted_by_vaddr.get(va)
        if not dec_slot or len(dec_slot) < 4:
            continue
        if dec_slot[0] == 0xFF and dec_slot[1] == 0xFF:
            continue
        dtc_idx = dec_slot[0]
        status_byte = dec_slot[2]
        if dtc_idx < len(ELV_DTC_ORDER):
            code = ELV_DTC_ORDER[dtc_idx]
            disp, desc = describe_elv(code)
        else:
            code = dtc_idx
            disp, desc = f"IDX_{dtc_idx:02X}", tr("Неизвестный индекс DTC", "Unknown DTC index")
        stored_dtcs.append(
            {
                "slot": slot_i,
                "vaddr_hex": f"0x{va:04X}",
                "dtc_index": dtc_idx,
                "code": code,
                "code_hex": f"{code:06X}",
                "display": disp,
                "description": desc,
                "status": status_byte,
                "status_hex": f"0x{status_byte:02X}",
                "raw_hex": dec_slot[:28].hex().upper(),
            }
        )

    return {
        "format": fmt,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "active_pool": chosen["pool_index"],
        "pool0_counter": pools[0]["counter_hex"],
        "pool1_counter": pools[1]["counter_hex"],
        "total_committed_instances": len(chosen["all_instances"]),
        "crc_valid_count": crc_valid_count,
        "crc_total_count": len(dir_entries),
        "all_crc_ok": crc_valid_count == len(dir_entries),
        "triple_copy_checks": triple_checks,
        "triple_copy_ok": all(triple_checks.values()),
        "identity": {
            "part_number": part_number,
            "sw_version": sw_version,
            "hw_part_number": hw_part_number,
            "hw_version": hw_version,
            "asam_odx": asam_odx,
            "asam_version": asam_version,
            "fazit": fazit,
            "serial": serial,
            "coding_hex": coding_hex,
            "coding_date": coding_date,
            "wsc_hex": wsc_hex,
            "dataset_pn": dataset_pn,
            "reprog_flag": reprog_flag_byte,
            "app_valid_byte": app_valid_byte,
        },
        "block34": {
            "vin": vin,
            "slot_a_hex": slot_a_bytes.hex().upper(),
            "power_class": power_class,
            "power_class_hex": f"0x{power_class:02X}" if power_class is not None else None,
            "config": cfg_byte,
            "config_hex": f"0x{cfg_byte:02X}" if cfg_byte is not None else None,
            "brand": brand_byte,
            "brand_hex": f"0x{brand_byte:02X}" if brand_byte is not None else None,
            "mode": mode,
            "mode_hex": f"0x{mode:02X}" if mode is not None else None,
            "mode_label": elv_mode_label(mode),
        },
        "block04": {
            "idp_hex": idp_bytes.hex().upper(),
            "idac_hex": idac_bytes.hex().upper(),
            "idac_state": idac_state,
            "idac_state_hex": f"0x{idac_state:02X}" if idac_state is not None else None,
            "idac_state_label": elv_idac_state_label(idac_state),
            "last_r_hex": last_r_bytes.hex().upper(),
        },
        "block02": {
            "lockout_timers_hex": lockout_timers_hex,
            "error_counters_hex": error_counters_hex,
            "virgin_opens_left": virgin_opens_left,
        },
        "block31": {
            "bolt_state": bolt_state,
            "bolt_state_hex": f"0x{bolt_state:02X}" if bolt_state is not None else None,
            "bolt_state_label": elv_bolt_state_label(bolt_state),
            "lock_cycles": lock_cycles,
        },
        "block32": {
            "reset_counter": reset_counter,
            "dem_fault_mask_hex": dem_fault_mask_hex,
        },
        "stored_dtcs": stored_dtcs,
        "records": records_out,
    }


def elv_update_dflash_records(
    raw: bytes,
    updates: dict[int, bytes],
    *,
    seed10: bytes = ELV_EEH_DEFAULT_SEED10,
) -> bytes:
    """Rebuild all committed copies of each updated `vaddr` in the active EEELib pool, preserving 32K or 64K format."""
    compact, markers, fmt = _unpack_dflash_input(raw)
    chosen, _ = _select_active_pool(compact, markers, seed10=seed10)
    active = chosen["active_records"]
    all_instances: list[tuple[int, int, int, bytes]] = chosen["all_instances"]

    touched: set[int] = set()
    for pos, va, vl, old_payload in all_instances:
        if va not in updates:
            continue
        new_dec = bytes(updates[va])
        if len(new_dec) != vl - 8:
            raise ValueError(
                f"Update length mismatch for vaddr 0x{va:04X}: expected {vl - 8} bytes, got {len(new_dec)}"
            )
        ref_payload = active[va][2] if va in active else old_payload
        flags = ref_payload[vl - 8]
        tail3 = ref_payload[vl - 3 : vl]
        new_payload = elv_build_eeh_payload(va, new_dec, flags, tail3, seed10=seed10)
        compact[pos + 4 : pos + 4 + vl] = new_payload
        touched.add(va)

    missing = set(updates.keys()) - touched
    if missing:
        miss_s = ", ".join(f"0x{v:04X}" for v in sorted(missing))
        raise ValueError(f"Requested vaddr(s) not present in active EEELib pool: {miss_s}")

    if fmt == "programmer_64k":
        assert markers is not None
        return elv_compact32k_to_raw64k(compact, markers)
    return bytes(compact)


def elv_virginize_dflash(
    raw: bytes,
    *,
    virgin_k5: bytes | str | None = None,
    seed10: bytes = ELV_EEH_DEFAULT_SEED10,
) -> bytes:
    """Offline Virginizer (`Mode 2 -> Mode 1`): clears VIN/IDac/lockouts and sets Virgin state across all triple copies."""
    compact, markers, _ = _unpack_dflash_input(raw)
    chosen, _ = _select_active_pool(compact, markers, seed10=seed10)
    active = chosen["active_records"]

    dec4 = _select_valid_triple_copy((0x0201, 0x0219, 0x0231), active, seed10)
    if dec4 is None:
        raise ValueError(
            tr(
                "Ни одна из 3 копий Block 4 (0x0201 / 0x0219 / 0x0231, IDp/IDac) не прошла проверку CRC-32 — "
                "операция отменена, чтобы не перезаписать повреждённый IDp во все 3 копии.",
                "None of the 3 copies of Block 4 (0x0201 / 0x0219 / 0x0231, IDp/IDac) passed CRC-32 verification — "
                "aborted to avoid sealing a corrupted IDp into all 3 copies.",
            )
        )
    dec34 = _select_valid_triple_copy((0x07D1, 0x0809, 0x0841), active, seed10)
    if dec34 is None:
        raise ValueError(
            tr(
                "Ни одна из 3 копий Block 34 (0x07D1 / 0x0809 / 0x0841, WFS5 / K_5) не прошла проверку CRC-32 — "
                "операция отменена, чтобы не перезаписать повреждённый K_5 во все 3 копии.",
                "None of the 3 copies of Block 34 (0x07D1 / 0x0809 / 0x0841, WFS5 / K_5) passed CRC-32 verification — "
                "aborted to avoid sealing a corrupted K_5 key into all 3 copies.",
            )
        )

    k5 = _norm_hex_bytes(virgin_k5, 16, "virgin_k5") if virgin_k5 is not None else dec34[17:33]

    # Block 2: clear lockout timers & error counters, restore 255 Virgin unlocks
    new_dec2 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]) + (b"\xff" * 8)

    # Block 4: keep ELV's own IDp (+1..2), clear learned IDac (+3..4), learning state (+5 = 0x00), last R (+6..9)
    new_dec4 = bytearray(dec4)
    new_dec4[3:5] = b"\x00\x00"
    new_dec4[5] = 0x00
    new_dec4[6:10] = b"\x00\x00\x00\x00"

    # Block 34: VIN = '-'*17, K_5 = k5, PowerClass = 0x00, Config = 0x80, Brand = 0x00, Mode = 0x01
    new_dec34 = (b"-" * 17) + k5 + bytes([0x00, 0x80, 0x00, 0x01]) + bytes(11)

    updates = {
        0x0181: new_dec2,
        0x0199: new_dec2,
        0x01B1: new_dec2,
        0x0201: bytes(new_dec4),
        0x0219: bytes(new_dec4),
        0x0231: bytes(new_dec4),
        0x07D1: new_dec34,
        0x0809: new_dec34,
        0x0841: new_dec34,
    }
    return elv_update_dflash_records(raw, updates, seed10=seed10)


def elv_adapt_dflash(
    raw: bytes,
    *,
    vin: str | bytes,
    k5: bytes | str,
    power_class: int,
    idac: bytes | str | None = None,
    config_byte: int | None = None,
    brand_byte: int | None = None,
    seed10: bytes = ELV_EEH_DEFAULT_SEED10,
) -> bytes:
    """Offline direct vehicle adapter: writes VIN, `K_5 / Slot A`, `PowerClass`, `Mode=2`, and `IDac` (or auto-learn)."""
    compact, markers, _ = _unpack_dflash_input(raw)
    chosen, _ = _select_active_pool(compact, markers, seed10=seed10)
    active = chosen["active_records"]

    dec4 = _select_valid_triple_copy((0x0201, 0x0219, 0x0231), active, seed10)
    if dec4 is None:
        raise ValueError(
            tr(
                "Ни одна из 3 копий Block 4 (0x0201 / 0x0219 / 0x0231, IDp/IDac) не прошла проверку CRC-32 — "
                "операция отменена, чтобы не перезаписать повреждённый IDp во все 3 копии.",
                "None of the 3 copies of Block 4 (0x0201 / 0x0219 / 0x0231, IDp/IDac) passed CRC-32 verification — "
                "aborted to avoid sealing a corrupted IDp into all 3 copies.",
            )
        )
    dec34 = _select_valid_triple_copy((0x07D1, 0x0809, 0x0841), active, seed10)
    if dec34 is None:
        raise ValueError(
            tr(
                "Ни одна из 3 копий Block 34 (0x07D1 / 0x0809 / 0x0841, WFS5 / K_5) не прошла проверку CRC-32 — "
                "операция отменена, чтобы не перезаписать повреждённый блок WFS5 во все 3 копии.",
                "None of the 3 copies of Block 34 (0x07D1 / 0x0809 / 0x0841, WFS5 / K_5) passed CRC-32 verification — "
                "aborted to avoid sealing a corrupted WFS5 block into all 3 copies.",
            )
        )

    vin_bytes = _norm_vin17(vin)
    k5_bytes = _norm_hex_bytes(k5, 16, "k5")
    pc = _validate_u8(power_class, "power_class")
    if config_byte is None:
        raw_cfg = dec34[34]
        cfg = 0x80 if raw_cfg in (0x00, 0xFF) else raw_cfg
    else:
        cfg = _validate_u8(config_byte, "config_byte")
    if brand_byte is None:
        raw_brand = dec34[35]
        brand = 0x01 if raw_brand in (0x00, 0xFF) else raw_brand
    else:
        brand = _validate_u8(brand_byte, "brand_byte")

    new_dec2 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]) + (b"\xff" * 8)

    new_dec4 = bytearray(dec4)
    if idac is not None and str(idac).strip() != "":
        idac_bytes = _norm_hex_bytes(idac, 2, "idac")
        new_dec4[3:5] = idac_bytes
        new_dec4[5] = 0xAA  # Locked to target instrument cluster IDac
    else:
        new_dec4[3:5] = b"\x00\x00"
        new_dec4[5] = 0x00  # Auto-learns target cluster IDac on first two 0x01B handshakes
    new_dec4[6:10] = b"\x00\x00\x00\x00"

    new_dec34 = vin_bytes + k5_bytes + bytes([pc, cfg, brand, 0x02]) + bytes(11)

    updates = {
        0x0181: new_dec2,
        0x0199: new_dec2,
        0x01B1: new_dec2,
        0x0201: bytes(new_dec4),
        0x0219: bytes(new_dec4),
        0x0231: bytes(new_dec4),
        0x07D1: new_dec34,
        0x0809: new_dec34,
        0x0841: new_dec34,
    }
    return elv_update_dflash_records(raw, updates, seed10=seed10)


# ────────────────────────────── Online UDS & CAN Protocol Builders ──────────────────────────────


def elv_compute_02f9_mac(
    k5: bytes | str,
    *,
    fazit: bytes | str,
    vin: bytes | str,
    did_02ed: bytes,
    did_02ee: bytes,
    c_diag: bytes,
) -> bytes:
    """Compute the exact 5-byte `UDS 22 02F9` reply (`FUN_ram_00028058`).

    Algorithm verified against live bench hardware (`3Q0 905 861 SW 0032`):
      1. `buf64 = FAZIT[23] || VIN[17] || DID_02ED[10] || DID_02EE[10] || C_diag[4]`
      2. `crc   = elv_crc32(buf64)`
      3. `pt16  = pack('<I', crc) || ROM[0x11ED1..0x11EDC] (0cc348950d3089a23f47e658)`
      4. `ct16  = AES-128-ECB(K_5, pt16)`
      5. `reply = b'\\x82' || ct16[3::-1]`
    """
    k5_bytes = _norm_hex_bytes(k5, 16, "k5")
    fazit_b = (fazit.encode("ascii") if isinstance(fazit, str) else bytes(fazit))[:23].ljust(23, b" ")
    vin_b = (vin.encode("ascii") if isinstance(vin, str) else bytes(vin))[:17].ljust(17, b" ")
    if len(did_02ed) != 10:
        raise ValueError(f"DID 0x02ED must be 10 bytes, got {len(did_02ed)}")
    if len(did_02ee) != 10:
        raise ValueError(f"DID 0x02EE must be 10 bytes, got {len(did_02ee)}")
    if len(c_diag) != 4:
        raise ValueError(f"DID 0x02E0 challenge must be 4 bytes, got {len(c_diag)}")

    buf64 = fazit_b + vin_b + bytes(did_02ed) + bytes(did_02ee) + bytes(c_diag)
    assert len(buf64) == 64
    crc = elv_crc32(buf64)
    pt16 = struct.pack("<I", crc) + ELV_02F9_CONST12
    ct16 = elv_aes128_ecb_encrypt(k5_bytes, pt16)
    return bytes([0x82]) + ct16[3::-1]


def elv_verify_02f9(
    k5: bytes | str,
    response_02f9: bytes,
    *,
    fazit: bytes | str,
    vin: bytes | str,
    did_02ed: bytes,
    did_02ee: bytes,
    c_diag: bytes,
) -> dict[str, Any]:
    """Verify a live 5-byte `UDS 22 02F9` response against candidate `K_5 / Slot A`."""
    expected = elv_compute_02f9_mac(
        k5,
        fazit=fazit,
        vin=vin,
        did_02ed=did_02ed,
        did_02ee=did_02ee,
        c_diag=c_diag,
    )
    actual = bytes(response_02f9)
    return {
        "match": actual == expected,
        "status_byte": actual[0] if actual else None,
        "expected_hex": expected.hex().upper(),
        "actual_hex": actual.hex().upper(),
        "expected_mac_hex": expected[1:].hex().upper(),
        "actual_mac_hex": actual[1:].hex().upper() if len(actual) >= 5 else "",
    }


def elv_build_02e1_payload(
    k5: bytes | str,
    c_diag: bytes | str,
    *,
    cmd: int = 0x04,
    arg: int = 0x80,
) -> bytes:
    """Build the exact 4-byte `UDS 2E 02E1` command payload (`FUN_ram_00027dd6`).

    Supported commands in 3Q0 905 861 SW 0032:
      - `(cmd=0x04, arg=0x80)`: Reset learned `IDac` state (`0xAA -> 0x00`) in Adapted Mode 2.
      - `(cmd=0x08, arg=0x00)`: Set internal diagnostic WFS authorization test flag (`c69b = 1`).
    """
    if (cmd, arg) not in (ELV_CMD_RESET_IDAC, ELV_CMD_DIAG_TEST):
        raise ValueError(
            f"Unsupported 0x02E1 (cmd, arg) = (0x{cmd:02X}, 0x{arg:02X}); "
            "expected (0x04, 0x80) [reset IDac] or (0x08, 0x00) [diag test]"
        )
    k5_bytes = _norm_hex_bytes(k5, 16, "k5")
    cd_bytes = _norm_hex_bytes(c_diag, 4, "c_diag")
    if cd_bytes == b"\x00\x00\x00\x00":
        raise ValueError("c_diag challenge from DID 0x02E0 must be non-zero")
    pt16 = bytes([cmd & 0xFF, arg & 0xFF]) + cd_bytes + ELV_02E1_CONST10
    ct16 = elv_aes128_ecb_encrypt(k5_bytes, pt16)
    tag16 = elv_crc16_ccitt(ct16)
    return struct.pack(">H", tag16) + bytes([cmd & 0xFF, arg & 0xFF])


def elv_build_02e2_adapt_payload(
    current_k5: bytes | str,
    *,
    new_vin: str | bytes,
    new_k5: bytes | str,
    new_power_class: int,
    cfg_byte: int = 0x80,
    brand_byte: int = 0x01,
) -> bytes:
    """Build the 52-byte `UDS 2E 02E2` payload for vehicle adaptation (`FUN_ram_00027bc2`).

    Format: `AES-128-ECB(current_k5, pt[0..47]) || BigEndian_u32(CRC32(pt[0..47]))`.
    On acceptance, ELV writes new VIN/K_5/PowerClass, sets Mode=2, clears lockouts, and resets `IDac` state to `0x00`.
    """
    cur_k5 = _norm_hex_bytes(current_k5, 16, "current_k5")
    target_k5 = _norm_hex_bytes(new_k5, 16, "new_k5")
    vin_bytes = _norm_vin17(new_vin)
    pc = _validate_u8(new_power_class, "new_power_class")
    cfg = _validate_u8(cfg_byte, "cfg_byte")
    brand = _validate_u8(brand_byte, "brand_byte")
    pt = (
        vin_bytes
        + target_k5
        + bytes([pc, cfg, brand, 0x02])
        + bytes(11)
    )
    assert len(pt) == 48
    crc = elv_crc32(pt)
    ct = elv_aes128_ecb_encrypt(cur_k5, pt)
    return ct + struct.pack(">I", crc)


def elv_build_02e2_virgin_payload(
    current_k5: bytes | str,
    *,
    virgin_k5: bytes | str | None = None,
) -> bytes:
    """Build the 52-byte `UDS 2E 02E2` Virgin Reset payload (`FUN_ram_00027ad0`, `Mode 2 -> Mode 1` over CAN).

    If `virgin_k5` is omitted, keeps `current_k5` as the Virgin transport key so future CAN operations stay authenticated.
    """
    cur_k5 = _norm_hex_bytes(current_k5, 16, "current_k5")
    vk5 = _norm_hex_bytes(virgin_k5, 16, "virgin_k5") if virgin_k5 is not None else cur_k5
    pt = (b"\xff" * 17) + vk5 + bytes([0x00, 0xFF, 0xFF, 0x03]) + bytes(11)
    assert len(pt) == 48
    crc = elv_crc32(pt)
    ct = elv_aes128_ecb_encrypt(cur_k5, pt)
    return ct + struct.pack(">I", crc)


def elv_wfs5_mac(
    k5: bytes | str,
    power_class: int,
    data_a: bytes,
    data_b: bytes,
    suffix3: bytes,
) -> bytes:
    """Compute the 4-byte WFS5 CAN `0x01A/0x01B` MAC (`FUN_ram_00026f94` / `FUN_ram_000272aa`).

    Firmware compares/emits CRC-32 bytes in **Little-Endian** order: `(crc & 0xFF), (crc >> 8), (crc >> 16), (crc >> 24)`.
    """
    k5_bytes = _norm_hex_bytes(k5, 16, "k5")
    pc = _validate_u8(power_class, "power_class")
    if len(data_a) != 4 or len(data_b) != 4 or len(suffix3) != 3:
        raise ValueError("WFS5 MAC requires 4B data_a, 4B data_b, and 3B suffix3")
    pt = ELV_WFS5_PREFIX + bytes([pc]) + bytes(data_a) + bytes(data_b) + bytes(suffix3)
    ct = elv_aes128_ecb_encrypt(k5_bytes, pt)
    return struct.pack("<I", elv_crc32(ct))


def elv_build_wfs5_01b_response(
    k5: bytes | str,
    power_class: int,
    p_challenge: bytes,
    r_challenge: bytes,
    idac: bytes | str,
) -> bytes:
    """Build an 8-byte Kombi `0x01B` response to ELV's `0x01A` Type 1 challenge `P` (`FUN_ram_00026f94`)."""
    idac_b = _norm_hex_bytes(idac, 2, "idac")
    mac = elv_wfs5_mac(k5, power_class, p_challenge, r_challenge, ELV_WFS5_SUFFIX_01B_REPLY)
    return bytes([mac[0], mac[1], mac[2] ^ idac_b[0], mac[3] ^ idac_b[1]]) + bytes(r_challenge)


def elv_build_wfs5_01b_casc_request(
    k5: bytes | str,
    power_class: int,
    r_challenge: bytes,
    idac: bytes | str,
) -> bytes:
    """Build an 8-byte autonomous Kombi `0x01B` `'casc'` challenge (`FUN_ram_000272aa`)."""
    idac_b = _norm_hex_bytes(idac, 2, "idac")
    mac = elv_wfs5_mac(k5, power_class, ELV_WFS5_CASC, r_challenge, ELV_WFS5_SUFFIX_01B_CASC)
    return bytes([mac[0], mac[1], mac[2] ^ idac_b[0], mac[3] ^ idac_b[1]]) + bytes(r_challenge)


def elv_verify_wfs5_01a_reply(
    k5: bytes | str,
    power_class: int,
    frame_01a: bytes,
    *,
    r_challenge: bytes,
    p_challenge: bytes | None = None,
    expected_idp: bytes | str | None = None,
) -> dict[str, Any]:
    """Verify an ELV `0x01A` Type 2 (`p_challenge` given) or Type 3 (`'casc'`) response and recover `IDp`."""
    pc = _validate_u8(power_class, "power_class")
    raw = bytes(frame_01a)
    if len(raw) < 8:
        raise ValueError(f"Expected 8-byte 0x01A frame, got {len(raw)} bytes")
    msg_type = raw[0]
    if msg_type == 0x02:
        if p_challenge is None:
            raise ValueError("p_challenge is required to verify 0x01A Type 2 reply")
        mac = elv_wfs5_mac(k5, pc, r_challenge, p_challenge, ELV_WFS5_SUFFIX_01A_TYPE2)
    elif msg_type == 0x03:
        mac = elv_wfs5_mac(k5, pc, r_challenge, ELV_WFS5_CASC, ELV_WFS5_SUFFIX_01A_TYPE3)
    else:
        return {"ok": False, "type": msg_type, "reason": f"Unexpected 0x01A message type 0x{msg_type:02X}"}

    mac_match = raw[1] == mac[0] and raw[2] == mac[1]
    recovered_idp = bytes([raw[3] ^ mac[2], raw[4] ^ mac[3]])
    state_byte = raw[7]
    idp_match = True
    if expected_idp is not None:
        exp_b = _norm_hex_bytes(expected_idp, 2, "expected_idp")
        idp_match = recovered_idp == exp_b
    return {
        "ok": mac_match and idp_match and (state_byte & 0x03) == 0x03,
        "type": msg_type,
        "mac_match": mac_match,
        "idp_match": idp_match,
        "recovered_idp_hex": recovered_idp.hex().upper(),
        "state_byte": state_byte,
        "auth_granted": bool(state_byte & 0x01),
    }


def elv_build_3c0_frame(
    *,
    bz: int = 0,
    kl_s: bool = False,
    kl_15: bool = False,
    kl_50: bool = False,
) -> bytes:
    """Build a 4-byte E2E-valid `0x3C0 Klemmen_Status_01` frame (AUTOSAR CRC-8 `0x2F` + `Kennung 0xC3`)."""
    b1 = bz & 0x0F
    b2 = (0x01 if kl_s else 0) | (0x02 if kl_15 else 0) | (0x10 if kl_50 else 0)
    b3 = 0x00
    crc = elv_crc8_autosar(bytes([b1, b2, b3, ELV_KL_STATUS_KENNUNG]))
    return bytes([crc, b1, b2, b3])


def elv_build_dev_mem_read_frame(addr: int, length: int = 8) -> bytes:
    """Build an 8-byte `0x1BFD8A0B` Marquardt developer memory-read request (`FUN_ram_00025a62`)."""
    addr_u32 = _validate_u32(addr, "addr")
    if isinstance(length, bool) or not isinstance(length, int) or not (1 <= length <= 8):
        raise ValueError(f"Developer memory read length must be 1..8, got {length}")
    return struct.pack("<IB", addr_u32, length) + ELV_DEV_MEM_MAGIC


# ────────────────────────────── UDS Status Decoder & FPK_E Integration ──────────────────────────────


def elv_decode_status_dids(raw_dids: dict[int, bytes]) -> dict[str, Any]:
    """Decode live ELV UDS status DIDs (`1105`, `02ED`, `02EE`, `02EF`, `02E0`, `02F9`, `2C8B`, `1109`, `0600`, `F1DF`)."""
    out: dict[str, Any] = {
        "raw_dids": {f"{k:04X}": bytes(v).hex().upper() for k, v in sorted(raw_dids.items())},
    }

    if 0x1105 in raw_dids and raw_dids[0x1105]:
        mode = raw_dids[0x1105][0]
        out["mode"] = mode
        out["mode_hex"] = f"0x{mode:02X}"
        out["mode_label"] = elv_mode_label(mode)

    if 0x02ED in raw_dids and len(raw_dids[0x02ED]) >= 4:
        d = raw_dids[0x02ED]
        out["did_02ed_hex"] = d.hex().upper()
        out["wfs_mode_02ed"] = d[0]
        out["brand"] = d[1]
        out["brand_hex"] = f"0x{d[1]:02X}"
        out["wfs_version"] = d[2]
        out["power_class"] = d[3]
        out["power_class_hex"] = f"0x{d[3]:02X}"
        if "mode" not in out:
            out["mode"] = d[0]
            out["mode_hex"] = f"0x{d[0]:02X}"
            out["mode_label"] = elv_mode_label(d[0])

    if 0x02EE in raw_dids and len(raw_dids[0x02EE]) >= 2:
        d = raw_dids[0x02EE]
        out["did_02ee_hex"] = d.hex().upper()
        out["wfs_status_b0"] = d[0]
        out["wfs_status_b1"] = d[1]
        out["config_bit7"] = bool(d[1] & 0x80)
        out["idac_locked"] = bool(d[1] & 0x40)

    if 0x02EF in raw_dids and len(raw_dids[0x02EF]) >= 2:
        d = raw_dids[0x02EF]
        out["did_02ef_hex"] = d.hex().upper()
        out["lockout_02e2_timer"] = d[0]
        out["lockout_02e1_timer"] = d[1]

    if 0x02E0 in raw_dids and len(raw_dids[0x02E0]) >= 4:
        out["c_diag_hex"] = raw_dids[0x02E0][:4].hex().upper()

    if 0x02F9 in raw_dids and len(raw_dids[0x02F9]) >= 5:
        d = raw_dids[0x02F9]
        out["did_02f9_hex"] = d[:5].hex().upper()
        out["did_02f9_status"] = d[0]
        out["did_02f9_mac_hex"] = d[1:5].hex().upper()

    if 0x2C8B in raw_dids and len(raw_dids[0x2C8B]) >= 2:
        out["lock_cycles"] = struct.unpack_from(">H", raw_dids[0x2C8B], 0)[0]

    if 0x1109 in raw_dids and len(raw_dids[0x1109]) >= 4:
        d = raw_dids[0x1109]
        out["unlock_time_ms"] = struct.unpack_from(">H", d, 0)[0] * 5
        out["lock_time_ms"] = struct.unpack_from(">H", d, 2)[0] * 5

    if 0x0600 in raw_dids:
        out["coding_hex"] = raw_dids[0x0600].hex().upper()

    if 0xF1DF in raw_dids and raw_dids[0xF1DF]:
        f1df = raw_dids[0xF1DF][0]
        out["f1df_hex"] = f"0x{f1df:02X}"
        out["in_bootloader"] = (f1df & 0x04) != 0

    return out


def elv_extract_cluster_material(
    fpke_dflash: bytes,
    fpke_cflash: bytes | None = None,
    *,
    s0_hex: str | None = None,
    s1_hex: str | None = None,
) -> dict[str, Any]:
    """Extract target vehicle `VIN`, `Slot A / K_5`, `PowerClass`, `IDac`, and registered ELV `IDp` from an FPK_E dump."""
    info = analyze_fpke_dflash(fpke_dflash, fpke_cflash)
    meta = info.get("metadata") or {}
    immo_cfg = info.get("immo_config") or {}
    slot_sec = info.get("slot_secrets") or {}
    mac_fields = immo_cfg.get("mac_fields") or {}
    partners = immo_cfg.get("partners") or []

    eff_s0 = "".join((s0_hex or str(slot_sec.get("S0") or "")).split()).upper()
    eff_s1 = "".join((s1_hex or str(slot_sec.get("S1") or "")).split()).upper()
    exp_a_crc = str(slot_sec.get("A_crc32_le") or "").strip() or None
    exp_b_crc = str(slot_sec.get("B_crc32_le") or "").strip() or None

    slot_a_hex = ""
    slot_a_crc_ok: bool | None = None
    slot_a_warning: str | None = None
    if len(eff_s0) == 32 and len(eff_s1) == 32:
        try:
            ver = fpke_verify_s0_s1(
                bytes.fromhex(eff_s0),
                bytes.fromhex(eff_s1),
                expected_crc_a_le=exp_a_crc,
                expected_crc_b_le=exp_b_crc,
            )
            if ver.get("not_blank"):
                slot_a_hex = str(ver.get("slot_a_hex") or "").upper()
                slot_a_crc_ok = bool(ver.get("crc_a_ok"))
                if slot_a_crc_ok is False:
                    slot_a_warning = tr(
                        "Контрольная сумма CRC-32 ключа Slot A (K_5) не совпадает с записью EEL 0x68 в дампе FPK_E — "
                        "адаптация ELV с этим ключом небезопасна.",
                        "Slot A (K_5) CRC-32 does not match EEL 0x68 in the FPK_E dump — "
                        "adapting ELV with this key is unsafe.",
                    )
        except ValueError:
            pass

    power_class = immo_cfg.get("power_class")
    elv_partner = next((p for p in partners if str(p.get("code", "")).upper() == "ELV"), None)

    return {
        "part_number": str(meta.get("part_number") or ""),
        "vin": str(meta.get("vin") or ""),
        "immo_mode": meta.get("immo_mode"),
        "slot_a_hex": slot_a_hex,
        "slot_a_crc_ok": slot_a_crc_ok,
        "warning": slot_a_warning,
        "power_class": int(power_class) if power_class is not None else None,
        "power_class_hex": f"0x{int(power_class):02X}" if power_class is not None else "",
        "cluster_mac_id": str(immo_cfg.get("cluster_mac_id") or "").upper(),
        "cluster_elv_idp": str(mac_fields.get("elv") or "").upper(),
        "elv_adapted_in_cluster": bool(elv_partner.get("adapted")) if elv_partner else False,
    }


def is_elv_ident(ident: list[dict[str, str]]) -> bool:
    """Return True if a UDS identification list belongs to a VAG MQB Marquardt ELV (`2B` / `3Q0 905 861`)."""
    vals = " ".join(str(it.get("value", "")).upper() for it in ident)
    if "ELVMARQ" in vals or "ELV-MQB" in vals:
        return True
    for it in ident:
        did = str(it.get("did", "")).upper()
        val = str(it.get("value", "")).upper().replace(" ", "")
        if did in ("F187", "F191") and val.startswith(("3Q0905861", "5Q0905861", "2Q0905861")):
            return True
    return False


def elv_detect_folder_files(folder: Path) -> dict[str, Path]:
    """Find ELV Data Flash dump (32 KiB or 64 KiB) and optional `elv_report.json` inside `folder`."""
    found: dict[str, Path] = {}
    if not folder.is_dir():
        return found

    preferred_bins = (
        "elv_dflash_32k.bin",
        "elv_dflash_64k.bin",
        "elv_dflash.bin",
        "elv_dflash_32k_backup.bin",
        "elv_dflash_32k.raw",
        "elv_dflash_64k.raw",
    )
    for name in preferred_bins:
        cand = folder / name
        if cand.is_file():
            try:
                if elv_is_dflash_bytes(cand.read_bytes()):
                    found["dflash"] = cand
                    break
            except OSError:
                pass

    if "dflash" not in found:
        for cand in sorted(folder.iterdir()):
            if not cand.is_file() or cand.suffix.lower() not in (".bin", ".raw"):
                continue
            try:
                sz = cand.stat().st_size
                if sz in (ELV_DFLASH_COMPACT_SIZE, ELV_DFLASH_RAW64K_SIZE):
                    if elv_is_dflash_bytes(cand.read_bytes()):
                        found["dflash"] = cand
                        break
            except OSError:
                continue

    for jname in ("elv_report.json", "elv_read_report.json", "elv_backup_report.json"):
        jcand = folder / jname
        if jcand.is_file():
            found["report"] = jcand
            break

    return found
