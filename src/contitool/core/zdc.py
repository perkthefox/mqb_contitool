"""ZDC dataset parameterization engine (0x0000..0x303F) for Continental J533 Gateways.

Supports:
- ZDC Passport (`0x0000..0x007F`, 128 B): DID 0xF1A0 / 0xF1A1 / 0xF1A4, pad cleanup, LE CRC-32
- Per-block binary export / import / donor transplant / erase (`ZDC #0..#6`, keeping 0x3040..0xFFFF intact)
- `ZDC #1` (`MKE` Driver Alert, `0x0100..0x01FF`, 256 B)
- `ZDC #2` (`Start-Stop Reasons` BAP LSG 0x27, `0x0200..0x09FF`, 2048 B)
- `ZDC #4` (`MultiKo / FPA`, `0x1340..0x243F`, 4352 B): profiles, 2-level Kl.15 memory, Console MODE +
  simultaneous Steering-Wheel MFL button mapping, S031 target matrix, S033 Individual menu, schema-preserving
  presets (`JC00` / `PC00` / `NC00`), and `DID 0x0600` Long Coding consistency
- `ZDC #6` (`BEM` 14V LIN Alternator, `0x2440..0x303F`, 3072 B): 9-slot manager & 21 ROM alternator catalog
- 1-click SWaP FeC <-> ZDC dataset auto-parameterization
"""

from __future__ import annotations

from collections.abc import Iterable
import dataclasses
import struct
import zlib

from contitool.core.analyzer import analyze_dflash_datasets, check_fec_dataset_support, validate_dflash_bytes
from contitool.core.constants import (
    ZDC_DATASET_SPECS,
    ZDC_PASSPORT_EQUIP_OFF,
    ZDC_PASSPORT_PN_OFF,
    ZDC_PASSPORT_VER_OFF,
    ZDC_UDS_UPLOAD_MAP,
)
from contitool.core.zdc_templates import (
    BEM_SUPPLIER_NAMES,
    BEM_ZDC_FIELDS,
    FPA_INST1_SLOT_DEFAULTS,
    FPA_PROFILE_NAMES,
    FPA_SEC_CNTS,
    FPA_SEC_OFFS,
    FPA_SG_CATALOG,
    FPA_SHARED_SECTIONS,
    FPA_SLOT_DEFAULTS,
    FPA_TARGET_MODE_NAMES,
    MFL_KEYCODE_PRESETS,
    ROM_BEM_CATALOG,
    get_rom_bem_records,
    get_zdc_template_bytes,
)
from contitool.i18n import get_lang, tr
from contitool.progress import NULL_REPORTER, OperationReporter

ZDC_REGION_END = 0x3040
_SPEC_BY_IDX: dict[int, tuple[int, str, int, int, str, str]] = {spec[0]: spec for spec in ZDC_DATASET_SPECS}

# Powertrain & Start-Stop logical SG IDs subject to WLTP Kl.15 reset in S075
POWERTRAIN_KL15_SG_IDS: frozenset[int] = frozenset({0x21, 0x03, 0x01, 0x02, 0x04, 0x12, 0x4C})


def zdc_crc32_le(payload: bytes | bytearray | memoryview) -> int:
    """Compute IEEE 802.3 CRC-32 matching J533 firmware table-driven verifier."""
    return zlib.crc32(payload) & 0xFFFFFFFF


def seal_zdc_block_crc(raw_block: bytes | bytearray, uds_len: int | None = None) -> bytes:
    """Recompute and write trailing Little-Endian CRC-32 at `uds_len - 4`."""
    buf = bytearray(raw_block)
    pay_total = len(buf) if uds_len is None else uds_len
    if pay_total < 8 or pay_total > len(buf):
        raise ValueError(f"Invalid ZDC payload length: {pay_total} vs buffer {len(buf)}")
    crc = zdc_crc32_le(buf[: pay_total - 4])
    struct.pack_into("<I", buf, pay_total - 4, crc)
    if pay_total < len(buf):
        buf[pay_total:] = b"\xff" * (len(buf) - pay_total)
    return bytes(buf)


def _ascii_field(raw: bytes) -> str:
    if all(b == 0xFF for b in raw) or all(b == 0x00 for b in raw):
        return ""
    chars: list[str] = []
    for b in raw:
        if b in (0x00, 0xFF):
            break
        if 32 <= b <= 126:
            chars.append(chr(b))
        else:
            return ""
    return "".join(chars).strip()


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ZDC Passport (`0x0000..0x007F`, 128 B) & Per-Block Operations
# ═══════════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass
class ZdcPassport:
    empty: bool
    crc_stored: int
    crc_calc: int
    crc_ok: bool
    dataset_pn: str
    dataset_ver: str
    equip_bytes: bytes
    pads_clean: bool

    @property
    def equip_hex(self) -> str:
        return self.equip_bytes.hex().upper()

    @property
    def equip_ascii(self) -> str:
        return _ascii_field(self.equip_bytes)


_PASSPORT_PAD_SLICES: tuple[slice, ...] = (
    slice(0x04, 0x10),
    slice(0x1B, 0x20),
    slice(0x24, 0x28),
    slice(0x34, 0x80),
)


def parse_zdc_passport(df: bytes) -> ZdcPassport:
    """Decode the 128-byte ZDC Passport header at `0x0000..0x007F`."""
    validate_dflash_bytes(df)
    buf = df[0x0000:0x0080]
    empty = all(b == 0xFF for b in buf)
    crc_st, = struct.unpack_from("<I", buf, 0x00)
    crc_ca = zdc_crc32_le(buf[0x04:0x80])
    pads_clean = all(all(b == 0xFF for b in buf[sl]) for sl in _PASSPORT_PAD_SLICES)
    return ZdcPassport(
        empty=empty,
        crc_stored=crc_st,
        crc_calc=crc_ca,
        crc_ok=(not empty) and (crc_st == crc_ca),
        dataset_pn=_ascii_field(buf[ZDC_PASSPORT_PN_OFF : ZDC_PASSPORT_PN_OFF + 11]),
        dataset_ver=_ascii_field(buf[ZDC_PASSPORT_VER_OFF : ZDC_PASSPORT_VER_OFF + 4]),
        equip_bytes=bytes(buf[ZDC_PASSPORT_EQUIP_OFF : ZDC_PASSPORT_EQUIP_OFF + 12]),
        pads_clean=pads_clean,
    )


def _encode_equip_12b(val: bytes | str | None, fallback: bytes) -> bytes:
    if val is None:
        return fallback if len(fallback) == 12 else (b"\xff" * 12)
    if isinstance(val, bytes):
        if len(val) != 12:
            raise ValueError(tr("DID 0xF1A4 должен быть ровно 12 байт", "DID 0xF1A4 must be exactly 12 bytes"))
        return val
    s = val.strip()
    if not s:
        return b"\xff" * 12
    hex_cand = s.replace(" ", "").replace(":", "")
    if len(hex_cand) == 24 and all(c in "0123456789abcdefABCDEF" for c in hex_cand):
        return bytes.fromhex(hex_cand)
    raw = s.encode("ascii", errors="strict")
    if len(raw) > 12:
        raise ValueError(
            tr(
                "Код комплектации F1A4 должен быть до 12 ASCII-символов или 24 hex-символа",
                "Equipment code F1A4 must be at most 12 ASCII chars or 24 hex digits",
            )
        )
    return raw.ljust(12, b" ")


def apply_zdc_passport(
    df: bytes,
    *,
    dataset_pn: str | None = None,
    dataset_ver: str | None = None,
    equip: bytes | str | None = None,
    clean_pads: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Update ZDC Passport (`0x0000..0x007F`), optionally clean SRAM pad bytes to `0xFF`, and recalculate CRC-32."""
    validate_dflash_bytes(df)
    cur = parse_zdc_passport(df)
    out = bytearray(df)
    buf = bytearray(out[0x0000:0x0080])
    if cur.empty or clean_pads:
        for sl in _PASSPORT_PAD_SLICES:
            buf[sl] = b"\xff" * (sl.stop - sl.start)

    pn_str = (cur.dataset_pn or "V03935256AA") if dataset_pn is None else dataset_pn.strip().upper()
    if not pn_str or len(pn_str) > 11 or not all(32 <= ord(c) <= 126 for c in pn_str):
        raise ValueError(
            tr(
                "Номер датасета F1A0 должен содержать от 1 до 11 печатных ASCII-символов",
                "Dataset number F1A0 must be 1..11 printable ASCII characters",
            )
        )
    ver_str = (cur.dataset_ver or "0001") if dataset_ver is None else dataset_ver.strip().upper()
    valid_ver = len(ver_str) == 4 and ver_str != "0000" and (ver_str == "----" or (ver_str.isascii() and ver_str.isdigit()))
    if not valid_ver:
        raise ValueError(
            tr(
                "Версия датасета F1A1 должна состоять ровно из 4 цифр (или '----') и не быть '0000' (например '0001')",
                "Dataset version F1A1 must be 4 ASCII digits (or '----') and not '0000' (e.g. '0001')",
            )
        )
    eq_12 = _encode_equip_12b(equip, cur.equip_bytes)

    buf[ZDC_PASSPORT_PN_OFF : ZDC_PASSPORT_PN_OFF + 11] = pn_str.encode("ascii").ljust(11, b" ")
    buf[ZDC_PASSPORT_VER_OFF : ZDC_PASSPORT_VER_OFF + 4] = ver_str.encode("ascii")
    buf[ZDC_PASSPORT_EQUIP_OFF : ZDC_PASSPORT_EQUIP_OFF + 12] = eq_12
    crc = zdc_crc32_le(buf[0x04:0x80])
    struct.pack_into("<I", buf, 0x00, crc)

    out[0x0000:0x0080] = buf
    reporter.info(
        tr(
            f"Паспорт ZDC обновлён: F1A0={pn_str}, F1A1={ver_str}, CRC-32=0x{crc:08X}",
            f"Updated ZDC Passport: F1A0={pn_str}, F1A1={ver_str}, CRC-32=0x{crc:08X}",
        )
    )
    return bytes(out)


@dataclasses.dataclass(frozen=True)
class OdisZdcFile:
    """One ZDC dataset exactly as ODIS hands it out, with the identity that belongs to it."""

    zdc_idx: int
    payload: bytes
    dataset_pn: str
    dataset_ver: str
    start_address: int
    diagnostic_address: int
    header_tag: str


ODIS_ZDC_FILE_MAX_BYTES = 8 * 1024 * 1024  # a 4352-byte block as hex plus metadata is ~10 KB
# Written into the passport only when the unit has no dataset number of its own. It is a label served over UDS;
# the firmware never compares it with the dataset content.
ZDC_PLACEHOLDER_PN = "V03935256AA"
_ODIS_ADDR_TO_IDX = {addr: (idx, size) for idx, (addr, size) in ZDC_UDS_UPLOAD_MAP.items()}


def populated_zdc_blocks(df: bytes) -> list[int]:
    """ZDC blocks of `df` that hold a dataset with a valid CRC-32: what an upload or an export carries."""
    out = []
    for idx in sorted(ZDC_UDS_UPLOAD_MAP):
        payload = export_zdc_block(df, idx)
        if any(b != 0xFF for b in payload) and int.from_bytes(payload[-4:], "little") == zdc_crc32_le(payload[:-4]):
            out.append(idx)
    return out


# A parameterization file as ODIS writes it (GetParametrizeData, arbeits_datei_*.xml): CRLF, one space per level,
# the block as one line of upper-case hex. The ODIS_EXPLORER part is ODIS's own, copied as it is.
_ODIS_FILE_LINES = (
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<MESSAGE VERSION="1.1" DTD="XMLMSG">',
    " <RESULT>",
    '  <RESPONSE VERSION="1.4.7.1" ID="0" NAME="GetParametrizeData" DTD="RepairHints">',
    "   <DATA>",
    "    <REQUEST_ID>000000000</REQUEST_ID>",
    '    <PARAMETER_DATA LOGIN_IND="" ZDC_VERSION="{ver}" LOGIN="20103" SESSIONNAME="" DIAGNOSTIC_ADDRESS="0x19" '
    'PR_IDX="" START_ADDRESS="{addr}" DSD_TYPE="1" ZDC_NAME="{pn}" FILENAME="">{hex}</PARAMETER_DATA>',
    "   </DATA>",
    "  </RESPONSE>",
    " </RESULT>",
    ' <ODIS_EXPLORER VERSION="3">',
    '  <DATASETS DESCRIPTION="">',
    '   <DATASET ID_DATAMAPS="1" DESCRIPTION="" INDEX="0" DIAGNOSTIC_ADDRESS="0x19" START_ADDRESS="{addr}"/>',
    "  </DATASETS>",
    "  <DATAMAPS_LIST>",
    *(line for i, nxt in ((0, 9), (1, 8), (2, 7), (3, 6)) for line in (
        f'   <DATAMAPS ID="{i}" NAME="">', f'    <GROUPS ID_NEXT="{nxt}">', '     <GROUP ID="0" NAME="Maps tree"/>',
        "    </GROUPS>", "   </DATAMAPS>")),
    "  </DATAMAPS_LIST>",
    '  <LABELSETS ID_NEXT="1"/>',
    " </ODIS_EXPLORER>",
    "</MESSAGE>",
)


def build_odis_zdc_file(df: bytes, idx: int) -> bytes:
    """ZDC block `idx` of `df` as an ODIS parameterization file — what parse_odis_zdc_file reads back: the block with
    its CRC-32, its ODX address, diagnostic address 0x19, and the dataset number and version from the passport (the
    placeholder number and 0001 when the passport is blank)."""
    if idx not in populated_zdc_blocks(df):
        raise ValueError(tr(f"Блок ZDC #{idx} пуст или с неверной CRC-32 — экспортировать нечего",
                            f"ZDC #{idx} is empty or has a bad CRC-32 — nothing to export"))
    pp = parse_zdc_passport(df)
    pn = (pp.dataset_pn or "").strip() or ZDC_PLACEHOLDER_PN
    ver = pp.dataset_ver if (len(pp.dataset_ver) == 4 and pp.dataset_ver != "0000") else "0001"
    text = "\r\n".join(_ODIS_FILE_LINES).format(
        ver=ver, pn=pn, addr=f"0x{ZDC_UDS_UPLOAD_MAP[idx][0]:04X}", hex=export_zdc_block(df, idx).hex().upper())
    return (text + "\r\n").encode("utf-8")


def parse_odis_zdc_file(data: bytes | str) -> OdisZdcFile:
    """Read an ODIS parameterization file (`GetParametrizeData`, the `arbeits_datei_*.xml` work file).

    It is the vehicle's own dataset with its own identity: the block content, its part number (`ZDC_NAME` ->
    `DID 0xF1A0`) and its version (`ZDC_VERSION` -> `DID 0xF1A1`). The firmware does not compare the passport
    with the content (no dataset carries its own part number); the passport is what UDS reports.

    `START_ADDRESS` is the block's ODX address (`ZDC_UDS_UPLOAD_MAP`, e.g. `0x0B80` for the FPA block #4), not
    a DataFlash offset — the FPA block really lives at DataFlash `0x1340`."""
    import xml.etree.ElementTree as ET  # noqa: PLC0415 - only this one reader needs it

    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if len(raw) > ODIS_ZDC_FILE_MAX_BYTES:
        raise ValueError(
            tr(
                f"Файл параметризации слишком велик: {len(raw):,} Б (ожидается не больше {ODIS_ZDC_FILE_MAX_BYTES:,} Б)",
                f"Parameterization file is too large: {len(raw):,} B (expected at most {ODIS_ZDC_FILE_MAX_BYTES:,} B)",
            )
        )
    try:
        root = ET.fromstring(raw)  # noqa: S314 - a local file the user picked; no entities are resolved
    except ET.ParseError as exc:
        raise ValueError(tr(f"Это не XML-файл параметризации ODIS: {exc}", f"Not an ODIS parameterization XML file: {exc}")) from exc

    node = next((el for el in root.iter() if el.tag.rpartition("}")[2] == "PARAMETER_DATA"), None)
    if node is None or not (node.text or "").strip():
        raise ValueError(
            tr(
                "В файле нет элемента PARAMETER_DATA с данными датасета.",
                "The file has no PARAMETER_DATA element carrying a dataset.",
            )
        )
    hex_text = "".join((node.text or "").split())
    try:
        payload = bytes.fromhex(hex_text)
    except ValueError as exc:
        raise ValueError(tr(f"Данные датасета не шестнадцатеричные: {exc}", f"The dataset payload is not hexadecimal: {exc}")) from exc

    def _addr(name: str) -> int:
        txt = (node.get(name) or "").strip()
        try:
            return int(txt, 16) if txt.lower().startswith("0x") else int(txt or "0")
        except ValueError:
            return -1

    start, diag = _addr("START_ADDRESS"), _addr("DIAGNOSTIC_ADDRESS")
    known = _ODIS_ADDR_TO_IDX.get(start)
    if known is None or known[1] != len(payload):
        expect = ", ".join(f"0x{a:04X}/{s} Б" for a, (_i, s) in sorted(_ODIS_ADDR_TO_IDX.items()))
        raise ValueError(
            tr(
                f"Файл не для шлюза J533: адрес 0x{start:04X} и длина {len(payload)} Б не совпадают ни с одним "
                f"блоком ZDC ({expect}).",
                f"Not a J533 gateway file: address 0x{start:04X} with {len(payload)} B matches no ZDC block "
                f"({expect}).",
            )
        )
    idx = known[0]
    if diag not in (-1, 0x19):
        raise ValueError(
            tr(
                f"Файл параметризации адресован блоку 0x{diag:02X}, а не шлюзу 0x19.",
                f"This parameterization file addresses ECU 0x{diag:02X}, not the gateway 0x19.",
            )
        )
    stored = int.from_bytes(payload[-4:], "little")
    if zdc_crc32_le(payload[:-4]) != stored:
        raise ValueError(
            tr(
                f"Не сходится CRC-32 датасета в файле (в файле 0x{stored:08X}, расчёт 0x{zdc_crc32_le(payload[:-4]):08X}).",
                f"The dataset CRC-32 in the file does not match (file 0x{stored:08X}, calculated 0x{zdc_crc32_le(payload[:-4]):08X}).",
            )
        )
    pn = (node.get("ZDC_NAME") or "").strip().upper()
    ver = (node.get("ZDC_VERSION") or "").strip().upper()
    if not pn or len(pn) > 11 or not all(32 <= ord(c) <= 126 for c in pn):
        raise ValueError(
            tr(
                f"В файле нет пригодного номера датасета ZDC_NAME (получено {pn!r}).",
                f"The file carries no usable ZDC_NAME dataset number (got {pn!r}).",
            )
        )
    return OdisZdcFile(
        zdc_idx=idx,
        payload=payload,
        dataset_pn=pn,
        dataset_ver=ver if len(ver) == 4 and ver != "0000" else "0001",
        start_address=start,
        diagnostic_address=0x19 if diag == -1 else diag,
        header_tag=_ascii_field(payload[:4]),
    )


def apply_odis_zdc_file(
    df: bytes,
    parsed: OdisZdcFile,
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Write an ODIS dataset into its ZDC block and stamp the passport that belongs to that very dataset."""
    validate_dflash_bytes(df)
    had = parse_zdc_passport(df)
    out = import_zdc_block(df, parsed.zdc_idx, parsed.payload, fix_crc=False, reporter=reporter)
    out = apply_zdc_passport(
        out,
        dataset_pn=parsed.dataset_pn,
        dataset_ver=parsed.dataset_ver,
        equip=had.equip_bytes,
        clean_pads=True,
        reporter=reporter,
    )
    reporter.success(
        tr(
            f"Датасет из файла ODIS записан в ZDC #{parsed.zdc_idx} "
            f"(схема {parsed.header_tag or '—'}, {parsed.dataset_pn}/{parsed.dataset_ver}) вместе со своим паспортом",
            f"Wrote the ODIS dataset into ZDC #{parsed.zdc_idx} "
            f"(schema {parsed.header_tag or '—'}, {parsed.dataset_pn}/{parsed.dataset_ver}) together with its own passport",
        )
    )
    return out


def _block_alloc_and_uds_len(idx: int) -> tuple[int, int, int, str]:
    if idx not in _SPEC_BY_IDX:
        raise ValueError(f"Unknown ZDC block index: {idx}")
    _, code, off, sz, _, _ = _SPEC_BY_IDX[idx]
    uds_len = ZDC_UDS_UPLOAD_MAP[idx][1]
    # DataFlash allocation for ZDC #5 is 0x0140 (0x1200..0x133F), UDS payload is 0x012E
    alloc = 0x0140 if idx == 5 else sz
    return off, alloc, uds_len, code


def export_zdc_block(df: bytes, idx: int) -> bytes:
    """Export raw ZDC block `idx` (`0..6`) of its exact UDS length (`sz` bytes, including trailing CRC-32)."""
    validate_dflash_bytes(df)
    off, _alloc, uds_len, _ = _block_alloc_and_uds_len(idx)
    return bytes(df[off : off + uds_len])


def erase_zdc_block(df: bytes, idx: int, *, reporter: OperationReporter = NULL_REPORTER) -> bytes:
    """Erase ZDC block `idx` (`0..6`) to `0xFF` without touching any other DataFlash region."""
    validate_dflash_bytes(df)
    off, alloc, _uds_len, code = _block_alloc_and_uds_len(idx)
    out = bytearray(df)
    out[off : off + alloc] = b"\xff" * alloc
    reporter.info(
        tr(
            f"Блок ZDC #{idx} ({code}) стёрт в FF..FF (0x{off:04X}..0x{off + alloc - 1:04X})",
            f"Erased ZDC #{idx} ({code}) to FF..FF (0x{off:04X}..0x{off + alloc - 1:04X})",
        )
    )
    return bytes(out)


def import_zdc_block(
    df: bytes,
    idx: int,
    blob_or_donor_df: bytes,
    *,
    fix_crc: bool = True,
    copy_donor_passport: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Import ZDC block `idx` from either a standalone `.bin` block or a 64 KB donor `DataFlash.bin`."""
    validate_dflash_bytes(df)
    off, alloc, uds_len, code = _block_alloc_and_uds_len(idx)
    out = bytearray(df)

    donor_is_full_df = len(blob_or_donor_df) == len(df) and uds_len != len(df)
    if donor_is_full_df:
        raw_blk = bytearray(blob_or_donor_df[off : off + alloc])
        if copy_donor_passport:
            dp = parse_zdc_passport(blob_or_donor_df)
            if not dp.empty:
                out[:] = apply_zdc_passport(
                    bytes(out),
                    dataset_pn=dp.dataset_pn or "V03935256AA",
                    dataset_ver=dp.dataset_ver or "0001",
                    equip=dp.equip_bytes,
                    clean_pads=True,
                )
    elif len(blob_or_donor_df) == alloc:
        raw_blk = bytearray(blob_or_donor_df)
    elif len(blob_or_donor_df) == uds_len:
        raw_blk = bytearray(b"\xff" * alloc)
        raw_blk[:uds_len] = blob_or_donor_df
    elif len(blob_or_donor_df) == uds_len - 4:
        raw_blk = bytearray(b"\xff" * alloc)
        raw_blk[: uds_len - 4] = blob_or_donor_df
        fix_crc = True
    else:
        raise ValueError(
            tr(
                f"Неверный размер файла для ZDC #{idx} ({code}): ожидается {uds_len} Б (или 65 536 Б DataFlash), получено {len(blob_or_donor_df)} Б",
                f"Invalid size for ZDC #{idx} ({code}): expected {uds_len} B (or 65,536 B DataFlash), got {len(blob_or_donor_df)} B",
            )
        )

    if all(b == 0xFF for b in raw_blk[:uds_len]):
        out[off : off + alloc] = b"\xff" * alloc
        reporter.info(tr(f"Блок ZDC #{idx} ({code}) пуст в источнике -> очищен в FF..FF", f"Source ZDC #{idx} ({code}) is empty -> erased to FF..FF"))
        return bytes(out)

    if fix_crc:
        sealed = seal_zdc_block_crc(raw_blk, uds_len=uds_len)
    else:
        sealed = bytes(raw_blk)
    out[off : off + alloc] = sealed
    crc_val, = struct.unpack_from("<I", sealed, uds_len - 4)
    reporter.info(
        tr(
            f"Импортирован блок ZDC #{idx} ({code}) @ 0x{off:04X} (CRC-32=0x{crc_val:08X})",
            f"Imported ZDC #{idx} ({code}) @ 0x{off:04X} (CRC-32=0x{crc_val:08X})",
        )
    )
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ZDC #1 — MKE Driver Alert (`0x0100..0x01FF`, 256 B)
# ═══════════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass
class MkeConfig:
    empty: bool
    crc_ok: bool
    plausible: bool
    version_tag: str = "86"
    min_drive_min: int = 15          # +0x04: Minimum driving window before fatigue evaluation (min, stock 15)
    primary_window_min: int = 1      # +0x08: Primary fatigue accumulation window (min, stock 1)
    short_break_min: int = 15        # +0x09: Short standstill break timer (min, stock 15)
    full_rest_min: int = 15          # +0x0A: Full rest / pause reset timer (min, stock 15)
    suppress_stage1_min: int = 0     # +0x1F: Repeat warning suppression interval 1 (min, stock 0)
    suppress_stage2_min: int = 5     # +0x20: Repeat warning suppression interval 2 (min, stock 5)
    speed_on_kmh: int = 60           # +0xC4: Lower vehicle speed bound (km/h, Q6 <<6, stock 60; +5 hyst = 65)
    speed_off_high_kmh: int = 200    # +0xC5: Upper vehicle speed bound (km/h, Q6 <<6, stock 200)
    speed_hyst_low_kmh: int = 5      # +0x30: Lower speed hysteresis delta (km/h, stock 5)
    speed_urban_reset_kmh: int = 20  # +0x31: Low-speed / urban manoeuvre threshold (km/h, stock 20)
    speed_hyst_high_kmh: int = 5     # +0x32: Speed qualification delay (s, 0..25, stock 5; legacy field name kept)
    stage1_threshold: int = 5        # +0x34: HMI / BAP 0x22 alert stage 1 threshold (stock 5)
    stage2_threshold: int = 2        # +0x35: HMI / BAP 0x22 alert stage 2 threshold (stock 2)
    raw_256: bytes = b""


def parse_mke_block(df: bytes) -> MkeConfig:
    """Parse `ZDC #1` (`0x0100..0x01FF`, 256 B) Driver Alert System parameters."""
    validate_dflash_bytes(df)
    buf = df[0x0100:0x0200]
    if all(b == 0xFF for b in buf):
        return MkeConfig(empty=True, crc_ok=False, plausible=False, raw_256=bytes(buf))
    crc_st, = struct.unpack_from("<I", buf, 0xFC)
    crc_ca = zdc_crc32_le(buf[:0xFC])
    plaus = buf[0x00] == 0x38 and buf[0x02] == 0x96 and (buf[0x23] >> 4) == 1
    tag = _ascii_field(buf[0x00:0x02]) or "86"
    return MkeConfig(
        empty=False,
        crc_ok=(crc_st == crc_ca),
        plausible=plaus,
        version_tag=tag,
        min_drive_min=buf[0x04],
        primary_window_min=buf[0x08],
        short_break_min=buf[0x09],
        full_rest_min=buf[0x0A],
        suppress_stage1_min=buf[0x1F],
        suppress_stage2_min=buf[0x20],
        speed_on_kmh=buf[0xC4],
        speed_off_high_kmh=buf[0xC5],
        speed_hyst_low_kmh=buf[0x30],
        speed_urban_reset_kmh=buf[0x31],
        speed_hyst_high_kmh=buf[0x32],
        stage1_threshold=buf[0x34],
        stage2_threshold=buf[0x35],
        raw_256=bytes(buf),
    )


def inject_mke_preset(
    df: bytes,
    variant: str = "86",
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Write stock VAG `ZDC #1` MKE preset (`'86'` or `'84'`) into `0x0100..0x01FF`."""
    validate_dflash_bytes(df)
    key = "MKE_84" if variant == "84" else "MKE_86"
    tpl = get_zdc_template_bytes(key)
    out = bytearray(df)
    out[0x0100:0x0200] = tpl
    reporter.info(tr(f"Записан заводской пресет MKE '{variant}' (ZDC #1 @ 0x0100)", f"Injected stock MKE '{variant}' preset (ZDC #1 @ 0x0100)"))
    return bytes(out)


def apply_mke_config(
    df: bytes,
    cfg: MkeConfig,
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Apply edited `MkeConfig` parameters to `ZDC #1` (`0x0100..0x01FF`) and seal CRC-32."""
    validate_dflash_bytes(df)
    base_key = "MKE_84" if cfg.version_tag == "84" else "MKE_86"
    if len(cfg.raw_256) == 256 and not cfg.empty and cfg.plausible:
        buf = bytearray(cfg.raw_256)
    else:
        buf = bytearray(get_zdc_template_bytes(base_key))

    tag_s = cfg.version_tag if len(cfg.version_tag) == 2 and cfg.version_tag.startswith("8") else "86"
    buf[0x00:0x02] = tag_s.encode("ascii")
    buf[0x02] = 0x96
    buf[0x23] = (buf[0x23] & 0x0F) | 0x10

    def _u8(v: int) -> int:
        return max(0, min(255, int(v)))

    buf[0x04] = _u8(cfg.min_drive_min)
    buf[0x08] = _u8(cfg.primary_window_min)
    buf[0x09] = _u8(cfg.short_break_min)
    buf[0x0A] = _u8(cfg.full_rest_min)
    buf[0x1F] = _u8(cfg.suppress_stage1_min)
    buf[0x20] = _u8(cfg.suppress_stage2_min)
    buf[0xC4] = _u8(cfg.speed_on_kmh)
    buf[0xC5] = _u8(cfg.speed_off_high_kmh)
    buf[0x30] = _u8(cfg.speed_hyst_low_kmh)
    buf[0x31] = _u8(cfg.speed_urban_reset_kmh)
    buf[0x32] = max(0, min(25, int(cfg.speed_hyst_high_kmh)))
    buf[0x34] = _u8(cfg.stage1_threshold)
    buf[0x35] = _u8(cfg.stage2_threshold)

    sealed = seal_zdc_block_crc(buf, uds_len=256)
    out = bytearray(df)
    out[0x0100:0x0200] = sealed
    reporter.info(
        tr(
            f"Параметры MKE (ZDC #1) обновлены: порог {buf[0xC4]}..{buf[0xC5]} км/ч, окно {buf[0x04]} мин",
            f"Updated MKE (ZDC #1): speed window {buf[0xC4]}..{buf[0xC5]} km/h, min drive {buf[0x04]} min",
        )
    )
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ZDC #2 — Start-Stop Inhibition Reasons HMI (`0x0200..0x09FF`, 2048 B)
# ═══════════════════════════════════════════════════════════════════════════════


SSA_OUTPUT_MODES: tuple[tuple[int, str, str], ...] = (
    (1, "Стандартно: краткий статус Старт-Стоп (заводская настройка)", "Standard: summary Start-Stop status (factory default)"),
    (2, "Подробно: показывать полный список причин на экране магнитолы", "Detailed: show full list of Start-Stop reasons on screen"),
    (0, "Только текстовые причины без сводного индикатора", "Reason messages only (without summary icon)"),
    (3, "Скрыть уведомления и причины Старт-Стоп в меню магнитолы", "Hide Start-Stop reason messages on head unit"),
)


@dataclasses.dataclass
class SsaConfig:
    empty: bool
    crc_ok: bool
    version_tag: str = "4C"
    bap_output_mode: int = 2               # +0x0023 bits 3..2 (0..3)
    standstill_notice_delay_ms: int = 4000 # +0x002C u16_be (ms)
    fault_autoclear_s: int = 10            # +0x001E u16_be (s)
    summary_suppress_kmh: int = 20         # +0x0020 u16_be (km/h)
    enabled_reasons_count: int = 0
    raw_2048: bytes = b""


def parse_ssa_block(df: bytes) -> SsaConfig:
    """Parse `ZDC #2` (`0x0200..0x09FF`, 2048 B) Start-Stop HMI Reason Display (`BAP LSG 0x27`)."""
    validate_dflash_bytes(df)
    buf = df[0x0200:0x0A00]
    if all(b == 0xFF for b in buf):
        return SsaConfig(empty=True, crc_ok=False, raw_2048=bytes(buf))
    crc_st, = struct.unpack_from("<I", buf, 0x07FC)
    crc_ca = zdc_crc32_le(buf[:0x07FC])
    tag = _ascii_field(buf[0x00:0x02]) or "4C"
    bap_mode = (buf[0x0023] >> 2) & 0x03
    fault_s, suppress_kmh = struct.unpack_from(">HH", buf, 0x001E)
    delay_ms, = struct.unpack_from(">H", buf, 0x002C)
    en_cnt = 0
    for rid in range(177):
        hi_flags = buf[0x0050 + rid * 5 + 3]
        if hi_flags & 0x08:
            en_cnt += 1
    return SsaConfig(
        empty=False,
        crc_ok=(crc_st == crc_ca),
        version_tag=tag,
        bap_output_mode=bap_mode,
        standstill_notice_delay_ms=delay_ms,
        fault_autoclear_s=fault_s,
        summary_suppress_kmh=suppress_kmh,
        enabled_reasons_count=en_cnt,
        raw_2048=bytes(buf),
    )


def inject_ssa_preset(df: bytes, *, reporter: OperationReporter = NULL_REPORTER) -> bytes:
    """Write stock `'4C'` `ZDC #2` Start-Stop HMI Reasons dataset into `0x0200..0x09FF`."""
    validate_dflash_bytes(df)
    out = bytearray(df)
    out[0x0200:0x0A00] = get_zdc_template_bytes("SSA_4C")
    reporter.info(tr("Записан заводской пресет индикации Старт-Стоп '4C' (ZDC #2 @ 0x0200)", "Injected stock Start-Stop reasons preset '4C' (ZDC #2 @ 0x0200)"))
    return bytes(out)


def apply_ssa_config(
    df: bytes,
    cfg: SsaConfig,
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Apply `SsaConfig` edits to `ZDC #2` (`0x0200..0x09FF`) and recalculate CRC-32."""
    validate_dflash_bytes(df)
    if len(cfg.raw_2048) == 2048 and not cfg.empty and cfg.raw_2048[:2] == b"4C":
        buf = bytearray(cfg.raw_2048)
    else:
        buf = bytearray(get_zdc_template_bytes("SSA_4C"))

    mode_bits = max(0, min(3, int(cfg.bap_output_mode)))
    buf[0x0023] = (buf[0x0023] & ~0x0C) | (mode_bits << 2)
    struct.pack_into(">H", buf, 0x001E, max(0, min(65535, int(cfg.fault_autoclear_s))))
    struct.pack_into(">H", buf, 0x0020, max(0, min(65535, int(cfg.summary_suppress_kmh))))
    struct.pack_into(">H", buf, 0x002C, max(0, min(65535, int(cfg.standstill_notice_delay_ms))))

    sealed = seal_zdc_block_crc(buf, uds_len=2048)
    out = bytearray(df)
    out[0x0200:0x0A00] = sealed
    reporter.info(
        tr(
            f"Параметры индикации Старт-Стоп (ZDC #2) обновлены: режим BAP 0x27 = {mode_bits}",
            f"Updated Start-Stop HMI reasons (ZDC #2): BAP 0x27 mode = {mode_bits}",
        )
    )
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. ZDC #4 — MultiKo / Driving Profile Selection FPA (`0x1340..0x243F`, 4352 B)
# ═══════════════════════════════════════════════════════════════════════════════


def fpa_section_slice(sec_id: int) -> slice:
    if not 0 <= sec_id < FPA_SHARED_SECTIONS:
        raise ValueError(f"S{sec_id:03d} differs between firmware builds; only S000..S{FPA_SHARED_SECTIONS - 1:03d} share one layout")
    return slice(FPA_SEC_OFFS[sec_id], FPA_SEC_OFFS[sec_id + 1])


@dataclasses.dataclass
class FpaSlotState:
    slot: int
    profile_id: int
    name_ru: str
    name_en: str
    selectable: bool
    swap_gated: bool
    kl15_next_slot: int
    kombi_icon: int
    flags_s074: int
    fec_code: int

    @property
    def name(self) -> str:
        return self.name_en if get_lang() == "en" else self.name_ru

    @property
    def kl15_persists(self) -> bool:
        return self.kl15_next_slot == self.slot


@dataclasses.dataclass
class FpaButtonConfig:
    mode: str                    # "none" | "console" | "mfl" | "both"
    mfl_keycode: int             # S057[0], e.g. 0x19 Voice, 0x23 VIEW
    mfl_long_press: bool         # True if S039[mfl_inp] == 0x04, False if 0x03
    console_ring: list[int]      # Active slots in Switch 0 column of S041
    mfl_ring: list[int]          # Active slots in MFL switch column of S041
    normal_led_off: bool         # S037[0] == 0x01 (off in Normal) vs 0x02 (always lit)
    led_pwm: int                 # S011 (0..15)
    mib_popup: bool              # S056 != 0
    popup_timeout_100ms: int     # S020[0] (0 = HMI default)
    decouple_dsg_lever: bool     # S034 != 0
    personalization_pso: bool    # (S013 & 0x04) != 0
    has_4motion_rotary: bool     # a 4Motion input of the car's own (source 4 or 5), kept as it is
    vehicle_mode_button: bool = False  # S036 0x05: the car's own MODE button (4Motion: on-road and off-road rings)


# Input types (S036) ContiTool writes itself; every other input is the car's own and is never touched.
_OWN_CONSOLE, _OWN_MFL = 0x01, (0xFD, 0xFE, 0xFC)
_VEHICLE_MODE_BUTTON = 0x05  # e.g. T-Roc 4Motion: switch 0 = off-road ring, switch 1 = on-road ring (S042 01 / 02)


class FpaDataset:
    """Lossless, section-accurate editor over the 4352-byte `ZDC #4` (`MultiKo / FPA`) block."""

    def __init__(self, raw_4352: bytes | bytearray) -> None:
        if len(raw_4352) != 4352:
            raise ValueError(f"Expected 4352-byte ZDC #4 block, got {len(raw_4352)} B")
        self.buf = bytearray(raw_4352)
        self._parked_ids: dict[int, int] = {}  # slot -> the ID it had before it was switched off

    @classmethod
    def from_dflash(cls, df: bytes) -> FpaDataset:
        validate_dflash_bytes(df)
        return cls(df[0x1340:0x2440])

    @property
    def empty(self) -> bool:
        return all(b == 0xFF for b in self.buf)

    @property
    def crc_stored(self) -> int:
        return struct.unpack_from("<I", self.buf, 0x10FC)[0]

    @property
    def crc_calc(self) -> int:
        return zdc_crc32_le(self.buf[:0x10FC])

    @property
    def crc_ok(self) -> bool:
        return (not self.empty) and (self.crc_stored == self.crc_calc)

    @property
    def schema_tag(self) -> str:
        return _ascii_field(self.buf[0x0000:0x0004])

    @property
    def header_s005(self) -> int:
        return self.buf[FPA_SEC_OFFS[5]]

    def sec_bytes(self, sec_id: int) -> bytearray:
        return self.buf[fpa_section_slice(sec_id)]

    def set_sec_bytes(self, sec_id: int, data: bytes | bytearray | list[int]) -> None:
        sl = fpa_section_slice(sec_id)
        b = bytes(data)
        if len(b) != (sl.stop - sl.start):
            raise ValueError(f"Section S{sec_id:03d} length mismatch: expected {sl.stop - sl.start}, got {len(b)}")
        self.buf[sl] = b

    def sec_u16_be(self, sec_id: int) -> list[int]:
        raw = self.buf[fpa_section_slice(sec_id)]
        cnt = FPA_SEC_CNTS[sec_id]
        return list(struct.unpack(f">{cnt}H", raw))

    def set_sec_u16_be(self, sec_id: int, vals: list[int] | tuple[int, ...]) -> None:
        cnt = FPA_SEC_CNTS[sec_id]
        if len(vals) != cnt:
            raise ValueError(f"Section S{sec_id:03d} u16 count mismatch: expected {cnt}, got {len(vals)}")
        self.buf[fpa_section_slice(sec_id)] = struct.pack(f">{cnt}H", *(v & 0xFFFF for v in vals))

    @property
    def selectable_mask(self) -> int:
        return self.sec_u16_be(30)[0]

    @selectable_mask.setter
    def selectable_mask(self, mask: int) -> None:
        self.set_sec_u16_be(30, [mask & 0xFFFF])

    @property
    def menu_mask(self) -> int:
        """Slots the gateway offers the head unit (bit = slot): S028[slot] holds an ID 1..0x13. The slot's FeC must be
        active as well — that lives in the SWaP area, not here (firmware 5388/5504, FSG-Setup builder)."""
        s028 = self.sec_bytes(28)
        return sum(1 << s for s in range(1, 13) if 1 <= s028[s] <= 0x13)

    @property
    def swap_gated_mask(self) -> int:
        return self.sec_u16_be(70)[0]

    @swap_gated_mask.setter
    def swap_gated_mask(self, mask: int) -> None:
        self.set_sec_u16_be(70, [mask & 0xFFFF])

    @property
    def is_passive_base(self) -> bool:
        """True if ZDC #4 is empty, corrupt, or a passive non-FPA gateway dataset (e.g. S028[2] == 0x14)."""
        if self.empty or not self.crc_ok:
            return True
        s028 = self.sec_bytes(28)
        if s028[2] == 0x14:
            return True
        active_std = [s for s in range(1, 10) if 1 <= s028[s] <= 0x13]
        return len(active_std) <= 1

    @property
    def has_4motion_rotary(self) -> bool:
        """The car's own 4Motion inputs, kept as they are: source 4 (BCM_01 bit 21, the Offroad button of the Tiguan
        dataset NC00) or source 5 (LIN frame 0x0B, a MODE button with an off-road ring). Firmware 5388/5504."""
        if self.empty:
            return False
        s036 = self.sec_bytes(36)
        return 0x04 in s036 or _VEHICLE_MODE_BUTTON in s036

    def detected_preset(self) -> str:
        """Infer the closest factory chassis preset (`fwd`, `fwd_dcc`, `awd`, `awd_dcc`) from dataset tables."""
        if self.empty:
            return "fwd_dcc"
        s028 = self.sec_bytes(28)
        s030 = self.menu_mask
        if s028[2] == 0x14 or sum(1 for s in range(1, 10) if s030 & (1 << s)) <= 1:
            return "fwd_dcc"
        is_awd = (
            self.has_4motion_rotary
            or bool(s030 & (1 << 8))
            or s028[10] != 0
            or self.schema_tag == "NC00"
        )
        has_dcc_comfort = bool(s030 & (1 << 1)) and s028[1] == 0x01
        if is_awd:
            return "awd_dcc" if has_dcc_comfort else "awd"
        return "fwd_dcc" if has_dcc_comfort else "fwd"

    def chassis_summary(self) -> tuple[str, str]:
        """Human-readable `(ru, en)` summary of the chassis configuration stored in this `ZDC #4` dataset."""
        if self.empty:
            return ("не настроена (раздел пуст)", "not configured (empty)")
        s028 = self.sec_bytes(28)
        s030 = self.menu_mask
        if s028[2] == 0x14 or sum(1 for s in range(1, 10) if s030 & (1 << s)) <= 1:
            return ("базовый датасет без профилей движения", "base dataset without driving profiles")
        ru, en = {
            "fwd": ("передний привод, обычная подвеска", "front-wheel drive, standard suspension"),
            "fwd_dcc": ("передний привод, DCC", "front-wheel drive, DCC"),
            "awd": ("4Motion, обычная подвеска", "4Motion, standard suspension"),
            "awd_dcc": ("4Motion, DCC", "4Motion, DCC"),
        }[self.detected_preset()]
        # a guess from the profiles the dataset holds: it describes the dataset, not the car
        return (ru, en)

    def slots(self) -> list[FpaSlotState]:
        if self.empty:
            return []
        s028 = self.sec_bytes(28)
        s029 = self.sec_bytes(29)
        s070 = self.swap_gated_mask
        s071 = self.sec_bytes(71)
        s074 = self.sec_u16_be(74)
        out: list[FpaSlotState] = []
        for slot in range(1, 13):
            pid = s028[slot]
            def_pid, fec_code, _def_icon, _def_flg, _sru, _sen = FPA_SLOT_DEFAULTS[slot]
            name_ru, name_en = FPA_PROFILE_NAMES.get(pid if pid != 0 else def_pid, (f"Профиль 0x{pid:02X}", f"Profile 0x{pid:02X}"))
            out.append(
                FpaSlotState(
                    slot=slot,
                    profile_id=pid,
                    name_ru=name_ru,
                    name_en=name_en,
                    selectable=1 <= pid <= 0x13,  # in the head unit's menu (given the slot's FeC)
                    swap_gated=bool(s070 & (1 << slot)),
                    kl15_next_slot=s029[slot - 1],
                    kombi_icon=s071[slot],
                    flags_s074=s074[slot],
                    fec_code=fec_code,
                )
            )
        return out

    # ── Kl.15 Ignition-Cycle Memory (Level 1: S029/S201, Level 2: S075 nibbles) ──

    @property
    def all_active_profiles_persist_kl15(self) -> bool:
        if self.empty:
            return False
        s028 = self.sec_bytes(28)
        s029 = self.sec_bytes(29)
        checked = 0
        for slot in range(1, 10):
            if 1 <= s028[slot] <= 0x13:
                checked += 1
                if s029[slot - 1] != slot:
                    return False
        return checked > 0

    def get_s075_nibble(self, mode_v: int, log_idx: int) -> int:
        s075 = self.sec_bytes(75)
        b = s075[(mode_v >> 1) * 30 + log_idx]
        return (b >> 4) & 0x0F if (mode_v & 1) else (b & 0x0F)

    def set_s075_nibble(self, mode_v: int, log_idx: int, target_v: int) -> None:
        sl = fpa_section_slice(75)
        idx = sl.start + (mode_v >> 1) * 30 + log_idx
        cur = self.buf[idx]
        nib = target_v & 0x0F
        if mode_v & 1:
            self.buf[idx] = (cur & 0x0F) | (nib << 4)
        else:
            self.buf[idx] = (cur & 0xF0) | nib

    @property
    def powertrain_persists_kl15(self) -> bool:
        if self.empty:
            return False
        s032 = self.sec_bytes(32)
        pt_indices = [i for i, fg in enumerate(s032) if fg in POWERTRAIN_KL15_SG_IDS]
        if not pt_indices:
            return False
        return all(self.get_s075_nibble(3, i) == 3 and self.get_s075_nibble(5, i) == 5 for i in pt_indices)

    def set_kl15_persistence(
        self,
        *,
        persist_profiles: bool | None = None,
        persist_powertrain: bool | None = None,
        original: FpaDataset | None = None,
    ) -> None:
        """`persist_profiles`: the profile after ignition on (S029/S201/S154). `persist_powertrain`: S075 for the
        powertrain and Start-Stop groups. S075 is the per-group filter of the modes a system is passed (firmware
        5388/5504, FUN_bba70; anything else becomes 0, "no request"). True passes every mode; False puts back the
        cells `original` has (the dataset as loaded) and changes nothing without it — never a fixed value, which
        would make Sport/Eco/Offroad request Normal from the engine and gearbox."""
        if self.empty:
            return
        if persist_profiles is not None:
            s028 = self.sec_bytes(28)
            s029 = self.sec_bytes(29)
            s201 = self.sec_bytes(201)
            for slot in range(1, 13):
                pid = s028[slot]
                if pid == 0:
                    continue
                if 1 <= pid <= 0x13:
                    if persist_profiles:
                        s029[slot - 1] = slot
                        s201[slot] = 0x00
                    else:
                        # Stock VAG WLTP behavior: Individual (7) keeps slot 7 shell, others reset to Normal (2)
                        s029[slot - 1] = 7 if pid == 7 else 2
            self.set_sec_bytes(29, s029)
            self.set_sec_bytes(201, s201)
            s153 = self.sec_bytes(153)
            s154 = self.sec_bytes(154)
            for idx1 in range(1, 7):
                if s153[idx1] != 0 and s154[idx1 - 1] != 0xFF:
                    s154[idx1 - 1] = idx1 if persist_profiles else 2
            self.set_sec_bytes(154, s154)

        if persist_powertrain is not None:
            s032 = self.sec_bytes(32)
            for i, fg in enumerate(s032):
                if fg not in POWERTRAIN_KL15_SG_IDS:
                    continue
                if persist_powertrain:
                    for v in range(1, 16):
                        self.set_s075_nibble(v, i, v)
                    continue
                src = _s075_filter_for(fg, original)
                if src is not None:
                    for v in range(1, 16):
                        self.set_s075_nibble(v, i, src[v])

    def s075_filter(self, group_id: int) -> list[int] | None:
        """Mode -> value passed for logical group `group_id` (S075), or None when the dataset has no such group."""
        if self.empty or not self.crc_ok:
            return None
        s032 = self.sec_bytes(32)
        i = next((n for n, g in enumerate(s032) if g == group_id), None)
        return None if i is None else [self.get_s075_nibble(v, i) for v in range(16)]

    def set_slot_kl15_next(self, slot: int, next_slot: int) -> None:
        if not (1 <= slot <= 12):
            raise ValueError(f"Slot must be 1..12, got {slot}")
        s029 = self.sec_bytes(29)
        s029[slot - 1] = next_slot & 0xFF
        self.set_sec_bytes(29, s029)

    # ── Active Profiles Manager & Target Matrix (`S031`) / Individual (`S033`) ──

    def _copy_reference_row(self, slot: int, pid: int) -> bool:
        """Fill `slot`'s S031/S033 rows from a factory dataset that has profile `pid` (OZ00 for Snow 0x0A and Offroad
        Individual 0x0B, NC00 for Offroad 0x04), mapped onto this car's groups by group ID. False when none has it."""
        for key in ("FPA_OZ00_4MOTION_AC", "FPA_NC00_AWD_DCC"):
            ref = FpaDataset(get_zdc_template_bytes(key))
            r028 = ref.sec_bytes(28)
            src = next((s for s in range(1, 13) if r028[s] == pid and any(ref.sec_bytes(31)[s * 30 : s * 30 + 30])), None)
            if src is None or pid not in (0x04, 0x0A, 0x0B):
                continue
            s031, s033 = self.sec_bytes(31), self.sec_u16_be(33)
            r031, r032, r033 = ref.sec_bytes(31), ref.sec_bytes(32), ref.sec_u16_be(33)
            for j, gid in enumerate(self.sec_bytes(32)):
                if not gid:
                    continue
                i = next((n for n, g in enumerate(r032) if g == gid), None)
                s031[slot * 30 + j] = r031[src * 30 + i] if i is not None else 0x02
                s033[(slot - 1) * 30 + j] = r033[(src - 1) * 30 + i] if i is not None else 1 << 2
            self.set_sec_bytes(31, s031)
            self.set_sec_u16_be(33, s033)
            return True
        return False

    def _populate_default_slot_targets(self, slot: int, pid: int) -> None:
        """If `slot`'s row in `S031` / `S033` is completely zero, synthesize valid target requests."""
        s031 = self.sec_bytes(31)
        s032 = self.sec_bytes(32)
        s033 = self.sec_u16_be(33)
        row_slice = slice(slot * 30, (slot + 1) * 30)
        if any(s031[row_slice]):
            return

        if self._copy_reference_row(slot, pid):
            return
        # Choose closest donor row already present in this dataset (e.g. Sport=3 for Race=6, Normal=2 otherwise)
        donor_slot = 3 if pid in (3, 6) and any(s031[3 * 30 : 4 * 30]) else 2
        donor_targets = list(s031[donor_slot * 30 : (donor_slot + 1) * 30])
        indiv_slot = self._individual_slot()
        indiv_masks = s033[(indiv_slot - 1) * 30 : indiv_slot * 30] if 1 <= indiv_slot <= 12 else [0] * 30

        for lidx, fg in enumerate(s032):
            if fg == 0:
                continue
            allowed = indiv_masks[lidx]
            base_mode = donor_targets[lidx] or 2
            if pid == 1:  # Comfort
                cand = 1 if (allowed & (1 << 1)) or fg in (0x0B, 0x09) else 2
            elif pid == 3:  # Sport
                cand = 3 if (allowed & (1 << 3)) or fg in (0x21, 0x03, 0x01, 0x05, 0x0B, 0x0E, 0x08, 0x09) else base_mode
            elif pid == 4:  # Offroad
                cand = 4 if (allowed & (1 << 4)) or fg in (0x21, 0x03, 0x09, 0x1C, 0x2C, 0x08) else base_mode
            elif pid == 5:  # Eco
                cand = 5 if (allowed & (1 << 5)) or fg in (0x21, 0x03, 0x01, 0x02, 0x24, 0x0A, 0x09) else base_mode
            elif pid == 6:  # Race / Cupra: use 6 where explicitly allowed, otherwise Sport (3) so no ECU rejects it
                cand = 6 if (allowed & (1 << 6)) else (3 if base_mode == 3 or (allowed & (1 << 3)) else base_mode)
            elif pid in (8, 9, 10):  # Snow / Allroad
                cand = 8 if (allowed & (1 << 8)) else (4 if (allowed & (1 << 4)) else base_mode)
            else:
                cand = base_mode
            s031[slot * 30 + lidx] = cand
            if s033[(slot - 1) * 30 + lidx] == 0 and cand > 0:
                s033[(slot - 1) * 30 + lidx] = 1 << cand

        self.set_sec_bytes(31, s031)
        self.set_sec_u16_be(33, s033)

    def set_slot_enabled(
        self,
        slot: int,
        enabled: bool,
        *,
        profile_id: int | None = None,
        kl15_persist: bool | None = None,
    ) -> None:
        """Put profile `slot` (1..12) into the head unit's menu or take it out.

        The gateway offers a slot when S028[slot] holds an ID 1..0x13 and the slot's FeC is active (firmware 5388/5504,
        FSG-Setup builder). Off clears S028[slot] only, so switching the slot on again brings back everything it had;
        on fills S029/S071/S074 and the S031/S033 rows only where they are empty. S030 marks the slots remembered as
        the user's last profile: set with the slot, as factory datasets have it. S070 (cluster notification triggers)
        is never touched; S073 gets its factory routing [1, 2] only when it is empty."""
        if not (1 <= slot <= 12):
            raise ValueError(f"FPA slot must be 1..12, got {slot}")
        def_pid, _fec, def_icon, def_flg, _, _ = FPA_SLOT_DEFAULTS[slot]
        s028 = self.sec_bytes(28)
        s029 = self.sec_bytes(29)
        s071 = self.sec_bytes(71)
        s073 = self.sec_bytes(73)
        s074 = self.sec_u16_be(74)
        s030 = self.selectable_mask | 0x0001  # bit 0 is set in every factory dataset

        if enabled:
            parked = self._parked_ids.pop(slot, 0)
            pid = profile_id if profile_id is not None else (s028[slot] if s028[slot] not in (0, 0x14) else (parked or def_pid))
            s028[slot] = pid & 0xFF
            s030 |= 1 << slot
            if s071[slot] == 0:
                s071[slot] = def_icon
            if s074[slot] == 0:
                s074[slot] = def_flg
            if s073[0] == 0 and s073[1] == 0:
                s073[0], s073[1] = 1, 2
            if kl15_persist is True:
                s029[slot - 1] = slot
            elif kl15_persist is False:
                s029[slot - 1] = 7 if pid == 7 else 2
            elif s029[slot - 1] in (0, 0xFF):
                s029[slot - 1] = slot if self.all_active_profiles_persist_kl15 else (7 if pid == 7 else 2)
            self._populate_default_slot_targets(slot, pid)
        else:
            if slot in self._vehicle_ring_slots():
                raise ValueError(tr(
                    f"Слот {slot} — положение шайбы или кнопки самой машины; без него это положение перестанет работать",
                    f"Slot {slot} is a position of the car's own knob or button; without it that position stops working",
                ))
            if s028[slot]:
                self._parked_ids[slot] = s028[slot]
            s028[slot] = 0
            s030 &= ~(1 << slot)

        self.set_sec_bytes(28, s028)
        self.set_sec_bytes(29, s029)
        self.selectable_mask = s030
        self.set_sec_bytes(71, s071)
        self.set_sec_bytes(73, s073)
        self.set_sec_u16_be(74, s074)

    def set_inst1_slot_enabled(
        self,
        inst1_slot: int,
        enabled: bool,
        *,
        profile_id: int | None = None,
        kl15_persist: bool | None = None,
    ) -> None:
        """Enable or disable secondary `Inst1` EV/Hybrid profile slot `1..6` (`S152/S153/S154/S158/S169/S188`).

        FeC `0x10001A00` (EV / E-Mode) maps to `inst1_slot=1`; FeC `0x10001B00` (GTE / Hybrid) maps to `inst1_slot=2`.
        Never modifies `Inst0` `S028[10..12]` (`4Motion` rotary sub-states).
        """
        if not (1 <= inst1_slot <= 6):
            raise ValueError(f"FPA Inst1 slot must be 1..6, got {inst1_slot}")
        def_pid = FPA_INST1_SLOT_DEFAULTS.get(inst1_slot, (0x0A + inst1_slot, 0, "", ""))[0]
        s152 = self.sec_bytes(152)
        s153 = self.sec_bytes(153)
        s154 = self.sec_bytes(154)
        s158 = self.sec_bytes(158)
        s169 = self.sec_u16_be(169)[0]
        s188 = self.sec_u16_be(188)[0]

        if enabled:
            pid = profile_id if profile_id is not None else (s153[inst1_slot] or def_pid)
            s153[inst1_slot] = pid & 0xFF
            if s152[0] == 0:
                s152[0] = 0x01
            s158[0] |= 1 << (inst1_slot - 1)
            s188 |= 0x0001 | (1 << inst1_slot)
            s169 |= 1 << inst1_slot
            if kl15_persist is True:
                s154[inst1_slot - 1] = inst1_slot
            elif kl15_persist is False:
                s154[inst1_slot - 1] = 2
            elif s154[inst1_slot - 1] in (0, 0xFF):
                s154[inst1_slot - 1] = inst1_slot if self.all_active_profiles_persist_kl15 else 2
        else:
            s153[inst1_slot] = 0
            s154[inst1_slot - 1] = 0xFF
            s158[0] &= ~(1 << (inst1_slot - 1))
            s188 &= ~(1 << inst1_slot)
            s169 &= ~(1 << inst1_slot)
            if not any(s153[1:]):
                s152[0], s152[1] = 0, 0
                s188 = 0

        self.set_sec_bytes(152, s152)
        self.set_sec_bytes(153, s153)
        self.set_sec_bytes(154, s154)
        self.set_sec_bytes(158, s158)
        self.set_sec_u16_be(169, [s169])
        self.set_sec_u16_be(188, [s188])

    def logical_groups(self) -> list[tuple[int, int, str]]:
        """Return `(log_idx, fg_id, localized_name)` for all non-zero entries in `S032[0..29]`."""
        if self.empty:
            return []
        s032 = self.sec_bytes(32)
        out: list[tuple[int, int, str]] = []
        for idx, fg in enumerate(s032):
            if fg != 0:
                ru, en = FPA_SG_CATALOG.get(fg, (f"Подсистема 0x{fg:02X}", f"Subsystem 0x{fg:02X}"))
                out.append((idx, fg, en if get_lang() == "en" else ru))
        return out

    def get_target_mode(self, slot: int, log_idx: int) -> int:
        return self.sec_bytes(31)[slot * 30 + log_idx]

    def set_target_mode(self, slot: int, log_idx: int, mode: int) -> None:
        sl = fpa_section_slice(31)
        self.buf[sl.start + slot * 30 + log_idx] = max(0, min(15, int(mode)))

    def get_individual_mask(self, log_idx: int) -> int:
        indiv_slot = self._individual_slot()
        return self.sec_u16_be(33)[(indiv_slot - 1) * 30 + log_idx]

    def set_individual_mask(self, log_idx: int, mask: int) -> None:
        indiv_slot = self._individual_slot()
        s033 = self.sec_u16_be(33)
        s033[(indiv_slot - 1) * 30 + log_idx] = mask & 0xFFFF
        self.set_sec_u16_be(33, s033)

    # ── Console `MODE` + Simultaneous Steering-Wheel `MFL` Button Mapper ──

    def default_cycle_ring(self) -> list[int]:
        """Build canonical VAG cyclic button order over currently selectable Onroad/Snow profiles."""
        if self.empty:
            return [2]
        s028 = self.sec_bytes(28)
        order = (5, 1, 2, 3, 6, 7, 4, 8, 9)
        theirs = {slot for sw in self._vehicle_switches() for slot in self._read_switch_ring(sw)}
        ring = [s for s in order if 1 <= s028[s] <= 0x13 and s not in theirs]
        return ring[:8] if ring else [2]

    def _individual_slot(self) -> int:
        """The slot holding Individual (ID 7). S015 is the number of personalisation users, not this slot."""
        s028 = self.sec_bytes(28)
        return next((s for s in range(1, 13) if s028[s] == 0x07), 7)

    @property
    def has_knob(self) -> bool:
        """A positional input (S037 type 4): the 4MOTION Active Control knob, read from LIN frame 0x0B bits 0..3."""
        s036, s037 = self.sec_bytes(36), self.sec_bytes(37)
        return any(s036[i] and s037[i] == 0x04 for i in range(5))

    def add_4motion_knob(self) -> None:
        """Add the 4MOTION Active Control knob the way the factory dataset of a 2019 Tiguan with it (OZ00) has it.

        OZ00 together with the firmware (5388/5504): one positional input (S036 5, S037 type 4: LIN frame 0x0B bits
        0..3) on its own switch, ring [slot 8 Snow, the on-road profile of the menu switch (0xE7 + its index), slot 4
        Offroad, slot 9 Offroad Individual], start position 1 (on-road), S045 0x06 told to the head unit. The on-road
        profiles live on a switch without an input that the head unit drives (S045 0xFA, ring Eco, Comfort, Normal,
        Sport, Individual as configured, start at Normal). The knob replaces the console MODE button, so ContiTool's
        own console input goes; wheel buttons stay. Slots 4, 8 and 9 take OZ00's settings mapped onto this car's
        systems by group ID where they are empty; FeCs 10001400, 10001800 and 10001900 license them. Raises
        ValueError when slot 8 or 9 holds another profile or there is no free input or two free switches."""
        if self.has_knob:
            return
        if self.empty or not self.menu_mask & 0x3FE:  # no profile in slots 1..9 (the CRC is stale while editing)
            raise ValueError(tr("Сначала настройте профили движения — в датасете их нет",
                                "Set up the driving profiles first — the dataset has none"))
        snapshot = bytes(self.buf)
        try:
            self._add_4motion_knob()
        except ValueError:
            self.buf[:] = snapshot  # nothing half-done stays behind
            raise

    def _add_4motion_knob(self) -> None:
        oz = FpaDataset(get_zdc_template_bytes("FPA_OZ00_4MOTION_AC"))
        s028 = self.sec_bytes(28)
        if s028[8] not in (0, 0x0A) or s028[9] not in (0, 0x0B):
            raise ValueError(tr("Слоты 8 и 9 заняты другими профилями — шайбе нужны Snow и Offroad Individual",
                                "Slots 8 and 9 hold other profiles — the knob needs Snow and Offroad Individual"))
        # 1. the knob's profiles: slots 4, 8, 9 as OZ00 has them, per group of this car
        g_self, g_oz = self.sec_bytes(32), oz.sec_bytes(32)
        s029, s031, s071, s074, s033 = (self.sec_bytes(29), self.sec_bytes(31), self.sec_bytes(71),
                                        self.sec_u16_be(74), self.sec_u16_be(33))
        o029, o031, o071, o074, o033 = oz.sec_bytes(29), oz.sec_bytes(31), oz.sec_bytes(71), oz.sec_u16_be(74), oz.sec_u16_be(33)
        for slot in (4, 8, 9):
            if s028[slot]:
                continue
            s028[slot], s029[slot - 1], s071[slot], s074[slot] = oz.sec_bytes(28)[slot], o029[slot - 1], o071[slot], o074[slot]
            for j, gid in enumerate(g_self):
                if not gid:
                    continue
                i = next((n for n, g in enumerate(g_oz) if g == gid), None)
                s031[slot * 30 + j] = o031[slot * 30 + i] if i is not None else 0x02
                s033[(slot - 1) * 30 + j] = o033[(slot - 1) * 30 + i] if i is not None else 1 << 2
        self.set_sec_bytes(28, s028)
        self.set_sec_bytes(29, s029)
        self.set_sec_bytes(31, s031)
        self.set_sec_u16_be(33, s033)
        self.set_sec_bytes(71, s071)
        self.set_sec_u16_be(74, s074)
        # 2. the knob replaces ContiTool's console MODE button
        s036, s037, s038, s039, s040 = (self.sec_bytes(i) for i in (36, 37, 38, 39, 40))
        s042, s043, s045, s044 = self.sec_bytes(42), self.sec_bytes(43), self.sec_bytes(45), self.sec_u16_be(44)
        for i in range(5):
            if s036[i] == _OWN_CONSOLE:
                sw = s040[i]
                s036[i] = s037[i] = s038[i] = s039[i] = 0x00
                s040[i] = 0xFF
                if sw < 4:
                    s042[sw], s043[sw], s044[sw], s045[sw] = 0x00, 0xFF, 0x0000, 0x00
                    self._write_switch_ring(sw, [])
        taken = {s040[i] for i in range(5) if s036[i] and s040[i] < 4}
        taken |= {sw for sw in range(4) if self._read_switch_ring(sw) or s042[sw] or s043[sw] != 0xFF or s045[sw]}
        free_in = [i for i in range(5) if s036[i] == 0]
        free_sw = [sw for sw in range(4) if sw not in taken]
        if not free_in or len(free_sw) < 2:
            raise ValueError(tr("Нет свободного входа или двух свободных переключателей для шайбы",
                                "No free input or two free switches for the knob"))
        k, sw_knob, sw_menu = free_in[0], free_sw[0], free_sw[1]
        o036, o037, o038, o039, o040 = (oz.sec_bytes(i) for i in (36, 37, 38, 39, 40))
        o042, o043, o045, o044 = oz.sec_bytes(42), oz.sec_bytes(43), oz.sec_bytes(45), oz.sec_u16_be(44)
        src = next(i for i in range(5) if o037[i] == 0x04)
        oz_knob, oz_menu = o040[src], next(sw for sw in range(4) if o045[sw] == 0xFA)
        s036[k], s037[k], s038[k], s039[k], s040[k] = o036[src], o037[src], o038[src], o039[src], sw_knob
        for src_sw, dst in ((oz_knob, sw_knob), (oz_menu, sw_menu)):
            s042[dst], s043[dst], s044[dst], s045[dst] = o042[src_sw], o043[src_sw], o044[src_sw], o045[src_sw]
        for i, data in ((36, s036), (37, s037), (38, s038), (39, s039), (40, s040), (42, s042), (43, s043), (45, s045)):
            self.set_sec_bytes(i, data)
        self.set_sec_u16_be(44, s044)
        menu_ring = [s for s in oz._read_switch_ring(oz_menu) if 1 <= self.sec_bytes(28)[s] <= 0x13]
        self._write_switch_ring(sw_menu, menu_ring)
        if 2 in menu_ring:
            s042[sw_menu] = menu_ring.index(2)  # start at Normal, as OZ00 does
            self.set_sec_bytes(42, s042)
        ref = 0xE7 + oz_menu  # OZ00's reference to its menu switch, moved to ours
        self._write_switch_ring(sw_knob, [0xE7 + sw_menu if v == ref else v for v in oz._read_switch_ring(oz_knob)])

    def _vehicle_ring_slots(self) -> set[int]:
        """Slots reached through the car's own inputs (knob, a 0x05 MODE button, the Offroad button)."""
        return {v for sw in self._vehicle_switches() for v in self._read_switch_ring(sw) if 1 <= v <= 12}

    def _own_inputs(self) -> list[int]:
        s036 = self.sec_bytes(36)
        return [i for i in range(5) if s036[i] == _OWN_CONSOLE or s036[i] in _OWN_MFL]

    def _vehicle_switches(self) -> set[int]:
        """Switches ContiTool did not set up: every configured switch not bound to one of its own inputs."""
        s040, s042, s043, s045 = self.sec_bytes(40), self.sec_bytes(42), self.sec_bytes(43), self.sec_bytes(45)
        own = {s040[i] for i in self._own_inputs() if s040[i] < 4}
        used = {sw for sw in range(4) if s042[sw] or s043[sw] != 0xFF or s045[sw] or self._read_switch_ring(sw)}
        bound = {s040[i] for i in range(5) if s040[i] < 4}
        return (used | bound) - own

    def _read_switch_ring(self, sw_idx: int) -> list[int]:
        s041 = self.sec_bytes(41)
        ring: list[int] = []
        for step in range(8):
            val = s041[step * 4 + sw_idx]
            if val == 0:
                break
            ring.append(val)
        return ring

    def _write_switch_ring(self, sw_idx: int, ring: Iterable[int]) -> None:
        s041 = self.sec_bytes(41)
        vals = [int(x) & 0xFF for x in ring if int(x) > 0][:8]
        for step in range(8):
            s041[step * 4 + sw_idx] = vals[step] if step < len(vals) else 0
        self.set_sec_bytes(41, s041)

    def button_config(self) -> FpaButtonConfig:
        """Inspect current Console `MODE` + Steering-Wheel `MFL` button & comfort settings."""
        if self.empty:
            return FpaButtonConfig(
                mode="none",
                mfl_keycode=0x19,
                mfl_long_press=False,
                console_ring=[],
                mfl_ring=[],
                normal_led_off=True,
                led_pwm=15,
                mib_popup=True,
                popup_timeout_100ms=0,
                decouple_dsg_lever=False,
                personalization_pso=False,
                has_4motion_rotary=False,
            )
        s036 = self.sec_bytes(36)
        s037 = self.sec_bytes(37)
        s039 = self.sec_bytes(39)
        s040 = self.sec_bytes(40)
        s057 = self.sec_bytes(57)

        console_inps = [i for i in range(5) if s036[i] in (_OWN_CONSOLE, _VEHICLE_MODE_BUTTON) and s040[i] < 4]
        mfl_inps = [i for i in range(5) if s036[i] in (0xFD, 0xFE, 0xFC) and 1 <= s037[i] <= 5 and s040[i] < 4]

        if console_inps and mfl_inps:
            mode = "both"
        elif console_inps:
            mode = "console"
        elif mfl_inps:
            mode = "mfl"
        else:
            mode = "none"

        con_sw = s040[console_inps[0]] if console_inps else 0
        mfl_inp = mfl_inps[0] if mfl_inps else -1
        mfl_sw = s040[mfl_inp] if mfl_inp >= 0 else (1 if mode == "both" else 0)
        mfl_slot = {0xFD: 0, 0xFE: 1, 0xFC: 2}.get(s036[mfl_inp], 0) if mfl_inp >= 0 else 0
        keycode = s057[mfl_slot] if s057[mfl_slot] != 0 else 0x19
        long_press = (s039[mfl_inp] == 0x04) if mfl_inp >= 0 else False
        normal_led_off = (s037[console_inps[0]] != 0x02) if console_inps else True

        return FpaButtonConfig(
            mode=mode,
            mfl_keycode=keycode,
            mfl_long_press=long_press,
            console_ring=self._read_switch_ring(con_sw),
            mfl_ring=self._read_switch_ring(mfl_sw) if mfl_inp >= 0 else [],
            normal_led_off=normal_led_off,
            led_pwm=self.buf[FPA_SEC_OFFS[11]],
            mib_popup=(self.buf[FPA_SEC_OFFS[56]] != 0),
            popup_timeout_100ms=self.sec_bytes(20)[0],
            decouple_dsg_lever=(self.buf[FPA_SEC_OFFS[34]] != 0),
            personalization_pso=bool(self.buf[FPA_SEC_OFFS[13]] & 0x04),
            has_4motion_rotary=(0x04 in s036 or _VEHICLE_MODE_BUTTON in s036),
            vehicle_mode_button=_VEHICLE_MODE_BUTTON in s036,
        )

    def configure_buttons(
        self,
        *,
        mode: str,
        mfl_keycode: int = 0x19,
        mfl_long_press: bool = False,
        console_ring: list[int] | None = None,
        mfl_ring: list[int] | None = None,
        normal_led_off: bool = True,
        led_pwm: int | None = None,
        mib_popup: bool | None = None,
        popup_timeout_100ms: int | None = None,
        decouple_dsg_lever: bool | None = None,
        personalization_pso: bool | None = None,
    ) -> None:
        """Configure Console `MODE`, Steering-Wheel `MFL` (`0xFD`), or BOTH simultaneously while preserving `4Motion`."""
        if mode not in ("none", "console", "mfl", "both"):
            raise ValueError(f"Unsupported button mode: {mode}")
        if self.empty:
            return

        s036 = self.sec_bytes(36)
        s037 = self.sec_bytes(37)
        s038 = self.sec_bytes(38)
        s039 = self.sec_bytes(39)
        s040 = self.sec_bytes(40)
        s042 = self.sec_bytes(42)
        s043 = self.sec_bytes(43)
        s044 = self.sec_u16_be(44)
        s045 = self.sec_bytes(45)
        s057 = self.sec_bytes(57)
        s058 = self.sec_bytes(58)

        # Only ContiTool's own inputs (console 0x01, wheel 0xFD/FE/FC) and their switches are rebuilt. The car's
        # own — the 4Motion rotary (0x04), a MODE button with on-road and off-road rings (0x05), anything else —
        # stay exactly as they are, rings included: wiping a 0x05 button killed MODE and the 4Motion modes.
        own_inputs = set(self._own_inputs())
        rotary_inputs = {i for i in range(5) if s036[i] not in (0x00,) and i not in own_inputs}
        rotary_switches = self._vehicle_switches()
        vehicle_mode_button = _VEHICLE_MODE_BUTTON in s036

        for i in range(5):
            if i in own_inputs:
                s036[i] = 0x00
                s037[i] = 0x00
                s038[i] = 0x00
                s039[i] = 0x00
                s040[i] = 0xFF
        for sw in range(4):
            if sw not in rotary_switches:
                s042[sw] = 0x00
                s043[sw] = 0xFF
                s044[sw] = 0x0000
                s045[sw] = 0x00
                self._write_switch_ring(sw, [])
        s057[0], s058[0] = 0x00, 0x00
        self.set_sec_bytes(36, s036)
        self.set_sec_bytes(40, s040)  # the default ring below must see the freed switches as free

        def_ring = self.default_cycle_ring()
        c_ring = console_ring if console_ring else def_ring
        m_ring = mfl_ring if mfl_ring else c_ring

        free_inputs = [i for i in range(5) if i not in rotary_inputs]
        free_switches = [sw for sw in range(4) if sw not in rotary_switches]
        rotary_inputs = {i for i in rotary_inputs if s036[i] == 0x04}  # what the console switch type below means

        if mode in ("console", "both") and not vehicle_mode_button:  # the car's own MODE button already is one
            con_inp = free_inputs.pop(0)
            con_sw = free_switches.pop(0)
            s036[con_inp] = 0x01
            s037[con_inp] = 0x01 if normal_led_off else 0x02
            s038[con_inp] = 0x01
            s039[con_inp] = 0x03
            s040[con_inp] = con_sw
            s042[con_sw] = 0x02 if rotary_inputs else 0x00
            s043[con_sw] = 0x02
            s044[con_sw] = 0x0002
            s045[con_sw] = 0xFA
            self._write_switch_ring(con_sw, c_ring)

        if mode in ("mfl", "both"):
            mfl_inp = free_inputs.pop(0)
            mfl_sw = free_switches.pop(0)
            s036[mfl_inp] = 0xFD
            s037[mfl_inp] = 0x01
            s038[mfl_inp] = 0x01
            s039[mfl_inp] = 0x04 if mfl_long_press else 0x03
            s040[mfl_inp] = mfl_sw
            s042[mfl_sw] = 0x00
            s043[mfl_sw] = 0x02
            s044[mfl_sw] = 0x0002
            # Advertise 0xFA cyclic switch on sw=0 if MFL is the sole switch; keep 0x00 when Console already has 0xFA
            s045[mfl_sw] = 0xFA if mode == "mfl" and not vehicle_mode_button else 0x00
            s057[0] = mfl_keycode & 0xFF
            s058[0] = 0x02
            self._write_switch_ring(mfl_sw, m_ring)

        self.set_sec_bytes(36, s036)
        self.set_sec_bytes(37, s037)
        self.set_sec_bytes(38, s038)
        self.set_sec_bytes(39, s039)
        self.set_sec_bytes(40, s040)
        self.set_sec_bytes(42, s042)
        self.set_sec_bytes(43, s043)
        self.set_sec_u16_be(44, s044)
        self.set_sec_bytes(45, s045)
        self.set_sec_bytes(57, s057)
        self.set_sec_bytes(58, s058)

        if led_pwm is not None:
            self.buf[FPA_SEC_OFFS[11]] = max(0, min(15, int(led_pwm)))
        if mib_popup is not None:  # S056 is a mode, not a flag: keep the car's own non-zero value (e.g. 2)
            cur = self.buf[FPA_SEC_OFFS[56]]
            self.buf[FPA_SEC_OFFS[56]] = (cur or 1) if mib_popup else 0
            if mib_popup:
                self.set_sec_u16_be(49, [0x0001])
        if popup_timeout_100ms is not None:
            s020 = self.sec_bytes(20)
            s020[0] = max(0, min(255, int(popup_timeout_100ms)))
            self.set_sec_bytes(20, s020)
        if decouple_dsg_lever is not None:
            self.buf[FPA_SEC_OFFS[34]] = 1 if decouple_dsg_lever else 0
        if personalization_pso is not None:
            cur_s013 = self.buf[FPA_SEC_OFFS[13]] | 0x02  # Keep BAP active
            self.buf[FPA_SEC_OFFS[13]] = (cur_s013 | 0x04) if personalization_pso else (cur_s013 & ~0x04)

    def to_sealed_bytes(self) -> bytes:
        """Seal the LE `CRC-32` at `+0x10FC`; every other byte stays exactly as edited."""
        return seal_zdc_block_crc(self.buf, uds_len=4352)


FPA_PRESET_CATALOG: tuple[tuple[str, str, str], ...] = (
    ("fwd", "Передний привод — обычная подвеска (Normal, Sport, Eco, Individual)", "Front-wheel drive — standard suspension (Normal, Sport, Eco, Individual)"),
    ("fwd_dcc", "Передний привод + адаптивная подвеска DCC (с режимом Comfort)", "Front-wheel drive + adaptive DCC (includes Comfort)"),
    ("awd", "Полный привод 4Motion — обычная подвеска (+ Offroad и Snow)", "4Motion AWD — standard suspension (+ Offroad & Snow)"),
    ("awd_dcc", "Полный привод 4Motion + адаптивная подвеска DCC (максимальный набор)", "4Motion AWD + adaptive DCC (full profile set)"),
)


def build_fpa_preset_block(
    preset: str = "fwd_dcc",
    *,
    target_schema: str | None = None,
    existing_zdc4: bytes | None = None,
) -> FpaDataset:
    """Build an `FpaDataset` from a built-in chassis preset.

    The presets are whole datasets of two other gateways (`PC00` from a 3Q0907530AL, `NC00` from a 3Q0907530AR),
    so the result keeps their own tag and model-year byte: the tag names a dataset, not a firmware schema, and
    relabelling it would only hide that this is another vehicle's data."""
    del target_schema, existing_zdc4  # ponytail: callers still pass these; drop them with the GUI/CLI schema picker
    if preset not in ("fwd", "fwd_dcc", "awd", "awd_dcc"):
        raise ValueError(f"Unknown FPA preset '{preset}' (expected fwd, fwd_dcc, awd, awd_dcc)")

    tpl_key = "FPA_NC00_AWD_DCC" if preset.startswith("awd") else "FPA_PC00_FWD_DCC"
    fpa = FpaDataset(get_zdc_template_bytes(tpl_key))

    if preset == "fwd":
        fpa.set_slot_enabled(1, False)  # Comfort off without DCC
        fpa.set_slot_enabled(4, False)  # Offroad off on standard road 2WD
        fpa.configure_buttons(mode="console", console_ring=fpa.default_cycle_ring())
    elif preset == "fwd_dcc":
        fpa.set_slot_enabled(4, False)  # Offroad off on 2WD + DCC
        fpa._write_switch_ring(0, fpa.default_cycle_ring())
    elif preset == "awd":
        fpa.set_slot_enabled(1, False)  # Comfort off without DCC
        fpa.set_slot_enabled(4, True)   # Offroad selectable on HMI as well as 4Motion rotary
        fpa._write_switch_ring(0, fpa.default_cycle_ring())
    elif preset == "awd_dcc":
        fpa.set_slot_enabled(4, True)   # Offroad selectable on HMI as well as 4Motion rotary
        fpa._write_switch_ring(0, fpa.default_cycle_ring())

    return fpa


def apply_fpa_dataset(
    df: bytes,
    fpa: FpaDataset,
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Write sealed `FpaDataset` into `ZDC #4` (`0x1340..0x243F`) of `DataFlash`."""
    validate_dflash_bytes(df)
    sealed = fpa.to_sealed_bytes()
    out = bytearray(df)
    out[0x1340:0x2440] = sealed
    crc_val, = struct.unpack_from("<I", sealed, 0x10FC)
    active_names = [s.name for s in fpa.slots() if s.selectable]
    reporter.info(
        tr(
            f"Записан датасет FPA [{fpa.schema_tag}] (CRC-32=0x{crc_val:08X}, профилей: {len(active_names)})",
            f"Updated FPA dataset [{fpa.schema_tag}] (CRC-32=0x{crc_val:08X}, profiles: {len(active_names)})",
        )
    )
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Physical ECU List & Gateway Long Coding (`DID 0x0600`, 30 B) Consistency
# ═══════════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass
class MasterCodingGate:
    zdc_idx: int
    code: str
    byte_idx: int
    bit_idx: int
    dataset_present: bool
    coding_enabled: bool | None  # None when coding30 not loaded

    @property
    def consistent(self) -> bool:
        if self.coding_enabled is None:
            return True
        return self.dataset_present == self.coding_enabled


@dataclasses.dataclass
class PacoParticipantInfo:
    phys_slot: int
    sg_id: int
    sg_name_ru: str
    sg_name_en: str
    paco_bit_1based: int
    coding_byte: int | None
    coding_bit: int | None
    can_channel: int
    coding_enabled: bool | None

    @property
    def sg_name(self) -> str:
        return self.sg_name_en if get_lang() == "en" else self.sg_name_ru


@dataclasses.dataclass
class GatewayCodingReport:
    master_gates: list[MasterCodingGate]
    paco_ecus: list[PacoParticipantInfo]
    warnings: list[str]


_MASTER_ZDC_CODING_GATES: tuple[tuple[int, str, int, int], ...] = (
    (6, "BEM (14V LIN Alternator)", 0, 0),
    (4, "FPA / MultiKo", 8, 0),
    (2, "SSA (Start-Stop HMI Reasons)", 15, 0),
    (1, "MKE (Driver Alert)", 17, 0),
    (3, "Reserve #3", 19, 0),
    (5, "Reserve #5", 29, 0),
)


def analyze_gateway_coding_consistency(
    df: bytes,
    coding30: bytes | None = None,
) -> GatewayCodingReport:
    """Compare populated ZDC blocks & FPA `PaCo` (`S076`/`S079`) against 30-byte Gateway Long Coding (`DID 0x0600`)."""
    ds = analyze_dflash_datasets(df)
    by_idx = {b.idx: b for b in ds.blocks}
    fpa = FpaDataset.from_dflash(df)
    has_coding = coding30 is not None and len(coding30) >= 30

    gates: list[MasterCodingGate] = []
    warnings: list[str] = []
    for zidx, label, b_idx, bit_idx in _MASTER_ZDC_CODING_GATES:
        blk = by_idx[zidx]
        if zidx == 4:
            present = blk.crc_ok and not fpa.is_passive_base
        else:
            present = blk.crc_ok
        c_en = bool(coding30[b_idx] & (1 << bit_idx)) if has_coding and coding30 is not None else None
        gate = MasterCodingGate(
            zdc_idx=zidx,
            code=label,
            byte_idx=b_idx,
            bit_idx=bit_idx,
            dataset_present=present,
            coding_enabled=c_en,
        )
        gates.append(gate)
        if c_en is not None:
            if zidx == 4:
                # Byte 8 Bit 0 can be 1 only when FPA is active; if Byte 8 Bit 0 == 1 and ZDC #4 is empty -> B200500
                if c_en and not blk.crc_ok:
                    warnings.append(
                        tr(
                            f"Byte {b_idx} Bit {bit_idx} ({label}) включён в 0x0600, но блок ZDC #{zidx} пуст -> ошибка B200500!",
                            f"Byte {b_idx} Bit {bit_idx} ({label}) is set in 0x0600 while ZDC #{zidx} is empty -> DTC B200500!",
                        )
                    )
                elif present and not c_en:
                    warnings.append(
                        tr(
                            f"Датасет FPA активен в ZDC #4, но Byte {b_idx} Bit {bit_idx} выключен в кодировке 0x0600 -> профили FPA не запустятся!",
                            f"Active FPA dataset in ZDC #4, but Byte {b_idx} Bit {bit_idx} is off in 0x0600 coding -> FPA will stay inactive!",
                        )
                    )
            else:
                if c_en and not blk.crc_ok:
                    warnings.append(
                        tr(
                            f"Byte {b_idx} Bit {bit_idx} ({label}) включён в 0x0600, но блок ZDC #{zidx} пуст -> ошибка B200500!",
                            f"Byte {b_idx} Bit {bit_idx} ({label}) is set in 0x0600 while ZDC #{zidx} is empty -> DTC B200500!",
                        )
                    )
                elif blk.crc_ok and not c_en and zidx in (1, 2, 6):
                    warnings.append(
                        tr(
                            f"Блок ZDC #{zidx} ({label}) записан, но Byte {b_idx} Bit {bit_idx} выключен в кодировке 0x0600.",
                            f"ZDC #{zidx} ({label}) is present, but Byte {b_idx} Bit {bit_idx} is disabled in 0x0600 coding.",
                        )
                    )

    paco_list: list[PacoParticipantInfo] = []
    if fpa.crc_ok:
        s076 = fpa.sec_bytes(76)
        s079 = fpa.sec_bytes(79)
        s080 = fpa.sec_bytes(80)
        for i in range(30):
            sg = s076[i]
            if sg == 0:
                continue
            ru, en = FPA_SG_CATALOG.get(sg, (f"Блок 0x{sg:02X}", f"ECU 0x{sg:02X}"))
            pbit = s079[i]
            if 1 <= pbit <= 32:
                # 1-based PaCo bit mapped across DID 0x0600 Bytes 9..12
                c_byte = 9 + (pbit - 1) // 8
                c_bit = (pbit - 1) % 8
                c_en = bool(coding30[c_byte] & (1 << c_bit)) if has_coding and coding30 is not None else None
            else:
                c_byte, c_bit, c_en = None, None, True
            paco_list.append(
                PacoParticipantInfo(
                    phys_slot=i,
                    sg_id=sg,
                    sg_name_ru=ru,
                    sg_name_en=en,
                    paco_bit_1based=pbit,
                    coding_byte=c_byte,
                    coding_bit=c_bit,
                    can_channel=s080[i],
                    coding_enabled=c_en,
                )
            )

    return GatewayCodingReport(master_gates=gates, paco_ecus=paco_list, warnings=warnings)


def _passes_everything(row: list[int]) -> bool:
    return all(row[v] == v for v in range(1, 16))


def _s075_filter_for(group_id: int, original: FpaDataset | None) -> list[int] | None:
    """The filter to put back for `group_id`: the loaded dataset's own when it is a real filter; when that one already
    passes every mode (an older ContiTool's option), the factory one of the reference datasets (PC00 and NC00 match
    the Golf JD00 for the powertrain and Start-Stop groups). Nothing without the loaded dataset."""
    if original is None:
        return None
    own = original.s075_filter(group_id)
    if own is not None and not _passes_everything(own):
        return own
    for key in ("FPA_PC00_FWD_DCC", "FPA_NC00_AWD_DCC", "FPA_OZ00_4MOTION_AC"):
        ref = FpaDataset(get_zdc_template_bytes(key)).s075_filter(group_id)
        if ref is not None and not _passes_everything(ref):
            return ref
    return None


def fecs_required_by_dataset(df: bytes) -> list[int]:
    """SWaP features the datasets in `df` rely on: MKE (0x10000300) when ZDC #1 holds a dataset, and the feature code of
    every FPA profile in the menu (slots 1..9): the gateway offers a slot to the head unit only with its FeC active."""
    out: list[int] = []
    if check_fec_dataset_support(df, 0x10000300).supported:
        out.append(0x10000300)
    fpa = FpaDataset.from_dflash(df)
    if fpa.crc_ok and not fpa.is_passive_base:
        out += [s.fec_code for s in fpa.slots() if 1 <= s.slot <= 9 and s.selectable and s.fec_code]
    return out


def sync_gateway_coding_for_zdc(df: bytes, coding30: bytes, blocks: Iterable[int] | None = None) -> bytes:
    """Update master ZDC enable bits in 30-byte Gateway Long Coding (`DID 0x0600`) to match `DataFlash` ZDC blocks.

    `blocks` limits it to those ZDC indexes (the ones just written): bits of blocks nobody touched stay as coded.
    Each bit decides whether the gateway loads its block at all (firmware 5366 table 0x0001E550, e.g. block #4 ->
    byte 8 bit 0); a dataset written with its bit clear is never used — confirmed on the bench 2026-11-09: an
    active FPA dataset with byte 8 bit 0 clear stayed unused, setting the bit made the gateway accept it."""
    if len(coding30) != 30:
        raise ValueError(tr(f"Кодировка 0x0600 должна быть ровно 30 байт, получено {len(coding30)} Б", f"Gateway coding 0x0600 must be 30 bytes, got {len(coding30)} B"))
    ds = analyze_dflash_datasets(df)
    by_idx = {b.idx: b for b in ds.blocks}
    fpa = FpaDataset.from_dflash(df)
    out = bytearray(coding30)

    only = None if blocks is None else set(blocks)
    for zidx, _label, b_idx, bit_idx in _MASTER_ZDC_CODING_GATES:
        if only is not None and zidx not in only:
            continue
        present = (by_idx[4].crc_ok and not fpa.is_passive_base) if zidx == 4 else by_idx[zidx].crc_ok
        mask = 1 << bit_idx
        if present:
            out[b_idx] |= mask
        else:
            out[b_idx] &= ~mask

    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. ZDC #6 — BEM 14V LIN Alternator Models (`0x2440..0x303F`, 3072 B)
# ═══════════════════════════════════════════════════════════════════════════════


def zdc6_record_be_to_rom_le(zdc_rec: bytes) -> bytes:
    """Convert 332-byte Big-Endian `ZDC #6` alternator record to firmware 332-byte Little-Endian ROM struct."""
    if len(zdc_rec) != 332:
        raise ValueError(f"Expected 332-byte ZDC #6 record, got {len(zdc_rec)}")
    out = bytearray(332)
    for z_off, _sz, r_off, elem_fmt, cnt, *_ in BEM_ZDC_FIELDS:
        vals = struct.unpack_from(f">{cnt}{elem_fmt}", zdc_rec, z_off)
        struct.pack_into(f"<{cnt}{elem_fmt}", out, r_off, *vals)
    return bytes(out)


def rom_le_to_zdc6_record_be(rom_rec: bytes, schema_ver: str = "2222") -> bytes:
    """Convert 332-byte firmware ROM record (`'2222'` convention) into `ZDC #6` BE record (`'2222'` or `'0101'`)."""
    if len(rom_rec) != 332:
        raise ValueError(f"Expected 332-byte ROM BEM record, got {len(rom_rec)}")
    out = bytearray(332)
    for z_off, _sz, r_off, elem_fmt, cnt, name, _unit in BEM_ZDC_FIELDS:
        vals = list(struct.unpack_from(f"<{cnt}{elem_fmt}", rom_rec, r_off))
        if schema_ver == "0101":
            if name == "mech_loss_speed_x":
                vals = [min(65535, v + 99) for v in vals]
            elif name == "t_cu_min_clamp" and vals[0] == 80:
                vals = [120]
            elif name in ("steinmetz_alpha", "steinmetz_beta"):
                vals = [max(-128, min(127, v + 9)) for v in vals]
        struct.pack_into(f">{cnt}{elem_fmt}", out, z_off, *vals)
    return bytes(out)


@dataclasses.dataclass
class BemSlotInfo:
    slot_idx: int
    empty: bool
    class_id: int
    supplier_id: int
    supplier_name: str
    matched_rom_idx: int | None = None
    matched_diff_bytes: int = 332
    matched_label_ru: str = ""
    matched_label_en: str = ""
    r_stator_mohm: float = 0.0
    u_diode_mv: int = 0
    p_max_w: int = 0

    @property
    def matched_label(self) -> str:
        return self.matched_label_en if get_lang() == "en" else self.matched_label_ru


@dataclasses.dataclass
class BemDataset:
    empty: bool
    crc_ok: bool
    version_tag: str
    slots: list[BemSlotInfo]
    raw_3072: bytes


def parse_bem_block(df: bytes) -> BemDataset:
    """Decode `ZDC #6` (`0x2440..0x303F`, 3072 B) and match all 9 slots against the 21 ROM alternators."""
    validate_dflash_bytes(df)
    buf = df[0x2440:0x3040]
    if all(b == 0xFF for b in buf):
        return BemDataset(empty=True, crc_ok=False, version_tag="", slots=[], raw_3072=bytes(buf))

    crc_st, = struct.unpack_from("<I", buf, 0x0BFC)
    crc_ca = zdc_crc32_le(buf[:0x0BFC])
    tag = _ascii_field(buf[0x0000:0x0004]) or "2222"
    rom_recs = get_rom_bem_records()
    cat_by_idx = {item[0]: item for item in ROM_BEM_CATALOG}

    slots: list[BemSlotInfo] = []
    for sidx in range(9):
        cls_id, sup_id = struct.unpack_from("BB", buf, 0x0004 + sidx * 2)
        sup_ru, sup_en = BEM_SUPPLIER_NAMES.get(sup_id, (f"Поставщик 0x{sup_id:02X}", f"Supplier 0x{sup_id:02X}"))
        sup_name = sup_en if get_lang() == "en" else sup_ru
        rec = buf[0x0018 + sidx * 332 : 0x0018 + (sidx + 1) * 332]
        if all(b == 0xFF for b in rec):
            slots.append(BemSlotInfo(slot_idx=sidx, empty=True, class_id=cls_id, supplier_id=sup_id, supplier_name=sup_name))
            continue

        # Normalize '0101' record to '2222' before comparing with ROM_REC[0..20] so diff == 0 on both schemas!
        norm_be = bytearray(rec)
        if tag == "0101":
            spd = [max(0, x - 99) for x in struct.unpack_from(">14H", norm_be, 0x0CF)]
            struct.pack_into(">14H", norm_be, 0x0CF, *spd)
            if struct.unpack_from(">H", norm_be, 0x116)[0] == 120:
                struct.pack_into(">H", norm_be, 0x116, 80)
            a, b = struct.unpack_from(">bb", norm_be, 0x148)
            struct.pack_into(">bb", norm_be, 0x148, max(-128, a - 9), max(-128, b - 9))

        rom_le = zdc6_record_be_to_rom_le(bytes(norm_be))
        diffs = [(sum(1 for x, y in zip(rom_le, rr, strict=True) if x != y), ridx) for ridx, rr in enumerate(rom_recs)]
        min_diff, best_idx = min(diffs)
        cat = cat_by_idx[best_idx]

        r_stat = struct.unpack_from(">I", rec, 0x10A)[0] * 0.01
        u_dio = struct.unpack_from(">H", rec, 0x142)[0]
        p_max = rec[0x0EB] * 50

        slots.append(
            BemSlotInfo(
                slot_idx=sidx,
                empty=False,
                class_id=cls_id,
                supplier_id=sup_id,
                supplier_name=sup_name,
                matched_rom_idx=best_idx,
                matched_diff_bytes=min_diff,
                matched_label_ru=cat[7],
                matched_label_en=cat[8],
                r_stator_mohm=r_stat,
                u_diode_mv=u_dio,
                p_max_w=p_max,
            )
        )

    return BemDataset(
        empty=False,
        crc_ok=(crc_st == crc_ca),
        version_tag=tag,
        slots=slots,
        raw_3072=bytes(buf),
    )


def inject_bem_preset(
    df: bytes,
    variant: str = "2222",
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Write stock `'2222'` or `'0101'` `ZDC #6` BEM alternator dataset into `0x2440..0x303F`."""
    validate_dflash_bytes(df)
    key = "BEM_0101" if variant == "0101" else "BEM_2222"
    out = bytearray(df)
    out[0x2440:0x3040] = get_zdc_template_bytes(key)
    reporter.info(tr(f"Записан заводской пресет генераторов BEM '{variant}' (ZDC #6 @ 0x2440)", f"Injected stock BEM alternator preset '{variant}' (ZDC #6 @ 0x2440)"))
    return bytes(out)


def replace_bem_slot_from_rom(
    df: bytes,
    slot_idx: int,
    rom_idx: int | None,
    *,
    class_id: int | None = None,
    supplier_id: int | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Replace or clear `slot_idx` (`0..8`) in `ZDC #6` using one of the 21 factory ROM alternator models."""
    validate_dflash_bytes(df)
    if not (0 <= slot_idx <= 8):
        raise ValueError(f"BEM slot must be 0..8, got {slot_idx}")

    cur = parse_bem_block(df)
    if cur.empty or not cur.crc_ok:
        buf = bytearray(get_zdc_template_bytes("BEM_2222"))
        schema = "2222"
    else:
        buf = bytearray(cur.raw_3072)
        schema = cur.version_tag if cur.version_tag in ("0101", "2222") else "2222"

    desc_off = 0x0004 + slot_idx * 2
    rec_off = 0x0018 + slot_idx * 332

    if rom_idx is None:
        empty_cls = 0x1F if schema == "0101" else 0x31
        buf[desc_off : desc_off + 2] = bytes([empty_cls, 0x07])
        buf[rec_off : rec_off + 332] = b"\xff" * 332
        msg_ru = f"Слот генератора #{slot_idx} в ZDC #6 очищен"
        msg_en = f"Cleared BEM alternator slot #{slot_idx} in ZDC #6"
    else:
        if not (0 <= rom_idx < 21):
            raise ValueError(f"ROM BEM index must be 0..20, got {rom_idx}")
        cat = {item[0]: item for item in ROM_BEM_CATALOG}[rom_idx]
        sup = cat[1] if supplier_id is None else (supplier_id & 0xFF)
        cls = cat[2] if class_id is None else (class_id & 0xFF)
        rec_be = rom_le_to_zdc6_record_be(get_rom_bem_records()[rom_idx], schema_ver=schema)
        buf[desc_off : desc_off + 2] = bytes([cls, sup])
        buf[rec_off : rec_off + 332] = rec_be
        msg_ru = f"Слот BEM #{slot_idx} обновлён -> {cat[7]} (кл. 0x{cls:02X}, пост. 0x{sup:02X})"
        msg_en = f"Updated BEM slot #{slot_idx} -> {cat[8]} (class 0x{cls:02X}, sup 0x{sup:02X})"

    sealed = seal_zdc_block_crc(buf, uds_len=3072)
    out = bytearray(df)
    out[0x2440:0x3040] = sealed
    reporter.info(tr(msg_ru, msg_en))
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Unified 1-Click SWaP FeC <-> ZDC Auto-Parameterizer
# ═══════════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass
class ZdcAutoParamConfig:
    """Options for 1-click dataset parameterization when enabling SWaP FeC features."""

    enabled: bool = True
    fpa_preset: str = "surgical"         # "surgical" | "fwd" | "fwd_dcc" | "awd" | "awd_dcc"
    button_mode: str = "keep"            # "keep" | "console" | "both" | "mfl"
    mfl_keycode: int = 0x19
    mfl_long_press: bool = False
    kl15_persist_profiles: bool = False
    kl15_persist_powertrain: bool = False


def parameterize_dflash_for_fecs(
    df: bytes,
    fecs: Iterable[int],
    config: ZdcAutoParamConfig | None = None,
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, list[str]]:
    """Automatically parameterize `ZDC #1`, `ZDC #4` & `Passport` in `df` so all selected `fecs` are supported."""
    validate_dflash_bytes(df)
    cfg = config or ZdcAutoParamConfig()
    if not cfg.enabled:
        return df, []

    wanted = [int(f) & 0xFFFFFFFF for f in fecs]
    out = bytes(df)
    actions_done: list[str] = []

    # 1. MKE Driver Alert (0x10000300)
    if 0x10000300 in wanted and not check_fec_dataset_support(out, 0x10000300).supported:
        out = inject_mke_preset(out, variant="86", reporter=reporter)
        actions_done.append("ZDC #1 (MKE '86')")

    # 2. GRA (0x10000100) & FPA Profiles (0x10001100..0x10001B00)
    fpa_fecs = [c for c in wanted if (c & 0xFFFFF0FF) == 0x10001000 and 1 <= ((c - 0x10001000) >> 8) <= 11]
    need_gra = 0x10000100 in wanted and not check_fec_dataset_support(out, 0x10000100).supported
    unsup_fpa = [c for c in fpa_fecs if not check_fec_dataset_support(out, c).supported]
    force_fpa_edit = bool(fpa_fecs) and (
        cfg.fpa_preset != "surgical"
        or cfg.button_mode != "keep"
        or cfg.kl15_persist_profiles
        or cfg.kl15_persist_powertrain
    )

    if need_gra or unsup_fpa or force_fpa_edit:
        cur_fpa = FpaDataset.from_dflash(out)
        was_passive = cur_fpa.is_passive_base

        if fpa_fecs:
            if cfg.fpa_preset != "surgical":
                fpa = build_fpa_preset_block(cfg.fpa_preset, existing_zdc4=bytes(cur_fpa.buf))
            elif was_passive:
                # Upgrade empty/passive dataset to full schema-preserving 2WD+DCC base
                fpa = build_fpa_preset_block("fwd_dcc", existing_zdc4=bytes(cur_fpa.buf))
            else:
                fpa = cur_fpa

            for fec_code in fpa_fecs:
                slot = (fec_code - 0x10001000) >> 8
                if 1 <= slot <= 9:
                    s028_val = fpa.sec_bytes(28)[slot]
                    if not 1 <= s028_val <= 0x13:
                        fpa.set_slot_enabled(slot, True)
                elif slot in (10, 11):
                    inst1_slot = slot - 9
                    s153_val = fpa.sec_bytes(153)[inst1_slot]
                    if not (1 <= s153_val <= 0x3F):
                        fpa.set_inst1_slot_enabled(inst1_slot, True)

            # Refresh cycle ring if new profiles were added or button mapping requested
            btn_cur = fpa.button_config()
            eff_btn_mode = cfg.button_mode
            if eff_btn_mode == "keep":
                if was_passive and btn_cur.mode == "none":
                    eff_btn_mode = "console"
                elif btn_cur.mode in ("console", "mfl", "both"):
                    # Keep current button mode, just update ring to include newly enabled profiles
                    new_ring = fpa.default_cycle_ring()
                    fpa.configure_buttons(
                        mode=btn_cur.mode,
                        mfl_keycode=btn_cur.mfl_keycode,
                        mfl_long_press=btn_cur.mfl_long_press,
                        console_ring=new_ring,
                        mfl_ring=new_ring,
                        normal_led_off=btn_cur.normal_led_off,
                    )
            if eff_btn_mode != "keep":
                ring = fpa.default_cycle_ring()
                fpa.configure_buttons(
                    mode=eff_btn_mode,
                    mfl_keycode=cfg.mfl_keycode,
                    mfl_long_press=cfg.mfl_long_press,
                    console_ring=ring,
                    mfl_ring=ring,
                )

            if cfg.kl15_persist_profiles or cfg.kl15_persist_powertrain:
                fpa.set_kl15_persistence(
                    persist_profiles=True if cfg.kl15_persist_profiles else None,
                    persist_powertrain=True if cfg.kl15_persist_powertrain else None,
                )

            out = apply_fpa_dataset(out, fpa, reporter=reporter)
            actions_done.append(f"ZDC #4 (FPA {fpa.schema_tag})")
        elif need_gra and cur_fpa.empty:
            # GRA only on a completely empty ZDC #4 -> inject passive JC00 base
            out_arr = bytearray(out)
            out_arr[0x1340:0x2440] = get_zdc_template_bytes("FPA_JC00_BASE")
            out = bytes(out_arr)
            reporter.info(tr("Записан базовый датасет шлюза JC00 (ZDC #4) для поддержки GRA", "Injected base JC00 gateway dataset (ZDC #4) for GRA support"))
            actions_done.append("ZDC #4 (JC00 Base)")

    # 3. Ensure ZDC Passport (`0x0000..0x007F`) is valid if we wrote any ZDC block
    if actions_done:
        pp = parse_zdc_passport(out)
        if pp.empty or not pp.crc_ok:
            out = apply_zdc_passport(
                out,
                dataset_pn=pp.dataset_pn or ZDC_PLACEHOLDER_PN,
                dataset_ver=pp.dataset_ver if (len(pp.dataset_ver) == 4 and pp.dataset_ver != "0000") else "0001",
                equip=pp.equip_bytes,
                clean_pads=True,
                reporter=reporter,
            )
            actions_done.append("Passport (F1A0/F1A1)")

    return out, actions_done


__all__ = [
    "BEM_SUPPLIER_NAMES",
    "BemDataset",
    "BemSlotInfo",
    "FPA_PRESET_CATALOG",
    "FPA_PROFILE_NAMES",
    "FPA_SG_CATALOG",
    "FPA_SLOT_DEFAULTS",
    "FPA_TARGET_MODE_NAMES",
    "FpaButtonConfig",
    "FpaDataset",
    "FpaSlotState",
    "GatewayCodingReport",
    "MFL_KEYCODE_PRESETS",
    "MasterCodingGate",
    "MkeConfig",
    "POWERTRAIN_KL15_SG_IDS",
    "PacoParticipantInfo",
    "ROM_BEM_CATALOG",
    "SSA_OUTPUT_MODES",
    "SsaConfig",
    "ZDC_REGION_END",
    "ZdcAutoParamConfig",
    "ZdcPassport",
    "OdisZdcFile",
    "ZDC_PLACEHOLDER_PN",
    "analyze_gateway_coding_consistency",
    "apply_fpa_dataset",
    "apply_mke_config",
    "apply_ssa_config",
    "apply_odis_zdc_file",
    "apply_zdc_passport",
    "build_fpa_preset_block",
    "erase_zdc_block",
    "export_zdc_block",
    "import_zdc_block",
    "inject_bem_preset",
    "inject_mke_preset",
    "inject_ssa_preset",
    "parameterize_dflash_for_fecs",
    "parse_bem_block",
    "parse_mke_block",
    "parse_ssa_block",
    "parse_odis_zdc_file",
    "parse_zdc_passport",
    "replace_bem_slot_from_rom",
    "rom_le_to_zdc6_record_be",
    "seal_zdc_block_crc",
    "build_odis_zdc_file",
    "fecs_required_by_dataset",
    "populated_zdc_blocks",
    "sync_gateway_coding_for_zdc",
    "zdc6_record_be_to_rom_le",
    "zdc_crc32_le",
]
