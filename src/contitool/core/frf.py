"""ODIS flash containers (.frf) for the J533 gateway: the application, its signature, and where it may go.

An FRF is a ZIP XOR-ed with a fixed keystream (frf_key.py) holding one ODX. For the gateway the ODX carries:
  * FD_0DATA — the application as plain bytes (ENCRYPT-COMPRESS-METHOD 00) for 0x00C200, 1,523,200 B;
  * the SHA1-RSA1024 signature (SECURITY-METHOD SIG_SHA1-RSA1024_S, 128 B) the factory bootloader checks in
    CheckMemory (31 01 02 02) — with it the application goes in over UDS on any bootloader, as ODIS flashes it;
  * EXPECTED-IDENTs — the spare part numbers (F187), software versions (F189), hardware numbers (F191) and hardware
    versions (F1A3) it may be flashed onto.
"""

from __future__ import annotations

import base64
import dataclasses
from functools import lru_cache
import hashlib
import io
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib

from contitool.core.checksums import app_crc
from contitool.core.constants import APP_BASE, STOCK_FBL_MODULUS
from contitool.core.crypto import rsassa_pkcs1_v15_verify
from contitool.core.frf_key import _FRF_KEYSTREAM_B85, FRF_KEYSTREAM_LEN, FRF_KEYSTREAM_SHA256
from contitool.i18n import tr

APP_SIZE_FRF = 0x180000 - 0xC200
FRF_MAX_BYTES = 8 * 1024 * 1024
# EXPECTED-IDENT short name -> the gateway DID it is checked against
IDENT_DIDS = {
    "EI_VWSparePartNumbe": "F187",
    "EI_VWAppliSoftwVersiNumbe": "F189",
    "EI_VWECUHardwNumbe": "F191",
    "EI_VWECUHardwVersiNumbe": "F1A3",
}
HARDWARE_IDENTS = ("F191", "F1A3")  # flashing onto other hardware is refused outright


@dataclasses.dataclass(frozen=True)
class FrfImage:
    name: str  # FL_3Q0907530AC_5388_S
    part_number: str  # 3Q0907530AC
    sw_version: str  # 5388
    app: bytes  # 1,523,200 B for 0x00C200
    signature: bytes  # 128 B, SHA1-RSA1024
    idents: dict[str, tuple[str, ...]]  # DID -> allowed values


@lru_cache(maxsize=1)
def _keystream() -> bytes:
    ks = zlib.decompress(base64.b85decode("".join(_FRF_KEYSTREAM_B85)))
    if len(ks) != FRF_KEYSTREAM_LEN or hashlib.sha256(ks).hexdigest() != FRF_KEYSTREAM_SHA256:
        raise RuntimeError("FRF keystream is damaged")
    return ks


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def read_frf(data: bytes) -> FrfImage:
    """Decrypt and check an FRF for the J533 gateway; raises ValueError with the reason when it is not one."""
    if len(data) > FRF_MAX_BYTES:
        raise ValueError(tr(f"Файл слишком велик для FRF шлюза: {len(data):,} Б", f"Too large for a gateway FRF: {len(data):,} B"))
    ks = _keystream()
    if len(data) > len(ks):
        raise ValueError(tr(
            f"FRF длиннее известного ключевого потока ({len(data):,} > {len(ks):,} Б) — такой ContiTool не расшифрует",
            f"The FRF is longer than the known keystream ({len(data):,} > {len(ks):,} B) — ContiTool cannot decrypt it",
        ))
    plain = bytes(a ^ b for a, b in zip(data, ks))
    try:
        zf = zipfile.ZipFile(io.BytesIO(plain))
        odx_name = next(n for n in zf.namelist() if n.lower().endswith(".odx"))
        root = ET.fromstring(zf.read(odx_name))  # noqa: S314 - a file the user picked; no entities are resolved
    except (zipfile.BadZipFile, StopIteration, ET.ParseError, KeyError, zlib.error) as exc:
        raise ValueError(tr("Это не FRF ODIS или он повреждён", "Not an ODIS FRF, or it is damaged")) from exc

    app, signature, idents, mem = None, None, {}, ""
    for el in root.iter():
        tag = _local(el.tag)
        if tag == "ECU-MEM" and not mem:
            mem = next((c.text or "" for c in el if _local(c.tag) == "SHORT-NAME"), "")
        elif tag == "FLASHDATA" and (el.get("ID") or "").endswith("FD_0DATA"):
            method = next((c.text for c in el if _local(c.tag) == "ENCRYPT-COMPRESS-METHOD"), "00")
            if (method or "00").strip() != "00":
                raise ValueError(tr(f"Данные FRF сжаты или зашифрованы (метод {method}) — не поддерживается",
                                    f"The FRF data is compressed or encrypted (method {method}) — not supported"))
            hex_text = next((c.text for c in el if _local(c.tag) == "DATA"), "") or ""
            app = bytes.fromhex("".join(hex_text.split()))
        elif tag == "SECURITY":
            method = next((c.text or "" for c in el if _local(c.tag) == "SECURITY-METHOD"), "")
            sig = next((c.text or "" for c in el if _local(c.tag) == "FW-SIGNATURE"), "")
            if method.strip().startswith("SIG_") and signature is None:
                signature = bytes.fromhex("".join(sig.split()))
        elif tag == "EXPECTED-IDENT":
            name = next((c.text or "" for c in el if _local(c.tag) == "SHORT-NAME"), "")
            did = IDENT_DIDS.get(name.strip())
            if did:
                vals = tuple(v.text.strip() for v in el.iter() if _local(v.tag) == "IDENT-VALUE" and v.text)
                idents[did] = idents.get(did, ()) + vals

    if app is None or len(app) != APP_SIZE_FRF:
        raise ValueError(tr("В FRF нет приложения шлюза J533 (FD_0DATA, 1 523 200 Б с 0xC200)",
                            "The FRF has no J533 gateway application (FD_0DATA, 1,523,200 B at 0xC200)"))
    if signature is None or len(signature) != 128:
        raise ValueError(tr("В FRF нет подписи приложения (SIG_SHA1-RSA1024, 128 Б)",
                            "The FRF has no application signature (SIG_SHA1-RSA1024, 128 B)"))
    stored, calc = app_crc(app)
    if stored != calc:
        raise ValueError(tr(f"Приложение в FRF повреждено: CRC-16 0x{stored:04X} != 0x{calc:04X}",
                            f"The FRF application is damaged: CRC-16 0x{stored:04X} != 0x{calc:04X}"))
    m = re.match(r"EMEM_(\w+?)(\d{4})_", mem or "")
    part, ver = (m.group(1), m.group(2)) if m else ("", "")
    name = odx_name.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    return FrfImage(name, part, ver, app, signature, idents)


def frf_signature_ok(app: bytes, signature: bytes, modulus: bytes = STOCK_FBL_MODULUS) -> bool:
    """The check the bootloader makes in CheckMemory (31 01 02 02), done here before anything is erased:
    SHA-1 over BE32(0xC200) | BE32(length) | application, PKCS#1 v1.5, RSA-1024 e=3 (crypto.sign_fbl_odx_application
    signs the same message). Verified against a real ODIS FRF (5388) with the factory key."""
    return rsassa_pkcs1_v15_verify(struct.pack(">II", APP_BASE, len(app)) + app, signature, modulus, 3, "sha1")


def frf_signature_problem(frf: FrfImage, *, fbl_modulus: bytes | None = None, fbl_open: bool = False) -> str:
    """Why this ECU's bootloader would refuse the FRF ("" when it takes it). `fbl_modulus`: the key in the ECU's
    CodeFlash (0xA2F7) when a read of it is at hand — ContiTool can replace it with the user's own — else the factory
    key; `fbl_open`: the engineering bootloader, which checks no signature."""
    if fbl_open:
        return ""
    custom = fbl_modulus is not None and fbl_modulus != STOCK_FBL_MODULUS
    if frf_signature_ok(frf.app, frf.signature, fbl_modulus or STOCK_FBL_MODULUS):
        return ""
    return tr(
        "Подпись FRF не сходится с ключом загрузчика этого блока" + (" (в нём свой ключ)" if custom else "") +
        ": загрузчик не примет приложение и блок останется в загрузчике. Ничего не стёрто.",
        "The FRF signature does not verify with this ECU's bootloader key" + (" (it has its own key)" if custom else "") +
        ": the bootloader would refuse the application and the ECU would stay in it. Nothing is erased.",
    )


def frf_ident_problems(frf: FrfImage, ecu: dict[str, str]) -> tuple[list[str], list[str]]:
    """(hardware mismatches — refused, other mismatches — ODIS would refuse, the user may override) for the ECU's DIDs."""
    labels = {"F187": tr("номер детали", "part number"), "F189": tr("версия ПО", "software version"),
              "F191": tr("номер оборудования", "hardware number"), "F1A3": tr("версия оборудования", "hardware version")}
    hard: list[str] = []
    soft: list[str] = []
    for did, allowed in frf.idents.items():
        have = (ecu.get(did) or "").strip()
        if not have:  # a gateway stuck in its bootloader may not answer every one: the user decides
            soft.append(tr(f"{labels[did]} блока не прочитан", f"the ECU's {labels[did]} could not be read"))
        elif have not in {a.strip() for a in allowed}:
            line = tr(f"{labels[did]} блока {have} нет в списке FRF", f"the ECU's {labels[did]} {have} is not in the FRF's list")
            (hard if did in HARDWARE_IDENTS else soft).append(line)
    return hard, soft


__all__ = ["APP_BASE", "FrfImage", "frf_ident_problems", "frf_signature_problem", "read_frf"]
