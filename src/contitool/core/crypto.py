"""Pure-Python TeleTrusT RIPEMD-160, RSA-1024 (e=3), PEM/DER, SWaP FSC & ODX signing."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import time

from contitool.core.checksums import app_crc
from contitool.core.constants import (
    APP_BASE,
    APP_SIZE,
    CFLASH_SIZE,
    DFLASH_SIZE,
    FSC_SIGNED_BODY_SIZE,
    FSC_TOTAL_SIZE,
    PKCS1_DIGESTINFO_RIPEMD160,
    PKCS1_DIGESTINFO_SHA1,
    UFLASH_SIZE,
    clean_user_path,
)
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationReporter


def ripemd160(msg: bytes) -> bytes:
    """Pure-Python TeleTrusT RIPEMD-160 (used by Continental J533 FSAG SWaP FSC verification)."""
    rl = (
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    )
    rr = (
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    )
    sl = (
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    )
    sr = (
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    )
    kl = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
    kr = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)

    def _rol(x: int, s: int) -> int:
        return ((x << s) | (x >> (32 - s))) & 0xFFFFFFFF

    def _f(j: int, x: int, y: int, z: int) -> int:
        r = j // 16
        if r == 0:
            return x ^ y ^ z
        if r == 1:
            return (x & y) | ((~x & 0xFFFFFFFF) & z)
        if r == 2:
            return (x | (~y & 0xFFFFFFFF)) ^ z
        if r == 3:
            return (x & z) | (y & (~z & 0xFFFFFFFF))
        return x ^ (y | (~z & 0xFFFFFFFF))

    ml = len(msg) * 8
    buf = bytearray(msg) + b"\x80"
    while (len(buf) % 64) != 56:
        buf.append(0)
    buf += struct.pack("<Q", ml)
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    for off in range(0, len(buf), 64):
        words = struct.unpack_from("<16I", buf, off)
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for j in range(80):
            tl = (al + _f(j, bl, cl, dl) + words[rl[j]] + kl[j // 16]) & 0xFFFFFFFF
            tl = (_rol(tl, sl[j]) + el) & 0xFFFFFFFF
            al, bl, cl, dl, el = el, tl, bl, _rol(cl, 10), dl
            tr_ = (ar + _f(79 - j, br, cr, dr) + words[rr[j]] + kr[j // 16]) & 0xFFFFFFFF
            tr_ = (_rol(tr_, sr[j]) + er) & 0xFFFFFFFF
            ar, br, cr, dr, er = er, tr_, br, _rol(cr, 10), dr
        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t
    return struct.pack("<5I", h0, h1, h2, h3, h4)


_SMALL_PRIMES: tuple[int, ...] = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
    163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
    241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
)


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2 or (n & 1) == 0:
        return n == 2
    for sp in _SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d = n - 1
    r = 0
    while (d & 1) == 0:
        d >>= 1
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime_512_for_e3(reporter: OperationReporter, label: str, base_pct: int) -> int:
    """Generate a random 512-bit prime p with top two bits set and gcd(p - 1, 3) == 1 (p % 3 == 2)."""
    attempts = 0
    while True:
        reporter.check_cancelled()
        attempts += 1
        if attempts % 25 == 0:
            reporter.progress(
                min(base_pct + 35, base_pct + attempts // 8),
                100,
                detail=f"{label}: tested {attempts} candidates…",
            )
        cand = secrets.randbits(512) | (3 << 510) | 1
        rem = cand % 3
        if rem in (0, 1):
            cand += 2
        if cand.bit_length() == 512 and (cand % 3) == 2 and _is_probable_prime(cand):
            reporter.info(
                tr(
                    f"Найдено простое 512-бит число {label} за {attempts} попыток",
                    f"Found 512-bit prime {label} in {attempts} attempts",
                )
            )
            return cand


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    enc = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(enc)]) + enc


def _der_int(val: int) -> bytes:
    raw = val.to_bytes(max(1, (val.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_len(len(raw)) + raw


def _der_seq(items: list[bytes]) -> bytes:
    body = b"".join(items)
    return b"\x30" + _der_len(len(body)) + body


def _pem_wrap(label: str, der_bytes: bytes) -> str:
    b64 = base64.b64encode(der_bytes).decode("ascii")
    chunks = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(chunks) + f"\n-----END {label}-----\n"


def export_rsa_keypair_pems(kp: dict) -> tuple[str, str]:
    """Return (private_pkcs1_pem, public_spki_pem) for OpenSSL compatibility."""
    n = int(kp["n_hex"], 16)
    e = int(kp["e"])
    d = int(kp["d_hex"], 16)
    p = int(kp["p_hex"], 16)
    q = int(kp["q_hex"], 16)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)
    priv_der = _der_seq([
        _der_int(0), _der_int(n), _der_int(e), _der_int(d),
        _der_int(p), _der_int(q), _der_int(dp), _der_int(dq), _der_int(qinv),
    ])
    pub_pkcs1 = _der_seq([_der_int(n), _der_int(e)])
    alg_id = bytes.fromhex("300d06092a864886f70d0101010500")
    bit_str = b"\x03" + _der_len(len(pub_pkcs1) + 1) + b"\x00" + pub_pkcs1
    spki_der = _der_seq([alg_id, bit_str])
    return _pem_wrap("RSA PRIVATE KEY", priv_der), _pem_wrap("PUBLIC KEY", spki_der)


def _pkcs1_v15_encode_1024(msg: bytes, hash_alg: str) -> bytes:
    if hash_alg == "ripemd160":
        digest = ripemd160(msg)
        di = PKCS1_DIGESTINFO_RIPEMD160 + digest
    elif hash_alg == "sha1":
        digest = hashlib.sha1(msg).digest()
        di = PKCS1_DIGESTINFO_SHA1 + digest
    else:
        raise ValueError(f"Unsupported hash_alg: {hash_alg}")
    pad_len = 128 - 3 - len(di)
    return b"\x00\x01" + (b"\xff" * pad_len) + b"\x00" + di


def rsassa_pkcs1_v15_sign(msg: bytes, n_int: int, d_int: int, hash_alg: str) -> bytes:
    """Sign message with RSA-1024 PKCS#1 v1.5 (`ripemd160` for SWaP FSC, `sha1` for FBL ODX)."""
    em = _pkcs1_v15_encode_1024(msg, hash_alg)
    sig_int = pow(int.from_bytes(em, "big"), d_int, n_int)
    return sig_int.to_bytes(128, "big")


def rsassa_pkcs1_v15_verify(msg: bytes, sig: bytes, n_bytes: bytes, e_int: int, hash_alg: str) -> bool:
    """Verify 128-byte RSA-1024 PKCS#1 v1.5 signature."""
    if len(sig) != 128 or len(n_bytes) != 128:
        return False
    n_int = int.from_bytes(n_bytes, "big")
    sig_int = int.from_bytes(sig, "big")
    if not (1 < sig_int < n_int):
        return False
    em = pow(sig_int, e_int, n_int).to_bytes(128, "big")
    return em == _pkcs1_v15_encode_1024(msg, hash_alg)


def generate_rsa1024_e3_keypair(*, reporter: OperationReporter = NULL_REPORTER) -> dict:
    """Generate a cryptographic 1024-bit RSA keypair with public exponent e = 3."""
    reporter.step(1, 3, tr("Поиск 512-битного простого числа p (e = 3)", "Searching 512-bit prime p (e = 3)"))
    reporter.progress(5, 100)
    while True:
        p = _gen_prime_512_for_e3(reporter, "p", 5)
        reporter.step(2, 3, tr("Поиск 512-битного простого числа q (e = 3)", "Searching 512-bit prime q (e = 3)"))
        reporter.progress(45, 100)
        q = _gen_prime_512_for_e3(reporter, "q", 45)
        if p == q or abs(p - q).bit_length() < 496:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        if n.bit_length() != 1024:
            continue
        reporter.step(
            3,
            3,
            tr(
                "Вычисление приватной экспоненты d и самопроверка подписи PKCS#1 v1.5",
                "Computing private exponent d & verifying PKCS#1 v1.5 self-test",
            ),
        )
        phi = (p - 1) * (q - 1)
        d = pow(3, -1, phi)
        n_bytes = n.to_bytes(128, "big")
        test_sig = rsassa_pkcs1_v15_sign(b"CONTI_J533_RSA1024_SELFTEST", n, d, "ripemd160")
        if not rsassa_pkcs1_v15_verify(b"CONTI_J533_RSA1024_SELFTEST", test_sig, n_bytes, 3, "ripemd160"):
            raise RuntimeError("RSA-1024 self-test failed")
        reporter.progress(100, 100)
        reporter.success(
            tr(
                f"Ключевая пара RSA-1024 (e=3) успешно сгенерирована: N={n_bytes[:8].hex()}…",
                f"RSA-1024 (e=3) keypair generated: N={n_bytes[:8].hex()}…",
            )
        )
        return {
            "algorithm": "RSA-1024",
            "e": 3,
            "bits": 1024,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "n_hex": n_bytes.hex(),
            "d_hex": d.to_bytes(128, "big").hex(),
            "p_hex": p.to_bytes(64, "big").hex(),
            "q_hex": q.to_bytes(64, "big").hex(),
        }


def save_rsa1024_keypair_bundle(json_path: Path, kp: dict) -> tuple[Path, Path, Path]:
    """Save JSON keypair + private PKCS#1 PEM + public SPKI PEM next to each other."""
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(kp, indent=2) + "\n", encoding="utf-8")
    priv_pem, pub_pem = export_rsa_keypair_pems(kp)
    stem = json_path.stem
    priv_path = json_path.with_name(f"{stem}.private.pem")
    pub_path = json_path.with_name(f"{stem}.public.pem")
    priv_path.write_text(priv_pem, encoding="utf-8")
    pub_path.write_text(pub_pem, encoding="utf-8")
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass
    return json_path, priv_path, pub_path


def _parse_der_integers(der: bytes) -> list[int]:
    """Extract ASN.1 INTEGERs from a PKCS#1 / PKCS#8 / SPKI DER blob."""
    found: list[int] = []
    i = 0
    n_len = len(der)
    while i < n_len - 1:
        tag = der[i]
        lb = der[i + 1]
        if lb < 0x80:
            ln, hdr = lb, 2
        else:
            cnt = lb & 0x7F
            if cnt == 0 or cnt > 3 or i + 2 + cnt > n_len:
                i += 1
                continue
            ln = int.from_bytes(der[i + 2 : i + 2 + cnt], "big")
            hdr = 2 + cnt
        if i + hdr + ln > n_len:
            i += 1
            continue
        if tag in (0x30, 0x03, 0x04):
            i += hdr + (1 if tag == 0x03 and ln > 0 and der[i + hdr] == 0 else 0)
            continue
        if tag == 0x02:
            val = int.from_bytes(der[i + hdr : i + hdr + ln], "big")
            found.append(val)
        i += hdr + ln
    return found


def load_rsa1024_key_material(raw_spec: str | Path) -> tuple[bytes, int | None]:
    """Load 128-byte RSA-1024 modulus (and optional private d) from JSON, PEM, .bin, or 256-hex string."""
    p = clean_user_path(raw_spec)
    try:
        is_file = p.is_file()
    except OSError:  # a 256-hex modulus is too long for a file name (raised on Python 3.12 / 3.13)
        is_file = False
    if is_file:
        data = p.read_bytes()
        if len(data) == 128:
            if (data[0] & 0x80) == 0:
                raise ValueError(
                    tr(
                        "Старший бит 128-байтного модуля RSA должен быть 1 (1024 бита).",
                        "Top bit of the 128-byte RSA modulus must be 1 (full 1024-bit modulus).",
                    )
                )
            return data, None
        txt = data.decode("utf-8", errors="replace").strip()
        if txt.startswith("{"):
            obj = json.loads(txt)
            n_hex = re.sub(r"[\s:]+", "", str(obj.get("n_hex", "")))
            if len(n_hex) != 256:
                raise ValueError(
                    tr(
                        "Поле n_hex в JSON должно быть 256 hex-символов (128 Б)",
                        "JSON n_hex must be 256 hex chars (128 B)",
                    )
                )
            if int(obj.get("e", 3)) != 3:
                raise ValueError(
                    tr(
                        "Экспонента e в прошивке Continental J533 должна быть равна 3!",
                        "Public exponent e for Continental J533 must be 3!",
                    )
                )
            n_bytes = bytes.fromhex(n_hex)
            d_val = int(obj["d_hex"], 16) if obj.get("d_hex") else None
            return n_bytes, d_val
        if "-----BEGIN" in txt:
            b64_lines = [
                ln.strip() for ln in txt.splitlines() if ln.strip() and not ln.strip().startswith("-----")
            ]
            der = base64.b64decode("".join(b64_lines))
            ints = _parse_der_integers(der)
            mods = [x for x in ints if x.bit_length() == 1024]
            if not mods:
                raise ValueError(
                    tr(
                        "В PEM-файле не найден 1024-битный модуль RSA!",
                        "No 1024-bit RSA modulus found in PEM file!",
                    )
                )
            if 3 not in ints:
                raise ValueError(
                    tr(
                        "Экспонента e в PEM-файле не равна 3 (J533 требует e=3)!",
                        "PEM public exponent e is not 3 (J533 requires e=3)!",
                    )
                )
            n_val = mods[0]
            priv_cands = [x for x in ints if x != n_val and x.bit_length() > 900]
            return n_val.to_bytes(128, "big"), (priv_cands[0] if priv_cands else None)
        raw_spec = txt

    cleaned = re.sub(r"0x", "", str(raw_spec).strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"[\s:,\-_]+", "", cleaned)
    if len(cleaned) != 256 or not re.fullmatch(r"[0-9a-fA-F]{256}", cleaned):
        raise ValueError(
            tr(
                "Укажите путь к файлу ключей (.json / .pem / 128B .bin) или 256 hex-символов модуля RSA-1024.",
                "Provide a path to a key file (.json / .pem / 128B .bin) or a 256-hex-char RSA-1024 modulus.",
            )
        )
    mod = bytes.fromhex(cleaned)
    if (mod[0] & 0x80) == 0:
        raise ValueError(
            tr(
                "Старший бит модуля RSA-1024 должен быть равен 1 (первый байт >= 0x80).",
                "Top bit of RSA-1024 modulus must be 1 (first byte >= 0x80).",
            )
        )
    return mod, None


def build_signed_fsc(
    fec_code: int,
    vcrn_5b: bytes,
    vin_str: str,
    n_bytes: bytes,
    d_int: int,
    *,
    timestamp_unix: int | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Build & sign a 171-byte (0xAB) VAG SWaP FSC v2 certificate for Continental FSAG."""
    reporter.step(1, 2, tr("Формирование 43-байтного контейнера VAG SWaP FSC v2", "Building 43-byte VAG SWaP FSC v2 body"))
    if len(vcrn_5b) != 5:
        raise ValueError(
            tr("VCRN должен иметь длину ровно 5 байт (10 hex-символов)", "VCRN must be 5 bytes (10 hex chars)")
        )
    vin_clean = vin_str.strip().upper()
    if vin_clean and len(vin_clean) != 17:
        raise ValueError(
            tr("VIN должен содержать ровно 17 ASCII-символов", "VIN must be exactly 17 ASCII characters")
        )
    vin_field = (vin_clean.encode("ascii") + b"\x00") if vin_clean else (b"\x00" * 18)
    ts = int(time.time()) if timestamp_unix is None else int(timestamp_unix)
    if not 0 <= fec_code <= 0xFFFFFFFF:  # the certificate holds both in 32 bits: refuse, never cut to fit
        raise ValueError(tr(f"Код FeC вне диапазона 0..0xFFFFFFFF: {fec_code:#x}", f"FeC code out of range 0..0xFFFFFFFF: {fec_code:#x}"))
    if not 0 <= ts <= 0xFFFFFFFF:
        raise ValueError(tr(f"Время вне диапазона 0..0xFFFFFFFF: {ts}", f"Timestamp out of range 0..0xFFFFFFFF: {ts}"))
    validity_9b = b"\x00" * 9
    body = (
        b"\x11\x02"
        + struct.pack(">I", fec_code & 0xFFFFFFFF)
        + b"\x03"
        + vcrn_5b
        + vin_field
        + struct.pack(">I", ts & 0xFFFFFFFF)
        + validity_9b
    )
    assert len(body) == FSC_SIGNED_BODY_SIZE
    reporter.progress(50, 100)
    reporter.step(
        2,
        2,
        tr(
            "Подпись RIPEMD-160 + RSA-1024 (e=3) и самопроверка сертификата",
            "Signing RIPEMD-160 + RSA-1024 (e=3) & verifying certificate",
        ),
    )
    n_int = int.from_bytes(n_bytes, "big")
    sig = rsassa_pkcs1_v15_sign(body, n_int, d_int, "ripemd160")
    if not rsassa_pkcs1_v15_verify(body, sig, n_bytes, 3, "ripemd160"):
        raise RuntimeError("FSC signature verification failed")
    fsc = body + sig
    assert len(fsc) == FSC_TOTAL_SIZE
    reporter.progress(100, 100)
    reporter.success(
        tr(
            f"Сертификат FSC v2 для FeC 0x{fec_code:08X} подписан (171 байт)",
            f"Signed FSC v2 certificate for FeC 0x{fec_code:08X} (171 bytes)",
        )
    )
    return fsc


def _extract_app_slice(raw_cflash_or_app: bytes) -> bytes:
    if len(raw_cflash_or_app) == CFLASH_SIZE:
        return raw_cflash_or_app[APP_BASE:]
    if len(raw_cflash_or_app) == APP_SIZE:
        return raw_cflash_or_app
    if len(raw_cflash_or_app) in (DFLASH_SIZE, UFLASH_SIZE):
        raise ValueError(
            tr(
                f"Ожидался CodeFlash ({CFLASH_SIZE:,} Б) или FD_0DATA ({APP_SIZE:,} Б), получен {len(raw_cflash_or_app):,} Б",
                f"Expected CodeFlash ({CFLASH_SIZE:,} B) or FD_0DATA ({APP_SIZE:,} B), got {len(raw_cflash_or_app):,} B",
            )
        )
    raise ValueError(
        tr(
            f"Неверный размер прошивки: {len(raw_cflash_or_app):,} Б",
            f"Invalid firmware size: {len(raw_cflash_or_app):,} B",
        )
    )


def sign_fbl_odx_application(
    raw_cflash_or_app: bytes,
    n_bytes: bytes,
    d_int: int,
    *,
    ignore_input_crc: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> bytes:
    """Sign FD_0DATA (0x0000C200..0x0017FFFF) for Continental FBL CheckMemory (0x31 01 02 02)."""
    reporter.step(1, 2, tr("Проверка App CRC-16 @ 0x0000C21C перед подписью ODX", "Validating App CRC-16 @ 0x0000C21C"))
    app = _extract_app_slice(raw_cflash_or_app)
    _, range_cnt = struct.unpack_from("<HH", app, 0x1C)
    if range_cnt == 0 and not ignore_input_crc:
        raise ValueError(
            tr(
                "Поле [0x0000C21E] == 0! Бутлодер FBL в CheckProgrammingDependencies (31 01 FF 01) "
                "отвергнет такую прошивку даже с верной подписью RSA. Сначала исправьте образ через патчинг.",
                "Header field [0x0000C21E] == 0! FBL CheckProgrammingDependencies (31 01 FF 01) "
                "rejects [0xC21E]==0 even with a valid RSA signature. Repair the image first.",
            )
        )
    if range_cnt != 0:
        stored_crc, calc_crc = app_crc(app)
        if stored_crc != calc_crc and not ignore_input_crc:
            raise ValueError(
                tr(
                    f"Не совпадает App CRC-16 @ 0x0000C21C (в файле 0x{stored_crc:04X}, расчёт 0x{calc_crc:04X})! "
                    "Сначала обновите CRC-16 утилитой.",
                    f"Application CRC-16 mismatch @ 0x0000C21C (stored 0x{stored_crc:04X}, calculated 0x{calc_crc:04X})! "
                    "Update CRC-16 with this tool before signing.",
                )
            )
    reporter.progress(45, 100)
    reporter.step(2, 2, tr("Вычисление SHA-1 и подписи RSA-1024 (e=3) блока FD_0DATA", "Computing SHA-1 & RSA-1024 signature"))
    msg = struct.pack(">II", APP_BASE, APP_SIZE) + bytes(app)
    n_int = int.from_bytes(n_bytes, "big")
    sig = rsassa_pkcs1_v15_sign(msg, n_int, d_int, "sha1")
    if not rsassa_pkcs1_v15_verify(msg, sig, n_bytes, 3, "sha1"):
        raise RuntimeError("ODX signature verification failed")
    reporter.progress(100, 100)
    reporter.success(
        tr(
            f"Подпись ODX <FW-SIGNATURE> успешно создана ({sig[:8].hex()}…)",
            f"ODX <FW-SIGNATURE> created ({sig[:8].hex()}…)",
        )
    )
    return sig
