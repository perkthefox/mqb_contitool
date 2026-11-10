"""ODIS FRF: decrypt, read the ODX (application, signature, expected idents), and flash it over UDS."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import zipfile

import pytest

from contitool.core.analyzer import split_cflash_or_app
from contitool.core import frf as frf_mod
from contitool.core.constants import STOCK_FBL_MODULUS
from contitool.core.crypto import generate_rsa1024_e3_keypair, sign_fbl_odx_application
from contitool.core.frf import _keystream, frf_ident_problems, read_flash_file, read_frf, read_odx
from contitool.i18n import set_lang

SIG = bytes(range(128))


def _odx(app: bytes, *, sw: str = "5388", sig: bytes = SIG) -> str:
    idents = {"EI_VWSparePartNumbe": ["3Q0907530C ", "3Q0907530AA"], "EI_VWAppliSoftwVersiNumbe": ["5301", "5388"],
              "EI_VWECUHardwNumbe": ["3Q0907530C "], "EI_VWECUHardwVersiNumbe": ["517", "521"]}
    ei = "".join(f"<EXPECTED-IDENT><SHORT-NAME>{k}</SHORT-NAME><IDENT-VALUES>"
                 + "".join(f'<IDENT-VALUE TYPE="A_ASCIISTRING">{v}</IDENT-VALUE>' for v in vals)
                 + "</IDENT-VALUES></EXPECTED-IDENT>" for k, vals in idents.items())
    odx = (f'<?xml version="1.0" encoding="UTF-8"?><ODX><FLASH><ECU-MEMS><ECU-MEM><SHORT-NAME>EMEM_3Q0907530AC{sw}_S'
           "</SHORT-NAME><MEM><FLASHDATAS>"
           '<FLASHDATA ID="EMEM_X.FD_0ERASEDATA"><ENCRYPT-COMPRESS-METHOD>00</ENCRYPT-COMPRESS-METHOD><DATA>01</DATA></FLASHDATA>'
           f'<FLASHDATA ID="EMEM_X.FD_0DATA"><ENCRYPT-COMPRESS-METHOD>00</ENCRYPT-COMPRESS-METHOD><DATA>{app.hex().upper()}</DATA></FLASHDATA>'
           "</FLASHDATAS></MEM><SECURITYS>"
           "<SECURITY><SECURITY-METHOD>SA2</SECURITY-METHOD><FW-SIGNATURE>814A0A84</FW-SIGNATURE></SECURITY>"
           f"<SECURITY><SECURITY-METHOD>SIG_SHA1-RSA1024_S</SECURITY-METHOD><FW-SIGNATURE>{sig.hex()}</FW-SIGNATURE></SECURITY>"
           f"</SECURITYS>{ei}</ECU-MEM></ECU-MEMS></FLASH></ODX>")
    return odx


def _frf(app: bytes, *, sw: str = "5388", sig: bytes = SIG) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"FL_3Q0907530AC_{sw}_S.odx", _odx(app, sw=sw, sig=sig))
    plain = buf.getvalue()
    return bytes(a ^ b for a, b in zip(plain, _keystream()))


_real_signature_check = frf_mod.frf_signature_ok


@pytest.fixture(autouse=True)
def _signature_is_sig(monkeypatch):
    """A synthetic FRF carries no VW signature: here SIG counts as the valid one; the real check is tested below."""
    monkeypatch.setattr(frf_mod, "frf_signature_ok", lambda app, sig, modulus=None: sig == SIG)


def test_the_signature_check_matches_what_the_bootloader_verifies(synth_cflash: bytes) -> None:
    """The message the FBL hashes in CheckMemory, as the ODX signer builds it: a key of ours signs, the check
    agrees; one byte of the application changed and it refuses."""
    kp = generate_rsa1024_e3_keypair()
    n = bytes.fromhex(kp["n_hex"])
    app = bytes(split_cflash_or_app(synth_cflash)[1])
    sig = sign_fbl_odx_application(app, n, int(kp["d_hex"], 16))
    assert _real_signature_check(app, sig, n)
    assert not _real_signature_check(app[:-1] + bytes([app[-1] ^ 1]), sig, n)
    assert not _real_signature_check(app, sig, STOCK_FBL_MODULUS)


def test_the_signature_is_checked_with_this_ecus_bootloader_key_before_anything_else(
        synth_cflash: bytes, tmp_path: Path, monkeypatch) -> None:
    """ContiTool can put its own key into the bootloader: the FRF is checked with the key the ECU holds (its latest
    read), with none on the engineering bootloader, and a refused one never opens the bus."""
    from contitool.can import workflows
    from contitool.storage import latest_area

    set_lang("en")
    monkeypatch.setattr(frf_mod, "frf_signature_ok", _real_signature_check)
    kp = generate_rsa1024_e3_keypair()
    own = bytes.fromhex(kp["n_hex"])
    app = bytes(split_cflash_or_app(synth_cflash)[1])
    frf = read_frf(_frf(app, sig=sign_fbl_odx_application(app, own, int(kp["d_hex"], 16))))
    assert "own key" not in frf_mod.frf_signature_problem(frf)  # factory key: refused
    assert "own key" in frf_mod.frf_signature_problem(frf, fbl_modulus=STOCK_FBL_MODULUS[::-1])
    assert frf_mod.frf_signature_problem(frf, fbl_modulus=own) == ""
    assert frf_mod.frf_signature_problem(frf, fbl_open=True) == ""
    monkeypatch.setattr(workflows, "J533CanLink", lambda *a, **k: pytest.fail("the bus must stay closed"))
    with pytest.raises(RuntimeError, match="does not verify"):
        workflows.can_flash_frf("fake", frf, session_dir=tmp_path / "s")

    unit = tmp_path / "3Q0907530C_TST-SYN01.01.260000001"
    for d, size in (("base_read", 0x180000), ("2026-11-09_10-00-00_read", 0x180000),
                    ("2026-11-09_11-00-00_flashed", 0x180000), ("2026-11-09_12-00-00_read", 100)):
        (unit / "dumps" / d).mkdir(parents=True)
        (unit / "dumps" / d / "Cflash.bin").write_bytes(bytes(size))
    assert latest_area(unit, "Cflash.bin") == unit / "dumps" / "2026-11-09_11-00-00_flashed" / "Cflash.bin"
    assert latest_area(unit, "Uflash.bin") is None


def test_an_frf_decrypts_to_its_application_signature_and_idents(synth_cflash: bytes) -> None:
    set_lang("en")
    app = bytes(split_cflash_or_app(synth_cflash)[1])
    frf = read_frf(_frf(app))
    assert (frf.part_number, frf.sw_version, frf.app, frf.signature) == ("3Q0907530AC", "5388", app, SIG)
    ecu = {"F187": "3Q0907530AA", "F189": "5301", "F191": "3Q0907530C", "F1A3": "521"}
    assert frf_ident_problems(frf, ecu) == ([], [])
    hard, soft = frf_ident_problems(frf, ecu | {"F191": "5Q0907530", "F189": "5366"})
    assert len(hard) == 1 and "5Q0907530" in hard[0] and len(soft) == 1 and "5366" in soft[0]
    broken = bytearray(app)
    broken[0x1000] ^= 0xFF
    with pytest.raises(ValueError, match="CRC-16"):
        read_frf(_frf(bytes(broken)))
    with pytest.raises(ValueError, match="Not an ODIS FRF"):
        read_frf(b"PK" + bytes(100))


def test_a_plain_odx_is_the_same_container_without_the_frf_wrapping(synth_cflash: bytes) -> None:
    """FL_..._S.odx as it lies inside the FRF: same application, signature and idents; the file picker tells the two
    apart by content, not by extension."""
    set_lang("en")
    app = bytes(split_cflash_or_app(synth_cflash)[1])
    odx = _odx(app).encode()
    from_frf = read_frf(_frf(app))
    plain = read_odx(odx, "C:\\flash\\FL_3Q0907530AC_5388_S.odx")
    assert (plain.name, plain.kind, from_frf.kind) == ("FL_3Q0907530AC_5388_S", "ODX", "FRF")
    assert (plain.app, plain.signature, plain.idents, plain.part_number, plain.sw_version) == (
        from_frf.app, from_frf.signature, from_frf.idents, from_frf.part_number, from_frf.sw_version)
    assert read_flash_file(b"\xef\xbb\xbf\r\n" + odx, "x.odx").kind == "ODX"  # BOM and a blank line first
    assert read_flash_file(odx).name == "FL_3Q0907530AC_5388_S"  # no file name: taken from the ECU-MEM
    assert read_flash_file(_frf(app), "renamed.odx").kind == "FRF"  # content decides, not the extension
    broken = bytearray(app)
    broken[0x1000] ^= 0xFF
    with pytest.raises(ValueError, match="ODX application is damaged: CRC-16"):
        read_odx(_odx(bytes(broken)).encode())
    with pytest.raises(ValueError, match="Not an ODX file"):
        read_flash_file(b"<?xml version='1.0'?><ODX><unclosed>")
    with pytest.raises(ValueError, match="compressed or encrypted"):
        read_odx(_odx(app).replace("<ENCRYPT-COMPRESS-METHOD>00</ENCRYPT-COMPRESS-METHOD><DATA>" + app.hex().upper()[:8],
                                   "<ENCRYPT-COMPRESS-METHOD>11</ENCRYPT-COMPRESS-METHOD><DATA>" + app.hex().upper()[:8]).encode())


def test_frf_flash_checks_the_ecu_then_programs_with_the_frf_signature(synth_cflash: bytes, tmp_path: Path, monkeypatch) -> None:
    from contitool.can import workflows

    set_lang("en")
    frf = read_frf(_frf(bytes(split_cflash_or_app(synth_cflash)[1])))
    ecu = {"F187": "3Q0907530AA", "F189": "5366", "F191": "3Q0907530C", "F1A3": "521"}
    programmed: list[bytes] = []
    monkeypatch.setattr(workflows, "J533CanLink", lambda *a, **k: contextlib.nullcontext())
    monkeypatch.setattr(workflows, "_read_ident_dids", lambda _link: dict(ecu))
    monkeypatch.setattr(workflows, "_probe_app_or_fbl", lambda *a, **k: ("5003", False))
    monkeypatch.setattr(workflows, "_program_application_uds",
                        lambda _l, app, signature_128b, **_k: programmed.append(signature_128b) or {})
    monkeypatch.setattr(workflows.time, "sleep", lambda _s: None)

    with pytest.raises(RuntimeError, match="5366"):  # ODIS would not flash 5388 onto 5366: not without asking
        workflows.can_flash_frf("fake", frf, session_dir=tmp_path / "a")
    assert programmed == []
    res = workflows.can_flash_frf("fake", frf, session_dir=tmp_path / "b", allow_unlisted=True)
    assert programmed == [SIG] and res["complete"]
    ecu["F191"] = "5Q0907530"  # other hardware: refused even when told to go on
    with pytest.raises(RuntimeError, match="5Q0907530"):
        workflows.can_flash_frf("fake", frf, session_dir=tmp_path / "c", allow_unlisted=True)
    assert programmed == [SIG]
