"""Offline image inspection and dataset editing must fail cleanly (or not at all) on damaged or unusual input."""

from __future__ import annotations

import errno
import io
import pathlib
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

from contitool.core.analyzer import analyze_cflash, detect_dump_file
from contitool.core.constants import APP_BASE, APP_SIZE, CFLASH_SIZE, STOCK_SWAP_MODULUS, clean_user_path
from contitool.core.crypto import load_rsa1024_key_material
from contitool.core.frf import _keystream, read_frf
from contitool.core.zdc import (
    FpaDataset,
    ZdcAutoParamConfig,
    apply_fpa_dataset,
    apply_zdc_passport,
    build_fpa_preset_block,
    build_odis_zdc_file,
    import_zdc_block,
    parameterize_dflash_for_fecs,
    parse_odis_zdc_file,
    parse_zdc_passport,
)
from contitool.core.zdc_templates import get_zdc_template_bytes
from contitool.i18n import set_lang


@pytest.fixture(autouse=True)
def _english() -> None:
    set_lang("en")


# 1. a unit sitting in its bootloader: the application area is erased
def test_an_erased_application_is_a_codeflash_with_a_bad_crc(synth_cflash: bytes, tmp_path: Path) -> None:
    erased = synth_cflash[:APP_BASE] + b"\xff" * (CFLASH_SIZE - APP_BASE)
    info = analyze_cflash(erased)
    assert not info.crc_ok and info.hw_pn == "3Q0907530AR"

    # a range that leaves the application is a bad header too, not a crash
    bad_range = bytearray(synth_cflash)
    struct.pack_into("<II", bad_range, APP_BASE + 0x20, 0, CFLASH_SIZE)
    assert not analyze_cflash(bytes(bad_range)).crc_ok

    for name, raw, kind in (("Cflash.bin", erased, "cflash"), ("FD_0DATA.bin", b"\xff" * APP_SIZE, "fd_0data")):
        p = tmp_path / name
        p.write_bytes(raw)
        det = detect_dump_file(p)
        assert (det.kind, det.valid) == (kind, True)
        assert not det.cflash_info.crc_ok and "CRC ERR" in det.summary_text


# 2. no room for a wheel button: refuse, and leave the dataset as it was
def test_configure_buttons_without_a_free_switch_refuses_and_changes_nothing(synth_dflash: bytes) -> None:
    knob = build_fpa_preset_block("awd_dcc")
    knob.add_4motion_knob()
    for mode in ("mfl", "both"):
        before = bytes(knob.buf)
        with pytest.raises(ValueError, match="free"):
            knob.configure_buttons(mode=mode)
        assert bytes(knob.buf) == before

    nc00 = FpaDataset(get_zdc_template_bytes("FPA_NC00_AWD_DCC"))
    s45 = nc00.sec_bytes(45)
    s45[3] = 0x06  # a third switch of the car's own
    nc00.set_sec_bytes(45, s45)
    before = bytes(nc00.buf)
    with pytest.raises(ValueError, match="free"):
        nc00.configure_buttons(mode="both")
    assert bytes(nc00.buf) == before

    df = apply_fpa_dataset(synth_dflash, knob)
    for mode in ("mfl", "both"):
        with pytest.raises(ValueError, match="free"):
            parameterize_dflash_for_fecs(df, [0x10001600], ZdcAutoParamConfig(button_mode=mode))


# 3. a 256-hex modulus is too long for a file name on Python 3.12 / 3.13
def test_a_hex_modulus_is_read_even_where_its_name_is_too_long_for_a_file(monkeypatch) -> None:
    def too_long(self, *a, **k):
        raise OSError(errno.ENAMETOOLONG, "File name too long", str(self))

    monkeypatch.setattr(pathlib.Path, "is_file", too_long)
    for spec in (
        STOCK_SWAP_MODULUS.hex(),
        "0x" + ":".join(f"{b:02x}" for b in STOCK_SWAP_MODULUS),
        " ".join(f"{b:02X}" for b in STOCK_SWAP_MODULUS),
    ):
        assert load_rsa1024_key_material(spec) == (STOCK_SWAP_MODULUS, None)


# 4. a backslash is a path separator on Windows, not a shell escape
def test_windows_paths_keep_their_backslashes(monkeypatch) -> None:
    for raw in (
        r"C:\dumps\(old)\Cflash.bin",
        r"D:\J533\(1) backup\Dflash.bin",
        r"\\bench\share\[2026]\Uflash.bin",
    ):
        assert str(clean_user_path(raw)) == raw
    if sys.platform != "win32":  # a path dropped from a macOS / Linux terminal is still unescaped
        assert str(clean_user_path(r"/tmp/My\ Dumps/\(1\)/Cflash.bin")) == "/tmp/My Dumps/(1)/Cflash.bin"
    monkeypatch.setattr(sys, "platform", "win32")
    assert str(clean_user_path(r"dumps\(old)\Cflash.bin")) == r"dumps\(old)\Cflash.bin"


# 5. a damaged deflate stream inside the FRF
def test_a_corrupt_frf_is_refused_with_a_clean_error() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("FL_X.odx", b"<ODX>" + b"A" * 4000 + b"</ODX>")
    plain = bytearray(buf.getvalue())
    data_at = 30 + len("FL_X.odx")  # local header, no extra field
    plain[data_at] = 0xFF  # BTYPE 11: an invalid deflate block
    with pytest.raises(ValueError, match="Not an ODIS FRF"):
        read_frf(bytes(a ^ b for a, b in zip(plain, _keystream())))


def _xml(good: bytes, **attrs: str | None) -> str:
    base = {"START_ADDRESS": "0x0B80", "DIAGNOSTIC_ADDRESS": "0x19", "ZDC_NAME": "V09999999ZZ", "ZDC_VERSION": "0001"}
    base.update(attrs)
    tags = " ".join(f'{k}="{v}"' for k, v in base.items() if v is not None)
    return f"<MESSAGE><PARAMETER_DATA {tags}>{good.hex()}</PARAMETER_DATA></MESSAGE>"


def _fpa_payload() -> bytes:
    good = bytearray(b"QQ00" + bytes(4348))
    struct.pack_into("<I", good, 0x10FC, zlib.crc32(bytes(good[:0x10FC])) & 0xFFFFFFFF)
    return bytes(good)


# 6. no DIAGNOSTIC_ADDRESS means the gateway; an unreadable one is not the gateway
def test_odis_file_diagnostic_address_absent_is_the_gateway_unreadable_is_refused() -> None:
    good = _fpa_payload()
    assert parse_odis_zdc_file(_xml(good, DIAGNOSTIC_ADDRESS=None)).diagnostic_address == 0x19
    assert parse_odis_zdc_file(_xml(good, DIAGNOSTIC_ADDRESS="")).diagnostic_address == 0x19
    with pytest.raises(ValueError, match="gateway 0x19"):
        parse_odis_zdc_file(_xml(good, DIAGNOSTIC_ADDRESS="zz"))


def _bad_passport(df: bytes, ver: bytes) -> bytes:
    b = bytearray(df)
    b[0:0x80] = b"\xff" * 0x80
    b[0x10:0x1B] = b"V03935256AA"
    b[0x20:0x24] = ver
    struct.pack_into("<I", b, 0, (zlib.crc32(bytes(b[4:0x80])) & 0xFFFFFFFF) ^ 1)  # and a bad CRC
    return bytes(b)


# 7. a bad version in the passport falls back to 0001 everywhere; only an explicit bad version is refused
def test_a_bad_passport_version_is_repaired_not_refused(synth_dflash: bytes) -> None:
    for ver in (b"0000", b"12\xff\xff", b"A001"):
        df = _bad_passport(synth_dflash, ver)
        pp = parse_zdc_passport(apply_zdc_passport(df))
        assert pp.crc_ok and pp.dataset_ver == "0001"
        out, _ = parameterize_dflash_for_fecs(df, [0x10001600])
        assert parse_zdc_passport(out).dataset_ver == "0001"
        donor = apply_fpa_dataset(df, build_fpa_preset_block("fwd"))
        out = import_zdc_block(synth_dflash, 4, donor, copy_donor_passport=True)
        assert parse_zdc_passport(out).dataset_ver == "0001"
    with pytest.raises(ValueError, match="F1A1"):
        apply_zdc_passport(_bad_passport(synth_dflash, b"0000"), dataset_ver="A001")
    assert parse_odis_zdc_file(_xml(_fpa_payload(), ZDC_VERSION="A001")).dataset_ver == "0001"


# 8. the dataset number goes into an XML attribute
def test_odis_export_escapes_the_dataset_number(synth_dflash: bytes) -> None:
    df = apply_fpa_dataset(synth_dflash, build_fpa_preset_block("fwd"))
    df = apply_zdc_passport(df, dataset_pn='A&B<"C>', dataset_ver="0002")
    parsed = parse_odis_zdc_file(build_odis_zdc_file(df, 4))
    assert (parsed.dataset_pn, parsed.dataset_ver) == ('A&B<"C>', "0002")


# 9. analyze_dflash_swap strips 0xFF/non-printable VIN and analyze_dflash falls back to intact mirror / non-erased bank
def test_dflash_swap_vin_sanitization_and_dflash_mirror_fallback(synth_dflash: bytes) -> None:
    from contitool.core.analyzer import analyze_dflash, analyze_dflash_swap
    from contitool.core.constants import DFLASH_FSC_BASE_OFF, DFLASH_FSC_PAY_SIZE
    from contitool.core.patcher import parse_slot_selector, write_dflash_slots

    # 1) FSC slot with 0xFF-filled VIN must NOT leak U+FFFD into detected_vin
    df_bad_vin = bytearray(synth_dflash)
    off0 = DFLASH_FSC_BASE_OFF
    spay = bytearray(DFLASH_FSC_PAY_SIZE)
    spay[0:2] = b"\x11\x02"
    struct.pack_into(">I", spay, 2, 0x10000100)
    spay[6] = 0x03
    spay[7:12] = bytes.fromhex("1122334455")  # matches synth_dflash VCRN
    spay[12:29] = b"\xff" * 17
    struct.pack_into("<I", df_bad_vin, off0, 0x55555555)
    df_bad_vin[off0 + 4 : off0 + 4 + DFLASH_FSC_PAY_SIZE] = spay
    struct.pack_into("<I", df_bad_vin, off0 + 0xB0, zlib.crc32(spay) & 0xFFFFFFFF)
    sw_res = analyze_dflash_swap(bytes(df_bad_vin))
    assert sw_res.vin == ""
    assert len(sw_res.active_fscs) == 1 and sw_res.active_fscs[0].vin == ""

    # 2) Primary bank corrupted CRC-32 falls back to intact mirror off2
    spec_5f = parse_slot_selector("5F")
    ika = bytes.fromhex("A1B2C3D4E5F60718293A4B5C6D7E8F90")
    df_keyed, _ = write_dflash_slots(synth_dflash, [(spec_5f, ika)])
    corrupted_primary = bytearray(df_keyed)
    corrupted_primary[spec_5f.off1 + 4] ^= 0xFF  # keep magic 0x55555555, break primary CRC
    st_5f = next(s for s in analyze_dflash(bytes(corrupted_primary)) if s.spec.ecu_addr == "5F")
    assert st_5f.crc_ok is True
    assert st_5f.mirrored is False
    assert st_5f.first16_hex == ika.hex()

    # 3) Primary bank has partial magic while mirror is erased -> reports non-erased bank off1, not erased off2
    partial_df = bytearray(synth_dflash)
    struct.pack_into("<I", partial_df, spec_5f.off1, 0x12345678)
    partial_df[spec_5f.off1 + 4 : spec_5f.off1 + 20] = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
    st_part = next(s for s in analyze_dflash(bytes(partial_df)) if s.spec.ecu_addr == "5F")
    assert st_part.kind == "PARTIAL"
    assert st_part.crc_ok is False
    assert st_part.first16_hex == "0102030405060708090a0b0c0d0e0f10"


def test_barrel_all_exports_are_complete_and_valid() -> None:
    import importlib
    import pkgutil

    for pkg_name in ("contitool.core", "contitool.can"):
        pkg = importlib.import_module(pkg_name)
        pkg_all = set(getattr(pkg, "__all__", []))
        assert pkg_all
        for sym in pkg_all:
            assert hasattr(pkg, sym), f"{pkg_name}.__all__ references missing symbol {sym!r}"
        for mod_info in pkgutil.iter_modules(pkg.__path__):
            mod = importlib.import_module(f"{pkg_name}.{mod_info.name}")
            sub_all = getattr(mod, "__all__", None)
            if sub_all is None:
                continue
            for sym in sub_all:
                assert hasattr(mod, sym), f"{pkg_name}.{mod_info.name}.__all__ references missing {sym!r}"
                assert sym in pkg_all, f"{pkg_name}.{mod_info.name}.{sym!r} not re-exported in {pkg_name}.__all__"

    fpke_mod = importlib.import_module("contitool.fpke")
    for sym in fpke_mod.__all__:
        assert hasattr(fpke_mod, sym), f"contitool.fpke.__all__ references missing symbol {sym!r}"
    assert "fpke_support_info" in fpke_mod.__all__
    assert "FPKE_VERIFIED_SW_VERSIONS" in fpke_mod.__all__

