"""Unit tests for core analyzers, checksums, CP/Engineering patchers, and RSA-1024/SWaP crypto."""

from __future__ import annotations

from pathlib import Path
import pytest

from contitool.core import (
    analyze_cflash,
    analyze_dflash,
    analyze_dflash_swap,
    analyze_uflash,
    apply_cflash_patch,
    apply_cflash_rsa_modulus,
    apply_dflash_swap_rsa_modulus,
    apply_engineering_patch,
    apply_uflash_rsa_patch,
    bind_cp_turnkey,
    build_signed_fsc,
    check_key_warnings,
    clear_dflash_slots,
    detect_dump_file,
    generate_rsa1024_e3_keypair,
    load_rsa1024_key_material,
    parse_hex_key,
    parse_slot_selector,
    ripemd160,
    rsassa_pkcs1_v15_verify,
    save_rsa1024_keypair_bundle,
    sign_fbl_odx_application,
    validate_dflash_bytes,
)


def test_ripemd160_official_vectors() -> None:
    vectors = {
        b"": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        b"a": "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
        b"abc": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        b"message digest": "5d0689ef49d2fae572b881b123a85ffa21595f36",
        b"abcdefghijklmnopqrstuvwxyz": "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
    }
    for msg, expected in vectors.items():
        assert ripemd160(msg).hex() == expected


def test_cflash_cp_and_engineering_roundtrips(synth_cflash: bytes) -> None:
    info0 = analyze_cflash(synth_cflash)
    assert info0.crc_ok
    assert info0.hook_mode == "STOCK"
    assert not info0.mask_bypassed
    assert not info0.eng_gate_unlocked

    # Patch Hybrid CP + 95640 mask bypass -> then restore back to exact stock bytes
    cf_hyb, _, _ = apply_cflash_patch(synth_cflash, mode="hybrid", bypass_eeprom_mask=True)
    info_hyb = analyze_cflash(cf_hyb)
    assert info_hyb.crc_ok
    assert info_hyb.hook_mode == "HYBRID"
    assert info_hyb.mask_bypassed

    cf_restored, _, _ = apply_cflash_patch(cf_hyb, mode="restore_stock")
    assert cf_restored == synth_cflash

    # Patch Engineering Mode -> then restore back to exact stock bytes
    cf_eng, _, _ = apply_engineering_patch(synth_cflash)
    info_eng = analyze_cflash(cf_eng)
    assert info_eng.crc_ok
    assert info_eng.eng_gate_unlocked
    assert info_eng.ccp_blacklist_bypassed
    assert info_eng.a167_branch_bypassed

    cf_eng_restored, _, _ = apply_engineering_patch(cf_eng, restore_stock=True)
    assert cf_eng_restored == synth_cflash


def test_uflash_roundtrip_and_truncated_dflash_guard(synth_uflash: bytes, tmp_path: Path) -> None:
    uf_eng, _ = apply_uflash_rsa_patch(synth_uflash)
    assert analyze_uflash(uf_eng).rsa_bypassed
    uf_stock, _ = apply_uflash_rsa_patch(uf_eng, restore_stock=True)
    assert uf_stock == synth_uflash

    # 32 KB non-Uflash buffer must be caught as truncated R7F7010343AFP Dflash!
    bad_32k = b"\xff" * 0x8000
    with pytest.raises(ValueError):
        validate_dflash_bytes(bad_32k)
    p_bad = tmp_path / "truncated_dflash.bin"
    p_bad.write_bytes(bad_32k)
    det = detect_dump_file(p_bad)
    assert not det.valid
    assert det.kind == "truncated_dflash"

    # another bootloader build (no RSA check where ours have it) is still a bootloader, and it cannot be patched
    other_fbl = bytearray(synth_uflash)
    other_fbl[0x3424:0x3434] = bytes(16)
    other_fbl[0x7000:0x7012] = b"SH850T01xxxxxxV200"
    p_fbl = tmp_path / "Uflash.bin"
    p_fbl.write_bytes(other_fbl)
    det = detect_dump_file(p_fbl)
    assert (det.kind, det.valid, det.uflash_info.signature_found) == ("uflash", True, False)
    with pytest.raises(ValueError):
        apply_uflash_rsa_patch(bytes(other_fbl))


def test_turnkey_cp_binding_and_key_guardrails(synth_cflash: bytes, synth_dflash: bytes) -> None:
    # Suspicious keys must raise STOP warnings
    assert any(sev == "STOP" for sev, _ in check_key_warnings(b"\x00" * 16))
    assert any(sev == "STOP" for sev, _ in check_key_warnings(bytes.fromhex("000000000000000000000000000000E5")))

    spec_5f = parse_slot_selector("5F")
    spec_47 = parse_slot_selector("47")
    ika = parse_hex_key("A1B2C3D4E5F60718293A4B5C6D7E8F90")
    assert not check_key_warnings(ika)

    out_cf, out_df, summary = bind_cp_turnkey(
        synth_cflash,
        synth_dflash,
        [(spec_5f, ika), (spec_47, ika)],
    )
    assert summary["eeprom_mask_bypassed"] is True  # Banks were empty -> auto-enabled!
    assert analyze_cflash(out_cf).hook_mode == "HYBRID"

    slots = {s.spec.ecu_addr: s for s in analyze_dflash(out_df)}
    assert slots["5F"].kind == "PLAIN" and slots["5F"].crc_ok and slots["5F"].mirrored
    assert slots["5F"].first16_hex == ika.hex()
    assert slots["47"].kind == "PLAIN" and slots["47"].crc_ok

    cleared_df = clear_dflash_slots(out_df, [spec_5f, spec_47])
    assert cleared_df == synth_dflash


def test_rsa1024_keygen_pem_fsc_and_odx_signing(
    synth_cflash: bytes,
    synth_dflash: bytes,
    tmp_path: Path,
) -> None:
    kp = generate_rsa1024_e3_keypair()
    j_path, priv_pem, pub_pem = save_rsa1024_keypair_bundle(tmp_path / "test_rsa.json", kp)

    n_from_json, d_from_json = load_rsa1024_key_material(j_path)
    n_from_priv, d_from_priv = load_rsa1024_key_material(priv_pem)
    n_from_pub, d_from_pub = load_rsa1024_key_material(pub_pem)
    assert n_from_json == n_from_priv == n_from_pub
    assert d_from_json == d_from_priv and d_from_json is not None
    assert d_from_pub is None

    # Embed custom RSA modulus into Cflash & Dflash
    cf_rsa, _, _ = apply_cflash_rsa_modulus(synth_cflash, n_from_json, patch_swap=True, patch_fbl=True)
    df_rsa, _, vcrn = apply_dflash_swap_rsa_modulus(synth_dflash, n_from_json)
    assert analyze_cflash(cf_rsa).swap_rsa_mod == n_from_json
    assert analyze_cflash(cf_rsa).fbl_rsa_mod == n_from_json
    assert analyze_dflash_swap(df_rsa).swap_rsa_mod == n_from_json
    assert vcrn == bytes.fromhex("1122334455")

    # Sign 171-byte FSC v2 & verify PKCS#1 v1.5 RIPEMD-160 signature
    fsc = build_signed_fsc(0x10000100, vcrn, "WVWZZZAUZJW000001", n_from_json, d_from_json)
    assert len(fsc) == 171
    assert rsassa_pkcs1_v15_verify(fsc[:43], fsc[43:], n_from_json, 3, "ripemd160")

    # Sign ODX FD_0DATA
    sig_odx = sign_fbl_odx_application(cf_rsa, n_from_json, d_from_json)
    assert len(sig_odx) == 128


def test_cli_subcommands_end_to_end(
    synth_cflash: bytes,
    synth_dflash: bytes,
    synth_uflash: bytes,
    tmp_path: Path,
) -> None:
    from contitool.cli.main import main

    cf = tmp_path / "Cflash.bin"
    df = tmp_path / "Dflash.bin"
    uf = tmp_path / "Uflash.bin"
    cf.write_bytes(synth_cflash)
    df.write_bytes(synth_dflash)
    uf.write_bytes(synth_uflash)

    assert main(["-l", "en", "banks"]) == 0
    assert main(["-l", "ru", "guide"]) == 0
    assert main(["inspect", "--cflash", str(cf), "--dflash", str(df), "--uflash", str(uf)]) == 0

    cf_hyb = tmp_path / "cf_hyb.bin"
    cf_rst = tmp_path / "cf_rst.bin"
    assert main(["patch-cflash", "-i", str(cf), "-o", str(cf_hyb), "--bypass-eeprom-mask"]) == 0
    assert main(["patch-cflash", "-i", str(cf_hyb), "-o", str(cf_rst), "--restore-stock"]) == 0
    assert cf_rst.read_bytes() == synth_cflash

    cf_b = tmp_path / "cf_bind.bin"
    df_b = tmp_path / "df_bind.bin"
    assert (
        main(
            [
                "bind-cp",
                "--cflash-in",
                str(cf),
                "--dflash-in",
                str(df),
                "--cflash-out",
                str(cf_b),
                "--dflash-out",
                str(df_b),
                "--set",
                "5F=112233445566778899AABBCCDDEEFF00",
            ]
        )
        == 0
    )

    cf_eng = tmp_path / "cf_eng.bin"
    uf_eng = tmp_path / "uf_eng.bin"
    assert (
        main(
            [
                "patch-engineering",
                "--cflash-in",
                str(cf),
                "--cflash-out",
                str(cf_eng),
                "--uflash-in",
                str(uf),
                "--uflash-out",
                str(uf_eng),
            ]
        )
        == 0
    )

    kp_json = tmp_path / "rsa.json"
    cf_rsa = tmp_path / "cf_rsa.bin"
    df_rsa = tmp_path / "df_rsa.bin"
    fsc_out = tmp_path / "out.fsc"
    sig_out = tmp_path / "out.sig"
    assert (
        main(
            [
                "set-rsa-key",
                "--generate-key",
                str(kp_json),
                "--cflash-in",
                str(cf),
                "--cflash-out",
                str(cf_rsa),
                "--dflash-in",
                str(df),
                "--dflash-out",
                str(df_rsa),
                "--target",
                "both",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "sign-fsc",
                "-k",
                str(kp_json),
                "--fec",
                "10000100",
                "--dflash",
                str(df_rsa),
                "--no-vin",
                "-o",
                str(fsc_out),
            ]
        )
        == 0
    )
    assert len(fsc_out.read_bytes()) == 171
    assert main(["sign-odx", "-i", str(cf_rsa), "-k", str(kp_json), "-o", str(sig_out)]) == 0
    assert len(sig_out.read_bytes()) == 128
