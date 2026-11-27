"""Unit, protocol-simulation, and GUI tests for the VAG / Audi FPK_E (Kombi, 83A920700E) module."""

from __future__ import annotations

import os
from pathlib import Path
import struct
import zlib

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import can  # noqa: E402
import pytest  # noqa: E402

from contitool.can import can_identify  # noqa: E402
from contitool.fpke import (  # noqa: E402
    BFASELR_ADDR,
    EEL_83A_IDS,
    EEL_MARK,
    FPKE_APPLET_ENTRY,
    FPKE_ARM_ID,
    FPKE_ARM_RESPONSE_ID,
    FPKE_BLOCK_ID,
    FPKE_CALLER_RETURN,
    FPKE_CFLASH_ADDR,
    FPKE_CFLASH_CONTROL_PREFIX,
    FPKE_CF_CH9_ID,
    FPKE_DFLASH_ADDR,
    FPKE_DFLASH_SIZE,
    FPKE_EXTRA_ADDR,
    FPKE_EXTRA_SIZE,
    FPKE_FORGED_PTR,
    FPKE_MARKER_ADDR,
    FPKE_POINTER_FRAME,
    FPKE_RESULT_ADDR,
    FPKE_RESULT_SIZE,
    FPKE_SAVED_RETURN,
    FPKE_SOURCE_PARAM,
    FPKE_STREAM_RX_ID,
    FPKE_UDS_RX_ID,
    FPKE_UDS_TX_ID,
    FpkeCanLink,
    IDAUTH_ADDR,
    IDST_ADDR,
    analyze_fpke_dflash,
    analyze_fpke_extra_area,
    build_fd11_proof,
    build_fpke_dflash_bc_applet,
    build_fpke_dflash_write_applet,
    build_fpke_swresa_reset_applet,
    can_fpke_full_read,
    can_fpke_read_region,
    can_fpke_write_dflash,
    detect_fpke_files,
    eel_cs24,
    eel_faci_word_mask,
    extract_fpke_eel_updates,
    flood_payload,
    format_fpke_report,
    fpke_eel_layout,
    is_fpke_dflash,
    is_fpke_extra_area,
    is_fpke_ident,
    normalize_fpke_dflash_for_faci,
    summarize_fpke_dflash_changes,
    validate_fpke_extra_area,
    verify_fpke_self_tests,
)
from contitool.i18n import set_lang  # noqa: E402


# ────────────────────────────── Synthetic EEL T01 & Extra Area Builders ──────────────────────────────


def _crc32_le(data: bytes) -> bytes:
    return struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF)


def _put_eel_record(df: bytearray, vb: int, ref_idx: int, top_off: int, ident: int, payload: bytes, *, active: bool = True) -> None:
    """Write one EEL T01 virtual block header, DRP reference entry, and top-down word-reversed record."""
    base = vb * 0x800
    if active:
        # Active VB: p=0x55555555 (+4), a0=0x55555555 (+8), a1=0x55555555 (+0xC), ec=eel_cs24(10+vb) (+0x10)
        struct.pack_into("<5I", df, base, 0xFFFFFFFF, EEL_MARK, EEL_MARK, EEL_MARK, eel_cs24(10 + vb))
        struct.pack_into("<I", df, base + 0x14, eel_cs24(0x7FC))
    else:
        # Invalidated historical VB: i0=0x55555555 (+0), a0=0x55555555 (+8), i1=0x55555555 (+0x7FC)
        struct.pack_into("<5I", df, base, EEL_MARK, EEL_MARK, EEL_MARK, EEL_MARK, eel_cs24(5 + vb))
        struct.pack_into("<I", df, base + 0x7FC, EEL_MARK)

    size = EEL_83A_IDS[ident]
    assert len(payload) == size
    padded = payload + b"\xff" * (((size + 3) & ~3) - size)
    for idx in range(0, len(padded), 4):
        df[base + top_off - idx : base + top_off - idx + 4] = padded[idx : idx + 4]

    ref_addr = base + 0x18 + ref_idx * 0x10
    drp = (ident & 0xFFFF) | ((top_off & 0x7FFF) << 16)
    struct.pack_into("<4I", df, ref_addr, EEL_MARK, EEL_MARK, EEL_MARK, drp)


def build_synthetic_fpke_dflash() -> bytes:
    """Construct a valid 64 KiB FPK_E DataFlash image with EEL T01 records (0x45, 0x60, 0x63, 0x64, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D)."""
    df = bytearray(b"\xff" * FPKE_DFLASH_SIZE)
    for vb in range(28):
        base = vb * 0x800
        struct.pack_into("<5I", df, base, EEL_MARK, EEL_MARK, EEL_MARK, EEL_MARK, eel_cs24(1 + vb))
        struct.pack_into("<I", df, base + 0x7FC, EEL_MARK)

    # VB 2: active block holding secret records
    # 0x63 (140 B): FD11 identifier + level 0..6 key + CRC + level 7 key + CRC + aux + CRC
    r63 = bytearray(b"\xff" * EEL_83A_IDS[0x63])
    r63[:2] = struct.pack("<H", len(r63))
    r63[2:17] = bytes.fromhex("383341393230373030452036313831")  # 15B ID
    k_l06 = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    k_l7 = bytes.fromhex("202122232425262728292a2b2c2d2e2f")
    k_aux = bytes.fromhex("303132333435363738393a3b3c3d3e3f")
    r63[0x16:0x26] = k_l06
    r63[0x26:0x2A] = _crc32_le(k_l06)
    r63[0x2A:0x3A] = k_l7
    r63[0x3A:0x3E] = _crc32_le(k_l7)
    r63[0x3E:0x4E] = k_aux
    r63[0x4E:0x52] = _crc32_le(k_aux)

    # 0x64 (64 B): CRC-valid field at +0x02
    r64 = bytearray(b"\xff" * EEL_83A_IDS[0x64])
    r64[:2] = struct.pack("<H", len(r64))
    f64 = bytes.fromhex("404142434445464748494a4b4c4d4e4f")
    r64[0x02:0x12] = f64
    r64[0x12:0x16] = _crc32_le(f64)

    # 0x66 (24 B): Cluster WFS ID (+0x02) & 8 partner MAC IDs (MSG_1 +0x04, GSG +0x0E, ELV +0x0C)
    r66 = bytearray(b"\xff" * EEL_83A_IDS[0x66])
    r66[:2] = struct.pack("<H", len(r66))
    r66[0x02:0x04] = bytes.fromhex("a001")  # WFS
    r66[0x04:0x06] = bytes.fromhex("e001")  # MSG_1 (ECU 1)
    r66[0x0C:0x0E] = bytes.fromhex("e005")  # ELV
    r66[0x0E:0x10] = bytes.fromhex("e002")  # GSG (TCU)
    r66[0x10:0x12] = b"\x00\x00"            # no partner in learning

    # 0x67 (40 B): Transponder table (allowed=8, learned=2, key 0 & key 1)
    r67 = bytearray(b"\xff" * EEL_83A_IDS[0x67])
    r67[:2] = struct.pack("<H", len(r67))
    r67[2:6] = bytes.fromhex("a1b2c3d4")
    r67[6:10] = bytes.fromhex("e5f60718")
    r67[0x22] = 8
    r67[0x23] = 0x22  # flags=2, learned=2
    r67[0x24] = 2

    # 0x68 (128 B): VIN at +0x17..0x28, K_c at +0x28..0x38, Slot A/B CRCs at +0x38..0x40, PowerClass at +0x40, partners mask at +0x41
    r68 = bytearray(b"\xff" * EEL_83A_IDS[0x68])
    r68[:2] = struct.pack("<H", len(r68))
    r68[0x17:0x28] = b"TESTVIN0123456789"
    r68[0x28:0x38] = bytes.fromhex("505152535455565758595a5b5c5d5e5f")
    r68[0x38:0x40] = bytes.fromhex("1122334455667788")
    r68[0x40] = 0x4C  # PowerClass (P_class)
    r68[0x41] = 0x23  # MSG_1 (bit 0) + GSG (bit 1) + ELV (bit 5)
    r68[0x42] = 0x03
    r68[0x44] = 0x00
    r68[0x45:0x4B] = b"\x00" * 6
    r68[0x4B] = 1     # normal adapted mode
    r68[0x4C] = 1     # identity counter
    r68[0x4D] = 0x80  # key_over_can (KESSY)

    # 0x69 (36 B): Slot S0 / S1
    r69 = bytearray(b"\xff" * EEL_83A_IDS[0x69])
    r69[:2] = struct.pack("<H", len(r69))

    # 0x6A (124 B): Transponder queue
    r6a = bytearray(b"\xff" * EEL_83A_IDS[0x6A])
    r6a[:2] = struct.pack("<H", len(r6a))
    r6a[2] = 1
    r6a[3:19] = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

    # 0x6B (84 B): IKA / CP working key /3 (+0x02..0x12) + CP /1 bank 0..3 (+0x12..0x52)
    r6b = bytearray(b"\xff" * EEL_83A_IDS[0x6B])
    r6b[:2] = struct.pack("<H", len(r6b))
    r6b[0x02:0x12] = bytes.fromhex("606162636465666768696a6b6c6d6e6f")
    for b_idx in range(4):
        r6b[0x12 + b_idx * 16 : 0x22 + b_idx * 16] = bytes([0x70 + b_idx] * 16)

    # 0x6C (20 B) & 0x6D (100 B)
    r6c = bytearray(b"\xff" * EEL_83A_IDS[0x6C])
    r6c[:2] = struct.pack("<H", len(r6c))
    r6c[0x02:0x12] = bytes.fromhex("808182838485868788898a8b8c8d8e8f")

    r6d = bytearray(b"\xff" * EEL_83A_IDS[0x6D])
    r6d[:2] = struct.pack("<H", len(r6d))
    r6d[0x02:0x0C] = bytes.fromhex("90919293949596979899")

    # 0x45 (240 B) part number & 0x60 (16 B) odometer
    r45 = bytearray(b"\xff" * EEL_83A_IDS[0x45])
    r45[:2] = struct.pack("<H", len(r45))
    r45[2:6] = b"6181"
    r45[37:48] = b"83A920700E "

    r60 = bytearray(b"\xff" * EEL_83A_IDS[0x60])
    r60[:2] = struct.pack("<H", len(r60))
    struct.pack_into("<3I", r60, 4, 12345, 12345, 12345)  # 24,690 km

    top = 0x7F0
    for ref_idx, (ident, rec) in enumerate(
        (
            (0x63, r63),
            (0x64, r64),
            (0x66, r66),
            (0x67, r67),
            (0x68, r68),
            (0x69, r69),
            (0x6A, r6a),
            (0x6B, r6b),
            (0x6C, r6c),
            (0x6D, r6d),
            (0x45, r45),
            (0x60, r60),
        )
    ):
        _put_eel_record(df, 2, ref_idx, top, ident, bytes(rec), active=True)
        top -= ((len(rec) + 3) & ~3) + 8

    return bytes(df)


def build_synthetic_extra_area() -> bytes:
    """Construct a valid 256-byte RH850 Extra Area image (`0xFF300000`)."""
    ex = bytearray(b"\xff" * FPKE_EXTRA_SIZE)
    # Security word at 0x40: Command Protection + Serial Programming + Read/Write/Erase enabled (0xE9FFFFFF)
    struct.pack_into("<I", ex, 0x40, 0xE9FFFFFF)
    # 16-byte IDCODE at 0x50
    ex[0x50:0x60] = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    # Reset vector at 0x60
    struct.pack_into("<I", ex, 0x60, 0x00000000)
    # OPBT0 at 0x70
    struct.pack_into("<I", ex, 0x70, 0xB9FFEFF7)
    # ICU bound at 0x9C
    struct.pack_into("<I", ex, 0x9C, 0x00000001)
    return bytes(ex)


# ────────────────────────────── Tests: Offline Analysis & Self-Tests ──────────────────────────────


def test_fpke_self_tests_and_pointer_math() -> None:
    verify_fpke_self_tests()
    assert FPKE_POINTER_FRAME == 1019
    assert flood_payload(FPKE_POINTER_FRAME) == FPKE_FORGED_PTR.to_bytes(4, "little") + b"\x00\x00\x00\x00"


def test_fpke_dflash_eel_analysis_and_historical_fallback() -> None:
    set_lang("en")
    df = build_synthetic_fpke_dflash()
    assert is_fpke_dflash(df)

    res = analyze_fpke_dflash(df)
    assert res["fd11_identifier"] == "383341393230373030452036313831"
    by_id = {it["key_id"]: it for it in res["items"]}
    assert by_id["fd11_l0_6"]["hex"] == "101112131415161718191a1b1c1d1e1f"
    assert by_id["fd11_l0_6"]["crc_valid"] is True
    assert by_id["fd11_l7"]["hex"] == "202122232425262728292a2b2c2d2e2f"
    assert by_id["fd11_l7"]["crc_valid"] is True
    assert by_id["kc"]["hex"] == "505152535455565758595a5b5c5d5e5f"
    assert by_id["ika_cp3"]["hex"] == "606162636465666768696a6b6c6d6e6f"
    assert by_id["cp1_bank_0"]["hex"] == "70" * 16
    assert res["metadata"]["vin"] == "TESTVIN0123456789"
    assert res["metadata"]["part_number"] == "83A920700E"
    assert res["metadata"]["power_class"] == "0x4C"
    assert res["metadata"]["power_class_int"] == 0x4C
    assert res["metadata"]["partners_mask"] == "0x23"
    assert res["metadata"]["adapted_partners"] == ["MSG_1", "GSG", "ELV"]
    assert res["immo_config"]["cluster_mac_id"] == "A001"
    assert res["immo_config"]["key_over_can"] is True
    by_pcode = {p["code"]: p for p in res["immo_config"]["partners"]}
    assert by_pcode["MSG_1"]["adapted"] is True and by_pcode["MSG_1"]["mac_id_hex"] == "E001"
    assert by_pcode["GSG"]["adapted"] is True and by_pcode["GSG"]["mac_id_hex"] == "E002"
    assert by_pcode["ELV"]["adapted"] is True and by_pcode["ELV"]["mac_id_hex"] == "E005"
    assert by_pcode["OCU"]["adapted"] is False
    assert res["metadata"]["odometer_km"] == 24690
    assert res["odometer"]["unanimous"] is True
    assert res["transponder_records"]["learned_keys"] == 2
    assert res["transponder_records"]["key_ids"][0]["hex"] == "a1b2c3d4"

    # Historical VB fallback: if VB 2's 0x6B record has a corrupted FEE size header, eel_read_record_any recovers from VB 1
    df_hist = bytearray(df)
    r6b_good = bytearray(b"\xff" * EEL_83A_IDS[0x6B])
    r6b_good[:2] = struct.pack("<H", len(r6b_good))
    r6b_good[0x02:0x12] = bytes.fromhex("deadbeefcafebabe0123456789abcdef")
    _put_eel_record(df_hist, 1, 0, 0x700, 0x6B, bytes(r6b_good), active=False)

    # Corrupt FEE header of 0x6B in active VB 2
    lay = fpke_eel_layout()
    _, latest = __import__("contitool.fpke", fromlist=["eel_parse_pool"]).eel_parse_pool(lay, bytes(df_hist))
    _vb2, top_6b, _ref = latest[0x6B]
    df_hist[top_6b : top_6b + 2] = b"\x00\x00"

    res_hist = analyze_fpke_dflash(bytes(df_hist))
    by_id_hist = {it["key_id"]: it for it in res_hist["items"]}
    assert by_id_hist["ika_cp3"]["hex"] == "deadbeefcafebabe0123456789abcdef"
    assert res_hist["record_sources"]["0x6B"]["generation"] == "historical"
    assert res_hist["record_sources"]["0x6B"]["vb"] == 1


def test_fpke_immo_passport_comparator_and_a_to_b_transfer_plan() -> None:
    from contitool.fpke import (
        EEL_1703_IDS,
        compare_fpke_immo_passports,
        decode_fpke_02ed,
        decode_fpke_02ee,
        extract_fpke_immo_passport,
        plan_fpke_a_to_b_transfer,
        vote_fpke_odometer,
    )

    # 1. Decode UDS 02ED (PowerClass at byte[3], Brand at byte[2], Identity counter at byte[1]) & 02EE
    d_ed = decode_fpke_02ed(bytes([0x02, 0x01, 0x03, 0xE6, 0x02, 0x00, 0x06, 0x00, 0x01, 0x00]))
    assert d_ed["life_state"] == 2
    assert d_ed["identity_counter"] == 1
    assert d_ed["brand_id"] == 3
    assert d_ed["power_class"] == 0xE6
    assert d_ed["power_class_hex"] == "0xE6"
    assert d_ed["learned_keys"] == 2
    assert d_ed["remaining_keys"] == 6
    assert d_ed["keyless_coded"] is True

    d_ee = decode_fpke_02ee(bytes([0x00, 0x03, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x07, 0x00, 0x00]))
    by_code = {p["code"]: p for p in d_ee["partners"]}
    assert by_code["MSG_1"]["mac_verified"] is True and by_code["MSG_1"]["response_sent"] is True
    assert by_code["GSG"]["mac_verified"] is True
    assert by_code["ELV"]["mac_verified"] is True and by_code["ELV"]["response_sent"] is False

    # 2. Odometer 2-of-3 majority voting when one copy is corrupted
    r60_corrupt = struct.pack("<HH3I", 16, 0xFFFF, 50_000, 999_999, 50_000)
    odo_v = vote_fpke_odometer(r60_corrupt, b"\x04\x00\x00\x01")
    assert odo_v["odometer_km"] == 100_000
    assert odo_v["unanimous"] is False
    assert odo_v["repair_count"] == 1

    # 3. Read-only Immo passport extraction (§4, §5, §8, §9, §11)
    donor_df = build_synthetic_fpke_dflash()
    passport_a = extract_fpke_immo_passport(donor_df)
    assert passport_a["read_only"] is True
    assert passport_a["immo"]["personalized"] is True
    assert passport_a["immo"]["vin"] == "TESTVIN0123456789"
    assert passport_a["immo"]["vin_state"] == "present"
    assert passport_a["immo"]["cs"] == "505152535455565758595A5B5C5D5E5F"
    assert passport_a["immo"]["vdo_cs_plus"] == "1122334455667788"
    assert passport_a["immo"]["crc32_a_le"] == "11223344"
    assert passport_a["immo"]["crc32_b_le"] == "55667788"
    assert passport_a["immo"]["power_class"] == "4C"
    assert passport_a["immo"]["power_class_hex"] == "0x4C"
    assert passport_a["immo"]["mac_fields"] == {"dash": "A001", "ecu": "E001", "elv": "E005", "tcu": "E002"}
    assert passport_a["immo"]["mac4"] == "A001E001"
    # Key IDs in diagnostic u32 little-endian display order (a1b2c3d4 -> D4C3B2A1, e5f60718 -> 1807F6E5)
    assert passport_a["immo"]["keys"][:2] == ["D4C3B2A1", "1807F6E5"]
    assert passport_a["immo"]["keys"][2:] == [None] * 6
    assert passport_a["immo"]["counts"]["allowed_keys"] == 8
    assert passport_a["immo"]["counts"]["learned_keys"] == 2
    assert passport_a["immo"]["counts"]["session_xor_flags"] == 2
    assert passport_a["immo"]["s0_s1"]["state"] == "empty_expected_in_mode_1"
    assert "0x66" in passport_a["record_sources"] and "0x68" in passport_a["record_sources"]

    # 4. Semantic comparison across two dumps with different physical VB/top/ref (§6.3, §11)
    donor_re_read = bytearray(donor_df)
    lay = fpke_eel_layout()
    r68_orig, _ = __import__("contitool.fpke", fromlist=["eel_read_record_any"]).eel_read_record_any(lay, donor_df, 0x68)
    _put_eel_record(donor_re_read, 5, 0, 0x7A0, 0x68, r68_orig, active=True)
    cmp_res = compare_fpke_immo_passports(donor_df, bytes(donor_re_read))
    assert cmp_res["semantic_match"] is True
    assert cmp_res["r68_sha256_equal"] is True
    assert cmp_res["dflash_sha256_equal"] is False
    assert cmp_res["physical_vb_differs"] is True

    # 5. Static Donor A -> Recipient B transfer plan (§7, §8, §9, §12)
    recipient_df = bytearray(build_synthetic_fpke_dflash())
    r30_b = bytearray(b"\xff" * EEL_83A_IDS[0x30])
    r30_b[:2] = struct.pack("<H", len(r30_b))
    r30_b[11:31] = bytes.fromhex("05a50a186b8400080188720b1001000000000000")
    r45_b = bytearray(b"\xff" * EEL_83A_IDS[0x45])
    r45_b[:2] = struct.pack("<H", len(r45_b))
    r45_b[2:6] = b"1711"
    r45_b[37:48] = b"5E0920790A "
    r68_b = bytearray(b"\xff" * EEL_83A_IDS[0x68])
    r68_b[:2] = struct.pack("<H", len(r68_b))
    r68_b[0x17:0x28] = b"RECIPIENTVIN00000"
    r68_b[0x28:0x38] = b"\x99" * 16
    r68_b[0x40] = 0xB0
    r68_b[0x41] = 0x01
    r68_b[0x4B] = 1
    r60_b = bytearray(b"\xff" * EEL_83A_IDS[0x60])
    r60_b[:2] = struct.pack("<H", len(r60_b))
    struct.pack_into("<3I", r60_b, 4, 45000, 45000, 45000)
    _put_eel_record(recipient_df, 3, 0, 0x7F0, 0x30, bytes(r30_b), active=True)
    _put_eel_record(recipient_df, 3, 1, 0x770, 0x45, bytes(r45_b), active=True)
    _put_eel_record(recipient_df, 3, 2, 0x700, 0x68, bytes(r68_b), active=True)
    _put_eel_record(recipient_df, 3, 3, 0x670, 0x60, bytes(r60_b), active=True)

    plan = plan_fpke_a_to_b_transfer(donor_df, bytes(recipient_df))
    assert plan["read_only"] is True
    assert plan["raw_dflash_clone_prohibited"] is True
    assert plan["transfer_from_a"]["vin"] == "TESTVIN0123456789"
    assert plan["transfer_from_a"]["power_class"] == "4C"
    assert plan["transfer_from_a"]["mac4"] == "A001E001"
    assert plan["preserve_on_b"]["part_number"] == "5E0920790A"
    assert plan["preserve_on_b"]["coding_hex"] == "05A50A186B8400080188720B1001000000000000"
    assert plan["preserve_on_b"]["current_kc_on_b"] == "99" * 16
    assert plan["odometer_sync"]["donor_a_km"] == 24690
    assert plan["odometer_sync"]["recipient_b_km"] == 90000
    assert plan["s0_s1_and_0x6a_policy"]["allow_02f7_with_stub_s0_s1"] is False
    assert len(EEL_1703_IDS) == 162


def test_fpke_extra_area_validation_and_report() -> None:
    set_lang("ru")
    ex = build_synthetic_extra_area()
    assert is_fpke_extra_area(ex)
    info = analyze_fpke_extra_area(ex)
    assert info["protection_mode"] == "Command Protection"
    assert info["serial_programming_enabled"] is True
    assert info["idcode"] == "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"

    report_txt = format_fpke_report(
        dflash_info=analyze_fpke_dflash(build_synthetic_fpke_dflash()),
        extra_info=info,
        idauth_info={"idst_before": "00000001", "idst_after_idcode": "00000000", "idst_after_relock": "00000001"},
    )
    assert "IKA / CP working key /3" in report_txt
    assert "ПРИНЯТ (00000000)" in report_txt

    bad_ex = bytearray(ex)
    bad_ex[0] = 0x00
    with pytest.raises(RuntimeError, match="reserved prefix"):
        validate_fpke_extra_area(bytes(bad_ex))

    # Factory-unlocked Extra Area (security=0xFFFFFFFF, blank IDCODE, valid OPBT0=0xFFFCDF87 as on 5NA920790D SW 1701)
    unlocked_ex = bytearray(b"\xff" * FPKE_EXTRA_SIZE)
    struct.pack_into("<I", unlocked_ex, 0x60, 0x00000000)
    struct.pack_into("<I", unlocked_ex, 0x70, 0xFFFCDF87)
    assert is_fpke_extra_area(bytes(unlocked_ex))
    unlocked_info = analyze_fpke_extra_area(bytes(unlocked_ex))
    assert unlocked_info["security_raw"] == "0xFFFFFFFF"
    assert unlocked_info["opbt0"] == "0xFFFCDF87"
    assert unlocked_info["idcode_is_blank_ff"] is True

    # Completely blank all-0xFF (OPBT0=0xFFFFFFFF) or zeroed security (0x00000000) must still be rejected
    with pytest.raises(RuntimeError, match="invalid security or OPBT0 word"):
        validate_fpke_extra_area(b"\xff" * FPKE_EXTRA_SIZE)
    zero_sec = bytearray(unlocked_ex)
    struct.pack_into("<I", zero_sec, 0x40, 0x00000000)
    with pytest.raises(RuntimeError, match="invalid security or OPBT0 word"):
        validate_fpke_extra_area(bytes(zero_sec))


# ────────────────────────────── Simulated FPK_E CAN Bus ──────────────────────────────


class FakeFpkeBus:
    """Simulates a VAG FPK_E (83A920700E SW 83A or 5E0920790A SW 1703/1711) cluster on 0x714/0x77E, 0x1BFCA2xx, 0x17FA0E14, and 0x6F1."""

    def __init__(self, *, enable_stream_0x6f1: bool = True, sw_profile: str = "83a") -> None:
        from contitool.can.fpke import fpke_get_profile

        self.enable_stream_0x6f1 = enable_stream_0x6f1
        self.sw_profile = sw_profile.strip().lower()
        self.prof = fpke_get_profile(self.sw_profile)
        self.rx: list[can.Message] = []
        self.dflash = build_synthetic_fpke_dflash()
        self.faci_mask = eel_faci_word_mask(fpke_eel_layout(None, self.dflash), self.dflash)
        self.faci_busy_countdown = 0
        self.faci_erases = 0
        self.faci_words_written = 0
        self.swresa_resets = 0
        self.extra = build_synthetic_extra_area()
        self.cflash_head = FPKE_CFLASH_CONTROL_PREFIX + bytes(range(1, 13))
        self.ram: dict[int, bytes] = {
            int(self.prof["applet_entry"]): b"\x11" * 256,
            int(self.prof["source_param"]): b"\x22" * 8,
            int(self.prof["result_addr"]): b"\x33" * FPKE_RESULT_SIZE,
            int(self.prof["marker_addr"]): b"\x44" * 32,
            int(self.prof["saved_return"]): int(self.prof["caller_return"]).to_bytes(4, "little"),
            BFASELR_ADDR: b"\x00",
        }
        self.idst = b"\x01\x00\x00\x00"
        self.vendor_level = 0
        self.ec_Count = 0
        self.ed_count = 0
        self.forged_ptr_seen = False
        self.writes_0x3d = 0
        self._isotp_len = 0
        self._isotp_buf = bytearray()
        self._stream_idx = 0
        self.sent_std: list[tuple[int, bytes]] = []
        self.dtcs_cleared = False
        if self.sw_profile in ("1703", "1711"):
            part_b = b"5E0920790A "
            hw_b = b"5E0920790  "
            sw_b = self.sw_profile.encode("ascii")
            odx_b = b"EV_DashBoardVDDMQBAB"
        else:
            part_b = b"83A920700E "
            hw_b = b"83A920700  "
            sw_b = b"6181"
            odx_b = b"EV_DashBoardAU27X"
        self.ident_map = {
            0xF187: part_b,
            0xF191: hw_b,
            0xF189: sw_b,
            0xF1A3: b"103",
            0xF197: b"FPK_E       ",
            0xF190: b"TESTVIN0123456789",
            0xF17C: b"XX0-00018.08.2300010000",
            0xF19E: odx_b,
            0x02ED: bytes([0x01, 0x00, 0x03, 0x4C, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00]),
            0x02EF: bytes([0, 0, 0, 0, 0, 0]),
            0x03DE: bytes([0x00, 0x00]),
            0x02E0: bytes.fromhex("2ae91569"),
        }

    def _push_uds_reply(self, payload: bytes) -> None:
        if len(payload) <= 7:
            self.rx.append(
                can.Message(
                    arbitration_id=FPKE_UDS_RX_ID,
                    data=(bytes([len(payload)]) + payload).ljust(8, b"\x55"),
                    is_extended_id=False,
                )
            )
            return
        ff = bytes([0x10 | ((len(payload) >> 8) & 0x0F), len(payload) & 0xFF]) + payload[:6]
        self.rx.append(can.Message(arbitration_id=FPKE_UDS_RX_ID, data=ff, is_extended_id=False))
        self._pending_cf_payload = payload[6:]

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        raw = bytes(msg.data)
        if msg.is_extended_id:
            if msg.arbitration_id == FPKE_ARM_ID:
                self.ec_Count += 1
                if self.ec_Count % 3 == 0:
                    self._stream_idx = 0
                    self.forged_ptr_seen = False
                    self.rx.append(
                        can.Message(
                            arbitration_id=FPKE_ARM_RESPONSE_ID,
                            data=bytes.fromhex("1402ffffffffffff"),
                            is_extended_id=True,
                        )
                    )
            elif msg.arbitration_id == FPKE_BLOCK_ID:
                exp_frame = int(self.prof["pointer_frame"])
                exp_ptr = int(self.prof["forged_ptr"]).to_bytes(4, "little")
                if self._stream_idx == exp_frame and raw[:4] == exp_ptr:
                    self.forged_ptr_seen = True
                self._stream_idx += 1
                self.ed_count += 1
            elif msg.arbitration_id == FPKE_CF_CH9_ID:
                if raw[0] == 0x21 and self.forged_ptr_seen and raw[1] == 8:
                    self.vendor_level = 8
            return

        if msg.arbitration_id != FPKE_UDS_TX_ID:
            self.sent_std.append((msg.arbitration_id, raw))
            return
        pci = raw[0] >> 4
        if pci == 3:
            # FlowControl from tester -> emit remaining ConsecutiveFrames
            rem = getattr(self, "_pending_cf_payload", b"")
            self._pending_cf_payload = b""
            for seq, off in enumerate(range(0, len(rem), 7), start=1):
                cf = bytes([0x20 | (seq & 0x0F)]) + rem[off : off + 7].ljust(7, b"\x55")
                self.rx.append(can.Message(arbitration_id=FPKE_UDS_RX_ID, data=cf, is_extended_id=False))
            return
        if pci == 0:
            self._handle_uds(raw[1 : 1 + (raw[0] & 0x0F)])
        elif pci == 1:
            self._isotp_len = ((raw[0] & 0x0F) << 8) | raw[1]
            self._isotp_buf = bytearray(raw[2:8])
            self.rx.append(
                can.Message(
                    arbitration_id=FPKE_UDS_RX_ID,
                    data=b"\x30\x00\x00\x55\x55\x55\x55\x55",
                    is_extended_id=False,
                )
            )
        elif pci == 2:
            self._isotp_buf.extend(raw[1:8])
            if len(self._isotp_buf) >= self._isotp_len:
                req = bytes(self._isotp_buf[: self._isotp_len])
                self._isotp_len = 0
                self._handle_uds(req)

    def _read_region_slice(self, addr: int, size: int) -> bytes:
        if addr == FPKE_CFLASH_ADDR and size == 16:
            return self.cflash_head
        if FPKE_DFLASH_ADDR <= addr < FPKE_DFLASH_ADDR + FPKE_DFLASH_SIZE:
            off = addr - FPKE_DFLASH_ADDR
            return self.dflash[off : off + size]
        if FPKE_EXTRA_ADDR <= addr < FPKE_EXTRA_ADDR + FPKE_EXTRA_SIZE:
            off = addr - FPKE_EXTRA_ADDR
            return self.extra[off : off + size]
        if addr == IDST_ADDR:
            return self.idst
        if addr == IDAUTH_ADDR + 0x0C:
            return b"\x00\x00\x00\x00"
        if addr in self.ram:
            buf = self.ram[addr]
            pad_b = {
                int(self.prof["applet_entry"]): b"\x11",
                int(self.prof["source_param"]): b"\x22",
                int(self.prof["result_addr"]): b"\x33",
                int(self.prof["marker_addr"]): b"\x44",
            }.get(addr, b"\x22")
            return buf[:size].ljust(size, pad_b)
        return b"\xaa" * size

    def _handle_uds(self, req: bytes) -> None:
        sid = req[0]
        if sid == 0x10:
            self._push_uds_reply(bytes([0x50, req[1], 0x00, 0x32, 0x01, 0xF4]))
        elif sid == 0x11:
            self.vendor_level = 0
            self._push_uds_reply(bytes([0x51, req[1]]))
        elif sid == 0x14:
            self.dtcs_cleared = True
            self._push_uds_reply(b"\x54")
        elif sid == 0x19:
            # Always include an untested 0x10 slot (as real clusters do after clear); include active/stored faults before clear
            body = (
                bytes.fromhex("a0004410")
                if self.dtcs_cleared
                else bytes.fromhex("a0004410a0004909903e1209ffff0408")
            )
            self._push_uds_reply(b"\x59\x02\x19" + body)
        elif sid == 0x2F:
            self._push_uds_reply(b"\x6f" + req[1:4])
        elif sid == 0x31:
            self._push_uds_reply(b"\x71" + req[1:4] + b"\x02\x01")
        elif sid == 0x3E:
            self._push_uds_reply(b"\x7e\x00")
        elif sid == 0x22:
            did = int.from_bytes(req[1:3], "big")
            if did in self.ident_map:
                self._push_uds_reply(b"\x62" + req[1:3] + self.ident_map[did])
            else:
                self._push_uds_reply(b"\x7f\x22\x31")
        elif sid == 0x27:
            if req[1] == 0x03:
                self._push_uds_reply(b"\x67\x03\x12\x34\x56\x78")
            elif req[1] == 0x04:
                self._push_uds_reply(b"\x67\x04")
        elif sid == 0x2E:
            did = int.from_bytes(req[1:3], "big")
            if did == 0xFD11:
                sub = req[3]
                if sub == 0x03:
                    c8 = bytes.fromhex("0102030405060708")
                    ident15 = bytes.fromhex("383341393230373030452036313831")
                    self._last_fd11_challenge = b"\x6e\xfd\x11" + c8 + ident15
                    self._push_uds_reply(self._last_fd11_challenge)
                elif sub == 0x04:
                    expected_proof = build_fd11_proof(
                        self._last_fd11_challenge,
                        bytes.fromhex("101112131415161718191a1b1c1d1e1f"),
                    )
                    if req[4:] == expected_proof:
                        self.vendor_level = 6
                        self._push_uds_reply(b"\x6e\xfd\x11")
                    else:
                        self._push_uds_reply(b"\x7f\x2e\x35")
                elif sub == 0x06:
                    self._push_uds_reply(b"\x6e\xfd\x11")
            else:
                self._push_uds_reply(b"\x6e" + req[1:3])
        elif sid == 0x23:
            if self.vendor_level < 6:
                self._push_uds_reply(b"\x7f\x23\x33")
                return
            addr = int.from_bytes(req[2:6], "big")
            size = int.from_bytes(req[6:10], "big")
            self._push_uds_reply(b"\x63" + self._read_region_slice(addr, size))
        elif sid == 0x3D:
            self.writes_0x3d += 1
            addr = int.from_bytes(req[2:6], "big")
            size = int.from_bytes(req[6:10], "big")
            data = req[10 : 10 + size]
            if addr == IDAUTH_ADDR:
                self.idst = b"\x00\x00\x00\x00" if data == self.extra[0x50:0x60] else b"\x01\x00\x00\x00"
            elif addr == int(self.prof["saved_return"]) and data == int(self.prof["applet_entry"]).to_bytes(4, "little"):
                app_entry = int(self.prof["applet_entry"])
                src_param = int(self.prof["source_param"])
                res_addr = int(self.prof["result_addr"])
                mark_addr = int(self.prof["marker_addr"])
                app_code = self.ram.get(app_entry, b"")
                param = self.ram.get(src_param, b"")
                bc_code = build_fpke_dflash_bc_applet(
                    applet_entry=app_entry,
                    caller_return=int(self.prof["caller_return"]),
                    caller_r29=int(self.prof["caller_r29"]),
                )
                wr_code = build_fpke_dflash_write_applet(
                    applet_entry=app_entry,
                    caller_return=int(self.prof["caller_return"]),
                )
                rst_code = build_fpke_swresa_reset_applet()
                if app_code.startswith(rst_code):
                    self.swresa_resets += 1
                    self.vendor_level = 0
                    info = analyze_fpke_dflash(self.dflash)
                    meta = info.get("metadata") or {}
                    if meta.get("vin"):
                        self.ident_map[0xF190] = str(meta["vin"]).encode("ascii")
                    if meta.get("coding_hex"):
                        self.ident_map[0x0600] = bytes.fromhex(str(meta["coding_hex"]))
                elif app_code.startswith(bc_code):
                    df_off, groups = struct.unpack_from("<II", param, 0)
                    if self.faci_busy_countdown > 0:
                        self.faci_busy_countdown -= 1
                        self.ram[res_addr] = (b"\x00" * 256) + b"BUSY"
                    else:
                        out_words: list[int] = []
                        for grp in range(groups):
                            bits = 0
                            base_off = df_off + grp * 128
                            for w_idx in range(32):
                                pos = base_off + w_idx * 4
                                if any(self.faci_mask[pos : pos + 4]):
                                    bits |= 1 << w_idx
                            out_words.append(bits)
                        packed = struct.pack(f"<{len(out_words)}I", *out_words).ljust(256, b"\x00")
                        self.ram[res_addr] = packed + b"SCAN"
                elif app_code.startswith(wr_code):
                    blk_off, do_erase, prog_mask_shifted = struct.unpack_from("<HHI", param, 0)
                    prog_mask = (prog_mask_shifted >> 16) & 0xFFFF
                    blk_data = param[8:72]
                    if self.faci_busy_countdown > 0:
                        self.faci_busy_countdown -= 1
                        res_hdr = struct.pack("<II", 6, 0x00008000).ljust(256, b"\x00")
                        self.ram[res_addr] = res_hdr + b"SCAN"
                    elif self.idst != b"\x00\x00\x00\x00":
                        res_hdr = struct.pack("<II", 4, 0x00009000).ljust(256, b"\x00")
                        self.ram[res_addr] = res_hdr + b"SCAN"
                    else:
                        df_mut = bytearray(self.dflash)
                        mask_mut = bytearray(self.faci_mask)
                        if do_erase:
                            self.faci_erases += 1
                            df_mut[blk_off : blk_off + 64] = b"\xff" * 64
                            mask_mut[blk_off : blk_off + 64] = b"\x00" * 64
                        status = 1
                        fstatr = 0x00008000
                        for w_idx in range(16):
                            if not ((prog_mask >> w_idx) & 1):
                                continue
                            pos = blk_off + w_idx * 4
                            if any(mask_mut[pos : pos + 4]):
                                status = 4
                                fstatr = 0x00009000
                                break
                            df_mut[pos : pos + 4] = blk_data[w_idx * 4 : w_idx * 4 + 4]
                            mask_mut[pos : pos + 4] = b"\xff\xff\xff\xff"
                            self.faci_words_written += 1
                        if status == 1:
                            self.dflash = bytes(df_mut)
                            self.faci_mask = mask_mut
                        res_hdr = struct.pack("<II", status, fstatr).ljust(256, b"\x00")
                        self.ram[res_addr] = res_hdr + b"SCAN"
                elif len(param) == 8:
                    # Streaming applet trigger (auto-increments source_addr at source_param)
                    exp_ret = int(self.prof["caller_return"]).to_bytes(4, "little")
                    if exp_ret not in app_code:
                        raise RuntimeError(f"Stream applet caller_return mismatch on {self.sw_profile}")
                    src_addr, frame_cnt = struct.unpack("<II", param)
                    if self.enable_stream_0x6f1:
                        blob = self._read_region_slice(src_addr, frame_cnt * 8)
                        for off in range(0, len(blob), 8):
                            self.rx.append(
                                can.Message(
                                    arbitration_id=FPKE_STREAM_RX_ID,
                                    data=blob[off : off + 8],
                                    is_extended_id=False,
                                )
                            )
                        self.ram[src_param] = struct.pack("<II", (src_addr + frame_cnt * 8) & 0xFFFFFFFF, frame_cnt)
                        self.ram[mark_addr] = b"SCAN" + self.ram[mark_addr][4:]
                else:
                    # 256-byte buffer applet trigger
                    exp_ret = int(self.prof["caller_return"]).to_bytes(4, "little")
                    if exp_ret not in app_code:
                        raise RuntimeError(f"Buffer applet caller_return mismatch on {self.sw_profile}")
                    src_addr = int.from_bytes(param[:4], "little")
                    chunk256 = self._read_region_slice(src_addr, 256)
                    self.ram[res_addr] = chunk256 + b"SCAN"
            else:
                self.ram[addr] = data
            self._push_uds_reply(b"\x7d" + req[1:10])

    def recv(self, timeout: float | None = None) -> can.Message | None:
        if self.rx:
            return self.rx.pop(0)
        return None

    def shutdown(self) -> None:
        pass


# ────────────────────────────── Tests: CAN Workflows & GUI Routing ──────────────────────────────


def test_can_identify_detects_fpke_and_rejects_non_native_interface() -> None:
    set_lang("en")
    res = can_identify("fake", interface="slcan", bus=FakeFpkeBus())
    assert res["responding"] is True
    assert res["ecu_kind"] == "fpke"
    assert res["uds_tx_id"] == "0x714"
    assert is_fpke_ident(res["ident"])
    assert "unsupported" not in res

    res_dpdu = can_identify("fake", interface="dpdu", bus=FakeFpkeBus())
    assert res_dpdu["ecu_kind"] == "fpke"
    assert "native CAN adapter" in res_dpdu["unsupported"]

    with pytest.raises(RuntimeError, match="native CAN adapter"):
        FpkeCanLink("fake", interface="dpdu")


def test_fpke_strict_dflash_read_uses_zero_0x3d_writes(tmp_path: Path) -> None:
    bus = FakeFpkeBus()
    out_file = tmp_path / "Dflash.bin"
    res = can_fpke_read_region(
        "fake",
        mode="dflash",
        frame_delay=0.0,
        wake_seconds=0.0,
        use_stream=False,
        output_path=out_file,
        bus=bus,
    )
    assert bus.writes_0x3d == 0
    assert res["read"]["protocol"] == "uds_0x23"
    assert res["read"]["requests"] == 132
    assert out_file.read_bytes() == bus.dflash
    assert res["secrets"]["metadata"]["part_number"] == "83A920700E"


def test_fpke_fast_stream_0x6f1_and_automatic_fallback_to_uds_0x23(tmp_path: Path) -> None:
    from contitool.can.fpke import FPKE_STREAM_CHUNK_BYTES, build_fpke_can_stream_applet

    assert FPKE_STREAM_CHUNK_BYTES == 1024
    for mode in ("direct", "bflash", "uflash"):
        app_blob = build_fpke_can_stream_applet(mode)
        # Must save PSW into caller-saved r18 (`stsr 5, r18, 0; di` = e5974000e0076001) and restore r29 + PSW from r18
        assert app_blob.startswith(bytes.fromhex("e5974000e0076001"))
        assert bytes.fromhex("3d06c831dffe3f060ecf09000052f22f20007f00") in app_blob
        assert bytes.fromhex("edff") not in app_blob

    # 1. Fast RSCAN0 TM17 stream succeeds with auto-incremented 0xFEDF1900 (only 1 param write + 64 triggers + 4 guard writes = 69 total 0x3D)
    bus_fast = FakeFpkeBus(enable_stream_0x6f1=True)
    res_fast = can_fpke_read_region(
        "fake",
        mode="dflash",
        frame_delay=0.0,
        wake_seconds=0.0,
        use_stream=True,
        output_path=tmp_path / " fast" / "Dflash.bin",
        bus=bus_fast,
    )
    assert res_fast["read"]["protocol"] == "rscan_stream_0x6F1"
    assert res_fast["read"]["chunk_size"] == 1024
    assert res_fast["read"]["requests"] == 64
    assert bus_fast.writes_0x3d == 69
    assert Path(res_fast["output"]).read_bytes() == bus_fast.dflash

    # 2. If 0x6F1 frames are dropped/blocked (even if session drops to Default Session), automatically re-establishes level 8 and falls back to UDS 0x23
    class DropAndResetStreamBus(FakeFpkeBus):
        def _handle_uds(self, req: bytes) -> None:
            if req[:6] == b"\x3d\x44\xfe\xdc\x3b\x78":
                self.vendor_level = 0
            super()._handle_uds(req)

    bus_fallback = DropAndResetStreamBus(enable_stream_0x6f1=False)
    res_fb = can_fpke_read_region(
        "fake",
        mode="dflash",
        frame_delay=0.0,
        wake_seconds=0.0,
        use_stream=True,
        output_path=tmp_path / "fb" / "Dflash.bin",
        bus=bus_fallback,
    )
    assert res_fb["read"]["protocol"] == "uds_0x23"
    assert Path(res_fb["output"]).read_bytes() == bus_fallback.dflash


def test_fpke_full_read_and_known_key_mode(tmp_path: Path) -> None:
    bus = FakeFpkeBus()
    rep = can_fpke_full_read(
        "fake",
        session_dir=tmp_path / "full",
        frame_delay=0.0,
        wake_seconds=0.0,
        use_stream=True,
        bus=bus,
    )
    assert rep["idauth"]["accepted"] is True
    assert rep["idauth"]["idst_after_idcode"] == "00000000"
    assert rep["idauth"]["idst_after_relock"] == "01000000"
    assert (tmp_path / "full" / "Dflash.bin").read_bytes() == bus.dflash
    assert (tmp_path / "full" / "ExtraArea.bin").read_bytes() == bus.extra

    bus_kk = FakeFpkeBus()
    rep_kk = can_fpke_read_region(
        "fake",
        mode="known-key",
        length=64,
        wake_seconds=0.0,
        fd11_key_hex="101112131415161718191a1b1c1d1e1f",
        output_path=tmp_path / "kk" / "Dflash_64.bin",
        bus=bus_kk,
    )
    assert rep_kk["target_keys_used"] is True
    assert Path(rep_kk["output"]).read_bytes() == bus_kk.dflash[:64]


def test_gui_opens_dedicated_kombi_screen_for_fpke_uds_and_dumps(monkeypatch, tmp_path: Path) -> None:
    from PySide6.QtCore import QEventLoop, QTimer

    from contitool.gui import main_window
    from contitool.gui.app import create_window

    set_lang("ru")
    app, win = create_window()
    win.conn.out_dir = tmp_path / "runs"
    kombi_ident = can_identify("fake", interface="slcan", bus=FakeFpkeBus())
    assert any(it["did"] == "F190" and it["value"] == "TESTVIN0123456789" for it in kombi_ident["ident"])

    monkeypatch.setattr(main_window, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(main_window, "can_identify", lambda *a, **k: kombi_ident)

    reads: list[str] = []

    def fake_fpke_full_read(_port: str, *, session_dir: Path, ident=None, **_kw):
        reads.append("fpke_read")
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "Dflash.bin").write_bytes(build_synthetic_fpke_dflash())
        (session_dir / "ExtraArea.bin").write_bytes(build_synthetic_extra_area())
        return {
            "session_dir": str(session_dir),
            "ident": ident or [],
            "idauth": {"idst_before": "01000000", "idst_after_idcode": "00000000", "idst_after_relock": "01000000"},
        }

    monkeypatch.setattr(main_window, "can_fpke_full_read", fake_fpke_full_read)

    def run_flow(confirm: int) -> None:
        def check_dlg(self) -> int:
            assert self.windowTitle() == "Блок на связи"
            assert self.btn_ok is not None and self.btn_ok.text() == "Считать блок"
            return confirm

        monkeypatch.setattr(main_window.EcuFoundDialog, "exec", check_dlg)
        loop = QEventLoop()
        win.runner.operation_finished.connect(loop.quit)
        win.read_over_can()
        QTimer.singleShot(5000, loop.quit)
        loop.exec()
        win.runner.operation_finished.disconnect(loop.quit)
        for _ in range(15):
            app.processEvents()
        if win.runner.is_busy:
            loop2 = QEventLoop()
            win.runner.operation_finished.connect(loop2.quit)
            QTimer.singleShot(5000, loop2.quit)
            loop2.exec()
            win.runner.operation_finished.disconnect(loop2.quit)
            for _ in range(15):
                app.processEvents()

    # 1. Cancel in EcuFoundDialog -> neither read nor screen switch happens
    run_flow(0)
    assert reads == []
    assert win.fpke_screen.is_open is False
    assert win.stack.currentWidget() is win.start_screen

    # 2. Confirm in EcuFoundDialog -> reads cluster first, and ONLY THEN opens FpkeScreen on secrets tab with VIN
    run_flow(1)
    assert reads == ["fpke_read"]
    assert win.fpke_screen.is_open is True
    assert win.ws.is_open is False
    assert win.stack.currentWidget() is win.fpke_screen
    assert win.fpke_screen._key == "secrets"
    assert win.fpke_screen.part_number == "83A920700E"
    assert win.fpke_screen.dflash_info["metadata"]["vin"] == "TESTVIN0123456789"
    assert win.tab_ecu.text() == "Блок 83A920700E"

    # Opening a folder of FPK_E dumps loads secrets, transponders, and Extra Area into FpkeScreen
    win.close_ecu()
    assert win.fpke_screen.is_open is False
    assert win.stack.currentWidget() is win.start_screen

    dump_dir = tmp_path / "fpke_dumps"
    dump_dir.mkdir()
    (dump_dir / "Dflash.bin").write_bytes(build_synthetic_fpke_dflash())
    (dump_dir / "ExtraArea.bin").write_bytes(build_synthetic_extra_area())
    assert set(detect_fpke_files([dump_dir])) == {"dflash", "extra"}

    win.open_folder(str(dump_dir))
    assert win.fpke_screen.is_open is True
    assert win.stack.currentWidget() is win.fpke_screen
    assert win.fpke_screen.dflash_info is not None
    assert win.fpke_screen.extra_info is not None

    win.show()
    win.resize(1180, 840)
    app.processEvents()

    # Load Recipient B dump too so the A -> B transfer page is tested in its populated state as well
    recipient_b_file = tmp_path / "recipient_b_dflash.bin"
    recipient_b_file.write_bytes(build_synthetic_fpke_dflash())
    win.fpke_screen.set_recipient_dflash(recipient_b_file)

    # Render every navigation page in RU and EN and verify zero horizontal overflow + all pages fit in one screen at 1180x840
    for lang in ("ru", "en"):
        set_lang(lang)
        for w_sz, h_sz in ((940, 640), (1180, 840)):
            win.resize(w_sz, h_sz)
            win._set_console_visible(True)
            app.processEvents()
            for nav_key in ("read", "can_ctrl", "secrets", "cp", "keys", "transfer", "extra"):
                win.fpke_screen.select(nav_key)
                app.processEvents()
                assert win.fpke_screen._key == nav_key
                vp = win.fpke_screen.page_area.viewport()
                pg = win.fpke_screen.page_area.widget()
                assert pg.minimumSizeHint().width() <= vp.width()
                assert pg.width() <= vp.width()
                if w_sz == 1180:
                    assert win.fpke_screen.page_area.verticalScrollBar().maximum() == 0

    # Standalone CAN control dialog fits cleanly without horizontal clipping or vertical scroll
    from contitool.gui.screens.fpke import FpkeCanDialog

    for lang in ("ru", "en"):
        set_lang(lang)
        dlg = FpkeCanDialog(win.conn, win.runner, part_number="83A920700E", parent=win)
        dlg.show()
        app.processEvents()
        dvp = dlg._scroll.viewport()
        dpg = dlg._scroll.widget()
        assert dpg.minimumSizeHint().width() <= dvp.width()
        assert dlg._scroll.verticalScrollBar().maximum() == 0
        dlg.close()

    # Switching to CAN terminal while Kombi is open pre-selects 714 / 77E
    win.set_mode("terminal")
    app.processEvents()
    assert win.terminal.ed_tx.text() == "714"
    assert win.terminal.ed_rx.text() == "77E"
    win.close()


def test_fpke_persistent_session_reuses_level8_and_reunlocks_after_reset(tmp_path: Path) -> None:
    from contitool.can.fpke import (
        build_fpke_drive_frame,
        close_active_fpke_link,
        fpke_e2e_crc,
        fpke_run_procedure,
        get_active_fpke_link,
    )

    close_active_fpke_link()
    bus = FakeFpkeBus()
    try:
        # 1. Initial read with keep_open=True establishes level 8 once and keeps link alive
        r1 = can_fpke_full_read(
            "fake",
            session_dir=tmp_path / "s1",
            frame_delay=0.0,
            wake_seconds=0.0,
            keep_open=True,
            bus=bus,
        )
        assert bus.ed_count == 1020
        assert not r1["exploit"].get("reused_session")
        link = get_active_fpke_link("fake", "slcan")
        assert link is not None and not link.is_closed
        assert link.is_keepalive_running() is True
        assert link.level8_active is True

        # 2. Subsequent read in the same open session verifies level 8 and skips the 1022-frame exploit
        r2 = can_fpke_read_region(
            "fake",
            mode="dflash",
            frame_delay=0.0,
            wake_seconds=0.0,
            keep_open=True,
            output_path=tmp_path / "s2" / "Dflash.bin",
            bus=bus,
        )
        assert r2["access"]["reused_session"] is True
        assert bus.ed_count == 1020  # zero extra exploit frames sent

        # 3. KL15 toggle, MFL button press, drive frame E2E CRC, and UDS procedures on the open link
        link.set_kl15(False)
        assert link.is_keepalive_running() is False
        assert any(cid == 0x3C0 and data == b"\x00\x00\x00\x00" for cid, data in bus.sent_std)

        link.set_kl15(True)
        assert link.is_keepalive_running() is True
        link.send_mfl_button(0x07, 0x01, hold_s=0.0)
        assert any(cid == 0x5BF and data == b"\x07\x00\x01\x00" for cid, data in bus.sent_std)
        assert any(cid == 0x5BF and data == b"\x00\x00\x00\x00" for cid, data in bus.sent_std)

        f31b = build_fpke_drive_frame(0x31B, 5, speed_kmh=100.0, rpm=2500.0, distance_m=42.0)
        assert len(f31b) == 8 and f31b[0] == fpke_e2e_crc(0x31B, f31b) and (f31b[1] & 0x0F) == 5

        immo_res = fpke_run_procedure(link, "immo_status")
        assert immo_res["learned_keys"] == 2 and immo_res["challenge_r"] == "2AE91569"

        set_lang("ru")
        dtc_res = fpke_run_procedure(link, "read_dtc")
        assert dtc_res["untested_count"] == 1
        assert dtc_res["active_count"] == 2 and dtc_res["stored_count"] == 1
        assert [d["display"] for d in dtc_res["dtcs"]] == ["B200049", "B103E1B", "U112100"]
        assert "Датчик уровня топлива 1" in dtc_res["summary"]
        fpke_run_procedure(link, "clear_dtc")
        dtc_after = fpke_run_procedure(link, "read_dtc")
        assert dtc_after["dtcs"] == [] and dtc_after["untested_count"] == 1

        # 4. ECU reset drops level 8 -> subsequent read detects level 8 is gone and re-unlocks automatically
        fpke_run_procedure(link, "ecu_reset")
        assert bus.vendor_level == 0 and link.level8_active is False

        r3 = can_fpke_read_region(
            "fake",
            mode="dflash",
            frame_delay=0.0,
            wake_seconds=0.0,
            keep_open=True,
            output_path=tmp_path / "s3" / "Dflash.bin",
            bus=bus,
        )
        assert not r3["access"].get("reused_session")
        assert bus.ed_count == 2040  # re-ran the 1022-frame unlock automatically
        assert link.level8_active is True
    finally:
        close_active_fpke_link()
        assert get_active_fpke_link() is None


def test_fpke_can_panel_async_lifecycle_and_human_dtc_dialog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import time
    from PySide6.QtWidgets import QApplication
    from contitool.can.fpke import FpkeCanLink, close_active_fpke_link, set_active_fpke_link
    from contitool.gui.main_window import MainWindow
    from contitool.gui.screens.fpke import FpkeCanDialog, FpkeDtcDialog
    from contitool.gui.theme import apply_theme

    app = QApplication.instance() or QApplication([])
    apply_theme(app)  # type: ignore[arg-type]

    uncaught: list[BaseException] = []
    monkeypatch.setattr(sys, "excepthook", lambda _et, ev, _tb: uncaught.append(ev))

    close_active_fpke_link()
    bus = FakeFpkeBus()
    link = FpkeCanLink("fake-port", interface="slcan", bus=bus)
    link.level8_active = True
    link.start_keepalive()
    set_active_fpke_link(link)

    try:
        set_lang("ru")
        win = MainWindow()
        failures: list[Any] = []
        monkeypatch.setattr(win, "offer_problem_report", lambda f: failures.append(f))
        win.conn.port = "fake-port"
        win.conn.interface = "slcan"
        dump_dir = tmp_path / "kombi_live"
        dump_dir.mkdir()
        (dump_dir / "Dflash.bin").write_bytes(build_synthetic_fpke_dflash())
        (dump_dir / "ExtraArea.bin").write_bytes(build_synthetic_extra_area())
        win.open_folder(str(dump_dir))
        win.show()
        win.resize(1180, 840)
        win.fpke_screen.select("can_ctrl")
        app.processEvents()

        def wait_idle() -> None:
            deadline = time.monotonic() + 5.0
            while win.runner.is_busy and time.monotonic() < deadline:
                app.processEvents()
                time.sleep(0.005)
            for _ in range(12):
                app.processEvents()
                time.sleep(0.003)

        panel = win.fpke_screen._active_can_panel
        assert panel is not None

        # 1. Live threaded click on "Считать" (read_dtc) must keep panel alive, decode human descriptions, and show "Список…"
        panel._proc_buttons[0].click()
        wait_idle()
        assert not uncaught
        assert win.fpke_screen._active_can_panel is panel
        assert "Датчик уровня топлива 1" in panel.lbl_status.text()
        assert panel.btn_dtc_details.isVisible() is True

        # 2. Verify FpkeDtcDialog renders human-readable text and clears codes cleanly
        dtc_dlg = FpkeDtcDialog(
            panel._last_dtcs,
            part_number="83A920700E",
            clear_callback=panel._clear_dtcs_sync,
            parent=win,
        )
        dtc_dlg.show()
        app.processEvents()
        txt = dtc_dlg.format_plain_text()
        assert "B103E1B" in txt and "Датчик уровня топлива 1" in txt
        assert "U112100" in txt and "BCM_01" in txt
        dtc_dlg._on_clear()
        wait_idle()
        assert bus.dtcs_cleared is True
        assert panel.btn_dtc_details.isVisible() is False

        # 3. Switch away from can_ctrl mid-flight while async procedure runs -> zero deleted-QLabel errors
        bus.dtcs_cleared = False
        panel._proc_buttons[0].click()
        win.fpke_screen.select("secrets")
        app.processEvents()
        wait_idle()
        assert not uncaught

        # Returning to can_ctrl preserves status & DTC list button
        win.fpke_screen.select("can_ctrl")
        app.processEvents()
        assert win.fpke_screen._active_can_panel is not None
        assert win.fpke_screen._active_can_panel.btn_dtc_details.isVisible() is True

        # 4. Closing FpkeCanDialog mid-flight while async procedure runs -> zero deleted-QLabel errors
        dlg = FpkeCanDialog(win.conn, win.runner, part_number="83A920700E", parent=win)
        dlg.show()
        app.processEvents()
        dlg.panel._proc_buttons[2].click()  # immo_status
        dlg.close()
        dlg.deleteLater()
        wait_idle()
        assert not uncaught
        win.close()
    finally:
        close_active_fpke_link()


def test_fpke_cli_immo_export_compare_and_transfer_plan(tmp_path: Path) -> None:
    import json
    from contitool.cli.main import main

    df_a = tmp_path / "unit_a.bin"
    df_b = tmp_path / "unit_b.bin"
    passport_out = tmp_path / "unit_a_immo_passport.json"
    plan_out = tmp_path / "a_to_b_transfer_plan.json"
    df_a.write_bytes(build_synthetic_fpke_dflash())

    raw_b = bytearray(build_synthetic_fpke_dflash())
    r68_b = bytearray(b"\xff" * EEL_83A_IDS[0x68])
    r68_b[:2] = struct.pack("<H", len(r68_b))
    r68_b[0x17:0x28] = b"OTHERCLUSTER00001"
    r68_b[0x28:0x38] = b"\x77" * 16
    r68_b[0x40] = 0xB0
    r68_b[0x4B] = 1
    _put_eel_record(raw_b, 4, 0, 0x7E0, 0x68, bytes(r68_b), active=True)
    df_b.write_bytes(bytes(raw_b))

    assert main(["--no-color", "fpke", "export-immo", "--dflash", str(df_a), "-o", str(passport_out)]) == 0
    saved_passport = json.loads(passport_out.read_text(encoding="utf-8"))
    assert saved_passport["schema"] == "contitool.fpke.immo_passport.v1"
    assert saved_passport["immo"]["power_class"] == "4C"

    # Compare dump A against its own exported passport -> exit code 0 (semantic match)
    assert main(["--no-color", "fpke", "compare-immo", "--dflash", str(df_a), "--dflash-b", str(passport_out)]) == 0
    # Compare dump A against different cluster B -> exit code 2 (mismatch)
    assert main(["--no-color", "fpke", "compare-immo", "--dflash", str(df_a), "--dflash-b", str(df_b)]) == 2

    # Build A -> B transfer plan -> exit code 0 and writes JSON container
    assert (
        main(["--no-color", "fpke", "plan-transfer", "--donor-dflash", str(df_a), "--recipient-dflash", str(df_b), "-o", str(plan_out)])
        == 0
    )
    saved_plan = json.loads(plan_out.read_text(encoding="utf-8"))
    assert saved_plan["schema"] == "contitool.fpke.transfer_plan.v1"
    assert saved_plan["transfer_from_a"]["power_class"] == "4C"
    assert saved_plan["preserve_on_b"]["current_kc_on_b"] == "77" * 16


def test_fpke_eel_append_field_editing_and_donor_transfer_workflow(tmp_path: Path) -> None:
    from contitool.fpke import (
        apply_fpke_dflash_edits,
        compare_fpke_immo_passports,
        eel_append_records,
        eel_read_record_any,
        extract_fpke_immo_passport,
        transfer_fpke_donor_to_target,
    )
    from contitool.gui.app import create_window

    base_df = build_synthetic_fpke_dflash()
    lay = fpke_eel_layout()

    # 1. Unchanged record is a no-op; manual field editing appends only modified EEL records
    r68_orig, _ = eel_read_record_any(lay, base_df, 0x68)
    assert eel_append_records(base_df, {0x68: r68_orig}) == base_df

    edited_df = apply_fpke_dflash_edits(
        base_df,
        vin="MANUALVIN00000001",
        cs_hex="0102030405060708090a0b0c0d0e0f10",
        crc_a_hex="AABBCCDD",
        crc_b_hex="EEFF0011",
        power_class="E6",
        immo_mode=1,
        key_over_can=False,
        partners_mask=0x03,
        clear_lockouts=True,
        mac_dash_hex="B8FE",
        partner_macs={"MSG_1": "C471", "GSG": "A70C", "ELV": ""},
        key_display_ids=["11223344", "55667788", "99AABBCC"] + [None] * 5,
        learned_keys=3,
        allowed_keys=8,
        session_xor_flags=2,
        ika_key_hex="A0A1A2A3A4A5A6A7A8A9AAABACADAEAF",
        gfa_key_hex="B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
        reset_cp_counter=True,
        odometer_km=128_400,
        coding_hex="05A50A186B8400080188720B1001000000000000",
    )
    p_ed = extract_fpke_immo_passport(edited_df)
    assert p_ed["immo"]["vin"] == "MANUALVIN00000001"
    assert p_ed["immo"]["cs"] == "0102030405060708090A0B0C0D0E0F10"
    assert p_ed["immo"]["crc32_a_le"] == "AABBCCDD"
    assert p_ed["immo"]["crc32_b_le"] == "EEFF0011"
    assert p_ed["immo"]["power_class"] == "E6"
    assert p_ed["immo"]["mac4"] == "B8FEC471"
    assert p_ed["immo"]["mac_fields"] == {"dash": "B8FE", "ecu": "C471", "elv": None, "tcu": "A70C"}
    assert p_ed["immo"]["mode_and_flags"]["key_over_can"] is False
    assert p_ed["immo"]["mode_and_flags"]["adapted_partner_codes"] == ["MSG_1", "GSG"]
    assert p_ed["immo"]["keys"][:3] == ["11223344", "55667788", "99AABBCC"]
    assert p_ed["immo"]["counts"]["learned_keys"] == 3
    assert p_ed["component_protection_separate"]["ika_cp3"] == "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
    assert p_ed["component_protection_separate"]["cp1_gfa"] == "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
    assert p_ed["component_protection_separate"]["active"] is False
    assert p_ed["component_protection_separate"]["adapted"] is True
    assert p_ed["cluster_metadata"]["odometer_km"] == 128_400
    assert p_ed["cluster_metadata"]["coding_hex"] == "05A50A186B8400080188720B1001000000000000"
    assert p_ed["cluster_metadata"]["part_number"] == "83A920700E"

    # 2. Donor -> Target transfer preserves Target's part number & coding while transferring Immo, Keys, and Odometer
    target_df = apply_fpke_dflash_edits(
        base_df,
        vin="TARGETVIN00000002",
        power_class="4C",
        odometer_km=12_000,
        coding_hex="111122223333444455556666777788889999AAAA",
    )
    transferred_df, xfer_summary = transfer_fpke_donor_to_target(
        edited_df,
        target_df,
        copy_immo=True,
        copy_keys=True,
        copy_odometer=True,
        copy_cp=False,
    )
    assert xfer_summary["vin"] == "MANUALVIN00000001"
    assert xfer_summary["power_class_hex"] == "0xE6"
    assert xfer_summary["learned_keys"] == 3
    assert xfer_summary["odometer_km"] == 128_400
    cmp_after = compare_fpke_immo_passports(edited_df, transferred_df)
    assert cmp_after["semantic_match"] is True
    p_target_after = extract_fpke_immo_passport(transferred_df)
    assert p_target_after["cluster_metadata"]["coding_hex"] == "111122223333444455556666777788889999AAAA"

    # 3. GUI non-destructive working copy (ContiTool_edited/Dflash.bin) + Revert to original
    set_lang("ru")
    app, win = create_window()
    unit_dir = tmp_path / "target_unit"
    unit_dir.mkdir()
    orig_file = unit_dir / "Dflash.bin"
    orig_file.write_bytes(target_df)
    (unit_dir / "ExtraArea.bin").write_bytes(build_synthetic_extra_area())
    donor_file = tmp_path / "donor_unit.bin"
    donor_file.write_bytes(edited_df)

    win.open_folder(str(unit_dir))
    assert win.fpke_screen.is_dflash_modified is False
    assert win.fpke_screen.write_bar.isHidden() is True

    win.fpke_screen.set_donor_source(donor_file)
    win.fpke_screen.apply_donor_transfer_to_current()
    app.processEvents()

    assert win.fpke_screen.is_dflash_modified is True
    assert win.fpke_screen.write_bar.isHidden() is False
    assert (unit_dir / "ContiTool_edited" / "Dflash.bin").is_file()
    assert orig_file.read_bytes() == target_df  # original file untouched!
    assert win.fpke_screen.dflash_info["metadata"]["vin"] == "MANUALVIN00000001"

    win.fpke_screen.revert_dflash_edits()
    app.processEvents()
    assert win.fpke_screen.is_dflash_modified is False
    assert win.fpke_screen.write_bar.isHidden() is True
    assert win.fpke_screen.dflash_info["metadata"]["vin"] == "TARGETVIN00000002"
    win.close()


def test_fpke_extra_area_retries_on_transient_eel_dflash_aliasing(tmp_path: Path) -> None:
    class TransientEelContentionBus(FakeFpkeBus):
        """Simulates RV40F hardware aliasing 0xFF300000 -> DataFlash VB 0 while R_EEL_Handler is in FENTRYD mode."""

        def __init__(self) -> None:
            super().__init__()
            self.extra_reads = 0

        def _read_region_slice(self, addr: int, size: int) -> bytes:
            if FPKE_EXTRA_ADDR <= addr < FPKE_EXTRA_ADDR + FPKE_EXTRA_SIZE:
                self.extra_reads += 1
                # Reproduce hardware trace 01-09-22: 1st read OK, 2nd & 3rd reads hit EEL FENTRYD (VB 0), 4th read OK
                if self.extra_reads in (2, 3):
                    return self.dflash[:size]
            return super()._read_region_slice(addr, size)

    bus = TransientEelContentionBus()
    rep = can_fpke_full_read(
        "fake",
        session_dir=tmp_path / "eel_retry",
        frame_delay=0.0,
        wake_seconds=0.0,
        use_stream=True,
        bus=bus,
    )
    assert bus.extra_reads == 4
    assert rep["extra"]["eel_contention_retries"] == 2
    assert rep["idauth"]["accepted"] is True
    assert rep["idauth"]["idst_after_relock"] == "01000000"
    assert (tmp_path / "eel_retry" / "ExtraArea.bin").read_bytes() == bus.extra


def test_fpke_coil_key_learning_end_to_end_and_dialog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import zlib
    from PySide6.QtWidgets import QApplication
    from contitool.can.fpke import (
        FPKE_83A_RAM_EEL67_ADDR,
        FPKE_83A_RAM_EEL68_ADDR,
        FPKE_83A_RAM_EEL69_ADDR,
        FPKE_83A_RAM_LAST_KEY_ID_ADDR,
        FPKE_83A_RAM_RECOG_STATE_ADDR,
        FPKE_83A_RAM_S0_ADDR,
        FPKE_83A_RAM_SLOTS_FLAG_ADDR,
        FpkeCanLink,
        close_active_fpke_link,
        fpke_coil_poll_transponder,
        fpke_extract_live_s0_s1_from_coil,
        fpke_finish_coil_key_learning,
        fpke_learn_next_key_on_coil,
        fpke_prepare_additive_coil_learning,
        fpke_start_coil_key_learning,
        set_active_fpke_link,
    )
    from contitool.core.fpke import (
        apply_fpke_dflash_edits,
        build_fpke_02e1_request,
        build_fpke_02f7_payload,
        encode_fpke_02f7_config,
        fpke_compute_02e1_mac,
        fpke_crc16_ccitt,
        fpke_s0_s1_from_slots,
        fpke_slots_from_s0_s1,
        fpke_verify_s0_s1,
    )
    from contitool.gui.main_window import MainWindow
    from contitool.gui.screens.fpke import FpkeCoilKeyLearnDialog
    from contitool.gui.theme import apply_theme

    # 1. Verify firmware CRC-16/CCITT and 02E1 MAC against ac-immo-diag.md §12 vector
    assert fpke_crc16_ccitt(b"123456789") == 0x29B1
    assert fpke_compute_02e1_mac(b"LAB IMMO KC KEY!", bytes.fromhex("2ae91569"), 0x10, 0x01).hex() == "14db"
    assert build_fpke_02e1_request(0x40, 0x00) == bytes.fromhex("2e02e100004000")
    assert build_fpke_02e1_request(0x80, 0x00) == bytes.fromhex("2e02e100008000")

    # 2. Verify Slot A/B <-> S0/S1 permutation and 02F7 config byte encoding (0x13A99C inverse)
    slot_a = b"LAB IMMO SLOT A!"
    slot_b = b"LAB IMMO SLOT B!"
    s0, s1 = fpke_s0_s1_from_slots(slot_a, slot_b)
    assert fpke_slots_from_s0_s1(s0, s1) == (slot_a, slot_b)
    crc_a_le = struct.pack("<I", zlib.crc32(slot_a))
    crc_b_le = struct.pack("<I", zlib.crc32(slot_b))
    ver = fpke_verify_s0_s1(s0, s1, crc_a_le, crc_b_le)
    assert ver["valid"] is True
    assert ver["crc_a_le_hex"] == "E80B6C4F"
    assert ver["crc_b_le_hex"] == "2B584164"

    b42, b43 = encode_fpke_02f7_config(3, partner_mask=0x05, key_flags=0x80, force_local_coil=True)
    assert (b42 & 0x0F) == 3
    assert (b43 & 0x01) == 0x00  # local LF coil forced (bit 0 = 0)
    assert (b43 & 0x30) == 0x30  # partner 0 (ECU, 0x10) + partner 2 (TCU, 0x20)

    # 3. Simulated cluster bus with working Key 1 in coil -> extract S0/S1 -> 2E 02F7 -> 3x 2E 02E1 40 00 -> 2E 02E1 80 00
    class CoilLearnBus(FakeFpkeBus):
        def __init__(self) -> None:
            super().__init__()
            self.ram[FPKE_83A_RAM_S0_ADDR] = s0 + s1
            self.ram[FPKE_83A_RAM_SLOTS_FLAG_ADDR] = b"\x03"
            self.ram[FPKE_83A_RAM_RECOG_STATE_ADDR] = b"\x04"
            self.ram[FPKE_83A_RAM_LAST_KEY_ID_ADDR] = bytes.fromhex("a1b2c3d4")
            self.coil_queue = ["D4C3B2A1", "1807F6E5", "5A4B3C2D"]
            self.learned_ids: list[str] = ["D4C3B2A1", "1807F6E5"]
            self.allowed_cnt = 2
            self.mode_fam = 2
            self.last_02f7: bytes = b""
            self._sync_ident_map()

        def _sync_ident_map(self) -> None:
            cur_coil = self.coil_queue[0] if self.coil_queue else "5A4B3C2D"
            self.ident_map[0x02E4] = bytes.fromhex(cur_coil)
            rem = max(0, self.allowed_cnt - len(self.learned_ids))
            self.ident_map[0x02ED] = bytes([self.mode_fam, 0x01, 0x03, 0x4C, len(self.learned_ids), 0x00, rem, 0x00, 0x00, 0x00])
            for idx in range(8):
                did = 0x02E5 + idx
                if idx < len(self.learned_ids):
                    self.ident_map[did] = bytes.fromhex(self.learned_ids[idx])
                else:
                    self.ident_map.pop(did, None)
            self.ident_map[0x02FA] = b"\x01\x33\xea\x91\xd3"

        def _handle_uds(self, req: bytes) -> None:
            if req[:3] == b"\x2e\x02\xf7":
                assert len(req) == 87
                self.last_02f7 = req
                self.mode_fam = 3
                self.learned_ids = []
                self.allowed_cnt = 3
                self._sync_ident_map()
                self._push_uds_reply(b"\x6e\x02\xf7")
                return
            if req[:3] == b"\x2e\x02\xe1":
                cmd, param = req[5], req[6]
                if cmd == 0x40:
                    nxt = self.coil_queue.pop(0) if self.coil_queue else "5A4B3C2D"
                    self.learned_ids.append(nxt)
                    self.mode_fam = 3
                    self._sync_ident_map()
                    self._push_uds_reply(b"\x6e\x02\xe1")
                    return
                if cmd == 0x80 and param in (0x00, 0x01):
                    self.mode_fam = 2
                    self.allowed_cnt = len(self.learned_ids)
                    self._sync_ident_map()
                    self._push_uds_reply(b"\x6e\x02\xe1")
                    return
            super()._handle_uds(req)

    close_active_fpke_link()
    bus = CoilLearnBus()
    link = FpkeCanLink("fake-port", interface="slcan", bus=bus)
    link.level8_active = True
    set_active_fpke_link(link)
    try:
        ext = fpke_extract_live_s0_s1_from_coil(
            link,
            expected_crc_a_le=crc_a_le,
            expected_crc_b_le=crc_b_le,
            wake_seconds=0.0,
        )
        assert ext["ok"] is True
        assert ext["s0_hex"] == s0.hex().upper()
        assert ext["s1_hex"] == s1.hex().upper()
        assert ext["coil_key_id"] == "D4C3B2A1"

        # Wrong expected CRC must block 2E 02F7
        with pytest.raises(RuntimeError, match="CRC-32"):
            fpke_start_coil_key_learning(
                link,
                vin="TESTVIN0123456789",
                s0_hex=ext["s0_hex"],
                s1_hex=ext["s1_hex"],
                kc_hex="505152535455565758595A5B5C5D5E5F",
                power_class=0x4C,
                allowed_keys=3,
                expected_crc_a_le="DEADBEEF",
                expected_crc_b_le=crc_b_le,
            )

        st_open = fpke_start_coil_key_learning(
            link,
            vin="TESTVIN0123456789",
            s0_hex=ext["s0_hex"],
            s1_hex=ext["s1_hex"],
            kc_hex="505152535455565758595A5B5C5D5E5F",
            power_class=0x4C,
            allowed_keys=3,
            expected_crc_a_le=crc_a_le,
            expected_crc_b_le=crc_b_le,
        )
        assert st_open["ok"] is True and st_open["poll"]["learned_keys"] == 0 and st_open["poll"]["remaining_keys"] == 3

        k1 = fpke_learn_next_key_on_coil(link)
        k2 = fpke_learn_next_key_on_coil(link)
        k3 = fpke_learn_next_key_on_coil(link)
        assert k1["learned_keys"] == 1 and k2["learned_keys"] == 2 and k3["learned_keys"] == 3
        assert k3["learned_key_ids"] == ["D4C3B2A1", "1807F6E5", "5A4B3C2D"]

        fin = fpke_finish_coil_key_learning(link, sync_channel3=False)
        assert fin["ok"] is True
        assert fin["learned_keys"] == 3 and fin["remaining_keys"] == 0
        assert fin["learned_key_ids"] == ["D4C3B2A1", "1807F6E5", "5A4B3C2D"]

        # 3b. Method A (additive RAM mode 4 without 2E 02F7): preserves existing 2 keys and adds only Key 3
        bus.learned_ids = ["D4C3B2A1", "1807F6E5"]
        bus.allowed_cnt = 2
        bus.mode_fam = 2
        bus.coil_queue = ["5A4B3C2D"]
        bus._sync_ident_map()

        prep_a = fpke_prepare_additive_coil_learning(
            link,
            s0_hex=ext["s0_hex"],
            s1_hex=ext["s1_hex"],
            kc_hex="505152535455565758595A5B5C5D5E5F",
            allowed_keys=3,
            expected_crc_a_le=crc_a_le,
            expected_crc_b_le=crc_b_le,
            wake_seconds=0.0,
        )
        assert prep_a["ok"] is True
        assert prep_a["preserved_keys"] == 2
        assert prep_a["allowed_keys"] == 3
        assert bus.ram[FPKE_83A_RAM_EEL69_ADDR] == s0 + s1
        assert bus.ram[FPKE_83A_RAM_EEL67_ADDR][:8] == bytes.fromhex("a1b2c3d4e5f60718")
        assert bus.ram[FPKE_83A_RAM_EEL67_ADDR][0x20] == 3
        assert (bus.ram[FPKE_83A_RAM_EEL67_ADDR][0x21] & 0x0F) == 2
        assert (bus.ram[FPKE_83A_RAM_EEL68_ADDR + 0x42][0] & 0x01) == 0x01
        assert bus.ram[FPKE_83A_RAM_EEL68_ADDR + 0x42][7] == 0x05  # mode 5 (stays in 5 when learned < allowed)

        k3_only = fpke_learn_next_key_on_coil(link)
        assert k3_only["learned_keys"] == 3
        assert k3_only["learned_key_ids"] == ["D4C3B2A1", "1807F6E5", "5A4B3C2D"]
        fin_a = fpke_finish_coil_key_learning(link, sync_channel3=False)
        assert fin_a["learned_keys"] == 3 and fin_a["remaining_keys"] == 0

        # 4. Exercise FpkeCoilKeyLearnDialog UI & synchronization back into FpkeScreen working dump
        app = QApplication.instance() or QApplication([])
        apply_theme(app)  # type: ignore[arg-type]

        df_unit = apply_fpke_dflash_edits(
            build_synthetic_fpke_dflash(),
            slot_s0_hex=s0.hex(),
            slot_s1_hex=s1.hex(),
            crc_a_hex=crc_a_le.hex(),
            crc_b_hex=crc_b_le.hex(),
        )
        # Clear S0/S1 in EEL 0x69 while keeping the valid CRC-32(A/B) in EEL 0x68
        df_mode1 = apply_fpke_dflash_edits(df_unit, slot_s0_hex="FF" * 16, slot_s1_hex="FF" * 16)
        unit_dir = tmp_path / "coil_gui_unit"
        unit_dir.mkdir(parents=True, exist_ok=True)
        (unit_dir / "Dflash.bin").write_bytes(df_mode1)
        (unit_dir / "ExtraArea.bin").write_bytes(build_synthetic_extra_area())

        win = MainWindow()
        win.open_folder(str(unit_dir))
        win.fpke_screen.select("keys")
        app.processEvents()

        synced_calls: list[tuple[list[str], int, int]] = []
        dlg = FpkeCoilKeyLearnDialog(
            win.conn,
            win.runner,
            dflash_info=win.fpke_screen.dflash_info,
            part_number="83A920700E",
            on_learned_keys_synced=lambda ids, lrn, alw: synced_calls.append((ids, lrn, alw)),
            parent=win,
        )
        assert dlg.btn_prepare_additive.isEnabled() is False
        assert dlg.btn_start_02f7.isEnabled() is False
        dlg.ed_s0.setText(s0.hex().upper())
        dlg.ed_s1.setText(s1.hex().upper())
        app.processEvents()
        assert dlg.btn_prepare_additive.isEnabled() is True
        assert dlg.btn_start_02f7.isEnabled() is True
        dlg.close()
        win.close()
    finally:
        close_active_fpke_link()


def test_fpke_eel_append_block_rollover_rwp_separator_and_ring_wrap() -> None:
    from contitool.core.fpke import (
        EEL_MARK,
        eel_append_records,
        eel_cs24,
        eel_parse_pool,
        eel_read_record_any,
        fpke_eel_layout,
    )

    df = build_synthetic_fpke_dflash()
    lay = fpke_eel_layout(None, df)
    init_blocks, _ = eel_parse_pool(lay, df)
    init_head = max((b for b in init_blocks if b["state"] == "active"), key=lambda b: (b["ec"] or 0, b["vb"]))["vb"]
    next_vb = (init_head + 1) % lay["n_vb"]

    # Append enough large ID=1 (252 B) records to overflow init_head into next_vb
    cur = df
    for seq in range(10):
        payload = struct.pack("<H", 252) + bytes([seq]) * 250
        cur = eel_append_records(cur, {1: payload})

    blocks, _ = eel_parse_pool(lay, cur)
    assert blocks[init_head]["state"] == "active"
    assert blocks[next_vb]["state"] == "active"
    assert blocks[next_vb]["ec"] == blocks[init_head]["ec"]  # EC does NOT increment at next_vb != 0

    # init_head must retain a clean 4-byte separator word (0xFFFFFFFF) at its separator offset,
    # and next_vb's RWP (+0x14) must store the full DataFlash pool byte offset of init_head's separator.
    head_sep = init_head * lay["vb"] + blocks[init_head]["separator"]
    assert cur[head_sep : head_sep + 4] == b"\xff\xff\xff\xff"
    assert blocks[next_vb]["rwp_ok"] is True
    assert blocks[next_vb]["rwp"] == head_sep

    # Test ring wrap-around VB 27 -> VB 0 (EC increments by +1 at VB 0)
    ring_df = bytearray(b"\xff" * 0x10000)
    for n in range(28):
        b = n * 0x800
        ec_val = 11 if n < 3 else 10
        struct.pack_into("<I", ring_df, b + 0x04, EEL_MARK)  # P
        struct.pack_into("<I", ring_df, b + 0x10, eel_cs24(ec_val))
    # Activate VB 27 at EC=10
    b27 = 27 * 0x800
    struct.pack_into("<I", ring_df, b27 + 0x08, EEL_MARK)
    struct.pack_into("<I", ring_df, b27 + 0x14, eel_cs24(26 * 0x800 + 0x18))
    struct.pack_into("<I", ring_df, b27 + 0x0C, EEL_MARK)

    wrapped = bytes(ring_df)
    for seq in range(9):
        wrapped = eel_append_records(wrapped, {1: struct.pack("<H", 252) + bytes([0xA0 + seq]) * 250})

    w_blocks, _ = eel_parse_pool(lay, wrapped)
    assert w_blocks[27]["state"] == "active" and w_blocks[27]["ec"] == 10
    assert w_blocks[0]["state"] == "active" and w_blocks[0]["ec"] == 11  # incremented at VB 0
    vb27_sep = 27 * 0x800 + w_blocks[27]["separator"]
    assert wrapped[vb27_sep : vb27_sep + 4] == b"\xff\xff\xff\xff"
    assert w_blocks[0]["rwp_ok"] is True
    assert w_blocks[0]["rwp"] == vb27_sep
    rec_back, src_back = eel_read_record_any(lay, wrapped, 1)
    assert src_back["vb"] == 0 and rec_back[2] == 0xA8

    # Pool exhaustion guard: if activating next_vb would leave 0 prepared/invalid blocks, refuse cleanly
    exhausted = bytearray(ring_df)
    for n in range(26):
        b = n * 0x800
        struct.pack_into("<I", exhausted, b + 0x08, EEL_MARK)
        struct.pack_into("<I", exhausted, b + 0x14, eel_cs24(((n - 1) % 28) * 0x800 + 0x18))
        struct.pack_into("<I", exhausted, b + 0x0C, EEL_MARK)
    # Now only VB 26 is prepared (VB 0..25 and VB 27 active -> head is VB 25 at EC=11)
    almost_full = bytes(exhausted)
    with pytest.raises(RuntimeError, match="EEL pool"):
        for seq in range(10):
            almost_full = eel_append_records(almost_full, {1: struct.pack("<H", 252) + bytes([seq]) * 250})


def test_fpke_coil_kessy_preservation_and_mode2_exit() -> None:
    import zlib
    from contitool.can.fpke import (
        FPKE_83A_RAM_EEL67_ADDR,
        FPKE_83A_RAM_EEL68_ADDR,
        FpkeCanLink,
        fpke_finish_coil_key_learning,
        fpke_prepare_additive_coil_learning,
    )
    from contitool.core.fpke import fpke_s0_s1_from_slots

    slot_a = b"LAB IMMO SLOT A!"
    slot_b = b"LAB IMMO SLOT B!"
    s0, s1 = fpke_s0_s1_from_slots(slot_a, slot_b)
    crc_a_le = struct.pack("<I", zlib.crc32(slot_a))
    crc_b_le = struct.pack("<I", zlib.crc32(slot_b))

    class KessyAndMode2Bus(FakeFpkeBus):
        def __init__(self) -> None:
            super().__init__()
            # Populate SW 83A RAM mirror with 1 learned key and KESSY key_over_can = 0x80
            self.ram[FPKE_83A_RAM_EEL67_ADDR] = bytes.fromhex("a1b2c3d4") + b"\xff" * 28 + bytes([1, 0x01, 0, 0, 0])
            self.ram[FPKE_83A_RAM_EEL68_ADDR + 0x42] = bytes([0x00, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 0x80])
            self.ident_map[0x02ED] = bytes([2, 0x01, 0x03, 0x4C, 1, 0x00, 0, 0x00, 0x01, 0x00])
            self.ident_map[0x02E5] = bytes.fromhex("d4c3b2a1")
            self.ident_map[0x02FA] = b"\x01\x11\x22\x33\x44"
            self.flag_at_80_00: int | None = None

        def _read_region_slice(self, addr: int, size: int) -> bytes:
            for base, buf in sorted(self.ram.items()):
                if base <= addr and addr + size <= base + len(buf):
                    off = addr - base
                    return bytes(buf[off : off + size])
            return super()._read_region_slice(addr, size)

        def _handle_uds(self, req: bytes) -> None:
            if req[:2] == b"\x3d\x44":
                addr = int.from_bytes(req[2:6], "big")
                size = int.from_bytes(req[6:10], "big")
                data = req[10 : 10 + size]
                updated = False
                for base, buf in list(self.ram.items()):
                    if base <= addr and addr + size <= base + len(buf):
                        arr = bytearray(buf)
                        off = addr - base
                        arr[off : off + size] = data
                        self.ram[base] = bytes(arr)
                        updated = True
                        break
                if not updated:
                    self.ram[addr] = data
                self._push_uds_reply(b"\x7d\x44" + req[2:10])
                return
            if req[:3] == b"\x2e\x02\xe1" and req[5] == 0x80:
                tail = self.ram[FPKE_83A_RAM_EEL68_ADDR + 0x42]
                cur_mode = tail[7]
                if cur_mode not in (4, 5):
                    # Firmware rejects 0x80 with NRC 0x7F in mode 2
                    self._push_uds_reply(b"\x7f\x2e\x7f")
                    return
                self.flag_at_80_00 = tail[9]
                arr = bytearray(tail)
                arr[7] = 0x01
                self.ram[FPKE_83A_RAM_EEL68_ADDR + 0x42] = bytes(arr)
                self._push_uds_reply(b"\x6e\x02\xe1")
                return
            super()._handle_uds(req)

    bus = KessyAndMode2Bus()
    with FpkeCanLink("fake-port", interface="slcan", bus=bus) as link:
        link.level8_active = True
        prep = fpke_prepare_additive_coil_learning(
            link,
            s0_hex=s0.hex(),
            s1_hex=s1.hex(),
            allowed_keys=4,
            expected_crc_a_le=crc_a_le,
            expected_crc_b_le=crc_b_le,
            wake_seconds=0.0,
        )
        assert prep["kessy_preserved"] is True
        assert prep["immo_mode"] == 5
        # During coil learning, bit 7 of 0x5303 is temporarily 0 so the local LF coil is active
        assert (bus.ram[FPKE_83A_RAM_EEL68_ADDR + 0x42][9] & 0x80) == 0x00

        # Simulate cluster dropping to mode 2 before finish: finish promotes 2 -> 5 AND restores KESSY 0x80 before 80 00!
        arr = bytearray(bus.ram[FPKE_83A_RAM_EEL68_ADDR + 0x42])
        arr[7] = 0x02
        bus.ram[FPKE_83A_RAM_EEL68_ADDR + 0x42] = bytes(arr)

        fin = fpke_finish_coil_key_learning(link, sync_channel3=False)
        assert fin["ok"] is True
        assert fin["promoted_mode2"] is True
        assert fin["kessy_restored"] is True
        assert bus.flag_at_80_00 == 0x80
        assert (bus.ram[FPKE_83A_RAM_EEL68_ADDR + 0x42][9] & 0x80) == 0x80


def test_fpke_link_release_problem_report_dumps_and_public_exports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import ast
    from PySide6.QtWidgets import QApplication
    import can as pycan
    from contitool.can.fpke import FpkeCanLink, close_active_fpke_link, get_active_fpke_link, set_active_fpke_link
    from contitool.can.transport import J533CanLink
    from contitool.core.fpke import apply_fpke_dflash_edits
    from contitool.gui.main_window import MainWindow
    from contitool.gui.theme import apply_theme
    from contitool.report import Failure

    # 1. Opening J533CanLink with bus=None closes any background FpkeCanLink first
    fake_fpke_bus = FakeFpkeBus()
    fpke_link = FpkeCanLink("shared-port", interface="slcan", bus=fake_fpke_bus)
    set_active_fpke_link(fpke_link)
    assert get_active_fpke_link() is fpke_link

    class DummyRawBus:
        def shutdown(self) -> None:
            pass

    monkeypatch.setattr(pycan.interface, "Bus", lambda **_kw: DummyRawBus())
    with J533CanLink("shared-port", interface="socketcan", bus=None):
        assert fpke_link.is_closed is True
        assert get_active_fpke_link() is None
    close_active_fpke_link()

    # 2. MainWindow.offer_problem_report includes loaded & edited FPK_E dumps when fpke_screen is open
    app = QApplication.instance() or QApplication([])
    apply_theme(app)  # type: ignore[arg-type]
    unit_dir = tmp_path / "report_fpke_unit"
    unit_dir.mkdir()
    orig_df = build_synthetic_fpke_dflash()
    (unit_dir / "Dflash.bin").write_bytes(orig_df)
    (unit_dir / "ExtraArea.bin").write_bytes(build_synthetic_extra_area())

    win = MainWindow()
    win.open_folder(str(unit_dir))
    edited_df = apply_fpke_dflash_edits(orig_df, vin="REPORTVIN00000001")
    win.fpke_screen._commit_dflash_bytes(edited_df, "edited")
    app.processEvents()

    win.offer_problem_report(Failure("Test failure", "trace", started=0.0))
    assert win._report_dlg is not None
    dump_keys = set(win._report_dlg.dumps.keys())
    assert "loaded/Dflash.bin" in dump_keys
    assert "loaded/ExtraArea.bin" in dump_keys
    assert "edited/Dflash.bin" in dump_keys
    assert win._report_dlg.dumps["loaded/Dflash.bin"].read_bytes() == orig_df
    assert win._report_dlg.dumps["edited/Dflash.bin"].read_bytes() == edited_df
    win._report_dlg.close()
    win.close()

    # 3. Verify __all__ covers 100% of top-level imports in contitool/fpke.py, core/__init__.py, and can/__init__.py
    repo_root = Path(__file__).resolve().parents[1]
    for rel in ("src/contitool/fpke.py", "src/contitool/core/__init__.py", "src/contitool/can/__init__.py"):
        tree = ast.parse((repo_root / rel).read_text(encoding="utf-8"))
        all_set: set[str] = set()
        imported_set: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "__all__" and isinstance(node.value, (ast.List, ast.Tuple)):
                        all_set = {elt.value for elt in node.value.elts if isinstance(elt, ast.Constant)}
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    if not name.startswith("_"):
                        imported_set.add(name)
        assert imported_set == all_set, f"{rel} mismatch: missing={imported_set - all_set}, extra={all_set - imported_set}"


def test_fpke_faci_normalization_and_cpu_read_floating_gate_noise() -> None:
    from contitool.core.fpke import apply_fpke_dflash_edits, eel_parse_pool

    base_df = build_synthetic_fpke_dflash()
    lay = fpke_eel_layout(None, base_df)
    clean_base, mask_base = normalize_fpke_dflash_for_faci(base_df)

    # Simulate a CPU-read (UDS 0x23) dump where erased RV40F cells contain floating-gate noise (including 0x55555555 ghosts)
    noisy = bytearray(clean_base)
    for off in range(0, len(noisy), 4):
        if not any(mask_base[off : off + 4]):
            # Fill blank words with realistic floating-gate residue (0x57555455 / 0x55555555)
            noisy[off : off + 4] = struct.pack("<I", 0x55555555 if (off % 32 == 8) else 0x57555455)

    # Prepared VB 3 has P=0x55555555 and EC=eel_cs24(12), plus ghost A0=0x55555555 and a ghost DRP for EEL 0x30
    b3 = 3 * 0x800
    struct.pack_into("<I", noisy, b3 + 0x04, EEL_MARK)
    struct.pack_into("<I", noisy, b3 + 0x08, EEL_MARK)
    struct.pack_into("<I", noisy, b3 + 0x10, eel_cs24(12))
    struct.pack_into("<4I", noisy, b3 + 0x18, EEL_MARK, EEL_MARK, EEL_MARK, 0x30 | (0x7F0 << 16))

    # Appending odometer + coding onto noisy CPU-read dump must fit inside active head VB 2 and pass 0x30 verification
    edited = apply_fpke_dflash_edits(
        bytes(noisy),
        odometer_km=77_700,
        coding_hex="44FD0A0F67840008100777021000000000001D03",
    )
    norm_edited, mask_edited = normalize_fpke_dflash_for_faci(edited)
    blocks_after, _ = eel_parse_pool(lay, norm_edited, mask_edited)
    active_vbs = [b["vb"] for b in blocks_after if b["state"] == "active"]
    assert active_vbs == [2]
    assert blocks_after[3]["state"] == "prepared"

    chg = summarize_fpke_dflash_changes(bytes(noisy), edited)
    assert chg["changed"] is True
    assert chg["is_pure_eel_update"] is True
    assert chg["changed_eel_ids"] == ["0x30", "0x35", "0x60"]


def test_can_fpke_write_dflash_smart_eel_zero_erase_and_backup_restore(tmp_path: Path) -> None:
    from contitool.can.fpke import close_active_fpke_link
    from contitool.core.fpke import apply_fpke_dflash_edits

    close_active_fpke_link()
    bus = FakeFpkeBus()
    orig_dflash = bus.dflash

    try:
        # 1. Edit VIN, odometer, and learned keys -> smart EEL append writes into blank cells with ZERO erases!
        cand_df = apply_fpke_dflash_edits(
            orig_dflash,
            vin="WRITEVIN000012345",
            odometer_km=64_200,
            key_display_ids=["11223344", "55667788", "AABBCCDD"] + [None] * 5,
            learned_keys=3,
            allowed_keys=8,
        )
        # Also simulate transient R_EEL_Handler FENTRYD contention on the first 2 applet invocations
        bus.faci_busy_countdown = 2

        rep = can_fpke_write_dflash(
            "fake",
            cand_df,
            base_dflash=orig_dflash,
            session_dir=tmp_path / "smart_write",
            frame_delay=0.0,
            wake_seconds=0.0,
            keep_open=True,
            bus=bus,
        )
        assert rep["ok"] is True
        assert rep["mode"] == "smart_eel_append"
        assert rep["blocks_erased"] == 0
        assert rep["blocks_written"] >= 2
        assert bus.faci_erases == 0
        assert bus.swresa_resets == 1
        assert rep["idauth"]["idst_after_idcode"] == "00000000"
        assert rep["idauth"]["idst_after_relock"] == "01000000"
        assert rep["secrets"]["metadata"]["vin"] == "WRITEVIN000012345"
        assert rep["secrets"]["metadata"]["odometer_km"] == 64_200
        assert rep["secrets"]["transponder_records"]["learned_keys"] == 3
        assert bus.ident_map[0xF190] == b"WRITEVIN000012345"
        assert (tmp_path / "smart_write" / "Dflash_before.bin").read_bytes() == orig_dflash
        assert (tmp_path / "smart_write" / "Dflash_readback.bin").read_bytes() == bus.dflash

        # 2. Foreign cluster FD11 safety check refuses a dump with a different FD11 identifier
        from contitool.core.fpke import eel_append_records

        r63_foreign = bytearray(b"\xff" * EEL_83A_IDS[0x63])
        r63_foreign[:2] = struct.pack("<H", len(r63_foreign))
        r63_foreign[2:17] = b"5E0920790A 1703"
        foreign_df = eel_append_records(orig_dflash, {0x63: bytes(r63_foreign)})
        with pytest.raises(RuntimeError, match="FD11"):
            can_fpke_write_dflash(
                "fake",
                foreign_df,
                session_dir=tmp_path / "foreign_write",
                frame_delay=0.0,
                wake_seconds=0.0,
                bus=bus,
            )

        # 3. Full backup restore (full_rewrite=True) erases the newly written blocks and restores orig_dflash 1:1
        rep_restore = can_fpke_write_dflash(
            "fake",
            orig_dflash,
            base_dflash=None,
            full_rewrite=True,
            session_dir=tmp_path / "restore_write",
            frame_delay=0.0,
            wake_seconds=0.0,
            keep_open=False,
            bus=bus,
        )
        assert rep_restore["ok"] is True
        assert rep_restore["mode"] == "full_blank_checked_diff"
        assert rep_restore["blocks_erased"] >= 2
        assert bus.dflash == orig_dflash
        assert bus.ident_map[0xF190] == b"TESTVIN0123456789"
    finally:
        close_active_fpke_link()


def test_fpke_gui_one_click_write_to_ecu_staged_write_bar_and_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time
    from PySide6.QtWidgets import QApplication, QMessageBox
    from contitool.can.fpke import FpkeCanLink, close_active_fpke_link, set_active_fpke_link
    from contitool.cli.main import main
    from contitool.core.fpke import apply_fpke_dflash_edits
    from contitool.gui import main_window
    from contitool.gui.main_window import MainWindow
    from contitool.gui.screens import fpke as fpke_gui
    from contitool.gui.theme import apply_theme

    app = QApplication.instance() or QApplication([])
    apply_theme(app)  # type: ignore[arg-type]

    close_active_fpke_link()
    bus = FakeFpkeBus()
    bus.vendor_level = 8
    link = FpkeCanLink("fake-port", interface="slcan", bus=bus)
    link.level8_active = True
    set_active_fpke_link(link)

    try:
        set_lang("ru")
        monkeypatch.setattr(fpke_gui, "ensure_ready", lambda *_a: True)
        monkeypatch.setattr(main_window, "ensure_ready", lambda *_a: True)
        monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.StandardButton.Yes)

        win = MainWindow()
        failures: list[Any] = []
        monkeypatch.setattr(win, "offer_problem_report", lambda f: failures.append(f))
        win.conn.port = "fake-port"
        win.conn.interface = "slcan"
        win.conn.out_dir = tmp_path / "runs"
        win.fpke_screen._wake_seconds = 0.0

        unit_dir = tmp_path / "gui_write_unit"
        unit_dir.mkdir()
        orig_df = bus.dflash
        (unit_dir / "Dflash.bin").write_bytes(orig_df)
        (unit_dir / "ExtraArea.bin").write_bytes(bus.extra)
        win.open_folder(str(unit_dir))
        win.show()
        win.resize(1180, 840)
        app.processEvents()

        def wait_idle() -> None:
            deadline = time.monotonic() + 5.0
            while win.runner.is_busy and time.monotonic() < deadline:
                app.processEvents()
                time.sleep(0.005)
            for _ in range(15):
                app.processEvents()
                time.sleep(0.003)

        # 1. Stage an edit into ContiTool_edited/Dflash.bin -> WriteBar appears with semantic summary and "Записать в блок"
        staged_df = apply_fpke_dflash_edits(orig_df, odometer_km=44_000, vin="GUIWRITEVIN000001")
        win.fpke_screen._commit_dflash_bytes(staged_df, "staged")
        app.processEvents()
        assert win.fpke_screen.is_dflash_modified is True
        assert win.fpke_screen.write_bar.isHidden() is False
        assert "44 000" in win.fpke_screen.lbl_write_bar.text()
        assert win.fpke_screen.btn_write_ecu.text() == "Записать в блок"

        # 2. Clicking "Записать в блок" on WriteBar writes changes over CAN, clears modified state, and updates IdentityBar
        win.fpke_screen.btn_write_ecu.click()
        wait_idle()
        assert win.fpke_screen.is_dflash_modified is False
        assert win.fpke_screen.write_bar.isHidden() is True
        assert win.fpke_screen.dflash_info["metadata"]["odometer_km"] == 44_000
        assert win.fpke_screen.dflash_info["metadata"]["vin"] == "GUIWRITEVIN000001"
        assert analyze_fpke_dflash(bus.dflash)["metadata"]["odometer_km"] == 44_000

        # 3. Restore original backup via restore_dflash_from_file
        backup_file = tmp_path / "orig_backup.bin"
        backup_file.write_bytes(orig_df)
        win.fpke_screen.restore_dflash_from_file(backup_file, confirm=True)
        wait_idle()
        assert bus.dflash == orig_df
        assert win.fpke_screen.dflash_info["metadata"]["vin"] == "TESTVIN0123456789"
        win.close()

        # 4. CLI fpke write-dflash --yes roundtrip
        cli_cand = tmp_path / "cli_cand.bin"
        cli_base = tmp_path / "cli_base.bin"
        cli_base.write_bytes(orig_df)
        cli_cand.write_bytes(apply_fpke_dflash_edits(orig_df, odometer_km=88_000))
        link2 = FpkeCanLink("fake-port", interface="slcan", bus=bus)
        link2.level8_active = True
        set_active_fpke_link(link2)
        rc = main(
            [
                "--no-color",
                "fpke",
                "write-dflash",
                "--port",
                "fake-port",
                "--dflash",
                str(cli_cand),
                "--base-dflash",
                str(cli_base),
                "--wake-seconds",
                "0",
                "--output-dir",
                str(tmp_path / "cli_runs"),
                "--yes",
            ]
        )
        assert rc == 0
        assert analyze_fpke_dflash(bus.dflash)["metadata"]["odometer_km"] == 88_000
    finally:
        close_active_fpke_link()


def test_fpke_sw1703_and_sw1711_level8_read_and_write(tmp_path: Path) -> None:
    from contitool.can.fpke import (
        FPKE_1703_APPLET_ENTRY,
        FPKE_1703_CALLER_RETURN,
        FPKE_1703_FORGED_PTR,
        FPKE_1703_POINTER_FRAME,
        FPKE_1711_CALLER_RETURN,
        FpkeCanLink,
        build_fpke_bflash_buf_applet,
        build_fpke_can_stream_applet,
        build_fpke_uflash_buf_applet,
        can_fpke_full_read,
        can_fpke_write_dflash,
        close_active_fpke_link,
        flood_payload,
        fpke_detect_sw_profile,
        fpke_establish_level8,
        fpke_get_profile,
    )
    from contitool.core.fpke import apply_fpke_dflash_edits

    assert fpke_detect_sw_profile(f189="1703", f187="5E0920790A") == "1703"
    assert fpke_detect_sw_profile(f189="1711", f187="5E0920790A") == "1711"
    assert fpke_detect_sw_profile(f189="", f187="5E0 920 790 A") == "1703"
    assert fpke_detect_sw_profile(f189="6181", f187="83A920700E") == "83a"
    assert fpke_get_profile("1703")["applet_entry"] == FPKE_1703_APPLET_ENTRY == 0xFEDF4400
    assert fpke_get_profile("1703")["caller_return"] == FPKE_1703_CALLER_RETURN
    assert fpke_get_profile("1711")["caller_return"] == FPKE_1711_CALLER_RETURN
    assert flood_payload(FPKE_1703_POINTER_FRAME, profile="1703")[:4] == FPKE_1703_FORGED_PTR.to_bytes(4, "little")

    # Verify MPM (SR 0, sel 5) & ICCTRL/CDBCR (SR 24, sel 4 / sel 13) encodings in generated applets
    stsr_mpm_r19 = bytes.fromhex("e09f4028")  # stsr 0, r19, 5
    ldsr_r19_mpm = bytes.fromhex("f3072028")  # ldsr r19, 0, 5
    stsr_cdbcr = bytes.fromhex("f8674068")    # stsr 24, r12, 13
    ldsr_cdbcr = bytes.fromhex("ecc72068")    # ldsr r12, 24, 13
    for prof_name in ("83a", "1703", "1711"):
        uf_buf = build_fpke_uflash_buf_applet(prof_name)
        uf_str = build_fpke_can_stream_applet("uflash", profile=prof_name)
        bf_str = build_fpke_can_stream_applet("bflash", profile=prof_name)
        assert stsr_mpm_r19 in uf_buf and ldsr_r19_mpm in uf_buf
        assert stsr_mpm_r19 in uf_str and ldsr_r19_mpm in uf_str
        assert stsr_cdbcr in bf_str and ldsr_cdbcr in bf_str
        if prof_name in ("1703", "1711"):
            bf_buf = build_fpke_bflash_buf_applet(prof_name)
            assert stsr_cdbcr in bf_buf and ldsr_cdbcr in bf_buf

    for prof_name in ("1703", "1711"):
        close_active_fpke_link()
        bus = FakeFpkeBus(sw_profile=prof_name, enable_stream_0x6f1=True)
        if prof_name == "1711":
            # Simulate a 1711 cluster whose F189 initially reports 1703 to verify stack-based refinement before applet build
            bus.ident_map[0xF189] = b"1703"
        read_dir = tmp_path / f"read_{prof_name}"
        rep = can_fpke_full_read(
            "fake",
            session_dir=read_dir,
            frame_delay=0.0,
            wake_seconds=0.0,
            use_stream=True,
            read_uflash=True,
            bus=bus,
        )
        assert rep["sw_profile"] == prof_name
        assert f"SW {prof_name}" in rep["target"]
        assert rep["exploit"]["sw_profile"] == prof_name
        assert rep["exploit"]["pointer_frame"] == FPKE_1703_POINTER_FRAME
        assert bus.ed_count == FPKE_1703_POINTER_FRAME + 1  # 965 frames
        assert (read_dir / "Dflash.bin").read_bytes() == bus.dflash
        assert (read_dir / "ExtraArea.bin").read_bytes() == bus.extra
        assert (read_dir / "Uflash.bin").stat().st_size == 0x8000

        edited_df = apply_fpke_dflash_edits(bus.dflash, odometer_km=77_700 if prof_name == "1703" else 99_900)
        write_dir = tmp_path / f"write_{prof_name}"
        wr_rep = can_fpke_write_dflash(
            "fake",
            edited_df,
            base_dflash=bus.dflash,
            session_dir=write_dir,
            frame_delay=0.0,
            wake_seconds=0.0,
            keep_open=False,
            bus=bus,
        )
        assert wr_rep["ok"] is True
        assert wr_rep["sw_profile"] == prof_name
        assert (write_dir / "fpke.can.log").is_file()
        assert (write_dir / "fpke.can.log").stat().st_size > 0
        assert analyze_fpke_dflash(bus.dflash)["metadata"]["odometer_km"] == (
            77_700 if prof_name == "1703" else 99_900
        )

    # Verify persistent FpkeCanLink re-probes sw_profile when swapped from 83A cluster to 1711 cluster
    bus_83a = FakeFpkeBus(sw_profile="83a")
    link = FpkeCanLink("fake", interface="slcan", bus=bus_83a)
    try:
        res_83a = fpke_establish_level8(link, frame_delay=0.0, wake_seconds=0.0, post_exploit_sleep=0.0)
        assert res_83a["sw_profile"] == "83a"
        link.bus = FakeFpkeBus(sw_profile="1711")
        res_1711 = fpke_establish_level8(link, frame_delay=0.0, wake_seconds=0.0, post_exploit_sleep=0.0)
        assert res_1711["sw_profile"] == "1711"
    finally:
        link.close()
        close_active_fpke_link()


def test_fpke_k_ffb_derivation_and_gui_calculator(tmp_path: Path) -> None:
    from PySide6.QtWidgets import QApplication, QLineEdit

    from contitool.core.bcm import bcm_derive_k_ffb
    from contitool.fpke import (
        FPKE_FFB_C16,
        aes128_ecb_encrypt,
        extract_fpke_immo_passport,
        fpke_derive_k_ffb,
        plan_fpke_a_to_b_transfer,
    )
    from contitool.gui.main_window import MainWindow

    df = build_synthetic_fpke_dflash()
    info = analyze_fpke_dflash(df)
    by_id = {it["key_id"]: it for it in info["items"]}
    kc_hex = by_id["kc"]["hex"].upper()
    expected_k_ffb = aes128_ecb_encrypt(bytes.fromhex(kc_hex), FPKE_FFB_C16).hex().upper()

    assert fpke_derive_k_ffb(kc_hex).hex().upper() == expected_k_ffb
    assert fpke_derive_k_ffb(bytes.fromhex(kc_hex)).hex().upper() == expected_k_ffb
    assert bcm_derive_k_ffb(bytes.fromhex(kc_hex)).hex().upper() == expected_k_ffb
    assert info["immo_config"]["k_ffb_hex"] == expected_k_ffb
    assert expected_k_ffb in format_fpke_report(dflash_info=info)

    passport = extract_fpke_immo_passport(df)
    assert passport["immo"]["k_ffb"] == expected_k_ffb
    plan = plan_fpke_a_to_b_transfer(df, df)
    assert plan["transfer_from_a"]["k_ffb"] == expected_k_ffb

    app = QApplication.instance() or QApplication([])
    win = MainWindow()
    try:
        # 1. Standalone K_ffb calculator when no DataFlash dump is loaded yet
        win.fpke_screen.open_from_ident({"ident": []})
        win.fpke_screen.select("secrets")
        app.processEvents()
        edits_empty = win.fpke_screen.page_area.findChildren(QLineEdit)
        assert len(edits_empty) >= 2
        edits_empty[0].setText(kc_hex)
        app.processEvents()
        assert any(e.text().strip().upper() == expected_k_ffb for e in edits_empty)

        # 2. Loaded DataFlash shows live K_ffb on both Immobilizer ('secrets') and Keys ('keys') pages
        df_file = tmp_path / "Dflash.bin"
        df_file.write_bytes(df)
        win.fpke_screen.open_from_files(
            {"dflash": df_file},
            folder=tmp_path,
            source="disk",
        )
        for nav_key in ("secrets", "keys"):
            win.fpke_screen.select(nav_key)
            app.processEvents()
            page_edits = win.fpke_screen.page_area.findChildren(QLineEdit)
            assert any(e.text().strip().upper() == expected_k_ffb for e in page_edits)
    finally:
        win.close()


def build_synthetic_fpke_cflash(
    bolo_version: bytes = b"4094",
    *,
    include_lzss_backrefs: bool = True,
    backref_to_patch_byte: bool = False,
) -> bytes:
    """Build a synthetic 256 KiB FPK_E CodeFlash prefix containing BOLO `.secinfo`, `.LoaderRAMCOPY` (Okumura LZSS), and `.MemCheckCrcTblApp`."""
    from contitool.fpke import (
        FPKE_CFLASH_BOLO_VERSION_OFFSET,
        FPKE_CFLASH_FBL_AESKEY_OFFSET,
        FPKE_CFLASH_MEMCHECK_APP_ENTRIES,
        FPKE_CFLASH_MEMCHECK_APP_OFFSET,
        FPKE_LOADER_RAM_CODE_ADDR,
        FPKE_STOCK_FBL_AES_KEY,
        fpke_crc32_app,
    )

    cf = bytearray(b"\xff" * 0x040000)
    cf[FPKE_CFLASH_BOLO_VERSION_OFFSET : FPKE_CFLASH_BOLO_VERSION_OFFSET + 4] = bolo_version
    cf[FPKE_CFLASH_FBL_AESKEY_OFFSET : FPKE_CFLASH_FBL_AESKEY_OFFSET + 16] = FPKE_STOCK_FBL_AES_KEY

    # Construct a valid Okumura LZSS stream containing the rsa_verify tail plus real back-reference tokens
    # Pad raw_ram_code to a multiple of 8 bytes (130 + 50 + 68 = 248) so the next byte is a fresh LZSS flag byte.
    raw_ram_code = (
        b"\x00" * 0x82
        + bytes.fromhex(
            "e051ea1523f688000a08caf1c309a10f07006010e111ba0541ea9d0041528a000a0680ff89f51d0680ffe2e700001c50031e"
        )
        + b"\x00" * 68
    )
    assert len(raw_ram_code) % 8 == 0
    comp = bytearray()
    for i in range(0, len(raw_ram_code), 8):
        chunk = raw_ram_code[i : i + 8]
        comp.append((1 << len(chunk)) - 1)
        comp.extend(chunk)

    if include_lzss_backrefs:
        # Emit an Okumura LZSS back-reference token (flag bit 0 = backref, bits 1..7 = 7 literal zeros):
        # either referencing harmless prologue bytes (offset 0) or deliberately referencing the patched bne byte (0x84).
        ref_ram_off = 0x84 if backref_to_patch_byte else 0x00
        ring_pos = (4096 - 18 + ref_ram_off) & 0xFFF
        ref_len = 4
        comp.append(0xFE)  # bit 0 = backref, bits 1..7 = literals
        comp.append(ring_pos & 0xFF)
        comp.append(((ring_pos >> 4) & 0xF0) | ((ref_len - 3) & 0x0F))
        comp.extend(b"\x00" * 7)

    # Pad compressed stream into realistic BOLO range (>= 0x8000 bytes)
    while len(comp) < 0x8100:
        comp.append(0xFF)
        comp.extend(b"\x00" * 8)

    src_off = 0x0103D4
    cf[src_off : src_off + len(comp)] = comp
    struct.pack_into("<3I", cf, 0x007F5C, FPKE_LOADER_RAM_CODE_ADDR, src_off, len(comp))

    # Populate 6 .MemCheckCrcTblApp entries @ 0x00031380 (entry 0 covers BOLO 0x000000..0x02EEE0)
    ranges = (
        (0x000000, 0x02EEE0),
        (0x030000, 0x001373),
        (0x031500, 0x002B00),
        (0x034000, 0x004000),
        (0x038000, 0x004000),
        (0x03C000, 0x004000),
    )
    assert len(ranges) == FPKE_CFLASH_MEMCHECK_APP_ENTRIES
    for idx, (s_addr, length) in enumerate(ranges):
        crc = fpke_crc32_app(bytes(cf[s_addr : s_addr + length]))
        struct.pack_into(
            "<5I",
            cf,
            FPKE_CFLASH_MEMCHECK_APP_OFFSET + idx * 20,
            s_addr,
            s_addr,
            length,
            crc,
            0x55,
        )
    return bytes(cf)


def test_fpke_engineering_bootloader_and_fbl_rsa_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from PySide6.QtWidgets import QApplication, QFileDialog

    from contitool.core.crypto import _is_probable_prime, rsassa_pkcs1_v15_verify
    from contitool.fpke import (
        FPKE_DFLASH_FBL_RSAKEY_OFFSET,
        FPKE_DFLASH_FBL_RSAKEYVERS_OFFSET,
        FPKE_STOCK_FBL_RSA_MODULUS_BE,
        FPKE_STOCK_FBL_RSA_MODULUS_LE,
        analyze_fpke_cflash_bootloader,
        analyze_fpke_dflash,
        analyze_fpke_dflash_fbl_key,
        apply_fpke_cflash_rsa_patch,
        apply_fpke_dflash_edits,
        apply_fpke_dflash_fbl_rsa_key,
        format_fpke_report,
        okumura_lzss_decompress_with_map,
        sign_fpke_odx_datablock,
    )
    from contitool.gui.main_window import MainWindow
    from contitool.gui.screens.fpke import _FpkeOdxSignDialog
    from contitool.report import Failure

    # 1. Verify stock VAG ODX signature from FL_83A920700E_6181___S.odx (FD_01ERASEPROGRROUTI: addr=0xF0, usize=16)
    stock_odx_sig = bytes.fromhex(
        "490c445a407ef66918f5dd3821879cb86d64329fbd3793ae4a92588ded0cb6f6"
        "eb54fa4d4c275768f7adbf18dfdc808a51f6ded39a13dd835f922518c7d305e0"
        "959019f2d4f3070da1440adca89b52d1f147c33fbdffb2ec54eefbb1a8ca5dfe"
        "442cd8cc2a1c2d4a03d70afe2b14a22a78d21c1aa0967f8a5526f0784653a0ec"
    )
    fd_01 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    msg_01 = struct.pack(">II", 0x000000F0, 16) + fd_01
    assert rsassa_pkcs1_v15_verify(msg_01, stock_odx_sig, FPKE_STOCK_FBL_RSA_MODULUS_BE, 3, "sha1")

    # 2. Verify DataFlash .FBL_RSAKEY strict 2-block isolation (0xED00/0xED40 only by default, opt-in metadata),
    #    invalid modulus rejection, and ODX signing validation
    df_blank_tail = build_synthetic_fpke_dflash()
    df_stock_only = apply_fpke_dflash_fbl_rsa_key(df_blank_tail, restore_stock=True)
    # Default populate_metadata=False must NOT touch block 0xED80
    assert df_stock_only[FPKE_DFLASH_FBL_RSAKEYVERS_OFFSET : FPKE_DFLASH_FBL_RSAKEYVERS_OFFSET + 10] == b"\xff" * 10
    df_base = apply_fpke_dflash_fbl_rsa_key(df_blank_tail, restore_stock=True, populate_metadata=True)
    assert df_base[FPKE_DFLASH_FBL_RSAKEYVERS_OFFSET : FPKE_DFLASH_FBL_RSAKEYVERS_OFFSET + 2] == b"\x23\x00"

    fbl_st = analyze_fpke_dflash_fbl_key(df_base)
    assert fbl_st["state"] == "stock"
    assert fbl_st["modulus_le_hex"] == FPKE_STOCK_FBL_RSA_MODULUS_LE.hex().upper()
    assert fbl_st["modulus_be_hex"] == FPKE_STOCK_FBL_RSA_MODULUS_BE.hex().upper()

    # Invalid RSA moduli must be rejected
    with pytest.raises(ValueError):
        apply_fpke_dflash_fbl_rsa_key(df_base, b"\x7f" + b"\x11" * 126 + b"\x01")  # MSB bit 7 == 0
    with pytest.raises(ValueError):
        apply_fpke_dflash_fbl_rsa_key(df_base, b"\x80" + b"\x11" * 126 + b"\x02")  # even LSB

    # Deterministic 1024-bit RSA test keypair (e = 3)
    p_test = 0xD5BBB96D30086EC484EBA3D7F9CAEB0753D1F4452B986324F15C6C775E5B130B2C8497E153D9668F7C6B985E290F7B41E519A67F0252E8C7D29F456B03D6A44B
    q_test = 0xC97FB1F027F453F6341233EAAAD1D9353F6C42D08866B1D05A0F2035028B9D869840B41666B42E92EA0DA3B43204B5CFCE3352524D0416A5A441E700AF46128B
    while not (p_test.bit_length() == 512 and p_test % 3 == 2 and _is_probable_prime(p_test)):
        p_test += 2
    while not (q_test.bit_length() == 512 and q_test % 3 == 2 and _is_probable_prime(q_test)):
        q_test += 2
    n_test = p_test * q_test
    d_test = pow(3, -1, (p_test - 1) * (q_test - 1))
    n_test_be = n_test.to_bytes(128, "big")

    custom_sig = sign_fpke_odx_datablock(
        fd_01,
        source_start_address=0x000000F0,
        uncompressed_size=16,
        n_bytes=n_test_be,
        d_int=d_test,
    )
    assert rsassa_pkcs1_v15_verify(msg_01, custom_sig, n_test_be, 3, "sha1")
    with pytest.raises(ValueError):
        sign_fpke_odx_datablock(fd_01, source_start_address=-1, uncompressed_size=16, n_bytes=n_test_be, d_int=d_test)
    with pytest.raises(ValueError):
        sign_fpke_odx_datablock(fd_01, source_start_address=0xF0, uncompressed_size=0, n_bytes=n_test_be, d_int=d_test)

    df_custom = apply_fpke_dflash_fbl_rsa_key(df_base, n_test_be)
    fbl_cu = analyze_fpke_dflash_fbl_key(df_custom)
    assert fbl_cu["state"] == "custom"
    assert fbl_cu["modulus_be_hex"] == n_test_be.hex().upper()
    assert df_custom[FPKE_DFLASH_FBL_RSAKEY_OFFSET : FPKE_DFLASH_FBL_RSAKEY_OFFSET + 128] == n_test_be[::-1]

    chg = summarize_fpke_dflash_changes(df_base, df_custom)
    assert chg["changed"] is True
    assert chg["raw_diff_blocks"] == 2
    assert any("0xFF20ED00" in ln for ln in chg["lines"])

    # 3. Verify can_fpke_write_dflash: smart_tail_update, 0xFFFFFFFF word programming, floating-gate noise preservation,
    #    atomic key replacement over colliding words, and combined smart_eel_and_tail mode
    bus = FakeFpkeBus()
    bus.dflash = df_base
    bus.faci_mask = eel_faci_word_mask(fpke_eel_layout(None, bus.dflash), bus.dflash)
    wr_res = can_fpke_write_dflash(
        "fake",
        df_custom,
        base_dflash=df_base,
        session_dir=tmp_path / "write_fbl_key",
        frame_delay=0.0,
        wake_seconds=0.0,
        keep_open=False,
        bus=bus,
    )
    assert wr_res["ok"] is True
    assert wr_res["mode"] == "smart_tail_update"
    assert wr_res["blocks_written"] == 2
    assert analyze_fpke_dflash_fbl_key(bus.dflash)["modulus_be_hex"] == n_test_be.hex().upper()

    # 3a. Custom modulus containing a literal 0xFFFFFFFF 32-bit word must be programmed (faci_mask == 1 on all 32 words)
    mod_with_ff = bytearray(n_test_be)
    mod_with_ff[16:20] = b"\xff\xff\xff\xff"
    df_ff_mod = apply_fpke_dflash_fbl_rsa_key(df_base, bytes(mod_with_ff))
    ff_mask = eel_faci_word_mask(fpke_eel_layout(None, df_ff_mod), df_ff_mod)
    assert all(ff_mask[FPKE_DFLASH_FBL_RSAKEY_OFFSET : FPKE_DFLASH_FBL_RSAKEY_OFFSET + 128])
    wr_ff = can_fpke_write_dflash(
        "fake",
        df_ff_mod,
        base_dflash=df_custom,
        session_dir=tmp_path / "write_ff_word_key",
        frame_delay=0.0,
        wake_seconds=0.0,
        keep_open=False,
        bus=bus,
    )
    assert wr_ff["ok"] is True
    assert wr_ff["mode"] == "smart_tail_update"
    assert all(bus.faci_mask[FPKE_DFLASH_FBL_RSAKEY_OFFSET : FPKE_DFLASH_FBL_RSAKEY_OFFSET + 128])
    assert analyze_fpke_dflash_fbl_key(bus.dflash)["modulus_be_hex"] == bytes(mod_with_ff).hex().upper()

    # 3b. Atomic key replacement: live ECU has mod_with_ff, ref_base has stock key, cand has Key B sharing a 32-bit word with stock
    mod_b = bytearray(n_test_be)
    mod_b[0:4] = FPKE_STOCK_FBL_RSA_MODULUS_BE[0:4]  # collides with ref_base (stock) while differing from live bus (mod_with_ff)
    mod_b[16:20] = b"\x12\x34\x56\x78"
    df_mod_b = apply_fpke_dflash_fbl_rsa_key(df_base, bytes(mod_b))
    wr_atom = can_fpke_write_dflash(
        "fake",
        df_mod_b,
        base_dflash=df_base,
        session_dir=tmp_path / "write_atomic_key",
        frame_delay=0.0,
        wake_seconds=0.0,
        keep_open=False,
        bus=bus,
    )
    assert wr_atom["ok"] is True
    assert wr_atom["mode"] == "smart_tail_update"
    assert analyze_fpke_dflash_fbl_key(bus.dflash)["modulus_be_hex"] == bytes(mod_b).hex().upper()

    # 3c. Floating-gate noise in erased cells 0xED8C..0xEDFF must NOT be programmed during smart_tail_update
    noisy_raw = bytearray(df_stock_only)
    noisy_raw[0xED8C:0xEE00] = bytes((i * 37 + 13) & 0xFF for i in range(0xEE00 - 0xED8C))
    bus_noise = FakeFpkeBus()
    bus_noise.dflash = bytes(noisy_raw)
    bus_noise.faci_mask = eel_faci_word_mask(fpke_eel_layout(None, df_stock_only), df_stock_only)
    # Mark 0xED80..0xEDFF truly blank in hardware BCST (erased cells with CPU-read floating-gate noise)
    bus_noise.faci_mask[0xED80:0xEE00] = b"\x00" * 0x80
    cand_meta = apply_fpke_dflash_fbl_rsa_key(bytes(noisy_raw), n_test_be, populate_metadata=True)
    wr_noise = can_fpke_write_dflash(
        "fake",
        cand_meta,
        base_dflash=bytes(noisy_raw),
        session_dir=tmp_path / "write_tail_noise",
        frame_delay=0.0,
        wake_seconds=0.0,
        keep_open=False,
        bus=bus_noise,
    )
    assert wr_noise["ok"] is True
    assert wr_noise["mode"] == "smart_tail_update"
    assert wr_noise["blocks_written"] == 3  # 0xED00, 0xED40, 0xED80 only (NOT 0xEDC0)
    assert not any(bus_noise.faci_mask[0xED8C:0xEE00])  # erased cells remain unprogrammed

    # 3d. Combined EEL + .FBL_RSAKEY edits use smart_eel_and_tail (not 64 KB full_blank_checked_diff)
    bus_comb = FakeFpkeBus()
    bus_comb.dflash = df_base
    bus_comb.faci_mask = eel_faci_word_mask(fpke_eel_layout(None, df_base), df_base)
    df_comb = apply_fpke_dflash_edits(df_base, vin="WAUZZZ8V0LA123456")
    df_comb = apply_fpke_dflash_fbl_rsa_key(df_comb, n_test_be)
    wr_comb = can_fpke_write_dflash(
        "fake",
        df_comb,
        base_dflash=df_base,
        session_dir=tmp_path / "write_eel_and_tail",
        frame_delay=0.0,
        wake_seconds=0.0,
        keep_open=False,
        bus=bus_comb,
    )
    assert wr_comb["ok"] is True
    assert wr_comb["mode"] == "smart_eel_and_tail"
    rb_comb = analyze_fpke_dflash(bus_comb.dflash)
    assert rb_comb["metadata"]["vin"] == "WAUZZZ8V0LA123456"
    assert rb_comb["fbl_rsa_key"]["modulus_be_hex"] == n_test_be.hex().upper()

    # 4. Verify CodeFlash BOLO RSA-Free patch, LZSS back-ref protection, modified App [1..5] tolerance, and roundtrip restore
    cf_stock = build_synthetic_fpke_cflash(b"4094", include_lzss_backrefs=True)
    b_stock = analyze_fpke_cflash_bootloader(cf_stock)
    assert b_stock["bolo_version"] == "4094"
    assert b_stock["state"] == "stock"
    assert b_stock["memcheck_crc_valid"] is True

    # Confirm synthetic LZSS stream really includes non-literal back-reference tokens
    src_off = int(b_stock["loader_rom_offset"], 16)
    comp_len = int(b_stock["loader_compressed_size"])
    dec_stock, src_map_stock = okumura_lzss_decompress_with_map(cf_stock[src_off : src_off + comp_len])
    assert any(m is None for m in src_map_stock)

    cf_eng, b_eng = apply_fpke_cflash_rsa_patch(cf_stock, restore_stock=False)
    assert b_eng["state"] == "engineering"
    assert b_eng["bne_hex"] == "0052"
    assert b_eng["cmov_hex"] == "01E2"
    assert b_eng["memcheck_crc_valid"] is True
    assert b_eng["memcheck_bolo_entry"]["stored_crc"] != b_stock["memcheck_bolo_entry"]["stored_crc"]

    dec_eng, _ = okumura_lzss_decompress_with_map(cf_eng[src_off : src_off + comp_len])
    diff_offs = [i for i in range(len(dec_stock)) if dec_stock[i] != dec_eng[i]]
    assert set(diff_offs) == set(b_stock["patch_ram_offsets_int"])

    # If an LZSS back-reference copies from a patched byte, apply_fpke_cflash_rsa_patch MUST reject it
    cf_bad_backref = build_synthetic_fpke_cflash(b"4094", include_lzss_backrefs=True, backref_to_patch_byte=True)
    with pytest.raises(RuntimeError):
        apply_fpke_cflash_rsa_patch(cf_bad_backref, restore_stock=False)

    # If Application ranges [1..5] are already modified (memcheck_crc_valid=False), BOLO patching must STILL succeed
    cf_mod_app = bytearray(cf_stock)
    cf_mod_app[0x030010] ^= 0x5A
    b_mod_before = analyze_fpke_cflash_bootloader(bytes(cf_mod_app))
    assert b_mod_before["memcheck_bolo_entry"]["valid"] is True
    assert b_mod_before["memcheck_crc_valid"] is False
    _cf_mod_eng, b_mod_eng = apply_fpke_cflash_rsa_patch(bytes(cf_mod_app), restore_stock=False)
    assert b_mod_eng["state"] == "engineering"
    assert b_mod_eng["memcheck_bolo_entry"]["valid"] is True
    assert b_mod_eng["memcheck_crc_valid"] is False

    cf_restored, b_restored = apply_fpke_cflash_rsa_patch(cf_eng, restore_stock=True)
    assert b_restored["state"] == "stock"
    assert b_restored["memcheck_crc_valid"] is True
    assert cf_restored == cf_stock

    # Report formatting includes BOLO section when bolo_info is passed
    rep_txt = format_fpke_report(dflash_info=analyze_fpke_dflash(df_custom), bolo_info=b_eng)
    assert "BOLO" in rep_txt and b_eng["memcheck_bolo_entry"]["stored_crc"] in rep_txt

    # 5. Verify GUI 'boot' tab, orig Cflash preservation, cleanup on restore, and _FpkeOdxSignDialog
    app = QApplication.instance() or QApplication([])
    win = MainWindow()
    try:
        df_file = tmp_path / "Dflash.bin"
        cf_file = tmp_path / "Cflash.bin"
        df_file.write_bytes(df_base)
        cf_file.write_bytes(cf_stock)
        key_file = tmp_path / "test_key.json"
        key_file.write_text(
            f'{{"n_hex": "{n_test_be.hex()}", "e": 3, "d_hex": "{d_test.to_bytes(128, "big").hex()}"}}\n',
            encoding="utf-8",
        )

        win.fpke_screen.open_from_files(
            {"dflash": df_file, "cflash": cf_file},
            folder=tmp_path,
            source="disk",
        )
        win.fpke_screen.select("boot")
        app.processEvents()
        assert win.fpke_screen.is_cflash_modified is False
        assert win.fpke_screen._orig_cflash_path == cf_file

        win.fpke_screen.embed_fbl_rsa_key_from_file(key_file)
        app.processEvents()
        assert win.fpke_screen.is_dflash_modified is True
        assert win.fpke_screen.dflash_info["fbl_rsa_key"]["state"] == "custom"
        assert win.fpke_screen._fbl_key_file == key_file

        win.fpke_screen.apply_cflash_engineering_bootloader(restore_stock=False)
        app.processEvents()
        edited_cf = tmp_path / "ContiTool_edited" / "Cflash.bin"
        assert win.fpke_screen.is_cflash_modified is True
        assert win.fpke_screen._orig_cflash_path == cf_file
        assert win.fpke_screen._working_cflash_path == edited_cf
        assert edited_cf.is_file()
        assert cf_file.read_bytes() == cf_stock  # original untouched
        assert win.fpke_screen._cflash_boot_info["state"] == "engineering"

        # export_backup MUST export the unmodified original Cflash.bin (and Dflash.bin), not ContiTool_edited/
        backup_dir = tmp_path / "exported_backup"
        backup_dir.mkdir()
        monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *_a, **_kw: str(backup_dir))
        win.fpke_screen.export_backup()
        assert (backup_dir / "Cflash.bin").read_bytes() == cf_stock
        assert (backup_dir / "Dflash.bin").read_bytes() == df_base

        # MainWindow.offer_problem_report MUST include loaded/Cflash.bin (orig) and edited/Cflash.bin (patched)
        win.stack.setCurrentWidget(win.fpke_screen)
        win.offer_problem_report(Failure("Test", "trace", started=0.0))
        assert win._report_dlg is not None
        assert win._report_dlg.dumps["loaded/Cflash.bin"] == cf_file
        assert win._report_dlg.dumps["edited/Cflash.bin"] == edited_cf
        win._report_dlg.close()

        # Restoring stock must remove ContiTool_edited/Cflash.bin and clear is_cflash_modified
        win.fpke_screen.apply_cflash_engineering_bootloader(restore_stock=True)
        win.fpke_screen.restore_stock_fbl_rsa_key()
        app.processEvents()
        assert win.fpke_screen.is_cflash_modified is False
        assert not edited_cf.exists()
        assert win.fpke_screen.files["cflash"] == cf_file
        assert win.fpke_screen._cflash_boot_info["state"] == "stock"
        assert win.fpke_screen.dflash_info["fbl_rsa_key"]["state"] == "stock"

        # Verify _FpkeOdxSignDialog validation & field parsing
        block_file = tmp_path / "fd01.bin"
        block_file.write_bytes(fd_01)
        dlg = _FpkeOdxSignDialog(key_path=key_file, default_dir=tmp_path, parent=win)
        try:
            assert dlg.btn_ok.isEnabled() is False
            dlg._data_path = block_file
            dlg.ed_data.setText(str(block_file))
            dlg.ed_addr.setText("0x000000F0")
            dlg.ed_usize.setText("16")
            dlg._sync()
            assert dlg.btn_ok.isEnabled() is True
            assert dlg.source_start_address == 0xF0
            assert dlg.uncompressed_size == 16
        finally:
            dlg.close()
    finally:
        win.close()


def test_fpke_smart_write_rollover_into_invalid_vb(tmp_path: Path) -> None:
    """Critical C3 regression: smart EEL append rolling over into an `invalid` VB must erase old I0/I1 & write new block."""
    from contitool.can.fpke import close_active_fpke_link
    from contitool.core.fpke import apply_fpke_dflash_edits, eel_parse_pool, extract_fpke_immo_passport

    close_active_fpke_link()
    base_df = bytearray(build_synthetic_fpke_dflash())
    lay = fpke_eel_layout(None, bytes(base_df))
    vb_sz = lay["vb"]
    # Fill VB 0 until it cannot hold another 0x68 record, and put an `invalid` VB at VB 1 with old I0/I1 + old DRP/data
    cur = bytes(base_df)
    blocks0, _ = eel_parse_pool(lay, cur)
    head_vb = max((b for b in blocks0 if b["state"] == "active"), key=lambda b: (b["ec"] or 0, b["vb"]))["vb"]
    # Append 0x60 edits until head_vb has < (size(0x68) + 0x10) bytes free so the next 0x68 edit MUST roll over into next_vb
    while True:
        blks, _ = eel_parse_pool(lay, cur)
        hd = blks[head_vb]
        free = int(hd.get("next_top", 0)) - (head_vb * vb_sz + int(hd.get("separator", 0x18)))
        if free < lay["ids"][0x68] + 0x10:
            break
        cur = apply_fpke_dflash_edits(cur, odometer_km=10000 + free)
    # Mark next_vb as `invalid` with old programmed I0, P, A0, A1, EC, RWP, DRP0, an unreferenced stale word, and I1
    next_vb = (head_vb + 1) % lay["n_vb"]
    mut = bytearray(cur)
    nb = next_vb * vb_sz
    struct.pack_into(
        "<6I",
        mut,
        nb,
        EEL_MARK,  # I0 (invalidated!)
        EEL_MARK,  # P
        EEL_MARK,  # A0
        EEL_MARK,  # A1
        eel_cs24(1),
        eel_cs24(nb + 0x18),
    )
    struct.pack_into("<4I", mut, nb + 0x18, EEL_MARK, EEL_MARK, EEL_MARK, 0x60 | ((vb_sz - 8) << 16))
    struct.pack_into("<I", mut, nb + 0x400, 0xCAFEBABE)  # unreferenced stale word inside invalid VB
    struct.pack_into("<I", mut, nb + vb_sz - 4, EEL_MARK)  # I1 (invalidated!)
    live_df = bytes(mut)

    cand_df = apply_fpke_dflash_edits(live_df, vin="WAUZZZ8V9LA999888")
    bus = FakeFpkeBus()
    bus.dflash = live_df
    bus.faci_mask = eel_faci_word_mask(lay, live_df)
    bus.faci_mask[nb + 0x400 : nb + 0x404] = b"\xff\xff\xff\xff"  # hardware BCST=1 on unreferenced stale word!
    try:
        rep = can_fpke_write_dflash(
            "fake",
            cand_df,
            base_dflash=live_df,
            session_dir=tmp_path / "rollover_invalid_vb",
            frame_delay=0.0,
            wake_seconds=0.0,
            reset_after=False,
            bus=bus,
        )
        assert rep["ok"] is True
        assert rep["blocks_erased"] > 0
        # Even the unreferenced stale word at nb + 0x400 MUST have been erased cleanly!
        assert not any(bus.faci_mask[nb + 0x400 : nb + 0x404])
        after_blocks, _ = eel_parse_pool(lay, bus.dflash)
        assert after_blocks[next_vb]["state"] == "active"
        assert extract_fpke_immo_passport(bus.dflash)["immo"]["vin"] == "WAUZZZ8V9LA999888"
    finally:
        close_active_fpke_link()


def test_fpke_coil_finish_passes_restore_key_flags_via_gateway(monkeypatch) -> None:
    """Critical C4 regression: finishing coil learning via gateway must pass restore_key_flags to preserve KESSY."""
    from contitool.gui.app import create_window
    from contitool.gui.screens import fpke as fpke_gui_mod

    app, win = create_window()
    try:
        captured_kwargs: dict[str, object] = {}

        def _fake_finish(link, **kw):
            captured_kwargs.update(kw)
            return {
                "ok": True,
                "summary": "ok",
                "learned_keys": 1,
                "remaining_keys": 7,
                "learned_key_ids": ["11223344"],
                "kessy_restored": True,
            }

        monkeypatch.setattr(fpke_gui_mod, "fpke_finish_coil_key_learning", _fake_finish)
        df_info = analyze_fpke_dflash(build_synthetic_fpke_dflash())
        dlg = fpke_gui_mod.FpkeCoilKeyLearnDialog(
            win.conn,
            win.runner,
            dflash_info=df_info,
            via_gateway=True,
            gateway_bridge=True,
            gateway_channel=0,
            parent=win,
        )
        try:
            dlg._key_flags = 0x80
            monkeypatch.setattr(
                dlg,
                "_run_l8_task",
                lambda title, action, on_ok, needs_level8=True: (
                    captured_kwargs.setdefault("_needs_level8", needs_level8),
                    action(object(), None),
                ),
            )
            dlg.run_finish_learning()
            assert captured_kwargs.get("_needs_level8") is True
            assert captured_kwargs.get("restore_key_flags") == 0x80
        finally:
            dlg.close()
    finally:
        win.close()


def test_fpke_verify_s0_s1_and_fbl_rsa_key_reject_invalid_inputs() -> None:
    from contitool.core.fpke import apply_fpke_dflash_fbl_rsa_key, fpke_verify_s0_s1

    s0 = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    s1 = bytes.fromhex("1112131415161718191a1b1c1d1e1f20")
    with pytest.raises(ValueError, match="expected_crc_a_le"):
        fpke_verify_s0_s1(s0, s1, expected_crc_a_le="DEADBE")
    with pytest.raises(ValueError, match="expected_crc_b_le"):
        fpke_verify_s0_s1(s0, s1, expected_crc_b_le=b"\xde\xad")
    assert fpke_verify_s0_s1(s0, s1, expected_crc_a_le="", expected_crc_b_le=None)["valid"] is True

    df = build_synthetic_fpke_dflash()
    with pytest.raises(ValueError, match="RSA-1024"):
        apply_fpke_dflash_fbl_rsa_key(df, b"\xff" * 128)


def test_fpke_donor_transfer_preserves_target_fields_on_partial_donor() -> None:
    from contitool.core.fpke import extract_fpke_immo_passport, transfer_fpke_donor_to_target

    target_df = build_synthetic_fpke_dflash()
    before = extract_fpke_immo_passport(target_df)
    partial_donor = {
        "immo": {
            "vin": None,
            "cs": None,
            "crc32_a_le": None,
            "crc32_b_le": None,
            "power_class": None,
            "power_class_int": None,
            "mode_and_flags": {},
            "mac_fields": {},
            "partners": [],
            "keys": [],
            "counts": {},
        },
        "component_protection_separate": {},
        "cluster_metadata": {},
    }
    updated_df, summary = transfer_fpke_donor_to_target(
        partial_donor,
        target_df,
        copy_immo=True,
        copy_keys=True,
        copy_odometer=True,
        copy_cp=True,
    )
    after = extract_fpke_immo_passport(updated_df)
    assert after["immo"]["vin"] == before["immo"]["vin"]
    assert after["immo"]["cs"] == before["immo"]["cs"]
    assert after["immo"]["mac_fields"]["dash"] == before["immo"]["mac_fields"]["dash"]
    assert after["immo"]["mode_and_flags"]["partners_mask"] == before["immo"]["mode_and_flags"]["partners_mask"]
    assert after["immo"]["keys"] == before["immo"]["keys"]
    assert after["component_protection_separate"]["ika_cp3"] == before["component_protection_separate"]["ika_cp3"]
    assert summary["copied_sections"] == {"immo": False, "keys": False, "odometer": False, "cp": False}


def test_fpke_eel_rollover_ec0_and_non_contiguous_ring_start() -> None:
    from contitool.core.fpke import eel_append_records, eel_parse_pool

    lay = fpke_eel_layout(None, build_synthetic_fpke_dflash())
    # 1. Non-contiguous active blocks across wrap 27 -> 0 -> 2 (VB 1 missing/prepared)
    df = bytearray(b"\xff" * FPKE_DFLASH_SIZE)
    for vb_idx, ec_val, val_u32 in ((27, 10, 10000), (0, 11, 20000), (2, 11, 30000)):
        b = vb_idx * lay["vb"]
        struct.pack_into("<6I", df, b, 0xFFFFFFFF, EEL_MARK, EEL_MARK, EEL_MARK, eel_cs24(ec_val), eel_cs24(b + 0x18))
        rec = bytearray(b"\x00" * lay["ids"][0x60])
        struct.pack_into("<H", rec, 0, lay["ids"][0x60])
        struct.pack_into("<I", rec, 4, val_u32)
        padded = (len(rec) + 3) & ~3
        top = b + lay["vb"] - 8
        for i in range(0, padded, 4):
            df[top - i : top - i + 4] = rec[i : i + 4]
        struct.pack_into("<4I", df, b + 0x18, EEL_MARK, EEL_MARK, EEL_MARK, 0x60 | ((top - b) << 16))
    blocks, latest = eel_parse_pool(lay, bytes(df))
    assert latest[0x60][0] == 2

    # 2. Rollover with head ec=0 into prepared next_vb ec=0 must preserve ec=0 (not bump to 1)
    df0 = bytearray(b"\xff" * FPKE_DFLASH_SIZE)
    b0 = 5 * lay["vb"]
    struct.pack_into("<6I", df0, b0, 0xFFFFFFFF, EEL_MARK, EEL_MARK, EEL_MARK, eel_cs24(0), eel_cs24(b0 + 0x18))
    # Fill VB 5 so next append rolls over to VB 6 (prepared with ec=0)
    b1 = 6 * lay["vb"]
    struct.pack_into("<5I", df0, b1, 0xFFFFFFFF, EEL_MARK, 0xFFFFFFFF, 0xFFFFFFFF, eel_cs24(0))
    # Leave VB 7 prepared so pool has a free block
    b2 = 7 * lay["vb"]
    struct.pack_into("<5I", df0, b2, 0xFFFFFFFF, EEL_MARK, 0xFFFFFFFF, 0xFFFFFFFF, eel_cs24(0))
    rec_68 = bytearray(b"\x00" * lay["ids"][0x68])
    struct.pack_into("<H", rec_68, 0, lay["ids"][0x68])
    cur = bytes(df0)
    for k in range(15):
        rec_68[4] = k + 1
        cur = eel_append_records(cur, {0x68: bytes(rec_68)})
    blocks_after, latest_after = eel_parse_pool(lay, cur)
    assert latest_after[0x68][0] == 6
    assert blocks_after[6]["ec"] == 0


def test_fpke_restore_dialog_rejects_fpke_dflash_and_start_screen_hides_restore(tmp_path) -> None:
    from contitool.gui.app import create_window
    from contitool.gui.dialogs.restore import RestoreDialog

    _app, win = create_window()
    try:
        win.start_screen.set_target_kind("fpke")
        assert win.start_screen.btn_restore.isVisible() is False

        df_path = tmp_path / "Dflash.bin"
        df_path.write_bytes(build_synthetic_fpke_dflash())
        dlg = RestoreDialog(win, str(tmp_path))
        try:
            rejected = dlg.add_files([df_path])
            assert rejected == ["Dflash.bin"]
            assert "dflash" not in dlg.files
        finally:
            dlg.close()
    finally:
        win.close()


def test_fpke_h7_faci_word_mask_invalid_vb_and_drp_blank_words() -> None:
    """H7 regression: invalid VBs never resurrect as active or degrade to prepared, and blank DRP words stay BCST 0."""
    from contitool.core.fpke import eel_parse_pool

    lay = fpke_eel_layout()
    vb_sz = lay["vb"]

    def _make_r60(val_u32: int) -> bytes:
        rec = bytearray(b"\xff" * lay["ids"][0x60])
        rec[:2] = struct.pack("<H", len(rec))
        struct.pack_into("<3I", rec, 4, val_u32, val_u32, val_u32)
        return bytes(rec)

    def _write_rec_top(buf: bytearray, b: int, top_off: int, rec: bytes) -> None:
        padded = rec + b"\xff" * (((len(rec) + 3) & ~3) - len(rec))
        for i in range(0, len(padded), 4):
            buf[b + top_off - i : b + top_off - i + 4] = padded[i : i + 4]

    # (a) Noisy dump with RWP-linked invalid chain (VB 14 inv -> VB 15 inv), active VB 16, invalid VB 17 (RWP-linked!)
    df = bytearray(b"\x57\x55\x54\x55" * (FPKE_DFLASH_SIZE // 4))
    r60_a = _make_r60(1000)
    r60_b = _make_r60(2000)
    r60_c = _make_r60(3000)
    r60_d = _make_r60(4000)
    top0 = vb_sz - 8
    drp0 = 0x60 | (top0 << 16)

    for vb_idx, is_inv, rwp_target, rec in (
        (14, True, 13 * vb_sz + 0x18, r60_a),
        (15, True, 14 * vb_sz + 0x28, r60_b),
        (16, False, 15 * vb_sz + 0x28, r60_c),
        (17, True, 16 * vb_sz + 0x28, r60_d),
    ):
        b = vb_idx * vb_sz
        struct.pack_into(
            "<6I",
            df,
            b,
            EEL_MARK if is_inv else 0x57555455,
            EEL_MARK,
            EEL_MARK,
            EEL_MARK,
            eel_cs24(10),
            eel_cs24(rwp_target),
        )
        struct.pack_into("<I", df, b + vb_sz - 4, EEL_MARK if is_inv else 0x57555455)
        _write_rec_top(df, b, top0, rec)
        struct.pack_into("<4I", df, b + 0x18, EEL_MARK, EEL_MARK, EEL_MARK, drp0)

    mask = eel_faci_word_mask(lay, bytes(df))
    blocks, latest = eel_parse_pool(lay, bytes(df), mask)
    assert blocks[14]["state"] == "invalid"
    assert blocks[15]["state"] == "invalid"
    assert blocks[16]["state"] == "active"
    assert blocks[17]["state"] == "invalid"
    assert latest[0x60][0] == 16

    # (a2) RWP-linked invalid pair (VB 14 inv -> VB 15 inv) + standalone active VB 20 (exercises len(best_chain) <= 1)
    df2 = bytearray(b"\x57\x55\x54\x55" * (FPKE_DFLASH_SIZE // 4))
    for vb_idx, is_inv, rwp_target, rec in (
        (14, True, 13 * vb_sz + 0x18, r60_a),
        (15, True, 14 * vb_sz + 0x28, r60_b),
        (20, False, 19 * vb_sz + 0x18, r60_c),
    ):
        b = vb_idx * vb_sz
        struct.pack_into(
            "<6I",
            df2,
            b,
            EEL_MARK if is_inv else 0x57555455,
            EEL_MARK,
            EEL_MARK,
            EEL_MARK,
            eel_cs24(10),
            eel_cs24(rwp_target),
        )
        struct.pack_into("<I", df2, b + vb_sz - 4, EEL_MARK if is_inv else 0x57555455)
        _write_rec_top(df2, b, top0, rec)
        struct.pack_into("<4I", df2, b + 0x18, EEL_MARK, EEL_MARK, EEL_MARK, drp0)

    mask2 = eel_faci_word_mask(lay, bytes(df2))
    blocks2, _ = eel_parse_pool(lay, bytes(df2), mask2)
    assert blocks2[14]["state"] == "invalid"
    assert blocks2[15]["state"] == "invalid"
    assert blocks2[20]["state"] == "active"

    # (b) Invalid VBs from the CURRENT erase cycle (ec == current_ec) must NOT degrade to prepared in has_fg_noise
    df3 = bytearray(b"\x57\x55\x54\x55" * (FPKE_DFLASH_SIZE // 4))
    # Active VB 5 at EC=12
    b5 = 5 * vb_sz
    struct.pack_into("<6I", df3, b5, 0x57555455, EEL_MARK, EEL_MARK, EEL_MARK, eel_cs24(12), eel_cs24(4 * vb_sz + 0x18))
    _write_rec_top(df3, b5, top0, r60_a)
    struct.pack_into("<4I", df3, b5 + 0x18, EEL_MARK, EEL_MARK, EEL_MARK, drp0)
    # Invalid VB 3 at EC=12 (before active VB 5, no succ, no RWP)
    b3 = 3 * vb_sz
    struct.pack_into("<5I", df3, b3, EEL_MARK, EEL_MARK, EEL_MARK, EEL_MARK, eel_cs24(12))
    struct.pack_into("<I", df3, b3 + vb_sz - 4, EEL_MARK)
    # Invalid VB 10 at EC=12 (with valid RWP, no succ)
    b10 = 10 * vb_sz
    struct.pack_into("<6I", df3, b10, EEL_MARK, EEL_MARK, EEL_MARK, EEL_MARK, eel_cs24(12), eel_cs24(9 * vb_sz + 0x18))
    struct.pack_into("<I", df3, b10 + vb_sz - 4, EEL_MARK)
    # Prepared VB 6 at EC=12 (ahead of active VB 5, ghost A0, no RWP, no valid DRP)
    b6 = 6 * vb_sz
    struct.pack_into("<5I", df3, b6, 0x57555455, EEL_MARK, EEL_MARK, 0x57555455, eel_cs24(12))

    mask3 = eel_faci_word_mask(lay, bytes(df3))
    blocks3, _ = eel_parse_pool(lay, bytes(df3), mask3)
    assert blocks3[3]["state"] == "invalid"
    assert blocks3[5]["state"] == "active"
    assert blocks3[6]["state"] == "prepared"
    assert blocks3[10]["state"] == "invalid"

    # (c) Blank/unprogrammed 0xFFFFFFFF word at DRP a+4 or a+8 must remain BCST 0 (0x00*4)
    df4 = bytearray(b"\xff" * FPKE_DFLASH_SIZE)
    b2 = 2 * vb_sz
    struct.pack_into("<6I", df4, b2, 0xFFFFFFFF, EEL_MARK, EEL_MARK, EEL_MARK, eel_cs24(10), eel_cs24(1 * vb_sz + 0x18))
    rec_sz_pad = (lay["ids"][0x60] + 3) & ~3
    top1 = top0 - rec_sz_pad
    _write_rec_top(df4, b2, top0, r60_a)
    _write_rec_top(df4, b2, top1, r60_b)
    # DRP 0: a+4 is unprogrammed 0xFFFFFFFF, a+8 is EEL_MARK
    ref0 = b2 + 0x18
    struct.pack_into("<4I", df4, ref0, EEL_MARK, 0xFFFFFFFF, EEL_MARK, 0x60 | (top0 << 16))
    # DRP 1: a+4 is EEL_MARK, a+8 is unprogrammed 0xFFFFFFFF
    ref1 = b2 + 0x28
    struct.pack_into("<4I", df4, ref1, EEL_MARK, EEL_MARK, 0xFFFFFFFF, 0x60 | (top1 << 16))

    mask4 = eel_faci_word_mask(lay, bytes(df4))
    assert mask4[ref0 : ref0 + 4] == b"\xff\xff\xff\xff"
    assert mask4[ref0 + 4 : ref0 + 8] == b"\x00\x00\x00\x00"
    assert mask4[ref0 + 8 : ref0 + 12] == b"\xff\xff\xff\xff"
    assert mask4[ref0 + 12 : ref0 + 16] == b"\xff\xff\xff\xff"
    assert mask4[ref1 : ref1 + 4] == b"\xff\xff\xff\xff"
    assert mask4[ref1 + 4 : ref1 + 8] == b"\xff\xff\xff\xff"
    assert mask4[ref1 + 8 : ref1 + 12] == b"\x00\x00\x00\x00"
    assert mask4[ref1 + 12 : ref1 + 16] == b"\xff\xff\xff\xff"
    blocks4, latest4 = eel_parse_pool(lay, bytes(df4), mask4)
    assert blocks4[2]["refs"] == 2
    assert latest4[0x60][1] == b2 + top1


def test_fpke_h9_cflash_rsa_patch_rejects_custom_state() -> None:
    """H9 regression: apply_fpke_cflash_rsa_patch refuses to blindly overwrite state=='custom' unless allow_custom=True."""
    from contitool.core.fpke import (
        FPKE_CFLASH_MEMCHECK_APP_OFFSET,
        analyze_fpke_cflash_bootloader,
        apply_fpke_cflash_rsa_patch,
        fpke_crc32_app,
    )

    cf_stock = build_synthetic_fpke_cflash()
    info_stock = analyze_fpke_cflash_bootloader(cf_stock)
    assert info_stock["state"] == "stock"

    # Mutate one of the 4 BOLO RSA check literal bytes to a custom instruction and update MemCheckCrcTblApp[0]
    cf_custom = bytearray(cf_stock)
    cf_custom[info_stock["patch_cflash_offsets_int"][0]] ^= 0x0F
    s1, _s2, length, _old_crc, _flag = struct.unpack_from("<5I", cf_custom, FPKE_CFLASH_MEMCHECK_APP_OFFSET)
    struct.pack_into(
        "<I",
        cf_custom,
        FPKE_CFLASH_MEMCHECK_APP_OFFSET + 12,
        fpke_crc32_app(bytes(cf_custom[s1 : s1 + length])),
    )
    cf_custom_bytes = bytes(cf_custom)
    assert analyze_fpke_cflash_bootloader(cf_custom_bytes)["state"] == "custom"

    set_lang("en")
    with pytest.raises(ValueError, match="custom"):
        apply_fpke_cflash_rsa_patch(cf_custom_bytes, restore_stock=False)
    set_lang("ru")
    with pytest.raises(ValueError, match="custom"):
        apply_fpke_cflash_rsa_patch(cf_custom_bytes, restore_stock=True)

    # Explicit opt-in allow_custom=True permits patching/restoring
    cf_eng, after_eng = apply_fpke_cflash_rsa_patch(cf_custom_bytes, restore_stock=False, allow_custom=True)
    assert after_eng["state"] == "engineering"
    assert after_eng["memcheck_bolo_entry"]["valid"] is True
    _cf_rest, after_stock = apply_fpke_cflash_rsa_patch(cf_custom_bytes, restore_stock=True, allow_custom=True)
    assert after_stock["state"] == "stock"
    assert after_stock["memcheck_bolo_entry"]["valid"] is True
    assert cf_eng != cf_custom_bytes


def test_fpke_h10_dflash_edits_s0_s1_flag_and_eel67_sync() -> None:
    """H10 regression: EEL 0x69 edits sync r68[0x44] bit 0, and EEL 0x67 edits align queue_count/learned/blank slots."""
    from contitool.core.fpke import (
        apply_fpke_dflash_edits,
        eel_append_records,
        eel_read_record_any,
        extract_fpke_immo_passport,
    )

    lay = fpke_eel_layout()
    base_df = build_synthetic_fpke_dflash()

    # Set cp_deferred (bit 1 = 0x02) in r68[0x44] to confirm bit 0 sync preserves unrelated flag bits
    r68_orig, _ = eel_read_record_any(lay, base_df, 0x68)
    r68_mut = bytearray(r68_orig)
    r68_mut[0x44] = 0x02
    df_flags = eel_append_records(base_df, {0x68: bytes(r68_mut)})

    # 1. Writing S0/S1 in EEL 0x69 must set r68[0x44] bit 0 (s0_s1_stored_in_0x69 == True) while keeping bit 1
    df_s0_s1 = apply_fpke_dflash_edits(df_flags, slot_s0_hex="11" * 16, slot_s1_hex="22" * 16)
    p_set = extract_fpke_immo_passport(df_s0_s1)
    assert p_set["immo"]["s0_s1"]["state"] == "present"
    assert p_set["immo"]["mode_and_flags"]["s0_s1_stored_in_0x69"] is True
    assert p_set["immo"]["mode_and_flags"]["cp_deferred"] is True
    r68_after_set, _ = eel_read_record_any(lay, df_s0_s1, 0x68)
    assert r68_after_set[0x44] == 0x03

    # 2. Clearing S0/S1 back to FF*16 must clear r68[0x44] bit 0 while preserving bit 1
    df_cleared = apply_fpke_dflash_edits(df_s0_s1, slot_s0_hex="FF" * 16, slot_s1_hex="FF" * 16)
    p_clr = extract_fpke_immo_passport(df_cleared)
    assert p_clr["immo"]["s0_s1"]["state"] == "empty_expected_in_mode_1"
    assert p_clr["immo"]["mode_and_flags"]["s0_s1_stored_in_0x69"] is False
    assert p_clr["immo"]["mode_and_flags"]["cp_deferred"] is True
    r68_after_clr, _ = eel_read_record_any(lay, df_cleared, 0x68)
    assert r68_after_clr[0x44] == 0x02

    # 3. EEL 0x67 sync from blank 0xFF record: byte +0x24 is queue_count (0, NOT learned_keys!), compact keys & blank tail
    r67_blank = bytearray(b"\xff" * lay["ids"][0x67])
    r67_blank[:2] = struct.pack("<H", len(r67_blank))
    df_blank_67 = eel_append_records(base_df, {0x67: bytes(r67_blank)})

    df_k2 = apply_fpke_dflash_edits(df_blank_67, key_display_ids=["11223344", None, "55667788"])
    info_k2 = analyze_fpke_dflash(df_k2)
    tp2 = info_k2["transponder_records"]
    assert tp2["learned_keys"] == 2
    assert tp2["allowed_keys"] == 2
    assert tp2["queue_count"] == 0
    assert tp2["queue_pending_mask"] == 0
    assert tp2["queue_flags"] == 0
    assert tp2["display_ids"] == ["11223344", "55667788"] + [None] * 6
    assert [k["state"] for k in tp2["key_ids"]] == ["active", "active"] + ["empty"] * 6

    # 4. Reducing learned_keys clears trailing slots >= learned_keys to 0xFFFFFFFF (no outside_learned_count)
    df_k1 = apply_fpke_dflash_edits(df_k2, learned_keys=1)
    tp1 = analyze_fpke_dflash(df_k1)["transponder_records"]
    assert tp1["learned_keys"] == 1
    assert tp1["display_ids"] == ["11223344"] + [None] * 7
    assert [k["state"] for k in tp1["key_ids"]] == ["active"] + ["empty"] * 7

    # 5. Requesting learned_keys > populated keys clamps to populated count
    df_clamp = apply_fpke_dflash_edits(df_k1, learned_keys=5)
    assert analyze_fpke_dflash(df_clamp)["transponder_records"]["learned_keys"] == 1


def test_fpke_m6a_layout_early_magic_dflash_validation_02f7_secondary_macs_and_pool_exhausted() -> None:
    """M6a regression: early magic search, DFlash size/power_class/odo checks, 02F7 guards, secondary MACs, pool exhaustion."""
    from contitool.core.fpke import (
        FDL_POOL_MAGIC_120MHZ,
        FPKE_CFLASH_SIZE,
        apply_fpke_dflash_edits,
        build_fpke_02f7_payload,
        compare_fpke_immo_passports,
        eel_append_records,
    )

    # 1. fpke_eel_layout must NOT abort when FDL_POOL_MAGIC appears at offset < 0x10
    cf = bytearray(b"\xff" * FPKE_CFLASH_SIZE)
    cf[0x04 : 0x04 + len(FDL_POOL_MAGIC_120MHZ)] = FDL_POOL_MAGIC_120MHZ
    idl_off = 0x100000
    custom_ids = [(1, 16), (2, 32), (3, 64)]
    for idx, (eid, esz) in enumerate(custom_ids):
        struct.pack_into("<HH", cf, idl_off + 4 * idx, eid, esz)
    desc_off = 0x180000
    struct.pack_into("<HHIIH", cf, desc_off, 32, 8, idl_off, 0, len(custom_ids))
    cf[desc_off + 0x10 : desc_off + 0x18] = FDL_POOL_MAGIC_120MHZ
    lay_found = fpke_eel_layout(bytes(cf))
    assert lay_found["ids"] == {1: 16, 2: 32, 3: 64}

    # 2. apply_fpke_dflash_edits upfront size check, power_class="-"/"—"/"", and odd odometer_km validation
    base_df = build_synthetic_fpke_dflash()
    with pytest.raises(ValueError):
        apply_fpke_dflash_edits(b"\xff" * 128)
    for dash_pc in ("-", "—", "", "  -  "):
        df_pc = apply_fpke_dflash_edits(base_df, power_class=dash_pc)
        r68_pc, _ = __import__("contitool.core.fpke", fromlist=["eel_read_record_any"]).eel_read_record_any(
            fpke_eel_layout(), df_pc, 0x68
        )
        assert r68_pc[0x40] == 0xFF
    with pytest.raises(ValueError):
        apply_fpke_dflash_edits(base_df, power_class="ZZ")
    with pytest.raises(ValueError):
        apply_fpke_dflash_edits(base_df, odometer_km=12345)

    # 3. build_fpke_02f7_payload rejects 0xAA*16 / 0xFF*16 / 0x00*16 / empty for S0, S1, current_kc, new_kc
    good_s0 = bytes(range(1, 17))
    good_s1 = bytes(range(17, 33))
    good_kc = bytes(range(33, 49))
    req, plain = build_fpke_02f7_payload(
        vin="TESTVIN0123456789",
        s0=good_s0,
        s1=good_s1,
        current_kc=good_kc,
        power_class=0x4C,
        allowed_keys=2,
    )
    assert len(req) == 87 and len(plain) == 80
    for bad_key in (b"\xaa" * 16, b"\xff" * 16, b"\x00" * 16, b""):
        with pytest.raises(ValueError):
            build_fpke_02f7_payload(
                vin="TESTVIN0123456789",
                s0=good_s0,
                s1=good_s1,
                current_kc=good_kc,
                new_kc=bad_key,
                power_class=0x4C,
                allowed_keys=2,
            )
    with pytest.raises(ValueError):
        build_fpke_02f7_payload(
            vin="TESTVIN0123456789",
            s0=b"\xaa" * 16,
            s1=good_s1,
            current_kc=good_kc,
            power_class=0x4C,
            allowed_keys=2,
        )
    with pytest.raises(ValueError):
        build_fpke_02f7_payload(
            vin="TESTVIN0123456789",
            s0=good_s0,
            s1=good_s1,
            current_kc=b"\xaa" * 16,
            power_class=0x4C,
            allowed_keys=2,
        )

    # 4. compare_fpke_immo_passports must compare secondary partner MACs (MSG_2, MSG_3, MSG_4, OCU, VTS)
    df_sec_a = apply_fpke_dflash_edits(base_df, partner_macs={"MSG_2": "1234", "OCU": "ABCD"})
    df_sec_b = apply_fpke_dflash_edits(base_df, partner_macs={"MSG_2": "1234", "OCU": "BEEF"})
    cmp_diff = compare_fpke_immo_passports(df_sec_a, df_sec_b)
    assert cmp_diff["field_checks"]["mac_fields"] is True
    assert cmp_diff["field_checks"]["partner_macs"] is False
    assert cmp_diff["semantic_match"] is False
    assert "partner_macs" in cmp_diff["mismatched_fields"]
    assert compare_fpke_immo_passports(df_sec_a, df_sec_a)["semantic_match"] is True

    # 5. Bilingual EEL pool exhausted error matches in both RU and EN
    lay = fpke_eel_layout()
    exhausted = bytearray(b"\xff" * FPKE_DFLASH_SIZE)
    for n in range(28):
        b = n * 0x800
        ec = 11 if n < 27 else 10
        struct.pack_into("<5I", exhausted, b, 0xFFFFFFFF, EEL_MARK, 0xFFFFFFFF, 0xFFFFFFFF, eel_cs24(ec))
    for n in range(26):
        b = n * 0x800
        struct.pack_into("<I", exhausted, b + 0x08, EEL_MARK)
        struct.pack_into("<I", exhausted, b + 0x14, eel_cs24(((n - 1) % 28) * 0x800 + 0x18))
        struct.pack_into("<I", exhausted, b + 0x0C, EEL_MARK)
    b27 = 27 * 0x800
    struct.pack_into("<I", exhausted, b27 + 0x08, EEL_MARK)
    struct.pack_into("<I", exhausted, b27 + 0x14, eel_cs24(26 * 0x800 + 0x18))
    struct.pack_into("<I", exhausted, b27 + 0x0C, EEL_MARK)
    for lang in ("en", "ru"):
        set_lang(lang)
        cur = bytes(exhausted)
        with pytest.raises(RuntimeError, match="EEL pool"):
            for seq in range(10):
                cur = eel_append_records(cur, {1: struct.pack("<H", 252) + bytes([seq]) * 250})


def test_fpke_h25_m3_gateway_guards_log_lock_and_superseded_link_close(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """H25 + M3a/b regression: via_gateway refuses KL15/drive-sim, _log_lock prevents close race, open_or_reuse closes superseded link."""
    import threading
    from contitool.can import fpke as can_fpke_mod
    from contitool.can.fpke import close_active_fpke_link, open_or_reuse_fpke_link

    # 1. H25: via_gateway=True refuses set_kl15 and start_drive_simulation without sending any Komfort CAN frames
    gw_bus = FakeFpkeBus()
    gw_link = FpkeCanLink("fake-gw", interface="slcan", bus=gw_bus, via_gateway=True)
    try:
        set_lang("en")
        with pytest.raises(RuntimeError, match="gateway"):
            gw_link.set_kl15(True)
        with pytest.raises(RuntimeError, match="gateway"):
            gw_link.set_kl15(False)
        with pytest.raises(RuntimeError, match="gateway"):
            gw_link.start_drive_simulation()
        assert gw_link.tx_frames == 0
        assert gw_link.is_keepalive_running() is False
        assert gw_link.is_drive_simulation_running() is False
    finally:
        gw_link.close()

    # 2. M3a: concurrent _record_frame and close() with log file must not raise ValueError on closed file
    log_file = tmp_path / "race.jsonl"
    race_link = FpkeCanLink("fake-race", interface="slcan", bus=FakeFpkeBus(), log_path=log_file)
    errors: list[Exception] = []
    stop_evt = threading.Event()

    def _writer() -> None:
        while not stop_evt.is_set():
            try:
                race_link._record_frame("tx", 0x3C0, False, b"\x00\x00\x03\x00")
            except Exception as exc:
                errors.append(exc)
                break

    t = threading.Thread(target=_writer, daemon=True)
    t.start()
    try:
        for _ in range(20):
            race_link._record_frame("tx", 0x663, False, b"\x00" * 8)
        race_link.close()
        stop_evt.set()
        t.join(timeout=2.0)
    finally:
        stop_evt.set()
        t.join(timeout=2.0)
    assert errors == []

    # 3. M3b: open_or_reuse_fpke_link closes any link installed concurrently while a new link is being constructed
    close_active_fpke_link()
    first_bus = FakeFpkeBus()
    second_bus = FakeFpkeBus()
    raced_link = FpkeCanLink("port-a", interface="slcan", bus=first_bus)
    orig_cls = can_fpke_mod.FpkeCanLink

    def _racing_ctor(*args, **kwargs):
        # Simulate another thread registering `raced_link` into `_ACTIVE_LINK` mid-construction
        with can_fpke_mod._ACTIVE_LINK_LOCK:
            can_fpke_mod._ACTIVE_LINK = raced_link
        return orig_cls(*args, **kwargs)

    monkeypatch.setattr(can_fpke_mod, "FpkeCanLink", _racing_ctor)
    try:
        winner = open_or_reuse_fpke_link("port-b", interface="slcan", bus=second_bus)
        assert raced_link.is_closed is True
        assert winner.is_closed is False
        assert can_fpke_mod.get_active_fpke_link("port-b", "slcan") is winner
    finally:
        monkeypatch.setattr(can_fpke_mod, "FpkeCanLink", orig_cls)
        close_active_fpke_link()


def test_gui_and_cli_remaining_high_guards(monkeypatch) -> None:
    """Regressions for H22 tail (MRR _xcp_available dynamic j2534), H25 (FPK_E gateway disables raw CAN), H26 (CLI --yes & dpdu)."""
    from contitool.cli.main import build_arg_parser, main as cli_main
    from contitool.gui.app import create_window

    set_lang("en")
    app, win = create_window()
    try:
        # H25 GUI: via_gateway disables raw Komfort CAN sender & presets
        win.fpke_screen.open_from_ident(
            {"ecu_kind": "fpke", "via_gateway": True, "gateway_bridge": True, "gateway_channel": 0, "ident": []}
        )
        win.fpke_screen.select("can_ctrl")
        app.processEvents()
        panel = win.fpke_screen._active_can_panel
        assert panel is not None
        assert panel.btn_send_pkt.isEnabled() is False
        assert panel.cmb_preset.isEnabled() is False

        # H22 tail: MRR _xcp_available() re-evaluates conn.interface dynamically on switch to j2534
        win.conn.interface = "slcan"
        win.mrr_screen.set_routing(via_gateway=False, gateway_bridge=False, gateway_channel=2)
        assert win.mrr_screen._xcp_available() is True
        win.conn.interface = "j2534"
        assert win.mrr_screen._xcp_available() is False
    finally:
        win.close()

    # H26 CLI: destructive BCM/MRR commands refuse without --yes, and dpdu/j2534 allow omitting --port
    parser = build_arg_parser()
    args_bcm_no_port = parser.parse_args(["bcm", "status", "--interface", "dpdu", "--via-gateway"])
    assert not args_bcm_no_port.port
    args_mrr_no_port = parser.parse_args(["mrr", "status", "--interface", "j2534", "--via-gateway"])
    assert not args_mrr_no_port.port

    rc_bcm = cli_main(["bcm", "write-keys", "--interface", "slcan", "--port", "fake", "--new-gfa", "11" * 16])
    assert rc_bcm != 0
    rc_mrr_wk = cli_main(["mrr", "write-keys", "--interface", "slcan", "--port", "fake", "--new-gfa", "11" * 16])
    assert rc_mrr_wk != 0
    rc_mrr_rst = cli_main(["mrr", "reset-cp-counter", "--interface", "slcan", "--port", "fake"])
    assert rc_mrr_rst != 0
    # fpke --interface dpdu without --via-gateway must fail cleanly
    rc_fpke_dpdu = cli_main(["fpke", "read", "--interface", "dpdu"])
    assert rc_fpke_dpdu != 0


def test_fpke_unverified_sw_allows_read_and_shows_pn_sw_warning(tmp_path: Path) -> None:
    from PySide6.QtWidgets import QApplication, QLabel

    from contitool.can.fpke import can_fpke_full_read
    from contitool.core.fpke import fpke_support_info
    from contitool.gui.main_window import MainWindow
    from contitool.i18n import set_lang
    from contitool.progress import OperationReporter

    set_lang("ru")
    # Verified SW versions -> no warning
    assert fpke_support_info(f187="83A920700E", f189="6181")["warning"] is None
    assert fpke_support_info(f187="5NA920790D", f189="1701")["warning"] is None
    assert fpke_support_info(f187="5E0920790A", f189="1703")["warning"] is None
    assert fpke_support_info(f187="5E0920790A", f189="1711")["warning"] is None

    # Unverified SW or non-Continental cluster -> warning with PN + SW, still non-blocking
    sup_unk = fpke_support_info(f187="5G1920791B", f189="4191", f197="KOMBI VISTEON")
    assert sup_unk["verified"] is False
    assert sup_unk["warning"] and "5G1920791B" in sup_unk["warning"] and "4191" in sup_unk["warning"]
    assert "официально не поддерживается" in sup_unk["warning"]

    bus = FakeFpkeBus(sw_profile="83a")
    bus.ident_map[0xF187] = b"83A920700B "
    bus.ident_map[0xF189] = b"0295"
    warns: list[str] = []

    class RecRep(OperationReporter):
        def warning(self, message: str) -> None:
            warns.append(message)

    rep = can_fpke_full_read(
        "fake",
        session_dir=tmp_path,
        frame_delay=0.0,
        wake_seconds=0.0,
        bus=bus,
        reporter=RecRep(),
    )
    assert rep["officially_supported"] is False
    assert rep["support_warning"] and "83A920700B" in rep["support_warning"] and "0295" in rep["support_warning"]
    assert any("83A920700B" in w and "0295" in w for w in warns)

    # FpkeScreen renders support warning callout
    app = QApplication.instance() or QApplication([])
    win = MainWindow()
    try:
        win.fpke_screen.open_from_ident(
            {
                "ident": [
                    {"did": "F187", "label_ru": "Номер детали", "label_en": "Part", "value": "83A920700B"},
                    {"did": "F189", "label_ru": "ПО", "label_en": "SW", "value": "0295"},
                ]
            }
        )
        app.processEvents()
        page_w = win.fpke_screen.page_area.widget()
        texts = [lbl.text() for lbl in page_w.findChildren(QLabel)]
        assert any("83A920700B" in t and "0295" in t and "официально не поддерживается" in t for t in texts)
    finally:
        win.close()






