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
    can_fpke_full_read,
    can_fpke_read_region,
    detect_fpke_files,
    eel_cs24,
    flood_payload,
    format_fpke_report,
    fpke_eel_layout,
    is_fpke_dflash,
    is_fpke_extra_area,
    is_fpke_ident,
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


# ────────────────────────────── Simulated FPK_E CAN Bus ──────────────────────────────


class FakeFpkeBus:
    """Simulates an Audi FPK_E (83A920700E) instrument cluster on 0x714/0x77E, 0x1BFCA2xx, 0x17FA0E14, and 0x6F1."""

    def __init__(self, *, enable_stream_0x6f1: bool = True) -> None:
        self.enable_stream_0x6f1 = enable_stream_0x6f1
        self.rx: list[can.Message] = []
        self.dflash = build_synthetic_fpke_dflash()
        self.extra = build_synthetic_extra_area()
        self.cflash_head = FPKE_CFLASH_CONTROL_PREFIX + bytes(range(1, 13))
        self.ram: dict[int, bytes] = {
            FPKE_APPLET_ENTRY: b"\x11" * 256,
            FPKE_SOURCE_PARAM: b"\x22" * 8,
            FPKE_RESULT_ADDR: b"\x33" * FPKE_RESULT_SIZE,
            FPKE_MARKER_ADDR: b"\x44" * 32,
            FPKE_SAVED_RETURN: FPKE_CALLER_RETURN.to_bytes(4, "little"),
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
        self.ident_map = {
            0xF187: b"83A920700E ",
            0xF191: b"83A920700  ",
            0xF189: b"6181",
            0xF1A3: b"103",
            0xF197: b"FPK_E       ",
            0xF190: b"TESTVIN0123456789",
            0xF17C: b"XX0-00018.08.2300010000",
            0xF19E: b"EV_DashBoardAU27X",
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
                if self._stream_idx == FPKE_POINTER_FRAME and raw[:4] == FPKE_FORGED_PTR.to_bytes(4, "little"):
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
            return self.ram[addr][:size]
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
            elif addr == FPKE_SAVED_RETURN and data == FPKE_APPLET_ENTRY.to_bytes(4, "little"):
                param = self.ram.get(FPKE_SOURCE_PARAM, b"")
                if len(param) == 8:
                    # Streaming applet trigger
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
                        self.ram[FPKE_MARKER_ADDR] = b"SCAN" + self.ram[FPKE_MARKER_ADDR][4:]
                else:
                    # 256-byte buffer applet trigger
                    src_addr = int.from_bytes(param[:4], "little")
                    chunk256 = self._read_region_slice(src_addr, 256)
                    self.ram[FPKE_RESULT_ADDR] = chunk256 + b"SCAN"
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
    # 1. Fast RSCAN0 TM17 stream succeeds
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
    assert Path(res_fast["output"]).read_bytes() == bus_fast.dflash

    # 2. If 0x6F1 frames are dropped/blocked, automatically falls back to UDS 0x23
    bus_fallback = FakeFpkeBus(enable_stream_0x6f1=False)
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
        app.processEvents()
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
        assert bus.ram[FPKE_83A_RAM_EEL68_ADDR + 0x42][7] == 0x04  # mode 4

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
