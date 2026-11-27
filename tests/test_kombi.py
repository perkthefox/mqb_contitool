"""Tests for the separate 17 Kombi VDD (V850E2/Dx4, SW 0310, Supplier Level 7) handler."""

from __future__ import annotations

from pathlib import Path
import struct
from typing import Any
import zlib

from contitool.can.ecus import ECU_SPEC_BY_KIND, _build_slave_ecu, get_ecu_spec
from contitool.can.kombi import (
    can_kombi_write_dflash,
    kombi_authenticate_fd11,
    kombi_check_sl7,
    kombi_ensure_sl7,
    kombi_extract_live_s0_s1_from_coil,
    kombi_extract_sl7_key,
    kombi_prepare_additive_coil_learning,
    kombi_read_all_eel_in_session,
)
from contitool.core.fpke import build_fd11_proof, fpke_slots_from_s0_s1, is_fpke_ident
from contitool.core.kombi import (
    EEL_KOMBI_0310_IDS,
    EEL_KOMBI_2220_IDS,
    KOMBI_2220_RAM_EEL67_ADDR,
    KOMBI_2220_RAM_EEL68_ADDR,
    KOMBI_2220_RAM_EEL69_ADDR,
    KOMBI_2220_RAM_EEL_PHYS_TABLE_ADDR,
    KOMBI_2220_RAM_FD11_STATE_ADDR,
    KOMBI_2220_RAM_IMMO_MODE_ADDR,
    KOMBI_2220_RAM_LAST_KEY_ID_ADDR,
    KOMBI_2220_RAM_ODO_DPOOL_ADDR,
    KOMBI_2220_RAM_ODO_METERS_ADDR,
    KOMBI_2220_RAM_RECOG_STATE_ADDR,
    KOMBI_2220_RAM_S0_ADDR,
    KOMBI_2220_RAM_SL7_KEY_ADDR,
    KOMBI_2220_RAM_SLOTS_FLAG_ADDR,
    KOMBI_2220_RAM_SLOT_A_ADDR,
    KOMBI_2220_RAM_SLOT_B_ADDR,
    KOMBI_2220_RAM_STAGING_ADDR,
    KOMBI_2220_RETAIN_ODO_DPOOL_ADDR,
    KOMBI_2220_SA1_DELTA,
    KOMBI_EEL_2220_LOGICAL_SIZE,
    KOMBI_EEL_LOGICAL_SIZE,
    KOMBI_NVM_BLOCK_CODING,
    KOMBI_NVM_BLOCK_IMMO,
    KOMBI_NVM_BLOCK_ODO,
    KOMBI_NVM_BLOCK_ODO_REPAIR,
    KOMBI_NVM_STAGED_EEL_MAP,
    KOMBI_RAM_EEL_PHYS_TABLE_ADDR,
    KOMBI_RAM_IMMO_MODE_ADDR,
    KOMBI_RAM_ODO_DPOOL_ADDR,
    KOMBI_RAM_ODO_METERS_ADDR,
    KOMBI_RAM_SL7_KEY_ADDR,
    KOMBI_RAM_STAGING_ADDR,
    KOMBI_RETAIN_ODO_DPOOL_ADDR,
    KOMBI_SA1_DELTA,
    analyze_kombi_dflash,
    apply_kombi_dflash_edits,
    build_kombi_eel_dflash,
    detect_kombi_files,
    extract_kombi_eel_updates,
    extract_kombi_immo_passport,
    format_kombi_report,
    format_kombi_transfer_plan,
    get_kombi_sw_profile,
    is_kombi_dflash,
    is_kombi_ident,
    kombi_crc16_ccitt,
    kombi_support_info,
    normalize_kombi_dflash_input,
    plan_kombi_a_to_b_transfer,
    summarize_kombi_dflash_changes,
    transfer_kombi_donor_to_target,
)


def _pack_with_crc32(payload: bytes) -> bytes:
    return payload + struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)


def _build_synthetic_kombi_records(
    *,
    vin: str = "XW8ZZZ5NZJG235992",
    part_number: str = "5NA920740B ",
    sw_version: str = "0310",
    sl6_key: bytes = bytes.fromhex("8268dcf2746cf6479f7e6fb4633f4ca0"),
    sl7_key: bytes = bytes.fromhex("b470743235eb2e588d41888aed960e42"),
    fd11_id: bytes = bytes.fromhex("100e100106003f0013021788797411"),
    cs_kc: bytes = bytes.fromhex("ea046275eea646ef01e6d703f77899db"),
    ika: bytes = bytes.fromhex("4d6b7c5472a7659bfbe10df4be36c44d"),
    gfa: bytes = bytes.fromhex("e54e0aab8198ebcd8e781cceb0a3b33c"),
    power_class: int = 0x49,
    odometer_km: int = 1000,
) -> dict[int, bytes]:
    records: dict[int, bytes] = {}
    for ident, sz in sorted(EEL_KOMBI_0310_IDS.items()):
        records[ident] = struct.pack("<H", sz) + (b"\xff" * (sz - 2))

    # 0x0030 (43 B): coding at +11..+31 (20 B) + big-endian CRC-16/CCITT-FALSE at +41..+43
    r30 = bytearray(struct.pack("<H", 43) + bytes.fromhex("25082600000000002e") + (b"\x00" * 32))
    r30[11:31] = bytes.fromhex("07a501002280000811883a011400000800000000")
    struct.pack_into(">H", r30, 41, kombi_crc16_ccitt(bytes(r30[2:41])))
    records[0x0030] = bytes(r30)

    # 0x0035 (4 B): odometer status
    records[0x0035] = struct.pack("<HBB", 4, 0, 0)

    # 0x0045 (95 B): SW version (+2..+6), ODX (+12..+32), and Part Number (+37..+49)
    r45 = bytearray(records[0x0045])
    r45[2:6] = sw_version.encode("ascii")[:4].ljust(4, b" ")
    r45[12:32] = b"EV_DashBoardVDDMQBAB"
    r45[37:49] = part_number.encode("ascii")[:12].ljust(12, b" ")
    r45[64:76] = part_number.encode("ascii")[:12].ljust(12, b" ")
    records[0x0045] = bytes(r45)

    # 0x0060 (16 B, eel_off = 4): +2..+3 is 0xFF 0xFF alignment padding, +4..+16 is 3 x uint32 LE of km // 2
    r60 = bytearray(struct.pack("<H", 16) + b"\xff\xff" + (b"\x00" * 12))
    half_km = odometer_km // 2
    struct.pack_into("<3I", r60, 4, half_km, half_km, half_km)
    records[0x0060] = bytes(r60)

    # 0x0063 (126 B): FD11 ID (+0x02, 20 B), SL6 key (+0x16, 20 B), SL7 key (+0x2A, 20 B), Slot 3 (+0x3E, 20 B), 32B (+0x52, 36 B), flags (+0x76, 8 B)
    r63 = bytearray(struct.pack("<H", 126) + (b"\xff" * 124))
    r63[0x02:0x16] = _pack_with_crc32(fd11_id.ljust(16, b"\xff"))
    r63[0x16:0x2A] = _pack_with_crc32(sl6_key)
    r63[0x2A:0x3E] = _pack_with_crc32(sl7_key)
    r63[0x3E:0x52] = _pack_with_crc32(bytes.fromhex("2a655da2b4c67a750a03b7aa6d499d6b"))
    r63[0x52:0x76] = _pack_with_crc32(bytes.fromhex("1415161702191c39") + (b"\xff" * 24))
    r63[0x76:0x7E] = _pack_with_crc32(bytes.fromhex("fc03fc03"))
    records[0x0063] = bytes(r63)

    # 0x0064 (146 B): Slot 5 (+0x02, 20 B), Slot 6 (+0x16, 20 B)
    r64 = bytearray(struct.pack("<H", 146) + (b"\xff" * 144))
    r64[0x02:0x16] = _pack_with_crc32(bytes.fromhex("36dfecfdefd7d4ec99f6152f755efdeb"))
    r64[0x16:0x2A] = _pack_with_crc32(b"\xff" * 16)
    records[0x0064] = bytes(r64)

    # 0x0066 (22 B): WFS5 MAC IDs (dash @ +0x02, ecu @ +0x04, elv @ +0x0C, tcu @ +0x0E)
    r66 = bytearray(struct.pack("<H", 22) + (b"\xff" * 20))
    r66[0x02:0x04] = bytes.fromhex("55bb")
    r66[0x04:0x06] = bytes.fromhex("1122")
    r66[0x10] = 0x00
    records[0x0066] = bytes(r66)

    # 0x0067 (39 B): Transponder IDs (8 x 4 B at +2..+34, allowed at +34, learned_flags at +35)
    r67 = bytearray(struct.pack("<H", 39) + (b"\xff" * 37))
    r67[2:6] = bytes.fromhex("d2032d00")
    r67[6:10] = bytes.fromhex("d9662d00")
    r67[0x22] = 8
    r67[0x23] = 2
    r67[0x24] = 2
    r67[0x25] = 0
    r67[0x26] = 0
    records[0x0067] = bytes(r67)

    # 0x0068 (128 B): VIN (+0x17..+0x28), Kc (+0x28..+0x38), PowerClass (+0x40), PartnersMask (+0x41), ImmoMode (+0x4B)
    r68 = bytearray(struct.pack("<H", 128) + (b"\x00" * 126))
    r68[0x17:0x28] = vin.encode("ascii")[:17].ljust(17, b" ")
    r68[0x28:0x38] = cs_kc
    r68[0x40] = power_class
    r68[0x41] = 0x03
    r68[0x44] = 0x01
    r68[0x4B] = 0x01
    r68[0x4C] = 0x01
    r68[0x4D] = 0x80
    records[0x0068] = bytes(r68)

    # 0x0069 (34 B): S0 (+0x02..+0x12) and S1 (+0x12..+0x22)
    r69 = bytearray(struct.pack("<H", 34) + (b"\x00" * 32))
    r69[0x02:0x12] = bytes.fromhex("dc1279b9c430833849c3f3d32a3c2bf6")
    r69[0x12:0x22] = bytes.fromhex("4a1c3810bc4f9c2ba7347cf0006fc829")
    records[0x0069] = bytes(r69)

    # 0x006B (50 B on Kombi 0310): CP /4 master VIN tail (+0x02..+0x12), CP /1 GFA (+0x12..+0x22), CP /3 IKA (+0x22..+0x32)
    r6b = bytearray(struct.pack("<H", 50) + (b"\xff" * 48))
    r6b[0x02:0x12] = b"M" * 16
    r6b[0x12:0x22] = gfa
    r6b[0x22:0x32] = ika
    records[0x006B] = bytes(r6b)

    return records


def test_kombi_ident_and_ecu_spec_separation() -> None:
    kombi_ident = [
        {"did": "F187", "value": "5NA920740B"},
        {"did": "F189", "value": "0310"},
        {"did": "F197", "value": "Kombi"},
        {"did": "F19E", "value": "EV_DashBoardVDDMQBAB"},
    ]
    fpke_ident = [
        {"did": "F187", "value": "5E0920790A"},
        {"did": "F189", "value": "1703"},
        {"did": "F197", "value": "Kombi FPK"},
        {"did": "F19E", "value": "EV_DashBoardFPKContinentMQBAB"},
    ]
    assert is_kombi_ident(kombi_ident) is True
    assert is_fpke_ident(kombi_ident) is False
    assert is_kombi_ident(fpke_ident) is False
    assert is_fpke_ident(fpke_ident) is True

    spec_kombi = get_ecu_spec("kombi")
    spec_fpke = get_ecu_spec("fpke")
    assert spec_kombi.kind == "kombi"
    assert spec_fpke.kind == "fpke"
    assert spec_kombi.diag_addr == "17"
    assert spec_fpke.diag_addr == "17"
    assert spec_kombi.uds_tx_id == 0x714
    assert spec_kombi.uds_rx_id == 0x77E
    assert spec_kombi.needs_bridge_for_memory is False
    assert spec_fpke.needs_bridge_for_memory is True
    assert "kombi" in ECU_SPEC_BY_KIND

    # Verify _build_slave_ecu automatically determines 'kombi' vs 'fpke' from block 17's UDS passport
    ecu_from_kombi = _build_slave_ecu(
        spec_fpke,
        kombi_ident,
        via_gateway=True,
        gateway_bridge_capable=False,
        interface="slcan",
        bus_injected=True,
        in_fbl=False,
    )
    assert ecu_from_kombi.kind == "kombi"
    assert ecu_from_kombi.memory_access_available is True

    ecu_from_fpke = _build_slave_ecu(
        spec_fpke,
        fpke_ident,
        via_gateway=True,
        gateway_bridge_capable=False,
        interface="slcan",
        bus_injected=True,
        in_fbl=False,
    )
    assert ecu_from_fpke.kind == "fpke"
    assert ecu_from_fpke.memory_access_available is False

    sup_ok = kombi_support_info(kombi_ident)
    assert sup_ok["verified"] is True
    assert sup_ok["warning"] is None


def test_kombi_dflash_build_analyze_edit_and_transfer(tmp_path: Path) -> None:
    recs = _build_synthetic_kombi_records()
    logical_blob = b"".join(recs[i] for i in sorted(EEL_KOMBI_0310_IDS))
    assert len(logical_blob) == KOMBI_EEL_LOGICAL_SIZE
    assert is_kombi_dflash(logical_blob) is True

    dflash_64k = build_kombi_eel_dflash(recs)
    assert len(dflash_64k) == 65536
    assert is_kombi_dflash(dflash_64k) is True
    assert normalize_kombi_dflash_input(logical_blob) == dflash_64k

    info = analyze_kombi_dflash(logical_blob)
    assert info["platform"] == "V850E2-KOMBI-0310"
    assert info["metadata"]["part_number"] == "5NA920740B"
    assert info["metadata"]["sw_version_eel"] == "0310"
    assert info["metadata"]["vin"] == "XW8ZZZ5NZJG235992"
    assert info["metadata"]["power_class_int"] == 0x49
    assert info["metadata"]["odometer_km"] == 1000
    keys_by_id = {it["key_id"]: it for it in info["items"]}
    assert keys_by_id["kc"]["hex"] == "ea046275eea646ef01e6d703f77899db"
    assert keys_by_id["fd11_l0_6"]["hex"] == "8268dcf2746cf6479f7e6fb4633f4ca0"
    assert keys_by_id["fd11_l0_6"]["crc_valid"] is True
    assert keys_by_id["fd11_l7"]["hex"] == "b470743235eb2e588d41888aed960e42"
    assert keys_by_id["fd11_l7"]["crc_valid"] is True
    assert keys_by_id["ika_cp3"]["hex"] == "4d6b7c5472a7659bfbe10df4be36c44d"
    assert keys_by_id["cp1_bank_0"]["hex"] == "e54e0aab8198ebcd8e781cceb0a3b33c"
    assert keys_by_id["cp4_vin_tail"]["hex"] == (b"M" * 16).hex()

    passport = extract_kombi_immo_passport(dflash_64k)
    assert passport["schema"] == "contitool.kombi.immo_passport.v1"
    assert passport["immo"]["vin"] == "XW8ZZZ5NZJG235992"

    # Edit VIN, odometer, Long Coding (with CRC-16 recalculation), and IKA (/3 at +0x22..+0x32 in 50 B EEL 0x006B)
    new_ika = "cbe4ee713ad83895bb6703f0c8efec48"
    new_coding = "07A501552280000811883A011400000800000000"
    edited_df = apply_kombi_dflash_edits(
        dflash_64k,
        vin="WVWZZZAUZJW123456",
        odometer_km=25400,
        coding_hex=new_coding,
        ika_key_hex=new_ika,
    )
    updates = extract_kombi_eel_updates(dflash_64k, edited_df)
    assert 0x0030 in updates
    assert 0x0060 in updates
    assert 0x0068 in updates
    assert 0x006B in updates
    assert updates[0x0060][2:4] == b"\xff\xff"
    edited_info = analyze_kombi_dflash(edited_df)
    assert edited_info["metadata"]["coding_hex"] == new_coding
    assert edited_info["metadata"]["coding_crc16_valid"] is True
    edited_keys = {it["key_id"]: it for it in edited_info["items"]}
    assert edited_keys["ika_cp3"]["hex"] == new_ika
    assert edited_keys["cp1_bank_0"]["hex"] == "e54e0aab8198ebcd8e781cceb0a3b33c"
    assert edited_keys["cp4_vin_tail"]["hex"] == (b"M" * 16).hex()
    diff = summarize_kombi_dflash_changes(dflash_64k, edited_df)
    assert len(diff["changed_eel_ids"]) == len(updates)

    rep_txt = format_kombi_report(dflash_info=edited_info)
    assert "VAG KOMBI VDD" in rep_txt
    assert "V850E2/Dx4" in rep_txt
    assert "FPK_E" not in rep_txt
    assert "RH850" not in rep_txt

    plan = plan_kombi_a_to_b_transfer(passport, extract_kombi_immo_passport(edited_df))
    plan_txt = format_kombi_transfer_plan(plan)
    assert "KOMBI VDD" in plan_txt
    assert "FPK_E" not in plan_txt

    # Transfer donor -> target preserves target FD11 keys (0x0063/0x0064)
    donor_recs = _build_synthetic_kombi_records(
        vin="TMBJJ7NE8J0112233",
        sl7_key=bytes.fromhex("11111111222222223333333344444444"),
        odometer_km=54320,
    )
    donor_df = build_kombi_eel_dflash(donor_recs)
    merged_df, xfer_summary = transfer_kombi_donor_to_target(
        donor_df,
        dflash_64k,
        copy_immo=True,
        copy_keys=True,
        copy_odometer=True,
        copy_cp=True,
    )
    merged_info = analyze_kombi_dflash(merged_df)
    assert merged_info["metadata"]["vin"] == "TMBJJ7NE8J0112233"
    assert merged_info["metadata"]["odometer_km"] == 54320
    merged_keys = {it["key_id"]: it for it in merged_info["items"]}
    assert merged_keys["fd11_l7"]["hex"] == "b470743235eb2e588d41888aed960e42"
    assert xfer_summary["copied_sections"]["immo"] is True
    assert 0x0063 not in extract_kombi_eel_updates(dflash_64k, merged_df)

    # File detection prioritizes Kombi over FPK_E
    df_file = tmp_path / "Dflash.bin"
    log_file = tmp_path / "EelLogical.bin"
    df_file.write_bytes(dflash_64k)
    log_file.write_bytes(logical_blob)
    detected = detect_kombi_files([tmp_path])
    assert detected["dflash"] == df_file
    assert detected["eel_logical"] == log_file


class _FakeKombiCanLink:
    """Simulates V850E2 `5NA 920 740 B` (`SW 0310`) UDS responses for SL 7 staging and EEL read/write."""

    def __init__(self, records: dict[int, bytes]) -> None:
        self.records = {k: bytes(v) for k, v in records.items()}
        self.via_gateway = False
        self.level8_active = False
        self.session = 0x01
        self.sa_level = 0
        self.sl_level = 0
        self.ram_staging = bytearray(b"\x00" * 252)
        self.ram_immo_mode = self.records[0x0068][0x4B]
        init_km = struct.unpack_from("<I", self.records[0x0060], 4)[0] * 2
        self.ram_odo_meters = init_km * 1000
        self.dpool_odo_meters = init_km * 1000
        self.retain_odo_meters = init_km * 1000
        self.physical_dflash_32k = build_kombi_eel_dflash(self.records)[:0x8000]
        self.nvm_reloads: list[int] = []
        self.last_seed = 0x12345678
        self.last_t16 = b"\xaa" * 16
        self.last_t8 = b"\x55" * 8
        self.last_req_level = 7

    def start_keepalive(self, _seconds: float = 0.0) -> None:
        return None

    def save_can_log(self, _path: Path) -> None:
        return None

    def request_uds(self, req: bytes, expected_first_byte: int | None = None, *, timeout: float = 2.0) -> bytes:
        resp = self.uds_request(req, timeout=timeout)
        if expected_first_byte is not None and (not resp or resp[0] != expected_first_byte):
            raise RuntimeError(f"Negative UDS response: {resp.hex()}")
        return resp

    def uds_request(self, req: bytes, timeout: float = 2.0) -> bytes:  # noqa: ARG002
        if req == bytes.fromhex("1003"):
            self.session = 0x03
            self.sa_level = 0
            return bytes.fromhex("5003003201f4")
        if req == bytes.fromhex("1060"):
            self.session = 0x60
            self.sa_level = 0
            return bytes.fromhex("5060003201f4")
        if req == bytes.fromhex("104f"):
            self.session = 0x4F
            self.sa_level = 0
            return bytes.fromhex("504f003201f4")
        if req == bytes.fromhex("2efd1101"):
            return bytes([0x6E, 0xFD, 0x11, self.sl_level])
        if req == bytes.fromhex("2efd110e"):
            return bytes.fromhex("6efd11000000")
        if req == bytes.fromhex("2efd110800"):
            # Stage NVM Block 0x5C (60 bytes: EEL 0x0063 +0x02..+0x3D) into 0xFEDD5508..0xFEDD5543
            r63 = self.records[0x0063]
            self.ram_staging[0:60] = r63[0x02:0x3E]
            return bytes.fromhex("6efd11")
        if req == bytes.fromhex("2703"):
            return bytes([0x67, 0x03]) + struct.pack(">I", self.last_seed)
        if req[:2] == bytes.fromhex("2704") and len(req) == 6:
            exp_key = (self.last_seed + KOMBI_SA1_DELTA) & 0xFFFFFFFF
            got_key = struct.unpack(">I", req[2:6])[0]
            if got_key != exp_key:
                return bytes.fromhex("7f2735")
            self.sa_level = 1
            # NVM Block 0x18 overwrites only the first 27 bytes (0xFEDD5508..0xFEDD5522)
            self.ram_staging[0:27] = b"\x00" * 27
            return bytes.fromhex("6704")
        if req[:3] == bytes.fromhex("2efd11") and len(req) == 29 and req[3] == 0x03:
            self.last_t16 = req[4:20]
            self.last_t8 = req[20:28]
            self.last_req_level = req[28]
            r63 = self.records[0x0063]
            ecu_r8 = bytes.fromhex("0102030405060708")
            ecu_id15 = r63[0x02:0x11]
            self.last_challenge = bytes([0x6E, 0xFD, 0x11]) + ecu_r8 + ecu_id15
            return self.last_challenge
        if req[:4] == bytes.fromhex("2efd1104") and len(req) == 36:
            r63 = self.records[0x0063]
            # 2E FD 11 04 loads NVM Block 0x5C (60 bytes: EEL 0x0063 +0x02..+0x3D) into 0xFEDD5508..0xFEDD5543
            self.ram_staging[0:60] = r63[0x02:0x3E]
            key = r63[0x2A:0x3A] if self.last_req_level == 7 else r63[0x16:0x26]
            exp_proof = build_fd11_proof(
                self.last_challenge,
                key,
                t16=self.last_t16,
                t8=self.last_t8,
            )
            if req[4:36] == exp_proof:
                self.sl_level = self.last_req_level
            return bytes.fromhex("6efd11")
        if req[:4] == bytes.fromhex("2efd110a") and len(req) == 5:
            if self.sl_level < 7:
                return bytes.fromhex("7f2e33")
            idx = req[4]
            r63 = self.records[0x0063]
            r64 = self.records[0x0064]
            mapping = {
                1: r63[0x16:0x2A],
                2: r63[0x2A:0x3E],
                3: r63[0x3E:0x52],
                4: r63[0x76:0x7E],
                5: r64[0x02:0x16],
                6: r64[0x16:0x2A],
            }
            sub = mapping[idx]
            self.ram_staging[: len(sub)] = sub
            return bytes.fromhex("6efd11")
        if req == bytes.fromhex("2efd1106"):
            if self.sl_level < 7:
                return bytes.fromhex("7f2e33")
            sub = self.records[0x0063][0x52:0x76]
            self.ram_staging[: len(sub)] = sub
            return bytes.fromhex("6efd11")
        if req[:3] == bytes.fromhex("2efd3a") and len(req) == 5:
            if self.sl_level < 6:
                return bytes.fromhex("7f2e33")
            nvm_blk = int.from_bytes(req[3:5], "big")
            self.nvm_reloads.append(nvm_blk)
            if nvm_blk == KOMBI_NVM_BLOCK_IMMO:
                self.ram_immo_mode = self.records[0x0068][0x4B]
            return bytes.fromhex("6efd3a01")
        if req == bytes.fromhex("1102"):
            # Warm reset restores Retention RAM (0xFF7605DC) into DPOOL 0x260 (0xFEDC1338)
            self.dpool_odo_meters = self.retain_odo_meters
            self.ram_odo_meters = self.retain_odo_meters
            return bytes.fromhex("5102")
        if req == bytes.fromhex("222203"):
            km = self.dpool_odo_meters // 1000
            return b"\x62\x22\x03" + km.to_bytes(3, "big")
        if req == bytes.fromhex("22f187"):
            return b"\x62\xf1\x875NA920740B  "
        if req == bytes.fromhex("22f189"):
            return b"\x62\xf1\x890310"
        if req == bytes.fromhex("3e00"):
            return bytes.fromhex("7e00")
        if req[:2] == bytes.fromhex("2344") and len(req) == 10:
            addr, size = struct.unpack(">II", req[2:10])
            if KOMBI_RAM_STAGING_ADDR <= addr < KOMBI_RAM_STAGING_ADDR + 252:
                if self.sa_level < 1 and self.sl_level < 7:
                    return bytes.fromhex("7f2333")
                off = addr - KOMBI_RAM_STAGING_ADDR
                return b"\x63" + bytes(self.ram_staging[off : off + size])
            if addr == KOMBI_RAM_IMMO_MODE_ADDR and size == 1:
                # RD_tbl0[20] (0xFEDC7E88..0xFEDC87AB) has levels=[3, 6, 7, 8]:
                # when ram_immo_mode != 0, reading 0xFEDC8075 requires level 8 (returns 7F 23 33 at SL 7)
                if self.sl_level < 7 or self.ram_immo_mode != 0:
                    return bytes.fromhex("7f2333")
                return bytes([0x63, self.ram_immo_mode])
            if addr == KOMBI_RAM_EEL_PHYS_TABLE_ADDR:
                return b"\x63" + (b"\x20\x00" * (size // 2))
            if 0x02000000 <= addr and addr + size <= 0x02008000:
                # RD_tbl0[5] (0x02000000..0x02007FFF) has levels=[3, 6, 7, 8]:
                # requires ram_immo_mode == 0 at SL 7
                if self.sl_level < 7 or self.ram_immo_mode != 0:
                    return bytes.fromhex("7f2333")
                off = addr - 0x02000000
                return b"\x63" + bytes(self.physical_dflash_32k[off : off + size])
            if (addr >> 16) == 0xEF00:
                # RD_tbl0[12] (0xEF006300..0xEF006429) has levels=[3, 6, 7, 8]
                if 0xEF006300 <= addr <= 0xEF006429 and (self.sl_level < 7 or self.ram_immo_mode != 0):
                    return bytes.fromhex("7f2333")
                blk = (addr >> 8) & 0xFF
                off = addr & 0xFF
                rec = self.records[blk]
                return b"\x63" + bytes(rec[off : off + size])
        if req[:2] == bytes.fromhex("3d44") and len(req) > 10:
            addr, size = struct.unpack(">II", req[2:10])
            payload = req[10 : 10 + size]
            # Simulate WR_tbl0 check (0x001A046E):
            # When ram_immo_mode != 0, levels[3] == 8 blocks 0xEF0060xx, 0xEF00300E, RAM (0xFEDC..), and Retention RAM (0xFF76..)
            if self.ram_immo_mode != 0:
                if 0xEF006000 <= addr <= 0xEF006429:
                    return bytes.fromhex("7f3d33")
                if addr <= 0xEF00300E < addr + size:
                    return bytes.fromhex("7f3d33")
                if (addr >> 16) in (0xFEDC, 0xFEDD, 0xFF76):
                    return bytes.fromhex("7f3d33")
            if self.sl_level < 7:
                return bytes.fromhex("7f3d33")
            if (addr >> 16) == 0xEF00:
                blk = (addr >> 8) & 0xFF
                off = addr & 0xFF
                rec_mut = bytearray(self.records[blk])
                rec_mut[off : off + size] = payload
                self.records[blk] = bytes(rec_mut)
                return b"\x7d" + req[1:10]
            if addr == KOMBI_RAM_ODO_METERS_ADDR and size == 4:
                self.ram_odo_meters = struct.unpack("<I", payload)[0]
                return b"\x7d" + req[1:10]
            if addr == KOMBI_RAM_ODO_DPOOL_ADDR and size == 4:
                self.dpool_odo_meters = struct.unpack("<I", payload)[0]
                return b"\x7d" + req[1:10]
            if addr == KOMBI_RETAIN_ODO_DPOOL_ADDR and size == 4:
                self.retain_odo_meters = struct.unpack("<I", payload)[0]
                return b"\x7d" + req[1:10]
        return bytes.fromhex("7f2331")


def test_kombi_sl7_key_extraction_and_full_132_record_read() -> None:
    recs = _build_synthetic_kombi_records()
    link = _FakeKombiCanLink(recs)

    assert kombi_check_sl7(link) is False
    key_16b, extracted = kombi_extract_sl7_key(link)
    assert key_16b.hex() == "b470743235eb2e588d41888aed960e42"
    assert extracted["key_hex"] == "b470743235eb2e588d41888aed960e42"
    assert extracted["crc32_valid"] is True
    assert extracted["staging_addr"] == f"0x{KOMBI_RAM_SL7_KEY_ADDR:08X}"

    fd11_id_hex = kombi_authenticate_fd11(link, key_16b, level=7)
    assert fd11_id_hex == "100e100106003f0013021788797411"
    assert kombi_check_sl7(link) is True

    # Reset SL and test full one-shot kombi_ensure_sl7 + 132-record read
    link.sl_level = 0
    ens = kombi_ensure_sl7(link, wake_seconds=0.0)
    assert ens["supplier_level"] == 7
    assert ens["reused_session"] is False

    dflash_64k, logical_9533, meta = kombi_read_all_eel_in_session(link, read_physical_dflash=True)
    assert len(dflash_64k) == 65536
    assert len(logical_9533) == KOMBI_EEL_LOGICAL_SIZE
    assert meta["eel_blocks_read"] == 132
    assert meta["logical_size"] == KOMBI_EEL_LOGICAL_SIZE
    assert meta["eel_0063_0064_direct"] is True
    assert meta["physical_size"] == 32768
    assert len(meta["physical_dflash_bytes"]) == 32768
    assert link.records[0x0068][0x4B] == 0x01
    assert link.ram_immo_mode == 0x01

    parsed = analyze_kombi_dflash(dflash_64k)
    assert parsed["metadata"]["vin"] == "XW8ZZZ5NZJG235992"
    keys_by_id = {it["key_id"]: it for it in parsed["items"]}
    assert keys_by_id["fd11_l0_6"]["hex"] == "8268dcf2746cf6479f7e6fb4633f4ca0"
    assert keys_by_id["fd11_l7"]["hex"] == "b470743235eb2e588d41888aed960e42"
    assert keys_by_id["ika_cp3"]["hex"] == "4d6b7c5472a7659bfbe10df4be36c44d"


def test_kombi_sl7_odometer_and_coding_write_via_temporary_immo_mode0(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    import contextlib as _ctx
    import contitool.can.kombi as can_kombi_mod

    recs = _build_synthetic_kombi_records(odometer_km=1000)
    link = _FakeKombiCanLink(recs)
    assert link.ram_immo_mode == 0x01

    @_ctx.contextmanager
    def _fake_session(*_a: Any, **_kw: Any) -> Any:
        yield link

    monkeypatch.setattr(can_kombi_mod, "_managed_kombi_session", _fake_session)

    base_df = build_kombi_eel_dflash(recs)
    # Edit odometer (1000 -> 50 km) AND Long Coding byte +0x0E (blocked in WR_tbl0 unless immo_mode == 0)
    cand_df = apply_kombi_dflash_edits(
        base_df,
        odometer_km=50,
        coding_hex="07A501992280000811883A011400000800000000",
    )

    rep = can_kombi_write_dflash(
        "MOCK",
        cand_df,
        base_dflash=base_df,
        session_dir=tmp_path / "kombi_odo_write",
        wake_seconds=0.0,
        reset_after=True,
    )
    assert rep["ok"] is True
    assert rep["mode"] == "uds_0x3d_eel_sl7_mode0_unlock"
    assert "0x60" in rep["written_eel_ids"]
    assert "0x30" in rep["written_eel_ids"]
    assert rep["odometer_ram_sync"] == {
        "target_km": 50,
        "target_meters": 50000,
        "ram_meters_addr": f"0x{KOMBI_RAM_ODO_METERS_ADDR:08X}",
        "dpool_ram_addr": f"0x{KOMBI_RAM_ODO_DPOOL_ADDR:08X}",
        "retention_ram_addr": f"0x{KOMBI_RETAIN_ODO_DPOOL_ADDR:08X}",
    }
    assert rep["reset"]["odometer_2203_km"] == 50
    assert rep["secrets"]["metadata"]["odometer_km"] == 50
    assert rep["secrets"]["metadata"]["coding_hex"] == "07A501992280000811883A011400000800000000"
    assert rep["secrets"]["metadata"]["coding_crc16_valid"] is True

    # Verify immo_mode was restored to 0x01 in both EEL 0x0068+0x4B and RAM 0xFEDC8075
    assert link.records[0x0068][0x4B] == 0x01
    assert link.ram_immo_mode == 0x01
    assert link.ram_odo_meters == 50000
    assert link.dpool_odo_meters == 50000
    assert link.retain_odo_meters == 50000
    assert KOMBI_NVM_BLOCK_IMMO in link.nvm_reloads
    assert KOMBI_NVM_BLOCK_ODO in link.nvm_reloads
    assert KOMBI_NVM_BLOCK_CODING in link.nvm_reloads


def test_gui_single_17_selector_and_kombi_workspace_routing(tmp_path: Path) -> None:
    from contitool.gui.app import create_window

    _app, win = create_window()
    try:
        # Only one 17 selector card on StartScreen ('fpke' card covers both FPK_E and Kombi VDD; passport determines handler)
        assert set(win.start_screen._target_cards.keys()) == {"all", "j533", "fpke", "bcm", "mrr", "elv"}
        card_17 = win.start_screen._target_cards["fpke"]
        assert "FPK_E / Kombi" in card_17.lbl_meta.text()

        # Opening a Kombi dump folder routes to KombiScreen (not FpkeScreen)
        recs = _build_synthetic_kombi_records()
        logical_blob = b"".join(recs[i] for i in sorted(EEL_KOMBI_0310_IDS))
        dflash_64k = build_kombi_eel_dflash(recs)
        (tmp_path / "Dflash.bin").write_bytes(dflash_64k)
        (tmp_path / "EelLogical.bin").write_bytes(logical_blob)

        win.open_folder(str(tmp_path))
        assert win.kombi_screen.is_open is True
        assert win.fpke_screen.is_open is False
        assert win._active_screen == "kombi"
        assert win.stack.currentWidget() is win.kombi_screen
        assert win.kombi_screen.part_number == "5NA920740B"
        gui_rep = win.kombi_screen._format_report()
        assert "VAG KOMBI VDD" in gui_rep
        assert "V850E2/Dx4" in gui_rep
        assert "FPK_E" not in gui_rep
        assert "RH850" not in gui_rep

        # Cluster material provider supplies Kombi material to 09 BCM / 13 MRR / 2B ELV
        mat = win._provide_fpke_cluster_material()
        assert mat is not None
        assert len(mat["dflash_bytes"]) == 65536
    finally:
        win.close()


def test_kombi_2220_8v0920860e_sl7_extraction_and_130_record_staged_read(tmp_path: Path, monkeypatch: Any) -> None:
    import contextlib as _ctx
    import contitool.can.kombi as can_kombi_mod

    ident_2220 = [
        {"did": "F187", "value": "8V0920860E"},
        {"did": "F189", "value": "2220"},
        {"did": "F197", "value": "KombiInstr."},
        {"did": "F19E", "value": "EV_DashBoardVDDMQBAB"},
        {"did": "F17C", "value": "VDD-02404.02.1455010551"},
    ]
    assert is_kombi_ident(ident_2220) is True
    assert is_fpke_ident(ident_2220) is False
    sup_2220 = kombi_support_info(ident_2220)
    assert sup_2220["verified"] is True
    assert sup_2220["warning"] is None
    prof_2220 = get_kombi_sw_profile(sw_version="2220", part_number="8V0920860E")
    assert prof_2220["sw_profile"] == "2220"
    assert prof_2220["sa1_delta"] == KOMBI_2220_SA1_DELTA
    assert prof_2220["ram_staging_addr"] == KOMBI_2220_RAM_STAGING_ADDR
    assert prof_2220["ram_sl7_key_addr"] == KOMBI_2220_RAM_SL7_KEY_ADDR

    base_0310 = _build_synthetic_kombi_records(
        vin="WAUZZZ8V4FA123456",
        part_number="8V0920860E ",
        sw_version="2220",
        fd11_id=bytes.fromhex("100361010400020214550105510035"),
        odometer_km=167360,
    )
    recs_2220: dict[int, bytes] = {}
    for ident, sz in sorted(EEL_KOMBI_2220_IDS.items()):
        if ident in base_0310 and len(base_0310[ident]) == sz:
            recs_2220[ident] = base_0310[ident]
        elif ident in base_0310:
            recs_2220[ident] = struct.pack("<H", sz) + base_0310[ident][2:sz].ljust(sz - 2, b"\xff")
        else:
            recs_2220[ident] = struct.pack("<H", sz) + (b"\xff" * (sz - 2))
    # On SW 2220 (8V0 920 860 E), EEL 0x0030 has 0x0000 padding at bytes 41..43 (no trailing CRC-16)
    r30_2220 = bytearray(recs_2220[0x0030])
    r30_2220[41:43] = b"\x00\x00"
    recs_2220[0x0030] = bytes(r30_2220)

    # Populate expected CRC-32(Slot A) and CRC-32(Slot B) in EEL 0x0068 (+0x38..+0x3F) and wipe 0x0069 to 0xFF (normal mode 1)
    test_s0 = bytes.fromhex("dc1279b9c430833849c3f3d32a3c2bf6")
    test_s1 = bytes.fromhex("4a1c3810bc4f9c2ba7347cf0006fc829")
    test_slot_a, test_slot_b = fpke_slots_from_s0_s1(test_s0, test_s1)
    crc_a_le = struct.pack("<I", zlib.crc32(test_slot_a) & 0xFFFFFFFF)
    crc_b_le = struct.pack("<I", zlib.crc32(test_slot_b) & 0xFFFFFFFF)
    r68_2220 = bytearray(recs_2220[0x0068])
    r68_2220[0x38:0x3C] = crc_a_le
    r68_2220[0x3C:0x40] = crc_b_le
    recs_2220[0x0068] = bytes(r68_2220)
    recs_2220[0x0069] = struct.pack("<H", EEL_KOMBI_2220_IDS[0x0069]) + (b"\xff" * 32)

    class _FakeKombi2220Link(_FakeKombiCanLink):
        def __init__(self) -> None:
            super().__init__(recs_2220)
            self.last_seed = 0x5E7840BF
            self.nvm_to_eel = {nvm_id: (eid, plen) for eid, (nvm_id, plen) in KOMBI_NVM_STAGED_EEL_MAP.items()}
            self.fde3_calls = 0
            self.fd11_state_ram = bytearray(recs_2220[0x0065][2:14])
            self.ram_odo_writes: dict[int, int] = {}
            self.ram_s0_buf = bytearray(test_s0 + test_s1)
            self.ram_slot_a_buf = bytearray(test_slot_a)
            self.ram_slot_b_buf = bytearray(test_slot_b)
            self.ram_slots_flag = 0x03
            self.ram_recog_state = 0x04
            self.ram_last_key_id = bytes.fromhex("20055e76")[::-1]

        def uds_request(self, req: bytes, timeout: float = 2.0) -> bytes:
            if req == bytes.fromhex("22f187"):
                return b"\x62\xf1\x878V0920860E "
            if req == bytes.fromhex("22f189"):
                return b"\x62\xf1\x892220"
            if req == bytes.fromhex("2202e4"):
                return b"\x62\x02\xe4" + self.ram_last_key_id[::-1]
            if req == bytes.fromhex("2202ed"):
                r67_cur = self.records[0x0067]
                r68_cur = self.records[0x0068]
                allowed = r67_cur[0x22] & 0x0F
                learned = r67_cur[0x23] & 0x0F
                rem = max(0, allowed - learned)
                mode = self.ram_immo_mode
                life_st = 1 if mode == 0 else (2 if mode in (1, 2) else 3)
                return bytes([0x62, 0x02, 0xED, life_st, 1, 0, r68_cur[0x40], learned, rem, rem, 0, 0, 0])
            if req == bytes.fromhex("2202ef"):
                return bytes([0x62, 0x02, 0xEF, 0, 0, 0, 0, 0, 0])
            if req == bytes.fromhex("2202e0"):
                return bytes.fromhex("6202e011223344")
            if req == bytes.fromhex("2202ee"):
                return bytes.fromhex("6202ee0000")
            if len(req) == 3 and req[0] == 0x22 and 0x02E5 <= int.from_bytes(req[1:3], "big") <= 0x02EC:
                k_idx = int.from_bytes(req[1:3], "big") - 0x02E5
                raw_id = self.records[0x0067][2 + k_idx * 4 : 6 + k_idx * 4]
                return req[:3].replace(b"\x22", b"\x62", 1) + raw_id[::-1]
            if req[:2] == bytes.fromhex("2704") and len(req) == 6:
                exp_key = (self.last_seed + KOMBI_2220_SA1_DELTA) & 0xFFFFFFFF
                got_key = struct.unpack(">I", req[2:6])[0]
                if got_key != exp_key:
                    return bytes.fromhex("7f2735")
                self.sa_level = 1
                # On SW 2220, NvM 0x18 (EEL 0x002C, 17 B) only overwrites 0xFEDD2458..0xFEDD2468
                self.ram_staging[0:17] = b"\x00" * 17
                return bytes.fromhex("6704")
            if req == bytes.fromhex("2efde3"):
                if self.session != 0x60 or self.sl_level < 6:
                    return bytes.fromhex("7f2e33")
                self.fde3_calls += 1
                # Simulate 2E FD E3 stages 0..6: wipes 0x0063 (+0x02..0x3D, +0x76..0x7D), 0x0065..0x006A, 0x006B (+0x12..0x31),
                # wipes 0xFEDC8EE0..0xFEDC8EFF with 0xAA (FUN_ram_0017a70a), while leaving 0xFEDC8E30 (Slot A) and 0xFEDC8E50 (Slot B) untouched!
                r63 = bytearray(self.records[0x0063])
                r63[0x02:0x3E] = b"\xff" * 60
                r63[0x76:0x7E] = b"\xff" * 8
                self.records[0x0063] = bytes(r63)
                for eid in (0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A):
                    nvm_len = KOMBI_NVM_STAGED_EEL_MAP[eid][1]
                    r_cur = bytearray(self.records[eid])
                    r_cur[2 : 2 + nvm_len] = b"\x00" * nvm_len
                    if eid == 0x0065:
                        r_cur[2:7] = b"\xff" * 5
                    self.records[eid] = bytes(r_cur)
                r6b = bytearray(self.records[0x006B])
                r6b[0x12:0x32] = b"\x00" * 32
                self.records[0x006B] = bytes(r6b)
                self.ram_s0_buf[:] = b"\xaa" * 32
                self.ram_slots_flag = 0x00
                self.ram_immo_mode = 0x00
                return bytes.fromhex("6efde3")
            if req[:3] == bytes.fromhex("2efd3a") and len(req) == 5:
                if self.sl_level < 6:
                    return bytes.fromhex("7f2e33")
                nvm_blk = int.from_bytes(req[3:5], "big")
                self.nvm_reloads.append(nvm_blk)
                if nvm_blk in self.nvm_to_eel:
                    eid, plen = self.nvm_to_eel[nvm_blk]
                    self.ram_staging[:plen] = self.records[eid][2 : 2 + plen]
                if nvm_blk == KOMBI_NVM_BLOCK_IMMO:
                    self.ram_immo_mode = self.records[0x0068][0x4B]
                return bytes.fromhex("6efd3a01")
            if req[:2] == bytes.fromhex("2344") and len(req) == 10:
                addr, size = struct.unpack(">II", req[2:10])
                if addr == KOMBI_2220_RAM_IMMO_MODE_ADDR and size == 1:
                    if self.sl_level < 7:
                        return bytes.fromhex("7f2333")
                    return bytes([0x63, self.ram_immo_mode & 0xFF])
                if addr in (
                    KOMBI_2220_RAM_SLOT_A_ADDR,
                    KOMBI_2220_RAM_SLOT_B_ADDR,
                    KOMBI_2220_RAM_S0_ADDR,
                    KOMBI_2220_RAM_SLOTS_FLAG_ADDR,
                    KOMBI_2220_RAM_RECOG_STATE_ADDR,
                    KOMBI_2220_RAM_LAST_KEY_ID_ADDR,
                    KOMBI_2220_RAM_EEL69_ADDR,
                ):
                    if self.ram_immo_mode != 0 and self.sl_level < 8:
                        return bytes.fromhex("7f2333")
                    if addr == KOMBI_2220_RAM_SLOT_A_ADDR and size == 16:
                        return b"\x63" + bytes(self.ram_slot_a_buf)
                    if addr == KOMBI_2220_RAM_SLOT_B_ADDR and size == 16:
                        return b"\x63" + bytes(self.ram_slot_b_buf)
                    if addr == KOMBI_2220_RAM_S0_ADDR and size == 32:
                        return b"\x63" + bytes(self.ram_s0_buf)
                    if addr == KOMBI_2220_RAM_SLOTS_FLAG_ADDR and size == 1:
                        return bytes([0x63, self.ram_slots_flag])
                    if addr == KOMBI_2220_RAM_RECOG_STATE_ADDR and size == 1:
                        return bytes([0x63, self.ram_recog_state])
                    if addr == KOMBI_2220_RAM_LAST_KEY_ID_ADDR and size == 4:
                        return b"\x63" + self.ram_last_key_id
                    if addr == KOMBI_2220_RAM_EEL69_ADDR and size == 32:
                        return b"\x63" + bytes(self.records[0x0069][2:34])
                if KOMBI_2220_RAM_STAGING_ADDR <= addr < KOMBI_2220_RAM_STAGING_ADDR + 252:
                    if self.sa_level < 1 and self.sl_level < 6:
                        return bytes.fromhex("7f2333")
                    off = addr - KOMBI_2220_RAM_STAGING_ADDR
                    return b"\x63" + bytes(self.ram_staging[off : off + size])
                if addr == KOMBI_2220_RAM_EEL_PHYS_TABLE_ADDR:
                    return b"\x63" + (b"\x20\x00" * (size // 2))
                if (addr >> 16) == 0xEF00:
                    # On SW 2220 with immo_mode == 1, RD_tbl0[12..13] (0xEF006300..0xEF007001) requires Level 8
                    if 0xEF006300 <= addr <= 0xEF007001 and self.ram_immo_mode != 0 and self.sl_level < 8:
                        return bytes.fromhex("7f2333")
                    blk = (addr >> 8) & 0xFF
                    off = addr & 0xFF
                    rec = self.records[blk]
                    return b"\x63" + bytes(rec[off : off + size])
            if req[:2] == bytes.fromhex("3d44") and len(req) > 10:
                addr, size = struct.unpack(">II", req[2:10])
                payload = req[10:]
                if len(payload) != size:
                    return bytes.fromhex("7f3d13")
                if addr == KOMBI_2220_RAM_FD11_STATE_ADDR and size == 12:
                    if self.ram_immo_mode != 0 and self.sl_level < 8:
                        return bytes.fromhex("7f3d33")
                    self.fd11_state_ram[:] = payload
                    return bytes.fromhex("7d")
                if addr in (
                    KOMBI_2220_RAM_EEL67_ADDR,
                    KOMBI_2220_RAM_EEL68_ADDR,
                    KOMBI_2220_RAM_EEL69_ADDR,
                    KOMBI_2220_RAM_SLOT_A_ADDR,
                    KOMBI_2220_RAM_SLOT_B_ADDR,
                    KOMBI_2220_RAM_S0_ADDR,
                    KOMBI_2220_RAM_SLOTS_FLAG_ADDR,
                ):
                    if self.ram_immo_mode != 0 and self.sl_level < 8:
                        return bytes.fromhex("7f3d33")
                    if addr == KOMBI_2220_RAM_SLOT_A_ADDR and size == 16:
                        self.ram_slot_a_buf[:] = payload
                    elif addr == KOMBI_2220_RAM_SLOT_B_ADDR and size == 16:
                        self.ram_slot_b_buf[:] = payload
                    elif addr == KOMBI_2220_RAM_S0_ADDR and size == 32:
                        self.ram_s0_buf[:] = payload
                    elif addr == KOMBI_2220_RAM_SLOTS_FLAG_ADDR and size == 1:
                        self.ram_slots_flag = payload[0]
                    return bytes.fromhex("7d")
                if addr in (
                    KOMBI_2220_RAM_ODO_METERS_ADDR,
                    KOMBI_2220_RAM_ODO_DPOOL_ADDR,
                    KOMBI_2220_RETAIN_ODO_DPOOL_ADDR,
                ) and size == 4:
                    if self.ram_immo_mode != 0 and self.sl_level < 8:
                        return bytes.fromhex("7f3d33")
                    self.ram_odo_writes[addr] = struct.unpack("<I", payload)[0]
                    return bytes.fromhex("7d")
                if (addr >> 16) == 0xEF00:
                    if 0xEF006000 <= addr <= 0xEF0070FF and self.ram_immo_mode != 0 and self.sl_level < 8:
                        return bytes.fromhex("7f3d33")
            return super().uds_request(req, timeout=timeout)

    link_2220 = _FakeKombi2220Link()
    ens = kombi_ensure_sl7(link_2220, wake_seconds=0.0)
    assert ens["supplier_level"] == 7
    assert ens["staging_addr"] == f"0x{KOMBI_2220_RAM_SL7_KEY_ADDR:08X}"

    dflash_64k, logical_8334, meta = kombi_read_all_eel_in_session(link_2220, read_physical_dflash=True)
    assert len(dflash_64k) == 65536
    assert len(logical_8334) == KOMBI_EEL_2220_LOGICAL_SIZE
    assert meta["eel_blocks_read"] == 130
    assert meta["logical_size"] == KOMBI_EEL_2220_LOGICAL_SIZE
    assert link_2220.fde3_calls == 0  # Read must never call 2E FD E3
    assert is_kombi_dflash(logical_8334) is True
    assert is_kombi_dflash(dflash_64k) is True

    parsed = analyze_kombi_dflash(dflash_64k)
    assert parsed["platform"] == "V850E2-KOMBI-2220"
    assert parsed["pool"]["total_ids"] == 130
    assert parsed["metadata"]["part_number"] == "8V0920860E"
    assert parsed["metadata"]["sw_version_eel"] == "2220"
    assert parsed["metadata"]["vin"] == "WAUZZZ8V4FA123456"
    assert parsed["metadata"]["odometer_km"] == 167360
    assert "coding_crc16_hex" not in parsed["metadata"]
    assert parsed["immo_config"]["EEL_0x66_present"] is True
    assert parsed["immo_config"]["cluster_mac_id"] == "55BB"
    keys_by_id = {it["key_id"]: it for it in parsed["items"]}
    assert keys_by_id["kc"]["hex"] == "ea046275eea646ef01e6d703f77899db"
    assert keys_by_id["fd11_l0_6"]["hex"] == "8268dcf2746cf6479f7e6fb4633f4ca0"
    assert keys_by_id["fd11_l7"]["hex"] == "b470743235eb2e588d41888aed960e42"
    assert keys_by_id["ika_cp3"]["hex"] == "4d6b7c5472a7659bfbe10df4be36c44d"

    # Editing only odometer_km on SW 2220 must NOT falsely touch EEL 0x0030 (Long Coding)
    cand_odo0 = apply_kombi_dflash_edits(
        dflash_64k,
        odometer_km=0,
        coding_hex=parsed["metadata"]["coding_hex"],
    )
    odo_updates = extract_kombi_eel_updates(dflash_64k, cand_odo0)
    assert set(odo_updates) == {0x0060}

    # Test full can_kombi_write_dflash odometer write on SW 2220 via 2E FD E3 + immediate SL 7 restore
    @_ctx.contextmanager
    def _fake_session(*_a: Any, **_kw: Any) -> Any:
        yield link_2220

    monkeypatch.setattr(can_kombi_mod, "_managed_kombi_session", _fake_session)
    orig_protected = {eid: bytes(link_2220.records[eid]) for eid in (0x0063, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B)}
    write_rep = can_kombi_write_dflash(
        "MOCK",
        cand_odo0,
        base_dflash=dflash_64k,
        session_dir=tmp_path / "kombi_2220_write",
        wake_seconds=0.0,
    )
    assert write_rep["ok"] is True
    assert write_rep["sw_profile"] == "2220"
    assert write_rep["written_eel_ids"] == ["0x60"]
    assert link_2220.fde3_calls == 1
    assert link_2220.ram_immo_mode == 0x01
    for eid, exp_rec in orig_protected.items():
        assert link_2220.records[eid] == exp_rec
    assert link_2220.ram_odo_writes[KOMBI_2220_RAM_ODO_METERS_ADDR] == 0
    assert link_2220.ram_odo_writes[KOMBI_2220_RAM_ODO_DPOOL_ADDR] == 0
    assert link_2220.ram_odo_writes[KOMBI_2220_RETAIN_ODO_DPOOL_ADDR] == 0
    assert write_rep["secrets"]["metadata"]["odometer_km"] == 0
    assert write_rep["secrets"]["metadata"]["vin"] == "WAUZZZ8V4FA123456"

    # Test live coil S0 / S1 extraction on SW 2220 (8V0 920 860 E):
    # Even though 2E FD E3 wipes 0xFEDC8EE0 with 0xAA, 0xFEDC8E30 (Slot A) and 0xFEDC8E50 (Slot B) survive and yield exact S0/S1
    ext_s01 = kombi_extract_live_s0_s1_from_coil(
        link_2220,
        expected_crc_a_le=crc_a_le.hex().upper(),
        expected_crc_b_le=crc_b_le.hex().upper(),
        wake_seconds=0.0,
        poll_timeout=0.0,
    )
    assert ext_s01["ok"] is True
    assert ext_s01["valid"] is True
    assert ext_s01["s0_hex"] == test_s0.hex().upper()
    assert ext_s01["s1_hex"] == test_s1.hex().upper()
    assert ext_s01["coil_key_id"] == "20055E76"
    assert link_2220.ram_immo_mode == 0x01
    for eid, exp_rec in orig_protected.items():
        if eid != 0x0060:
            assert link_2220.records[eid] == exp_rec

    # Test additive coil key learning preparation (mode 5) on SW 2220 without erasing old keys
    prep_res = kombi_prepare_additive_coil_learning(
        link_2220,
        s0_hex=ext_s01["s0_hex"],
        s1_hex=ext_s01["s1_hex"],
        allowed_keys=3,
        expected_crc_a_le=crc_a_le.hex().upper(),
        expected_crc_b_le=crc_b_le.hex().upper(),
        wake_seconds=0.0,
    )
    assert prep_res["ok"] is True
    assert prep_res["immo_mode"] == 5
    assert prep_res["preserved_keys"] == 2
    assert prep_res["allowed_keys"] == 3
    assert link_2220.ram_immo_mode == 5
    assert link_2220.records[0x0069][2:34] == test_s0 + test_s1
    assert link_2220.records[0x0067][0x22] == 3
    assert link_2220.records[0x0067][0x23] == 2
    assert prep_res["poll"]["mode_family"] == 3
    assert prep_res["poll"]["remaining_keys"] == 1

    # Test 7F 27 37 (SecurityAccess lockout) bypass using known FD11 SL 7 key from dump or saved kombi_report.json
    from contitool.can.transport import UdsNegativeResponse

    class _LockedSa1Link(_FakeKombi2220Link):
        def request_uds(self, req: bytes, expected_first_byte: int | None = None, *, timeout: float = 2.0) -> bytes:
            if req == bytes.fromhex("2703"):
                raise UdsNegativeResponse(0x27, 0x37, bytes.fromhex("7f2737"))
            return super().request_uds(req, expected_first_byte, timeout=timeout)

    locked_link = _LockedSa1Link()
    ens_direct = kombi_ensure_sl7(
        locked_link,
        sl7_key="b470743235eb2e588d41888aed960e42",
        expected_fd11_id="100361010400020214550105510035",
        wake_seconds=0.0,
    )
    assert ens_direct["supplier_level"] == 7
    assert ens_direct["method"] == "fd11_sl7_known_key"

    # Also test automatic fallback to saved kombi_report.json when 27 03 returns 7F 27 37 without explicit sl7_key
    import json as _json
    import contitool.storage as storage_mod

    fake_runs = tmp_path / "runs"
    rep_dir = fake_runs / "8V0920860E_test" / "dumps" / "2026-11-27_read"
    rep_dir.mkdir(parents=True)
    (rep_dir / "kombi_report.json").write_text(
        _json.dumps(
            {
                "access": {
                    "fd11_identifier": "100361010400020214550105510035",
                    "key_hex": "b470743235eb2e588d41888aed960e42",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(storage_mod, "runs_root", lambda: fake_runs)
    locked_link2 = _LockedSa1Link()
    ens_cached = kombi_ensure_sl7(locked_link2, wake_seconds=0.0)
    assert ens_cached["supplier_level"] == 7
    assert ens_cached["method"] == "fd11_sl7_saved_cache"

    # Test built-in +0x62EF (27 04 00 00 62 EF) delay-timer reset on a brand-new cluster with NO saved dump or key
    monkeypatch.setattr(storage_mod, "runs_root", lambda: tmp_path / "empty_runs")

    class _ResettableSa1Link(_FakeKombi2220Link):
        def __init__(self, *, non_zero_seed_initially: bool = False) -> None:
            super().__init__()
            self.sa1_state = 4
            self.lockout_seed = 0x11223344 if non_zero_seed_initially else 0

        def request_uds(self, req: bytes, expected_first_byte: int | None = None, *, timeout: float = 2.0) -> bytes:
            if req == bytes.fromhex("2703"):
                if self.sa1_state == 4:
                    raise UdsNegativeResponse(0x27, 0x37, bytes.fromhex("7f2737"))
                return super().request_uds(req, expected_first_byte, timeout=timeout)
            if req.startswith(bytes.fromhex("2704")) and len(req) == 6 and self.sa1_state == 4:
                got_key = int.from_bytes(req[2:6], "big")
                if got_key == ((self.lockout_seed + 0x62EF) & 0xFFFFFFFF):
                    self.sa1_state = 1
                    return bytes.fromhex("6704")
                # Simulate S3 timeout or 11 02 zeroing last_seed before the retry
                self.lockout_seed = 0
                raise UdsNegativeResponse(0x27, 0x24, bytes.fromhex("7f2724"))
            return super().request_uds(req, expected_first_byte, timeout=timeout)

    # Case A: last_seed == 0 (fresh boot / after S3 timeout) -> instant 27 04 00 00 62 EF reset
    fresh_locked = _ResettableSa1Link(non_zero_seed_initially=False)
    ens_reset_direct = kombi_ensure_sl7(fresh_locked, wake_seconds=0.0)
    assert ens_reset_direct["supplier_level"] == 7
    assert ens_reset_direct["sa1_delay_timer_reset"]["stage"] == "direct"
    assert fresh_locked.sa1_state == 1

    # Case B: last_seed != 0 -> first 27 04 00 00 62 EF returns 7F 27 24 -> S3 timeout zeroes last_seed -> re-stages EEL 0x0063
    s3_locked = _ResettableSa1Link(non_zero_seed_initially=True)
    k_s3, meta_s3 = kombi_extract_sl7_key(s3_locked, s3_wait_s=0.0, ecu_reset_wait_s=0.0)
    assert k_s3 == bytes.fromhex("b470743235eb2e588d41888aed960e42")
    assert meta_s3["sa1_delay_timer_reset"]["stage"] == "s3_timeout"
    assert meta_s3["sa1_delay_timer_reset"]["needs_restage"] is True


def test_kombi_2220_75byte_eel68_kessy_bit7_and_uflash_guard() -> None:
    from contitool.core.fpke import parse_fpke_immo_config
    from contitool.core.kombi import (
        EEL_KOMBI_2220_IDS,
        apply_kombi_dflash_edits,
        build_kombi_eel_dflash,
        is_kombi_dflash,
    )

    # 1. 32 KiB random/Uflash-like bytes must NOT false-positive as Kombi physical DataFlash
    assert is_kombi_dflash(bytes(range(256)) * 128) is False

    # 2. SW 2220 75-byte EEL 0x0068 layout: rec[0x41] bit 7 = key_over_can, bits 0..6 = partners_mask, rec[0x4D:0x80] == 0xFF*51
    base_recs = _build_synthetic_kombi_records()
    recs_2220: dict[int, bytes] = {}
    for eid, sz in sorted(EEL_KOMBI_2220_IDS.items()):
        if eid in base_recs and len(base_recs[eid]) == sz:
            recs_2220[eid] = base_recs[eid]
        elif eid in base_recs:
            recs_2220[eid] = struct.pack("<H", sz) + base_recs[eid][2:sz].ljust(sz - 2, b"\xff")
        else:
            recs_2220[eid] = struct.pack("<H", sz) + (b"\xff" * (sz - 2))
    r68 = bytearray(recs_2220[0x0068])
    r68[0x40] = 0x42  # power_class
    r68[0x41] = 0x83  # bit 7 = key_over_can (True), bits 0..6 = 0x03 (MSG_1 + GSG)
    r68[0x4B] = 0x01  # immo_mode
    r68[0x4C] = 0x01  # identity_counter
    r68[0x4D:0x80] = b"\xff" * 51
    recs_2220[0x0068] = bytes(r68)

    cfg = parse_fpke_immo_config(recs_2220[0x0066], recs_2220[0x0068])
    assert cfg["power_class"] == 0x42
    assert cfg["key_over_can"] is True
    assert cfg["partners_mask"] == 0x03

    df_2220 = build_kombi_eel_dflash(recs_2220)
    edited_df = apply_kombi_dflash_edits(
        df_2220,
        key_over_can=False,
        partners_mask=0x23,
    )
    from contitool.core.fpke import eel_read_record_any
    from contitool.core.kombi import analyze_kombi_dflash, kombi_eel_layout

    lay_2220 = kombi_eel_layout(edited_df)
    r68_after, _ = eel_read_record_any(lay_2220, edited_df, 0x0068)
    assert r68_after is not None
    assert r68_after[0x41] == 0x23  # bit 7 cleared, bits 0..6 = 0x23
    assert r68_after[0x4D:0x80] == b"\xff" * 51  # 51-byte tail untouched
    an = analyze_kombi_dflash(edited_df)
    assert an["immo_config"]["key_over_can"] is False
    assert an["immo_config"]["partners_mask"] == 0x23

    # Toggling key_over_can back to True must set bit 7 while preserving partners_mask=0x23
    edited_df2 = apply_kombi_dflash_edits(edited_df, key_over_can=True)
    r68_after2, _ = eel_read_record_any(lay_2220, edited_df2, 0x0068)
    assert r68_after2 is not None
    assert r68_after2[0x41] == 0xA3
    assert r68_after2[0x4D:0x80] == b"\xff" * 51


def test_kombi_6p0920740a_sw1422_auto_discovers_ram_staging_and_fe30_eel_layout(tmp_path: Path) -> None:
    """When a V850E2 Kombi cluster (e.g. 6P0920740A SW 1422) has its NvM staging buffer at a shifted RAM address
    (and 0xFEDD5530 holds a timing table like `64 00 fa 00 f4 01...`), `kombi_extract_sl7_key` auto-scans RAM,
    locates the NvM staging buffer + SL 7 key, authenticates SL 7, queries `22 FE 30` for the live EEL layout,
    and reads the full DataFlash cleanly."""
    from contitool.can.kombi import KOMBI_2220_RAM_SL7_KEY_ADDR, kombi_ensure_sl7, kombi_read_all_eel_in_session
    from contitool.core.kombi import analyze_kombi_dflash, detect_kombi_files, is_kombi_ident

    assert is_kombi_ident([{"did": "F187", "value": "6P0920740A"}, {"did": "F189", "value": "1422"}]) is True

    shifted_staging_addr = 0xFEDD1848
    shifted_sl7_addr = shifted_staging_addr + 0x28  # 0xFEDD1870
    shifted_phys_tbl_addr = 0xFEDC7900
    desc_tbl_addr = 0x00015320

    class Fake6P0KombiLink(_FakeKombiCanLink):
        def __init__(self) -> None:
            super().__init__(_build_synthetic_kombi_records())
            # Custom EEL layout on SW 1422: 131 blocks, with block 3 sized 190 B instead of 249 B
            self.custom_eel_ids = {k: v for k, v in EEL_KOMBI_0310_IDS.items() if k <= 131}
            self.custom_eel_ids[3] = 190
            self.records[3] = struct.pack("<H", 190) + bytes(i & 0xFF for i in range(188))
            del self.records[132]

        def uds_request(self, req: bytes, timeout: float = 2.0) -> bytes:
            if req == bytes.fromhex("22f187"):
                return b"\x62\xf1\x876P0920740A  "
            if req == bytes.fromhex("22f189"):
                return b"\x62\xf1\x891422"
            if req == bytes.fromhex("22fe30"):
                # 62 FE 30 + desc_addr(4B) + n_blocks(2B) + dflash_base(4B) + 0003 + phys_tbl_addr(4B) + 000A
                return (
                    b"\x62\xfe\x30"
                    + desc_tbl_addr.to_bytes(4, "big")
                    + len(self.custom_eel_ids).to_bytes(2, "big")
                    + (0x02000000).to_bytes(4, "big")
                    + b"\x00\x03"
                    + shifted_phys_tbl_addr.to_bytes(4, "big")
                    + b"\x00\x0a"
                )
            if req[:2] == bytes.fromhex("2344") and len(req) == 10:
                addr, size = struct.unpack(">II", req[2:10])
                # At 0xFEDD5530, return the exact timing constant table seen on real 6P0920740A SW 1422
                if addr == KOMBI_RAM_SL7_KEY_ADDR and size == 20:
                    return b"\x63" + bytes.fromhex("6400fa00f401000032006400c800f40100001500")
                if addr == KOMBI_2220_RAM_SL7_KEY_ADDR and size == 20:
                    return b"\x63" + (b"\x00" * 20)
                # Descriptor table in CodeFlash @ 0x00015320
                if desc_tbl_addr <= addr and addr + size <= desc_tbl_addr + len(self.custom_eel_ids) * 4:
                    tbl = bytearray()
                    for eid, esz in sorted(self.custom_eel_ids.items()):
                        tbl.extend(struct.pack("<HH", eid, esz))
                    off = addr - desc_tbl_addr
                    return b"\x63" + bytes(tbl[off : off + size])
                if addr == shifted_phys_tbl_addr:
                    return b"\x63" + (b"\x20\x00" * (size // 2))
                # Any RAM read in 0xFEDD0000..0xFEDE0000 returns a memory image containing the NvM header + shifted staging buffer
                if 0xFEDD0000 <= addr and addr + size <= 0xFEDE0000:
                    if self.sa_level < 1 and self.sl_level < 7:
                        return bytes.fromhex("7f2333")
                    out = bytearray(size)
                    for i in range(size):
                        cur = addr + i
                        # 8-byte NvM manager state header at shifted_staging_addr - 8: block 0x0018, status 0x08
                        if shifted_staging_addr - 8 <= cur < shifted_staging_addr:
                            hdr = bytes.fromhex("1800000000080000")
                            out[i] = hdr[cur - (shifted_staging_addr - 8)]
                        elif shifted_staging_addr <= cur < shifted_staging_addr + len(self.ram_staging):
                            out[i] = self.ram_staging[cur - shifted_staging_addr]
                    return b"\x63" + bytes(out)
            return super().uds_request(req, timeout=timeout)

    link = Fake6P0KombiLink()
    acc = kombi_ensure_sl7(link, wake_seconds=0.0)
    assert acc["supplier_level"] == 7
    assert acc["staging_addr"] == f"0x{shifted_sl7_addr:08X}"
    assert acc["nvm_staging_base_addr"] == f"0x{shifted_staging_addr:08X}"

    df_bytes, logical_bytes, meta = kombi_read_all_eel_in_session(link, read_physical_dflash=True)
    assert len(df_bytes) == 65536
    assert len(logical_bytes) == sum(link.custom_eel_ids.values())
    assert meta["eel_blocks_read"] == 131

    sdir = tmp_path / "6p0_read"
    sdir.mkdir()
    (sdir / "Dflash.bin").write_bytes(df_bytes)
    (sdir / "EelLogical.bin").write_bytes(logical_bytes)
    det = detect_kombi_files([sdir])
    assert det["dflash"] == sdir / "Dflash.bin"
    assert det["eel_logical"] == sdir / "EelLogical.bin"

    info = analyze_kombi_dflash(df_bytes)
    assert info["metadata"]["vin"] == "XW8ZZZ5NZJG235992"
    info_from_logical = analyze_kombi_dflash(logical_bytes)
    assert info_from_logical["metadata"]["vin"] == "XW8ZZZ5NZJG235992"


def test_kombi_ram_scanner_edge_cases_tail_l06_and_range2_scoring() -> None:
    """Verify RAM scanner disambiguates L0..6 at chunk tail (+468) vs SL 7 (+488) and prefers score>=2 in range 2 over score==1 decoy in range 1."""
    import zlib
    from contitool.can.kombi import _scan_ram_for_sl7_key
    from contitool.can.transport import UdsNegativeResponse

    l06_key = bytes(range(0x10, 0x20))
    l06_rec = l06_key + struct.pack("<I", zlib.crc32(l06_key) & 0xFFFFFFFF)
    sl7_key = bytes(range(0x40, 0x50))
    sl7_rec = sl7_key + struct.pack("<I", zlib.crc32(sl7_key) & 0xFFFFFFFF)
    decoy_key = bytes(range(0x80, 0x90))
    decoy_rec = decoy_key + struct.pack("<I", zlib.crc32(decoy_key) & 0xFFFFFFFF)

    # Place decoy (score=1, no NvM header) in range 1 @ 0xFEDD0400, and real staging buffer in range 2
    # with L0..6 landing right at chunk tail (0xFEDD8000 + 468) and SL 7 at +488!
    real_staging = 0xFEDD8000 + 468 - 0x14  # 0xFEDD81C0
    real_sl7 = real_staging + 0x28          # 0xFEDD81E8

    class EdgeScanLink:
        def __init__(self) -> None:
            self.mem: dict[int, int] = {}
            for i, b in enumerate(decoy_rec):
                self.mem[0xFEDD0400 + i] = b
            for i, b in enumerate(bytes.fromhex("1800000000080000")):
                self.mem[real_staging - 8 + i] = b
            for i, b in enumerate(l06_rec):
                self.mem[real_staging + 0x14 + i] = b
            for i, b in enumerate(sl7_rec):
                self.mem[real_sl7 + i] = b

        def request_uds(self, req: bytes, expected_first_byte: int | None = None, *, timeout: float = 2.0) -> bytes:  # noqa: ARG002
            if req == b"\x3e\x00":
                return b"\x7e\x00"
            if req[:2] == b"\x23\x44":
                addr, size = struct.unpack(">II", req[2:10])
                # Simulate a protected hole at 0xFEDD4000..0xFEDD4080 inside range 1
                if addr < 0xFEDD4080 and addr + size > 0xFEDD4000:
                    raise UdsNegativeResponse(0x23, 0x33, "protected")
                return b"\x63" + bytes(self.mem.get(addr + i, 0) for i in range(size))
            raise UdsNegativeResponse(req[0], 0x11, "unsupported")

    found = _scan_ram_for_sl7_key(EdgeScanLink(), checked_addrs={KOMBI_RAM_SL7_KEY_ADDR})  # type: ignore[arg-type]
    assert found is not None
    found_key, found_crc, found_addr = found
    assert found_addr == real_sl7
    assert found_key == sl7_key
    assert found_crc == (zlib.crc32(sl7_key) & 0xFFFFFFFF)


def test_is_kombi_ident_separates_fpke_mqba0_and_v850_mqbab_clusters() -> None:
    """Issues #60, #61, #62: RH850 FPK_E (`EV_DashBoardVDDMQBA0` / `*920790*`) must never be routed to V850E2 Kombi."""
    # Issue #60: SEAT Leon FPK_E (5F0920790A SW 1701, EV_DashBoardVDDMQBA0, F197=KOMBI)
    ident_60 = [
        {"did": "F187", "value": "5F0920790A"},
        {"did": "F191", "value": "5F0920790A"},
        {"did": "F189", "value": "1701"},
        {"did": "F197", "value": "KOMBI"},
        {"did": "F19E", "value": "EV_DashBoardVDDMQBA0"},
    ]
    assert is_kombi_ident(ident_60) is False
    assert is_fpke_ident(ident_60) is True

    # Issue #61: Skoda Kodiaq FPK_E (565920790C SW 4300, EV_DashBoardVDDMQBA0, F197=KOMBI)
    ident_61 = [
        {"did": "F187", "value": "565920790C"},
        {"did": "F189", "value": "4300"},
        {"did": "F197", "value": "KOMBI"},
        {"did": "F19E", "value": "EV_DashBoardVDDMQBA0"},
    ]
    assert is_kombi_ident(ident_61) is False
    assert is_fpke_ident(ident_61) is True

    # Issue #62: SEAT Leon V850E2 Kombi (5F0920863 SW 6420, EV_DashBoardVDDMQBAB, even when F187 was missed)
    ident_62 = [
        {"did": "F189", "value": "6420"},
        {"did": "F197", "value": "KOMBI"},
        {"did": "F19E", "value": "EV_DashBoardVDDMQBAB"},
    ]
    assert is_kombi_ident(ident_62) is True
    assert is_fpke_ident(ident_62) is False

    # 5E0920790A (FPK_E) stays FPK_E even if ODX says EV_DashBoardVDDMQBAB or EV_DashBoardVDDMQBA0
    for odx in ("EV_DashBoardVDDMQBA0", "EV_DashBoardVDDMQBAB", "EV_DashBoardFPKContinentMQBAB"):
        ident_5e0 = [{"did": "F187", "value": "5E0920790A"}, {"did": "F189", "value": "1703"}, {"did": "F19E", "value": odx}]
        assert is_kombi_ident(ident_5e0) is False
        assert is_fpke_ident(ident_5e0) is True

    # Audi Q3 FPK_E (83A920700E) stays FPK_E
    ident_83a = [{"did": "F187", "value": "83A920700E"}, {"did": "F189", "value": "6181"}, {"did": "F19E", "value": "EV_DashBoardVDDMQBAU27"}]
    assert is_kombi_ident(ident_83a) is False
    assert is_fpke_ident(ident_83a) is True

    # Missing F187 with EV_DashBoardVDDMQBA0 defaults to FPK_E, not Kombi
    ident_mqba0_no_pn = [{"did": "F189", "value": "1701"}, {"did": "F197", "value": "KOMBI"}, {"did": "F19E", "value": "EV_DashBoardVDDMQBA0"}]
    assert is_kombi_ident(ident_mqba0_no_pn) is False
    assert is_fpke_ident(ident_mqba0_no_pn) is True

    # 6P0920740A (V850E2 Kombi) stays Kombi regardless of F19E variant
    for odx in ("EV_DashBoardVDDMQBAB", "EV_DashBoardVDDMQBA0", ""):
        ident_6p0 = [{"did": "F187", "value": "6P0920740A"}, {"did": "F189", "value": "1422"}, {"did": "F19E", "value": odx}]
        assert is_kombi_ident(ident_6p0) is True
        assert is_fpke_ident(ident_6p0) is False

    # Passat B8 analog V850E2 Kombi (EV_DashBoardVDDMQBAB)
    ident_3g0 = [{"did": "F187", "value": "3G0920798A"}, {"did": "F189", "value": "0310"}, {"did": "F19E", "value": "EV_DashBoardVDDMQBAB"}]
    assert is_kombi_ident(ident_3g0) is True
    assert is_fpke_ident(ident_3g0) is False


def test_is_kombi_dflash_rejects_fpke_83a_and_1703_and_accepts_dynamic_137_id_kombi() -> None:
    """Ensure 64 KiB FPK_E dumps (83A 235-ID and 1703 162-ID) are never misclassified as Kombi, while dynamic Kombi (e.g. 137 IDs) works."""
    from contitool.core.fpke import (
        EEL_83A_IDS,
        EEL_1703_IDS,
        FPKE_DFLASH_FBL_RSAKEY_OFFSET,
        eel_append_records,
        is_fpke_dflash,
    )
    from contitool.core.kombi import _build_empty_eel_t01_pool, kombi_eel_layout

    for id_map in (EEL_83A_IDS, EEL_1703_IDS):
        lay = {"vb": 0x800, "n_vb": 28, "base": 0, "threshold": 8, "ids": dict(id_map)}
        updates = {k: struct.pack("<H", sz) + (b"\xff" * (sz - 2)) for k, sz in sorted(id_map.items())}
        fpke_df = eel_append_records(_build_empty_eel_t01_pool(updates[1]), updates, layout=lay)
        assert is_fpke_dflash(fpke_df) is True
        assert is_kombi_dflash(fpke_df) is False

    # Dynamic 137-ID Kombi 64 KiB container (IDs 133..137 beyond 0310's 132) must be recognized & layout-recovered
    recs_dyn = _build_synthetic_kombi_records()
    dyn_ids = dict(EEL_KOMBI_0310_IDS)
    for extra_id, extra_sz in ((133, 24), (134, 16), (135, 32), (136, 12), (137, 20)):
        dyn_ids[extra_id] = extra_sz
        recs_dyn[extra_id] = struct.pack("<H", extra_sz) + bytes((extra_id + i) & 0xFF for i in range(extra_sz - 2))
    df_dyn = build_kombi_eel_dflash(recs_dyn, eel_ids=dyn_ids)
    assert is_kombi_dflash(df_dyn) is True
    lay_dyn = kombi_eel_layout(df_dyn)
    assert len(lay_dyn["ids"]) == 137
    assert lay_dyn["ids"][137] == 20

    # A 64 KiB dump containing an FPK_E .FBL_RSAKEY at 0xED00 must never be classified as Kombi
    df_with_rsa = bytearray(df_dyn)
    df_with_rsa[FPKE_DFLASH_FBL_RSAKEY_OFFSET : FPKE_DFLASH_FBL_RSAKEY_OFFSET + 128] = b"\x01" + (b"\xaa" * 126) + b"\x80"
    assert is_kombi_dflash(bytes(df_with_rsa)) is False







