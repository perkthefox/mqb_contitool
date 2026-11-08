"""Comprehensive tests for ZDC dataset parameterization, CAN ZDC/MFL/0x0600 workflows, GUI dialogs, and SWaP integration."""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import can  # noqa: E402
from PySide6.QtCore import QEventLoop, Qt, QTimer  # noqa: E402
import pytest  # noqa: E402

from contitool.can import (  # noqa: E402
    can_learn_mfl_button,
    can_read_gateway_coding,
    can_upload_zdc_datasets,
    can_write_gateway_coding,
)
from contitool.cli.main import main  # noqa: E402
from contitool.core import (  # noqa: E402
    FpaDataset,
    ROM_BEM_CATALOG,
    UNSUPPORTED_DATASET_WARNING,
    ZDC_UDS_UPLOAD_MAP,
    ZdcAutoParamConfig,
    analyze_dflash_datasets,
    analyze_dflash_swap,
    analyze_gateway_coding_consistency,
    apply_dflash_swap_fecs,
    apply_fpa_dataset,
    apply_mke_config,
    apply_ssa_config,
    apply_zdc_passport,
    build_fpa_preset_block,
    check_fec_dataset_support,
    erase_zdc_block,
    export_zdc_block,
    import_zdc_block,
    inject_bem_preset,
    inject_mke_preset,
    inject_ssa_preset,
    parameterize_dflash_for_fecs,
    parse_bem_block,
    parse_mke_block,
    parse_ssa_block,
    parse_zdc_passport,
    replace_bem_slot_from_rom,
    sync_gateway_coding_for_zdc,
    zdc_crc32_le,
)
from contitool.gui.app import create_window  # noqa: E402
from contitool.gui.dialogs.crypto import SwapActivateDialog  # noqa: E402
from contitool.gui.dialogs.zdc import (  # noqa: E402
    BemEditorDialog,
    FpaEditorDialog,
    MkeEditorDialog,
    SsaEditorDialog,
    ZdcPassportBlocksDialog,
)
from contitool.i18n import set_lang  # noqa: E402


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Core ZDC Passport & Per-Block Operations
# ═══════════════════════════════════════════════════════════════════════════════


def test_zdc_passport_and_block_transplant_preserve_cp_and_swap(synth_dflash: bytes) -> None:
    pp0 = parse_zdc_passport(synth_dflash)
    assert pp0.empty and not pp0.crc_ok

    with pytest.raises(ValueError):
        apply_zdc_passport(synth_dflash, dataset_pn="V03935256AA", dataset_ver="0000")

    # Dirty pad bytes before applying passport -> clean_pads=True wipes pads to 0xFF
    dirty = bytearray(synth_dflash)
    dirty[0x0008:0x0010] = b"GARBAGE!"
    df1 = apply_zdc_passport(
        bytes(dirty),
        dataset_pn="V03935300AR",
        dataset_ver="0002",
        equip="PR-2H4",
        clean_pads=True,
    )
    pp1 = parse_zdc_passport(df1)
    assert pp1.crc_ok
    assert pp1.pads_clean
    assert pp1.dataset_pn == "V03935300AR"
    assert pp1.dataset_ver == "0002"
    assert pp1.equip_ascii == "PR-2H4"
    assert df1[0x3040:] == synth_dflash[0x3040:]

    # Build a donor DataFlash with MKE + FPA + BEM and transplant ONLY ZDC #4 into target
    donor = inject_mke_preset(synth_dflash, "86")
    donor = apply_fpa_dataset(donor, build_fpa_preset_block("awd_dcc"))
    donor = inject_bem_preset(donor, "2222")

    transplanted = import_zdc_block(df1, 4, donor, fix_crc=True)
    assert transplanted[0x3040:] == synth_dflash[0x3040:]
    assert export_zdc_block(transplanted, 4) == export_zdc_block(donor, 4)
    assert all(b == 0xFF for b in export_zdc_block(transplanted, 1))

    erased = erase_zdc_block(transplanted, 4)
    assert all(b == 0xFF for b in export_zdc_block(erased, 4))
    assert erased[0x3040:] == synth_dflash[0x3040:]


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ZDC #1 (MKE), ZDC #2 (Start-Stop HMI), and ZDC #6 (BEM 21 ROM Alternators)
# ═══════════════════════════════════════════════════════════════════════════════


def test_mke_and_ssa_editors_roundtrip(synth_dflash: bytes) -> None:
    df = inject_mke_preset(synth_dflash, "86")
    mke = parse_mke_block(df)
    assert mke.crc_ok and mke.plausible
    assert (mke.speed_on_kmh, mke.speed_hyst_low_kmh, mke.speed_off_high_kmh) == (60, 5, 200)
    assert check_fec_dataset_support(df, 0x10000300).supported

    mke.speed_on_kmh = 70
    mke.speed_off_high_kmh = 210
    mke.full_rest_min = 12
    df2 = apply_mke_config(df, mke)
    mke2 = parse_mke_block(df2)
    assert mke2.crc_ok and mke2.plausible
    assert (mke2.speed_on_kmh, mke2.speed_off_high_kmh, mke2.full_rest_min) == (70, 210, 12)

    df_ssa = inject_ssa_preset(df2)
    ssa = parse_ssa_block(df_ssa)
    assert ssa.crc_ok and ssa.bap_output_mode == 1 and ssa.enabled_reasons_count > 50
    ssa.bap_output_mode = 3
    ssa.standstill_notice_delay_ms = 2500
    df_ssa2 = apply_ssa_config(df_ssa, ssa)
    ssa2 = parse_ssa_block(df_ssa2)
    assert ssa2.crc_ok and ssa2.bap_output_mode == 3 and ssa2.standstill_notice_delay_ms == 2500


def test_bem_21_rom_models_zero_diff_on_both_2222_and_0101(synth_dflash: bytes) -> None:
    for schema in ("2222", "0101"):
        df = inject_bem_preset(synth_dflash, schema)
        bem = parse_bem_block(df)
        assert bem.crc_ok and bem.version_tag == schema
        populated = [s for s in bem.slots if not s.empty]
        assert len(populated) == (3 if schema == "2222" else 4)
        max_stock_diff = 0 if schema == "2222" else 1
        for s in populated:
            assert s.matched_diff_bytes <= max_stock_diff, (
                f"Schema {schema} slot {s.slot_idx} had {s.matched_diff_bytes} diff bytes"
            )

        # Replace slot #7 with 250A Valeo (rom_idx=12) and verify 0-byte diff round-trip
        df_mod = replace_bem_slot_from_rom(df, 7, 12)
        bem_mod = parse_bem_block(df_mod)
        assert bem_mod.crc_ok
        assert not bem_mod.slots[7].empty
        assert bem_mod.slots[7].matched_rom_idx == 12
        assert bem_mod.slots[7].matched_diff_bytes == 0

        # Clear slot #7 back to FF..FF
        df_clr = replace_bem_slot_from_rom(df_mod, 7, None)
        assert parse_bem_block(df_clr).slots[7].empty
    assert len(ROM_BEM_CATALOG) == 21


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ZDC #4 (FPA Profiles, Kl.15 Memory, Simultaneous MODE + MFL, Coding 0x0600)
# ═══════════════════════════════════════════════════════════════════════════════


def test_fpa_presets_kl15_memory_simultaneous_buttons_and_coding(synth_dflash: bytes) -> None:
    # 1. Schema preservation on older 'JC00' gateway
    jc_fpa = build_fpa_preset_block("fwd_dcc", target_schema="JC00")
    df_jc = apply_fpa_dataset(synth_dflash, jc_fpa)
    parsed_jc = FpaDataset.from_dflash(df_jc)
    assert parsed_jc.crc_ok and parsed_jc.schema_tag == "JC00" and parsed_jc.header_s005 == 0x08

    # 2. 4Motion AWD preset ('NC00'): preserves 4Motion rotary knob (0x04) when enabling Console MODE + MFL simultaneously!
    awd = build_fpa_preset_block("awd_dcc")
    assert awd.has_4motion_rotary
    assert not check_fec_dataset_support(apply_fpa_dataset(synth_dflash, awd), 0x10001600).supported

    # Enable Race / Cupra (slot 6)
    awd.set_slot_enabled(6, True)
    df_race = apply_fpa_dataset(synth_dflash, awd)
    assert check_fec_dataset_support(df_race, 0x10001600).supported

    # Configure BOTH Console MODE + Steering-Wheel MFL (0x23 VIEW, long press, custom M1/M2 toggle [2, 6])
    awd.configure_buttons(
        mode="both",
        mfl_keycode=0x23,
        mfl_long_press=True,
        console_ring=[5, 1, 2, 3, 6, 7],
        mfl_ring=[2, 6],
        decouple_dsg_lever=True,
        personalization_pso=True,
    )
    bcfg = awd.button_config()
    assert bcfg.mode == "both"
    assert bcfg.has_4motion_rotary  # 4Motion rotary preserved!
    assert bcfg.mfl_keycode == 0x23
    assert bcfg.mfl_long_press is True
    assert bcfg.console_ring == [5, 1, 2, 3, 6, 7]
    assert bcfg.mfl_ring == [2, 6]
    assert bcfg.decouple_dsg_lever is True
    assert bcfg.personalization_pso is True

    # Two-level Kl.15 memory (S029 + S075 powertrain nibbles)
    awd.set_kl15_persistence(persist_profiles=True, persist_powertrain=True)
    assert awd.all_active_profiles_persist_kl15 is True
    assert awd.powertrain_persists_kl15 is True

    # S031 target matrix & S033 Individual menu edits
    groups = awd.logical_groups()
    assert len(groups) >= 10
    first_lidx = groups[0][0]
    awd.set_target_mode(6, first_lidx, 6)
    awd.set_individual_mask(first_lidx, 0b0111110)
    assert awd.get_target_mode(6, first_lidx) == 6
    assert awd.get_individual_mask(first_lidx) == 0b0111110

    # Gateway 0x0600 coding consistency & sync (ROM 0x0001EF38: #6=B0, #4=B8, #2=B15, #1=B17, #3=B19, #5=B29)
    df_full = inject_ssa_preset(inject_mke_preset(inject_bem_preset(apply_fpa_dataset(synth_dflash, awd), "2222"), "86"))
    blank_coding = bytearray(30)
    blank_coding[19] = 0x01  # Reserve #3 bit set while ZDC #3 empty -> B200500 warning!
    blank_coding[29] = 0x01  # Reserve #5 bit set while ZDC #5 empty -> B200500 warning!
    rep_before = analyze_gateway_coding_consistency(df_full, bytes(blank_coding))
    assert rep_before.warnings

    synced_coding = sync_gateway_coding_for_zdc(df_full, bytes(blank_coding))
    rep_after = analyze_gateway_coding_consistency(df_full, synced_coding)
    assert not rep_after.warnings
    assert all(g.consistent for g in rep_after.master_gates)
    assert (synced_coding[0] & 1) == 1   # BEM ZDC #6
    assert (synced_coding[8] & 1) == 1   # FPA ZDC #4
    assert (synced_coding[15] & 1) == 1  # SSA ZDC #2
    assert (synced_coding[17] & 1) == 1  # MKE ZDC #1
    assert (synced_coding[19] & 1) == 0  # Reserve #3 cleared
    assert (synced_coding[29] & 1) == 0  # Reserve #5 cleared

    # Passive JC00 base clears Byte 8 Bit 0 so all gates stay 100% consistent
    df_passive = synth_dflash
    c_passive = sync_gateway_coding_for_zdc(df_passive, bytes([0x01] * 30))
    rep_passive = analyze_gateway_coding_consistency(df_passive, c_passive)
    assert not rep_passive.warnings
    assert all(g.consistent for g in rep_passive.master_gates)
    assert (c_passive[8] & 1) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. 1-Click SWaP <-> ZDC Auto-Parameterization
# ═══════════════════════════════════════════════════════════════════════════════


def test_one_click_swap_autoparameterization_eliminates_unsupported_warnings(synth_dflash: bytes) -> None:
    assert ZDC_UDS_UPLOAD_MAP == {
        0: (0x00000A00, 0x0080),
        1: (0x00000A80, 0x0100),
        2: (0x00002880, 0x0800),
        3: (0x00003080, 0x0400),
        4: (0x00000B80, 0x1100),
        5: (0x00003E00, 0x012E),
        6: (0x00001C80, 0x0C00),
    }
    wanted_fecs = [
        0x10000100,
        0x10000300,
        0x10001100,
        0x10001200,
        0x10001300,
        0x10001600,
        0x10001700,
        0x10001A00,
        0x10001B00,
    ]
    # Start from NC00 4Motion AWD+DCC so S028[10..12] hold 0x36, 0x3B, 0x3A rotary sub-profiles
    df_nc00 = apply_fpa_dataset(synth_dflash, build_fpa_preset_block("awd_dcc"))
    s028_rotary_before = bytes(FpaDataset.from_dflash(df_nc00).sec_bytes(28)[10:13])
    assert s028_rotary_before == bytes([0x36, 0x3B, 0x3A])
    assert not check_fec_dataset_support(df_nc00, 0x10001A00).supported
    assert not check_fec_dataset_support(df_nc00, 0x10001B00).supported

    cfg = ZdcAutoParamConfig(
        enabled=True,
        fpa_preset="surgical",
        button_mode="both",
        mfl_keycode=0x19,
        kl15_persist_profiles=True,
        kl15_persist_powertrain=True,
    )
    df_param, actions = parameterize_dflash_for_fecs(df_nc00, wanted_fecs, cfg)
    assert len(actions) >= 3
    # 4Motion rotary slots S028[10..12] MUST stay untouched while Inst1 S153[1..2] are enabled!
    fpa_after = FpaDataset.from_dflash(df_param)
    assert bytes(fpa_after.sec_bytes(28)[10:13]) == s028_rotary_before
    assert fpa_after.sec_bytes(153)[1] != 0 and fpa_after.sec_bytes(153)[2] != 0

    logs: list[str] = []
    from contitool.progress import OperationReporter

    rep = OperationReporter(on_log=lambda entry: logs.append(f"{entry.level}:{entry.message}"))
    df_final, summary = apply_dflash_swap_fecs(df_param, enable_fecs=wanted_fecs, reporter=rep)
    assert summary["unsupported_fecs"] == []
    assert not any(UNSUPPORTED_DATASET_WARNING in line for line in logs)
    for code in wanted_fecs:
        assert check_fec_dataset_support(df_final, code).supported


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Mock ISO-TP UDS CAN Tests (ZDC Upload, MFL Button Learn, 0x0600 Coding)
# ═══════════════════════════════════════════════════════════════════════════════


class FakeZdcGateway:
    """ISO-TP single- & multi-frame mock J533 gateway matching real Continental RH850 UDS state machine."""

    def __init__(
        self,
        *,
        mfl_frames: list[bytes] | None = None,
        gra_frames: list[bytes] | None = None,
        force_crc_fail: bool = False,
    ) -> None:
        self.rx: list[bytes] = []
        self._tx_buf = bytearray()
        self._tx_expected = 0
        self.session = 0x01
        self.unlocked = False
        self.downloads: dict[int, bytearray] = {}
        self._cur_addr: int | None = None
        self._last_addr: int | None = None
        self._awaiting_check_memory = False
        self._passport_unlocked = False
        self._force_crc_fail = force_crc_fail
        self._cur_buf = bytearray()
        self._poll_count = 0
        self.dids: dict[int, bytes] = {
            0x0600: bytes(30),
        }
        self._mfl_frames = list(mfl_frames or [bytes(8)])
        self._gra_frames = list(gra_frames or [bytes.fromhex("AA01000000000000")])

    def _reply(self, payload: bytes) -> None:
        if len(payload) <= 7:
            self.rx.append(bytes([len(payload)]) + payload.ljust(7, b"\xaa"))
            return
        self.rx.append(bytes([0x10 | (len(payload) >> 8), len(payload) & 0xFF]) + payload[:6])
        for seq, off in enumerate(range(6, len(payload), 7), start=1):
            self.rx.append(bytes([0x20 | (seq & 0x0F)]) + payload[off : off + 7].ljust(7, b"\xaa"))

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        if msg.arbitration_id != 0x710:
            return
        d = bytes(msg.data)
        pci_type = d[0] >> 4
        if pci_type == 3:
            return  # FlowControl from tester
        if pci_type == 0:
            req = d[1 : 1 + (d[0] & 0x0F)]
            self._handle_uds(req)
        elif pci_type == 1:
            self._tx_expected = ((d[0] & 0x0F) << 8) | d[1]
            self._tx_buf = bytearray(d[2:8])
            self.rx.append(b"\x30\x00\x00\xaa\xaa\xaa\xaa\xaa")
        elif pci_type == 2:
            self._tx_buf.extend(d[1:8])
            if len(self._tx_buf) >= self._tx_expected:
                req = bytes(self._tx_buf[: self._tx_expected])
                self._tx_expected = 0
                self._handle_uds(req)

    def _handle_uds(self, req: bytes) -> None:
        sid = req[0]
        if sid == 0x10:
            self.session = req[1]
            self._reply(bytes([0x50, req[1], 0x00, 0x32, 0x01, 0xF4]))
        elif sid == 0x11:
            self._reply(bytes([0x51, req[1]]))
        elif sid == 0x27:
            if req[1] == 0x01:
                self._reply(b"\x67\x01\x12\x34\x56\x78")
            elif req[1] == 0x02:
                expected = (0x12345678 + 20103) & 0xFFFFFFFF
                if int.from_bytes(req[2:6], "big") == expected:
                    self.unlocked = True
                    self._reply(b"\x67\x02")
                else:
                    self._reply(b"\x7f\x27\x35")
        elif sid == 0x22:
            did = int.from_bytes(req[1:3], "big")
            if did == 0x1F07:
                frm = self._mfl_frames.pop(0) if len(self._mfl_frames) > 1 else self._mfl_frames[0]
                self._reply(b"\x62\x1f\x07" + frm)
            elif did == 0x1F19:
                frm = self._gra_frames.pop(0) if len(self._gra_frames) > 1 else self._gra_frames[0]
                self._reply(b"\x62\x1f\x19" + frm)
            elif did in self.dids:
                self._reply(b"\x62" + req[1:3] + self.dids[did])
            else:
                self._reply(b"\x7f\x22\x31")
        elif sid == 0x2E:
            did = int.from_bytes(req[1:3], "big")
            if did in (0xF1A0, 0xF1A1, 0xF1A4) and not self._passport_unlocked:
                self._reply(b"\x7f\x2e\x22")
                return
            self.dids[did] = req[3:]
            self._reply(b"\x6e" + req[1:3])
        elif sid == 0x34:
            assert self.session == 0x40 and self.unlocked
            if self._awaiting_check_memory:
                # Real J533 rejects back-to-back 0x34 without 0x02EF with NRC 0x22!
                self._reply(b"\x7f\x34\x22")
                return
            addr = int.from_bytes(req[3:7], "big")
            size = int.from_bytes(req[7:11], "big")
            if (addr, size) not in set(ZDC_UDS_UPLOAD_MAP.values()):
                self._reply(b"\x7f\x34\x70")
                return
            self._cur_addr = addr
            self._cur_buf = bytearray()
            self._reply(b"\x74\x20\x00\xfc")
        elif sid == 0x36:
            self._cur_buf.extend(req[2:])
            self._reply(bytes([0x76, req[1]]))
        elif sid == 0x37:
            assert self._cur_addr is not None
            self.downloads[self._cur_addr] = bytearray(self._cur_buf)
            self._last_addr = self._cur_addr
            self._cur_addr = None
            self._awaiting_check_memory = True
            self._reply(b"\x77")
        elif sid == 0x31:
            if req[:4] == bytes.fromhex("310102EF"):
                if not self._awaiting_check_memory or self._last_addr is None:
                    self._reply(b"\x7f\x31\x24")
                    return
                self._poll_count = 0
                self._awaiting_check_memory = False
                self._reply(bytes.fromhex("710102EF01"))
            elif req[:4] == bytes.fromhex("310302EF"):
                self._poll_count += 1
                if self._poll_count == 1:
                    self._reply(bytes.fromhex("710302EF01"))
                else:
                    assert self._last_addr is not None
                    buf = self.downloads[self._last_addr]
                    ok = (not self._force_crc_fail) and (
                        int.from_bytes(buf[-4:], "little") == zdc_crc32_le(buf[:-4])
                    )
                    if ok:
                        self._passport_unlocked = True
                    # Real Continental J533: 02 FF FF = CRC PASS, 02 00 00 = CRC FAIL
                    self._reply(bytes.fromhex("710302EF02FFFF" if ok else "710302EF020000"))

    def recv(self, timeout: float | None = None) -> can.Message | None:
        if self.rx:
            return can.Message(arbitration_id=0x77A, data=self.rx.pop(0), is_extended_id=False)
        return None

    def shutdown(self) -> None:
        pass


def test_can_upload_zdc_mfl_learn_and_gateway_coding(synth_dflash: bytes) -> None:
    df = inject_mke_preset(synth_dflash, "86")
    df = apply_fpa_dataset(df, build_fpa_preset_block("fwd_dcc"))
    df = apply_zdc_passport(df, dataset_pn="V03935256EE", dataset_ver="0003")

    gw = FakeZdcGateway()
    res = can_upload_zdc_datasets("fake", df, bus=gw)
    assert res["complete"] is True
    assert [b["idx"] for b in res["uploaded_blocks"]] == [1, 4]
    assert gw.downloads[ZDC_UDS_UPLOAD_MAP[1][0]] == export_zdc_block(df, 1)
    assert gw.downloads[ZDC_UDS_UPLOAD_MAP[4][0]] == export_zdc_block(df, 4)
    assert gw.dids[0xF1A0] == b"V03935256EE"
    assert gw.dids[0xF1A1] == b"0003"

    # Verify negative CRC check (71 03 02 EF 02 00 00 -> RuntimeError)
    gw_bad = FakeZdcGateway(force_crc_fail=True)
    with pytest.raises(RuntimeError, match="02EF"):
        can_upload_zdc_datasets("fake", df, bus=gw_bad)

    # MFL button live learn: idle (rolling GRA counter changes ignored!) -> Voice key 0x19 pressed
    gw_mfl = FakeZdcGateway(
        mfl_frames=[
            bytes.fromhex("0000000000000000"),  # baseline
            bytes.fromhex("0000000000000000"),  # poll 1 (idle)
            bytes.fromhex("0019000100000000"),  # poll 2 (Voice 0x19 pressed!)
        ],
        gra_frames=[
            bytes.fromhex("AA01000000000000"),  # baseline BZ=1
            bytes.fromhex("BB02000000000000"),  # poll 1 BZ=2, different CRC -> MUST NOT false-trigger!
            bytes.fromhex("CC03000000000000"),
        ],
    )
    learn_ok = can_learn_mfl_button("fake", bus=gw_mfl, timeout_s=2.0)
    assert learn_ok["captured"] is True
    assert learn_ok["keycode"] == 0x19
    assert learn_ok["gra_button_detected"] is False

    # GRA_Neu Travel Assist press detected cleanly when 0x1F07 stays 0x00 and 0x1F19 button byte changes
    gw_ta = FakeZdcGateway(
        mfl_frames=[bytes(8), bytes(8)],
        gra_frames=[
            bytes.fromhex("AA01000000000000"),
            bytes.fromhex("DD02100000000000"),  # byte 2 bit 4 (TA_Taste) set!
        ],
    )
    learn_ta = can_learn_mfl_button("fake", bus=gw_ta, timeout_s=2.0)
    assert learn_ta["captured"] is False
    assert learn_ta["gra_button_detected"] is True

    # Gateway 0x0600 Long Coding read + write + readback verification
    new_coding = bytes.fromhex("030100047F08" + "00" * 24)
    w_res = can_write_gateway_coding("fake", new_coding, bus=gw)
    assert w_res["coding"] == new_coding
    r_res = can_read_gateway_coding("fake", bus=gw)
    assert r_res["coding"] == new_coding


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Headless GUI Tests (`Параметрирование` Page, 5 ZDC Dialogs, SWaP 1-Click)
# ═══════════════════════════════════════════════════════════════════════════════


def test_gui_parameterization_page_dialogs_and_swap_integration(
    synth_cflash: bytes,
    synth_dflash: bytes,
    synth_uflash: bytes,
    tmp_path: Path,
) -> None:
    set_lang("ru")
    app, win = create_window()
    try:
        folder = tmp_path / "ecu_zdc"
        folder.mkdir()
        (folder / "Cflash.bin").write_bytes(synth_cflash)
        (folder / "Dflash.bin").write_bytes(synth_dflash)
        (folder / "Uflash.bin").write_bytes(synth_uflash)

        win.open_folder(str(folder))
        app.processEvents()
        screen = win.ecu_screen
        assert "zdc" in screen.nav_rows
        assert screen.nav_rows["zdc"].lbl_name.text() == "Параметрирование"

        screen.select("zdc")
        app.processEvents()
        for btn_key in ("zdc_fpa", "zdc_mke", "zdc_ssa", "zdc_bem", "zdc_passport", "zdc_can_upload"):
            assert btn_key in screen.actions

        # Exercise all 5 ZDC dialogs headlessly
        for pkey in ("fwd", "fwd_dcc", "awd", "awd_dcc"):
            assert build_fpa_preset_block(pkey).detected_preset() == pkey
        assert not build_fpa_preset_block("fwd_dcc").slots()[3].selectable  # Offroad (slot 4) must stay OFF on 2WD+DCC
        assert build_fpa_preset_block("awd_dcc").slots()[3].selectable

        # 1) Empty dump: honest initial state (no fake pre-checked profiles)
        dlg_fpa = FpaEditorDialog(synth_dflash)
        assert dlg_fpa._unconfigured is True
        assert dlg_fpa.cmb_preset.currentData() == ""
        assert not dlg_fpa.btn_ok.isEnabled()
        for r in range(9):
            assert dlg_fpa.tbl_slots.item(r, 0).checkState() == Qt.CheckState.Unchecked
            assert dlg_fpa.tbl_slots.item(r, 2).text() == "Не в датасете"
        assert dlg_fpa.result_dflash() == synth_dflash

        # Toggling ignition memory auto-bootstraps preset and unlocks controls
        dlg_fpa.chk_kl15_profiles.setChecked(True)
        assert dlg_fpa._unconfigured is False
        assert dlg_fpa.btn_ok.isEnabled()
        dlg_fpa.chk_kl15_powertrain.setChecked(True)
        dlg_fpa._toggle_slot_row(5, 1)  # toggle Race/Cupra (slot 6) on configured dump
        assert dlg_fpa.tbl_slots.item(5, 0).checkState() == Qt.CheckState.Checked
        dlg_fpa.cmb_btn_mode.setCurrentIndex(dlg_fpa.cmb_btn_mode.findData("both"))
        dlg_fpa.ed_mfl_hex.setText("23")
        dlg_fpa.set_mfl_ring_slots([2, 3])
        df_after_fpa = dlg_fpa.result_dflash()
        dlg_fpa.close()
        fpa_chk = FpaDataset.from_dflash(df_after_fpa)
        assert fpa_chk.crc_ok and fpa_chk.all_active_profiles_persist_kl15 and fpa_chk.powertrain_persists_kl15
        assert fpa_chk.slots()[5].selectable  # slot 6 enabled via row click
        assert fpa_chk.button_config().mode == "both" and fpa_chk.button_config().mfl_keycode == 0x23
        assert fpa_chk.button_config().mfl_ring == [2, 3]

        # 2) Passive base JC00 dump (V03935293BA-style): 0 profiles on open, preserves JC00 when configured
        passive_jc00 = build_fpa_preset_block("fwd_dcc", target_schema="JC00")
        s028_p = passive_jc00.sec_bytes(28)
        s028_p[2] = 0x14
        passive_jc00.set_sec_bytes(28, s028_p)
        passive_jc00.selectable_mask = 0x0001
        df_passive_jc00 = apply_fpa_dataset(synth_dflash, passive_jc00)
        assert FpaDataset.from_dflash(df_passive_jc00).is_passive_base
        assert FpaDataset.from_dflash(df_passive_jc00).schema_tag == "JC00"

        dlg_jc = FpaEditorDialog(df_passive_jc00)
        assert dlg_jc._unconfigured is True
        assert dlg_jc.cmb_preset.currentData() == ""
        assert not dlg_jc.btn_ok.isEnabled()
        for r in range(9):
            assert dlg_jc.tbl_slots.item(r, 0).checkState() == Qt.CheckState.Unchecked
            assert dlg_jc.tbl_slots.item(r, 2).text() == "Не в датасете"
        dlg_jc.cmb_preset.setCurrentIndex(dlg_jc.cmb_preset.findData("fwd_dcc"))
        assert dlg_jc._unconfigured is False
        assert dlg_jc.btn_ok.isEnabled()
        assert dlg_jc.tbl_slots.item(0, 0).checkState() == Qt.CheckState.Checked  # Comfort ON
        assert dlg_jc.tbl_slots.item(3, 0).checkState() == Qt.CheckState.Unchecked  # Offroad OFF on 2WD+DCC
        fpa_jc_saved = FpaDataset.from_dflash(dlg_jc.result_dflash())
        dlg_jc.close()
        assert fpa_jc_saved.crc_ok and not fpa_jc_saved.is_passive_base
        assert fpa_jc_saved.schema_tag == "JC00"
        assert {s.slot for s in fpa_jc_saved.slots() if s.selectable} == {1, 2, 3, 5, 7}

        # Re-open on populated dump: auto-detects chassis and keeps destructive reset panel collapsed
        dlg_fpa2 = FpaEditorDialog(df_after_fpa)
        assert dlg_fpa2._unconfigured is False
        assert not dlg_fpa2.pnl_reset_preset.isVisible()
        assert "DCC" in dlg_fpa2.lbl_detected_base.text()
        dlg_fpa2.close()

        dlg_mke = MkeEditorDialog(df_after_fpa)
        dlg_mke._spins["speed_on_kmh"].setValue(68)
        df_after_mke = dlg_mke.result_dflash()
        dlg_mke.close()
        assert parse_mke_block(df_after_mke).speed_on_kmh == 68

        dlg_ssa = SsaEditorDialog(df_after_mke)
        dlg_ssa.cmb_mode.setCurrentIndex(dlg_ssa.cmb_mode.findData(3))
        df_after_ssa = dlg_ssa.result_dflash()
        dlg_ssa.close()
        assert parse_ssa_block(df_after_ssa).bap_output_mode == 3

        dlg_bem = BemEditorDialog(df_after_ssa)
        dlg_bem.cmb_slot.setCurrentIndex(4)
        dlg_bem.cmb_rom.setCurrentIndex(dlg_bem.cmb_rom.findData(12))
        dlg_bem._assign_slot()
        df_after_bem = dlg_bem.result_dflash()
        dlg_bem.close()
        assert parse_bem_block(df_after_bem).slots[4].matched_rom_idx == 12

        dlg_pp = ZdcPassportBlocksDialog(df_after_bem)
        dlg_pp.ed_pn.setText("V03935999ZZ")
        dlg_pp.ed_ver.setText("0009")
        dlg_pp._on_accept()
        df_after_pp = dlg_pp.result_dflash()
        dlg_pp.close()
        assert parse_zdc_passport(df_after_pp).dataset_pn == "V03935999ZZ"

        # Exercise SwapActivateDialog 1-click auto-parameterization on empty ZDC DataFlash
        dlg_sw = SwapActivateDialog(analyze_dflash_swap(synth_dflash), analyze_dflash_datasets(synth_dflash))
        dlg_sw.show()
        dlg_sw.set_fec_checked(0x10000300, True)
        dlg_sw.set_fec_checked(0x10001600, True)
        app.processEvents()
        assert dlg_sw.warn_callout.isVisible()
        assert dlg_sw.param_frame.isVisible()
        ap_cfg = dlg_sw.auto_param_config()
        assert ap_cfg is not None and ap_cfg.enabled is True
        dlg_sw.close()

        screen._apply_swap_direct([0x10000300, 0x10001600], vin="", auto_param=ap_cfg)
        loop = QEventLoop()
        win.runner.operation_finished.connect(lambda *_: loop.quit())
        QTimer.singleShot(8000, loop.quit)
        loop.exec()
        app.processEvents()

        patched_df = win.ws.path("dflash").read_bytes()
        assert check_fec_dataset_support(patched_df, 0x10000300).supported
        assert check_fec_dataset_support(patched_df, 0x10001600).supported
    finally:
        set_lang("en")
        win.close()
        app.processEvents()


# ═══════════════════════════════════════════════════════════════════════════════
# 7. CLI Subcommands & Repository Hygiene Scan
# ═══════════════════════════════════════════════════════════════════════════════


def test_cli_parameterize_and_activate_swap_auto_parameterize(synth_dflash: bytes, tmp_path: Path) -> None:
    df_in = tmp_path / "Dflash_in.bin"
    df_p1 = tmp_path / "Dflash_param.bin"
    df_p2 = tmp_path / "Dflash_swap_auto.bin"
    blk4_bin = tmp_path / "zdc4.bin"
    df_in.write_bytes(synth_dflash)

    rc1 = main(
        [
            "-l",
            "en",
            "--no-color",
            "parameterize",
            "-i",
            str(df_in),
            "-o",
            str(df_p1),
            "--fpa-preset",
            "awd_dcc",
            "--enable-fpa-slots",
            "6",
            "--button-mode",
            "both",
            "--mfl-key",
            "0x19",
            "--mfl-long-press",
            "--kl15-profiles",
            "keep",
            "--kl15-powertrain",
            "keep",
            "--mke-preset",
            "86",
            "--ssa-preset",
            "4C",
            "--bem-preset",
            "2222",
            "--dataset-pn",
            "V03935256AR",
            "--dataset-ver",
            "0004",
        ]
    )
    assert rc1 == 0
    raw_p1 = df_p1.read_bytes()
    assert check_fec_dataset_support(raw_p1, 0x10001600).supported
    assert check_fec_dataset_support(raw_p1, 0x10000300).supported
    assert parse_zdc_passport(raw_p1).dataset_pn == "V03935256AR"

    rc_exp = main(["-l", "en", "--no-color", "parameterize", "-i", str(df_p1), "--export-block", f"4={blk4_bin}"])
    assert rc_exp == 0 and blk4_bin.stat().st_size == 4352

    rc2 = main(
        [
            "-l",
            "en",
            "--no-color",
            "activate-swap",
            "-i",
            str(df_in),
            "-o",
            str(df_p2),
            "--fec",
            "10000300",
            "10001600",
            "--auto-parameterize",
            "--button-mode",
            "both",
            "--kl15-memory",
            "--no-vin",
        ]
    )
    assert rc2 == 0
    raw_p2 = df_p2.read_bytes()
    assert check_fec_dataset_support(raw_p2, 0x10000300).supported
    assert check_fec_dataset_support(raw_p2, 0x10001600).supported


def test_live_can_work_never_runs_on_the_gui_thread(synth_dflash: bytes, monkeypatch) -> None:
    """Without a free runner the dialog refuses instead of talking to the adapter from the GUI thread."""
    from PySide6.QtWidgets import QMessageBox

    from contitool.gui.dialogs import zdc as zdc_dialogs

    set_lang("en")
    app, win = create_window()
    called: list[str] = []
    shown: list[str] = []
    monkeypatch.setattr(zdc_dialogs, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(zdc_dialogs, "can_read_gateway_coding", lambda *a, **k: called.append("read") or {})
    monkeypatch.setattr(QMessageBox, "information", lambda _p, _t, text, *a, **k: shown.append(text))
    dlg = zdc_dialogs.FpaEditorDialog(synth_dflash, win.conn, None, win)
    dlg._read_coding_live()
    assert called == [] and "Wait until" in shown[0]
    win.close()
