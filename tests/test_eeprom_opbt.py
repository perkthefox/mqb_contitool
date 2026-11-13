"""Tests for external ST M95640 SPI EEPROM and Renesas RH850/F1L Option Bytes (OPBT) read-only support."""

from __future__ import annotations

import json
import os
from pathlib import Path
import struct
from typing import Any
import can
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QMessageBox  # noqa: E402

from contitool.can import (  # noqa: E402
    EEPROM_M95640_READER_STUB,
    OPBT_READER_STUB,
    build_loader_packet,
    build_m95640_reader_payload,
    build_opbt_reader_payload,
    can_backup,
    can_read_eeprom,
    can_read_opbt,
    verify_payload_self_tests,
)
from contitool.cli.main import main as cli_main  # noqa: E402
from contitool.core import (  # noqa: E402
    EEPROM_SIZE,
    EXTRA_AREA_SIZE,
    OPBT_LEGACY_SIZE,
    OPBT_SIZE,
    analyze_eeprom,
    analyze_opbt,
    crc16_ccitt_false,
    decode_m95640_rdsr,
    detect_dump_file,
    is_plausible_eeprom_bytes,
    is_plausible_opbt_bytes,
    parse_cflash_eeprom_nvm_table,
)
from contitool.gui.app import create_window  # noqa: E402
from contitool.gui.screens import status  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402
from contitool.progress import OperationReporter  # noqa: E402
from contitool.storage import keep_as_base  # noqa: E402
from test_can_full_write import SimulatedJ533CanBus, SimulatedRh850FaciMcu  # noqa: E402


def _put_tlv_record(buf: bytearray, offset: int, payload: bytes, *, mirror: bool = False) -> None:
    tag = offset - 0x0020
    crc = crc16_ccitt_false(payload)
    rec = struct.pack("<HHH", tag, len(payload), crc) + payload
    buf[offset : offset + len(rec)] = rec
    if mirror:
        m_off = offset + len(rec)
        m_hdr = struct.pack("<HHH", m_off - 0x0020, len(payload), crc)
        buf[m_off : m_off + 6 + len(payload)] = m_hdr + payload


def make_synthetic_eeprom() -> bytes:
    """Construct a realistic 8 KB Continental J533 ST M95640 image with valid CRC-16/CCITT-FALSE records."""
    ee = bytearray(b"\xff" * EEPROM_SIZE)

    # NvM 0x00 (0x0000..0x005D, 94 B headerless passport)
    ee[0x0000:0x005E] = b"\x00" * 94
    ee[0x001C:0x0020] = b"5504"
    ee[0x0020:0x002B] = b"3Q0907530AR"
    ee[0x002C:0x0039] = b"EV_GatewConti"
    ee[0x0046:0x004F] = b"013020A01"

    # NvM 0x01 (0x0064, 2 B headerless)
    ee[0x0064:0x0066] = b"\x01\x00"

    # NvM 0x08: Programming date (BCD 26-11-13) + counter = 3 (5 B @ 0x00F2)
    _put_tlv_record(ee, 0x00F2, bytes([0x26, 0x11, 0x13, 0x00, 0x03]))

    # NvM 0x09: Verbauliste DID 0x04A3 (32 B @ 0x0100)
    verbauliste = bytes(range(0x10, 0x30))
    _put_tlv_record(ee, 0x0100, verbauliste)

    # NvM 0x0D: Long Coding DID 0x0600 (30 B @ 0x03D0)
    coding = bytes.fromhex("030100347F085700000002581C0000000001000000000000000000000000")
    _put_tlv_record(ee, 0x03D0, coding)

    # NvM 0x0E: Transport mode (6 B @ 0x0420)
    _put_tlv_record(ee, 0x0420, b"\x00\x01\x02\x03\x04\x05")

    # NvM 0x0F: 17-char VIN (@ 0x0460)
    _put_tlv_record(ee, 0x0460, b"WVWZZZ3CZWE000123")

    # NvM 0x21: Workshop code F198 (6 B @ 0x0810)
    _put_tlv_record(ee, 0x0810, bytes.fromhex("123456789ABC"))

    # NvM 0x27: BEM battery adaptation (42 B @ 0x0850)
    p27 = bytearray(42)
    p27[0] = 68  # 68 Ah
    p27[2:5] = b"JCB"
    p27[5:15] = b"1111111111"
    _put_tlv_record(ee, 0x0850, bytes(p27))

    # NvM 0x31: Stored DTCs (30 B = 5 x 6 B @ 0x0A40)
    p31 = bytearray(b"\xff" * 30)
    p31[0:6] = bytes([0x29, 0x01, 0x00, 0x00, 0x04, 0x01])  # DTC 0x000401, status 0x29
    _put_tlv_record(ee, 0x0A40, bytes(p31))

    # NvM 0x5E: Security / CP learned mask & engineering flags (18 B @ 0x1324)
    # Learned mask bits: bit 0 (slot #1 = 5F), bit 1 (slot #2 = 17), bit 4 (slot #5 = 47) -> 0x0013
    # Master CP learned = bit 0 of byte 11; Showroom off; eng_disable_mask = 0x000A (0x80=ON, 0x81=OFF, 0x83=OFF)
    p5e = bytearray(18)
    p5e[4] = 0  # showroom counter
    struct.pack_into("<H", p5e, 5, 0x0013)
    p5e[11] = 0x01  # master_cp_learned=True, showroom=False
    struct.pack_into("<H", p5e, 12, 0x000A)
    _put_tlv_record(ee, 0x1324, bytes(p5e))

    # NvM 0x5F: CMAC security block (55 B @ 0x133C)
    _put_tlv_record(ee, 0x133C, bytes((i * 3) & 0xFF for i in range(55)))

    return bytes(ee)


def make_synthetic_opbt36(*, opbt0: int = 0x9AA7FFEF, opbt1: int = 0, opbt8: int = 0x0FFFFFFF) -> bytes:
    return struct.pack("<9I", opbt0, opbt1, 0, 0, 0, 0, 0, 0, opbt8)


def _embed_cflash_eeprom_table(cflash: bytes) -> bytes:
    """Embed a 96-entry (NvM 0x00..0x5F) 16-byte external EEPROM descriptor table into synthetic Cflash."""
    cf = bytearray(cflash)
    base = 0x22000
    specs: dict[int, tuple[int, int, int]] = {
        0x00: (0x0000, 94, 0),
        0x01: (0x0064, 2, 0),
        0x08: (0x00F2, 5, 0),
        0x09: (0x0100, 32, 0),
        0x0D: (0x03D0, 30, 0),
        0x0E: (0x0420, 6, 0),
        0x0F: (0x0460, 17, 0),
        0x21: (0x0810, 6, 0),
        0x27: (0x0850, 42, 0),
        0x31: (0x0A40, 30, 0),
        0x5E: (0x1324, 18, 0),
        0x5F: (0x133C, 55, 0),
    }
    next_free = 0x1500
    for nvm_id in range(0x60):
        if nvm_id in specs:
            off, sz, flags = specs[nvm_id]
        else:
            off, sz, flags = next_free, 4, 0
            next_free += 10
        struct.pack_into("<HHIII", cf, base + nvm_id * 16, off, sz, flags, 0, 0)
    return bytes(cf)


def test_opbt_decoder_and_plausibility_across_all_formats(tmp_path: Path) -> None:
    raw36 = make_synthetic_opbt36()
    raw32 = raw36[:OPBT_LEGACY_SIZE]
    extra256 = bytearray(b"\xff" * EXTRA_AREA_SIZE)
    extra256[0x70 : 0x70 + OPBT_SIZE] = raw36

    for raw, exp_words, exp_icus in (
        (raw36, 9, True),
        (raw32, 8, None),
        (bytes(extra256), 9, True),
    ):
        assert is_plausible_opbt_bytes(raw) is True
        info = analyze_opbt(raw)
        assert len(info.words) == exp_words
        assert info.opbt0 == 0x9AA7FFEF
        assert info.reserved_bits_ok is True
        assert info.blank is False
        assert info.jtag_mode == 0 and info.jtag_enabled is False
        assert info.wdta0_enabled is False and info.wdta0_var_code is False
        assert info.wdta1_enabled is True and info.wdta1_var_code is False
        assert info.wdt_overflow_exp == 16
        assert info.memcdiv_div4 is True
        assert info.cvm_high_enabled is True and info.cvm_low_enabled is False
        assert info.icus_activated is exp_icus

    # OPBT8 bit 31 == 1 -> ICU-S inactive
    inactive = analyze_opbt(make_synthetic_opbt36(opbt8=0xFFFFFFFF))
    assert inactive.icus_activated is False

    # Arbitrary 36-byte random/text file is NOT misclassified as OPBT
    junk_path = tmp_path / "notes.bin"
    junk_path.write_bytes(b"NOT_AN_OPBT_FILE_AT_ALL_1234567890!!")
    assert is_plausible_opbt_bytes(junk_path.read_bytes()) is False
    det_junk = detect_dump_file(junk_path)
    assert det_junk.valid is False

    opbt_path = tmp_path / "Opbt.bin"
    opbt_path.write_bytes(raw36)
    det_ok = detect_dump_file(opbt_path)
    assert det_ok.valid is True and det_ok.kind == "opbt"


def test_eeprom_decoder_standalone_and_with_cflash_nvm_table(synth_cflash: bytes, tmp_path: Path) -> None:
    ee_raw = make_synthetic_eeprom()
    assert is_plausible_eeprom_bytes(ee_raw) is True

    rdsr = decode_m95640_rdsr(0x8C)
    assert rdsr.srwd is True and rdsr.bp_bits == 3 and not rdsr.wel and not rdsr.wip

    # 1. Standalone TLV analysis
    standalone = analyze_eeprom(ee_raw, rdsr=0x8C)
    assert standalone.from_cflash_table is False
    assert standalone.part_number == "3Q0907530AR"
    assert standalone.sw_version == "5504"
    assert standalone.asam_id == "EV_GatewConti"
    assert standalone.vin == "WVWZZZ3CZWE000123"
    assert standalone.prog_date == "2026-11-13"
    assert standalone.prog_counter == 3
    assert standalone.workshop_hex == "123456789ABC"
    assert len(standalone.long_coding) == 30
    assert len(standalone.verbauliste) == 32
    assert standalone.bem_capacity_ah == 68
    assert standalone.bem_vendor == "JCB"
    assert standalone.bem_serial == "1111111111"
    assert standalone.stored_dtcs == ((0x000401, 0x29),)
    assert standalone.nvm_5e_present is True and standalone.nvm_5e_crc_ok is True
    assert standalone.learned_cp_mask == 0x0013
    assert [s.ecu_addr for s in standalone.learned_cp_slots] == ["17", "09", "47"]
    assert standalone.master_cp_learned is True
    assert standalone.showroom_mode_active is False
    assert standalone.eng_disable_mask == 0x000A
    assert standalone.feat_80_enabled is True
    assert standalone.feat_81_enabled is False
    assert standalone.feat_83_enabled is False
    assert standalone.crc_bad_count == 0 and standalone.crc_ok_count >= 9

    # 2. Cflash NvM table-driven analysis + mirror fallback on primary CRC error
    cf_with_tbl = _embed_cflash_eeprom_table(synth_cflash)
    tbl = parse_cflash_eeprom_nvm_table(cf_with_tbl)
    assert len(tbl) == 96
    from_cf = analyze_eeprom(ee_raw, cf_with_tbl)
    assert from_cf.from_cflash_table is True
    assert from_cf.vin == "WVWZZZ3CZWE000123"
    assert from_cf.crc_bad_count == 0

    # Corrupt 1 byte inside NvM 0x0D -> detected as CRC error
    corrupted = bytearray(ee_raw)
    corrupted[0x03D8] ^= 0xFF
    bad_summary = analyze_eeprom(bytes(corrupted), cf_with_tbl)
    assert bad_summary.crc_bad_count == 1

    ee_file = tmp_path / "Eeprom.bin"
    ee_file.write_bytes(ee_raw)
    det_ee = detect_dump_file(ee_file)
    assert det_ee.valid is True and det_ee.kind == "eeprom"


def test_rh850_opbt_and_m95640_applets_execute_on_cpu_simulator(
    synth_cflash: bytes, synth_uflash: bytes, synth_dflash: bytes
) -> None:
    verify_payload_self_tests()
    assert build_opbt_reader_payload() == OPBT_READER_STUB
    assert build_m95640_reader_payload() == EEPROM_M95640_READER_STUB
    assert len(build_loader_packet(OPBT_READER_STUB)) < 1024
    assert len(build_loader_packet(EEPROM_M95640_READER_STUB)) < 2560

    mcu = SimulatedRh850FaciMcu(synth_cflash, synth_uflash, synth_dflash)
    ee_expected = make_synthetic_eeprom()
    mcu.eeprom[:] = ee_expected

    # 1. Execute OPBT_READER_STUB on SimulatedRh850FaciMcu
    mcu.wdta_kicks = {0xFFED0000: 0, 0xFFED1000: 0}
    mcu.execute_loader_payload(OPBT_READER_STUB)
    hdr_off = 0xFEDE9000 - mcu.RAM_BASE
    status_opbt, init_bfa, final_bfa = struct.unpack_from("<3I", mcu.ram, hdr_off)
    assert (status_opbt, init_bfa, final_bfa) == (1, 0, 0)
    assert mcu.bfaselr == 0
    assert mcu.wdta_kicks == {0xFFED0000: 2, 0xFFED0000 + 0x1000: 2}
    opbt_slice = bytes(mcu.ram[hdr_off + 0x170 : hdr_off + 0x194])
    assert opbt_slice == make_synthetic_opbt36()

    # 2. Execute EEPROM_M95640_READER_STUB on SimulatedRh850FaciMcu
    mcu.wdta_kicks = {0xFFED0000: 0, 0xFFED1000: 0}
    mcu.execute_loader_payload(EEPROM_M95640_READER_STUB)
    status_ee, rdsr_val, n_read = struct.unpack_from("<3I", mcu.ram, hdr_off)
    assert status_ee == 1
    assert rdsr_val == 0x8C
    assert n_read == EEPROM_SIZE
    # Port 10 (+0x100..+0x127 vs +0x180..+0x1A7) & CSIH1 (+0x130..+0x14B vs +0x1B0..+0x1CB) restored bit-for-bit
    assert mcu.ram[hdr_off + 0x100 : hdr_off + 0x128] == mcu.ram[hdr_off + 0x180 : hdr_off + 0x1A8]
    assert mcu.ram[hdr_off + 0x130 : hdr_off + 0x14C] == mcu.ram[hdr_off + 0x1B0 : hdr_off + 0x1CC]
    assert mcu.wdta_kicks == {0xFFED0000: 66, 0xFFED1000: 66}  # 1 entry + 64 x 128B + 1 exit
    ee_out_off = 0xFEDEA000 - mcu.RAM_BASE
    assert bytes(mcu.ram[ee_out_off : ee_out_off + EEPROM_SIZE]) == ee_expected


class _CaptureReporter(OperationReporter):
    def __init__(self) -> None:
        super().__init__()
        self.warnings: list[str] = []

    def warning(self, text: str) -> None:
        self.warnings.append(text)


def test_can_backup_includes_extras_and_emits_non_fatal_warning_on_failure(
    synth_cflash: bytes,
    synth_uflash: bytes,
    synth_dflash: bytes,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time
    import contitool.can.workflows as wf

    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    mcu = SimulatedRh850FaciMcu(synth_cflash, synth_uflash, synth_dflash)
    ee_expected = make_synthetic_eeprom()
    mcu.eeprom[:] = ee_expected
    sim_bus = SimulatedJ533CanBus(mcu)
    monkeypatch.setattr(can.interface, "Bus", lambda **kwargs: sim_bus)

    # 1. Full CAN backup succeeds for all 5 files (Cflash, Uflash, Dflash, Opbt, Eeprom)
    rep_ok = _CaptureReporter()
    dir_ok = tmp_path / "unit1" / "dumps" / "2026-11-13_read"
    dir_ok.mkdir(parents=True)
    res_ok = can_backup("mock0", session_dir=dir_ok, reporter=rep_ok)
    assert res_ok["complete"] is True
    assert "warnings" not in res_ok
    assert rep_ok.warnings == []
    base_dir = keep_as_base(dir_ok)
    assert base_dir.name == "base_read"
    assert (base_dir / "Cflash.bin").read_bytes() == synth_cflash
    assert (base_dir / "Uflash.bin").read_bytes() == synth_uflash
    assert (base_dir / "Dflash.bin").read_bytes() == synth_dflash
    assert (base_dir / "Opbt.bin").read_bytes() == make_synthetic_opbt36()
    assert (base_dir / "Eeprom.bin").read_bytes() == ee_expected

    # Standalone `can_read_opbt` and `can_read_eeprom` also succeed
    op_single = tmp_path / "single_opbt.bin"
    ee_single = tmp_path / "single_eeprom.bin"
    assert can_read_opbt("mock0", op_single, session_dir=tmp_path / "s_op")["complete"] is True
    assert op_single.read_bytes() == make_synthetic_opbt36()
    assert can_read_eeprom("mock0", ee_single, session_dir=tmp_path / "s_ee")["complete"] is True
    assert ee_single.read_bytes() == ee_expected

    # 2. MISO stuck at 0x00 -> EEPROM read fails with non-fatal Warning, main backup STILL succeeds!
    mcu.eeprom_miso_stuck_zero = True
    rep_miso = _CaptureReporter()
    dir_miso = tmp_path / "unit2" / "dumps" / "2026-11-13_read"
    dir_miso.mkdir(parents=True)
    res_miso = can_backup("mock0", session_dir=dir_miso, reporter=rep_miso)
    assert res_miso["complete"] is True
    assert len(rep_miso.warnings) == 1
    assert "M95640" in rep_miso.warnings[0]
    assert "eeprom" in res_miso["area_warnings"]
    assert "opbt" not in res_miso["area_warnings"]
    assert not (dir_miso / "Eeprom.bin").exists()
    assert (dir_miso / "Opbt.bin").is_file()
    base_miso = keep_as_base(dir_miso)
    assert base_miso.name == "base_read"
    assert (base_miso / "Cflash.bin").is_file() and (base_miso / "Dflash.bin").is_file()

    # 3. Both OPBT and EEPROM raise TimeoutError -> BOTH degrade to Warnings, main backup STILL completes!
    def _fail_opbt(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise TimeoutError("simulated OPBT timeout")

    def _fail_eeprom(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise TimeoutError("simulated EEPROM timeout")

    monkeypatch.setattr(wf, "read_opbt_in_loader", _fail_opbt)
    monkeypatch.setattr(wf, "read_eeprom_in_loader", _fail_eeprom)
    rep_both = _CaptureReporter()
    dir_both = tmp_path / "unit3" / "dumps" / "2026-11-13_read"
    dir_both.mkdir(parents=True)
    res_both = can_backup("mock0", session_dir=dir_both, reporter=rep_both)
    assert res_both["complete"] is True
    assert len(rep_both.warnings) == 2
    assert set(res_both["area_warnings"].keys()) == {"opbt", "eeprom"}
    assert (dir_both / "Cflash.bin").read_bytes() == synth_cflash
    assert (dir_both / "Uflash.bin").read_bytes() == synth_uflash
    assert (dir_both / "Dflash.bin").read_bytes() == synth_dflash
    assert not (dir_both / "Opbt.bin").exists()
    assert not (dir_both / "Eeprom.bin").exists()


def test_cli_inspect_and_gui_hw_screen_and_warnings(
    synth_cflash: bytes,
    synth_dflash: bytes,
    synth_uflash: bytes,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ee_raw = make_synthetic_eeprom()
    # Real RH850/F1L J533 silicon layout: OPBT1 = 0xFEFFFBDB (clock/PLL), OPBT2..7 = 0xFFFFFFFF
    op_raw = struct.pack("<9I", 0x9AA7FFEF, 0xFEFFFBDB, *([0xFFFFFFFF] * 6), 0x0FFFFFFF)
    assert is_plausible_opbt_bytes(op_raw)

    folder = tmp_path / "full_dump"
    folder.mkdir()
    (folder / "Cflash.bin").write_bytes(synth_cflash)
    (folder / "Dflash.bin").write_bytes(synth_dflash)
    (folder / "Uflash.bin").write_bytes(synth_uflash)
    (folder / "Eeprom.bin").write_bytes(ee_raw)
    (folder / "Opbt.bin").write_bytes(op_raw)

    # 1. CLI `inspect --eeprom ... --opbt ...`
    rc = cli_main(
        [
            "--lang",
            "en",
            "inspect",
            "--eeprom",
            str(folder / "Eeprom.bin"),
            "--opbt",
            str(folder / "Opbt.bin"),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "WVWZZZ3CZWE000123" in out
    assert "0x9AA7FFEF" in out
    assert "0xFEFFFBDB" in out
    assert "0x0FFFFFFF" in out

    # 2. GUI Workspace & `hw` page with both EEPROM + OPBT loaded
    set_lang("ru")
    app, win = create_window()
    win.open_folder(str(folder))
    app.processEvents()
    assert win.ws.path("eeprom") == folder / "Eeprom.bin"
    assert win.ws.path("opbt") == folder / "Opbt.bin"
    hw_state = status.hardware_extras(win.ws)
    assert hw_state.tone == "ok" and hw_state.text == "EEPROM + OPBT"

    win.ecu_screen.select("hw")
    app.processEvents()
    assert "hw_read_eeprom" in win.ecu_screen.actions
    assert "hw_read_opbt" in win.ecu_screen.actions
    assert "hw_report_eeprom" in win.ecu_screen.actions
    assert "hw_report_opbt" in win.ecu_screen.actions

    set_lang("en")
    app.processEvents()
    assert status.hardware_extras(win.ws).text == "EEPROM + OPBT"

    # 3. Folder with manifest `area_warnings` loads into yellow warning state without crashing
    warn_folder = tmp_path / "warn_dump"
    warn_folder.mkdir()
    (warn_folder / "Cflash.bin").write_bytes(synth_cflash)
    (warn_folder / "Dflash.bin").write_bytes(synth_dflash)
    (warn_folder / "Uflash.bin").write_bytes(synth_uflash)
    (warn_folder / "manifest.json").write_text(
        json.dumps(
            {
                "complete": True,
                "area_warnings": {
                    "eeprom": "ContiTool could not read external M95640 EEPROM: timeout.",
                },
            }
        ),
        encoding="utf-8",
    )
    win.open_folder(str(warn_folder))
    app.processEvents()
    assert "eeprom" in win.ws.read_warnings
    st_warn = status.hardware_extras(win.ws)
    assert st_warn.tone == "warn"

    shown_warnings: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _p, _t, msg: shown_warnings.append(msg))
    win._show_backup_warnings(["ContiTool could not read external M95640 EEPROM: timeout."])
    assert len(shown_warnings) == 1 and "M95640" in shown_warnings[0]

    win.close()
