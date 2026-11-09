"""Tests for direct certificate-free Multi-FSC SWaP activation & ZDC dataset compatibility checking."""

from __future__ import annotations

import os
from pathlib import Path
import struct
import sys
import time
import zlib

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import can  # noqa: E402
import pytest  # noqa: E402
from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402

from contitool.can import can_write_dflash  # noqa: E402
from contitool.cli.main import main  # noqa: E402
from contitool.core import (  # noqa: E402
    GATEWAY_SWAP_SLOT_ORDER,
    STOCK_SWAP_MODULUS,
    UNSUPPORTED_DATASET_WARNING,
    analyze_dflash_datasets,
    analyze_dflash_swap,
    apply_dflash_swap_fecs,
    build_factory_multi_fsc_slot,
    check_fec_dataset_support,
)
from contitool.core.constants import (  # noqa: E402
    DFLASH_FSC_BASE_OFF,
    DFLASH_FSC_STRIDE,
    DFLASH_SWAP_NVM_OFF,
    ZDC_MAINGW_FPA_MAP_OFF,
    ZDC_PASSPORT_PN_OFF,
    ZDC_PASSPORT_VER_OFF,
)
from contitool.gui.app import create_window  # noqa: E402
from contitool.gui.dialogs.crypto import SwapActivateDialog  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402
from contitool.progress import OperationReporter  # noqa: E402


def _populate_zdc_block(df: bytearray, offset: int, size: int, header_tag: bytes, extra_patches: dict[int, bytes] | None = None) -> None:
    """Write a valid synthetic ZDC block with IEEE CRC-32 stored in the last 4 bytes (little-endian)."""
    body = bytearray(size - 4)
    body[: len(header_tag)] = header_tag
    for rel_off, blob in (extra_patches or {}).items():
        body[rel_off : rel_off + len(blob)] = blob
    crc = zlib.crc32(body) & 0xFFFFFFFF
    df[offset : offset + size - 4] = body
    struct.pack_into("<I", df, offset + size - 4, crc)


def make_dflash_with_zdc(
    base_dflash: bytes,
    *,
    maingw_tag: bytes = b"NC00",
    fpa_map_13b: bytes = bytes([0, 1, 2, 3, 4, 5, 0, 7, 10, 0, 54, 59, 58]),
    include_mke: bool = True,
    dataset_pn: bytes = b"V03935000AA",
    dataset_ver: bytes = b"0001",
    selectable_mask: int = 0x1DAF,
) -> bytes:
    """Populate synthetic ZDC blocks (Passport @ 0x0000, #1 MKE @ 0x0100, #4 MainGW @ 0x1340) in DataFlash."""
    df = bytearray(base_dflash)
    # Dataset Passport (0x0000..0x007F)
    df[0x0000:0x0080] = b"\x00" * 0x0080
    df[ZDC_PASSPORT_PN_OFF : ZDC_PASSPORT_PN_OFF + len(dataset_pn)] = dataset_pn
    df[ZDC_PASSPORT_VER_OFF : ZDC_PASSPORT_VER_OFF + len(dataset_ver)] = dataset_ver

    # ZDC #1 MKE Driver Alert (0x0100..0x01FF, size 0x0100)
    if include_mke:
        _populate_zdc_block(df, 0x0100, 0x0100, b"0101")

    # ZDC #4 MainGW (0x1340..0x243F, size 0x1100) with FPA profile map @ +0x032C
    assert len(fpa_map_13b) == 13
    _populate_zdc_block(
        df,
        0x1340,
        0x1100,
        maingw_tag,
        # S030 selectable-profile mask as in the factory NC00 dataset (3Q0907530AR SW 5504): slots 1..3,5,7,8,10..12
        extra_patches={ZDC_MAINGW_FPA_MAP_OFF: fpa_map_13b, ZDC_MAINGW_FPA_MAP_OFF + 0x19: selectable_mask.to_bytes(2, "big")},
    )
    return bytes(df)


def test_zdc_dataset_analyzer_detects_nc00_and_jc00_fec_support(synth_dflash: bytes) -> None:
    # 1. NC00 MainGW + MKE: GRA, MKE, and every FPA slot whose S028 ID is 1..0x13 (1, 2, 3, 4, 5, 7, 8) supported;
    #    slots 6 (0), 9 (0) and the rotary slots 10..12 (0x36/0x3B/0x3A, never offered) unsupported
    df_nc00 = make_dflash_with_zdc(synth_dflash)
    ds = analyze_dflash_datasets(df_nc00)
    assert ds.has_any_valid_dataset is True
    assert ds.dataset_pn == "V03935000AA"
    assert ds.dataset_ver == "0001"
    assert ds.maingw_tag == "NC00"
    assert set(ds.supported_fecs) == {
        0x10000100,
        0x10000300,
        0x10001100,
        0x10001200,
        0x10001300,
        0x10001400,
        0x10001500,
        0x10001700,
        0x10001800,
    }
    # Offroad: S030 bit 4 is clear in factory NC00, but S030 only marks remembered profiles; S028[4] = 4 offers it
    assert check_fec_dataset_support(ds, 0x10001400).supported is True
    assert check_fec_dataset_support(ds, 0x10001600).supported is False  # Race = 0
    assert check_fec_dataset_support(ds, 0x10001A00).supported is False  # EV = 54 (> 15)
    assert check_fec_dataset_support(ds, 0x10001B00).supported is False  # GTE = 59 (> 15)
    assert check_fec_dataset_support(ds, 0x10009900).supported is False  # Unknown custom FeC

    # 2. JC00 MainGW without FPA (byte at k=2 is 20 > 15) and without MKE block: only GRA (0x10000100) supported
    df_jc00 = make_dflash_with_zdc(
        synth_dflash,
        maingw_tag=b"JC00",
        fpa_map_13b=bytes([0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        include_mke=False,
        dataset_pn=b"V03935000BB",
    )
    ds_jc = analyze_dflash_datasets(df_jc00)
    assert ds_jc.maingw_tag == "JC00"
    assert ds_jc.supported_fecs == [0x10000100]
    assert check_fec_dataset_support(ds_jc, 0x10000300).supported is False
    assert check_fec_dataset_support(ds_jc, 0x10001200).supported is False


def test_build_factory_multi_fsc_slot_binary_layout() -> None:
    vcrn = bytes.fromhex("1122334455")
    vin = "WVWZZZAUZJW000001"
    slot_rec, ent_hdr, slot_crc = build_factory_multi_fsc_slot(
        0x10000100,
        vcrn,
        vin,
        timestamp_unix=0x5F000102,
    )
    assert len(slot_rec) == 192  # 0xC0 stride
    assert slot_rec[:4] == struct.pack("<I", 0x55555555)
    spay = slot_rec[4:175]
    assert len(spay) == 171
    assert spay[:2] == b"\x11\x02"
    assert spay[2:6] == bytes.fromhex("10000100")
    assert spay[6:7] == b"\x03"
    assert spay[7:12] == vcrn
    assert spay[12:30] == vin.encode("ascii") + b"\x00"
    assert spay[30:34] == bytes.fromhex("5F000102")
    assert spay[34:43] == b"\x00" * 9
    assert spay[43:171] == b"\x00" * 128  # Zero RSA signature in factory Multi-FSC
    assert slot_rec[0xAF:0xB0] == b"\x00"  # Zero alignment pad byte before CRC
    assert struct.unpack_from("<I", slot_rec, 0xB0)[0] == slot_crc == (zlib.crc32(spay) & 0xFFFFFFFF)
    assert slot_rec[0xB4:0xC0] == b"\xff" * 12  # Erased 12-byte tail for FACI Blank-Check
    assert ent_hdr == bytes.fromhex("00000000100001005F000102FF01")


def test_apply_dflash_swap_fecs_supported_unsupported_and_deactivation(synth_dflash: bytes) -> None:
    set_lang("en")
    df_nc00 = make_dflash_with_zdc(synth_dflash)

    # 1. Enable supported FeCs -> zero warnings, stock RSA modulus untouched, factory_eol=True
    logs_ok: list[tuple[str, str]] = []
    rep_ok = OperationReporter(on_log=lambda e: logs_ok.append((e.level, e.message)))
    df_step1, sum1 = apply_dflash_swap_fecs(
        df_nc00,
        enable_fecs=["10000100", "10000300", "10001100", "10001300"],
        vin="WVWZZZAUZJW000001",
        timestamp_unix=1700000000,
        reporter=rep_ok,
    )
    assert sum1["warnings"] == []
    assert sum1["unsupported_fecs"] == []
    assert not any(lvl == "warning" for lvl, _ in logs_ok)

    sw1 = analyze_dflash_swap(df_step1)
    assert sw1.crc_ok
    assert sw1.swap_rsa_mod == STOCK_SWAP_MODULUS
    assert sw1.vin == "WVWZZZAUZJW000001"
    assert [f.fec_code for f in sw1.active_fscs] == [0x10000300, 0x10000100, 0x10001100, 0x10001300]
    assert all(f.factory_eol and f.crc_ok for f in sw1.active_fscs)

    # 2. Enable an UNSUPPORTED FeC (0x10001600 Race, mapped to 0 in NC00) -> STILL activates + emits exact warning!
    logs_warn: list[tuple[str, str]] = []
    rep_warn = OperationReporter(on_log=lambda e: logs_warn.append((e.level, e.message)))
    df_step2, sum2 = apply_dflash_swap_fecs(
        df_step1,
        enable_fecs=[0x10001600],
        reporter=rep_warn,
    )
    assert sum2["unsupported_fecs"] == ["0x10001600"]
    assert len(sum2["warnings"]) == 1
    assert UNSUPPORTED_DATASET_WARNING in sum2["warnings"][0]
    assert any(lvl == "warning" and UNSUPPORTED_DATASET_WARNING in msg for lvl, msg in logs_warn)

    sw2 = analyze_dflash_swap(df_step2)
    assert sw2.crc_ok
    assert 0x10001600 in [f.fec_code for f in sw2.active_fscs]

    # 3. Monotonic timestamp check: if existing slot timestamp is in the future, auto-timestamp stays >= prev_ts
    future_ts = int(time.time()) + 500_000
    df_fut, _ = apply_dflash_swap_fecs(df_nc00, enable_fecs=[0x10000100], timestamp_unix=future_ts)
    df_re, _ = apply_dflash_swap_fecs(df_fut, enable_fecs=[0x10000100], vin="WVWZZZAUZJW000002")
    sw_re = analyze_dflash_swap(df_re)
    assert sw_re.active_fscs[0].timestamp >= future_ts

    # 4. Deactivate all via preserve_existing_active=False -> slots erased to 192 x 0xFF and headers reset to b0 02
    df_cleared, sum_clr = apply_dflash_swap_fecs(df_step2, enable_fecs=[], preserve_existing_active=False)
    sw_clr = analyze_dflash_swap(df_cleared)
    assert sw_clr.crc_ok
    assert sw_clr.active_fscs == []
    assert sum_clr["active_fecs"] == []
    for slot_idx, canon_fec in enumerate(GATEWAY_SWAP_SLOT_ORDER):
        off = DFLASH_FSC_BASE_OFF + slot_idx * DFLASH_FSC_STRIDE
        assert df_cleared[off : off + DFLASH_FSC_STRIDE] == b"\xff" * DFLASH_FSC_STRIDE
        ent_off = DFLASH_SWAP_NVM_OFF + 4 + 0x10E + slot_idx * 14
        assert df_cleared[ent_off : ent_off + 14] == b"\x00\x00\x00\x00" + struct.pack(">II", canon_fec, 0) + b"\xb0\x02"


def test_cli_activate_swap_and_inspect_warnings(synth_dflash: bytes, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    df_in = tmp_path / "Dflash_in.bin"
    df_sup = tmp_path / "Dflash_sup.bin"
    df_unsup = tmp_path / "Dflash_unsup.bin"
    df_in.write_bytes(make_dflash_with_zdc(synth_dflash))

    # 1. Activate all dataset-supported FeCs -> zero warnings
    capsys.readouterr()
    rc1 = main(["-l", "en", "--no-color", "activate-swap", "-i", str(df_in), "-o", str(df_sup), "--all-supported", "--no-vin"])
    out1, err1 = capsys.readouterr()
    assert rc1 == 0
    assert UNSUPPORTED_DATASET_WARNING not in err1
    assert "DataFlash Multi-FSC" in out1
    assert len(analyze_dflash_swap(df_sup.read_bytes()).active_fscs) == 9  # GRA, MKE and slots 1..5, 7, 8

    # 2. Activate unsupported FeC 10001600 -> emits exact warning on stderr AND activates 0x10001600
    rc2 = main(
        [
            "-l",
            "en",
            "--no-color",
            "activate-swap",
            "-i",
            str(df_in),
            "-o",
            str(df_unsup),
            "--fec",
            "10000100",
            "10001600",
            "--replace",
            "--no-vin",
        ]
    )
    out2, err2 = capsys.readouterr()
    assert rc2 == 0
    assert UNSUPPORTED_DATASET_WARNING in err2
    assert "0x10001600" in out2
    sw_unsup = analyze_dflash_swap(df_unsup.read_bytes())
    assert {f.fec_code for f in sw_unsup.active_fscs} == {0x10000100, 0x10001600}

    # 3. `inspect --dflash` shows both [Multi-FSC] and Dataset OK / Unsupported Dataset badges
    rc3 = main(["-l", "en", "--no-color", "inspect", "--dflash", str(df_unsup)])
    out3, _ = capsys.readouterr()
    assert rc3 == 0
    assert "[Multi-FSC]" in out3
    assert "Dataset OK" in out3
    assert "Unsupported Dataset" in out3


def test_gui_swap_activate_dialog_and_direct_dflash_edit(
    synth_cflash: bytes,
    synth_dflash: bytes,
    synth_uflash: bytes,
    tmp_path: Path,
) -> None:
    set_lang("en")
    app, win = create_window()
    df_nc00 = make_dflash_with_zdc(synth_dflash)

    # 1. Dialog behavior: dataset-supported selection hides warning; ticking unsupported FeC shows warning WITHOUT disabling OK
    dlg = SwapActivateDialog(analyze_dflash_swap(df_nc00), analyze_dflash_datasets(df_nc00))
    dlg.show()
    dlg._select_supported()
    app.processEvents()
    assert not dlg.warn_callout.isVisible()
    assert dlg.btn_ok.isEnabled()
    assert 0x10000100 in dlg.selected_fecs
    assert 0x10001600 not in dlg.selected_fecs

    dlg.set_fec_checked(0x10001600, True)
    app.processEvents()
    assert dlg.warn_callout.isVisible()
    assert UNSUPPORTED_DATASET_WARNING in dlg.warn_callout.label.text()
    assert dlg.btn_ok.isEnabled()  # Non-blocking!
    assert dlg.unsupported_selected == [0x10001600]
    dlg.close()

    # 2. Full EcuScreen direct activation: modifies ONLY DataFlash (CodeFlash stays untouched)
    folder = tmp_path / "gw_dumps"
    folder.mkdir()
    (folder / "Cflash.bin").write_bytes(synth_cflash)
    (folder / "Dflash.bin").write_bytes(df_nc00)
    (folder / "Uflash.bin").write_bytes(synth_uflash)

    win.open_folder(str(folder))
    app.processEvents()
    screen = win.ecu_screen
    screen.select("swap")
    app.processEvents()
    assert "swap_direct" in screen.actions
    assert screen.actions["swap_direct"].isEnabled()

    screen._apply_swap_direct([0x10000100, 0x10001600], vin="")
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop.quit())
    QTimer.singleShot(8000, loop.quit)
    loop.exec()
    app.processEvents()

    assert screen.change_state("dflash")[0] == "changed"
    assert screen.change_state("cflash")[0] == "unchanged"
    assert screen.change_state("uflash")[0] == "unchanged"
    assert UNSUPPORTED_DATASET_WARNING in win.console.txt_full.toPlainText()

    edited_df = win.ws.path("dflash").read_bytes()
    sw_after = analyze_dflash_swap(edited_df)
    assert {f.fec_code for f in sw_after.active_fscs} == {0x10000100, 0x10001600}
    assert sw_after.swap_rsa_mod == STOCK_SWAP_MODULUS
    win.close()


def test_can_write_dflash_verifies_multifsc_patched_image_byte_for_byte(
    synth_cflash: bytes,
    synth_uflash: bytes,
    synth_dflash: bytes,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tests_dir = str(Path(__file__).resolve().parent)
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)
    from test_can_full_write import SimulatedJ533CanBus, SimulatedRh850FaciMcu

    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    df_nc00 = make_dflash_with_zdc(synth_dflash)
    mcu = SimulatedRh850FaciMcu(synth_cflash, synth_uflash, df_nc00)
    sim_bus = SimulatedJ533CanBus(mcu)
    monkeypatch.setattr(can.interface, "Bus", lambda **kwargs: sim_bus)

    patched_df, _ = apply_dflash_swap_fecs(
        df_nc00,
        enable_fecs=GATEWAY_SWAP_SLOT_ORDER,
        vin="WVWZZZAUZJW000001",
        timestamp_unix=1700000123,
    )
    target_path = tmp_path / "Dflash_multifsc.bin"
    target_path.write_bytes(patched_df)

    res = can_write_dflash("mock0", target_path, session_dir=tmp_path / "s_multifsc_write")
    assert res["complete"] is True
    assert bytes(mcu.dflash) == patched_df
    assert len(analyze_dflash_swap(bytes(mcu.dflash)).active_fscs) == 13


def test_active_certificates_are_kept_byte_for_byte(synth_dflash: bytes) -> None:
    """Re-applying the feature list must not rebuild a valid certificate: a VAG-signed one would lose its signature."""
    from contitool.core.constants import DFLASH_FSC_PAY_SIZE, FSC_SIGNED_BODY_SIZE

    set_lang("en")
    df, _ = apply_dflash_swap_fecs(make_dflash_with_zdc(synth_dflash), enable_fecs=[0x10000300], vin="WVWZZZAUZJW000001")
    signed = bytearray(df)
    slot = analyze_dflash_swap(df).active_fscs[0]
    off = slot.dflash_off
    signed[off + 4 + FSC_SIGNED_BODY_SIZE : off + 4 + FSC_SIGNED_BODY_SIZE + 128] = b"\x5a" * 128  # an RSA signature
    struct.pack_into("<I", signed, off + 0xB0, zlib.crc32(bytes(signed[off + 4 : off + 4 + DFLASH_FSC_PAY_SIZE])) & 0xFFFFFFFF)
    before = analyze_dflash_swap(bytes(signed)).active_fscs[0]
    assert before.crc_ok and not before.factory_eol

    out, _ = apply_dflash_swap_fecs(bytes(signed), enable_fecs=[0x10000300, 0x10000100], preserve_existing_active=False)
    assert out[off : off + DFLASH_FSC_STRIDE] == signed[off : off + DFLASH_FSC_STRIDE]  # signature kept
    assert [f.fec_code for f in analyze_dflash_swap(out).active_fscs] == [0x10000300, 0x10000100]

    both, summary = apply_dflash_swap_fecs(bytes(signed), enable_fecs=[0x10000300], disable_fecs=[0x10000300],
                                           preserve_existing_active=False)  # `--replace --enable X --disable X`
    assert both[off : off + DFLASH_FSC_STRIDE] == signed[off : off + DFLASH_FSC_STRIDE] and "0x10000300" in str(summary)

    logs: list[str] = []
    rep = OperationReporter(on_log=lambda e: logs.append(e.message))
    out2, _ = apply_dflash_swap_fecs(bytes(signed), enable_fecs=[0x10000300], vin="WVWZZZAUZJW000002", reporter=rep)
    assert out2[off : off + DFLASH_FSC_STRIDE] != signed[off : off + DFLASH_FSC_STRIDE]  # the user changed the VIN
    assert any("signed certificate 0x10000300" in m for m in logs)


def test_cli_auto_parameterize_accepts_comma_separated_codes(synth_dflash: bytes, tmp_path: Path) -> None:
    df_in, df_out = tmp_path / "Dflash.bin", tmp_path / "Dflash_out.bin"
    df_in.write_bytes(make_dflash_with_zdc(synth_dflash))
    rc = main(["-l", "en", "--no-color", "activate-swap", "-i", str(df_in), "-o", str(df_out),
               "--fec", "10000100,10000300", "--auto-parameterize", "--no-vin"])
    assert rc == 0
    assert {0x10000100, 0x10000300} <= {f.fec_code for f in analyze_dflash_swap(df_out.read_bytes()).active_fscs}


def test_the_menu_follows_the_profile_ids_not_the_remembered_mask(synth_dflash: bytes) -> None:
    """The gateway offers slot n when S028[n] holds an ID 1..0x13 (with its FeC); S030 only marks the profiles kept
    as the user's last one. Clearing S030 changes nothing in the menu, clearing S028 takes the profile out."""
    from contitool.core.zdc import FpaDataset, apply_fpa_dataset

    df = make_dflash_with_zdc(synth_dflash)
    fpa = FpaDataset.from_dflash(df)
    fpa.selectable_mask = 0
    df2 = apply_fpa_dataset(df, fpa)
    assert check_fec_dataset_support(analyze_dflash_datasets(df2), 0x10001100, raw_df=df2).supported
    fpa.set_slot_enabled(1, False)
    df3 = apply_fpa_dataset(df, fpa)
    assert not check_fec_dataset_support(analyze_dflash_datasets(df3), 0x10001100, raw_df=df3).supported
    fpa.set_slot_enabled(1, True)  # back on: the slot gets back what it had
    assert FpaDataset.from_dflash(apply_fpa_dataset(df, fpa)).sec_bytes(28) == FpaDataset.from_dflash(df).sec_bytes(28)


def test_a_profile_taken_out_of_the_menu_is_no_fault(synth_cflash, synth_dflash, tmp_path) -> None:
    """Profile FeCs already active when the dump was opened stay quiet when their profile is switched off;
    a FeC switched on afterwards without a profile for it is reported."""
    from contitool.core.zdc import FpaDataset, apply_fpa_dataset
    from contitool.gui.app import create_window
    from contitool.gui.screens import status

    app, win = create_window()
    df = make_dflash_with_zdc(synth_dflash)
    df, _ = apply_dflash_swap_fecs(df, enable_fecs=[0x10001100, 0x10001200])
    folder = tmp_path / "dumps"
    folder.mkdir()
    (folder / "Cflash.bin").write_bytes(synth_cflash)
    (folder / "Dflash.bin").write_bytes(df)
    win.open_folder(str(folder))
    fpa = FpaDataset.from_dflash(df)
    fpa.set_slot_enabled(1, False)  # Comfort out of the menu, its FeC stays
    edited = apply_fpa_dataset(df, fpa)
    (tmp_path / "e1.bin").write_bytes(edited)
    win.ws.commit("dflash", tmp_path / "e1.bin")
    assert status.unsupported_active_fecs(win.ws) == []
    fpa.set_slot_enabled(6, False)
    edited2, _ = apply_dflash_swap_fecs(apply_fpa_dataset(df, fpa), enable_fecs=[0x10001600])  # Race FeC, no Race
    (tmp_path / "e2.bin").write_bytes(edited2)
    win.ws.commit("dflash", tmp_path / "e2.bin")
    assert status.unsupported_active_fecs(win.ws) == [0x10001600]
    win.close()
