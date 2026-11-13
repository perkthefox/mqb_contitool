"""Leftovers of the reviewed-bug pass that cross directories: terminal 29-bit IDs, where contitool_runs goes, an erased
application's CRC line, FPA save titles, one passport-version rule, cancel bookkeeping, key files in a report, odd
GitHub answers, 32-bit FSC fields, tasks raising BaseException, re-committed unchanged files."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from contitool import report, storage  # noqa: E402
from contitool.can import can_write_cflash, workflows  # noqa: E402
from contitool.can.workflows import can_restore_backup, can_upload_zdc_datasets  # noqa: E402
from contitool.core import (  # noqa: E402
    apply_fpa_dataset,
    apply_zdc_passport,
    build_factory_multi_fsc_slot,
    build_fpa_preset_block,
    build_signed_fsc,
    generate_rsa1024_e3_keypair,
    inject_mke_preset,
    save_rsa1024_keypair_bundle,
)
from contitool.core.constants import APP_BASE, FBL_MOD_OFFSET  # noqa: E402
from contitool.gui.app import create_window  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402
from contitool.progress import OperationCancelledError, OperationReporter  # noqa: E402
from contitool.updates import newer_release  # noqa: E402
from test_bugfix_can import _cancel_at_step, _sim  # noqa: E402
from test_restore_backup import _backup, fake_ecu  # noqa: E402, F401 - fake_ecu is a fixture
from test_zdc_editor import FakeZdcGateway  # noqa: E402

UNIT = "3Q0907530AR_TST-SYN01.01.2400000001"
VCRN = bytes.fromhex("1122334455")


def _wait(app, cond, timeout: float = 8.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end and not cond():
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()


# A. UDS mode of the terminal is 11-bit only


def test_terminal_uds_mode_refuses_a_29_bit_id_and_frame_mode_still_sends_one() -> None:
    set_lang("en")
    app, win = create_window()
    term = win.terminal
    sent: list[tuple] = []
    term.session = SimpleNamespace(send_uds=lambda *a: sent.append(("uds", *a)),
                                   send_frame=lambda *a: sent.append(("frame", *a)))
    term._state = "on"
    term.btn_mode_uds.setChecked(True)
    term.cmb_uds.setEditText("22 F1 90")
    for tx, rx in (("18DA10F1", "77A"), ("710", "18DAF110")):
        term.ed_tx.setText(tx)
        term.ed_rx.setText(rx)
        term._send()
        assert "11-bit" in term.lbl_msg.text()
    assert sent == []
    term.ed_tx.setText("710")
    term.ed_rx.setText("77A")
    term._send()
    assert sent == [("uds", 0x710, 0x77A, b"\x22\xf1\x90")]
    term.btn_mode_frame.setChecked(True)
    term.ed_id.setText("18DA10F1")
    term.cmb_frame.setEditText("02 10 03")
    term._send()
    assert sent[-1] == ("frame", 0x18DA10F1, b"\x02\x10\x03", True)
    term.session, term._state = None, "off"
    win.close()


# B. contitool_runs: next to conti_cp_tool.py, otherwise the working folder


def test_runs_folder_is_the_working_folder_unless_started_from_conti_cp_tool(tmp_path: Path, monkeypatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    for launcher in (tmp_path / "site-packages" / "contitool" / "__main__.py",  # python -m contitool
                     tmp_path / "venv" / "bin" / "contitool"):  # the console script
        launcher.parent.mkdir(parents=True)
        launcher.touch()
        monkeypatch.setattr(sys, "argv", [str(launcher)])
        assert storage.app_dir().resolve() == work.resolve()
    repo = tmp_path / "ContiTool"
    repo.mkdir()
    (repo / "conti_cp_tool.py").touch()
    monkeypatch.setattr(sys, "argv", [str(repo / "conti_cp_tool.py")])
    assert storage.app_dir().resolve() == repo.resolve()


def test_tests_never_put_their_runs_into_the_repository() -> None:
    """conftest._runs_in_tmp: neither the repository's contitool_runs (real bench data) nor .venv/bin."""
    repo = Path(__file__).resolve().parents[1]
    assert repo not in storage.runs_root().resolve().parents


# C. an application without a usable CRC table


def test_an_application_without_a_crc_table_says_so(synth_cflash: bytes) -> None:
    from contitool.cli.formatting import format_cflash_report
    from contitool.core.analyzer import analyze_cflash
    from contitool.gui.screens.status import passport_rows

    set_lang("en")
    erased = bytearray(synth_cflash)
    erased[APP_BASE:] = b"\xff" * (len(erased) - APP_BASE)  # the unit sits in its bootloader
    damaged = bytearray(synth_cflash)
    struct.pack_into("<I", damaged, APP_BASE + 0x20, 0)  # one range, but it starts outside the application
    for raw in (erased, damaged):
        s = analyze_cflash(bytes(raw))
        line = next(x for x in format_cflash_report(s).splitlines() if "App CRC-16" in x)
        assert "!=" not in line and "no CRC table" in line
        ws = SimpleNamespace(info=lambda k, s=s: SimpleNamespace(cflash_info=s) if k == "cflash" else None)
        row = next(r for r in passport_rows(ws) if r[0] == "Checksum")
        assert "no CRC table" in row[1] and row[2] == "err"
    good = analyze_cflash(synth_cflash)
    assert "==" in next(x for x in format_cflash_report(good).splitlines() if "App CRC-16" in x)


# D. FPA editor: a button-setup error is not a knob error


def test_a_button_setup_error_is_not_titled_as_a_knob_error(synth_dflash: bytes, monkeypatch) -> None:
    from contitool.core import FpaDataset
    from contitool.gui.dialogs import zdc

    set_lang("en")
    app, win = create_window()
    df = apply_zdc_passport(apply_fpa_dataset(synth_dflash, build_fpa_preset_block("fwd")))
    dlg = zdc.FpaEditorDialog(df, None, None, win)
    knob_title = "4MOTION Active Control knob"
    titles: list[str] = []
    monkeypatch.setattr(zdc.QMessageBox, "warning", lambda _p, title, *_a, **_k: titles.append(title))

    def no_room(self, **_k) -> None:  # noqa: ANN001
        raise ValueError("No free input or switch left for the button")

    monkeypatch.setattr(FpaDataset, "configure_buttons", no_room)
    for knob in (False, True):  # with the knob ticked, the knob itself goes in and then the buttons fail
        dlg.chk_knob.setChecked(knob)
        dlg._on_accept()
    assert len(titles) == 2 and knob_title not in titles

    def knob_refused(self) -> None:  # noqa: ANN001
        raise ValueError("Slots 8 and 9 hold other profiles")

    monkeypatch.setattr(FpaDataset, "add_4motion_knob", knob_refused)
    dlg._on_accept()
    assert titles[-1] == knob_title and not dlg.result()
    win.close()


def test_the_button_setup_applied_again_for_the_result_does_not_fail(synth_dflash: bytes) -> None:
    """result_dflash() repeats the button setup; after _on_accept succeeded, the same setup fits again."""
    from contitool.gui.dialogs import zdc

    set_lang("en")
    app, win = create_window()
    df = apply_zdc_passport(apply_fpa_dataset(synth_dflash, build_fpa_preset_block("fwd")))
    dlg = zdc.FpaEditorDialog(df, None, None, win)
    dlg.chk_knob.setChecked(True)
    dlg.cmb_btn_mode.setCurrentIndex(dlg.cmb_btn_mode.findData("both"))
    dlg._on_accept()
    assert dlg.result()
    out = dlg.result_dflash()
    assert out != df
    win.close()


# E. one F1A1 rule for a stored passport version


@pytest.mark.parametrize(("stored", "kept"), (("0003", "0003"), ("----", "----"), ("A001", "0001"), ("0000", "0001")))
def test_a_stored_passport_version_is_kept_only_when_valid(synth_dflash: bytes, stored: str, kept: str) -> None:
    from contitool.core import zdc_ver_ok
    from contitool.gui.dialogs.zdc import ZdcPassportBlocksDialog

    assert zdc_ver_ok(stored) == (stored == kept)
    df = bytearray(apply_zdc_passport(apply_fpa_dataset(inject_mke_preset(synth_dflash, "86"),
                                                        build_fpa_preset_block("fwd_dcc")),
                                      dataset_pn="V03935256EE", dataset_ver="0003"))
    df[0x20:0x24] = stored.encode("ascii")  # F1A1 as found in a dump
    gw = FakeZdcGateway()
    can_upload_zdc_datasets("fake", bytes(df), bus=gw)
    assert gw.dids[0xF1A1] == kept.encode("ascii")  # a valid stored version goes out exactly as before
    set_lang("en")
    app, win = create_window()
    assert ZdcPassportBlocksDialog(bytes(df), win).ed_ver.text() == kept
    win.close()


# F. restore: the engineering-bootloader write itself raises the held-back cancel


def test_a_cancel_raised_by_the_engineering_bootloader_write_still_says_it_stays(
    fake_ecu, synth_cflash, synth_dflash, synth_uflash, tmp_path, monkeypatch  # noqa: F811
) -> None:
    set_lang("en")
    ecu, calls = fake_ecu
    ecu.update(cflash=synth_cflash, dflash=synth_dflash)

    def written_then_cancelled(*_a, session_dir: Path, **_k):  # what can_write_uflash leaves on a held-back cancel
        calls.append("uflash_eng")
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "uflash_write_result.json").write_text(json.dumps({"write_performed": True}))
        raise OperationCancelledError("cancelled")

    monkeypatch.setattr(workflows, "can_write_uflash", written_then_cancelled)
    logs: list[str] = []
    files = _backup(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    with pytest.raises(OperationCancelledError):
        can_restore_backup("fake", files, ["cflash"], session_dir=tmp_path / "run",
                           reporter=OperationReporter(on_log=lambda e: logs.append(e.message)))
    assert calls == ["uflash_eng"]
    assert any("engineering bootloader stays" in m for m in logs)
    owner = json.loads((tmp_path / "run" / "owner" / "owner.json").read_text())
    assert owner["uflash_engineering"]["write_performed"] is True


# G. CodeFlash raw FACI write: a held-back cancel keeps the write on record


def test_a_cancel_held_back_by_the_raw_faci_cflash_write_leaves_the_write_on_record(
    monkeypatch, synth_cflash, synth_uflash, synth_dflash, tmp_path
) -> None:
    mcu = _sim(monkeypatch, synth_cflash, synth_uflash, synth_dflash)
    cand = bytearray(synth_cflash)
    cand[FBL_MOD_OFFSET : FBL_MOD_OFFSET + 128] = b"\x99" + b"\x42" * 126 + b"\x01"  # block 5
    path = tmp_path / "cand.bin"
    path.write_bytes(cand)
    with pytest.raises(OperationCancelledError):  # step 3 is the FACI write: the cancel waits for it
        can_write_cflash("mock0", path, raw_faci=True, session_dir=tmp_path / "s", reporter=_cancel_at_step(3))
    res = json.loads((tmp_path / "s" / "cflash_write_result.json").read_text())
    assert bytes(mcu.cflash[0xA000:0xC000]) == cand[0xA000:0xC000]  # written…
    assert res["faci_blocks"]  # …and on record


# H. a key bundle saved by hand inside the swept folder


def test_a_key_bundle_saved_outside_contitool_keys_stays_out_of_the_report(tmp_path: Path) -> None:
    runs = tmp_path / "contitool_runs"
    sess = runs / UNIT / "writes" / "2026-11-10_01-02-03_write"
    sess.mkdir(parents=True)
    (sess / "manifest.json").write_text("{}")
    (sess / "cflash_write_result.json").write_text('{"complete": false}')
    started = time.time()
    save_rsa1024_keypair_bundle(runs / "mykey.json", generate_rsa1024_e3_keypair())  # e.g. gen-rsa-key -o …
    z = report.build_report_zip(tmp_path / "r.zip", report.Failure("t", "m", started=started), {"Adapter": "-"},
                                "log\n", runs, driver_dirs=[])
    with zipfile.ZipFile(z) as zf:
        names = zf.namelist()
        assert not any(b"d_hex" in zf.read(n) or b"PRIVATE KEY" in zf.read(n) for n in names), names
        assert any(n.endswith("/manifest.json") for n in names) and any(n.endswith("/cflash_write_result.json") for n in names)


# I. GitHub answers something that is not a release object


@pytest.mark.parametrize("answer", ([], [{"tag_name": "v9.0.0"}], "v9.0.0", None, 3))
def test_an_unexpected_github_answer_is_no_newer_release(answer) -> None:  # noqa: ANN001
    assert newer_release(answer, "2.0.2") is None


# J. FSC: FeC and timestamp are 32-bit, refused rather than cut


N_HEX = (
    "c494eab071cfa881ce9fc8cdc6fd07d6826f87a1bf71e10453ab23295b67a8998e481b718db9044f77991b0b1ea84a7d7016d67c7d5945855fbfb"
    "8200af734f6680e2d0cf03853e69323d7b37bbc50430988388a48f3206938b7b99fc64c777e26d565ea9fb9d0f42e7d871b5ff08f53392f71066f"
    "65e18307f7163714e5c913"
)
D_HEX = (
    "830df1caf68a705689bfdb33d9fe0539ac4a5a6bd4f69602e2721770e79a70665edabcf65e7b5834fa66120769c586fe4ab9e452fe3b83ae3fd52"
    "56ab1fa234dc4a92d4afb7ad8ece1addeea96537293099cc9e6f5d4f3f9e75c4d8deb5006e4f369b447f9253bcc89ab8cff698256f8a93e2be2c3"
    "56e96a38810314c9ae6ecb"
)


@pytest.mark.parametrize(("fec", "ts", "vin", "sha"), (  # outputs recorded before the range check was added
    (0x10000100, 0, "", "a71f32e631665384e92d33d22592c83cf338299bebf4484ae49da38599ca7fc4"),
    (0xFFFFFFFF, 0xFFFFFFFF, "WVWZZZAUZJW000001", "c5d474183914c756564d893f28afb56e54b8dac5e9f61a7a769b38ec0da95324"),
    (0, 1_700_000_000, "", "8ad67c40a08ff76210ab7069e055979fa8ba0a4cc42df2c679dc7fec46c18194"),
    (0x10001200, 0x12345678, "", "2e33d345e321dbd034278d815f27c43af35d27aae8e90edf228d1b35cbace478"),
))
def test_an_fsc_in_range_is_byte_identical(fec: int, ts: int, vin: str, sha: str) -> None:
    fsc = build_signed_fsc(fec, VCRN, vin, bytes.fromhex(N_HEX), int(D_HEX, 16), timestamp_unix=ts)
    assert hashlib.sha256(fsc).hexdigest() == sha


@pytest.mark.parametrize(("fec", "ts"), ((0x1_0000_0000, 0), (-1, 0), (0x10000100, -1), (0x10000100, 0x1_0000_0000)))
def test_an_fsc_out_of_range_is_refused(fec: int, ts: int) -> None:
    with pytest.raises(ValueError):
        build_signed_fsc(fec, VCRN, "", bytes.fromhex(N_HEX), int(D_HEX, 16), timestamp_unix=ts)


@pytest.mark.parametrize(("fec", "ts", "sha", "crc"), (  # recorded before the range check was added
    (0x10000100, 0, "92c9a80ed5cd5b5dc111b893c0ff05347ca84e2e209b47e88ce16f6adb14cc4a", 0x3B7135A0),
    (0x10000100, 1, "92c9a80ed5cd5b5dc111b893c0ff05347ca84e2e209b47e88ce16f6adb14cc4a", 0x3B7135A0),
    (0xFFFFFFFF, 0xFFFFFFFF, "2bcb38b6cdf9d1736b7267d3bb55cc1ca313ca6b25c98c5b5fffa86499aee59c", 0x025D11F4),
    (0x10001200, 1_700_000_000, "ff6e2367973731281b6d3c47009363403cd4a8803c34360c32aff1e40db98f56", 0x19BFEA51),
))
def test_an_fsc_slot_in_range_is_byte_identical(fec: int, ts: int, sha: str, crc: int) -> None:
    rec, hdr, slot_crc = build_factory_multi_fsc_slot(fec, VCRN, "", timestamp_unix=ts)
    assert hashlib.sha256(rec + hdr).hexdigest() == sha and slot_crc == crc


@pytest.mark.parametrize("ts", (-1, 0x1_0000_0000))
def test_an_fsc_slot_with_an_out_of_range_timestamp_is_refused(ts: int) -> None:
    with pytest.raises(ValueError):
        build_factory_multi_fsc_slot(0x10000100, VCRN, "", timestamp_unix=ts)


# K. a task that raises a BaseException other than a cancel


class _LibraryGaveUp(BaseException):
    pass


@pytest.mark.parametrize("exc", (_LibraryGaveUp("gave up"), SystemExit("library gave up")))
def test_a_task_raising_a_base_exception_ends_as_a_failure(exc: BaseException) -> None:
    from PySide6.QtWidgets import QApplication

    from contitool.gui.worker import OperationRunner

    app = QApplication.instance() or QApplication([])
    runner = OperationRunner()  # no window: a runner stuck busy would make closing one ask "quit anyway?"
    ended: list[bool] = []
    runner.operation_finished.connect(lambda ok, _msg, _p: ended.append(ok))

    def task(_rep):  # noqa: ANN001, ANN202
        raise exc

    assert runner.run_task("library call", task)
    _wait(app, lambda: not runner.is_busy, 3.0)
    assert ended == [False] and not runner.is_busy and runner.last_failure is not None


# L. a re-commit of the bytes already in the ECU


def test_a_recommit_of_the_bytes_already_written_is_not_pending(synth_cflash, synth_dflash, synth_uflash,
                                                                 tmp_path: Path) -> None:
    app, win = create_window()
    ws = win.ws
    folder = tmp_path / "dumps"
    folder.mkdir()
    for name, raw in (("Cflash.bin", synth_cflash), ("Dflash.bin", synth_dflash), ("Uflash.bin", synth_uflash)):
        (folder / name).write_bytes(raw)
    ws.open_folder(folder)
    out = ws.edit_path("dflash")
    out.parent.mkdir()
    df = bytearray(synth_dflash)
    df[0x100] ^= 1
    out.write_bytes(df)
    ws.commit("dflash", out)
    ws.mark_written(["dflash"])
    out.write_bytes(df)  # e.g. an IKA/CP adaptation saves DataFlash again without changing it
    ws.commit("dflash", out)
    assert not ws.pending("dflash")
    win.close()


# M. F187 software part number (AA, AC, AR, …) from FD_0DATA 8-tier variant table


def _with_sw_variant_table(
    synth_cflash: bytes,
    *,
    sw_ver: str = "5366",
    hw_pn: str = "3Q0907530C",
    hw_ver: str = "521",
    hw_variant: int | None = 3,
    high_pn: str = "3Q0907530AA",
    ev_pn: str = "3Q0907530AB",
    tt_pn: str = "8S0907468J",
) -> bytes:
    from contitool.core.checksums import app_crc

    buf = bytearray(synth_cflash)
    buf[0xA257:0xA25A] = f"{hw_ver:<3}".encode("ascii")[:3]
    buf[0xA25A:0xA265] = f"{hw_pn:<11}".encode("ascii")[:11]
    struct.pack_into("<I", buf, 0xA600, 0xFFFFFFFF if hw_variant is None else hw_variant)

    app = bytearray(buf[APP_BASE:])
    sw_off = 0x1000
    pn_off = 0x1100
    nm_off = 0x1200
    did_off = 0x1300
    pns = ("3Q0907530", "3Q0907530K", "3Q0907530J", high_pn, ev_pn, tt_pn, "8V1907468", "5Q0907530in")
    nms = ("GW MQB Full", "GW MQB Mid", "GW MQB Low", "GW MQB High", "GW MQB EV", "GW MQB TT3", "GW MQB High", "GW MQB Inval.")
    app[sw_off : sw_off + 4] = sw_ver.encode("ascii")
    for i, (pn, nm) in enumerate(zip(pns, nms, strict=True)):
        p_addr = APP_BASE + pn_off + i * 11
        n_addr = APP_BASE + nm_off + i * 16
        app[pn_off + i * 11 : pn_off + (i + 1) * 11] = f"{pn:<11}".encode("ascii")[:11]
        app[nm_off + i * 16 : nm_off + i * 16 + 13] = f"{nm:<13}".encode("ascii")[:13]
        struct.pack_into("<I", app, sw_off + 0x14 + i * 4, p_addr)
        struct.pack_into("<I", app, sw_off + 0x34 + i * 4, n_addr)
    struct.pack_into("<II", app, 0x40, APP_BASE + pn_off, APP_BASE + sw_off)
    app[did_off : did_off + 12] = b"\x89\xf1\x01\x00\x04\x00\x00\x00" + struct.pack("<I", APP_BASE + sw_off)

    _, calc = app_crc(app)
    struct.pack_into("<H", app, 0x1C, calc)
    buf[APP_BASE:] = app
    return bytes(buf)


def test_sw_part_number_resolved_and_displayed_in_identity_bar(
    synth_cflash: bytes, synth_dflash: bytes, synth_uflash: bytes, tmp_path: Path
) -> None:
    from contitool.cli.formatting import format_cflash_report
    from contitool.core.analyzer import analyze_cflash
    from contitool.gui.screens.status import passport_rows

    cf_aa = _with_sw_variant_table(synth_cflash, sw_ver="5366", hw_pn="3Q0907530C", hw_ver="521", hw_variant=3, high_pn="3Q0907530AA")
    info_aa = analyze_cflash(cf_aa)
    assert (info_aa.sw_pn, info_aa.sw_ver, info_aa.system_name, info_aa.hw_pn, info_aa.hw_ver) == (
        "3Q0907530AA", "5366", "GW MQB High", "3Q0907530C", "521",
    )
    assert "3Q0907530AA" in format_cflash_report(info_aa)

    # EV tier (hw_variant=4) and Audi TT tier (hw_variant=5), plus standalone FD_0DATA without prefix
    cf_ev = _with_sw_variant_table(synth_cflash, sw_ver="5504", hw_pn="3Q0907530H", hw_ver="527", hw_variant=4, high_pn="3Q0907530AR", ev_pn="3Q0907530AS")
    assert analyze_cflash(cf_ev).sw_pn == "3Q0907530AS"
    assert analyze_cflash(cf_aa[APP_BASE:]).sw_pn == "3Q0907530AA"

    set_lang("ru")
    app, win = create_window()
    folder = tmp_path / "backup_20261109_142145"
    folder.mkdir()
    for name, raw in (("Cflash.bin", cf_aa), ("Dflash.bin", synth_dflash), ("Uflash.bin", synth_uflash)):
        (folder / name).write_bytes(raw)
    win.ws.open_folder(folder)
    assert win.ws.part_number == "3Q0907530AA"
    assert win.ecu_screen.lbl_pn.text() == "3Q0907530AA"
    rows = dict((lbl, val) for lbl, val, _tone in passport_rows(win.ws))
    assert rows["Версия ПО"] == "3Q0907530AA · 5366"
    assert rows["Оборудование"] == "3Q0907530C · 521"
    win.close()
