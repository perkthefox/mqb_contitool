"""Reviewed GUI bugs: edits after a write, quitting mid-operation, busy state, FPA editor, stale results, adapter dialog,
terminal session threads."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent, Qt  # noqa: E402
from PySide6.QtWidgets import QMessageBox  # noqa: E402
from shiboken6 import isValid  # noqa: E402

from contitool.can import FoundAdapter, dpdu  # noqa: E402
from contitool.gui import connection  # noqa: E402
from contitool.gui.app import create_window  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402


def _dumps(folder: Path, cflash: bytes, dflash: bytes, uflash: bytes) -> Path:
    folder.mkdir(parents=True)
    for name, raw in (("Cflash.bin", cflash), ("Dflash.bin", dflash), ("Uflash.bin", uflash)):
        (folder / name).write_bytes(raw)
    return folder


def _wait(app, cond, timeout: float = 8.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end and not cond():
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()


def _scanned(app, dlg) -> None:
    while dlg._scan is not None:
        dlg._scan.wait(3000)
        app.processEvents()


# 1
def test_a_new_edit_after_a_write_is_pending_again(synth_cflash, synth_dflash, synth_uflash, tmp_path: Path) -> None:
    app, win = create_window()
    ws = win.ws
    ws.open_folder(_dumps(tmp_path / "dumps", synth_cflash, synth_dflash, synth_uflash))
    out = ws.edit_path("dflash")
    out.parent.mkdir()
    df = bytearray(synth_dflash)
    df[0x100] ^= 1
    out.write_bytes(df)
    ws.commit("dflash", out)
    ws.mark_written(["dflash"])
    assert not ws.pending("dflash")
    df[0x101] ^= 1  # every edit of DataFlash goes to the same ContiTool_edited file
    out.write_bytes(df)
    ws.commit("dflash", out)
    assert ws.pending("dflash")
    win.close()


# 2
def test_quitting_during_an_operation_closes_once_its_thread_has_ended(monkeypatch) -> None:
    from contitool.gui import main_window

    set_lang("en")
    app, win = create_window()
    win.show()
    monkeypatch.setattr(main_window.QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Yes)
    ended: list[bool] = []

    def task(rep) -> None:  # noqa: ANN001
        try:
            while not rep.is_cancelled:
                time.sleep(0.02)
        finally:
            time.sleep(0.1)  # closing the link
            ended.append(True)

    assert win.runner.run_task("write", task)
    win.close()
    open_while_running = win.isVisible()
    _wait(app, lambda: not win.runner.is_busy)
    _wait(app, lambda: not win.isVisible(), 2)
    assert open_while_running
    assert ended and not win.isVisible()


# 3
def test_ecu_buttons_are_disabled_while_an_operation_runs(synth_cflash, synth_dflash, synth_uflash, tmp_path: Path) -> None:
    set_lang("en")
    app, win = create_window()
    win.show()
    win.open_folder(str(_dumps(tmp_path / "dumps", synth_cflash, synth_dflash, synth_uflash)))
    app.processEvents()
    es = win.ecu_screen
    assert es.actions["cp"].isEnabled() and es.btn_restore.isEnabled()
    go = threading.Event()
    assert win.runner.run_task("slow", lambda _rep: go.wait(5))
    app.processEvents()
    during = (win.runner.is_busy, es.actions["cp"].isEnabled(), es.btn_restore.isEnabled())
    go.set()
    _wait(app, lambda: not win.runner.is_busy)
    assert during == (True, False, False)
    assert es.actions["cp"].isEnabled() and es.btn_restore.isEnabled()
    win.close()


# 4
def test_fpa_editor_cannot_save_while_its_own_can_action_runs(synth_dflash: bytes, monkeypatch) -> None:
    from contitool.gui.dialogs import zdc

    set_lang("en")
    app, win = create_window()
    errors: list[str] = []
    monkeypatch.setattr(sys, "excepthook", lambda t, e, _tb: errors.append(f"{t.__name__}: {e}"))
    go = threading.Event()
    monkeypatch.setattr(zdc, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(zdc, "can_learn_mfl_button",
                        lambda _port, **_k: go.wait(5) and {"captured": True, "keycode": 0x1A, "label_en": "x"})
    monkeypatch.setattr(zdc.QMessageBox, "information", lambda *a, **k: None)
    dlg = zdc.FpaEditorDialog(synth_dflash, win.conn, win.runner, win)
    dlg.show()
    dlg.cmb_preset.setCurrentIndex(1)  # a car template: the dataset has profiles, Save is possible
    assert dlg.btn_ok.isEnabled()

    dlg._learn_mfl_live()
    save_during = dlg.btn_ok.isEnabled()
    go.set()
    _wait(app, lambda: not win.runner.is_busy)
    assert not save_during
    assert dlg.btn_ok.isEnabled() and dlg.ed_mfl_hex.text() == "1A"

    go.clear()
    dlg._learn_mfl_live()
    dlg.reject()  # the user leaves the editor while the detect still runs
    dlg.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(dlg)
    go.set()
    _wait(app, lambda: not win.runner.is_busy)
    assert errors == []
    win.close()


# 5
@pytest.mark.parametrize(
    ("console", "wheel"),
    [([2, 3], None), (None, [2, 3]), ([2, 3, 5], [2, 7]), ([2, 3], [3, 2]), ([3, 2, 5], None)],
)
def test_fpa_editor_saved_untouched_leaves_the_dataset_as_it_was(synth_dflash: bytes, console, wheel) -> None:
    from contitool.core import FpaDataset, apply_fpa_dataset, apply_zdc_passport, build_fpa_preset_block
    from contitool.gui.dialogs.zdc import FpaEditorDialog

    set_lang("en")
    app, win = create_window()
    fpa = build_fpa_preset_block("fwd_dcc")
    full = fpa.default_cycle_ring()  # None above: every profile
    fpa.configure_buttons(mode="both", mfl_keycode=0x19, mfl_long_press=True, console_ring=console or full,
                          mfl_ring=wheel or full)
    df = apply_zdc_passport(apply_fpa_dataset(synth_dflash, fpa))
    dlg = FpaEditorDialog(df, None, None, win)
    dlg._on_accept()
    out = dlg.result_dflash()
    cfg_in, cfg_out = FpaDataset.from_dflash(df).button_config(), FpaDataset.from_dflash(out).button_config()
    assert (cfg_out.console_ring, cfg_out.mfl_ring) == (cfg_in.console_ring, cfg_in.mfl_ring)
    assert out == df
    win.close()


# 6
def test_results_of_a_task_go_only_to_the_gateway_it_was_started_on(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    from contitool.gui.screens import ecu

    set_lang("en")
    app, win = create_window()
    win.show()
    a = _dumps(tmp_path / "unitA", synth_cflash, synth_dflash, synth_uflash)
    b = _dumps(tmp_path / "unitB", synth_cflash, synth_dflash, synth_uflash)
    win.conn.out_dir = tmp_path / "runs"
    go = threading.Event()

    def write_uflash(_port, *, session_dir: Path, **_k) -> dict:
        go.wait(5)
        rb = bytearray(synth_uflash)
        rb[0x10] ^= 0x55
        (session_dir / "Uflash_readback.bin").write_bytes(rb)
        return {}

    monkeypatch.setattr(ecu, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(ecu.QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(ecu, "can_write_uflash", write_uflash)
    monkeypatch.setattr(ecu, "apply_engineering_patch", lambda raw, **_k: (go.wait(5) and raw[:-1] + b"\x00", None))
    starts = (lambda: win.ecu_screen._flash_bootloader(engineering=True),
              lambda: win.ecu_screen._patch_engineering(restore=False))
    seen = []
    for start in starts:
        for switch in (lambda: win.open_folder(str(b)), win.close_ecu):
            win.open_folder(str(a))
            app.processEvents()
            go.clear()
            start()
            assert win.runner.is_busy
            switch()
            app.processEvents()
            go.set()
            _wait(app, lambda: not win.runner.is_busy)
            seen.append((win.ws.folder, win.ws.path("uflash"), win.ws.modified("cflash")))
    assert seen == [(b, b / "Uflash.bin", False), (None, None, False)] * 2
    win.close()


# 8
def test_unverified_driver_needs_consent_while_manual_entry_is_open_and_empty(monkeypatch) -> None:
    set_lang("en")
    app, win = create_window()
    vas = FoundAdapter("dpdu", "VAS6154A", "VAS6154A", "D-PDU 99.9", driver="99.9.1")
    assert not dpdu.driver_supported(vas.driver)
    monkeypatch.setattr(connection, "discover_adapters", lambda: [vas])
    win.conn.port = ""
    dlg = connection.ConnectionDialog(win.conn, win)
    _scanned(app, dlg)
    dlg.show()
    dlg._toggle_manual(True)  # "Not listed? Enter manually", nothing typed: the list pick still counts
    assert dlg.selection() == ("dpdu", "VAS6154A", "VAS6154A")
    assert not dlg.chk_driver.isHidden()
    assert not dlg.btn_ok.isEnabled() and not dlg.btn_check.isEnabled()
    win.close()


# 9
def test_live_results_of_one_gateway_are_dropped_when_another_is_opened(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path
) -> None:
    set_lang("en")
    app, win = create_window()
    win.show()
    a = _dumps(tmp_path / "unitA", synth_cflash, synth_dflash, synth_uflash)
    b = _dumps(tmp_path / "unitB", synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(a))
    es = win.ecu_screen
    es._dtc, es._dtc_at = [{"dtc": "C10000", "status": "09"}], "12:00"
    es._swap_live, es._key_file = [{"fsid": 0x00060800, "status": 0xFF}], tmp_path / "key.json"
    es.refresh()
    assert es.nav_rows["dtc"].pill.text() == "1 active"
    win.open_folder(str(b))
    app.processEvents()
    assert (es._dtc, es._swap_live, es._key_file) == (None, None, None)
    assert es.nav_rows["dtc"].pill.text() != "1 active"
    win.close()


def test_the_key_file_stays_when_the_dumps_a_write_produced_are_opened(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    """Same gateway, now as written: the key it was given is still the one to sign its certificates with."""
    from contitool.core.constants import FBL_MOD_OFFSET
    from contitool.gui.screens import ecu

    set_lang("en")
    app, win = create_window()
    folder = _dumps(tmp_path / "dumps", synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    edited = bytearray(synth_cflash)
    edited[FBL_MOD_OFFSET] ^= 0xFF
    (tmp_path / "Cflash_edit.bin").write_bytes(edited)
    win.ws.commit("cflash", tmp_path / "Cflash_edit.bin")
    win.ecu_screen._key_file = tmp_path / "key.json"
    win.conn.out_dir = tmp_path / "runs"
    monkeypatch.setattr(ecu, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(ecu, "can_write_cflash", lambda *a, **k: {})
    win.ecu_screen._write_to_ecu()
    _wait(app, lambda: not win.runner.is_busy)
    assert win.ws.folder != folder and win.ecu_screen._key_file == tmp_path / "key.json"
    win.close()


# 10
def test_terminal_waits_for_a_failed_session_thread_before_deleting_it(monkeypatch) -> None:
    from contitool.gui.can_session import CanSession

    set_lang("en")
    app, win = create_window()
    term = win.terminal
    term.problem.disconnect()
    go = threading.Event()

    class DeadBus:
        def recv(self, timeout=None):  # noqa: ANN001, ANN202
            go.wait(5)
            raise OSError("adapter unplugged")

        def send(self, msg, timeout=None) -> None:  # noqa: ANN001
            pass

        def shutdown(self) -> None:
            pass

    running_at_delete: list[bool] = []
    monkeypatch.setattr(CanSession, "deleteLater", lambda self: running_at_delete.append(self.isRunning()))
    term.connect_bus(bus=DeadBus())
    s = term.session
    # the thread is still inside run() after `closed`: make that last moment long
    s.closed.connect(lambda _e: time.sleep(0.3), Qt.ConnectionType.DirectConnection)
    go.set()
    _wait(app, lambda: term.session is None, 5)
    s.wait()
    assert running_at_delete == [False]
    win.close()


# 11
def test_a_failed_button_setup_takes_the_knob_back_out(synth_dflash: bytes, monkeypatch) -> None:
    from contitool.core import FpaDataset, apply_fpa_dataset, apply_zdc_passport, build_fpa_preset_block
    from contitool.gui.dialogs import zdc

    set_lang("en")
    app, win = create_window()
    df = apply_zdc_passport(apply_fpa_dataset(synth_dflash, build_fpa_preset_block("fwd")))
    dlg = zdc.FpaEditorDialog(df, None, None, win)
    before = bytes(dlg.fpa.buf)
    assert dlg.chk_knob.isEnabled()
    dlg.chk_knob.setChecked(True)
    warned: list[str] = []
    monkeypatch.setattr(zdc.QMessageBox, "warning", lambda _p, _t, text, *a, **k: warned.append(text))

    def refuse(self, **_k) -> None:  # noqa: ANN001
        raise ValueError("No free input for the wheel button")

    monkeypatch.setattr(FpaDataset, "configure_buttons", refuse)
    dlg._on_accept()
    assert warned == ["No free input for the wheel button"] and not dlg.result()
    assert not dlg.fpa.has_knob and bytes(dlg.fpa.buf) == before
    win.close()
