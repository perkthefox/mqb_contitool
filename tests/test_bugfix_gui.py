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
        # close_ecu() is intentionally blocked while busy; closing ws directly still exercises _here() drop-on-close
        for switch in (lambda: win.open_folder(str(b)), win.ws.close):
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


# ────────────────────────────── Code-review GUI regression suite ──────────────────────────────


def _make_synth_kombi_dflash(
    *,
    sw_version: str = "0310",
    part_number: str = "5NA920740B ",
    vin: str = "XW8ZZZ5NZJG235992",
    gfa_hex: str = "e54e0aab8198ebcd8e781cceb0a3b33c",
    kc_hex: str = "ea046275eea646ef01e6d703f77899db",
) -> tuple[bytes, bytes]:
    """Return `(dflash_64k, eel_logical_bytes)` for a valid synthetic Kombi SW 0310 or SW 2220 dump."""
    import struct
    import zlib

    from contitool.core.kombi import (
        EEL_KOMBI_0310_IDS,
        EEL_KOMBI_2220_IDS,
        build_kombi_eel_dflash,
        kombi_crc16_ccitt,
    )

    id_table = EEL_KOMBI_2220_IDS if sw_version == "2220" else EEL_KOMBI_0310_IDS
    records: dict[int, bytes] = {
        ident: struct.pack("<H", sz) + (b"\xff" * (sz - 2))
        for ident, sz in sorted(id_table.items())
    }
    # Coding EEL 0x0030
    sz30 = id_table[0x0030]
    r30 = bytearray(struct.pack("<H", sz30) + bytes.fromhex("25082600000000002e") + (b"\x00" * (sz30 - 11)))
    r30[11:31] = bytes.fromhex("07a501002280000811883a011400000800000000")
    struct.pack_into(">H", r30, sz30 - 2, kombi_crc16_ccitt(bytes(r30[2 : sz30 - 2])))
    records[0x0030] = bytes(r30)
    records[0x0035] = struct.pack("<HBB", 4, 0, 0)

    r45 = bytearray(records[0x0045])
    r45[2:6] = sw_version.encode("ascii")[:4].ljust(4, b" ")
    r45[12:32] = b"EV_DashBoardVDDMQBAB"
    r45[37:49] = part_number.encode("ascii")[:12].ljust(12, b" ")
    if len(r45) >= 76:
        r45[64:76] = part_number.encode("ascii")[:12].ljust(12, b" ")
    records[0x0045] = bytes(r45)

    r60 = bytearray(struct.pack("<H", 16) + b"\xff\xff" + (b"\x00" * 12))
    struct.pack_into("<3I", r60, 4, 500, 500, 500)
    records[0x0060] = bytes(r60)

    def _crc32_pack(p: bytes) -> bytes:
        return p + struct.pack("<I", zlib.crc32(p) & 0xFFFFFFFF)

    r63 = bytearray(records[0x0063])
    r63[0x02:0x16] = _crc32_pack(bytes.fromhex("100e100106003f0013021788797411").ljust(16, b"\xff"))
    r63[0x16:0x2A] = _crc32_pack(bytes.fromhex("8268dcf2746cf6479f7e6fb4633f4ca0"))
    r63[0x2A:0x3E] = _crc32_pack(bytes.fromhex("b470743235eb2e588d41888aed960e42"))
    records[0x0063] = bytes(r63)

    r66 = bytearray(records[0x0066])
    r66[0x02:0x04] = bytes.fromhex("55bb")
    r66[0x04:0x06] = bytes.fromhex("1122")
    records[0x0066] = bytes(r66)

    r67 = bytearray(records[0x0067])
    r67[2:6] = bytes.fromhex("d2032d00")
    r67[0x22] = 8
    r67[0x23] = 1
    r67[0x24] = 1
    records[0x0067] = bytes(r67)

    r68 = bytearray(struct.pack("<H", id_table[0x0068]) + (b"\x00" * (id_table[0x0068] - 2)))
    r68[0x17:0x28] = vin.encode("ascii")[:17].ljust(17, b" ")
    r68[0x28:0x38] = bytes.fromhex(kc_hex)
    r68[0x40] = 0x49
    r68[0x41] = 0x03
    r68[0x4B] = 0x01
    records[0x0068] = bytes(r68)

    r69 = bytearray(struct.pack("<H", 34) + (b"\x00" * 32))
    r69[0x02:0x12] = bytes.fromhex("dc1279b9c430833849c3f3d32a3c2bf6")
    r69[0x12:0x22] = bytes.fromhex("4a1c3810bc4f9c2ba7347cf0006fc829")
    records[0x0069] = bytes(r69)

    r6b = bytearray(struct.pack("<H", 50) + (b"\xff" * 48))
    r6b[0x02:0x12] = b"M" * 16
    r6b[0x12:0x22] = bytes.fromhex(gfa_hex)
    r6b[0x22:0x32] = bytes.fromhex("4d6b7c5472a7659bfbe10df4be36c44d")
    records[0x006B] = bytes(r6b)

    df64 = build_kombi_eel_dflash(records, eel_ids=id_table)
    logical = b"".join(records[ident] for ident in sorted(id_table))
    return df64, logical


def _make_synth_fpke_dflash(
    *,
    vin: str = "TMBJJ7NE9J0123456",
    part_number: str = "5E0920790A ",
    gfa_hex: str = "11223344556677889900aabbccddeeff",
    kc_hex: str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0",
    empty_coding: bool = False,
) -> bytes:
    """Build a minimal valid 64 KiB RH850 FPK_E EEL T01 DataFlash."""
    import struct

    from contitool.core.fpke import EEL_MARK, eel_append_records, fpke_eel_layout
    from contitool.core.kombi import _build_empty_eel_t01_pool

    lay = fpke_eel_layout()
    id_map = lay["ids"]
    updates: dict[int, bytes] = {}
    for ident, sz in sorted(id_map.items()):
        updates[ident] = struct.pack("<H", sz) + (b"\xff" * (sz - 2))

    # 0x0030 (42 B on FPK_E): coding at +10..+30
    r30 = bytearray(updates[0x0030])
    if not empty_coding:
        r30[10:30] = bytes.fromhex("07a501002280000811883a011400000800000000")
    updates[0x0030] = bytes(r30)

    # 0x0045: metadata
    r45 = bytearray(updates[0x0045])
    r45[2:6] = b"1703"
    r45[12:41] = b"EV_DashBoardFPKContinentMQBAB"
    r45[45:57] = part_number.encode("ascii")[:12].ljust(12, b" ")
    updates[0x0045] = bytes(r45)

    # 0x0068: VIN + Kc
    r68 = bytearray(struct.pack("<H", id_map[0x0068]) + (b"\x00" * (id_map[0x0068] - 2)))
    r68[0x17:0x28] = vin.encode("ascii")[:17].ljust(17, b" ")
    r68[0x28:0x38] = bytes.fromhex(kc_hex)
    r68[0x40] = 0x49
    r68[0x41] = 0x03
    r68[0x4B] = 0x01
    updates[0x0068] = bytes(r68)

    # 0x006B (68 B on FPK_E): CP /3 IKA @ +2..+18, CP /1 bank 0 GFA @ +18..+34
    r6b = bytearray(updates[0x006B])
    r6b[0x02:0x12] = bytes.fromhex("4d6b7c5472a7659bfbe10df4be36c44d")
    r6b[0x12:0x22] = bytes.fromhex(gfa_hex)
    updates[0x006B] = bytes(r6b)

    empty = bytearray(_build_empty_eel_t01_pool(updates[1]))
    # Ensure standard FPK_E pool header mark
    struct.pack_into("<I", empty, 0x18, EEL_MARK)
    return eel_append_records(bytes(empty), updates, layout=lay)


def test_operation_runner_finishes_before_on_success() -> None:
    """_on_worker_ok must clean up busy state & emit operation_finished BEFORE invoking on_success (allowing chaining)."""
    set_lang("en")
    app, win = create_window()
    events: list[str] = []
    chained_started: list[bool] = []
    chained_done: list[str] = []

    win.runner.operation_finished.connect(lambda ok, _s, _t: events.append(f"finished:{ok}:{win.runner.is_busy}"))

    def first_ok(res: str) -> None:
        events.append(f"on_success:{res}:{win.runner.is_busy}")
        started = win.runner.run_task("second", lambda _r: "two", on_success=lambda r: chained_done.append(r))
        chained_started.append(started)

    assert win.runner.run_task("first", lambda _r: "one", on_success=first_ok)
    _wait(app, lambda: bool(chained_done) and not win.runner.is_busy)
    assert events[0] == "finished:True:False"
    assert events[1] == "on_success:one:False"
    assert chained_started == [True]
    assert chained_done == ["two"]
    win.close()


def test_kombi_non_native_callout_edited_dflash_and_sw2220_text(tmp_path: Path) -> None:
    """KombiScreen: non-native Callout won't crash with TypeError, edits save to ContiTool_edited/Dflash.bin, and SW 2220 shows 130 blk."""
    from PySide6.QtWidgets import QLabel

    set_lang("en")
    app, win = create_window()
    win.conn.interface = "dpdu"
    win.conn.port = "VW_PDUAPI"
    win.conn.wiring_confirmed = True

    _df_0310, logical_0310 = _make_synth_kombi_dflash(sw_version="0310")
    folder = tmp_path / "kombi_0310"
    folder.mkdir()
    (folder / "EelLogical.bin").write_bytes(logical_0310)
    win.open_folder(str(folder))
    app.processEvents()
    assert win.kombi_screen.is_open
    # Rendering the "read" page on a non-native adapter used to raise TypeError in Callout("", "warn")
    win.kombi_screen.select("read")
    app.processEvents()

    # Editing an EelLogical.bin-only folder must save 64 KiB edited bytes to ContiTool_edited/Dflash.bin
    edited_bytes = bytearray(win.kombi_screen._working_dflash_bytes)
    edited_bytes[0x200] ^= 0x01
    win.kombi_screen._commit_dflash_bytes(bytes(edited_bytes), "test edit")
    expected_edit = folder / "ContiTool_edited" / "Dflash.bin"
    assert expected_edit.is_file() and len(expected_edit.read_bytes()) == 65536
    assert not (folder / "ContiTool_edited" / "EelLogical.bin").exists()

    # Reopening the folder reloads the edited ContiTool_edited/Dflash.bin
    win.kombi_screen.close_kombi()
    win.open_folder(str(folder))
    app.processEvents()
    assert win.kombi_screen.is_dflash_modified
    assert win.kombi_screen._working_dflash_path == expected_edit

    # SW 2220 (8334 B / 130 blocks) must report 130 blk instead of hardcoding 132 blk
    _df_2220, logical_2220 = _make_synth_kombi_dflash(sw_version="2220", part_number="8V0920860G ")
    folder2 = tmp_path / "kombi_2220"
    folder2.mkdir()
    (folder2 / "EelLogical.bin").write_bytes(logical_2220)
    win.kombi_screen.close_kombi()
    win.open_folder(str(folder2))
    win.kombi_screen.select("read")
    app.processEvents()
    assert win.kombi_screen._eel_total_ids() == 130
    texts = " ".join(lbl.text() for lbl in win.kombi_screen.findChildren(QLabel))
    assert "130" in texts
    assert "0x0082" in texts
    win.close()


def test_fpke_rejects_kombi_restore_accepts_kombi_donor_and_validates_empty_coding(tmp_path: Path, monkeypatch) -> None:
    """FpkeScreen: restore rejects Kombi dumps, donor loader accepts Kombi dumps, coding validator binds when empty, close disabled while busy."""
    from PySide6.QtWidgets import QLineEdit

    from contitool.gui.screens import fpke as fpke_mod

    set_lang("en")
    app, win = create_window()
    fpke_df = _make_synth_fpke_dflash(empty_coding=True)
    kombi_df, _kombi_logical = _make_synth_kombi_dflash(sw_version="0310")

    fpke_dir = tmp_path / "fpke_unit"
    fpke_dir.mkdir()
    (fpke_dir / "Dflash.bin").write_bytes(fpke_df)
    kombi_path = tmp_path / "kombi_donor.bin"
    kombi_path.write_bytes(kombi_df)

    win.open_folder(str(fpke_dir))
    app.processEvents()
    scr = win.fpke_screen
    assert scr.is_open

    # 1. restore_dflash_from_file must reject a Kombi 64 KiB Dflash
    warned: list[str] = []
    monkeypatch.setattr(fpke_mod.QFileDialog, "getOpenFileName", lambda *a, **k: (str(kombi_path), ""))
    monkeypatch.setattr(fpke_mod.QMessageBox, "warning", lambda _p, _t, msg, *a, **k: warned.append(msg))
    scr.restore_dflash_from_file()
    assert warned and "Kombi" in warned[0]

    # 2. set_donor_source must accept a Kombi Dflash (Kombi -> FPK_E upgrade)
    scr.set_donor_source(kombi_path)
    assert scr._donor_passport is not None
    assert scr._donor_passport.get("schema") == "contitool.kombi.immo_passport.v1"
    assert (scr._donor_passport.get("cluster_metadata") or {}).get("vin") == "XW8ZZZ5NZJG235992"

    # 3. Coding hex validator must be bound even when current coding is empty (all 0xFF)
    scr.select("keys")
    app.processEvents()
    coding_edits = [
        e for e in scr.findChildren(QLineEdit)
        if "40 hex" in (e.placeholderText() or "").lower()
    ]
    assert coding_edits
    ed_cod = coding_edits[0]
    ed_cod.setText("ZZZ")
    app.processEvents()
    assert ed_cod.property("tone") == "err"

    # 4. btn_close must be disabled when runner is busy
    go = threading.Event()
    win.runner.run_task("hold", lambda _r: go.wait(5))
    app.processEvents()
    busy_close_enabled = scr.btn_close.isEnabled()
    go.set()
    _wait(app, lambda: not win.runner.is_busy)
    assert busy_close_enabled is False
    assert scr.btn_close.isEnabled() is True

    # 5. _on_learned_keys_synced logs warning note instead of silently suppressing errors
    notes: list[str] = []
    scr.note.connect(notes.append)
    captured_dlgs: list[object] = []
    monkeypatch.setattr(fpke_mod, "run_dialog", lambda d: captured_dlgs.append(d) or 0)
    scr.open_coil_key_learn_dialog()
    assert len(captured_dlgs) == 1
    coil_dlg = captured_dlgs[0]
    monkeypatch.setattr(scr, "_commit_dflash_bytes", lambda *_a, **_k: (_ for _ in ()).throw(OSError("disk full")))
    coil_dlg._on_learned_keys_synced(["532B3512"], 1, 2)  # type: ignore[attr-defined]
    assert any("disk full" in n for n in notes)
    win.close()


def test_fpke_coil_dialog_and_can_panel_safety(monkeypatch) -> None:
    """Coil dialog confirms 2E 02F7, guards invalid S0/S1 ValueError, disables while busy & disconnects; CAN panel disconnects & routes Kombi DTC."""
    from PySide6.QtCore import QCoreApplication, QEvent

    from contitool.gui.screens import fpke as fpke_mod

    set_lang("en")
    app, win = create_window()
    win.conn.interface = "slcan"
    win.conn.port = "COM1"
    win.conn.wiring_confirmed = True

    dlg = fpke_mod.FpkeCoilKeyLearnDialog(
        win.conn,
        win.runner,
        dflash_info={
            "metadata": {"vin": "XW8ZZZ5NZJG235992"},
            "immo_config": {"power_class": 0x49},
            "items": [{"key_id": "kc", "hex": "aa" * 16}],
            "slot_secrets": {},
            "transponder_records": {"learned_keys": 1},
        },
        part_number="5NA920740B",
        via_gateway=True,
        gateway_bridge=True,
        gateway_channel=0,
        kombi_mode=True,
        parent=win,
    )
    # 1. Invalid S0/S1 hex or ValueError inside fpke_verify_s0_s1 must not crash
    monkeypatch.setattr(fpke_mod, "fpke_verify_s0_s1", lambda *_a, **_k: (_ for _ in ()).throw(ValueError("bad crc")))
    dlg.ed_s0.setText("11" * 16)
    dlg.ed_s1.setText("22" * 16)
    app.processEvents()
    assert not dlg.btn_start_02f7.isEnabled()
    monkeypatch.setattr(
        fpke_mod,
        "fpke_verify_s0_s1",
        lambda *_a, **_k: {
            "valid": True,
            "not_blank": True,
            "crc_a_ok": True,
            "crc_b_ok": True,
            "slot_a_hex": "AA" * 16,
            "slot_b_hex": "BB" * 16,
            "crc_a_le_hex": "12345678",
            "crc_b_le_hex": "87654321",
        },
    )
    dlg._update_s01_validation()
    assert dlg.btn_start_02f7.isEnabled()

    # 2. run_start_learning_02f7 requires QMessageBox.warning confirmation and aborts on No
    warn_calls: list[str] = []
    monkeypatch.setattr(fpke_mod, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(fpke_mod.QMessageBox, "warning", lambda _p, _t, msg, *a, **k: warn_calls.append(msg) or QMessageBox.StandardButton.No)
    dlg.run_start_learning_02f7()
    assert warn_calls and "02F7" in warn_calls[0]
    assert not win.runner.is_busy

    # 3. Busy runner disables buttons; done() disconnects busy_changed
    go = threading.Event()
    win.runner.run_task("busy", lambda _r: go.wait(5))
    app.processEvents()
    assert not dlg.btn_start_02f7.isEnabled()
    assert not dlg.btn_poll_coil.isEnabled()
    dlg.done(0)
    go.set()
    _wait(app, lambda: not win.runner.is_busy)

    # 4. _FpkeCanControlPanel disconnects on destroy and routes _clear_dtcs_sync via kombi_run_procedure when kombi_mode=True
    from contitool.can import kombi as can_kombi

    panel = fpke_mod._FpkeCanControlPanel(win.conn, win.runner, kombi_mode=True)
    routed: list[str] = []
    monkeypatch.setattr(fpke_mod, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(fpke_mod, "get_active_fpke_link", lambda *_a, **_k: None)
    monkeypatch.setattr(fpke_mod, "open_or_reuse_fpke_link", lambda *_a, **_k: object())
    monkeypatch.setattr(
        can_kombi,
        "kombi_run_procedure",
        lambda _lnk, proc_id, **_k: routed.append(f"kombi:{proc_id}") or {"summary": "Cleared"},
    )
    panel._clear_dtcs_sync()
    _wait(app, lambda: not win.runner.is_busy)
    assert routed == ["kombi:clear_dtc"]

    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(panel)
    # Emitting busy_changed after panel deletion must not raise
    win.runner.busy_changed.emit(True)
    win.runner.busy_changed.emit(False)
    win.close()


def test_main_window_cluster_provider_close_guard_kombi_symmetry_and_frf(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    """MainWindow: _last_cluster_screen, busy close guard, Kombi symmetry, BCM/MRR report isolation, show_about, MRR FRF, closeEvent."""
    from PySide6.QtGui import QCloseEvent

    from contitool.gui import main_window

    set_lang("en")
    app, win = create_window()
    fpke_df = _make_synth_fpke_dflash(gfa_hex="11" * 16)
    kombi_df, _ = _make_synth_kombi_dflash(sw_version="0310", gfa_hex="22" * 16)

    fpke_dir = tmp_path / "fpke"
    fpke_dir.mkdir()
    (fpke_dir / "Dflash.bin").write_bytes(fpke_df)
    kombi_dir = tmp_path / "kombi"
    kombi_dir.mkdir()
    (kombi_dir / "Dflash.bin").write_bytes(kombi_df)

    # Open both clusters, focus kombi, then switch to BCM -> cluster provider must serve Kombi!
    win.open_folder(str(fpke_dir))
    win.open_folder(str(kombi_dir))
    win.bcm_screen.open_from_read_result({"passport": {"part_number": "5Q0937084EA"}, "status": {}})
    win.switch_ecu_view("bcm")
    mat1 = win._provide_fpke_cluster_material()
    assert mat1 is not None and mat1["dflash_bytes"] == kombi_df

    # Focus FPK_E, then return to BCM -> cluster provider must now serve FPK_E!
    win.switch_ecu_view("fpke")
    win.switch_ecu_view("bcm")
    mat2 = win._provide_fpke_cluster_material()
    assert mat2 is not None and mat2["dflash_bytes"] == fpke_df

    # close_ecu() is blocked while busy and act_close / bcm btn_close_top are disabled
    go = threading.Event()
    win.runner.run_task("hold", lambda _r: go.wait(5))
    app.processEvents()
    assert not win.act_close.isEnabled()
    assert not win.bcm_screen.btn_close_top.isEnabled()
    win.close_ecu()
    assert win.bcm_screen.is_open
    go.set()
    _wait(app, lambda: not win.runner.is_busy)
    assert win.act_close.isEnabled()
    assert win.bcm_screen.btn_close_top.isEnabled()

    # Closing BCM when Kombi was last focused cluster falls back cleanly to Kombi (or FPK_E)
    win.close_ecu()
    assert not win.bcm_screen.is_open
    assert win._active_screen in ("fpke", "kombi")

    # Opening J533 without bus scan must close BOTH fpke_screen and kombi_screen symmetrically
    j533_dir = _dumps(tmp_path / "j533", synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(j533_dir))
    app.processEvents()
    assert win.ws.is_open
    assert not win.fpke_screen.is_open
    assert not win.kombi_screen.is_open

    # offer_problem_report must NOT attach J533 dumps when BCM or MRR is active
    captured_dumps: list[dict] = []
    orig_dlg = main_window.ProblemReportDialog

    class _CapDlg(orig_dlg):
        def __init__(self, parent, failure, conn, log_text, dumps):  # noqa: ANN001
            captured_dumps.append(dict(dumps))
            super().__init__(parent, failure, conn, log_text, dumps)

    monkeypatch.setattr(main_window, "ProblemReportDialog", _CapDlg)
    from contitool.report import Failure

    win.bcm_screen.open_from_read_result({"passport": {"part_number": "5Q0937084EA"}, "status": {}})
    win.switch_ecu_view("bcm")
    win.offer_problem_report(Failure("bcm fail", ""))
    assert captured_dumps[-1] == {}

    mrr_dump = tmp_path / "mrr_dflash.bin"
    mrr_dump.write_bytes(b"\xAA" * 64)
    win.mrr_screen.open_offline()
    win.mrr_screen._last_mem_report = {"regions": [{"file": str(mrr_dump)}]}
    win.switch_ecu_view("mrr")
    win.offer_problem_report(Failure("mrr fail", ""))
    assert captured_dumps[-1] == {"loaded/mrr_dflash.bin": mrr_dump}
    if win._report_dlg is not None:
        win._report_dlg.close()

    # act_frf routes to mrr_screen.action_flash_frf() when MRR is active
    frf_called: list[str] = []
    monkeypatch.setattr(win.mrr_screen, "action_flash_frf", lambda: frf_called.append("mrr"))
    win.act_frf.trigger()
    assert frf_called == ["mrr"]

    # show_about lists all 5 supported MQB units and author support links
    about_texts: list[str] = []
    monkeypatch.setattr(main_window.QMessageBox, "about", lambda _p, _t, body: about_texts.append(body))
    win.show_about()
    for token in (
        "19 J533",
        "17 FPK_E / Kombi",
        "09 BCM",
        "13 ACC MRR",
        "2B ELV",
        "https://t.me/tribute/app?startapp=dUo2",
        "UQAqOBO5Yh3Ci2zYidIymqC6SPWrVcV5Erq6-U2trXvH09ol",
        "TESSKf8XFw6jCHcRjGiX6sWJW2AHS76wUD",
        "bc1qltnsw22g5rg5pfcdkzrw08pzjztlx7z6wrtg7x",
    ):
        assert token in about_texts[0]

    # closeEvent prompts on dirty FPK_E Cflash and cancels close if user picks No
    win.open_folder(str(fpke_dir))
    win.fpke_screen._cflash_dirty = True
    monkeypatch.setattr(main_window.QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    ev = QCloseEvent()
    win.closeEvent(ev)
    assert not ev.isAccepted()
    win.fpke_screen._cflash_dirty = False

    # closeEvent does NOT hang if worker finishes while the modal warning dialog is open
    go2 = threading.Event()
    win.runner.run_task("quick", lambda _r: go2.wait(5))
    app.processEvents()

    def _finish_during_prompt(*_a, **_k):  # noqa: ANN202
        go2.set()
        _wait(app, lambda: not win.runner.is_busy)
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(main_window.QMessageBox, "warning", _finish_during_prompt)
    ev2 = QCloseEvent()
    win.closeEvent(ev2)
    assert ev2.isAccepted()

    # _on_operation_finished returns early when _quit_when_idle is True
    offered: list[bool] = []
    monkeypatch.setattr(win, "offer_problem_report", lambda _f: offered.append(True))
    win.runner.last_failure = Failure("boom", "tb")
    win.runner.was_cancelled = False
    win._quit_when_idle = True
    win._on_operation_finished(False, "boom", None)
    assert offered == []


def test_bcm_session_gen_drafts_validation_confirmations_profile_and_kombi(tmp_path: Path, monkeypatch) -> None:
    """BcmScreen: session_gen drops stale callbacks, drafts don't resurrect, strict hex validation, FFB confirmations, profile rerender, Kombi load."""
    from PySide6.QtWidgets import QLabel

    from contitool.gui.screens import bcm as bcm_mod

    set_lang("en")
    app, win = create_window()
    scr = win.bcm_screen
    scr.conn.interface = "slcan"
    scr.conn.port = "COM1"
    scr.conn.wiring_confirmed = True

    scr.open_from_read_result(
        {
            "passport": {"part_number": "5Q0937084EA", "sw_version": "0511"},
            "status": {"freq_code": 0x03, "freq_label": "433 MHz", "rf_0a65_hex": "06"},
            "ika_hex": "aa" * 16,
            "gfa_working_hex": "bb" * 16,
            "dtcs": [],
        }
    )
    gen1 = scr._session_gen

    # 1. Stale generation callback is dropped
    scr._on_status_read({"passport": {"part_number": "STALE999"}}, expected_gen=gen1 - 1)
    assert scr.part_number == "5Q0937084EA"

    # 2. Clearing fields must persist blank across refresh (no draft resurrection)
    scr.ed_write_cur_ika.setText("")
    scr.ed_write_new_gfa.setText("")
    scr.refresh()
    assert scr.ed_write_cur_ika.text() == ""
    assert scr.ed_write_new_gfa.text() == ""

    scr.select("ffb")
    app.processEvents()
    scr.ed_ffb_gfa.setText("")
    scr.refresh()
    assert scr.ed_ffb_gfa.text() == ""

    # 3. Strict hex validation rejects non-hex BEFORE confirmation / CAN launch
    monkeypatch.setattr(bcm_mod, "ensure_ready", lambda *_a: True)
    warns: list[str] = []
    questions: list[str] = []
    monkeypatch.setattr(bcm_mod.QMessageBox, "warning", lambda _p, _t, msg, *a, **k: warns.append(msg))
    monkeypatch.setattr(bcm_mod.QMessageBox, "question", lambda _p, _t, msg, *a, **k: questions.append(msg) or QMessageBox.StandardButton.No)

    scr._draft_cur_ika = "ZZ" * 16
    scr._draft_new_gfa = "BB" * 16
    scr.select("cp_keys")
    scr.action_write_keys(include_ika=False)
    assert warns and not questions

    warns.clear()
    scr.select("ffb")
    scr._draft_ffb_kc = "GG" * 16
    scr._draft_ffb_kffb = ""
    scr.ed_ffb_kc.setText("GG" * 16)
    scr.action_adapt_selected_ffb()
    assert warns and not questions

    warns.clear()
    scr.ed_ffb_kc.setText("11" * 16)
    scr._draft_ffb_rows[0] = {"enabled": True, "serial": "GGGGGGGG", "counter": 0, "source": "manual"}
    scr.action_adapt_selected_ffb()
    assert warns and not questions

    # Clear all FFB also validates hex BEFORE confirmation
    warns.clear()
    scr.ed_ffb_gfa.setText("NOTHEX")
    scr.action_clear_all_ffb()
    assert warns and not questions

    # 4. Valid inputs trigger confirmation dialogs on adapt_selected_ffb & read_cluster_and_adapt_ffb
    warns.clear()
    scr.ed_ffb_gfa.setText("")
    scr.ed_ffb_kc.setText("11" * 16)
    scr._draft_ffb_rows[0] = {"enabled": True, "serial": "532B3512", "counter": 0, "source": "manual"}
    scr.action_adapt_selected_ffb()
    assert not warns and len(questions) == 1 and not win.runner.is_busy

    questions.clear()
    scr.action_read_cluster_and_adapt_ffb()
    assert len(questions) == 1 and not win.runner.is_busy

    # 5. _on_profile_changed re-renders the status page immediately
    scr.select("status")
    app.processEvents()
    idx_dd = scr.cmb_profile.findData("dd_0273")
    assert idx_dd >= 0
    scr.cmb_profile.setCurrentIndex(idx_dd)
    app.processEvents()
    status_texts = " ".join(lbl.text() for lbl in scr.page_area.findChildren(QLabel))
    assert "0273" in status_texts

    # 6. action_load_cluster_dflash_file accepts Kombi dumps and rejects invalid files
    kombi_df, _ = _make_synth_kombi_dflash(sw_version="0310", gfa_hex="77" * 16)
    kfile = tmp_path / "kombi_df.bin"
    kfile.write_bytes(kombi_df)
    monkeypatch.setattr(bcm_mod.QFileDialog, "getOpenFileName", lambda *a, **k: (str(kfile), ""))
    scr.action_load_cluster_dflash_file()
    assert scr._cluster_material is not None
    assert scr._cluster_material.get("gfa_hex", "").lower() == "77" * 16

    warns.clear()
    bad_file = tmp_path / "bad.bin"
    bad_file.write_bytes(b"\x00" * 100)
    monkeypatch.setattr(bcm_mod.QFileDialog, "getOpenFileName", lambda *a, **k: (str(bad_file), ""))
    scr.action_load_cluster_dflash_file()
    assert warns

    # 7. close_bcm bumps session_gen and drops late callbacks
    gen_before_close = scr._session_gen
    scr.close_bcm()
    assert scr._session_gen > gen_before_close
    scr._on_keys_read({"ika_hex": "cc" * 16}, expected_gen=gen_before_close)
    assert scr._ika_hex == ""
    win.close()


def test_mrr_elv_ecu_start_problem_report_fixes(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    """Verify MRR, ELV, ECU, StartScreen, and ProblemReportDialog fixes."""
    from contitool.gui.dialogs import problem_report as pr_mod
    from contitool.gui.screens import ecu as ecu_mod
    from contitool.gui.screens import elv as elv_mod
    from contitool.gui.screens import mrr as mrr_mod
    from contitool.gui.screens.start import _summarize_recent_folder
    from contitool.report import Failure

    set_lang("en")
    app, win = create_window()
    kombi_df, kombi_2220_logical = _make_synth_kombi_dflash(sw_version="2220", gfa_hex="33" * 16)

    # ── MRR ──
    mrr = win.mrr_screen
    mrr.open_offline()
    mrr._profile_override = "0682"
    g_mrr = mrr._session_gen
    # Stale callback ignored
    mrr._on_status_read({"passport": {"part_number": "STALE"}}, expected_gen=g_mrr - 1)
    assert mrr._passport == {}
    # _on_frf_flashed clears _profile_override
    mrr._on_frf_flashed({"passport_after": {"part_number": "3QF907561D", "sw_version": "0780"}}, expected_gen=g_mrr)
    assert mrr._profile_override == ""
    # _mrr_session_dir handles OSError gracefully
    mrr_warns: list[str] = []
    monkeypatch.setattr(mrr_mod, "new_session", lambda *_a, **_k: (_ for _ in ()).throw(OSError("read-only fs")))
    monkeypatch.setattr(mrr_mod.QMessageBox, "warning", lambda _p, _t, msg, *a, **k: mrr_warns.append(msg))
    assert mrr._mrr_session_dir("mrr_keys") is None and mrr_warns
    # action_fill_gfa_from_cluster accepts Kombi Dflash
    k_path = tmp_path / "kombi_gfa.bin"
    k_path.write_bytes(kombi_df)
    monkeypatch.setattr(mrr_mod.QFileDialog, "getOpenFileName", lambda *a, **k: (str(k_path), ""))
    mrr.action_fill_gfa_from_cluster()
    assert mrr._draft_new_gfa == ("33" * 16).upper()

    # ── ELV ──
    elv = win.elv_screen
    elv.open_from_read_result({"passport": {"part_number": "3Q0905861", "vin": "WVWZZZ3CZGE000001"}, "status": {"mode": 2}})
    # Merging a partial update with empty VIN must NOT wipe existing VIN
    elv.open_from_read_result({"passport": {"part_number": "3Q0905861", "vin": ""}, "status": {"mode": 2, "lock_time_ms": 0}})
    assert elv._passport["vin"] == "WVWZZZ3CZGE000001"
    assert elv._status["lock_time_ms"] == 0
    # action_load_cluster_dflash accepts Kombi dump
    monkeypatch.setattr(elv_mod.QFileDialog, "getOpenFileName", lambda *a, **k: (str(k_path), ""))
    monkeypatch.setattr(elv_mod.QMessageBox, "warning", lambda *_a, **_k: None)
    elv.action_load_cluster_dflash()
    assert elv._cluster_material is not None
    assert elv._cluster_material.get("vin") == "XW8ZZZ5NZJG235992"
    # action_can_adapt / action_can_virginize invalidate cached _dflash_bytes & _dflash_parsed on ok=True
    elv._dflash_bytes = b"\xAA" * 32768
    elv._dflash_parsed = {"mode": 2}
    elv._dflash_path = tmp_path / "old_elv.bin"
    elv._draft_vin = "WVWZZZ3CZGE000001"
    elv._draft_new_k5 = "11" * 16
    elv._draft_cur_k5 = "22" * 16
    elv._draft_pc = "49"
    elv._draft_cfg = "02"
    elv._draft_brand = "01"
    elv._draft_offline_idac = "AABB"
    elv._create_session_dir = lambda *_a, **_k: tmp_path  # type: ignore[method-assign]
    monkeypatch.setattr(elv_mod, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(elv_mod, "run_dialog", lambda *_a: True)
    monkeypatch.setattr(elv_mod, "can_elv_adapt", lambda *_a, **_k: {"ok": True, "post_status": {"mode": 2}})
    elv.action_can_adapt()
    _wait(app, lambda: not win.runner.is_busy)
    assert elv._dflash_bytes is None and elv._dflash_parsed is None and elv._dflash_path is None

    elv._dflash_bytes = b"\xBB" * 32768
    elv._dflash_parsed = {"mode": 2}
    monkeypatch.setattr(elv_mod, "can_elv_virginize", lambda *_a, **_k: {"ok": True, "post_status": {"mode": 1}})
    elv.action_can_virginize()
    _wait(app, lambda: not win.runner.is_busy)
    assert elv._dflash_bytes is None and elv._dflash_parsed is None

    # ── ECU ──
    from contitool.core import apply_fpa_dataset, build_fpa_preset_block

    df_with_zdc = apply_fpa_dataset(synth_dflash, build_fpa_preset_block("fwd"))
    ecu_dir = _dumps(tmp_path / "ecu_zdc", synth_cflash, df_with_zdc, synth_uflash)
    win.open_folder(str(ecu_dir))
    ecu_warns: list[str] = []
    monkeypatch.setattr(ecu_mod.QFileDialog, "getExistingDirectory", lambda *a, **k: str(tmp_path))
    monkeypatch.setattr(ecu_mod.QMessageBox, "warning", lambda _p, _t, msg, *a, **k: ecu_warns.append(msg))
    with monkeypatch.context() as mp:
        mp.setattr(Path, "write_bytes", lambda *_a, **_k: (_ for _ in ()).throw(OSError("no space")))
        win.ecu_screen._export_zdc()
    assert ecu_warns and "no space" in ecu_warns[0]

    # ── StartScreen ──
    kombi_8v0_only = tmp_path / "8V0920860G_2220"
    kombi_8v0_only.mkdir()
    (kombi_8v0_only / "Dflash.bin").write_bytes(kombi_df)
    meta_prefix = _summarize_recent_folder(kombi_8v0_only)
    assert meta_prefix["addr"] == "17" and meta_prefix["tone"] == "can"
    (kombi_8v0_only / "EelLogical.bin").write_bytes(kombi_2220_logical)
    meta_eel = _summarize_recent_folder(kombi_8v0_only)
    assert "EEL 130" in meta_eel["tags"]

    # ── ProblemReportDialog ──
    from PySide6.QtWidgets import QLabel

    pr_dlg = pr_mod.ProblemReportDialog(win, Failure("err", "tb"), win.conn, "log", {})
    all_pr_texts = " ".join(lbl.text() for lbl in pr_dlg.findChildren(QLabel))
    assert "stripped/masked" in all_pr_texts
    evil_dest = tmp_path / "<b>dir&1<x>.zip"
    evil_dest.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    monkeypatch.setattr(pr_mod, "build_report_zip", lambda dest, *_a, **_k: dest)
    pr_dlg.create(dest=evil_dest, open_browser=False)
    assert "&lt;b&gt;dir&amp;1&lt;x&gt;.zip" in pr_dlg.lbl_status.text()
    pr_dlg.close()
    win.close()
