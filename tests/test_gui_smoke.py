"""Headless GUI tests: start screen, loading an ECU, feature states, edits, and RU<->EN switching."""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QSettings, QTimer  # noqa: E402

from contitool.core import T20_BENCH_PINS  # noqa: E402
from contitool.gui.app import create_window  # noqa: E402
from contitool.gui.dialogs.cp import CpBindDialog  # noqa: E402
from contitool.gui.screens import status  # noqa: E402
from contitool.i18n import get_lang, set_lang  # noqa: E402


def _dump_folder(tmp_path: Path, cflash: bytes, dflash: bytes, uflash: bytes) -> Path:
    folder = tmp_path / "dumps"
    folder.mkdir()
    (folder / "Cflash.bin").write_bytes(cflash)
    (folder / "Dflash.bin").write_bytes(dflash)
    (folder / "Uflash.bin").write_bytes(uflash)
    return folder


def _run_pending(app, win, timeout_ms: int = 8000) -> None:
    """Wait for the current background operation to finish."""
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop.quit())
    QTimer.singleShot(timeout_ms, loop.quit)
    loop.exec()
    app.processEvents()


def test_t20_diagnosis_can_pinout_is_9_and_19() -> None:
    pin_map = {pin: sig for pin, sig, _, _ in T20_BENCH_PINS}
    assert set(pin_map.keys()) == {1, 14, 11, 19, 9}
    assert pin_map[19] == "Diag CAN-H"
    assert pin_map[9] == "Diag CAN-L"

    from contitool.gui.widgets.pinout_card import PinoutCard

    set_lang("ru")
    app, win = create_window()
    card = PinoutCard()
    assert not card.grab().isNull()
    assert "Pin 19" in card.lbl_warn.text()
    assert "Pin 9" in card.lbl_warn.text()
    app.processEvents()
    win.close()


def test_start_screen_until_an_ecu_is_loaded(synth_cflash, synth_dflash, synth_uflash, tmp_path: Path) -> None:
    QSettings().clear()
    set_lang("ru")
    app, win = create_window()
    win.show()
    assert win.stack.currentWidget() is win.start_screen

    folder = _dump_folder(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()

    assert win.ws.is_open
    assert win.stack.currentWidget() is win.ecu_screen
    assert win.ws.part_number == "3Q0907530AR"
    assert "3Q0907530AR" in win.tab_ecu.text()

    win.close_ecu()
    app.processEvents()
    assert win.stack.currentWidget() is win.start_screen
    win.close()


def test_feature_states_read_from_the_dumps(synth_cflash, synth_dflash, synth_uflash, tmp_path: Path) -> None:
    set_lang("en")
    app, win = create_window()
    folder = _dump_folder(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()

    assert status.component_protection(win.ws).text == "factory"
    assert status.engineering(win.ws).text == "off"
    assert status.bootloader(win.ws).text == "factory"
    assert status.swap_key(win.ws).text == "factory VAG"
    assert status.fbl_key(win.ws).text == "factory VAG"

    # A missing dump degrades to "unknown" instead of hiding the feature
    win.ws.current.pop("uflash")
    win.ws._info.pop("uflash")
    assert status.bootloader(win.ws).known is False
    win.close()


def test_editing_a_dump_writes_a_copy_and_offers_to_write_it(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path
) -> None:
    set_lang("ru")
    app, win = create_window()
    folder = _dump_folder(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()

    original = win.ws.path("cflash")
    assert not win.ecu_screen.changes.isVisible()

    win.ecu_screen._patch_engineering(restore=False)
    _run_pending(app, win)

    edited = win.ws.path("cflash")
    assert edited != original
    assert edited.parent.name == "ContiTool_edited"
    assert original.read_bytes() == synth_cflash  # original is never touched
    assert win.ws.pending("cflash")
    assert status.engineering(win.ws).text == "включён"
    assert win.console.progress_bar.value() == 1000

    win.ws.revert()
    app.processEvents()
    assert win.ws.path("cflash") == original
    assert not win.ws.pending("cflash")
    win.close()


def test_language_switch_updates_every_visible_screen(synth_cflash, synth_dflash, synth_uflash, tmp_path: Path) -> None:
    set_lang("ru")
    app, win = create_window()
    win.show()
    assert "блок" in win.start_screen.lbl_title.text().lower()

    win._lang_buttons["en"].click()
    app.processEvents()
    assert get_lang() == "en"
    assert "ECU" in win.start_screen.lbl_title.text()

    folder = _dump_folder(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()
    assert win.ecu_screen.nav_rows["cp"].lbl_name.text() == "Module pairing"

    win._lang_buttons["ru"].click()
    app.processEvents()
    assert win.ecu_screen.nav_rows["cp"].lbl_name.text() == "Привязка модулей"
    win.close()


def test_bind_dialog_requires_a_bank_and_a_sane_key(synth_dflash) -> None:
    from contitool.core import analyze_dflash

    set_lang("ru")
    app, _win = create_window()
    dlg = CpBindDialog(analyze_dflash(synth_dflash))

    assert not dlg.btn_ok.isEnabled()  # nothing ticked, no key
    dlg.tbl.item(0, 0).setCheckState(dlg.tbl.item(0, 0).checkState().Checked)
    dlg.ed_key.setText("00" * 16)
    app.processEvents()
    assert not dlg.btn_ok.isEnabled()  # all-zero key is refused until explicitly allowed

    dlg.chk_allow_suspicious.setChecked(True)
    app.processEvents()
    assert dlg.btn_ok.isEnabled()

    dlg._generate()
    app.processEvents()
    assert dlg.btn_ok.isEnabled()
    assert len(dlg._parsed_key()[0]) == 16
    dlg.close()


def test_identity_rows_are_rebuilt_not_stacked(synth_cflash, synth_dflash, synth_uflash, tmp_path: Path) -> None:
    set_lang("ru")
    app, win = create_window()
    folder = _dump_folder(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()
    before = win.ecu_screen.grid_id.count()

    for _ in range(3):
        win._lang_buttons["en"].click()
        win._lang_buttons["ru"].click()
        app.processEvents()

    assert win.ecu_screen.grid_id.count() == before


def test_swap_page_walks_through_key_then_certificate(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path
) -> None:
    set_lang("en")
    app, win = create_window()
    win.show()
    folder = _dump_folder(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()
    screen = win.ecu_screen
    screen.select("swap")
    app.processEvents()
    assert "swap_stock" not in screen.actions
    assert not screen.actions["fsc"].isEnabled()  # no own key yet: step 2 waits for step 1

    screen._set_key("swap", None)  # generates a fresh keypair and embeds it
    _run_pending(app, win, timeout_ms=60000)
    assert status.swap_key(win.ws).text == "custom"
    assert screen.actions["swap_stock"].isVisible()
    assert screen.actions["fsc"].isEnabled()
    keys = list((folder / "ContiTool_keys").glob("j533_swap_*.json"))
    assert len(keys) == 1 and screen._key_file == keys[0]
    win.close()


def test_changes_panel_says_which_dumps_to_write_and_how(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    from PySide6.QtWidgets import QFileDialog

    set_lang("en")
    app, win = create_window()
    folder = _dump_folder(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()
    screen = win.ecu_screen

    screen._patch_engineering(restore=False)
    _run_pending(app, win)
    assert screen.change_state("cflash")[0] == "changed"
    assert screen.change_state("cflash")[2] == "written over CAN with “Write to ECU”"  # 0xA167 alone is no reason to warn
    assert screen.change_state("dflash")[0] == "unchanged"
    assert screen.change_state("uflash")[0] == "unchanged"
    assert screen.btn_write.isEnabled()

    # an FBL key lives at 0xA2F7 in boot block 5 and is also written over CAN via FACI
    screen._set_key("fbl", None)
    _run_pending(app, win, timeout_ms=60000)
    assert "FBL" in screen.change_state("cflash")[2]
    assert "Write to ECU" in screen.change_state("cflash")[2]

    # saving copies only the changed dump, never into the originals' folder
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(out))
    screen._save_dumps()
    assert sorted(p.name for p in out.iterdir()) == ["Cflash.bin"]
    assert (out / "Cflash.bin").read_bytes() == win.ws.path("cflash").read_bytes()

    from PySide6.QtWidgets import QMessageBox

    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(folder))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Ok)
    screen._save_dumps()
    assert (folder / "Cflash.bin").read_bytes() == synth_cflash
    win.close()


def test_writing_codeflash_activates_the_engineering_bootloader_first(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    from PySide6.QtWidgets import QMessageBox

    from contitool.gui.screens import ecu

    set_lang("en")
    app, win = create_window()
    folder = _dump_folder(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()
    win.ecu_screen._patch_engineering(restore=False)
    _run_pending(app, win)

    calls: list[tuple[str, dict]] = []
    win.conn.out_dir = tmp_path / "runs"  # session folders go here, not into the repository
    monkeypatch.setattr(ecu, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(ecu, "can_write_uflash", lambda port, **kw: calls.append(("uflash", kw)) or {})
    monkeypatch.setattr(ecu, "can_write_cflash", lambda port, path, **kw: calls.append(("cflash", kw)) or {})

    win.ecu_screen._write_to_ecu()
    _run_pending(app, win)
    assert [c[0] for c in calls] == ["uflash", "cflash"]
    assert calls[0][1]["restore_stock"] is False
    assert not win.ws.pending("cflash")
    assert win.ecu_screen.change_state("cflash")[0] == "written"
    win.close()


def test_writing_dataflash_over_can_without_bench_programmer(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    from PySide6.QtWidgets import QMessageBox

    from contitool.core import bind_cp_turnkey, parse_hex_key, parse_slot_selector
    from contitool.gui.screens import ecu

    set_lang("en")
    app, win = create_window()
    folder = _dump_folder(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()

    # Apply a DataFlash-only modification (e.g. edited Dflash.bin) and verify Write to ECU writes Dflash over CAN
    _, df_edited, _ = bind_cp_turnkey(
        synth_cflash,
        synth_dflash,
        [(parse_slot_selector("5F"), parse_hex_key("112233445566778899AABBCCDDEEFF00"))],
    )
    edited_df_path = tmp_path / "Dflash_edited.bin"
    edited_df_path.write_bytes(df_edited)
    win.ws.commit("dflash", edited_df_path)
    app.processEvents()

    assert win.ecu_screen.change_state("dflash") == (
        "changed",
        "info",
        "written over CAN with “Write to ECU”",
    )
    assert win.ecu_screen.btn_write.isEnabled()

    calls: list[tuple[str, Path, dict]] = []
    monkeypatch.setattr(ecu, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(
        ecu, "can_write_dflash", lambda port, path, **kw: calls.append(("dflash", path, kw)) or {}
    )

    win.ecu_screen._write_to_ecu()
    _run_pending(app, win)
    assert len(calls) == 1 and calls[0][0] == "dflash"
    assert calls[0][1].read_bytes() == df_edited
    assert not win.ws.pending("dflash")
    assert win.ecu_screen.change_state("dflash")[0] == "written"
    win.close()


def test_short_log_hides_addresses_and_raw_bytes() -> None:
    from contitool.gui.widgets.execution_panel import plain_step

    assert plain_step("Пересчёт Application CRC-16/MODBUS @ 0x0000C21C") == "Пересчёт Application CRC-16/MODBUS"
    assert plain_step("Чтение регистра ошибок DTC (UDS 19 02 FF)") == "Чтение регистра ошибок DTC"
    assert plain_step("Проверка активного RAM-Loader (0x6F0)") == "Проверка активного RAM-Loader"
    assert plain_step("Анализ банков CP в DataFlash (64 КБ)") == "Анализ банков CP в DataFlash (64 КБ)"


def test_short_log_lists_steps_and_outcome(synth_cflash, synth_dflash, synth_uflash, tmp_path: Path) -> None:
    set_lang("ru")
    app, win = create_window()
    folder = _dump_folder(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()

    win.ecu_screen._patch_engineering(restore=False)
    _run_pending(app, win)

    short = win.console.txt_short.toPlainText()
    assert "Включение расширенной диагностики" in short
    assert "готово" in short
    assert "0x0000C21C" not in short  # technical detail stays in the detailed view
    assert "0x0000C21C" in win.console.txt_full.toPlainText()
    win.close()
