"""Dataset export to ODIS parameterization files and back."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402

from contitool.core.zdc import (  # noqa: E402
    apply_odis_zdc_file,
    build_fpa_preset_block,
    build_odis_zdc_file,
    erase_zdc_block,
    export_zdc_block,
    parse_odis_zdc_file,
    populated_zdc_blocks,
)
from contitool.i18n import set_lang  # noqa: E402


def _with_fpa(df: bytes) -> bytes:
    out = bytearray(df)
    out[0x1340:0x2440] = build_fpa_preset_block("fwd", existing_zdc4=bytes(out[0x1340:0x2440])).to_sealed_bytes()
    return bytes(out)


def test_odis_file_round_trips(synth_dflash: bytes) -> None:
    df = _with_fpa(synth_dflash)
    xml = build_odis_zdc_file(df, 4)
    assert xml.startswith(b'<?xml version="1.0" encoding="UTF-8"?>\r\n') and b'START_ADDRESS="0x0B80"' in xml
    parsed = parse_odis_zdc_file(xml)
    assert parsed.zdc_idx == 4 and parsed.payload == export_zdc_block(df, 4)
    blank = erase_zdc_block(df, 4)
    assert 4 not in populated_zdc_blocks(blank)
    assert export_zdc_block(apply_odis_zdc_file(blank, parsed), 4) == export_zdc_block(df, 4)
    with pytest.raises(ValueError):
        build_odis_zdc_file(blank, 4)


def test_export_and_import_from_the_dataset_page(synth_dflash: bytes, tmp_path: Path, monkeypatch) -> None:
    from PySide6.QtGui import QDesktopServices
    from PySide6.QtWidgets import QFileDialog

    from contitool.gui.app import create_window

    set_lang("en")
    app, win = create_window()
    folder = tmp_path / "dumps"
    folder.mkdir()
    df = _with_fpa(synth_dflash)
    (folder / "Dflash.bin").write_bytes(df)
    win.open_folder(str(folder))
    out = tmp_path / "export"
    out.mkdir()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(out))
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda *a, **k: True)
    win.ecu_screen._export_zdc()
    exported = next(out.iterdir())
    names = {p.name for p in exported.iterdir()}
    assert {"ZDC4_MAIN_GW.xml", "ZDC4_MAIN_GW.bin", "ZDC_area_0000-303F.bin"} <= names

    # the exported FPA file goes into a DataFlash whose block #4 is blank
    blank = folder / "blank" / "Dflash.bin"
    blank.parent.mkdir()
    blank.write_bytes(erase_zdc_block(df, 4))
    win.open_folder(str(blank.parent))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(exported / "ZDC4_MAIN_GW.xml"), ""))
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop.quit())
    QTimer.singleShot(5000, loop.quit)
    win.ecu_screen._import_odis_zdc()
    loop.exec()
    app.processEvents()
    assert win.ws.modified("dflash")
    assert export_zdc_block(win.ws.path("dflash").read_bytes(), 4) == export_zdc_block(df, 4)
    win.close()
