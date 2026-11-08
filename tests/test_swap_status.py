"""After a SWaP patch: the gateway's own answer (UDS 22 3C 00) shows which features it accepted."""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtWidgets import QLabel  # noqa: E402

from contitool.can import can_swap_status, workflows  # noqa: E402
from contitool.core import apply_dflash_swap_fecs  # noqa: E402
from contitool.gui.app import create_window  # noqa: E402
from contitool.gui.screens import status  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402
from test_identify import IDENT, FakeGateway  # noqa: E402
from test_swap_multifsc import make_dflash_with_zdc  # noqa: E402


def test_swap_status_lists_what_the_ecu_reports(monkeypatch) -> None:
    set_lang("en")
    sleeps: list[float] = []
    monkeypatch.setitem(IDENT, 0x3C00, bytes.fromhex("10000100FF" "10000300B0" "10001600FB" "FFFFFFFFFF"))
    monkeypatch.setattr(workflows.time, "sleep", sleeps.append)
    res = can_swap_status("fake", bus=FakeGateway())
    assert res["features"] == [
        {"fsid": 0x10000100, "status": 0xFF},
        {"fsid": 0x10000300, "status": 0xB0},
        {"fsid": 0x10001600, "status": 0xFB},
    ]  # the empty slot is left out
    assert len(sleeps) == 2  # a certificate that failed a check is read again while the ECU may still be checking it
    states = [status.swap_live_state(f["status"]) for f in res["features"]]
    assert [s.key for s in states] == ["on", "off", "err"]
    assert states[2].detail == "the certificate is for another ECU (VCRN)"


def test_writing_a_swap_patch_shows_what_the_ecu_accepted(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    from PySide6.QtWidgets import QMessageBox

    from contitool.gui.screens import ecu

    set_lang("en")
    app, win = create_window()
    folder = tmp_path / "dumps"
    folder.mkdir()
    df = make_dflash_with_zdc(synth_dflash)
    (folder / "Cflash.bin").write_bytes(synth_cflash)
    (folder / "Dflash.bin").write_bytes(df)
    (folder / "Uflash.bin").write_bytes(synth_uflash)
    win.open_folder(str(folder))
    app.processEvents()
    patched, _ = apply_dflash_swap_fecs(df, enable_fecs=[0x10000100, 0x10001600])
    (tmp_path / "Dflash_swap.bin").write_bytes(patched)
    win.ws.commit("dflash", tmp_path / "Dflash_swap.bin")
    app.processEvents()

    checks: list[str] = []
    win.conn.out_dir = tmp_path / "runs"
    monkeypatch.setattr(ecu, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(ecu, "can_write_dflash", lambda port, path, **kw: {})
    answer = [{"fsid": 0x10000100, "status": 0xFF}, {"fsid": 0x10001600, "status": 0xFB}, {"fsid": 0x10000300, "status": 0xB0}]
    monkeypatch.setattr(ecu, "can_swap_status", lambda port, **kw: checks.append(port) or {"features": answer})

    win.ecu_screen._write_to_ecu()
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop.quit())
    QTimer.singleShot(8000, loop.quit)
    loop.exec()
    app.processEvents()

    screen = win.ecu_screen
    assert len(checks) == 1 and screen._key == "swap"
    texts = [lbl.text() for lbl in screen.page_area.widget().findChildren(QLabel)]
    assert "✕  The ECU did not accept: Driving Profile FPA 6 — Race / Cupra" in texts
    assert "the certificate is for another ECU (VCRN)" in texts
    assert texts.count("active") == 1 and "NOT ACTIVATED (1) — SUPPORTED, NO CERTIFICATE" in texts and "Check again" in screen.actions["swap_check"].text()

    set_lang("ru")  # the list follows a language switch
    app.processEvents()
    texts = [lbl.text() for lbl in screen.page_area.widget().findChildren(QLabel)]
    assert "активна" in texts and "сертификат выпущен для другого блока (VCRN)" in texts
    set_lang("en")
    win.close()
