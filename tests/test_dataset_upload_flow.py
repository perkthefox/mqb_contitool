"""'Write datasets over CAN': SWaP the datasets need are switched on first, then the upload, then the DTC offer."""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402

from contitool.core.zdc import build_fpa_preset_block, fecs_required_by_dataset  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402

MKE, NORMAL, SPORT, ECO = 0x10000300, 0x10001200, 0x10001300, 0x10001500


def _with_fpa(df: bytes) -> bytes:
    out = bytearray(df)
    out[0x1340:0x2440] = build_fpa_preset_block("fwd", existing_zdc4=bytes(out[0x1340:0x2440])).to_sealed_bytes()
    return bytes(out)


def test_every_profile_in_the_menu_needs_its_slots_feature(synth_dflash: bytes) -> None:
    """The gateway offers a slot to the head unit only with that slot's FeC active (FSG-Setup builder, 5388/5504)."""
    need = fecs_required_by_dataset(_with_fpa(synth_dflash))
    assert set(need) == {NORMAL, SPORT, ECO, 0x10001700}  # the "fwd" preset: Normal, Sport, Eco, Individual


def test_missing_swap_is_activated_before_the_upload(synth_dflash: bytes, tmp_path: Path, monkeypatch) -> None:
    from PySide6.QtWidgets import QMessageBox

    from contitool.gui.app import create_window
    from contitool.gui.screens import ecu

    set_lang("en")
    app, win = create_window()
    folder = tmp_path / "dumps"
    folder.mkdir()
    df = _with_fpa(synth_dflash)
    (folder / "Dflash.bin").write_bytes(df)
    win.open_folder(str(folder))
    win.conn.out_dir = tmp_path / "runs"
    calls: list[tuple] = []
    live = [{"fsid": MKE, "status": 0x7F}, {"fsid": NORMAL, "status": 0x00}, {"fsid": SPORT, "status": 0x00}]

    def swap_status(*_a, **_k):
        calls.append(("status",))
        return {"features": live}

    def activate(_p, fecs, **_k):
        calls.append(("activate", sorted(fecs)))
        for f in live:
            f["status"] = 0x7F
        return {}

    def click(box):  # the plan: take "Activate SWaP and upload"
        next(b for b in box.buttons() if b.text().startswith("Activate")).click()
        return 0

    monkeypatch.setattr(ecu, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(ecu, "can_swap_status", swap_status)
    monkeypatch.setattr(ecu, "can_read_gateway_coding", lambda *_a, **_k: {"coding": bytes(30)})
    monkeypatch.setattr(ecu, "can_activate_swap", activate)
    monkeypatch.setattr(ecu, "can_upload_zdc_datasets", lambda *_a, **_k: calls.append(("upload",)) or {})
    monkeypatch.setattr(ecu, "can_health_check", lambda *_a, **k: calls.append(("dtc", k["clear_dtc"])) or {})
    monkeypatch.setattr(QMessageBox, "exec", click)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)

    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: calls[-1][0] == "dtc" and loop.quit())
    QTimer.singleShot(8000, loop.quit)
    win.ecu_screen._upload_zdc_over_can()
    loop.exec()
    app.processEvents()
    assert calls == [("status",), ("activate", sorted({SPORT, NORMAL, ECO, 0x10001700} - {MKE})), ("upload",), ("status",), ("dtc", True)]
    win.close()
