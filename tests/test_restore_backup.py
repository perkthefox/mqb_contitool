"""Writing a backup back: only into the ECU it was taken from (same FAZIT / VCRN), checked before any write."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from contitool.can import workflows  # noqa: E402
from contitool.can.workflows import backup_identity, backup_owner_problems, can_restore_backup  # noqa: E402
from contitool.core.constants import CFLASH_ADDR_START, DFLASH_ADDR_START  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402


def test_owner_check(synth_cflash: bytes, synth_dflash: bytes) -> None:
    set_lang("en")
    mine = backup_identity(synth_cflash, synth_dflash)
    assert mine == {"fazit": "TST-SYN01.01.260000001", "vcrn": "1122334455"}
    ecu = {k: str(v) for k, v in mine.items()}
    assert backup_owner_problems(ecu, mine, {"cflash", "dflash", "uflash"}) == []
    assert backup_owner_problems(ecu, {"fazit": None, "vcrn": "1122334455"}, {"dflash"}) == []  # DataFlash alone is enough

    other = backup_owner_problems(ecu, {"fazit": "ABC-XYZ01.01.260000099", "vcrn": "1122334455"}, {"dflash"})
    assert len(other) == 1 and "another ECU" in other[0]  # refused even though only DataFlash would be written
    erased = backup_owner_problems(ecu, {"fazit": "TST-SYN01.01.260000001", "vcrn": ""}, {"dflash"})
    assert len(erased) == 1 and "erase" in erased[0]
    assert backup_owner_problems(ecu, {"fazit": None, "vcrn": ""}, {"uflash"})  # nothing to compare -> refused


@pytest.fixture
def fake_ecu(monkeypatch: pytest.MonkeyPatch):
    """The ECU's flash as the loader would read it, and the write calls the restore makes."""
    ecu: dict[str, bytes] = {}
    calls: list[str] = []

    def read_area(_link, start, end, path, **_kw):
        base, img = (DFLASH_ADDR_START, ecu["dflash"]) if start >= DFLASH_ADDR_START else (CFLASH_ADDR_START, ecu["cflash"])
        path.write_bytes(img[start - base : end - base])
        return {}

    monkeypatch.setattr(workflows, "J533CanLink", lambda *a, **k: contextlib.nullcontext())
    monkeypatch.setattr(workflows, "enter_ram_loader", lambda *a, **k: {})
    monkeypatch.setattr(workflows, "_reset_to_application", lambda *a, **k: {})
    monkeypatch.setattr(workflows, "read_memory_area", read_area)
    monkeypatch.setattr(workflows, "can_write_cflash", lambda *a, **k: calls.append("cflash") or {})
    monkeypatch.setattr(workflows, "can_write_dflash", lambda *a, **k: calls.append("dflash") or {})
    def write_uflash(*_a, **k):
        if k.get("input_uflash") is None:
            calls.append("uflash_eng")
            return {"write_performed": True}  # the ECU had the factory bootloader
        calls.append(f"uflash:{Path(k['input_uflash']).name}")
        return {}

    monkeypatch.setattr(workflows, "can_write_uflash", write_uflash)
    return ecu, calls


def _backup(tmp_path: Path, cf: bytes, df: bytes, uf: bytes) -> dict[str, Path]:
    files = {"cflash": tmp_path / "Cflash.bin", "dflash": tmp_path / "Dflash.bin", "uflash": tmp_path / "Uflash.bin"}
    for kind, raw in (("cflash", cf), ("dflash", df), ("uflash", uf)):
        files[kind].write_bytes(raw)
    return files


def test_restore_writes_own_backup_bootloader_last(fake_ecu, synth_cflash, synth_dflash, synth_uflash, tmp_path) -> None:
    ecu, calls = fake_ecu
    ecu.update(cflash=synth_cflash, dflash=synth_dflash)
    files = _backup(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    res = can_restore_backup("fake", files, ["cflash", "dflash", "uflash"], session_dir=tmp_path / "run")
    assert res["ecu"] == {"fazit": "TST-SYN01.01.260000001", "vcrn": "1122334455"}
    assert calls == ["uflash_eng", "cflash", "dflash", "uflash:Uflash.bin"]


def test_restoring_codeflash_alone_puts_the_ecus_bootloader_back(fake_ecu, synth_cflash, synth_dflash, synth_uflash, tmp_path) -> None:
    ecu, calls = fake_ecu
    ecu.update(cflash=synth_cflash, dflash=synth_dflash)
    files = _backup(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    can_restore_backup("fake", files, ["cflash"], session_dir=tmp_path / "run")
    assert calls == ["uflash_eng", "cflash", "uflash:Uflash_before.bin"]  # not left on the engineering bootloader


def test_restore_refuses_a_backup_of_another_ecu(fake_ecu, synth_cflash, synth_dflash, synth_uflash, tmp_path) -> None:
    set_lang("en")
    ecu, calls = fake_ecu
    other = bytearray(synth_cflash)
    other[0xA240:0xA257] = b"ABC-XYZ01.01.260000099 "
    ecu.update(cflash=bytes(other), dflash=synth_dflash)
    files = _backup(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    with pytest.raises(RuntimeError, match="another ECU"):
        can_restore_backup("fake", files, ["dflash"], session_dir=tmp_path / "run")
    assert calls == []  # nothing was written


def test_restore_writes_the_files_the_user_picks(synth_cflash, synth_dflash, synth_uflash, tmp_path, monkeypatch) -> None:
    from PySide6.QtCore import QEventLoop, QTimer

    from contitool.gui import main_window
    from contitool.gui.app import create_window
    from contitool.gui.dialogs.restore import RestoreDialog

    set_lang("en")
    app, win = create_window()
    folder = tmp_path / "picked"
    folder.mkdir()
    for name, raw in (("Cflash.bin", synth_cflash), ("Dflash.bin", synth_dflash), ("Uflash.bin", synth_uflash), ("notes.bin", b"x" * 100)):
        (folder / name).write_bytes(raw)

    dlg = RestoreDialog(win)
    assert dlg.kinds == [] and not dlg.ok.isEnabled()  # nothing is taken from the open ECU: the user picks the files
    rejected = dlg.add_files(sorted(folder.iterdir()))
    assert rejected == ["notes.bin"]
    assert dlg.kinds == ["cflash", "dflash", "uflash"] and dlg.ok.isEnabled()
    assert dlg.lbl_ident.text() == "FAZIT: TST-SYN01.01.260000001    VCRN: 1122334455"
    dlg.boxes["cflash"].setChecked(False)
    assert dlg.kinds == ["dflash", "uflash"]

    calls: list[tuple] = []
    fake = type("D", (), {"exec": lambda s: True, "deleteLater": lambda s: None, "kinds": ["dflash"], "files": dict(dlg.files)})
    monkeypatch.setattr(main_window, "RestoreDialog", lambda *_a: fake())
    monkeypatch.setattr(main_window, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(main_window, "can_restore_backup", lambda port, files, kinds, **kw: calls.append((sorted(files), kinds)) or {})
    win.conn.out_dir = tmp_path / "runs"
    win.act_restore.trigger()  # File menu, no ECU open
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop.quit())
    QTimer.singleShot(8000, loop.quit)
    loop.exec()
    assert calls == [(["cflash", "dflash", "uflash"], ["dflash"])]  # the whole backup goes to the FAZIT/VCRN check
    win.close()


def test_export_backup_copies_the_dumps_as_read(synth_cflash, synth_dflash, synth_uflash, tmp_path, monkeypatch) -> None:
    from PySide6.QtWidgets import QFileDialog

    from contitool.core import apply_dflash_swap_fecs
    from contitool.gui.app import create_window

    set_lang("en")
    app, win = create_window()
    session = tmp_path / "contitool_runs" / "backup_20261108_120000"
    session.mkdir(parents=True)
    for name, raw in (("Cflash.bin", synth_cflash), ("Dflash.bin", synth_dflash), ("Uflash.bin", synth_uflash)):
        (session / name).write_bytes(raw)
    (session / "manifest.json").write_text("{}")
    win.ws.open_folder(session, source="can")
    app.processEvents()
    patched, _ = apply_dflash_swap_fecs(synth_dflash, enable_fecs=[0x10000100])
    (tmp_path / "edited.bin").write_bytes(patched)
    win.ws.commit("dflash", tmp_path / "edited.bin")  # an edit must not leak into the export

    target = tmp_path / "my backups"
    target.mkdir()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(target))
    win.act_export.trigger()
    win.act_export.trigger()  # a second export never overwrites the first
    out = sorted(target.iterdir())
    assert len(out) == 2 and out[0].name.startswith("3Q0907530AR_") and out[1].name.endswith("_2")
    assert sorted(f.name for f in out[0].iterdir()) == ["Cflash.bin", "Dflash.bin", "Uflash.bin", "manifest.json"]
    assert (out[0] / "Dflash.bin").read_bytes() == synth_dflash
    win.close()


def test_failed_codeflash_restore_keeps_the_engineering_bootloader_and_says_so(
    fake_ecu, synth_cflash, synth_dflash, synth_uflash, tmp_path, monkeypatch
) -> None:
    from contitool.progress import OperationReporter

    set_lang("en")
    ecu, calls = fake_ecu
    ecu.update(cflash=synth_cflash, dflash=synth_dflash)

    def broken(*_a, **_k):
        calls.append("cflash")
        raise RuntimeError("CodeFlash readback mismatch")

    monkeypatch.setattr(workflows, "can_write_cflash", broken)
    logs: list[str] = []
    files = _backup(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    with pytest.raises(RuntimeError, match="readback mismatch"):
        can_restore_backup("fake", files, ["cflash"], session_dir=tmp_path / "run",
                           reporter=OperationReporter(on_log=lambda e: logs.append(e.message)))
    assert calls == ["uflash_eng", "cflash"]  # no stock bootloader over a half-written application
    assert any("engineering bootloader stays" in m for m in logs)
