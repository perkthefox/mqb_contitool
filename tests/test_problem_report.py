"""Problem report archive and issue text, the offer after a failed operation, and the startup disclaimer."""

from __future__ import annotations

import os
import time
import urllib.parse
import zipfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QSettings, QTimer  # noqa: E402

from contitool import __version__  # noqa: E402
from contitool import report  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402

VIN, FAZIT = "WVWZZZAUZNW000001", "TST-SYN01.01.2400000001"  # test values the hygiene check allows


def _session(out_dir: Path) -> None:
    run = out_dir / "backup_20261108_182015"
    run.mkdir(parents=True)
    (run / "can.jsonl").write_text("".join(f'{{"n": {i}}}\n' for i in range(20_000)))
    (run / "manifest.json").write_text('{"complete": false}')
    (run / "Cflash.bin").write_bytes(b"\xff" * 4096)  # a memory dump never leaves the machine in a report


def test_report_zip_holds_logs_but_no_dumps_and_masks_ids(tmp_path: Path) -> None:
    set_lang("en")
    out_dir, drv = tmp_path / "runs", tmp_path / "ProgramData/Volkswagen/VW_D_PDU_API_OE/logs"
    started = time.time() - 1
    _session(out_dir)
    drv.mkdir(parents=True)
    (drv / "PDUAPI_VW_#7.log").write_text("connect\n")
    old = drv / "PDUAPI_VW_#1.log"
    old.write_text("last week\n")
    os.utime(old, (started - 86400, started - 86400))

    failure = report.Failure("Reading the ECU memory", "No CAN frame from 0x6F1 within 1.5s", "Traceback …", started)
    env = report.environment("dpdu", "VW_D_PDU_API_OE", "VAS 6154 / VNCI")
    log = f"F190 VIN: {VIN}\nF17C FAZIT: {FAZIT}\nERR No CAN frame from 0x6F1 within 1.5s\n"
    dest = report.build_report_zip(tmp_path / "r.zip", failure, env, log, out_dir, driver_dirs=[drv])

    with zipfile.ZipFile(dest) as z:
        names = set(z.namelist())
        assert {"README.txt", "issue.md", "contitool_log.txt", "traceback.txt",
                "sessions/backup_20261108_182015/manifest.json", "sessions/backup_20261108_182015/can.jsonl",
                "driver_logs/VW_D_PDU_API_OE/PDUAPI_VW_#7.log"} <= names
        assert not any(n.endswith(".bin") for n in names)
        assert "driver_logs/VW_D_PDU_API_OE/PDUAPI_VW_#1.log" not in names  # older than the operation
        can_log = z.read("sessions/backup_20261108_182015/can.jsonl").decode().splitlines()
        assert len(can_log) == report.CAN_LOG_HEAD + report.CAN_LOG_TAIL + 1 and can_log[-1] == '{"n": 19999}'
        text = z.read("contitool_log.txt").decode()
        assert VIN not in text and FAZIT not in text and "WVWZZZAUZNW******" in text

    url = report.issue_url(failure, env, log)
    assert url.startswith(report.ISSUES_URL) and len(url) < 3 * report.URL_BODY_LIMIT
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert query["title"][0].startswith(f"[{__version__}] Reading the ECU memory: No CAN frame")
    assert "VAS 6154 / VNCI" in query["body"][0] and VIN not in query["body"][0]


def test_failed_operation_offers_a_report(tmp_path: Path) -> None:
    from contitool.gui.app import create_window

    set_lang("en")
    app, win = create_window()
    win.conn.out_dir = tmp_path
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_a: loop.quit())
    QTimer.singleShot(5000, loop.quit)
    win.runner.run_task("Reading the ECU memory", lambda _rep: (_ for _ in ()).throw(TimeoutError("No CAN frame from 0x6F1")))
    loop.exec()
    app.processEvents()

    dlg = win._report_dlg
    assert dlg is not None and dlg.isVisible() and not dlg.isModal()
    assert dlg.failure.title == "Reading the ECU memory" and "TimeoutError" in dlg.failure.traceback
    path = dlg.create(tmp_path / "report.zip", open_browser=False)  # saved into the scanned folder itself
    with zipfile.ZipFile(path) as z:
        assert "No CAN frame from 0x6F1" in z.read("contitool_log.txt").decode()
        assert not any(n.endswith(".zip") for n in z.namelist())

    dlg.close()
    app.processEvents()
    win.runner.was_cancelled = True  # a cancelled operation is not a problem to report
    win._on_operation_finished(False, "", None)
    assert win._report_dlg is None
    win.close()


def test_disclaimer_needs_consent_and_can_stay_quiet_until_the_next_version() -> None:
    from contitool.gui.dialogs import disclaimer

    set_lang("en")
    from contitool.gui.app import create_window

    create_window()
    s = QSettings()
    saved = s.value(disclaimer._SETTING)
    try:
        s.remove(disclaimer._SETTING)
        dlg = disclaimer.DisclaimerDialog()
        assert not dlg.btn_ok.isEnabled()
        dlg.accept()  # not ticked: stays open
        assert dlg.result() == 0
        dlg.chk_agree.setChecked(True)
        assert dlg.btn_ok.isEnabled()
        dlg.chk_quiet.setChecked(True)
        dlg.accept()
        assert dlg.result() == 1 and QSettings().value(disclaimer._SETTING) == __version__
        assert disclaimer.confirm_disclaimer()  # no dialog for the same version
    finally:
        if saved is None:
            s.remove(disclaimer._SETTING)
        else:
            s.setValue(disclaimer._SETTING, saved)


def test_the_newest_driver_log_is_always_collected(tmp_path: Path, monkeypatch) -> None:
    """The error is in the log the driver wrote last; an older megabyte-sized CAN trace must not crowd it out."""
    monkeypatch.setattr(report, "DRIVER_LOG_BUDGET", 100)
    drv = tmp_path / "logs"
    drv.mkdir()
    started = time.time() - 5
    for i, size in enumerate((200, 10, 20)):  # a huge trace of the successful read, then two small ones
        p = drv / f"PDUAPI_VW_#{i}.log"
        p.write_bytes(b"x" * size)
        os.utime(p, (started + i, started + i))

    assert [p.name for p in report.driver_logs(started, [drv])] == ["PDUAPI_VW_#1.log", "PDUAPI_VW_#2.log"]


def test_an_oversized_driver_log_goes_in_as_its_tail(tmp_path: Path, monkeypatch) -> None:
    """One log now covers a whole run and holds every CAN frame of it: zip its end, where the error is."""
    monkeypatch.setattr(report, "DRIVER_LOG_TAIL", 64)
    drv = tmp_path / "ProgramData/Volkswagen/VW_D_PDU_API_OE/logs"
    drv.mkdir(parents=True)
    (drv / "PDUAPI_VW_#9.log").write_bytes(b"old frames" * 100 + b"\nPDUModuleConnect FAILED\n")
    failure = report.Failure("Reading the ECU memory", "boom", "Traceback …", time.time() - 1)
    dest = report.build_report_zip(tmp_path / "r.zip", failure, report.environment("dpdu", "x", "y"),
                                   "log\n", tmp_path / "runs", driver_dirs=[drv])

    with zipfile.ZipFile(dest) as z:
        kept = z.read("driver_logs/VW_D_PDU_API_OE/PDUAPI_VW_#9.log")
    assert len(kept) == 64 and kept.endswith(b"PDUModuleConnect FAILED\n")
