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
    assert url.startswith(report.ISSUES_URL) and len(url) <= report.URL_LIMIT
    # a Russian log takes six URL characters per letter: still within the limit, the newest lines kept
    ru_log = "\n".join(f"12:{i:02d}:00 CAN   Чтение памяти: прочитано {i} блоков из 384 — сверка" for i in range(60))
    ru = report.issue_url(report.Failure("Чтение памяти блока", "Блок не ответил на этапе 1. " * 40), env, ru_log)
    ru_query = urllib.parse.parse_qs(urllib.parse.urlsplit(ru).query)
    assert len(ru) <= report.URL_LIMIT and ru_query["log"][0].endswith("прочитано 59 блоков из 384 — сверка")
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert query["title"][0].startswith(f"[{__version__}] Reading the ECU memory: No CAN frame")
    assert query["template"] == [report.ISSUE_FORM]
    assert "VAS 6154 / VNCI" in query["environment"][0]
    assert "No CAN frame from 0x6F1" in query["error"][0]
    assert not any(VIN in v[0] or FAZIT in v[0] for v in query.values())  # masked in every field, the log too


def test_the_report_link_fills_fields_the_issue_form_really_has() -> None:
    """GitHub prefills a form field from the query parameter named after its id; a renamed field in
    .github/ISSUE_TEMPLATE/problem.yml would silently drop that part of every report."""
    import re

    form = (Path(__file__).resolve().parents[1] / ".github/ISSUE_TEMPLATE" / report.ISSUE_FORM).read_text("utf-8")
    ids = set(re.findall(r"^\s+id: (\S+)$", form, re.M))
    failure = report.Failure("Writing to ECU: CodeFlash", "boom", "Traceback …", time.time())
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(report.issue_url(failure, {"OS": "x"}, "log\n")).query)
    assert set(query) - {"template", "title"} <= ids


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


def test_a_silent_stage_1_offers_the_fingerprint_cure_not_a_report() -> None:
    from contitool.can.workflows import Stage1SilentError
    from contitool.gui.app import create_window

    set_lang("en")
    app, win = create_window()
    offered: list[str] = []
    win.offer_fingerprint_cure = lambda: offered.append("cure")
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_a: loop.quit())
    QTimer.singleShot(5000, loop.quit)
    win.runner.run_task("Reading the ECU memory", lambda _rep: (_ for _ in ()).throw(Stage1SilentError("stage 1 silent")))
    loop.exec()
    app.processEvents()
    assert offered == ["cure"] and win._report_dlg is None
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


def test_driver_logs_come_from_the_driver_the_operation_ran_on(tmp_path: Path) -> None:
    """A 2.0.1c report for a run on VW_D_PDU_API_OS carried VCTool driver logs from an hour before, and the log
    of the failure was missing. Another driver's logs are never a stand-in for the one in use."""
    set_lang("en")
    root = tmp_path / "ProgramData/Volkswagen"
    used, other = root / "VW_D_PDU_API_OS/logs", root / "VW_D_PDU_API_VCTOOL_29_0_0_X64/logs"
    used.mkdir(parents=True)
    other.mkdir(parents=True)
    started = time.time()
    for d, name, age in ((used, "PDUAPI_VW_#3.log", 600), (other, "PDUAPI_VW_#4.log", 60)):
        p = d / name
        p.write_text("x\n")
        os.utime(p, (started - age, started - age))  # neither was written during the operation

    failure = report.Failure("Writing to ECU: CodeFlash", "boom", "Traceback …", started)
    env = report.environment("dpdu", "VW_D_PDU_API_OS", "VAS 6154 / VNCI")
    dest = report.build_report_zip(tmp_path / "r.zip", failure, env, "log\n", tmp_path / "runs",
                                   driver_dirs=[used, other])
    with zipfile.ZipFile(dest) as z:
        logs = [n for n in z.namelist() if n.startswith("driver_logs/")]
    assert logs == ["driver_logs/VW_D_PDU_API_OS/PDUAPI_VW_#3.log"]


def test_dumps_go_in_only_when_asked(tmp_path: Path) -> None:
    """Dumps carry VIN / FAZIT / VCRN: none by default; asked for, the loaded ones and the operation's own."""
    started = time.time()
    runs = tmp_path / "runs" / "PN_FZ" / "writes" / "2026-11-09_17-00-00_write" / "dflash" / "backup"
    runs.mkdir(parents=True)
    (runs / "Dflash_before.bin").write_bytes(b"\x01" * 64)
    (runs.parent / "dflash_write_result.json").write_text("{}")
    loaded = tmp_path / "Cflash.bin"
    loaded.write_bytes(b"\x02" * 64)
    failure = report.Failure("Writing to ECU: DataFlash", "boom", "tb", started)
    env = report.environment("slcan", "x", "y")

    plain = report.build_report_zip(tmp_path / "plain.zip", failure, env, "log\n", tmp_path / "runs", driver_dirs=[])
    with zipfile.ZipFile(plain) as z:
        assert not any(n.endswith(".bin") for n in z.namelist())
    full = report.build_report_zip(tmp_path / "full.zip", failure, env, "log\n", tmp_path / "runs", driver_dirs=[],
                                   dumps={"loaded/Cflash.bin": loaded})
    with zipfile.ZipFile(full) as z:
        names = set(z.namelist())
        assert "dumps/loaded/Cflash.bin" in names
        assert "sessions/PN_FZ/writes/2026-11-09_17-00-00_write/dflash/backup/Dflash_before.bin" in names
        assert "VIN" in z.read("README.txt").decode()


def test_session_archive_paths_and_json_contents_mask_fazit_vin_and_escaped_home(tmp_path: Path, monkeypatch) -> None:
    """Session folder names `<PN>_<FAZIT>` and JSON fields (`fazit`, `session_dir` with `\\\\` on Windows) must be masked."""
    fake_home = r"C:\Users\SecretTech"
    monkeypatch.setattr(report.os.path, "expanduser", lambda _p: fake_home)
    started = time.time() - 1
    gw_dir = tmp_path / "runs" / f"3Q0907530C_{FAZIT}" / "dumps" / "2026-11-13_12-00-00_read"
    gw_dir.mkdir(parents=True)
    win_escaped = fake_home.replace("\\", "\\\\") + f"\\\\runs\\\\3Q0907530C_{FAZIT}"
    (gw_dir / "manifest.json").write_text(f'{{"session_dir": "{win_escaped}", "fazit": "{FAZIT}", "vin": "{VIN}"}}')

    failure = report.Failure("Reading the ECU memory", "boom", "tb", started)
    dest = report.build_report_zip(tmp_path / "masked.zip", failure, {"OS": "Windows"}, "log\n", tmp_path / "runs", driver_dirs=[])
    with zipfile.ZipFile(dest) as z:
        names = z.namelist()
        assert not any(FAZIT in n or VIN in n for n in names)
        manifest_entry = next(n for n in names if n.endswith("/manifest.json"))
        assert "TST-SYN01.01.24********" in manifest_entry
        body = z.read(manifest_entry).decode("utf-8")
        assert FAZIT not in body and VIN not in body and "SecretTech" not in body
        assert "~" in body and "WVWZZZAUZNW******" in body
