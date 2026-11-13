"""Adapter picker: found adapters listed and preselected, unusable drivers greyed, manual entry, link check."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402

from contitool.can import FoundAdapter  # noqa: E402
from contitool.gui import connection  # noqa: E402
from contitool.gui.app import create_window  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402

FOUND = [
    FoundAdapter("slcan", "/dev/cu.usbmodem1101", "CANable2", "SLCAN · /dev/cu.usbmodem1101"),
    FoundAdapter("j2534", "VAS6154A", "VAS6154A", "J2534 · VW", problem="32-bit driver — not usable"),
]


def _scanned(app, dlg) -> None:
    """Adapter search runs in the background; wait for it like the user would."""
    while dlg._scan is not None:
        dlg._scan.wait(3000)
        app.processEvents()


def test_found_adapter_is_preselected_checked_and_saved(monkeypatch) -> None:
    set_lang("en")
    app, win = create_window()
    monkeypatch.setattr(connection, "discover_adapters", lambda: FOUND)
    monkeypatch.setattr(connection, "can_identify", lambda port, **k: {"responding": True, "ident": [
        {"did": "F187", "value": "3Q0907530AA"}, {"did": "F189", "value": "5366"}]})
    win.conn.port = ""
    dlg = connection.ConnectionDialog(win.conn, win)
    _scanned(app, dlg)

    assert dlg.selection() == ("slcan", "/dev/cu.usbmodem1101", "CANable2")
    assert not dlg.list.item(1).flags()  # the 32-bit driver cannot be picked
    assert not dlg.btn_ok.isEnabled()  # 120 Ohm not confirmed yet

    loop = QEventLoop()
    dlg._check_link()
    dlg._check.finished.connect(loop.quit)
    QTimer.singleShot(3000, loop.quit)
    loop.exec()
    for _ in range(5):
        app.processEvents()
    assert dlg.lbl_check.text() == "✓ ECU answers: 3Q0907530AA, SW 5366"

    dlg.chk_120ohm.setChecked(True)
    assert dlg.btn_ok.isEnabled()
    dlg._save()
    assert (win.conn.interface, win.conn.port, win.conn.ready) == ("slcan", "/dev/cu.usbmodem1101", True)
    assert win.conn.display() == "CANable2 (cu.usbmodem1101)"
    win.close()


def test_saved_adapter_that_is_not_found_opens_manual_entry(monkeypatch) -> None:
    set_lang("en")
    app, win = create_window()
    monkeypatch.setattr(connection, "discover_adapters", lambda: [])
    win.conn.interface, win.conn.port = "pcan", "PCAN_USBBUS1"
    dlg = connection.ConnectionDialog(win.conn, win)
    _scanned(app, dlg)
    assert dlg.manual.isVisibleTo(dlg)
    assert dlg.selection() == ("pcan", "PCAN_USBBUS1", "")
    win.close()


def test_link_check_never_competes_with_a_running_operation(monkeypatch) -> None:
    """A second link to the adapter during a flash would steal its frames: the check and new CAN work are refused."""
    import threading

    from PySide6.QtWidgets import QMessageBox

    set_lang("en")
    app, win = create_window()
    monkeypatch.setattr(connection, "discover_adapters", lambda: FOUND)
    shown: list[str] = []
    monkeypatch.setattr(QMessageBox, "information", lambda _p, _t, text, *a, **k: shown.append(text))
    release = threading.Event()
    win.runner.run_task("flash", lambda rep: release.wait(5))
    try:
        dlg = connection.ConnectionDialog(win.conn, win)
        _scanned(app, dlg)
        assert not dlg.btn_check.isEnabled() and "operation is running" in dlg.btn_check.toolTip()
        dlg._check_link()
        assert dlg._check is None and "operation is running" in dlg.lbl_check.text()
        assert connection.ensure_ready(win.conn, win) is False and "operation is running" in shown[0]
    finally:
        release.set()
        win.runner._worker.wait()

    # closing the dialog while a link check runs neither blocks nor kills the thread; the adapter stays taken till it ends
    gate = threading.Event()
    monkeypatch.setattr(connection, "can_identify", lambda port, **k: gate.wait(5) and {"ident": []})
    dlg = connection.ConnectionDialog(win.conn, win)
    _scanned(app, dlg)
    dlg._check_link()
    worker = dlg._check
    dlg.reject()
    assert worker.isRunning() and "link check" in win.conn.busy_reason()
    gate.set()
    worker.wait(3000)
    app.processEvents()
    assert win.conn.busy_reason() == ""
    win.close()


def test_closed_dialogs_are_freed(monkeypatch) -> None:
    """Every opened connection dialog used to stay alive and keep retranslating its pinout card."""
    import time

    from PySide6.QtCore import QCoreApplication, QEvent

    from contitool import i18n

    set_lang("en")
    app, win = create_window()
    monkeypatch.setattr(connection, "discover_adapters", lambda: time.sleep(0.3) or [])  # still searching when closed
    monkeypatch.setattr(connection.ConnectionDialog, "exec", lambda self: self.done(0) or 0)  # a real exec ends in done()
    before = len(i18n._LISTENERS)
    for _ in range(3):
        win.show_connection()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()
    assert len(i18n._LISTENERS) == before
    for w in list(connection._ORPHANS):  # searches of closed dialogs end on their own
        w.wait(3000)
    win.close()


def test_builtin_terminator_hides_the_checkbox(monkeypatch) -> None:
    """VAS 6154 / VNCI (D-PDU) and J2534 adapters terminate CAN themselves: the reminder is not shown at all."""
    set_lang("en")
    app, win = create_window()
    monkeypatch.setattr(connection, "discover_adapters", lambda: [
        FoundAdapter("dpdu", "VW_PDUAPI", "VAS 6154 / VNCI", "D-PDU 27.2.0 · VW_PDUAPI", driver="27.2.0"),
        FoundAdapter("slcan", "/dev/cu.usbmodem1101", "CANable2", "SLCAN · /dev/cu.usbmodem1101"),
    ])
    win.conn.port, win.conn.wiring_confirmed = "", False
    dlg = connection.ConnectionDialog(win.conn, win)
    _scanned(app, dlg)
    assert dlg.selection()[0] == "dpdu"
    assert not dlg.chk_120ohm.isVisibleTo(dlg) and not dlg.lbl_term_help.isVisibleTo(dlg)  # nothing to confirm
    assert dlg.btn_ok.isEnabled()

    dlg.list.setCurrentRow(1)  # CANable: back to what the user confirmed themselves (nothing yet)
    assert dlg.chk_120ohm.isVisibleTo(dlg) and not dlg.chk_120ohm.isChecked() and not dlg.btn_ok.isEnabled()
    assert "120 Ω resistor between Pin 19 CAN-H" in dlg.chk_120ohm.text()
    assert "only a reminder" in dlg.lbl_term_help.text()

    dlg.list.setCurrentRow(0)
    dlg._save()
    assert win.conn.interface == "dpdu" and win.conn.ready
    win.close()


def test_unverified_dpdu_driver_needs_an_explicit_go_ahead(monkeypatch) -> None:
    """A D-PDU driver ContiTool was not checked with reflashes the VCI on connect: never use it silently."""
    from contitool.can import dpdu

    set_lang("en")
    app, win = create_window()
    monkeypatch.setattr(dpdu, "accepted_drivers", set())
    monkeypatch.setattr(connection, "discover_adapters", lambda: [
        FoundAdapter("dpdu", "VW_D_PDU_API_OE", "VAS 6154 / VNCI", "D-PDU 30.3.0 · VW_D_PDU_API_OE", driver="30.3.0")])
    dlg = connection.ConnectionDialog(win.conn, win)
    _scanned(app, dlg)
    assert dlg.chk_driver.isVisibleTo(dlg) and "30.3.0" in dlg.chk_driver.text()
    assert "unstable" in dlg.chk_driver.text() and "driver 27.2" in dlg.chk_driver.text()  # what to pick instead
    assert "Close ODIS and VCTool" in dlg.lbl_vnci.text() and "This is safe: ODIS writes its own" in dlg.lbl_vnci.text()
    assert not dlg.btn_ok.isEnabled() and not dlg.btn_check.isEnabled()
    dlg.chk_driver.setChecked(True)
    assert dlg.btn_ok.isEnabled()
    dlg._save()
    assert dpdu.accepted_drivers == {"30.3.0"}

    monkeypatch.setattr(connection, "discover_adapters", lambda: [
        FoundAdapter("dpdu", "ContiTool · VW_PDUAPI_27.2", "VAS 6154 / VNCI", "D-PDU 27.2.0 · ContiTool · VW_PDUAPI_27.2",
                     driver="27.2.0")])
    dlg = connection.ConnectionDialog(win.conn, win)
    _scanned(app, dlg)
    assert not dlg.chk_driver.isVisibleTo(dlg) and dlg.btn_ok.isEnabled()  # the driver that ships with ContiTool asks nothing
    dlg.done(0)
    win.close()


def test_dialog_keeps_its_size_and_never_scrolls_sideways(monkeypatch) -> None:
    """Long texts wrap and the folder path is shortened: opening the wiring diagram scrolls down, nothing widens."""
    set_lang("ru")
    app, win = create_window()
    monkeypatch.setattr(connection, "discover_adapters", lambda: FOUND)
    dlg = connection.ConnectionDialog(win.conn, win)
    _scanned(app, dlg)
    dlg.show()
    app.processEvents()
    size = dlg.size()
    dlg._toggle_pinout(True)
    app.processEvents()
    assert dlg.size() == size
    assert dlg._scroll.widget().minimumSizeHint().width() <= dlg._scroll.viewport().width()
    assert dlg._scroll.widget().width() <= dlg._scroll.viewport().width()
    dlg.close()
    win.close()


def test_a_link_check_through_a_wrapped_j2534_driver_shows_the_warning(monkeypatch) -> None:
    """Issue #17: the ECU answers through a J2534 driver behind the VW driver, but memory cannot be read that way."""
    set_lang("en")
    app, win = create_window()
    monkeypatch.setattr(connection, "discover_adapters", lambda: FOUND)
    dlg = connection.ConnectionDialog(win.conn, win)
    _scanned(app, dlg)
    dlg._check_ok({"responding": True, "ident": [{"did": "F187", "value": "3Q0907530AG"}],
                   "adapter_warning": "Adapter “OpenVCX32” (OpenVCX) is not a VAS 6154"})
    assert dlg.lbl_check.text() == "⚠ ECU answers: 3Q0907530AG\nAdapter “OpenVCX32” (OpenVCX) is not a VAS 6154"
    win.close()
