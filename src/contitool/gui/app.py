"""QApplication bootstrap for ContiTool Desktop Studio."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from contitool import __version__
from contitool.can import dpdu
from contitool.gui.main_window import MainWindow
from contitool.gui.theme import apply_theme, build_app_icon


_APP: QApplication | None = None


def create_window() -> tuple[QApplication, MainWindow]:
    """Instantiate QApplication (if needed) and MainWindow (used both by app entry & GUI tests)."""
    global _APP
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    assert isinstance(app, QApplication)
    _APP = app
    app.setApplicationName("ContiTool")
    app.setApplicationVersion(__version__)
    app.setOrganizationName("PerkTheFox")
    app.setWindowIcon(build_app_icon())
    apply_theme(app)
    win = MainWindow()
    return app, win


def run_gui() -> int:
    """Launch the ContiTool Desktop GUI event loop."""
    from contitool.gui.dialogs.disclaimer import confirm_disclaimer
    from contitool.report import failure_from_exception

    app, win = create_window()
    win.show()
    if not confirm_disclaimer(win):
        return 0
    if getattr(sys, "frozen", False):  # a release build; one run from source is its own newest version
        win.updates.check(manual=False)
    reporting = False

    def excepthook(exc_type, exc, tb) -> None:  # noqa: ANN001 - any error Qt slots let through: offer a report
        nonlocal reporting
        sys.__excepthook__(exc_type, exc, tb)
        if reporting or not issubclass(exc_type, Exception):
            return
        reporting = True
        try:
            win.offer_problem_report(failure_from_exception(exc_type, exc, tb, win.runner.started_at or win._opened_at))
        finally:
            reporting = False

    sys.excepthook = excepthook
    # The VW driver wants its links stopped before the process goes away: a VCI left with a stale monitor link
    # drops the next session about 2 s after it connects.
    app.aboutToQuit.connect(dpdu.close_session)
    return app.exec()
