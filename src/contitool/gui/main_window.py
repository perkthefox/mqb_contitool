"""Main window: menu, mode tabs, the start/ECU screen or the CAN terminal, the log, and the status bar."""

from __future__ import annotations

from pathlib import Path
import time
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from contitool import __version__
from contitool.can import can_backup, can_identify, can_restore_backup, default_session_dir, unsupported_ecu_reason
from contitool.cli.formatting import (
    Style,
    format_cflash_report,
    format_dflash_report,
    format_uflash_report,
)
from contitool.core import (
    AUTHOR_CREDIT,
    AUTHOR_DRIVE2_URL,
    AUTHOR_SITE_SHORT,
    AUTHOR_SITE_URL,
    AUTHOR_TG_URL,
    analyze_cflash,
    analyze_dflash,
    analyze_dflash_datasets,
    analyze_dflash_swap,
    analyze_uflash,
)
from contitool.gui.connection import CanConnection, ConnectionDialog, ensure_ready
from contitool.gui.dialogs.guide import GuideDialog
from contitool.gui.dialogs.problem_report import ProblemReportDialog
from contitool.gui.dialogs.restore import RestoreDialog
from contitool.gui.screens.ecu import EcuScreen
from contitool.gui.screens.start import StartScreen
from contitool.gui.screens.terminal import TerminalScreen
from contitool.gui import theme
from contitool.gui.theme import build_app_icon, dot_icon, mono_font
from contitool.gui.widgets.execution_panel import ExecutionPanel
from contitool.gui.widgets.page import Callout, Dialog, TextResultDialog, button, hint, run_dialog
from contitool.gui.worker import OperationRunner
from contitool.gui.workspace import NAMES, Workspace
from contitool.i18n import get_lang, set_lang, subscribe_lang_change, tr
from contitool.report import Failure


class MainWindow(QMainWindow):
    """Owns the gateway being worked on, the adapter settings, and the single operation runner."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowIcon(build_app_icon())
        self.resize(1180, 840)
        self.setMinimumSize(940, 640)

        self.runner = OperationRunner(self)
        self.ws = Workspace(self)
        self.conn = CanConnection(self)

        root = QWidget()
        self.setCentralWidget(root)
        lay = QVBoxLayout(root)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self._build_header())

        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setHandleWidth(1)

        self.stack = QStackedWidget()
        self.start_screen = StartScreen()
        self.ecu_screen = EcuScreen(self.ws, self.conn, self.runner)
        self.stack.addWidget(self.start_screen)
        self.stack.addWidget(self.ecu_screen)

        self.start_screen.read_can_requested.connect(self.read_over_can)
        self.start_screen.restore_requested.connect(self.restore_backup)
        self.start_screen.open_folder_requested.connect(self.open_folder)
        self.start_screen.open_files_requested.connect(self.open_files)
        self.start_screen.files_dropped.connect(self._load_paths)
        self.start_screen.wiring_requested.connect(self.show_connection)
        self.ecu_screen.report_requested.connect(self.show_report)
        self.ecu_screen.close_requested.connect(self.close_ecu)
        self.ecu_screen.restore_requested.connect(self.restore_backup)
        self.ecu_screen.terminal_requested.connect(self._open_in_terminal)

        self.console = ExecutionPanel(self.runner)
        self.console.setMinimumHeight(110)
        self.ecu_screen.note.connect(self.console.note)
        self.splitter.addWidget(self.stack)
        self.splitter.addWidget(self.console)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setSizes([640, 170])

        self.terminal = TerminalScreen(self.conn, self.runner)
        self.conn.in_use = self._adapter_in_use
        self.modes = QStackedWidget()
        self.modes.addWidget(self.splitter)
        self.modes.addWidget(self.terminal)
        lay.addWidget(self.modes, 1)

        self._build_menu()
        self.statusBar().setSizeGripEnabled(False)
        self.statusBar().addWidget(self.console.status_widget, 1)

        self.ws.changed.connect(self._refresh_header)
        self.ws.changed.connect(self._refresh_screen)
        self.conn.changed.connect(self._refresh_header)
        self.runner.operation_started.connect(self._ensure_console_visible)
        self.runner.busy_changed.connect(self._on_busy)
        self.runner.operation_finished.connect(self._on_operation_finished)
        self.terminal.problem.connect(self.offer_problem_report)
        self._opened_at = time.time()
        self._report_dlg: ProblemReportDialog | None = None
        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.retranslate_ui()
        self._refresh_screen()

    # ────────────────────────────── header & menu ──────────────────────────────
    def _build_header(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("Header")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(16, 0, 16, 0)
        lay.setSpacing(8)

        logo = QLabel()
        logo.setPixmap(build_app_icon().pixmap(QSize(18, 18)))
        lay.addWidget(logo)
        self.lbl_app = QLabel("ContiTool")
        self.lbl_app.setObjectName("AppName")
        lay.addWidget(self.lbl_app)
        lay.addSpacing(18)

        self.tab_ecu = QPushButton()
        self.tab_term = QPushButton()
        tabs = QButtonGroup(self)
        for b, mode in ((self.tab_ecu, "ecu"), (self.tab_term, "terminal")):
            b.setObjectName("TabBtn")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _c=False, m=mode: self.set_mode(m))
            tabs.addButton(b)
            lay.addWidget(b)
        self.tab_ecu.setChecked(True)
        lay.addStretch(1)

        self.btn_conn = button("", "Chip", slot=self.show_connection)
        self.btn_conn.setCursor(Qt.CursorShape.PointingHandCursor)
        lay.addWidget(self.btn_conn)
        lay.addSpacing(4)

        self._lang_buttons: dict[str, QPushButton] = {}
        lang_group = QButtonGroup(self)
        lang = QHBoxLayout()
        lang.setSpacing(0)
        for code, pos in (("ru", "left"), ("en", "right")):
            b = QPushButton(code.upper())
            b.setObjectName("SegBtn")
            b.setProperty("pos", pos)
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _c=False, c=code: set_lang(c))
            lang_group.addButton(b)
            lang.addWidget(b)
            self._lang_buttons[code] = b
        lay.addLayout(lang)
        return bar

    def _build_menu(self) -> None:
        def act(slot, shortcut: QKeySequence | QKeySequence.StandardKey | str | None = None) -> QAction:  # noqa: ANN001
            a = QAction(self)
            a.triggered.connect(lambda _c=False: slot())
            if shortcut is not None:
                a.setShortcut(QKeySequence(shortcut))
            return a

        mb = self.menuBar()
        self.menu_file = mb.addMenu("")
        self.act_read = act(self.read_over_can, "Ctrl+R")
        self.act_folder = act(self.open_folder, QKeySequence.StandardKey.Open)
        self.act_files = act(self.open_files, "Ctrl+Shift+O")
        self.act_export = act(lambda: self.ecu_screen.export_backup())
        self.act_restore = act(self.restore_backup)
        self.act_report = act(self.show_report, "Ctrl+I")
        self.act_close = act(self.close_ecu, QKeySequence.StandardKey.Close)
        self.act_conn = act(self.show_connection)
        self.act_quit = act(self.close, QKeySequence.StandardKey.Quit)
        self.act_quit.setMenuRole(QAction.MenuRole.QuitRole)
        for a in (self.act_read, self.act_folder, self.act_files, None, self.act_export, self.act_restore, None, self.act_report, self.act_close, None, self.act_conn, None, self.act_quit):
            self.menu_file.addSeparator() if a is None else self.menu_file.addAction(a)

        self.menu_view = mb.addMenu("")
        self.act_mode_ecu = act(lambda: self.set_mode("ecu"), "Ctrl+1")
        self.act_mode_term = act(lambda: self.set_mode("terminal"), "Ctrl+2")
        self.menu_view.addAction(self.act_mode_ecu)
        self.menu_view.addAction(self.act_mode_term)

        self.menu_help = mb.addMenu("")
        self.act_guide = act(self.show_guide, QKeySequence.StandardKey.HelpContents)
        self.act_problem = act(self.report_problem)
        self.act_about = act(self.show_about)
        self.act_about.setMenuRole(QAction.MenuRole.AboutRole)
        self.menu_help.addAction(self.act_guide)
        self.menu_help.addAction(self.act_problem)
        self.menu_help.addAction(self.act_about)

    def _refresh_header(self) -> None:
        open_ = self.ws.is_open
        self.tab_ecu.setText(tr("Блок", "ECU") + (f"  ·  {self.ws.part_number}" if open_ and self.ws.part_number else ""))
        self.tab_term.setText(tr("CAN-терминал", "CAN terminal"))
        self.act_report.setEnabled(open_)
        self.act_export.setEnabled(open_)
        self.act_close.setEnabled(open_)
        if self.conn.port or self.conn.title:
            self.btn_conn.setText(self.conn.display())
            self.btn_conn.setIcon(dot_icon(theme.OK if self.conn.ready else theme.WARN))
            self.btn_conn.setToolTip(
                tr("Адаптер готов", "Adapter ready")
                if self.conn.ready
                else tr("Подтвердите схему подключения", "Confirm the bench wiring")
            )
        else:
            self.btn_conn.setText(tr("Адаптер не настроен", "No adapter set up"))
            self.btn_conn.setIcon(dot_icon(theme.TEXT_MUTED))
            self.btn_conn.setToolTip(tr("Настроить подключение к блоку", "Set up the ECU connection"))

    def set_mode(self, mode: str) -> None:
        """Switch between the ECU workspace and the CAN terminal. Leaving the terminal frees the adapter."""
        term = mode == "terminal" and not self.runner.is_busy
        if not term:
            self.terminal.disconnect_bus()
        self.modes.setCurrentWidget(self.terminal if term else self.splitter)
        (self.tab_term if term else self.tab_ecu).setChecked(True)

    def _open_in_terminal(self, request: str) -> None:
        self.set_mode("terminal")
        if self.modes.currentWidget() is self.terminal:
            self.terminal.prefill_uds(request)

    def _on_busy(self, busy: bool) -> None:
        self.tab_term.setEnabled(not busy)
        self.act_mode_term.setEnabled(not busy)
        self.tab_term.setToolTip(tr("Недоступно, пока идёт операция", "Unavailable while an operation runs") if busy else "")

    def _refresh_screen(self) -> None:
        self.stack.setCurrentWidget(self.ecu_screen if self.ws.is_open else self.start_screen)
        if not self.ws.is_open:
            self.start_screen.refresh_recent()

    def _ensure_console_visible(self, _title: str) -> None:
        sizes = self.splitter.sizes()
        if len(sizes) == 2 and sizes[1] < 160:
            total = sum(sizes)
            self.splitter.setSizes([max(340, total - 190), 190])

    # ────────────────────────────── loading ──────────────────────────────
    def open_folder(self, folder: str = "") -> None:
        self.set_mode("ecu")
        chosen = folder or QFileDialog.getExistingDirectory(
            self, tr("Папка с дампами блока", "Folder with the ECU dumps"), str(Path.cwd())
        )
        if chosen:
            self._report_missing(self.ws.open_folder(Path(chosen)), Path(chosen))

    def open_files(self) -> None:
        self.set_mode("ecu")
        chosen, _ = QFileDialog.getOpenFileNames(
            self,
            tr("Файлы дампов", "Dump files"),
            str(Path.cwd()),
            "Binary (*.bin *.raw);;All Files (*)",
        )
        if chosen:
            self._load_paths([Path(c) for c in chosen])

    def _load_paths(self, paths: list[Path]) -> None:
        if len(paths) == 1 and paths[0].is_dir():
            self.open_folder(str(paths[0]))
            return
        rejected = self.ws.open_files([p for p in paths if p.is_file()])
        if not self.ws.is_open:
            QMessageBox.warning(
                self,
                tr("Это не дампы шлюза", "Not gateway dumps"),
                tr(
                    "Ни один файл не опознан как CodeFlash, DataFlash или Uflash этого шлюза.",
                    "None of the files is a CodeFlash, DataFlash or Uflash of this gateway.",
                ),
            )
        elif rejected:
            QMessageBox.information(
                self,
                tr("Часть файлов пропущена", "Some files were skipped"),
                tr(f"Не опознаны: {', '.join(rejected)}", f"Not recognised: {', '.join(rejected)}"),
            )

    def _report_missing(self, missing: list[str], folder: Path) -> None:
        if not self.ws.is_open:
            QMessageBox.warning(
                self,
                tr("Дампы не найдены", "No dumps found"),
                tr(
                    f"В папке {folder.name} нет файлов CodeFlash, DataFlash или Uflash.",
                    f"The folder {folder.name} has no CodeFlash, DataFlash or Uflash files.",
                ),
            )
        elif missing:
            names = ", ".join(NAMES[k] for k in missing)
            self.console.note(
                tr(
                    f"Не найдено в папке: {names}. Часть функций будет недоступна.",
                    f"Not found in the folder: {names}. Some features will be unavailable.",
                )
            )

    def read_over_can(self) -> None:
        """Check the link and show who answers first; the backup starts only after the user confirms."""
        self.set_mode("ecu")  # frees the adapter if the terminal holds it
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        self.runner.run_task(
            tr("Проверка связи с блоком", "Checking the ECU link"),
            lambda rep: can_identify(port, interface=iface, reporter=rep),
            # the runner is still busy inside on_success: ask once it has finished
            on_success=lambda res: QTimer.singleShot(0, lambda: self._confirm_read(res)),
        )

    def _confirm_read(self, ident: dict[str, Any]) -> None:
        dlg = EcuFoundDialog(ident, self.conn, self)
        if run_dialog(dlg) and not dlg.unsupported:
            if dlg.restore_chosen:
                self.restore_backup()
            else:
                self._backup_over_can()

    def _backup_over_can(self) -> None:
        port, iface = self.conn.port, self.conn.interface
        sdir = default_session_dir(self.conn.out_dir, "backup")

        def done(res: dict[str, Any]) -> None:
            folder = Path(str(res.get("session_dir", sdir)))
            self._report_missing(self.ws.open_folder(folder, source="can"), folder)

        self.runner.run_task(
            tr("Чтение памяти блока", "Reading the ECU memory"),
            lambda rep: can_backup(port, interface=iface, session_dir=sdir, reporter=rep),
            on_success=done,
        )

    def _adapter_in_use(self) -> str:
        if self.runner.is_busy:
            return tr("Идёт операция с блоком — дождитесь её окончания.", "An ECU operation is running — wait until it finishes.")
        if self.terminal.holds_adapter():
            return tr(
                "Адаптер занят CAN-терминалом или ещё освобождается — отключите терминал и повторите через несколько секунд.",
                "The CAN terminal holds the adapter or is still releasing it — disconnect it and retry in a few seconds.",
            )
        return ""

    def restore_backup(self) -> None:
        """Write backup files the user picks back into the ECU; the workflow refuses a backup of another ECU."""
        self.set_mode("ecu")  # frees the adapter if the terminal holds it
        dlg = RestoreDialog(self, str(self.ws.folder or self.conn.out_dir))
        if not run_dialog(dlg) or not dlg.kinds or not ensure_ready(self.conn, self):
            return
        files, kinds = dict(dlg.files), dlg.kinds
        port, iface = self.conn.port, self.conn.interface
        sdir = default_session_dir(self.conn.out_dir, "restore")
        names = ", ".join(NAMES[k] for k in kinds)
        self.runner.run_task(
            tr(f"Заливка бэкапа в блок: {names}", f"Writing the backup to the ECU: {names}"),
            lambda rep: can_restore_backup(port, files, kinds, interface=iface, session_dir=sdir, reporter=rep),
        )

    def close_ecu(self) -> None:
        if not self.ws.is_open:
            return
        pending = [k for k in ("cflash", "dflash", "uflash") if self.ws.pending(k)]
        if pending and QMessageBox.question(
            self,
            tr("Закрыть блок", "Close the ECU"),
            tr(
                "Есть изменения, не записанные в блок. Изменённые файлы останутся на диске.\n\nЗакрыть?",
                "There are changes that were not written to the ECU. The edited files stay on disk.\n\nClose?",
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self.ws.close()

    # ────────────────────────────── dialogs ──────────────────────────────
    def show_connection(self) -> None:
        run_dialog(ConnectionDialog(self.conn, self))

    def show_guide(self) -> None:
        run_dialog(GuideDialog(self))

    def _on_operation_finished(self, ok: bool, _summary: str, _target: object) -> None:
        if not ok and not self.runner.was_cancelled and self.runner.last_failure is not None:
            self.offer_problem_report(self.runner.last_failure)

    def report_problem(self) -> None:
        """Help menu: about the last failed operation, or everything since the last operation started."""
        since = self.runner.started_at or self._opened_at
        self.offer_problem_report(self.runner.last_failure or Failure(tr("Сообщение о проблеме", "Problem report"), "", started=since))

    def offer_problem_report(self, failure: Failure) -> None:
        """Non-blocking: the log and the screen stay usable while the offer is open; a newer failure replaces it."""
        if self._report_dlg is not None:
            self._report_dlg.close()
        dlg = ProblemReportDialog(self, failure, self.conn, self.console.txt_full.toPlainText())
        dlg.setModal(False)
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dlg.destroyed.connect(lambda *_a, d=dlg: setattr(self, "_report_dlg", None) if self._report_dlg is d else None)
        self._report_dlg = dlg
        dlg.show()

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            tr("О программе", "About"),
            tr(
                f"<b>ContiTool {__version__}</b><br>Сервисный инструмент для шлюза VAG MQB J533.<br><br>"
                f"{AUTHOR_CREDIT}<br>"
                f'<a href="{AUTHOR_SITE_URL}">{AUTHOR_SITE_SHORT}</a> · '
                f'<a href="{AUTHOR_DRIVE2_URL}">Drive2</a> · <a href="{AUTHOR_TG_URL}">Telegram</a><br><br>'
                "Бесплатный инструмент сообщества, не для продажи. Программа предоставляется «как есть», "
                "без каких-либо гарантий.",
                f"<b>ContiTool {__version__}</b><br>Service tool for the VAG MQB J533 gateway.<br><br>"
                f"{AUTHOR_CREDIT}<br>"
                f'<a href="{AUTHOR_SITE_URL}">{AUTHOR_SITE_SHORT}</a> · '
                f'<a href="{AUTHOR_DRIVE2_URL}">Drive2</a> · <a href="{AUTHOR_TG_URL}">Telegram</a><br><br>'
                "Free community tool, not for sale. Provided “as is”, without warranty of any kind.",
            ),
        )

    def show_report(self) -> None:
        """Full offline analysis of every loaded dump, as plain text."""
        if not self.ws.is_open:
            return
        plain = Style(False)
        sections: list[str] = []
        for kind, build in (
            ("cflash", lambda raw, p: format_cflash_report(analyze_cflash(raw), plain, p)),
            ("uflash", lambda raw, p: format_uflash_report(analyze_uflash(raw), plain, p)),
            (
                "dflash",
                lambda raw, p: format_dflash_report(
                    analyze_dflash(raw),
                    analyze_dflash_swap(raw),
                    plain,
                    p,
                    dataset_summary=analyze_dflash_datasets(raw),
                ),
            ),
        ):
            path = self.ws.path(kind)
            if path is not None:
                sections.append(build(path.read_bytes(), str(path)))
        run_dialog(
            TextResultDialog(
                self,
                tr("Подробный отчёт", "Full report"),
                "\n\n".join(sections),
                self.ws.part_number,
            )
        )

    # ────────────────────────────── misc ──────────────────────────────
    def retranslate_ui(self) -> None:
        self.setWindowTitle(f"ContiTool {__version__}")
        self._lang_buttons[get_lang()].setChecked(True)
        self.menu_file.setTitle(tr("Файл", "File"))
        self.act_read.setText(tr("Считать блок по CAN", "Read the ECU over CAN"))
        self.act_folder.setText(tr("Открыть папку с дампами…", "Open dump folder…"))
        self.act_files.setText(tr("Открыть файлы…", "Open files…"))
        self.act_export.setText(tr("Экспортировать бэкап…", "Export backup…"))
        self.act_restore.setText(tr("Залить бэкап в блок…", "Write backup to ECU…"))
        self.act_report.setText(tr("Подробный отчёт", "Full report"))
        self.act_close.setText(tr("Закрыть блок", "Close ECU"))
        self.act_conn.setText(tr("Подключение к блоку…", "ECU connection…"))
        self.act_quit.setText(tr("Выход", "Quit"))
        self.menu_view.setTitle(tr("Вид", "View"))
        self.act_mode_ecu.setText(tr("Блок", "ECU"))
        self.act_mode_term.setText(tr("CAN-терминал", "CAN terminal"))
        self.menu_help.setTitle(tr("Справка", "Help"))
        self.act_guide.setText(tr("Памятка по стенду", "Bench guide"))
        self.act_problem.setText(tr("Сообщить о проблеме…", "Report a problem…"))
        self.act_about.setText(tr("О программе", "About ContiTool"))
        self._refresh_header()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.runner.is_busy:
            ans = QMessageBox.warning(
                self,
                tr("Операция выполняется", "Operation in progress"),
                tr(
                    "Прерывание записи во Flash может повредить прошивку блока.\n\nВсё равно закрыть программу?",
                    "Interrupting a flash write can corrupt the ECU firmware.\n\nQuit anyway?",
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if ans != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.runner.cancel_current()
        self._unsub()
        self.terminal.disconnect_bus()
        for session in list(self.terminal._closing):  # a QThread destroyed while running aborts the process
            session.wait()
        event.accept()


class EcuFoundDialog(Dialog):
    """The ECU that answered on CAN, before its memory is read."""

    def __init__(self, ident: dict[str, Any], conn: CanConnection, parent: QWidget | None = None) -> None:
        unsupported = str(ident.get("unsupported") or unsupported_ecu_reason(ident.get("ident", [])) or "")
        in_fbl = bool(ident.get("in_fbl")) and not unsupported
        self.unsupported = unsupported
        self.restore_chosen = False
        if unsupported:
            title = tr("Блок не поддерживается", "Unsupported ECU")
            subtitle = tr(
                f"На {conn.display()} ответил шлюз неподдерживаемой аппаратной платформы.",
                f"An unsupported gateway hardware platform answered on {conn.display()}.",
            )
        elif in_fbl:
            title = tr("Блок в режиме загрузчика (FBL)", "ECU in bootloader mode (FBL)")
            subtitle = tr(
                f"Ответил блок на {conn.display()}. Проверьте, что это нужный блок.",
                f"An ECU answered on {conn.display()}. Check that it is the one you want.",
            )
        else:
            title = tr("Блок на связи", "ECU found")
            subtitle = tr(
                f"Ответил блок на {conn.display()}. Проверьте, что это нужный блок.",
                f"An ECU answered on {conn.display()}. Check that it is the one you want.",
            )
        super().__init__(parent, title, subtitle, width=620)
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(5)
        for r, item in enumerate(ident.get("ident", [])):
            name = QLabel(tr(item["label_ru"], item["label_en"]))
            name.setObjectName("Hint")
            value = QLabel(item["value"])
            value.setFont(mono_font(13))
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setWordWrap(True)
            grid.addWidget(name, r, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(value, r, 1)
        grid.setColumnStretch(1, 1)
        if ident.get("ident"):
            self.body.addLayout(grid)
        if unsupported:
            err = Callout("err")
            err.label.setText(unsupported)
            self.body.addWidget(err)
            self.btn_ok = None
            self.finish(cancel_text=tr("Закрыть", "Close"))
        elif in_fbl:
            warn = Callout("warn")
            warn.label.setText(
                tr(
                    "Основная прошивка блока сейчас не запущена (например, после прерванной записи). "
                    "Чтобы восстановить блок из ранее сохранённого бэкапа, нажмите <b>«Залить бэкап в блок…»</b>.",
                    "The main ECU firmware is not running right now (for example, after an interrupted write). "
                    "To recover the ECU from a previously saved backup, click <b>“Write backup to ECU…”</b>.",
                )
            )
            self.body.addWidget(warn)
            self.body.addWidget(
                hint(
                    tr(
                        "Если нажать «Считать как есть», программа снимет текущее (частично стёртое) содержимое памяти.",
                        "If you click “Read anyway”, ContiTool will read the current (partially erased) memory contents.",
                    )
                )
            )
            self.btn_read_anyway = button(tr("Считать как есть", "Read anyway"), "GhostBtn", slot=self.accept)
            self.btn_ok = button(
                tr("Залить бэкап в блок…", "Write backup to ECU…"),
                "PrimaryBtn",
                slot=self._choose_restore,
            )
            self.finish(self.btn_read_anyway, ok=self.btn_ok)
        else:
            self.body.addWidget(
                hint(
                    tr(
                        "Будет снята полная копия памяти: CodeFlash, Uflash и DataFlash, около полутора минут. "
                        "Блок перейдёт в режим загрузчика и потом вернётся в обычный режим; в память ничего не пишется.",
                        "A full memory copy will be taken: CodeFlash, Uflash and DataFlash, about a minute and a half. "
                        "The ECU switches to its loader and back to normal afterwards; nothing is written to its memory.",
                    )
                )
            )
            self.btn_ok = button(tr("Считать блок", "Read the ECU"), "PrimaryBtn", slot=self.accept)
            self.finish(ok=self.btn_ok)

    def _choose_restore(self) -> None:
        self.restore_chosen = True
        self.accept()
