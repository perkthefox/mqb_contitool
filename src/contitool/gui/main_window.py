"""Main window: menu, mode tabs, the start/ECU screen or the CAN terminal, the log, and the status bar."""

from __future__ import annotations

from pathlib import Path
import json
import sys
import time
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent, QIcon, QKeySequence
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
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from contitool import __version__
from contitool.can import (
    BusScanResult,
    DiscoveredEcu,
    can_backup,
    can_bcm_read_all,
    can_cure_fbl_fingerprint,
    can_elv_read_dflash,
    can_elv_status,
    can_flash_frf,
    can_fpke_full_read,
    can_identify,
    can_kombi_full_read,
    can_mrr_read_keys,
    can_mrr_status,
    can_restore_backup,
    can_scan_bus,
    can_uds_read_dtc,
    close_active_fpke_link,
    unsupported_ecu_reason,
)
from contitool.cli.formatting import (
    Style,
    format_cflash_report,
    format_dflash_report,
    format_eeprom_report,
    format_opbt_report,
    format_uflash_report,
)
from contitool.core import (
    AUTHOR_CREDIT,
    AUTHOR_DONATE_BTC,
    AUTHOR_DONATE_TRIBUTE_URL,
    AUTHOR_DONATE_USDT_TON,
    AUTHOR_DONATE_USDT_TRC20,
    AUTHOR_DRIVE2_URL,
    AUTHOR_SITE_SHORT,
    AUTHOR_SITE_URL,
    AUTHOR_TG_URL,
    analyze_cflash,
    analyze_dflash,
    analyze_dflash_datasets,
    analyze_dflash_swap,
    analyze_eeprom,
    analyze_opbt,
    analyze_uflash,
)
from contitool.can.bridge import BRIDGE_NATIVE_INTERFACES
from contitool.core.elv import (
    ELV_DFLASH_COMPACT_SIZE,
    ELV_DFLASH_RAW64K_SIZE,
    elv_detect_folder_files,
    elv_is_dflash_bytes,
    is_elv_ident,
)
from contitool.core.fpke import detect_fpke_files, is_fpke_ident
from contitool.core.kombi import detect_kombi_files, is_kombi_ident
from contitool.core.mrr import MRR_DFLASH_SIZE, mrr_detect_profile, mrr_parse_dflash_fee
from contitool.gui.connection import CanConnection, ConnectionDialog, ensure_ready
from contitool.gui.dialogs.guide import GuideDialog
from contitool.gui.dialogs.problem_report import ProblemReportDialog
from contitool.gui.dialogs.restore import RestoreDialog
from contitool.gui.dialogs.settings import SettingsDialog
from contitool.gui.screens.bcm import BcmScreen
from contitool.gui.screens.bus import BusScreen
from contitool.gui.screens.ecu import EcuScreen
from contitool.gui.screens.elv import ElvScreen
from contitool.gui.screens.fpke import FpkeScreen
from contitool.gui.screens.kombi import KombiScreen
from contitool.gui.screens.mrr import MrrScreen
from contitool.gui.screens.start import StartScreen
from contitool.gui.screens.terminal import TerminalScreen
from contitool.gui import theme
from contitool.gui.theme import build_app_icon, dot_icon, mono_font
from contitool.gui.widgets.execution_panel import ExecutionPanel
from contitool.gui.widgets.page import Callout, Dialog, TextResultDialog, button, hint, run_dialog, vdivider
from contitool.gui.update_check import UpdateChecker
from contitool.gui.worker import OperationRunner
from contitool.gui.workspace import NAMES, Workspace, _remember_recent
from contitool.i18n import get_lang, set_lang, subscribe_lang_change, tr
from contitool.core.constants import FBL_MOD_OFFSET
from contitool.core.frf import FrfImage, frf_ident_problems, frf_signature_problem, read_flash_file
from contitool.report import Failure
from contitool.storage import keep_as_base, latest_area, new_session, unit_name, unit_of_cflash, unit_of_ident

CURE_TITLE = ("Исправление отпечатка программирования", "Fixing the programming fingerprint")


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
        self._active_screen: str = "start"  # "start" | "bus" | "j533" | "fpke" | "kombi" | "bcm" | "mrr" | "elv"
        self._last_cluster_screen: str = "fpke"  # "fpke" | "kombi" — last focused cluster for BCM/MRR/ELV material

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
        self.start_screen = StartScreen(self.conn)
        self.bus_screen = BusScreen(self.conn, self.runner)
        self.ecu_screen = EcuScreen(self.ws, self.conn, self.runner)
        self.fpke_screen = FpkeScreen(self.conn, self.runner)
        self.kombi_screen = KombiScreen(self.conn, self.runner)
        self.bcm_screen = BcmScreen(
            self.conn,
            self.runner,
            cluster_provider=self._provide_fpke_cluster_material,
        )
        self.mrr_screen = MrrScreen(
            self.conn,
            self.runner,
            cluster_provider=self._provide_fpke_cluster_material,
        )
        self.elv_screen = ElvScreen(
            self.conn,
            self.runner,
            cluster_provider=self._provide_fpke_cluster_material,
        )
        self.stack.addWidget(self.start_screen)
        self.stack.addWidget(self.bus_screen)
        self.stack.addWidget(self.ecu_screen)
        self.stack.addWidget(self.fpke_screen)
        self.stack.addWidget(self.kombi_screen)
        self.stack.addWidget(self.bcm_screen)
        self.stack.addWidget(self.mrr_screen)
        self.stack.addWidget(self.elv_screen)

        self.start_screen.scan_bus_requested.connect(self.scan_can_bus)
        self.start_screen.read_can_requested.connect(self.read_over_can)
        self.start_screen.restore_requested.connect(self.restore_backup)
        self.start_screen.open_folder_requested.connect(self.open_folder)
        self.start_screen.open_files_requested.connect(self.open_files)
        self.start_screen.files_dropped.connect(self._load_paths)
        self.start_screen.wiring_requested.connect(self.show_guide)
        self.start_screen.connection_requested.connect(self.show_connection)
        self.bus_screen.scan_requested.connect(self.scan_can_bus)
        self.bus_screen.read_ecu_requested.connect(self._on_bus_read_ecu)
        self.bus_screen.restore_ecu_requested.connect(self._on_bus_restore_ecu)
        self.bus_screen.open_j533_workspace_requested.connect(lambda: self.switch_ecu_view("j533"))
        self.bus_screen.open_fpke_workspace_requested.connect(self._on_bus_open_fpke_workspace)
        self.bus_screen.open_kombi_workspace_requested.connect(self._on_bus_open_kombi_workspace)
        self.bus_screen.open_bcm_workspace_requested.connect(self._on_bus_open_bcm_workspace)
        self.bus_screen.open_mrr_workspace_requested.connect(self._on_bus_open_mrr_workspace)
        self.bus_screen.open_elv_workspace_requested.connect(self._on_bus_open_elv_workspace)
        self.bus_screen.open_terminal_requested.connect(self._on_bus_open_terminal)
        self.bus_screen.back_requested.connect(lambda: self.switch_ecu_view("start"))
        self.ecu_screen.report_requested.connect(self.show_report)
        self.ecu_screen.close_requested.connect(self.close_ecu)
        self.ecu_screen.restore_requested.connect(lambda: self.restore_backup(force_j533=True))
        self.ecu_screen.terminal_requested.connect(self._open_in_terminal)
        self.fpke_screen.close_requested.connect(self.close_ecu)
        self.kombi_screen.close_requested.connect(self.close_ecu)
        self.bcm_screen.close_requested.connect(self.close_ecu)
        self.bcm_screen.open_terminal_requested.connect(self._on_bcm_open_terminal)
        self.mrr_screen.close_requested.connect(self.close_ecu)
        self.mrr_screen.open_terminal_requested.connect(self._on_mrr_open_terminal)
        self.elv_screen.close_requested.connect(self.close_ecu)
        self.elv_screen.open_terminal_requested.connect(self._on_elv_open_terminal)

        self.console = ExecutionPanel(self.runner)
        self.console.setMinimumHeight(120)
        self.console.setVisible(False)
        self.bus_screen.note.connect(self.console.note)
        self.bus_screen.note.connect(lambda _m: self._ensure_console_visible())
        self.ecu_screen.note.connect(self.console.note)
        self.ecu_screen.note.connect(lambda _m: self._ensure_console_visible())
        self.fpke_screen.note.connect(self.console.note)
        self.fpke_screen.note.connect(lambda _m: self._ensure_console_visible())
        self.kombi_screen.note.connect(self.console.note)
        self.kombi_screen.note.connect(lambda _m: self._ensure_console_visible())
        self.bcm_screen.note.connect(self.console.note)
        self.bcm_screen.note.connect(lambda _m: self._ensure_console_visible())
        self.mrr_screen.note.connect(self.console.note)
        self.mrr_screen.note.connect(lambda _m: self._ensure_console_visible())
        self.elv_screen.note.connect(self.console.note)
        self.elv_screen.note.connect(lambda _m: self._ensure_console_visible())
        self.splitter.addWidget(self.stack)
        self.splitter.addWidget(self.console)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setSizes([660, 180])

        self.terminal = TerminalScreen(self.conn, self.runner)
        self.conn.in_use = self._adapter_in_use
        self.modes = QStackedWidget()
        self.modes.addWidget(self.splitter)
        self.modes.addWidget(self.terminal)
        lay.addWidget(self.modes, 1)
        lay.addWidget(self.console.status_widget)

        self._build_menu()

        self.ws.changed.connect(self._refresh_header)
        self.ws.changed.connect(self._refresh_screen)
        self.fpke_screen.changed.connect(self._refresh_header)
        self.fpke_screen.changed.connect(self._refresh_screen)
        self.kombi_screen.changed.connect(self._refresh_header)
        self.kombi_screen.changed.connect(self._refresh_screen)
        self.bcm_screen.changed.connect(self._refresh_header)
        self.bcm_screen.changed.connect(self._refresh_screen)
        self.mrr_screen.changed.connect(self._refresh_header)
        self.mrr_screen.changed.connect(self._refresh_screen)
        self.elv_screen.changed.connect(self._refresh_header)
        self.elv_screen.changed.connect(self._refresh_screen)
        self.conn.changed.connect(self._refresh_header)
        self.console.btn_toggle_log.toggled.connect(self._set_console_visible)
        self.console.btn_hide.clicked.connect(lambda: self._set_console_visible(False))
        self.runner.operation_started.connect(self._ensure_console_visible)
        self.runner.busy_changed.connect(self._on_busy)
        self.runner.operation_finished.connect(self._on_operation_finished)
        self.terminal.problem.connect(self.offer_problem_report)
        self._opened_at = time.time()
        self._report_dlg: ProblemReportDialog | None = None
        self._quit_when_idle = False  # Quit was confirmed during an operation: close once it has ended
        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.retranslate_ui()
        self._refresh_screen()

    # ────────────────────────────── header & menu ──────────────────────────────
    def _build_header(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("Header")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(14, 0, 14, 0)
        lay.setSpacing(8)

        logo = QLabel()
        logo.setPixmap(build_app_icon().pixmap(QSize(20, 20)))
        lay.addWidget(logo, 0, Qt.AlignmentFlag.AlignVCenter)
        self.lbl_app = QLabel("ContiTool")
        self.lbl_app.setObjectName("AppName")
        lay.addWidget(self.lbl_app, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addSpacing(2)
        sep = vdivider()
        sep.setFixedHeight(16)
        lay.addWidget(sep, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addSpacing(2)

        track = QFrame()
        track.setObjectName("ModeTrack")
        self._mode_track = track
        track_lay = QHBoxLayout(track)
        track_lay.setContentsMargins(2, 2, 2, 2)
        track_lay.setSpacing(2)
        self.tab_bus = QPushButton()
        self.tab_ecu = QPushButton()
        self.tab_term = QPushButton()
        tabs = QButtonGroup(self)
        for b, mode in ((self.tab_bus, "bus"), (self.tab_ecu, "ecu"), (self.tab_term, "terminal")):
            b.setObjectName("TabBtn")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            b.clicked.connect(lambda _c=False, m=mode: self.set_mode(m))
            tabs.addButton(b)
            track_lay.addWidget(b)
        self.tab_bus.setVisible(False)
        self.tab_ecu.setChecked(True)
        lay.addWidget(track, 0, Qt.AlignmentFlag.AlignVCenter)

        self.ecu_switch_track = QFrame()
        self.ecu_switch_track.setObjectName("ModeTrack")
        sw_lay = QHBoxLayout(self.ecu_switch_track)
        sw_lay.setContentsMargins(2, 2, 2, 2)
        sw_lay.setSpacing(2)
        self.btn_sw_j533 = QPushButton()
        self.btn_sw_fpke = QPushButton()
        self.btn_sw_kombi = QPushButton()
        self.btn_sw_bcm = QPushButton()
        self.btn_sw_mrr = QPushButton()
        self.btn_sw_elv = QPushButton()
        for b, target in (
            (self.btn_sw_j533, "j533"),
            (self.btn_sw_fpke, "fpke"),
            (self.btn_sw_kombi, "kombi"),
            (self.btn_sw_bcm, "bcm"),
            (self.btn_sw_mrr, "mrr"),
            (self.btn_sw_elv, "elv"),
        ):
            b.setObjectName("TabBtn")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            b.clicked.connect(lambda _c=False, t=target: self.switch_ecu_view(t))
            sw_lay.addWidget(b)
        self.ecu_switch_track.setVisible(False)
        lay.addWidget(self.ecu_switch_track, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addStretch(1)

        self.btn_conn = button("", "Chip", slot=self.show_connection)
        self.btn_conn.setCursor(Qt.CursorShape.PointingHandCursor)
        lay.addWidget(self.btn_conn, 0, Qt.AlignmentFlag.AlignVCenter)

        self.btn_settings = button("", "Chip", slot=self.show_settings)
        self.btn_settings.setCursor(Qt.CursorShape.PointingHandCursor)
        lay.addWidget(self.btn_settings, 0, Qt.AlignmentFlag.AlignVCenter)

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
            b.clicked.connect(lambda _c=False, c=code: self._on_lang_picked(c))
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
        self.act_scan = act(lambda: self.scan_can_bus("all"), "Ctrl+Shift+R")
        self.act_read = act(self.read_over_can, "Ctrl+R")
        self.act_folder = act(self.open_folder, QKeySequence.StandardKey.Open)
        self.act_files = act(self.open_files, "Ctrl+Shift+O")
        self.act_export = act(self._export_active)
        self.act_restore = act(self.restore_backup)
        self.act_frf = act(self._flash_frf_active)
        self.act_report = act(self.show_report, "Ctrl+I")
        self.act_close = act(self.close_ecu, QKeySequence.StandardKey.Close)
        self.act_conn = act(self.show_connection)
        self.act_settings = act(self.show_settings, QKeySequence.StandardKey.Preferences)
        self.act_settings.setMenuRole(QAction.MenuRole.PreferencesRole)
        self.act_quit = act(self.close, QKeySequence.StandardKey.Quit)
        self.act_quit.setMenuRole(QAction.MenuRole.QuitRole)
        for a in (self.act_scan, self.act_read, self.act_folder, self.act_files, None, self.act_export, self.act_restore, self.act_frf, None, self.act_report, self.act_close, None, self.act_conn, self.act_settings, None, self.act_quit):
            self.menu_file.addSeparator() if a is None else self.menu_file.addAction(a)

        self.menu_view = mb.addMenu("")
        self.act_mode_bus = act(lambda: self.set_mode("bus"), "Ctrl+B")
        self.act_mode_ecu = act(lambda: self.set_mode("ecu"), "Ctrl+1")
        self.act_mode_term = act(lambda: self.set_mode("terminal"), "Ctrl+2")
        self.act_log = QAction(self)
        self.act_log.setCheckable(True)
        self.act_log.setShortcut(QKeySequence("Ctrl+J"))
        self.act_log.toggled.connect(self._set_console_visible)
        self.menu_view.addAction(self.act_mode_bus)
        self.menu_view.addAction(self.act_mode_ecu)
        self.menu_view.addAction(self.act_mode_term)
        self.menu_view.addSeparator()
        self.menu_view.addAction(self.act_log)

        self.menu_help = mb.addMenu("")
        self.act_guide = act(self.show_guide, QKeySequence.StandardKey.HelpContents)
        self.act_problem = act(self.report_problem)
        self.updates = UpdateChecker(self)
        self.act_updates = act(lambda: self.updates.check(manual=True))
        self.act_about = act(self.show_about)
        self.act_about.setMenuRole(QAction.MenuRole.AboutRole)
        self.menu_help.addAction(self.act_guide)
        self.menu_help.addAction(self.act_problem)
        self.menu_help.addAction(self.act_updates)
        self.menu_help.addAction(self.act_about)

    def _is_fpke_active(self) -> bool:
        return self.fpke_screen.is_open and (
            self._active_screen == "fpke"
            or (
                not self.ws.is_open
                and not self.kombi_screen.is_open
                and not self.bcm_screen.is_open
                and not self.mrr_screen.is_open
                and not self.elv_screen.is_open
            )
        )

    def _is_kombi_active(self) -> bool:
        return self.kombi_screen.is_open and (
            self._active_screen == "kombi"
            or (
                not self.ws.is_open
                and not self.fpke_screen.is_open
                and not self.bcm_screen.is_open
                and not self.mrr_screen.is_open
                and not self.elv_screen.is_open
            )
        )

    def _is_bcm_active(self) -> bool:
        return self.bcm_screen.is_open and (
            self._active_screen == "bcm"
            or (
                not self.ws.is_open
                and not self.fpke_screen.is_open
                and not self.kombi_screen.is_open
                and not self.mrr_screen.is_open
                and not self.elv_screen.is_open
            )
        )

    def _is_mrr_active(self) -> bool:
        return self.mrr_screen.is_open and (
            self._active_screen == "mrr"
            or (
                not self.ws.is_open
                and not self.fpke_screen.is_open
                and not self.kombi_screen.is_open
                and not self.bcm_screen.is_open
                and not self.elv_screen.is_open
            )
        )

    def _is_elv_active(self) -> bool:
        return self.elv_screen.is_open and (
            self._active_screen == "elv"
            or (
                not self.ws.is_open
                and not self.fpke_screen.is_open
                and not self.kombi_screen.is_open
                and not self.bcm_screen.is_open
                and not self.mrr_screen.is_open
            )
        )

    def _export_active(self) -> None:
        if self._is_elv_active():
            self.elv_screen.action_export_json()
        elif self._is_mrr_active():
            self.mrr_screen.action_export_json()
        elif self._is_bcm_active():
            self.bcm_screen.action_export_keys_json()
        elif self._is_kombi_active():
            self.kombi_screen.export_backup()
        elif self._is_fpke_active():
            self.fpke_screen.export_backup()
        else:
            self.ecu_screen.export_backup()

    def _flash_frf_active(self) -> None:
        if self._is_mrr_active():
            self.mrr_screen.action_flash_frf()
        else:
            self.flash_frf()

    def _create_session_dir(self, unit: str, kind: str, *, dumps: bool = False) -> Path | None:
        try:
            return new_session(self.conn.out_dir, unit, kind, dumps=dumps)
        except OSError as exc:
            QMessageBox.warning(
                self,
                tr("Ошибка создания папки сессии", "Session folder error"),
                str(exc),
            )
            return None

    def _provide_fpke_cluster_material(self) -> dict[str, Any] | None:
        scr: FpkeScreen | None = None
        if self.fpke_screen.is_open and self.kombi_screen.is_open:
            prefer = self._active_screen if self._active_screen in ("fpke", "kombi") else self._last_cluster_screen
            scr = self.kombi_screen if prefer == "kombi" else self.fpke_screen
        elif self.fpke_screen.is_open:
            scr = self.fpke_screen
        elif self.kombi_screen.is_open:
            scr = self.kombi_screen
        if scr is None:
            return None
        df_bytes = scr._working_dflash_bytes
        cf_bytes = scr._cflash_bytes
        if df_bytes is not None:
            return {
                "dflash_bytes": df_bytes,
                "cflash_bytes": cf_bytes,
                "s0_hex": str(getattr(scr, "_cached_s0_hex", "") or ""),
                "s1_hex": str(getattr(scr, "_cached_s1_hex", "") or ""),
            }
        df_path = scr._working_dflash_path or scr.files.get("dflash")
        if df_path is None or not df_path.is_file():
            return None
        cf_path = scr.files.get("cflash")
        try:
            df_raw = df_path.read_bytes()
            cf_raw = cf_bytes if cf_bytes is not None else (cf_path.read_bytes() if (cf_path is not None and cf_path.is_file()) else None)
        except OSError:
            return None
        return {
            "dflash_bytes": df_raw,
            "cflash_bytes": cf_raw,
            "s0_hex": str(getattr(scr, "_cached_s0_hex", "") or ""),
            "s1_hex": str(getattr(scr, "_cached_s1_hex", "") or ""),
        }

    def _refresh_header(self) -> None:
        has_scan = self.bus_screen.has_scan
        scan_cnt = len(self.bus_screen.scan_result.ecus) if (has_scan and self.bus_screen.scan_result) else 0
        show_bus = has_scan or self._active_screen == "bus"
        self.tab_bus.setVisible(show_bus)
        self.act_mode_bus.setVisible(show_bus)
        self.act_mode_bus.setEnabled(show_bus)
        self.tab_bus.setText(
            tr(f"Шина CAN ({scan_cnt})", f"CAN Bus ({scan_cnt})") if scan_cnt else tr("Шина CAN", "CAN Bus")
        )
        self._mode_track.updateGeometry()
        self.bus_screen.set_loaded_flags(
            j533_loaded=self.ws.is_open,
            fpke_loaded=self.fpke_screen.is_open,
            kombi_loaded=self.kombi_screen.is_open,
            bcm_loaded=self.bcm_screen.is_open,
            mrr_loaded=self.mrr_screen.is_open,
            elv_loaded=self.elv_screen.is_open,
        )

        open_count = (
            int(self.ws.is_open)
            + int(self.fpke_screen.is_open)
            + int(self.kombi_screen.is_open)
            + int(self.bcm_screen.is_open)
            + int(self.mrr_screen.is_open)
            + int(self.elv_screen.is_open)
        )
        can_close_idle = not self.runner.is_busy
        if self._is_elv_active():
            self.tab_ecu.setText(tr("Блок", "ECU") if open_count >= 2 else tr("Блок", "ECU") + f" {self.elv_screen.part_number}")
            self.tab_term.setText(tr("CAN-терминал", "CAN terminal"))
            self.act_report.setEnabled(False)
            self.act_export.setEnabled(bool(self.elv_screen._dflash_parsed or self.elv_screen._passport))
            self.act_close.setEnabled(can_close_idle)
        elif self._is_mrr_active():
            self.tab_ecu.setText(tr("Блок", "ECU") if open_count >= 2 else tr("Блок", "ECU") + f" {self.mrr_screen.part_number}")
            self.tab_term.setText(tr("CAN-терминал", "CAN terminal"))
            self.act_report.setEnabled(False)
            self.act_export.setEnabled(
                bool(
                    self.mrr_screen._passport
                    or self.mrr_screen._status
                    or self.mrr_screen._ika_hex
                    or self.mrr_screen._gfa_hex
                )
            )
            self.act_close.setEnabled(can_close_idle)
        elif self._is_bcm_active():
            self.tab_ecu.setText(tr("Блок", "ECU") if open_count >= 2 else tr("Блок", "ECU") + f" {self.bcm_screen.part_number}")
            self.tab_term.setText(tr("CAN-терминал", "CAN terminal"))
            self.act_report.setEnabled(False)
            self.act_export.setEnabled(bool(self.bcm_screen._ika_hex or self.bcm_screen._gfa_hex or self.bcm_screen._status))
            self.act_close.setEnabled(can_close_idle)
        elif self._is_kombi_active():
            self.tab_ecu.setText(tr("Блок", "ECU") if open_count >= 2 else tr("Блок", "ECU") + f" {self.kombi_screen.part_number}")
            self.tab_term.setText(tr("CAN-терминал", "CAN terminal"))
            self.act_report.setEnabled(True)
            self.act_export.setEnabled(bool(self.kombi_screen.files))
            self.act_close.setEnabled(can_close_idle)
        elif self._is_fpke_active():
            self.tab_ecu.setText(tr("Блок", "ECU") if open_count >= 2 else tr("Блок", "ECU") + f" {self.fpke_screen.part_number}")
            self.tab_term.setText(tr("CAN-терминал", "CAN terminal"))
            self.act_report.setEnabled(True)
            self.act_export.setEnabled(bool(self.fpke_screen.files))
            self.act_close.setEnabled(can_close_idle)
        else:
            open_ = self.ws.is_open
            self.tab_ecu.setText(
                tr("Блок", "ECU")
                if open_count >= 2
                else tr("Блок", "ECU") + (f" {self.ws.part_number}" if open_ and self.ws.part_number else "")
            )
            self.tab_term.setText(tr("CAN-терминал", "CAN terminal"))
            self.act_report.setEnabled(open_ or self.fpke_screen.is_open or self.kombi_screen.is_open)
            self.act_export.setEnabled(open_ or bool(self.fpke_screen.files) or bool(self.kombi_screen.files))
            self.act_close.setEnabled(
                can_close_idle
                and (
                    open_
                    or self.fpke_screen.is_open
                    or self.kombi_screen.is_open
                    or self.bcm_screen.is_open
                    or self.mrr_screen.is_open
                    or self.elv_screen.is_open
                )
            )

        self.ecu_switch_track.setVisible(open_count >= 2)
        if open_count >= 2:
            self.btn_sw_j533.setVisible(self.ws.is_open)
            self.btn_sw_fpke.setVisible(self.fpke_screen.is_open)
            self.btn_sw_kombi.setVisible(self.kombi_screen.is_open)
            self.btn_sw_bcm.setVisible(self.bcm_screen.is_open)
            self.btn_sw_mrr.setVisible(self.mrr_screen.is_open)
            self.btn_sw_elv.setVisible(self.elv_screen.is_open)
            self.btn_sw_j533.setText("19 J533")
            self.btn_sw_j533.setToolTip(f"19 J533 — {self.ws.part_number}" if self.ws.part_number else "19 J533")
            self.btn_sw_fpke.setText("17 FPK_E")
            self.btn_sw_fpke.setToolTip(f"17 FPK_E — {self.fpke_screen.part_number}" if self.fpke_screen.part_number else "17 FPK_E")
            self.btn_sw_kombi.setText("17 Kombi")
            self.btn_sw_kombi.setToolTip(f"17 Kombi — {self.kombi_screen.part_number}" if self.kombi_screen.part_number else "17 Kombi")
            self.btn_sw_bcm.setText("09 BCM")
            self.btn_sw_bcm.setToolTip(f"09 BCM — {self.bcm_screen.part_number}" if self.bcm_screen.part_number else "09 BCM")
            self.btn_sw_mrr.setText("13 MRR")
            self.btn_sw_mrr.setToolTip(f"13 MRR — {self.mrr_screen.part_number}" if self.mrr_screen.part_number else "13 MRR")
            self.btn_sw_elv.setText("2B ELV")
            self.btn_sw_elv.setToolTip(f"2B ELV — {self.elv_screen.part_number}" if self.elv_screen.part_number else "2B ELV")
            self.btn_sw_j533.setChecked(self._active_screen == "j533")
            self.btn_sw_fpke.setChecked(self._active_screen == "fpke")
            self.btn_sw_kombi.setChecked(self._active_screen == "kombi")
            self.btn_sw_bcm.setChecked(self._active_screen == "bcm")
            self.btn_sw_mrr.setChecked(self._active_screen == "mrr")
            self.btn_sw_elv.setChecked(self._active_screen == "elv")
            for b in (self.btn_sw_j533, self.btn_sw_fpke, self.btn_sw_kombi, self.btn_sw_bcm, self.btn_sw_mrr, self.btn_sw_elv):
                b.updateGeometry()
            self.ecu_switch_track.updateGeometry()
        for b in (self.tab_bus, self.tab_ecu, self.tab_term):
            b.updateGeometry()
        self._mode_track.updateGeometry()

        if self.conn.port or self.conn.title:
            full_disp = self.conn.display()
            max_conn_px = 112 if open_count >= 2 else 165
            short_disp = self.btn_conn.fontMetrics().elidedText(full_disp, Qt.TextElideMode.ElideMiddle, max_conn_px)
            self.btn_conn.setText(short_disp)
            self.btn_conn.setIcon(dot_icon(theme.OK if self.conn.ready else theme.WARN, 6))
            status_tip = (
                tr("Адаптер готов", "Adapter ready")
                if self.conn.ready
                else tr("Подтвердите схему подключения", "Confirm the bench wiring")
            )
            self.btn_conn.setToolTip(f"{full_disp}\n{status_tip}")
        else:
            self.btn_conn.setText(tr("Подключение…", "Connection…"))
            self.btn_conn.setIcon(QIcon())
            self.btn_conn.setToolTip(tr("Настроить адаптер и подключение к блоку", "Set up the CAN adapter and ECU connection"))

    def switch_ecu_view(self, target: str) -> None:
        """Switch between `'start'`, `'bus'`, `'j533'`, `'fpke'`, `'kombi'`, `'bcm'`, `'mrr'`, and `'elv'` inside the main workspace stack."""
        self._active_screen = target
        if target in ("fpke", "kombi"):
            self._last_cluster_screen = target
        if self.modes.currentWidget() is self.terminal:
            self.terminal.disconnect_bus()
            self.modes.setCurrentWidget(self.splitter)
        if target == "bus":
            self.tab_bus.setChecked(True)
        else:
            self.tab_ecu.setChecked(True)
        self._refresh_header()
        self._refresh_screen()

    def set_mode(self, mode: str) -> None:
        """Switch between the CAN Bus view, ECU workspace, and the CAN terminal. Leaving the terminal frees the adapter."""
        term = mode == "terminal" and not self.runner.is_busy
        if not term:
            self.terminal.disconnect_bus()
        elif self._is_elv_active():
            self.terminal.set_target_ecu("elv")
        elif self._is_mrr_active():
            self.terminal.set_target_ecu("mrr")
        elif self._is_bcm_active():
            self.terminal.set_target_ecu("bcm")
        elif self._is_kombi_active():
            self.terminal.set_target_ecu("kombi")
        elif self._is_fpke_active():
            self.terminal.set_target_ecu("fpke")
        elif self._active_screen == "j533" or self.ws.is_open:
            self.terminal.set_target_ecu("j533")
        if mode == "bus":
            self._active_screen = "bus"
        elif mode == "ecu" and self._active_screen == "bus":
            if self.elv_screen.is_open and not self.ws.is_open and not self.fpke_screen.is_open and not self.kombi_screen.is_open and not self.bcm_screen.is_open and not self.mrr_screen.is_open:
                self._active_screen = "elv"
            elif self.mrr_screen.is_open and not self.ws.is_open and not self.fpke_screen.is_open and not self.kombi_screen.is_open and not self.bcm_screen.is_open:
                self._active_screen = "mrr"
            elif self.bcm_screen.is_open and not self.ws.is_open and not self.fpke_screen.is_open and not self.kombi_screen.is_open:
                self._active_screen = "bcm"
            elif self.kombi_screen.is_open and not self.ws.is_open and not self.fpke_screen.is_open:
                self._active_screen = "kombi"
            elif self.fpke_screen.is_open and not self.ws.is_open:
                self._active_screen = "fpke"
            elif self.ws.is_open:
                self._active_screen = "j533"
            else:
                self._active_screen = "start"
        self.modes.setCurrentWidget(self.terminal if term else self.splitter)
        if term:
            self.tab_term.setChecked(True)
        elif self._active_screen == "bus":
            self.tab_bus.setChecked(True)
        else:
            self.tab_ecu.setChecked(True)
        self.console.status_divider.setVisible(not term)
        self.console.btn_toggle_log.setVisible(not term)
        self.act_log.setEnabled(not term)
        self._refresh_header()
        self._refresh_screen()

    def _open_in_terminal(self, request: str) -> None:
        self.set_mode("terminal")
        if self.modes.currentWidget() is self.terminal:
            self.terminal.prefill_uds(request)

    def _on_busy(self, busy: bool) -> None:
        self.tab_term.setEnabled(not busy)
        self.act_mode_term.setEnabled(not busy)
        self.tab_term.setToolTip(tr("Недоступно, пока идёт операция", "Unavailable while an operation runs") if busy else "")
        self._refresh_header()

    def _refresh_screen(self) -> None:
        if self._active_screen == "bus":
            self.stack.setCurrentWidget(self.bus_screen)
            return
        if self._active_screen == "elv" and self.elv_screen.is_open:
            self.stack.setCurrentWidget(self.elv_screen)
            return
        if self._active_screen == "mrr" and self.mrr_screen.is_open:
            self.stack.setCurrentWidget(self.mrr_screen)
            return
        if self._active_screen == "bcm" and self.bcm_screen.is_open:
            self.stack.setCurrentWidget(self.bcm_screen)
            return
        if self._active_screen == "kombi" and self.kombi_screen.is_open:
            self._last_cluster_screen = "kombi"
            self.stack.setCurrentWidget(self.kombi_screen)
            return
        if self._active_screen == "fpke" and self.fpke_screen.is_open:
            self._last_cluster_screen = "fpke"
            self.stack.setCurrentWidget(self.fpke_screen)
            return
        if self._active_screen == "j533" and self.ws.is_open:
            self.stack.setCurrentWidget(self.ecu_screen)
            return
        if self.kombi_screen.is_open:
            self._active_screen = "kombi"
            self._last_cluster_screen = "kombi"
            self.stack.setCurrentWidget(self.kombi_screen)
        elif self.fpke_screen.is_open:
            self._active_screen = "fpke"
            self._last_cluster_screen = "fpke"
            self.stack.setCurrentWidget(self.fpke_screen)
        elif self.ws.is_open:
            self._active_screen = "j533"
            self.stack.setCurrentWidget(self.ecu_screen)
        elif self.bcm_screen.is_open:
            self._active_screen = "bcm"
            self.stack.setCurrentWidget(self.bcm_screen)
        elif self.mrr_screen.is_open:
            self._active_screen = "mrr"
            self.stack.setCurrentWidget(self.mrr_screen)
        elif self.elv_screen.is_open:
            self._active_screen = "elv"
            self.stack.setCurrentWidget(self.elv_screen)
        elif self._active_screen == "bus":
            self.stack.setCurrentWidget(self.bus_screen)
        else:
            self._active_screen = "start"
            self.stack.setCurrentWidget(self.start_screen)
            self.start_screen.refresh_recent()

    def _set_console_visible(self, show: bool) -> None:
        self.console.setVisible(show)
        for ctrl in (self.console.btn_toggle_log, self.act_log):
            ctrl.blockSignals(True)
            ctrl.setChecked(show)
            ctrl.blockSignals(False)
        if show:
            sizes = self.splitter.sizes()
            total = sum(sizes) or max(540, self.height() - 80)
            if len(sizes) == 2 and sizes[1] < 160:
                self.splitter.setSizes([max(340, total - 185), 185])

    def _ensure_console_visible(self, _title: str = "") -> None:
        self._set_console_visible(True)

    # ────────────────────────────── loading ──────────────────────────────
    @staticmethod
    def _detect_mrr_offline_file(paths: list[Path], *, json_only: bool = False) -> Path | None:
        """Return a recognizable offline 13 ACC Radar file (mrr_keys.json, verified CodeFlash/App, or MRR Dflash)."""
        files: list[Path] = []
        for p in paths:
            if p.is_dir():
                files.extend(sorted(f for f in p.iterdir() if f.is_file()))
            elif p.is_file():
                files.append(p)
        # 1. Explicit MRR JSON reports (mrr_keys.json or exported report JSON)
        for f in files:
            if f.suffix.lower() != ".json":
                continue
            try:
                if f.stat().st_size > 2 * 1024 * 1024:
                    continue
                data = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and (
                data.get("ecu_kind") == "mrr"
                or ("dflash_fee" in data and ("ika_hex" in data or "cflash_cp" in data))
            ):
                return f
        if json_only:
            return None
        # 2. Verified MRR CodeFlash / Application binary dump (skip if a J533 Uflash is present)
        if any("uflash" in f.name.lower() for f in files):
            return None
        for f in files:
            if f.suffix.lower() not in (".bin", ".raw"):
                continue
            try:
                sz = f.stat().st_size
                if sz not in (0x180000, 0x150000, 0x200000, 0x1D0000):
                    continue
                prof = mrr_detect_profile(image_bytes=f.read_bytes())
                if prof.get("verified"):
                    return f
            except OSError:
                continue
        # 3. 64 KiB DFLASH0 containing verified AUTOSAR Fee KS_META or ShadowSecret
        for f in files:
            if f.suffix.lower() not in (".bin", ".raw"):
                continue
            try:
                if f.stat().st_size != MRR_DFLASH_SIZE:
                    continue
                fee = mrr_parse_dflash_fee(f.read_bytes())
                if fee.get("encryption_scheme", "unknown") != "unknown" or fee.get("shadow_secret_present"):
                    return f
            except (OSError, ValueError):
                continue
        return None

    @staticmethod
    def _detect_elv_report_file(paths: list[Path]) -> Path | None:
        """Return a recognizable offline 2B ELV JSON report (`elv_report.json`, etc.)."""
        files: list[Path] = []
        for p in paths:
            if p.is_dir():
                files.extend(sorted(f for f in p.iterdir() if f.is_file()))
            elif p.is_file():
                files.append(p)
        for f in files:
            if f.suffix.lower() != ".json":
                continue
            try:
                if f.stat().st_size > 2 * 1024 * 1024:
                    continue
                data = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and (
                data.get("ecu_kind") == "elv"
                or (
                    f.name.lower() in ("elv_report.json", "elv_read_report.json", "elv_backup_report.json")
                    and ("passport" in data or "status" in data)
                )
            ):
                return f
        return None

    def open_folder(self, folder: str = "") -> None:
        self.set_mode("ecu")
        chosen = folder or QFileDialog.getExistingDirectory(
            self, tr("Папка с дампами блока", "Folder with the ECU dumps"), str(Path.cwd())
        )
        if chosen:
            folder_path = Path(chosen)
            kombi_files = detect_kombi_files([folder_path])
            if kombi_files:
                if self.ws.is_open and not self.bus_screen.has_scan:
                    self.ws.close()
                self._active_screen = "kombi"
                self.kombi_screen.open_from_files(kombi_files, folder=folder_path, source="disk")
                self._refresh_header()
                self._refresh_screen()
                return
            fpke_files = detect_fpke_files([folder_path])
            if fpke_files:
                if self.ws.is_open and not self.bus_screen.has_scan:
                    self.ws.close()
                self._active_screen = "fpke"
                self.fpke_screen.open_from_files(fpke_files, folder=folder_path, source="disk")
                self._refresh_header()
                self._refresh_screen()
                return
            mrr_file = self._detect_mrr_offline_file([folder_path], json_only=False)
            if mrr_file is not None:
                self._active_screen = "mrr"
                self.mrr_screen.open_offline(mrr_file)
                _remember_recent(folder_path)
                self._refresh_header()
                self._refresh_screen()
                return
            elv_files = elv_detect_folder_files(folder_path)
            if "dflash" in elv_files:
                try:
                    self.elv_screen.open_from_dflash_file(elv_files["dflash"])
                except (OSError, ValueError) as exc:
                    QMessageBox.warning(
                        self,
                        tr("Ошибка чтения дампа 2B ELV", "2B ELV dump read error"),
                        tr(
                            f"Не удалось открыть дамп ELV ({elv_files['dflash'].name}):\n{exc}",
                            f"Could not open ELV dump ({elv_files['dflash'].name}):\n{exc}",
                        ),
                    )
                    return
                self._active_screen = "elv"
                _remember_recent(folder_path)
                self._refresh_header()
                self._refresh_screen()
                return
            elv_report = elv_files.get("report") or self._detect_elv_report_file([folder_path])
            if elv_report is not None:
                try:
                    self.elv_screen.open_from_report_file(elv_report)
                except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                    QMessageBox.warning(
                        self,
                        tr("Ошибка чтения отчёта 2B ELV", "2B ELV report read error"),
                        tr(
                            f"Не удалось открыть отчёт ELV ({elv_report.name}):\n{exc}",
                            f"Could not open ELV report ({elv_report.name}):\n{exc}",
                        ),
                    )
                    return
                self._active_screen = "elv"
                _remember_recent(folder_path)
                self._refresh_header()
                self._refresh_screen()
                return
            missing = self.ws.open_folder(folder_path)
            if self.ws.is_open:
                self._active_screen = "j533"
                if not self.bus_screen.has_scan:
                    if self.fpke_screen.is_open:
                        self.fpke_screen.close_kombi()
                    if self.kombi_screen.is_open:
                        self.kombi_screen.close_kombi()
            self._report_missing(missing, folder_path)
            self._refresh_header()
            self._refresh_screen()

    def open_files(self) -> None:
        self.set_mode("ecu")
        chosen, _ = QFileDialog.getOpenFileNames(
            self,
            tr("Файлы дампов", "Dump files"),
            str(Path.cwd()),
            "Binary / JSON (*.bin *.raw *.json);;All Files (*)",
        )
        if chosen:
            self._load_paths([Path(c) for c in chosen])

    def _load_paths(self, paths: list[Path]) -> None:
        if len(paths) == 1 and paths[0].is_dir():
            self.open_folder(str(paths[0]))
            return
        file_list = [p for p in paths if p.is_file()]
        kombi_files = detect_kombi_files(file_list)
        if kombi_files:
            if self.ws.is_open and not self.bus_screen.has_scan:
                self.ws.close()
            self._active_screen = "kombi"
            self.kombi_screen.open_from_files(kombi_files, folder=file_list[0].parent if file_list else None, source="disk")
            self._refresh_header()
            self._refresh_screen()
            return
        fpke_files = detect_fpke_files(file_list)
        if fpke_files:
            if self.ws.is_open and not self.bus_screen.has_scan:
                self.ws.close()
            self._active_screen = "fpke"
            self.fpke_screen.open_from_files(fpke_files, folder=file_list[0].parent if file_list else None, source="disk")
            self._refresh_header()
            self._refresh_screen()
            return
        mrr_file = self._detect_mrr_offline_file(file_list, json_only=False)
        if mrr_file is not None:
            self._active_screen = "mrr"
            self.mrr_screen.open_offline(mrr_file)
            self._refresh_header()
            self._refresh_screen()
            return
        for cand in file_list:
            if cand.suffix.lower() in (".bin", ".raw"):
                try:
                    sz = cand.stat().st_size
                    if sz in (ELV_DFLASH_COMPACT_SIZE, ELV_DFLASH_RAW64K_SIZE):
                        raw = cand.read_bytes()
                        if elv_is_dflash_bytes(raw):
                            try:
                                self.elv_screen.open_from_dflash_file(cand, raw=raw)
                            except (OSError, ValueError) as exc:
                                QMessageBox.warning(
                                    self,
                                    tr("Ошибка чтения дампа 2B ELV", "2B ELV dump read error"),
                                    tr(
                                        f"Не удалось открыть дамп ELV ({cand.name}):\n{exc}",
                                        f"Could not open ELV dump ({cand.name}):\n{exc}",
                                    ),
                                )
                                return
                            self._active_screen = "elv"
                            self._refresh_header()
                            self._refresh_screen()
                            return
                except OSError:
                    continue
        elv_report = self._detect_elv_report_file(file_list)
        if elv_report is not None:
            try:
                self.elv_screen.open_from_report_file(elv_report)
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                QMessageBox.warning(
                    self,
                    tr("Ошибка чтения отчёта 2B ELV", "2B ELV report read error"),
                    tr(
                        f"Не удалось открыть отчёт ELV ({elv_report.name}):\n{exc}",
                        f"Could not open ELV report ({elv_report.name}):\n{exc}",
                    ),
                )
                return
            self._active_screen = "elv"
            self._refresh_header()
            self._refresh_screen()
            return
        rejected = self.ws.open_files(file_list)
        if self.ws.is_open:
            self._active_screen = "j533"
            if not self.bus_screen.has_scan:
                if self.fpke_screen.is_open:
                    self.fpke_screen.close_kombi()
                if self.kombi_screen.is_open:
                    self.kombi_screen.close_kombi()
            self._refresh_header()
            self._refresh_screen()
            if rejected:
                QMessageBox.information(
                    self,
                    tr("Часть файлов пропущена", "Some files were skipped"),
                    tr(f"Не опознаны: {', '.join(rejected)}", f"Not recognised: {', '.join(rejected)}"),
                )
            return
        QMessageBox.warning(
            self,
            tr("Это не дампы блока", "Not recognised ECU dumps"),
            tr(
                "Ни один файл не опознан как дамп шлюза J533, приборной панели FPK_E, радара 13 ACC или защёлки руля 2B ELV.",
                "None of the files was recognised as a J533 gateway, FPK_E cluster, 13 ACC radar, or 2B ELV dump.",
            ),
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
            self._ensure_console_visible()
            self.console.note(
                tr(
                    f"Не найдено в папке: {names}. Часть функций будет недоступна.",
                    f"Not found in the folder: {names}. Some features will be unavailable.",
                )
            )

    def scan_can_bus(self, target_kind: str = "all") -> None:
        """Scan Diagnosis CAN (J533 gateway + connected slave ECUs) or a direct CAN bench harness."""
        self.terminal.disconnect_bus()
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        eff_target = None if (not target_kind or target_kind == "all") else target_kind
        self.bus_screen.target_kind = target_kind or "all"
        self.runner.run_task(
            tr("Сканирование шины CAN (шлюз и ведомые блоки)", "Scanning CAN bus (gateway & slave ECUs)"),
            lambda rep: can_scan_bus(port, interface=iface, target_kind=eff_target, reporter=rep),
            on_success=lambda res: QTimer.singleShot(0, lambda: self._on_bus_scanned(res)),
        )

    def _on_bus_scanned(self, res: BusScanResult) -> None:
        self.bus_screen.set_scan_result(res)
        for ecu in res.ecus:
            ecu_pn = (ecu.part_number or "").replace(" ", "").upper()
            if ecu.kind == "fpke" and self.fpke_screen.is_open:
                has_fpke_pn = bool(
                    any(it.get("did") in ("F187", "F191") for it in self.fpke_screen.ident_items)
                    or (self.fpke_screen.dflash_info or {}).get("metadata", {}).get("part_number")
                )
                fpke_pn = self.fpke_screen.part_number.replace(" ", "").upper() if has_fpke_pn else ""
                if not fpke_pn or not ecu_pn or fpke_pn == ecu_pn:
                    self.fpke_screen.via_gateway = bool(ecu.via_gateway)
                    self.fpke_screen.gateway_bridge = bool(ecu.bridge_available)
                    self.fpke_screen.gateway_channel = 0 if ecu.gateway_channel is None else int(ecu.gateway_channel)
                    self.fpke_screen.refresh()
            elif ecu.kind == "kombi" and self.kombi_screen.is_open:
                has_kombi_pn = bool(
                    any(it.get("did") in ("F187", "F191") for it in self.kombi_screen.ident_items)
                    or (self.kombi_screen.dflash_info or {}).get("metadata", {}).get("part_number")
                )
                kombi_pn = self.kombi_screen.part_number.replace(" ", "").upper() if has_kombi_pn else ""
                if not kombi_pn or not ecu_pn or kombi_pn == ecu_pn:
                    self.kombi_screen.via_gateway = bool(ecu.via_gateway)
                    self.kombi_screen.gateway_bridge = bool(ecu.bridge_available)
                    self.kombi_screen.gateway_channel = 0 if ecu.gateway_channel is None else int(ecu.gateway_channel)
                    self.kombi_screen.refresh()
            elif ecu.kind == "bcm" and self.bcm_screen.is_open:
                bcm_pn = (
                    self.bcm_screen._passport.get("part_number")
                    or self.bcm_screen._passport.get("hw_part_number")
                    or ""
                ).replace(" ", "").upper()
                if not bcm_pn or not ecu_pn or bcm_pn == ecu_pn:
                    self.bcm_screen.set_routing(
                        via_gateway=bool(ecu.via_gateway),
                        gateway_bridge=bool(ecu.bridge_available),
                        gateway_channel=0 if ecu.gateway_channel is None else int(ecu.gateway_channel),
                    )
            elif ecu.kind == "mrr" and self.mrr_screen.is_open:
                mrr_pn = (
                    self.mrr_screen._passport.get("part_number")
                    or self.mrr_screen._passport.get("hw_part_number")
                    or ""
                ).replace(" ", "").upper()
                if not mrr_pn or not ecu_pn or mrr_pn == ecu_pn:
                    self.mrr_screen.set_routing(
                        via_gateway=bool(ecu.via_gateway),
                        gateway_bridge=bool(ecu.bridge_available),
                        gateway_channel=2 if ecu.gateway_channel is None else int(ecu.gateway_channel),
                    )
            elif ecu.kind == "elv" and self.elv_screen.is_open:
                elv_pn = (
                    self.elv_screen._passport.get("part_number")
                    or self.elv_screen._passport.get("hw_part_number")
                    or ""
                ).replace(" ", "").upper()
                if not elv_pn or not ecu_pn or elv_pn == ecu_pn:
                    self.elv_screen.set_routing(
                        via_gateway=bool(ecu.via_gateway),
                        gateway_bridge=bool(ecu.bridge_available),
                        gateway_channel=0 if ecu.gateway_channel is None else int(ecu.gateway_channel),
                    )
        self.switch_ecu_view("bus")

    def _on_bus_read_ecu(self, ecu: DiscoveredEcu) -> None:
        self._confirm_read(ecu.to_ident_dict())

    def _on_bus_open_bcm_workspace(self, ecu: DiscoveredEcu) -> None:
        if self.bcm_screen.is_open:
            self.bcm_screen.set_routing(
                via_gateway=bool(ecu.via_gateway),
                gateway_bridge=bool(ecu.bridge_available),
                gateway_channel=int(ecu.gateway_channel or 0),
            )
            self.switch_ecu_view("bcm")
            return
        self.bcm_screen.open_from_discovered(ecu, auto_read=True)
        self.switch_ecu_view("bcm")

    def _on_bcm_open_terminal(self, _kind: str = "bcm") -> None:
        self.set_mode("terminal")
        self.terminal.set_target_ecu("bcm")
        self.terminal.ed_tx.setText("70E")
        self.terminal.ed_rx.setText("778")

    def _on_bus_open_mrr_workspace(self, ecu: DiscoveredEcu) -> None:
        if self.mrr_screen.is_open:
            self.mrr_screen.set_routing(
                via_gateway=bool(ecu.via_gateway),
                gateway_bridge=bool(ecu.bridge_available),
                gateway_channel=2 if ecu.gateway_channel is None else int(ecu.gateway_channel),
            )
            self.switch_ecu_view("mrr")
            return
        self.mrr_screen.open_from_discovered(ecu, auto_read=True)
        self.switch_ecu_view("mrr")

    def _on_mrr_open_terminal(self, _kind: str = "mrr") -> None:
        self.set_mode("terminal")
        self.terminal.set_target_ecu("mrr")
        self.terminal.ed_tx.setText("757")
        self.terminal.ed_rx.setText("7C1")

    def _on_bus_open_elv_workspace(self, ecu: DiscoveredEcu) -> None:
        if self.elv_screen.is_open:
            self.elv_screen.set_routing(
                via_gateway=bool(ecu.via_gateway),
                gateway_bridge=bool(ecu.bridge_available),
                gateway_channel=0 if ecu.gateway_channel is None else int(ecu.gateway_channel),
            )
            self.switch_ecu_view("elv")
            return
        self.elv_screen.open_from_discovered(ecu)
        self.switch_ecu_view("elv")

    def _on_elv_open_terminal(self, _kind: str = "elv") -> None:
        self.set_mode("terminal")
        self.terminal.set_target_ecu("elv")
        self.terminal.ed_tx.setText("731")
        self.terminal.ed_rx.setText("79B")

    def _on_bus_restore_ecu(self, ecu: DiscoveredEcu) -> None:
        ident = ecu.to_ident_dict()
        if ecu.kind == "kombi":
            self._active_screen = "kombi"
            self.kombi_screen.open_from_ident(ident)
            self._refresh_header()
            self._refresh_screen()
            self.kombi_screen.restore_dflash_from_file()
        elif ecu.kind == "fpke":
            self._active_screen = "fpke"
            self.fpke_screen.open_from_ident(ident)
            self._refresh_header()
            self._refresh_screen()
            self.fpke_screen.restore_dflash_from_file()
        else:
            self.restore_backup(force_j533=True)

    def _on_bus_open_terminal(self, ecu: DiscoveredEcu) -> None:
        self.set_mode("terminal")
        self.terminal.set_target_ecu(ecu.kind)
        self.terminal.ed_tx.setText(f"{ecu.uds_tx_id:03X}")
        self.terminal.ed_rx.setText(f"{ecu.uds_rx_id:03X}")

    def _on_bus_open_fpke_workspace(self, ecu: DiscoveredEcu) -> None:
        ident = ecu.to_ident_dict()
        if self.fpke_screen.is_open:
            self.fpke_screen.via_gateway = bool(ecu.via_gateway)
            self.fpke_screen.gateway_bridge = bool(ecu.bridge_available)
            self.fpke_screen.gateway_channel = int(ecu.gateway_channel or 0)
            if not self.fpke_screen.ident_items and ecu.ident:
                self.fpke_screen.ident_items = list(ecu.ident)
            self.fpke_screen.refresh()
        else:
            self.fpke_screen.open_from_ident(ident)
        self.switch_ecu_view("fpke")

    def _on_bus_open_kombi_workspace(self, ecu: DiscoveredEcu) -> None:
        ident = ecu.to_ident_dict()
        if self.kombi_screen.is_open:
            self.kombi_screen.via_gateway = bool(ecu.via_gateway)
            self.kombi_screen.gateway_bridge = bool(ecu.bridge_available)
            self.kombi_screen.gateway_channel = int(ecu.gateway_channel or 0)
            if not self.kombi_screen.ident_items and ecu.ident:
                self.kombi_screen.ident_items = list(ecu.ident)
            self.kombi_screen.refresh()
        else:
            self.kombi_screen.open_from_ident(ident)
        self.switch_ecu_view("kombi")

    def read_over_can(self) -> None:
        """Check the link and show who answers first; the read starts only after the user confirms."""
        self.set_mode("ecu")  # frees the adapter if the terminal holds it
        target_kind = self.start_screen.selected_target_kind()
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        if target_kind in ("j533", "fpke", "kombi", "bcm", "mrr", "elv"):
            self.bus_screen.clear_scan()
            self._refresh_header()

            def _scan_target(rep: Any) -> dict[str, Any]:
                scan_res = can_scan_bus(port, interface=iface, target_kind=target_kind, reporter=rep)
                for ecu in scan_res.ecus:
                    if ecu.kind == target_kind or (target_kind in ("fpke", "kombi") and ecu.diag_addr == "17"):
                        return ecu.to_ident_dict()
                return scan_res.ecus[0].to_ident_dict()

            self.runner.run_task(
                tr("Проверка связи с блоком", "Checking the ECU link"),
                _scan_target,
                on_success=lambda ident_dict: QTimer.singleShot(0, lambda: self._confirm_read(ident_dict)),
            )
            return

        self.runner.run_task(
            tr("Проверка связи с блоком", "Checking the ECU link"),
            lambda rep: can_identify(port, interface=iface, reporter=rep),
            # the runner is still busy inside on_success: ask once it has finished
            on_success=lambda res: QTimer.singleShot(0, lambda: self._confirm_read(res)),
        )

    def _confirm_read(self, ident: dict[str, Any]) -> None:
        is_v850_kombi = ident.get("ecu_kind") == "kombi" or is_kombi_ident(ident.get("ident") or [])
        is_fpke_cluster = (not is_v850_kombi) and (ident.get("ecu_kind") == "fpke" or is_fpke_ident(ident.get("ident") or []))
        is_bcm = ident.get("ecu_kind") == "bcm"
        is_mrr = ident.get("ecu_kind") == "mrr"
        is_elv = ident.get("ecu_kind") == "elv" or is_elv_ident(ident.get("ident") or [])
        dlg = EcuFoundDialog(ident, self.conn, self)
        if run_dialog(dlg) and not dlg.unsupported:
            if is_bcm:
                self._read_bcm_over_can(ident)
                return
            if is_mrr:
                self._read_mrr_over_can(ident)
                return
            if is_elv:
                self._read_elv_over_can(ident)
                return
            if dlg.restore_chosen:
                if is_v850_kombi:
                    if self.ws.is_open and not self.bus_screen.has_scan:
                        self.ws.close()
                    self._active_screen = "kombi"
                    self.kombi_screen.open_from_ident(ident)
                    self._refresh_header()
                    self._refresh_screen()
                    self.kombi_screen.restore_dflash_from_file()
                elif is_fpke_cluster:
                    if self.ws.is_open and not self.bus_screen.has_scan:
                        self.ws.close()
                    self._active_screen = "fpke"
                    self.fpke_screen.open_from_ident(ident)
                    self._refresh_header()
                    self._refresh_screen()
                    self.fpke_screen.restore_dflash_from_file()
                else:
                    self._force_j533_restore = True
                    try:
                        self.restore_backup()
                    finally:
                        self._force_j533_restore = False
            elif is_v850_kombi:
                self._read_kombi_over_can(ident)
            elif is_fpke_cluster:
                self._read_fpke_over_can(ident)
            else:
                self._backup_over_can(ident)

    def _read_bcm_over_can(self, ident: dict[str, Any]) -> None:
        """Read 09 BCM passport, CP/RF status, FFB slots, and DTCs over UDS (without IKA/GFA), then open BcmScreen."""
        port, iface = self.conn.port, self.conn.interface
        via_gw = bool(ident.get("via_gateway", False))
        gw_br = bool(ident.get("gateway_bridge", ident.get("bridge_available", False)))
        gw_ch = int(ident.get("gateway_channel") or 0)

        def task(rep: Any) -> dict[str, Any]:
            return can_bcm_read_all(
                port,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                include_keys=False,
                reporter=rep,
            )

        def done(res: dict[str, Any]) -> None:
            self._active_screen = "bcm"
            self.bcm_screen.open_from_read_result(
                res,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
            )
            self._refresh_header()
            self._refresh_screen()

        self.runner.run_task(
            tr("Чтение данных 09 BCM", "Reading 09 BCM data"),
            task,
            on_success=done,
        )

    def _read_mrr_over_can(self, ident: dict[str, Any]) -> None:
        """Read 13 ACC Radar passport, Code Flash CP & SWaP state, DFLASH0 (IKA/GFA), and DTCs, then open MrrScreen."""
        port, iface = self.conn.port, self.conn.interface
        via_gw = bool(ident.get("via_gateway", False))
        gw_br = bool(ident.get("gateway_bridge", ident.get("bridge_available", False)))
        gw_ch = 2 if ident.get("gateway_channel") is None else int(ident["gateway_channel"])
        caps = set(ident.get("capabilities") or ())
        # On direct bench CAN, read full XCP keys + DFLASH0 automatically; via a vehicle gateway, open over pure UDS
        # first (matching 09 BCM) so opening the screen never interrupts other vehicle buses without explicit confirmation.
        xcp_on_open = (not via_gw) and (iface in BRIDGE_NATIVE_INTERFACES or "memory" in caps)

        ident_list = list(ident.get("ident") or [])
        mrr_unit = unit_of_ident(ident_list)
        if mrr_unit == "unknown":
            vals = {i.get("did"): i.get("value", "") for i in ident_list}
            pn = vals.get("F187") or vals.get("F191") or str(ident.get("part_number") or ident.get("hw_number") or "")
            fz = vals.get("F17C") or str(ident.get("fazit") or "")
            mrr_unit = unit_name(pn, fz)
            if mrr_unit == "unknown" and pn:
                mrr_unit = unit_name(pn, "MRR")
            if mrr_unit == "unknown":
                mrr_unit = "mrr_radar"
        s_dir = self._create_session_dir(mrr_unit, "mrr_read", dumps=True)
        if s_dir is None:
            return

        def task(rep: Any) -> dict[str, Any]:
            if xcp_on_open:
                try:
                    st_res = can_mrr_read_keys(
                        port,
                        interface=iface,
                        via_gateway=via_gw,
                        gateway_bridge=gw_br,
                        gateway_channel=gw_ch,
                        session_dir=s_dir,
                        reporter=rep,
                    )
                except Exception as exc:  # noqa: BLE001
                    if ident.get("officially_supported", True):
                        raise
                    rep.warning(
                        tr(
                            f"Чтение памяти XCP не удалось ({exc}) — переключаемся на чтение статуса и DTC по UDS.",
                            f"XCP memory read failed ({exc}) — falling back to UDS status & DTC read.",
                        )
                    )
                    st_res = can_mrr_status(
                        port,
                        interface=iface,
                        via_gateway=via_gw,
                        gateway_bridge=False,
                        gateway_channel=gw_ch,
                        reporter=rep,
                    )
                    st_res["session_dir"] = str(s_dir)
                    s_dir.mkdir(parents=True, exist_ok=True)
                    (s_dir / "mrr_read_report.json").write_text(
                        json.dumps(st_res, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                    )
            else:
                st_res = can_mrr_status(
                    port,
                    interface=iface,
                    via_gateway=via_gw,
                    gateway_bridge=False,
                    gateway_channel=gw_ch,
                    reporter=rep,
                )
                st_res["session_dir"] = str(s_dir)
                s_dir.mkdir(parents=True, exist_ok=True)
                (s_dir / "mrr_read_report.json").write_text(
                    json.dumps(st_res, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
            if st_res.get("dtcs") is None:
                try:
                    dtc_res = can_uds_read_dtc(
                        port,
                        0x757,
                        0x7C1,
                        interface=iface,
                        ecu_kind="mrr",
                        via_gateway=via_gw,
                        reporter=rep,
                    )
                    st_res["dtcs"] = dtc_res.get("dtcs", [])
                except Exception as exc:  # noqa: BLE001
                    rep.warning(
                        tr(
                            f"Не удалось прочитать ошибки DTC радара 13 ACC ({exc}) — открываем экран без списка DTC.",
                            f"Could not read 13 ACC radar DTCs ({exc}) — opening workspace without DTC list.",
                        )
                    )
                    st_res["dtcs"] = []
            return st_res

        def done(res: dict[str, Any]) -> None:
            saved_dir = Path(str(res.get("session_dir") or s_dir))
            if saved_dir.is_dir():
                _remember_recent(saved_dir)
                self.start_screen.refresh_recent()
            self._active_screen = "mrr"
            self.mrr_screen.open_from_status_result(
                res,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
            )
            self._refresh_header()
            self._refresh_screen()

        self.runner.run_task(
            tr("Чтение данных 13 ACC Radar", "Reading 13 ACC Radar data"),
            task,
            on_success=done,
        )

    def _read_elv_over_can(self, ident: dict[str, Any]) -> None:
        """Read 2B ELV passport, status, 32 KB Data Flash (when direct CAN or bridge available), and live 02F9 MAC."""
        port, iface = self.conn.port, self.conn.interface
        via_gw = bool(ident.get("via_gateway", False))
        gw_br = bool(ident.get("gateway_bridge", ident.get("bridge_available", False)))
        gw_ch = 0 if ident.get("gateway_channel") is None else int(ident["gateway_channel"])
        caps = set(ident.get("capabilities") or ())
        read_df_on_open = (not via_gw) and (iface in BRIDGE_NATIVE_INTERFACES or "memory" in caps)

        ident_list = list(ident.get("ident") or [])
        elv_unit = unit_of_ident(ident_list)
        if elv_unit == "unknown":
            vals = {i.get("did"): i.get("value", "") for i in ident_list}
            pn = vals.get("F187") or vals.get("F191") or "3Q0905861"
            fz = vals.get("F17C") or "ELV"
            elv_unit = unit_name(pn, fz)
            if elv_unit == "unknown":
                elv_unit = "elv_3q0905861"
        s_dir = self._create_session_dir(elv_unit, "elv_dflash", dumps=True)
        if s_dir is None:
            return

        def task(rep: Any) -> dict[str, Any]:
            if read_df_on_open:
                res = can_elv_read_dflash(
                    port,
                    out_dir=s_dir,
                    interface=iface,
                    via_gateway=via_gw,
                    gateway_bridge=gw_br,
                    gateway_channel=gw_ch,
                    reporter=rep,
                )
            else:
                res = can_elv_status(
                    port,
                    interface=iface,
                    via_gateway=via_gw,
                    gateway_bridge=False,
                    gateway_channel=gw_ch,
                    reporter=rep,
                )
                s_dir.mkdir(parents=True, exist_ok=True)
                (s_dir / "elv_report.json").write_text(
                    json.dumps(res, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
            res["session_dir"] = str(s_dir)
            return res

        def done(res: dict[str, Any]) -> None:
            saved_dir = Path(str(res.get("session_dir") or s_dir))
            if saved_dir.is_dir():
                _remember_recent(saved_dir)
                self.start_screen.refresh_recent()
            self._active_screen = "elv"
            self.elv_screen.open_from_read_result(
                res,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
            )
            self._refresh_header()
            self._refresh_screen()

        self.runner.run_task(
            tr("Чтение данных 2B ELV", "Reading 2B ELV data"),
            task,
            on_success=done,
        )

    def _read_fpke_over_can(self, ident: dict[str, Any]) -> None:
        """Read Kombi FPK_E Extra Area + IDAUTH + DataFlash 64 KB over CAN, then open the dedicated Kombi screen."""
        port, iface = self.conn.port, self.conn.interface
        ident_list = list(ident.get("ident") or [])
        via_gw = bool(ident.get("via_gateway", False))
        gw_br = bool(ident.get("gateway_bridge", ident.get("bridge_available", False)))
        gw_ch = int(ident.get("gateway_channel") or 0)
        sdir = self._create_session_dir(unit_of_ident(ident_list), "fpke_read", dumps=True)
        if sdir is None:
            return

        def task(rep: Any) -> dict[str, Any]:
            res = can_fpke_full_read(
                port,
                interface=iface,
                session_dir=sdir,
                ident=ident_list,
                keep_open=not via_gw,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                reporter=rep,
            )
            res["session_dir"] = str(keep_as_base(sdir))
            return res

        def done(res: dict[str, Any]) -> None:
            folder = Path(str(res.get("session_dir", sdir)))
            detected = detect_fpke_files([folder])
            if self.ws.is_open and not self.bus_screen.has_scan:
                self.ws.close()
            self._active_screen = "fpke"
            self.fpke_screen.ident_items = ident_list
            self.fpke_screen.idauth_info = res.get("idauth")
            self.fpke_screen.open_from_files(
                detected,
                folder=folder,
                source="can",
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
            )
            self._refresh_header()
            self._refresh_screen()

        self.runner.run_task(
            tr("Чтение памяти блока", "Reading the ECU memory"),
            task,
            on_success=done,
        )

    def _read_kombi_over_can(self, ident: dict[str, Any]) -> None:
        """Read V850E2 17 Kombi VDD DataFlash (132 EEL records at SL 7) over CAN, then open KombiScreen."""
        port, iface = self.conn.port, self.conn.interface
        ident_list = list(ident.get("ident") or [])
        via_gw = bool(ident.get("via_gateway", False))
        gw_br = bool(ident.get("gateway_bridge", ident.get("bridge_available", False)))
        gw_ch = int(ident.get("gateway_channel") or 0)
        sdir = self._create_session_dir(unit_of_ident(ident_list), "kombi_read", dumps=True)
        if sdir is None:
            return

        def task(rep: Any) -> dict[str, Any]:
            res = can_kombi_full_read(
                port,
                interface=iface,
                session_dir=sdir,
                ident=ident_list,
                keep_open=not via_gw,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                reporter=rep,
            )
            res["session_dir"] = str(keep_as_base(sdir))
            return res

        def done(res: dict[str, Any]) -> None:
            folder = Path(str(res.get("session_dir", sdir)))
            detected = detect_kombi_files([folder])
            if self.ws.is_open and not self.bus_screen.has_scan:
                self.ws.close()
            self._active_screen = "kombi"
            self.kombi_screen.ident_items = ident_list
            self.kombi_screen.open_from_files(
                detected,
                folder=folder,
                source="can",
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
            )
            self._refresh_header()
            self._refresh_screen()

        self.runner.run_task(
            tr("Чтение EEL DataFlash 17 Kombi (SL 7)", "Reading 17 Kombi EEL DataFlash (SL 7)"),
            task,
            on_success=done,
        )

    def _backup_over_can(self, ident: dict[str, Any]) -> None:
        """Into the gateway's own dumps/ folder; its first complete read becomes its base_read (storage.py)."""
        port, iface = self.conn.port, self.conn.interface
        sdir = self._create_session_dir(unit_of_ident(ident.get("ident") or []), "read", dumps=True)
        if sdir is None:
            return

        def task(rep: Any) -> dict[str, Any]:
            res = can_backup(port, interface=iface, session_dir=sdir, reporter=rep)
            res["session_dir"] = str(keep_as_base(sdir))
            return res

        def done(res: dict[str, Any]) -> None:
            folder = Path(str(res.get("session_dir", sdir)))
            self._active_screen = "j533"
            self._report_missing(self.ws.open_folder(folder, source="can"), folder)
            area_warns = res.get("area_warnings")
            if isinstance(area_warns, dict) and area_warns:
                self.ws.read_warnings.update({k: str(v) for k, v in area_warns.items() if v})
                self.ws.changed.emit()
            self._refresh_header()
            self._refresh_screen()
            warns = [str(w) for w in (res.get("warnings") or []) if w]
            if warns:
                QTimer.singleShot(0, lambda w=warns: self._show_backup_warnings(w))

        self.runner.run_task(tr("Чтение памяти блока", "Reading the ECU memory"), task, on_success=done)

    def _show_backup_warnings(self, warnings: list[str]) -> None:
        QMessageBox.warning(
            self,
            tr("Предупреждение при чтении EEPROM / OPBT", "EEPROM / OPBT read warning"),
            tr(
                "CodeFlash, Uflash и DataFlash сохранены, но часть дополнительных областей не прочиталась:\n\n",
                "CodeFlash, Uflash, and DataFlash were saved, but optional areas could not be read:\n\n",
            )
            + "\n\n".join(f"• {w}" for w in warnings),
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

    def restore_backup(self, *, force_j533: bool = False) -> None:
        """Write backup files the user picks back into the ECU; the workflow refuses a backup of another ECU."""
        self.set_mode("ecu")  # frees the adapter if the terminal holds it
        force_j533 = force_j533 or bool(getattr(self, "_force_j533_restore", False))
        if not force_j533 and self._is_kombi_active():
            self.kombi_screen.restore_dflash_from_file()
            return
        if not force_j533 and self._is_fpke_active():
            self.fpke_screen.restore_dflash_from_file()
            return
        dlg = RestoreDialog(self, str(self.ws.folder or self.conn.out_dir))
        if not run_dialog(dlg) or not dlg.kinds or not ensure_ready(self.conn, self):
            return
        close_active_fpke_link()
        files, kinds = dict(dlg.files), dlg.kinds
        port, iface = self.conn.port, self.conn.interface
        cf = files.get("cflash")
        try:
            cf_bytes = cf.read_bytes() if cf else None
            sdir = new_session(self.conn.out_dir, unit_of_cflash(cf_bytes), "restore")
        except OSError as exc:
            QMessageBox.critical(self, tr("Ошибка чтения файла", "File read error"), str(exc))
            return
        names = ", ".join(NAMES[k] for k in kinds)
        self.runner.run_task(
            tr(f"Заливка бэкапа в блок: {names}", f"Writing the backup to the ECU: {names}"),
            lambda rep: can_restore_backup(port, files, kinds, interface=iface, session_dir=sdir, reporter=rep),
        )

    def _pick_next_active_screen(self) -> str:
        if self.kombi_screen.is_open and (self._last_cluster_screen == "kombi" or not self.fpke_screen.is_open):
            return "kombi"
        if self.fpke_screen.is_open:
            return "fpke"
        if self.kombi_screen.is_open:
            return "kombi"
        if self.ws.is_open:
            return "j533"
        if self.bcm_screen.is_open:
            return "bcm"
        if self.mrr_screen.is_open:
            return "mrr"
        if self.elv_screen.is_open:
            return "elv"
        if self.bus_screen.has_scan:
            return "bus"
        return "start"

    def close_ecu(self) -> None:
        if self.runner.is_busy:
            return
        if self._is_elv_active():
            self.elv_screen.close_elv()
            self._active_screen = self._pick_next_active_screen()
            self._refresh_header()
            self._refresh_screen()
            return
        if self._is_mrr_active():
            self.mrr_screen.close_mrr()
            self._active_screen = self._pick_next_active_screen()
            self._refresh_header()
            self._refresh_screen()
            return
        if self._is_bcm_active():
            self.bcm_screen.close_bcm()
            self._active_screen = self._pick_next_active_screen()
            self._refresh_header()
            self._refresh_screen()
            return
        if self._is_kombi_active():
            if self.kombi_screen.is_dflash_modified and QMessageBox.question(
                self,
                tr("Закрыть блок", "Close the ECU"),
                tr(
                    "Есть изменения DataFlash, не записанные в приборную панель. Изменённый дамп останется на диске.\n\nЗакрыть?",
                    "There are DataFlash changes that were not written to the cluster. The edited dump stays on disk.\n\nClose?",
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            ) != QMessageBox.StandardButton.Yes:
                return
            self.kombi_screen.close_kombi()
            self._active_screen = self._pick_next_active_screen()
            self._refresh_header()
            self._refresh_screen()
            return
        if self._is_fpke_active():
            if self.fpke_screen.is_cflash_dirty and QMessageBox.question(
                self,
                tr("Закрыть блок", "Close the ECU"),
                tr(
                    "Патч загрузчика в CodeFlash (Cflash.bin) ещё не сохранён на диск и будет потерян.\n\nЗакрыть без сохранения?",
                    "The patched CodeFlash (Cflash.bin) bootloader has not been saved to disk and will be lost.\n\nClose without saving?",
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            ) != QMessageBox.StandardButton.Yes:
                return
            if self.fpke_screen.is_dflash_modified and QMessageBox.question(
                self,
                tr("Закрыть блок", "Close the ECU"),
                tr(
                    "Есть изменения DataFlash, не записанные в приборную панель. Изменённый дамп останется на диске.\n\nЗакрыть?",
                    "There are DataFlash changes that were not written to the cluster. The edited dump stays on disk.\n\nClose?",
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            ) != QMessageBox.StandardButton.Yes:
                return
            self.fpke_screen.close_kombi()
            self._active_screen = self._pick_next_active_screen()
            self._refresh_header()
            self._refresh_screen()
            return
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
        self._active_screen = self._pick_next_active_screen()
        self._refresh_header()
        self._refresh_screen()

    # ────────────────────────────── dialogs ──────────────────────────────
    def show_connection(self) -> None:
        run_dialog(ConnectionDialog(self.conn, self))

    def show_guide(self) -> None:
        run_dialog(GuideDialog(self))

    def _on_operation_finished(self, ok: bool, _summary: str, _target: object) -> None:
        if self._quit_when_idle:
            return
        failure = self.runner.last_failure
        if ok or self.runner.was_cancelled or failure is None:
            return
        if "Stage1SilentError" in failure.traceback and failure.title not in CURE_TITLE:
            QTimer.singleShot(0, self.offer_fingerprint_cure)  # a known cause with a cure: no report needed
        else:
            self.offer_problem_report(failure)

    def offer_fingerprint_cure(self) -> None:
        """Stage 1 of the RAM-loader entry went silent: offer the cure, one UDS reprogram of this ECU's application."""
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle(tr("Вход в RAM-Loader закрыт", "RAM-Loader entry closed"))
        box.setText(tr(
            "В отпечатке программирования записан ненулевой серийник тестера — загрузчик блокирует вход в RAM-Loader.\n"
            "Исправляется одной прошивкой приложения по UDS с нулевым серийником (RAM-Loader не нужен).\n\n"
            "Выберите источник:\n"
            "• CodeFlash этого блока (бэкап, проверяется по FAZIT);\n"
            "• Файл FRF / ODX ODIS (прошивается с собственной подписью).\n\n"
            "Займёт несколько минут — не отключайте питание.",
            "The last programming fingerprint carries a non-zero tester serial, so the bootloader blocks RAM-Loader entry.\n"
            "One UDS application reflash with a zero serial fixes it (no RAM-Loader required).\n\n"
            "Choose a source:\n"
            "• This ECU's CodeFlash backup (verified against FAZIT);\n"
            "• An ODIS FRF / ODX file (flashed with its own signature).\n\n"
            "Takes a few minutes — keep power on.",
        ))
        from_cf = box.addButton(tr("CodeFlash этого блока…", "This ECU's CodeFlash…"), QMessageBox.ButtonRole.AcceptRole)
        from_frf = box.addButton(tr("Файл FRF / ODX…", "FRF / ODX file…"), QMessageBox.ButtonRole.ActionRole)
        box.addButton(tr("Отмена", "Cancel"), QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is from_frf:
            self.flash_frf()
            return
        if box.clickedButton() is not from_cf:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, tr("CodeFlash этого блока", "This ECU's CodeFlash"), str(self.ws.folder or self.conn.out_dir),
            "Binary (*.bin *.raw);;All Files (*)",
        )
        if not path or not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        try:
            sdir = new_session(self.conn.out_dir, unit_of_cflash(Path(path).read_bytes()), "fingerprint")
        except OSError as exc:
            QMessageBox.critical(self, tr("Ошибка чтения файла", "File read error"), str(exc))
            return
        self.runner.run_task(
            tr(*CURE_TITLE),
            lambda rep: can_cure_fbl_fingerprint(port, Path(path), interface=iface, session_dir=sdir, reporter=rep),
        )

    def flash_frf(self, path: str = "") -> None:
        """An ODIS FRF or plain ODX over UDS with its own signature (can_flash_frf): a software update on any
        bootloader, and the cure for a fingerprint that closed the RAM-loader entry, without a backup of the ECU."""
        self.set_mode("ecu")
        path = path or QFileDialog.getOpenFileName(
            self, tr("Файл прошивки ODIS (.frf / .odx)", "ODIS flash file (.frf / .odx)"), str(Path.home()),
            tr("Прошивка ODIS (*.frf *.odx);;Все файлы (*)", "ODIS flash file (*.frf *.odx);;All Files (*)"))[0]
        if not path:
            return
        try:
            frf = read_flash_file(Path(path).read_bytes(), Path(path).name)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, tr("Прошивка FRF / ODX", "FRF / ODX flash"), str(exc))
            return
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        self.runner.run_task(
            tr("Идентификация блока для FRF", "Identifying the ECU for the FRF"),
            lambda rep: can_identify(port, interface=iface, reporter=rep),
            # the runner is still busy inside on_success: ask once it has finished
            on_success=lambda ident: QTimer.singleShot(0, lambda: self._confirm_frf(frf, ident)),
        )

    def _confirm_frf(self, frf: FrfImage, ident: dict[str, Any]) -> None:
        vals = {i["did"]: str(i["value"]).strip() for i in ident.get("ident") or []}
        hard, soft = frf_ident_problems(frf, vals)
        head = tr(
            f"{frf.kind}: {frf.name} — {frf.part_number}, ПО {frf.sw_version}.\n"
            f"Блок: {vals.get('F187', '?')}, ПО {vals.get('F189', '?')}, оборудование {vals.get('F191', '?')} / "
            f"{vals.get('F1A3', '?')}.\n\n",
            f"{frf.kind}: {frf.name} — {frf.part_number}, software {frf.sw_version}.\n"
            f"ECU: {vals.get('F187', '?')}, software {vals.get('F189', '?')}, hardware {vals.get('F191', '?')} / "
            f"{vals.get('F1A3', '?')}.\n\n",
        )
        title = tr(f"Прошивка {frf.kind}", f"{frf.kind} flash")
        # the bootloader checks the signature with the key in CodeFlash (0xA2F7), which ContiTool can replace; the
        # engineering bootloader checks none. Both are known from this gateway's latest read or write, if any.
        unit_dir = self.conn.out_dir / unit_of_ident(ident.get("ident") or [])
        cf, uf = latest_area(unit_dir, "Cflash.bin"), latest_area(unit_dir, "Uflash.bin")
        try:
            fbl_modulus = cf.read_bytes()[FBL_MOD_OFFSET : FBL_MOD_OFFSET + 128] if cf else None
        except OSError:
            fbl_modulus = None
        try:
            fbl_open = bool(uf) and analyze_uflash(uf.read_bytes()).rsa_bypassed
        except (OSError, ValueError):
            fbl_open = False
        why = frf_signature_problem(frf, fbl_modulus=fbl_modulus, fbl_open=fbl_open)
        if why:
            src = tr(f"\n\nКлюч загрузчика взят из {cf}", f"\n\nBootloader key taken from {cf}") if cf else ""
            QMessageBox.critical(self, title, head + why + src)
            return
        if hard:
            QMessageBox.critical(self, title, head + tr(f"Этот {frf.kind} для другого оборудования: ",
                                                        f"This {frf.kind} is for other hardware: ") + "; ".join(hard) + ".")
            return
        text = head + tr(
            f"Приложение будет стёрто и записано заново по UDS с подписью из {frf.kind}, как это делает ODIS. "
            "Серийник тестера в отпечатке будет нулевым. Запись занимает несколько минут; не отключайте "
            "питание.",
            f"The application is erased and written again over UDS with the {frf.kind}'s own signature, as ODIS does "
            "it. The tester serial in the fingerprint will be zero. The write takes a few minutes; keep the "
            "power on.",
        )
        if soft:
            text += (tr(f"\n\n⚠ ODIS не стал бы лить этот {frf.kind} на этот блок: ",
                        f"\n\n⚠ ODIS would not flash this {frf.kind} onto this ECU: ")
                     + "; ".join(soft) + tr(". Прошивать всё равно?", ". Flash it anyway?"))
        else:
            text += tr("\n\nПрошить?", "\n\nFlash it?")
        if QMessageBox.question(self, title, text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        port, iface = self.conn.port, self.conn.interface
        try:
            sdir = new_session(self.conn.out_dir, unit_of_ident(ident.get("ident") or []), "frf")
        except OSError as exc:
            QMessageBox.critical(self, title, str(exc))
            return
        self.runner.run_task(
            tr(f"Прошивка {frf.name}", f"Flashing {frf.name}"),
            lambda rep: can_flash_frf(port, frf, interface=iface, session_dir=sdir, allow_unlisted=bool(soft),
                                      fbl_modulus=fbl_modulus, fbl_open=fbl_open, reporter=rep),
        )

    def report_problem(self) -> None:
        """Help menu: about the last failed operation, or everything since the last operation started."""
        since = self.runner.started_at or self._opened_at
        self.offer_problem_report(self.runner.last_failure or Failure(tr("Сообщение о проблеме", "Problem report"), "", started=since))

    def offer_problem_report(self, failure: Failure) -> None:
        """Non-blocking: the log and the screen stay usable while the offer is open; a newer failure replaces it."""
        if self._report_dlg is not None:
            self._report_dlg.close()
        if self._is_kombi_active():
            dumps: dict[str, Path] = {}
            orig_df = self.kombi_screen._orig_dflash_path
            if orig_df is not None and orig_df.is_file():
                dumps[f"loaded/{orig_df.name}"] = orig_df
            for kind, p in self.kombi_screen.files.items():
                if kind == "dflash" and orig_df is not None:
                    continue
                if p is not None and p.is_file():
                    dumps[f"loaded/{p.name}"] = p
            work_df = self.kombi_screen._working_dflash_path
            if self.kombi_screen.is_dflash_modified and work_df is not None and work_df.is_file():
                dumps[f"edited/{work_df.name}"] = work_df
        elif self._is_fpke_active():
            dumps = {}
            orig_df = self.fpke_screen._orig_dflash_path
            orig_cf = self.fpke_screen._orig_cflash_path
            if orig_df is not None and orig_df.is_file():
                dumps[f"loaded/{orig_df.name}"] = orig_df
            if orig_cf is not None and orig_cf.is_file():
                dumps[f"loaded/{orig_cf.name}"] = orig_cf
            for kind, p in self.fpke_screen.files.items():
                if (kind == "dflash" and orig_df is not None) or (kind == "cflash" and orig_cf is not None):
                    continue
                if p is not None and p.is_file():
                    dumps[f"loaded/{p.name}"] = p
            work_df = self.fpke_screen._working_dflash_path
            if self.fpke_screen.is_dflash_modified and work_df is not None and work_df.is_file():
                dumps[f"edited/{work_df.name}"] = work_df
            work_cf = self.fpke_screen._working_cflash_path
            if self.fpke_screen.is_cflash_modified and work_cf is not None and work_cf.is_file():
                dumps[f"edited/{work_cf.name}"] = work_cf
        elif self._is_bcm_active():
            dumps = {}
        elif self._is_mrr_active():
            dumps = {}
            mem_rep = self.mrr_screen._last_mem_report
            for reg in (mem_rep.get("regions") or []):
                if isinstance(reg, dict) and reg.get("file"):
                    p = Path(str(reg["file"]))
                    if p.is_file():
                        dumps[f"loaded/{p.name}"] = p
            s_dir_raw = mem_rep.get("session_dir")
            if s_dir_raw:
                s_dir_p = Path(str(s_dir_raw))
                if s_dir_p.is_dir():
                    for name in ("mrr_keys.json", "mrr_read_report.json", "Dflash.bin", "Cflash.bin"):
                        cand = s_dir_p / name
                        if cand.is_file():
                            dumps.setdefault(f"loaded/{cand.name}", cand)
        elif self._is_elv_active():
            dumps = {}
            df_path = self.elv_screen._dflash_path
            if df_path is not None and df_path.is_file():
                dumps[f"loaded/{df_path.name}"] = df_path
                for rep_name in ("elv_report.json", "elv_read_report.json", "elv_backup_report.json"):
                    rep_p = df_path.parent / rep_name
                    if rep_p.is_file():
                        dumps[f"loaded/{rep_p.name}"] = rep_p
            rep_path = getattr(self.elv_screen, "_report_path", None)
            if isinstance(rep_path, Path) and rep_path.is_file():
                dumps.setdefault(f"loaded/{rep_path.name}", rep_path)
        else:
            dumps = {f"loaded/{p.name}": p for p in self.ws.original.values()}
            dumps.update({f"edited/{p.name}": p for k, p in self.ws.current.items() if self.ws.modified(k)})
        dlg = ProblemReportDialog(self, failure, self.conn, self.console.txt_full.toPlainText(), dumps)
        dlg.setModal(False)
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dlg.destroyed.connect(lambda *_a, d=dlg: setattr(self, "_report_dlg", None) if self._report_dlg is d else None)
        self._report_dlg = dlg
        dlg.show()

    @staticmethod
    def _on_lang_picked(code: str) -> None:
        from PySide6.QtCore import QSettings

        chosen = set_lang(code)
        QSettings().setValue("ui/language", chosen)

    def show_settings(self) -> None:
        dlg = SettingsDialog(self)
        if not run_dialog(dlg):
            return
        if dlg.check_now_requested:
            self.updates.check(manual=True)
        elif dlg.selected_channel != dlg.initial_channel and getattr(sys, "frozen", False):
            self.updates.check(manual=False)

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            tr("О программе", "About"),
            tr(
                f"<b>ContiTool {__version__}</b><br>"
                "Сервисный инструмент для блоков VAG MQB: "
                "19 J533 (Gateway), 17 FPK_E / Kombi, 09 BCM, 13 ACC MRR, 2B ELV.<br><br>"
                f"{AUTHOR_CREDIT}<br>"
                f'<a href="{AUTHOR_SITE_URL}">{AUTHOR_SITE_SHORT}</a>&nbsp;&nbsp;|&nbsp;&nbsp;'
                f'<a href="{AUTHOR_DRIVE2_URL}">Drive2</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="{AUTHOR_TG_URL}">Telegram</a><br><br>'
                "<b>Поддержать автора:</b><br>"
                f'Telegram Tribute: <a href="{AUTHOR_DONATE_TRIBUTE_URL}">{AUTHOR_DONATE_TRIBUTE_URL}</a><br>'
                f"USDT (TON): <code>{AUTHOR_DONATE_USDT_TON}</code><br>"
                f"USDT (TRON / TRC20): <code>{AUTHOR_DONATE_USDT_TRC20}</code><br>"
                f"BTC (Bitcoin): <code>{AUTHOR_DONATE_BTC}</code><br><br>"
                "Бесплатный инструмент сообщества, не для продажи. Программа предоставляется «как есть», "
                "без каких-либо гарантий.",
                f"<b>ContiTool {__version__}</b><br>"
                "Service tool for VAG MQB control units: "
                "19 J533 (Gateway), 17 FPK_E / Kombi, 09 BCM, 13 ACC MRR, 2B ELV.<br><br>"
                f"{AUTHOR_CREDIT}<br>"
                f'<a href="{AUTHOR_SITE_URL}">{AUTHOR_SITE_SHORT}</a>&nbsp;&nbsp;|&nbsp;&nbsp;'
                f'<a href="{AUTHOR_DRIVE2_URL}">Drive2</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="{AUTHOR_TG_URL}">Telegram</a><br><br>'
                "<b>Support the author:</b><br>"
                f'Telegram Tribute: <a href="{AUTHOR_DONATE_TRIBUTE_URL}">{AUTHOR_DONATE_TRIBUTE_URL}</a><br>'
                f"USDT (TON): <code>{AUTHOR_DONATE_USDT_TON}</code><br>"
                f"USDT (TRON / TRC20): <code>{AUTHOR_DONATE_USDT_TRC20}</code><br>"
                f"BTC (Bitcoin): <code>{AUTHOR_DONATE_BTC}</code><br><br>"
                "Free community tool, not for sale. Provided “as is”, without warranty of any kind.",
            ),
        )

    def show_report(self) -> None:
        """Full offline analysis of every loaded dump, as plain text."""
        if self._is_kombi_active():
            self.kombi_screen.show_report()
            return
        if self._is_fpke_active():
            self.fpke_screen.show_report()
            return
        if not self.ws.is_open:
            return
        plain = Style(False)
        sections: list[str] = []
        cf_path = self.ws.path("cflash")
        try:
            cf_raw = cf_path.read_bytes() if cf_path is not None and cf_path.is_file() else None
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
                ("eeprom", lambda raw, p: format_eeprom_report(analyze_eeprom(raw, cf_raw), plain, p)),
                (
                    "opbt",
                    lambda raw, p: format_opbt_report(
                        analyze_opbt(raw, extra_idcode=self.ws.extra_idcode, chip_id=self.ws.chip_id),
                        plain,
                        p,
                    ),
                ),
            ):
                path = self.ws.path(kind)
                if path is not None:
                    sections.append(build(path.read_bytes(), str(path)))
        except OSError as exc:
            QMessageBox.warning(self, tr("Ошибка чтения дампа", "Dump read error"), str(exc))
            return
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
        self.act_scan.setText(tr("Сканировать шину CAN…", "Scan CAN bus…"))
        self.act_read.setText(tr("Считать блок по CAN", "Read the ECU over CAN"))
        self.act_folder.setText(tr("Открыть папку с дампами…", "Open dump folder…"))
        self.act_files.setText(tr("Открыть файлы…", "Open files…"))
        self.act_export.setText(tr("Экспортировать бэкап…", "Export backup…"))
        self.act_restore.setText(tr("Залить бэкап в блок…", "Write backup to ECU…"))
        self.act_frf.setText(tr("Прошить FRF / ODX ODIS…", "Flash an ODIS FRF / ODX…"))
        self.act_report.setText(tr("Подробный отчёт", "Full report"))
        self.act_close.setText(tr("Закрыть блок", "Close ECU"))
        self.act_conn.setText(tr("Подключение к блоку…", "ECU connection…"))
        self.act_settings.setText(tr("Настройки…", "Settings…"))
        self.btn_settings.setText(tr("Настройки", "Settings"))
        self.btn_settings.setToolTip(tr("Настройки программы и канал обновлений", "Application settings and update channel"))
        self.act_quit.setText(tr("Выход", "Quit"))
        self.menu_view.setTitle(tr("Вид", "View"))
        self.act_mode_bus.setText(tr("Шина CAN (топология)", "CAN Bus (topology)"))
        self.act_mode_ecu.setText(tr("Блок", "ECU"))
        self.act_mode_term.setText(tr("CAN-терминал", "CAN terminal"))
        self.act_log.setText(tr("Журнал операций", "Operation log"))
        self.menu_help.setTitle(tr("Справка", "Help"))
        self.act_guide.setText(tr("Памятка по стенду", "Bench guide"))
        self.act_problem.setText(tr("Сообщить о проблеме…", "Report a problem…"))
        self.act_updates.setText(tr("Проверить обновления…", "Check for updates…"))
        self.act_about.setText(tr("О программе", "About ContiTool"))
        self._refresh_header()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.runner.is_busy and self._quit_when_idle:
            event.ignore()
            return
        if not self._quit_when_idle and self.fpke_screen.is_open and self.fpke_screen.is_cflash_dirty:
            ans_cf = QMessageBox.question(
                self,
                tr("Несохранённый CodeFlash", "Unsaved CodeFlash"),
                tr(
                    "Патч загрузчика в CodeFlash (Cflash.bin) ещё не сохранён на диск и будет потерян.\n\nВыйти без сохранения?",
                    "The patched CodeFlash (Cflash.bin) bootloader has not been saved to disk and will be lost.\n\nQuit without saving?",
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if ans_cf != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
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
            if self.runner.is_busy:
                # the task closes its link and a flash write finishes first; a QThread destroyed while running aborts
                self._quit_when_idle = True
                self.runner.cancel_current()
                self.runner.busy_changed.connect(lambda busy: busy or QTimer.singleShot(0, self.close))
                self.console.note(tr("Программа закроется, как только операция остановится.",
                                     "ContiTool quits as soon as the operation stops."))
                event.ignore()
                return
        self._unsub()
        close_active_fpke_link()
        self.terminal.disconnect_bus()
        for session in list(self.terminal._closing):  # a QThread destroyed while running aborts the process
            session.wait()
        event.accept()


class EcuFoundDialog(Dialog):
    """The ECU that answered on CAN, before its memory is read."""

    def __init__(self, ident: dict[str, Any], conn: CanConnection, parent: QWidget | None = None) -> None:
        ecu_kind = str(ident.get("ecu_kind") or "")
        is_v850_kombi = ecu_kind == "kombi" or is_kombi_ident(ident.get("ident") or [])
        is_kombi = is_v850_kombi or ecu_kind == "fpke" or is_fpke_ident(ident.get("ident") or [])
        is_bcm = ecu_kind == "bcm"
        is_mrr = ecu_kind == "mrr"
        is_elv = ecu_kind == "elv" or is_elv_ident(ident.get("ident") or [])
        mem_unavail = str(ident.get("memory_unavailable_reason") or "")
        unsupported = str(ident.get("unsupported") or ("" if (is_kombi or is_bcm or is_mrr or is_elv) else (unsupported_ecu_reason(ident.get("ident", [])) or "")))
        if not unsupported and is_kombi and not is_v850_kombi and ident.get("via_gateway") and not ident.get("bridge_available") and mem_unavail:
            unsupported = mem_unavail
        in_fbl = bool(ident.get("in_fbl")) and not unsupported and not is_kombi and not is_bcm and not is_mrr and not is_elv
        self.unsupported = unsupported
        self.restore_chosen = False
        if unsupported:
            title = (
                tr("Чтение памяти недоступно", "Memory read unavailable")
                if (is_bcm or is_mrr or is_elv or (is_kombi and ident.get("via_gateway")))
                else tr("Блок не поддерживается", "Unsupported ECU")
            )
            if is_bcm:
                subtitle = tr(
                    f"На {conn.display()} ответил блок бортовой сети BCM (09).",
                    f"A BCM (09) control unit answered on {conn.display()}.",
                )
            elif is_mrr:
                subtitle = tr(
                    f"На {conn.display()} ответил радар ACC (13).",
                    f"An ACC Radar (13) control unit answered on {conn.display()}.",
                )
            elif is_elv:
                subtitle = tr(
                    f"На {conn.display()} ответил блокиратор руля ELV (2B).",
                    f"An ELV (2B) steering column lock answered on {conn.display()}.",
                )
            elif is_v850_kombi:
                subtitle = tr(
                    f"На {conn.display()} ответила приборная панель 17 Kombi VDD (V850E2).",
                    f"A 17 Kombi VDD (V850E2) instrument cluster answered on {conn.display()}.",
                )
            elif is_kombi:
                subtitle = tr(
                    f"На {conn.display()} ответила приборная панель Kombi FPK_E.",
                    f"A Kombi FPK_E instrument cluster answered on {conn.display()}.",
                )
            else:
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
        support_warning = str(ident.get("support_warning") or "")
        support_tone = str(ident.get("support_warning_tone") or "warn")
        if support_warning and not unsupported:
            sup_box = Callout(support_tone if support_tone in ("warn", "info") else "warn")
            sup_box.label.setText(support_warning)
            self.body.addWidget(sup_box)
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
                    "Приложение блока не запущено (например, после прерванной записи). Восстановить блок из бэкапа "
                    "можно кнопкой <b>«Залить бэкап в блок…»</b>.",
                    "The ECU's application is not running (after an interrupted write, for example). Restore it from "
                    "a backup with <b>“Write backup to ECU…”</b>.",
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
        elif is_v850_kombi:
            gw_hint = tr(
                "Будет получен доступ Supplier Level 7 (SL 7) и считаны все 132 блока EEL DataFlash "
                "(0x0001..0x0084: иммо WFS5, транспондеры, пробег, кодировка, ключи FD11) по штатному UDS 0x23. В память ничего не пишется.",
                "Supplier Level 7 (SL 7) will be established and all 132 EEL DataFlash records "
                "(0x0001..0x0084: WFS5 immo, transponders, odometer, coding, FD11 keys) will be read over standard UDS 0x23. Nothing is written to memory.",
            )
            self.body.addWidget(hint(gw_hint))
            self.btn_ok = button(tr("Считать блок (SL 7)", "Read ECU (SL 7)"), "PrimaryBtn", slot=self.accept)
            self.finish(ok=self.btn_ok)
        elif is_kombi:
            if ident.get("via_gateway"):
                gw_hint = tr(
                    "Через мост шлюза J533 будут считаны DataFlash (64 КБ) и Extra Area (IDCODE), "
                    "после чего шлюз вернётся в штатный режим.",
                    "DataFlash (64 KB) and Extra Area (IDCODE) will be read via the J533 gateway bridge, "
                    "then the gateway returns to normal mode.",
                )
            else:
                gw_hint = tr(
                    "Будут считаны DataFlash (64 КБ) и Extra Area (IDCODE). В память ничего не пишется.",
                    "DataFlash (64 KB) and Extra Area (IDCODE) will be read. Nothing is written to memory.",
                )
            self.body.addWidget(hint(gw_hint))
            self.btn_ok = button(tr("Считать блок", "Read the ECU"), "PrimaryBtn", slot=self.accept)
            self.finish(ok=self.btn_ok)
        elif is_mrr:
            via_gw = bool(ident.get("via_gateway", False))
            gw_br = bool(ident.get("gateway_bridge", ident.get("bridge_available", False)))
            caps = set(ident.get("capabilities") or ())
            xcp_ok = (not via_gw and (conn.interface in BRIDGE_NATIVE_INTERFACES or "memory" in caps)) or (via_gw and gw_br)
            if mem_unavail and not xcp_ok:
                info_box = Callout("info")
                info_box.label.setText(mem_unavail)
                self.body.addWidget(info_box)
            if xcp_ok:
                mrr_hint = tr(
                    "Будут считаны паспорт, статус CP, 7 контрольных точек Code Flash, дамп DFLASH0 (64 КиБ, ключи IKA/GFA) "
                    "и ошибки DTC. Если XcpGate (DID 0x0902 bit 3) закрыт, программа откроет его автоматически; Code Flash не изменяется.",
                    "Passport, CP status, 7 Code Flash CP sites, DFLASH0 (64 KiB, IKA/GFA keys), and DTCs will be read. "
                    "If XcpGate (DID 0x0902 bit 3) is closed, ContiTool opens it automatically; Code Flash is not modified.",
                )
            else:
                mrr_hint = tr(
                    "Будут считаны паспорт, статус защиты компонентов и ошибки DTC по UDS (в память ничего не пишется).",
                    "Passport, Component Protection status, and DTCs will be read over UDS (nothing is written to memory).",
                )
            self.body.addWidget(hint(mrr_hint))
            self.btn_ok = button(tr("Считать блок", "Read the ECU"), "PrimaryBtn", slot=self.accept)
            self.finish(ok=self.btn_ok)
        elif is_elv:
            via_gw = bool(ident.get("via_gateway", False))
            gw_br = bool(ident.get("gateway_bridge", ident.get("bridge_available", False)))
            caps = set(ident.get("capabilities") or ())
            df_ok = (not via_gw and (conn.interface in BRIDGE_NATIVE_INTERFACES or "memory" in caps)) or (via_gw and gw_br)
            if mem_unavail and not df_ok:
                info_box = Callout("info")
                info_box.label.setText(mem_unavail)
                self.body.addWidget(info_box)
            if df_ok and not via_gw:
                elv_hint = tr(
                    "Будут считаны паспорт, 32 КБ Data Flash (VIN, ключ иммо K_5, IDp/IDac, все 47 записей), "
                    "проверка ключа 22 02F9 и ошибки DTC. В память ничего не пишется.",
                    "Passport, 32 KB Data Flash (VIN, immo key K_5, IDp/IDac, all 47 records), "
                    "22 02F9 key check, and DTCs will be read. Nothing is written to memory.",
                )
            elif df_ok:
                elv_hint = tr(
                    "Сначала будут считаны паспорт, статус WFS5 и ошибки DTC по UDS (в память ничего не пишется). "
                    "Чтение 32 КБ Data Flash через мост шлюза 3Q0 доступно в рабочем окне 2B ELV.",
                    "Passport, WFS5 status, and DTCs will be read over UDS first (nothing is written). "
                    "Reading 32 KB Data Flash via the 3Q0 gateway bridge is available inside the 2B ELV workspace.",
                )
            elif via_gw:
                elv_hint = tr(
                    "Через этот шлюз доступны только статус, ошибки DTC и привязка с известным ключом по UDS "
                    "(в память ничего не пишется). Для чтения 32 КБ Data Flash нужно прямое подключение к CAN или шлюз 3Q0 с мостом.",
                    "Through this gateway, only UDS status, DTCs, and adaptation with a known key are available "
                    "(nothing is written). Reading 32 KB Data Flash needs direct CAN or a 3Q0 bridge.",
                )
            else:
                elv_hint = tr(
                    "С этим адаптером доступны только статус, ошибки DTC и привязка с известным ключом по UDS "
                    "(в память ничего не пишется). Для чтения 32 КБ Data Flash нужен нативный CAN-адаптер "
                    "(CANable / SLCAN / PCAN / Kvaser / Vector).",
                    "With this adapter, only UDS status, DTCs, and adaptation with a known key are available "
                    "(nothing is written). Reading 32 KB Data Flash needs a native CAN adapter "
                    "(CANable / SLCAN / PCAN / Kvaser / Vector).",
                )
            self.body.addWidget(hint(elv_hint))
            self.btn_ok = button(tr("Считать блок", "Read the ECU"), "PrimaryBtn", slot=self.accept)
            self.finish(ok=self.btn_ok)
        elif is_bcm:
            if mem_unavail:
                info_box = Callout("info")
                info_box.label.setText(mem_unavail)
                self.body.addWidget(info_box)
            self.body.addWidget(
                hint(
                    tr(
                        "Будут считаны паспорт, статус защиты компонентов и ошибки DTC по UDS "
                        "(в память ничего не пишется).",
                        "Passport, Component Protection status, and DTCs will be read over UDS "
                        "(nothing is written to memory).",
                    )
                )
            )
            self.btn_ok = button(tr("Считать блок", "Read the ECU"), "PrimaryBtn", slot=self.accept)
            self.finish(ok=self.btn_ok)
        else:
            self.body.addWidget(
                hint(
                    tr(
                        "Будет снята полная копия памяти (CodeFlash, Uflash, DataFlash, EEPROM, OPBT — около 1,5 мин). "
                        "В память ничего не пишется.",
                        "A full memory backup will be read (CodeFlash, Uflash, DataFlash, EEPROM, OPBT — ~1.5 min). "
                        "Nothing is written to memory.",
                    )
                )
            )
            self.btn_ok = button(tr("Считать блок", "Read the ECU"), "PrimaryBtn", slot=self.accept)
            self.finish(ok=self.btn_ok)

    def _choose_restore(self) -> None:
        self.restore_chosen = True
        self.accept()
