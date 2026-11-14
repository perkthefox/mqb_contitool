"""The working screen for one gateway: its identity, a list of functions with the selected one explained on
the right, and a panel saying which dumps changed and how each of them gets back into the ECU."""

from __future__ import annotations

from pathlib import Path
import shutil
import time
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFontMetrics
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from contitool.can import (
    can_activate_swap,
    can_health_check,
    can_learn_mfl_button,
    can_read_eeprom,
    can_read_gateway_coding,
    can_read_opbt,
    can_swap_status,
    can_upload_zdc_datasets,
    can_sync_zdc_coding,
    can_write_cflash,
    can_write_dflash,
    can_write_uflash,
)
from contitool.cli.formatting import Style, format_eeprom_report, format_opbt_report
from contitool.core import (
    CFLASH_SIZE,
    FpaDataset,
    MFL_KEYCODE_PRESETS,
    STOCK_FBL_MODULUS,
    STOCK_SWAP_MODULUS,
    UNSUPPORTED_DATASET_RU,
    UNSUPPORTED_DATASET_WARNING,
    ZDC_UDS_UPLOAD_MAP,
    ZdcAutoParamConfig,
    analyze_eeprom,
    analyze_opbt,
    apply_cflash_rsa_modulus,
    apply_dflash_swap_fecs,
    apply_dflash_swap_rsa_modulus,
    apply_engineering_patch,
    apply_odis_zdc_file,
    bind_cp_turnkey,
    build_odis_zdc_file,
    build_signed_fsc,
    chip_id_lot_ascii,
    clear_dflash_slots,
    export_zdc_block,
    fecs_required_by_dataset,
    format_chip_id,
    format_idcode,
    generate_rsa1024_e3_keypair,
    load_rsa1024_key_material,
    parameterize_dflash_for_fecs,
    populated_zdc_blocks,
    parse_bem_block,
    parse_mke_block,
    parse_odis_zdc_file,
    parse_ssa_block,
    parse_zdc_passport,
    save_rsa1024_keypair_bundle,
    sign_fbl_odx_application,
    split_cflash_or_app,
    sync_gateway_coding_for_zdc,
)
from contitool.core import dtc
from contitool.core.constants import DFLASH_FSC_BASE_OFF, DFLASH_FSC_STRIDE, DFLASH_SWAP_NVM_OFF, FBL_MOD_OFFSET, ZDC_DATASET_SPECS
from contitool.gui.connection import CanConnection, PathLabel, ensure_ready
from contitool.gui.dialogs.cp import CpBindDialog
from contitool.gui.dialogs.crypto import FscDialog, OdxSignDialog, RsaKeyDialog, SwapActivateDialog
from contitool.gui.dialogs.zdc import (
    BemEditorDialog,
    FpaEditorDialog,
    MkeEditorDialog,
    SsaEditorDialog,
    ZdcPassportBlocksDialog,
)
from contitool.gui.screens import status
from contitool.gui.screens.status import State
from contitool.gui import theme
from contitool.gui.theme import mono_font, set_tone
from contitool.gui.widgets.page import (
    Callout,
    TextResultDialog,
    button,
    clear_layout,
    divider,
    group_label,
    hint,
    pill,
    row,
    run_dialog,
    set_pill,
    status_readout,
    vdivider,
)
from contitool.gui.worker import OperationRunner
from contitool.gui.workspace import CANDIDATES, KINDS, NAMES, OPTIONAL_KINDS, Workspace
from contitool.storage import AREA_FILES, changed_ranges, has_full_read, new_session, record_flashed, unit_of_cflash
from contitool.i18n import subscribe_lang_change, tr

GROUPS = (("main", ("cp", "eng", "swap", "zdc", "dtc")), ("service", ("boot", "hw")))


def _restart_note() -> str:
    """After a dataset change: the gateway restarts itself, the other modules (the head unit above all) do not."""
    return tr(
        "Чтобы изменения датасета вступили в силу во всех блоках, перезапустите их: на автомобиле выключите и снова "
        "включите зажигание, на столе отключите питание на несколько секунд. Если магнитола продолжает показывать "
        "старый список режимов движения, перезагрузите её: удерживайте кнопку питания около 10 секунд.",
        "For the dataset changes to take effect in every module, restart them: in a car switch the ignition off and "
        "on again; on the bench cut the power for a few seconds. If the head unit still shows the old list of driving "
        "modes, restart it by holding its power button for about 10 seconds.",
    )


def _title(key: str) -> str:
    return {
        "cp": tr("Адаптация IKA/CP", "IKA/CP adaptation"),
        "eng": tr("Расширенная диагностика", "Extended diagnostics"),
        "swap": tr("Активация SWaP/FEC", "SWaP/FEC activation"),
        "zdc": tr("Параметрирование", "Parameterization"),
        "dtc": tr("Регистратор DTC", "DTC memory"),
        "boot": tr("Загрузчик и подпись", "Bootloader & signing"),
        "hw": tr("EEPROM и OPBT", "EEPROM & OPBT"),
    }[key]


class _NavRow(QWidget):
    """Function name on the left with quiet semantic status text on the right."""

    def __init__(self) -> None:
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 0, 10, 0)
        lay.setSpacing(8)
        self.lbl_name = QLabel()
        self.pill = pill()
        lay.addWidget(self.lbl_name, 1)
        lay.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_active(self, active: bool) -> None:
        f = self.lbl_name.font()
        f.setWeight(f.Weight.DemiBold if active else f.Weight.Normal)
        self.lbl_name.setFont(f)
        self.lbl_name.setStyleSheet(f"color: {'#FFFFFF' if active else theme.TEXT};")


class EcuScreen(QWidget):
    """Identity card, function list + page, and the changed-dumps panel for the open gateway."""

    report_requested = Signal()
    restore_requested = Signal()
    close_requested = Signal()
    terminal_requested = Signal(str)  # a UDS request to open in the CAN terminal
    note = Signal(str)  # a line for the log

    def __init__(
        self,
        ws: Workspace,
        conn: CanConnection,
        runner: OperationRunner,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.ws = ws
        self.conn = conn
        self.runner = runner
        self._key = "cp"
        self._dtc: list[dict[str, Any]] | None = None
        self._show_untested = False
        self._dtc_at = ""
        self._swap_live: list[dict[str, Any]] | None = None  # last UDS 22 3C 00 answer
        self._swap_at = ""
        self._key_file: Path | None = None  # last key generated or picked, offered again when signing
        self._folder: Path | None = None  # the gateway the three above belong to
        self.actions: dict[str, QPushButton] = {}  # buttons of the page on screen

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_identity())
        split = QHBoxLayout()
        split.setContentsMargins(0, 0, 0, 0)
        split.setSpacing(0)
        split.addWidget(self._build_nav())
        split.addWidget(self._build_page_area(), 1)
        outer.addLayout(split, 1)
        self.changes = self._build_changes()
        outer.addWidget(self.changes)

        ws.changed.connect(self._on_workspace_changed)
        conn.changed.connect(self.refresh)
        runner.busy_changed.connect(lambda _b: self.refresh())
        self._unsub = subscribe_lang_change(lambda _l: self.refresh())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.refresh()

    # ────────────────────────────── layout ──────────────────────────────
    def _build_identity(self) -> QWidget:
        self.sec_id = QFrame()
        self.sec_id.setObjectName("IdentityBar")
        body = QVBoxLayout(self.sec_id)
        body.setContentsMargins(24, 12, 24, 12)
        body.setSpacing(10)

        head = QHBoxLayout()
        head.setSpacing(10)
        self.lbl_pn = QLabel()
        self.lbl_pn.setObjectName("PartNumber")
        self.lbl_pn.setFont(mono_font(20, bold=True))
        self.lbl_pn.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_sys = QLabel()
        self.lbl_sys.setObjectName("Hint")
        self.sep_source = vdivider()
        self.sep_source.setFixedHeight(14)
        self.pill_source = QLabel()
        self.pill_source.setObjectName("Hint")
        self.lbl_folder = PathLabel()
        self.lbl_folder.setObjectName("Hint")
        self.lbl_folder.setFont(mono_font(12))
        head.addWidget(self.lbl_pn, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.lbl_sys, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.sep_source, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.pill_source, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.lbl_folder, 1, Qt.AlignmentFlag.AlignVCenter)
        head.addSpacing(8)

        self.btn_export = button("", slot=self.export_backup)
        self.btn_restore = button("", slot=self.restore_requested.emit)
        self.btn_report = button("", slot=self.report_requested.emit)
        self.btn_close = button("", "GhostBtn", slot=self.close_requested.emit)
        for b in (self.btn_export, self.btn_restore, self.btn_report, self.btn_close):
            b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            head.addWidget(b)
        body.addLayout(head)

        body.addWidget(divider())

        self.grid_id = QGridLayout()
        self.grid_id.setHorizontalSpacing(22)
        self.grid_id.setVerticalSpacing(2)
        body.addLayout(self.grid_id)

        self.grid_mcu_id = QGridLayout()
        self.grid_mcu_id.setContentsMargins(0, 0, 0, 0)
        self.grid_mcu_id.setHorizontalSpacing(28)
        self.grid_mcu_id.setVerticalSpacing(2)
        body.addLayout(self.grid_mcu_id)
        return self.sec_id

    def _build_nav(self) -> QWidget:
        pane = QFrame()
        pane.setObjectName("NavPane")
        pane.setFixedWidth(306)
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(6, 6, 6, 0)
        lay.setSpacing(0)
        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        self.nav_rows: dict[str, _NavRow] = {}
        self._nav_items: dict[str, QListWidgetItem] = {}
        self._group_labels: dict[str, QLabel] = {}
        for group, keys in GROUPS:
            head = QListWidgetItem(self.nav)
            head.setFlags(Qt.ItemFlag.NoItemFlags)
            head.setSizeHint(QSize(0, 26))
            lbl = group_label()
            lbl.setContentsMargins(12, 8, 0, 0)
            self.nav.setItemWidget(head, lbl)
            self._group_labels[group] = lbl
            for key in keys:
                item = QListWidgetItem(self.nav)
                item.setData(Qt.ItemDataRole.UserRole, key)
                item.setSizeHint(QSize(0, 33))
                nav_row = _NavRow()
                self.nav.setItemWidget(item, nav_row)
                self.nav_rows[key] = nav_row
                self._nav_items[key] = item
        self.nav.currentItemChanged.connect(self._on_nav)
        lay.addWidget(self.nav, 1)

        self.nav_dumps = QFrame()
        self.nav_dumps.setObjectName("NavDumps")
        nd_lay = QVBoxLayout(self.nav_dumps)
        nd_lay.setContentsMargins(16, 10, 16, 12)
        nd_lay.setSpacing(4)
        self.lbl_dumps_hdr = group_label()
        nd_lay.addWidget(self.lbl_dumps_hdr)
        self.dumps_list = QVBoxLayout()
        self.dumps_list.setContentsMargins(0, 1, 0, 0)
        self.dumps_list.setSpacing(3)
        nd_lay.addLayout(self.dumps_list)
        lay.addWidget(self.nav_dumps)
        return pane

    def _build_page_area(self) -> QWidget:
        self.page_area = QScrollArea()
        self.page_area.setWidgetResizable(True)
        self.page_area.setFrameShape(QFrame.Shape.NoFrame)
        self.page_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        return self.page_area

    def _build_changes(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("WriteBar")
        lay = QVBoxLayout(bar)
        lay.setContentsMargins(24, 10, 24, 10)
        lay.setSpacing(6)
        top = QHBoxLayout()
        top.setSpacing(8)
        self.lbl_changes = QLabel()
        self.lbl_changes.setObjectName("FieldLabel")
        top.addWidget(self.lbl_changes)
        top.addStretch(1)
        self.btn_revert = button("", "GhostBtn", slot=self._revert)
        self.btn_save = button("", slot=self._save_dumps)
        self.btn_write = button("", "PrimaryBtn", slot=self._write_pending)
        self.btn_write_df = button("", slot=self._write_to_ecu)  # dataset-only edits: the RAM-Loader way
        for b in (self.btn_revert, self.btn_save, self.btn_write_df, self.btn_write):
            top.addWidget(b)
        lay.addLayout(top)
        self.grid_changes = QGridLayout()
        self.grid_changes.setHorizontalSpacing(16)
        self.grid_changes.setVerticalSpacing(3)
        lay.addLayout(self.grid_changes)
        bar.setVisible(False)
        return bar

    # ────────────────────────────── state ──────────────────────────────
    def _on_workspace_changed(self) -> None:
        if self.ws.folder != self._folder:  # another ECU (or none): forget what belonged to the last one
            self._folder = self.ws.folder
            self._dtc, self._key_file, self._swap_live = None, None, None
        self.refresh()

    def _here(self, fn: Any) -> Any:
        """`fn` as on_success of a task on the open ECU: dropped if another one (or none) is open when it ends."""
        folder = self.ws.folder
        return lambda res: fn(res) if self.ws.folder == folder else None

    def refresh(self) -> None:
        if not self.ws.is_open:
            return
        self._refresh_identity()
        self._refresh_nav()
        self._render_page()
        self._refresh_changes()

    def select(self, key: str) -> None:
        self.nav.setCurrentItem(self._nav_items[key])

    def _on_nav(self, item: QListWidgetItem | None, _prev: QListWidgetItem | None) -> None:
        key = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if key:
            self._key = key
            for k, nav_row in self.nav_rows.items():
                nav_row.set_active(k == key)
            self._render_page()

    @staticmethod
    def _fmt_dump_size(path: Path) -> str:
        try:
            n = path.stat().st_size
        except OSError:
            return "—"
        if n >= 1024 * 1024 and n % (512 * 1024) == 0:
            return f"{n / (1024 * 1024):.1f} MB"
        if n >= 1024:
            return f"{n // 1024} KB"
        return f"{n} B"

    @staticmethod
    def _dump_ledger_row(name: str, val: str, tone: str = "muted", tip: str = "") -> QWidget:
        w = QWidget()
        if tip:
            w.setToolTip(tip)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        lbl_n = QLabel(name)
        lbl_n.setObjectName("Hint")
        if tone == "muted":
            set_tone(lbl_n, "muted")
        lbl_v = QLabel(val)
        lbl_v.setFont(mono_font(11))
        set_tone(lbl_v, tone if tone in ("warn", "err", "info") else "muted")
        lay.addWidget(lbl_n, 1)
        lay.addWidget(lbl_v, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return w

    def _refresh_identity(self) -> None:
        self.lbl_pn.setText(self.ws.part_number or tr("Блок не определён", "Unknown ECU"))
        cf_inf = self.ws.info("cflash")
        sys_name = (cf_inf.cflash_info.system_name if (cf_inf and cf_inf.cflash_info) else "").strip()
        self.lbl_sys.setText(sys_name)
        self.lbl_sys.setVisible(bool(sys_name))
        folder = self.ws.folder
        is_can = self.ws.source == "can"
        self.pill_source.setVisible(is_can or not folder)
        self.pill_source.setText(
            tr("Считан по CAN", "Read over CAN") if is_can else tr("Открыт из файлов", "Opened from files")
        )
        set_tone(self.pill_source, "info" if is_can else "muted")
        self.lbl_folder.setVisible(bool(folder))
        if folder:
            self.lbl_folder.set_path(folder.name)
            self.lbl_folder.setToolTip(str(folder))
        else:
            self.lbl_folder.set_path("")
        self.btn_export.setText(tr("Экспорт бэкапа…", "Export backup…"))
        self.btn_export.setToolTip(tr("Копирует дампы в том виде, как они считаны, в выбранную папку", "Copies the dumps as read to a folder you pick"))
        self.btn_restore.setText(tr("Залить бэкап…", "Write backup…"))
        self.btn_restore.setEnabled(not self.runner.is_busy)
        self.btn_report.setText(tr("Подробный отчёт", "Full report"))
        self.btn_close.setText(tr("Закрыть", "Close"))

        clear_layout(self.grid_id)
        clear_layout(self.grid_mcu_id)
        for c in range(12):
            self.grid_id.setColumnStretch(c, 0)
        for c in range(4):
            self.grid_mcu_id.setColumnStretch(c, 0)
        rows = status.passport_rows(self.ws)
        top_rows = [r for r in rows if r[0] not in ("IDCODE", "CHIP ID")]
        mcu_rows = [r for r in rows if r[0] in ("IDCODE", "CHIP ID")]
        for col, (label, value, tone) in enumerate(top_rows):
            cap = QLabel(label.upper())
            cap.setObjectName("GroupLabel")
            val = QLabel(value)
            val.setFont(mono_font(12))
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if tone != "muted":
                set_tone(val, tone)
            self.grid_id.addWidget(cap, 0, col)
            self.grid_id.addWidget(val, 1, col)
        self.grid_id.setColumnStretch(len(top_rows), 1)

        self.grid_mcu_id.setContentsMargins(0, 6 if (top_rows and mcu_rows) else 0, 0, 0)
        for col, (label, value, tone) in enumerate(mcu_rows):
            cap = QLabel(label.upper())
            cap.setObjectName("GroupLabel")
            val = QLabel(value)
            val.setFont(mono_font(11))
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if tone != "muted":
                set_tone(val, tone)
            self.grid_mcu_id.addWidget(cap, 0, col)
            self.grid_mcu_id.addWidget(val, 1, col)
        self.grid_mcu_id.setColumnStretch(len(mcu_rows), 1)

        self.lbl_dumps_hdr.setText(tr("ФАЙЛЫ ПАМЯТИ", "MEMORY DUMPS"))
        clear_layout(self.dumps_list)
        for k in KINDS:
            p_k = self.ws.path(k)
            if p_k is not None:
                self.dumps_list.addWidget(self._dump_ledger_row(NAMES[k], self._fmt_dump_size(p_k), "ok", str(p_k)))
            else:
                self.dumps_list.addWidget(
                    self._dump_ledger_row(NAMES[k], tr("нет", "missing"), "warn", tr("Файла нет в папке", "Not in the folder"))
                )
        for k in OPTIONAL_KINDS:
            p_opt = self.ws.path(k)
            if p_opt is not None:
                self.dumps_list.addWidget(self._dump_ledger_row(NAMES[k], self._fmt_dump_size(p_opt), "ok", str(p_opt)))
            elif k in self.ws.read_warnings:
                self.dumps_list.addWidget(
                    self._dump_ledger_row(NAMES[k], tr("сбой", "warning"), "warn", self.ws.read_warnings[k])
                )

    def _state(self, key: str) -> State:
        if key == "cp":
            return status.component_protection(self.ws)
        if key == "eng":
            return status.engineering(self.ws)
        if key == "swap":
            return status.swap_features(self.ws)
        if key == "zdc":
            return status.parameterization(self.ws)
        if key == "boot":
            return status.bootloader(self.ws)
        if key == "hw":
            return status.hardware_extras(self.ws)
        if self._dtc is None:
            return State(tr("по запросу", "on request"), "muted")
        groups = self._dtc_groups()
        if groups["active"]:
            return State(tr(f"активных: {len(groups['active'])}", f"{len(groups['active'])} active"), "err")
        if groups["stored"]:
            return State(tr(f"сохранено: {len(groups['stored'])}", f"{len(groups['stored'])} stored"), "warn")
        return State(tr("нет ошибок", "none"), "ok")

    def _dtc_groups(self) -> dict[str, list[tuple[int, int]]]:
        """(code, status) of the last read, split into active / stored / untested."""
        groups: dict[str, list[tuple[int, int]]] = {"active": [], "stored": [], "untested": []}
        for r in self._dtc or []:
            code, st = int(str(r.get("dtc", "0")), 16), int(str(r.get("status", "0")), 16)
            groups[dtc.group(st)].append((code, st))
        return groups

    def _refresh_nav(self) -> None:
        self._group_labels["main"].setText(tr("ФУНКЦИИ", "FUNCTIONS"))
        self._group_labels["service"].setText(tr("СЕРВИС", "SERVICE"))
        for key, nav_row in self.nav_rows.items():
            st = self._state(key)
            nav_row.lbl_name.setText(_title(key))
            nav_row.set_active(key == self._key)
            set_pill(nav_row.pill, st.text, st.tone)
        if self.nav.currentItem() is not self._nav_items[self._key]:
            self.nav.setCurrentItem(self._nav_items[self._key])

    # ────────────────────────────── page building blocks ──────────────────────────────
    def _render_page(self) -> None:
        if not self.ws.is_open:
            return
        page = QWidget()
        page.setObjectName("PageCanvas")
        outer = QHBoxLayout(page)
        outer.setContentsMargins(28, 20, 28, 24)
        outer.setSpacing(0)
        column = QWidget()
        column.setMaximumWidth(960)
        lay = QVBoxLayout(column)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        self.actions = {}
        pages = {
            "cp": self._page_cp,
            "eng": self._page_eng,
            "swap": self._page_swap,
            "zdc": self._page_zdc,
            "dtc": self._page_dtc,
            "boot": self._page_boot,
            "hw": self._page_hw,
        }
        pages[self._key](lay)
        lay.addStretch(1)
        outer.addWidget(column, 1)
        outer.addStretch(0)
        self.page_area.setWidget(page)  # the scroll area deletes the previous page

    def _head(self, lay: QVBoxLayout, key: str) -> State:
        st = self._state(key)
        h = QHBoxLayout()
        h.setSpacing(12)
        t = QLabel(_title(key))
        t.setObjectName("PageTitle")
        h.addWidget(t)
        h.addStretch(1)
        h.addWidget(status_readout(st.text, st.tone), 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addLayout(h)
        return st

    @staticmethod
    def _label(text: str, *, primary: bool = False) -> QLabel:
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        if not primary:
            lbl.setObjectName("Hint")
        return lbl

    def _text(self, lay: QVBoxLayout, text: str, *, primary: bool = False) -> QLabel:
        lbl = self._label(text, primary=primary)
        lay.addWidget(lbl)
        return lbl

    def _btn(self, key: str, text: str, slot: Any, kind: str = "", enabled: bool = True, tip: str = "") -> QPushButton:
        b = button(text, kind, slot=slot)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.setEnabled(enabled and not self.runner.is_busy)
        b.setToolTip(tip)
        self.actions[key] = b
        return b

    def _block(
        self, lay: QVBoxLayout, title: str, state: State | None, text: str, *btns: QPushButton, num: str = ""
    ) -> None:
        """Unified single-surface architectural card: aligned right status readout, inline action (1 btn) or bottom row (2+ btns)."""
        frame = QFrame()
        frame.setObjectName("Step")
        outer = QVBoxLayout(frame)
        outer.setContentsMargins(18, 15, 18, 16)
        outer.setSpacing(7)

        h = QHBoxLayout()
        h.setSpacing(9)
        if num:
            n = QLabel(num)
            n.setObjectName("StepNum")
            n.setFixedSize(20, 20)
            n.setAlignment(Qt.AlignmentFlag.AlignCenter)
            h.addWidget(n, 0, Qt.AlignmentFlag.AlignVCenter)
        t = QLabel(title)
        t.setObjectName("FieldLabel")
        h.addWidget(t)
        h.addStretch(1)
        if state is not None:
            h.addWidget(status_readout(state.text, state.tone), 0, Qt.AlignmentFlag.AlignVCenter)
        outer.addLayout(h)

        if len(btns) == 1 and not num and text:
            row_lay = QHBoxLayout()
            row_lay.setSpacing(20)
            row_lay.addWidget(self._label(text), 1)
            btns[0].setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            row_lay.addWidget(btns[0], 0, Qt.AlignmentFlag.AlignVCenter)
            outer.addLayout(row_lay)
        else:
            if text:
                outer.addWidget(self._label(text))
            if btns:
                outer.addSpacing(3)
                f_lay = QHBoxLayout()
                f_lay.setSpacing(8)
                for b in btns:
                    f_lay.addWidget(b)
                f_lay.addStretch(1)
                outer.addLayout(f_lay)
        lay.addWidget(frame)

    @staticmethod
    def _table(lay: QVBoxLayout, title: str, rows: list[tuple[str, ...]], muted: bool = False) -> None:
        """Clean single-surface inspector table with subtle hairline dividers."""
        frame = QFrame()
        frame.setObjectName("Step")
        outer = QVBoxLayout(frame)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        hdr = QFrame()
        hdr.setObjectName("TableHead")
        h = QHBoxLayout(hdr)
        h.setContentsMargins(18, 10, 18, 8)
        h.setSpacing(8)
        h.addWidget(group_label(title.upper()))
        h.addStretch(1)
        cnt = QLabel(str(len(rows)))
        cnt.setFont(mono_font(11))
        cnt.setObjectName("Hint")
        h.addWidget(cnt)
        outer.addWidget(hdr)

        col0_font = mono_font(12)
        fm = QFontMetrics(col0_font)
        col0_w = min(max((fm.horizontalAdvance(c[0]) for c in rows if c), default=100) + 14, 240)
        col0_w = max(col0_w, 125)

        for idx, cells in enumerate(rows):
            r_frame = QFrame()
            r_frame.setObjectName("TableRow")
            if idx == len(rows) - 1:
                r_frame.setProperty("last", True)
            rl = QHBoxLayout(r_frame)
            rl.setContentsMargins(18, 7, 18, 7)
            rl.setSpacing(16)

            lbl0 = QLabel(cells[0] if cells else "")
            lbl0.setFont(col0_font)
            lbl0.setFixedWidth(col0_w)
            lbl0.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if muted:
                lbl0.setObjectName("Hint")
            rl.addWidget(lbl0, 0, Qt.AlignmentFlag.AlignTop)

            lbl1 = QLabel(cells[1] if len(cells) > 1 else "")
            lbl1.setWordWrap(True)
            lbl1.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if muted:
                lbl1.setObjectName("Hint")
            rl.addWidget(lbl1, 1)

            if len(cells) > 2 and cells[2]:
                lbl2 = QLabel(cells[2])
                lbl2.setFont(mono_font(11))
                lbl2.setObjectName("Hint")
                lbl2.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
                rl.addWidget(lbl2, 0, Qt.AlignmentFlag.AlignTop)
            outer.addWidget(r_frame)
        lay.addWidget(frame)

    @staticmethod
    def _note(lay: QVBoxLayout, text: str, tone: str = "info") -> None:
        c = Callout(tone)
        c.label.setTextFormat(Qt.TextFormat.PlainText)
        c.label.setText(text)
        lay.addWidget(c)

    def _need(self, *kinds: str) -> tuple[bool, str]:
        missing = [NAMES[k] for k in kinds if self.ws.path(k) is None]
        if not missing:
            return True, ""
        return False, tr(f"Нужен дамп: {', '.join(missing)}", f"Requires the dump: {', '.join(missing)}")

    # ────────────────────────────── pages ──────────────────────────────
    def _page_cp(self, lay: QVBoxLayout) -> None:
        st = self._head(lay, "cp")
        self._text(
            lay,
            tr(
                "Component Protection: модули (магнитола, приборная панель, усилитель и др.) сверяют через шлюз, "
                "что установлены в своём автомобиле. Адаптация добавляет в шлюз модуль с другого автомобиля; "
                "заводские модули не затрагиваются.",
                "Component Protection: modules (head unit, instrument cluster, amplifier and others) check "
                "through the gateway that they sit in their own car. Adaptation adds a module from another car to "
                "the gateway; the factory modules are not affected.",
            ),
        )
        self._note(
            lay,
            tr(
                "Нужен ключ IKA адаптируемого модуля (16 байт), известный заранее. Его читают из дампа памяти "
                "самого модуля. Без ключа модуль не адаптировать. Другой вариант — сгенерировать свой ключ и записать "
                "его и в шлюз, и в слот IKA модуля.",
                "You need the IKA key of the module being adapted (16 bytes), known in advance. It is read from "
                "a memory dump of the module itself. Without the key the module cannot be adapted. The alternative is to "
                "generate your own key and write it into both the gateway and the module's IKA slot.",
            ),
            tone="warn",
        )
        inf = self.ws.info("dflash")
        bound = [
            (s.spec.ecu_addr, tr(s.spec.short_ru, s.spec.short_en))
            for s in ((inf.dflash_slots or []) if inf else [])
            if s.spec.slot > 0 and not s.empty and s.kind == "PLAIN"
        ]
        if bound:
            self._table(lay, tr("Привязаны по ключу", "Bound by key"), bound)
        ok, tip = self._need("cflash", "dflash")
        self._block(
            lay,
            tr("Таблица ведомых модулей IKA", "Slave module IKA table"),
            None,
            st.detail
            or tr(
                "Настройка слотов ведомых модулей в CodeFlash и DataFlash без затрагивания заводских блоков.",
                "Configure slave module slots in CodeFlash and DataFlash without touching factory modules.",
            ),
            self._btn("cp", tr("Адаптировать модули…", "Adapt modules…"), self._bind_modules, "PrimaryBtn", ok, tip),
        )
        self._note(
            lay,
            tr(
                "Адаптация меняет CodeFlash и DataFlash; в блок они записываются кнопкой «Записать в блок».",
                "Adaptation changes CodeFlash and DataFlash; they go into the ECU with “Write to ECU”.",
            ),
        )

    def _page_eng(self, lay: QVBoxLayout) -> None:
        st = self._head(lay, "eng")
        desc = tr(
            "Включает заводские инженерные службы шлюза: функции 0x80/0x81/0x83, ASAM CCP (чтение и запись "
            "памяти по CAN) и RAM-Loader 0x6F0.",
            "Enables the gateway's factory engineering services: functions 0x80/0x81/0x83, ASAM CCP (memory "
            "read and write over CAN) and the 0x6F0 RAM-Loader.",
        )
        if st.key == "partial" and st.detail:
            desc = f"{desc}\n\n{st.detail}"
        ok, tip = self._need("cflash")
        if st.key == "on":
            btns = [self._btn("eng_off", tr("Выключить", "Turn off"), lambda: self._patch_engineering(True), "", ok, tip)]
        else:
            btns = [self._btn("eng_on", tr("Включить", "Turn on"), lambda: self._patch_engineering(False), "PrimaryBtn", ok, tip)]
            if st.key == "partial":
                btns.append(
                    self._btn("eng_off", tr("Вернуть заводское", "Restore factory"), lambda: self._patch_engineering(True), "GhostBtn", ok)
                )
        self._block(
            lay,
            tr("Инженерные службы и RAM-Loader", "Engineering services & RAM-Loader"),
            None,
            desc,
            *btns,
        )
        self._note(lay, tr(
            "Меняется только CodeFlash; в блок он записывается кнопкой «Записать в блок».",
            "Only CodeFlash changes; it goes into the ECU with “Write to ECU”.",
        ))

    def _page_swap(self, lay: QVBoxLayout) -> None:
        st = self._head(lay, "swap")
        self._text(
            lay,
            tr(
                "Функции SWaP шлюза (круиз-контроль GRA, контроль усталости MKE, профили движения FPA) включаются"
                " записью кодов FEC в слоты Multi-FSC в DataFlash. Ключ RSA, сертификаты и изменение CodeFlash "
                "для этого не нужны.",
                "The gateway's SWaP features (GRA cruise control, MKE fatigue detection, FPA driving profiles) "
                "are switched on by writing FEC codes into the Multi-FSC slots in DataFlash. No RSA key, "
                "certificate or CodeFlash change is needed.",
            ),
        )
        self._swap_live_block(lay)
        features = status.active_features_detailed(self.ws)
        if features:
            self._table(
                lay,
                tr("Включены в DataFlash", "Enabled in DataFlash"),
                [
                    (
                        code,
                        name,
                        ("Multi-FSC" if factory else "RSA-FSC")
                        + (tr(", есть в датасете", ", in the dataset") if ds_ok else tr(", нет в датасете", ", not in the dataset")),
                    )
                    for _, code, name, factory, ds_ok in features
                ],
            )
        else:
            self._text(lay, st.detail or tr("Включённых функций нет.", "No features enabled."), primary=True)

        unsup_active = status.unsupported_active_fecs(self.ws)
        if unsup_active:
            unsup_hex = ", ".join(f"{c:08X}" for c in unsup_active)
            self._note(
                lay,
                f"{tr(UNSUPPORTED_DATASET_RU, UNSUPPORTED_DATASET_WARNING)}\n"
                + tr(
                    f"Включённые коды ({unsup_hex}) не поддерживаются текущим датасетом ZDC в DataFlash.",
                    f"Active codes ({unsup_hex}) are not supported by the current ZDC dataset in DataFlash.",
                ),
                tone="warn",
            )
            lay.addLayout(
                row(
                    self._btn(
                        "swap_autoparam_now",
                        tr("Параметрировать под активные SWaP", "Parameterize for active SWaP"),
                        self._parameterize_for_active_swap,
                        "PrimaryBtn",
                    ),
                    self._btn(
                        "swap_goto_zdc",
                        tr("Открыть «Параметрирование»", "Open Parameterization"),
                        lambda: self.select("zdc"),
                        "GhostBtn",
                    ),
                )
            )

        df_inf = self.ws.info("dflash")
        sw_info = df_inf.dflash_swap if df_inf else None
        ok_df, tip_df = self._need("dflash")
        if ok_df and (sw_info is None or not sw_info.initialized or not sw_info.magic_ok):
            ok_df = False
            tip_df = tr(
                "Область SWaP NvM 0x7C в DataFlash пуста (сначала запустите шлюз на столе)",
                "SWaP NvM 0x7C in DataFlash is empty (boot the gateway once on bench first)",
            )
        self._block(
            lay,
            tr(
                "Активация в DataFlash",
                "Activation in DataFlash",
            ),
            status.dataset_state(self.ws),
            tr(
                "Записывает выбранные FEC в слоты Multi-FSC в DataFlash и проверяет, есть ли для них данные в "
                "датасете ZDC. CodeFlash и ключ VAG не меняются.",
                "Writes the selected FECs into the Multi-FSC slots in DataFlash and checks that the ZDC dataset "
                "has data for them. CodeFlash and the VAG key stay as they are.",
            ),
            self._btn(
                "swap_direct",
                tr("Настроить функции SWaP…", "Configure SWaP features…"),
                self._activate_swap_direct,
                "PrimaryBtn",
                ok_df,
                tip_df,
            ),
        )

        lay.addWidget(divider())
        lay.addWidget(
            group_label(
                tr(
                    "ДОПОЛНИТЕЛЬНО: СЕРТИФИКАТЫ ПО UDS (СВОЙ КЛЮЧ RSA-1024)",
                    "ADVANCED: UDS CERTIFICATES (CUSTOM RSA-1024 KEY)",
                )
            )
        )

        key = status.swap_key(self.ws)
        own = key.key == "custom"
        ok, tip = self._need("cflash")
        key_btns = [
            self._btn(
                "swap_key",
                tr("Заменить ключ…", "Replace key…") if own else tr("Вшить свой ключ…", "Embed your key…"),
                lambda: self._replace_key("swap"),
                "" if own else "",
                ok,
                tip,
            )
        ]
        if own:
            key_btns.append(self._btn("swap_stock", tr("Вернуть ключ VAG", "Restore VAG key"), lambda: self._restore_key("swap"), "GhostBtn", ok))
        self._block(
            lay,
            tr("Свой ключ в шлюзе", "Your key in the gateway"),
            key,
            tr(
                "Ключ RSA-1024 записывается в CodeFlash и в кэш SWaP в DataFlash. Новая пара ключей сохраняется в"
                " папке ContiTool_keys рядом с дампами. Без приватного ключа сертификат не подписать — сохраните "
                "его.",
                "The RSA-1024 key is written into CodeFlash and into the SWaP cache in DataFlash. A new key pair "
                "is saved in the ContiTool_keys folder next to the dumps. Without the private key no certificate "
                "can be signed — keep it.",
            ),
            *key_btns,
            num="1",
        )
        self._block(
            lay,
            tr("Сертификат функции", "Feature certificate"),
            None,
            tr(
                "Выберите функцию — ContiTool подпишет сертификат вашим ключом для VCRN и VIN этого блока.",
                "Pick a feature — ContiTool signs a certificate with your key for this ECU's VCRN and VIN.",
            ),
            self._btn(
                "fsc",
                tr("Выпустить сертификат…", "Issue certificate…"),
                self._issue_certificate,
                "PrimaryBtn" if own else "",
                own,
                "" if own else tr("Сначала вшейте свой ключ (шаг 1)", "Embed your key first (step 1)"),
            ),
            num="2",
        )
        self._block(
            lay,
            tr("Отправка в блок", "Sending to the ECU"),
            None,
            tr(
                "Сертификат отправляется в шлюз (адрес 19) командой UDS 31 01 06 55 из CAN-терминала ContiTool "
                "или тестером. Готовый сертификат открывается в CAN-терминале.",
                "The certificate goes to the gateway (address 19) with UDS 31 01 06 55, from ContiTool's CAN "
                "terminal or a scan tool. A signed certificate opens in the CAN terminal.",
            ),
            num="3",
        )

    def _swap_live_block(self, lay: QVBoxLayout) -> None:
        """What the gateway itself reports for every feature (UDS 22 3C 00): the proof that a patch was accepted."""
        btn = self._btn(
            "swap_check",
            tr("Проверить в блоке", "Check in the ECU") if self._swap_live is None else tr("Проверить снова", "Check again"),
            self._swap_check,
            "" if self._swap_live is None else "GhostBtn",
        )
        if self._swap_live is None:
            self._block(
                lay,
                tr("Состояние в блоке", "State in the ECU"),
                None,
                tr(
                    "Читает из блока статус всех FEC (UDS 22 3C 00): какие приняты, какие отклонены и почему. После "
                    "записи области SWaP запускается сам.",
                    "Reads the status of every FEC from the ECU (UDS 22 3C 00): which are accepted, which are "
                    "rejected and why. Runs by itself after the SWaP area is written.",
                ),
                btn,
            )
            return

        frame = QFrame()
        frame.setObjectName("Step")
        outer = QVBoxLayout(frame)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        hdr = QFrame()
        hdr.setObjectName("TableHead")
        h = QHBoxLayout(hdr)
        h.setContentsMargins(18, 12, 18, 10)
        h.setSpacing(10)
        t = QLabel(tr("Состояние в блоке", "State in the ECU"))
        t.setObjectName("FieldLabel")
        h.addWidget(t)
        h.addStretch(1)
        h.addWidget(hint(tr(f"проверено в {self._swap_at}", f"checked at {self._swap_at}")))
        h.addWidget(btn)
        outer.addWidget(hdr)

        body = QWidget()
        g = QGridLayout(body)
        g.setContentsMargins(18, 12, 18, 16)
        g.setHorizontalSpacing(14)
        g.setVerticalSpacing(7)
        summary = status.swap_live_summary(self._swap_live, self.ws)
        box = Callout("info" if summary.tone == "muted" else summary.tone)
        box.label.setTextFormat(Qt.TextFormat.PlainText)
        box.label.setText(("✓  " if summary.key == "on" else "✕  " if summary.key == "err" else "") + summary.text)
        box.label.setObjectName("FieldLabel")
        g.addWidget(box, 0, 0, 1, 3)

        def code_label(code: int) -> QLabel:
            num = hint(f"{code:08X}")
            num.setFont(mono_font(12))
            return num

        states = [(status.swap_live_state(f["status"]), f["fsid"]) for f in self._swap_live]
        r = 1
        for st, code in sorted((s for s in states if s[0].key != "off"), key=lambda x: (x[0].key != "on", x[1])):
            g.addWidget(status_readout(st.text, st.tone), r, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
            cell = QVBoxLayout()
            cell.setSpacing(1)
            cell.addWidget(self._label(status.fec_name(code), primary=True))
            if st.detail:
                why = hint(st.detail)
                why.setWordWrap(True)
                set_tone(why, "err")
                cell.addWidget(why)
            g.addLayout(cell, r, 1)
            g.addWidget(code_label(code), r, 2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
            r += 1
        off = sorted(code for st, code in states if st.key == "off")
        if off:
            head = group_label(
                tr(
                    f"НЕ АКТИВИРОВАНЫ ({len(off)}): ПОДДЕРЖИВАЮТСЯ БЛОКОМ, СЕРТИФИКАТА НЕТ",
                    f"NOT ACTIVATED ({len(off)}): SUPPORTED BY THE ECU, NO CERTIFICATE",
                )
            )
            head.setContentsMargins(0, 8, 0, 0)
            g.addWidget(head, r, 0, 1, 3)
            for r, code in enumerate(off, start=r + 1):
                g.addWidget(self._label(status.fec_name(code)), r, 1)
                g.addWidget(code_label(code), r, 2, Qt.AlignmentFlag.AlignRight)
        g.setColumnStretch(1, 1)
        outer.addWidget(body)
        lay.addWidget(frame)

    def _page_zdc(self, lay: QVBoxLayout) -> None:
        st = self._head(lay, "zdc")
        self._text(
            lay,
            tr(
                "Датасеты ZDC шлюза: профили движения и кнопки MODE и руля, контроль усталости (MKE), сообщения "
                "Старт-Стоп на экране, генератор (BEM).",
                "The gateway's ZDC datasets: driving profiles and the MODE and wheel buttons, fatigue detection "
                "(MKE), Start-Stop messages on screen, alternator (BEM).",
            ),
        )
        ok_df, tip_df = self._need("dflash")
        df_path = self.ws.path("dflash")
        raw_df = df_path.read_bytes() if (ok_df and df_path is not None and df_path.is_file()) else None

        unsup_active = status.unsupported_active_fecs(self.ws)
        if st.detail and not (unsup_active and raw_df is not None):
            self._text(lay, st.detail, primary=True)
        if unsup_active and raw_df is not None:
            unsup_names = ", ".join(status.fec_name(c) for c in unsup_active)
            self._note(
                lay,
                tr(
                    f"Для включённых FEC ({unsup_names}) в параметрии нет данных. Кнопка ниже добавит их в датасет.",
                    f"The parameterization has no data for the enabled FECs ({unsup_names}). The button below adds "
                    "them to the dataset.",
                ),
                tone="warn",
            )
            lay.addLayout(
                row(
                    self._btn(
                        "zdc_fix_swap",
                        tr("Настроить параметрию под включённые функции", "Auto-configure for enabled features"),
                        self._parameterize_for_active_swap,
                        "PrimaryBtn",
                        ok_df,
                        tip_df,
                    )
                )
            )

        if raw_df is not None:
            pp = parse_zdc_passport(raw_df)
            fpa = FpaDataset.from_dflash(raw_df)
            if fpa.crc_ok and not fpa.is_passive_base:
                act_profs = [s.name_en for s in fpa.slots() if s.selectable]  # as the head unit labels them
                bcfg = fpa.button_config()
                wheel_short = f"0x{bcfg.mfl_keycode:02X}"
                for kcode, kru, ken in MFL_KEYCODE_PRESETS:
                    if kcode == bcfg.mfl_keycode:
                        wheel_short = tr(kru.split(" (")[0], ken.split(" (")[0])
                        break
                btn_map = {
                    "none": tr("только с экрана магнитолы", "head-unit screen only"),
                    "console": tr("кнопка MODE", "MODE button"),
                    "mfl": tr(f"кнопка на руле ({wheel_short})", f"wheel button ({wheel_short})"),
                    "both": tr(f"кнопка MODE + руль ({wheel_short})", f"MODE + wheel ({wheel_short})"),
                }
                kl15_ok = fpa.all_active_profiles_persist_kl15
                fpa_st = State(
                    tr(f"режимов: {len(act_profs)}", f"{len(act_profs)} modes"),
                    "ok",
                    key="on",
                )
                fpa_desc = tr(
                    f"В меню: {', '.join(act_profs)}.\nПереключение: {btn_map.get(bcfg.mode, bcfg.mode)}. "
                    f"После выключения зажигания: {'профиль сохраняется' if kl15_ok else 'сброс в Normal'}.",
                    f"In the menu: {', '.join(act_profs)}.\nSwitching: {btn_map.get(bcfg.mode, bcfg.mode)}. "
                    f"After the ignition is off: {'the profile is kept' if kl15_ok else 'back to Normal'}.",
                )
            elif fpa.crc_ok:
                fpa_st = State(tr("отключены", "disabled"), "muted", key="off")
                fpa_desc = tr(
                    "Записан базовый датасет без профилей движения. Включите нужные режимы в настройке.",
                    "A base dataset without driving profiles is written. Enable the modes you need in the settings.",
                )
            else:
                fpa_st = State(tr("не настроено", "not set"), "warn", key="off")
                fpa_desc = tr(
                    "Профили движения не настроены. Нажмите кнопку ниже и выберите шаблон.",
                    "Driving profiles are not configured. Press the button below and pick a template.",
                )

            mke = parse_mke_block(raw_df)
            mke_st = (
                State(tr(f"от {mke.speed_on_kmh} км/ч", f"from {mke.speed_on_kmh} km/h"), "ok", key="on")
                if (mke.crc_ok and mke.plausible)
                else State(tr("не настроен", "not set"), "muted", key="off")
            )

            ssa = parse_ssa_block(raw_df)
            if ssa.crc_ok:
                ssa_lbl = {
                    0: tr("только причины", "reasons only"),
                    1: tr("стандартно", "standard"),
                    2: tr("подробно", "detailed"),
                    3: tr("скрыты", "hidden"),
                }.get(ssa.bap_output_mode, tr("включены", "enabled"))
                ssa_st = State(ssa_lbl, "ok", key="on")
            else:
                ssa_st = State(tr("не настроено", "not set"), "muted", key="off")

            bem = parse_bem_block(raw_df)
            bem_pop = sum(1 for s in bem.slots if not s.empty)
            bem_st = (
                State(tr(f"моделей: {bem_pop}", f"{bem_pop} models"), "ok", key="on")
                if bem.crc_ok
                else State(tr("не настроен", "not set"), "muted", key="off")
            )
            pp_st = (
                State(f"{pp.dataset_pn} ({pp.dataset_ver})", "ok", key="on")
                if pp.crc_ok
                else State(tr("не заполнен", "not set"), "muted", key="off")
            )
        else:
            fpa_st = mke_st = ssa_st = bem_st = pp_st = status.parameterization(self.ws)
            fpa_desc = tr(
                "Откройте дамп DataFlash, чтобы настроить профили вождения и кнопки.",
                "Load a DataFlash dump to configure driving profiles and buttons.",
            )

        self._block(
            lay,
            tr("Параметрия блока", "ECU datasets"),
            pp_st,
            tr(
                "Запись по UDS (сессия 10 40, доступ 20103). Перед записью ContiTool читает из блока статус SWaP "
                "и кодировку и предлагает включить недостающее. Экспорт сохраняет датасеты файлами ODIS (.xml) и "
                "как есть (.bin); импорт загружает датасет из файла ODIS с его номером и версией.",
                "Written over UDS (session 10 40, access 20103). Before the write ContiTool reads the ECU's SWaP "
                "status and coding and offers to switch on what is missing. Export saves the datasets as ODIS "
                "files (.xml) and as they are (.bin); import loads a dataset from an ODIS file with its number "
                "and version.",
            ),
            self._btn("zdc_can_upload", tr("Записать параметрию по CAN…", "Write datasets over CAN…"),
                      self._upload_zdc_over_can, "PrimaryBtn", ok_df, tip_df),
            self._btn("zdc_export", tr("Экспорт…", "Export…"), self._export_zdc, "", ok_df, tip_df),
            self._btn("zdc_import_odis", tr("Импорт ODIS…", "Import ODIS…"), self._import_odis_zdc, "", ok_df, tip_df),
            self._btn("zdc_passport", tr("Паспорт и разделы…", "Passport & sections…"), self._open_passport_editor,
                      "", ok_df, tip_df),
        )
        self._block(
            lay,
            tr("Профили вождения и кнопки (MODE и руль)", "Driving Profiles & Buttons (MODE & Wheel)"),
            fpa_st,
            fpa_desc,
            self._btn(
                "zdc_fpa",
                tr("Настроить профили и кнопки…", "Configure profiles & buttons…"),
                self._open_fpa_editor,
                "",
                ok_df,
                tip_df,
            ),
            self._btn(
                "zdc_learn_mfl",
                tr("Проверить кнопку руля по CAN…", "Test wheel button over CAN…"),
                self._test_mfl_button_live,
                "",
            ),
        )
        self._block(
            lay,
            tr("Контроль усталости водителя (MKE)", "Driver Fatigue Detection (MKE)"),
            mke_st,
            tr(
                "Скорость, с которой включается контроль (обычно 65 км/ч), и длительность остановки, после "
                "которой сбрасывается предупреждение.",
                "The speed at which monitoring starts (usually 65 km/h) and how long a stop resets the warning.",
            ),
            self._btn("zdc_mke", tr("Настроить…", "Configure…"), self._open_mke_editor, "", ok_df, tip_df),
        )
        self._block(
            lay,
            tr("Уведомления системы Старт-Стоп на экране", "Start-Stop Screen Notifications"),
            ssa_st,
            tr(
                "Причины, по которым Старт-Стоп не глушит или запускает двигатель, на экране магнитолы.",
                "Why Start-Stop keeps the engine running or restarts it, shown on the head unit.",
            ),
            self._btn("zdc_ssa", tr("Настроить…", "Configure…"), self._open_ssa_editor, "", ok_df, tip_df),
        )
        self._block(
            lay,
            tr("Генератор 14В и умная зарядка (BEM)", "14V Alternator & Smart Charging (BEM)"),
            bem_st,
            tr(
                "Модель генератора автомобиля из заводского каталога (Bosch, Valeo, Denso, 110–250 А).",
                "The car's alternator model from the factory catalogue (Bosch, Valeo, Denso, 110–250 A).",
            ),
            self._btn("zdc_bem", tr("Выбрать генератор…", "Select alternator…"), self._open_bem_editor, "", ok_df, tip_df),
        )


    def _page_dtc(self, lay: QVBoxLayout) -> None:
        self._head(lay, "dtc")
        dtc_st = State(tr(f"прочитано в {self._dtc_at}", f"read at {self._dtc_at}"), "info") if self._dtc is not None else None
        self._block(
            lay,
            tr("Опрос регистратора событий (UDS 0x19 / 0x14)", "Event memory query (UDS 0x19 / 0x14)"),
            dtc_st,
            tr(
                "Коды неисправностей читаются напрямую из блока по CAN; в файлах дампов они не хранятся.",
                "Trouble codes are read directly from the ECU over CAN; dump files do not store them.",
            ),
            self._btn("dtc", tr("Прочитать ошибки", "Read codes"), lambda: self._dtc_run(False), "PrimaryBtn"),
            self._btn("dtc_clear", tr("Стереть ошибки", "Clear codes"), lambda: self._dtc_run(True)),
        )
        if self._dtc is None:
            return
        groups = self._dtc_groups()
        faults = len(groups["active"]) + len(groups["stored"])
        summary = self._text(
            lay,
            tr(
                f"Прочитано в {self._dtc_at}: активных {len(groups['active'])}, сохранённых {len(groups['stored'])}, "
                f"не проверялись {len(groups['untested'])}",
                f"Read at {self._dtc_at}: {len(groups['active'])} active, {len(groups['stored'])} stored, "
                f"{len(groups['untested'])} not tested",
            ),
            primary=True,
        )
        if not faults:
            summary.setText(tr(f"Неисправностей нет, прочитано в {self._dtc_at}", f"No faults, read at {self._dtc_at}"))
            set_tone(summary, "ok")

        def rows(items: list[tuple[int, int]], status: str = "") -> list[tuple[str, ...]]:
            out = []
            for code, st in items:
                display, text = dtc.describe(code)
                out.append((display or f"{code:06X}", text, f"{status or dtc.status_text(st)}, {code:06X}"))
            return out

        if groups["active"]:
            self._table(lay, tr("Активные — неисправность есть сейчас", "Active — failing now"), rows(groups["active"]))
        if groups["stored"]:
            self._table(lay, tr("Сохранённые — неисправность была", "Stored — failed earlier"), rows(groups["stored"]))
        if groups["untested"]:
            n = len(groups["untested"])
            toggle = self._btn(
                "dtc_untested",
                tr(f"Скрыть невыполненные проверки ({n})", f"Hide checks not run yet ({n})")
                if self._show_untested
                else tr(f"Показать невыполненные проверки ({n})", f"Show checks not run yet ({n})"),
                self._toggle_untested,
                "GhostBtn",
            )
            lay.addLayout(row(toggle))
            if self._show_untested:
                self._text(
                    lay,
                    tr(
                        "Это не ошибки: это проверки, которые блок после стирания ещё не выполнял. Часть из них (память, "
                        "сторожевой таймер) идёт только при цикле зажигания: выключите клемму 15, дождитесь сна блока и "
                        "включите снова.",
                        "These are not faults: they are checks the ECU has not run since the codes were cleared. Some "
                        "(memory, watchdog) run only on an ignition cycle: switch terminal 15 off, let the ECU sleep and "
                        "switch it on again.",
                    ),
                )
                self._table(
                    lay,
                    tr("Проверки, которые блок ещё не выполнял", "Checks the ECU has not run yet"),
                    rows(groups["untested"], tr("проверка не выполнялась", "check not run")),
                    muted=True,
                )

    def _toggle_untested(self) -> None:
        self._show_untested = not self._show_untested
        self._render_page()

    def _page_boot(self, lay: QVBoxLayout) -> None:
        st = self._head(lay, "boot")
        self._text(
            lay,
            tr(
                "Загрузчик (Uflash) записывает прошивку в блок. Заводской загрузчик принимает только CodeFlash с "
                "подписью VAG, а любое изменение CodeFlash эту подпись нарушает. Инженерный загрузчик подпись не "
                "проверяет — с ним изменённый CodeFlash записывается по CAN. От заводского он отличается одной "
                "инструкцией: 4 байта по адресу 0x0100342A.",
                "The bootloader (Uflash) writes firmware into the ECU. The factory bootloader accepts only CodeFlash "
                "signed by VAG, and any change to CodeFlash breaks that signature. The engineering bootloader does not "
                "check the signature, so a modified CodeFlash can be written over CAN. It differs from the factory one "
                "by a single instruction: 4 bytes at 0x0100342A.",
            ),
        )
        btns = []
        if st.key != "open":
            btns.append(
                self._btn("boot_on", tr("Активировать инженерный…", "Activate engineering…"), lambda: self._flash_bootloader(True))
            )
        if st.key != "stock":
            btns.append(
                self._btn("boot_off", tr("Вернуть заводской…", "Restore factory…"), lambda: self._flash_bootloader(False), "GhostBtn")
            )
        self._block(
            lay,
            tr("Инженерный загрузчик", "Engineering bootloader"),
            st,
            tr(
                "Uflash меняется только через FACI: в RAM блока загружается программа, которая перезаписывает "
                "загрузчик, после записи — проверка чтением. Перед записью CodeFlash ContiTool ставит инженерный "
                "загрузчик сам, если его нет.",
                "Uflash is changed only through FACI: a program loaded into the ECU's RAM rewrites the "
                "bootloader, which is then read back. Before a CodeFlash write ContiTool installs the engineering"
                " bootloader itself if it is not there.",
            )
            + ("" if st.known else "\n" + tr("Состояние видно по дампу Uflash.", "The state comes from the Uflash dump.")),
            *btns,
        )

        fbl = status.fbl_key(self.ws)
        ok, tip = self._need("cflash")
        btns = [
            self._btn("fbl_key", tr("Вшить свой ключ…", "Embed your key…"), lambda: self._replace_key("fbl"), "", ok, tip),
            self._btn("odx", tr("Подписать прошивку для ODX…", "Sign firmware for ODX…"), self._sign_odx, "", ok, tip),
        ]
        if fbl.key == "custom":
            btns.append(self._btn("fbl_stock", tr("Вернуть ключ VAG", "Restore VAG key"), lambda: self._restore_key("fbl"), "GhostBtn", ok))
        self._block(
            lay,
            tr("Свой ключ FBL — для ODX и ODIS", "Your FBL key — for ODX and ODIS"),
            fbl,
            tr(
                "Вместо инженерного загрузчика можно записать свой ключ FBL и подписывать им прошивку, например "
                "для контейнера .odx под ODIS. Ключ хранится в CodeFlash по адресу 0xA2F7 и записывается в блок "
                "через FACI кнопкой «Записать в блок».",
                "Instead of the engineering bootloader you can write your own FBL key and sign firmware with it, "
                "for an .odx container for ODIS, say. The key sits in CodeFlash at 0xA2F7 and goes into the ECU "
                "through FACI with “Write to ECU”.",
            ),
            *btns,
        )

    def _page_hw(self, lay: QVBoxLayout) -> None:
        self._head(lay, "hw")
        self._text(
            lay,
            tr(
                "Внешняя SPI EEPROM ST M95640 (8 КБ на шине CSIH1) хранит паспорт блока, VIN, кодировку 0x0600, "
                "список оборудования 0x04A3, данные АКБ BEM и блок состояния безопасности NvM 0x5E. Опционные "
                "байты RH850/F1L (OPBT0..OPBT8, 36 Б) задают режим отладки JTAG/LPD, сторожевые таймеры WDTA0/1, "
                "монитор питания CVM и активацию криптомодуля ICU-S.",
                "The external ST M95640 SPI EEPROM (8 KB on CSIH1) stores the ECU passport, VIN, coding 0x0600, "
                "installation list 0x04A3, BEM battery data, and the NvM 0x5E security state block. The RH850/F1L "
                "Option Bytes (OPBT0..OPBT8, 36 B) configure JTAG/LPD debug mode, WDTA0/1 watchdogs, CVM voltage "
                "monitoring, and ICU-S cryptographic activation.",
            ),
        )
        self._note(
            lay,
            tr(
                "Режим только для чтения и диагностики: запись в OPBT и внешнюю EEPROM намеренно не предусмотрена. "
                "Некорректное значение OPBT необратимо блокирует запуск и отладку процессора RH850, а записи "
                "безопасности NvM 0x5E/0x5F в M95640 защищены аппаратными тегами AES-CMAC (ICU-S).",
                "Diagnostic read-only mode: writing to OPBT or the external EEPROM is intentionally disabled. "
                "Invalid OPBT values can lock RH850 boot and debug access, and security records NvM 0x5E/0x5F in "
                "M95640 are paired with hardware ICU-S AES-CMAC tags.",
            ),
        )
        if self.ws.read_warnings:
            warn_lines = [w for w in self.ws.read_warnings.values() if w]
            if warn_lines:
                self._note(lay, "\n\n".join(warn_lines), tone="warn")

        cf_path = self.ws.path("cflash")
        try:
            cf_bytes = cf_path.read_bytes() if cf_path is not None else None
        except OSError:
            cf_bytes = None

        # ── External SPI EEPROM (ST M95640, 8 KB) ──
        ee_path = self.ws.path("eeprom")
        ee_summary = None
        if ee_path is not None:
            try:
                ee_summary = analyze_eeprom(ee_path.read_bytes(), cf_bytes)
            except (OSError, ValueError):
                ee_summary = None
        if ee_summary is not None:
            ee_state = State(
                tr("8 КБ загружено", "8 KB loaded"),
                "ok" if ee_summary.crc_bad_count == 0 and not ee_summary.blank else "warn",
            )
        elif "eeprom" in self.ws.read_warnings:
            ee_state = State(tr("не удалось считать", "read warning"), "warn")
        else:
            ee_state = State(tr("не загружен", "not loaded"), "muted")

        ee_btns = [
            self._btn(
                "hw_read_eeprom",
                tr("Считать EEPROM по CAN", "Read EEPROM over CAN"),
                self._read_eeprom_live,
                "PrimaryBtn" if ee_path is None else "",
            ),
            self._btn(
                "hw_open_eeprom",
                tr("Открыть файл…", "Open file…"),
                lambda: self._pick_optional_file("eeprom"),
            ),
        ]
        if ee_path is not None:
            ee_btns.append(
                self._btn(
                    "hw_report_eeprom",
                    tr("Подробный отчёт EEPROM", "Full EEPROM report"),
                    self._show_eeprom_report,
                )
            )
        self._block(
            lay,
            tr("Внешняя SPI EEPROM (ST M95640, 8 КБ)", "External SPI EEPROM (ST M95640, 8 KB)"),
            ee_state,
            tr(
                "Читается по шине SPI CSIH1 в режиме RAM-Loader (без модификации регистров и памяти) и автоматически "
                "снимается при полном чтении блока.",
                "Read over the CSIH1 SPI bus inside RAM-Loader (read-only, restoring all registers) and included "
                "automatically in a full ECU backup.",
            ),
            *ee_btns,
        )
        if ee_summary is not None:
            ee_rows: list[tuple[str, ...]] = []
            pn_sw = (ee_summary.part_number or "—") + (f"  SW {ee_summary.sw_version}" if ee_summary.sw_version else "")
            ee_rows.append((tr("Паспорт NvM 0x00", "Passport NvM 0x00"), pn_sw, f"{ee_summary.asam_id or '—'} {ee_summary.odx_version}".strip()))
            src_lbl = tr("таблица NvM из Cflash", "Cflash NvM table") if ee_summary.from_cflash_table else tr("TLV-сканер", "TLV scan")
            ee_rows.append(
                (
                    tr("Записи и CRC-16", "Records & CRC-16"),
                    f"CRC OK: {ee_summary.crc_ok_count}, CRC ERR: {ee_summary.crc_bad_count}",
                    f"{src_lbl}, {tr('пустых', 'erased')}: {ee_summary.erased_count}",
                )
            )
            if ee_summary.vin:
                ee_rows.append(("VIN (NvM 0x0F)", ee_summary.vin, ""))
            if ee_summary.long_coding:
                lc_spaced = " ".join(f"{b:02X}" for b in ee_summary.long_coding)
                ee_rows.append((tr("Кодировка 0x0600", "Coding 0x0600"), lc_spaced, "NvM 0x0D"))
            if ee_summary.prog_date or ee_summary.prog_counter is not None or ee_summary.workshop_hex:
                cnt_txt = f"#{ee_summary.prog_counter}" if ee_summary.prog_counter is not None else ""
                ee_rows.append(
                    (
                        tr("Прошивки (F199/F198)", "Flashing (F199/F198)"),
                        f"{ee_summary.prog_date or '—'} {cnt_txt}".strip(),
                        ee_summary.workshop_hex or "",
                    )
                )
            if ee_summary.bem_capacity_ah is not None or ee_summary.bem_vendor or ee_summary.bem_serial:
                cap_txt = f"{ee_summary.bem_capacity_ah} Ah" if ee_summary.bem_capacity_ah is not None else "—"
                ee_rows.append(
                    (
                        tr("АКБ BEM (NvM 0x27)", "BEM battery (0x27)"),
                        f"{cap_txt}  {ee_summary.bem_vendor}".strip(),
                        f"SN {ee_summary.bem_serial}" if ee_summary.bem_serial else "",
                    )
                )
            if ee_summary.nvm_5e_present and ee_summary.learned_cp_mask is not None:
                slots_txt = ", ".join(s.ecu_addr for s in ee_summary.learned_cp_slots) or tr("нет ведомых", "no slaves")
                m_txt = tr("Мастер CP: обучен", "Master CP: learned") if ee_summary.master_cp_learned else tr("Мастер CP: нет", "Master CP: no")
                if ee_summary.showroom_mode_active:
                    m_txt += ", Showroom ON"
                ee_rows.append(
                    (
                        tr("CP в NvM 0x5E", "CP in NvM 0x5E"),
                        f"0x{ee_summary.learned_cp_mask:03X} ({len(ee_summary.learned_cp_slots)}/12: {slots_txt})",
                        m_txt,
                    )
                )
                if ee_summary.eng_disable_mask is not None:
                    f_txt = (
                        f"0x80={'ON' if ee_summary.feat_80_enabled else 'OFF'}, "
                        f"0x81={'ON' if ee_summary.feat_81_enabled else 'OFF'}, "
                        f"0x83={'ON' if ee_summary.feat_83_enabled else 'OFF'}"
                    )
                    ee_rows.append(
                        (
                            tr("Инженерная маска", "Engineering mask"),
                            f"0x{ee_summary.eng_disable_mask:04X}",
                            f_txt,
                        )
                    )
            self._table(lay, tr("Сводка внешней EEPROM", "External EEPROM summary"), ee_rows)

        # ── Renesas RH850/F1L Option Bytes (OPBT0..OPBT8, 36 B) & MCU Identity ──
        op_path = self.ws.path("opbt")
        op_summary = None
        if op_path is not None:
            try:
                op_summary = analyze_opbt(
                    op_path.read_bytes(),
                    extra_idcode=self.ws.extra_idcode,
                    chip_id=self.ws.chip_id,
                )
            except (OSError, ValueError):
                op_summary = None
        if op_summary is not None:
            op_state = State(
                f"{len(op_summary.words)} × 32-bit",
                "ok" if op_summary.reserved_bits_ok and not op_summary.blank else "warn",
            )
        elif "opbt" in self.ws.read_warnings:
            op_state = State(tr("не удалось считать", "read warning"), "warn")
        else:
            op_state = State(tr("не загружен", "not loaded"), "muted")

        op_btns = [
            self._btn(
                "hw_read_opbt",
                tr("Считать OPBT по CAN", "Read OPBT over CAN"),
                self._read_opbt_live,
                "PrimaryBtn" if op_path is None else "",
            ),
            self._btn(
                "hw_open_opbt",
                tr("Открыть файл…", "Open file…"),
                lambda: self._pick_optional_file("opbt"),
            ),
        ]
        if op_path is not None:
            op_btns.append(
                self._btn(
                    "hw_report_opbt",
                    tr("Подробный отчёт OPBT", "Full OPBT report"),
                    self._show_opbt_report,
                )
            )
        self._block(
            lay,
            tr("Опционные байты RH850/F1L (OPBT0..OPBT8, 36 Б)", "RH850/F1L Option Bytes (OPBT0..OPBT8, 36 B)"),
            op_state,
            tr(
                "Считываются через окно Extra Area (BFASELR=1 @ 0x01000070) с полным сохранением состояния кэша и буфера предвыборки.",
                "Read via the Extra Area flash window (BFASELR=1 @ 0x01000070) while saving and restoring I-cache and prefetch state.",
            ),
            *op_btns,
        )

        cf_inf = self.ws.info("cflash")
        cf_idcode = cf_inf.cflash_info.idcode if (cf_inf and cf_inf.cflash_info) else b""
        extra_idcode = op_summary.idcode if op_summary is not None else self.ws.extra_idcode
        chip_id = op_summary.chip_id if op_summary is not None else self.ws.chip_id
        mcu_id_rows: list[tuple[str, ...]] = []
        if cf_idcode:
            mcu_id_rows.append(("IDCODE (CFlash @ 0x0000AB00)", format_idcode(cf_idcode), "SELFID / FACI (16 B)"))
        if extra_idcode:
            if cf_idcode:
                id_note = (
                    tr("совпадает с CFlash (0xAB00)", "matches CFlash (0xAB00)")
                    if extra_idcode == cf_idcode
                    else tr("НЕ СОВПАДАЕТ с CFlash!", "MISMATCH vs CFlash!")
                )
            else:
                id_note = "Extra Area + 0x50 (16 B)"
            mcu_id_rows.append(("IDCODE (Extra Area @ 0xFF300050)", format_idcode(extra_idcode), id_note))
        if chip_id:
            lot = (op_summary.chip_id_lot if op_summary is not None else "") or chip_id_lot_ascii(chip_id)
            lot_note = f"Lot: {lot} (SCDS 32 B)" if lot else "SCDS @ 0xFFCD00E0 (32 B)"
            mcu_id_rows.append(("CHIP ID (@ 0xFFCD00E0)", format_chip_id(chip_id), lot_note))

        if op_summary is not None:
            op_rows: list[tuple[str, ...]] = [
                *mcu_id_rows,
                (
                    "OPBT0",
                    f"0x{op_summary.opbt0:08X}",
                    tr("резервные биты OK", "reserved bits OK")
                    if op_summary.reserved_bits_ok
                    else tr("нестандартные биты", "non-standard bits"),
                ),
            ]
            if len(op_summary.words) >= 2:
                op_rows.append(("OPBT1", f"0x{op_summary.words[1]:08X}", tr("тактирование / PLL0", "clock / PLL0")))
            if op_summary.opbt8 is not None:
                icus_txt = (
                    tr("ICU-S активен", "ICU-S active")
                    if op_summary.icus_activated
                    else tr("ICU-S выключен (bit 31 = 1)", "ICU-S disabled (bit 31 = 1)")
                )
                op_rows.append(("OPBT8 (ICU-S)", f"0x{op_summary.opbt8:08X}", icus_txt))
            for fld in op_summary.fields:
                op_rows.append((f"[{fld.bits}] {fld.name}", fld.value_text, f"0x{fld.raw_value:X}"))
            self._table(lay, tr("Расшифровка OPBT", "Decoded OPBT"), op_rows)
        elif mcu_id_rows:
            self._table(lay, tr("Идентификаторы процессора RH850", "RH850 MCU Identifiers"), mcu_id_rows)

    def _pick_optional_file(self, kind: str) -> None:
        title = (
            tr("Файл внешней EEPROM M95640 (8 КБ)", "External M95640 EEPROM dump (8 KB)")
            if kind == "eeprom"
            else tr("Файл опционных байтов OPBT (32 / 36 / 256 Б)", "RH850 OPBT dump (32 / 36 / 256 B)")
        )
        chosen, _ = QFileDialog.getOpenFileName(
            self,
            title,
            str(self.ws.folder or Path.cwd()),
            "Binary (*.bin *.raw);;All Files (*)",
        )
        if not chosen:
            return
        err = self.ws.replace(kind, Path(chosen))
        if err is not None:
            QMessageBox.warning(self, title, err)

    def _adopt_optional_read(self, kind: str, session_file: Path) -> None:
        if not session_file.is_file():
            return
        target = session_file
        if self.ws.folder is not None and self.ws.folder.is_dir():
            cand = self.ws.folder / CANDIDATES[kind][0]
            try:
                if session_file.resolve() != cand.resolve():
                    shutil.copy2(session_file, cand)
                target = cand
                if kind == "opbt":
                    meta_src = session_file.parent / "read_opbt.json"
                    meta_dst = self.ws.folder / "read_opbt.json"
                    if meta_src.is_file() and meta_src.resolve() != meta_dst.resolve():
                        shutil.copy2(meta_src, meta_dst)
            except OSError:
                target = session_file
        self.ws.replace(kind, target)
        self.note.emit(tr(f"Считано и загружено: {target}", f"Read and loaded: {target}"))

    def _read_eeprom_live(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        sdir = self._session("read_eeprom")
        out_file = sdir / "Eeprom.bin"
        cf_path = self.ws.path("cflash")
        try:
            cf_bytes = cf_path.read_bytes() if cf_path is not None else None
        except OSError:
            cf_bytes = None
        self.runner.run_task(
            tr("Чтение внешней EEPROM M95640 (8 КБ)", "Reading external M95640 EEPROM (8 KB)"),
            lambda rep: can_read_eeprom(
                port,
                out_file,
                interface=iface,
                session_dir=sdir,
                cflash_bytes=cf_bytes,
                reporter=rep,
            ),
            on_success=self._here(lambda _res: self._adopt_optional_read("eeprom", out_file)),
        )

    def _read_opbt_live(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        sdir = self._session("read_opbt")
        out_file = sdir / "Opbt.bin"
        self.runner.run_task(
            tr("Чтение опционных байтов OPBT (36 Б)", "Reading RH850 Option Bytes OPBT (36 B)"),
            lambda rep: can_read_opbt(
                port,
                out_file,
                interface=iface,
                session_dir=sdir,
                reporter=rep,
            ),
            on_success=self._here(lambda _res: self._adopt_optional_read("opbt", out_file)),
        )

    def _show_eeprom_report(self) -> None:
        p = self.ws.path("eeprom")
        if p is None:
            return
        cf_path = self.ws.path("cflash")
        cf_bytes = cf_path.read_bytes() if cf_path is not None and cf_path.is_file() else None
        txt = format_eeprom_report(analyze_eeprom(p.read_bytes(), cf_bytes), Style(False), str(p))
        run_dialog(TextResultDialog(self, tr("Подробный отчёт EEPROM", "Full EEPROM report"), txt, self.ws.part_number))

    def _show_opbt_report(self) -> None:
        p = self.ws.path("opbt")
        if p is None:
            return
        oinfo = analyze_opbt(
            p.read_bytes(),
            extra_idcode=self.ws.extra_idcode,
            chip_id=self.ws.chip_id,
        )
        txt = format_opbt_report(oinfo, Style(False), str(p))
        run_dialog(TextResultDialog(self, tr("Подробный отчёт OPBT", "Full OPBT report"), txt, self.ws.part_number))

    # ────────────────────────────── changed dumps ──────────────────────────────
    def _fbl_key_changed(self) -> bool:
        """True when the edited CodeFlash carries another FBL key at 0xA2F7 (written via FACI boot block)."""
        cur, orig = self.ws.path("cflash"), self.ws.original.get("cflash")
        if cur is None or orig is None or cur == orig:
            return False
        try:
            if cur.stat().st_size != CFLASH_SIZE or orig.stat().st_size != CFLASH_SIZE:
                return False
            with cur.open("rb") as a, orig.open("rb") as b:
                a.seek(FBL_MOD_OFFSET)
                b.seek(FBL_MOD_OFFSET)
                return a.read(128) != b.read(128)
        except OSError:
            return False

    def _dataset_only_edit(self) -> bool:
        """Only DataFlash is waiting and every edit lies inside a ZDC dataset block that the UDS upload writes, and
        that block is not erased in the edited file: then it goes in the standard way, as datasets over UDS. An erased
        block, the passport or any byte between blocks goes through the RAM-Loader (the upload skips all of those)."""
        if not self.ws.pending("dflash") or any(self.ws.pending(k) for k in KINDS if k != "dflash"):
            return False
        cur, orig = self.ws.path("dflash"), self.ws.original.get("dflash")
        try:
            key = (str(cur), str(orig), cur.stat().st_mtime_ns, orig.stat().st_mtime_ns)  # type: ignore[union-attr]
        except (AttributeError, OSError):
            return False
        if self._dataset_only_cache[0] == key:
            return self._dataset_only_cache[1]
        try:
            a, b = orig.read_bytes(), cur.read_bytes()  # type: ignore[union-attr]
        except OSError:
            return False
        blocks = [(off, off + size) for idx, _n, off, size, _r, _e in ZDC_DATASET_SPECS
                  if idx in ZDC_UDS_UPLOAD_MAP and any(v != 0xFF for v in b[off : off + size])]
        ok = len(a) == len(b) and all(any(lo <= s0 and e0 <= hi for lo, hi in blocks) for s0, e0 in changed_ranges(a, b))
        self._dataset_only_cache = (key, ok)
        return ok

    _dataset_only_cache: tuple[tuple | None, bool] = (None, False)

    def _write_pending(self) -> None:
        if self._dataset_only_edit():
            self._upload_zdc_over_can()
        else:
            self._write_to_ecu()

    def change_state(self, kind: str) -> tuple[str, str, str]:
        """(tag, tone, how it gets into the ECU) for one loaded dump."""
        if not self.ws.modified(kind):
            return tr("без изменений", "unchanged"), "muted", tr("записывать не нужно", "nothing to write")
        if not self.ws.pending(kind):
            return tr("записан", "written"), "ok", tr("уже в блоке", "already in the ECU")
        if kind == "cflash" and self._fbl_key_changed():
            return (
                tr("изменён", "changed"),
                "info",
                tr(
                    "запишется по CAN кнопкой «Записать в блок» (включая ключ FBL через FACI)",
                    "written over CAN with “Write to ECU” (including the FBL key via FACI)",
                ),
            )
        if kind == "dflash" and self._dataset_only_edit():
            return (
                tr("изменён", "changed"),
                "info",
                tr("изменена только параметрия — запишется штатно по UDS кнопкой «Записать параметрию по CAN»",
                   "only the datasets changed — written the standard way over UDS with “Write datasets over CAN”"),
            )
        return tr("изменён", "changed"), "info", tr("запишется по CAN кнопкой «Записать в блок»", "written over CAN with “Write to ECU”")

    def _refresh_changes(self) -> None:
        changed = [k for k in KINDS if self.ws.modified(k)]
        self.changes.setVisible(bool(changed))
        if not changed:
            return
        self.lbl_changes.setText(tr("Изменённые дампы", "Changed dumps"))
        clear_layout(self.grid_changes)
        for r, kind in enumerate(k for k in KINDS if self.ws.path(k) is not None):
            tag, tone, how = self.change_state(kind)
            name = QLabel(NAMES[kind])
            name.setObjectName("FieldLabel")
            self.grid_changes.addWidget(name, r, 0)
            self.grid_changes.addWidget(status_readout(tag, tone), r, 1, Qt.AlignmentFlag.AlignLeft)
            self.grid_changes.addWidget(hint(how), r, 2)
        self.grid_changes.setColumnStretch(2, 1)

        busy = self.runner.is_busy
        self.btn_save.setText(tr("Сохранить дампы…", "Save dumps…"))
        self.btn_save.setToolTip(tr("Копирует изменённые дампы в выбранную папку", "Copies the changed dumps to a folder you pick"))
        self.btn_revert.setText(tr("Отменить изменения", "Discard changes"))
        dataset_only = self._dataset_only_edit()
        self.btn_write.setText(tr("Записать параметрию по CAN…", "Write datasets over CAN…") if dataset_only
                               else tr("Записать в блок", "Write to ECU"))
        self.btn_write_df.setText(tr("Записать DataFlash целиком…", "Write the whole DataFlash…"))
        self.btn_write_df.setToolTip(tr("Через RAM-Loader, как «Записать в блок»", "Through the RAM-Loader, like “Write to ECU”"))
        self.btn_write_df.setVisible(dataset_only)
        self.btn_write_df.setEnabled(not busy)
        can_write = any(self.ws.pending(k) for k in KINDS)
        self.btn_write.setEnabled(can_write and not busy)
        self.btn_write.setToolTip(
            ""
            if can_write
            else tr("Все изменённые дампы уже записаны в блок", "All changed dumps are already in the ECU")
        )
        self.btn_save.setEnabled(not busy)
        self.btn_revert.setEnabled(not busy)

    def _save_dumps(self) -> None:
        changed = [k for k in KINDS if self.ws.modified(k)]
        chosen = QFileDialog.getExistingDirectory(
            self, tr("Куда сохранить изменённые дампы", "Where to save the changed dumps"), str(self.ws.folder or Path.cwd())
        )
        if not chosen or not changed:
            return
        dest = Path(chosen)
        targets = {k: dest / self.ws.original[k].name for k in changed}
        if any(t.resolve() == self.ws.original[k].resolve() for k, t in targets.items()):
            QMessageBox.warning(
                self,
                tr("Это папка с исходными дампами", "This is the folder with the original dumps"),
                tr("Исходные дампы не перезаписываются. Выберите другую папку.", "The original dumps are never overwritten. Pick another folder."),
            )
            return
        copies = {k: t for k, t in targets.items() if t.resolve() != self.ws.path(k).resolve()}
        existing = [t.name for t in copies.values() if t.exists()]
        if existing and QMessageBox.question(
            self,
            tr("Файлы уже есть", "Files already exist"),
            tr(f"В папке уже есть: {', '.join(existing)}. Заменить?", f"The folder already has: {', '.join(existing)}. Replace?"),
        ) != QMessageBox.StandardButton.Yes:
            return
        for k, t in copies.items():
            shutil.copy2(self.ws.path(k), t)
        names = ", ".join(t.name for t in targets.values())
        self.note.emit(tr(f"Изменённые дампы сохранены в {dest}: {names}", f"Changed dumps saved to {dest}: {names}"))

    def export_backup(self) -> None:
        """Copy the dumps as they were read (not the edited copies) into a new folder where the user wants them."""
        if not self.ws.original:
            return
        chosen = QFileDialog.getExistingDirectory(self, tr("Куда экспортировать бэкап", "Where to export the backup"), str(Path.home()))
        if not chosen:
            return
        name = f"{self.ws.part_number or 'J533'}_{time.strftime('%Y-%m-%d_%H-%M')}"
        dest, n = Path(chosen) / name, 2
        while dest.exists():
            dest, n = Path(chosen) / f"{name}_{n}", n + 1
        dest.mkdir(parents=True)
        for kind, src in self.ws.original.items():
            shutil.copy2(src, dest / CANDIDATES[kind][0])  # standard names, so "Open dump folder" finds them
        if self.ws.folder is not None and (self.ws.folder / "manifest.json").is_file():
            shutil.copy2(self.ws.folder / "manifest.json", dest / "manifest.json")  # read session: SHA-256 of every area
        self.note.emit(tr(f"Бэкап экспортирован в {dest}", f"Backup exported to {dest}"))

    # ────────────────────────────── edits ──────────────────────────────
    def _edit(self, title: str, kind: str, fn: Any) -> None:
        """Run `fn(raw, reporter) -> new bytes` on one dump and adopt the result as the current file."""
        src = self.ws.path(kind)
        if src is None:
            return
        out = self.ws.edit_path(kind)

        def task(rep: Any) -> Path:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(fn(src.read_bytes(), rep))
            rep.success(tr(f"Сохранено: {out}", f"Saved: {out}"))
            return out

        self.runner.run_task(title, task, on_success=self._here(lambda p: self.ws.commit(kind, p)))

    def _bind_modules(self) -> None:
        inf = self.ws.info("dflash")
        dlg = CpBindDialog((inf.dflash_slots or []) if inf else [], self)
        if not run_dialog(dlg):
            return
        banks, key, force = dlg.banks, dlg.key, dlg.force_mask

        if dlg.action == "clear":
            self._edit(
                tr("Очистка банков", "Erasing banks"),
                "dflash",
                lambda raw, rep: clear_dflash_slots(raw, banks, reporter=rep),
            )
            return

        cf_src, df_src = self.ws.path("cflash"), self.ws.path("dflash")
        if cf_src is None or df_src is None:
            return
        cf_out, df_out = self.ws.edit_path("cflash"), self.ws.edit_path("dflash")
        updates = [(s, key) for s in banks]

        def task(rep: Any) -> Path:
            cf_out.parent.mkdir(parents=True, exist_ok=True)
            new_cf, new_df, _ = bind_cp_turnkey(
                cf_src.read_bytes(),
                df_src.read_bytes(),
                updates,
                force_bypass_eeprom_mask=force,
                reporter=rep,
            )
            cf_out.write_bytes(new_cf)
            df_out.write_bytes(new_df)
            return cf_out

        def done(_p: Path) -> None:
            self.ws.commit("cflash", cf_out)
            self.ws.commit("dflash", df_out)

        addrs = ", ".join(s.ecu_addr for s in banks)
        self.runner.run_task(tr(f"Адаптация IKA/CP: {addrs}", f"IKA/CP adaptation: {addrs}"), task, on_success=self._here(done))

    def _patch_engineering(self, restore: bool) -> None:
        self._edit(
            tr("Возврат заводской диагностики", "Restoring factory diagnostics")
            if restore
            else tr("Включение расширенной диагностики", "Enabling extended diagnostics"),
            "cflash",
            lambda raw, rep: apply_engineering_patch(raw, restore_stock=restore, reporter=rep)[0],
        )

    def _activate_swap_direct(self) -> None:
        inf = self.ws.info("dflash")
        sw = inf.dflash_swap if inf else None
        ds = inf.dflash_datasets if inf else None
        if sw is None or not sw.initialized:
            return
        dlg = SwapActivateDialog(sw, ds, self)
        if run_dialog(dlg):
            self._apply_swap_direct(dlg.selected_fecs, dlg.vin, auto_param=dlg.auto_param_config())

    def _apply_swap_direct(
        self,
        selected_fecs: list[int],
        vin: str | None = None,
        auto_param: ZdcAutoParamConfig | None = None,
    ) -> None:
        """Apply direct Multi-FSC activation/deactivation (and optional 1-click ZDC parameterization) to DataFlash."""

        def _patch_fn(raw: bytes, rep: Any) -> bytes:
            if auto_param is not None and auto_param.enabled:
                raw, _ = parameterize_dflash_for_fecs(raw, selected_fecs, auto_param, reporter=rep)
            return apply_dflash_swap_fecs(
                raw,
                enable_fecs=selected_fecs,
                vin=vin,
                preserve_existing_active=False,
                reporter=rep,
            )[0]

        self._edit(
            tr(
                "Активация FEC в DataFlash",
                "FEC activation in DataFlash",
            ),
            "dflash",
            _patch_fn,
        )

    def _parameterize_for_active_swap(self) -> None:
        inf = self.ws.info("dflash")
        sw = inf.dflash_swap if inf else None
        if sw is None or not sw.active_fscs:
            return
        fecs = [f.fec_code for f in sw.active_fscs]
        self._edit(
            tr(
                "Параметрия ZDC под включённые FEC",
                "ZDC parameterization for the enabled FECs",
            ),
            "dflash",
            lambda raw, rep: parameterize_dflash_for_fecs(raw, fecs, ZdcAutoParamConfig(enabled=True), reporter=rep)[0],
        )

    def _open_fpa_editor(self) -> None:
        src = self.ws.path("dflash")
        if src is None:
            return
        dlg = FpaEditorDialog(src.read_bytes(), self.conn, self.runner, self)
        if run_dialog(dlg):
            new_df = dlg.result_dflash()
            self._edit(tr("Сохранение параметрии FPA (ZDC #4)", "Saving FPA parameterization (ZDC #4)"), "dflash", lambda _r, _rep: new_df)

    def _open_mke_editor(self) -> None:
        src = self.ws.path("dflash")
        if src is None:
            return
        dlg = MkeEditorDialog(src.read_bytes(), self)
        if run_dialog(dlg):
            new_df = dlg.result_dflash()
            self._edit(tr("Сохранение параметров MKE (ZDC #1)", "Saving MKE parameters (ZDC #1)"), "dflash", lambda _r, _rep: new_df)

    def _open_ssa_editor(self) -> None:
        src = self.ws.path("dflash")
        if src is None:
            return
        dlg = SsaEditorDialog(src.read_bytes(), self)
        if run_dialog(dlg):
            new_df = dlg.result_dflash()
            self._edit(
                tr("Сохранение параметров индикации Старт-Стоп (ZDC #2)", "Saving Start-Stop HMI parameters (ZDC #2)"),
                "dflash",
                lambda _r, _rep: new_df,
            )

    def _open_bem_editor(self) -> None:
        src = self.ws.path("dflash")
        if src is None:
            return
        dlg = BemEditorDialog(src.read_bytes(), self)
        if run_dialog(dlg):
            new_df = dlg.result_dflash()
            self._edit(tr("Сохранение моделей генераторов BEM (ZDC #6)", "Saving BEM alternator models (ZDC #6)"), "dflash", lambda _r, _rep: new_df)

    def _open_passport_editor(self) -> None:
        src = self.ws.path("dflash")
        if src is None:
            return
        dlg = ZdcPassportBlocksDialog(src.read_bytes(), self)
        if run_dialog(dlg):
            new_df = dlg.result_dflash()
            self._edit(tr("Обновление паспорта и блоков ZDC", "Updating ZDC passport & blocks"), "dflash", lambda _r, _rep: new_df)

    def _export_zdc(self) -> None:
        src = self.ws.path("dflash")
        if src is None:
            return
        df = src.read_bytes()
        blocks = populated_zdc_blocks(df)
        if not blocks:
            QMessageBox.information(self, tr("Экспорт параметрии", "Dataset export"),
                                    tr("В DataFlash нет заполненных блоков ZDC.", "DataFlash holds no populated ZDC blocks."))
            return
        chosen = QFileDialog.getExistingDirectory(
            self, tr("Куда сохранить параметрию", "Where to save the datasets"), str(self.ws.folder or Path.home()))
        if not chosen:
            return
        dest, n = Path(chosen) / f"ZDC_{self.ws.part_number or 'J533'}_{time.strftime('%Y-%m-%d_%H-%M')}", 2
        while dest.exists():
            dest, n = Path(chosen) / f"ZDC_{self.ws.part_number or 'J533'}_{time.strftime('%Y-%m-%d_%H-%M')}_{n}", n + 1
        dest.mkdir(parents=True)
        codes = {spec[0]: spec[1] for spec in ZDC_DATASET_SPECS}
        for idx in blocks:
            name = f"ZDC{idx}_{codes.get(idx, 'BLOCK')}"
            (dest / f"{name}.xml").write_bytes(build_odis_zdc_file(df, idx))
            (dest / f"{name}.bin").write_bytes(export_zdc_block(df, idx))
        (dest / "ZDC_area_0000-303F.bin").write_bytes(df[:0x3040])  # passport and all blocks, as DataFlash holds them
        self.note.emit(tr(f"Параметрия сохранена ({len(blocks)} бл.): {dest}", f"Datasets saved ({len(blocks)} blocks): {dest}"))
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(dest)))

    def _import_odis_zdc(self) -> None:
        src, _ = QFileDialog.getOpenFileName(
            self, tr("Файл параметрии ODIS", "ODIS parameterization file"), str(self.ws.folder or Path.home()),
            "ODIS XML (*.xml);;All files (*)")
        if not src:
            return
        try:
            parsed = parse_odis_zdc_file(Path(src).read_bytes())
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, tr("Импорт файла ODIS", "ODIS file import"), str(exc))
            return
        self._edit(
            tr(f"Импорт параметрии ODIS в ZDC #{parsed.zdc_idx} ({parsed.dataset_pn})",
               f"Importing the ODIS dataset into ZDC #{parsed.zdc_idx} ({parsed.dataset_pn})"),
            "dflash",
            lambda raw, rep: apply_odis_zdc_file(raw, parsed, reporter=rep),
        )

    def _upload_zdc_over_can(self) -> None:
        """Datasets into the gateway the way a workshop does it: first see which SWaP features and coding the ECU
        has, switch on what the datasets need, upload them over the gateway's own UDS, align the coding, then offer
        to clear the trouble codes."""
        src = self.ws.path("dflash")
        if src is None or not ensure_ready(self.conn, self):
            return
        df_bytes = src.read_bytes()
        port, iface = self.conn.port, self.conn.interface

        def precheck(rep: Any) -> dict[str, Any]:
            features = can_swap_status(port, interface=iface, reporter=rep)["features"]
            return {"features": features, **can_read_gateway_coding(port, interface=iface, reporter=rep)}

        self.runner.run_task(
            tr("Проверка блока перед загрузкой параметрии", "Checking the ECU before the dataset upload"),
            precheck,
            # the runner is still busy inside on_success: plan once it has finished
            on_success=self._here(lambda pre: QTimer.singleShot(0, lambda: self._zdc_upload_plan(df_bytes, pre))),
        )

    def _zdc_blocks_to_upload(self, df_bytes: bytes) -> list[int]:
        """Upload only the ZDC blocks edited since the base DataFlash read; fall back to all populated blocks when
        uploading an untouched standalone dump directly."""
        non_empty = [i for i in sorted(ZDC_UDS_UPLOAD_MAP) if any(b != 0xFF for b in export_zdc_block(df_bytes, i))]
        orig = self.ws.original.get("dflash")
        if orig is not None:
            try:
                orig_bytes = orig.read_bytes()
            except OSError:
                orig_bytes = b""
            if len(orig_bytes) == len(df_bytes):
                changed = [i for i in non_empty if export_zdc_block(df_bytes, i) != export_zdc_block(orig_bytes, i)]
                if changed:
                    return changed
        return non_empty

    def _zdc_upload_plan(self, df_bytes: bytes, pre: dict[str, Any]) -> None:
        self._swap_live, self._swap_at = list(pre["features"]), time.strftime("%H:%M")
        active = {f["fsid"] for f in pre["features"] if status.swap_live_state(f["status"]).key == "on"}
        blocks = self._zdc_blocks_to_upload(df_bytes)
        required = fecs_required_by_dataset(df_bytes, blocks=blocks)
        missing = [c for c in required if c not in active]
        coding = bytes(pre["coding"])
        want = sync_gateway_coding_for_zdc(df_bytes, coding, blocks=blocks)
        diff = [i for i in range(len(want)) if want[i] != coding[i]]
        lines = []
        if missing:
            names = "\n".join(f"• {status.fec_name(c)}" for c in missing)
            lines.append(tr(
                f"Для части датасета в блоке нет активных FEC:\n{names}\n\nБез FEC шлюз не показывает профиль в "
                "меню магнитолы, а MKE не работает. Команды для включения FEC у шлюза нет: ContiTool запишет их в "
                "область SWaP в DataFlash через RAM-Loader, остальной DataFlash не меняется.",
                f"Part of the dataset has no active FEC in the ECU:\n{names}\n\nWithout its FEC the gateway does "
                "not offer a profile to the head unit, and MKE does not work. The gateway has no command to switch "
                "FECs on: ContiTool writes them into the SWaP area of DataFlash through the RAM-Loader; the rest of "
                "DataFlash stays as it is.",
            ))
        elif required:
            lines.append(tr("Все функции SWaP, которых требует датасет, в блоке активны.",
                            "Every SWaP feature the dataset needs is active in the ECU."))
        blk = ", ".join(f"ZDC #{i}" for i in blocks)
        lines.append(tr(f"Параметрия ({blk}) — штатно по UDS (10 40, код 20103).",
                        f"Datasets ({blk}) — the standard way, over UDS (10 40, code 20103)."))
        if diff:
            ch = ", ".join(f"{i}: {coding[i]:02X} → {want[i]:02X}" for i in diff)
            lines.append(tr(f"Кодировка 0x0600 после загрузки, байт {ch}.", f"Coding 0x0600 after the upload, byte {ch}."))
        else:
            lines.append(tr("Кодировка 0x0600 уже подходит.", "Coding 0x0600 already fits."))
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle(tr("Загрузка параметрии по CAN", "Dataset upload over CAN"))
        box.setText("\n\n".join(lines))
        act = box.addButton(tr("Активировать SWaP и загрузить", "Activate SWaP and upload"), QMessageBox.ButtonRole.AcceptRole) if missing else None
        only = box.addButton(tr("Только загрузить", "Upload only") if missing else tr("Загрузить", "Upload"),
                             QMessageBox.ButtonRole.ActionRole if missing else QMessageBox.ButtonRole.AcceptRole)
        box.addButton(tr("Отмена", "Cancel"), QMessageBox.ButtonRole.RejectRole)
        box.exec()
        clicked = box.clickedButton()
        if clicked is not None and clicked in (act, only):
            self._zdc_upload_run(df_bytes, missing if clicked is act else [], blocks=blocks)
        else:
            self.refresh()

    def _zdc_upload_run(self, df_bytes: bytes, activate: list[int], *, blocks: list[int] | None = None) -> None:
        port, iface = self.conn.port, self.conn.interface
        sdir = self._session("zdc_upload")
        cf_path = self.ws.path("cflash")
        try:
            cflash_bytes = cf_path.read_bytes() if cf_path is not None else None
        except OSError:
            cflash_bytes = None

        def task(rep: Any) -> dict[str, Any]:
            out: dict[str, Any] = {"session_dir": str(sdir)}
            if activate:
                out["swap"] = can_activate_swap(port, activate, interface=iface, session_dir=sdir / "swap", reporter=rep)
            out["upload"] = can_upload_zdc_datasets(
                port,
                df_bytes,
                blocks=blocks,
                cflash_bytes=cflash_bytes,
                interface=iface,
                session_dir=sdir / "upload",
                reporter=rep,
            )
            out["features"] = can_swap_status(port, interface=iface, reporter=rep)["features"]  # did the ECU take them?
            return out

        def done(res: dict[str, Any]) -> None:
            self._swap_live, self._swap_at = list(res["features"]), time.strftime("%H:%M")
            cur = self.ws.path("dflash")
            if self._dataset_only_edit() and cur is not None and cur.read_bytes() == df_bytes:
                self.ws.mark_written(["dflash"])  # the ECU holds this file's datasets, and nothing else was edited
            QTimer.singleShot(0, lambda: self._offer_dtc_clear(res, activate))

        self.runner.run_task(tr("Загрузка параметрии по CAN", "Dataset upload over CAN"), task, on_success=self._here(done))

    def _offer_dtc_clear(self, res: dict[str, Any], activated: list[int]) -> None:
        active = {f["fsid"] for f in res["features"] if status.swap_live_state(f["status"]).key == "on"}
        refused = [c for c in activated if c not in active]
        text = tr("Параметрия загружена.", "The datasets are uploaded.")
        if refused:
            names = ", ".join(status.fec_name(c) for c in refused)
            text += tr(f"\n\nБлок не принял FEC: {names}. Подробности — на странице «Активация SWaP/FEC».",
                       f"\n\nThe ECU did not accept FEC: {names}. Details are on the SWaP/FEC activation page.")
        elif activated:
            text += tr(" Нужные FEC в блоке активны.", " The FECs it needs are active in the ECU.")
        text += "\n\n" + _restart_note()
        text += tr("\n\nСтереть ошибки в блоке? После смены параметрии старые записи обычно уже неактуальны.",
                   "\n\nClear the trouble codes in the ECU? After a dataset change the old entries are usually stale.")
        if QMessageBox.question(self, tr("Загрузка параметрии по CAN", "Dataset upload over CAN"), text) == QMessageBox.StandardButton.Yes:
            self._dtc_run(clear=True)
        else:
            self.refresh()

    def _test_mfl_button_live(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface

        def show_res(res: dict[str, Any]) -> None:
            if res.get("captured") and res.get("keycode"):
                kc = int(res["keycode"])
                QMessageBox.information(
                    self,
                    tr("Кнопка руля распознана", "Steering-wheel button captured"),
                    tr(
                        f"Код MFL_Tastencode: 0x{kc:02X} ({res.get('label_ru', '')})\nКадр 0x1F07: {res.get('raw_1f07', '')}",
                        f"MFL_Tastencode: 0x{kc:02X} ({res.get('label_en', '')})\n0x1F07 frame: {res.get('raw_1f07', '')}",
                    ),
                )
            elif res.get("gra_button_detected"):
                QMessageBox.warning(
                    self,
                    tr("Линия круиз-контроля (GRA_Neu)", "Cruise-control line (GRA_Neu)"),
                    tr(
                        "Нажатая кнопка относится к круиз-контролю / Travel Assist (кадр GRA_Neu LIN 0x0F) и не отправляет MFL_Tastencode.",
                        "The pressed button belongs to cruise control / Travel Assist (GRA_Neu LIN 0x0F) and does not emit an MFL_Tastencode.",
                    ),
                )
            else:
                QMessageBox.information(
                    self,
                    tr("Нажатие не обнаружено", "No button press detected"),
                    tr("В течение 12 секунд нажатие кнопки руля не зафиксировано.", "No steering-wheel button press was detected within 12 seconds."),
                )

        self.runner.run_task(
            tr("Ожидание нажатия кнопки на руле (12 с)", "Waiting for steering-wheel button press (12 s)"),
            lambda rep: can_learn_mfl_button(port, interface=iface, reporter=rep),
            on_success=show_res,
        )

    def _replace_key(self, target: str) -> None:
        dlg = RsaKeyDialog(target, self)
        if run_dialog(dlg):
            self._set_key(target, dlg.key_path)

    def _restore_key(self, target: str) -> None:
        self._set_key(target, STOCK_SWAP_MODULUS if target == "swap" else STOCK_FBL_MODULUS)

    def _set_key(self, target: str, source: Path | bytes | None) -> None:
        """Embed a public modulus for `target` (swap | fbl). `source`: None = new keypair, a key file, or raw modulus."""
        cf_src, df_src = self.ws.path("cflash"), self.ws.path("dflash")
        if cf_src is None:
            return
        swap = target == "swap"
        cf_out = self.ws.edit_path("cflash")
        df_out = self.ws.edit_path("dflash") if df_src is not None and swap else None
        # A fresh name every time: overwriting an earlier private key would lose a key the gateway may already trust.
        bundle = (self.ws.folder or Path.cwd()) / "ContiTool_keys" / f"j533_{target}_{time.strftime('%Y%m%d_%H%M%S')}.json"

        def task(rep: Any) -> Path:
            if source is None:
                kp = generate_rsa1024_e3_keypair(reporter=rep)
                for p in save_rsa1024_keypair_bundle(bundle, kp):
                    rep.success(tr(f"Ключ сохранён: {p}", f"Key saved: {p}"))
                modulus, _ = load_rsa1024_key_material(bundle)
            elif isinstance(source, Path):
                modulus, _ = load_rsa1024_key_material(source)
            else:
                modulus = source
            cf_out.parent.mkdir(parents=True, exist_ok=True)
            new_cf, _, _ = apply_cflash_rsa_modulus(cf_src.read_bytes(), modulus, patch_swap=swap, patch_fbl=not swap, reporter=rep)
            cf_out.write_bytes(new_cf)
            if df_out is not None and df_src is not None:
                new_df, _, _ = apply_dflash_swap_rsa_modulus(df_src.read_bytes(), modulus, reporter=rep)
                df_out.write_bytes(new_df)
            return cf_out

        def done(_p: Path) -> None:
            if source is None:
                self._key_file = bundle
            elif isinstance(source, Path):
                self._key_file = source
            self.ws.commit("cflash", cf_out)
            if df_out is not None and df_out.is_file():
                self.ws.commit("dflash", df_out)

        if isinstance(source, bytes):
            title = tr("Возврат ключа VAG", "Restoring the VAG key")
        else:
            title = tr("Свой ключ SWaP", "Your SWaP key") if swap else tr("Свой ключ FBL", "Your FBL key")
        self.runner.run_task(title, task, on_success=self._here(done))

    # ────────────────────────────── certificates ──────────────────────────────
    def _issue_certificate(self) -> None:
        inf = self.ws.info("dflash")
        sw = inf.dflash_swap if inf else None
        dlg = FscDialog(sw.vcrn.hex().upper() if sw and sw.vcrn else "", sw.vin if sw else "", self._key_file, self)
        if not run_dialog(dlg):
            return
        key_path, fec, vcrn, vin = dlg.key_path, dlg.fec_code, dlg.vcrn, dlg.vin
        if key_path is None or fec is None:
            return
        out_file = (self.ws.folder or Path.cwd()) / f"FSC_{fec:08X}.fsc"

        def task(rep: Any) -> bytes:
            modulus, d_int = load_rsa1024_key_material(key_path)
            if d_int is None:
                raise ValueError(
                    tr(
                        "В файле нет приватной части ключа — сертификат подписать нечем.",
                        "The file has no private key part — nothing to sign the certificate with.",
                    )
                )
            fsc = build_signed_fsc(fec, vcrn, vin, modulus, d_int, reporter=rep)
            out_file.write_bytes(fsc)
            rep.success(tr(f"Сохранено: {out_file}", f"Saved: {out_file}"))
            return fsc

        def done(fsc: bytes) -> None:
            self._key_file = key_path
            command = f"3101065500{fsc.hex().upper()}"
            holder: list[TextResultDialog] = []

            def to_terminal() -> None:
                holder[0].accept()
                self.terminal_requested.emit(command)

            dlg_res = TextResultDialog(
                self,
                tr("Сертификат готов", "Certificate ready"),
                f"# {out_file}\n{fsc.hex().upper()}\n\n# UDS RoutineControl 0x0655\n{command}",
                tr(
                    "Отправьте вторую строку в блок 19 — из CAN-терминала или диагностическим тестером.",
                    "Send the second line to module 19 — from the CAN terminal or a diagnostic tester.",
                ),
                actions=(button(tr("Открыть в CAN-терминале", "Open in CAN terminal"), slot=to_terminal),),
            )
            holder.append(dlg_res)
            run_dialog(dlg_res)

        # the runner is still busy inside on_success: show the result (it can open the terminal) once it has finished
        self.runner.run_task(tr(f"Подпись сертификата {fec:08X}", f"Signing certificate {fec:08X}"), task,
                             on_success=lambda fsc: QTimer.singleShot(0, lambda: done(fsc)))

    def _sign_odx(self) -> None:
        dlg = OdxSignDialog(self._key_file, self)
        if not run_dialog(dlg):
            return
        key_path, cf_src = dlg.key_path, self.ws.path("cflash")
        if key_path is None or cf_src is None:
            return

        def task(rep: Any) -> bytes:
            modulus, d_int = load_rsa1024_key_material(key_path)
            if d_int is None:
                raise ValueError(
                    tr(
                        "В файле нет приватной части ключа — подписать прошивку нечем.",
                        "The file has no private key part — nothing to sign the firmware with.",
                    )
                )
            return sign_fbl_odx_application(cf_src.read_bytes(), modulus, d_int, reporter=rep)

        def done(sig: bytes) -> None:
            self._key_file = key_path
            run_dialog(
                TextResultDialog(
                    self,
                    tr("Подпись прошивки", "Firmware signature"),
                    f'<FW-SIGNATURE TYPE="A_BYTEFIELD">{sig.hex().upper()}</FW-SIGNATURE>',
                    tr("Вставьте строку в контейнер .odx.", "Paste this line into the .odx container."),
                )
            )

        self.runner.run_task(tr("Подпись прошивки для ODX", "Signing firmware for ODX"), task, on_success=done)

    # ────────────────────────────── bench ──────────────────────────────
    def _dtc_run(self, clear: bool) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        sdir = self._session("dtc")

        def done(res: dict[str, Any]) -> None:
            self._dtc = list(res.get("dtc_records") or [])
            self._dtc_at = time.strftime("%H:%M")
            self._key = "dtc"
            self.refresh()

        self.runner.run_task(
            tr("Сброс ошибок блока", "Clearing trouble codes") if clear else tr("Чтение ошибок блока", "Reading trouble codes"),
            lambda rep: can_health_check(port, interface=iface, session_dir=sdir, clear_dtc=clear, reporter=rep),
            on_success=self._here(done),
        )

    def _swap_check(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        self.runner.run_task(
            tr("Проверка функций SWaP в блоке", "Checking SWaP features in the ECU"),
            lambda rep: can_swap_status(port, interface=iface, reporter=rep),
            on_success=self._here(self._swap_done),
        )

    def _swap_done(self, res: dict[str, Any]) -> None:
        self._swap_live = list(res.get("features") or [])
        self._swap_at = time.strftime("%H:%M")
        self._key = "swap"
        self.refresh()

    def _swap_area_changed(self) -> bool:
        """True when the edited DataFlash differs from the original in the SWaP NvM or its 15 certificate slots."""
        cur, orig = self.ws.path("dflash"), self.ws.original.get("dflash")
        if cur is None or orig is None or cur == orig:
            return False
        end = DFLASH_FSC_BASE_OFF + 15 * DFLASH_FSC_STRIDE
        try:
            return cur.read_bytes()[DFLASH_SWAP_NVM_OFF:end] != orig.read_bytes()[DFLASH_SWAP_NVM_OFF:end]
        except OSError:
            return False

    def _session(self, kind: str) -> Path:
        """A writes/ session in the folder of the gateway the loaded dumps belong to (storage.py)."""
        cf = self.ws.original.get("cflash")
        return new_session(self.conn.out_dir, unit_of_cflash(cf.read_bytes() if cf else None), kind)

    @staticmethod
    def _record_flashed(unit_dir: Path, sdir: Path, now_files: dict[str, Path | None], base_files: dict[str, Path]) -> Path:
        """What the ECU holds after the write, as the gateway's dumps/<date>_flashed: for each area written its readback
        (what the ECU answered, verified against what was meant), the loaded file for the rest. A bootloader that went
        in on the way (the engineering one) shows up the same way."""
        files: dict[str, Path] = {}
        for kind, name in zip(KINDS, AREA_FILES):
            rb = sdir / kind / name.replace(".bin", "_readback.bin")
            src = rb if rb.is_file() else now_files.get(kind)
            if src is not None:
                files[name] = src
        return record_flashed(unit_dir, files, sdir, base_files)

    def _adopt_uflash(self, session_dir: Path) -> None:
        """After a bootloader write, show the Uflash actually read back from the ECU."""
        rb = session_dir / "Uflash_readback.bin"
        if rb.is_file():
            self.ws.replace("uflash", rb)

    def _flash_bootloader(self, engineering: bool) -> None:
        """Activate the engineering bootloader or restore the factory one, directly on the ECU through FACI."""
        if not ensure_ready(self.conn, self):
            return
        question = (
            tr("Активировать в блоке инженерный загрузчик?", "Activate the engineering bootloader on the ECU?")
            if engineering
            else tr("Вернуть в блок заводской загрузчик?", "Restore the factory bootloader on the ECU?")
        )
        if QMessageBox.question(
            self,
            tr("Загрузчик", "Bootloader"),
            question
            + tr(
                "\n\nUflash перезаписывается через FACI. Перед записью он читается (если этот блок ещё ни разу не "
                "читался целиком — вся память), после — проверка чтением. Питание +12 В должно оставаться "
                "стабильным до конца операции.",
                "\n\nUflash is rewritten through FACI. It is read first (the whole memory if this ECU was never read "
                "completely) and the result is read back. The +12 V supply must stay stable until the operation "
                "finishes.",
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        port, iface = self.conn.port, self.conn.interface
        sdir = self._session("bootloader")
        have_read = has_full_read(sdir.parent.parent)  # a full copy only for a gateway never read completely
        self.runner.run_task(
            tr("Активация инженерного загрузчика", "Activating the engineering bootloader")
            if engineering
            else tr("Возврат заводского загрузчика", "Restoring the factory bootloader"),
            lambda rep: can_write_uflash(port, restore_stock=not engineering, interface=iface, session_dir=sdir,
                                         skip_full_backup=have_read, reporter=rep),
            on_success=self._here(lambda _r: self._adopt_uflash(sdir)),
        )

    def _revert(self) -> None:
        ans = QMessageBox.question(
            self,
            tr("Отменить изменения", "Discard changes"),
            tr(
                "Вернуться к исходным дампам? Изменённые копии останутся на диске.",
                "Go back to the original dumps? The edited copies stay on disk.",
            ),
        )
        if ans == QMessageBox.StandardButton.Yes:
            self.ws.revert()

    def _write_to_ecu(self) -> None:
        pending_kinds = [k for k in ("cflash", "dflash") if self.ws.pending(k)]  # Uflash goes via "Bootloader & signing"
        if not pending_kinds or not ensure_ready(self.conn, self):
            return
        target_names = ", ".join(NAMES[k] for k in pending_kinds)
        text = tr(
            f"Будут записаны: {target_names}.\n\nКаждая область перед записью читается из блока, после записи — "
            "проверяется чтением. Полная копия памяти снимается, только если этот блок ещё ни разу не читался"
            " целиком. Для прикладной области CodeFlash ContiTool сначала ставит инженерный загрузчик, если "
            "его нет.\n\nНе отключайте питание +12 В (Pin 1 и 14) до конца записи.",
            f"To be written: {target_names}.\n\nEach area is read from the ECU before the write and verified by "
            "reading it back after. A full memory copy is taken only if this ECU was never read completely. "
            "For the CodeFlash application ContiTool first installs the engineering bootloader if it is not "
            "there.\n\nKeep the +12 V supply (Pin 1 and 14) on until the write finishes.",
        )
        if QMessageBox.question(
            self,
            tr("Запись в блок", "Write to ECU"),
            text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return

        port, iface = self.conn.port, self.conn.interface
        sdir = self._session("write")
        unit_dir = sdir.parent.parent
        now_files = {k: self.ws.path(k) for k in KINDS}  # what each area is if this write does not touch it
        base_files = {CANDIDATES[k][0]: p for k, p in self.ws.original.items()}
        cf_path = self.ws.path("cflash") if "cflash" in pending_kinds else None
        df_path = self.ws.path("dflash") if "dflash" in pending_kinds else None
        cf_orig = self.ws.original.get("cflash")
        df_orig = self.ws.original.get("dflash")  # the backup the edits were made on: only the edits are written
        check_swap = df_path is not None and self._swap_area_changed()

        have_read = has_full_read(unit_dir)  # then each write reads only its own area

        def task(rep: Any) -> dict[str, Any]:
            out: dict[str, Any] = {"session_dir": str(sdir)}
            did_backup = have_read
            app_changed = cf_path is not None and (
                cf_orig is None
                or split_cflash_or_app(cf_path.read_bytes())[1] != split_cflash_or_app(cf_orig.read_bytes())[1]
            )
            if app_changed:
                # UDS programming of the application needs the engineering bootloader; boot blocks go via FACI
                out["uflash"] = can_write_uflash(
                    port,
                    restore_stock=False,
                    interface=iface,
                    session_dir=sdir / "uflash",
                    skip_full_backup=did_backup,
                    return_to_app=(df_path is None),
                    reporter=rep,
                )
                did_backup = did_backup or not bool(out["uflash"].get("step3_skipped_backup"))

            if df_path is not None:
                out["dflash"] = can_write_dflash(
                    port,
                    df_path,
                    base_dflash=df_orig.read_bytes() if df_orig is not None else None,
                    interface=iface,
                    session_dir=sdir / "dflash",
                    skip_full_backup=did_backup,
                    return_to_app=(cf_path is None),
                    reporter=rep,
                )
                did_backup = True

            if cf_path is not None:
                out["cflash"] = can_write_cflash(
                    port,
                    cf_path,
                    interface=iface,
                    session_dir=sdir / "cflash",
                    skip_backup=did_backup,  # a full read is on file, or the bootloader / DataFlash step took one
                    reporter=rep,
                )
                zdc_blocks = out.get("dflash", {}).get("zdc_blocks_written")
                if zdc_blocks:  # DataFlash went first without the application; its coding is due now
                    try:
                        out["auto_coding"] = can_sync_zdc_coding(port, df_path.read_bytes(), zdc_blocks, interface=iface, reporter=rep)
                    except Exception as exc:  # noqa: BLE001 — both areas are written and verified; only the coding is left
                        rep.warning(tr(
                            f"Запись прошла, но кодировку 0x0600 для датасетов ZDC {zdc_blocks} согласовать не удалось "
                            f"({exc}). Без неё датасеты не работают: повторите запись DataFlash или включите их в кодировке.",
                            f"The write succeeded, but coding 0x0600 for ZDC datasets {zdc_blocks} could not be aligned "
                            f"({exc}). Without it the datasets are not used: repeat the DataFlash write or enable them in the "
                            "coding.",
                        ))
            out["flashed"] = str(self._record_flashed(unit_dir, sdir, now_files, base_files))
            if check_swap:
                try:
                    out["swap"] = can_swap_status(port, interface=iface, reporter=rep)
                except Exception as exc:  # noqa: BLE001 — the write itself succeeded; this was only the confirmation
                    rep.warning(
                        tr(
                            f"Запись прошла, но прочитать состояние SWaP не удалось ({exc}). Нажмите «Проверить в блоке».",
                            f"The write succeeded but the SWaP state could not be read ({exc}). Press “Check in the ECU”.",
                        )
                    )
            return out

        def done(r: dict[str, Any]) -> None:
            flashed = Path(r["flashed"])
            self._folder = flashed  # the same ECU as it now is: what belongs to it stays
            self.ws.open_folder(flashed, source="can")  # what the ECU now holds; nothing left pending
            self.note.emit(tr(f"Открыты дампы, как они теперь в блоке: {flashed}", f"Opened the dumps as the ECU now holds them: {flashed}"))
            if "swap" in r:
                self._swap_done(r["swap"])
            if r.get("dflash", {}).get("zdc_blocks_written"):  # the runner is still busy here: tell once it is done
                QTimer.singleShot(0, lambda: QMessageBox.information(self, tr("Запись в блок", "Write to ECU"), _restart_note()))

        self.runner.run_task(
            tr(f"Запись в блок: {target_names}", f"Writing to ECU: {target_names}"),
            task,
            on_success=self._here(done),
        )
