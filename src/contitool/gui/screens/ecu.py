"""The working screen for one gateway: its identity, a list of functions with the selected one explained on
the right, and a panel saying which dumps changed and how each of them gets back into the ECU."""

from __future__ import annotations

from pathlib import Path
import shutil
import time
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
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
    QVBoxLayout,
    QWidget,
)

from contitool.can import (
    can_activate_swap,
    can_health_check,
    can_learn_mfl_button,
    can_read_gateway_coding,
    can_swap_status,
    can_upload_zdc_datasets,
    can_sync_zdc_coding,
    can_write_cflash,
    can_write_dflash,
    can_write_uflash,
)
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
    apply_cflash_rsa_modulus,
    apply_dflash_swap_fecs,
    apply_dflash_swap_rsa_modulus,
    apply_engineering_patch,
    apply_odis_zdc_file,
    bind_cp_turnkey,
    build_odis_zdc_file,
    build_signed_fsc,
    clear_dflash_slots,
    export_zdc_block,
    fecs_required_by_dataset,
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
from contitool.gui.connection import CanConnection, ensure_ready
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
from contitool.gui.theme import mono_font, set_tone
from contitool.gui.widgets.page import (
    Callout,
    Section,
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
)
from contitool.gui.worker import OperationRunner
from contitool.gui.workspace import CANDIDATES, KINDS, NAMES, Workspace
from contitool.storage import AREA_FILES, new_session, record_flashed, unit_of_cflash
from contitool.i18n import subscribe_lang_change, tr

GROUPS = (("main", ("cp", "eng", "swap", "zdc", "dtc")), ("service", ("boot",)))


def _title(key: str) -> str:
    return {
        "cp": tr("Привязка модулей", "Module pairing"),
        "eng": tr("Расширенная диагностика", "Extended diagnostics"),
        "swap": tr("Активация функций", "Feature activation"),
        "zdc": tr("Параметрирование", "Parameterization"),
        "dtc": tr("Ошибки блока", "Trouble codes"),
        "boot": tr("Загрузчик и подпись", "Bootloader & signing"),
    }[key]


class _NavRow(QWidget):
    """Function name with its current state on the right."""

    def __init__(self) -> None:
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 0, 8, 0)
        lay.setSpacing(8)
        self.lbl_name = QLabel()
        self.pill = pill()
        lay.addWidget(self.lbl_name, 1)
        lay.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)


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
        self.actions: dict[str, QPushButton] = {}  # buttons of the page on screen

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 18, 28, 14)
        outer.setSpacing(12)
        outer.addWidget(self._build_identity())
        split = QHBoxLayout()
        split.setSpacing(12)
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
        self.sec_id = Section()
        self.sec_id.body.setContentsMargins(20, 14, 20, 14)
        self.sec_id.body.setSpacing(8)
        self.lbl_pn = QLabel()
        self.lbl_pn.setObjectName("PartNumber")
        self.lbl_pn.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.pill_source = pill()
        self.sec_id.head.insertWidget(0, self.lbl_pn)
        self.sec_id.lbl_title.setVisible(False)
        self.sec_id.head.insertWidget(1, self.pill_source)
        self.sec_id.head.setAlignment(self.pill_source, Qt.AlignmentFlag.AlignVCenter)
        self.btn_export = button("", "GhostBtn", slot=self.export_backup)
        self.btn_restore = button("", "GhostBtn", slot=self.restore_requested.emit)
        self.btn_report = button("", "GhostBtn", slot=self.report_requested.emit)
        self.btn_close = button("", slot=self.close_requested.emit)
        self.sec_id.head.addWidget(self.btn_export)
        self.sec_id.head.addWidget(self.btn_restore)
        self.sec_id.head.addWidget(self.btn_report)
        self.sec_id.head.addWidget(self.btn_close)

        self.lbl_files = hint()
        self.sec_id.body.addWidget(self.lbl_files)
        self.sec_id.body.addWidget(divider())

        self.grid_id = QGridLayout()
        self.grid_id.setHorizontalSpacing(36)
        self.grid_id.setVerticalSpacing(3)
        self.sec_id.body.addLayout(self.grid_id)
        return self.sec_id

    def _build_nav(self) -> QWidget:
        sec = Section()
        sec.hide_head()
        sec.body.setContentsMargins(6, 4, 6, 6)
        sec.setFixedWidth(310)
        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        self.nav_rows: dict[str, _NavRow] = {}
        self._nav_items: dict[str, QListWidgetItem] = {}
        self._group_labels: dict[str, QLabel] = {}
        for group, keys in GROUPS:
            head = QListWidgetItem(self.nav)
            head.setFlags(Qt.ItemFlag.NoItemFlags)
            head.setSizeHint(QSize(0, 30))
            lbl = group_label()
            lbl.setContentsMargins(10, 10, 0, 0)
            self.nav.setItemWidget(head, lbl)
            self._group_labels[group] = lbl
            for key in keys:
                item = QListWidgetItem(self.nav)
                item.setData(Qt.ItemDataRole.UserRole, key)
                item.setSizeHint(QSize(0, 38))
                nav_row = _NavRow()
                self.nav.setItemWidget(item, nav_row)
                self.nav_rows[key] = nav_row
                self._nav_items[key] = item
        self.nav.currentItemChanged.connect(self._on_nav)
        sec.body.addWidget(self.nav)
        return sec

    def _build_page_area(self) -> QWidget:
        sec = Section()
        sec.hide_head()
        sec.body.setContentsMargins(0, 0, 0, 0)
        self.page_area = QScrollArea()
        self.page_area.setWidgetResizable(True)
        self.page_area.setFrameShape(QFrame.Shape.NoFrame)
        self.page_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sec.body.addWidget(self.page_area)
        return sec

    def _build_changes(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("WriteBar")
        lay = QVBoxLayout(bar)
        lay.setContentsMargins(16, 10, 14, 10)
        lay.setSpacing(6)
        top = QHBoxLayout()
        top.setSpacing(8)
        self.lbl_changes = QLabel()
        self.lbl_changes.setObjectName("FieldLabel")
        top.addWidget(self.lbl_changes)
        top.addStretch(1)
        self.btn_revert = button("", "GhostBtn", slot=self._revert)
        self.btn_save = button("", slot=self._save_dumps)
        self.btn_write = button("", "PrimaryBtn", slot=self._write_to_ecu)
        for b in (self.btn_revert, self.btn_save, self.btn_write):
            top.addWidget(b)
        lay.addLayout(top)
        self.grid_changes = QGridLayout()
        self.grid_changes.setHorizontalSpacing(14)
        self.grid_changes.setVerticalSpacing(3)
        lay.addLayout(self.grid_changes)
        bar.setVisible(False)
        return bar

    # ────────────────────────────── state ──────────────────────────────
    def _on_workspace_changed(self) -> None:
        if not self.ws.is_open:  # a different ECU next time: forget what belonged to this one
            self._dtc, self._key_file, self._swap_live = None, None, None
        self.refresh()

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
            self._render_page()

    def _refresh_identity(self) -> None:
        self.lbl_pn.setText(self.ws.part_number or tr("Блок не определён", "Unknown ECU"))
        set_pill(
            self.pill_source,
            tr("считан по CAN", "read over CAN") if self.ws.source == "can" else tr("из файлов", "from files"),
            "info" if self.ws.source == "can" else "muted",
        )
        self.btn_export.setText(tr("Экспортировать бэкап…", "Export backup…"))
        self.btn_export.setToolTip(tr("Копирует дампы в том виде, как они считаны, в выбранную папку", "Copies the dumps as read to a folder you pick"))
        self.btn_restore.setText(tr("Залить бэкап в блок…", "Write backup to ECU…"))
        self.btn_restore.setEnabled(not self.runner.is_busy)
        self.btn_report.setText(tr("Подробный отчёт", "Full report"))
        self.btn_close.setText(tr("Закрыть блок", "Close ECU"))

        clear_layout(self.grid_id)
        rows = status.passport_rows(self.ws)
        for col, (label, value, tone) in enumerate(rows):
            cap = QLabel(label.upper())
            cap.setObjectName("GroupLabel")
            val = QLabel(value)
            val.setFont(mono_font(13))
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if tone != "muted":
                set_tone(val, tone)
            self.grid_id.addWidget(cap, 0, col)
            self.grid_id.addWidget(val, 1, col)
        self.grid_id.setColumnStretch(len(rows), 1)

        parts = [NAMES[k] if self.ws.path(k) else tr(f"{NAMES[k]} — нет", f"{NAMES[k]} — missing") for k in KINDS]
        folder = self.ws.folder
        where = tr(f"папка {folder.name}", f"folder {folder.name}") if folder else ""
        self.lbl_files.setText("  ·  ".join(parts) + (f"    —    {where}" if where else ""))
        self.lbl_files.setToolTip(str(folder or ""))

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
            set_pill(nav_row.pill, st.text, st.tone)
        if self.nav.currentItem() is not self._nav_items[self._key]:
            self.nav.setCurrentItem(self._nav_items[self._key])

    # ────────────────────────────── page building blocks ──────────────────────────────
    def _render_page(self) -> None:
        if not self.ws.is_open:
            return
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 18, 24, 20)
        lay.setSpacing(12)
        self.actions = {}
        pages = {
            "cp": self._page_cp,
            "eng": self._page_eng,
            "swap": self._page_swap,
            "zdc": self._page_zdc,
            "dtc": self._page_dtc,
            "boot": self._page_boot,
        }
        pages[self._key](lay)
        lay.addStretch(1)
        self.page_area.setWidget(page)  # the scroll area deletes the previous page

    def _head(self, lay: QVBoxLayout, key: str) -> State:
        st = self._state(key)
        h = QHBoxLayout()
        h.setSpacing(10)
        t = QLabel(_title(key))
        t.setObjectName("PageTitle")
        h.addWidget(t)
        h.addWidget(pill(st.text, st.tone), 0, Qt.AlignmentFlag.AlignVCenter)
        h.addStretch(1)
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
        b.setEnabled(enabled and not self.runner.is_busy)
        b.setToolTip(tip)
        self.actions[key] = b
        return b

    def _block(
        self, lay: QVBoxLayout, title: str, state: State | None, text: str, *btns: QPushButton, num: str = ""
    ) -> None:
        """A bordered part of a page: optional step number, title with state, explanation, buttons."""
        frame = QFrame()
        frame.setObjectName("Step")
        g = QGridLayout(frame)
        g.setContentsMargins(14, 12, 14, 12)
        g.setHorizontalSpacing(12)
        g.setVerticalSpacing(6)
        col = 0
        if num:
            n = QLabel(num)
            n.setObjectName("StepNum")
            n.setFixedSize(22, 22)
            n.setAlignment(Qt.AlignmentFlag.AlignCenter)
            g.addWidget(n, 0, 0, Qt.AlignmentFlag.AlignTop)
            col = 1
        h = QHBoxLayout()
        h.setSpacing(8)
        t = QLabel(title)
        t.setObjectName("FieldLabel")
        h.addWidget(t)
        if state is not None:
            h.addWidget(pill(state.text, state.tone), 0, Qt.AlignmentFlag.AlignVCenter)
        h.addStretch(1)
        g.addLayout(h, 0, col)
        r = 1
        if text:
            g.addWidget(self._label(text), r, col)
            r += 1
        if btns:
            g.addLayout(row(*btns), r, col)
        g.setColumnStretch(col, 1)
        lay.addWidget(frame)

    @staticmethod
    def _table(lay: QVBoxLayout, title: str, rows: list[tuple[str, ...]], muted: bool = False) -> None:
        """Small read-only list: the first column in monospace, a third column muted."""
        frame = QFrame()
        frame.setObjectName("Step")
        g = QGridLayout(frame)
        g.setContentsMargins(14, 10, 14, 12)
        g.setHorizontalSpacing(16)
        g.setVerticalSpacing(4)
        g.addWidget(group_label(title.upper()), 0, 0, 1, 3)
        for r, cells in enumerate(rows, start=1):
            for c, text in enumerate(cells):
                lbl = QLabel(text)
                if c == 0:
                    lbl.setFont(mono_font(13))
                elif c == 1:
                    lbl.setWordWrap(True)  # long descriptions wrap instead of widening the page
                if muted or c == 2:
                    lbl.setObjectName("Hint")
                g.addWidget(lbl, r, c)
        g.setColumnStretch(1, 1)
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
                "Модули автомобиля — магнитола, приборная панель, усилитель и другие — проверяют через шлюз, что "
                "стоят в «своём» автомобиле (Component Protection). Привязка добавляет модуль с другого автомобиля "
                "по его ключу IKA; заводские модули продолжают работать как прежде.",
                "Vehicle modules — head unit, instrument cluster, amplifier and others — check through the gateway "
                "that they sit in “their” car (Component Protection). Binding adds a module from another car by its "
                "IKA key; factory modules keep working as before.",
            ),
        )
        if st.detail:
            self._text(lay, st.detail, primary=True)
        inf = self.ws.info("dflash")
        bound = [
            (s.spec.ecu_addr, tr(s.spec.short_ru, s.spec.short_en))
            for s in ((inf.dflash_slots or []) if inf else [])
            if s.spec.slot > 0 and not s.empty and s.kind == "PLAIN"
        ]
        if bound:
            self._table(lay, tr("Привязаны по ключу", "Bound by key"), bound)
        ok, tip = self._need("cflash", "dflash")
        lay.addLayout(row(self._btn("cp", tr("Привязать модули…", "Bind modules…"), self._bind_modules, "PrimaryBtn", ok, tip)))
        self._note(
            lay,
            tr(
                "Привязка меняет CodeFlash и DataFlash — оба дампа записываются в блок по CAN кнопкой «Записать в блок».",
                "Binding changes CodeFlash and DataFlash — both dumps are written to the ECU over CAN with “Write to ECU”.",
            ),
        )

    def _page_eng(self, lay: QVBoxLayout) -> None:
        st = self._head(lay, "eng")
        self._text(
            lay,
            tr(
                "Открывает закрытые на заводе инженерные службы шлюза: функции 0x80/0x81/0x83, ASAM CCP (чтение и "
                "запись памяти по CAN) и заводской RAM-Loader 0x6F0. Нужна для глубокой диагностики и сервисных "
                "работ с памятью блока.",
                "Opens the gateway's factory-locked engineering services: functions 0x80/0x81/0x83, ASAM CCP (memory "
                "read and write over CAN) and the factory RAM-Loader 0x6F0. Needed for deep diagnostics and service "
                "work on the ECU memory.",
            ),
        )
        if st.key == "partial":
            self._text(lay, st.detail, primary=True)
        ok, tip = self._need("cflash")
        if st.key == "on":
            btns = [self._btn("eng_off", tr("Выключить", "Turn off"), lambda: self._patch_engineering(True), "", ok, tip)]
        else:
            btns = [self._btn("eng_on", tr("Включить", "Turn on"), lambda: self._patch_engineering(False), "PrimaryBtn", ok, tip)]
            if st.key == "partial":
                btns.append(
                    self._btn("eng_off", tr("Вернуть заводское", "Restore factory"), lambda: self._patch_engineering(True), "GhostBtn", ok)
                )
        lay.addLayout(row(*btns))
        self._note(lay, tr("Меняется только CodeFlash — он записывается в блок по CAN.", "Only CodeFlash changes — it is written to the ECU over CAN."))

    def _page_swap(self, lay: QVBoxLayout) -> None:
        st = self._head(lay, "swap")
        self._text(
            lay,
            tr(
                "Функции SWaP / FeC шлюза (круиз-контроль GRA, контроль усталости MKE, профили движения FPA) можно "
                "включить напрямую в DataFlash в штатном заводском формате Multi-FSC — без генерации ключей RSA, "
                "без выпуска сертификатов и без модификации CodeFlash.",
                "Gateway SWaP / FeC features (GRA cruise control, MKE driver alert, FPA driving profiles) can be "
                "activated directly in DataFlash using the native factory Multi-FSC format — with no RSA keys, "
                "no certificates, and no CodeFlash modifications.",
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
                        (tr("Multi-FSC", "Multi-FSC") if factory else tr("RSA-FSC", "RSA-FSC"))
                        + " · "
                        + (tr("датасет ОК", "dataset OK") if ds_ok else tr("⚠ нет в датасете", "⚠ unsupported dataset")),
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
            tr("Прямая активация в DataFlash (рекомендуется)", "Direct activation in DataFlash (recommended)"),
            status.dataset_state(self.ws),
            tr(
                "Записывает выбранные коды FeC прямо в слоты Multi-FSC DataFlash и проверяет совместимость с "
                "текущим датасетом ZDC. Заводской ключ VAG и прошивка CodeFlash остаются полностью нетронутыми.",
                "Writes the selected FeC codes directly into DataFlash Multi-FSC slots and checks compatibility with "
                "the current ZDC dataset. The stock VAG key and CodeFlash firmware remain completely untouched.",
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
                "Ключ RSA-1024 вшивается в CodeFlash и в кэш SWaP в DataFlash. Новая пара сохраняется рядом с дампами "
                "в папке ContiTool_keys — приватную часть не теряйте: без неё сертификат не подписать.",
                "The RSA-1024 key goes into CodeFlash and the SWaP cache in DataFlash. A new pair is saved next to the "
                "dumps in ContiTool_keys — keep the private part: certificates cannot be signed without it.",
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
                "Сертификат отправляется в шлюз (адрес 19) командой UDS 31 01 06 55 — из CAN-терминала ContiTool или "
                "диагностическим тестером. Готовый сертификат можно сразу открыть в CAN-терминале.",
                "The certificate is sent to the gateway (address 19) with UDS 31 01 06 55 — from the ContiTool CAN "
                "terminal or a diagnostic tester. A ready certificate can be opened in the CAN terminal right away.",
            ),
            num="3",
        )

    def _swap_live_block(self, lay: QVBoxLayout) -> None:
        """What the gateway itself reports for every feature (UDS 22 3C 00): the proof that a patch was accepted."""
        btn = self._btn(
            "swap_check",
            tr("Проверить в блоке", "Check in the ECU") if self._swap_live is None else tr("Проверить снова", "Check again"),
            self._swap_check,
            "PrimaryBtn" if self._swap_live is None else "GhostBtn",
        )
        if self._swap_live is None:
            self._block(
                lay,
                tr("Состояние в блоке", "State in the ECU"),
                None,
                tr(
                    "Читает по CAN, какие функции блок сам считает активными (UDS 22 3C 00), — так видно, что патч "
                    "принят. После записи изменённой области SWaP проверка запускается сама.",
                    "Reads over CAN which features the ECU itself treats as active (UDS 22 3C 00) — this shows that "
                    "the patch was accepted. After writing a changed SWaP area the check runs by itself.",
                ),
                btn,
            )
            return

        frame = QFrame()
        frame.setObjectName("Step")
        g = QGridLayout(frame)
        g.setContentsMargins(14, 10, 14, 12)
        g.setHorizontalSpacing(14)
        g.setVerticalSpacing(7)
        g.addLayout(
            row(group_label(tr("СОСТОЯНИЕ В БЛОКЕ", "STATE IN THE ECU")), 1, hint(tr(f"проверено в {self._swap_at}", f"checked at {self._swap_at}")), btn),
            0, 0, 1, 3,
        )
        summary = status.swap_live_summary(self._swap_live, self.ws)
        box = Callout("info" if summary.tone == "muted" else summary.tone)
        box.label.setTextFormat(Qt.TextFormat.PlainText)
        box.label.setText(("✓  " if summary.key == "on" else "✕  " if summary.key == "err" else "") + summary.text)
        box.label.setObjectName("FieldLabel")
        g.addWidget(box, 1, 0, 1, 3)

        def code_label(code: int) -> QLabel:
            num = hint(f"{code:08X}")
            num.setFont(mono_font(12))
            return num

        states = [(status.swap_live_state(f["status"]), f["fsid"]) for f in self._swap_live]
        r = 2
        for st, code in sorted((s for s in states if s[0].key != "off"), key=lambda x: (x[0].key != "on", x[1])):
            g.addWidget(pill(st.text, st.tone), r, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
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
                tr(f"НЕ АКТИВИРОВАНЫ ({len(off)}) — БЛОК ИХ ЗНАЕТ, СЕРТИФИКАТА НЕТ", f"NOT ACTIVATED ({len(off)}) — SUPPORTED, NO CERTIFICATE")
            )
            head.setContentsMargins(0, 8, 0, 0)
            g.addWidget(head, r, 0, 1, 3)
            for r, code in enumerate(off, start=r + 1):
                g.addWidget(self._label(status.fec_name(code)), r, 1)
                g.addWidget(code_label(code), r, 2, Qt.AlignmentFlag.AlignRight)
        g.setColumnStretch(1, 1)
        lay.addWidget(frame)

    def _page_zdc(self, lay: QVBoxLayout) -> None:
        st = self._head(lay, "zdc")
        self._text(
            lay,
            tr(
                "Настройка поведения систем автомобиля: профили вождения и переключение кнопками (MODE и руль), "
                "память выбранного режима после перезапуска двигателя, контроль усталости водителя, "
                "подсказки Старт-Стоп на экране и выбор генератора.",
                "Configure vehicle subsystem behavior: driving profiles & physical buttons (MODE and steering wheel), "
                "ignition restart memory, driver fatigue detection, Start-Stop screen messages, and alternator model.",
            ),
        )
        if st.detail:
            self._text(lay, st.detail, primary=True)

        ok_df, tip_df = self._need("dflash")
        df_path = self.ws.path("dflash")
        raw_df = df_path.read_bytes() if (ok_df and df_path is not None and df_path.is_file()) else None

        unsup_active = status.unsupported_active_fecs(self.ws)
        if unsup_active and raw_df is not None:
            unsup_names = ", ".join(status.fec_name(c) for c in unsup_active)
            self._note(
                lay,
                tr(
                    f"Включённые функции ({unsup_names}) ещё не прописаны в параметрии — нажмите кнопку ниже, чтобы настроить их в один клик.",
                    f"Enabled features ({unsup_names}) are not yet configured in the parameterization — click below to set them up in one click.",
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
                act_profs = [s.name for s in fpa.slots() if s.selectable and 1 <= s.profile_id <= 15]
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
                kl15_ok = fpa.all_active_profiles_persist_kl15 and fpa.powertrain_persists_kl15
                fpa_st = State(
                    tr(f"режимов: {len(act_profs)}", f"{len(act_profs)} modes"),
                    "ok",
                    key="on",
                )
                fpa_desc = tr(
                    f"Доступны: {', '.join(act_profs)} · Переключение: {btn_map.get(bcfg.mode, bcfg.mode)} · "
                    f"Память после перезапуска: {'включена (профиль и коробка/газ)' if kl15_ok else 'заводской сброс в Normal'}.",
                    f"Enabled: {', '.join(act_profs)} · Buttons: {btn_map.get(bcfg.mode, bcfg.mode)} · "
                    f"Restart memory: {'enabled (profile & powertrain)' if kl15_ok else 'factory reset to Normal'}.",
                )
            elif fpa.crc_ok:
                fpa_st = State(tr("отключены", "disabled"), "muted", key="off")
                fpa_desc = tr(
                    "Записан базовый шаблон без выбора профилей вождения — откройте настройку, чтобы включить нужные режимы.",
                    "Base gateway template without selectable driving profiles — open settings to enable modes.",
                )
            else:
                fpa_st = State(tr("не настроено", "not set"), "warn", key="off")
                fpa_desc = tr(
                    "Профили вождения ещё не настроены — нажмите кнопку ниже, чтобы выбрать готовый шаблон под ваш автомобиль.",
                    "Driving profiles are not configured yet — click below to pick a ready-made template for your car.",
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
                    0: tr("скрыты", "hidden"),
                    1: tr("стандартно", "standard"),
                    3: tr("подробно", "detailed"),
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
            tr("Профили вождения и кнопки (MODE и руль)", "Driving Profiles & Buttons (MODE & Wheel)"),
            fpa_st,
            fpa_desc,
            self._btn(
                "zdc_fpa",
                tr("Настроить профили и кнопки…", "Configure profiles & buttons…"),
                self._open_fpa_editor,
                "PrimaryBtn",
                ok_df,
                tip_df,
            ),
        )
        self._block(
            lay,
            tr("Контроль усталости водителя (MKE)", "Driver Fatigue Detection (MKE)"),
            mke_st,
            tr(
                "Скорость автоматического включения слежения (обычно с 65 км/ч) и длительность остановки для сброса предупреждения.",
                "Speed threshold for fatigue monitoring (typically 65 km/h) and stop duration required to reset the warning.",
            ),
            self._btn("zdc_mke", tr("Настроить…", "Configure…"), self._open_mke_editor, "", ok_df, tip_df),
        )
        self._block(
            lay,
            tr("Уведомления системы Старт-Стоп на экране", "Start-Stop Screen Notifications"),
            ssa_st,
            tr(
                "Показ на экране магнитолы понятных причин, почему двигатель сейчас не заглушен или запустился автоматически.",
                "Controls whether and how Start-Stop status and inhibition reasons appear on the head-unit screen.",
            ),
            self._btn("zdc_ssa", tr("Настроить…", "Configure…"), self._open_ssa_editor, "", ok_df, tip_df),
        )
        self._block(
            lay,
            tr("Генератор 14В и умная зарядка (BEM)", "14V Alternator & Smart Charging (BEM)"),
            bem_st,
            tr(
                "Выбор установленного на автомобиле генератора (Bosch, Valeo, Denso от 110 А до 250 А) из заводского каталога.",
                "Pick the vehicle's installed alternator (Bosch, Valeo, Denso 110A–250A) from the built-in factory catalog.",
            ),
            self._btn("zdc_bem", tr("Выбрать генератор…", "Select alternator…"), self._open_bem_editor, "", ok_df, tip_df),
        )

        lay.addWidget(divider())
        lay.addWidget(group_label(tr("ЗАПИСЬ В МАШИНУ ПО CAN И ДОПОЛНИТЕЛЬНО", "DIRECT CAN WRITE & ADVANCED")))
        self._block(
            lay,
            tr("Быстрая запись параметрии по CAN (без разборки блока)", "Quick Parameterization Write over CAN (No Boot Mode)"),
            None,
            tr(
                "Записывает настроенную параметрию напрямую через разъём OBD в машине или на столе за пару секунд — "
                "разбирать шлюз и активировать инженерный загрузчик не требуется.",
                "Writes configured parameterization directly over OBD in the car or on the bench in seconds — "
                "no boot mode or bootloader modification needed.",
            ),
            self._btn(
                "zdc_can_upload",
                tr("Записать параметрию по CAN…", "Write over CAN…"),
                self._upload_zdc_over_can,
                "PrimaryBtn",
                ok_df,
                tip_df,
            ),
            self._btn(
                "zdc_learn_mfl",
                tr("Проверить кнопку руля по CAN…", "Test wheel button over CAN…"),
                self._test_mfl_button_live,
                "GhostBtn",
            ),
        )
        self._block(
            lay,
            tr("Паспорт параметрии и перенос разделов", "Dataset Passport & Section Transfer"),
            pp_st,
            tr(
                "Диагностический номер и версия датасета (отображаются в сканере), а также сохранение и перенос отдельных разделов из другого дампа.",
                "Diagnostic dataset part number & version, plus standalone section export/import from another dump.",
            ),
            self._btn("zdc_passport", tr("Паспорт и разделы…", "Passport & sections…"), self._open_passport_editor, "", ok_df, tip_df),
        )
        self._block(
            lay,
            tr("Экспорт и импорт параметрии", "Dataset export & import"),
            None,
            tr(
                "Экспорт сохраняет каждый заполненный блок ZDC файлом параметрии ODIS (.xml) и как есть (.bin), плюс всю "
                "область параметрии. Импорт берёт датасет из файла ODIS вместе с его номером и версией.",
                "Export saves every populated ZDC block as an ODIS parameterization file (.xml) and as it is (.bin), plus "
                "the whole dataset area. Import takes a dataset from an ODIS file together with its number and version.",
            ),
            self._btn("zdc_export", tr("Экспорт параметрии…", "Export datasets…"), self._export_zdc, "", ok_df, tip_df),
            self._btn("zdc_import_odis", tr("Импорт файла ODIS…", "Import ODIS file…"), self._import_odis_zdc, "", ok_df, tip_df),
        )

    def _page_dtc(self, lay: QVBoxLayout) -> None:
        self._head(lay, "dtc")
        self._text(
            lay,
            tr(
                "Коды неисправностей читаются из блока на стенде по CAN — в дампах их нет.",
                "Trouble codes are read live from the bench ECU over CAN — dumps do not contain them.",
            ),
        )
        lay.addLayout(
            row(
                self._btn("dtc", tr("Прочитать ошибки", "Read codes"), lambda: self._dtc_run(False), "PrimaryBtn"),
                self._btn("dtc_clear", tr("Стереть ошибки", "Clear codes"), lambda: self._dtc_run(True), "GhostBtn"),
            )
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
            summary.setText(tr(f"Неисправностей нет · прочитано в {self._dtc_at}", f"No faults · read at {self._dtc_at}"))
            set_tone(summary, "ok")

        def rows(items: list[tuple[int, int]], status: str = "") -> list[tuple[str, ...]]:
            out = []
            for code, st in items:
                display, text = dtc.describe(code)
                out.append((display or f"{code:06X}", text, f"{status or dtc.status_text(st)} · {code:06X}"))
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
                        "Это не ошибки, а список проверок, которые блок ещё не провёл после стирания: результата у них "
                        "пока нет. Часть из них (память, сторожевой таймер) выполняется только при цикле зажигания — "
                        "выключите клемму 15, дайте блоку уснуть и включите снова.",
                        "These are not faults but checks the ECU has not run since codes were cleared: they have no "
                        "result yet. Some (memory, watchdog) only run over an ignition cycle — switch terminal 15 off, "
                        "let the ECU go to sleep and switch it on again.",
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
                "Uflash меняется только через FACI: в RAM блока по CAN загружается программа, которая перезаписывает "
                "загрузчик, затем — проверка чтением. Перед записью CodeFlash ContiTool активирует инженерный загрузчик "
                "сам, если он ещё не активен, — отдельно нажимать ничего не нужно.",
                "Uflash can be changed only through FACI: a program is loaded into the ECU's RAM over CAN, rewrites the "
                "bootloader, and the result is read back. Before writing CodeFlash, ContiTool activates the engineering "
                "bootloader itself if it is not active yet — no separate step needed.",
            )
            + ("" if st.known else "\n" + tr("Состояние видно по дампу Uflash.", "The state comes from the Uflash dump.")),
            *btns,
        )

        fbl = status.fbl_key(self.ws)
        ok, tip = self._need("cflash")
        btns = [
            self._btn("fbl_key", tr("Вшить свой ключ…", "Embed your key…"), lambda: self._replace_key("fbl"), "", ok, tip),
            self._btn("odx", tr("Подписать прошивку для ODX…", "Sign firmware for ODX…"), self._sign_odx, "GhostBtn", ok, tip),
        ]
        if fbl.key == "custom":
            btns.append(self._btn("fbl_stock", tr("Вернуть ключ VAG", "Restore VAG key"), lambda: self._restore_key("fbl"), "GhostBtn", ok))
        self._block(
            lay,
            tr("Свой ключ FBL — для ODX и ODIS", "Your FBL key — for ODX and ODIS"),
            fbl,
            tr(
                "Вместо инженерного загрузчика можно вшить свой ключ и подписывать им прошивку, например для "
                "контейнера .odx под ODIS. Ключ лежит в области загрузчика CodeFlash (0xA2F7) и также записывается "
                "в блок по CAN через FACI кнопкой «Записать в блок».",
                "Instead of the engineering bootloader you can embed your own key and sign firmware with it, e.g. for an "
                ".odx container for ODIS. The key lives in the CodeFlash bootloader area (0xA2F7) and is also written "
                "to the ECU over CAN through FACI with “Write to ECU”.",
            ),
            *btns,
        )

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
            self.grid_changes.addWidget(pill(tag, tone), r, 1, Qt.AlignmentFlag.AlignLeft)
            self.grid_changes.addWidget(hint(how), r, 2)
        self.grid_changes.setColumnStretch(2, 1)

        busy = self.runner.is_busy
        self.btn_save.setText(tr("Сохранить дампы…", "Save dumps…"))
        self.btn_save.setToolTip(tr("Копирует изменённые дампы в выбранную папку", "Copies the changed dumps to a folder you pick"))
        self.btn_revert.setText(tr("Отменить изменения", "Discard changes"))
        self.btn_write.setText(tr("Записать в блок", "Write to ECU"))
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

        self.runner.run_task(title, task, on_success=lambda p: self.ws.commit(kind, p))

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
        self.runner.run_task(tr(f"Привязка модулей: {addrs}", f"Binding modules: {addrs}"), task, on_success=done)

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
            tr("Прямая настройка функций SWaP в DataFlash", "Direct SWaP feature setup in DataFlash"),
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
            tr("Автопараметризация датасета ZDC под активные функции SWaP", "Auto-parameterizing ZDC dataset for active SWaP features"),
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
            on_success=lambda pre: QTimer.singleShot(0, lambda: self._zdc_upload_plan(df_bytes, pre)),
        )

    def _zdc_upload_plan(self, df_bytes: bytes, pre: dict[str, Any]) -> None:
        self._swap_live, self._swap_at = list(pre["features"]), time.strftime("%H:%M")
        active = {f["fsid"] for f in pre["features"] if status.swap_live_state(f["status"]).key == "on"}
        required = fecs_required_by_dataset(df_bytes)
        missing = [c for c in required if c not in active]
        blocks = [i for i in sorted(ZDC_UDS_UPLOAD_MAP) if any(b != 0xFF for b in export_zdc_block(df_bytes, i))]
        coding = bytes(pre["coding"])
        want = sync_gateway_coding_for_zdc(df_bytes, coding, blocks=blocks)
        diff = [i for i in range(len(want)) if want[i] != coding[i]]
        lines = []
        if missing:
            names = "\n".join(f"• {status.fec_name(c)}" for c in missing)
            lines.append(tr(
                f"Датасет требует функций SWaP, которые в блоке не активны:\n{names}\n\nШтатной команды для этого "
                "нет: активировать их можно только записью области SWaP в DataFlash через RAM-Loader (остальной "
                "DataFlash не меняется).",
                f"The dataset needs SWaP features the ECU does not have active:\n{names}\n\nThere is no standard "
                "command for that: they can only be switched on by writing the SWaP area of DataFlash through the "
                "RAM-Loader (the rest of DataFlash stays as it is).",
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
            self._zdc_upload_run(df_bytes, missing if clicked is act else [])
        else:
            self.refresh()

    def _zdc_upload_run(self, df_bytes: bytes, activate: list[int]) -> None:
        port, iface = self.conn.port, self.conn.interface
        sdir = self._session("zdc_upload")

        def task(rep: Any) -> dict[str, Any]:
            out: dict[str, Any] = {"session_dir": str(sdir)}
            if activate:
                out["swap"] = can_activate_swap(port, activate, interface=iface, session_dir=sdir / "swap", reporter=rep)
            out["upload"] = can_upload_zdc_datasets(port, df_bytes, interface=iface, session_dir=sdir / "upload", reporter=rep)
            out["features"] = can_swap_status(port, interface=iface, reporter=rep)["features"]  # did the ECU take them?
            return out

        def done(res: dict[str, Any]) -> None:
            self._swap_live, self._swap_at = list(res["features"]), time.strftime("%H:%M")
            QTimer.singleShot(0, lambda: self._offer_dtc_clear(res, activate))

        self.runner.run_task(tr("Загрузка параметрии по CAN", "Dataset upload over CAN"), task, on_success=done)

    def _offer_dtc_clear(self, res: dict[str, Any], activated: list[int]) -> None:
        active = {f["fsid"] for f in res["features"] if status.swap_live_state(f["status"]).key == "on"}
        refused = [c for c in activated if c not in active]
        text = tr("Параметрия загружена.", "The datasets are uploaded.")
        if refused:
            text += tr(f"\n\nБлок не принял SWaP: {', '.join(status.fec_name(c) for c in refused)} — подробности на "
                       "странице «Активация функций».",
                       f"\n\nThe ECU did not accept SWaP: {', '.join(status.fec_name(c) for c in refused)} — details on "
                       "the Feature activation page.")
        elif activated:
            text += tr(" Функции SWaP активны в блоке.", " The SWaP features are active in the ECU.")
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
        self.runner.run_task(title, task, on_success=done)

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

        self.runner.run_task(tr(f"Подпись сертификата {fec:08X}", f"Signing certificate {fec:08X}"), task, on_success=done)

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
            on_success=done,
        )

    def _swap_check(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        self.runner.run_task(
            tr("Проверка функций SWaP в блоке", "Checking SWaP features in the ECU"),
            lambda rep: can_swap_status(port, interface=iface, reporter=rep),
            on_success=self._swap_done,
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
                "\n\nUflash перезаписывается через FACI. Перед записью снимается полная копия памяти, после — "
                "проверка чтением. Питание +12 В должно оставаться стабильным до конца операции.",
                "\n\nUflash is rewritten through FACI. A full memory backup is taken first and the result is read "
                "back. The +12 V supply must stay stable until the operation finishes.",
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        port, iface = self.conn.port, self.conn.interface
        sdir = self._session("bootloader")
        self.runner.run_task(
            tr("Активация инженерного загрузчика", "Activating the engineering bootloader")
            if engineering
            else tr("Возврат заводского загрузчика", "Restoring the factory bootloader"),
            lambda rep: can_write_uflash(port, restore_stock=not engineering, interface=iface, session_dir=sdir, reporter=rep),
            on_success=lambda _r: self._adopt_uflash(sdir),
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
            f"В блок по CAN будут записаны: {target_names}\n\n"
            "1. Снимается полная резервная копия памяти блока.\n"
            "2. При записи прикладной области CodeFlash при необходимости активируется инженерный загрузчик.\n"
            "3. Все изменённые области (CodeFlash включая бут-сектор, DataFlash и/или Uflash) записываются и проверяются чтением побайтово.\n\n"
            "Питание +12 В (Pin 1 и Pin 14) должно оставаться стабильным до конца операции.",
            f"The following will be written to the ECU over CAN: {target_names}\n\n"
            "1. A full memory backup of the ECU is taken.\n"
            "2. When writing Application CodeFlash, the engineering bootloader is activated if needed.\n"
            "3. All changed regions (CodeFlash including boot blocks, DataFlash, and/or Uflash) are programmed and verified byte by byte.\n\n"
            "The +12 V supply (Pin 1 and Pin 14) must stay stable until the operation finishes.",
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

        def task(rep: Any) -> dict[str, Any]:
            out: dict[str, Any] = {"session_dir": str(sdir)}
            did_backup = False
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
                    return_to_app=(df_path is None),
                    reporter=rep,
                )
                did_backup = not bool(out["uflash"].get("step3_skipped_backup"))

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
                    skip_backup=did_backup,  # the bootloader or DataFlash step took the full backup already
                    reporter=rep,
                )
                zdc_blocks = out.get("dflash", {}).get("zdc_blocks_written")
                if zdc_blocks:  # DataFlash went first without the application; its coding is due now
                    try:
                        out["auto_coding"] = can_sync_zdc_coding(port, df_path.read_bytes(), zdc_blocks, interface=iface, reporter=rep)
                    except Exception as exc:  # noqa: BLE001 — both areas are written and verified; only the coding is left
                        rep.warning(tr(
                            f"Запись прошла, но кодировку 0x0600 под датасеты ZDC {zdc_blocks} согласовать не удалось ({exc}). "
                            "Без неё датасеты не используются — повторите запись DataFlash или включите их в кодировке.",
                            f"The write succeeded but coding 0x0600 for ZDC datasets {zdc_blocks} could not be aligned ({exc}). "
                            "Without it the datasets are not used — write DataFlash again or enable them in the coding.",
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
            self.ws.open_folder(flashed, source="can")  # what the ECU now holds; nothing left pending
            self.note.emit(tr(f"Открыты дампы, как они теперь в блоке: {flashed}", f"Opened the dumps as the ECU now holds them: {flashed}"))
            if "swap" in r:
                self._swap_done(r["swap"])

        self.runner.run_task(
            tr(f"Запись в блок: {target_names}", f"Writing to ECU: {target_names}"),
            task,
            on_success=done,
        )
