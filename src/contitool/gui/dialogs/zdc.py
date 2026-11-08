"""User-friendly ZDC parameterization dialogs: Driving Profiles & Buttons (FPA), Driver Alert (MKE), Start-Stop, Alternator (BEM), and Passport/Blocks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from contitool.can import can_learn_mfl_button, can_read_gateway_coding, can_write_gateway_coding
from contitool.core import (
    BEM_SUPPLIER_NAMES,
    FPA_PRESET_CATALOG,
    FPA_TARGET_MODE_NAMES,
    MFL_KEYCODE_PRESETS,
    ROM_BEM_CATALOG,
    SSA_OUTPUT_MODES,
    FpaDataset,
    analyze_dflash_datasets,
    analyze_gateway_coding_consistency,
    apply_fpa_dataset,
    apply_mke_config,
    apply_ssa_config,
    apply_zdc_passport,
    build_fpa_preset_block,
    erase_zdc_block,
    export_zdc_block,
    import_zdc_block,
    inject_bem_preset,
    inject_mke_preset,
    inject_ssa_preset,
    parse_bem_block,
    parse_mke_block,
    parse_ssa_block,
    parse_zdc_passport,
    replace_bem_slot_from_rom,
    sync_gateway_coding_for_zdc,
)
from contitool.gui import theme
from contitool.gui.connection import CanConnection, ensure_ready
from contitool.gui.theme import mono_font
from contitool.gui.widgets.page import Callout, Dialog, Section, button, divider, group_label, hint, row
from contitool.gui.worker import OperationRunner
from contitool.i18n import get_lang, tr

# Human-readable descriptions for standard driving profile slots 1..9
_SLOT_DESCRIPTIONS: dict[int, tuple[str, str, str, str]] = {
    1: (
        "Comfort",
        "Comfort",
        "Мягкая подвеска DCC и плавные отклики для трассы и неровных дорог",
        "Soft DCC damping and relaxed responses for cruising",
    ),
    2: (
        "Normal",
        "Normal",
        "Стандартный сбалансированный режим на каждый день",
        "Balanced everyday factory driving mode",
    ),
    3: (
        "Sport",
        "Sport",
        "Острый отклик педали газа, руля, подвески и спорт-режим КПП (S)",
        "Sharper throttle, steering, chassis, and gearbox Sport (S) mode",
    ),
    4: (
        "Offroad",
        "Offroad",
        "Внедорожный режим полного привода, ABS/ESC и помощник спуска с горы",
        "Offroad AWD traction logic, ABS/ESC calibration, and hill descent",
    ),
    5: (
        "Eco",
        "Eco",
        "Экономичный режим климата, плавная тяга и движение накатом",
        "Fuel-saving throttle, climate eco mode, and coasting (freewheeling)",
    ),
    6: (
        "Race / Cupra",
        "Race / Cupra",
        "Максимальный спортивный режим (Golf R / Audi S3 / Cupra)",
        "Maximum performance track mode (Golf R / Audi S3 / Cupra)",
    ),
    7: (
        "Individual",
        "Individual",
        "Персональный режим — водитель сам настраивает каждый узел на экране ГУ",
        "Custom mode — driver picks each subsystem's behaviour on the head unit",
    ),
    8: (
        "Snow",
        "Snow",
        "Зимний режим плавного старта и уверенной тяги на снегу и льду",
        "Winter mode with gentle throttle and snow traction control",
    ),
    9: (
        "Allroad / Доп.",
        "Allroad / Extra",
        "Дополнительный вседорожный слот (для некоторых версий шасси)",
        "Additional all-road profile slot (chassis-specific)",
    ),
}

_WHEEL_QUICK_PAIRS: tuple[tuple[str, tuple[int, int], str, str], ...] = (
    ("2_3", (2, 3), "Быстрое переключение 2 режимов: Normal ↔ Sport", "Quick 2-mode toggle: Normal ↔ Sport"),
    ("2_7", (2, 7), "Быстрое переключение 2 режимов: Normal ↔ Individual", "Quick 2-mode toggle: Normal ↔ Individual"),
    ("2_6", (2, 6), "Быстрое переключение 2 режимов: Normal ↔ Race / Cupra", "Quick 2-mode toggle: Normal ↔ Race / Cupra"),
)


def _scroll_tab(content: QWidget) -> QScrollArea:
    for sec in content.findChildren(Section):
        sec.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        sec.lbl_desc.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setWidget(content)
    return area


def _slot_short_name(slot: int) -> str:
    meta = _SLOT_DESCRIPTIONS.get(slot)
    if meta:
        return meta[1] if get_lang() == "en" else meta[0]
    return f"#{slot}"


def _format_ring_preview(slots: list[int]) -> str:
    names = [_slot_short_name(s) for s in slots if 1 <= s <= 12]
    if not names:
        return "—"
    if len(names) == 2:
        return f"{names[0]} ↔ {names[1]}"
    return " → ".join(names)


class FpaEditorDialog(Dialog):
    """User-friendly editor for Driving Profiles (`FPA`), `Kl.15` memory, and Console `MODE` + Steering-Wheel buttons."""

    def __init__(
        self,
        df: bytes,
        conn: CanConnection | None = None,
        runner: OperationRunner | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(
            parent,
            tr("Профили вождения и кнопки переключения", "Driving Profiles & Mode Buttons"),
            tr(
                "Выберите доступные режимы вождения, включите память профиля после перезапуска двигателя "
                "и настройте переключение кнопкой MODE на консоли и кнопкой на руле.",
                "Choose available driving modes, keep your selected profile across engine restarts, "
                "and configure switching via the console MODE button and steering-wheel button.",
            ),
            width=920,
        )
        self._df = bytes(df)
        self._conn = conn
        self._runner = runner

        self._orig_loaded = FpaDataset.from_dflash(self._df)
        self._was_empty = self._orig_loaded.empty or not self._orig_loaded.crc_ok
        self._was_passive = (not self._was_empty) and self._orig_loaded.is_passive_base
        self._needs_onboarding = self._was_empty or self._was_passive
        self._unconfigured = self._needs_onboarding
        self.fpa = FpaDataset(bytes(self._orig_loaded.buf))

        self.cmb_preset = QComboBox()
        if self._needs_onboarding:
            self.cmb_preset.addItem(
                tr(
                    "— Не выбрано (сейчас в дампе профилей нет) —",
                    "— Not selected (no profiles in dump right now) —",
                ),
                "",
            )
        for key, ru, en in FPA_PRESET_CATALOG:
            self.cmb_preset.addItem(en if get_lang() == "en" else ru, key)
        if not self._needs_onboarding:
            det_idx = self.cmb_preset.findData(self.fpa.detected_preset())
            if det_idx >= 0:
                self.cmb_preset.setCurrentIndex(det_idx)

        self.cmb_schema = QComboBox()
        self.cmb_schema.addItem(tr("Автоматически (под версию прошивки)", "Automatic (match ECU firmware)"), "")
        for tag, desc in (("PC00", "PC00 (2WD)"), ("NC00", "NC00 (4Motion)"), ("JC00", "JC00 (SW 5366)")):
            self.cmb_schema.addItem(desc, tag)
        self.cmb_schema.setVisible(False)
        self.lbl_schema_info = hint()
        self.lbl_schema_info.setVisible(False)
        self.btn_load_preset = button(tr("Перезаполнить по шаблону", "Overwrite with template"), slot=self._on_load_preset)

        if self._needs_onboarding:
            self.onboard_frame = QFrame()
            self.onboard_frame.setObjectName("Callout")
            ob_lay = QVBoxLayout(self.onboard_frame)
            ob_lay.setContentsMargins(16, 12, 16, 12)
            ob_lay.setSpacing(8)
            self.lbl_onboard = QLabel()
            self.lbl_onboard.setWordWrap(True)
            ob_lay.addWidget(self.lbl_onboard)
            pick_lay = QHBoxLayout()
            pick_lay.setSpacing(10)
            pick_lay.addWidget(QLabel(tr("Комплектация автомобиля:", "Vehicle configuration:")))
            pick_lay.addWidget(self.cmb_preset, 1)
            ob_lay.addLayout(pick_lay)
            self.cmb_preset.currentIndexChanged.connect(lambda _i: self._on_load_preset())
            self.btn_load_preset.setVisible(False)
            self.body.addWidget(self.onboard_frame)
            self.lbl_detected_base = QLabel()
            self.lbl_detected_base.setVisible(False)
            self.pnl_reset_preset = QWidget()
            self.pnl_reset_preset.setVisible(False)
        else:
            self.onboard_frame = None
            self.lbl_onboard = None
            status_bar = QHBoxLayout()
            status_bar.setSpacing(8)
            self.lbl_detected_base = hint()
            self.btn_toggle_reset = button(
                tr("Сбросить по шаблону авто ▸", "Reset from car template ▸"),
                "GhostBtn",
            )
            self.btn_toggle_reset.setCheckable(True)
            self.btn_toggle_reset.toggled.connect(self._on_toggle_reset_preset)
            status_bar.addWidget(self.lbl_detected_base, 1)
            status_bar.addWidget(self.btn_toggle_reset)
            self.body.addLayout(status_bar)

            self.pnl_reset_preset = QFrame()
            self.pnl_reset_preset.setObjectName("Step")
            rp_lay = QVBoxLayout(self.pnl_reset_preset)
            rp_lay.setContentsMargins(14, 10, 14, 10)
            rp_lay.setSpacing(8)
            rp_lay.addWidget(
                hint(
                    tr(
                        "Используйте только если блок взят с другой машины (например, с полного привода на передний) "
                        "и нужно полностью заменить базовые таблицы агрегатов заводским шаблоном:",
                        "Use only if the ECU came from a different car (e.g. AWD to FWD) and you want to replace "
                        "all subsystem tables with a fresh factory template:",
                    )
                )
            )
            preset_bar = QHBoxLayout()
            preset_bar.setSpacing(8)
            preset_bar.addWidget(self.cmb_preset, 1)
            preset_bar.addWidget(self.btn_load_preset)
            rp_lay.addLayout(preset_bar)
            self.pnl_reset_preset.setVisible(False)
            self.body.addWidget(self.pnl_reset_preset)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_tab_profiles(), tr("Профили и память", "Profiles & Memory"))
        self.tabs.addTab(self._build_tab_buttons(), tr("Кнопки MODE и руль", "MODE & Wheel Buttons"))
        self.tabs.addTab(self._build_tab_matrix(), tr("Режимы агрегатов", "Subsystem Modes"))
        self.tabs.addTab(self._build_tab_individual(), tr("Меню Individual", "Individual Menu"))
        self.tabs.addTab(self._build_tab_coding(), tr("Кодировка блока", "ECU Coding"))
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.body.addWidget(self.tabs, 1)

        self.btn_ok = button(tr("Сохранить настройки", "Save settings"), "PrimaryBtn", slot=self._on_accept)
        self.finish(ok=self.btn_ok)
        self.resize(940, 780)
        self._load_all_from_fpa()

    # ── Tab 1: Profiles & Ignition Memory ──

    def _build_tab_profiles(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(12)

        sec_mem = Section()
        sec_mem.set_text(
            tr("Память профиля после выключения зажигания", "Remember profile after engine restart"),
            tr(
                "По заводским нормам после каждого запуска двигателя коробка DSG, педаль газа и Старт-Стоп "
                "принудительно сбрасываются обратно в обычный режим Normal. Эти две галочки убирают сброс.",
                "By factory default, gearbox Sport mode, throttle response, and Start-Stop reset to Normal on every "
                "ignition restart. Enable both options below to keep your chosen mode.",
            ),
        )
        self.chk_kl15_profiles = QCheckBox(
            tr(
                "Запоминать выбранный профиль вождения (Comfort, Sport, Eco, Individual…)",
                "Remember the selected driving profile across ignition restarts",
            )
        )
        self.chk_kl15_powertrain = QCheckBox(
            tr(
                "Не сбрасывать коробку DSG (S), отклик двигателя и Старт-Стоп в обычный режим",
                "Keep gearbox (S), engine response, and Start-Stop mode after restart",
            )
        )
        self.chk_kl15_profiles.toggled.connect(self._on_kl15_profiles_toggled)
        self.chk_kl15_powertrain.toggled.connect(self._on_kl15_powertrain_toggled)
        sec_mem.body.addWidget(self.chk_kl15_profiles)
        sec_mem.body.addWidget(self.chk_kl15_powertrain)
        lay.addWidget(sec_mem)

        sec_profs = Section()
        sec_profs.set_text(
            tr("Доступные профили на экране магнитолы", "Profiles shown on the head-unit screen"),
            tr(
                "Отметьте галочками режимы, которые должны отображаться на экране автомобиля.",
                "Tick the driving modes that should appear on the head-unit selection screen.",
            ),
        )
        self.tbl_slots = QTableWidget(9, 3)
        self.tbl_slots.setHorizontalHeaderLabels(
            [
                tr("Профиль", "Profile"),
                tr("Описание режима", "What it does"),
                tr("Состояние", "State"),
            ]
        )
        self.tbl_slots.verticalHeader().setVisible(False)
        self.tbl_slots.verticalHeader().setDefaultSectionSize(29)
        self.tbl_slots.setShowGrid(False)
        self.tbl_slots.setAlternatingRowColors(True)
        self.tbl_slots.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.tbl_slots.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.tbl_slots.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        hh = self.tbl_slots.horizontalHeader()
        hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_slots.setFixedHeight(29 * 9 + 32)
        self.tbl_slots.itemChanged.connect(self._on_slot_item_changed)
        self.tbl_slots.cellClicked.connect(self._toggle_slot_row)
        sec_profs.body.addWidget(self.tbl_slots)
        lay.addWidget(sec_profs)
        lay.addStretch(1)
        return _scroll_tab(w)

    # ── Tab 2: Console MODE & Steering-Wheel Buttons (Redesigned!) ──

    def _build_tab_buttons(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(12)

        # 1. Where physical buttons live
        sec_mode = Section()
        sec_mode.set_text(
            tr("Чем переключать профили вождения", "Which physical buttons switch profiles"),
            tr(
                "Можно оставить штатную кнопку MODE возле селектора КПП, добавить переключение кнопкой на руле "
                "или включить обе кнопки сразу — они работают параллельно и не мешают друг другу.",
                "Use the console MODE button, a steering-wheel button, or both simultaneously.",
            ),
        )
        self.cmb_btn_mode = QComboBox()
        for val, ru, en in (
            ("both", "Кнопка MODE на консоли + кнопка на руле одновременно (рекомендуется)", "Both: Console MODE button + Steering-wheel button (recommended)"),
            ("console", "Только штатная кнопка MODE на центральной консоли", "Console MODE button only"),
            ("mfl", "Только кнопка на руле (если кнопки MODE в салоне нет)", "Steering-wheel button only (no console MODE button)"),
            ("none", "Без физических кнопок (переключение только на экране магнитолы)", "Touchscreen only (no physical buttons)"),
        ):
            self.cmb_btn_mode.addItem(en if get_lang() == "en" else ru, val)
        self.cmb_btn_mode.currentIndexChanged.connect(lambda _i: self._sync_button_controls())
        sec_mode.body.addWidget(self.cmb_btn_mode)
        lay.addWidget(sec_mode)

        # 2. Steering-wheel button picker (ONLY visible when 'mfl' or 'both' is selected!)
        self.sec_wheel = Section()
        self.sec_wheel.set_text(
            tr("Какую кнопку на руле использовать", "Steering-wheel button setup"),
            tr(
                "Выберите удобную кнопку на руле из списка или нажмите «Определить нажатием по CAN…» и просто нажмите кнопку в машине.",
                "Pick a steering-wheel button below or click “Detect press over CAN…” and press the button on your wheel.",
            ),
        )
        grid_mfl = QGridLayout()
        grid_mfl.setHorizontalSpacing(12)
        grid_mfl.setVerticalSpacing(10)

        self.cmb_mfl_preset = QComboBox()
        for code, ru, en in MFL_KEYCODE_PRESETS:
            self.cmb_mfl_preset.addItem(en if get_lang() == "en" else ru, code)
        self.cmb_mfl_preset.addItem(tr("Другая кнопка (ввести код вручную)…", "Other button (enter code manually)…"), -1)
        self.cmb_mfl_preset.currentIndexChanged.connect(self._on_mfl_preset_changed)

        self.btn_learn_mfl = button(
            tr("Определить нажатием по CAN…", "Detect press over CAN…"),
            slot=self._learn_mfl_live,
        )

        self.row_custom_hex = QWidget()
        hex_lay = QHBoxLayout(self.row_custom_hex)
        hex_lay.setContentsMargins(0, 0, 0, 0)
        hex_lay.setSpacing(8)
        self.ed_mfl_hex = QLineEdit("19")
        self.ed_mfl_hex.setFont(mono_font(13))
        self.ed_mfl_hex.setMaximumWidth(90)
        self.ed_mfl_hex.textChanged.connect(self._on_mfl_hex_changed)
        hex_lay.addWidget(QLabel(tr("Код кнопки (Hex):", "Button code (Hex):")))
        hex_lay.addWidget(self.ed_mfl_hex)
        hex_lay.addWidget(hint(tr("Например: 19 (Голос), 23 (VIEW), 74 (Ассистенты)", "Example: 19 (Voice), 23 (VIEW), 74 (Assistants)")), 1)
        self.row_custom_hex.setVisible(False)

        self.cmb_mfl_press = QComboBox()
        self.cmb_mfl_press.addItem(
            tr("По длинному удержанию (короткое нажатие остаётся штатным)", "Long press / hold (short press keeps normal function)"),
            True,
        )
        self.cmb_mfl_press.addItem(
            tr("По короткому одиночному нажатию", "Short single press"),
            False,
        )

        grid_mfl.addWidget(QLabel(tr("Кнопка на руле:", "Wheel button:")), 0, 0)
        grid_mfl.addWidget(self.cmb_mfl_preset, 0, 1)
        grid_mfl.addWidget(self.btn_learn_mfl, 0, 2)
        grid_mfl.addWidget(self.row_custom_hex, 1, 1, 1, 2)
        grid_mfl.addWidget(QLabel(tr("Как срабатывает:", "Trigger:")), 2, 0)
        grid_mfl.addWidget(self.cmb_mfl_press, 2, 1, 1, 2)
        grid_mfl.setColumnStretch(1, 1)
        self.sec_wheel.body.addLayout(grid_mfl)
        self.sec_wheel.body.addWidget(
            hint(
                tr(
                    "Подсказка: кнопки круиз-контроля (SET, RES и Travel Assist) подключены к отдельной линии круиза "
                    "и переключать профили не могут — используйте кнопку Голоса, VIEW, Ассистентов или Обогрева руля.",
                    "Tip: cruise-control buttons (SET, RES, Travel Assist) use a separate cruise line and cannot switch "
                    "profiles — choose Voice, VIEW, Assistants, or Steering Heating instead.",
                )
            )
        )
        lay.addWidget(self.sec_wheel)

        # 3. Which profiles each button cycles through — NO RAW NUMBERS!
        self.sec_rings = Section()
        self.sec_rings.set_text(
            tr("Какие профили листают кнопки при нажатии", "Which profiles each button cycles through"),
            tr(
                "Например, кнопка MODE на консоли может листать все режимы подряд, а кнопка на руле — "
                "мгновенно переключать только два любимых режима (Normal ↔ Sport, как кнопка M1/M2).",
                "For example, the console MODE button can cycle all profiles while the steering-wheel button "
                "toggles instantly between two favourites (like Normal ↔ Sport).",
            ),
        )

        # 3a. Console MODE ring block
        self.box_console_ring = QWidget()
        con_lay = QVBoxLayout(self.box_console_ring)
        con_lay.setContentsMargins(0, 0, 0, 0)
        con_lay.setSpacing(8)
        self.cmb_console_ring_mode = QComboBox()
        self.cmb_console_ring_mode.addItem(
            tr("Все включённые профили по кругу (рекомендуется)", "All enabled profiles in order (recommended)"),
            "all",
        )
        self.cmb_console_ring_mode.addItem(
            tr("Выбрать вручную галочками…", "Choose profiles manually…"),
            "custom",
        )
        self.cmb_console_ring_mode.currentIndexChanged.connect(lambda _i: self._on_ring_mode_changed())
        con_head = QGridLayout()
        con_head.setHorizontalSpacing(12)
        con_head.addWidget(QLabel(tr("Кнопка MODE на консоли:", "Console MODE button:")), 0, 0)
        con_head.addWidget(self.cmb_console_ring_mode, 0, 1)
        con_head.setColumnStretch(1, 1)
        con_lay.addLayout(con_head)

        self.pnl_console_checks, self._console_ring_checks = self._build_ring_checkbox_grid(is_mfl=False)
        con_lay.addWidget(self.pnl_console_checks)
        self.lbl_console_preview = hint()
        con_lay.addWidget(self.lbl_console_preview)
        self.sec_rings.body.addWidget(self.box_console_ring)

        self.ring_divider = divider()
        self.sec_rings.body.addWidget(self.ring_divider)

        # 3b. Steering-wheel ring block
        self.box_mfl_ring = QWidget()
        mfl_lay = QVBoxLayout(self.box_mfl_ring)
        mfl_lay.setContentsMargins(0, 0, 0, 0)
        mfl_lay.setSpacing(8)
        self.cmb_mfl_ring_mode = QComboBox()
        self.cmb_mfl_ring_mode.addItem(
            tr("Все включённые профили по кругу (как на кнопке MODE)", "All enabled profiles (same as MODE button)"),
            "all",
        )
        for key, _pair, ru, en in _WHEEL_QUICK_PAIRS:
            self.cmb_mfl_ring_mode.addItem(en if get_lang() == "en" else ru, key)
        self.cmb_mfl_ring_mode.addItem(
            tr("Выбрать свой набор профилей галочками…", "Choose custom profiles…"),
            "custom",
        )
        self.cmb_mfl_ring_mode.currentIndexChanged.connect(lambda _i: self._on_ring_mode_changed())
        mfl_head = QGridLayout()
        mfl_head.setHorizontalSpacing(12)
        mfl_head.addWidget(QLabel(tr("Кнопка на руле:", "Steering-wheel button:")), 0, 0)
        mfl_head.addWidget(self.cmb_mfl_ring_mode, 0, 1)
        mfl_head.setColumnStretch(1, 1)
        mfl_lay.addLayout(mfl_head)

        self.pnl_mfl_checks, self._mfl_ring_checks = self._build_ring_checkbox_grid(is_mfl=True)
        mfl_lay.addWidget(self.pnl_mfl_checks)
        self.lbl_mfl_preview = hint()
        mfl_lay.addWidget(self.lbl_mfl_preview)
        self.sec_rings.body.addWidget(self.box_mfl_ring)
        lay.addWidget(self.sec_rings)

        # 4. Cabin comfort & indication
        sec_comfort = Section()
        sec_comfort.set_text(
            tr("Подсветка и удобства в салоне", "Cabin behaviour & lighting"),
        )
        self.chk_led_off_normal = QCheckBox(
            tr(
                "Гасить жёлтую подсветку кнопки MODE, когда выбран обычный режим Normal",
                "Turn off the amber MODE button light when Normal mode is active",
            )
        )
        self.chk_mib_popup = QCheckBox(
            tr(
                "Показывать всплывающее окно выбора профиля на экране магнитолы при нажатии кнопки",
                "Show the profile selection popup on the head unit when pressing the button",
            )
        )
        self.chk_decouple_dsg = QCheckBox(
            tr(
                "Качок селектора КПП D↔S переключает только коробку, не сбивая общий профиль машины",
                "Pulling the DSG lever D↔S only toggles the gearbox without changing the car's profile",
            )
        )
        self.chk_pso = QCheckBox(
            tr(
                "Привязывать выбранный профиль к ключу зажигания (персонализация водителя)",
                "Link selected profile to the ignition key / driver account",
            )
        )
        for chk in (self.chk_led_off_normal, self.chk_mib_popup, self.chk_decouple_dsg, self.chk_pso):
            sec_comfort.body.addWidget(chk)

        # Collapsible fine-tuning (LED brightness & popup timeout)
        self.btn_more_comfort = button(tr("Тонкая настройка подсветки и окна ▸", "Fine-tune brightness & popup ▸"), "GhostBtn")
        self.btn_more_comfort.setCheckable(True)
        self.pnl_more_comfort = QWidget()
        more_lay = QHBoxLayout(self.pnl_more_comfort)
        more_lay.setContentsMargins(8, 4, 0, 0)
        more_lay.setSpacing(12)
        self.spn_led_pwm = QSpinBox()
        self.spn_led_pwm.setRange(0, 15)
        self.spn_popup_timeout = QSpinBox()
        self.spn_popup_timeout.setRange(0, 255)
        more_lay.addWidget(QLabel(tr("Яркость подсветки кнопки MODE (0–15):", "MODE LED brightness (0–15):")))
        more_lay.addWidget(self.spn_led_pwm)
        more_lay.addSpacing(12)
        more_lay.addWidget(QLabel(tr("Время показа окна на ГУ (0 = стандартно):", "Popup duration (0 = default):")))
        more_lay.addWidget(self.spn_popup_timeout)
        more_lay.addStretch(1)
        self.pnl_more_comfort.setVisible(False)
        self.btn_more_comfort.toggled.connect(self._toggle_more_comfort)
        sec_comfort.body.addLayout(row(self.btn_more_comfort))
        sec_comfort.body.addWidget(self.pnl_more_comfort)

        lay.addWidget(sec_comfort)
        lay.addStretch(1)
        return _scroll_tab(w)

    def _build_ring_checkbox_grid(self, *, is_mfl: bool) -> tuple[QWidget, dict[int, QCheckBox]]:
        pnl = QFrame()
        pnl.setObjectName("Step")
        grid = QGridLayout(pnl)
        grid.setContentsMargins(12, 8, 12, 8)
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(6)
        checks: dict[int, QCheckBox] = {}
        ordered_slots = (5, 1, 2, 3, 6, 7, 4, 8)
        for idx, slot in enumerate(ordered_slots):
            chk = QCheckBox(_slot_short_name(slot))
            chk.toggled.connect(lambda _c, m=is_mfl: self._update_ring_previews(from_checks=True, is_mfl=m))
            checks[slot] = chk
            r, c = divmod(idx, 4)
            grid.addWidget(chk, r, c)
        pnl.setVisible(False)
        return pnl, checks

    def _toggle_more_comfort(self, on: bool) -> None:
        self.pnl_more_comfort.setVisible(on)
        self.btn_more_comfort.setText(
            tr("Тонкая настройка подсветки и окна ▾", "Fine-tune brightness & popup ▾")
            if on
            else tr("Тонкая настройка подсветки и окна ▸", "Fine-tune brightness & popup ▸")
        )

    # ── Tab 3: Subsystem Target Matrix ──

    def _build_tab_matrix(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)
        lay.addWidget(
            hint(
                tr(
                    "Здесь видно, какую команду шлюз отправляет каждому агрегату автомобиля при выборе профиля. "
                    "В большинстве случаев заводские настройки шаблона уже оптимальны.",
                    "Shows which behaviour mode the gateway requests from each vehicle subsystem in every active profile. "
                    "Template defaults are already optimal for most cars.",
                )
            )
        )
        self.tbl_s031 = QTableWidget(0, 0)
        self.tbl_s031.setAlternatingRowColors(True)
        self.tbl_s031.verticalHeader().setDefaultSectionSize(34)
        lay.addWidget(self.tbl_s031, 1)
        return w

    # ── Tab 4: Individual Setup Menu ──

    def _build_tab_individual(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)
        lay.addWidget(
            hint(
                tr(
                    "Отметьте варианты, которые водитель сможет выбирать вручную внутри настроек режима Individual на экране магнитолы.",
                    "Tick the modes selectable by the driver inside the Individual setup screen on the head unit.",
                )
            )
        )
        self.tbl_s033 = QTableWidget(0, 6)
        self.tbl_s033.setHorizontalHeaderLabels(["Comfort", "Normal", "Sport", "Offroad", "Eco", "Race"])
        self.tbl_s033.setAlternatingRowColors(True)
        self.tbl_s033.verticalHeader().setDefaultSectionSize(30)
        self.tbl_s033.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_s033.itemChanged.connect(self._on_s033_item_changed)
        lay.addWidget(self.tbl_s033, 1)
        return w

    # ── Tab 5: Gateway Coding Check (0x0600) ──

    def _build_tab_coding(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)

        lay.addWidget(
            hint(
                tr(
                    "Чтобы активированные подсистемы работали без ошибок, соответствующие галочки должны быть включены "
                    "в кодировке гейтвея. Нажмите «Прочитать из блока по CAN», затем «Подобрать биты автоматически».",
                    "Read the gateway's coding over CAN and click “Auto-match coding bits” so all enabled features match.",
                )
            )
        )
        self.ed_coding = QLineEdit()
        self.ed_coding.setFont(mono_font(12))
        self.ed_coding.setPlaceholderText(tr("Длинная кодировка блока (30 байт / 60 hex-символов)…", "30-byte gateway coding (60 hex characters)…"))
        self.ed_coding.textChanged.connect(lambda _t: self._refresh_coding_tab())

        btn_read = button(tr("Прочитать из блока по CAN", "Read from ECU over CAN"), slot=self._read_coding_live)
        btn_sync = button(tr("Подобрать биты автоматически", "Auto-match coding bits"), slot=self._sync_coding_bits)
        btn_write = button(tr("Записать кодировку по CAN", "Write coding over CAN"), "PrimaryBtn", slot=self._write_coding_live)
        lay.addWidget(self.ed_coding)
        lay.addLayout(row(btn_read, btn_sync, btn_write))

        self.coding_warn = Callout("warn")
        self.coding_warn.label.setTextFormat(Qt.TextFormat.PlainText)
        self.coding_warn.setVisible(False)
        lay.addWidget(self.coding_warn)

        self.tbl_coding = QTableWidget(0, 3)
        self.tbl_coding.setHorizontalHeaderLabels(
            [
                tr("Подсистема / Блок", "Subsystem / ECU"),
                tr("Байт и бит кодировки", "Coding Byte & Bit"),
                tr("Состояние", "State"),
            ]
        )
        self.tbl_coding.verticalHeader().setVisible(False)
        self.tbl_coding.verticalHeader().setDefaultSectionSize(28)
        self.tbl_coding.setAlternatingRowColors(True)
        hh = self.tbl_coding.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        lay.addWidget(self.tbl_coding, 1)
        return w

    # ── State load & sync ──

    def _on_toggle_reset_preset(self, on: bool) -> None:
        self.pnl_reset_preset.setVisible(on)
        self.btn_toggle_reset.setText(
            tr("Сбросить по шаблону авто ▾", "Reset from car template ▾")
            if on
            else tr("Сбросить по шаблону авто ▸", "Reset from car template ▸")
        )

    def _sync_onboarding_banner(self) -> None:
        for tab_idx in (1, 2, 3):
            self.tabs.setTabEnabled(tab_idx, not self._unconfigured)
        self.btn_ok.setEnabled(not self._unconfigured)
        if self.onboard_frame is None or self.lbl_onboard is None:
            return
        if self._unconfigured:
            theme.set_tone(self.onboard_frame, "warn")
            self.lbl_onboard.setText(
                tr(
                    "Сейчас в этом дампе раздел профилей вождения пуст. "
                    "Чтобы добавить профили, выберите комплектацию вашего автомобиля ниже (или отметьте нужные режимы галочками):",
                    "Driving profiles are currently empty in this dump. "
                    "Pick your car's configuration below (or tick desired modes) to add them:",
                )
                if self._was_empty
                else tr(
                    "Сейчас в этом дампе профили вождения отсутствуют (записан базовый датасет без выбора режимов). "
                    "Чтобы добавить профили, выберите комплектацию вашего автомобиля ниже (или отметьте нужные режимы галочками):",
                    "This dump currently has no driving profiles (passive base dataset without mode selection). "
                    "Pick your car's configuration below (or tick desired modes) to add them:",
                )
            )
        else:
            theme.set_tone(self.onboard_frame, "ok")
            self.lbl_onboard.setText(
                tr(
                    "Профили вождения подготовлены к записи в дамп — при необходимости скорректируйте галочки и вкладку «Кнопки MODE и руль», затем нажмите «Сохранить настройки».",
                    "Driving profiles are ready to be written — review the checkboxes and the “MODE & Wheel Buttons” tab, then click “Save settings”.",
                )
            )

    def _bootstrap_if_needed(self, preset: str = "fwd_dcc", *, custom_slots: tuple[int, ...] | None = None) -> None:
        if not self._unconfigured:
            return
        schema = str(self.cmb_schema.currentData() or "") or None
        self.fpa = build_fpa_preset_block(preset, target_schema=schema, existing_zdc4=bytes(self._orig_loaded.buf))
        if custom_slots is not None:
            wanted = set(custom_slots)
            for s in range(1, 10):
                self.fpa.set_slot_enabled(s, s in wanted)
            self.fpa._write_switch_ring(0, self.fpa.default_cycle_ring())
        self._unconfigured = False
        p_idx = self.cmb_preset.findData(self.fpa.detected_preset())
        if p_idx >= 0:
            self.cmb_preset.blockSignals(True)
            self.cmb_preset.setCurrentIndex(p_idx)
            self.cmb_preset.blockSignals(False)
        self._load_all_from_fpa()

    def _load_all_from_fpa(self) -> None:
        rotary_txt = tr(" · шайба 4Motion сохранена", " · 4Motion rotary kept") if self.fpa.has_4motion_rotary else ""
        self.lbl_schema_info.setText(
            f"{tr('Формат блока:', 'ECU format:')} {self.fpa.schema_tag or '—'}{rotary_txt}"
        )
        ch_ru, ch_en = self.fpa.chassis_summary()
        ch_txt = ch_en if get_lang() == "en" else ch_ru
        self.lbl_detected_base.setText(
            f"{tr('Прочитано из текущего датасета:', 'Read from current dataset:')}  {ch_txt}"
        )
        if not self._needs_onboarding:
            det_idx = self.cmb_preset.findData(self.fpa.detected_preset())
            if det_idx >= 0 and det_idx != self.cmb_preset.currentIndex():
                self.cmb_preset.blockSignals(True)
                self.cmb_preset.setCurrentIndex(det_idx)
                self.cmb_preset.blockSignals(False)
        self._sync_onboarding_banner()
        self._populate_slots_table()
        self._populate_buttons_tab()
        self._rebuild_matrix_tabs()
        self._refresh_coding_tab()

    def _on_load_preset(self) -> None:
        preset = str(self.cmb_preset.currentData() or "")
        if not preset:
            self._unconfigured = True
            self.fpa = FpaDataset(bytes(self._orig_loaded.buf))
            self._load_all_from_fpa()
            return
        self._unconfigured = False
        schema = str(self.cmb_schema.currentData() or "") or None
        base_buf = bytes(self._orig_loaded.buf) if self._needs_onboarding else bytes(self.fpa.buf)
        self.fpa = build_fpa_preset_block(preset, target_schema=schema, existing_zdc4=base_buf)
        self._load_all_from_fpa()

    def _populate_slots_table(self) -> None:
        self.tbl_slots.blockSignals(True)
        try:
            self.chk_kl15_profiles.blockSignals(True)
            self.chk_kl15_powertrain.blockSignals(True)
            if self._unconfigured:
                self.chk_kl15_profiles.setChecked(False)
                self.chk_kl15_powertrain.setChecked(False)
            else:
                self.chk_kl15_profiles.setChecked(self.fpa.all_active_profiles_persist_kl15)
                self.chk_kl15_powertrain.setChecked(self.fpa.powertrain_persists_kl15)
            self.chk_kl15_profiles.blockSignals(False)
            self.chk_kl15_powertrain.blockSignals(False)

            by_slot = {st.slot: st for st in self.fpa.slots()}
            for r in range(9):
                slot_num = r + 1
                st = by_slot.get(slot_num)
                is_on = False if (self._unconfigured or st is None) else bool(st.selectable)
                name_ru, name_en, desc_ru, desc_en = _SLOT_DESCRIPTIONS[slot_num]
                title = name_en if get_lang() == "en" else name_ru
                desc = desc_en if get_lang() == "en" else desc_ru

                it_en = QTableWidgetItem(f"  {title}")
                it_en.setData(Qt.ItemDataRole.UserRole, slot_num)
                it_en.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
                it_en.setCheckState(Qt.CheckState.Checked if is_on else Qt.CheckState.Unchecked)

                it_desc = QTableWidgetItem(desc)
                it_desc.setFlags(Qt.ItemFlag.ItemIsEnabled)

                if self._unconfigured:
                    state_txt = tr("Не в датасете", "Not in dataset")
                    state_col = theme.TEXT_MUTED
                elif is_on:
                    state_txt = tr("Включён", "Enabled")
                    state_col = theme.OK
                else:
                    state_txt = tr("Выключен", "Off")
                    state_col = theme.TEXT_MUTED
                it_state = QTableWidgetItem(state_txt)
                it_state.setFlags(Qt.ItemFlag.ItemIsEnabled)
                it_state.setForeground(QColor(state_col))

                self.tbl_slots.setItem(r, 0, it_en)
                self.tbl_slots.setItem(r, 1, it_desc)
                self.tbl_slots.setItem(r, 2, it_state)
        finally:
            self.tbl_slots.blockSignals(False)

    def _toggle_slot_row(self, r: int, c: int) -> None:
        if c != 0:
            it = self.tbl_slots.item(r, 0)
            if it is not None:
                it.setCheckState(
                    Qt.CheckState.Unchecked if it.checkState() == Qt.CheckState.Checked else Qt.CheckState.Checked
                )

    def _on_slot_item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        slot = item.data(Qt.ItemDataRole.UserRole)
        if not slot:
            return
        slot_i = int(slot)
        en = item.checkState() == Qt.CheckState.Checked
        if self._unconfigured:
            if not en:
                return
            base_preset = "awd_dcc" if slot_i in (4, 8) else "fwd_dcc"
            self._bootstrap_if_needed(base_preset, custom_slots=(2, slot_i))
            return
        self.fpa.set_slot_enabled(
            slot_i,
            en,
            kl15_persist=self.chk_kl15_profiles.isChecked(),
        )
        ch_ru, ch_en = self.fpa.chassis_summary()
        self.lbl_detected_base.setText(
            f"{tr('Прочитано из текущего датасета:', 'Read from current dataset:')}  {ch_en if get_lang() == 'en' else ch_ru}"
        )
        self._populate_slots_table()
        self._update_ring_previews(from_checks=False, is_mfl=False)

    def _on_kl15_profiles_toggled(self, checked: bool) -> None:
        if self._unconfigured and checked:
            self._bootstrap_if_needed("fwd_dcc")
        if not self._unconfigured:
            self.fpa.set_kl15_persistence(
                persist_profiles=checked,
                persist_powertrain=self.chk_kl15_powertrain.isChecked(),
            )

    def _on_kl15_powertrain_toggled(self, checked: bool) -> None:
        if self._unconfigured and checked:
            self._bootstrap_if_needed("fwd_dcc")
        if not self._unconfigured:
            self.fpa.set_kl15_persistence(
                persist_profiles=self.chk_kl15_profiles.isChecked(),
                persist_powertrain=checked,
            )

    # ── Buttons tab state & ring helpers ──

    def _set_ring_checks(self, checks: dict[int, QCheckBox], slots: list[int]) -> None:
        wanted = set(slots)
        for slot, chk in checks.items():
            chk.blockSignals(True)
            chk.setChecked(slot in wanted)
            chk.blockSignals(False)

    def _read_ring_checks(self, checks: dict[int, QCheckBox], fallback: list[int]) -> list[int]:
        ordered = (5, 1, 2, 3, 6, 7, 4, 8)
        picked = [s for s in ordered if checks[s].isChecked()]
        return picked[:8] if picked else list(fallback)

    def set_console_ring_slots(self, slots: list[int]) -> None:
        """Programmatically select a custom profile list for the console MODE button."""
        def_ring = self.fpa.default_cycle_ring()
        if slots == def_ring:
            self.cmb_console_ring_mode.setCurrentIndex(self.cmb_console_ring_mode.findData("all"))
        else:
            self._set_ring_checks(self._console_ring_checks, slots)
            self.cmb_console_ring_mode.setCurrentIndex(self.cmb_console_ring_mode.findData("custom"))
        self._on_ring_mode_changed()

    def set_mfl_ring_slots(self, slots: list[int]) -> None:
        """Programmatically select a profile list (or quick 2-mode pair) for the steering-wheel button."""
        def_ring = self.fpa.default_cycle_ring()
        matched_key = None
        if slots == def_ring:
            matched_key = "all"
        else:
            for key, pair, _ru, _en in _WHEEL_QUICK_PAIRS:
                if list(slots) == list(pair) or set(slots) == set(pair) and len(slots) == 2:
                    matched_key = key
                    break
        self._set_ring_checks(self._mfl_ring_checks, slots)
        if matched_key is not None:
            self.cmb_mfl_ring_mode.setCurrentIndex(self.cmb_mfl_ring_mode.findData(matched_key))
        else:
            self.cmb_mfl_ring_mode.setCurrentIndex(self.cmb_mfl_ring_mode.findData("custom"))
        self._on_ring_mode_changed()

    def _current_console_ring(self) -> list[int]:
        def_ring = self.fpa.default_cycle_ring()
        mode = str(self.cmb_console_ring_mode.currentData() or "all")
        if mode == "all":
            return def_ring
        return self._read_ring_checks(self._console_ring_checks, def_ring)

    def _current_mfl_ring(self) -> list[int]:
        c_ring = self._current_console_ring()
        mode = str(self.cmb_mfl_ring_mode.currentData() or "all")
        if mode == "all":
            return c_ring
        for key, pair, _ru, _en in _WHEEL_QUICK_PAIRS:
            if mode == key:
                return list(pair)
        return self._read_ring_checks(self._mfl_ring_checks, c_ring)

    def _populate_buttons_tab(self) -> None:
        cfg = self.fpa.button_config()
        def_ring = self.fpa.default_cycle_ring()

        self.cmb_btn_mode.blockSignals(True)
        self.cmb_btn_mode.setCurrentIndex(max(0, self.cmb_btn_mode.findData(cfg.mode)))
        self.cmb_btn_mode.blockSignals(False)

        kc = cfg.mfl_keycode or 0x19
        self.ed_mfl_hex.blockSignals(True)
        self.ed_mfl_hex.setText(f"{kc:02X}")
        self.ed_mfl_hex.blockSignals(False)
        p_idx = self.cmb_mfl_preset.findData(kc)
        self.cmb_mfl_preset.blockSignals(True)
        self.cmb_mfl_preset.setCurrentIndex(p_idx if p_idx >= 0 else self.cmb_mfl_preset.count() - 1)
        self.cmb_mfl_preset.blockSignals(False)
        self.row_custom_hex.setVisible(p_idx < 0)

        self.cmb_mfl_press.setCurrentIndex(max(0, self.cmb_mfl_press.findData(cfg.mfl_long_press)))

        c_ring = cfg.console_ring or def_ring
        m_ring = cfg.mfl_ring or c_ring
        self._set_ring_checks(self._console_ring_checks, c_ring)
        self._set_ring_checks(self._mfl_ring_checks, m_ring)
        self.set_console_ring_slots(c_ring)
        self.set_mfl_ring_slots(m_ring)

        self.chk_led_off_normal.setChecked(cfg.normal_led_off)
        self.chk_mib_popup.setChecked(cfg.mib_popup)
        self.spn_led_pwm.setValue(cfg.led_pwm)
        self.spn_popup_timeout.setValue(cfg.popup_timeout_100ms)
        self.chk_decouple_dsg.setChecked(cfg.decouple_dsg_lever)
        self.chk_pso.setChecked(cfg.personalization_pso)
        self._sync_button_controls()

    def _sync_button_controls(self) -> None:
        mode = str(self.cmb_btn_mode.currentData() or "none")
        use_con = mode in ("console", "both")
        use_mfl = mode in ("mfl", "both")
        self.sec_wheel.setVisible(use_mfl)
        self.sec_rings.setVisible(use_con or use_mfl)
        self.box_console_ring.setVisible(use_con)
        self.box_mfl_ring.setVisible(use_mfl)
        self.ring_divider.setVisible(use_con and use_mfl)
        self._on_ring_mode_changed()

    def _on_mfl_preset_changed(self, _idx: int) -> None:
        val = int(self.cmb_mfl_preset.currentData() or -1)
        if val > 0:
            self.ed_mfl_hex.blockSignals(True)
            self.ed_mfl_hex.setText(f"{val:02X}")
            self.ed_mfl_hex.blockSignals(False)
            self.row_custom_hex.setVisible(False)
        else:
            self.row_custom_hex.setVisible(True)

    def _on_mfl_hex_changed(self, txt: str) -> None:
        if self.row_custom_hex.isVisible():
            return
        try:
            kc = int(txt.strip().removeprefix("0x"), 16) & 0xFF
        except ValueError:
            return
        if kc <= 0:
            return
        p_idx = self.cmb_mfl_preset.findData(kc)
        self.cmb_mfl_preset.blockSignals(True)
        self.cmb_mfl_preset.setCurrentIndex(p_idx if p_idx >= 0 else self.cmb_mfl_preset.count() - 1)
        self.cmb_mfl_preset.blockSignals(False)
        if p_idx < 0:
            self.row_custom_hex.setVisible(True)

    def _on_ring_mode_changed(self) -> None:
        c_custom = str(self.cmb_console_ring_mode.currentData() or "all") == "custom"
        m_custom = str(self.cmb_mfl_ring_mode.currentData() or "all") == "custom"
        self.pnl_console_checks.setVisible(c_custom)
        self.pnl_mfl_checks.setVisible(m_custom)
        self._update_ring_previews(from_checks=False, is_mfl=False)

    def _update_ring_previews(self, *, from_checks: bool, is_mfl: bool) -> None:
        _ = (from_checks, is_mfl)
        c_slots = self._current_console_ring()
        m_slots = self._current_mfl_ring()
        self.lbl_console_preview.setText(
            f"{tr('Порядок переключения кнопкой MODE:', 'MODE button cycle:')}  {_format_ring_preview(c_slots)}"
        )
        self.lbl_mfl_preview.setText(
            f"{tr('Порядок переключения кнопкой на руле:', 'Wheel button cycle:')}  {_format_ring_preview(m_slots)}"
        )

    def _commit_buttons_to_fpa(self) -> None:
        mode = str(self.cmb_btn_mode.currentData() or "none")
        preset_kc = int(self.cmb_mfl_preset.currentData() or -1)
        if preset_kc > 0:
            kc = preset_kc
        else:
            try:
                kc = int(self.ed_mfl_hex.text().strip().removeprefix("0x"), 16) & 0xFF
            except ValueError:
                kc = 0x19
        if kc == 0:
            kc = 0x19

        c_ring = self._current_console_ring()
        m_ring = self._current_mfl_ring()
        # Automatically enable any profile explicitly picked for a quick toggle (e.g. Sport / Race / Individual)
        if mode in ("mfl", "both"):
            for s in m_ring:
                if 1 <= s <= 9 and not self.fpa.slots()[s - 1].selectable:
                    self.fpa.set_slot_enabled(s, True, kl15_persist=self.chk_kl15_profiles.isChecked())

        self.fpa.configure_buttons(
            mode=mode,
            mfl_keycode=kc,
            mfl_long_press=bool(self.cmb_mfl_press.currentData()),
            console_ring=c_ring,
            mfl_ring=m_ring,
            normal_led_off=self.chk_led_off_normal.isChecked(),
            led_pwm=self.spn_led_pwm.value(),
            mib_popup=self.chk_mib_popup.isChecked(),
            popup_timeout_100ms=self.spn_popup_timeout.value(),
            decouple_dsg_lever=self.chk_decouple_dsg.isChecked(),
            personalization_pso=self.chk_pso.isChecked(),
        )

    def _learn_mfl_live(self) -> None:
        if self._conn is None or not ensure_ready(self._conn, self):
            return
        port, iface = self._conn.port, self._conn.interface

        def apply_res(res: dict[str, Any]) -> None:
            if res.get("captured") and res.get("keycode"):
                kc = int(res["keycode"])
                self.ed_mfl_hex.setText(f"{kc:02X}")
                idx = self.cmb_mfl_preset.findData(kc)
                self.cmb_mfl_preset.setCurrentIndex(idx if idx >= 0 else self.cmb_mfl_preset.count() - 1)
                self.row_custom_hex.setVisible(idx < 0)
                if self.cmb_btn_mode.currentData() in ("none", "console"):
                    self.cmb_btn_mode.setCurrentIndex(self.cmb_btn_mode.findData("both"))
                QMessageBox.information(
                    self,
                    tr("Кнопка руля определена", "Steering-wheel button detected"),
                    tr(
                        f"Распознана кнопка руля: {res.get('label_ru', '')} (код 0x{kc:02X}).\nОна сразу выбрана в настройках.",
                        f"Detected wheel button: {res.get('label_en', '')} (code 0x{kc:02X}).\nIt has been selected automatically.",
                    ),
                )
            elif res.get("gra_button_detected"):
                QMessageBox.warning(
                    self,
                    tr("Это кнопка круиз-контроля", "Cruise-control button pressed"),
                    tr(
                        "Нажатая кнопка (например, Travel Assist, SET или RES) относится к блоку круиз-контроля "
                        "и технически не может переключать профили вождения.\n\n"
                        "Пожалуйста, выберите кнопку из другой группы: Голосовое управление, VIEW, Меню ассистентов или Обогрев руля.",
                        "The pressed button (e.g. Travel Assist, SET, or RES) belongs to the cruise-control cluster "
                        "and cannot switch driving profiles.\n\n"
                        "Please pick Voice, VIEW, Assistants menu, or Steering Heating instead.",
                    ),
                )
            else:
                QMessageBox.information(
                    self,
                    tr("Нажатие не обнаружено", "No button press detected"),
                    tr("За время ожидания нажатие кнопки на руле не зафиксировано.", "No steering-wheel button press was detected within the timeout."),
                )

        self._run_live(
            tr("Определение кнопки руля по CAN", "Detecting steering-wheel button over CAN"),
            lambda rep: can_learn_mfl_button(port, interface=iface, reporter=rep),
            apply_res,
        )

    def _run_live(self, title: str, fn: Any, done: Any = None) -> None:
        """CAN work always goes through the shared runner: never on the GUI thread, never next to another operation."""
        if self._runner is None or not self._runner.run_task(title, fn, on_success=done):
            QMessageBox.information(
                self,
                tr("Адаптер занят", "Adapter busy"),
                tr("Дождитесь окончания текущей операции с блоком.", "Wait until the current ECU operation finishes."),
            )

    def _on_tab_changed(self, idx: int) -> None:
        if idx in (2, 3):
            self._rebuild_matrix_tabs()
        elif idx == 4:
            self._refresh_coding_tab()

    def _rebuild_matrix_tabs(self) -> None:
        groups = self.fpa.logical_groups()
        act_slots = [s for s in self.fpa.slots() if s.selectable and 1 <= s.profile_id <= 15]

        self.tbl_s031.setRowCount(len(groups))
        self.tbl_s031.setColumnCount(len(act_slots))
        self.tbl_s031.setHorizontalHeaderLabels([_slot_short_name(s.slot) for s in act_slots])
        self.tbl_s031.setVerticalHeaderLabels([name for _lidx, _fg, name in groups])
        for r, (lidx, _fg, _name) in enumerate(groups):
            for c, st in enumerate(act_slots):
                cmb = QComboBox()
                cur_m = self.fpa.get_target_mode(st.slot, lidx)
                for mval, (mru, men) in FPA_TARGET_MODE_NAMES.items():
                    cmb.addItem(men if get_lang() == "en" else mru, mval)
                if cmb.findData(cur_m) < 0:
                    cmb.addItem(f"{cur_m}", cur_m)
                cmb.setCurrentIndex(max(0, cmb.findData(cur_m)))
                cmb.currentIndexChanged.connect(
                    lambda _i, slot=st.slot, li=lidx, cb=cmb: self.fpa.set_target_mode(slot, li, int(cb.currentData() or 0))
                )
                self.tbl_s031.setCellWidget(r, c, cmb)
        self.tbl_s031.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

        self.tbl_s033.blockSignals(True)
        try:
            self.tbl_s033.setRowCount(len(groups))
            self.tbl_s033.setVerticalHeaderLabels([name for _lidx, _fg, name in groups])
            for r, (lidx, _fg, _name) in enumerate(groups):
                mask = self.fpa.get_individual_mask(lidx)
                for c, bit in enumerate((1, 2, 3, 4, 5, 6)):
                    it = QTableWidgetItem("")
                    it.setData(Qt.ItemDataRole.UserRole, (lidx, bit))
                    it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
                    it.setCheckState(Qt.CheckState.Checked if (mask & (1 << bit)) else Qt.CheckState.Unchecked)
                    self.tbl_s033.setItem(r, c, it)
        finally:
            self.tbl_s033.blockSignals(False)

    def _on_s033_item_changed(self, item: QTableWidgetItem) -> None:
        meta = item.data(Qt.ItemDataRole.UserRole)
        if not meta:
            return
        lidx, bit = meta
        mask = self.fpa.get_individual_mask(lidx)
        if item.checkState() == Qt.CheckState.Checked:
            mask |= 1 << bit
        else:
            mask &= ~(1 << bit)
        self.fpa.set_individual_mask(lidx, mask)

    def _parsed_coding30(self) -> bytes | None:
        raw = self.ed_coding.text().strip().replace(" ", "")
        if len(raw) == 60 and all(c in "0123456789abcdefABCDEF" for c in raw):
            return bytes.fromhex(raw)
        return None

    def _refresh_coding_tab(self) -> None:
        preview_df = apply_fpa_dataset(self._df, self.fpa)
        c30 = self._parsed_coding30()
        rep = analyze_gateway_coding_consistency(preview_df, c30)
        if rep.warnings:
            self.coding_warn.label.setText("\n".join(rep.warnings))
            self.coding_warn.setVisible(True)
        else:
            self.coding_warn.setVisible(False)

        rows_data: list[tuple[str, str, str, str]] = []
        for g in rep.master_gates:
            st_txt = (
                tr("Согласовано", "Matched")
                if g.consistent and g.coding_enabled is not None
                else (
                    tr("Нужно поправить кодировку", "Coding mismatch")
                    if not g.consistent
                    else (tr("Включено в параметрии", "Present in dataset") if g.dataset_present else tr("Не используется", "Empty"))
                )
            )
            tone = theme.OK if (g.consistent and g.coding_enabled is not None) else (theme.WARN if not g.consistent else theme.TEXT_MUTED)
            rows_data.append((g.code, f"Byte {g.byte_idx}, Bit {g.bit_idx}", st_txt, tone))

        for p in rep.paco_ecus:
            bit_txt = f"Byte {p.coding_byte}, Bit {p.coding_bit}" if p.coding_byte is not None else tr("Постоянно", "Always")
            st_txt = (
                tr("Включён в кодировке", "Enabled in coding")
                if p.coding_enabled is True
                else (tr("Выключен в кодировке", "Off in coding") if p.coding_enabled is False else tr("Участник профилей", "Profile participant"))
            )
            tone = theme.OK if p.coding_enabled is True else theme.TEXT_MUTED
            rows_data.append((p.sg_name, bit_txt, st_txt, tone))

        self.tbl_coding.setRowCount(len(rows_data))
        for r, (c0, c1, c2, color) in enumerate(rows_data):
            for c, val in enumerate((c0, c1, c2)):
                it = QTableWidgetItem(val)
                it.setFlags(Qt.ItemFlag.ItemIsEnabled)
                if c == 1:
                    it.setFont(mono_font(11))
                if c == 2:
                    it.setForeground(QColor(color))
                self.tbl_coding.setItem(r, c, it)

    def _read_coding_live(self) -> None:
        if self._conn is None or not ensure_ready(self._conn, self):
            return
        port, iface = self._conn.port, self._conn.interface

        def done(res: dict[str, Any]) -> None:
            self.ed_coding.setText(str(res.get("coding_hex", "")))

        self._run_live(
            tr("Чтение кодировки блока", "Reading ECU coding"),
            lambda rep: can_read_gateway_coding(port, interface=iface, reporter=rep),
            done,
        )

    def _sync_coding_bits(self) -> None:
        c30 = self._parsed_coding30()
        if c30 is None:
            QMessageBox.information(
                self,
                tr("Сначала прочитайте кодировку", "Read coding first"),
                tr(
                    "Нажмите «Прочитать из блока по CAN» или вставьте 30 байт кодировки (60 hex-символов).",
                    "Click “Read from ECU over CAN” first or paste the 30-byte coding (60 hex characters).",
                ),
            )
            return
        preview_df = apply_fpa_dataset(self._df, self.fpa)
        synced = sync_gateway_coding_for_zdc(preview_df, c30)
        self.ed_coding.setText(synced.hex().upper())

    def _write_coding_live(self) -> None:
        c30 = self._parsed_coding30()
        if c30 is None:
            QMessageBox.warning(
                self,
                tr("Проверьте кодировку", "Invalid coding length"),
                tr("Длинная кодировка должна содержать ровно 30 байт (60 hex-символов).", "Coding must be 30 bytes (60 hex characters)."),
            )
            return
        if self._conn is None or not ensure_ready(self._conn, self):
            return
        port, iface = self._conn.port, self._conn.interface
        self._run_live(
            tr("Запись кодировки в блок", "Writing coding to ECU"),
            lambda rep: can_write_gateway_coding(port, c30, interface=iface, reporter=rep),
        )

    def _on_accept(self) -> None:
        self._commit_buttons_to_fpa()
        self.accept()

    def result_dflash(self) -> bytes:
        if self._unconfigured:
            return self._df
        self._commit_buttons_to_fpa()
        out = apply_fpa_dataset(self._df, self.fpa)
        pp = parse_zdc_passport(out)
        if pp.empty or not pp.crc_ok:
            out = apply_zdc_passport(out)
        return out


class MkeEditorDialog(Dialog):
    """Simple, friendly editor for Driver Alert System (`MKE`)."""

    def __init__(self, df: bytes, parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            tr("Контроль усталости водителя (MKE)", "Driver Alert System (MKE)"),
            tr(
                "Система оценивает характер подруливаний на трассе и предлагает сделать перерыв на кофе, "
                "если замечает признаки усталости.",
                "Monitors steering corrections on highway trips and suggests a coffee break when drowsiness is detected.",
            ),
            width=660,
        )
        self._df = bytes(df)
        self._erased = False
        self._cfg = parse_mke_block(self._df)
        was_missing = self._cfg.empty or not self._cfg.plausible
        if was_missing:
            self._cfg = parse_mke_block(inject_mke_preset(self._df, "86"))
            empty_banner = Callout("warn")
            empty_banner.label.setTextFormat(Qt.TextFormat.PlainText)
            empty_banner.label.setText(
                tr(
                    "Сейчас в этом дампе раздел MKE отсутствует. Ниже показаны стандартные заводские значения — "
                    "они запишутся в дамп только если вы нажмёте «Сохранить настройки».",
                    "MKE is currently absent in this dump. Standard factory defaults are shown below — "
                    "they will only be written if you click “Save settings”.",
                )
            )
            self.body.addWidget(empty_banner)

        self.body.addLayout(
            row(
                button(tr("Восстановить заводские настройки", "Restore factory defaults"), "GhostBtn", slot=lambda: self._load_preset("86")),
                button(tr("Пресет новых блоков", "Newer ECU preset"), "GhostBtn", slot=lambda: self._load_preset("84")),
                1,
                button(tr("Удалить из параметрии", "Remove from dataset"), "DangerBtn", slot=self._erase_and_accept),
            )
        )

        self._spins: dict[str, QSpinBox] = {}
        sec_main = Section()
        sec_main.set_text(tr("Основные параметры работы", "Main operating parameters"))
        grid_main = QGridLayout()
        grid_main.setHorizontalSpacing(16)
        grid_main.setVerticalSpacing(10)
        main_fields = (
            ("speed_on_kmh", tr("Нижний порог скорости (штатно 60 км/ч):", "Minimum operating speed (stock 60 km/h):")),
            ("speed_off_high_kmh", tr("Верхний предел скорости (штатно 200 км/ч):", "Maximum operating speed (stock 200 km/h):")),
            ("min_drive_min", tr("Начинать оценку через, мин поездки:", "Start evaluation after driving (min):")),
            ("full_rest_min", tr("Длительность стоянки для сброса усталости, мин:", "Stop duration to reset fatigue (min):")),
        )
        for r, (attr, label) in enumerate(main_fields):
            spn = QSpinBox()
            spn.setRange(0, 255)
            spn.setValue(int(getattr(self._cfg, attr)))
            self._spins[attr] = spn
            grid_main.addWidget(QLabel(label), r, 0)
            grid_main.addWidget(spn, r, 1)
        grid_main.setColumnStretch(0, 1)
        sec_main.body.addLayout(grid_main)
        self.body.addWidget(sec_main)

        # Collapsible expert settings
        self.btn_adv = button(tr("Дополнительные настройки чувствительности ▸", "Advanced sensitivity settings ▸"), "GhostBtn")
        self.btn_adv.setCheckable(True)
        self.pnl_adv = Section()
        self.pnl_adv.hide_head()
        grid_adv = QGridLayout()
        grid_adv.setHorizontalSpacing(16)
        grid_adv.setVerticalSpacing(8)
        adv_fields = (
            ("speed_hyst_low_kmh", tr("Запас скорости при включении, км/ч:", "Activation speed hysteresis (km/h):")),
            ("speed_hyst_high_kmh", tr("Задержка включения при наборе скорости, сек:", "Speed qualification delay (s):")),
            ("speed_urban_reset_kmh", tr("Порог городского движения, км/ч:", "Urban driving threshold (km/h):")),
            ("primary_window_min", tr("Шаг накопления оценки, мин:", "Accumulation step window (min):")),
            ("short_break_min", tr("Короткая пауза, мин:", "Short break threshold (min):")),
            ("suppress_stage1_min", tr("Пауза перед 1-м повтором сигнала, мин:", "Repeat suppression stage 1 (min):")),
            ("suppress_stage2_min", tr("Пауза перед 2-м повтором сигнала, мин:", "Repeat suppression stage 2 (min):")),
            ("stage1_threshold", tr("Порог 1-го предупреждения:", "Stage 1 alert threshold:")),
            ("stage2_threshold", tr("Порог повторного предупреждения:", "Stage 2 alert threshold:")),
        )
        for idx, (attr, label) in enumerate(adv_fields):
            r, c = divmod(idx, 2)
            spn = QSpinBox()
            spn.setRange(0, 25 if attr == "speed_hyst_high_kmh" else 255)
            spn.setValue(int(getattr(self._cfg, attr)))
            self._spins[attr] = spn
            grid_adv.addWidget(QLabel(label), r, c * 2)
            grid_adv.addWidget(spn, r, c * 2 + 1)
        grid_adv.setColumnStretch(0, 1)
        grid_adv.setColumnStretch(2, 1)
        self.pnl_adv.body.addLayout(grid_adv)
        self.pnl_adv.setVisible(False)
        self.btn_adv.toggled.connect(self._toggle_adv)
        self.body.addLayout(row(self.btn_adv))
        self.body.addWidget(self.pnl_adv)

        self.btn_ok = button(tr("Сохранить настройки", "Save settings"), "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)

    def _toggle_adv(self, on: bool) -> None:
        self.pnl_adv.setVisible(on)
        self.btn_adv.setText(
            tr("Дополнительные настройки чувствительности ▾", "Advanced sensitivity settings ▾")
            if on
            else tr("Дополнительные настройки чувствительности ▸", "Advanced sensitivity settings ▸")
        )
        self.adjustSize()

    def _load_preset(self, variant: str) -> None:
        self._erased = False
        self._cfg = parse_mke_block(inject_mke_preset(self._df, variant))
        for attr, spn in self._spins.items():
            spn.setValue(int(getattr(self._cfg, attr)))

    def _erase_and_accept(self) -> None:
        self._erased = True
        self.accept()

    def result_dflash(self) -> bytes:
        if self._erased:
            return erase_zdc_block(self._df, 1)
        for attr, spn in self._spins.items():
            setattr(self._cfg, attr, spn.value())
        out = apply_mke_config(self._df, self._cfg)
        pp = parse_zdc_passport(out)
        if pp.empty or not pp.crc_ok:
            out = apply_zdc_passport(out)
        return out


class SsaEditorDialog(Dialog):
    """Friendly editor for Start-Stop messages on the head unit."""

    def __init__(self, df: bytes, parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            tr("Уведомления Старт-Стоп на магнитоле", "Start-Stop Messages on Head Unit"),
            tr(
                "Настраивает, как автомобиль объясняет на экране магнитолы (в разделе Состояние авто), "
                "почему двигатель не заглушился на светофоре или запустился сам.",
                "Controls how Start-Stop status and inhibition reasons are shown on the head-unit vehicle status screen.",
            ),
            width=660,
        )
        self._df = bytes(df)
        self._erased = False
        self._cfg = parse_ssa_block(self._df)
        if self._cfg.empty or not self._cfg.crc_ok:
            self._cfg = parse_ssa_block(inject_ssa_preset(self._df))
            empty_banner = Callout("warn")
            empty_banner.label.setTextFormat(Qt.TextFormat.PlainText)
            empty_banner.label.setText(
                tr(
                    "Сейчас в этом дампе раздел уведомлений Старт-Стоп отсутствует. Ниже показаны стандартные заводские значения — "
                    "они запишутся в дамп только если вы нажмёте «Сохранить настройки».",
                    "Start-Stop status messages are currently absent in this dump. Standard factory defaults are shown below — "
                    "they will only be written if you click “Save settings”.",
                )
            )
            self.body.addWidget(empty_banner)

        note = Callout("info")
        note.label.setTextFormat(Qt.TextFormat.PlainText)
        note.label.setText(
            tr(
                "Совет: здесь настраиваются только информационные подсказки на экране. "
                "Чтобы сам Старт-Стоп и спорт-режим не сбрасывались после перезапуска двигателя, "
                "включите память зажигания в разделе «Профили вождения и кнопки».",
                "Tip: this dialog only controls head-unit status messages. To stop Start-Stop and Sport mode "
                "from resetting on engine restart, enable ignition memory in “Driving Profiles & Mode Buttons”.",
            )
        )
        self.body.addWidget(note)

        self.body.addLayout(
            row(
                button(tr("Восстановить заводские настройки", "Restore factory defaults"), "GhostBtn", slot=self._load_stock),
                1,
                button(tr("Удалить из параметрии", "Remove from dataset"), "DangerBtn", slot=self._erase_and_accept),
            )
        )

        sec = Section()
        sec.set_text(tr("Отображение на экране магнитолы", "Head-unit display options"))
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(10)

        self.cmb_mode = QComboBox()
        for val, ru, en in SSA_OUTPUT_MODES:
            self.cmb_mode.addItem(en if get_lang() == "en" else ru, val)
        self.cmb_mode.setCurrentIndex(max(0, self.cmb_mode.findData(self._cfg.bap_output_mode)))

        self.spn_delay = QSpinBox()
        self.spn_delay.setRange(0, 65535)
        self.spn_delay.setSingleStep(500)
        self.spn_delay.setValue(self._cfg.standstill_notice_delay_ms)

        self.spn_fault = QSpinBox()
        self.spn_fault.setRange(0, 65535)
        self.spn_fault.setValue(self._cfg.fault_autoclear_s)

        self.spn_speed = QSpinBox()
        self.spn_speed.setRange(0, 65535)
        self.spn_speed.setValue(self._cfg.summary_suppress_kmh)

        grid.addWidget(QLabel(tr("Режим показа сообщений:", "Message display mode:")), 0, 0)
        grid.addWidget(self.cmb_mode, 0, 1)
        grid.addWidget(QLabel(tr("Задержка подсказки после остановки, мс:", "Notice delay after stopping (ms):")), 1, 0)
        grid.addWidget(self.spn_delay, 1, 1)
        grid.addWidget(QLabel(tr("Скрывать статус при скорости выше, км/ч:", "Hide status above speed (km/h):")), 2, 0)
        grid.addWidget(self.spn_speed, 2, 1)
        grid.addWidget(QLabel(tr("Автосброс текста ошибки, сек (0 = выкл):", "Auto-clear fault notice, s (0 = off):")), 3, 0)
        grid.addWidget(self.spn_fault, 3, 1)
        grid.setColumnStretch(1, 1)
        sec.body.addLayout(grid)
        self.body.addWidget(sec)

        self.btn_ok = button(tr("Сохранить настройки", "Save settings"), "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)

    def _load_stock(self) -> None:
        self._erased = False
        self._cfg = parse_ssa_block(inject_ssa_preset(self._df))
        self.cmb_mode.setCurrentIndex(max(0, self.cmb_mode.findData(self._cfg.bap_output_mode)))
        self.spn_delay.setValue(self._cfg.standstill_notice_delay_ms)
        self.spn_fault.setValue(self._cfg.fault_autoclear_s)
        self.spn_speed.setValue(self._cfg.summary_suppress_kmh)

    def _erase_and_accept(self) -> None:
        self._erased = True
        self.accept()

    def result_dflash(self) -> bytes:
        if self._erased:
            return erase_zdc_block(self._df, 2)
        self._cfg.bap_output_mode = int(self.cmb_mode.currentData() or 0)
        self._cfg.standstill_notice_delay_ms = self.spn_delay.value()
        self._cfg.fault_autoclear_s = self.spn_fault.value()
        self._cfg.summary_suppress_kmh = self.spn_speed.value()
        out = apply_ssa_config(self._df, self._cfg)
        pp = parse_zdc_passport(out)
        if pp.empty or not pp.crc_ok:
            out = apply_zdc_passport(out)
        return out


class BemEditorDialog(Dialog):
    """Friendly editor for 14V LIN Alternator models (`BEM`)."""

    def __init__(self, df: bytes, parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            tr("Генератор 14В и умная зарядка (BEM)", "14V Alternator & Smart Charging (BEM)"),
            tr(
                "При замене генератора на более мощный (например, 180 А или 250 А вместо 140 А) выберите его модель "
                "из заводского каталога — шлюз будет точно рассчитывать нагрузку и рекуперацию.",
                "When upgrading the alternator (e.g. 180 A or 250 A instead of 140 A), pick the matching model "
                "below so the gateway calculates load and smart charging accurately.",
            ),
            width=820,
        )
        self._df = bytes(df)
        cur = parse_bem_block(self._df)
        if cur.empty or not cur.crc_ok:
            self._df = inject_bem_preset(self._df, "2222")
            empty_banner = Callout("warn")
            empty_banner.label.setTextFormat(Qt.TextFormat.PlainText)
            empty_banner.label.setText(
                tr(
                    "Сейчас в этом дампе каталог генераторов 14В (BEM) пуст. Ниже показан заводской набор — "
                    "он запишется в дамп только если вы нажмёте «Сохранить настройки».",
                    "The 14V alternator catalog (BEM) is currently empty in this dump. The factory set is shown below — "
                    "it will only be written if you click “Save settings”.",
                )
            )
            self.body.addWidget(empty_banner)

        self.body.addLayout(
            row(
                button(tr("Заводской набор (новые блоки)", "Factory set (newer ECUs)"), "GhostBtn", slot=lambda: self._load_preset("2222")),
                button(tr("Заводской набор (ранние блоки)", "Factory set (earlier ECUs)"), "GhostBtn", slot=lambda: self._load_preset("0101")),
                1,
                button(tr("Очистить весь раздел", "Clear entire section"), "DangerBtn", slot=self._erase_all),
            )
        )

        self.tbl = QTableWidget(9, 4)
        self.tbl.setHorizontalHeaderLabels(
            [
                tr("Ячейка", "Slot"),
                tr("Производитель", "Supplier"),
                tr("Модель генератора", "Alternator Model"),
                tr("Макс. мощность", "Max Power"),
            ]
        )
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.verticalHeader().setDefaultSectionSize(30)
        self.tbl.setShowGrid(False)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.tbl.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        hh = self.tbl.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.setFixedHeight(30 * 9 + 34)
        self.tbl.currentCellChanged.connect(self._on_row_selected)
        self.body.addWidget(self.tbl)

        sec_pick = Section()
        sec_pick.set_text(tr("Установить модель генератора в выбранную ячейку", "Assign alternator model to slot"))
        self.cmb_slot = QComboBox()
        for i in range(9):
            self.cmb_slot.addItem(tr(f"Ячейка #{i + 1}", f"Slot #{i + 1}"), i)
        self.cmb_rom = QComboBox()
        for item in ROM_BEM_CATALOG:
            ridx, _sup, _cls, _amps, _rm, _ud, _pm, ru, en = item
            self.cmb_rom.addItem(en if get_lang() == "en" else ru, ridx)
        self.cmb_rom.addItem(tr("— Очистить ячейку —", "— Clear slot —"), None)
        self.cmb_rom.currentIndexChanged.connect(self._on_rom_model_picked)

        self.btn_apply_slot = button(tr("Установить в ячейку", "Assign to slot"), slot=self._assign_slot)
        pick_row = QHBoxLayout()
        pick_row.setSpacing(10)
        pick_row.addWidget(self.cmb_slot)
        pick_row.addWidget(self.cmb_rom, 1)
        pick_row.addWidget(self.btn_apply_slot)
        sec_pick.body.addLayout(pick_row)

        # Hidden-by-default manual LIN class/supplier override
        self.btn_adv = button(tr("Ручной код LIN-класса (для специалистов) ▸", "Manual LIN class override ▸"), "GhostBtn")
        self.btn_adv.setCheckable(True)
        self.pnl_adv = QWidget()
        adv_lay = QHBoxLayout(self.pnl_adv)
        adv_lay.setContentsMargins(4, 4, 0, 0)
        adv_lay.setSpacing(10)
        self.spn_cls = QSpinBox()
        self.spn_cls.setRange(0, 255)
        self.spn_cls.setDisplayIntegerBase(16)
        self.spn_cls.setPrefix("0x")
        self.cmb_sup = QComboBox()
        for sid, (sru, sen) in BEM_SUPPLIER_NAMES.items():
            self.cmb_sup.addItem(sen if get_lang() == "en" else sru, sid)
        adv_lay.addWidget(QLabel(tr("Класс LIN:", "LIN Class:")))
        adv_lay.addWidget(self.spn_cls)
        adv_lay.addWidget(QLabel(tr("Поставщик:", "Supplier:")))
        adv_lay.addWidget(self.cmb_sup)
        adv_lay.addStretch(1)
        self.pnl_adv.setVisible(False)
        self.btn_adv.toggled.connect(lambda on: self.pnl_adv.setVisible(on))
        sec_pick.body.addLayout(row(self.btn_adv))
        sec_pick.body.addWidget(self.pnl_adv)
        self.body.addWidget(sec_pick)

        self.btn_ok = button(tr("Сохранить настройки", "Save settings"), "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)
        self._on_rom_model_picked(0)
        self._refresh_table()

    def _load_preset(self, variant: str) -> None:
        self._df = inject_bem_preset(self._df, variant)
        self._refresh_table()

    def _erase_all(self) -> None:
        self._df = erase_zdc_block(self._df, 6)
        self.accept()

    def _on_row_selected(self, row_idx: int, _col: int, _pr: int, _pc: int) -> None:
        if 0 <= row_idx < 9:
            self.cmb_slot.setCurrentIndex(row_idx)

    def _on_rom_model_picked(self, _idx: int) -> None:
        ridx = self.cmb_rom.currentData()
        if ridx is not None:
            cat = {x[0]: x for x in ROM_BEM_CATALOG}[int(ridx)]
            self.spn_cls.setValue(cat[2])
            s_idx = self.cmb_sup.findData(cat[1])
            if s_idx >= 0:
                self.cmb_sup.setCurrentIndex(s_idx)

    def _assign_slot(self) -> None:
        sidx = int(self.cmb_slot.currentData() or 0)
        ridx = self.cmb_rom.currentData()
        if ridx is None:
            self._df = replace_bem_slot_from_rom(self._df, sidx, None)
        else:
            self._df = replace_bem_slot_from_rom(
                self._df,
                sidx,
                int(ridx),
                class_id=self.spn_cls.value(),
                supplier_id=int(self.cmb_sup.currentData() or 1),
            )
        self._refresh_table()

    def _refresh_table(self) -> None:
        bem = parse_bem_block(self._df)
        for s in bem.slots:
            vals = (
                f"  #{s.slot_idx + 1}",
                "—" if s.empty else s.supplier_name,
                tr("— свободна —", "— empty —") if s.empty else s.matched_label,
                "—" if s.empty else f"{s.p_max_w} W",
            )
            for c, txt in enumerate(vals):
                it = QTableWidgetItem(txt)
                it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                if s.empty:
                    it.setForeground(QColor(theme.TEXT_MUTED))
                self.tbl.setItem(s.slot_idx, c, it)

    def result_dflash(self) -> bytes:
        out = self._df
        bem = parse_bem_block(out)
        if not bem.empty and bem.crc_ok:
            pp = parse_zdc_passport(out)
            if pp.empty or not pp.crc_ok:
                out = apply_zdc_passport(out)
        return out


class ZdcPassportBlocksDialog(Dialog):
    """Passport (`F1A0`/`F1A1`/`F1A4`) & Per-Block Export/Import/Donor Transplant manager."""

    def __init__(self, df: bytes, parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            tr("Паспорт датасета и перенос разделов", "Dataset Passport & Section Transfer"),
            tr(
                "Здесь указываются номер и версия датасета (отображаются в диагностике ODIS / Вася Диагност), "
                "а также можно сохранить или перенести отдельные разделы параметрии из другого дампа без затрагивания ключей CP и SWaP.",
                "Edit the dataset number & version reported to diagnostic tools, or export/transplant individual "
                "parameterization sections from another dump without touching CP or SWaP keys.",
            ),
            width=820,
        )
        self._df = bytes(df)
        pp = parse_zdc_passport(self._df)

        sec_pp = Section()
        sec_pp.set_text(tr("Идентификация датасета в диагностике", "Dataset diagnostic identification"))
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(10)
        self.ed_pn = QLineEdit(pp.dataset_pn or "V03935256AA")
        self.ed_pn.setFont(mono_font(13))
        self.ed_pn.setMaxLength(11)
        self.ed_ver = QLineEdit(pp.dataset_ver if (len(pp.dataset_ver) == 4 and pp.dataset_ver != "0000") else "0001")
        self.ed_ver.setFont(mono_font(13))
        self.ed_ver.setMaxLength(4)
        init_equip = "" if pp.equip_bytes == b"\xff" * 12 else (pp.equip_ascii or pp.equip_hex)
        self.ed_equip = QLineEdit(init_equip)
        self.ed_equip.setFont(mono_font(12))
        self.ed_equip.setPlaceholderText(tr("Необязательно", "Optional"))

        grid.addWidget(QLabel(tr("Номер датасета (F1A0):", "Dataset number (F1A0):")), 0, 0)
        grid.addWidget(self.ed_pn, 0, 1)
        grid.addWidget(QLabel(tr("Версия (F1A1):", "Version (F1A1):")), 0, 2)
        grid.addWidget(self.ed_ver, 0, 3)
        grid.addWidget(QLabel(tr("Код комплектации (F1A4):", "Equipment code (F1A4):")), 1, 0)
        grid.addWidget(self.ed_equip, 1, 1, 1, 3)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)
        sec_pp.body.addLayout(grid)

        self.chk_clean_pads = QCheckBox(
            tr("Очистить служебные поля паспорта и пересчитать контрольную сумму", "Clean unused passport bytes & recalculate checksum")
        )
        self.chk_clean_pads.setChecked(True)
        sec_pp.body.addWidget(self.chk_clean_pads)
        self.body.addWidget(sec_pp)

        sec_blks = Section()
        sec_blks.set_text(tr("Разделы параметрии в DataFlash", "Parameterization sections in DataFlash"))
        self.tbl = QTableWidget(7, 4)
        self.tbl.setHorizontalHeaderLabels(
            [
                tr("Раздел", "Section"),
                tr("Назначение", "Subsystem"),
                tr("Размер", "Size"),
                tr("Состояние", "State"),
            ]
        )
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.verticalHeader().setDefaultSectionSize(30)
        self.tbl.setShowGrid(False)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.tbl.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        hh = self.tbl.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.setFixedHeight(30 * 7 + 34)
        sec_blks.body.addWidget(self.tbl)

        sec_blks.body.addLayout(
            row(
                button(tr("Сохранить раздел в .bin…", "Export section .bin…"), "GhostBtn", slot=self._export_selected),
                button(tr("Загрузить из файла или донорского дампа…", "Import from .bin or donor dump…"), slot=self._import_selected),
                1,
                button(tr("Очистить раздел", "Clear section"), "DangerBtn", slot=self._erase_selected),
            )
        )
        self.body.addWidget(sec_blks)

        self.btn_ok = button(tr("Сохранить", "Save"), "PrimaryBtn", slot=self._on_accept)
        self.finish(ok=self.btn_ok)
        self.tbl.selectRow(4)
        self._refresh_blocks_table()

    def _selected_idx(self) -> int:
        r = self.tbl.currentRow()
        return r if 0 <= r <= 6 else 4

    def _refresh_blocks_table(self) -> None:
        ds = analyze_dflash_datasets(self._df)
        for b in ds.blocks:
            if b.empty:
                st = tr("не заполнен", "empty")
                col = theme.TEXT_MUTED
            elif b.crc_ok:
                tag = f"({b.version_tag}) " if b.version_tag else ""
                st = tr(f"✓ записан {tag}", f"✓ valid {tag}").strip()
                col = theme.OK
            else:
                st = tr("✗ ошибка контрольной суммы", "✗ checksum error")
                col = theme.ERR
            cells = (
                f"  ZDC #{b.idx}",
                b.label,
                f"{b.size} B",
                st,
            )
            for c, txt in enumerate(cells):
                it = QTableWidgetItem(txt)
                it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                if c == 0:
                    it.setFont(mono_font(11))
                if c == 3:
                    it.setForeground(QColor(col))
                self.tbl.setItem(b.idx, c, it)

    def _export_selected(self) -> None:
        idx = self._selected_idx()
        raw = export_zdc_block(self._df, idx)
        dest, _ = QFileDialog.getSaveFileName(
            self,
            tr(f"Сохранить раздел ZDC #{idx}", f"Save section ZDC #{idx}"),
            f"ZDC_block_{idx}.bin",
            "Binary (*.bin);;All files (*)",
        )
        if dest:
            Path(dest).write_bytes(raw)

    def _import_selected(self) -> None:
        idx = self._selected_idx()
        src, _ = QFileDialog.getOpenFileName(
            self,
            tr(
                f"Выберите файл раздела ZDC #{idx} (.bin) или полный дамп-донор DataFlash (64 КБ)",
                f"Choose ZDC #{idx} block (.bin) or a 64 KB donor DataFlash dump",
            ),
            "",
            "Binary (*.bin);;All files (*)",
        )
        if not src:
            return
        try:
            blob = Path(src).read_bytes()
            self._df = import_zdc_block(self._df, idx, blob, fix_crc=True)
            self._refresh_blocks_table()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, tr("Ошибка импорта", "Import error"), str(exc))

    def _erase_selected(self) -> None:
        idx = self._selected_idx()
        self._df = erase_zdc_block(self._df, idx)
        self._refresh_blocks_table()

    def _on_accept(self) -> None:
        try:
            self._df = apply_zdc_passport(
                self._df,
                dataset_pn=self.ed_pn.text(),
                dataset_ver=self.ed_ver.text(),
                equip=self.ed_equip.text(),
                clean_pads=self.chk_clean_pads.isChecked(),
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, tr("Проверьте паспорт датасета", "Check Dataset Passport"), str(exc))
            return
        self.accept()

    def result_dflash(self) -> bytes:
        return self._df
