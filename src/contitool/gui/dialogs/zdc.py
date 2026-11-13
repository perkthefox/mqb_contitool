"""User-friendly ZDC parameterization dialogs: Driving Profiles & Buttons (FPA), Driver Alert (MKE), Start-Stop, Alternator (BEM), and Passport/Blocks."""

from __future__ import annotations

import copy
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
from shiboken6 import isValid

from contitool.can import can_learn_mfl_button, can_read_gateway_coding, can_write_gateway_coding
from contitool.core.analyzer import analyze_dflash_swap
from contitool.core.zdc_templates import FPA_SLOT_DEFAULTS
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
    zdc_ver_ok,
)
from contitool.gui import theme
from contitool.gui.connection import CanConnection, ensure_ready
from contitool.gui.theme import mono_font
from contitool.gui.widgets.page import Callout, Dialog, Section, button, divider, group_label, hint, row
from contitool.gui.worker import OperationRunner
from contitool.i18n import get_lang, tr

# Human-readable descriptions for standard driving profile slots 1..9
_SLOT_DESCRIPTIONS: dict[int, tuple[str, str, str, str]] = {
    1: ("Comfort", "Comfort", "Комфортные настройки систем; с DCC — мягкая подвеска",
        "Comfort settings of the systems; with DCC, soft damping"),
    2: ("Normal", "Normal", "Заводской режим по умолчанию", "The factory default mode"),
    3: ("Sport", "Sport", "Спортивные настройки газа, руля, подвески и коробки (S)",
        "Sport settings for throttle, steering, suspension and gearbox (S)"),
    4: ("Offroad", "Offroad", "Для полного привода: режим Offroad у ESC, муфты и помощника спуска",
        "For AWD: the Offroad mode of ESC, the clutch and hill descent"),
    5: ("Eco", "Eco", "Экономичные настройки двигателя и климата, движение накатом",
        "Economical engine and climate settings, coasting"),
    6: ("Race / Cupra", "Race / Cupra", "Race у Golf R и Cupra. Без своих настроек Race системы получают режим Sport",
        "Race on the Golf R and Cupra. Without its own Race settings the systems get Sport"),
    7: ("Individual", "Individual", "Водитель выбирает режим каждой системы на магнитоле",
        "The driver picks each system's mode on the head unit"),
    8: ("Snow", "Snow", "Для полного привода (как в Tiguan): режим для снега", "For AWD (as in the Tiguan): the snow mode"),
    9: ("Offroad Individual", "Offroad Individual", "Для полного привода (как в Tiguan): Offroad с настройками водителя",
        "For AWD (as in the Tiguan): Offroad with the driver's own settings"),
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
                "Доступные режимы движения, память режима после выключения зажигания, переключение кнопкой MODE и"
                " кнопкой на руле.",
                "Available driving modes, keeping the mode after the ignition is switched off, switching with the"
                " MODE button and a wheel button.",
            ),
            width=920,
        )
        self._df = bytes(df)
        self._conn = conn
        self._runner = runner
        try:  # which slots the gateway may offer: a profile needs its slot's FEC active
            self._active_fecs = {f.fec_code for f in analyze_dflash_swap(self._df).active_fscs}
        except ValueError:
            self._active_fecs = set()

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
                        "Шаблон — это датасет другого автомобиля: он целиком заменяет таблицы профилей и список систем-"
                        "участников. Используйте, только если блок с другой машины (например, с полного привода на "
                        "передний):",
                        "A template is another car's dataset: it replaces the profile tables and the list of "
                        "participating systems as a whole. Use it only if the ECU came from another car (from AWD to FWD,"
                        " say):",
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
        if runner is not None:
            runner.busy_changed.connect(self._on_runner_busy)
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
            tr("Профиль после выключения зажигания и режимы систем", "Profile after ignition off, and system modes"),
            tr(
                "Первая галочка: после включения зажигания остаётся выбранный профиль, а не Normal (S029). Вторая: "
                "силовой агрегат и Старт-Стоп получают и режимы Comfort, Sport и Offroad. С завода шлюз передаёт им "
                "только те режимы, которые эти блоки принимают (S075), остальные заменяет на «без запроса». Примут "
                "ли блоки остальные режимы, не проверено.",
                "First option: after the ignition is switched on the selected profile stays instead of Normal (S029). "
                "Second: the powertrain and Start-Stop also get the Comfort, Sport and Offroad modes. From the factory "
                "the gateway passes them only the modes these ECUs accept (S075) and replaces the rest with “no "
                "request”. Whether the ECUs accept the other modes is not verified.",
            ),
        )
        self.chk_kl15_profiles = QCheckBox(
            tr(
                "Оставлять выбранный профиль после выключения зажигания",
                "Keep the selected profile after the ignition is switched off",
            )
        )
        self.chk_kl15_powertrain = QCheckBox(
            tr(
                "Передавать Comfort, Sport и Offroad силовому агрегату и Старт-Стоп",
                "Pass Comfort, Sport and Offroad to the powertrain and Start-Stop",
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
                "Режимы в меню выбора на магнитоле. Профиль появляется, только если для его слота активен FEC (страница «Активация SWaP/FEC»).",
                "The modes in the head unit's selection menu. A profile appears only if its slot's FEC is active (SWaP/FEC activation page).",
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
                "Кнопка MODE у селектора КПП, кнопка на руле или обе сразу.",
                "The MODE button by the gear selector, a wheel button, or both.",
            ),
        )
        self.cmb_btn_mode = QComboBox()
        for val, ru, en in (
            ("both", "Кнопка MODE на консоли и кнопка на руле", "Console MODE button and a wheel button"),
            ("console", "Только кнопка MODE на консоли", "Console MODE button only"),
            ("mfl", "Только кнопка на руле (если кнопки MODE нет)", "Wheel button only (no MODE button)"),
            ("none", "Без кнопок, только экран магнитолы", "No buttons, head-unit screen only"),
        ):
            self.cmb_btn_mode.addItem(en if get_lang() == "en" else ru, val)
        self.cmb_btn_mode.currentIndexChanged.connect(lambda _i: self._sync_button_controls())
        sec_mode.body.addWidget(self.cmb_btn_mode)
        lay.addWidget(sec_mode)

        # 1a. The 4MOTION Active Control knob, as the factory dataset of a 2019 Tiguan (OZ00) has it
        sec_knob = Section()
        sec_knob.set_text(
            tr("Шайба 4MOTION Active Control", "4MOTION Active Control knob"),
            tr(
                "Как в заводском датасете Tiguan 2019 (OZ00): положения шайбы Snow, On-road, Offroad и Offroad "
                "Individual; профиль On-road выбирается в меню магнитолы. Шайба заменяет кнопку MODE на консоли, "
                "кнопка на руле остаётся. Нужны сама шайба (модуль консоли с LIN-кадром 0x0B) и FEC 10001400, "
                "10001800 и 10001900.",
                "As in the factory dataset of a 2019 Tiguan (OZ00): knob positions Snow, On-road, Offroad and Offroad "
                "Individual; the on-road profile is picked in the head-unit menu. The knob replaces the console MODE "
                "button; a wheel button stays. It needs the knob itself (the console module sending LIN frame 0x0B) "
                "and FECs 10001400, 10001800 and 10001900.",
            ),
        )
        self.chk_knob = QCheckBox(tr("Добавить шайбу в датасет", "Add the knob to the dataset"))
        sec_knob.body.addWidget(self.chk_knob)
        lay.addWidget(sec_knob)


        # 2. Steering-wheel button picker (ONLY visible when 'mfl' or 'both' is selected!)
        self.sec_wheel = Section()
        self.sec_wheel.set_text(
            tr("Какую кнопку на руле использовать", "Steering-wheel button setup"),
            tr(
                "Выберите кнопку из списка или нажмите «Определить нажатием по CAN…» и нажмите её в машине.",
                "Pick the button from the list, or press “Detect over CAN…” and press it in the car.",
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
                    "Кнопки круиз-контроля (SET, RES, Travel Assist) идут по отдельной линии и профили переключать не"
                    " могут. Подходят кнопки голосового управления, VIEW, ассистентов или обогрева руля.",
                    "The cruise-control buttons (SET, RES, Travel Assist) use a separate line and cannot switch "
                    "profiles. The voice, VIEW, assistants or wheel-heating buttons work.",
                )
            )
        )
        lay.addWidget(self.sec_wheel)

        # 3. Which profiles each button cycles through — NO RAW NUMBERS!
        self.sec_rings = Section()
        self.sec_rings.set_text(
            tr("Какие профили листают кнопки при нажатии", "Which profiles each button cycles through"),
            tr(
                "Например, MODE листает все режимы, а кнопка на руле переключает только два (Normal ↔ Sport, как "
                "M1/M2).",
                "For example, MODE steps through every mode while the wheel button toggles just two (Normal ↔ "
                "Sport, like M1/M2).",
            ),
        )

        # 3a. Console MODE ring block
        self.box_console_ring = QWidget()
        con_lay = QVBoxLayout(self.box_console_ring)
        con_lay.setContentsMargins(0, 0, 0, 0)
        con_lay.setSpacing(8)
        self.cmb_console_ring_mode = QComboBox()
        self.cmb_console_ring_mode.addItem(
            tr(
                "Все включённые профили по кругу",
                "All enabled profiles in turn",
            ),
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
                "Селектор D↔S меняет только режим коробки, профиль остаётся прежним",
                "The D↔S selector changes only the gearbox mode; the profile stays",
            )
        )
        self.chk_pso = QCheckBox(
            tr(
                "Запоминать профиль для каждого ключа (персонализация)",
                "Keep the profile per key (personalisation)",
            )
        )
        for chk in (self.chk_led_off_normal, self.chk_mib_popup, self.chk_decouple_dsg, self.chk_pso):
            sec_comfort.body.addWidget(chk)

        # Collapsible fine-tuning (LED brightness & popup timeout)
        self.btn_more_comfort = button(tr("Яркость подсветки MODE ▸", "MODE light brightness ▸"), "GhostBtn")
        self.btn_more_comfort.setCheckable(True)
        self.pnl_more_comfort = QWidget()
        more_lay = QHBoxLayout(self.pnl_more_comfort)
        more_lay.setContentsMargins(8, 4, 0, 0)
        more_lay.setSpacing(12)
        self.spn_led_pwm = QSpinBox()
        self.spn_led_pwm.setRange(0, 15)
        more_lay.addWidget(QLabel(tr("Яркость подсветки кнопки MODE (0–15):", "MODE LED brightness (0–15):")))
        more_lay.addWidget(self.spn_led_pwm)
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
            tr("Яркость подсветки MODE ▾", "MODE light brightness ▾")
            if on
            else tr("Яркость подсветки MODE ▸", "MODE light brightness ▸")
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
                    "Какой режим шлюз запрашивает у каждой системы автомобиля при выборе профиля.",
                    "The mode the gateway requests from each system of the car when a profile is selected.",
                )
            )
        )
        self.tbl_s031 = QTableWidget(0, 0)
        self.tbl_s031.setAlternatingRowColors(True)
        self.tbl_s031.verticalHeader().setDefaultSectionSize(34)
        lay.addWidget(self.tbl_s031, 1)
        return w

    # ── Tab 4: Individual Setup Menu ──

    _S033_MODE_BITS: tuple[int, ...] = (1, 2, 3, 4, 5, 6, 8, 9)
    _SLIDER_CAPABLE_FGS: frozenset[int] = frozenset({0x07, 0x0D, 0x22, 0x2A, 0x2B})

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
        self.tbl_s033 = QTableWidget(0, 9)
        self.tbl_s033.setHorizontalHeaderLabels(
            [
                "Comfort",
                "Normal",
                "Sport",
                "Offroad",
                "Eco",
                "Race",
                tr("Вкл", "On"),
                tr("Выкл", "Off"),
                tr("Слайдер 1–15", "Slider 1–15"),
            ]
        )
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
                    "Системы, участвующие в профилях, должны быть включены в кодировке шлюза. Нажмите «Прочитать из "
                    "блока по CAN», затем «Подобрать биты автоматически».",
                    "The systems taking part in the profiles must be enabled in the gateway coding. Press “Read from "
                    "ECU over CAN”, then “Auto-match coding bits”.",
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
        # a CAN action of this editor puts its result here when it ends: no saving before that
        self.btn_ok.setEnabled(not self._unconfigured and not (self._runner is not None and self._runner.is_busy))
        if self.onboard_frame is None or self.lbl_onboard is None:
            return
        if self._unconfigured:
            theme.set_tone(self.onboard_frame, "warn")
            self.lbl_onboard.setText(
                tr(
                    "Профилей движения в дампе нет. Выберите комплектацию автомобиля ниже или отметьте нужные режимы:",
                    "The dump has no driving profiles. Pick the car's equipment below or tick the modes you need:",
                )
                if self._was_empty
                else tr(
                    "В дампе записан базовый датасет без профилей движения. Выберите комплектацию автомобиля ниже или"
                    " отметьте нужные режимы:",
                    "The dump holds a base dataset without driving profiles. Pick the car's equipment below or tick "
                    "the modes you need:",
                )
            )
        else:
            theme.set_tone(self.onboard_frame, "ok")
            self.lbl_onboard.setText(
                tr(
                    "Профили подготовлены. Проверьте галочки и вкладку «Кнопки MODE и руль» и нажмите «Сохранить "
                    "настройки».",
                    "The profiles are prepared. Check the ticks and the “MODE & wheel buttons” tab, then press “Save "
                    "settings”.",
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
        has_knob = self.fpa.has_knob
        self.chk_knob.setChecked(has_knob)
        self.chk_knob.setEnabled(not has_knob and not self._unconfigured)  # the knob needs profiles to point at
        self.chk_knob.setText(tr("Шайба уже есть в датасете", "The knob is already in the dataset") if has_knob
                              else tr("Добавить шайбу в датасет", "Add the knob to the dataset"))
        rotary_txt = (tr(", заводские кнопки 4Motion сохранены", ", factory 4Motion buttons kept")
                      if self.fpa.button_config().has_4motion_rotary else "")
        self.lbl_schema_info.setText(
            f"{tr('Формат блока:', 'ECU format:')} {self.fpa.schema_tag or '—'}{rotary_txt}"
        )
        ch_ru, ch_en = self.fpa.chassis_summary()
        ch_txt = ch_en if get_lang() == "en" else ch_ru
        self.lbl_detected_base.setText(
            f"{tr('Ближайший шаблон:', 'Closest template:')} {ch_txt}"
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
                elif is_on and FPA_SLOT_DEFAULTS[slot_num][1] not in self._active_fecs:
                    state_txt = tr("Нет FEC", "No FEC")  # the gateway does not offer a slot without its licence
                    state_col = theme.WARN
                elif is_on:
                    state_txt = tr("В меню", "In the menu")
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
        self.fpa.set_slot_enabled(slot_i, en)  # switching a slot back on brings back what it had
        ch_ru, ch_en = self.fpa.chassis_summary()
        self.lbl_detected_base.setText(
            f"{tr('Ближайший шаблон:', 'Closest template:')} {ch_en if get_lang() == 'en' else ch_ru}"
        )
        self._populate_slots_table()
        self._update_ring_previews(from_checks=False, is_mfl=False)

    def _on_kl15_profiles_toggled(self, checked: bool) -> None:
        if self._unconfigured and checked:
            self._bootstrap_if_needed("fwd_dcc")
        if not self._unconfigured:
            self.fpa.set_kl15_persistence(persist_profiles=checked)

    def _on_kl15_powertrain_toggled(self, checked: bool) -> None:
        if self._unconfigured and checked:
            self._bootstrap_if_needed("fwd_dcc")
        if not self._unconfigured:
            self.fpa.set_kl15_persistence(persist_powertrain=checked, original=self._orig_loaded)

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
        matched_key = None
        if list(slots) == self._current_console_ring():  # "all" on the wheel is the MODE button's ring
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
        # the controls cannot show every ring (order, slot 9): one left as loaded is saved as the dataset has it
        self._rings_loaded = (self._current_console_ring(), self._current_mfl_ring(), c_ring, m_ring)

        self.chk_led_off_normal.setChecked(cfg.normal_led_off)
        self.chk_mib_popup.setChecked(cfg.mib_popup)
        self.spn_led_pwm.setValue(cfg.led_pwm)
        self.chk_decouple_dsg.setChecked(cfg.decouple_dsg_lever)
        self.chk_pso.setChecked(cfg.personalization_pso)
        self._sync_button_controls()

    def _sync_button_controls(self) -> None:
        mode = str(self.cmb_btn_mode.currentData() or "none")
        use_con = mode in ("console", "both")
        use_mfl = mode in ("mfl", "both")
        self.sec_wheel.setVisible(use_mfl)
        self.sec_rings.setVisible(use_con or use_mfl)
        # the car's own MODE button (on-road and off-road rings) is never rewritten: nothing to set up for it
        self.box_console_ring.setVisible(use_con and not self.fpa.button_config().vehicle_mode_button)
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
        if self.chk_knob.isChecked() and not self.fpa.has_knob:
            self.fpa.add_4motion_knob()  # first: the button setup below keeps the knob and its switches as the car's own
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
        shown_c, shown_m, loaded_c, loaded_m = self._rings_loaded
        c_ring = loaded_c if c_ring == shown_c else c_ring
        m_ring = loaded_m if m_ring == shown_m else m_ring
        # Automatically enable any profile explicitly picked for a quick toggle (e.g. Sport / Race / Individual)
        if mode in ("mfl", "both"):
            for s in m_ring:
                if 1 <= s <= 9 and not self.fpa.slots()[s - 1].selectable:
                    self.fpa.set_slot_enabled(s, True)

        self.fpa.configure_buttons(
            mode=mode,
            mfl_keycode=kc,
            mfl_long_press=bool(self.cmb_mfl_press.currentData()),
            console_ring=c_ring,
            mfl_ring=m_ring,
            normal_led_off=self.chk_led_off_normal.isChecked(),
            led_pwm=self.spn_led_pwm.value(),
            mib_popup=self.chk_mib_popup.isChecked(),
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
                        "Эта кнопка (Travel Assist, SET или RES) относится к круиз-контролю и переключать профили не "
                        "может.",
                        "This button (Travel Assist, SET or RES) belongs to cruise control and cannot switch profiles.",
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

        def to_dialog(res: Any) -> None:  # the editor may have been closed while the CAN action ran
            if done is not None and isValid(self) and self.isVisible():
                done(res)

        if self._runner is None or not self._runner.run_task(title, fn, on_success=to_dialog):
            QMessageBox.information(
                self,
                tr("Адаптер занят", "Adapter busy"),
                tr("Дождитесь окончания текущей операции с блоком.", "Wait until the current ECU operation finishes."),
            )

    def _on_runner_busy(self, _busy: bool) -> None:
        self._sync_onboarding_banner()

    def _on_tab_changed(self, idx: int) -> None:
        if idx in (2, 3):
            self._rebuild_matrix_tabs()
        elif idx == 4:
            self._refresh_coding_tab()

    def _rebuild_s031_table(self) -> None:
        groups = self.fpa.logical_groups()
        act_slots = [s for s in self.fpa.slots() if s.selectable]

        self.tbl_s031.setRowCount(len(groups))
        self.tbl_s031.setColumnCount(len(act_slots))
        self.tbl_s031.setHorizontalHeaderLabels([_slot_short_name(s.slot) for s in act_slots])
        self.tbl_s031.setVerticalHeaderLabels([name for _lidx, _fg, name in groups])
        dcc_step_notes = {
            1: tr(" (мягче)", " (softest)"),
            3: " (Comfort)",
            8: " (Normal)",
            13: " (Sport)",
            15: tr(" (жёстче)", " (stiffest)"),
        }
        for r, (lidx, fg, _name) in enumerate(groups):
            is_slider = fg in self._SLIDER_CAPABLE_FGS and self.fpa.get_individual_mask(lidx) == 0xFFFE
            for c, st in enumerate(act_slots):
                cmb = QComboBox()
                cur_m = self.fpa.get_target_mode(st.slot, lidx)
                if is_slider:
                    cmb.addItem(tr("Не задействован", "Off / Unused"), 0)
                    for step in range(1, 16):
                        cmb.addItem(f"{tr('Ступень', 'Step')} {step}{dcc_step_notes.get(step, '')}", step)
                else:
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

    def _populate_s033_row(self, r: int, lidx: int, fg: int) -> None:
        mask = self.fpa.get_individual_mask(lidx)
        is_slider = mask == 0xFFFE
        slider_col = len(self._S033_MODE_BITS)
        for c, bit in enumerate(self._S033_MODE_BITS):
            it = self.tbl_s033.item(r, c)
            if it is None:
                it = QTableWidgetItem("")
                self.tbl_s033.setItem(r, c, it)
            it.setData(Qt.ItemDataRole.UserRole, (r, lidx, fg, bit))
            if is_slider:
                it.setFlags(Qt.ItemFlag.NoItemFlags)
                it.setCheckState(Qt.CheckState.Unchecked)
            else:
                it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
                it.setCheckState(Qt.CheckState.Checked if (mask & (1 << bit)) else Qt.CheckState.Unchecked)

        sl_it = self.tbl_s033.item(r, slider_col)
        if sl_it is None:
            sl_it = QTableWidgetItem("")
            self.tbl_s033.setItem(r, slider_col, sl_it)
        sl_it.setData(Qt.ItemDataRole.UserRole, (r, lidx, fg, -1))
        if fg in self._SLIDER_CAPABLE_FGS or is_slider:
            sl_it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
            sl_it.setCheckState(Qt.CheckState.Checked if is_slider else Qt.CheckState.Unchecked)
        else:
            sl_it.setFlags(Qt.ItemFlag.NoItemFlags)
            sl_it.setCheckState(Qt.CheckState.Unchecked)

    def _rebuild_matrix_tabs(self) -> None:
        self._rebuild_s031_table()
        groups = self.fpa.logical_groups()
        self.tbl_s033.blockSignals(True)
        try:
            self.tbl_s033.setRowCount(len(groups))
            self.tbl_s033.setVerticalHeaderLabels([name for _lidx, _fg, name in groups])
            for r, (lidx, fg, _name) in enumerate(groups):
                self._populate_s033_row(r, lidx, fg)
        finally:
            self.tbl_s033.blockSignals(False)

    def _on_s033_item_changed(self, item: QTableWidgetItem) -> None:
        meta = item.data(Qt.ItemDataRole.UserRole)
        if not meta:
            return
        r, lidx, fg, bit = meta
        if bit == -1:
            to_slider = item.checkState() == Qt.CheckState.Checked
            self.fpa.set_individual_mask(lidx, 0xFFFE if to_slider else 0x000E)
            if fg == 0x07:
                for st in self.fpa.slots():
                    cur = self.fpa.get_target_mode(st.slot, lidx)
                    if cur == 0:
                        continue
                    if to_slider and cur in (1, 2, 3, 6):
                        self.fpa.set_target_mode(st.slot, lidx, {1: 3, 2: 8, 3: 13, 6: 15}[cur])
                    elif not to_slider:
                        self.fpa.set_target_mode(st.slot, lidx, 1 if cur <= 5 else (2 if cur <= 10 else 3))
            self.tbl_s033.blockSignals(True)
            try:
                self._populate_s033_row(r, lidx, fg)
            finally:
                self.tbl_s033.blockSignals(False)
            self._rebuild_s031_table()
            return
        mask = self.fpa.get_individual_mask(lidx)
        if mask == 0xFFFE:
            return
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
        before = copy.deepcopy(self.fpa)
        try:
            self._commit_buttons_to_fpa()
        except ValueError as exc:  # no room for the knob or the buttons: say so and stay in the dialog
            knob_refused = self.chk_knob.isChecked() and not self.fpa.has_knob  # the knob goes in before the buttons
            self.fpa = before  # the knob may already be in: nothing of the failed attempt stays
            title = (tr("Шайба 4MOTION Active Control", "4MOTION Active Control knob") if knob_refused
                     else tr("Настройки не сохранены", "Settings not saved"))
            QMessageBox.warning(self, title, str(exc))
            return
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
                "Система следит за подруливаниями и предлагает перерыв, если замечает признаки усталости.",
                "The system watches steering corrections and suggests a break when it sees signs of fatigue.",
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
                    "Раздела MKE в дампе нет. Ниже — заводские значения; в дамп они попадут после «Сохранить "
                    "настройки».",
                    "The dump has no MKE section. The factory values are shown below; they go into the dump with "
                    "“Save settings”.",
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
        self.fit_height()

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
                "Как магнитола (раздел «Состояние автомобиля») показывает, почему Старт-Стоп не заглушил "
                "двигатель или запустил его.",
                "How the head unit (Vehicle status) shows why Start-Stop did not stop the engine or restarted it.",
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
                    "Раздела уведомлений Старт-Стоп в дампе нет. Ниже — заводские значения; в дамп они попадут после "
                    "«Сохранить настройки».",
                    "The dump has no Start-Stop messages section. The factory values are shown below; they go into "
                    "the dump with “Save settings”.",
                )
            )
            self.body.addWidget(empty_banner)

        note = Callout("info")
        note.label.setTextFormat(Qt.TextFormat.PlainText)
        note.label.setText(
            tr(
                "Здесь настраиваются только сообщения на экране. Чтобы Старт-Стоп и режим коробки не сбрасывались"
                " после выключения зажигания, включите память в разделе «Профили вождения и кнопки».",
                "Only the on-screen messages are set here. To keep Start-Stop and the gearbox mode after the "
                "ignition is off, enable the memory in “Driving profiles & buttons”.",
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
                "После замены генератора (например, на 180 или 250 А вместо 140 А) выберите его модель из "
                "заводского каталога: по ней шлюз рассчитывает нагрузку и рекуперацию.",
                "After an alternator change (to 180 or 250 A instead of 140 A, say) pick its model from the "
                "factory catalogue: the gateway works out load and recuperation from it.",
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
                    "Каталог генераторов 14 В (BEM) в дампе пуст. Ниже — заводской набор; в дамп он попадёт после "
                    "«Сохранить настройки».",
                    "The dump's 14 V alternator catalogue (BEM) is empty. The factory set is shown below; it goes "
                    "into the dump with “Save settings”.",
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
                "Номер и версия датасета, которые показывают ODIS и VCDS, а также сохранение и перенос отдельных "
                "разделов параметрии из другого дампа. Ключи CP и SWaP не затрагиваются.",
                "The dataset number and version that ODIS and VCDS show, and saving or transferring single "
                "dataset sections from another dump. The CP and SWaP keys are not touched.",
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
        self.ed_ver = QLineEdit(pp.dataset_ver if zdc_ver_ok(pp.dataset_ver) else "0001")
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
