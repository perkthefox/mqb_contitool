"""Dialogs for direct Multi-FSC SWaP activation, embedding RSA-1024 keys, issuing FSCs, and ODX signing."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from contitool.core import (
    DflashDatasetSummary,
    DflashSwapSummary,
    FPA_PRESET_CATALOG,
    FecDatasetSupport,
    GATEWAY_SWAP_SLOT_ORDER,
    KNOWN_GATEWAY_FECS,
    MFL_KEYCODE_PRESETS,
    UNSUPPORTED_DATASET_RU,
    UNSUPPORTED_DATASET_WARNING,
    ZdcAutoParamConfig,
    check_fec_dataset_support,
)
from contitool.gui import theme
from contitool.gui.theme import mono_font, set_tone
from contitool.gui.widgets.file_drop import DumpFileSelector
from contitool.gui.widgets.page import Callout, Dialog, button, group_label, hint, row
from contitool.i18n import get_lang, tr

_SWAP_ROW_H = 27

def key_selector(private: bool, path: Path | None = None) -> DumpFileSelector:
    """File field accepting an RSA-1024 key bundle, optionally pre-filled with the last key used."""
    sel = DumpFileSelector(
        title_ru="Приватный ключ RSA-1024" if private else "Ключ RSA-1024",
        title_en="Private RSA-1024 key" if private else "RSA-1024 key",
        hint_ru=".json / .private.pem" if private else ".json / .pem / 128 Б .bin",
        hint_en=".json / .private.pem" if private else ".json / .pem / 128 B .bin",
        expected_kinds=("rsa_key",),
    )
    if path is not None and path.is_file():
        sel.set_path(path)
    return sel


class SwapActivateDialog(Dialog):
    """Direct certificate-free SWaP activation in DataFlash (Multi-FSC) with ZDC dataset compatibility check."""

    def __init__(
        self,
        swap_summary: DflashSwapSummary,
        dataset_summary: DflashDatasetSummary | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(
            parent,
            tr("Прямая активация функций SWaP (DataFlash)", "Direct SWaP feature activation (DataFlash)"),
            tr(
                "Отметьте функции, которые должны быть активны в шлюзе. Записи Multi-FSC формируются напрямую "
                "в DataFlash без генерации RSA-ключей, без сертификатов и без модификации CodeFlash.",
                "Tick the features that should be active in the gateway. Multi-FSC records are written directly "
                "into DataFlash without RSA key generation, certificates, or CodeFlash modifications.",
            ),
            width=780,
        )
        self._swap = swap_summary
        self._dataset = dataset_summary

        active_set = {f.fec_code for f in swap_summary.active_fscs}
        fecs: list[int] = list(GATEWAY_SWAP_SLOT_ORDER)
        for f in swap_summary.active_fscs:
            if f.fec_code not in fecs:
                fecs.append(f.fec_code)
        self._fecs = fecs
        self._support_by_fec: dict[int, FecDatasetSupport] = {}
        for code in self._fecs:
            if dataset_summary is not None:
                self._support_by_fec[code] = check_fec_dataset_support(dataset_summary, code)
            else:
                self._support_by_fec[code] = FecDatasetSupport(
                    fec_code=code,
                    supported=False,
                    reason_ru="Данные параметрии ZDC недоступны",
                    reason_en="ZDC dataset information unavailable",
                )

        if dataset_summary is not None and dataset_summary.has_any_valid_dataset:
            pn = dataset_summary.dataset_pn or "—"
            ver = f" ({dataset_summary.dataset_ver})" if dataset_summary.dataset_ver else ""
            tag = f" · {dataset_summary.maingw_tag}" if dataset_summary.maingw_tag else ""
            ds_line = tr(
                f"Текущий датасет ZDC: {pn}{ver}{tag} · поддерживается функций: {len(dataset_summary.supported_fecs)}",
                f"Current ZDC dataset: {pn}{ver}{tag} · supported features: {len(dataset_summary.supported_fecs)}",
            )
        else:
            ds_line = tr(
                "Текущий датасет ZDC: область 0x0000..0x303F пуста (параметрия не записана)",
                "Current ZDC dataset: region 0x0000..0x303F is empty (no dataset flashed)",
            )
        self.lbl_dataset = hint(ds_line)
        self.body.addWidget(self.lbl_dataset)

        # 1. Feature table + quick selection buttons
        self.btn_supported = button(
            tr("Поддерживаемые датасетом", "Dataset-supported"),
            "GhostBtn",
            slot=self._select_supported,
        )
        self.btn_supported.setEnabled(bool(dataset_summary and dataset_summary.supported_fecs))
        self.btn_all = button(tr("Выбрать все", "Select all"), "GhostBtn", slot=self._select_all)
        self.btn_none = button(tr("Снять все", "Clear all"), "GhostBtn", slot=self._select_none)
        self.body.addLayout(
            row(
                group_label(tr("1. ФУНКЦИИ SWAP / FEC", "1. SWAP / FEC FEATURES")),
                1,
                self.btn_supported,
                self.btn_all,
                self.btn_none,
            )
        )

        self.tbl = QTableWidget(len(self._fecs), 3)
        self.tbl.setHorizontalHeaderLabels(
            [
                tr("Код FeC", "FeC"),
                tr("Функция шлюза", "Gateway feature"),
                tr("Текущий датасет", "Current dataset"),
            ]
        )
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.verticalHeader().setDefaultSectionSize(_SWAP_ROW_H)
        self.tbl.setShowGrid(False)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setWordWrap(False)
        self.tbl.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.tbl.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        if len(self._fecs) <= 13:
            self.tbl.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        hh = self.tbl.horizontalHeader()
        hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)

        for r, code in enumerate(self._fecs):
            it_code = QTableWidgetItem(f"  {code:08X}")
            it_code.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
            it_code.setCheckState(Qt.CheckState.Checked if code in active_set else Qt.CheckState.Unchecked)
            it_code.setFont(mono_font(12, bold=True))

            ru_d, en_d = KNOWN_GATEWAY_FECS.get(code, (f"Пользовательский FeC (0x{code:08X})", f"Custom FeC (0x{code:08X})"))
            feat_label = (en_d if get_lang() == "en" else ru_d).replace(f" (0x{code:08X})", "")
            it_name = QTableWidgetItem(feat_label)
            it_name.setFlags(Qt.ItemFlag.ItemIsEnabled)

            sup = self._support_by_fec[code]
            it_ds = QTableWidgetItem(
                tr("✓ Поддерживается", "✓ Supported") if sup.supported else tr("⚠ Не в датасете", "⚠ Unsupported")
            )
            it_ds.setFlags(Qt.ItemFlag.ItemIsEnabled)
            it_ds.setForeground(QColor(theme.OK if sup.supported else theme.WARN))
            tip = sup.reason if sup.supported else f"{tr(UNSUPPORTED_DATASET_RU, UNSUPPORTED_DATASET_WARNING)}\n{sup.reason}"
            it_name.setToolTip(tip)
            it_ds.setToolTip(tip)

            for c, it in enumerate((it_code, it_name, it_ds)):
                self.tbl.setItem(r, c, it)

        visible_rows = min(len(self._fecs), 13)
        self.tbl.setFixedHeight(_SWAP_ROW_H * visible_rows + 32)
        self.tbl.itemChanged.connect(lambda _it: self._sync())
        self.tbl.cellClicked.connect(self._toggle_row)
        self.body.addWidget(self.tbl)

        self.warn_callout = Callout("warn")
        self.warn_callout.label.setTextFormat(Qt.TextFormat.PlainText)
        self.warn_callout.setVisible(False)
        self.body.addWidget(self.warn_callout)

        # Inline 1-click ZDC auto-parameterization panel (shown when unsupported FeCs are ticked)
        self.param_frame = QFrame()
        self.param_frame.setObjectName("Step")
        pf_lay = QVBoxLayout(self.param_frame)
        pf_lay.setContentsMargins(14, 12, 14, 12)
        pf_lay.setSpacing(10)
        self.chk_auto_param = QCheckBox(
            tr(
                "Сразу подготовить параметрию под выбранные функции (рекомендуется)",
                "Automatically prepare parameterization for selected features (recommended)",
            )
        )
        self.chk_auto_param.setChecked(True)
        pf_lay.addWidget(self.chk_auto_param)

        pf_grid = QGridLayout()
        pf_grid.setHorizontalSpacing(12)
        pf_grid.setVerticalSpacing(8)
        self.cmb_param_preset = QComboBox()
        self.cmb_param_preset.addItem(
            tr("Добавить в текущую параметрию (рекомендуется)", "Add into current parameterization (recommended)"),
            "surgical",
        )
        for pkey, pru, pen in FPA_PRESET_CATALOG:
            self.cmb_param_preset.addItem(pen if get_lang() == "en" else pru, pkey)

        self.cmb_param_btn = QComboBox()
        for bkey, bru, ben in (
            ("keep", "Оставить как есть (или штатная кнопка MODE)", "Keep existing setting (or console MODE)"),
            ("console", "Только штатная кнопка MODE на консоли", "Console MODE button only"),
            ("both", "Кнопка MODE на консоли + кнопка на руле", "Console MODE + steering-wheel button"),
            ("mfl", "Только кнопка на руле", "Steering-wheel button only"),
        ):
            self.cmb_param_btn.addItem(ben if get_lang() == "en" else bru, bkey)

        self.lbl_param_wheel = QLabel(tr("Кнопка на руле:", "Wheel button:"))
        self.cmb_param_mfl_key = QComboBox()
        for kcode, kru, ken in MFL_KEYCODE_PRESETS:
            self.cmb_param_mfl_key.addItem(ken if get_lang() == "en" else kru, kcode)

        pf_grid.addWidget(QLabel(tr("Шаблон профилей:", "Profile template:")), 0, 0)
        pf_grid.addWidget(self.cmb_param_preset, 0, 1)
        pf_grid.addWidget(QLabel(tr("Переключение кнопками:", "Physical buttons:")), 1, 0)
        pf_grid.addWidget(self.cmb_param_btn, 1, 1)
        pf_grid.addWidget(self.lbl_param_wheel, 2, 0)
        pf_grid.addWidget(self.cmb_param_mfl_key, 2, 1)
        pf_grid.setColumnStretch(1, 1)
        pf_lay.addLayout(pf_grid)

        self.chk_param_kl15 = QCheckBox(
            tr(
                "Запоминать выбранный профиль и спорт-режим коробки после перезапуска зажигания",
                "Remember selected profile & gearbox Sport mode after engine restart",
            )
        )
        pf_lay.addWidget(self.chk_param_kl15)
        self.param_frame.setVisible(False)
        self.body.addWidget(self.param_frame)

        self.chk_auto_param.toggled.connect(lambda _c: self._sync())
        self.cmb_param_btn.currentIndexChanged.connect(lambda _i: self._sync())

        # 2. Vehicle identity (VCRN + optional VIN)
        self.body.addWidget(group_label(tr("2. ИДЕНТИФИКАТОРЫ БЛОКА", "2. ECU IDENTITY")))
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        self.ed_vcrn = QLineEdit(swap_summary.vcrn.hex().upper())
        self.ed_vcrn.setFont(mono_font(13))
        self.ed_vcrn.setReadOnly(True)
        self.ed_vin = QLineEdit(swap_summary.vin)
        self.ed_vin.setFont(mono_font(13))
        self.ed_vin.setPlaceholderText("WVWZZZAUZJW000001")
        grid.addWidget(QLabel("VCRN"), 0, 0)
        grid.addWidget(self.ed_vcrn, 0, 1)
        grid.addWidget(QLabel("VIN"), 0, 2)
        grid.addWidget(self.ed_vin, 0, 3)
        self.body.addLayout(grid)

        self.chk_no_vin = QCheckBox(tr("Без привязки к VIN", "No VIN binding"))
        self.chk_no_vin.toggled.connect(lambda _c: self._sync())
        self.ed_vin.textChanged.connect(lambda _t: self._sync())
        self.body.addWidget(self.chk_no_vin)

        self.lbl_vin_guard = QLabel()
        self.lbl_vin_guard.setWordWrap(True)
        self.lbl_vin_guard.setVisible(False)
        self.body.addWidget(self.lbl_vin_guard)

        self.btn_ok = button(tr("Применить в DataFlash", "Apply to DataFlash"), "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)
        self._sync()

    def _toggle_row(self, r: int, c: int) -> None:
        if c != 0:
            it = self.tbl.item(r, 0)
            it.setCheckState(
                Qt.CheckState.Unchecked if it.checkState() == Qt.CheckState.Checked else Qt.CheckState.Checked
            )

    def _set_checked_set(self, wanted: set[int]) -> None:
        self.tbl.blockSignals(True)
        try:
            for r, code in enumerate(self._fecs):
                self.tbl.item(r, 0).setCheckState(
                    Qt.CheckState.Checked if code in wanted else Qt.CheckState.Unchecked
                )
        finally:
            self.tbl.blockSignals(False)
        self._sync()

    def _select_supported(self) -> None:
        sup_set = {code for code, sup in self._support_by_fec.items() if sup.supported}
        self._set_checked_set(sup_set)

    def _select_all(self) -> None:
        self._set_checked_set(set(self._fecs))

    def _select_none(self) -> None:
        self._set_checked_set(set())

    def set_fec_checked(self, fec_code: int, checked: bool = True) -> None:
        """Programmatically check or uncheck a specific FeC row."""
        for r, code in enumerate(self._fecs):
            if code == fec_code:
                self.tbl.item(r, 0).setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
                return

    @property
    def selected_fecs(self) -> list[int]:
        return [
            code
            for r, code in enumerate(self._fecs)
            if self.tbl.item(r, 0).checkState() == Qt.CheckState.Checked
        ]

    @property
    def unsupported_selected(self) -> list[int]:
        return [code for code in self.selected_fecs if not self._support_by_fec[code].supported]

    def auto_param_config(self) -> ZdcAutoParamConfig | None:
        """Return 1-click ZDC auto-parameterization config when unsupported FeCs are selected and auto-param is checked."""
        if not self.unsupported_selected or not self.chk_auto_param.isChecked():
            return None
        kl15 = self.chk_param_kl15.isChecked()
        return ZdcAutoParamConfig(
            enabled=True,
            fpa_preset=str(self.cmb_param_preset.currentData() or "surgical"),
            button_mode=str(self.cmb_param_btn.currentData() or "keep"),
            mfl_keycode=int(self.cmb_param_mfl_key.currentData() or 0x19),
            mfl_long_press=False,
            kl15_persist_profiles=kl15,
            kl15_persist_powertrain=kl15,
        )

    @property
    def vin(self) -> str:
        return "" if self.chk_no_vin.isChecked() else self.ed_vin.text().strip().upper()

    def _vin_valid(self) -> bool:
        v = self.vin
        if not v:
            self.lbl_vin_guard.setVisible(False)
            return True
        if len(v) == 17 and all(0x20 <= ord(ch) <= 0x7E for ch in v):
            self.lbl_vin_guard.setVisible(False)
            return True
        set_tone(self.lbl_vin_guard, "err")
        self.lbl_vin_guard.setText(
            tr("✗  VIN должен содержать ровно 17 ASCII-символов (или очистите поле)", "✗  VIN must be 17 ASCII characters (or leave empty)")
        )
        self.lbl_vin_guard.setVisible(True)
        return False

    def _sync(self) -> None:
        self.ed_vin.setEnabled(not self.chk_no_vin.isChecked())
        unsup = self.unsupported_selected
        if unsup:
            codes_txt = ", ".join(f"{c:08X}" for c in unsup)
            self.warn_callout.label.setText(
                f"{tr(UNSUPPORTED_DATASET_RU, UNSUPPORTED_DATASET_WARNING)}\n"
                + tr(
                    f"Выбранные функции ({codes_txt}) ещё не прописаны в параметрии блока — вы можете подготовить параметрию прямо сейчас галочкой ниже.",
                    f"Selected features ({codes_txt}) are missing from the dataset — leave the option below checked to prepare parameterization automatically.",
                )
            )
            self.warn_callout.setVisible(True)
            self.param_frame.setVisible(True)
            ap_on = self.chk_auto_param.isChecked()
            need_wheel = str(self.cmb_param_btn.currentData()) in ("both", "mfl")
            self.cmb_param_preset.setEnabled(ap_on)
            self.cmb_param_btn.setEnabled(ap_on)
            self.lbl_param_wheel.setVisible(need_wheel)
            self.cmb_param_mfl_key.setVisible(need_wheel)
            self.cmb_param_mfl_key.setEnabled(ap_on and need_wheel)
            self.chk_param_kl15.setEnabled(ap_on)
        else:
            self.warn_callout.setVisible(False)
            self.param_frame.setVisible(False)

        sh = self.sizeHint()
        if self.height() < sh.height():
            self.resize(max(self.width(), self._min_width), sh.height())

        sel_cnt = len(self.selected_fecs)
        self.btn_ok.setText(
            tr(f"Применить в DataFlash ({sel_cnt})", f"Apply to DataFlash ({sel_cnt})")
            if sel_cnt
            else tr("Отключить все в DataFlash", "Disable all in DataFlash")
        )
        self.btn_ok.setEnabled(self._vin_valid())


class RsaKeyDialog(Dialog):
    """Result: `key_path` (None = generate a new pair) for the SWaP or FBL key."""

    def __init__(self, target: str, parent: QWidget | None = None) -> None:
        swap = target == "swap"
        super().__init__(
            parent,
            tr("Свой ключ SWaP", "Your SWaP key") if swap else tr("Свой ключ FBL", "Your FBL key"),
            tr(
                "В CodeFlash вшивается публичная часть ключа RSA-1024 (e = 3). После записи в блок шлюз принимает "
                "сертификаты функций, подписанные этим ключом.",
                "The public part of an RSA-1024 (e = 3) key is embedded into CodeFlash. Once written to the ECU, "
                "the gateway accepts feature certificates signed with this key.",
            )
            if swap
            else tr(
                "В область загрузчика CodeFlash вшивается публичная часть ключа RSA-1024 (e = 3). Загрузчик будет "
                "принимать прошивки, подписанные этим ключом.",
                "The public part of an RSA-1024 (e = 3) key is embedded into the CodeFlash bootloader area. The "
                "bootloader will accept firmware signed with this key.",
            ),
        )
        self.rb_new = QRadioButton(tr("Создать новую пару ключей", "Create a new keypair"))
        self.rb_file = QRadioButton(tr("Взять из файла", "Use a key file"))
        grp = QButtonGroup(self)
        for rb in (self.rb_new, self.rb_file):
            grp.addButton(rb)
            self.body.addWidget(rb)
        self.rb_new.setChecked(True)

        self.lbl_new = hint(
            tr(
                "Пара сохраняется рядом с дампами в папку ContiTool_keys (.json, .private.pem, .public.pem), "
                "каждый раз в новый файл. Приватная часть нужна, чтобы подписывать, — не теряйте её.",
                "The pair is saved next to the dumps in ContiTool_keys (.json, .private.pem, .public.pem), "
                "each time to a new file. The private part is needed for signing — do not lose it.",
            )
        )
        self.body.addWidget(self.lbl_new)
        self.sel_key = key_selector(private=False)
        self.body.addWidget(self.sel_key)

        self.btn_ok = button(tr("Вшить ключ", "Embed key"), "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)
        for rb in (self.rb_new, self.rb_file):
            rb.toggled.connect(lambda _c: self._sync())
        self.sel_key.file_changed.connect(lambda _d: self._sync())
        self._sync()

    def _sync(self) -> None:
        use_file = self.rb_file.isChecked()
        self.sel_key.setVisible(use_file)
        self.lbl_new.setVisible(not use_file)
        self.btn_ok.setEnabled(not use_file or self.sel_key.is_valid_selection())

    @property
    def key_path(self) -> Path | None:
        return self.sel_key.current_path if self.rb_file.isChecked() else None


class FscDialog(Dialog):
    """Result: `key_path`, `fec_code`, `vcrn`, `vin` for one SWaP FSC certificate."""

    def __init__(
        self, vcrn: str = "", vin: str = "", key_path: Path | None = None, parent: QWidget | None = None
    ) -> None:
        super().__init__(
            parent,
            tr("Выпустить сертификат функции", "Issue a feature certificate"),
            tr(
                "Сертификат SWaP (FSC, 171 байт) включает функцию в шлюзе. Он подписывается приватным ключом, "
                "публичная часть которого уже вшита в прошивку.",
                "A SWaP certificate (FSC, 171 bytes) enables a feature in the gateway. It is signed with the private "
                "key whose public part is already embedded in the firmware.",
            ),
            width=720,
        )
        self.sel_key = key_selector(private=True, path=key_path)
        self.body.addWidget(self.sel_key)

        self.body.addWidget(group_label(tr("ПАРАМЕТРЫ", "PARAMETERS")))
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(8)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        self.cmb_fec = QComboBox()
        self.cmb_fec.setEditable(True)
        self.cmb_fec.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.cmb_fec.setMinimumContentsLength(28)
        for code, (ru_d, en_d) in KNOWN_GATEWAY_FECS.items():
            self.cmb_fec.addItem(f"{code:08X} — {en_d if get_lang() == 'en' else ru_d}", f"{code:08X}")
        grid.addWidget(QLabel(tr("Функция", "Feature")), 0, 0)
        grid.addWidget(self.cmb_fec, 0, 1, 1, 3)

        self.ed_vcrn = QLineEdit(vcrn)
        self.ed_vcrn.setFont(mono_font(13))
        self.ed_vcrn.setPlaceholderText("0A1B2C3D4E")
        self.ed_vin = QLineEdit(vin)
        self.ed_vin.setFont(mono_font(13))
        self.ed_vin.setPlaceholderText("WVWZZZAUZJW000001")
        grid.addWidget(QLabel("VCRN"), 1, 0)
        grid.addWidget(self.ed_vcrn, 1, 1)
        grid.addWidget(QLabel("VIN"), 1, 2)
        grid.addWidget(self.ed_vin, 1, 3)
        self.body.addLayout(grid)

        self.chk_no_vin = QCheckBox(tr("Без привязки к VIN", "No VIN binding"))
        self.chk_no_vin.toggled.connect(self._sync)
        self.body.addWidget(self.chk_no_vin)
        self.body.addWidget(
            hint(
                tr(
                    "VCRN и VIN подставлены из DataFlash этого блока. Сертификат действует только для них.",
                    "VCRN and VIN are taken from this ECU's DataFlash. The certificate is valid for those only.",
                )
                if vcrn or vin
                else tr(
                    "VCRN (5 байт) и VIN (17 символов) берутся из DataFlash автомобиля.",
                    "VCRN (5 bytes) and VIN (17 characters) come from the vehicle's DataFlash.",
                )
            )
        )

        self.btn_ok = button(tr("Подписать", "Sign"), "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)
        self.sel_key.file_changed.connect(lambda _d: self._sync())
        for ed in (self.ed_vcrn, self.ed_vin):
            ed.textChanged.connect(lambda _t: self._sync())
        self.cmb_fec.editTextChanged.connect(lambda _t: self._sync())
        self._sync()

    def _sync(self) -> None:
        self.ed_vin.setEnabled(not self.chk_no_vin.isChecked())
        ok = self.sel_key.is_valid_selection() and self.fec_code is not None and len(self.vcrn) == 5
        self.btn_ok.setEnabled(ok)

    @property
    def key_path(self) -> Path | None:
        return self.sel_key.current_path

    @property
    def fec_code(self) -> int | None:
        raw = self.cmb_fec.currentText().split("—", 1)[0].strip().removeprefix("0x")
        try:
            return int(raw, 16)
        except ValueError:
            return None

    @property
    def vcrn(self) -> bytes:
        try:
            return bytes.fromhex(self.ed_vcrn.text().strip().replace(" ", ""))
        except ValueError:
            return b""

    @property
    def vin(self) -> str:
        return "" if self.chk_no_vin.isChecked() else self.ed_vin.text().strip()


class OdxSignDialog(Dialog):
    """Result: `key_path` for signing the current CodeFlash as an ODX application."""

    def __init__(self, key_path: Path | None = None, parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            tr("Подписать прошивку для ODX", "Sign firmware for ODX"),
            tr(
                "Считает значение <FW-SIGNATURE> для текущего CodeFlash — его вставляют в контейнер .odx, "
                "чтобы заводской загрузчик принял прошивку.",
                "Computes the <FW-SIGNATURE> value for the current CodeFlash — paste it into the .odx container "
                "so the stock bootloader accepts the firmware.",
            ),
        )
        self.sel_key = key_selector(private=True, path=key_path)
        self.body.addWidget(self.sel_key)
        self.btn_ok = button(tr("Подписать", "Sign"), "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)
        self.sel_key.file_changed.connect(lambda _d: self._sync())
        self._sync()

    def _sync(self) -> None:
        self.btn_ok.setEnabled(self.sel_key.is_valid_selection())

    @property
    def key_path(self) -> Path | None:
        return self.sel_key.current_path
