"""Bind retrofitted ECUs to the gateway: pick CP banks and the 16-byte IKA key."""

from __future__ import annotations

import secrets

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from contitool.core import SLAVE_SLOTS, SlotSpec, SlotState, check_key_warnings, parse_hex_key
from contitool.gui import theme
from contitool.gui.theme import mono_font, set_tone
from contitool.gui.widgets.page import Dialog, button, group_label, hint, row
from contitool.i18n import tr

_ROW_H = 30


def slot_state_text(st: SlotState | None) -> tuple[str, str]:
    """(label, colour) for a CP bank state."""
    if st is None or st.empty:
        return tr("свободен", "empty"), theme.TEXT_MUTED
    if st.kind == "PLAIN":
        return tr("ключ IKA", "IKA key"), theme.OK
    if st.kind == "SHE":
        return tr("заводской SHE", "factory SHE"), theme.INFO
    return st.kind, theme.WARN


class CpBindDialog(Dialog):
    """Result: `action` = "bind" | "clear", `banks`, `key`, `force_mask`."""

    def __init__(self, slots: list[SlotState], parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            tr("Привязать модуль", "Bind a module"),
            tr(
                "Отметьте блоки, которые нужно привязать к этому шлюзу, и укажите их ключ IKA. "
                "Заводские блоки продолжат работать как прежде.",
                "Tick the ECUs to bind to this gateway and enter their IKA key. "
                "Factory ECUs keep working as before.",
            ),
            width=760,
        )
        self.action = ""
        self.banks: list[SlotSpec] = []
        self.key = b""
        states = {st.spec.slot: st for st in slots}

        # 1. ECUs
        self.body.addWidget(group_label(tr("1. БЛОКИ", "1. ECUs")))
        self.tbl = QTableWidget(len(SLAVE_SLOTS), 3)
        self.tbl.setHorizontalHeaderLabels([tr("Адрес", "Addr"), tr("Блок", "ECU"), tr("Сейчас в банке", "Bank now")])
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.verticalHeader().setDefaultSectionSize(_ROW_H)
        self.tbl.setShowGrid(False)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setWordWrap(False)
        self.tbl.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.tbl.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.tbl.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        hh = self.tbl.horizontalHeader()
        hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        for r, spec in enumerate(SLAVE_SLOTS):
            addr = QTableWidgetItem(f"  {spec.ecu_addr}")
            addr.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
            addr.setCheckState(Qt.CheckState.Unchecked)
            addr.setFont(mono_font(12, bold=True))
            name = QTableWidgetItem(spec.short)
            name.setFlags(Qt.ItemFlag.ItemIsEnabled)
            name.setToolTip(f"{spec.details}\nDataFlash 0x{spec.off1:04X} / 0x{spec.off2:04X} · bank #{spec.slot}")
            txt, col = slot_state_text(states.get(spec.slot))
            st = QTableWidgetItem(txt)
            st.setFlags(Qt.ItemFlag.ItemIsEnabled)
            st.setForeground(QColor(col))
            if states.get(spec.slot) and not states[spec.slot].empty:
                st.setToolTip(states[spec.slot].first16_hex.upper())
            for c, it in enumerate((addr, name, st)):
                self.tbl.setItem(r, c, it)
        self.tbl.setFixedHeight(_ROW_H * len(SLAVE_SLOTS) + 34)
        self.tbl.itemChanged.connect(lambda _it: self._sync())
        self.tbl.cellClicked.connect(self._toggle_row)
        self.body.addWidget(self.tbl)

        # 2. Key
        self.body.addWidget(group_label(tr("2. КЛЮЧ IKA", "2. IKA KEY")))
        self.ed_key = QLineEdit()
        self.ed_key.setFont(mono_font(14))
        self.ed_key.setPlaceholderText("A1B2C3D4E5F60718293A4B5C6D7E8F90")
        self.ed_key.textChanged.connect(lambda _t: self._sync())
        btn_gen = button(tr("Сгенерировать", "Generate"), slot=self._generate)
        btn_gen.setToolTip(
            tr(
                "Случайный ключ: тот же ключ нужно записать в слот IKA привязываемого блока.",
                "Random key: the same key must be written into the IKA slot of the bound ECU.",
            )
        )
        btn_copy = button(tr("Копировать", "Copy"), "GhostBtn", slot=self._copy)
        key_row = QHBoxLayout()
        key_row.setSpacing(6)
        key_row.addWidget(self.ed_key, 1)
        key_row.addWidget(btn_gen)
        key_row.addWidget(btn_copy)
        self.body.addLayout(key_row)
        self.lbl_guard = QLabel()
        self.lbl_guard.setWordWrap(True)
        self.body.addWidget(self.lbl_guard)
        self.body.addWidget(
            hint(
                tr(
                    "16 байт (32 hex-символа). Это открытый ключ из слота IKA привязываемого блока — "
                    "из его дампа или сгенерированный и записанный в оба блока.",
                    "16 bytes (32 hex characters). The plaintext key from the bound ECU's IKA slot — "
                    "read from its dump, or generated and written into both ECUs.",
                )
            )
        )

        # Advanced (collapsed)
        self.btn_more = button(tr("Дополнительно ▸", "Advanced ▸"), "GhostBtn")
        self.btn_more.setCheckable(True)
        self.adv = QWidget()
        adv_lay = QVBoxLayout(self.adv)
        adv_lay.setContentsMargins(8, 0, 0, 0)
        adv_lay.setSpacing(6)
        self.chk_force_mask = QCheckBox(
            tr(
                "Всегда обходить маску EEPROM 95640 (для пустых банков включается автоматически)",
                "Always bypass the 95640 EEPROM mask (automatic for empty banks)",
            )
        )
        self.chk_allow_suspicious = QCheckBox(
            tr("Разрешить нестандартный ключ (00..00 / заголовок M1)", "Allow a non-standard key (00..00 / M1 header)")
        )
        self.chk_allow_suspicious.toggled.connect(lambda _c: self._sync())
        adv_lay.addWidget(self.chk_force_mask)
        adv_lay.addWidget(self.chk_allow_suspicious)
        self.adv.setVisible(False)
        self.btn_more.toggled.connect(self._toggle_adv)
        self.body.addLayout(row(self.btn_more))
        self.body.addWidget(self.adv)

        self.btn_clear = button(tr("Очистить банки…", "Erase banks…"), "DangerBtn", slot=self._clear)
        self.btn_clear.setToolTip(
            tr("Вернуть отмеченные банки в заводское состояние FF..FF", "Return the ticked banks to factory FF..FF")
        )
        self.btn_ok = button(tr("Привязать", "Bind"), "PrimaryBtn", slot=self._bind)
        self.finish(self.btn_clear, ok=self.btn_ok)
        self._sync()

    def _toggle_row(self, r: int, c: int) -> None:
        if c != 0:  # whole row is clickable, column 0 toggles natively
            it = self.tbl.item(r, 0)
            it.setCheckState(Qt.CheckState.Unchecked if it.checkState() == Qt.CheckState.Checked else Qt.CheckState.Checked)

    def _toggle_adv(self, on: bool) -> None:
        self.adv.setVisible(on)
        self.btn_more.setText(tr("Дополнительно ▾", "Advanced ▾") if on else tr("Дополнительно ▸", "Advanced ▸"))

    def _checked(self) -> list[SlotSpec]:
        return [
            spec for r, spec in enumerate(SLAVE_SLOTS) if self.tbl.item(r, 0).checkState() == Qt.CheckState.Checked
        ]

    def _parsed_key(self) -> tuple[bytes | None, bool]:
        """(key or None, key is allowed). Updates the guard line."""
        raw = self.ed_key.text().strip()
        if not raw:
            self.lbl_guard.setVisible(False)
            return None, False
        self.lbl_guard.setVisible(True)
        try:
            k = parse_hex_key(raw)
        except ValueError as exc:
            set_tone(self.lbl_guard, "err")
            self.lbl_guard.setText(f"✗  {exc}")
            return None, False
        warns = check_key_warnings(k)
        if warns:
            sev, msg = warns[0]
            set_tone(self.lbl_guard, "err" if sev == "STOP" else "warn")
            self.lbl_guard.setText(f"⚠  {msg}")
            stop = any(s == "STOP" for s, _ in warns)
            return k, (not stop) or self.chk_allow_suspicious.isChecked()
        set_tone(self.lbl_guard, "ok")
        self.lbl_guard.setText(tr("✓  Ключ корректен", "✓  Valid key"))
        return k, True

    def _sync(self) -> None:
        banks = self._checked()
        key, allowed = self._parsed_key()
        self.btn_ok.setEnabled(bool(banks) and key is not None and allowed)
        self.btn_ok.setText(
            tr(f"Привязать ({len(banks)})", f"Bind ({len(banks)})") if banks else tr("Привязать", "Bind")
        )
        self.btn_clear.setEnabled(bool(banks))

    def _generate(self) -> None:
        while True:
            cand = secrets.token_bytes(16)
            if not check_key_warnings(cand):
                break
        self.ed_key.setText(cand.hex().upper())

    def _copy(self) -> None:
        if self.ed_key.text().strip():
            QGuiApplication.clipboard().setText(self.ed_key.text().strip())

    def _bind(self) -> None:
        key, allowed = self._parsed_key()
        if key is None or not allowed:
            return
        self.action, self.banks, self.key = "bind", self._checked(), key
        self.accept()

    def _clear(self) -> None:
        banks = self._checked()
        addrs = ", ".join(s.ecu_addr for s in banks)
        ans = QMessageBox.question(
            self,
            tr("Очистка банков", "Erase banks"),
            tr(
                f"Вернуть банки {addrs} в заводское пустое состояние FF..FF?\nИзменение попадёт в копию DataFlash.",
                f"Return banks {addrs} to factory empty FF..FF?\nThe change goes into the DataFlash copy.",
            ),
        )
        if ans == QMessageBox.StandardButton.Yes:
            self.action, self.banks = "clear", banks
            self.accept()

    @property
    def force_mask(self) -> bool:
        return self.chk_force_mask.isChecked()
