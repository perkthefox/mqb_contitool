"""J533 T20 (2x10) bench wiring diagram with the CAN termination callout."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from contitool.core import T20_BENCH_PINS
from contitool.gui import theme
from contitool.gui.theme import mono_font
from contitool.gui.widgets.page import Callout, Section
from contitool.i18n import get_lang, subscribe_lang_change, tr

PIN_COLORS = {
    1: theme.ERR,  # KL30 +12V
    14: "#E0884D",  # KL15 +12V
    11: "#A1A4AB",  # KL31 GND
    19: theme.OK,  # CAN-H
    9: theme.INFO,  # CAN-L
}


class _T20DiagramCanvas(QWidget):
    """Vector drawing of the 2x10 J533 T20 connector face."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(420, 148)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        housing = QRectF(8, 16, 326.0, 106.0)
        hp = QPainterPath()
        hp.addRoundedRect(housing, 8, 8)
        p.fillPath(hp, QColor(theme.BG_INPUT))
        p.setPen(QPen(QColor(theme.BORDER_STRONG), 1.5))
        p.drawPath(hp)

        cols = 10
        cell_w = (housing.width() - 24) / cols
        row_y = (housing.top() + 14, housing.top() + 58)
        pin_centers: dict[int, QPointF] = {}

        p.setFont(mono_font(11, bold=True))
        for col in range(cols):
            for r_idx, pin_num in enumerate((col + 1, col + 11)):
                box = QRectF(housing.left() + 15 + col * cell_w, row_y[r_idx], cell_w - 6, 32)
                pin_centers[pin_num] = box.center()
                bp = QPainterPath()
                bp.addRoundedRect(box, 4, 4)
                if pin_num in PIN_COLORS:
                    p.fillPath(bp, QColor(PIN_COLORS[pin_num]))
                    p.setPen(QColor(theme.BG_WINDOW))
                else:
                    p.fillPath(bp, QColor(theme.BG_HOVER))
                    p.setPen(QColor(theme.TEXT_MUTED))
                p.drawText(box, Qt.AlignmentFlag.AlignCenter, str(pin_num))

        # 120 Ohm bridge between Pin 9 (CAN-L, top row) and Pin 19 (CAN-H, bottom row)
        c9, c19 = pin_centers[9], pin_centers[19]
        res_x = housing.right() + 40
        y_top, y_bot = housing.top() - 7, housing.bottom() + 7
        rbox = QRectF(res_x - 28, housing.center().y() - 16, 56, 32)

        p.setPen(QPen(QColor(theme.WARN), 1.8))
        p.drawPolyline([QPointF(c9.x(), c9.y() - 16), QPointF(c9.x(), y_top), QPointF(res_x, y_top), QPointF(res_x, rbox.top())])
        p.drawPolyline([QPointF(c19.x(), c19.y() + 16), QPointF(c19.x(), y_bot), QPointF(res_x, y_bot), QPointF(res_x, rbox.bottom())])

        rp = QPainterPath()
        rp.addRoundedRect(rbox, 4, 4)
        p.fillPath(rp, QColor(theme.BG_INPUT))
        p.drawPath(rp)
        p.setFont(mono_font(12, bold=True))
        p.setPen(QColor(theme.WARN))
        p.drawText(rbox, Qt.AlignmentFlag.AlignCenter, "120 Ω")
        p.end()


class PinoutCard(Section):
    """Bench connection reference for the J533 T20 connector. `stacked`: the legend goes under the drawing and its
    lines wrap — for a narrow dialog; otherwise they sit side by side, one line each."""

    def __init__(self, parent: QWidget | None = None, *, stacked: bool = False) -> None:
        super().__init__(parent)
        content = QVBoxLayout() if stacked else QHBoxLayout()
        content.setSpacing(20)

        self.canvas = _T20DiagramCanvas()
        content.addWidget(self.canvas, 0, Qt.AlignmentFlag.AlignTop)

        right = QVBoxLayout()
        right.setSpacing(10)
        self.grid_pins = QGridLayout()
        self.grid_pins.setHorizontalSpacing(14)
        self.grid_pins.setVerticalSpacing(4)
        self.grid_pins.setColumnStretch(2, 1)
        self._pin_labels: list[tuple[QLabel, QLabel, QLabel]] = []
        for r, (pin, sig, _ru, _en) in enumerate(T20_BENCH_PINS):
            num = QLabel(f"Pin {pin}")
            num.setStyleSheet(f"color: {PIN_COLORS.get(pin, theme.TEXT)}; font-weight: 600;")
            name = QLabel(sig)
            name.setObjectName("Hint")
            desc = QLabel()  # side by side one line each: wrapped labels in a grid report a width the grid ignores
            desc.setWordWrap(stacked)
            for c, w in enumerate((num, name, desc)):
                self.grid_pins.addWidget(w, r, c, Qt.AlignmentFlag.AlignTop)
            self._pin_labels.append((num, name, desc))
        right.addLayout(self.grid_pins)

        self.warn_box = Callout("warn")
        self.lbl_warn = self.warn_box.label
        right.addWidget(self.warn_box)
        right.addStretch(1)
        content.addLayout(right, 1)
        self.body.addLayout(content)

        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.retranslate_ui()

    def retranslate_ui(self) -> None:
        self.set_text(tr("Разъём T20 — подключение на стенде", "T20 connector — bench wiring"))
        for (_pin, _sig, desc_ru, desc_en), (_num, _name, lbl) in zip(T20_BENCH_PINS, self._pin_labels, strict=True):
            lbl.setText(desc_ru if get_lang() == "ru" else desc_en)
        self.lbl_warn.setText(
            tr(
                "<b>Обязательно:</b> включён терминатор в адаптере или установлен резистор 120 Ом между "
                "Pin 19 (CAN-H) и Pin 9 (CAN-L). Без терминатора шина CAN уходит в Bus-Off.",
                "<b>Required:</b> the adapter's terminator is on or a 120 Ω resistor is fitted between "
                "Pin 19 (CAN-H) and Pin 9 (CAN-L). Without termination the CAN bus goes Bus-Off.",
            )
        )
