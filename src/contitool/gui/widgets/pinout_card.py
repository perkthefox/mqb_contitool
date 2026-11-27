"""Bench wiring diagrams for Continental J533 Gateway (T20, 2x10) and Kombi FPK_E (T18, 2x9)."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from contitool.core import T18_KOMBI_BENCH_PINS, T20_BENCH_PINS, T4_ELV_BENCH_PINS
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

KOMBI_T18_PIN_COLORS = {
    1: theme.ERR,    # KL30 +12V
    8: "#E0884D",    # D2 Coil 1 (125 kHz)
    9: "#E0884D",    # D2 Coil 2 (125 kHz)
    10: "#A1A4AB",   # KL31 GND
    18: theme.OK,    # CAN-H
    17: theme.INFO,  # CAN-L
}

ELV_T4_PIN_COLORS = {
    1: theme.OK,    # CAN-H
    2: theme.INFO,  # CAN-L
    3: theme.ERR,   # KL30 +12V
    4: "#A1A4AB",   # KL31 GND
}


class _T20DiagramCanvas(QWidget):
    """Vector drawing of the 2x10 J533 T20 connector face."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(376, 144)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        housing = QRectF(6, 16, 292.0, 102.0)
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


class _T18DiagramCanvas(QWidget):
    """Vector drawing of the 2x9 MQB Kombi FPK_E T18 connector face."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(376, 144)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        housing = QRectF(6, 16, 274.0, 102.0)
        hp = QPainterPath()
        hp.addRoundedRect(housing, 8, 8)
        p.fillPath(hp, QColor(theme.BG_INPUT))
        p.setPen(QPen(QColor(theme.BORDER_STRONG), 1.5))
        p.drawPath(hp)

        cols = 9
        cell_w = (housing.width() - 24) / cols
        row_y = (housing.top() + 14, housing.top() + 58)
        pin_centers: dict[int, QPointF] = {}

        p.setFont(mono_font(11, bold=True))
        for col in range(cols):
            for r_idx, pin_num in enumerate((col + 1, col + 10)):
                box = QRectF(housing.left() + 15 + col * cell_w, row_y[r_idx], cell_w - 6, 32)
                pin_centers[pin_num] = box.center()
                bp = QPainterPath()
                bp.addRoundedRect(box, 4, 4)
                if pin_num in KOMBI_T18_PIN_COLORS:
                    p.fillPath(bp, QColor(KOMBI_T18_PIN_COLORS[pin_num]))
                    p.setPen(QColor(theme.BG_WINDOW))
                else:
                    p.fillPath(bp, QColor(theme.BG_HOVER))
                    p.setPen(QColor(theme.TEXT_MUTED))
                p.drawText(box, Qt.AlignmentFlag.AlignCenter, str(pin_num))

        # 120 Ohm bridge between Pin 17 (CAN-L, bottom row) and Pin 18 (CAN-H, bottom row)
        c17, c18 = pin_centers[17], pin_centers[18]
        res_x = housing.right() + 52
        y_bot17 = housing.bottom() + 14
        y_bot18 = housing.bottom() + 6
        rbox = QRectF(res_x - 28, housing.center().y() - 16, 56, 32)

        p.setPen(QPen(QColor(theme.WARN), 1.8))
        p.drawPolyline([QPointF(c17.x(), c17.y() + 16), QPointF(c17.x(), y_bot17), QPointF(res_x, y_bot17), QPointF(res_x, rbox.bottom())])
        p.drawPolyline([QPointF(c18.x(), c18.y() + 16), QPointF(c18.x(), y_bot18), QPointF(res_x - 12, y_bot18), QPointF(res_x - 12, rbox.bottom())])

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
            desc = QLabel()
            desc.setWordWrap(True)
            desc.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            for c, w in enumerate((num, name, desc)):
                self.grid_pins.addWidget(w, r, c, Qt.AlignmentFlag.AlignTop)
            self._pin_labels.append((num, name, desc))
        right.addLayout(self.grid_pins)

        self.warn_box = Callout("warn")
        self.lbl_warn = self.warn_box.label
        self.lbl_warn.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        right.addWidget(self.warn_box)
        right.addStretch(1)
        content.addLayout(right, 1)
        self.body.addLayout(content)

        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.retranslate_ui()

    def retranslate_ui(self) -> None:
        self.set_text(tr("Шлюз J533 (T20) — подключение на стенде", "J533 gateway (T20) — bench wiring"))
        for (_pin, _sig, desc_ru, desc_en), (_num, _name, lbl) in zip(T20_BENCH_PINS, self._pin_labels, strict=True):
            lbl.setText(desc_ru if get_lang() == "ru" else desc_en)
        self.lbl_warn.setText(
            tr(
                "<b>Обязательно:</b> включите терминатор в адаптере или поставьте резистор 120 Ом между "
                "Pin 19 (CAN-H) и Pin 9 (CAN-L), иначе шина уйдёт в Bus-Off.",
                "<b>Required:</b> enable the adapter's terminator or fit a 120 Ω resistor between "
                "Pin 19 (CAN-H) and Pin 9 (CAN-L) to avoid Bus-Off.",
            )
        )


class KombiPinoutCard(Section):
    """Bench connection reference for the Continental Kombi / FPK_E 18-pin T18 connector."""

    def __init__(self, parent: QWidget | None = None, *, stacked: bool = False) -> None:
        super().__init__(parent)
        content = QVBoxLayout() if stacked else QHBoxLayout()
        content.setSpacing(20)

        self.canvas = _T18DiagramCanvas()
        content.addWidget(self.canvas, 0, Qt.AlignmentFlag.AlignTop)

        right = QVBoxLayout()
        right.setSpacing(10)
        self.grid_pins = QGridLayout()
        self.grid_pins.setHorizontalSpacing(14)
        self.grid_pins.setVerticalSpacing(4)
        self.grid_pins.setColumnStretch(2, 1)
        self._pin_labels: list[tuple[QLabel, QLabel, QLabel]] = []
        for r, (pin, sig, _ru, _en) in enumerate(T18_KOMBI_BENCH_PINS):
            num = QLabel(f"Pin {pin}")
            num.setStyleSheet(f"color: {KOMBI_T18_PIN_COLORS.get(pin, theme.TEXT)}; font-weight: 600;")
            name = QLabel(sig)
            name.setObjectName("Hint")
            desc = QLabel()
            desc.setWordWrap(True)
            desc.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            for c, w in enumerate((num, name, desc)):
                self.grid_pins.addWidget(w, r, c, Qt.AlignmentFlag.AlignTop)
            self._pin_labels.append((num, name, desc))
        right.addLayout(self.grid_pins)

        self.warn_box = Callout("info")
        self.lbl_warn = self.warn_box.label
        self.lbl_warn.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        right.addWidget(self.warn_box)
        right.addStretch(1)
        content.addLayout(right, 1)
        self.body.addLayout(content)

        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.retranslate_ui()

    def retranslate_ui(self) -> None:
        self.set_text(
            tr(
                "Панель Kombi FPK_E (T18) — подключение на стенде",
                "Kombi FPK_E cluster (T18) — bench wiring",
            )
        )
        for (_pin, _sig, desc_ru, desc_en), (_num, _name, lbl) in zip(
            T18_KOMBI_BENCH_PINS, self._pin_labels, strict=True
        ):
            lbl.setText(desc_ru if get_lang() == "ru" else desc_en)
        self.lbl_warn.setText(
            tr(
                "<b>Пробуждение по CAN:</b> отдельного пина KL15 нет — панель пробуждается автоматически по CAN "
                "(<code>0x3C0 / 0x663 / 0x585 / 0x3BE</code>). Нужен нативный CAN-адаптер "
                "(CANable / SLCAN / candleLight) и терминатор 120 Ом между Pin 18 (CAN-H) и Pin 17 (CAN-L).",
                "<b>CAN wake-up:</b> T18 has no KL15 pin — the cluster wakes automatically over CAN "
                "(<code>0x3C0 / 0x663 / 0x585 / 0x3BE</code>). Requires a native CAN adapter "
                "(CANable / SLCAN / candleLight) and 120 Ω termination between Pin 18 (CAN-H) and Pin 17 (CAN-L).",
            )
        )


class _T4ElvDiagramCanvas(QWidget):
    """Vector drawing of the 1x4 Marquardt ELV / J764 T4 connector face (Passat B8 / Kodiaq)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(376, 132)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        housing = QRectF(14, 24, 232.0, 66.0)
        hp = QPainterPath()
        hp.addRoundedRect(housing, 8, 8)
        p.fillPath(hp, QColor(theme.BG_INPUT))
        p.setPen(QPen(QColor(theme.BORDER_STRONG), 1.5))
        p.drawPath(hp)

        cell_w = (housing.width() - 28) / 4.0
        pin_centers: dict[int, QPointF] = {}
        p.setFont(mono_font(12, bold=True))
        for col in range(4):
            pin_num = col + 1
            box = QRectF(housing.left() + 18 + col * cell_w, housing.top() + 14, cell_w - 8, 38)
            pin_centers[pin_num] = box.center()
            bp = QPainterPath()
            bp.addRoundedRect(box, 5, 5)
            p.fillPath(bp, QColor(ELV_T4_PIN_COLORS[pin_num]))
            p.setPen(QColor(theme.BG_WINDOW))
            p.drawText(box, Qt.AlignmentFlag.AlignCenter, str(pin_num))

        # 120 Ohm bridge between Pin 1 (CAN-H) and Pin 2 (CAN-L)
        c1, c2 = pin_centers[1], pin_centers[2]
        res_x = housing.right() + 58
        y_top = housing.top() - 10
        y_bot = housing.bottom() + 14
        rbox = QRectF(res_x - 28, housing.center().y() - 16, 56, 32)
        p.setPen(QPen(QColor(theme.WARN), 1.8))
        p.drawPolyline([QPointF(c1.x(), c1.y() - 19), QPointF(c1.x(), y_top), QPointF(res_x, y_top), QPointF(res_x, rbox.top())])
        p.drawPolyline([QPointF(c2.x(), c2.y() + 19), QPointF(c2.x(), y_bot), QPointF(res_x, y_bot), QPointF(res_x, rbox.bottom())])

        rp = QPainterPath()
        rp.addRoundedRect(rbox, 4, 4)
        p.fillPath(rp, QColor(theme.BG_INPUT))
        p.drawPath(rp)
        p.setFont(mono_font(12, bold=True))
        p.setPen(QColor(theme.WARN))
        p.drawText(rbox, Qt.AlignmentFlag.AlignCenter, "120 Ω")
        p.end()


class ElvPinoutCard(Section):
    """Bench connection reference for the Marquardt MQB 2B ELV / J764 4-pin T4 connector."""

    def __init__(self, parent: QWidget | None = None, *, stacked: bool = False) -> None:
        super().__init__(parent)
        content = QVBoxLayout() if stacked else QHBoxLayout()
        content.setSpacing(20)

        self.canvas = _T4ElvDiagramCanvas()
        content.addWidget(self.canvas, 0, Qt.AlignmentFlag.AlignTop)

        right = QVBoxLayout()
        right.setSpacing(10)
        self.grid_pins = QGridLayout()
        self.grid_pins.setHorizontalSpacing(14)
        self.grid_pins.setVerticalSpacing(4)
        self.grid_pins.setColumnStretch(2, 1)
        self._pin_labels: list[tuple[QLabel, QLabel, QLabel]] = []
        for r, (pin, sig, _ru, _en) in enumerate(T4_ELV_BENCH_PINS):
            num = QLabel(f"Pin {pin}")
            num.setStyleSheet(f"color: {ELV_T4_PIN_COLORS.get(pin, theme.TEXT)}; font-weight: 600;")
            name = QLabel(sig)
            name.setObjectName("Hint")
            desc = QLabel()
            desc.setWordWrap(True)
            desc.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            for c, w in enumerate((num, name, desc)):
                self.grid_pins.addWidget(w, r, c, Qt.AlignmentFlag.AlignTop)
            self._pin_labels.append((num, name, desc))
        right.addLayout(self.grid_pins)

        self.warn_box = Callout("info")
        self.lbl_warn = self.warn_box.label
        self.lbl_warn.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        right.addWidget(self.warn_box)
        right.addStretch(1)
        content.addLayout(right, 1)
        self.body.addLayout(content)

        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.retranslate_ui()

    def retranslate_ui(self) -> None:
        self.set_text(
            tr(
                "Блокиратор руля ELV / J764 (T4) — подключение на стенде",
                "Steering column lock ELV / J764 (T4) — bench wiring",
            )
        )
        for (_pin, _sig, desc_ru, desc_en), (_num, _name, lbl) in zip(
            T4_ELV_BENCH_PINS, self._pin_labels, strict=True
        ):
            lbl.setText(desc_ru if get_lang() == "ru" else desc_en)
        self.lbl_warn.setText(
            tr(
                "<b>Пробуждение по CAN Komfort (500 кбит/с):</b> после подачи +12 В (Pin 3) и GND (Pin 4) "
                "защёлка просыпается кадром <code>0x1B000010</code>. Обязателен терминатор 120 Ом между Pin 1 (CAN-H) и Pin 2 (CAN-L).",
                "<b>Komfort CAN wake-up (500 kbit/s):</b> after applying +12 V (Pin 3) and GND (Pin 4), "
                "ELV wakes via <code>0x1B000010</code>. 120 Ω termination between Pin 1 (CAN-H) and Pin 2 (CAN-L) is required.",
            )
        )
