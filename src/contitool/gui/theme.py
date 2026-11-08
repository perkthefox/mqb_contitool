"""Neutral graphite theme: palette tokens, QSS, monospace font, tone helper, and app icon."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontDatabase,
    QIcon,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import QApplication, QComboBox, QProxyStyle, QStyle, QStyleFactory, QWidget

# Surfaces
BG_WINDOW = "#1E1F22"
BG_SIDEBAR = "#191A1C"  # header & console bars
BG_SECTION = "#25272A"
BG_INPUT = "#1B1C1F"
BG_HOVER = "#2E3034"
BG_SELECTED = "#2E436E"
BORDER = "#34363B"
BORDER_STRONG = "#46494F"

# Text
TEXT = "#DFE1E5"
TEXT_SECONDARY = "#A1A4AB"
TEXT_MUTED = "#6F737A"

# Accent & semantic tones
ACCENT = "#3574F0"
ACCENT_HOVER = "#4A84F5"
OK = "#5FB865"
WARN = "#E0A84D"
ERR = "#E5626D"
INFO = "#6EA6F8"
CAN = "#B189F5"

TONES = {"ok": OK, "warn": WARN, "err": ERR, "info": INFO, "muted": TEXT_MUTED}


def mono_font(px: int = 12, bold: bool = False) -> QFont:
    """Platform fixed-width font (SF Mono / Consolas / DejaVu Sans Mono) at a pixel size."""
    f = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    f.setPixelSize(px)
    f.setBold(bold)
    return f


def set_tone(widget: QWidget, tone: str) -> None:
    """Switch a widget's semantic `tone` property (ok / warn / err / info / muted) and repaint."""
    if widget.property("tone") == tone:
        return
    widget.setProperty("tone", tone)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


class _Style(QProxyStyle):
    """Fusion with check indicators that stay visible on a dark palette (Fusion outlines them near-black)."""

    _CHECKS = (
        QStyle.PrimitiveElement.PE_IndicatorCheckBox,
        QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck,
    )

    def drawPrimitive(self, element, option, painter, widget=None) -> None:  # noqa: N802 (Qt override)
        if element == QStyle.PrimitiveElement.PE_IndicatorRadioButton:
            self._draw_radio(option, painter)
            return
        if element == QStyle.PrimitiveElement.PE_IndicatorArrowDown and isinstance(widget, QComboBox):
            c = QRectF(option.rect).center()
            painter.save()
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            painter.setPen(QPen(QColor(TEXT_SECONDARY), 1.5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawPolyline([QPointF(c.x() - 4, c.y() - 2), QPointF(c.x(), c.y() + 2), QPointF(c.x() + 4, c.y() - 2)])
            painter.restore()
            return
        if element not in self._CHECKS:
            super().drawPrimitive(element, option, painter, widget)
            return
        r = QRectF(option.rect)
        side = min(r.width(), r.height(), 16.0) - 1
        box = QRectF(r.x() + 0.5, r.center().y() - side / 2, side, side)
        on = bool(option.state & QStyle.StateFlag.State_On)
        enabled = bool(option.state & QStyle.StateFlag.State_Enabled)
        hover = bool(option.state & QStyle.StateFlag.State_MouseOver)

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setOpacity(1.0 if enabled else 0.45)
        border = ACCENT if on or hover else "#6A6E75"
        painter.setPen(QPen(QColor(border), 1.0))
        painter.setBrush(QColor(ACCENT if on else BG_INPUT))
        painter.drawRoundedRect(box, 3, 3)
        if on:
            pen = QPen(QColor("#FFFFFF"), max(1.6, side * 0.13))
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            x, y, s = box.x(), box.y(), box.width()
            painter.drawPolyline(
                [QPointF(x + s * 0.25, y + s * 0.52), QPointF(x + s * 0.43, y + s * 0.70), QPointF(x + s * 0.76, y + s * 0.32)]
            )
        painter.restore()

    @staticmethod
    def _draw_radio(option, painter) -> None:  # noqa: ANN001 (Qt option types)
        r = QRectF(option.rect)
        side = min(r.width(), r.height(), 16.0) - 1
        box = QRectF(r.x() + 0.5, r.center().y() - side / 2, side, side)
        on = bool(option.state & QStyle.StateFlag.State_On)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setOpacity(1.0 if option.state & QStyle.StateFlag.State_Enabled else 0.45)
        painter.setPen(QPen(QColor(ACCENT if on else "#6A6E75"), 1.0))
        painter.setBrush(QColor(ACCENT if on else BG_INPUT))
        painter.drawEllipse(box)
        if on:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#FFFFFF"))
            painter.drawEllipse(box.adjusted(side * 0.3, side * 0.3, -side * 0.3, -side * 0.3))
        painter.restore()


_STYLE: _Style | None = None


def apply_theme(app: QApplication) -> None:
    """Fusion style + dark palette + stylesheet. Palette covers dialogs and native sub-controls."""
    global _STYLE
    if app.property("_contitool_themed"):
        return
    app.setProperty("_contitool_themed", True)
    _STYLE = _Style(QStyleFactory.create("Fusion"))
    app.setStyle(_STYLE)
    pal = QPalette()
    roles = {
        QPalette.ColorRole.Window: BG_WINDOW,
        QPalette.ColorRole.WindowText: TEXT,
        QPalette.ColorRole.Base: BG_INPUT,
        QPalette.ColorRole.AlternateBase: BG_SECTION,
        QPalette.ColorRole.Text: TEXT,
        QPalette.ColorRole.Button: BG_SECTION,
        QPalette.ColorRole.ButtonText: TEXT,
        QPalette.ColorRole.Highlight: ACCENT,
        QPalette.ColorRole.HighlightedText: "#FFFFFF",
        QPalette.ColorRole.ToolTipBase: BG_SECTION,
        QPalette.ColorRole.ToolTipText: TEXT,
        QPalette.ColorRole.PlaceholderText: TEXT_MUTED,
        QPalette.ColorRole.Link: INFO,
        QPalette.ColorRole.Mid: BORDER,
        QPalette.ColorRole.Dark: BG_SIDEBAR,
    }
    for role, hex_col in roles.items():
        pal.setColor(role, QColor(hex_col))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText, QPalette.ColorRole.WindowText):
        pal.setColor(QPalette.ColorGroup.Disabled, role, QColor(TEXT_MUTED))
    app.setPalette(pal)
    font = app.font()
    font.setPixelSize(13)
    app.setFont(font)
    app.setStyleSheet(build_stylesheet())


def build_app_icon() -> QIcon:
    """Flat chip glyph on an accent tile, rendered at standard DPI sizes."""
    icon = QIcon()
    for sz in (32, 64, 128, 256):
        pix = QPixmap(sz, sz)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        m = sz * 0.06
        tile = QPainterPath()
        tile.addRoundedRect(QRectF(m, m, sz - 2 * m, sz - 2 * m), sz * 0.2, sz * 0.2)
        p.fillPath(tile, QColor(ACCENT))

        pen = QPen(QColor("#FFFFFF"), max(1.5, sz * 0.045))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        for frac in (0.38, 0.50, 0.62):
            pos = sz * frac
            p.drawLine(QPointF(pos, sz * 0.20), QPointF(pos, sz * 0.30))
            p.drawLine(QPointF(pos, sz * 0.70), QPointF(pos, sz * 0.80))
            p.drawLine(QPointF(sz * 0.20, pos), QPointF(sz * 0.30, pos))
            p.drawLine(QPointF(sz * 0.70, pos), QPointF(sz * 0.80, pos))
        core = QPainterPath()
        core.addRoundedRect(QRectF(sz * 0.30, sz * 0.30, sz * 0.40, sz * 0.40), sz * 0.06, sz * 0.06)
        p.drawPath(core)
        p.end()
        icon.addPixmap(pix)
    return icon


def dot_icon(color: str, size: int = 8) -> QIcon:
    """Small filled status dot for chips and the status bar."""
    pix = QPixmap(size * 2, size * 2)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(color))
    p.drawEllipse(QRectF(size * 0.5, size * 0.5, size, size))
    p.end()
    return QIcon(pix)


def build_stylesheet() -> str:
    """QSS for ContiTool. Fonts are left to QApplication.setFont / mono_font() so setFont() keeps working."""
    return f"""
    QToolTip {{
        background-color: {BG_SECTION}; color: {TEXT}; border: 1px solid {BORDER_STRONG}; padding: 4px 6px;
    }}
    QMenuBar {{ background-color: {BG_SIDEBAR}; color: {TEXT_SECONDARY}; border-bottom: 1px solid {BORDER}; padding: 2px 8px; }}
    QMenuBar::item {{ background: transparent; padding: 4px 10px; border-radius: 4px; }}
    QMenuBar::item:selected {{ background-color: {BG_HOVER}; color: {TEXT}; }}
    QMenu {{ background-color: {BG_SECTION}; border: 1px solid {BORDER_STRONG}; padding: 4px; }}
    QMenu::item {{ padding: 5px 24px 5px 12px; border-radius: 4px; color: {TEXT}; }}
    QMenu::item:selected {{ background-color: {BG_SELECTED}; }}
    QMenu::item:disabled {{ color: {TEXT_MUTED}; }}
    QMenu::separator {{ height: 1px; background: {BORDER}; margin: 4px 6px; }}
    QStatusBar {{ background-color: {BG_SIDEBAR}; border-top: 1px solid {BORDER}; color: {TEXT_SECONDARY}; }}
    QStatusBar::item {{ border: none; }}

    /* ── Surfaces ── */
    QFrame#Header {{ background-color: {BG_SIDEBAR}; border-bottom: 1px solid {BORDER}; }}
    QFrame#Section {{ background-color: {BG_SECTION}; border: 1px solid {BORDER}; border-radius: 6px; }}
    QFrame#Console {{ background-color: {BG_WINDOW}; border-top: 1px solid {BORDER}; }}
    QFrame#Divider {{ background-color: {BORDER}; max-height: 1px; min-height: 1px; border: none; }}
    QFrame#WriteBar {{
        background-color: #1F2633; border: 1px solid #2B3F66; border-left: 3px solid {ACCENT}; border-radius: 6px;
    }}
    QFrame#Step {{ background-color: rgba(255, 255, 255, 0.025); border: 1px solid {BORDER}; border-radius: 6px; }}
    QLabel#StepNum {{ background-color: {BG_HOVER}; color: {TEXT}; border-radius: 11px; font-size: 11px; font-weight: 600; }}
    QListWidget#Nav {{ background: transparent; border: none; outline: 0; }}
    QListWidget#Nav::item {{ border-radius: 4px; margin: 1px 0; }}
    QListWidget#Nav::item:selected {{ background-color: {BG_SELECTED}; }}
    QListWidget#Nav::item:hover:!selected {{ background-color: {BG_HOVER}; }}
    QListWidget#Adapters {{ background-color: {BG_INPUT}; border: 1px solid {BORDER}; border-radius: 6px; padding: 2px; outline: 0; }}
    QListWidget#Adapters::item {{ border-radius: 4px; margin: 1px; }}
    QListWidget#Adapters::item:selected {{ background-color: {BG_SELECTED}; }}
    QListWidget#Adapters::item:hover:!selected {{ background-color: {BG_HOVER}; }}
    QLabel#AdapterTitle {{ color: {TEXT}; font-weight: 600; }}
    QLabel#AdapterTitle[tone="muted"] {{ color: {TEXT_MUTED}; }}
    QFrame#ListRow {{ background: transparent; border-radius: 4px; }}
    QFrame#ListRow:hover {{ background-color: {BG_HOVER}; }}
    QScrollArea {{ background: transparent; border: none; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QSplitter::handle {{ background-color: {BORDER}; }}

    QFrame#Callout {{ border-radius: 6px; border: 1px solid {BORDER}; border-left: 3px solid {INFO}; background-color: {BG_SECTION}; }}
    QFrame#Callout[tone="ok"] {{ border-left-color: {OK}; background-color: #232B25; }}
    QFrame#Callout[tone="warn"] {{ border-left-color: {WARN}; background-color: #2B2822; }}
    QFrame#Callout[tone="err"] {{ border-left-color: {ERR}; background-color: #2E2427; }}

    /* ── Typography ── */
    QLabel {{ background: transparent; }}
    QLabel#AppName {{ font-size: 13px; font-weight: 600; color: {TEXT}; }}
    QLabel#PageTitle {{ font-size: 17px; font-weight: 600; color: {TEXT}; }}
    QLabel#PartNumber {{ font-size: 20px; font-weight: 600; color: {TEXT}; }}
    QLabel#SectionTitle {{ font-size: 13px; font-weight: 600; color: {TEXT}; }}
    QLabel#GroupLabel {{ font-size: 11px; font-weight: 600; color: {TEXT_MUTED}; }}
    QLabel#FieldLabel {{ font-weight: 600; color: {TEXT}; }}
    QLabel#Hint {{ color: {TEXT_SECONDARY}; }}
    QLabel[tone="ok"], QLabel#Hint[tone="ok"] {{ color: {OK}; }}
    QLabel[tone="warn"], QLabel#Hint[tone="warn"] {{ color: {WARN}; }}
    QLabel[tone="err"], QLabel#Hint[tone="err"] {{ color: {ERR}; }}
    QLabel[tone="info"], QLabel#Hint[tone="info"] {{ color: {INFO}; }}
    QLabel[tone="muted"], QLabel#Hint[tone="muted"] {{ color: {TEXT_MUTED}; }}

    QLabel#Pill {{
        border-radius: 3px; padding: 1px 6px; font-size: 11px; font-weight: 600;
        background-color: rgba(255, 255, 255, 0.05); border: 1px solid {BORDER_STRONG}; color: {TEXT_SECONDARY};
    }}
    QLabel#Pill[tone="ok"] {{ background-color: rgba(95, 184, 101, 0.10); border-color: rgba(95, 184, 101, 0.35); color: {OK}; }}
    QLabel#Pill[tone="warn"] {{ background-color: rgba(224, 168, 77, 0.10); border-color: rgba(224, 168, 77, 0.35); color: {WARN}; }}
    QLabel#Pill[tone="err"] {{ background-color: rgba(229, 98, 109, 0.10); border-color: rgba(229, 98, 109, 0.35); color: {ERR}; }}
    QLabel#Pill[tone="info"] {{ background-color: rgba(110, 166, 248, 0.10); border-color: rgba(110, 166, 248, 0.35); color: {INFO}; }}

    /* ── Buttons ── */
    QPushButton, QToolButton {{
        background-color: #2B2D30; color: {TEXT}; border: 1px solid {BORDER_STRONG};
        border-radius: 4px; padding: 5px 12px; min-height: 18px;
    }}
    QPushButton:hover, QToolButton:hover {{ background-color: #34363A; }}
    QPushButton:pressed, QToolButton:pressed {{ background-color: {BORDER}; }}
    QPushButton:disabled, QToolButton:disabled {{ background-color: transparent; color: {TEXT_MUTED}; border-color: {BORDER}; }}
    QPushButton:focus, QToolButton:focus {{ outline: none; }}
    QPushButton:checked {{ background-color: {BG_SELECTED}; border-color: {ACCENT}; }}
    QToolButton::menu-indicator {{ image: none; width: 0; }}

    QPushButton#PrimaryBtn {{ background-color: {ACCENT}; border-color: {ACCENT}; color: #FFFFFF; font-weight: 600; }}
    QPushButton#PrimaryBtn:hover {{ background-color: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; }}
    QPushButton#PrimaryBtn:disabled {{ background-color: #2B3A57; border-color: #2B3A57; color: #7D8597; }}

    QPushButton#DangerBtn {{ background-color: transparent; border-color: #6B3A3F; color: {ERR}; }}
    QPushButton#DangerBtn:hover {{ background-color: #3A2629; }}
    QPushButton#DangerBtn:disabled {{ border-color: {BORDER}; color: {TEXT_MUTED}; }}

    QPushButton#GhostBtn, QToolButton#GhostBtn {{
        background-color: transparent; border-color: transparent; color: {TEXT_SECONDARY}; padding: 4px 8px;
    }}
    QPushButton#GhostBtn:hover, QToolButton#GhostBtn:hover {{ background-color: {BG_HOVER}; color: {TEXT}; }}
    QPushButton#GhostBtn:checked {{ background-color: {BG_HOVER}; color: {TEXT}; }}
    QPushButton#GhostBtn:disabled {{ color: {TEXT_MUTED}; }}

    QPushButton#LinkBtn {{ background: transparent; border: none; padding: 0; min-height: 0; color: {INFO}; }}
    QPushButton#LinkBtn:hover {{ color: {ACCENT_HOVER}; text-decoration: underline; }}

    QPushButton#Chip {{
        background-color: transparent; border: 1px solid {BORDER}; border-radius: 4px;
        padding: 3px 10px; min-height: 18px; color: {TEXT_SECONDARY};
    }}
    QPushButton#Chip:hover {{ background-color: {BG_HOVER}; color: {TEXT}; }}

    QPushButton#TabBtn {{
        background: transparent; border: none; border-bottom: 2px solid transparent; border-radius: 0;
        color: {TEXT_SECONDARY}; padding: 0 12px; min-height: 36px; font-weight: 600;
    }}
    QPushButton#TabBtn:hover {{ color: {TEXT}; }}
    QPushButton#TabBtn:checked {{ color: {TEXT}; border-bottom-color: {ACCENT}; background: transparent; }}
    QPushButton#TabBtn:disabled {{ color: {TEXT_MUTED}; }}

    QPushButton#SegBtn {{
        background-color: transparent; border: 1px solid {BORDER_STRONG}; color: {TEXT_SECONDARY};
        border-radius: 0; padding: 2px 9px; min-height: 18px; font-size: 11px; font-weight: 600;
    }}
    QPushButton#SegBtn:hover {{ color: {TEXT}; }}
    QPushButton#SegBtn:checked {{ background-color: {BG_HOVER}; border-color: {BORDER_STRONG}; color: {TEXT}; }}
    QPushButton#SegBtn[pos="left"] {{ border-top-left-radius: 4px; border-bottom-left-radius: 4px; border-right: none; }}
    QPushButton#SegBtn[pos="right"] {{ border-top-right-radius: 4px; border-bottom-right-radius: 4px; }}

    /* ── Inputs ── */
    QLineEdit, QComboBox, QSpinBox {{
        background-color: {BG_INPUT}; color: {TEXT}; border: 1px solid {BORDER_STRONG};
        border-radius: 4px; padding: 4px 8px; min-height: 22px; selection-background-color: {ACCENT};
    }}
    QPlainTextEdit, QTextEdit {{
        background-color: {BG_INPUT}; color: {TEXT}; border: 1px solid {BORDER_STRONG};
        border-radius: 4px; padding: 6px; selection-background-color: {ACCENT};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border-color: {ACCENT}; }}
    QLineEdit[tone="err"] {{ border-color: {ERR}; }}
    QLineEdit[drag="true"] {{ border: 1px dashed {ACCENT}; background-color: #1E2633; }}
    QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{ color: {TEXT_MUTED}; border-color: {BORDER}; }}
    QComboBox::drop-down {{ border: none; width: 24px; }}
    QComboBox QAbstractItemView {{
        background-color: {BG_SECTION}; border: 1px solid {BORDER_STRONG}; padding: 4px;
        selection-background-color: {BG_SELECTED}; outline: 0;
    }}
    QComboBox QAbstractItemView::item {{ min-height: 24px; padding: 3px 8px; border-radius: 3px; }}
    QCheckBox, QRadioButton {{ spacing: 8px; color: {TEXT}; background: transparent; min-height: 20px; }}
    QCheckBox:disabled, QRadioButton:disabled {{ color: {TEXT_MUTED}; }}

    /* ── Tabs ── */
    QTabWidget::pane {{
        border: 1px solid {BORDER}; border-radius: 6px; background-color: {BG_WINDOW}; top: -1px;
    }}
    QTabBar::tab {{
        background-color: transparent; color: {TEXT_SECONDARY}; border: 1px solid transparent;
        border-bottom: 2px solid transparent; padding: 7px 14px; min-height: 20px; font-weight: 600;
        margin-right: 2px;
    }}
    QTabBar::tab:hover:!selected {{ color: {TEXT}; background-color: {BG_HOVER}; border-top-left-radius: 4px; border-top-right-radius: 4px; }}
    QTabBar::tab:selected {{ color: {TEXT}; border-bottom-color: {ACCENT}; }}

    /* ── Progress ── */
    QProgressBar {{ background-color: {BG_HOVER}; border: none; border-radius: 2px; max-height: 4px; min-height: 4px; }}
    QProgressBar::chunk {{ background-color: {ACCENT}; border-radius: 2px; }}
    QProgressBar[tone="ok"]::chunk {{ background-color: {OK}; }}
    QProgressBar[tone="err"]::chunk {{ background-color: {ERR}; }}

    /* ── Tables ── */
    QTableView {{
        background-color: {BG_INPUT}; alternate-background-color: #202124; gridline-color: transparent;
        border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT};
        selection-background-color: {BG_SELECTED}; selection-color: {TEXT};
    }}
    QTableView::item {{ padding: 0 6px; }}
    QHeaderView::section {{
        background-color: {BG_SECTION}; color: {TEXT_SECONDARY}; border: none;
        border-bottom: 1px solid {BORDER}; padding: 5px 6px; font-weight: 600;
    }}

    /* ── Scrollbars ── */
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
    QScrollBar::handle {{ background: {BORDER_STRONG}; border-radius: 3px; min-height: 24px; min-width: 24px; }}
    QScrollBar::handle:hover {{ background: #5E6168; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    """
