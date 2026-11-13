"""Machined graphite & precision instrument theme: palette tokens, QSS, monospace font, tone helper, and app icon."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, QSize, Qt
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

# Precision machined graphite elevation hierarchy (subtle cool steel undertone, zero SaaS navy/purple)
BG_CHROME = "#0E1013"    # menu bar & status bar
BG_SIDEBAR = "#121519"   # header bar, left nav pane, dialog footers & journal header
BG_WINDOW = "#16191E"    # main workspace canvas
BG_SECTION = "#1C2027"   # single-level elevated panels & action cards
BG_INPUT = "#101317"     # recessed inputs, tables & log views
BG_HOVER = "#242932"
BG_SELECTED = "#272D38"
BORDER = "#282E38"
BORDER_SUBTLE = "#20252E"
BORDER_STRONG = "#39414F"

# Crisp high-legibility typography
TEXT = "#ECEEF2"
TEXT_SECONDARY = "#9AA2B0"
TEXT_MUTED = "#666E7C"

# Calibrated instrument-grade accent & semantic tones (authoritative, never neon)
ACCENT = "#2E66B8"
ACCENT_HOVER = "#3874CC"
OK = "#44B57B"
WARN = "#D99B38"
ERR = "#DF5A5A"
INFO = "#639BF2"
CAN = "#A98DF5"

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
    """Fusion with crisp check/radio/combo indicators and non-eliding button sizing."""

    _CHECKS = (
        QStyle.PrimitiveElement.PE_IndicatorCheckBox,
        QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck,
    )

    def sizeFromContents(self, ct, option, size, widget=None) -> QSize:  # noqa: ANN001, N802 (Qt override)
        sz = super().sizeFromContents(ct, option, size, widget)
        if ct == QStyle.ContentsType.CT_PushButton and widget is not None:
            name = widget.objectName()
            if name != "LinkBtn":
                # QSS medium/demibold font-weight widens glyphs beyond Fusion's base metric; pad so labels never elide.
                extra = 6 if name in ("SegBtn", "TabBtn") else 14
                sz.setWidth(sz.width() + extra)
        return sz

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
        border = ACCENT_HOVER if on else ("#687182" if hover else "#48505E")
        painter.setPen(QPen(QColor(border), 1.0))
        painter.setBrush(QColor(ACCENT if on else BG_INPUT))
        painter.drawRoundedRect(box, 3.2, 3.2)
        if on:
            pen = QPen(QColor("#FFFFFF"), max(1.6, side * 0.13))
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            x, y, s = box.x(), box.y(), box.width()
            painter.drawPolyline(
                [QPointF(x + s * 0.24, y + s * 0.52), QPointF(x + s * 0.43, y + s * 0.70), QPointF(x + s * 0.76, y + s * 0.32)]
            )
        painter.restore()

    @staticmethod
    def _draw_radio(option, painter) -> None:  # noqa: ANN001 (Qt option types)
        r = QRectF(option.rect)
        side = min(r.width(), r.height(), 16.0) - 1
        box = QRectF(r.x() + 0.5, r.center().y() - side / 2, side, side)
        on = bool(option.state & QStyle.StateFlag.State_On)
        hover = bool(option.state & QStyle.StateFlag.State_MouseOver)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setOpacity(1.0 if option.state & QStyle.StateFlag.State_Enabled else 0.45)
        painter.setPen(QPen(QColor(ACCENT_HOVER if on else ("#687182" if hover else "#48505E")), 1.0))
        painter.setBrush(QColor(ACCENT if on else BG_INPUT))
        painter.drawEllipse(box)
        if on:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#FFFFFF"))
            painter.drawEllipse(box.adjusted(side * 0.3, side * 0.3, -side * 0.3, -side * 0.3))
        painter.restore()


_STYLE: _Style | None = None


def apply_theme(app: QApplication) -> None:
    """Fusion style + machined graphite palette + QSS stylesheet."""
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
        QPalette.ColorRole.Dark: BG_CHROME,
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
    """Anodized graphite QFP microcontroller mark with a precision cobalt pin-1 dot."""
    icon = QIcon()
    for sz in (32, 64, 128, 256):
        pix = QPixmap(sz, sz)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        m = sz * 0.06
        rect = QRectF(m, m, sz - 2 * m, sz - 2 * m)
        tile = QPainterPath()
        tile.addRoundedRect(rect, sz * 0.20, sz * 0.20)
        p.fillPath(tile, QColor("#20252E"))
        p.setPen(QPen(QColor("#38404E"), max(1.0, sz * 0.03)))
        p.drawPath(tile)

        pen = QPen(QColor("#CFD5E0"), max(1.4, sz * 0.042))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        for frac in (0.37, 0.50, 0.63):
            pos = sz * frac
            p.drawLine(QPointF(pos, sz * 0.19), QPointF(pos, sz * 0.29))
            p.drawLine(QPointF(pos, sz * 0.71), QPointF(pos, sz * 0.81))
            p.drawLine(QPointF(sz * 0.19, pos), QPointF(sz * 0.29, pos))
            p.drawLine(QPointF(sz * 0.71, pos), QPointF(sz * 0.81, pos))

        core = QPainterPath()
        core.addRoundedRect(QRectF(sz * 0.30, sz * 0.30, sz * 0.40, sz * 0.40), sz * 0.055, sz * 0.055)
        p.fillPath(core, QColor("#13161B"))
        p.setPen(QPen(QColor("#ECEEF2"), max(1.3, sz * 0.038)))
        p.drawPath(core)

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(INFO))
        p.drawEllipse(QPointF(sz * 0.41, sz * 0.41), sz * 0.045, sz * 0.045)
        p.end()
        icon.addPixmap(pix)
    return icon


def dot_icon(color: str, size: int = 7) -> QIcon:
    """Crisp geometric status LED without blurry glow."""
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
        background-color: #21262F; color: {TEXT}; border: 1px solid {BORDER_STRONG};
        border-radius: 4px; padding: 4px 8px;
    }}
    QMenuBar {{
        background-color: {BG_CHROME}; color: {TEXT_SECONDARY};
        border-bottom: 1px solid #1C2027; padding: 2px 8px;
    }}
    QMenuBar::item {{ background: transparent; padding: 4px 10px; border-radius: 4px; }}
    QMenuBar::item:selected {{ background-color: {BG_HOVER}; color: {TEXT}; }}
    QMenu {{
        background-color: #1C2027; border: 1px solid {BORDER_STRONG};
        border-radius: 6px; padding: 4px;
    }}
    QMenu::item {{ padding: 5px 24px 5px 12px; border-radius: 4px; color: {TEXT}; }}
    QMenu::item:selected {{ background-color: {BG_SELECTED}; color: #FFFFFF; }}
    QMenu::item:disabled {{ color: {TEXT_MUTED}; }}
    QMenu::separator {{ height: 1px; background: {BORDER}; margin: 4px 6px; }}
    QStatusBar {{
        background-color: {BG_CHROME}; border-top: 1px solid #1E232B; color: {TEXT_SECONDARY};
    }}
    QStatusBar::item {{ border: none; }}

    /* ── Architectural Surfaces ── */
    QFrame#Header {{
        background-color: {BG_SIDEBAR};
        border-bottom: 1px solid {BORDER};
        min-height: 42px;
    }}
    QFrame#IdentityBar {{
        background-color: #191D24;
        border-bottom: 1px solid {BORDER};
    }}
    QFrame#NavPane {{
        background-color: {BG_SIDEBAR};
        border-right: 1px solid {BORDER};
    }}
    QWidget#DialogFooter {{
        background-color: {BG_SIDEBAR};
        border-top: 1px solid {BORDER};
    }}
    QFrame#Section {{
        background-color: {BG_SECTION};
        border: 1px solid {BORDER};
        border-top-color: #303743;
        border-radius: 6px;
    }}
    QFrame#Step {{
        background-color: {BG_SECTION};
        border: 1px solid {BORDER};
        border-top-color: #303743;
        border-radius: 6px;
    }}
    QFrame#Console {{
        background-color: {BG_SIDEBAR};
        border-top: 1px solid {BORDER};
    }}
    QFrame#Divider {{ background-color: {BORDER}; max-height: 1px; min-height: 1px; border: none; }}
    QFrame#WriteBar {{
        background-color: #18202C;
        border-top: 1px solid #2B3B52;
        border-left: 3px solid {ACCENT_HOVER};
    }}
    QLabel#StepNum {{
        background-color: #262C36; color: {TEXT}; border: 1px solid #353C4A;
        border-radius: 4px; font-size: 11px; font-weight: 600;
    }}

    QListWidget#Nav {{ background: transparent; border: none; outline: 0; }}
    QListWidget#Nav::item {{
        border-radius: 5px; margin: 1px 4px; border-left: 2px solid transparent;
    }}
    QListWidget#Nav::item:selected {{
        background-color: #202631;
        border-left: 2px solid {INFO};
    }}
    QListWidget#Nav::item:hover:!selected {{
        background-color: #1A1E26;
    }}

    QListWidget#Adapters {{
        background-color: {BG_INPUT}; border: 1px solid {BORDER};
        border-radius: 5px; padding: 3px; outline: 0;
    }}
    QListWidget#Adapters::item {{ border-radius: 4px; margin: 1px; }}
    QListWidget#Adapters::item:selected {{ background-color: {BG_SELECTED}; border-left: 2px solid {INFO}; }}
    QListWidget#Adapters::item:hover:!selected {{ background-color: {BG_HOVER}; }}
    QLabel#AdapterTitle {{ color: {TEXT}; font-weight: 600; }}
    QLabel#AdapterTitle[tone="muted"] {{ color: {TEXT_MUTED}; }}

    QFrame#ListRow {{
        background-color: transparent;
        border-bottom: 1px solid {BORDER_SUBTLE};
        border-radius: 0;
    }}
    QFrame#ListRow:hover {{
        background-color: #1B1F26;
        border-radius: 4px;
    }}

    QScrollArea {{ background: transparent; border: none; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QSplitter::handle {{ background-color: {BORDER}; }}

    QFrame#Callout {{
        border-radius: 5px; border: 1px solid #282F3B; border-left: 3px solid {INFO};
        background-color: #181D25;
    }}
    QFrame#Callout[tone="ok"] {{
        border-color: #24362E; border-left-color: {OK}; background-color: #161F1B;
    }}
    QFrame#Callout[tone="warn"] {{
        border-color: #3B3122; border-left-color: {WARN}; background-color: #1E1B16;
    }}
    QFrame#Callout[tone="err"] {{
        border-color: #3F2629; border-left-color: {ERR}; background-color: #201719;
    }}

    /* ── Typography & Pure Text Status Readouts (Zero Pill Capsules) ── */
    QLabel {{ background: transparent; }}
    QLabel#AppName {{ font-size: 13px; font-weight: 600; color: {TEXT}; letter-spacing: 0.2px; }}
    QLabel#PageTitle {{ font-size: 18px; font-weight: 600; color: {TEXT}; }}
    QLabel#PartNumber {{ font-size: 19px; font-weight: 600; color: {TEXT}; letter-spacing: 0.3px; }}
    QLabel#SectionTitle {{ font-size: 14px; font-weight: 600; color: {TEXT}; }}
    QLabel#GroupLabel {{ font-size: 10px; font-weight: 600; color: {TEXT_MUTED}; letter-spacing: 0.7px; }}
    QLabel#FieldLabel {{ font-weight: 600; color: {TEXT}; }}
    QLabel#Hint {{ color: {TEXT_SECONDARY}; }}
    QLabel[tone="ok"], QLabel#Hint[tone="ok"] {{ color: {OK}; }}
    QLabel[tone="warn"], QLabel#Hint[tone="warn"] {{ color: {WARN}; }}
    QLabel[tone="err"], QLabel#Hint[tone="err"] {{ color: {ERR}; }}
    QLabel[tone="info"], QLabel#Hint[tone="info"] {{ color: {INFO}; }}
    QLabel[tone="muted"], QLabel#Hint[tone="muted"] {{ color: {TEXT_MUTED}; }}

    QLabel#Pill {{
        background-color: transparent; border: none; padding: 0;
        font-size: 12px; font-weight: 500; color: {TEXT_MUTED};
    }}
    QLabel#Pill[tone="ok"] {{ color: {OK}; }}
    QLabel#Pill[tone="warn"] {{ color: {WARN}; }}
    QLabel#Pill[tone="err"] {{ color: {ERR}; }}
    QLabel#Pill[tone="info"] {{ color: {INFO}; }}
    QListWidget#Nav QLabel#Pill {{
        font-size: 11px; font-weight: 500;
    }}

    /* ── Tactile Machined Buttons ── */
    QPushButton, QToolButton {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2B303B, stop:1 #232831);
        color: {TEXT};
        border: 1px solid #373E4B;
        border-top-color: #444C5C;
        border-bottom-color: #1B1F26;
        border-radius: 5px;
        padding: 5px 13px;
        min-height: 20px;
    }}
    QPushButton:hover, QToolButton:hover {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #333946, stop:1 #2A303B);
        border-color: #4A5364;
        border-top-color: #586276;
    }}
    QPushButton:pressed, QToolButton:pressed {{
        background-color: #1E222A;
        border-color: #303642;
    }}
    QPushButton:disabled, QToolButton:disabled {{
        background-color: #181B21;
        color: {TEXT_MUTED};
        border-color: #252A33;
    }}
    QPushButton:focus, QToolButton:focus {{ outline: none; }}
    QPushButton:checked {{
        background-color: #2E3542; border-color: #4D576B; color: #FFFFFF;
    }}
    QToolButton::menu-indicator {{ image: none; width: 0; }}

    QPushButton#PrimaryBtn {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3570C6, stop:1 #2859A3);
        border: 1px solid #3A76CC;
        border-top-color: #508CE0;
        border-bottom-color: #1B3F75;
        color: #FFFFFF;
        font-weight: bold;
    }}
    QPushButton#PrimaryBtn:hover {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3F7CD4, stop:1 #2F65B5);
        border-color: #4E8AE0;
        border-top-color: #669EEB;
    }}
    QPushButton#PrimaryBtn:pressed {{
        background-color: #234E8F;
        border-color: #2D5FA8;
    }}
    QPushButton#PrimaryBtn:disabled {{
        background-color: #1D2533;
        border-color: #283345;
        color: #657082;
    }}

    QPushButton#DangerBtn {{
        background-color: #23181B;
        border: 1px solid #572F34;
        border-top-color: #6B393F;
        color: #EB6C6C;
    }}
    QPushButton#DangerBtn:hover {{
        background-color: #2F1D21;
        border-color: #7D4148;
        color: #F48383;
    }}
    QPushButton#DangerBtn:disabled {{ background-color: transparent; border-color: {BORDER}; color: {TEXT_MUTED}; }}

    QPushButton#GhostBtn, QToolButton#GhostBtn {{
        background-color: transparent; border: 1px solid transparent; color: {TEXT_SECONDARY}; padding: 4px 9px;
    }}
    QPushButton#GhostBtn:hover, QToolButton#GhostBtn:hover {{
        background-color: #222730; border-color: #2F3642; color: {TEXT};
    }}
    QPushButton#GhostBtn:checked {{ background-color: {BG_HOVER}; border-color: #363E4C; color: {TEXT}; }}
    QPushButton#GhostBtn:disabled {{ color: {TEXT_MUTED}; background: transparent; border-color: transparent; }}

    QPushButton#LinkBtn {{ background: transparent; border: none; padding: 0; min-height: 0; color: {INFO}; }}
    QPushButton#LinkBtn:hover {{ color: #82B0F7; text-decoration: underline; }}

    /* Header adapter readout: matches SegBtn geometry (4px radius, recessed instrument frame) */
    QPushButton#Chip {{
        background-color: #171B21; border: 1px solid #2B313C; border-radius: 4px;
        padding: 3px 10px; min-height: 18px; color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 500;
    }}
    QPushButton#Chip:hover {{ background-color: #1F242D; border-color: #3C4454; color: {TEXT}; }}

    QPushButton#TabBtn {{
        background: transparent; border: none; border-bottom: 2px solid transparent; border-radius: 0;
        color: {TEXT_SECONDARY}; padding: 0 12px; min-height: 41px; font-weight: 600;
    }}
    QPushButton#TabBtn:hover {{ color: {TEXT}; }}
    QPushButton#TabBtn:checked {{ color: {TEXT}; border-bottom-color: {INFO}; background: transparent; }}
    QPushButton#TabBtn:disabled {{ color: {TEXT_MUTED}; }}

    QPushButton#SegBtn {{
        background-color: #171B21; border: 1px solid #2B313C; color: {TEXT_SECONDARY};
        border-radius: 0; padding: 3px 9px; min-height: 18px; font-size: 11px; font-weight: 600;
    }}
    QPushButton#SegBtn:hover {{ color: {TEXT}; background-color: #1E232B; }}
    QPushButton#SegBtn:checked {{
        background-color: #2A303C; border-color: #3F4758; color: {TEXT};
    }}
    QPushButton#SegBtn[pos="left"] {{ border-top-left-radius: 4px; border-bottom-left-radius: 4px; border-right: none; }}
    QPushButton#SegBtn[pos="right"] {{ border-top-right-radius: 4px; border-bottom-right-radius: 4px; }}

    /* ── Inputs ── */
    QLineEdit, QComboBox, QSpinBox {{
        background-color: {BG_INPUT}; color: {TEXT}; border: 1px solid #2E3542;
        border-radius: 5px; padding: 5px 9px; min-height: 21px; selection-background-color: {ACCENT};
    }}
    QLineEdit:hover, QComboBox:hover, QSpinBox:hover {{ border-color: #414A5C; }}
    QPlainTextEdit, QTextEdit {{
        background-color: {BG_INPUT}; color: {TEXT}; border: 1px solid #242A34;
        border-radius: 5px; padding: 6px; selection-background-color: {ACCENT};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
        border-color: {INFO};
    }}
    QLineEdit[tone="err"] {{ border-color: {ERR}; }}
    QLineEdit[drag="true"] {{ border: 1px dashed {INFO}; background-color: #17202E; }}
    QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{ color: {TEXT_MUTED}; border-color: {BORDER}; }}
    QComboBox::drop-down {{ border: none; width: 24px; }}
    QComboBox QAbstractItemView {{
        background-color: #1C2027; border: 1px solid {BORDER_STRONG}; border-radius: 5px; padding: 4px;
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
    QTabBar::tab:hover:!selected {{
        color: {TEXT}; background-color: #1D222A; border-top-left-radius: 4px; border-top-right-radius: 4px;
    }}
    QTabBar::tab:selected {{ color: {TEXT}; border-bottom-color: {INFO}; }}

    /* ── Progress ── */
    QProgressBar {{
        background-color: #242A34; border: none; border-radius: 2px; max-height: 4px; min-height: 4px;
    }}
    QProgressBar::chunk {{ background-color: {INFO}; border-radius: 2px; }}
    QProgressBar[tone="ok"]::chunk {{ background-color: {OK}; }}
    QProgressBar[tone="err"]::chunk {{ background-color: {ERR}; }}
    QProgressBar[tone="warn"]::chunk {{ background-color: {WARN}; }}

    /* ── Tables ── */
    QTableView {{
        background-color: {BG_INPUT}; alternate-background-color: #14181E; gridline-color: #1F242D;
        border: 1px solid {BORDER}; border-radius: 5px; color: {TEXT};
        selection-background-color: {BG_SELECTED}; selection-color: {TEXT};
    }}
    QTableView::item {{ padding: 2px 8px; }}
    QTableView QComboBox {{
        background-color: transparent; border: none; border-radius: 0; padding: 2px 8px; min-height: 24px;
    }}
    QTableView QComboBox:hover {{ background-color: #1C222B; }}
    QHeaderView::section {{
        background-color: #171B22; color: {TEXT_SECONDARY}; border: none;
        border-bottom: 1px solid {BORDER}; padding: 6px 8px; font-weight: 600;
    }}

    /* ── Scrollbars ── */
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
    QScrollBar::handle {{ background: #313845; border-radius: 3px; min-height: 24px; min-width: 24px; }}
    QScrollBar::handle:hover {{ background: #454E60; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    """
