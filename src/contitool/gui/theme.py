"""Precision engineering dark theme: explicit antialiased fonts, balanced slate-graphite surfaces, and QSS."""

from __future__ import annotations

import sys

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

# Balanced engineering slate-graphite surfaces (L = 11%..21%: comfortable for long bench sessions, zero pitch-black glare)
BG_INPUT = "#181B22"     # recessed viewports: log body, CAN trace table, hex/text inputs
BG_CHROME = "#1B1E25"    # menu bar & status bar
BG_SIDEBAR = "#1E222A"   # top mode bar, left navigation rail, dialog footers
BG_WINDOW = "#22262F"    # main workbench canvas
BG_SECTION = "#282D37"   # elevated module blocks & cards
BG_HEADER = "#2E3440"    # structured header band inside blocks & inspector tables
BG_HOVER = "#343B48"
BG_SELECTED = "#2E3A4F"

BORDER_SUBTLE = "#313846"
BORDER = "#384050"
BORDER_STRONG = "#4A5468"

# Soft high-clarity engineering typography (avoids harsh #FFFFFF halation)
TEXT = "#E6E9EF"
TEXT_SECONDARY = "#A2AAB9"
TEXT_MUTED = "#727B8C"

# Calibrated engineering accents (inspired by JetBrains Islands / Saleae / Linear)
ACCENT = "#3574F0"
ACCENT_HOVER = "#4682F6"
OK = "#3FB984"
WARN = "#E5A93C"
ERR = "#E56464"
INFO = "#5C9CF5"
CAN = "#A68AF9"

TONES = {"ok": OK, "warn": WARN, "err": ERR, "info": INFO, "muted": TEXT_MUTED}

_UI_FAMILY: str | None = None
_MONO_FAMILY: str | None = None

_UI_CANDIDATES: tuple[str, ...] = (
    ("SF Pro Text", ".AppleSystemUIFont", "Helvetica Neue", "Arial")
    if sys.platform == "darwin"
    else ("Segoe UI Variable Text", "Segoe UI", "Inter", "Arial")
    if sys.platform == "win32"
    else ("Inter", "Noto Sans", "Ubuntu", "Cantarell", "DejaVu Sans")
)

_MONO_CANDIDATES: tuple[str, ...] = (
    ("SF Mono", "JetBrains Mono", "Menlo", "Monaco")
    if sys.platform == "darwin"
    else ("Cascadia Mono", "JetBrains Mono", "Consolas")
    if sys.platform == "win32"
    else ("JetBrains Mono", "Noto Sans Mono", "Ubuntu Mono", "DejaVu Sans Mono")
)


def _configure_smoothing(font: QFont) -> QFont:
    """Enable high-quality grayscale/subpixel antialiasing and platform-appropriate hinting."""
    font.setStyleStrategy(
        QFont.StyleStrategy.PreferAntialias | QFont.StyleStrategy.PreferQuality
    )
    if sys.platform == "darwin":
        font.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    elif sys.platform == "win32":
        font.setHintingPreference(QFont.HintingPreference.PreferVerticalHinting)
    else:
        font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
    return font


def ui_font(px: int = 13, bold: bool = False) -> QFont:
    """Platform UI sans-serif font with explicit antialiasing (never falls back to missing 'Sans Serif')."""
    global _UI_FAMILY
    if _UI_FAMILY is None:
        available = set(QFontDatabase.families())
        _UI_FAMILY = next(
            (c for c in _UI_CANDIDATES if c in available),
            QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont).family(),
        )
    f = QFont(_UI_FAMILY)
    f.setPixelSize(px)
    if bold:
        f.setWeight(QFont.Weight.DemiBold)
    return _configure_smoothing(f)


def mono_font(px: int = 12, bold: bool = False) -> QFont:
    """Tabular engineering monospace font with explicit antialiasing."""
    global _MONO_FAMILY
    if _MONO_FAMILY is None:
        available = set(QFontDatabase.families())
        _MONO_FAMILY = next(
            (c for c in _MONO_CANDIDATES if c in available),
            QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont).family(),
        )
    f = QFont(_MONO_FAMILY)
    f.setPixelSize(px)
    if bold:
        f.setWeight(QFont.Weight.DemiBold)
    return _configure_smoothing(f)


def set_tone(widget: QWidget, tone: str) -> None:
    """Switch a widget's semantic `tone` property (ok / warn / err / info / muted) and repaint."""
    if widget.property("tone") == tone:
        return
    widget.setProperty("tone", tone)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


class _Style(QProxyStyle):
    """Fusion with crisp antialiased vector check/radio/combo indicators and non-eliding button sizing."""

    _CHECKS = (
        QStyle.PrimitiveElement.PE_IndicatorCheckBox,
        QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck,
    )

    def sizeFromContents(self, ct, option, size, widget=None) -> QSize:  # noqa: ANN001, N802 (Qt override)
        sz = super().sizeFromContents(ct, option, size, widget)
        if ct == QStyle.ContentsType.CT_PushButton and widget is not None:
            name = widget.objectName()
            if name != "LinkBtn":
                extra = 6 if name in ("SegBtn", "TabBtn") else 12
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
        border = ACCENT_HOVER if on else ("#7A8499" if hover else "#545D70")
        painter.setPen(QPen(QColor(border), 1.1))
        painter.setBrush(QColor(ACCENT if on else BG_INPUT))
        painter.drawRoundedRect(box, 3.5, 3.5)
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
        painter.setPen(QPen(QColor(ACCENT_HOVER if on else ("#7A8499" if hover else "#545D70")), 1.1))
        painter.setBrush(QColor(ACCENT if on else BG_INPUT))
        painter.drawEllipse(box)
        if on:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#FFFFFF"))
            painter.drawEllipse(box.adjusted(side * 0.3, side * 0.3, -side * 0.3, -side * 0.3))
        painter.restore()


_STYLE: _Style | None = None


def apply_theme(app: QApplication) -> None:
    """Fusion style + balanced engineering slate-graphite palette + antialiased font + QSS."""
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
        QPalette.ColorRole.ToolTipBase: BG_HEADER,
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
    app.setFont(ui_font(13))
    app.setStyleSheet(build_stylesheet())


def build_app_icon() -> QIcon:
    """Precision QFP microcontroller mark with cerulean pin-1 dot."""
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
        p.fillPath(tile, QColor("#2A303C"))
        p.setPen(QPen(QColor("#465064"), max(1.0, sz * 0.03)))
        p.drawPath(tile)

        pen = QPen(QColor("#D5DCE8"), max(1.4, sz * 0.042))
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
        p.fillPath(core, QColor("#1B1F27"))
        p.setPen(QPen(QColor("#E6E9EF"), max(1.3, sz * 0.038)))
        p.drawPath(core)

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(INFO))
        p.drawEllipse(QPointF(sz * 0.41, sz * 0.41), sz * 0.048, sz * 0.048)
        p.end()
        icon.addPixmap(pix)
    return icon


def dot_icon(color: str, size: int = 7) -> QIcon:
    """Crisp antialiased status LED."""
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
        background-color: {BG_HEADER}; color: {TEXT}; border: 1px solid {BORDER_STRONG};
        border-radius: 5px; padding: 5px 9px;
    }}
    QMenuBar {{
        background-color: {BG_CHROME}; color: {TEXT_SECONDARY};
        border-bottom: 1px solid #282D37; padding: 2px 8px;
    }}
    QMenuBar::item {{ background: transparent; padding: 4px 10px; border-radius: 4px; }}
    QMenuBar::item:selected {{ background-color: {BG_HOVER}; color: {TEXT}; }}
    QMenu {{
        background-color: {BG_SECTION}; border: 1px solid {BORDER_STRONG};
        border-radius: 6px; padding: 4px;
    }}
    QMenu::item {{ padding: 5px 24px 5px 12px; border-radius: 4px; color: {TEXT}; }}
    QMenu::item:selected {{ background-color: {ACCENT}; color: #FFFFFF; }}
    QMenu::item:disabled {{ color: {TEXT_MUTED}; }}
    QMenu::separator {{ height: 1px; background: {BORDER}; margin: 4px 6px; }}
    QStatusBar {{
        background-color: {BG_CHROME}; border-top: 1px solid #2A2F3A; color: {TEXT_SECONDARY};
    }}
    QStatusBar::item {{ border: none; }}

    /* ── Engineering Workbench Architecture ── */
    QFrame#Header {{
        background-color: {BG_SIDEBAR};
        border-bottom: 1px solid {BORDER};
        min-height: 42px;
    }}
    QFrame#IdentityBar {{
        background-color: #252A34;
        border-bottom: 1px solid {BORDER};
    }}
    QFrame#TelemetryStrip {{
        background-color: #1B1F27;
        border: 1px solid #303746;
        border-radius: 5px;
    }}
    QFrame#BankCell {{
        background-color: #222731;
        border: 1px solid #333B4B;
        border-radius: 3px;
    }}
    QFrame#BankCell[tone="ok"] {{
        border-left: 2px solid {OK};
    }}
    QFrame#BankCell[tone="warn"] {{
        border-left: 2px solid {WARN};
        background-color: #28231D;
    }}
    QFrame#NavPane {{
        background-color: {BG_SIDEBAR};
        border-right: 1px solid {BORDER};
    }}
    QWidget#DialogFooter {{
        background-color: {BG_SIDEBAR};
        border-top: 1px solid {BORDER};
    }}

    /* Structured 2-tone Engineering Panels & Module Blocks */
    QFrame#Section, QFrame#Step, QFrame#RecentBox {{
        background-color: {BG_SECTION};
        border: 1px solid {BORDER};
        border-radius: 6px;
    }}
    QFrame#BlockHeader {{
        background-color: {BG_HEADER};
        border-bottom: 1px solid {BORDER};
        border-top-left-radius: 5px;
        border-top-right-radius: 5px;
    }}
    QFrame#BlockFooter {{
        background-color: #232832;
        border-top: 1px solid {BORDER_SUBTLE};
        border-bottom-left-radius: 5px;
        border-bottom-right-radius: 5px;
    }}
    QFrame#DropHint {{
        background-color: #1E222B;
        border: 1px dashed #3B4455;
        border-radius: 6px;
    }}

    /* Inspector Data Rows */
    QFrame#TableRow {{
        background-color: transparent;
        border-bottom: 1px solid {BORDER_SUBTLE};
    }}
    QFrame#TableRow[alt="true"] {{
        background-color: #252A34;
    }}
    QFrame#TableRow[last="true"] {{
        border-bottom: none;
        border-bottom-left-radius: 5px;
        border-bottom-right-radius: 5px;
    }}

    /* IDE Tool-Window Console Dock */
    QFrame#Console {{
        background-color: {BG_INPUT};
        border-top: 1px solid {BORDER};
    }}
    QFrame#ConsoleHeader {{
        background-color: #242933;
        border-bottom: 1px solid {BORDER_SUBTLE};
        min-height: 32px;
    }}
    QFrame#Console QTextEdit, QFrame#Console QPlainTextEdit {{
        background-color: {BG_INPUT};
        border: none;
        border-radius: 0;
        padding: 6px 16px;
    }}

    QFrame#Divider {{ background-color: {BORDER_SUBTLE}; max-height: 1px; min-height: 1px; border: none; }}
    QFrame#VDivider {{ background-color: #2D3340; max-width: 1px; min-width: 1px; border: none; }}
    QFrame#WriteBar {{
        background-color: #212A3A;
        border-top: 1px solid #354866;
        border-left: 3px solid {ACCENT};
    }}
    QLabel#StepNum {{
        background-color: #363E4D; color: {TEXT};
        border-radius: 4px; font-size: 11px; font-weight: bold;
    }}

    /* Navigation Rail */
    QListWidget#Nav {{ background: transparent; border: none; outline: 0; }}
    QListWidget#Nav::item {{
        border-radius: 5px; margin: 1px 4px; border-left: 2px solid transparent;
    }}
    QListWidget#Nav::item:selected {{
        background-color: {BG_SELECTED};
        border-left: 2px solid {ACCENT_HOVER};
    }}
    QListWidget#Nav::item:hover:!selected {{
        background-color: #262B34;
    }}

    QListWidget#Adapters {{
        background-color: {BG_INPUT}; border: 1px solid {BORDER};
        border-radius: 5px; padding: 3px; outline: 0;
    }}
    QListWidget#Adapters::item {{ border-radius: 4px; margin: 1px; }}
    QListWidget#Adapters::item:selected {{ background-color: {BG_SELECTED}; border-left: 2px solid {ACCENT_HOVER}; }}
    QListWidget#Adapters::item:hover:!selected {{ background-color: {BG_HOVER}; }}
    QLabel#AdapterTitle {{ color: {TEXT}; font-weight: bold; }}
    QLabel#AdapterTitle[tone="muted"] {{ color: {TEXT_MUTED}; }}

    QFrame#ListRow {{
        background-color: transparent;
        border-bottom: 1px solid {BORDER_SUBTLE};
    }}
    QFrame#ListRow[last="true"] {{
        border-bottom: none;
    }}
    QFrame#ListRow:hover {{
        background-color: {BG_HOVER};
    }}

    QScrollArea {{ background: transparent; border: none; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QWidget#PageCanvas {{ background-color: {BG_WINDOW}; }}
    QSplitter::handle {{ background-color: {BORDER}; }}

    QFrame#Callout {{
        border-radius: 5px; border: 1px solid #323E52; border-left: 3px solid {INFO};
        background-color: #202734;
    }}
    QFrame#Callout[tone="ok"] {{
        border-color: #2C443A; border-left-color: {OK}; background-color: #1E2B26;
    }}
    QFrame#Callout[tone="warn"] {{
        border-color: #4A3D29; border-left-color: {WARN}; background-color: #29241D;
    }}
    QFrame#Callout[tone="err"] {{
        border-color: #4F3034; border-left-color: {ERR}; background-color: #2B1F22;
    }}

    /* ── Typography & Telemetry Readouts ── */
    QLabel {{ background: transparent; }}
    QLabel#AppName {{ font-size: 13px; font-weight: bold; color: {TEXT}; }}
    QLabel#PageTitle {{ font-size: 18px; font-weight: bold; color: {TEXT}; }}
    QLabel#PartNumber {{ font-size: 19px; font-weight: bold; color: {TEXT}; letter-spacing: 0.3px; }}
    QLabel#SectionTitle {{ font-size: 13px; font-weight: bold; color: {TEXT}; }}
    QLabel#GroupLabel {{ font-size: 10px; font-weight: bold; color: {TEXT_MUTED}; letter-spacing: 0.6px; }}
    QLabel#FieldLabel {{ font-weight: bold; color: {TEXT}; }}
    QLabel#Hint {{ color: {TEXT_SECONDARY}; }}
    QLabel[tone="ok"], QLabel#Hint[tone="ok"] {{ color: {OK}; }}
    QLabel[tone="warn"], QLabel#Hint[tone="warn"] {{ color: {WARN}; }}
    QLabel[tone="err"], QLabel#Hint[tone="err"] {{ color: {ERR}; }}
    QLabel[tone="info"], QLabel#Hint[tone="info"] {{ color: {INFO}; }}
    QLabel[tone="muted"], QLabel#Hint[tone="muted"] {{ color: {TEXT_MUTED}; }}

    QLabel#Pill {{
        background-color: transparent; border: none; padding: 0;
        font-size: 12px; color: {TEXT_MUTED};
    }}
    QLabel#Pill[tone="ok"] {{ color: {OK}; }}
    QLabel#Pill[tone="warn"] {{ color: {WARN}; }}
    QLabel#Pill[tone="err"] {{ color: {ERR}; }}
    QLabel#Pill[tone="info"] {{ color: {INFO}; }}
    QListWidget#Nav QLabel#Pill {{ font-size: 11px; }}

    /* ── Tactile Engineering Controls & Buttons ── */
    QPushButton, QToolButton {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #353B48, stop:1 #2D323E);
        color: {TEXT};
        border: 1px solid #434B5C;
        border-top-color: #50596D;
        border-bottom-color: #232730;
        border-radius: 5px;
        padding: 5px 13px;
        min-height: 20px;
    }}
    QPushButton:hover, QToolButton:hover {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3E4554, stop:1 #343A47);
        border-color: #566075;
        border-top-color: #657089;
    }}
    QPushButton:pressed, QToolButton:pressed {{
        background-color: #262B35;
        border-color: #3B4252;
    }}
    QPushButton:disabled, QToolButton:disabled {{
        background-color: #22262E;
        color: {TEXT_MUTED};
        border-color: #2E3440;
    }}
    QPushButton:focus, QToolButton:focus {{ outline: none; }}
    QPushButton:checked {{
        background-color: #384050; border-color: #59657D; color: #FFFFFF;
    }}
    QToolButton::menu-indicator {{ image: none; width: 0; }}

    QPushButton#PrimaryBtn {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3E7BF2, stop:1 #2E67DC);
        border: 1px solid #4582F5;
        border-top-color: #6298FA;
        border-bottom-color: #214CA8;
        color: #FFFFFF;
        font-weight: bold;
    }}
    QPushButton#PrimaryBtn:hover {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4C87F7, stop:1 #3872E8);
        border-color: #5B93FA;
        border-top-color: #78A8FC;
    }}
    QPushButton#PrimaryBtn:pressed {{
        background-color: #2859C2;
        border-color: #3568D4;
    }}
    QPushButton#PrimaryBtn:disabled {{
        background-color: #252E3F;
        border-color: #313D54;
        color: #6E7B94;
    }}

    QPushButton#DangerBtn {{
        background-color: #312125;
        border: 1px solid #6B3A40;
        border-top-color: #80464D;
        color: #F07575;
    }}
    QPushButton#DangerBtn:hover {{
        background-color: #3D262B;
        border-color: #8C4A52;
        color: #F78B8B;
    }}
    QPushButton#DangerBtn:disabled {{ background-color: transparent; border-color: {BORDER}; color: {TEXT_MUTED}; }}

    QPushButton#GhostBtn, QToolButton#GhostBtn {{
        background-color: transparent; border: 1px solid transparent; color: {TEXT_SECONDARY}; padding: 4px 9px;
    }}
    QPushButton#GhostBtn:hover, QToolButton#GhostBtn:hover {{
        background-color: {BG_HOVER}; border-color: #3E4656; color: {TEXT};
    }}
    QPushButton#GhostBtn:checked {{ background-color: {BG_HOVER}; border-color: #485266; color: {TEXT}; }}
    QPushButton#GhostBtn:disabled {{ color: {TEXT_MUTED}; background: transparent; border-color: transparent; }}

    QPushButton#LinkBtn {{ background: transparent; border: none; padding: 0; min-height: 0; color: {INFO}; }}
    QPushButton#LinkBtn:hover {{ color: #82B4FA; text-decoration: underline; }}

    QPushButton#Chip {{
        background-color: #1A1E25; border: 1px solid #323946; border-radius: 4px;
        padding: 3px 10px; min-height: 18px; color: {TEXT_SECONDARY}; font-size: 12px;
    }}
    QPushButton#Chip:hover {{ background-color: #252A34; border-color: #465063; color: {TEXT}; }}

    QPushButton#TabBtn {{
        background: transparent; border: none; border-bottom: 2px solid transparent; border-radius: 0;
        color: {TEXT_SECONDARY}; padding: 0 12px; min-height: 41px; font-weight: bold;
    }}
    QPushButton#TabBtn:hover {{ color: {TEXT}; }}
    QPushButton#TabBtn:checked {{ color: {TEXT}; border-bottom-color: {ACCENT_HOVER}; background: transparent; }}
    QPushButton#TabBtn:disabled {{ color: {TEXT_MUTED}; }}

    QPushButton#SegBtn {{
        background-color: #1A1E25; border: 1px solid #323946; color: {TEXT_SECONDARY};
        border-radius: 0; padding: 2px 9px; min-height: 18px; font-size: 11px; font-weight: bold;
    }}
    QPushButton#SegBtn:hover {{ color: {TEXT}; background-color: #252A34; }}
    QPushButton#SegBtn:checked {{
        background-color: #343B49; border-color: #4B5569; color: {TEXT};
    }}
    QPushButton#SegBtn[pos="left"] {{ border-top-left-radius: 4px; border-bottom-left-radius: 4px; border-right: none; }}
    QPushButton#SegBtn[pos="right"] {{ border-top-right-radius: 4px; border-bottom-right-radius: 4px; }}

    /* ── Inputs ── */
    QLineEdit, QComboBox, QSpinBox {{
        background-color: {BG_INPUT}; color: {TEXT}; border: 1px solid #373F4E;
        border-radius: 5px; padding: 5px 9px; min-height: 21px; selection-background-color: {ACCENT};
    }}
    QLineEdit:hover, QComboBox:hover, QSpinBox:hover {{ border-color: #4B5569; }}
    QPlainTextEdit, QTextEdit {{
        background-color: {BG_INPUT}; color: {TEXT}; border: 1px solid #323946;
        border-radius: 5px; padding: 6px; selection-background-color: {ACCENT};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
        border-color: {ACCENT_HOVER};
    }}
    QLineEdit[tone="err"] {{ border-color: {ERR}; }}
    QLineEdit[drag="true"] {{ border: 1px dashed {ACCENT_HOVER}; background-color: #1E2738; }}
    QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{ color: {TEXT_MUTED}; border-color: {BORDER_SUBTLE}; }}
    QComboBox::drop-down {{ border: none; width: 24px; }}
    QComboBox QAbstractItemView {{
        background-color: {BG_SECTION}; border: 1px solid {BORDER_STRONG}; border-radius: 5px; padding: 4px;
        selection-background-color: {ACCENT}; selection-color: #FFFFFF; outline: 0;
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
        border-bottom: 2px solid transparent; padding: 7px 14px; min-height: 20px; font-weight: bold;
        margin-right: 2px;
    }}
    QTabBar::tab:hover:!selected {{
        color: {TEXT}; background-color: {BG_SECTION}; border-top-left-radius: 4px; border-top-right-radius: 4px;
    }}
    QTabBar::tab:selected {{ color: {TEXT}; border-bottom-color: {ACCENT_HOVER}; }}

    /* ── Progress ── */
    QProgressBar {{
        background-color: #2E3440; border: none; border-radius: 2px; max-height: 5px; min-height: 5px;
    }}
    QProgressBar::chunk {{ background-color: {ACCENT_HOVER}; border-radius: 2px; }}
    QProgressBar[tone="ok"]::chunk {{ background-color: {OK}; }}
    QProgressBar[tone="err"]::chunk {{ background-color: {ERR}; }}
    QProgressBar[tone="warn"]::chunk {{ background-color: {WARN}; }}

    /* ── Tables ── */
    QTableView {{
        background-color: {BG_INPUT}; alternate-background-color: #1D2128; gridline-color: #292F3B;
        border: 1px solid {BORDER}; border-radius: 5px; color: {TEXT};
        selection-background-color: {BG_SELECTED}; selection-color: {TEXT};
    }}
    QTableView::item {{ padding: 2px 8px; }}
    QTableView QComboBox {{
        background-color: transparent; border: none; border-radius: 0; padding: 2px 8px; min-height: 24px;
    }}
    QTableView QComboBox:hover {{ background-color: #262C37; }}
    QHeaderView::section {{
        background-color: #232832; color: {TEXT_SECONDARY}; border: none;
        border-bottom: 1px solid {BORDER}; padding: 6px 8px; font-weight: bold;
    }}

    /* ── Scrollbars ── */
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
    QScrollBar::handle {{ background: #3E4656; border-radius: 4px; min-height: 24px; min-width: 24px; }}
    QScrollBar::handle:hover {{ background: #525C70; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    """
