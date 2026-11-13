"""Architectural carbon dark theme: explicit antialiased typography, neutral zinc surfaces, and clean QSS."""

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

# Neutral architectural carbon-zinc ramp (inspired by Linear, Raycast, Saleae Logic 2, Xcode Dark)
BG_INPUT = "#101114"     # recessed viewports: log console, CAN trace table, text/hex inputs, segmented tracks
BG_CHROME = "#131417"    # unified frame: menu bar, header bar, identity bar, navigation rail, status bar
BG_SIDEBAR = "#131417"
BG_WINDOW = "#17181C"    # main workbench canvas
BG_SECTION = "#1D1F24"   # single-surface cards & panels
BG_CONTROL = "#252830"   # tactile flat buttons & interactive controls
BG_HEADER = "#24272F"    # tooltips, table headers, subtle tags
BG_HOVER = "#2B2F39"
BG_SELECTED = "#242832"

BORDER_SUBTLE = "#23262D"
BORDER = "#292C34"
BORDER_STRONG = "#383D48"

# High-clarity typography ramp
TEXT = "#F1F3F5"
TEXT_SECONDARY = "#9CA2AE"
TEXT_MUTED = "#686E7A"

# Restrained, authoritative semantic accents
ACCENT = "#2F6FED"
ACCENT_HOVER = "#3E7BF6"
OK = "#34B27B"
WARN = "#E5A035"
ERR = "#E55C5C"
INFO = "#5B9BF8"
CAN = "#A188F7"

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
    """Platform UI sans-serif font with explicit antialiasing."""
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
                extra = 8 if name in ("SegBtn", "TabBtn") else 12
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
            painter.setPen(QPen(QColor(TEXT_SECONDARY), 1.4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawPolyline([QPointF(c.x() - 3.8, c.y() - 1.8), QPointF(c.x(), c.y() + 2.0), QPointF(c.x() + 3.8, c.y() - 1.8)])
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
        border = ACCENT_HOVER if on else ("#5E6575" if hover else "#3E4350")
        painter.setPen(QPen(QColor(border), 1.1))
        painter.setBrush(QColor(ACCENT if on else BG_INPUT))
        painter.drawRoundedRect(box, 4.0, 4.0)
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
        painter.setPen(QPen(QColor(ACCENT_HOVER if on else ("#5E6575" if hover else "#3E4350")), 1.1))
        painter.setBrush(QColor(ACCENT if on else BG_INPUT))
        painter.drawEllipse(box)
        if on:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#FFFFFF"))
            painter.drawEllipse(box.adjusted(side * 0.3, side * 0.3, -side * 0.3, -side * 0.3))
        painter.restore()


_STYLE: _Style | None = None


def apply_theme(app: QApplication) -> None:
    """Fusion style + neutral carbon palette + antialiased platform font + QSS."""
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
        QPalette.ColorRole.AlternateBase: "#15171B",
        QPalette.ColorRole.Text: TEXT,
        QPalette.ColorRole.Button: BG_CONTROL,
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
    """Minimalist geometric ECU die icon."""
    icon = QIcon()
    for sz in (32, 64, 128, 256):
        pix = QPixmap(sz, sz)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        m = sz * 0.06
        rect = QRectF(m, m, sz - 2 * m, sz - 2 * m)
        tile = QPainterPath()
        tile.addRoundedRect(rect, sz * 0.22, sz * 0.22)
        p.fillPath(tile, QColor("#1F2229"))
        p.setPen(QPen(QColor("#363B47"), max(1.0, sz * 0.03)))
        p.drawPath(tile)

        pen = QPen(QColor("#9CA2AE"), max(1.3, sz * 0.04))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        for frac in (0.37, 0.50, 0.63):
            pos = sz * frac
            p.drawLine(QPointF(pos, sz * 0.19), QPointF(pos, sz * 0.28))
            p.drawLine(QPointF(pos, sz * 0.72), QPointF(pos, sz * 0.81))
            p.drawLine(QPointF(sz * 0.19, pos), QPointF(sz * 0.28, pos))
            p.drawLine(QPointF(sz * 0.72, pos), QPointF(sz * 0.81, pos))

        core = QPainterPath()
        core.addRoundedRect(QRectF(sz * 0.30, sz * 0.30, sz * 0.40, sz * 0.40), sz * 0.06, sz * 0.06)
        p.fillPath(core, QColor("#131417"))
        p.setPen(QPen(QColor("#F1F3F5"), max(1.3, sz * 0.038)))
        p.drawPath(core)

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(ACCENT_HOVER))
        p.drawEllipse(QPointF(sz * 0.41, sz * 0.41), sz * 0.046, sz * 0.046)
        p.end()
        icon.addPixmap(pix)
    return icon


def dot_icon(color: str, size: int = 6) -> QIcon:
    """Small antialiased indicator (used sparingly for active hardware connection state)."""
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
        border-radius: 6px; padding: 5px 9px;
    }}
    QMenuBar {{
        background-color: {BG_CHROME}; color: {TEXT_SECONDARY};
        border-bottom: 1px solid #1E2026; padding: 2px 8px;
    }}
    QMenuBar::item {{ background: transparent; padding: 4px 10px; border-radius: 5px; }}
    QMenuBar::item:selected {{ background-color: {BG_CONTROL}; color: {TEXT}; }}
    QMenu {{
        background-color: {BG_SECTION}; border: 1px solid {BORDER_STRONG};
        border-radius: 8px; padding: 5px;
    }}
    QMenu::item {{ padding: 6px 24px 6px 12px; border-radius: 5px; color: {TEXT}; }}
    QMenu::item:selected {{ background-color: {ACCENT}; color: #FFFFFF; }}
    QMenu::item:disabled {{ color: {TEXT_MUTED}; }}
    QMenu::separator {{ height: 1px; background: {BORDER}; margin: 4px 6px; }}
    QStatusBar {{
        background-color: {BG_CHROME}; border-top: 1px solid #22252C; color: {TEXT_SECONDARY};
        min-height: 30px;
    }}
    QStatusBar::item {{ border: none; }}

    /* ── Application Chrome & Architectural Surfaces ── */
    QFrame#Header {{
        background-color: {BG_CHROME};
        border-bottom: 1px solid #22252C;
        min-height: 44px;
    }}
    QFrame#ModeTrack {{
        background-color: {BG_INPUT};
        border: 1px solid #22252C;
        border-radius: 7px;
    }}
    QFrame#IdentityBar {{
        background-color: {BG_CHROME};
        border-bottom: 1px solid #22252C;
    }}
    QFrame#NavPane {{
        background-color: {BG_SIDEBAR};
        border-right: 1px solid #22252C;
    }}
    QFrame#NavDumps {{
        background-color: transparent;
        border-top: 1px solid #1F2229;
    }}
    QWidget#DialogFooter {{
        background-color: {BG_CHROME};
        border-top: 1px solid {BORDER};
    }}

    /* ── Unified Single-Surface Cards & Inspector Tables ── */
    QFrame#Section, QFrame#Step, QFrame#RecentBox {{
        background-color: {BG_SECTION};
        border: 1px solid {BORDER};
        border-radius: 8px;
    }}
    QFrame#TableHead {{
        background-color: transparent;
        border-bottom: 1px solid {BORDER_SUBTLE};
    }}
    QFrame#TableRow {{
        background-color: transparent;
        border-bottom: 1px solid {BORDER_SUBTLE};
    }}
    QFrame#TableRow[last="true"] {{
        border-bottom: none;
    }}

    /* ── Pure Typographic Status Readout (Zero Pills, Zero Glowing Dots) ── */
    QLabel#StatusReadout {{
        background: transparent;
        border: none;
        padding: 0;
        font-size: 12px;
        font-weight: bold;
        color: {TEXT_MUTED};
    }}
    QLabel#StatusReadout[tone="ok"] {{ color: {OK}; }}
    QLabel#StatusReadout[tone="info"] {{ color: {INFO}; }}
    QLabel#StatusReadout[tone="warn"] {{ color: {WARN}; }}
    QLabel#StatusReadout[tone="err"] {{ color: {ERR}; }}

    /* ── Collapsible Console Drawer ── */
    QFrame#Console {{
        background-color: {BG_INPUT};
        border-top: 1px solid #24272F;
    }}
    QFrame#ConsoleHeader {{
        background-color: #15171C;
        border-bottom: 1px solid #20232A;
        min-height: 32px;
    }}
    QFrame#Console QTextEdit, QFrame#Console QPlainTextEdit {{
        background-color: {BG_INPUT};
        border: none;
        border-radius: 0;
        padding: 8px 18px;
    }}

    QFrame#Divider {{ background-color: {BORDER_SUBTLE}; max-height: 1px; min-height: 1px; border: none; }}
    QFrame#VDivider {{ background-color: #23262E; max-width: 1px; min-width: 1px; border: none; }}
    QFrame#WriteBar {{
        background-color: #181E2B;
        border-top: 1px solid #2B3B59;
    }}
    QLabel#StepNum {{
        background-color: #272B35; color: {TEXT_SECONDARY};
        border-radius: 5px; font-size: 11px; font-weight: bold;
    }}

    /* ── Calm Navigation Rail ── */
    QListWidget#Nav {{ background: transparent; border: none; outline: 0; }}
    QListWidget#Nav::item {{
        border-radius: 6px; margin: 1px 6px; border: none;
    }}
    QListWidget#Nav::item:selected {{
        background-color: {BG_SELECTED};
    }}
    QListWidget#Nav::item:hover:!selected {{
        background-color: #1A1C22;
    }}

    QListWidget#Adapters {{
        background-color: {BG_INPUT}; border: 1px solid {BORDER};
        border-radius: 7px; padding: 4px; outline: 0;
    }}
    QListWidget#Adapters::item {{ border-radius: 5px; margin: 1px; }}
    QListWidget#Adapters::item:selected {{ background-color: {BG_SELECTED}; }}
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
        background-color: #23262E;
    }}

    QScrollArea {{ background: transparent; border: none; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QWidget#PageCanvas {{ background-color: {BG_WINDOW}; }}
    QSplitter::handle {{ background-color: #22252C; }}

    QFrame#Callout {{
        border-radius: 6px;
        border: 1px solid #242A36;
        border-left: 3px solid {INFO};
        background-color: #181B22;
    }}
    QFrame#Callout[tone="ok"] {{
        border-color: #21342B;
        border-left: 3px solid {OK};
        background-color: #151E1A;
    }}
    QFrame#Callout[tone="warn"] {{
        border-color: #3D311E;
        border-left: 3px solid {WARN};
        background-color: #201B14;
    }}
    QFrame#Callout[tone="err"] {{
        border-color: #422428;
        border-left: 3px solid {ERR};
        background-color: #221618;
    }}
    QFrame#Callout QLabel {{ color: #D2D7E0; font-size: 12px; }}
    QFrame#Callout QLabel#FieldLabel {{ color: {TEXT}; font-size: 13px; }}

    /* ── Typography ── */
    QLabel {{ background: transparent; }}
    QLabel#AppName {{ font-size: 13px; font-weight: bold; color: {TEXT}; }}
    QLabel#PageTitle {{ font-size: 20px; font-weight: bold; color: {TEXT}; }}
    QLabel#PartNumber {{ font-size: 20px; font-weight: bold; color: {TEXT}; }}
    QLabel#SectionTitle {{ font-size: 14px; font-weight: bold; color: {TEXT}; }}
    QLabel#GroupLabel {{ font-size: 10px; font-weight: bold; color: {TEXT_MUTED}; letter-spacing: 0.4px; }}
    QLabel#Eyebrow {{ font-size: 11px; font-weight: bold; color: {TEXT_MUTED}; }}
    QLabel#FieldLabel {{ font-weight: bold; color: {TEXT}; }}
    QLabel#Hint {{ color: {TEXT_SECONDARY}; }}
    QLabel[tone="ok"], QLabel#Hint[tone="ok"], QLabel#FieldLabel[tone="ok"] {{ color: {OK}; }}
    QLabel[tone="warn"], QLabel#Hint[tone="warn"], QLabel#FieldLabel[tone="warn"] {{ color: {WARN}; }}
    QLabel[tone="err"], QLabel#Hint[tone="err"], QLabel#FieldLabel[tone="err"] {{ color: {ERR}; }}
    QLabel[tone="info"], QLabel#Hint[tone="info"], QLabel#FieldLabel[tone="info"] {{ color: {INFO}; }}
    QLabel[tone="muted"], QLabel#Hint[tone="muted"] {{ color: {TEXT_MUTED}; }}
    QLabel#FieldLabel[tone="muted"] {{ color: {TEXT_MUTED}; font-weight: normal; }}

    QLabel#Pill {{
        background-color: transparent; border: none; padding: 0;
        font-size: 12px; color: {TEXT_MUTED};
    }}
    QLabel#Pill[tone="ok"] {{ color: {OK}; }}
    QLabel#Pill[tone="warn"] {{ color: {WARN}; }}
    QLabel#Pill[tone="err"] {{ color: {ERR}; }}
    QLabel#Pill[tone="info"] {{ color: {INFO}; }}
    /* In the sidebar, normal/stock ("ok") stays calm muted so only active changes or warnings draw the eye */
    QListWidget#Nav QLabel#Pill {{ font-size: 11px; color: {TEXT_MUTED}; }}
    QListWidget#Nav QLabel#Pill[tone="ok"] {{ color: {TEXT_MUTED}; }}
    QListWidget#Nav QLabel#Pill[tone="info"] {{ color: #6EA5FA; }}
    QListWidget#Nav QLabel#Pill[tone="warn"] {{ color: {WARN}; }}
    QListWidget#Nav QLabel#Pill[tone="err"] {{ color: {ERR}; }}

    /* ── Clean Flat-Tactile Controls & Buttons ── */
    QPushButton, QToolButton {{
        background-color: {BG_CONTROL};
        color: {TEXT};
        border: 1px solid #333742;
        border-radius: 6px;
        padding: 5px 13px;
        min-height: 20px;
    }}
    QPushButton:hover, QToolButton:hover {{
        background-color: {BG_HOVER};
        border-color: #424756;
    }}
    QPushButton:pressed, QToolButton:pressed {{
        background-color: #1E2128;
        border-color: #333742;
    }}
    QPushButton:disabled, QToolButton:disabled {{
        background-color: #191B20;
        color: {TEXT_MUTED};
        border-color: #24272F;
    }}
    QPushButton:focus, QToolButton:focus {{ outline: none; }}
    QPushButton:checked {{
        background-color: #2E333E; border-color: #484E5E; color: #FFFFFF;
    }}
    QToolButton::menu-indicator {{ image: none; width: 0; }}

    QPushButton#PrimaryBtn {{
        background-color: {ACCENT};
        border: 1px solid #3D7BF4;
        color: #FFFFFF;
        font-weight: bold;
    }}
    QPushButton#PrimaryBtn:hover {{
        background-color: {ACCENT_HOVER};
        border-color: #548BF7;
    }}
    QPushButton#PrimaryBtn:pressed {{
        background-color: #255ED4;
        border-color: #326BE0;
    }}
    QPushButton#PrimaryBtn:disabled {{
        background-color: #1D2536;
        border-color: #27324A;
        color: #63708A;
    }}

    QPushButton#DangerBtn {{
        background-color: #29191C;
        border: 1px solid #592B31;
        color: #F07575;
    }}
    QPushButton#DangerBtn:hover {{
        background-color: #341E22;
        border-color: #75373F;
        color: #F78B8B;
    }}
    QPushButton#DangerBtn:disabled {{ background-color: transparent; border-color: {BORDER}; color: {TEXT_MUTED}; }}

    QPushButton#GhostBtn, QToolButton#GhostBtn {{
        background-color: transparent; border: 1px solid transparent; color: {TEXT_SECONDARY}; padding: 4px 10px;
    }}
    QPushButton#GhostBtn:hover, QToolButton#GhostBtn:hover {{
        background-color: #20232B; border-color: #2D313C; color: {TEXT};
    }}
    QPushButton#GhostBtn:checked {{
        background-color: #22262F; border-color: #343946; color: {TEXT};
    }}
    QPushButton#GhostBtn:disabled {{ color: {TEXT_MUTED}; background: transparent; border-color: transparent; }}

    QPushButton#LinkBtn {{ background: transparent; border: none; padding: 0; min-height: 0; color: {INFO}; }}
    QPushButton#LinkBtn:hover {{ color: #82B4FA; text-decoration: underline; }}

    QPushButton#Chip {{
        background-color: #1A1C22; border: 1px solid #2A2E38; border-radius: 6px;
        padding: 4px 11px; min-height: 18px; color: {TEXT_SECONDARY}; font-size: 12px;
    }}
    QPushButton#Chip:hover {{ background-color: #22252D; border-color: #3A3F4D; color: {TEXT}; }}

    QPushButton#TabBtn {{
        background: transparent; border: 1px solid transparent; border-radius: 5px;
        color: {TEXT_SECONDARY}; padding: 3px 12px; min-height: 20px; font-size: 12px; font-weight: bold;
    }}
    QPushButton#TabBtn:hover:!checked {{ color: {TEXT}; }}
    QPushButton#TabBtn:checked {{
        color: {TEXT}; background-color: #252831; border-color: #343844;
    }}
    QPushButton#TabBtn:disabled {{ color: {TEXT_MUTED}; }}

    QPushButton#SegBtn {{
        background-color: {BG_INPUT}; border: 1px solid #282B34; color: {TEXT_SECONDARY};
        border-radius: 0; padding: 2px 9px; min-height: 18px; font-size: 11px; font-weight: bold;
    }}
    QPushButton#SegBtn:hover:!checked {{ color: {TEXT}; background-color: #1B1D23; }}
    QPushButton#SegBtn:checked {{
        background-color: #262A33; border-color: #3A3F4D; color: {TEXT};
    }}
    QPushButton#SegBtn[pos="left"] {{ border-top-left-radius: 5px; border-bottom-left-radius: 5px; border-right: none; }}
    QPushButton#SegBtn[pos="right"] {{ border-top-right-radius: 5px; border-bottom-right-radius: 5px; }}

    /* ── Inputs ── */
    QLineEdit, QComboBox, QSpinBox {{
        background-color: {BG_INPUT}; color: {TEXT}; border: 1px solid #2C303A;
        border-radius: 6px; padding: 5px 10px; min-height: 21px; selection-background-color: {ACCENT};
    }}
    QLineEdit:hover, QComboBox:hover, QSpinBox:hover {{ border-color: #3D4250; }}
    QPlainTextEdit, QTextEdit {{
        background-color: {BG_INPUT}; color: {TEXT}; border: 1px solid #282B34;
        border-radius: 6px; padding: 7px; selection-background-color: {ACCENT};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
        border-color: {ACCENT_HOVER};
    }}
    QLineEdit[tone="err"] {{ border-color: {ERR}; }}
    QLineEdit[drag="true"] {{ border: 1px dashed {ACCENT_HOVER}; background-color: #161E2E; }}
    QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{ color: {TEXT_MUTED}; border-color: {BORDER_SUBTLE}; }}
    QComboBox::drop-down {{ border: none; width: 24px; }}
    QComboBox QAbstractItemView {{
        background-color: {BG_SECTION}; border: 1px solid {BORDER_STRONG}; border-radius: 7px; padding: 4px;
        selection-background-color: {ACCENT}; selection-color: #FFFFFF; outline: 0;
    }}
    QComboBox QAbstractItemView::item {{ min-height: 24px; padding: 3px 8px; border-radius: 4px; }}
    QCheckBox, QRadioButton {{ spacing: 8px; color: {TEXT}; background: transparent; min-height: 20px; }}
    QCheckBox:disabled, QRadioButton:disabled {{ color: {TEXT_MUTED}; }}

    /* ── Tabs ── */
    QTabWidget::pane {{
        border: 1px solid {BORDER}; border-radius: 8px; background-color: {BG_WINDOW}; top: -1px;
    }}
    QTabBar::tab {{
        background-color: transparent; color: {TEXT_SECONDARY}; border: 1px solid transparent;
        border-bottom: 2px solid transparent; padding: 7px 14px; min-height: 20px; font-weight: bold;
        margin-right: 2px;
    }}
    QTabBar::tab:hover:!selected {{
        color: {TEXT}; background-color: {BG_SECTION}; border-top-left-radius: 5px; border-top-right-radius: 5px;
    }}
    QTabBar::tab:selected {{ color: {TEXT}; border-bottom-color: {ACCENT_HOVER}; }}

    /* ── Progress ── */
    QProgressBar {{
        background-color: #252830; border: none; border-radius: 2px; max-height: 4px; min-height: 4px;
    }}
    QProgressBar::chunk {{ background-color: {ACCENT_HOVER}; border-radius: 2px; }}
    QProgressBar[tone="ok"]::chunk {{ background-color: {OK}; }}
    QProgressBar[tone="err"]::chunk {{ background-color: {ERR}; }}
    QProgressBar[tone="warn"]::chunk {{ background-color: {WARN}; }}

    /* ── Tables ── */
    QTableView {{
        background-color: {BG_INPUT}; alternate-background-color: #14161A; gridline-color: #20232A;
        border: 1px solid {BORDER}; border-radius: 6px; color: {TEXT};
        selection-background-color: {BG_SELECTED}; selection-color: {TEXT};
    }}
    QTableView::item {{ padding: 2px 8px; }}
    QTableView QComboBox {{
        background-color: transparent; border: none; border-radius: 0; padding: 2px 8px; min-height: 24px;
    }}
    QTableView QComboBox:hover {{ background-color: #1F2229; }}
    QHeaderView::section {{
        background-color: #16181D; color: {TEXT_MUTED}; border: none;
        border-bottom: 1px solid {BORDER}; padding: 6px 8px; font-size: 11px; font-weight: bold;
    }}

    /* ── Scrollbars ── */
    QScrollBar:vertical {{ background: transparent; width: 9px; margin: 2px; }}
    QScrollBar:horizontal {{ background: transparent; height: 9px; margin: 2px; }}
    QScrollBar::handle {{ background: #2E323D; border-radius: 4px; min-height: 24px; min-width: 24px; }}
    QScrollBar::handle:hover {{ background: #404654; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    """
