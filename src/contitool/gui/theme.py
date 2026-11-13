"""Obsidian-cobalt automotive studio theme: palette tokens, QSS, vector icons, monospace font, and tone helpers."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontDatabase,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import QApplication, QComboBox, QProxyStyle, QStyle, QStyleFactory, QWidget

# Layered surfaces (deep obsidian -> slate canvas -> elevated card -> interactive hover)
BG_WINDOW = "#0E121A"
BG_SIDEBAR = "#090C12"  # header, menu & status bars
BG_SECTION = "#151B26"
BG_INPUT = "#0B0F16"
BG_HOVER = "#1E2636"
BG_SELECTED = "#1B3159"
BORDER = "#242E40"
BORDER_STRONG = "#334159"

# Crisp high-contrast text hierarchy
TEXT = "#ECF1F8"
TEXT_SECONDARY = "#97A4BA"
TEXT_MUTED = "#616F87"

# Luminous automotive accents & semantic tones
ACCENT = "#3B82F6"
ACCENT_HOVER = "#60A5FA"
OK = "#34D399"
WARN = "#FBBF24"
ERR = "#F87171"
INFO = "#60A5FA"
CAN = "#C084FC"

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
    """Fusion with crisp custom check/radio/combo indicators tailored for dark obsidian surfaces."""

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
            painter.setPen(QPen(QColor(TEXT_SECONDARY), 1.6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
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
        border = ACCENT_HOVER if on else (ACCENT if hover else "#4B5973")
        painter.setPen(QPen(QColor(border), 1.15))
        painter.setBrush(QColor(ACCENT if on else BG_INPUT))
        painter.drawRoundedRect(box, 3.8, 3.8)
        if on:
            pen = QPen(QColor("#FFFFFF"), max(1.7, side * 0.135))
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            x, y, s = box.x(), box.y(), box.width()
            painter.drawPolyline(
                [QPointF(x + s * 0.24, y + s * 0.52), QPointF(x + s * 0.43, y + s * 0.71), QPointF(x + s * 0.77, y + s * 0.31)]
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
        painter.setPen(QPen(QColor(ACCENT_HOVER if on else (ACCENT if hover else "#4B5973")), 1.15))
        painter.setBrush(QColor(ACCENT if on else BG_INPUT))
        painter.drawEllipse(box)
        if on:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#FFFFFF"))
            painter.drawEllipse(box.adjusted(side * 0.3, side * 0.3, -side * 0.3, -side * 0.3))
        painter.restore()


_STYLE: _Style | None = None


def apply_theme(app: QApplication) -> None:
    """Fusion style + dark obsidian palette + QSS stylesheet."""
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
    """Sapphire-indigo gradient MCU squircle with QFP pins and CAN pulse trace."""
    icon = QIcon()
    for sz in (32, 64, 128, 256):
        pix = QPixmap(sz, sz)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        m = sz * 0.055
        rect = QRectF(m, m, sz - 2 * m, sz - 2 * m)
        tile = QPainterPath()
        tile.addRoundedRect(rect, sz * 0.23, sz * 0.23)

        grad = QLinearGradient(rect.topLeft(), rect.bottomRight())
        grad.setColorAt(0.0, QColor("#4F94FF"))
        grad.setColorAt(0.55, QColor("#2563EB"))
        grad.setColorAt(1.0, QColor("#1E3A8A"))
        p.fillPath(tile, grad)

        # Subtle inner glass highlight border
        p.setPen(QPen(QColor(255, 255, 255, 55), max(1.0, sz * 0.024)))
        p.drawPath(tile)

        # QFP package pins
        pin_pen = QPen(QColor(255, 255, 255, 225), max(1.4, sz * 0.042))
        pin_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pin_pen)
        for frac in (0.37, 0.50, 0.63):
            pos = sz * frac
            p.drawLine(QPointF(pos, sz * 0.18), QPointF(pos, sz * 0.285))
            p.drawLine(QPointF(pos, sz * 0.715), QPointF(pos, sz * 0.82))
            p.drawLine(QPointF(sz * 0.18, pos), QPointF(sz * 0.285, pos))
            p.drawLine(QPointF(sz * 0.715, pos), QPointF(sz * 0.82, pos))

        # Silicon die core
        core_rect = QRectF(sz * 0.285, sz * 0.285, sz * 0.43, sz * 0.43)
        core = QPainterPath()
        core.addRoundedRect(core_rect, sz * 0.075, sz * 0.075)
        p.fillPath(core, QColor(11, 18, 38, 125))
        p.setPen(QPen(QColor("#FFFFFF"), max(1.4, sz * 0.04)))
        p.drawPath(core)

        # Crisp CAN differential square/pulse wave inside the silicon die
        wave_pen = QPen(QColor("#93C5FD"), max(1.2, sz * 0.036))
        wave_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        wave_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(wave_pen)
        p.drawPolyline(
            [
                QPointF(sz * 0.355, sz * 0.54),
                QPointF(sz * 0.42, sz * 0.54),
                QPointF(sz * 0.46, sz * 0.42),
                QPointF(sz * 0.535, sz * 0.58),
                QPointF(sz * 0.575, sz * 0.47),
                QPointF(sz * 0.645, sz * 0.47),
            ]
        )
        p.end()
        icon.addPixmap(pix)
    return icon


def dot_icon(color: str, size: int = 8) -> QIcon:
    """Luminous status dot with soft translucent halo for chips and the status bar."""
    pix = QPixmap(size * 2, size * 2)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    p.setPen(Qt.PenStyle.NoPen)
    halo = QColor(color)
    halo.setAlpha(52)
    p.setBrush(halo)
    p.drawEllipse(QRectF(size * 0.18, size * 0.18, size * 1.64, size * 1.64))
    p.setBrush(QColor(color))
    p.drawEllipse(QRectF(size * 0.52, size * 0.52, size * 0.96, size * 0.96))
    p.end()
    return QIcon(pix)


def _draw_glyph(p: QPainter, kind: str, rect: QRectF, color: QColor, stroke: float) -> None:
    pen = QPen(color, stroke, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    x, y, w, h = rect.x(), rect.y(), rect.width(), rect.height()

    if kind == "can":
        # ECU connector + dual CAN-H/CAN-L differential bus nodes
        p.drawRoundedRect(QRectF(x + w * 0.10, y + h * 0.24, w * 0.44, h * 0.52), w * 0.10, w * 0.10)
        p.drawLine(QPointF(x + w * 0.54, y + h * 0.38), QPointF(x + w * 0.80, y + h * 0.38))
        p.drawLine(QPointF(x + w * 0.54, y + h * 0.62), QPointF(x + w * 0.80, y + h * 0.62))
        p.setBrush(color)
        p.drawEllipse(QPointF(x + w * 0.85, y + h * 0.38), w * 0.065, w * 0.065)
        p.drawEllipse(QPointF(x + w * 0.85, y + h * 0.62), w * 0.065, w * 0.065)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawLine(QPointF(x + w * 0.24, y + h * 0.42), QPointF(x + w * 0.38, y + h * 0.42))
        p.drawLine(QPointF(x + w * 0.24, y + h * 0.58), QPointF(x + w * 0.38, y + h * 0.58))
    elif kind == "files":
        # Stacked flash memory layers (CodeFlash / DataFlash / Uflash)
        top = QPainterPath()
        top.moveTo(x + w * 0.50, y + h * 0.14)
        top.lineTo(x + w * 0.88, y + h * 0.33)
        top.lineTo(x + w * 0.50, y + h * 0.52)
        top.lineTo(x + w * 0.12, y + h * 0.33)
        top.closeSubpath()
        p.drawPath(top)
        p.drawPolyline([QPointF(x + w * 0.12, y + h * 0.50), QPointF(x + w * 0.50, y + h * 0.69), QPointF(x + w * 0.88, y + h * 0.50)])
        p.drawPolyline([QPointF(x + w * 0.12, y + h * 0.67), QPointF(x + w * 0.50, y + h * 0.86), QPointF(x + w * 0.88, y + h * 0.67)])
    elif kind == "folder":
        path = QPainterPath()
        path.moveTo(x + w * 0.10, y + h * 0.26)
        path.lineTo(x + w * 0.38, y + h * 0.26)
        path.lineTo(x + w * 0.47, y + h * 0.36)
        path.lineTo(x + w * 0.90, y + h * 0.36)
        path.lineTo(x + w * 0.90, y + h * 0.78)
        path.lineTo(x + w * 0.10, y + h * 0.78)
        path.closeSubpath()
        fill = QColor(color)
        fill.setAlpha(32)
        p.fillPath(path, fill)
        p.drawPath(path)
    elif kind == "cp":
        # Shield + security keyhole (IKA / Component Protection)
        sh = QPainterPath()
        sh.moveTo(x + w * 0.50, y + h * 0.12)
        sh.lineTo(x + w * 0.84, y + h * 0.25)
        sh.quadTo(x + w * 0.84, y + h * 0.65, x + w * 0.50, y + h * 0.88)
        sh.quadTo(x + w * 0.16, y + h * 0.65, x + w * 0.16, y + h * 0.25)
        sh.closeSubpath()
        p.drawPath(sh)
        p.drawEllipse(QPointF(x + w * 0.50, y + h * 0.45), w * 0.08, w * 0.08)
        p.drawLine(QPointF(x + w * 0.50, y + h * 0.53), QPointF(x + w * 0.50, y + h * 0.66))
    elif kind == "eng":
        # Diagnostic telemetry waveform
        p.drawPolyline(
            [
                QPointF(x + w * 0.10, y + h * 0.54),
                QPointF(x + w * 0.30, y + h * 0.54),
                QPointF(x + w * 0.42, y + h * 0.20),
                QPointF(x + w * 0.57, y + h * 0.82),
                QPointF(x + w * 0.69, y + h * 0.46),
                QPointF(x + w * 0.90, y + h * 0.46),
            ]
        )
    elif kind == "swap":
        # Key / FEC license emblem
        p.drawEllipse(QPointF(x + w * 0.34, y + h * 0.50), w * 0.20, w * 0.20)
        p.drawLine(QPointF(x + w * 0.54, y + h * 0.50), QPointF(x + w * 0.90, y + h * 0.50))
        p.drawLine(QPointF(x + w * 0.74, y + h * 0.50), QPointF(x + w * 0.74, y + h * 0.66))
        p.drawLine(QPointF(x + w * 0.86, y + h * 0.50), QPointF(x + w * 0.86, y + h * 0.63))
    elif kind == "zdc":
        # 3 calibration sliders (ZDC / FPA parameterization)
        for ry, knob in ((0.26, 0.36), (0.50, 0.68), (0.74, 0.44)):
            p.drawLine(QPointF(x + w * 0.14, y + h * ry), QPointF(x + w * 0.86, y + h * ry))
            p.setBrush(QColor(BG_SECTION))
            p.drawEllipse(QPointF(x + w * knob, y + h * ry), w * 0.09, w * 0.09)
            p.setBrush(Qt.BrushStyle.NoBrush)
    elif kind == "dtc":
        # Octagon / alert diagnostic indicator
        tri = QPainterPath()
        tri.moveTo(x + w * 0.50, y + h * 0.15)
        tri.lineTo(x + w * 0.88, y + h * 0.82)
        tri.lineTo(x + w * 0.12, y + h * 0.82)
        tri.closeSubpath()
        p.drawPath(tri)
        p.drawLine(QPointF(x + w * 0.50, y + h * 0.42), QPointF(x + w * 0.50, y + h * 0.60))
        p.setBrush(color)
        p.drawEllipse(QPointF(x + w * 0.50, y + h * 0.71), w * 0.03, w * 0.03)
        p.setBrush(Qt.BrushStyle.NoBrush)
    elif kind == "boot":
        # Bootloader shackle lock
        p.drawRoundedRect(QRectF(x + w * 0.20, y + h * 0.46, w * 0.60, h * 0.40), w * 0.10, w * 0.10)
        shackle = QPainterPath()
        shackle.moveTo(x + w * 0.32, y + h * 0.46)
        shackle.lineTo(x + w * 0.32, y + h * 0.31)
        shackle.arcTo(QRectF(x + w * 0.32, y + h * 0.14, w * 0.36, h * 0.34), 180, -180)
        shackle.lineTo(x + w * 0.68, y + h * 0.46)
        p.drawPath(shackle)
    else:  # "hw" (EEPROM & OPBT silicon IC)
        p.drawRoundedRect(QRectF(x + w * 0.25, y + h * 0.22, w * 0.50, h * 0.56), w * 0.09, w * 0.09)
        for ry in (0.34, 0.50, 0.66):
            p.drawLine(QPointF(x + w * 0.11, y + h * ry), QPointF(x + w * 0.25, y + h * ry))
            p.drawLine(QPointF(x + w * 0.75, y + h * ry), QPointF(x + w * 0.89, y + h * ry))
        p.setBrush(color)
        p.drawEllipse(QPointF(x + w * 0.37, y + h * 0.35), w * 0.035, w * 0.035)
        p.setBrush(Qt.BrushStyle.NoBrush)


def glyph_pixmap(kind: str, color: str = TEXT_SECONDARY, size: int = 16) -> QPixmap:
    """Crisp 2x HiDPI vector icon for navigation items, rows, and badges."""
    dpr = 2
    pix = QPixmap(size * dpr, size * dpr)
    pix.setDevicePixelRatio(dpr)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    _draw_glyph(p, kind, QRectF(1.0, 1.0, size - 2.0, size - 2.0), QColor(color), max(1.35, size * 0.095))
    p.end()
    return pix


def tile_badge_pixmap(kind: str, accent: str = ACCENT, size: int = 40) -> QPixmap:
    """Rounded translucent squircle badge with glowing border and crisp vector glyph inside."""
    dpr = 2
    pix = QPixmap(size * dpr, size * dpr)
    pix.setDevicePixelRatio(dpr)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    box = QRectF(1.0, 1.0, size - 2.0, size - 2.0)
    path = QPainterPath()
    path.addRoundedRect(box, size * 0.26, size * 0.26)

    c_top = QColor(accent)
    c_top.setAlpha(46)
    c_bot = QColor(accent)
    c_bot.setAlpha(18)
    grad = QLinearGradient(box.topLeft(), box.bottomRight())
    grad.setColorAt(0.0, c_top)
    grad.setColorAt(1.0, c_bot)
    p.fillPath(path, grad)

    rim = QColor(accent)
    rim.setAlpha(115)
    p.setPen(QPen(rim, 1.1))
    p.drawPath(path)

    inset = size * 0.24
    _draw_glyph(
        p,
        kind,
        QRectF(inset, inset, size - 2 * inset, size - 2 * inset),
        QColor(accent),
        max(1.6, size * 0.048),
    )
    p.end()
    return pix


def build_stylesheet() -> str:
    """QSS for ContiTool. Fonts are left to QApplication.setFont / mono_font() so setFont() keeps working."""
    return f"""
    QToolTip {{
        background-color: #1A2232; color: {TEXT}; border: 1px solid {BORDER_STRONG};
        border-radius: 6px; padding: 5px 8px;
    }}
    QMenuBar {{
        background-color: {BG_SIDEBAR}; color: {TEXT_SECONDARY};
        border-bottom: 1px solid #182030; padding: 3px 10px;
    }}
    QMenuBar::item {{ background: transparent; padding: 5px 11px; border-radius: 5px; }}
    QMenuBar::item:selected {{ background-color: {BG_HOVER}; color: {TEXT}; }}
    QMenu {{
        background-color: #171E2C; border: 1px solid {BORDER_STRONG};
        border-radius: 8px; padding: 5px;
    }}
    QMenu::item {{ padding: 6px 26px 6px 12px; border-radius: 5px; color: {TEXT}; }}
    QMenu::item:selected {{ background-color: {BG_SELECTED}; color: #FFFFFF; }}
    QMenu::item:disabled {{ color: {TEXT_MUTED}; }}
    QMenu::separator {{ height: 1px; background: {BORDER}; margin: 4px 8px; }}
    QStatusBar {{
        background-color: {BG_SIDEBAR}; border-top: 1px solid #1A2232; color: {TEXT_SECONDARY};
    }}
    QStatusBar::item {{ border: none; }}

    /* ── Surfaces ── */
    QFrame#Header {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0E131D, stop:1 {BG_SIDEBAR});
        border-bottom: 1px solid #1E2738;
        min-height: 46px;
    }}
    QFrame#Section {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #18202E, stop:1 #131924);
        border: 1px solid {BORDER};
        border-radius: 10px;
    }}
    QFrame#HeroBanner {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #17233B, stop:0.55 #141C2B, stop:1 #111723);
        border: 1px solid #2A3B5C;
        border-radius: 12px;
    }}
    QFrame#FeatureTile {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1A2334, stop:1 #131925);
        border: 1px solid #28344B;
        border-radius: 12px;
    }}
    QFrame#FeatureTile:hover {{
        border: 1px solid #3C547D;
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1E293D, stop:1 #151C2A);
    }}
    QFrame#IdentityCard {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #192338, stop:0.45 #161E2D, stop:1 #131924);
        border: 1px solid #2B3A55;
        border-radius: 12px;
    }}
    QFrame#MetricBox {{
        background-color: rgba(10, 14, 22, 0.58);
        border: 1px solid #20293A;
        border-radius: 8px;
    }}
    QFrame#Console {{
        background-color: #0B0F17;
        border-top: 1px solid #1E2738;
    }}
    QFrame#Divider {{ background-color: #20293B; max-height: 1px; min-height: 1px; border: none; }}
    QFrame#WriteBar {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1A2947, stop:1 #152038);
        border: 1px solid #314E85;
        border-left: 3px solid {ACCENT};
        border-radius: 10px;
    }}
    QFrame#Step {{
        background-color: rgba(255, 255, 255, 0.025);
        border: 1px solid {BORDER};
        border-radius: 8px;
    }}
    QLabel#StepNum {{
        background-color: #22304A; color: #93C5FD; border: 1px solid rgba(96, 165, 250, 0.35);
        border-radius: 11px; font-size: 11px; font-weight: 700;
    }}
    QListWidget#Nav {{ background: transparent; border: none; outline: 0; }}
    QListWidget#Nav::item {{
        border-radius: 7px; margin: 2px 2px; border: 1px solid transparent;
    }}
    QListWidget#Nav::item:selected {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(59, 130, 246, 0.24), stop:1 rgba(59, 130, 246, 0.06));
        border: 1px solid rgba(96, 165, 250, 0.30);
        border-left: 3px solid {ACCENT};
    }}
    QListWidget#Nav::item:hover:!selected {{
        background-color: rgba(255, 255, 255, 0.035);
        border: 1px solid rgba(255, 255, 255, 0.05);
    }}
    QListWidget#Adapters {{
        background-color: {BG_INPUT}; border: 1px solid {BORDER};
        border-radius: 8px; padding: 4px; outline: 0;
    }}
    QListWidget#Adapters::item {{ border-radius: 6px; margin: 2px; border: 1px solid transparent; }}
    QListWidget#Adapters::item:selected {{
        background-color: {BG_SELECTED}; border: 1px solid rgba(96, 165, 250, 0.40);
    }}
    QListWidget#Adapters::item:hover:!selected {{ background-color: {BG_HOVER}; }}
    QLabel#AdapterTitle {{ color: {TEXT}; font-weight: 600; }}
    QLabel#AdapterTitle[tone="muted"] {{ color: {TEXT_MUTED}; }}
    QFrame#ListRow {{
        background-color: rgba(21, 27, 38, 0.72);
        border: 1px solid #1F2838;
        border-radius: 8px;
    }}
    QFrame#ListRow:hover {{
        background-color: #1B2436;
        border: 1px solid #324463;
    }}
    QScrollArea {{ background: transparent; border: none; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QSplitter::handle {{ background-color: #1D2636; }}

    QFrame#Callout {{
        border-radius: 5px; border: 1px solid rgba(96, 165, 250, 0.24); border-left: 3px solid {INFO};
        background-color: #131D2E;
    }}
    QFrame#Callout[tone="ok"] {{
        border-color: rgba(52, 211, 153, 0.24); border-left: 3px solid {OK}; background-color: #11221E;
    }}
    QFrame#Callout[tone="warn"] {{
        border-color: rgba(251, 191, 36, 0.24); border-left: 3px solid {WARN}; background-color: #231E13;
    }}
    QFrame#Callout[tone="err"] {{
        border-color: rgba(248, 113, 113, 0.26); border-left: 3px solid {ERR}; background-color: #27171C;
    }}

    /* ── Typography ── */
    QLabel {{ background: transparent; }}
    QLabel#AppName {{ font-size: 14px; font-weight: 700; color: #F8FAFC; letter-spacing: 0.2px; }}
    QLabel#VersionBadge {{
        font-size: 10px; font-weight: 700; color: #93C5FD;
        background-color: rgba(59, 130, 246, 0.14); border: 1px solid rgba(96, 165, 250, 0.30);
        border-radius: 7px; padding: 1px 6px;
    }}
    QLabel#PageTitle {{ font-size: 19px; font-weight: 700; color: #F8FAFC; }}
    QLabel#PartNumber {{ font-size: 21px; font-weight: 700; color: #F8FAFC; letter-spacing: 0.4px; }}
    QLabel#SectionTitle {{ font-size: 14px; font-weight: 600; color: {TEXT}; }}
    QLabel#GroupLabel {{ font-size: 10px; font-weight: 700; color: {TEXT_MUTED}; letter-spacing: 0.7px; }}
    QLabel#FieldLabel {{ font-weight: 600; color: {TEXT}; }}
    QLabel#Hint {{ color: {TEXT_SECONDARY}; }}
    QLabel[tone="ok"], QLabel#Hint[tone="ok"] {{ color: {OK}; }}
    QLabel[tone="warn"], QLabel#Hint[tone="warn"] {{ color: {WARN}; }}
    QLabel[tone="err"], QLabel#Hint[tone="err"] {{ color: {ERR}; }}
    QLabel[tone="info"], QLabel#Hint[tone="info"] {{ color: {INFO}; }}
    QLabel[tone="muted"], QLabel#Hint[tone="muted"] {{ color: {TEXT_MUTED}; }}

    QLabel#Pill {{
        border-radius: 9px; padding: 2px 9px; font-size: 11px; font-weight: 600;
        background-color: rgba(148, 163, 184, 0.10); border: 1px solid rgba(148, 163, 184, 0.24);
        color: {TEXT_SECONDARY};
    }}
    QLabel#Pill[tone="ok"] {{
        background-color: rgba(52, 211, 153, 0.13); border-color: rgba(52, 211, 153, 0.38); color: {OK};
    }}
    QLabel#Pill[tone="warn"] {{
        background-color: rgba(251, 191, 36, 0.13); border-color: rgba(251, 191, 36, 0.38); color: {WARN};
    }}
    QLabel#Pill[tone="err"] {{
        background-color: rgba(248, 113, 113, 0.14); border-color: rgba(248, 113, 113, 0.40); color: {ERR};
    }}
    QLabel#Pill[tone="info"] {{
        background-color: rgba(96, 165, 250, 0.14); border-color: rgba(96, 165, 250, 0.40); color: {INFO};
    }}

    /* ── Buttons ── */
    QPushButton, QToolButton {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #232C3F, stop:1 #1A2130);
        color: {TEXT}; border: 1px solid {BORDER_STRONG};
        border-radius: 6px; padding: 5px 13px; min-height: 20px; font-weight: 500;
    }}
    QPushButton:hover, QToolButton:hover {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2B364D, stop:1 #212A3D);
        border-color: #46597A;
    }}
    QPushButton:pressed, QToolButton:pressed {{ background-color: #161C29; }}
    QPushButton:disabled, QToolButton:disabled {{
        background: rgba(255, 255, 255, 0.02); color: {TEXT_MUTED}; border-color: #1E2636;
    }}
    QPushButton:focus, QToolButton:focus {{ outline: none; }}
    QPushButton:checked {{ background-color: {BG_SELECTED}; border-color: {ACCENT}; color: #FFFFFF; }}
    QToolButton::menu-indicator {{ image: none; width: 0; }}

    QPushButton#PrimaryBtn {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4F8FF7, stop:1 #2563EB);
        border: 1px solid #60A5FA; border-bottom-color: #1D4ED8;
        color: #FFFFFF; font-weight: 600;
    }}
    QPushButton#PrimaryBtn:hover {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #60A5FA, stop:1 #3B82F6);
        border-color: #93C5FD;
    }}
    QPushButton#PrimaryBtn:pressed {{
        background: #1D4ED8; border-color: #2563EB;
    }}
    QPushButton#PrimaryBtn:disabled {{
        background: #1C2942; border-color: #253554; color: #697A98;
    }}

    QPushButton#DangerBtn {{
        background-color: rgba(248, 113, 113, 0.08); border-color: rgba(248, 113, 113, 0.42); color: {ERR};
    }}
    QPushButton#DangerBtn:hover {{
        background-color: rgba(248, 113, 113, 0.18); border-color: {ERR};
    }}
    QPushButton#DangerBtn:disabled {{ background: transparent; border-color: {BORDER}; color: {TEXT_MUTED}; }}

    QPushButton#GhostBtn, QToolButton#GhostBtn {{
        background: transparent; border-color: transparent; color: {TEXT_SECONDARY}; padding: 4px 10px;
    }}
    QPushButton#GhostBtn:hover, QToolButton#GhostBtn:hover {{
        background-color: rgba(255, 255, 255, 0.06); border-color: rgba(255, 255, 255, 0.08); color: {TEXT};
    }}
    QPushButton#GhostBtn:checked {{ background-color: {BG_HOVER}; color: {TEXT}; }}
    QPushButton#GhostBtn:disabled {{ color: {TEXT_MUTED}; background: transparent; border-color: transparent; }}

    QPushButton#LinkBtn {{ background: transparent; border: none; padding: 0; min-height: 0; color: {INFO}; font-weight: 500; }}
    QPushButton#LinkBtn:hover {{ color: #93C5FD; text-decoration: underline; }}

    QPushButton#Chip {{
        background-color: #131A26; border: 1px solid #29354B; border-radius: 13px;
        padding: 4px 12px; min-height: 18px; color: {TEXT}; font-size: 12px; font-weight: 500;
    }}
    QPushButton#Chip:hover {{ background-color: #1B2536; border-color: #3E5275; }}

    QPushButton#TabBtn {{
        background: transparent; border: none; border-bottom: 2px solid transparent; border-radius: 0;
        color: {TEXT_SECONDARY}; padding: 0 14px; min-height: 44px; font-weight: 600;
    }}
    QPushButton#TabBtn:hover {{ color: {TEXT}; background-color: rgba(255, 255, 255, 0.025); }}
    QPushButton#TabBtn:checked {{
        color: #FFFFFF; border-bottom: 2px solid {ACCENT};
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 transparent, stop:1 rgba(59, 130, 246, 0.12));
    }}
    QPushButton#TabBtn:disabled {{ color: {TEXT_MUTED}; }}

    QPushButton#SegBtn {{
        background-color: #111622; border: 1px solid #2A364D; color: {TEXT_SECONDARY};
        border-radius: 0; padding: 3px 10px; min-height: 18px; font-size: 11px; font-weight: 600;
    }}
    QPushButton#SegBtn:hover {{ color: {TEXT}; background-color: #192132; }}
    QPushButton#SegBtn:checked {{
        background-color: #213458; border-color: #3B82F6; color: #FFFFFF;
    }}
    QPushButton#SegBtn[pos="left"] {{ border-top-left-radius: 6px; border-bottom-left-radius: 6px; border-right: none; }}
    QPushButton#SegBtn[pos="right"] {{ border-top-right-radius: 6px; border-bottom-right-radius: 6px; }}

    /* ── Inputs ── */
    QLineEdit, QComboBox, QSpinBox {{
        background-color: {BG_INPUT}; color: {TEXT}; border: 1px solid #2A364B;
        border-radius: 6px; padding: 5px 9px; min-height: 22px; selection-background-color: {ACCENT};
    }}
    QLineEdit:hover, QComboBox:hover, QSpinBox:hover {{ border-color: #3A4B69; }}
    QPlainTextEdit, QTextEdit {{
        background-color: {BG_INPUT}; color: {TEXT}; border: 1px solid #222C3F;
        border-radius: 7px; padding: 6px; selection-background-color: {ACCENT};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
        border-color: {ACCENT};
    }}
    QLineEdit[tone="err"] {{ border-color: {ERR}; }}
    QLineEdit[drag="true"] {{ border: 1px dashed {ACCENT}; background-color: #152238; }}
    QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{ color: {TEXT_MUTED}; border-color: {BORDER}; }}
    QComboBox::drop-down {{ border: none; width: 24px; }}
    QComboBox QAbstractItemView {{
        background-color: #171E2C; border: 1px solid {BORDER_STRONG}; border-radius: 6px; padding: 4px;
        selection-background-color: {BG_SELECTED}; outline: 0;
    }}
    QComboBox QAbstractItemView::item {{ min-height: 25px; padding: 3px 8px; border-radius: 4px; }}
    QCheckBox, QRadioButton {{ spacing: 8px; color: {TEXT}; background: transparent; min-height: 20px; }}
    QCheckBox:disabled, QRadioButton:disabled {{ color: {TEXT_MUTED}; }}

    /* ── Tabs ── */
    QTabWidget::pane {{
        border: 1px solid {BORDER}; border-radius: 8px; background-color: {BG_WINDOW}; top: -1px;
    }}
    QTabBar::tab {{
        background-color: transparent; color: {TEXT_SECONDARY}; border: 1px solid transparent;
        border-bottom: 2px solid transparent; padding: 8px 15px; min-height: 20px; font-weight: 600;
        margin-right: 3px;
    }}
    QTabBar::tab:hover:!selected {{
        color: {TEXT}; background-color: {BG_HOVER}; border-top-left-radius: 6px; border-top-right-radius: 6px;
    }}
    QTabBar::tab:selected {{ color: #FFFFFF; border-bottom-color: {ACCENT}; }}

    /* ── Progress ── */
    QProgressBar {{
        background-color: #1A2334; border: none; border-radius: 3px; max-height: 6px; min-height: 6px;
    }}
    QProgressBar::chunk {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563EB, stop:1 #60A5FA);
        border-radius: 3px;
    }}
    QProgressBar[tone="ok"]::chunk {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10B981, stop:1 #34D399);
    }}
    QProgressBar[tone="err"]::chunk {{ background-color: {ERR}; }}
    QProgressBar[tone="warn"]::chunk {{ background-color: {WARN}; }}

    /* ── Tables ── */
    QTableView {{
        background-color: {BG_INPUT}; alternate-background-color: #101622; gridline-color: #1A2233;
        border: 1px solid {BORDER}; border-radius: 8px; color: {TEXT};
        selection-background-color: {BG_SELECTED}; selection-color: #FFFFFF;
    }}
    QTableView::item {{ padding: 2px 8px; }}
    QTableView::item:hover {{ background-color: rgba(255, 255, 255, 0.03); }}
    QHeaderView::section {{
        background-color: #141B28; color: {TEXT_SECONDARY}; border: none;
        border-bottom: 1px solid {BORDER}; padding: 6px 8px; font-weight: 600;
    }}

    /* ── Scrollbars ── */
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
    QScrollBar::handle {{ background: #2D3A52; border-radius: 4px; min-height: 26px; min-width: 26px; }}
    QScrollBar::handle:hover {{ background: #435578; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    """
