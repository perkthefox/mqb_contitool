"""Start screen: engineering CAN bus target workbench, drag-and-drop dump bar, and parsed recent ECUs."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QDragEnterEvent, QDragLeaveEvent, QDropEvent, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from contitool.gui import theme
from contitool.gui.theme import mono_font, set_tone, ui_font
from contitool.gui.widgets.page import Section, button, clear_layout, group_label, hint
from contitool.gui.workspace import recent_folders
from contitool.i18n import subscribe_lang_change, tr

_COLUMN_WIDTH = 920

_RE_TIMESTAMP_DIR = re.compile(r"^(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2}-\d{2})(?:_(.+))?$")
_RE_VAG_PN = re.compile(r"^([0-9A-Z]{3}[0-9]{6}[0-9A-Z]{0,2})(?:[_-](.+))?$")


def _summarize_recent_folder(folder: Path) -> dict[str, Any]:
    """Extract clean engineering metadata (ECU address, part number, FAZIT, dump tags, timestamp) from a dump folder."""
    unit_name = ""
    session_tag = ""
    raw_name = folder.name
    m_ts = _RE_TIMESTAMP_DIR.match(raw_name)
    if m_ts:
        session_tag = (m_ts.group(3) or "").replace("_", " ")
        # Walk up past `dumps/` to find `<part>_<fazit>`
        parent = folder.parent
        if parent.name.lower() == "dumps":
            parent = parent.parent
        unit_name = parent.name
    elif folder.parent.name.lower() == "dumps":
        session_tag = raw_name.replace("_", " ")
        unit_name = folder.parent.parent.name
    else:
        unit_name = raw_name

    part_num = unit_name
    fazit = ""
    m_pn = _RE_VAG_PN.match(unit_name)
    if m_pn:
        part_num = m_pn.group(1)
        fazit = (m_pn.group(2) or "").strip("_- ")

    # Lightweight directory listing for dump tags and ECU family detection (no file reads)
    file_sizes: dict[str, int] = {}
    try:
        for child in folder.iterdir():
            if child.is_file():
                file_sizes[child.name.lower()] = child.stat().st_size
    except OSError:
        pass

    is_mrr = (
        "mrr_keys.json" in file_sizes
        or "mrr_read_report.json" in file_sizes
        or "mrr" in raw_name.lower()
        or part_num.startswith(("3Q0907572", "5Q0907572", "3QF907561"))
    )
    is_elv = (
        not is_mrr
        and (
            "elv_dflash_32k.bin" in file_sizes
            or "elv_dflash_64k.bin" in file_sizes
            or "elv_report.json" in file_sizes
            or "elv_backup_report.json" in file_sizes
            or "elv" in raw_name.lower()
            or part_num.startswith(("3Q0905861", "5Q0905861", "2Q0905861"))
        )
    )
    if is_elv and not m_pn:
        for meta_name in ("elv_report.json", "elv_backup_report.json"):
            if meta_name in file_sizes and file_sizes[meta_name] <= 262144:
                try:
                    mdata = json.loads((folder / meta_name).read_text(encoding="utf-8"))
                    pp = mdata.get("passport") or mdata.get("identity") if isinstance(mdata, dict) else None
                    if isinstance(pp, dict):
                        pn_json = str(pp.get("part_number") or "").strip()
                        fz_json = str(pp.get("fazit") or "").strip()
                        if pn_json:
                            part_num = pn_json
                            fazit = fz_json
                            break
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    pass
    if is_mrr and not m_pn:
        for meta_name in ("mrr_keys.json", "mrr_read_report.json"):
            if meta_name in file_sizes and file_sizes[meta_name] <= 131072:
                try:
                    mdata = json.loads((folder / meta_name).read_text(encoding="utf-8"))
                    pp = mdata.get("passport") if isinstance(mdata, dict) else None
                    if isinstance(pp, dict):
                        pn_json = str(pp.get("part_number") or pp.get("hw_part_number") or "").strip()
                        fz_json = str(pp.get("fazit") or "").strip()
                        if pn_json:
                            part_num = pn_json
                            fazit = fz_json
                            break
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    pass
    is_kombi = (
        not is_mrr
        and not is_elv
        and (
            "kombi_report.json" in file_sizes
            or "eellogical.bin" in file_sizes
            or "eel_phys_offsets.bin" in file_sizes
            or "kombi" in raw_name.lower()
            or part_num.startswith(("5NA920740", "5NA920750", "5E0920740", "5E0920750", "5G0920", "3Q0920"))
        )
    )
    is_fpke = (
        not is_mrr
        and not is_elv
        and not is_kombi
        and (
            "extraarea.bin" in file_sizes
            or "fpke_report.json" in file_sizes
            or "immo_passport.json" in file_sizes
            or "fpke" in raw_name.lower()
            or part_num.startswith(("83A", "5E0", "3G0920", "5G1920", "8W5"))
        )
    )
    is_j533 = (
        not is_mrr
        and not is_elv
        and not is_kombi
        and not is_fpke
        and (
            part_num.startswith(("3Q0", "V03"))
            or any(n in file_sizes for n in ("uflash.bin", "eeprom.bin", "opbt.bin", "cflash.bin"))
        )
    )

    tags: list[str] = []
    if any("cflash" in n for n in file_sizes):
        sz = next(s for n, s in file_sizes.items() if "cflash" in n)
        tags.append("CF 2M" if sz >= 1_900_000 else "CF 1.5M")
    if any("application" in n for n in file_sizes):
        tags.append("APP")
    if any("bootloader" in n for n in file_sizes):
        tags.append("BOOT")
    if any("dflash" in n for n in file_sizes):
        sz_df = next(s for n, s in file_sizes.items() if "dflash" in n)
        tags.append("DF 32K" if sz_df == 32768 else "DF 64K")
    if "eellogical.bin" in file_sizes:
        tags.append("EEL 132")
    if any("sram" in n for n in file_sizes):
        tags.append("SRAM")
    if any("uflash" in n for n in file_sizes):
        tags.append("UF 32K")
    if any("extraarea" in n or "extra_area" in n for n in file_sizes):
        tags.append("EX 256B")
    if any("bflash" in n for n in file_sizes):
        tags.append("BF 96K")
    if any("eeprom" in n or "m95640" in n for n in file_sizes):
        tags.append("EE 8K")
    if any("opbt" in n for n in file_sizes):
        tags.append("OPBT")
    if is_mrr and not tags and ("mrr_keys.json" in file_sizes or "mrr_read_report.json" in file_sizes):
        tags.append("UDS")
    if is_elv and not tags and ("elv_report.json" in file_sizes or "elv_backup_report.json" in file_sizes):
        tags.append("UDS")

    try:
        when = datetime.fromtimestamp(folder.stat().st_mtime).strftime("%d.%m.%Y  %H:%M")
    except OSError:
        when = ""

    return {
        "addr": "2B" if is_elv else ("13" if is_mrr else ("17" if (is_fpke or is_kombi) else ("19" if is_j533 else "BIN"))),
        "tone": "warn" if is_elv else ("info" if is_mrr else ("can" if (is_fpke or is_kombi) else ("ok" if is_j533 else "muted"))),
        "title": part_num or raw_name,
        "subtitle": fazit or (session_tag if not m_pn else ""),
        "session": session_tag,
        "tags": tags[:4],
        "when": when,
    }


class _BusTopologyDiagram(QWidget):
    """Crisp antialiased vector schematic of the active CAN connection mode (Gateway L2 vs Direct L1)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._mode = "all"
        self.setFixedHeight(116)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_mode(self, mode: str) -> None:
        if self._mode != mode:
            self._mode = mode
            self.update()

    def paintEvent(self, _event: Any) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

        w, h = float(self.width()), float(self.height())
        bg = QPainterPath()
        bg.addRoundedRect(QRectF(0.5, 0.5, w - 1.0, h - 1.0), 7.0, 7.0)
        p.fillPath(bg, QColor("#121317"))
        p.setPen(QPen(QColor("#23262F"), 1.0))
        p.drawPath(bg)

        cy = h / 2.0
        f_title = mono_font(11, bold=True)
        f_sub = mono_font(10)

        def draw_node(
            x: float,
            y: float,
            nw: float,
            nh: float,
            title: str,
            sub: str,
            *,
            accent: str | None = None,
            dim: bool = False,
        ) -> QRectF:
            rect = QRectF(x, y, nw, nh)
            path = QPainterPath()
            path.addRoundedRect(rect, 6.0, 6.0)
            fill = "#172236" if accent == theme.ACCENT else ("#162620" if accent == theme.OK else "#1A1C22")
            border = accent if accent else ("#2A2E39" if dim else "#343946")
            p.fillPath(path, QColor(fill))
            p.setPen(QPen(QColor(border), 1.25 if accent else 1.0))
            p.drawPath(path)

            p.setFont(f_title)
            p.setPen(QColor(theme.TEXT if not dim else theme.TEXT_SECONDARY))
            p.drawText(QRectF(x + 8, y + 4, nw - 16, nh * 0.50), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, title)
            p.setFont(f_sub)
            p.setPen(QColor(accent if accent else theme.TEXT_MUTED))
            p.drawText(QRectF(x + 8, y + nh * 0.48, nw - 16, nh * 0.46), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, sub)
            return rect

        def draw_wire(x1: float, y1: float, x2: float, y2: float, label: str, *, color: str = "#475066", dashed: bool = False) -> None:
            pen = QPen(QColor(color), 1.4)
            if dashed:
                pen.setStyle(Qt.PenStyle.DashLine)
            p.setPen(pen)
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2))
            # Arrowhead at right end
            p.setPen(QPen(QColor(color), 1.4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            p.drawLine(QPointF(x2 - 5.0, y2 - 3.0), QPointF(x2, y2))
            p.drawLine(QPointF(x2 - 5.0, y2 + 3.0), QPointF(x2, y2))
            if label:
                p.setFont(f_sub)
                p.setPen(QColor(theme.TEXT_SECONDARY))
                mid_x = (x1 + x2) / 2.0
                lbl_r = QRectF(mid_x - 85.0, y1 - 16.0, 170.0, 14.0)
                p.drawText(lbl_r, Qt.AlignmentFlag.AlignCenter, label)

        pad = 16.0
        host_w = min(132.0, w * 0.17)
        node_h = 44.0
        host_r = draw_node(pad, cy - node_h / 2.0, host_w, node_h, "CAN 500k", tr("120 Ом", "120 Ω"))

        if self._mode == "all":
            gw_w = min(176.0, w * 0.22)
            sl_w = min(156.0, w * 0.20)
            gap1 = max(72.0, (w - pad * 2 - host_w - gw_w - sl_w) * 0.42)
            gw_x = host_r.right() + gap1
            gw_r = draw_node(gw_x, cy - node_h / 2.0, gw_w, node_h, "[19] J533", "0x710 / 0x77A", accent=theme.ACCENT)
            draw_wire(host_r.right() + 4, cy, gw_r.left() - 4, cy, "Diag CAN ch3", color=theme.INFO)

            sl_x = w - pad - sl_w
            row_h = 22.0
            gap_y = 4.0
            y0 = (h - (row_h * 4 + gap_y * 3)) / 2.0
            r17 = QRectF(sl_x, y0, sl_w, row_h)
            r09 = QRectF(sl_x, y0 + (row_h + gap_y), sl_w, row_h)
            r2b = QRectF(sl_x, y0 + (row_h + gap_y) * 2, sl_w, row_h)
            r13 = QRectF(sl_x, y0 + (row_h + gap_y) * 3, sl_w, row_h)

            # Branch trunk from GW ch0 (Komfort) & ch2 (Extended)
            branch_x = gw_r.right() + (sl_x - gw_r.right()) * 0.62
            p.setPen(QPen(QColor(theme.OK), 1.4))
            p.drawLine(QPointF(gw_r.right() + 4, cy), QPointF(branch_x, cy))
            p.drawLine(QPointF(branch_x, r17.center().y()), QPointF(branch_x, r2b.center().y()))
            p.setPen(QPen(QColor(theme.INFO), 1.4))
            p.drawLine(QPointF(branch_x, r2b.center().y()), QPointF(branch_x, r13.center().y()))
            draw_wire(branch_x, r17.center().y(), r17.left() - 4, r17.center().y(), "", color=theme.OK)
            draw_wire(branch_x, r09.center().y(), r09.left() - 4, r09.center().y(), "", color=theme.OK)
            draw_wire(branch_x, r2b.center().y(), r2b.left() - 4, r2b.center().y(), "", color=theme.OK)
            draw_wire(branch_x, r13.center().y(), r13.left() - 4, r13.center().y(), "", color=theme.INFO)

            # Trunk label
            p.setFont(f_sub)
            p.setPen(QColor(theme.OK))
            p.drawText(
                QRectF(gw_r.right() + 6, cy - 17.0, branch_x - gw_r.right() - 8, 14.0),
                Qt.AlignmentFlag.AlignCenter,
                tr("RAM-мост ch0/ch2", "RAM-Bridge ch0/ch2"),
            )
            p.setPen(QColor(theme.TEXT_MUTED))
            p.drawText(
                QRectF(gw_r.right() + 6, cy + 3.0, branch_x - gw_r.right() - 8, 14.0),
                Qt.AlignmentFlag.AlignCenter,
                "Komfort / Ext CAN",
            )

            # Compact slave pills on right (aligned columns)
            for rect, code, name, can_id, col in (
                (r17, "17", "FPK_E", "0x714", theme.CAN),
                (r09, "09", "BCM", "0x70E", theme.TEXT_SECONDARY),
                (r2b, "2B", "ELV", "0x731", theme.WARN),
                (r13, "13", "ACC", "0x757", theme.INFO),
            ):
                sp = QPainterPath()
                sp.addRoundedRect(rect, 5.0, 5.0)
                p.fillPath(sp, QColor("#1A1C23"))
                p.setPen(QPen(QColor("#333846"), 1.0))
                p.drawPath(sp)
                p.setFont(f_title)
                p.setPen(QColor(col))
                p.drawText(QRectF(rect.x() + 8, rect.y(), 22, rect.height()), Qt.AlignmentFlag.AlignVCenter, code)
                p.setFont(f_sub)
                p.setPen(QColor(theme.TEXT))
                p.drawText(QRectF(rect.x() + 30, rect.y(), rect.width() - 80, rect.height()), Qt.AlignmentFlag.AlignVCenter, name)
                p.setPen(QColor(theme.TEXT_MUTED))
                p.drawText(
                    QRectF(rect.right() - 50, rect.y(), 42, rect.height()),
                    Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                    can_id,
                )
        else:
            spec_map = {
                "j533": ("[19] J533 Gateway", "T20: Pin 19, Pin 9", "0x710 / 0x77A", theme.OK),
                "fpke": ("[17] FPK_E (RH850)", "T18: Pin 18, Pin 17", "0x714 / 0x77E", theme.CAN),
                "kombi": ("[17] Kombi VDD (V850)", "T18: Pin 18, Pin 17", "0x714 / 0x77E", theme.CAN),
                "bcm": ("[09] BCM J519", "Komfort CAN", "0x70E / 0x778", theme.INFO),
                "mrr": ("[13] ACC Radar MRR", "Extended CAN", "0x757 / 0x7C1", theme.ACCENT),
                "elv": ("[2B] ELV J764", "T4: Pin 1, Pin 2", "0x731 / 0x79B", theme.WARN),
            }
            title, sub, wire_lbl, accent = spec_map.get(self._mode, spec_map["j533"])
            dst_w = min(230.0, w * 0.34)
            dst_r = draw_node(w - pad - dst_w, cy - node_h / 2.0, dst_w, node_h, title, sub, accent=accent)
            draw_wire(host_r.right() + 6, cy, dst_r.left() - 6, cy, wire_lbl, color=accent)

        p.end()


class _TargetCard(QFrame):
    """Clickable engineering target selector card (replaces generic QComboBox)."""

    clicked = Signal(str)

    def __init__(self, code: str, badge_text: str, badge_tone: str = "") -> None:
        super().__init__()
        self.code = code
        self.setObjectName("TargetCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(13, 10, 13, 10)
        lay.setSpacing(4)

        top = QHBoxLayout()
        top.setSpacing(7)
        self.lbl_badge = QLabel(badge_text)
        self.lbl_badge.setObjectName("AddrBadge")
        self.lbl_badge.setFont(mono_font(10, bold=True))
        self.lbl_badge.setFixedWidth(32)
        self.lbl_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if badge_tone:
            set_tone(self.lbl_badge, badge_tone)

        self.lbl_name = QLabel()
        self.lbl_name.setObjectName("FieldLabel")
        self.lbl_name.setFont(ui_font(12, bold=True))

        top.addWidget(self.lbl_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        top.addWidget(self.lbl_name, 1, Qt.AlignmentFlag.AlignVCenter)
        lay.addLayout(top)

        self.lbl_meta = QLabel()
        self.lbl_meta.setObjectName("Hint")
        self.lbl_meta.setFont(mono_font(10))
        lay.addWidget(self.lbl_meta)

    def set_labels(self, title: str, meta: str) -> None:
        self.lbl_name.setText(title)
        self.lbl_meta.setText(meta)

    def set_selected(self, selected: bool) -> None:
        if self.property("selected") == selected:
            return
        self.setProperty("selected", selected)
        self.style().unpolish(self)
        self.style().polish(self)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001
        if self.rect().contains(event.position().toPoint()):
            self.clicked.emit(self.code)


class _RecentRow(QFrame):
    """Structured engineering recent-unit row: ECU address badge, part number, dump tags, and timestamp."""

    clicked = Signal()

    def __init__(self, folder: Path, *, is_last: bool = False) -> None:
        super().__init__()
        self.setObjectName("ListRow")
        if is_last:
            self.setProperty("last", True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(str(folder))

        meta = _summarize_recent_folder(folder)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 9, 14, 9)
        lay.setSpacing(10)

        badge = QLabel(meta["addr"])
        badge.setObjectName("AddrBadge")
        badge.setFont(mono_font(10, bold=True))
        badge.setFixedWidth(34)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if meta["tone"] in ("ok", "can", "accent", "info", "warn"):
            set_tone(badge, meta["tone"])
        lay.addWidget(badge, 0, Qt.AlignmentFlag.AlignVCenter)

        lbl_pn = QLabel(meta["title"])
        lbl_pn.setObjectName("FieldLabel")
        lbl_pn.setFont(mono_font(12, bold=True))
        lay.addWidget(lbl_pn, 0, Qt.AlignmentFlag.AlignVCenter)

        sub_txt = meta["subtitle"]
        if sub_txt:
            lbl_sub = QLabel()
            lbl_sub.setObjectName("Hint")
            lbl_sub.setFont(mono_font(11))
            lbl_sub.setText(lbl_sub.fontMetrics().elidedText(sub_txt, Qt.TextElideMode.ElideRight, 260))
            lay.addWidget(lbl_sub, 0, Qt.AlignmentFlag.AlignVCenter)

        lay.addStretch(1)

        for tag in meta["tags"]:
            t_lbl = QLabel(tag)
            t_lbl.setObjectName("DumpTag")
            t_lbl.setFont(mono_font(10))
            lay.addWidget(t_lbl, 0, Qt.AlignmentFlag.AlignVCenter)

        if meta["when"]:
            lay.addSpacing(4)
            stamp = QLabel(meta["when"])
            stamp.setFont(mono_font(10))
            stamp.setObjectName("Hint")
            lay.addWidget(stamp, 0, Qt.AlignmentFlag.AlignVCenter)

        arrow = QLabel("›")
        arrow.setObjectName("Hint")
        lay.addWidget(arrow, 0, Qt.AlignmentFlag.AlignVCenter)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001
        if self.rect().contains(event.position().toPoint()):
            self.clicked.emit()


class StartScreen(QWidget):
    """Engineering start workbench: CAN topology target selector, compact dump drop strip, and recent units."""

    scan_bus_requested = Signal(str)  # target_kind ("all", "j533", "fpke", "bcm", "mrr", "elv")
    read_can_requested = Signal()
    restore_requested = Signal()
    open_files_requested = Signal()
    open_folder_requested = Signal(str)  # "" = ask for a folder
    files_dropped = Signal(list)  # list[Path]
    wiring_requested = Signal()
    connection_requested = Signal()

    def __init__(self, conn: Any | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self._conn = conn
        self._target_kind = "all"

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        root.addWidget(scroll, 1)

        canvas = QWidget()
        canvas.setObjectName("PageCanvas")
        outer = QHBoxLayout(canvas)
        outer.setContentsMargins(32, 26, 32, 24)
        outer.addStretch(1)

        column = QWidget()
        column.setMaximumWidth(_COLUMN_WIDTH)
        outer.addWidget(column, 100)
        outer.addStretch(1)
        scroll.setWidget(canvas)

        body = QVBoxLayout(column)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(14)

        # ── 1. Compact Header Strip ──
        hdr = QHBoxLayout()
        hdr.setSpacing(12)
        title_col = QVBoxLayout()
        title_col.setContentsMargins(0, 0, 0, 0)
        title_col.setSpacing(3)
        self.lbl_title = QLabel()
        self.lbl_title.setObjectName("PageTitle")
        self.lbl_title.setFont(ui_font(21, bold=True))
        self.lbl_sub = hint()
        title_col.addWidget(self.lbl_title)
        title_col.addWidget(self.lbl_sub)
        hdr.addLayout(title_col, 1)

        self.btn_wiring = button("", "GhostBtn", slot=self.wiring_requested.emit)
        self.btn_wiring.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_wiring.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        hdr.addWidget(self.btn_wiring, 0, Qt.AlignmentFlag.AlignBottom)
        body.addLayout(hdr)

        # ── 2. Primary Full-Width CAN Bus Workbench Card ──
        self.tile_can = Section()
        self.tile_can.hide_head()
        self.tile_can.body.setContentsMargins(18, 14, 18, 14)
        self.tile_can.body.setSpacing(12)

        can_top = QHBoxLayout()
        can_top.setSpacing(10)
        self.lbl_can_eyebrow = group_label()
        can_top.addWidget(self.lbl_can_eyebrow, 0, Qt.AlignmentFlag.AlignVCenter)
        can_top.addStretch(1)
        self.lbl_proto = QLabel()
        self.lbl_proto.setObjectName("Hint")
        self.lbl_proto.setFont(mono_font(10))
        can_top.addWidget(self.lbl_proto, 0, Qt.AlignmentFlag.AlignVCenter)
        self.tile_can.body.addLayout(can_top)

        # Target Matrix (3×2 hardware cards — spacious, zero clipping)
        target_grid = QGridLayout()
        target_grid.setContentsMargins(0, 0, 0, 0)
        target_grid.setHorizontalSpacing(8)
        target_grid.setVerticalSpacing(8)
        for col in range(3):
            target_grid.setColumnStretch(col, 1)
        self._target_cards: dict[str, _TargetCard] = {}
        for idx, (code, badge, tone) in enumerate(
            (
                ("all", "GW", "accent"),
                ("j533", "19", "ok"),
                ("fpke", "17", "can"),
                ("bcm", "09", ""),
                ("mrr", "13", "info"),
                ("elv", "2B", "warn"),
            )
        ):
            card = _TargetCard(code, badge, tone)
            card.clicked.connect(self.set_target_kind)
            self._target_cards[code] = card
            target_grid.addWidget(card, idx // 3, idx % 3)
        self.tile_can.body.addLayout(target_grid)

        # Dynamic Vector Bus Topology Schematic
        self.diagram = _BusTopologyDiagram()
        self.tile_can.body.addWidget(self.diagram)

        # Spacious Action Bar (zero clipping)
        act_row = QHBoxLayout()
        act_row.setContentsMargins(0, 2, 0, 0)
        act_row.setSpacing(8)
        self.btn_scan = button("", "PrimaryBtn", slot=lambda: self.scan_bus_requested.emit("all"))
        self.btn_read = button("", "PrimaryBtn", slot=self.read_can_requested.emit)
        self.btn_restore = button("", "GhostBtn", slot=self.restore_requested.emit)
        for b in (self.btn_scan, self.btn_read, self.btn_restore):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        act_row.addWidget(self.btn_scan)
        act_row.addWidget(self.btn_read)
        act_row.addStretch(1)
        act_row.addWidget(self.btn_restore)
        self.tile_can.body.addLayout(act_row)
        body.addWidget(self.tile_can)

        # ── 3. Compact Offline Dumps Drop Bar ──
        self.drop_strip = QFrame()
        self.drop_strip.setObjectName("DropStrip")
        ds_lay = QHBoxLayout(self.drop_strip)
        ds_lay.setContentsMargins(18, 12, 18, 12)
        ds_lay.setSpacing(12)

        ds_txt = QVBoxLayout()
        ds_txt.setContentsMargins(0, 0, 0, 0)
        ds_txt.setSpacing(2)
        self.lbl_files_title = QLabel()
        self.lbl_files_title.setObjectName("FieldLabel")
        self.lbl_files_sub = QLabel()
        self.lbl_files_sub.setObjectName("Hint")
        ds_txt.addWidget(self.lbl_files_title)
        ds_txt.addWidget(self.lbl_files_sub)
        ds_lay.addLayout(ds_txt, 1)

        self.btn_folder = button("", slot=lambda: self.open_folder_requested.emit(""))
        self.btn_files = button("", slot=self.open_files_requested.emit)
        for b in (self.btn_folder, self.btn_files):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            ds_lay.addWidget(b, 0, Qt.AlignmentFlag.AlignVCenter)
        body.addWidget(self.drop_strip)

        # ── 4. Scannable Recent Units ──
        self.recent_wrap = QWidget()
        rw_lay = QVBoxLayout(self.recent_wrap)
        rw_lay.setContentsMargins(0, 4, 0, 0)
        rw_lay.setSpacing(6)
        self.lbl_recent = group_label()
        rw_lay.addWidget(self.lbl_recent)
        self.recent_box = QFrame()
        self.recent_box.setObjectName("RecentBox")
        self.recent_list = QVBoxLayout(self.recent_box)
        self.recent_list.setContentsMargins(0, 0, 0, 0)
        self.recent_list.setSpacing(0)
        rw_lay.addWidget(self.recent_box)
        body.addWidget(self.recent_wrap)

        body.addStretch(1)

        self.set_target_kind("all")
        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.retranslate_ui()

    def set_target_kind(self, code: str) -> None:
        if code not in self._target_cards:
            code = "all"
        self._target_kind = code
        for k, card in self._target_cards.items():
            card.set_selected(k == code)
        self.diagram.set_mode(code)
        self.diagram.setVisible(code == "all")
        self._update_action_labels()

    def selected_target_kind(self) -> str:
        return self._target_kind

    def _update_action_labels(self) -> None:
        is_gateway_bus = self._target_kind == "all"
        read_map = {
            "all": tr("Считать блок", "Read ECU"),
            "j533": tr("Считать 19 J533", "Read 19 J533"),
            "fpke": tr("Считать 17 Панель", "Read 17 Cluster"),
            "bcm": tr("Считать 09 BCM", "Read 09 BCM"),
            "mrr": tr("Считать 13 Радар", "Read 13 Radar"),
            "elv": tr("Считать 2B ELV", "Read 2B ELV"),
        }
        proto_map = {
            "all": tr("500 кбит/с · Шлюз + ведомые", "500 kbit/s · Gateway + slaves"),
            "j533": tr("500 кбит/с · Прямой CAN 0x710 / 0x77A", "500 kbit/s · Direct CAN 0x710 / 0x77A"),
            "fpke": tr("500 кбит/с · Прямой CAN 0x714 / 0x77E", "500 kbit/s · Direct CAN 0x714 / 0x77E"),
            "bcm": tr("500 кбит/с · Прямой CAN 0x70E / 0x778", "500 kbit/s · Direct CAN 0x70E / 0x778"),
            "mrr": tr("500 кбит/с · Extended CAN · 0x757 / 0x7C1", "500 kbit/s · Extended CAN · 0x757 / 0x7C1"),
            "elv": tr("500 кбит/с · Komfort CAN · 0x731 / 0x79B", "500 kbit/s · Komfort CAN · 0x731 / 0x79B"),
        }
        self.btn_scan.setText(tr("Сканировать шину", "Scan CAN bus"))
        self.btn_scan.setVisible(is_gateway_bus)
        self.btn_read.setText(read_map.get(self._target_kind, read_map["all"]))
        self.btn_read.setVisible(not is_gateway_bus)
        self.btn_read.setEnabled(True)
        hide_restore = self._target_kind in ("fpke", "bcm", "mrr", "elv")
        self.btn_restore.setVisible(not hide_restore)
        if self._target_kind == "bcm":
            read_tip = tr(
                "Проверить связь по UDS, считать паспорт, статус, радиоключи FFB и ошибки DTC и открыть 09 BCM",
                "Check UDS link, read passport, status, FFB remote keys & DTCs, and open 09 BCM",
            )
        elif self._target_kind == "mrr":
            read_tip = tr(
                "Проверить связь по UDS, считать статус CP (7 точек Code Flash), ключи IKA/GFA (DFLASH0) и ошибки DTC радара 13 ACC",
                "Check UDS link, read CP patch status (7 Code Flash sites), IKA/GFA keys (DFLASH0), and DTCs for 13 ACC Radar",
            )
        elif self._target_kind == "elv":
            read_tip = tr(
                "Проверить связь, считать паспорт, 32 КБ Data Flash (VIN, ключ иммо, IDp/IDac) и ошибки 2B ELV",
                "Check link, read passport, 32 KB Data Flash (VIN, immo key, IDp/IDac), and 2B ELV fault codes",
            )
        else:
            read_tip = ""
        self.btn_read.setToolTip(read_tip)
        self.lbl_proto.setText(proto_map.get(self._target_kind, proto_map["all"]))

    def refresh_recent(self) -> None:
        clear_layout(self.recent_list)
        folders = recent_folders()[:5]
        self.recent_wrap.setVisible(bool(folders))
        for idx, folder in enumerate(folders):
            r = _RecentRow(folder, is_last=(idx == len(folders) - 1))
            r.clicked.connect(lambda f=folder: self.open_folder_requested.emit(str(f)))
            self.recent_list.addWidget(r)

    def retranslate_ui(self) -> None:
        self.lbl_title.setText(tr("Подключение к блокам", "Connect to ECU"))
        self.lbl_sub.setText(
            tr(
                "Выберите режим CAN или откройте локальные дампы",
                "Choose a CAN mode or open local dumps",
            )
        )
        self.lbl_can_eyebrow.setText(tr("ПОДКЛЮЧЕНИЕ ПО CAN", "CAN CONNECTION"))

        self._target_cards["all"].set_labels(
            tr("Шлюз + вся шина", "Gateway + bus"),
            "19, 17, 09, 13, 2B",
        )
        self._target_cards["j533"].set_labels(
            tr("Шлюз J533", "J533 Gateway"),
            "0x710 / 0x77A",
        )
        self._target_cards["fpke"].set_labels(
            tr("Панель приборов", "Instrument Cluster"),
            "FPK_E / Kombi · 0x714 / 0x77E",
        )
        self._target_cards["bcm"].set_labels(
            tr("Блок BCM J519", "BCM J519"),
            "0x70E / 0x778",
        )
        self._target_cards["mrr"].set_labels(
            tr("Радар ACC", "ACC Radar"),
            "MRR · 0x757 / 0x7C1",
        )
        self._target_cards["elv"].set_labels(
            tr("Защёлка руля ELV", "Steering Lock ELV"),
            "J764 · 0x731 / 0x79B",
        )

        self._update_action_labels()
        self.diagram.update()
        self.btn_restore.setText(tr("Залить бэкап…", "Write backup…"))
        self.btn_restore.setToolTip(
            tr(
                "Восстановить блок из сохранённого бэкапа (включая режим загрузчика FBL)",
                "Restore an ECU from a saved backup (including FBL bootloader recovery)",
            )
        )
        self.btn_wiring.setText(tr("Распиновка T20 / T18 / T4", "Pinout T20 / T18 / T4"))
        self.btn_wiring.setToolTip(
            tr("Схемы подключения на стенде и справка", "Bench wiring diagrams and reference guide")
        )

        self.lbl_files_title.setText(tr("Локальные дампы", "Local dumps"))
        self.lbl_files_sub.setText(
            tr(
                "Перетащите папку с дампами или файлы .bin в окно",
                "Drop a dump folder or .bin files into the window",
            )
        )
        self.btn_folder.setText(tr("Открыть папку…", "Open folder…"))
        self.btn_files.setText(tr("Выбрать файлы…", "Choose files…"))
        self.lbl_recent.setText(tr("НЕДАВНИЕ БЛОКИ", "RECENT ECUS"))
        self.refresh_recent()

    def _set_drop_highlight(self, active: bool) -> None:
        if self.drop_strip.property("drag") == active:
            return
        self.drop_strip.setProperty("drag", active)
        self.drop_strip.style().unpolish(self.drop_strip)
        self.drop_strip.style().polish(self.drop_strip)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            self._set_drop_highlight(True)
            event.acceptProposedAction()

    def dragLeaveEvent(self, _event: QDragLeaveEvent) -> None:
        self._set_drop_highlight(False)

    def dropEvent(self, event: QDropEvent) -> None:
        self._set_drop_highlight(False)
        paths = [Path(u.toLocalFile()) for u in event.mimeData().urls() if u.toLocalFile()]
        if paths:
            self.files_dropped.emit(paths)
            event.acceptProposedAction()
