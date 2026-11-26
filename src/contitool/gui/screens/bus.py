"""CAN Bus Topology & Multi-ECU Workbench Screen.

Displays the discovered CAN topology with a live vector schematic and structured ECU cards:
  - **Level 2 (Via J533 Gateway)**: Master J533 (`19 · 0x710/0x77A`) + connected slaves behind it
    (`17` Kombi / FPK_E `0x714/0x77E`, `09` BCM `0x70E/0x778`) with transparent RAM-Bridge status (`ch3 ↔ ch0`).
  - **Level 1 (Direct CAN)**: Direct bench connection to individual ECUs.
"""

from __future__ import annotations

import os
from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
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
from shiboken6 import isValid as _qt_valid

from contitool.can.ecus import (
    BusScanResult,
    DiscoveredEcu,
    can_uds_clear_dtc,
    can_uds_read_dtc,
)
from contitool.gui import theme
from contitool.gui.connection import CanConnection, ensure_ready
from contitool.gui.screens.fpke import FpkeDtcDialog
from contitool.gui.theme import mono_font, set_tone, ui_font
from contitool.gui.widgets.page import (
    Callout,
    Section,
    button,
    group_label,
    run_dialog,
    status_readout,
    vdivider,
)
from contitool.gui.worker import OperationRunner
from contitool.i18n import subscribe_lang_change, tr


class _LiveTopologyDiagram(QWidget):
    """Antialiased vector schematic visualizing the actually discovered CAN nodes and bridge route."""

    def __init__(self, scan_result: BusScanResult, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._res = scan_result
        n_slaves = max(1, len(scan_result.slaves)) if scan_result.topology == "gateway" else max(1, len(scan_result.ecus))
        self.setFixedHeight(max(78, 22 + n_slaves * 34))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def paintEvent(self, _event: Any) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

        w, h = float(self.width()), float(self.height())
        bg = QPainterPath()
        bg.addRoundedRect(QRectF(0.5, 0.5, w - 1.0, h - 1.0), 8.0, 8.0)
        p.fillPath(bg, QColor("#121317"))
        p.setPen(QPen(QColor("#23262F"), 1.0))
        p.drawPath(bg)

        cy = h / 2.0
        f_title = mono_font(11, bold=True)
        f_sub = mono_font(10)
        pad = 18.0

        def draw_box(x: float, y: float, bw: float, bh: float, title: str, sub: str, accent: str) -> QRectF:
            rect = QRectF(x, y, bw, bh)
            path = QPainterPath()
            path.addRoundedRect(rect, 6.0, 6.0)
            fill = "#16251F" if accent == theme.OK else ("#172236" if accent == theme.ACCENT else "#1A1C23")
            p.fillPath(path, QColor(fill))
            p.setPen(QPen(QColor(accent), 1.25))
            p.drawPath(path)
            p.setFont(f_title)
            p.setPen(QColor(theme.TEXT))
            p.drawText(QRectF(x + 9, y + 4, bw - 18, bh * 0.48), Qt.AlignmentFlag.AlignVCenter, title)
            p.setFont(f_sub)
            p.setPen(QColor(accent if accent != "#3C4252" else theme.TEXT_MUTED))
            p.drawText(QRectF(x + 9, y + bh * 0.48, bw - 18, bh * 0.46), Qt.AlignmentFlag.AlignVCenter, sub)
            return rect

        def draw_arrow(x1: float, y1: float, x2: float, y2: float, color: str, dashed: bool = False) -> None:
            pen = QPen(QColor(color), 1.4)
            if dashed:
                pen.setStyle(Qt.PenStyle.DashLine)
            p.setPen(pen)
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2))
            p.setPen(QPen(QColor(color), 1.4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawLine(QPointF(x2 - 5.0, y2 - 3.0), QPointF(x2, y2))
            p.drawLine(QPointF(x2 - 5.0, y2 + 3.0), QPointF(x2, y2))

        host_w = min(148.0, w * 0.17)
        node_h = 46.0
        iface_lbl = (self._res.interface or "slcan").upper()
        host_r = draw_box(pad, cy - node_h / 2.0, host_w, node_h, f"{iface_lbl} 500k", "Diag CAN", "#3C4252")

        if self._res.topology == "gateway" and self._res.gateway is not None:
            gw = self._res.gateway
            gw_w = min(210.0, w * 0.25)
            sl_w = min(230.0, w * 0.27)
            gw_x = host_r.right() + max(72.0, (w - pad * 2 - host_w - gw_w - sl_w) * 0.40)
            gw_accent = theme.OK if self._res.gateway_bridge_capable else theme.INFO
            gw_sub = f"SW {gw.sw_version} (0x710)" if gw.sw_version else "0x710 / 0x77A"
            gw_r = draw_box(
                gw_x,
                cy - node_h / 2.0,
                gw_w,
                node_h,
                f"[19] {gw.part_number}",
                gw_sub,
                gw_accent,
            )
            draw_arrow(host_r.right() + 5, cy, gw_r.left() - 5, cy, theme.INFO)
            p.setFont(f_sub)
            p.setPen(QColor(theme.TEXT_SECONDARY))
            p.drawText(QRectF(host_r.right() + 4, cy - 16, gw_r.left() - host_r.right() - 8, 14), Qt.AlignmentFlag.AlignCenter, "ch3 Diag")

            slaves = self._res.slaves
            sl_x = w - pad - sl_w
            trunk_col = theme.OK if self._res.gateway_bridge_capable else "#4C556B"
            branch_x = gw_r.right() + (sl_x - gw_r.right()) * 0.62
            bus_chs = sorted({int(sl.gateway_channel) for sl in slaves if sl.gateway_channel is not None})
            if bus_chs == [2]:
                ch_str, bus_name = "ch2", "Extended CAN"
            elif 0 in bus_chs and 2 in bus_chs:
                ch_str, bus_name = "ch0/ch2", "Komfort / Extended"
            elif bus_chs:
                ch_str = "/".join(f"ch{c}" for c in bus_chs)
                bus_name = "Komfort CAN"
            else:
                ch_str, bus_name = "ch0/ch2", "Komfort / Extended"
            p.setFont(f_sub)
            p.setPen(QColor(trunk_col))
            p.drawText(
                QRectF(gw_r.right() + 4, cy - 17, branch_x - gw_r.right() - 8, 14),
                Qt.AlignmentFlag.AlignCenter,
                f"RAM-Bridge {ch_str}" if self._res.gateway_bridge_capable else "UDS routing",
            )
            p.setPen(QColor(theme.TEXT_MUTED))
            p.drawText(
                QRectF(gw_r.right() + 4, cy + 3, branch_x - gw_r.right() - 8, 14),
                Qt.AlignmentFlag.AlignCenter,
                bus_name,
            )

            if slaves:
                row_h = 28.0
                gap_y = 6.0
                total_h = len(slaves) * row_h + (len(slaves) - 1) * gap_y
                y0 = cy - total_h / 2.0
                ys = [y0 + i * (row_h + gap_y) + row_h / 2.0 for i in range(len(slaves))]

                p.setPen(QPen(QColor(trunk_col), 1.4))
                p.drawLine(QPointF(gw_r.right() + 5, cy), QPointF(branch_x, cy))
                p.drawLine(QPointF(branch_x, min(ys)), QPointF(branch_x, max(ys)))

                for idx, sl in enumerate(slaves):
                    ry = y0 + idx * (row_h + gap_y)
                    rect = QRectF(sl_x, ry, sl_w, row_h)
                    col = (
                        theme.CAN
                        if sl.kind == "fpke"
                        else (theme.ACCENT if sl.kind == "mrr" else (theme.WARN if sl.kind == "elv" else theme.INFO))
                    )
                    draw_arrow(branch_x, rect.center().y(), rect.left() - 5, rect.center().y(), col if sl.memory_access_available else "#586278", dashed=not sl.memory_access_available)
                    sp = QPainterPath()
                    sp.addRoundedRect(rect, 5.0, 5.0)
                    p.fillPath(sp, QColor("#1A1C23"))
                    p.setPen(QPen(QColor(col if sl.memory_access_available else "#363B48"), 1.1))
                    p.drawPath(sp)
                    p.setFont(f_title)
                    p.setPen(QColor(col))
                    p.drawText(QRectF(rect.x() + 8, rect.y(), 24, rect.height()), Qt.AlignmentFlag.AlignVCenter, sl.diag_addr)
                    p.setFont(f_sub)
                    p.setPen(QColor(theme.TEXT))
                    p.drawText(
                        QRectF(rect.x() + 30, rect.y(), rect.width() - 86, rect.height()),
                        Qt.AlignmentFlag.AlignVCenter,
                        sl.part_number,
                    )
                    p.setPen(QColor(theme.TEXT_MUTED))
                    p.drawText(
                        QRectF(rect.right() - 56, rect.y(), 48, rect.height()),
                        Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                        f"0x{sl.uds_tx_id:03X}",
                    )
            else:
                draw_arrow(gw_r.right() + 5, cy, sl_x - 5, cy, "#3A4050", dashed=True)
                sp = QPainterPath()
                rect = QRectF(sl_x, cy - 14, sl_w, 28)
                sp.addRoundedRect(rect, 5.0, 5.0)
                p.fillPath(sp, QColor("#16181D"))
                p.setPen(QPen(QColor("#2A2E38"), 1.0, Qt.PenStyle.DashLine))
                p.drawPath(sp)
                p.setFont(f_sub)
                p.setPen(QColor(theme.TEXT_MUTED))
                empty_lbl = (
                    tr("Ведомые не опрашивались", "Slaves not probed")
                    if self._res.scanned_targets == ("j533",)
                    else tr("Ведомые не найдены", "No slaves detected")
                )
                p.drawText(rect, Qt.AlignmentFlag.AlignCenter, empty_lbl)
        else:
            ecus = self._res.ecus
            sl_w = min(260.0, w * 0.36)
            sl_x = w - pad - sl_w
            row_h = 34.0
            gap_y = 6.0
            total_h = len(ecus) * row_h + max(0, len(ecus) - 1) * gap_y
            y0 = cy - total_h / 2.0
            for idx, ecu in enumerate(ecus):
                ry = y0 + idx * (row_h + gap_y)
                col = (
                    theme.CAN
                    if ecu.kind == "fpke"
                    else (theme.ACCENT if ecu.kind == "mrr" else (theme.WARN if ecu.kind == "elv" else theme.OK))
                )
                r_e = draw_box(sl_x, ry, sl_w, row_h, f"[{ecu.diag_addr}] {ecu.part_number}", f"0x{ecu.uds_tx_id:03X} → 0x{ecu.uds_rx_id:03X}", col)
                draw_arrow(host_r.right() + 6, cy, r_e.left() - 6, r_e.center().y(), col)

        p.end()


class BusScreen(QWidget):
    """Interactive topology view of all ECUs discovered on Diagnosis CAN or a direct bench harness."""

    scan_requested = Signal(str)  # target_kind ("all", "j533", "fpke", "bcm", "mrr", "elv")
    read_ecu_requested = Signal(object)  # DiscoveredEcu
    restore_ecu_requested = Signal(object)  # DiscoveredEcu
    open_j533_workspace_requested = Signal()
    open_fpke_workspace_requested = Signal(object)  # DiscoveredEcu
    open_bcm_workspace_requested = Signal(object)  # DiscoveredEcu
    open_mrr_workspace_requested = Signal(object)  # DiscoveredEcu
    open_elv_workspace_requested = Signal(object)  # DiscoveredEcu
    open_terminal_requested = Signal(object)  # DiscoveredEcu
    back_requested = Signal()
    note = Signal(str)

    def __init__(
        self,
        conn: CanConnection,
        runner: OperationRunner,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.conn = conn
        self.runner = runner
        self.scan_result: BusScanResult | None = None
        self.target_kind: str = "all"
        self.j533_loaded: bool = False
        self.fpke_loaded: bool = False
        self.bcm_loaded: bool = False
        self.mrr_loaded: bool = False
        self.elv_loaded: bool = False
        self._dtc_cache: dict[str, list[dict[str, Any]]] = {}
        self._status_cache: dict[str, tuple[str, str]] = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_header())

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(self.scroll, 1)

        self.conn.changed.connect(self.refresh)
        self.runner.busy_changed.connect(lambda _b: self.refresh())
        self._unsub = subscribe_lang_change(lambda _l: self.refresh())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.refresh()

    @property
    def has_scan(self) -> bool:
        return self.scan_result is not None and bool(self.scan_result.ecus)

    def set_scan_result(self, result: BusScanResult) -> None:
        self.scan_result = result
        self.refresh()

    def clear_scan(self) -> None:
        if self.scan_result is not None:
            self.scan_result = None
            self._dtc_cache.clear()
            self._status_cache.clear()
            self.refresh()

    def set_loaded_flags(
        self,
        *,
        j533_loaded: bool,
        fpke_loaded: bool,
        bcm_loaded: bool = False,
        mrr_loaded: bool = False,
        elv_loaded: bool = False,
    ) -> None:
        if (
            self.j533_loaded != j533_loaded
            or self.fpke_loaded != fpke_loaded
            or self.bcm_loaded != bcm_loaded
            or self.mrr_loaded != mrr_loaded
            or self.elv_loaded != elv_loaded
        ):
            self.j533_loaded = j533_loaded
            self.fpke_loaded = fpke_loaded
            self.bcm_loaded = bcm_loaded
            self.mrr_loaded = mrr_loaded
            self.elv_loaded = elv_loaded
            self.refresh()

    def selected_target_kind(self) -> str:
        return "all"

    def _build_header(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("IdentityBar")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(24, 10, 24, 10)
        lay.setSpacing(10)

        self.lbl_title = QLabel()
        self.lbl_title.setObjectName("PartNumber")
        self.lbl_title.setFont(ui_font(17, bold=True))

        self.sep_top = vdivider()
        self.sep_top.setFixedHeight(14)

        self.lbl_topology = status_readout("", "info")

        lay.addWidget(self.lbl_title, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addWidget(self.sep_top, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addWidget(self.lbl_topology, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addStretch(1)

        self.btn_scan = button("", "PrimaryBtn", slot=self._emit_scan)
        self.btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        self.btn_back = button("", "GhostBtn", slot=self.back_requested.emit)
        self.btn_back.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_back.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        lay.addWidget(self.btn_scan, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addWidget(self.btn_back, 0, Qt.AlignmentFlag.AlignVCenter)
        return bar

    def _emit_scan(self) -> None:
        self.scan_requested.emit("all")

    def refresh(self) -> None:
        if not _qt_valid(self):
            return
        busy = self.runner.is_busy
        self.btn_scan.setText(tr("Сканировать", "Rescan") if self.has_scan else tr("Сканировать шину", "Scan bus"))
        self.btn_scan.setEnabled(not busy)
        self.btn_back.setText(tr("На главную", "Start"))

        res = self.scan_result
        if res is None or not res.ecus:
            self.lbl_title.setText(tr("Шина CAN", "CAN Bus"))
            self.lbl_topology.setText(tr("Нет данных", "Idle"))
            set_tone(self.lbl_topology, "muted")
        elif res.topology == "gateway":
            self.lbl_title.setText(tr(f"Шина CAN ({len(res.ecus)})", f"CAN Bus ({len(res.ecus)})"))
            if res.gateway_bridge_capable:
                bus_chs = sorted({int(sl.gateway_channel) for sl in res.slaves if sl.gateway_channel is not None})
                ch_s = "/".join(f"ch{c}" for c in bus_chs) if bus_chs else "ch0/ch2"
                self.lbl_topology.setText(tr(f"Через шлюз (RAM-мост {ch_s})", f"Via gateway (RAM-Bridge {ch_s})"))
                set_tone(self.lbl_topology, "ok")
            else:
                self.lbl_topology.setText(tr("Через шлюз (UDS)", "Via gateway (UDS)"))
                set_tone(self.lbl_topology, "info")
        else:
            self.lbl_title.setText(tr(f"Прямой CAN ({len(res.ecus)})", f"Direct CAN ({len(res.ecus)})"))
            self.lbl_topology.setText(tr("Прямое подключение", "Direct connection"))
            set_tone(self.lbl_topology, "info")
        self.lbl_topology.setVisible(True)

        self._render_body()

    def _render_body(self) -> None:
        page = QWidget()
        page.setObjectName("PageCanvas")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(28, 18, 28, 24)
        lay.setSpacing(12)

        res = self.scan_result
        if res is None or not res.ecus:
            empty = Section()
            empty.set_text(
                tr("Шина CAN не просканирована", "CAN bus not scanned"),
                tr(
                    "Подключите адаптер к CAN шлюза (T20: Pin 19 / 9) или напрямую к блоку (панель T18, защёлка ELV T4).",
                    "Connect to gateway CAN (T20: Pin 19 / 9) or directly to an ECU (cluster T18, ELV T4).",
                ),
            )
            btn_go = button(tr("Сканировать шину", "Scan CAN bus"), "PrimaryBtn", slot=self._emit_scan)
            btn_go.setEnabled(not self.runner.is_busy)
            empty.add_footer(btn_go)
            lay.addWidget(empty)
            lay.addStretch(1)
            self.scroll.setWidget(page)
            return

        # Live vector topology diagram instead of verbose text walls
        lay.addWidget(_LiveTopologyDiagram(res))

        if res.adapter_warning:
            warn = Callout("warn")
            warn.label.setText(res.adapter_warning)
            lay.addWidget(warn)

        if res.topology == "gateway":
            if res.gateway is not None:
                lay.addWidget(group_label(tr("ШЛЮЗ ДИАГНОСТИКИ (0x19)", "DIAGNOSTIC GATEWAY (0x19)")))
                lay.addWidget(self._build_ecu_card(res.gateway))

            only_gw_probed = res.scanned_targets == ("j533",)
            lay.addWidget(
                group_label(
                    tr(
                        f"ВЕДОМЫЕ БЛОКИ ЗА ШЛЮЗОМ ({len(res.slaves)})",
                        f"SLAVE ECUS BEHIND GATEWAY ({len(res.slaves)})",
                    )
                )
            )
            if res.slaves:
                for slave in res.slaves:
                    lay.addWidget(self._build_ecu_card(slave))
            elif only_gw_probed:
                no_sl = Section()
                no_sl.set_text(
                    tr("Опрашивался только шлюз 19 J533", "Only 19 J533 gateway was probed"),
                    tr(
                        "Просканируйте всю шину, чтобы найти панель (17), BCM (09), защёлку руля ELV (2B) и радар ACC (13) за шлюзом.",
                        "Scan the full bus to find the cluster (17), BCM (09), steering lock ELV (2B), and ACC radar (13) behind the gateway.",
                    ),
                )
                btn_all = button(
                    tr("Сканировать всю шину", "Scan full bus"),
                    slot=lambda: self.scan_requested.emit("all"),
                )
                btn_all.setEnabled(not self.runner.is_busy)
                no_sl.add_footer(btn_all)
                lay.addWidget(no_sl)
            else:
                no_sl = Section()
                no_sl.set_text(
                    tr("Ведомые блоки не ответили", "No slave ECUs responded"),
                    tr(
                        "Проверьте питание ведомых блоков и шины шлюза: Komfort CAN ch0 (T20 Pin 5 / 15: 17 Kombi, 09 BCM, 2B ELV) "
                        "или Extended CAN ch2 (T20 Pin 7 / 17: 13 ACC).",
                        "Check slave power and gateway buses: Komfort CAN ch0 (T20 Pin 5 / 15: 17 Kombi, 09 BCM, 2B ELV) "
                        "or Extended CAN ch2 (T20 Pin 7 / 17: 13 ACC).",
                    ),
                )
                lay.addWidget(no_sl)
        else:
            lay.addWidget(group_label(tr("ПРЯМОЕ ПОДКЛЮЧЕНИЕ CAN", "DIRECT CAN CONNECTION")))
            for ecu in res.ecus:
                lay.addWidget(self._build_ecu_card(ecu))

        lay.addStretch(1)
        self.scroll.setWidget(page)

    def _build_ecu_card(self, ecu: DiscoveredEcu) -> QWidget:
        busy = self.runner.is_busy
        sec = Section()
        sec.head.setContentsMargins(16, 12, 16, 4)
        sec.body.setContentsMargins(16, 4, 16, 10)
        sec.body.setSpacing(8)

        # Replace plain title with address badge + mono part number + sans short name + mono CAN IDs
        addr_badge = QLabel(ecu.diag_addr)
        addr_badge.setObjectName("AddrBadge")
        addr_badge.setFont(mono_font(11, bold=True))
        addr_tone = "ok" if ecu.kind == "j533" else ("can" if ecu.kind == "fpke" else "accent")
        set_tone(addr_badge, addr_tone)
        sec.head.insertWidget(0, addr_badge, 0, Qt.AlignmentFlag.AlignVCenter)

        sec.lbl_title.setText(ecu.part_number)
        sec.lbl_title.setFont(mono_font(13, bold=True))

        lbl_short = QLabel(ecu.spec.short_name)
        lbl_short.setObjectName("Hint")
        sec.head.insertWidget(2, lbl_short, 0, Qt.AlignmentFlag.AlignVCenter)

        id_tag = QLabel(f"0x{ecu.uds_tx_id:03X}→0x{ecu.uds_rx_id:03X}")
        id_tag.setObjectName("DumpTag")
        id_tag.setFont(mono_font(10))
        sec.head.insertWidget(3, id_tag, 0, Qt.AlignmentFlag.AlignVCenter)

        if ecu.unsupported_reason:
            tone = "err"
        elif ecu.in_fbl:
            tone = "warn"
        elif ecu.memory_access_available:
            tone = "ok"
        else:
            tone = "info"
        badge = status_readout(ecu.access_summary, tone)
        sec.head.addWidget(badge, 0, Qt.AlignmentFlag.AlignVCenter)

        if ecu.unsupported_reason:
            un_box = Callout("err")
            un_box.label.setText(ecu.unsupported_reason)
            sec.body.addWidget(un_box)

        # Compact tabular passport columns
        vals = {it.get("did", ""): it.get("value", "").strip() for it in ecu.ident}
        fields: list[tuple[str, str]] = []
        if vals.get("F197"):
            fields.append((tr("СИСТЕМА", "SYSTEM"), vals["F197"]))
        if vals.get("F189"):
            fields.append(("SW (F189)", vals["F189"]))
        if vals.get("F191"):
            hw_v = vals.get("F1A3")
            fields.append(("HW (F191)", f"{vals['F191']} / {hw_v}" if hw_v else vals["F191"]))
        if vals.get("F19E"):
            fields.append(("ODX (F19E)", vals["F19E"]))
        if vals.get("0600"):
            fields.append(("CODING (0600)", vals["0600"]))
        if vals.get("F17C"):
            fields.append(("FAZIT", vals["F17C"]))

        if fields:
            grid = QGridLayout()
            grid.setHorizontalSpacing(22)
            grid.setVerticalSpacing(2)
            for col, (k, v) in enumerate(fields):
                lbl_k = QLabel(k)
                lbl_k.setObjectName("GroupLabel")
                lbl_v = QLabel(v)
                lbl_v.setFont(mono_font(12))
                lbl_v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                grid.addWidget(lbl_k, 0, col)
                grid.addWidget(lbl_v, 1, col)
            grid.setColumnStretch(len(fields), 1)
            sec.body.addLayout(grid)

        # Inline DTC / status strip
        st_entry = self._status_cache.get(ecu.diag_addr)
        dtcs = self._dtc_cache.get(ecu.diag_addr)
        if st_entry is not None:
            strip = QFrame()
            strip.setObjectName("ResultStrip")
            sl = QHBoxLayout(strip)
            sl.setContentsMargins(12, 5, 12, 5)
            sl.setSpacing(10)
            lbl_st = QLabel(st_entry[0])
            lbl_st.setWordWrap(True)
            set_tone(lbl_st, st_entry[1])
            sl.addWidget(lbl_st, 1)
            if dtcs:
                btn_list = button(
                    tr("Список…", "List…"),
                    "Chip",
                    slot=lambda e=ecu: self._show_dtc_dialog(e),
                )
                btn_list.setCursor(Qt.CursorShape.PointingHandCursor)
                sl.addWidget(btn_list, 0, Qt.AlignmentFlag.AlignVCenter)
            sec.body.addWidget(strip)

        # Footer action bar: bordered primary/tool buttons on left, secondary/recovery ghost actions neatly grouped
        left_actions: list[QWidget] = []
        right_actions: list[QWidget] = []
        if ecu.kind == "j533":
            btn_read = button(
                tr("Считать память", "Read memory"),
                "PrimaryBtn",
                slot=lambda e=ecu: self.read_ecu_requested.emit(e),
            )
            btn_read.setEnabled(not busy and ecu.memory_access_available and not ecu.in_fbl)
            left_actions.append(btn_read)

            if self.j533_loaded:
                btn_open = button(
                    tr("Открыть 19", "Open 19"),
                    slot=self.open_j533_workspace_requested.emit,
                )
                btn_open.setEnabled(not busy)
                left_actions.append(btn_open)

            btn_restore = button(
                tr("Залить бэкап…", "Write backup…"),
                "PrimaryBtn" if ecu.in_fbl else "GhostBtn",
                slot=lambda e=ecu: self.restore_ecu_requested.emit(e),
            )
            btn_restore.setEnabled(not busy and not ecu.unsupported_reason)
            (left_actions if ecu.in_fbl else right_actions).append(btn_restore)
        elif ecu.kind == "fpke":
            btn_read_fpk = button(
                tr("Считать (Level 8)", "Read (Level 8)"),
                "PrimaryBtn",
                slot=lambda e=ecu: self.read_ecu_requested.emit(e),
            )
            btn_read_fpk.setEnabled(not busy and ecu.memory_access_available)
            left_actions.append(btn_read_fpk)

            btn_open_fpk = button(
                tr("Открыть 17", "Open 17") if self.fpke_loaded else tr("Панель 17 (UDS)", "Workbench 17"),
                slot=lambda e=ecu: self.open_fpke_workspace_requested.emit(e),
            )
            btn_open_fpk.setEnabled(not busy)
            left_actions.append(btn_open_fpk)

            btn_restore_fpk = button(
                tr("Залить Dflash…", "Write Dflash…"),
                "GhostBtn",
                slot=lambda e=ecu: self.restore_ecu_requested.emit(e),
            )
            btn_restore_fpk.setEnabled(not busy and ecu.memory_access_available)
            right_actions.append(btn_restore_fpk)
        elif ecu.kind == "bcm":
            btn_read_bcm = button(
                tr("Считать 09 BCM", "Read 09 BCM"),
                "PrimaryBtn",
                slot=lambda e=ecu: self.read_ecu_requested.emit(e),
            )
            btn_read_bcm.setEnabled(not busy and not ecu.unsupported_reason)
            left_actions.append(btn_read_bcm)

            if self.bcm_loaded:
                btn_open_bcm = button(
                    tr("Открыть 09", "Open 09"),
                    slot=lambda e=ecu: self.open_bcm_workspace_requested.emit(e),
                )
                btn_open_bcm.setEnabled(not busy)
                left_actions.append(btn_open_bcm)
        elif ecu.kind == "mrr":
            btn_read_mrr = button(
                tr("Считать 13 Радар", "Read 13 Radar"),
                "PrimaryBtn",
                slot=lambda e=ecu: self.read_ecu_requested.emit(e),
            )
            btn_read_mrr.setEnabled(not busy and not ecu.unsupported_reason)
            left_actions.append(btn_read_mrr)

            btn_open_mrr = button(
                tr("Открыть 13", "Open 13") if self.mrr_loaded else tr("Рабочее место 13", "Workbench 13"),
                slot=lambda e=ecu: self.open_mrr_workspace_requested.emit(e),
            )
            btn_open_mrr.setEnabled(not busy)
            left_actions.append(btn_open_mrr)
        elif ecu.kind == "elv":
            btn_read_elv = button(
                tr("Считать 2B ELV", "Read 2B ELV"),
                "PrimaryBtn",
                slot=lambda e=ecu: self.read_ecu_requested.emit(e),
            )
            btn_read_elv.setEnabled(not busy and not ecu.unsupported_reason)
            left_actions.append(btn_read_elv)

            btn_open_elv = button(
                tr("Открыть 2B", "Open 2B") if self.elv_loaded else tr("Рабочее место 2B", "Workbench 2B"),
                slot=lambda e=ecu: self.open_elv_workspace_requested.emit(e),
            )
            btn_open_elv.setEnabled(not busy)
            left_actions.append(btn_open_elv)

        btn_dtc = button(
            tr("Ошибки DTC", "Read DTCs"),
            "PrimaryBtn" if ecu.kind not in ("j533", "fpke", "bcm", "mrr", "elv") else "",
            slot=lambda e=ecu: self._read_ecu_dtcs(e),
        )
        btn_dtc.setEnabled(not busy)
        left_actions.append(btn_dtc)

        btn_clr = button(
            tr("Сброс DTC", "Clear DTCs"),
            "GhostBtn",
            slot=lambda e=ecu: self._clear_ecu_dtcs(e),
        )
        btn_clr.setEnabled(not busy)
        left_actions.append(btn_clr)

        if ecu.kind not in ("j533", "fpke"):
            btn_term = button(
                tr("CAN-терминал", "CAN terminal"),
                "",
                slot=lambda e=ecu: self.open_terminal_requested.emit(e),
            )
            btn_term.setEnabled(not busy)
            right_actions.append(btn_term)

        for b in (*left_actions, *right_actions):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        foot = sec.add_footer(*left_actions)
        for b in right_actions:
            foot.addWidget(b)
        foot.setContentsMargins(16, 2, 16, 12)
        return sec

    def _read_ecu_dtcs(self, ecu: DiscoveredEcu) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface

        def task(rep: Any) -> dict[str, Any]:
            return can_uds_read_dtc(
                port,
                ecu.uds_tx_id,
                ecu.uds_rx_id,
                interface=iface,
                ecu_kind=ecu.kind,
                via_gateway=ecu.via_gateway,
                reporter=rep,
            )

        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self):
                return
            dtcs = list(res.get("dtcs") or [])
            self._dtc_cache[ecu.diag_addr] = dtcs
            if dtcs:
                act = int(res.get("active_count", 0))
                sto = int(res.get("stored_count", 0))
                preview = "; ".join(f"{d['display']} — {d['description']}" for d in dtcs[:2])
                msg = tr(
                    f"[{ecu.diag_addr}] Ошибок: {len(dtcs)} (акт.: {act}, пам.: {sto}) — {preview}",
                    f"[{ecu.diag_addr}] {len(dtcs)} DTC(s) ({act} active, {sto} stored) — {preview}",
                )
                tone = "warn" if act > 0 else "info"
            else:
                msg = tr(f"[{ecu.diag_addr}] Ошибок нет.", f"[{ecu.diag_addr}] No fault codes.")
                tone = "ok"
            self._status_cache[ecu.diag_addr] = (msg, tone)
            self.note.emit(msg)
            self.refresh()
            if (
                dtcs
                and self.window().isVisible()
                and os.environ.get("QT_QPA_PLATFORM") != "offscreen"
            ):
                self._show_dtc_dialog(ecu)

        self.runner.run_task(
            tr(f"DTC [{ecu.diag_addr}] {ecu.part_number}", f"DTCs [{ecu.diag_addr}] {ecu.part_number}"),
            task,
            on_success=lambda res: QTimer.singleShot(0, lambda: done(res)),
        )

    def _clear_ecu_dtcs(self, ecu: DiscoveredEcu) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface

        def task(rep: Any) -> dict[str, Any]:
            return can_uds_clear_dtc(
                port,
                ecu.uds_tx_id,
                ecu.uds_rx_id,
                interface=iface,
                ecu_kind=ecu.kind,
                via_gateway=ecu.via_gateway,
                reporter=rep,
            )

        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self):
                return
            self._dtc_cache[ecu.diag_addr] = []
            msg = f"[{ecu.diag_addr}] " + str(res.get("summary") or tr("Ошибки сброшены.", "DTCs cleared."))
            self._status_cache[ecu.diag_addr] = (msg, "ok")
            self.note.emit(msg)
            self.refresh()

        self.runner.run_task(
            tr(f"Сброс DTC [{ecu.diag_addr}] {ecu.part_number}", f"Clear DTCs [{ecu.diag_addr}] {ecu.part_number}"),
            task,
            on_success=lambda res: QTimer.singleShot(0, lambda: done(res)),
        )

    def _show_dtc_dialog(self, ecu: DiscoveredEcu) -> None:
        dtcs = self._dtc_cache.get(ecu.diag_addr) or []
        if not dtcs:
            return
        dlg = FpkeDtcDialog(
            dtcs,
            part_number=f"[{ecu.diag_addr}] {ecu.part_number}",
            clear_callback=None,
            parent=self.window(),
        )
        run_dialog(dlg)
