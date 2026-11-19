"""Working screen for VAG MQB 09 BCM / J519 (Continental MPC5607B): KS (IKA/GFA) read/write and WFS Ch 3 FFB adaptation."""

from __future__ import annotations

from collections.abc import Callable
import json
from pathlib import Path
import secrets as _py_secrets
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid as _qt_valid

from contitool.can.bcm import (
    can_bcm_adapt_ffb,
    can_bcm_adapt_ffb_from_cluster,
    can_bcm_read_all,
    can_bcm_read_gfa,
    can_bcm_read_keys,
    can_bcm_status,
    can_bcm_write_keys,
)
from contitool.can.ecus import DiscoveredEcu, can_uds_clear_dtc, can_uds_read_dtc
from contitool.core.bcm import (
    BCM_FREQUENCIES,
    BCM_UDS_RX_ID,
    BCM_UDS_TX_ID,
    bcm_derive_k_ffb,
    bcm_detect_profile,
    bcm_extract_cluster_ffb_material,
)
from contitool.gui import theme
from contitool.gui.connection import CanConnection, ensure_ready
from contitool.gui.theme import mono_font, set_tone
from contitool.gui.widgets.page import (
    Callout,
    Dialog,
    Section,
    TextResultDialog,
    button,
    clear_layout,
    divider,
    group_label,
    hint,
    pill,
    run_dialog,
    set_pill,
    status_readout,
    vdivider,
)
from contitool.gui.worker import OperationRunner
from contitool.i18n import subscribe_lang_change, tr

BCM_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("main", ("cp_keys", "ffb")),
    ("service", ("status", "dtc")),
)


class BcmReadKeysDialog(Dialog):
    """Confirmation dialog shown before keyless WFS Ch 3 + XCP extraction of IKA / GFA on 09 BCM."""

    def __init__(
        self,
        *,
        include_ika: bool = True,
        status: dict[str, Any] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        title = (
            tr("Чтение ключей IKA и GFA", "Read IKA & GFA keys")
            if include_ika
            else tr("Чтение группового ключа GFA", "Read GFA group key")
        )
        subtitle = tr(
            "Чтение ключей защиты компонентов через канал 3 WFS (0x17F8140E) и агент XCP (0x17FE5600).",
            "Reading Component Protection keys via WFS Channel 3 (0x17F8140E) and the XCP agent (0x17FE5600).",
        )
        super().__init__(parent, title, subtitle, width=620)

        st = status or {}
        slots = st.get("ffb_slots") or []
        pop_count = sum(1 for s in slots if s.get("populated")) or int(st.get("ffb_learned_count") or 0)

        if include_ika:
            what_text = tr(
                "<b>Что будет делать программа:</b><br>"
                "• Подключится к агенту XCP и каналу 3 WFS в оперативной памяти блока 09 BCM.<br>"
                "• Запустит <code>Crypto Job 5</code> и двухпроходную очередь <code>Crypto Job 3</code> в SRAM для извлечения "
                "ключей <b>GFA</b> и <b>IKA</b> без их перезаписи во Flash.<br>"
                "• Выполнит аппаратный перезапуск блока (<code>UDS 11 01</code> HardReset) для полной очистки ОЗУ.",
                "<b>What ContiTool will do:</b><br>"
                "• Connect to the XCP agent and WFS Channel 3 in 09 BCM SRAM.<br>"
                "• Run <code>Crypto Job 5</code> and a two-pass <code>Crypto Job 3</code> queue in SRAM to extract "
                "<b>GFA</b> and <b>IKA</b> without altering them in Flash.<br>"
                "• Perform a hardware reset (<code>UDS 11 01</code> HardReset) to restore clean SRAM.",
            )
        else:
            what_text = tr(
                "<b>Что будет делать программа:</b><br>"
                "• Подключится к агенту XCP и запустит задачу <code>Crypto Job 5</code> на канале 3 WFS (<code>80 01</code>) "
                "для чтения группового ключа <b>GFA</b> из ОЗУ блока.",
                "<b>What ContiTool will do:</b><br>"
                "• Connect to the XCP agent and trigger <code>Crypto Job 5</code> on WFS Channel 3 (<code>80 01</code>) "
                "to read the vehicle group key <b>GFA</b> from SRAM.",
            )
        what_lbl = hint(what_text)
        what_lbl.setTextFormat(Qt.TextFormat.RichText)
        self.body.addWidget(what_lbl)

        cp_warn = Callout("warn")
        cp_warn.label.setText(
            tr(
                "<b>Защита компонентов (SAFE CP):</b> во время процедуры и перезапуска на стенде (без активного обмена со "
                "шлюзом <code>19 J533</code>) блок перейдёт в состояние активной защиты компонентов "
                "(<code>SAFE CP</code>, ошибка <code>U110100</code> / <code>DID 0x03DE</code>).<br>"
                "Сами ключи <b>IKA</b> и <b>GFA</b> в памяти блока <b>не изменяются</b> — после подключения к шлюзу и первого "
                "валидного KS-хендшейка от гейтвея защита компонентов CP будет автоматически снята.",
                "<b>Component Protection (SAFE CP):</b> during this procedure and reset on the bench (without an active "
                "<code>19 J533</code> gateway on the bus), the BCM will enter active Component Protection "
                "(<code>SAFE CP</code>, DTC <code>U110100</code> / <code>DID 0x03DE</code>).<br>"
                "The <b>IKA</b> and <b>GFA</b> keys in memory are <b>not modified</b> — Component Protection clears "
                "automatically after the first valid KS handshake from the gateway.",
            )
        )
        self.body.addWidget(cp_warn)

        ffb_info = Callout("info")
        if pop_count > 0:
            ffb_info.label.setText(
                tr(
                    f"<b>Радиоключи FFB (обнаружено ключей: {pop_count}):</b> команда <code>80 01</code> в прошивке BCM временно "
                    "сбрасывает секрет радиоканала <code>K_ffb</code> (<code>NvM 0x02</code>) и слоты радиоключей "
                    "(<code>NvM 0x13..0x19</code>, <code>0x05..0x0B</code>). Программа предварительно извлечёт текущий "
                    "<code>K_ffb</code> и данные всех слотов, а в конце операции <b>автоматически запишет их обратно "
                    "(<code>80 01</code> + <code>80 02</code>)</b>.",
                    f"<b>FFB remote keys ({pop_count} learned):</b> BCM command <code>80 01</code> temporarily clears "
                    "the radio secret <code>K_ffb</code> (<code>NvM 0x02</code>) and key slots "
                    "(<code>NvM 0x13..0x19</code>, <code>0x05..0x0B</code>). ContiTool backs up <code>K_ffb</code> and all "
                    "learned slots first and <b>automatically restores them (<code>80 01</code> + <code>80 02</code>)</b> "
                    "at the end of the read.",
                )
            )
        else:
            ffb_info.label.setText(
                tr(
                    "<b>Радиоключи FFB:</b> вызов <code>80 01</code> затрагивает область радиоканала (<code>NvM 0x02</code> и "
                    "слоты <code>NvM 0x13..0x19</code>, <code>0x05..0x0B</code>). Если в блоке есть обученные радиоключи, "
                    "программа предварительно сохраняет <code>K_ffb</code> и слоты и автоматически восстанавливает их в конце чтения.",
                    "<b>FFB remote keys:</b> calling <code>80 01</code> touches the FFB area (<code>NvM 0x02</code> and "
                    "slots <code>NvM 0x13..0x19</code>, <code>0x05..0x0B</code>). If any FFB keys are stored in the BCM, "
                    "ContiTool backs up <code>K_ffb</code> and all slots beforehand and restores them automatically.",
                )
            )
        self.body.addWidget(ffb_info)

        ok_lbl = tr("Считать IKA + GFA", "Read IKA + GFA") if include_ika else tr("Считать GFA", "Read GFA")
        self.btn_ok = button(ok_lbl, "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)


def _bcm_nav_title(key: str) -> str:
    return {
        "cp_keys": tr("Защита компонентов", "Component protection"),
        "ffb": tr("Радиоключи FFB", "FFB remote keys"),
        "status": tr("Паспорт и статус", "Passport & status"),
        "dtc": tr("Ошибки (DTC)", "Fault codes (DTC)"),
    }[key]


class _BcmNavRow(QWidget):
    """Unified ContiTool sidebar row: function name on the left, quiet semantic status pill on the right."""

    def __init__(self) -> None:
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 0, 10, 0)
        lay.setSpacing(8)
        self.lbl_name = QLabel()
        self.pill = pill()
        lay.addWidget(self.lbl_name, 1)
        lay.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_active(self, active: bool) -> None:
        f = self.lbl_name.font()
        f.setWeight(f.Weight.DemiBold if active else f.Weight.Normal)
        self.lbl_name.setFont(f)
        self.lbl_name.setStyleSheet(f"color: {'#FFFFFF' if active else theme.TEXT};")


class BcmScreen(QWidget):
    """Unified workspace for 09 BCM / J519 matching EcuScreen (19 J533) and FpkeScreen (17 FPK_E)."""

    changed = Signal()
    close_requested = Signal()
    open_terminal_requested = Signal(str)
    note = Signal(str)

    def __init__(
        self,
        conn: CanConnection,
        runner: OperationRunner,
        *,
        cluster_provider: Callable[[], dict[str, Any] | None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.conn = conn
        self.runner = runner
        self._cluster_provider = cluster_provider
        self._is_open = False
        self._via_gateway = False
        self._gateway_bridge = False
        self._gateway_channel = 0
        self._passport: dict[str, Any] = {}
        self._status: dict[str, Any] = {}
        self._profile: dict[str, Any] = bcm_detect_profile()
        self._profile_override: str = ""  # "", "ea_0511", "dd_0273"
        self._ika_hex: str = ""
        self._gfa_hex: str = ""
        self._cluster_material: dict[str, Any] | None = None
        self._dtcs: list[dict[str, Any]] | None = None
        self._key = "cp_keys"

        # Persistent form drafts across page re-renders
        self._draft_cur_ika: str = ""
        self._draft_new_ika: str = ""
        self._draft_new_gfa: str = ""
        self._draft_write_reset: bool = True
        self._draft_ffb_gfa: str = ""
        self._draft_ffb_kc: str = ""
        self._draft_ffb_kffb: str = ""
        self._draft_ffb_freq: int = 0x03
        self._draft_sync_gfa: bool = False
        self._draft_ffb_rows: list[dict[str, Any]] = [
            {"enabled": idx == 1, "serial": "", "counter": 0, "source": "manual"}
            for idx in range(1, 8)
        ]

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_identity())

        split = QHBoxLayout()
        split.setContentsMargins(0, 0, 0, 0)
        split.setSpacing(0)
        split.addWidget(self._build_nav())
        split.addWidget(self._build_page_area(), 1)
        outer.addLayout(split, 1)

        self.conn.changed.connect(self._on_conn_or_busy)
        self.runner.busy_changed.connect(lambda _b: self._on_conn_or_busy())
        self._unsub = subscribe_lang_change(lambda _l: self.refresh())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.select("cp_keys")
        self.refresh()

    # ────────────────────────────── Public State API ──────────────────────────────

    @property
    def is_open(self) -> bool:
        return self._is_open

    @property
    def part_number(self) -> str:
        return (
            self._passport.get("part_number")
            or self._passport.get("hw_part_number")
            or "5Q0937084"
        )

    @property
    def via_gateway(self) -> bool:
        return self._via_gateway

    @property
    def gateway_bridge(self) -> bool:
        return self._gateway_bridge

    @property
    def gateway_channel(self) -> int:
        return self._gateway_channel

    def select(self, key: str) -> None:
        if key in self._nav_items:
            self.nav.setCurrentItem(self._nav_items[key])

    def open_from_discovered(
        self,
        ecu: DiscoveredEcu | None = None,
        *,
        via_gateway: bool = False,
        gateway_bridge: bool = False,
        gateway_channel: int = 0,
        auto_read: bool = True,
    ) -> None:
        """Open the 09 BCM workspace from a bus scan `DiscoveredEcu` and immediately read all BCM data."""
        self._is_open = True
        if ecu is not None:
            self._via_gateway = bool(ecu.via_gateway)
            self._gateway_bridge = bool(ecu.bridge_available)
            self._gateway_channel = 0 if ecu.gateway_channel is None else int(ecu.gateway_channel)
            self._passport = {
                "part_number": ecu.part_number,
                "sw_version": ecu.sw_version,
                "hw_part_number": ecu.hw_number,
                "hw_version": ecu.hw_version,
                "fazit": ecu.fazit,
                "system_name": ecu.system_name,
                "vin": ecu.vin,
            }
            self._profile = bcm_detect_profile(self._passport, sw_profile=self._profile_override or None)
        else:
            self._via_gateway = bool(via_gateway)
            self._gateway_bridge = bool(gateway_bridge)
            self._gateway_channel = int(gateway_channel)
        self._sync_cluster_material_if_available(silent=True)
        self.select(self._key)
        self.refresh()
        self.changed.emit()
        if auto_read and self.conn.ready and not self.conn.busy_reason() and not self.runner.is_busy:
            QTimer.singleShot(0, self.action_read_all)

    def open_from_read_result(
        self,
        res: dict[str, Any],
        *,
        gateway_bridge: bool = False,
        gateway_channel: int = 0,
    ) -> None:
        """Open the 09 BCM workspace on its first page populated from `can_bcm_read_all()`."""
        self._is_open = True
        self._via_gateway = bool(res.get("via_gateway", False))
        self._gateway_bridge = bool(gateway_bridge or res.get("gateway_bridged", False))
        self._gateway_channel = int(gateway_channel)
        self._ika_hex = ""
        self._gfa_hex = ""
        self._draft_cur_ika = ""
        self._passport = {}
        self._status = {}
        self._dtcs = None
        self._key = "cp_keys"
        self.select("cp_keys")
        self._sync_cluster_material_if_available(silent=True)
        self._on_all_read(res)

    def close_bcm(self) -> None:
        self._is_open = False
        self._passport = {}
        self._status = {}
        self._dtcs = None
        self._ika_hex = ""
        self._gfa_hex = ""
        self._draft_cur_ika = ""
        self._draft_new_ika = ""
        self._draft_new_gfa = ""
        self._draft_ffb_gfa = ""
        self.changed.emit()

    def set_routing(self, *, via_gateway: bool, gateway_bridge: bool, gateway_channel: int = 0) -> None:
        self._via_gateway = bool(via_gateway)
        self._gateway_bridge = bool(gateway_bridge)
        self._gateway_channel = int(gateway_channel)
        self.refresh()

    def _selected_sw_profile(self) -> str | None:
        return self._profile_override or None

    # ────────────────────────────── Layout Builders (Unified with EcuScreen & FpkeScreen) ──────────────────────────────

    def _build_identity(self) -> QWidget:
        self.sec_id = QFrame()
        self.sec_id.setObjectName("IdentityBar")
        body = QVBoxLayout(self.sec_id)
        body.setContentsMargins(24, 12, 24, 12)
        body.setSpacing(10)

        head = QHBoxLayout()
        head.setSpacing(10)
        self.lbl_pn = QLabel()
        self.lbl_pn.setObjectName("PartNumber")
        self.lbl_pn.setFont(mono_font(20, bold=True))
        self.lbl_pn.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.lbl_sys = QLabel()
        self.lbl_sys.setObjectName("Hint")
        self.sep_source = vdivider()
        self.sep_source.setFixedHeight(14)
        self.pill_source = QLabel()
        self.pill_source.setObjectName("Hint")

        head.addWidget(self.lbl_pn, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.lbl_sys, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.sep_source, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.pill_source, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addStretch(1)

        self.btn_poll_top = button("", slot=self.action_read_all)
        self.btn_export_top = button("", slot=self.action_export_keys_json)
        self.btn_term_top = button("", slot=lambda: self.open_terminal_requested.emit("bcm"))
        self.btn_close_top = button("", "GhostBtn", slot=self.close_requested.emit)
        for b in (self.btn_poll_top, self.btn_export_top, self.btn_term_top, self.btn_close_top):
            b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            head.addWidget(b)
        body.addLayout(head)

        body.addWidget(divider())

        self.grid_id = QGridLayout()
        self.grid_id.setHorizontalSpacing(22)
        self.grid_id.setVerticalSpacing(2)
        body.addLayout(self.grid_id)
        return self.sec_id

    def _build_nav(self) -> QWidget:
        pane = QFrame()
        pane.setObjectName("NavPane")
        pane.setFixedWidth(306)
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(6, 6, 6, 0)
        lay.setSpacing(0)

        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        self.nav_rows: dict[str, _BcmNavRow] = {}
        self._nav_items: dict[str, QListWidgetItem] = {}
        self._group_labels: dict[str, QLabel] = {}
        for group, keys in BCM_GROUPS:
            head = QListWidgetItem(self.nav)
            head.setFlags(Qt.ItemFlag.NoItemFlags)
            head.setSizeHint(QSize(0, 26))
            lbl = group_label()
            lbl.setContentsMargins(12, 8, 0, 0)
            self.nav.setItemWidget(head, lbl)
            self._group_labels[group] = lbl
            for key in keys:
                item = QListWidgetItem(self.nav)
                item.setData(Qt.ItemDataRole.UserRole, key)
                item.setSizeHint(QSize(0, 32))
                nav_row = _BcmNavRow()
                self.nav.setItemWidget(item, nav_row)
                self.nav_rows[key] = nav_row
                self._nav_items[key] = item
        self.nav.currentItemChanged.connect(self._on_nav)
        lay.addWidget(self.nav, 1)

        self.nav_dumps = QFrame()
        self.nav_dumps.setObjectName("NavDumps")
        nd_lay = QVBoxLayout(self.nav_dumps)
        nd_lay.setContentsMargins(16, 10, 16, 12)
        nd_lay.setSpacing(4)
        self.lbl_state_hdr = group_label()
        nd_lay.addWidget(self.lbl_state_hdr)
        self.state_list = QVBoxLayout()
        self.state_list.setContentsMargins(0, 1, 0, 0)
        self.state_list.setSpacing(3)
        nd_lay.addLayout(self.state_list)
        lay.addWidget(self.nav_dumps)
        return pane

    def _build_page_area(self) -> QWidget:
        self.page_area = QScrollArea()
        self.page_area.setWidgetResizable(True)
        self.page_area.setFrameShape(QFrame.Shape.NoFrame)
        self.page_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        return self.page_area

    def _on_nav(self, item: QListWidgetItem | None, _prev: QListWidgetItem | None) -> None:
        key = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if key:
            self._key = str(key)
            for k, nav_row in self.nav_rows.items():
                nav_row.set_active(k == self._key)
            self._render_page()

    # ────────────────────────────── Helpers Matching FpkeScreen ──────────────────────────────

    @staticmethod
    def _compact_section(sec: Section) -> Section:
        sec.head.setContentsMargins(14, 8, 14, 2)
        sec.body.setContentsMargins(14, 4, 14, 10)
        sec.body.setSpacing(8)
        return sec

    @staticmethod
    def _ledger_row(name: str, val: str, tone: str = "muted", tip: str = "") -> QWidget:
        w = QWidget()
        if tip:
            w.setToolTip(tip)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        lbl_n = QLabel(name)
        lbl_n.setObjectName("Hint")
        if tone == "muted":
            set_tone(lbl_n, "muted")
        lbl_v = QLabel(val)
        lbl_v.setFont(mono_font(11))
        set_tone(lbl_v, tone if tone in ("warn", "err", "info", "ok") else "muted")
        lay.addWidget(lbl_n, 1)
        lay.addWidget(lbl_v, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return w

    @staticmethod
    def _field_box(
        caption: str,
        control: QWidget,
        *,
        badge_text: str = "",
        badge_tone: str = "muted",
        trailing: tuple[QWidget, ...] = (),
        tip: str = "",
    ) -> tuple[QWidget, QLabel]:
        """Architectural form cell matching FpkeScreen: uppercase GroupLabel + right badge above input row."""
        cell = QWidget()
        if tip:
            cell.setToolTip(tip)
        vlay = QVBoxLayout(cell)
        vlay.setContentsMargins(0, 0, 0, 0)
        vlay.setSpacing(3)

        top = QHBoxLayout()
        top.setContentsMargins(1, 0, 1, 0)
        top.setSpacing(6)
        lbl_cap = group_label(caption)
        lbl_cap.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        lbl_badge = QLabel(badge_text)
        lbl_badge.setFont(mono_font(10))
        set_tone(lbl_badge, badge_tone)
        lbl_badge.setVisible(bool(badge_text))
        top.addWidget(lbl_cap, 1)
        top.addWidget(lbl_badge, 0)
        vlay.addLayout(top)

        if isinstance(control, QComboBox):
            control.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
            control.setMinimumContentsLength(5)
            control.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        elif isinstance(control, QLineEdit):
            control.setMinimumWidth(0)
            control.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)

        if trailing:
            in_row = QHBoxLayout()
            in_row.setContentsMargins(0, 0, 0, 0)
            in_row.setSpacing(6)
            in_row.addWidget(control, 1)
            for btn_w in trailing:
                btn_w.setCursor(Qt.CursorShape.PointingHandCursor)
                in_row.addWidget(btn_w)
            vlay.addLayout(in_row)
        else:
            vlay.addWidget(control)
        return cell, lbl_badge

    @staticmethod
    def _bind_hex_validator(ed: QLineEdit, badge: QLabel, expected_bytes: int, *, allow_empty: bool = True) -> None:
        def _check(txt: str) -> None:
            raw = "".join(txt.split()).replace("0x", "").replace("0X", "")
            if not raw:
                set_tone(ed, "")
                badge.setText(tr("пусто", "empty") if allow_empty else f"0/{expected_bytes * 2}")
                set_tone(badge, "muted" if allow_empty else "err")
                badge.setVisible(True)
                return
            hex_ok = all(c in "0123456789abcdefABCDEF" for c in raw)
            exact = hex_ok and len(raw) == expected_bytes * 2
            set_tone(ed, "" if exact else "err")
            badge.setText(f"{len(raw) // 2}/{expected_bytes} B" if len(raw) % 2 == 0 else f"{len(raw)}/{expected_bytes * 2}")
            set_tone(badge, "ok" if exact else "err")
            badge.setVisible(True)

        ed.textChanged.connect(_check)
        _check(ed.text())

    def _copy_hex(self, hex_value: str, label: str) -> None:
        cleaned = hex_value.strip().upper()
        if not cleaned or cleaned == "—":
            return
        cb = QGuiApplication.clipboard()
        if cb is not None:
            cb.setText(cleaned)
            self.note.emit(tr(f"Скопировано в буфер обмена: {label}", f"Copied to clipboard: {label}"))

    # ────────────────────────────── Refresh & Rendering ──────────────────────────────

    def _on_conn_or_busy(self) -> None:
        if not self._is_open or not _qt_valid(self):
            return
        self.refresh()

    def refresh(self) -> None:
        if not _qt_valid(self):
            return
        self._refresh_identity()
        self._refresh_nav()
        self._render_page()

    # Keep aliases used by main_window / tests
    def _refresh_banner(self) -> None:
        self._refresh_identity()
        self._refresh_nav()

    def _render_current_page(self) -> None:
        self._render_page()

    def _refresh_identity(self) -> None:
        busy = self.runner.is_busy
        self.lbl_pn.setText(self.part_number)
        sys_txt = self._passport.get("system_name") or tr("Блок бортовой сети BCM (09)", "Central Electrics BCM (09)")
        self.lbl_sys.setText(sys_txt)

        if self._via_gateway:
            if self._gateway_bridge:
                self.pill_source.setText(
                    tr(f"Через шлюз J533 (RAM-мост ch{self._gateway_channel})", f"Via J533 gateway (RAM-Bridge ch{self._gateway_channel})")
                )
                set_tone(self.pill_source, "ok")
            else:
                self.pill_source.setText(tr("Через шлюз J533 (только UDS)", "Via J533 gateway (UDS only)"))
                set_tone(self.pill_source, "warn")
        else:
            self.pill_source.setText(tr("Прямой CAN Komfort", "Direct Komfort CAN"))
            set_tone(self.pill_source, "info")

        self.btn_poll_top.setText(tr("Опросить BCM", "Poll BCM"))
        self.btn_poll_top.setEnabled(not busy)
        self.btn_export_top.setText(tr("Экспорт JSON", "Export JSON"))
        self.btn_export_top.setEnabled(bool(self._ika_hex or self._gfa_hex or self._status))
        self.btn_term_top.setText(tr("CAN-терминал", "CAN terminal"))
        self.btn_term_top.setEnabled(not busy)
        self.btn_close_top.setText(tr("Закрыть", "Close"))

        clear_layout(self.grid_id)
        for c in range(8):
            self.grid_id.setColumnStretch(c, 0)

        top_fields: list[tuple[str, str]] = []
        if self._passport.get("sw_version"):
            top_fields.append((tr("ВЕРСИЯ ПО", "SOFTWARE"), str(self._passport["sw_version"])))
        hw_pn = self._passport.get("hw_part_number") or ""
        hw_v = self._passport.get("hw_version") or ""
        if hw_pn:
            top_fields.append((tr("ОБОРУДОВАНИЕ", "HARDWARE"), f"{hw_pn} / {hw_v}" if hw_v else hw_pn))
        if self._passport.get("fazit"):
            top_fields.append(("FAZIT", str(self._passport["fazit"])))
        if self._passport.get("vin"):
            top_fields.append(("VIN", str(self._passport["vin"])))
        prof_id = self._profile.get("id", "ea_0511")
        prof_short = "EA / SW 0511" if prof_id == "ea_0511" else "DD / SW 0273"
        top_fields.append((tr("ПРОФИЛЬ ОЗУ", "RAM PROFILE"), prof_short))
        if self._status.get("rf_0a65_hex"):
            top_fields.append((tr("ЧАСТОТА FFB", "FFB RF"), str(self._status.get("freq_label") or "—")))
        else:
            top_fields.append(("CAN UDS", "0x70E → 0x778"))

        for col, (k, v) in enumerate(top_fields):
            lbl_k = QLabel(k)
            lbl_k.setObjectName("GroupLabel")
            lbl_v = QLabel(v)
            lbl_v.setFont(mono_font(12))
            lbl_v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.grid_id.addWidget(lbl_k, 0, col)
            self.grid_id.addWidget(lbl_v, 1, col)
        self.grid_id.setColumnStretch(len(top_fields), 1)

    def _refresh_nav(self) -> None:
        self._group_labels["main"].setText(tr("ОСНОВНОЕ", "MAIN"))
        self._group_labels["service"].setText(tr("СЕРВИС", "SERVICE"))

        for key, nav_row in self.nav_rows.items():
            nav_row.lbl_name.setText(_bcm_nav_title(key))
            nav_row.set_active(key == self._key)

        # CP / Keys status pill
        if self._status.get("cp_active_fault"):
            set_pill(self.nav_rows["cp_keys"].pill, "SAFE CP", "err")
        elif self._ika_hex and self._gfa_hex:
            set_pill(self.nav_rows["cp_keys"].pill, "IKA + GFA", "ok")
        elif self._gfa_hex:
            set_pill(self.nav_rows["cp_keys"].pill, "GFA", "info")
        elif self._status.get("ika_virgin"):
            set_pill(self.nav_rows["cp_keys"].pill, "virgin", "warn")
        else:
            set_pill(self.nav_rows["cp_keys"].pill, "—", "muted")

        # FFB status pill
        slots = self._status.get("ffb_slots") or []
        pop_slots = sum(1 for s in slots if s.get("populated"))
        learned = self._status.get("ffb_learned_count")
        eff_learned = pop_slots if (slots and (learned is None or pop_slots > 0)) else learned
        if eff_learned is not None:
            set_pill(
                self.nav_rows["ffb"].pill,
                tr(f"ключей: {eff_learned}", f"{eff_learned} keys"),
                "ok" if eff_learned else "muted",
            )
        elif self._cluster_material and self._cluster_material.get("kc_hex"):
            set_pill(self.nav_rows["ffb"].pill, "17 FPK_E", "info")
        else:
            set_pill(self.nav_rows["ffb"].pill, "—", "muted")

        # Status pill
        cp_cnt = self._status.get("cp_mismatch_counter")
        if cp_cnt is not None:
            if self._status.get("cp_active_fault"):
                set_pill(self.nav_rows["status"].pill, f"03DE={cp_cnt}", "err")
            else:
                set_pill(self.nav_rows["status"].pill, tr("в норме", "ok"), "ok")
        else:
            set_pill(self.nav_rows["status"].pill, "—", "muted")

        # DTC pill
        if self._dtcs is None:
            set_pill(self.nav_rows["dtc"].pill, "—", "muted")
        elif len(self._dtcs) == 0:
            set_pill(self.nav_rows["dtc"].pill, tr("нет", "none"), "ok")
        else:
            n_act = sum(1 for d in self._dtcs if d.get("active"))
            set_pill(
                self.nav_rows["dtc"].pill,
                tr(f"{len(self._dtcs)} шт.", f"{len(self._dtcs)}"),
                "err" if n_act else "warn",
            )

        # Bottom ledger (matching EcuScreen / FpkeScreen NavDumps)
        self.lbl_state_hdr.setText(tr("ДАННЫЕ 09 BCM", "09 BCM DATA"))
        clear_layout(self.state_list)
        self.state_list.addWidget(
            self._ledger_row(
                "IKA (00BE)",
                tr("считан", "read") if self._ika_hex else tr("нет", "none"),
                "ok" if self._ika_hex else "muted",
                self._ika_hex.upper() if self._ika_hex else "",
            )
        )
        self.state_list.addWidget(
            self._ledger_row(
                "GFA (00BD)",
                tr("считан", "read") if self._gfa_hex else tr("нет", "none"),
                "ok" if self._gfa_hex else "muted",
                self._gfa_hex.upper() if self._gfa_hex else "",
            )
        )
        rf_lbl = str(self._status.get("freq_label") or tr("не опрошен", "not polled"))
        self.state_list.addWidget(
            self._ledger_row(
                tr("Частота FFB", "FFB freq"),
                rf_lbl,
                "info" if self._status.get("rf_0a65_hex") else "muted",
            )
        )
        has_cluster = bool(self._cluster_material and self._cluster_material.get("kc_hex"))
        self.state_list.addWidget(
            self._ledger_row(
                tr("Панель приборов", "17 Cluster"),
                tr("открыта", "loaded") if has_cluster else tr("не открыта", "not open"),
                "ok" if has_cluster else "muted",
            )
        )

    def _render_page(self) -> None:
        page = QWidget()
        page.setObjectName("PageCanvas")
        outer = QHBoxLayout(page)
        outer.setContentsMargins(24, 6, 24, 14)
        outer.setSpacing(0)

        column = QWidget()
        column.setMaximumWidth(960)
        lay = QVBoxLayout(column)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        head_row = QHBoxLayout()
        head_row.setContentsMargins(0, 0, 0, 0)
        head_row.setSpacing(8)
        title = QLabel(_bcm_nav_title(self._key))
        title.setObjectName("PageTitle")
        head_row.addWidget(title)
        head_row.addStretch(1)

        if self._key == "cp_keys":
            btn_exp = button(tr("Экспорт JSON…", "Export JSON…"), "GhostBtn", slot=self.action_export_keys_json)
            btn_exp.setEnabled(bool(self._ika_hex or self._gfa_hex))
            head_row.addWidget(btn_exp)
        elif self._key == "ffb":
            btn_open_17 = button(
                tr("Взять из открытой 17 FPK_E", "From open 17 FPK_E"),
                "GhostBtn",
                slot=lambda: self._sync_cluster_material_if_available(silent=False),
            )
            btn_file_17 = button(
                tr("Загрузить Dflash.bin…", "Load Dflash.bin…"),
                "GhostBtn",
                slot=self.action_load_cluster_dflash_file,
            )
            head_row.addWidget(btn_open_17)
            head_row.addWidget(btn_file_17)
        elif self._key == "status":
            lbl_p = QLabel(tr("Профиль ОЗУ:", "RAM profile:"))
            lbl_p.setObjectName("Hint")
            self.cmb_profile = QComboBox()
            self.cmb_profile.setMinimumWidth(205)
            self.cmb_profile.addItem(tr("Авто (EA 0511 / DD 0273)", "Auto (EA 0511 / DD 0273)"), "")
            self.cmb_profile.addItem("EA / BH — SW 0511", "ea_0511")
            self.cmb_profile.addItem("DD / CG — SW 0273", "dd_0273")
            idx_p = self.cmb_profile.findData(self._profile_override)
            if idx_p >= 0:
                self.cmb_profile.setCurrentIndex(idx_p)
            self.cmb_profile.currentIndexChanged.connect(self._on_profile_changed)
            head_row.addWidget(lbl_p)
            head_row.addWidget(self.cmb_profile)

        lay.addLayout(head_row)

        if self._key == "cp_keys":
            self._build_cp_keys_page(lay)
        elif self._key == "ffb":
            self._build_ffb_page(lay)
        elif self._key == "status":
            self._build_status_page(lay)
        elif self._key == "dtc":
            self._build_dtc_page(lay)

        lay.addStretch(1)
        outer.addWidget(column, 1)
        outer.addStretch(0)
        self.page_area.setWidget(page)

    def _on_profile_changed(self, _idx: int) -> None:
        val = str(self.cmb_profile.currentData() or "")
        self._profile_override = val
        self._profile = bcm_detect_profile(self._passport, sw_profile=val or None)
        self._refresh_identity()

    # ────────────────────────────── Page 1: Component Protection (IKA / GFA) ──────────────────────────────

    def _build_cp_keys_page(self, lay: QVBoxLayout) -> None:
        busy = self.runner.is_busy

        # Card 1: Read keys via WFS Ch 3 + XCP (zero flash writes)
        sec_read = self._compact_section(Section())
        sec_read.set_text(
            tr("Чтение ключей IKA и GFA (WFS Ch 3 + XCP)", "Read IKA & GFA keys (WFS Ch 3 + XCP)"),
            tr(
                "Извлечение группового ключа GFA (Crypto Job 5) и индивидуального ключа IKA (двухпроходная очередь Crypto Job 3 "
                "на 0x17F8140E + XCP SHORT_UPLOAD) без записи во Flash.",
                "Extracts vehicle group key GFA (Crypto Job 5) and individual key IKA (two-pass Crypto Job 3 queue on "
                "0x17F8140E + XCP SHORT_UPLOAD) with zero flash writes.",
            ),
        )
        cp_cnt = self._status.get("cp_mismatch_counter")
        if self._status.get("cp_active_fault"):
            st_txt, st_tone = tr(f"SAFE CP (03DE={cp_cnt})", f"SAFE CP (03DE={cp_cnt})"), "err"
        elif self._ika_hex and self._gfa_hex:
            st_txt, st_tone = tr("IKA и GFA считаны", "IKA & GFA read"), "ok"
        elif self._gfa_hex:
            st_txt, st_tone = tr("GFA считан", "GFA read"), "info"
        else:
            st_txt, st_tone = tr("Ключи не считаны", "Not read yet"), "muted"
        sec_read.head.addWidget(status_readout(st_txt, st_tone), 0, Qt.AlignmentFlag.AlignVCenter)

        self.ed_read_ika = QLineEdit(self._ika_hex.upper())
        self.ed_read_ika.setFont(mono_font(12, bold=True))
        self.ed_read_ika.setReadOnly(True)
        self.ed_read_ika.setPlaceholderText(tr("Нажмите «Считать IKA + GFA»…", "Click “Read IKA + GFA”…"))
        btn_cp_ika = button(tr("Копировать", "Copy"), "GhostBtn", slot=lambda: self._copy_hex(self.ed_read_ika.text(), "IKA"))
        c_ika, _ = self._field_box(
            tr("ИНДИВИДУАЛЬНЫЙ КЛЮЧ IKA (16 БАЙТ, DID 0x00BE)", "INDIVIDUAL KEY IKA (16 BYTES, DID 0x00BE)"),
            self.ed_read_ika,
            badge_text="16 B" if self._ika_hex else "",
            badge_tone="ok" if self._ika_hex else "muted",
            trailing=(btn_cp_ika,),
            tip=f"RAM working IKA @ 0x{int(self._profile['ika_working_addr']):08X}",
        )
        sec_read.body.addWidget(c_ika)

        self.ed_read_gfa = QLineEdit(self._gfa_hex.upper())
        self.ed_read_gfa.setFont(mono_font(12))
        self.ed_read_gfa.setReadOnly(True)
        self.ed_read_gfa.setPlaceholderText(tr("Нажмите «Считать IKA + GFA» или «Только GFA»…", "Click “Read IKA + GFA” or “GFA only”…"))
        btn_cp_gfa = button(tr("Копировать", "Copy"), "GhostBtn", slot=lambda: self._copy_hex(self.ed_read_gfa.text(), "GFA"))
        c_gfa, _ = self._field_box(
            tr("ГРУППОВОЙ КЛЮЧ АВТОМОБИЛЯ GFA (16 БАЙТ, DID 0x00BD)", "VEHICLE GROUP KEY GFA (16 BYTES, DID 0x00BD)"),
            self.ed_read_gfa,
            badge_text="16 B" if self._gfa_hex else "",
            badge_tone="ok" if self._gfa_hex else "muted",
            trailing=(btn_cp_gfa,),
            tip=f"RAM AES GFA buf @ 0x{int(self._profile['gfa_aes_buf']):08X}",
        )
        sec_read.body.addWidget(c_gfa)

        btn_read_both = button(tr("Считать IKA + GFA", "Read IKA + GFA"), "PrimaryBtn", slot=self.action_read_keys)
        btn_read_gfa = button(tr("Только GFA (Job 5)", "GFA only (Job 5)"), slot=self.action_read_gfa)
        for b in (btn_read_both, btn_read_gfa):
            b.setEnabled(not busy)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        sec_read.add_footer(btn_read_both, btn_read_gfa)
        lay.addWidget(sec_read)

        # Card 2: Standard UDS write (22 02F9 -> 2E 00BE / 2E 00BD)
        sec_write = self._compact_section(Section())
        sec_write.set_text(
            tr("Запись ключей по UDS (2E 00BE / 2E 00BD)", "Write keys over UDS (2E 00BE / 2E 00BD)"),
            tr(
                "Штатный 34-байтный контейнер ODIS после вызова 22 02F9. Работает по обычному UDS 0x70E/0x778 напрямую и через любой шлюз без RAM-моста.",
                "Standard 34-byte ODIS container after 22 02F9 challenge. Works over standard UDS 0x70E/0x778 directly and through any gateway without RAM bridge.",
            ),
        )

        cur_ika_val = (self._draft_cur_ika or self._ika_hex).upper()
        self.ed_write_cur_ika = QLineEdit(cur_ika_val)
        self.ed_write_cur_ika.setFont(mono_font(12))
        self.ed_write_cur_ika.setPlaceholderText("32 HEX (16 B)")
        self.ed_write_cur_ika.textChanged.connect(lambda t: setattr(self, "_draft_cur_ika", t))
        c_cur, b_cur = self._field_box(
            tr("ТЕКУЩИЙ IKA БЛОКА (ШИФРУЕТ КОНТЕЙНЕР)", "CURRENT BCM IKA (ENCRYPTS CONTAINER)"),
            self.ed_write_cur_ika,
            tip="Текущий рабочий IKA этого BCM, под которым проверяется контейнер 2E 00BE / 2E 00BD",
        )
        self._bind_hex_validator(self.ed_write_cur_ika, b_cur, 16, allow_empty=False)
        sec_write.body.addWidget(c_cur)

        self.ed_write_new_ika = QLineEdit(self._draft_new_ika.upper())
        self.ed_write_new_ika.setFont(mono_font(12))
        self.ed_write_new_ika.setPlaceholderText(tr("Пусто = не менять IKA (записать только GFA)", "Blank = keep current IKA (write GFA only)"))
        self.ed_write_new_ika.textChanged.connect(lambda t: setattr(self, "_draft_new_ika", t))
        btn_gen_ika = button(
            tr("Сгенерировать", "Generate"),
            "GhostBtn",
            slot=lambda: self.ed_write_new_ika.setText(_py_secrets.token_hex(16).upper()),
        )
        btn_same_ika = button(
            tr("Текущий IKA", "Current IKA"),
            "GhostBtn",
            slot=lambda: self.ed_write_new_ika.setText(self.ed_write_cur_ika.text().strip()),
        )
        c_new_ika, b_new_ika = self._field_box(
            tr("НОВЫЙ IKA (DID 0x00BE, ОПЦИОНАЛЬНО)", "NEW IKA (DID 0x00BE, OPTIONAL)"),
            self.ed_write_new_ika,
            trailing=(btn_gen_ika, btn_same_ika),
            tip="При записи 2E 00BE прошивка BCM стирает GFA в FF×16, поэтому следом записывается 2E 00BD",
        )
        self._bind_hex_validator(self.ed_write_new_ika, b_new_ika, 16, allow_empty=True)
        sec_write.body.addWidget(c_new_ika)

        new_gfa_val = (self._draft_new_gfa or self._gfa_hex).upper()
        self.ed_write_new_gfa = QLineEdit(new_gfa_val)
        self.ed_write_new_gfa.setFont(mono_font(12))
        self.ed_write_new_gfa.setPlaceholderText("32 HEX (16 B)")
        self.ed_write_new_gfa.textChanged.connect(lambda t: setattr(self, "_draft_new_gfa", t))
        btn_gfa_17 = button(
            tr("Из 17 FPK_E (/1)", "From 17 FPK_E (/1)"),
            "GhostBtn",
            slot=self._fill_gfa_from_cluster,
        )
        c_new_gfa, b_new_gfa = self._field_box(
            tr("ЦЕЛЕВОЙ GFA АВТОМОБИЛЯ (DID 0x00BD)", "TARGET VEHICLE GFA (DID 0x00BD)"),
            self.ed_write_new_gfa,
            trailing=(btn_gfa_17,),
            tip="Групповой ключ автомобиля GFA (совпадает со слотом /1 в панели приборов 17 FPK_E)",
        )
        self._bind_hex_validator(self.ed_write_new_gfa, b_new_gfa, 16, allow_empty=True)
        sec_write.body.addWidget(c_new_gfa)

        self.chk_write_reset = QCheckBox(
            tr("Перезагрузить BCM после записи (UDS 11 01 HardReset)", "Hard-reset BCM after write (UDS 11 01)")
        )
        self.chk_write_reset.setChecked(self._draft_write_reset)
        self.chk_write_reset.toggled.connect(lambda v: setattr(self, "_draft_write_reset", bool(v)))
        sec_write.body.addWidget(self.chk_write_reset)

        note = Callout("info")
        note.label.setText(
            tr(
                "Запись нового <b>IKA (2E 00BE)</b> в прошивке BCM автоматически обнуляет <b>GFA</b> в <code>FF×16</code> "
                "— при выборе «Записать IKA + GFA» программа последовательно пишет <code>00BE</code>, затем <code>00BD</code> на новом IKA.",
                "Writing a new <b>IKA (2E 00BE)</b> in BCM firmware erases <b>GFA</b> to <code>FF×16</code> — "
                "“Write IKA + GFA” writes <code>00BE</code> first and immediately restores <code>00BD</code> under the new IKA.",
            )
        )
        sec_write.body.addWidget(note)

        btn_wr_gfa = button(tr("Записать GFA (00BD)", "Write GFA (00BD)"), "PrimaryBtn", slot=lambda: self.action_write_keys(include_ika=False))
        btn_wr_both = button(tr("Записать IKA + GFA (00BE → 00BD)", "Write IKA + GFA (00BE → 00BD)"), slot=lambda: self.action_write_keys(include_ika=True))
        for b in (btn_wr_gfa, btn_wr_both):
            b.setEnabled(not busy)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        sec_write.add_footer(btn_wr_gfa, btn_wr_both)
        lay.addWidget(sec_write)

    # ────────────────────────────── Page 2: FFB Remote Keys (WFS Ch 3) ──────────────────────────────

    def _build_ffb_page(self, lay: QVBoxLayout) -> None:
        busy = self.runner.is_busy
        self._sync_cluster_material_if_available(silent=True)
        cm = self._cluster_material or {}
        st = self._status
        slots = st.get("ffb_slots") or []
        pop_slots = [s for s in slots if s.get("populated")]
        n_learned_1983 = st.get("ffb_learned_count")
        n_learned = len(pop_slots) if (slots and (n_learned_1983 is None or len(pop_slots) > 0)) else n_learned_1983
        freq_lbl = str(st.get("freq_label") or "")

        # Card 1: Unified pre-populated Channel 3 parameters & 7 FFB remote key slots
        sec_cfg = self._compact_section(Section())
        sec_cfg.set_text(
            tr("Параметры канала 3 и радиоключи FFB (слоты 1..7)", "Channel 3 parameters & FFB remote key slots (1..7)"),
            tr(
                "Слоты, частота DID 0x0A65 и ключ GFA автоматически заполняются при подключении к 09 BCM "
                "(или из открытого дампа панели приборов 17 FPK_E).",
                "Key slots, DID 0x0A65 frequency, and GFA are populated automatically on 09 BCM connect "
                "(or from an open 17 FPK_E cluster dump).",
            ),
        )
        if not st:
            sec_cfg.head.addWidget(status_readout(tr("Не считано", "Not read yet"), "muted"), 0, Qt.AlignmentFlag.AlignVCenter)
        elif n_learned:
            hdr_txt = tr(f"Обучено в BCM: {n_learned}", f"Learned in BCM: {n_learned}")
            if freq_lbl:
                hdr_txt += f" · {freq_lbl}"
            sec_cfg.head.addWidget(status_readout(hdr_txt, "ok"), 0, Qt.AlignmentFlag.AlignVCenter)
        else:
            hdr_txt = tr("В BCM ключей нет (0)", "No keys in BCM (0)")
            if freq_lbl:
                hdr_txt += f" · {freq_lbl}"
            sec_cfg.head.addWidget(status_readout(hdr_txt, "warn"), 0, Qt.AlignmentFlag.AlignVCenter)

        # Row 1: GFA + Frequency
        r1 = QHBoxLayout()
        r1.setSpacing(10)
        gfa_val = (self._draft_ffb_gfa or self._gfa_hex or cm.get("gfa_hex") or "").upper()
        self.ed_ffb_gfa = QLineEdit(gfa_val)
        self.ed_ffb_gfa.setFont(mono_font(12))
        self.ed_ffb_gfa.setPlaceholderText(tr("Пусто = авто-чтение GFA из BCM по XCP", "Blank = auto-read GFA via XCP"))
        self.ed_ffb_gfa.textChanged.connect(lambda t: setattr(self, "_draft_ffb_gfa", t))
        c_fgfa, b_fgfa = self._field_box(tr("GFA БЛОКА 09 BCM (16 Б)", "09 BCM GFA (16 B)"), self.ed_ffb_gfa)
        self._bind_hex_validator(self.ed_ffb_gfa, b_fgfa, 16, allow_empty=True)

        self.cmb_ffb_freq = QComboBox()
        self.cmb_ffb_freq.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.cmb_ffb_freq.wheelEvent = lambda event: event.ignore()  # type: ignore[method-assign]
        for f_code, f_label in BCM_FREQUENCIES.items():
            disp_lbl = tr("Нет радиоканала", "No RF") if f_code == 0 else f_label
            self.cmb_ffb_freq.addItem(f"0x{f_code:02X} — {disp_lbl}", f_code)
        eff_freq = int(self._draft_ffb_freq)
        idx_f = self.cmb_ffb_freq.findData(eff_freq)
        if idx_f >= 0:
            self.cmb_ffb_freq.setCurrentIndex(idx_f)
        self._draft_ffb_freq = int(self.cmb_ffb_freq.currentData() if self.cmb_ffb_freq.currentData() is not None else 0x03)
        self.cmb_ffb_freq.currentIndexChanged.connect(
            lambda _i: setattr(self, "_draft_ffb_freq", int(self.cmb_ffb_freq.currentData() if self.cmb_ffb_freq.currentData() is not None else 0x03))
        )
        c_freq, _ = self._field_box(tr("ЧАСТОТА DID 0x0A65", "FREQUENCY DID 0x0A65"), self.cmb_ffb_freq)
        r1.addWidget(c_fgfa, 3)
        r1.addWidget(c_freq, 1)
        sec_cfg.body.addLayout(r1)

        # Row 2: K_c + K_ffb
        r2 = QHBoxLayout()
        r2.setSpacing(10)
        kc_val = (self._draft_ffb_kc or cm.get("kc_hex") or "").upper()
        self.ed_ffb_kc = QLineEdit(kc_val)
        self.ed_ffb_kc.setFont(mono_font(12))
        self.ed_ffb_kc.setPlaceholderText("32 HEX (EEL 0x68)")
        self.ed_ffb_kc.textChanged.connect(self._on_kc_text_changed)
        c_kc, b_kc = self._field_box(tr("МАСТЕР-КЛЮЧ K_c (17 FPK_E)", "IMMO MASTER KEY K_c (17 FPK_E)"), self.ed_ffb_kc)
        self._bind_hex_validator(self.ed_ffb_kc, b_kc, 16, allow_empty=True)

        kffb_val = (self._draft_ffb_kffb or cm.get("k_ffb_hex") or "").upper()
        self.ed_ffb_kffb = QLineEdit(kffb_val)
        self.ed_ffb_kffb.setFont(mono_font(12))
        self.ed_ffb_kffb.setPlaceholderText("AES_Kc(C16)")
        self.ed_ffb_kffb.textChanged.connect(lambda t: setattr(self, "_draft_ffb_kffb", t))
        c_kffb, b_kffb = self._field_box(tr("СЕКРЕТ РАДИОКАНАЛА K_ffb", "FFB SECRET K_ffb"), self.ed_ffb_kffb)
        self._bind_hex_validator(self.ed_ffb_kffb, b_kffb, 16, allow_empty=True)
        r2.addWidget(c_kc, 1)
        r2.addWidget(c_kffb, 1)
        sec_cfg.body.addLayout(r2)

        sec_cfg.body.addWidget(divider())

        if st and not pop_slots and not cm.get("kc_hex"):
            empty_callout = Callout("info")
            empty_callout.label.setText(
                tr(
                    f"В энергонезависимой памяти 09 BCM сейчас нет обученных радиоключей "
                    f"(0 из 7 слотов NvM 0x13..0x19, DID 0x1983 = {n_learned_1983 if n_learned_1983 is not None else 0}, "
                    f"частота: {freq_lbl or '—'}). Введите ключи ниже или нажмите «Считать панель приборов 17 по CAN и адаптировать FFB».",
                    f"No FFB remote keys are currently stored in 09 BCM memory "
                    f"(0 of 7 NvM 0x13..0x19 slots, DID 0x1983 = {n_learned_1983 if n_learned_1983 is not None else 0}, "
                    f"frequency: {freq_lbl or '—'}). Enter keys below or click “Read 17 cluster over CAN & adapt FFB”.",
                )
            )
            sec_cfg.body.addWidget(empty_callout)

        # 7 key slot rows
        k_grid = QGridLayout()
        k_grid.setHorizontalSpacing(12)
        k_grid.setVerticalSpacing(5)
        cnt_tip = tr(
            "Скользящий 24-битный счётчик радиокода (Rolling Counter, NvM 0x05..0x0B) — защита от перехвата/повтора.\n"
            "Увеличивается в брелоке на +1 при каждом нажатии кнопки. Для нового ключа оставляйте 0.",
            "24-bit anti-replay Rolling Counter (NvM 0x05..0x0B).\n"
            "Increments by +1 inside the key fob on every button press. Leave at 0 for fresh adaptation.",
        )
        for col, h_txt in enumerate(
            (
                tr("СЛОТ", "SLOT"),
                tr("СЕРИЙНЫЙ ID КЛЮЧА (8 HEX, EEL 0x67 / NvM 0x13..0x19)", "KEY SERIAL ID (8 HEX, EEL 0x67 / NvM 0x13..0x19)"),
                tr("СЧЁТЧИК НАЖАТИЙ", "ROLLING COUNTER"),
                tr("СОСТОЯНИЕ / ИСТОЧНИК", "STATE / SOURCE"),
            )
        ):
            hl = group_label(h_txt)
            if col == 1:
                hl.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            if col == 2:
                hl.setToolTip(cnt_tip)
            k_grid.addWidget(hl, 0, col)

        self._key_row_widgets: list[tuple[QCheckBox, QLineEdit, QSpinBox]] = []
        for idx in range(7):
            slot_num = idx + 1
            row_data = self._draft_ffb_rows[idx]
            chk = QCheckBox(f"#{slot_num}")
            chk.setFont(mono_font(11))
            chk.setChecked(bool(row_data["enabled"]))
            chk.toggled.connect(lambda v, i=idx: self._draft_ffb_rows[i].__setitem__("enabled", bool(v)))

            ed_ser = QLineEdit(str(row_data["serial"]))
            ed_ser.setFont(mono_font(12))
            ed_ser.setPlaceholderText("8 HEX (e.g. 532B3512)")
            ed_ser.textChanged.connect(lambda t, i=idx: self._draft_ffb_rows[i].__setitem__("serial", t))

            sp_cnt = QSpinBox()
            sp_cnt.setRange(0, 0x00FFFFFF)
            sp_cnt.setValue(int(row_data["counter"]))
            sp_cnt.setFont(mono_font(11))
            sp_cnt.setToolTip(cnt_tip)
            sp_cnt.valueChanged.connect(lambda v, i=idx: self._draft_ffb_rows[i].__setitem__("counter", int(v)))

            src_kind = row_data.get("source") or ("cluster" if row_data.get("from_cluster") else "manual")
            if src_kind == "cluster":
                if row_data.get("in_bcm"):
                    src_lbl = status_readout(tr("17 FPK_E · в BCM", "17 FPK_E · in BCM"), "ok")
                else:
                    src_lbl = status_readout(tr("17 FPK_E (EEL 0x67)", "17 FPK_E (EEL 0x67)"), "info")
            elif src_kind == "bcm":
                if row_data.get("desynced"):
                    src_lbl = status_readout(tr("09 BCM · рассинхр.", "09 BCM · desynced"), "warn")
                elif row_data.get("bcm_synced"):
                    src_lbl = status_readout(tr("09 BCM · синхронизирован", "09 BCM · synced"), "ok")
                else:
                    src_lbl = status_readout(tr("09 BCM · обучен", "09 BCM · learned"), "info")
            else:
                has_txt = bool(str(row_data["serial"]).strip())
                src_lbl = status_readout(
                    tr("вручную", "manual") if has_txt else tr("пусто", "empty"),
                    "muted",
                )
            k_grid.addWidget(chk, slot_num, 0)
            k_grid.addWidget(ed_ser, slot_num, 1)
            k_grid.addWidget(sp_cnt, slot_num, 2)
            k_grid.addWidget(src_lbl, slot_num, 3)
            self._key_row_widgets.append((chk, ed_ser, sp_cnt))
        k_grid.setColumnStretch(1, 2)
        sec_cfg.body.addLayout(k_grid)

        cnt_note = Callout("info")
        cnt_note.label.setText(
            tr(
                "<b>Счётчик нажатий (Rolling Counter)</b> — скользящий 24-битный счётчик радиопосылок брелока (защита от перехвата). "
                "Увеличивается на +1 при каждом нажатии кнопки. Для нового ключа оставляйте <b>0</b> — после записи BCM синхронизирует "
                "счётчик по первому нажатию (рабочее окно +1..359, двойное нажатие до +11 159).",
                "<b>Rolling Counter</b> — 24-bit anti-replay radio frame counter inside the key fob (+1 on each button press). "
                "Leave at <b>0</b> for fresh adaptation — BCM synchronizes the counter on button press (normal window +1..359, double-press resync up to +11,159).",
            )
        )
        sec_cfg.body.addWidget(cnt_note)

        btn_adapt = button(tr("Адаптировать ключи (80 01 + 80 02)", "Adapt keys (80 01 + 80 02)"), "PrimaryBtn", slot=self.action_adapt_selected_ffb)
        btn_clr = button(tr("Очистить слоты (80 02 00)", "Clear slots (80 02 00)"), "GhostBtn", slot=self.action_clear_all_ffb)
        for b in (btn_adapt, btn_clr):
            b.setEnabled(not busy)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        sec_cfg.add_footer(btn_adapt, btn_clr)
        lay.addWidget(sec_cfg)

        # Card 2: One-click cluster-driven stock protocol sync over CAN
        sec_auto = self._compact_section(Section())
        sec_auto.set_text(
            tr("Адаптация по данным панели приборов 17 FPK_E", "Adaptation from 17 FPK_E instrument cluster data"),
            tr(
                "Штатный протокол канала 3 WFS (0x17F8140E → 0x17FA0E14): 80 01 || AES_GFA(K_ffb) → C0 01, затем 80 02 || ключи с проверкой DID 0x0A65 и CRC-32 → C0 02.",
                "Stock WFS Channel 3 protocol (0x17F8140E → 0x17FA0E14): 80 01 || AES_GFA(K_ffb) → C0 01, then 80 02 || key records verified against DID 0x0A65 and CRC-32 → C0 02.",
            ),
        )
        if cm.get("kc_hex"):
            c_txt = tr(
                f"Открыт дамп 17 ({cm.get('part_number') or 'FPK_E'}, ключей: {cm.get('learned_keys', 0)})",
                f"17 dump open ({cm.get('part_number') or 'FPK_E'}, keys: {cm.get('learned_keys', 0)})",
            )
            sec_auto.head.addWidget(status_readout(c_txt, "info"), 0, Qt.AlignmentFlag.AlignVCenter)
        else:
            sec_auto.head.addWidget(
                status_readout(tr("Дамп 17 FPK_E не открыт", "17 FPK_E dump not open"), "muted"),
                0,
                Qt.AlignmentFlag.AlignVCenter,
            )

        self.chk_sync_gfa = QCheckBox(
            tr(
                "Синхронизировать GFA блока BCM с GFA (/1) панели приборов (2E 00BD)",
                "Sync BCM GFA to cluster GFA (/1) via 2E 00BD before sending 80 01",
            )
        )
        self.chk_sync_gfa.setChecked(self._draft_sync_gfa)
        self.chk_sync_gfa.toggled.connect(lambda v: setattr(self, "_draft_sync_gfa", bool(v)))
        sec_auto.body.addWidget(self.chk_sync_gfa)

        btn_auto_can = button(
            tr("Считать панель приборов 17 по CAN и адаптировать FFB", "Read 17 cluster over CAN & adapt FFB"),
            "PrimaryBtn",
            slot=self.action_read_cluster_and_adapt_ffb,
        )
        btn_auto_can.setEnabled(not busy)
        btn_auto_can.setCursor(Qt.CursorShape.PointingHandCursor)
        sec_auto.add_footer(btn_auto_can)
        lay.addWidget(sec_auto)

    # ────────────────────────────── Page 3: Passport & Status ──────────────────────────────

    def _build_status_page(self, lay: QVBoxLayout) -> None:
        busy = self.runner.is_busy

        sec_st = self._compact_section(Section())
        sec_st.set_text(
            tr("Диагностика Komponentenschutz (KS) и радиоканала FFB", "Komponentenschutz (KS) & FFB diagnostics"),
            tr(
                "Текущее состояние защиты компонентов (DID 0x03DE / 0x0440 / 0x02F9) и УВЧ-приёмника (DID 0x0A65 / 0x1983 / 0x24A6).",
                "Current Component Protection state (DID 0x03DE / 0x0440 / 0x02F9) and UHF receiver diagnostics (DID 0x0A65 / 0x1983 / 0x24A6).",
            ),
        )
        cp_cnt = self._status.get("cp_mismatch_counter")
        if cp_cnt is not None:
            if self._status.get("cp_active_fault"):
                sec_st.head.addWidget(status_readout(tr(f"CP активна (03DE={cp_cnt})", f"CP active (03DE={cp_cnt})"), "err"))
            else:
                sec_st.head.addWidget(status_readout(tr(f"CP в норме (03DE={cp_cnt})", f"CP OK (03DE={cp_cnt})"), "ok"))

        grid = QGridLayout()
        grid.setHorizontalSpacing(22)
        grid.setVerticalSpacing(6)
        last_slot = self._status.get("ffb_active_slot")
        last_slot_txt = (
            tr("нет нажатий", "no press")
            if last_slot in (None, 0xFF)
            else f"#{last_slot}"
        )
        pairs = [
            (
                tr("СЧЁТЧИК ОШИБОК CP (0x03DE)", "CP MISMATCH (0x03DE)"),
                f"{cp_cnt} " + (tr("(>= 31: DTC U110100)", "(>= 31: DTC U110100)") if self._status.get("cp_active_fault") else tr("(норма)", "(OK)"))
                if cp_cnt is not None
                else "—",
            ),
            (
                tr("СОСТОЯНИЕ IKA (0x0440)", "IKA STATE (0x0440)"),
                (tr("Virgin (заводской)", "Virgin (factory)") if self._status.get("ika_virgin") else tr("Персонализирован", "Personalized"))
                if self._status.get("ika_virgin") is not None
                else "—",
            ),
            (tr("ВЫЗОВ KS ODIS (0x02F9)", "KS CHALLENGE (0x02F9)"), self._status.get("challenge_02f9") or "—"),
            (
                tr("ЧАСТОТА FFB (0x0A65)", "FFB FREQ (0x0A65)"),
                f"{self._status.get('freq_label')} (0x{int(self._status.get('freq_code', 3)):02X})" if self._status.get("rf_0a65_hex") else "—",
            ),
            (
                tr("КЛЮЧИ FFB (0x1983)", "FFB STATUS (0x1983)"),
                tr(
                    f"обучено {self._status.get('ffb_learned_count')}, последний: {last_slot_txt}",
                    f"learned {self._status.get('ffb_learned_count')}, last: {last_slot_txt}",
                )
                if self._status.get("ffb_1983_hex")
                else "—",
            ),
            (tr("ПРОФИЛЬ ОЗУ", "RAM PROFILE"), str(self._profile.get("label") or self._profile.get("id") or "—")),
        ]
        for idx, (k_txt, v_txt) in enumerate(pairs):
            r, c = divmod(idx, 3)
            lk = group_label(k_txt)
            lv = QLabel(v_txt)
            lv.setFont(mono_font(12))
            lv.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(lk, r * 2, c)
            grid.addWidget(lv, r * 2 + 1, c)
        sec_st.body.addLayout(grid)

        if self._status.get("rf_0a65_hex") or self._status.get("ffb_24a6_hex"):
            strip = QFrame()
            strip.setObjectName("ResultStrip")
            sl = QHBoxLayout(strip)
            sl.setContentsMargins(10, 5, 10, 5)
            sl.setSpacing(16)
            for tag, raw_val in (
                ("0A65", self._status.get("rf_0a65_hex") or "—"),
                ("1983", self._status.get("ffb_1983_hex") or "—"),
                ("24A6", self._status.get("ffb_24a6_hex") or "—"),
            ):
                lbl = QLabel(f"{tag}: {raw_val}")
                lbl.setFont(mono_font(11))
                set_tone(lbl, "muted")
                sl.addWidget(lbl)
            sl.addStretch(1)
            sec_st.body.addWidget(strip)

        btn_poll = button(tr("Опросить статус 09 BCM", "Poll 09 BCM status"), "PrimaryBtn", slot=self.action_read_status)
        btn_poll.setEnabled(not busy)
        btn_poll.setCursor(Qt.CursorShape.PointingHandCursor)
        sec_st.add_footer(btn_poll)
        lay.addWidget(sec_st)

        # Learned FFB slots from NvM 0x05..0x19
        sec_slots = self._compact_section(Section())
        sec_slots.set_text(
            tr("Слоты радиоключей FFB в NvM (0x05..0x19)", "FFB remote key slots in NvM (0x05..0x19)"),
            tr(
                "Считываются в сессии разработки (10 4F → 23 12 <NvM_ID> 00 00): серийные номера (0x13..0x19) и скользящие счётчики (0x05..0x0B).",
                "Read in Development Session (10 4F → 23 12 <NvM_ID> 00 00): Serial IDs (0x13..0x19) and rolling counters (0x05..0x0B).",
            ),
        )
        slots = self._status.get("ffb_slots") or []
        if slots:
            s_grid = QGridLayout()
            s_grid.setHorizontalSpacing(18)
            s_grid.setVerticalSpacing(4)
            for col, h_txt in enumerate(
                (tr("СЛОТ", "SLOT"), tr("СЕРИЙНЫЙ ID (BE)", "SERIAL ID (BE)"), tr("СЧЁТЧИК НАЖАТИЙ", "ROLLING COUNTER"), tr("СОСТОЯНИЕ", "STATE"))
            ):
                s_grid.addWidget(group_label(h_txt), 0, col)
            for r_idx, sl_item in enumerate(slots, start=1):
                c0 = QLabel(f"#{sl_item['slot']}")
                c0.setFont(mono_font(11))
                c1 = QLabel(str(sl_item["display_id"]))
                c1.setFont(mono_font(12))
                c1.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                c2 = QLabel(f"{sl_item['rolling_counter']} (0x{sl_item['counter_hex']})" if sl_item["populated"] else "—")
                c2.setFont(mono_font(11))
                if sl_item.get("desynced"):
                    st_lbl = status_readout(tr("рассинхронизирован", "desynced"), "warn")
                elif sl_item["populated"] and sl_item.get("mask_synced"):
                    st_lbl = status_readout(tr("синхронизирован", "synced"), "ok")
                elif sl_item["populated"]:
                    st_lbl = status_readout(tr("обучен", "learned"), "info")
                else:
                    st_lbl = status_readout(tr("пусто", "empty"), "muted")
                s_grid.addWidget(c0, r_idx, 0)
                s_grid.addWidget(c1, r_idx, 1)
                s_grid.addWidget(c2, r_idx, 2)
                s_grid.addWidget(st_lbl, r_idx, 3)
            s_grid.setColumnStretch(3, 1)
            sec_slots.body.addLayout(s_grid)
        else:
            lbl_e = QLabel(
                tr("Нажмите «Опросить статус 09 BCM» для чтения слотов радиоключей из NvM.", "Click “Poll 09 BCM status” to read FFB slots from NvM.")
            )
            lbl_e.setObjectName("Hint")
            sec_slots.body.addWidget(lbl_e)
        lay.addWidget(sec_slots)

    # ────────────────────────────── Page 4: Fault Codes (DTC) ──────────────────────────────

    def _build_dtc_page(self, lay: QVBoxLayout) -> None:
        busy = self.runner.is_busy
        sec = self._compact_section(Section())
        sec.set_text(
            tr("Ошибки блока 09 BCM (UDS 19 02 / 14 FF FF FF)", "09 BCM fault codes (UDS 19 02 / 14 FF FF FF)"),
            tr(
                "Расшифровка неисправностей по базе ODIS BV_CentrElectUDS (VW37X / SK37X), включая коды защиты компонентов U110100 (0xEA6400) и U110000 (0xD10000).",
                "Decoded from ODIS BV_CentrElectUDS (VW37X / SK37X), including Component Protection DTCs U110100 (0xEA6400) and U110000 (0xD10000).",
            ),
        )
        if self._dtcs is None:
            lbl = QLabel(tr("Ошибки ещё не считывались.", "Fault codes have not been read yet."))
            lbl.setObjectName("Hint")
            sec.body.addWidget(lbl)
        elif not self._dtcs:
            sec.head.addWidget(status_readout(tr("Ошибок нет", "No faults"), "ok"))
            lbl = QLabel(tr("В памяти 09 BCM нет активных или сохранённых неисправностей.", "No active or stored fault codes in 09 BCM."))
            lbl.setObjectName("Hint")
            sec.body.addWidget(lbl)
        else:
            n_active = sum(1 for d in self._dtcs if d.get("active"))
            n_stored = len(self._dtcs) - n_active
            summary_txt = tr(
                f"Найдено: {len(self._dtcs)} (активных: {n_active}, в памяти: {n_stored})",
                f"Found: {len(self._dtcs)} ({n_active} active, {n_stored} stored)",
            )
            sec.head.addWidget(status_readout(summary_txt, "err" if n_active else "warn"))

            d_grid = QGridLayout()
            d_grid.setHorizontalSpacing(14)
            d_grid.setVerticalSpacing(6)
            for col, h_txt in enumerate(
                (tr("КОД ODIS", "ODIS CODE"), tr("UDS", "UDS"), tr("СТАТУС", "STATUS"), tr("ОПИСАНИЕ", "DESCRIPTION"))
            ):
                d_grid.addWidget(group_label(h_txt), 0, col)
            for idx, item in enumerate(self._dtcs, start=1):
                disp_code = str(item.get("display") or item.get("code") or item.get("code_hex") or "—")
                raw_code = str(item.get("code") or item.get("code_hex") or "")
                st_byte = str(item.get("status") or item.get("status_hex") or "")
                st_detail = str(item.get("status_text") or "")
                is_active = bool(item.get("active"))

                c0 = QLabel(disp_code)
                c0.setFont(mono_font(12, bold=True))
                c0.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

                c1 = QLabel(raw_code)
                c1.setFont(mono_font(11))
                set_tone(c1, "muted")
                c1.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

                st_badge_txt = (
                    tr("активна", "active") if is_active else tr("в памяти", "stored")
                ) + (f" · {st_byte}" if st_byte else "")
                c2 = status_readout(st_badge_txt, "err" if is_active else "warn")
                if st_detail:
                    c2.setToolTip(st_detail)

                desc_box = QVBoxLayout()
                desc_box.setContentsMargins(0, 0, 0, 0)
                desc_box.setSpacing(1)
                c3 = QLabel(str(item.get("description") or "—"))
                c3.setWordWrap(True)
                c3.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                desc_box.addWidget(c3)
                if st_detail:
                    c3_sub = QLabel(st_detail)
                    c3_sub.setObjectName("Hint")
                    c3_sub.setWordWrap(True)
                    desc_box.addWidget(c3_sub)

                d_grid.addWidget(c0, idx, 0, Qt.AlignmentFlag.AlignTop)
                d_grid.addWidget(c1, idx, 1, Qt.AlignmentFlag.AlignTop)
                d_grid.addWidget(c2, idx, 2, Qt.AlignmentFlag.AlignTop)
                d_grid.addLayout(desc_box, idx, 3)
            d_grid.setColumnStretch(3, 1)
            sec.body.addLayout(d_grid)

        btn_rd = button(tr("Считать DTC", "Read DTCs"), "PrimaryBtn", slot=self.action_read_dtc)
        btn_cl = button(tr("Сбросить DTC", "Clear DTCs"), "GhostBtn", slot=self.action_clear_dtc)
        for b in (btn_rd, btn_cl):
            b.setEnabled(not busy)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        sec.add_footer(btn_rd, btn_cl)
        lay.addWidget(sec)

    # ────────────────────────────── Cluster Material Sync ──────────────────────────────

    def _on_kc_text_changed(self, txt: str) -> None:
        self._draft_ffb_kc = txt
        cleaned = "".join(txt.split()).replace("0x", "").replace("0X", "")
        if len(cleaned) == 32:
            try:
                k_ffb = bcm_derive_k_ffb(bytes.fromhex(cleaned)).hex().upper()
                self._draft_ffb_kffb = k_ffb
                if hasattr(self, "ed_ffb_kffb") and _qt_valid(self.ed_ffb_kffb):
                    self.ed_ffb_kffb.setText(k_ffb)
            except ValueError:
                pass

    def _apply_cluster_material_to_drafts(self, mat: dict[str, Any]) -> None:
        self._cluster_material = mat
        if mat.get("kc_hex"):
            self._draft_ffb_kc = str(mat["kc_hex"]).upper()
        if mat.get("k_ffb_hex"):
            self._draft_ffb_kffb = str(mat["k_ffb_hex"]).upper()
        if mat.get("gfa_hex") and not self._draft_ffb_gfa and not self._gfa_hex:
            self._draft_ffb_gfa = str(mat["gfa_hex"]).upper()
        bcm_by_slot = {
            int(s["slot"]): s
            for s in (self._status.get("ffb_slots") or [])
            if s.get("populated")
        }
        bcm_by_serial = {
            str(s.get("display_id") or "").upper(): s
            for s in bcm_by_slot.values()
        }
        active_tp = {int(t["slot_number"]): t for t in (mat.get("active_transponders") or [])}
        for idx in range(7):
            tp = active_tp.get(idx + 1)
            if tp is not None:
                ser_str = str(tp.get("display_id") or "").upper()
                cnt_val = int(tp.get("rolling_counter", 0))
                b_match = bcm_by_serial.get(ser_str) or bcm_by_slot.get(idx + 1)
                in_bcm = bool(b_match and str(b_match.get("display_id") or "").upper() == ser_str)
                if in_bcm and int(b_match.get("rolling_counter", 0)) > cnt_val:
                    cnt_val = int(b_match["rolling_counter"])
                self._draft_ffb_rows[idx] = {
                    "enabled": True,
                    "serial": ser_str,
                    "counter": cnt_val,
                    "source": "cluster",
                    "in_bcm": in_bcm,
                }
            else:
                self._draft_ffb_rows[idx] = {
                    "enabled": False,
                    "serial": "",
                    "counter": 0,
                    "source": "manual",
                }

    def _apply_bcm_slots_to_drafts(self, *, refresh_ui: bool = True) -> None:
        slots = {int(s["slot"]): s for s in (self._status.get("ffb_slots") or [])}
        if not slots:
            return
        for idx in range(7):
            sl = slots.get(idx + 1)
            if sl and sl.get("populated"):
                self._draft_ffb_rows[idx] = {
                    "enabled": True,
                    "serial": str(sl.get("display_id") or ""),
                    "counter": int(sl.get("rolling_counter", 0)),
                    "source": "bcm",
                    "bcm_synced": bool(sl.get("mask_synced")),
                    "desynced": bool(sl.get("desynced")),
                }
            else:
                self._draft_ffb_rows[idx] = {
                    "enabled": False,
                    "serial": "",
                    "counter": 0,
                    "source": "manual",
                }
        if refresh_ui:
            self.refresh()

    def _sync_ffb_drafts_from_state(self) -> None:
        """Auto-populate FFB key slots directly from BCM NvM (or merge with open 17 FPK_E cluster material)."""
        if self._cluster_material and self._cluster_material.get("kc_hex"):
            self._apply_cluster_material_to_drafts(self._cluster_material)
        elif self._status.get("ffb_slots"):
            self._apply_bcm_slots_to_drafts(refresh_ui=False)

    def _sync_cluster_material_if_available(self, *, silent: bool = True) -> None:
        if self._cluster_provider is None:
            return
        cluster_info = self._cluster_provider()
        if not cluster_info or not cluster_info.get("dflash_bytes"):
            if not silent:
                QMessageBox.information(
                    self,
                    "ContiTool",
                    tr(
                        "Дамп DataFlash панели приборов 17 FPK_E не открыт. Используйте «Считать панель приборов 17 по CAN и адаптировать FFB» или «Загрузить Dflash.bin…».",
                        "No 17 FPK_E cluster DataFlash is open. Use “Read 17 cluster over CAN & adapt FFB” or “Load Dflash.bin…”.",
                    ),
                )
            return
        freq = int(self._status.get("freq_code", self._draft_ffb_freq))
        mat = bcm_extract_cluster_ffb_material(
            cluster_info["dflash_bytes"],
            cluster_info.get("cflash_bytes"),
            freq_code=freq,
        )
        self._apply_cluster_material_to_drafts(mat)
        if not silent:
            self.refresh()

    def _fill_gfa_from_cluster(self) -> None:
        self._sync_cluster_material_if_available(silent=True)
        gfa_hex = (self._cluster_material or {}).get("gfa_hex", "")
        if not gfa_hex:
            QMessageBox.information(
                self,
                "ContiTool",
                tr(
                    "В рабочем пространстве не открыт дамп DataFlash панели приборов 17 FPK_E с ключом GFA (/1, EEL 0x6B).",
                    "No 17 FPK_E DataFlash dump containing GFA (/1, EEL 0x6B) is currently loaded.",
                ),
            )
            return
        self._draft_new_gfa = gfa_hex.upper()
        if hasattr(self, "ed_write_new_gfa") and _qt_valid(self.ed_write_new_gfa):
            self.ed_write_new_gfa.setText(self._draft_new_gfa)

    def action_load_cluster_dflash_file(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            tr("Выберите DataFlash (Dflash.bin) панели приборов 17 FPK_E", "Select 17 FPK_E DataFlash (Dflash.bin)"),
            str(Path.cwd()),
            "Binary (*.bin *.raw);;All Files (*)",
        )
        if not path_str:
            return
        try:
            raw = Path(path_str).read_bytes()
            freq = int(self._status.get("freq_code", self._draft_ffb_freq))
            mat = bcm_extract_cluster_ffb_material(raw, freq_code=freq)
            self._apply_cluster_material_to_drafts(mat)
            self.refresh()
        except Exception as exc:
            QMessageBox.warning(self, "ContiTool", str(exc))

    # ────────────────────────────── Live CAN Actions ──────────────────────────────

    def action_read_all(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        sw_prof = self._selected_sw_profile()
        self.runner.run_task(
            tr("Опрос 09 BCM (паспорт, статус, радиоключи FFB, ошибки)", "Polling 09 BCM (passport, status, FFB keys, DTCs)"),
            lambda rep: can_bcm_read_all(
                port,
                interface=iface,
                via_gateway=self._via_gateway,
                gateway_bridge=self._gateway_bridge,
                gateway_channel=self._gateway_channel,
                sw_profile=sw_prof,
                include_keys=False,
                reporter=rep,
            ),
            on_success=self._on_all_read,
        )

    def _on_all_read(self, res: dict[str, Any]) -> None:
        if isinstance(res.get("passport"), dict):
            self._passport.update(res["passport"])
        if isinstance(res.get("status"), dict):
            self._status = res["status"]
            if self._status.get("rf_0a65_hex") and "freq_code" in self._status:
                self._draft_ffb_freq = int(self._status["freq_code"])
        if isinstance(res.get("profile"), dict):
            self._profile = res["profile"]
        if isinstance(res.get("dtcs"), list):
            self._dtcs = list(res["dtcs"])
        if res.get("ika_hex"):
            self._ika_hex = str(res["ika_hex"])
            self._draft_cur_ika = self._ika_hex.upper()
        if res.get("gfa_working_hex"):
            self._gfa_hex = str(res["gfa_working_hex"])
            if not self._draft_new_gfa:
                self._draft_new_gfa = self._gfa_hex.upper()
            self._draft_ffb_gfa = self._gfa_hex.upper()
        if res.get("k_ffb_hex"):
            self._draft_ffb_kffb = str(res["k_ffb_hex"]).upper()
        self._sync_ffb_drafts_from_state()
        self.refresh()
        self.changed.emit()

    def action_read_status(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        sw_prof = self._selected_sw_profile()
        self.runner.run_task(
            tr("Опрос паспорта и статуса 09 BCM (UDS 0x70E)", "Polling 09 BCM passport & status (UDS 0x70E)"),
            lambda rep: can_bcm_status(
                port,
                interface=iface,
                via_gateway=self._via_gateway,
                gateway_bridge=self._gateway_bridge,
                gateway_channel=self._gateway_channel,
                sw_profile=sw_prof,
                include_nvm_slots=True,
                reporter=rep,
            ),
            on_success=self._on_status_read,
        )

    def _on_status_read(self, res: dict[str, Any]) -> None:
        if isinstance(res.get("passport"), dict):
            self._passport.update(res["passport"])
        if isinstance(res.get("status"), dict):
            self._status = res["status"]
            if self._status.get("rf_0a65_hex") and "freq_code" in self._status:
                self._draft_ffb_freq = int(self._status["freq_code"])
        if isinstance(res.get("profile"), dict):
            self._profile = res["profile"]
        self._sync_ffb_drafts_from_state()
        self.refresh()
        self.changed.emit()

    def action_read_gfa(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        if not run_dialog(BcmReadKeysDialog(include_ika=False, status=self._status, parent=self)):
            return
        port, iface = self.conn.port, self.conn.interface
        sw_prof = self._selected_sw_profile()
        self.runner.run_task(
            tr("Чтение GFA из 09 BCM (WFS Job 5 + XCP)", "Reading GFA from 09 BCM (WFS Job 5 + XCP)"),
            lambda rep: can_bcm_read_gfa(
                port,
                interface=iface,
                via_gateway=self._via_gateway,
                gateway_bridge=self._gateway_bridge,
                gateway_channel=self._gateway_channel,
                sw_profile=sw_prof,
                reporter=rep,
            ),
            on_success=self._on_keys_read,
        )

    def action_read_keys(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        if not run_dialog(BcmReadKeysDialog(include_ika=True, status=self._status, parent=self)):
            return
        port, iface = self.conn.port, self.conn.interface
        sw_prof = self._selected_sw_profile()
        self.runner.run_task(
            tr("Чтение IKA + GFA из 09 BCM (WFS Ch 3 + XCP)", "Reading IKA + GFA from 09 BCM (WFS Ch 3 + XCP)"),
            lambda rep: can_bcm_read_keys(
                port,
                interface=iface,
                via_gateway=self._via_gateway,
                gateway_bridge=self._gateway_bridge,
                gateway_channel=self._gateway_channel,
                sw_profile=sw_prof,
                reporter=rep,
            ),
            on_success=self._on_keys_read,
        )

    def _on_keys_read(self, res: dict[str, Any]) -> None:
        if isinstance(res.get("passport"), dict):
            self._passport.update(res["passport"])
        if isinstance(res.get("status"), dict):
            self._status = res["status"]
            if self._status.get("rf_0a65_hex") and "freq_code" in self._status:
                self._draft_ffb_freq = int(self._status["freq_code"])
        if isinstance(res.get("profile"), dict):
            self._profile = res["profile"]
        if res.get("ika_hex"):
            self._ika_hex = str(res["ika_hex"])
            self._draft_cur_ika = self._ika_hex.upper()
        if res.get("gfa_working_hex"):
            self._gfa_hex = str(res["gfa_working_hex"])
            if not self._draft_new_gfa:
                self._draft_new_gfa = self._gfa_hex.upper()
            self._draft_ffb_gfa = self._gfa_hex.upper()
        if res.get("k_ffb_hex"):
            self._draft_ffb_kffb = str(res["k_ffb_hex"]).upper()
        self._sync_ffb_drafts_from_state()
        self.refresh()
        self.changed.emit()

    def action_export_keys_json(self) -> None:
        path_str, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить данные 09 BCM в JSON", "Save 09 BCM data to JSON"),
            str(Path.cwd() / f"bcm_{self.part_number.replace(' ', '_')}_keys.json"),
            "JSON (*.json)",
        )
        if not path_str:
            return
        payload = {
            "ecu_kind": "bcm",
            "passport": self._passport,
            "profile": self._profile.get("id"),
            "ika_hex": self._ika_hex,
            "gfa_working_hex": self._gfa_hex,
            "status": self._status,
        }
        Path(path_str).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self.note.emit(tr(f"Данные 09 BCM сохранены: {path_str}", f"09 BCM data saved: {path_str}"))

    def action_write_keys(self, *, include_ika: bool) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        cur_ika = (self.ed_write_cur_ika.text() if hasattr(self, "ed_write_cur_ika") else self._draft_cur_ika).strip()
        new_ika = ((self.ed_write_new_ika.text() if hasattr(self, "ed_write_new_ika") else self._draft_new_ika).strip() if include_ika else "")
        new_gfa = (self.ed_write_new_gfa.text() if hasattr(self, "ed_write_new_gfa") else self._draft_new_gfa).strip()
        hard_reset = self._draft_write_reset

        if not cur_ika:
            QMessageBox.warning(
                self,
                "ContiTool",
                tr("Укажите текущий IKA блока 09 BCM (или нажмите «Считать IKA + GFA»).", "Enter the current 09 BCM IKA (or click “Read IKA + GFA”)."),
            )
            return
        if include_ika and not new_ika:
            QMessageBox.warning(
                self,
                "ContiTool",
                tr("Укажите новый IKA (32 hex) для DID 0x00BE.", "Enter the new IKA (32 hex) for DID 0x00BE."),
            )
            return
        if not include_ika and not new_gfa:
            QMessageBox.warning(
                self,
                "ContiTool",
                tr("Укажите целевой GFA (32 hex) для DID 0x00BD.", "Enter the target GFA (32 hex) for DID 0x00BD."),
            )
            return

        port, iface = self.conn.port, self.conn.interface
        sw_prof = self._selected_sw_profile()
        self.runner.run_task(
            tr("Запись ключей CP (2E 00BE / 00BD) в 09 BCM", "Writing CP keys (2E 00BE / 00BD) to 09 BCM"),
            lambda rep: can_bcm_write_keys(
                port,
                current_ika=cur_ika,
                new_ika=new_ika or None,
                new_gfa=new_gfa or None,
                hard_reset=hard_reset,
                interface=iface,
                via_gateway=self._via_gateway,
                gateway_bridge=self._gateway_bridge,
                gateway_channel=self._gateway_channel,
                sw_profile=sw_prof,
                reporter=rep,
            ),
            on_success=self._on_keys_written,
        )

    def _on_keys_written(self, res: dict[str, Any]) -> None:
        if res.get("active_ika_hex"):
            self._ika_hex = str(res["active_ika_hex"])
            self._draft_cur_ika = self._ika_hex.upper()
        if res.get("new_gfa_hex"):
            self._gfa_hex = str(res["new_gfa_hex"])
            self._draft_new_gfa = self._gfa_hex.upper()
            self._draft_ffb_gfa = self._gfa_hex.upper()
        if isinstance(res.get("status_after"), dict):
            self._status = res["status_after"]
        self.refresh()
        self.changed.emit()

    def action_adapt_selected_ffb(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        gfa_txt = (self.ed_ffb_gfa.text() if hasattr(self, "ed_ffb_gfa") and _qt_valid(self.ed_ffb_gfa) else self._draft_ffb_gfa).strip()
        kc_txt = (self.ed_ffb_kc.text() if hasattr(self, "ed_ffb_kc") and _qt_valid(self.ed_ffb_kc) else self._draft_ffb_kc).strip()
        kffb_txt = (self.ed_ffb_kffb.text() if hasattr(self, "ed_ffb_kffb") and _qt_valid(self.ed_ffb_kffb) else self._draft_ffb_kffb).strip()
        if hasattr(self, "cmb_ffb_freq") and _qt_valid(self.cmb_ffb_freq) and self.cmb_ffb_freq.currentData() is not None:
            self._draft_ffb_freq = int(self.cmb_ffb_freq.currentData())
        freq_code = int(self._draft_ffb_freq)

        if not kffb_txt and not kc_txt:
            QMessageBox.warning(
                self,
                "ContiTool",
                tr(
                    "Укажите мастер-ключ K_c (или K_ffb), либо нажмите «Считать панель приборов 17 по CAN и адаптировать FFB».",
                    "Enter K_c (or K_ffb), or click “Read 17 cluster over CAN & adapt FFB”.",
                ),
            )
            return

        keys_list: list[dict[str, Any]] = []
        for idx, row_data in enumerate(self._draft_ffb_rows, start=1):
            if not row_data["enabled"]:
                continue
            ser_hex = "".join(str(row_data["serial"]).split()).replace("0x", "").replace("0X", "")
            if not ser_hex:
                continue
            if len(ser_hex) != 8:
                QMessageBox.warning(
                    self,
                    "ContiTool",
                    tr(f"Слот #{idx}: серийный ID ключа должен содержать 8 hex-символов.", f"Slot #{idx}: Serial ID must be 8 hex chars."),
                )
                return
            keys_list.append(
                {
                    "slot_number": idx,
                    "serial_id": ser_hex,
                    "rolling_counter": int(row_data["counter"]),
                    "freq_code": freq_code,
                }
            )

        if not keys_list:
            QMessageBox.warning(
                self,
                "ContiTool",
                tr("Выберите хотя бы один слот с заполненным серийным ID.", "Select at least one key slot with a Serial ID."),
            )
            return

        port, iface = self.conn.port, self.conn.interface
        sw_prof = self._selected_sw_profile()
        self.runner.run_task(
            tr("Адаптация радиоключей FFB (WFS Ch 3: 80 01 + 80 02)", "Adapting FFB remote keys (WFS Ch 3: 80 01 + 80 02)"),
            lambda rep: can_bcm_adapt_ffb(
                port,
                gfa=gfa_txt or None,
                kc=kc_txt or None,
                k_ffb=kffb_txt or None,
                keys=keys_list,
                freq_code=freq_code,
                verify_after=True,
                interface=iface,
                via_gateway=self._via_gateway,
                gateway_bridge=self._gateway_bridge,
                gateway_channel=self._gateway_channel,
                sw_profile=sw_prof,
                reporter=rep,
            ),
            on_success=self._on_ffb_adapted,
        )

    def action_clear_all_ffb(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        gfa_txt = self._draft_ffb_gfa.strip()
        kc_txt = self._draft_ffb_kc.strip()
        kffb_txt = self._draft_ffb_kffb.strip() or ("00" * 16)
        port, iface = self.conn.port, self.conn.interface
        sw_prof = self._selected_sw_profile()
        self.runner.run_task(
            tr("Очистка всех слотов радиоключей FFB (80 02 00)", "Clearing all FFB remote key slots (80 02 00)"),
            lambda rep: can_bcm_adapt_ffb(
                port,
                gfa=gfa_txt or None,
                kc=kc_txt or None,
                k_ffb=kffb_txt,
                clear_all=True,
                verify_after=True,
                interface=iface,
                via_gateway=self._via_gateway,
                gateway_bridge=self._gateway_bridge,
                gateway_channel=self._gateway_channel,
                sw_profile=sw_prof,
                reporter=rep,
            ),
            on_success=self._on_ffb_adapted,
        )

    def action_read_cluster_and_adapt_ffb(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        sw_prof = self._selected_sw_profile()
        sync_gfa = self._draft_sync_gfa
        self.runner.run_task(
            tr("Чтение 17 FPK_E по CAN и адаптация FFB в 09 BCM", "Reading 17 FPK_E over CAN and adapting FFB in 09 BCM"),
            lambda rep: can_bcm_adapt_ffb_from_cluster(
                port,
                fpke_dflash=None,
                sync_bcm_gfa_to_cluster=sync_gfa,
                current_bcm_ika=self._ika_hex or None,
                interface=iface,
                via_gateway=self._via_gateway,
                gateway_bridge=self._gateway_bridge,
                gateway_channel=self._gateway_channel,
                sw_profile=sw_prof,
                reporter=rep,
            ),
            on_success=self._on_ffb_adapted,
        )

    def _on_ffb_adapted(self, res: dict[str, Any]) -> None:
        if res.get("gfa_hex"):
            self._gfa_hex = str(res["gfa_hex"])
            self._draft_ffb_gfa = self._gfa_hex.upper()
        if isinstance(res.get("status_after"), dict):
            self._status = res["status_after"]
        if isinstance(res.get("cluster_material"), dict):
            self._apply_cluster_material_to_drafts(res["cluster_material"])
        else:
            self._sync_ffb_drafts_from_state()
        self.refresh()
        self.changed.emit()

    def action_read_dtc(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        self.runner.run_task(
            tr("Чтение ошибок 09 BCM (19 02)", "Reading 09 BCM fault codes (19 02)"),
            lambda rep: can_uds_read_dtc(
                port,
                tx_id=BCM_UDS_TX_ID,
                rx_id=BCM_UDS_RX_ID,
                ecu_kind="bcm",
                via_gateway=self._via_gateway,
                interface=iface,
                reporter=rep,
            ),
            on_success=self._on_dtc_read,
        )

    def action_clear_dtc(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        self.runner.run_task(
            tr("Сброс ошибок 09 BCM (14 FF FF FF)", "Clearing 09 BCM fault codes (14 FF FF FF)"),
            lambda rep: can_uds_clear_dtc(
                port,
                tx_id=BCM_UDS_TX_ID,
                rx_id=BCM_UDS_RX_ID,
                ecu_kind="bcm",
                via_gateway=self._via_gateway,
                interface=iface,
                reporter=rep,
            ),
            on_success=lambda _r: self._on_dtc_read({"dtcs": []}),
        )

    def _on_dtc_read(self, res: dict[str, Any]) -> None:
        self._dtcs = list(res.get("dtcs") or [])
        self.refresh()
