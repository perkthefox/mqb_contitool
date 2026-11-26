"""Working screen for VAG MQB 2B ELV / ESCL / J764 (Marquardt 3Q0 905 861): DFLASH 32/64 KB, WFS5, Virgin, IDac, DTC."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import html
import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
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
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid as _qt_valid

from contitool.can.ecus import DiscoveredEcu
from contitool.can.elv import (
    can_elv_adapt,
    can_elv_check_bootloader,
    can_elv_clear_dtc,
    can_elv_read_dflash,
    can_elv_reset_idac,
    can_elv_status,
    can_elv_virginize,
)
from contitool.core.dtc import describe_elv, status_text as dtc_status_text
from contitool.core.elv import (
    ELV_DFLASH_COMPACT_SIZE,
    ELV_DFLASH_RAW64K_SIZE,
    ELV_UDS_RX_ID,
    ELV_UDS_TX_ID,
    elv_adapt_dflash,
    elv_bolt_state_label,
    elv_extract_cluster_material,
    elv_idac_state_label,
    elv_is_dflash_bytes,
    elv_mode_label,
    elv_parse_dflash,
    elv_virginize_dflash,
)
from contitool.gui import theme
from contitool.gui.connection import CanConnection, ensure_ready
from contitool.gui.theme import mono_font, set_tone
from contitool.gui.widgets.page import (
    Callout,
    Dialog,
    Section,
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
from contitool.storage import new_session, unit_name

ELV_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("main", ("immo", "adapt")),
    ("service", ("status", "dtc")),
)

_SIBLING_DFLASH_NAMES: tuple[str, ...] = (
    "elv_dflash_32k.bin",
    "elv_dflash_64k.bin",
    "elv_dflash_32k_backup.bin",
    "elv_dflash.bin",
)


def _elv_nav_title(key: str) -> str:
    return {
        "immo": tr("Иммобилайзер и ключи", "Immobilizer & Keys"),
        "adapt": tr("Привязка и сброс", "Adaptation & Reset"),
        "status": tr("Паспорт и память", "Passport & Memory"),
        "dtc": tr("Ошибки (DTC)", "Fault codes (DTC)"),
    }[key]


def _clean_hex(txt: str) -> str:
    return "".join(txt.split()).replace("0x", "").replace("0X", "")


def _validate_hex_exact(txt: str, expected_bytes: int, label: str) -> str:
    cleaned = _clean_hex(txt)
    if len(cleaned) != expected_bytes * 2:
        raise ValueError(
            tr(
                f"Поле «{label}» должно содержать ровно {expected_bytes * 2} HEX-символов ({expected_bytes} Б).",
                f"“{label}” must be exactly {expected_bytes * 2} hex characters ({expected_bytes} B).",
            )
        )
    try:
        bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(
            tr(
                f"Поле «{label}» содержит недопустимые символы (допускаются только 0–9 и A–F).",
                f"“{label}” contains invalid characters (only 0–9 and A–F are allowed).",
            )
        ) from exc
    return cleaned.upper()


def _parse_hex_byte(txt: str, label: str) -> int:
    cleaned = _clean_hex(txt)
    if not cleaned or len(cleaned) > 2:
        raise ValueError(
            tr(
                f"Поле «{label}» должно быть одним байтом в HEX от 00 до FF.",
                f"“{label}” must be a single hex byte between 00 and FF.",
            )
        )
    try:
        val = int(cleaned, 16)
    except ValueError as exc:
        raise ValueError(
            tr(
                f"Поле «{label}» должно содержать HEX-значение (00..FF).",
                f"“{label}” must be a valid hex byte (00..FF).",
            )
        ) from exc
    if not (0 <= val <= 0xFF):
        raise ValueError(
            tr(
                f"Значение «{label}» должно быть в диапазоне 0x00..0xFF.",
                f"“{label}” must be in range 0x00..0xFF.",
            )
        )
    return val


def _short_mode_badge(mode: int | None) -> tuple[str, str]:
    if mode == 0x01:
        return tr("Новая (Virgin)", "New (Virgin)"), "ok"
    if mode == 0x02:
        return tr("Адаптирована", "Adapted"), "info"
    if mode == 0xFF:
        return tr("Заводская (0xFF)", "Plant (0xFF)"), "warn"
    return tr("Неизвестно", "Unknown"), "muted"


def _is_dtc_active(item: dict[str, Any]) -> bool:
    if "active" in item:
        return bool(item["active"])
    return str(item.get("group") or "").lower() == "active"


def _localize_elv_dtc(item: dict[str, Any]) -> tuple[str, str, str]:
    """Return `(display_code, description, status_text)` in the current UI language."""
    disp = str(item.get("display") or item.get("code_hex") or item.get("code") or "—")
    desc = str(item.get("description") or "—")
    code_raw = item.get("code")
    if isinstance(code_raw, int) and code_raw > 0:
        d_disp, d_desc = describe_elv(code_raw)
        if d_disp:
            disp = d_disp
        if d_desc:
            desc = d_desc
    st_detail = str(item.get("status_text") or "")
    st_raw = item.get("status")
    if isinstance(st_raw, int):
        st_detail = dtc_status_text(st_raw)
    return disp, desc, st_detail


class _ElvNavRow(QWidget):
    """Unified ContiTool sidebar row matching BcmScreen / MrrScreen / FpkeScreen."""

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


class ElvConfirmWriteDialog(Dialog):
    """Confirmation dialog before a mutating CAN write on 2B ELV (`2E 02E2` or `2E 02E1`)."""

    def __init__(
        self,
        *,
        title: str,
        subtitle: str,
        summary_html: str,
        action_label: str,
        via_gateway: bool = False,
        uses_bridge: bool = False,
        is_02e2: bool = True,
        danger: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent, title, subtitle, width=600)
        self.body.setSpacing(10)

        lbl = hint(summary_html)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        self.body.addWidget(lbl)

        safe = Callout("info")
        if via_gateway and not uses_bridge:
            safe.label.setText(
                tr(
                    "<b>Проверка ключа перед записью:</b> программа сверит указанный ключ <code>K_5</code> "
                    "через <code>22 02F9</code>, чтобы не сработал защитный таймер <code>02EF</code>. "
                    "Автоматический бэкап Data Flash по 29-бит CAN через обычный шлюз недоступен.",
                    "<b>Pre-write key check:</b> ContiTool verifies the entered <code>K_5</code> via "
                    "<code>22 02F9</code> so the <code>02EF</code> security lockout timer is not triggered. "
                    "Automatic 29-bit Data Flash backup is unavailable over a UDS-only gateway.",
                )
            )
        else:
            safe.label.setText(
                tr(
                    "<b>Автоматический бэкап и проверка:</b> перед записью программа сохранит резервную копию "
                    "Data Flash и проверит текущий ключ <code>K_5</code> через <code>22 02F9</code>, "
                    "чтобы не сработал защитный таймер <code>02EF</code>.",
                    "<b>Automatic backup & verification:</b> before writing, ContiTool saves a Data Flash backup "
                    "and verifies the current <code>K_5</code> via <code>22 02F9</code> so the <code>02EF</code> "
                    "security lockout timer is not triggered.",
                )
            )
        self.body.addWidget(safe)

        if uses_bridge:
            br_warn = Callout("warn")
            br_warn.label.setText(
                tr(
                    "<b>Через RAM-мост шлюза J533:</b> на время чтения Data Flash шлюз временно приостановит "
                    "обмен по остальным шинам автомобиля — не выключайте питание и не запускайте двигатель до завершения.",
                    "<b>Via J533 RAM-Bridge:</b> the gateway temporarily pauses other vehicle CAN buses while "
                    "reading Data Flash — keep power stable and do not start the engine until finished.",
                )
            )
            self.body.addWidget(br_warn)

        if is_02e2:
            if via_gateway:
                eng_warn = Callout("warn")
                eng_warn.label.setText(
                    tr(
                        "<b>Условие записи (2E 02E2):</b> двигатель автомобиля должен быть заглушен.",
                        "<b>Write precondition (2E 02E2):</b> the vehicle engine must be OFF.",
                    )
                )
                self.body.addWidget(eng_warn)
        else:
            idac_note = Callout("info")
            idac_note.label.setText(
                tr(
                    "<b>Безопасный сброс (2E 02E1):</b> VIN, ключ <code>K_5</code> и PowerClass не изменяются — "
                    "очищается только привязка к старой приборной панели (<code>IDac</code>).",
                    "<b>Non-destructive reset (2E 02E1):</b> VIN, <code>K_5</code>, and PowerClass remain intact — "
                    "only the learned cluster link (<code>IDac</code>) is cleared.",
                )
            )
            self.body.addWidget(idac_note)

        self.btn_ok = button(action_label, "DangerBtn" if danger else "PrimaryBtn", slot=self.accept)
        self.btn_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        self.finish(ok=self.btn_ok)


class ElvScreen(QWidget):
    """Unified workspace for 2B ELV / J764 (Marquardt 3Q0 905 861) matching BcmScreen and MrrScreen."""

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

        self._session_gen: int = 0
        self._is_open: bool = False
        self._offline_mode: bool = False
        self._via_gateway: bool = False
        self._gateway_bridge: bool = False
        self._gateway_channel: int = 0

        self._passport: dict[str, Any] = {}
        self._status: dict[str, Any] = {}
        self._dflash_bytes: bytes | None = None
        self._dflash_parsed: dict[str, Any] | None = None
        self._dflash_path: Path | None = None
        self._report_path: Path | None = None
        self._verify_02f9: dict[str, Any] | None = None
        self._bootloader_check: dict[str, Any] | None = None
        self._dtcs: list[dict[str, Any]] | None = None

        self._cluster_material: dict[str, Any] | None = None
        self._cluster_source_manual: bool = False
        self._cluster_dflash_sha: str = ""

        self._key: str = "immo"
        self._last_rendered_key: str = ""
        self._show_eeelib_records: bool = False
        self._eeelib_table: QFrame | None = None
        self._btn_eeelib_toggle: QPushButton | None = None
        self._eeelib_count: int = 0

        # Persistent drafts across page re-renders
        self._draft_vin: str = ""
        self._draft_new_k5: str = ""
        self._draft_power_class: str = ""
        self._draft_cfg: str = "80"
        self._draft_brand: str = "01"
        self._draft_cur_k5: str = ""
        self._draft_offline_idac: str = ""
        self._draft_virgin_k5: str = ""

        # Live line-edit references synced before rebuilds
        self._ed_vin: QLineEdit | None = None
        self._ed_new_k5: QLineEdit | None = None
        self._ed_pc: QLineEdit | None = None
        self._ed_cfg: QLineEdit | None = None
        self._ed_brand: QLineEdit | None = None
        self._ed_cur_k5: QLineEdit | None = None
        self._ed_offline_idac: QLineEdit | None = None
        self._ed_virgin_k5: QLineEdit | None = None

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
        self._unsub = subscribe_lang_change(lambda _l: self._refresh_all())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.select("immo")
        self._refresh_all()

    # ────────────────────────────── Properties & Lifecycle ──────────────────────────────

    @property
    def is_open(self) -> bool:
        return self._is_open

    @property
    def part_number(self) -> str:
        ident = (self._dflash_parsed or {}).get("identity") or {}
        return str(
            self._passport.get("part_number")
            or ident.get("part_number")
            or self._passport.get("hw_part_number")
            or "3Q0905861"
        )

    @property
    def current_k5_hex(self) -> str:
        b34 = (self._dflash_parsed or {}).get("block34") or {}
        return str(b34.get("slot_a_hex") or "").upper()

    @property
    def current_idp_hex(self) -> str:
        b04 = (self._dflash_parsed or {}).get("block04") or {}
        return str(b04.get("idp_hex") or "").upper()

    def _current_mode(self) -> int | None:
        if "mode" in self._status and self._status["mode"] is not None:
            return int(self._status["mode"])
        b34 = (self._dflash_parsed or {}).get("block34") or {}
        return b34.get("mode")

    def _elv_unit_name(self) -> str:
        ident = (self._dflash_parsed or {}).get("identity") or {}
        fazit = str(self._passport.get("fazit") or ident.get("fazit") or "ELV")
        u_name = unit_name(self.part_number, fazit)
        return "elv_3q0905861" if u_name == "unknown" else u_name

    def _reset_drafts(self, *, keep_cur_k5: str = "") -> None:
        self._draft_vin = ""
        self._draft_new_k5 = ""
        self._draft_power_class = ""
        self._draft_cfg = "80"
        self._draft_brand = "01"
        self._draft_cur_k5 = keep_cur_k5
        self._draft_offline_idac = ""
        self._draft_virgin_k5 = ""

    def select(self, key: str) -> None:
        if key in self._nav_items:
            self.nav.setCurrentItem(self._nav_items[key])

    def open_from_discovered(self, ecu: DiscoveredEcu) -> None:
        """Open the ELV screen from a bus scan card (`2B ELV`)."""
        self._session_gen += 1
        self._is_open = True
        self._offline_mode = False
        self._via_gateway = bool(ecu.via_gateway)
        self._gateway_bridge = bool(ecu.bridge_available)
        self._gateway_channel = 0 if ecu.gateway_channel is None else int(ecu.gateway_channel)
        self._passport = {
            "part_number": ecu.part_number,
            "sw_version": ecu.sw_version,
            "hw_part_number": ecu.hw_number,
            "hw_version": ecu.hw_version,
            "fazit": ecu.fazit,
            "vin": ecu.vin,
            "system_name": ecu.system_name,
            "in_bootloader": ecu.in_fbl,
        }
        self._status = {}
        self._dflash_bytes = None
        self._dflash_parsed = None
        self._dflash_path = None
        self._report_path = None
        self._verify_02f9 = None
        self._dtcs = None
        self._bootloader_check = None
        self._show_eeelib_records = False
        self._draft_cur_k5 = ""
        self._refresh_cluster_from_provider()
        self._refresh_all()
        self.changed.emit()

    def set_routing(
        self,
        *,
        via_gateway: bool = False,
        gateway_bridge: bool = False,
        gateway_channel: int = 0,
    ) -> None:
        self._offline_mode = False
        self._via_gateway = bool(via_gateway)
        self._gateway_bridge = bool(gateway_bridge)
        self._gateway_channel = int(gateway_channel)
        self._refresh_all()

    def open_from_read_result(
        self,
        res: dict[str, Any],
        *,
        via_gateway: bool = False,
        gateway_bridge: bool = False,
        gateway_channel: int = 0,
        dflash_path: Path | None = None,
    ) -> None:
        """Open or update ELV workspace from `can_elv_status` or `can_elv_read_dflash` result."""
        was_open = self._is_open
        self._session_gen += 1
        self._is_open = True
        self._offline_mode = False
        self._via_gateway = bool(via_gateway)
        self._gateway_bridge = bool(gateway_bridge)
        self._gateway_channel = int(gateway_channel)
        self._report_path = None

        if not was_open:
            self._passport = {}
            self._status = {}
            self._dflash_bytes = None
            self._dflash_parsed = None
            self._dflash_path = None
            self._verify_02f9 = None
            self._bootloader_check = None
            self._dtcs = None
            self._show_eeelib_records = False
            self._reset_drafts()

        if isinstance(res.get("passport"), dict):
            self._passport = dict(res["passport"])
        if isinstance(res.get("status"), dict):
            self._status = dict(res["status"])
        if res.get("dflash_bytes") is not None:
            self._dflash_bytes = bytes(res["dflash_bytes"])
        if isinstance(res.get("dflash_parsed"), dict):
            self._dflash_parsed = dict(res["dflash_parsed"])
            if not self._draft_cur_k5 and self.current_k5_hex:
                self._draft_cur_k5 = self.current_k5_hex
        if dflash_path is not None:
            self._dflash_path = dflash_path
        elif (res.get("saved_files") or {}).get("dflash"):
            self._dflash_path = Path(res["saved_files"]["dflash"])
        if isinstance(res.get("verify_02f9"), dict):
            self._verify_02f9 = dict(res["verify_02f9"])
        if isinstance(res.get("dtcs"), list):
            self._dtcs = list(res["dtcs"])

        self._refresh_cluster_from_provider()
        self._refresh_all()
        self.changed.emit()

    def open_from_dflash_file(self, path: Path, raw: bytes | None = None) -> None:
        """Open an offline 32 KiB or 64 KiB ELV Data Flash dump file."""
        data = path.read_bytes() if raw is None else bytes(raw)
        parsed = elv_parse_dflash(data)

        self._session_gen += 1
        self._is_open = True
        self._offline_mode = True
        self._via_gateway = False
        self._gateway_bridge = False
        self._gateway_channel = 0
        self._dflash_bytes = data
        self._dflash_parsed = parsed
        self._dflash_path = path
        self._report_path = None
        self._verify_02f9 = None
        self._bootloader_check = None
        self._dtcs = None
        self._show_eeelib_records = False

        ident = parsed["identity"]
        b34 = parsed["block34"]
        self._passport = {
            "part_number": ident.get("part_number", ""),
            "sw_version": ident.get("sw_version", ""),
            "hw_part_number": ident.get("hw_part_number", ""),
            "hw_version": ident.get("hw_version", ""),
            "asam_odx": ident.get("asam_odx", ""),
            "asam_version": ident.get("asam_version", ""),
            "fazit": ident.get("fazit", ""),
            "serial": ident.get("serial", ""),
            "vin": b34.get("vin", ""),
            "coding_hex": ident.get("coding_hex", ""),
        }
        self._status = {
            "mode": b34.get("mode"),
            "mode_hex": b34.get("mode_hex"),
            "mode_label": b34.get("mode_label"),
            "power_class": b34.get("power_class"),
            "power_class_hex": b34.get("power_class_hex"),
            "brand": b34.get("brand"),
            "brand_hex": b34.get("brand_hex"),
            "idac_locked": parsed["block04"].get("idac_state") == 0xAA,
            "lock_cycles": parsed["block31"].get("lock_cycles"),
        }
        self._reset_drafts(keep_cur_k5=str(b34.get("slot_a_hex") or "").upper())
        self._refresh_cluster_from_provider()
        self._refresh_all()
        self.changed.emit()

    def open_from_report_file(self, path: Path) -> None:
        """Open an offline ELV JSON report (`elv_report.json` / `elv_backup_report.json`), plus sibling DFLASH if present."""
        raw_text = path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                tr(f"Некорректный JSON-отчёт ELV: {exc}", f"Invalid ELV JSON report: {exc}")
            ) from exc
        if not isinstance(data, dict):
            raise ValueError(
                tr("JSON-отчёт ELV должен содержать объект.", "ELV JSON report must contain a JSON object.")
            )

        # Look for a sibling DFLASH binary in the same session folder
        sibling_bytes: bytes | None = None
        sibling_parsed: dict[str, Any] | None = None
        sibling_path: Path | None = None
        parent_dir = path.parent
        if parent_dir.is_dir():
            for fname in _SIBLING_DFLASH_NAMES:
                cand = parent_dir / fname
                if not cand.is_file():
                    continue
                try:
                    raw_bin = cand.read_bytes()
                    if elv_is_dflash_bytes(raw_bin):
                        sibling_parsed = elv_parse_dflash(raw_bin)
                        sibling_bytes = raw_bin
                        sibling_path = cand
                        break
                except (OSError, ValueError):
                    continue

        self._session_gen += 1
        self._is_open = True
        self._offline_mode = True
        self._via_gateway = False
        self._gateway_bridge = False
        self._gateway_channel = 0
        self._bootloader_check = None
        self._show_eeelib_records = False
        self._report_path = path

        self._dflash_bytes = sibling_bytes
        self._dflash_path = sibling_path

        if sibling_parsed is not None:
            self._dflash_parsed = sibling_parsed
        elif isinstance(data.get("dflash_parsed"), dict):
            self._dflash_parsed = dict(data["dflash_parsed"])
        elif any(isinstance(data.get(k), dict) for k in ("block34", "block04", "block02", "block31", "identity")):
            self._dflash_parsed = {
                "format": "programmer_64k" if data.get("dflash_size") == ELV_DFLASH_RAW64K_SIZE else "compact_32k",
                "size": data.get("dflash_size"),
                "sha256": data.get("dflash_sha256") or "",
                "active_pool": data.get("active_pool"),
                "pool0_counter": data.get("pool0_counter"),
                "pool1_counter": data.get("pool1_counter"),
                "crc_valid_count": data.get("crc_valid_count"),
                "crc_total_count": data.get("crc_total_count"),
                "all_crc_ok": data.get("all_crc_ok"),
                "triple_copy_ok": data.get("triple_copy_ok"),
                "identity": dict(data.get("identity") or {}),
                "block34": dict(data.get("block34") or {}),
                "block04": dict(data.get("block04") or {}),
                "block02": dict(data.get("block02") or {}),
                "block31": dict(data.get("block31") or {}),
                "block32": dict(data.get("block32") or {}),
                "stored_dtcs": list(data.get("stored_dtcs") or []),
                "records": list(data.get("records") or []),
            }
        else:
            self._dflash_parsed = None

        parsed_ident = (self._dflash_parsed or {}).get("identity") or {}
        parsed_b34 = (self._dflash_parsed or {}).get("block34") or {}
        parsed_b04 = (self._dflash_parsed or {}).get("block04") or {}
        parsed_b31 = (self._dflash_parsed or {}).get("block31") or {}

        passport_in = dict(data.get("passport") or {}) if isinstance(data.get("passport"), dict) else {}
        for k_field in (
            "part_number",
            "sw_version",
            "hw_part_number",
            "hw_version",
            "asam_odx",
            "asam_version",
            "fazit",
            "serial",
            "coding_hex",
        ):
            if not passport_in.get(k_field) and parsed_ident.get(k_field):
                passport_in[k_field] = parsed_ident[k_field]
        if not passport_in.get("vin") and parsed_b34.get("vin"):
            passport_in["vin"] = parsed_b34["vin"]
        self._passport = passport_in

        status_in = dict(data.get("status") or {}) if isinstance(data.get("status"), dict) else {}
        if status_in.get("mode") is None and parsed_b34.get("mode") is not None:
            status_in["mode"] = parsed_b34.get("mode")
            status_in["mode_hex"] = parsed_b34.get("mode_hex")
            status_in["mode_label"] = parsed_b34.get("mode_label")
        if status_in.get("power_class") is None and parsed_b34.get("power_class") is not None:
            status_in["power_class"] = parsed_b34.get("power_class")
            status_in["power_class_hex"] = parsed_b34.get("power_class_hex")
        if "idac_locked" not in status_in and parsed_b04.get("idac_state") is not None:
            status_in["idac_locked"] = parsed_b04.get("idac_state") == 0xAA
        if status_in.get("lock_cycles") is None and parsed_b31.get("lock_cycles") is not None:
            status_in["lock_cycles"] = parsed_b31.get("lock_cycles")
        self._status = status_in

        self._verify_02f9 = dict(data["verify_02f9"]) if isinstance(data.get("verify_02f9"), dict) else None
        self._dtcs = list(data["dtcs"]) if isinstance(data.get("dtcs"), list) else None

        self._reset_drafts(keep_cur_k5=self.current_k5_hex)
        self._refresh_cluster_from_provider()
        self._refresh_all()
        self.changed.emit()

    def close_elv(self) -> None:
        self._session_gen += 1
        self._is_open = False
        self._offline_mode = False
        self._via_gateway = False
        self._gateway_bridge = False
        self._gateway_channel = 0

        self._passport = {}
        self._status = {}
        self._dflash_bytes = None
        self._dflash_parsed = None
        self._dflash_path = None
        self._report_path = None
        self._verify_02f9 = None
        self._bootloader_check = None
        self._dtcs = None

        self._cluster_material = None
        self._cluster_source_manual = False
        self._cluster_dflash_sha = ""
        self._show_eeelib_records = False
        self._reset_drafts()

        self._key = "immo"
        self._last_rendered_key = ""
        if "immo" in self._nav_items:
            self.nav.blockSignals(True)
            self.nav.setCurrentItem(self._nav_items["immo"])
            self.nav.blockSignals(False)

        self._refresh_all()
        self.changed.emit()

    # ────────────────────────────── Layout Builders (Unified IdentityBar + NavPane + PageArea) ──────────────────────────────

    def _build_identity(self) -> QWidget:
        self.sec_id = QFrame()
        self.sec_id.setObjectName("IdentityBar")
        body = QVBoxLayout(self.sec_id)
        body.setContentsMargins(24, 10, 24, 10)
        body.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(10)

        self.lbl_pn = QLabel()
        self.lbl_pn.setObjectName("PartNumber")
        self.lbl_pn.setFont(mono_font(18, bold=True))
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

        self.btn_poll_top = button("", slot=self.action_read_status)
        self.btn_export_top = button("", slot=self.action_export_json)
        self.btn_term_top = button("", slot=lambda: self.open_terminal_requested.emit("elv"))
        self.btn_close_top = button("", "GhostBtn", slot=self.close_requested.emit)
        for b in (self.btn_poll_top, self.btn_export_top, self.btn_term_top, self.btn_close_top):
            b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            head.addWidget(b)
        body.addLayout(head)

        body.addWidget(divider())

        self.grid_id = QGridLayout()
        self.grid_id.setHorizontalSpacing(20)
        self.grid_id.setVerticalSpacing(2)
        body.addLayout(self.grid_id)
        return self.sec_id

    def _build_nav(self) -> QWidget:
        pane = QFrame()
        pane.setObjectName("NavPane")
        pane.setFixedWidth(284)
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(6, 6, 6, 0)
        lay.setSpacing(0)

        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        self._nav_rows: dict[str, _ElvNavRow] = {}
        self._nav_items: dict[str, QListWidgetItem] = {}
        self._group_labels: dict[str, QLabel] = {}

        for group, keys in ELV_GROUPS:
            hdr = QListWidgetItem(self.nav)
            hdr.setFlags(Qt.ItemFlag.NoItemFlags)
            hdr.setSizeHint(QSize(0, 24))
            lbl = group_label()
            lbl.setContentsMargins(12, 7, 0, 0)
            self.nav.setItemWidget(hdr, lbl)
            self._group_labels[group] = lbl
            for key in keys:
                item = QListWidgetItem(self.nav)
                item.setData(Qt.ItemDataRole.UserRole, key)
                item.setSizeHint(QSize(0, 32))
                row_w = _ElvNavRow()
                self.nav.setItemWidget(item, row_w)
                self._nav_rows[key] = row_w
                self._nav_items[key] = item

        self.nav.currentItemChanged.connect(self._on_nav_changed)
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

    def _on_nav_changed(self, cur: QListWidgetItem | None, _prev: QListWidgetItem | None) -> None:
        if cur is None:
            return
        key = cur.data(Qt.ItemDataRole.UserRole)
        if not isinstance(key, str) or key not in self._nav_rows:
            return
        self._sync_drafts()
        self._key = key
        for k, row_w in self._nav_rows.items():
            row_w.set_active(k == self._key)
        self._render_page()

    def _on_conn_or_busy(self) -> None:
        if not self._is_open or not _qt_valid(self):
            return
        self._refresh_all()

    # ────────────────────────────── Architectural UI Helpers ──────────────────────────────

    @staticmethod
    def _compact_section(title: str, desc: str = "") -> Section:
        sec = Section()
        sec.set_text(title, desc)
        sec.head.setContentsMargins(16, 10, 16, 2)
        sec.body.setContentsMargins(16, 4, 16, 12)
        sec.body.setSpacing(9)
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
        """Architectural form cell matching BcmScreen & MrrScreen: uppercase GroupLabel + right badge above input."""
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
        if not badge_text:
            lbl_badge.hide()
        top.addWidget(lbl_cap, 1)
        top.addWidget(lbl_badge, 0)
        vlay.addLayout(top)

        if isinstance(control, QLineEdit):
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
    def _bind_hex_validator(
        ed: QLineEdit,
        badge: QLabel,
        expected_bytes: int,
        *,
        allow_empty: bool = True,
        empty_label: str = "",
    ) -> None:
        def _check(txt: str) -> None:
            raw = _clean_hex(txt)
            if not raw:
                set_tone(ed, "")
                badge.setText(empty_label or (tr("опц.", "opt.") if allow_empty else f"0/{expected_bytes} B"))
                set_tone(badge, "muted")
                badge.setVisible(True)
                return
            hex_ok = all(c in "0123456789abcdefABCDEF" for c in raw)
            exact = hex_ok and len(raw) == expected_bytes * 2
            set_tone(ed, "" if exact else "err")
            badge.setText(
                f"{len(raw) // 2}/{expected_bytes} B"
                if len(raw) % 2 == 0
                else f"{len(raw)}/{expected_bytes * 2}"
            )
            set_tone(badge, "ok" if exact else "err")
            badge.setVisible(True)

        ed.textChanged.connect(_check)
        _check(ed.text())

    @staticmethod
    def _bind_vin_validator(ed: QLineEdit, badge: QLabel) -> None:
        def _check(txt: str) -> None:
            v = txt.strip()
            if not v:
                set_tone(ed, "")
                badge.setText("0/17")
                set_tone(badge, "muted")
                badge.setVisible(True)
                return
            ascii_ok = all(0x20 <= ord(c) < 0x7F for c in v)
            exact = ascii_ok and len(v) == 17
            set_tone(ed, "" if exact else "err")
            badge.setText(f"{len(v)}/17")
            set_tone(badge, "ok" if exact else "err")
            badge.setVisible(True)

        ed.textChanged.connect(_check)
        _check(ed.text())

    @staticmethod
    def _metric_strip(items: list[tuple[str, str, str]]) -> QFrame:
        """Recessed horizontal architectural KPI strip (label uppercase + monospace semantic value)."""
        strip = QFrame()
        strip.setObjectName("MetaStrip")
        lay = QHBoxLayout(strip)
        lay.setContentsMargins(14, 9, 14, 9)
        lay.setSpacing(14)
        for idx, (cap, val, tone) in enumerate(items):
            if idx > 0:
                sep = vdivider()
                sep.setFixedHeight(28)
                lay.addWidget(sep, 0, Qt.AlignmentFlag.AlignVCenter)
            col = QVBoxLayout()
            col.setContentsMargins(0, 0, 0, 0)
            col.setSpacing(2)
            lk = group_label(cap)
            lv = QLabel(val)
            lv.setFont(mono_font(12, bold=(tone in ("ok", "warn", "err"))))
            if tone in ("ok", "warn", "err", "info", "muted"):
                set_tone(lv, tone)
            lv.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            col.addWidget(lk)
            col.addWidget(lv)
            lay.addLayout(col, 1)
        return strip

    @staticmethod
    def _kv_cell(k_txt: str, v_txt: str, tone: str = "", tip: str = "") -> QWidget:
        """Compact vertical label+value pair matching MrrScreen."""
        w = QWidget()
        if tip:
            w.setToolTip(tip)
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(2)
        lk = group_label(k_txt)
        lv = QLabel(str(v_txt))
        lv.setFont(mono_font(12, bold=(tone in ("ok", "warn", "err"))))
        if tone in ("ok", "warn", "err", "info", "muted"):
            set_tone(lv, tone)
        lv.setWordWrap(True)
        lv.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(lk)
        v.addWidget(lv)
        return w

    def _bridge_blocked_tip(self) -> str:
        return tr(
            "Требуется прямое подключение к Komfort CAN (4 провода) или RAM-мост шлюза Continental 3Q0 907 530 "
            "(29-бит чтение памяти 0x1BFD8A0B недоступно через обычный шлюз).",
            "Requires a direct 4-wire Komfort CAN connection or a Continental 3Q0 907 530 gateway RAM-Bridge "
            "(29-bit memory read 0x1BFD8A0B is unavailable over a UDS-only gateway).",
        )

    def _copy_text(self, value: str, label: str) -> None:
        cleaned = value.strip()
        if not cleaned or cleaned == "—":
            return
        cb = QGuiApplication.clipboard()
        if cb is not None:
            cb.setText(cleaned)
            self.note.emit(tr(f"Скопировано в буфер: {label}", f"Copied to clipboard: {label}"))

    # ────────────────────────────── Draft Sync & Cluster Cache (M2) ──────────────────────────────

    def _sync_drafts(self) -> None:
        for attr, w in (
            ("_draft_vin", self._ed_vin),
            ("_draft_new_k5", self._ed_new_k5),
            ("_draft_power_class", self._ed_pc),
            ("_draft_cfg", self._ed_cfg),
            ("_draft_brand", self._ed_brand),
            ("_draft_cur_k5", self._ed_cur_k5),
            ("_draft_offline_idac", self._ed_offline_idac),
            ("_draft_virgin_k5", self._ed_virgin_k5),
        ):
            if w is not None and _qt_valid(w):
                setattr(self, attr, w.text().strip())

    def _refresh_cluster_from_provider(self, *, force: bool = False) -> bool:
        """Sync 17 FPK_E material from the open cluster workspace, cached by SHA-256 of DFLASH bytes."""
        if self._cluster_provider is None:
            return False
        if self._cluster_source_manual and not force:
            return self._cluster_material is not None

        mat = self._cluster_provider()
        if not mat or not mat.get("dflash_bytes"):
            if not self._cluster_source_manual or force:
                self._cluster_material = None
                self._cluster_dflash_sha = ""
            return False

        df_bytes = bytes(mat["dflash_bytes"])
        cf_bytes = bytes(mat["cflash_bytes"]) if mat.get("cflash_bytes") is not None else None
        s0_hex = str(mat.get("s0_hex") or "")
        s1_hex = str(mat.get("s1_hex") or "")
        cache_key = f"{hashlib.sha256(df_bytes).hexdigest()}:{s0_hex}:{s1_hex}:{len(cf_bytes) if cf_bytes else 0}"

        if not force and cache_key == self._cluster_dflash_sha and self._cluster_material is not None:
            return True

        try:
            extracted = elv_extract_cluster_material(
                df_bytes,
                cf_bytes,
                s0_hex=s0_hex or None,
                s1_hex=s1_hex or None,
            )
        except Exception:
            self._cluster_material = None
            self._cluster_dflash_sha = ""
            return False

        self._cluster_material = extracted
        self._cluster_dflash_sha = cache_key
        if force:
            self._cluster_source_manual = False
        return True

    # ────────────────────────────── Refresh & Rendering ──────────────────────────────

    def _refresh_all(self) -> None:
        if not _qt_valid(self):
            return
        self._sync_drafts()
        if self._is_open:
            self._refresh_cluster_from_provider()
        self._refresh_identity()
        self._refresh_nav()
        self._render_page()

    def _refresh_identity(self) -> None:
        busy = self.runner.is_busy
        ident = (self._dflash_parsed or {}).get("identity") or {}
        b34 = (self._dflash_parsed or {}).get("block34") or {}

        self.lbl_pn.setText(self.part_number)
        self.lbl_sys.setText(tr("Защёлка руля ELV (2B)", "Steering Lock ELV (2B)"))

        if self._offline_mode:
            src_name = (
                self._dflash_path.name
                if self._dflash_path is not None
                else (self._report_path.name if self._report_path is not None else "")
            )
            self.pill_source.setText(tr("Локальный файл (офлайн)", "Local file (offline)"))
            self.pill_source.setToolTip(
                str(self._dflash_path or self._report_path or src_name)
            )
            set_tone(self.pill_source, "muted")
        elif self._via_gateway:
            if self._gateway_bridge:
                self.pill_source.setText(
                    tr(
                        f"Через шлюз J533 (RAM-мост ch{self._gateway_channel})",
                        f"Via J533 gateway (RAM-Bridge ch{self._gateway_channel})",
                    )
                )
                self.pill_source.setToolTip("")
                set_tone(self.pill_source, "ok")
            else:
                self.pill_source.setText(tr("Через шлюз J533 (только UDS)", "Via J533 gateway (UDS only)"))
                self.pill_source.setToolTip(self._bridge_blocked_tip())
                set_tone(self.pill_source, "warn")
        else:
            self.pill_source.setText(tr("Прямой Komfort CAN", "Direct Komfort CAN"))
            self.pill_source.setToolTip("")
            set_tone(self.pill_source, "info")

        self.btn_poll_top.setText(tr("Опросить ELV", "Poll ELV"))
        self.btn_poll_top.setEnabled(not busy)
        self.btn_export_top.setText(tr("Экспорт JSON", "Export JSON"))
        self.btn_export_top.setEnabled(
            not busy and bool(self._dflash_parsed or self._passport or self._status)
        )
        self.btn_term_top.setText(tr("CAN-терминал", "CAN terminal"))
        self.btn_term_top.setEnabled(not busy)
        self.btn_close_top.setText(tr("Закрыть", "Close"))
        self.btn_close_top.setEnabled(not busy)

        clear_layout(self.grid_id)
        for c in range(8):
            self.grid_id.setColumnStretch(c, 0)

        sw = str(self._passport.get("sw_version") or ident.get("sw_version") or "")
        hw_pn = str(self._passport.get("hw_part_number") or ident.get("hw_part_number") or "")
        hw_v = str(self._passport.get("hw_version") or ident.get("hw_version") or "")
        fazit = str(self._passport.get("fazit") or ident.get("fazit") or "")
        vin = str(self._passport.get("vin") or b34.get("vin") or "")
        mode_txt, mode_tone = _short_mode_badge(self._current_mode())

        tx_id = str(self._passport.get("uds_tx_id") or f"0x{ELV_UDS_TX_ID:03X}")
        rx_id = str(self._passport.get("uds_rx_id") or f"0x{ELV_UDS_RX_ID:03X}")

        top_fields: list[tuple[str, str, str]] = []
        if sw:
            top_fields.append((tr("ВЕРСИЯ ПО", "SOFTWARE"), sw, ""))
        if hw_pn or hw_v:
            hw_disp = f"{hw_pn} / {hw_v}" if (hw_pn and hw_v) else (hw_pn or hw_v)
            top_fields.append((tr("ОБОРУДОВАНИЕ", "HARDWARE"), hw_disp, ""))
        if fazit:
            top_fields.append(("FAZIT", fazit, ""))
        if vin:
            top_fields.append(("VIN", vin, ""))
        top_fields.append((tr("РЕЖИМ", "MODE"), mode_txt, mode_tone))
        top_fields.append(("CAN UDS", f"{tx_id} → {rx_id}", ""))

        for col, (k_txt, v_txt, tone) in enumerate(top_fields):
            lbl_k = QLabel(k_txt)
            lbl_k.setObjectName("GroupLabel")
            lbl_v = QLabel(v_txt)
            lbl_v.setFont(mono_font(12, bold=(tone in ("ok", "warn", "err"))))
            if tone in ("ok", "warn", "err", "info", "muted"):
                set_tone(lbl_v, tone)
            lbl_v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.grid_id.addWidget(lbl_k, 0, col)
            self.grid_id.addWidget(lbl_v, 1, col)
        self.grid_id.setColumnStretch(len(top_fields), 1)

    def _refresh_nav(self) -> None:
        self._group_labels["main"].setText(tr("ОСНОВНОЕ", "MAIN"))
        self._group_labels["service"].setText(tr("СЕРВИС", "SERVICE"))

        for key, row_w in self._nav_rows.items():
            row_w.lbl_name.setText(_elv_nav_title(key))
            row_w.set_active(key == self._key)

        # Page 1: Immobilizer & Keys pill
        if self._dflash_parsed:
            v_cnt = self._dflash_parsed.get("crc_valid_count")
            t_cnt = self._dflash_parsed.get("crc_total_count")
            if v_cnt is not None and t_cnt:
                ok = bool(self._dflash_parsed.get("all_crc_ok"))
                set_pill(self._nav_rows["immo"].pill, f"{v_cnt}/{t_cnt}", "ok" if ok else "err")
            elif self.current_k5_hex:
                set_pill(self._nav_rows["immo"].pill, "K_5", "info")
            else:
                set_pill(self._nav_rows["immo"].pill, tr("отчёт", "report"), "info")
        else:
            set_pill(self._nav_rows["immo"].pill, tr("нет дампа", "no dump"), "muted")

        # Page 2: Adaptation & Reset pill
        mode = self._current_mode()
        if mode == 0x01:
            set_pill(self._nav_rows["adapt"].pill, tr("новая", "virgin"), "ok")
        elif mode == 0x02:
            set_pill(self._nav_rows["adapt"].pill, tr("привязана", "adapted"), "info")
        elif mode == 0xFF:
            set_pill(self._nav_rows["adapt"].pill, tr("завод.", "plant"), "warn")
        else:
            set_pill(self._nav_rows["adapt"].pill, "—", "muted")

        # Page 3: Passport & Memory pill
        recs = (self._dflash_parsed or {}).get("records") or []
        if recs:
            set_pill(
                self._nav_rows["status"].pill,
                tr(f"{len(recs)} зап.", f"{len(recs)} rec"),
                "info",
            )
        elif self._passport:
            sw = str(self._passport.get("sw_version") or "UDS")
            set_pill(self._nav_rows["status"].pill, sw, "info")
        else:
            set_pill(self._nav_rows["status"].pill, "—", "muted")

        # Page 4: DTC pill
        if self._dtcs is None:
            n_stored = len((self._dflash_parsed or {}).get("stored_dtcs") or [])
            set_pill(
                self._nav_rows["dtc"].pill,
                tr(f"{n_stored} в дампе", f"{n_stored} dump") if n_stored else "—",
                "warn" if n_stored else "muted",
            )
        elif len(self._dtcs) == 0:
            set_pill(self._nav_rows["dtc"].pill, tr("нет", "none"), "ok")
        else:
            n_act = sum(1 for d in self._dtcs if _is_dtc_active(d))
            set_pill(
                self._nav_rows["dtc"].pill,
                tr(f"{len(self._dtcs)} шт.", f"{len(self._dtcs)}"),
                "err" if n_act else "warn",
            )

        # Bottom summary ledger (`NavDumps`)
        self.lbl_state_hdr.setText(tr("ДАННЫЕ 2B ELV", "2B ELV DATA"))
        clear_layout(self.state_list)

        if self._dflash_bytes is not None and self._dflash_parsed:
            sz_kb = 64 if len(self._dflash_bytes) == ELV_DFLASH_RAW64K_SIZE else 32
            v_cnt = self._dflash_parsed.get("crc_valid_count", 0)
            t_cnt = self._dflash_parsed.get("crc_total_count", 47)
            crc_ok = bool(self._dflash_parsed.get("all_crc_ok"))
            df_txt = (
                tr(f"{sz_kb} КБ · {v_cnt}/{t_cnt} OK", f"{sz_kb} KB · {v_cnt}/{t_cnt} OK")
                if crc_ok
                else tr(f"{sz_kb} КБ · {v_cnt}/{t_cnt} ERR", f"{sz_kb} KB · {v_cnt}/{t_cnt} ERR")
            )
            df_tone = "ok" if crc_ok else "err"
            df_tip = str(self._dflash_path) if self._dflash_path else ""
        elif self._dflash_parsed:
            df_txt, df_tone = tr("из отчёта", "from report"), "info"
            df_tip = str(self._report_path) if self._report_path else ""
        else:
            df_txt, df_tone, df_tip = tr("не считан", "not read"), "muted", ""
        self.state_list.addWidget(self._ledger_row("Data Flash", df_txt, df_tone, df_tip))

        k5_hex = self.current_k5_hex
        self.state_list.addWidget(
            self._ledger_row(
                tr("Ключ K_5", "Key K_5"),
                tr("считан", "read") if k5_hex else tr("нет", "none"),
                "ok" if k5_hex else "muted",
                k5_hex,
            )
        )

        idp_hex = self.current_idp_hex
        self.state_list.addWidget(
            self._ledger_row(
                tr("Партнёр IDp", "Partner IDp"),
                idp_hex or "—",
                "info" if idp_hex else "muted",
            )
        )

        if self._cluster_material:
            cm = self._cluster_material
            if cm.get("slot_a_crc_ok") is False:
                cl_txt, cl_tone = tr("ошибка CRC", "CRC error"), "err"
            else:
                cl_txt, cl_tone = tr("загружена", "loaded"), "ok"
            cl_tip = f"{cm.get('part_number') or '17 FPK_E'} · {cm.get('vin') or ''}".strip(" ·")
        else:
            cl_txt, cl_tone, cl_tip = tr("не открыта", "not open"), "muted", ""
        self.state_list.addWidget(
            self._ledger_row(tr("Панель 17 FPK_E", "17 FPK_E cluster"), cl_txt, cl_tone, cl_tip)
        )

    def _render_page(self) -> None:
        self._ed_vin = None
        self._ed_new_k5 = None
        self._ed_pc = None
        self._ed_cfg = None
        self._ed_brand = None
        self._ed_cur_k5 = None
        self._ed_offline_idac = None
        self._ed_virgin_k5 = None
        self._eeelib_table = None
        self._btn_eeelib_toggle = None
        self._eeelib_count = 0

        vbar = self.page_area.verticalScrollBar()
        saved_scroll = vbar.value() if self._last_rendered_key == self._key else 0

        busy = self.runner.is_busy
        page = QWidget()
        page.setObjectName("PageCanvas")
        outer = QHBoxLayout(page)
        outer.setContentsMargins(24, 8, 24, 18)
        outer.setSpacing(0)

        column = QWidget()
        column.setMaximumWidth(960)
        lay = QVBoxLayout(column)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)

        head_row = QHBoxLayout()
        head_row.setContentsMargins(0, 0, 0, 2)
        head_row.setSpacing(8)
        title = QLabel(_elv_nav_title(self._key))
        title.setObjectName("PageTitle")
        head_row.addWidget(title)
        head_row.addStretch(1)

        if self._key == "immo":
            btn_open = button(tr("Открыть .bin…", "Open .bin…"), "InlineBtn", slot=self.action_open_dflash_file)
            btn_save = button(tr("Сохранить DFLASH…", "Save DFLASH…"), "InlineBtn", slot=self.action_save_dflash)
            btn_open.setEnabled(not busy)
            btn_save.setEnabled(not busy and self._dflash_bytes is not None)
            for b in (btn_open, btn_save):
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                head_row.addWidget(b)
        elif self._key == "adapt":
            btn_from_17 = button(
                tr("Из открытой 17 FPK_E", "From open 17 FPK_E"),
                "InlineBtn",
                slot=self._sync_cluster_from_open_workspace,
            )
            btn_file_17 = button(
                tr("Загрузить Dflash.bin…", "Load Dflash.bin…"),
                "InlineBtn",
                slot=self.action_load_cluster_dflash,
            )
            for b in (btn_from_17, btn_file_17):
                b.setEnabled(not busy)
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                head_row.addWidget(b)
        elif self._key == "dtc":
            btn_read_dtc = button(tr("Считать ошибки", "Read fault codes"), "PrimaryBtn", slot=self.action_read_status)
            btn_clear_dtc = button(tr("Очистить ошибки", "Clear fault codes"), "DangerBtn", slot=self.action_clear_dtc)
            for b in (btn_read_dtc, btn_clear_dtc):
                b.setEnabled(not busy)
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                head_row.addWidget(b)

        lay.addLayout(head_row)

        if self._key == "immo":
            self._build_page_immo(lay)
        elif self._key == "adapt":
            self._build_page_adapt(lay)
        elif self._key == "status":
            self._build_page_status(lay)
        elif self._key == "dtc":
            self._build_page_dtc(lay)

        lay.addStretch(1)
        outer.addWidget(column, 1)
        outer.addStretch(0)

        self.page_area.setUpdatesEnabled(False)
        try:
            old_page = self.page_area.takeWidget()
            self.page_area.setWidget(page)
            if old_page is not None:
                old_page.hide()
                old_page.setParent(self)
                old_page.deleteLater()
            self._last_rendered_key = self._key
            if saved_scroll:
                self.page_area.verticalScrollBar().setValue(saved_scroll)
        finally:
            self.page_area.setUpdatesEnabled(True)

        if saved_scroll:
            QTimer.singleShot(
                0,
                lambda s=saved_scroll: _qt_valid(self) and self.page_area.verticalScrollBar().setValue(s),
            )

    # ────────────────────────────── Page 1: Immobilizer & Keys ──────────────────────────────

    def _build_page_immo(self, lay: QVBoxLayout) -> None:
        busy = self.runner.is_busy
        bridge_blocked = self._via_gateway and not self._gateway_bridge
        parsed = self._dflash_parsed
        b34 = (parsed or {}).get("block34") or {}
        b04 = (parsed or {}).get("block04") or {}
        b02 = (parsed or {}).get("block02") or {}
        b31 = (parsed or {}).get("block31") or {}

        mode_val = self._current_mode()
        mode_txt, mode_tone = _short_mode_badge(mode_val)

        idac_val = str(b04.get("idac_hex") or "").upper()
        idac_state = b04.get("idac_state")
        if idac_state == 0xAA or (idac_state is None and self._status.get("idac_locked")):
            link_txt = tr(f"Привязана ({idac_val})", f"Linked ({idac_val})") if idac_val else tr("Привязана (0xAA)", "Linked (0xAA)")
            link_tone = "ok"
        elif idac_state == 0x55:
            link_txt, link_tone = tr("Обучение (0x55)", "Learning (0x55)"), "warn"
        elif idac_state == 0x00 or (idac_state is None and "idac_locked" in self._status and not self._status["idac_locked"]):
            link_txt, link_tone = tr("Автообучение", "Auto-learn"), "info"
        else:
            link_txt, link_tone = "—", "muted"

        bolt = b31.get("bolt_state")
        cycles = b31.get("lock_cycles") if b31.get("lock_cycles") is not None else self._status.get("lock_cycles")
        bolt_short = (
            tr("Открыт", "Unlocked")
            if bolt == 0xC3
            else (tr("Закрыт", "Locked") if bolt == 0x5A else "")
        )
        cyc_short = tr(f"{cycles} циклов", f"{cycles} cycles") if cycles is not None else ""
        bolt_parts = [p for p in (bolt_short, cyc_short) if p]
        bolt_kpi = " · ".join(bolt_parts) if bolt_parts else "—"
        bolt_tone = "ok" if bolt == 0xC3 else ("info" if bolt_parts else "muted")

        if parsed and parsed.get("crc_total_count"):
            v_cnt = int(parsed.get("crc_valid_count") or 0)
            t_cnt = int(parsed.get("crc_total_count") or 47)
            crc_ok = bool(parsed.get("all_crc_ok"))
            tc_ok = parsed.get("triple_copy_ok", True)
            df_kpi = f"{v_cnt}/{t_cnt} CRC · {'OK' if (crc_ok and tc_ok) else 'ERR'}"
            if self._verify_02f9 and self._verify_02f9.get("verified"):
                df_kpi += " · 02F9 OK" if self._verify_02f9.get("match") else " · 02F9 ERR"
            df_tone = "ok" if (crc_ok and tc_ok and (not self._verify_02f9 or not self._verify_02f9.get("verified") or self._verify_02f9.get("match"))) else "err"
        elif parsed:
            df_kpi, df_tone = tr("Из отчёта", "From report"), "info"
        else:
            df_kpi, df_tone = tr("Не считан", "Not read"), "muted"

        # ── Card 1: Status & Memory Read ──
        sec_read = self._compact_section(
            tr("Состояние и чтение памяти", "Status & Memory Read"),
            tr(
                "Чтение 32 КБ Data Flash (~4 с) сохраняет бэкап, ключ K_5, IDp и проверяет подпись 02F9. Опрос UDS обновляет статус, VIN и ошибки.",
                "32 KB Data Flash read (~4 s) saves a backup, K_5 key, IDp, and verifies live 02F9 MAC. UDS poll refreshes status, VIN, and DTCs.",
            ),
        )
        if self._verify_02f9 and self._verify_02f9.get("verified"):
            m_ok = bool(self._verify_02f9.get("match"))
            sec_read.head.addWidget(
                status_readout(
                    tr("Ключ K_5 подтверждён (02F9)", "K_5 verified (02F9)")
                    if m_ok
                    else tr("Подпись 02F9 не совпала", "02F9 MAC mismatch"),
                    "ok" if m_ok else "err",
                ),
                0,
                Qt.AlignmentFlag.AlignVCenter,
            )
        elif parsed and parsed.get("crc_total_count"):
            ok_all = bool(parsed.get("all_crc_ok")) and bool(parsed.get("triple_copy_ok", True))
            sec_read.head.addWidget(
                status_readout(
                    tr("Дамп целостен", "Dump intact") if ok_all else tr("Ошибка CRC дампа", "Dump CRC error"),
                    "ok" if ok_all else "err",
                ),
                0,
                Qt.AlignmentFlag.AlignVCenter,
            )
        elif self._status:
            sec_read.head.addWidget(
                status_readout(tr("Статус UDS получен", "UDS status read"), "info"),
                0,
                Qt.AlignmentFlag.AlignVCenter,
            )

        sec_read.body.addWidget(
            self._metric_strip(
                [
                    (tr("РЕЖИМ ELV", "ELV MODE"), mode_txt, mode_tone),
                    (tr("ПРИВЯЗКА ПРИБОРКИ", "CLUSTER LINK"), link_txt, link_tone),
                    (tr("РИГЕЛЬ И РЕСУРС", "BOLT & CYCLES"), bolt_kpi, bolt_tone),
                    (tr("ПАМЯТЬ DFLASH", "DFLASH MEMORY"), df_kpi, df_tone),
                ]
            )
        )

        btn_read_df = button(tr("Считать DFLASH (32 КБ)", "Read DFLASH (32 KB)"), "PrimaryBtn", slot=self.action_read_dflash)
        btn_read_df.setEnabled(not busy and not bridge_blocked)
        btn_read_df.setToolTip(self._bridge_blocked_tip() if bridge_blocked else "")
        btn_read_df.setCursor(Qt.CursorShape.PointingHandCursor)

        btn_status = button(tr("Обновить статус по UDS", "Refresh UDS status"), slot=self.action_read_status)
        btn_status.setEnabled(not busy)
        btn_status.setCursor(Qt.CursorShape.PointingHandCursor)

        sec_read.add_footer(btn_read_df, btn_status)
        lay.addWidget(sec_read)

        # ── Card 2: WFS5 Immobilizer Data ──
        sec_wfs = self._compact_section(
            tr("Данные иммобилайзера (WFS5)", "Immobilizer Data (WFS5)"),
            tr(
                "Основные криптоданные и идентификаторы защёлки (Блок 34 и Блок 4).",
                "Core steering lock crypto data and partner IDs (Block 34 & Block 4).",
            ),
        )

        vin_val = str(self._passport.get("vin") or b34.get("vin") or "")
        slot_a = str(b34.get("slot_a_hex") or "").upper()
        pc_val = self._status.get("power_class_hex") or b34.get("power_class_hex") or "—"
        cfg_val = b34.get("config_hex") or "—"
        brand_val = self._status.get("brand_hex") or b34.get("brand_hex") or "—"
        idp_val = str(b04.get("idp_hex") or "").upper()

        wfs_grid = QGridLayout()
        wfs_grid.setHorizontalSpacing(14)
        wfs_grid.setVerticalSpacing(10)
        wfs_grid.setColumnStretch(0, 1)
        wfs_grid.setColumnStretch(1, 1)

        def _ro_line(val: str, placeholder: str, *, bold: bool = False) -> QLineEdit:
            ed = QLineEdit(val)
            ed.setReadOnly(True)
            ed.setFont(mono_font(12, bold=bold))
            ed.setPlaceholderText(placeholder)
            ed.setCursorPosition(0)
            return ed

        # Row 0: VIN | PowerClass / Config / Brand
        ed_vin = _ro_line(vin_val, "—")
        btn_cp_vin = button(tr("Копировать", "Copy"), "InlineBtn", slot=lambda v=vin_val: self._copy_text(v, "VIN"))
        btn_cp_vin.setEnabled(bool(vin_val))
        c_vin, _ = self._field_box(
            tr("VIN АВТОМОБИЛЯ", "VEHICLE VIN"),
            ed_vin,
            badge_text="F190",
            badge_tone="muted",
            trailing=(btn_cp_vin,),
        )
        wfs_grid.addWidget(c_vin, 0, 0)

        pcb_disp = f"{pc_val} / {cfg_val} / {brand_val}"
        ed_pcb = _ro_line(pcb_disp if pcb_disp != "— / — / —" else "", "—")
        c_pcb, _ = self._field_box(
            "POWERCLASS / CONFIG / BRAND",
            ed_pcb,
            badge_text="02ED",
            badge_tone="muted",
            tip=tr("Класс мощности, байт конфигурации и бренд автомобиля", "Vehicle PowerClass, config byte, and brand byte"),
        )
        wfs_grid.addWidget(c_pcb, 0, 1)

        # Row 1 (full width): Key K_5 / Slot A
        ed_k5 = _ro_line(
            slot_a,
            tr("Считайте DFLASH (32 КБ) или откройте файл .bin…", "Read DFLASH (32 KB) or open a .bin dump…"),
            bold=True,
        )
        btn_cp_k5 = button(tr("Копировать", "Copy"), "InlineBtn", slot=lambda v=slot_a: self._copy_text(v, "K_5"))
        btn_cp_k5.setEnabled(bool(slot_a))
        c_k5, _ = self._field_box(
            tr("КЛЮЧ ИММОБИЛАЙЗЕРА (K_5 / SLOT A)", "IMMOBILIZER KEY (K_5 / SLOT A)"),
            ed_k5,
            badge_text="16 B" if slot_a else tr("нет дампа", "no dump"),
            badge_tone="ok" if slot_a else "muted",
            trailing=(btn_cp_k5,),
            tip=tr("16-байтный ключ иммобилайзера из Блока 34", "16-byte immobilizer key stored in Block 34"),
        )
        wfs_grid.addWidget(c_k5, 1, 0, 1, 2)

        # Row 2: IDp | IDac
        ed_idp = _ro_line(idp_val, "—", bold=True)
        btn_cp_idp = button(tr("Копировать", "Copy"), "InlineBtn", slot=lambda v=idp_val: self._copy_text(v, "IDp"))
        btn_cp_idp.setEnabled(bool(idp_val))
        c_idp, _ = self._field_box(
            tr("ID ПАРТНЁРА ELV (IDP ДЛЯ ПРИБОРКИ)", "ELV PARTNER ID (IDP FOR CLUSTER)"),
            ed_idp,
            badge_text="2 B" if idp_val else "",
            badge_tone="info" if idp_val else "muted",
            trailing=(btn_cp_idp,),
            tip=tr("Уникальный 2-байтный ID этой защёлки для прописки в приборной панели 17", "Unique 2-byte ID of this ELV to register in 17 instrument cluster"),
        )
        wfs_grid.addWidget(c_idp, 2, 0)

        if idac_state is not None:
            idac_disp = f"{idac_val or '0000'} · {elv_idac_state_label(idac_state)}"
            idac_badge = f"0x{idac_state:02X}"
            idac_btone = "ok" if idac_state == 0xAA else ("warn" if idac_state == 0x55 else "info")
        elif "idac_locked" in self._status:
            locked = bool(self._status["idac_locked"])
            idac_disp = tr("Привязана к приборке (0xAA)", "Locked to cluster (0xAA)") if locked else tr("Автообучение (0x00)", "Auto-learn (0x00)")
            idac_badge = "0xAA" if locked else "0x00"
            idac_btone = "ok" if locked else "info"
        else:
            idac_disp, idac_badge, idac_btone = "", "", "muted"

        ed_idac = _ro_line(idac_disp, "—")
        btn_cp_idac = button(tr("Копировать", "Copy"), "InlineBtn", slot=lambda v=idac_val: self._copy_text(v, "IDac"))
        btn_cp_idac.setEnabled(bool(idac_val))
        c_idac, _ = self._field_box(
            tr("ПРИВЯЗАННАЯ ПРИБОРКА (IDAC)", "LINKED CLUSTER (IDAC)"),
            ed_idac,
            badge_text=idac_badge,
            badge_tone=idac_btone,
            trailing=(btn_cp_idac,),
        )
        wfs_grid.addWidget(c_idac, 2, 1)

        sec_wfs.body.addLayout(wfs_grid)

        # Actionable 17 FPK_E IDp match/mismatch callout
        if self._is_open:
            self._refresh_cluster_from_provider()
        if self._cluster_material and idp_val:
            cl_idp = str(self._cluster_material.get("cluster_elv_idp") or "").upper()
            cl_pn = html.escape(str(self._cluster_material.get("part_number") or "17 FPK_E"))
            idp_esc = html.escape(idp_val)
            cl_idp_esc = html.escape(cl_idp) if cl_idp else tr("пусто", "empty")
            if cl_idp and cl_idp == idp_val:
                co = Callout("ok")
                co.label.setText(
                    tr(
                        f"<b>IDp совпадает с панелью {cl_pn}:</b> защёлка <code>{idp_esc}</code> уже прописана в приборной панели.",
                        f"<b>IDp matches cluster {cl_pn}:</b> this ELV (<code>{idp_esc}</code>) is already registered in the cluster.",
                    )
                )
            else:
                co = Callout("warn")
                co.label.setText(
                    tr(
                        f"<b>IDp не совпадает с панелью {cl_pn}:</b> у этой ELV <code>{idp_esc}</code>, "
                        f"а в приборке записано <code>{cl_idp_esc}</code>. После привязки пропишите <code>{idp_esc}</code> в партнёре ELV приборной панели.",
                        f"<b>IDp does not match cluster {cl_pn}:</b> this ELV has <code>{idp_esc}</code>, "
                        f"while the cluster stores <code>{cl_idp_esc}</code>. After adaptation, write <code>{idp_esc}</code> as the ELV partner ID in the cluster.",
                    )
                )
            sec_wfs.body.addWidget(co)

        # Compact technical verification footer strip
        if parsed or (self._verify_02f9 and self._verify_02f9.get("verified")):
            strip = QFrame()
            strip.setObjectName("ResultStrip")
            sl = QHBoxLayout(strip)
            sl.setContentsMargins(12, 6, 12, 6)
            sl.setSpacing(14)
            if parsed and parsed.get("crc_total_count"):
                fmt_lbl = (
                    tr("32 КБ CAN", "32 KB CAN")
                    if parsed.get("format") == "compact_32k"
                    else tr("64 КБ программатор", "64 KB programmer")
                )
                pool_s = f"{tr('Пул', 'Pool')} {parsed.get('active_pool')}" if parsed.get("active_pool") is not None else ""
                tc_ok = bool(parsed.get("triple_copy_ok", True))
                df_meta = QLabel(
                    " · ".join(
                        p
                        for p in (
                            fmt_lbl,
                            pool_s,
                            f"CRC {parsed.get('crc_valid_count')}/{parsed.get('crc_total_count')}",
                            tr("3× копии OK" if tc_ok else "3× копии ОШИБКА", "3× copies OK" if tc_ok else "3× copies DIFF"),
                        )
                        if p
                    )
                )
                df_meta.setFont(mono_font(10))
                set_tone(df_meta, "ok" if (parsed.get("all_crc_ok") and tc_ok) else "err")
                sl.addWidget(df_meta)
            if self._verify_02f9 and self._verify_02f9.get("verified"):
                m_ok = bool(self._verify_02f9.get("match"))
                mac_hex = str(self._verify_02f9.get("actual_mac_hex") or "")
                lbl_mac = QLabel(
                    tr(
                        f"Подпись 02F9: {mac_hex} ({'совпала' if m_ok else 'НЕ совпала'})",
                        f"02F9 MAC: {mac_hex} ({'match' if m_ok else 'MISMATCH'})",
                    )
                )
                lbl_mac.setFont(mono_font(10))
                set_tone(lbl_mac, "ok" if m_ok else "err")
                sl.addWidget(lbl_mac)
            sl.addStretch(1)
            sec_wfs.body.addWidget(strip)

        lay.addWidget(sec_wfs)

        # ── Card 3: Bolt Mechanics & Security Counters ──
        sec_mech = self._compact_section(
            tr("Механика ригеля и защитные счётчики", "Bolt Mechanics & Security Counters"),
        )
        mg = QGridLayout()
        mg.setHorizontalSpacing(22)
        mg.setVerticalSpacing(10)
        mg.setColumnStretch(0, 1)
        mg.setColumnStretch(1, 1)
        mg.setColumnStretch(2, 1)

        if "lockout_02e2_timer" in self._status or "lockout_02e1_timer" in self._status:
            t_e2 = int(self._status.get("lockout_02e2_timer", 0))
            t_e1 = int(self._status.get("lockout_02e1_timer", 0))
            lockout_txt = f"02E2={t_e2} / 02E1={t_e1}"
            lockout_tone = "err" if (t_e2 or t_e1) else "ok"
        elif b02.get("lockout_timers_hex"):
            lh = str(b02["lockout_timers_hex"])
            lockout_txt = lh + (tr(" (нет блок.)", " (clear)") if lh == "000000" else "")
            lockout_tone = "ok" if lh == "000000" else "warn"
        else:
            lockout_txt, lockout_tone = "—", "muted"

        err_cnt = str(b02.get("error_counters_hex") or "—")
        v_opens = b02.get("virgin_opens_left")
        v_opens_txt = str(v_opens) if v_opens is not None else "—"

        if "unlock_time_ms" in self._status and "lock_time_ms" in self._status:
            bolt_time_txt = tr(
                f"откр. {self._status['unlock_time_ms']} мс / закр. {self._status['lock_time_ms']} мс",
                f"unlock {self._status['unlock_time_ms']} ms / lock {self._status['lock_time_ms']} ms",
            )
        else:
            bolt_time_txt = "—"

        mech_items = (
            (tr("ПОЛОЖЕНИЕ РИГЕЛЯ", "BOLT POSITION"), elv_bolt_state_label(bolt), "ok" if bolt == 0xC3 else ""),
            (tr("СЧЁТЧИК ЦИКЛОВ (2C8B)", "LOCK CYCLES (2C8B)"), str(cycles) if cycles is not None else "—", ""),
            (tr("ОСТАТОК ПРОБНЫХ ОТКРЫТИЙ (VIRGIN)", "VIRGIN TEST UNLOCKS LEFT"), v_opens_txt, ""),
            (tr("ТАЙМЕРЫ ЗАЩИТЫ (02EF)", "SECURITY TIMERS (02EF)"), lockout_txt, lockout_tone),
            (tr("СЧЁТЧИКИ ОШИБОК (БЛОК 2)", "ERROR COUNTERS (BLOCK 2)"), err_cnt, ""),
            (tr("ВРЕМЯ ХОДА РИГЕЛЯ (1109)", "BOLT TRAVEL TIME (1109)"), bolt_time_txt, ""),
        )
        for idx, (k_txt, v_txt, tone) in enumerate(mech_items):
            r, c = divmod(idx, 3)
            mg.addWidget(self._kv_cell(k_txt, v_txt, tone), r, c)
        sec_mech.body.addLayout(mg)
        lay.addWidget(sec_mech)

    # ────────────────────────────── Page 2: Adaptation & Reset ──────────────────────────────

    def _build_page_adapt(self, lay: QVBoxLayout) -> None:
        busy = self.runner.is_busy
        if self._is_open:
            self._refresh_cluster_from_provider()

        # Optional 17 FPK_E cluster summary Callout
        if self._cluster_material:
            cm = self._cluster_material
            cl_pn = html.escape(str(cm.get("part_number") or "17 FPK_E"))
            cl_vin = html.escape(str(cm.get("vin") or "—"))
            cl_pc = html.escape(str(cm.get("power_class_hex") or "—"))
            cl_idac = html.escape(str(cm.get("cluster_mac_id") or "—"))
            cl_idp = html.escape(str(cm.get("cluster_elv_idp") or "—"))
            crc_invalid = cm.get("slot_a_crc_ok") is False

            co = Callout("err" if crc_invalid else "info")
            if crc_invalid:
                co.label.setText(
                    tr(
                        f"<b>Ошибка CRC ключа Slot A (K_5) в дампе приборки {cl_pn}!</b> "
                        "Автоподстановка ключа <code>K_5</code> заблокирована, чтобы не записать повреждённый ключ. "
                        f"Доступны только VIN (<code>{cl_vin}</code>) и PowerClass (<code>{cl_pc}</code>).",
                        f"<b>Invalid Slot A (K_5) CRC in cluster dump {cl_pn}!</b> "
                        "Automatic <code>K_5</code> fill is blocked to prevent writing a corrupted key. "
                        f"Only VIN (<code>{cl_vin}</code>) and PowerClass (<code>{cl_pc}</code>) can be filled.",
                    )
                )
            else:
                co.label.setText(
                    tr(
                        f"<b>Данные приборки 17 FPK_E ({cl_pn}):</b> VIN <code>{cl_vin}</code> · "
                        f"PowerClass <code>{cl_pc}</code> · IDac <code>{cl_idac}</code> · ELV IDp <code>{cl_idp}</code>",
                        f"<b>17 FPK_E cluster loaded ({cl_pn}):</b> VIN <code>{cl_vin}</code> · "
                        f"PowerClass <code>{cl_pc}</code> · IDac <code>{cl_idac}</code> · ELV IDp <code>{cl_idp}</code>",
                    )
                )

            co_lay = co.layout()
            if co_lay is not None:
                act_row = QHBoxLayout()
                act_row.setContentsMargins(0, 4, 0, 0)
                btn_fill = button(
                    tr("Подставить VIN и PowerClass", "Fill VIN & PowerClass")
                    if crc_invalid
                    else tr("Подставить в форму", "Fill form"),
                    "InlineBtn",
                    slot=self._apply_cluster_material_to_form,
                )
                btn_fill.setEnabled(not busy)
                btn_fill.setCursor(Qt.CursorShape.PointingHandCursor)
                act_row.addWidget(btn_fill)
                act_row.addStretch(1)
                co_lay.addLayout(act_row)  # type: ignore[attr-defined]
            lay.addWidget(co)

        # ── Card 1: Vehicle Adaptation ──
        sec_ad = self._compact_section(
            tr("Привязка ELV к автомобилю", "Adapt ELV to Vehicle"),
            tr(
                "Запись VIN, ключа иммобилайзера K_5 и PowerClass по CAN (2E 02E2) или в файл DFLASH.",
                "Write vehicle VIN, immobilizer key K_5, and PowerClass over CAN (2E 02E2) or into a DFLASH file.",
            ),
        )

        fg = QGridLayout()
        fg.setHorizontalSpacing(14)
        fg.setVerticalSpacing(10)
        fg.setColumnStretch(0, 1)
        fg.setColumnStretch(1, 1)

        def _make_edit(val: str, placeholder: str, draft_attr: str) -> QLineEdit:
            ed = QLineEdit(val)
            ed.setFont(mono_font(12))
            ed.setPlaceholderText(placeholder)
            ed.textChanged.connect(lambda t, a=draft_attr: setattr(self, a, t.strip()))
            return ed

        # Row 0: VIN | PowerClass
        self._ed_vin = _make_edit(
            self._draft_vin,
            tr("17 символов, например WVWZZZAUZJW000001", "17 characters, e.g. WVWZZZAUZJW000001"),
            "_draft_vin",
        )
        c_vin, b_vin = self._field_box(tr("VIN АВТОМОБИЛЯ (17 СИМВ.)", "VEHICLE VIN (17 CHARS)"), self._ed_vin)
        self._bind_vin_validator(self._ed_vin, b_vin)
        fg.addWidget(c_vin, 0, 0)

        self._ed_pc = _make_edit(
            self._draft_power_class,
            tr("1 байт HEX, например 6F или 76", "1 hex byte, e.g. 6F or 76"),
            "_draft_power_class",
        )
        c_pc, b_pc = self._field_box(tr("POWERCLASS (HEX)", "POWERCLASS (HEX)"), self._ed_pc)
        self._bind_hex_validator(self._ed_pc, b_pc, 1, allow_empty=False)
        fg.addWidget(c_pc, 0, 1)

        # Row 1 (full width): New K_5
        self._ed_new_k5 = _make_edit(
            self._draft_new_k5,
            tr("32 HEX-символа (16 байт ключа Slot A из приборной панели)", "32 hex chars (16-byte Slot A key from cluster)"),
            "_draft_new_k5",
        )
        c_nk5, b_nk5 = self._field_box(
            tr("НОВЫЙ КЛЮЧ ИММОБИЛАЙЗЕРА (K_5 / SLOT A)", "NEW IMMOBILIZER KEY (K_5 / SLOT A)"),
            self._ed_new_k5,
        )
        self._bind_hex_validator(self._ed_new_k5, b_nk5, 16, allow_empty=False)
        fg.addWidget(c_nk5, 1, 0, 1, 2)

        # Row 2: Current K_5 (optional) | Offline IDac (optional)
        cur_k5_init = self._draft_cur_k5 or self.current_k5_hex
        self._ed_cur_k5 = _make_edit(
            cur_k5_init,
            tr("пусто = считается сам по CAN", "empty = auto-read over CAN"),
            "_draft_cur_k5",
        )
        c_ck5, b_ck5 = self._field_box(
            tr("ТЕКУЩИЙ КЛЮЧ K_5 ЗАЩЁЛКИ", "CURRENT ELV KEY K_5"),
            self._ed_cur_k5,
            tip=tr("Нужен для шифрования команды 2E 02E2; если пусто, программа сама считает его из Data Flash", "Required to encrypt 2E 02E2; if empty, ContiTool reads it automatically from Data Flash"),
        )
        self._bind_hex_validator(
            self._ed_cur_k5,
            b_ck5,
            16,
            allow_empty=True,
            empty_label=tr("авто", "auto"),
        )
        fg.addWidget(c_ck5, 2, 0)

        self._ed_offline_idac = _make_edit(
            self._draft_offline_idac,
            tr("пусто = автообучение", "empty = auto-learn"),
            "_draft_offline_idac",
        )
        c_idac, b_idac = self._field_box(
            tr("ID ПРИБОРКИ ДЛЯ ОФЛАЙН-ДАМПА (IDAC)", "CLUSTER ID FOR OFFLINE DUMP (IDAC)"),
            self._ed_offline_idac,
            tip=tr("Используется только при сохранении в .bin; если оставить пустым, защёлка выучит приборку сама", "Used only when saving offline .bin; leave empty for automatic cluster learning"),
        )
        self._bind_hex_validator(
            self._ed_offline_idac,
            b_idac,
            2,
            allow_empty=True,
            empty_label=tr("авто", "auto"),
        )
        fg.addWidget(c_idac, 2, 1)

        # Row 3: Config | Brand
        self._ed_cfg = _make_edit(self._draft_cfg, "80", "_draft_cfg")
        c_cfg, b_cfg = self._field_box(
            tr("БАЙТ CONFIG (ПО УМОЛЧАНИЮ 80)", "CONFIG BYTE (DEFAULT 80)"),
            self._ed_cfg,
        )
        self._bind_hex_validator(self._ed_cfg, b_cfg, 1, allow_empty=True, empty_label="80")
        fg.addWidget(c_cfg, 3, 0)

        self._ed_brand = _make_edit(self._draft_brand, "01", "_draft_brand")
        c_br, b_br = self._field_box(
            tr("БАЙТ BRAND (ПО УМОЛЧАНИЮ 01)", "BRAND BYTE (DEFAULT 01)"),
            self._ed_brand,
        )
        self._bind_hex_validator(self._ed_brand, b_br, 1, allow_empty=True, empty_label="01")
        fg.addWidget(c_br, 3, 1)

        sec_ad.body.addLayout(fg)
        sec_ad.body.addWidget(
            hint(
                tr(
                    "Перед записью программа проверит текущий ключ K_5 через 22 02F9. Привязка приборки (IDac) сбросится в автообучение.",
                    "Before writing, ContiTool verifies the current K_5 via 22 02F9. Cluster link (IDac) resets to auto-learn.",
                )
            )
        )

        btn_can_adapt = button(tr("Привязать по CAN", "Adapt over CAN"), "PrimaryBtn", slot=self.action_can_adapt)
        btn_off_adapt = button(tr("Сохранить в файл .bin…", "Save to .bin file…"), slot=self.action_offline_adapt)
        btn_can_adapt.setEnabled(not busy)
        btn_off_adapt.setEnabled(not busy and self._dflash_bytes is not None)
        for b in (btn_can_adapt, btn_off_adapt):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        sec_ad.add_footer(btn_can_adapt, btn_off_adapt)
        lay.addWidget(sec_ad)

        # ── Card 2: Reset Steering Lock (Virgin / Unlink Cluster) ──
        sec_rst = self._compact_section(
            tr("Сброс защёлки (Virgin / отвязка от приборки)", "Reset Steering Lock (Virgin / Unlink Cluster)"),
        )

        # Sub-block A: Virgin reset
        lbl_vir_hdr = QLabel(tr("Сброс в заводское состояние (Virgin, Mode 2 → Mode 1)", "Factory Virgin Reset (Mode 2 → Mode 1)"))
        lbl_vir_hdr.setObjectName("FieldLabel")
        sec_rst.body.addWidget(lbl_vir_hdr)
        sec_rst.body.addWidget(
            hint(
                tr(
                    "Очищает VIN, PowerClass и привязку приборки, переводя защёлку в состояние новой детали.",
                    "Clears VIN, PowerClass, and cluster link, returning the steering lock to brand-new Virgin state.",
                )
            )
        )

        self._ed_virgin_k5 = _make_edit(
            self._draft_virgin_k5,
            tr("пусто = оставить текущий ключ K_5", "empty = keep current K_5"),
            "_draft_virgin_k5",
        )
        c_vk5, b_vk5 = self._field_box(
            tr("ТРАНСПОРТНЫЙ КЛЮЧ VIRGIN K_5 (ОПЦИОНАЛЬНО)", "VIRGIN TRANSPORT KEY K_5 (OPTIONAL)"),
            self._ed_virgin_k5,
        )
        self._bind_hex_validator(
            self._ed_virgin_k5,
            b_vk5,
            16,
            allow_empty=True,
            empty_label=tr("текущий", "keep"),
        )
        sec_rst.body.addWidget(c_vk5)

        vrow = QHBoxLayout()
        vrow.setSpacing(8)
        btn_can_vir = button(tr("Сбросить в Virgin по CAN", "Virginize over CAN"), "DangerBtn", slot=self.action_can_virginize)
        btn_off_vir = button(tr("Сохранить Virgin .bin…", "Save Virgin .bin…"), slot=self.action_offline_virginize)
        btn_can_vir.setEnabled(not busy)
        btn_off_vir.setEnabled(not busy and self._dflash_bytes is not None)
        for b in (btn_can_vir, btn_off_vir):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            vrow.addWidget(b)
        vrow.addStretch(1)
        sec_rst.body.addLayout(vrow)

        sec_rst.body.addWidget(divider())

        # Sub-block B: Unlink from cluster (Reset IDac)
        lbl_idac_hdr = QLabel(tr("Отвязать от приборной панели (сброс IDac)", "Unlink from Instrument Cluster (Reset IDac)"))
        lbl_idac_hdr.setObjectName("FieldLabel")
        sec_rst.body.addWidget(lbl_idac_hdr)
        sec_rst.body.addWidget(
            hint(
                tr(
                    "Очищает только привязку к старой приборке (0xAA → 0x00), сохраняя VIN, K_5 и PowerClass — "
                    "новая приборка с тем же ключом K_5 привяжется автоматически.",
                    "Clears only the old cluster pairing (0xAA → 0x00) while keeping VIN, K_5, and PowerClass — "
                    "a replacement cluster with the same K_5 will auto-learn.",
                )
            )
        )

        irow = QHBoxLayout()
        btn_reset_idac = button(tr("Сбросить привязку приборки", "Reset cluster link"), slot=self.action_can_reset_idac)
        btn_reset_idac.setEnabled(not busy)
        btn_reset_idac.setToolTip("UDS 2E 02E1 (cmd=04, arg=80)")
        btn_reset_idac.setCursor(Qt.CursorShape.PointingHandCursor)
        irow.addWidget(btn_reset_idac)
        irow.addStretch(1)
        sec_rst.body.addLayout(irow)

        lay.addWidget(sec_rst)

    # ────────────────────────────── Page 3: Passport & Memory ──────────────────────────────

    def _build_page_status(self, lay: QVBoxLayout) -> None:
        busy = self.runner.is_busy
        bridge_blocked = self._via_gateway and not self._gateway_bridge
        ident = (self._dflash_parsed or {}).get("identity") or {}
        p = self._passport

        # ── Card 1: Control Unit Passport ──
        sec_id = self._compact_section(
            tr("Паспорт блока", "Control Unit Passport"),
            tr("Идентификационные данные 2B ELV (Marquardt 3Q0 905 861).", "2B ELV identification data (Marquardt 3Q0 905 861)."),
        )

        g = QGridLayout()
        g.setHorizontalSpacing(24)
        g.setVerticalSpacing(10)
        g.setColumnStretch(0, 1)
        g.setColumnStretch(1, 1)

        hw_pn = p.get("hw_part_number") or ident.get("hw_part_number") or ""
        hw_ver = p.get("hw_version") or ident.get("hw_version") or ""
        hw_disp = f"{hw_pn} / {hw_ver}" if (hw_pn and hw_ver) else (hw_pn or hw_ver or "—")

        asam_odx = p.get("asam_odx") or ident.get("asam_odx") or ""
        asam_ver = p.get("asam_version") or ident.get("asam_version") or ""
        asam_disp = f"{asam_odx} {asam_ver}".strip() or "—"

        if "unlock_time_ms" in self._status and "lock_time_ms" in self._status:
            bolt_t = tr(
                f"открытие {self._status['unlock_time_ms']} мс / закрытие {self._status['lock_time_ms']} мс",
                f"unlock {self._status['unlock_time_ms']} ms / lock {self._status['lock_time_ms']} ms",
            )
        else:
            bolt_t = "—"

        pp_items = (
            (tr("НОМЕР ДЕТАЛИ (F187)", "PART NUMBER (F187)"), p.get("part_number") or ident.get("part_number") or "—"),
            (tr("ВЕРСИЯ ПО (F189)", "SW VERSION (F189)"), p.get("sw_version") or ident.get("sw_version") or "—"),
            (tr("ОБОРУДОВАНИЕ (F191 / F1A3)", "HARDWARE (F191 / F1A3)"), hw_disp),
            ("ASAM / ODX (F19E / F1A2)", asam_disp),
            ("FAZIT (F17C)", p.get("fazit") or ident.get("fazit") or "—"),
            (tr("СЕРИЙНЫЙ НОМЕР (F18C)", "SERIAL NUMBER (F18C)"), p.get("serial") or ident.get("serial") or "—"),
            (tr("КОДИРОВКА (0600)", "CODING (0600)"), p.get("coding_hex") or ident.get("coding_hex") or "—"),
            (tr("ВРЕМЯ ХОДА РИГЕЛЯ (1109)", "BOLT TIMING (1109)"), bolt_t),
        )
        for idx, (k_txt, v_txt) in enumerate(pp_items):
            r, c = divmod(idx, 2)
            g.addWidget(self._kv_cell(k_txt, str(v_txt)), r, c)
        sec_id.body.addLayout(g)
        lay.addWidget(sec_id)

        # ── Card 2: Bootloader (FBL) Check ──
        sec_bl = self._compact_section(
            tr("Проверка загрузчика (FBL)", "Bootloader Check (FBL)"),
            tr(
                "Проверяет условия для прошивки и (опционально) тестовый вход в загрузчик с автоматическим возвратом в рабочий режим.",
                "Checks programming preconditions and optionally tests bootloader entry with automatic reset back to normal mode.",
            ),
        )
        if self._bootloader_check:
            bc = self._bootloader_check
            all_ok = bool(bc.get("security_access_ok")) if bc.get("security_access_ok") is not None else bool(bc.get("preconditions_ok"))
            co = Callout("ok" if all_ok else "warn")

            parts: list[str] = []
            if bc.get("preconditions_ok"):
                parts.append(tr("<b>Условия прошивки (31 01 02 03):</b> соблюдены", "<b>Preconditions (31 01 02 03):</b> OK"))
            else:
                err_s = html.escape(str(bc.get("preconditions_error") or bc.get("preconditions_raw_hex") or "—"))
                parts.append(
                    tr(f"<b>Условия прошивки (31 01 02 03):</b> {err_s}", f"<b>Preconditions (31 01 02 03):</b> {err_s}")
                )

            if bc.get("wfs5_handshake_ok") is not None:
                ok_w = bool(bc["wfs5_handshake_ok"])
                parts.append(
                    tr(
                        f"<b>Авторизация WFS5 (01A/01B):</b> {'успешно' if ok_w else 'ошибка'}",
                        f"<b>WFS5 handshake (01A/01B):</b> {'OK' if ok_w else 'failed'}",
                    )
                )
            if bc.get("programming_session_ok") is not None:
                ok_p = bool(bc["programming_session_ok"])
                parts.append(
                    tr(
                        f"<b>Вход в загрузчик (10 02):</b> {'успешно' if ok_p else 'ошибка'}",
                        f"<b>Programming session (10 02):</b> {'OK' if ok_p else 'failed'}",
                    )
                )
            if bc.get("security_access_ok") is not None:
                ok_s = bool(bc["security_access_ok"])
                seed_h = html.escape(str(bc.get("bootloader_seed_hex") or ""))
                seed_s = f" (seed <code>{seed_h}</code>)" if seed_h else ""
                parts.append(
                    tr(
                        f"<b>Доступ SecurityAccess (27 11/12):</b> {'разблокирован' if ok_s else 'отклонен'}{seed_s}",
                        f"<b>SecurityAccess (27 11/12):</b> {'unlocked' if ok_s else 'rejected'}{seed_s}",
                    )
                )
            co.label.setText("<br>".join(parts))
            sec_bl.body.addWidget(co)

        btn_pre = button(
            tr("Проверить условия прошивки", "Check flashing preconditions"),
            slot=lambda: self.action_check_bootloader(False),
        )
        btn_pre.setEnabled(not busy)
        btn_pre.setToolTip("UDS 31 01 02 03")
        btn_pre.setCursor(Qt.CursorShape.PointingHandCursor)

        btn_bl = button(
            tr("Проверить вход в загрузчик (FBL)", "Test bootloader entry (FBL)"),
            slot=lambda: self.action_check_bootloader(True),
        )
        btn_bl.setEnabled(not busy and not bridge_blocked)
        btn_bl.setToolTip(
            self._bridge_blocked_tip()
            if bridge_blocked
            else tr(
                "Выполнит 10 02 + 27 11/12 и вернёт блок в рабочий режим через 11 02",
                "Runs 10 02 + 27 11/12 and resets the ECU back to normal mode via 11 02",
            )
        )
        btn_bl.setCursor(Qt.CursorShape.PointingHandCursor)

        sec_bl.add_footer(btn_pre, btn_bl)
        lay.addWidget(sec_bl)

        # ── Card 3: Collapsible EEELib Data Flash Records (47 blocks) ──
        recs = (self._dflash_parsed or {}).get("records") or []
        if self._dflash_parsed and recs:
            v_cnt = int(self._dflash_parsed.get("crc_valid_count") or 0)
            t_cnt = int(self._dflash_parsed.get("crc_total_count") or len(recs))
            crc_ok = bool(self._dflash_parsed.get("all_crc_ok"))

            sec_rec = self._compact_section(
                tr(f"Записи памяти Data Flash ({len(recs)} блоков EEELib)", f"Data Flash Memory Records ({len(recs)} EEELib blocks)"),
                tr(
                    "Таблица расшифрованных записей активного пула EEELib с проверкой CRC-32.",
                    "Decrypted records in the active EEELib pool with per-record CRC-32 check.",
                ),
            )
            sec_rec.head.addWidget(
                status_readout(f"{v_cnt}/{t_cnt} CRC {'OK' if crc_ok else 'ERR'}", "ok" if crc_ok else "err"),
                0,
                Qt.AlignmentFlag.AlignVCenter,
            )

            tbl = self._build_eeelib_table(recs)
            tbl.setVisible(self._show_eeelib_records)
            sec_rec.body.addWidget(tbl)

            self._eeelib_table = tbl
            self._eeelib_count = len(recs)
            self._btn_eeelib_toggle = button(
                self._eeelib_toggle_label(),
                "InlineBtn",
                slot=self._toggle_eeelib_records,
            )
            self._btn_eeelib_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
            sec_rec.add_footer(self._btn_eeelib_toggle)
            lay.addWidget(sec_rec)

    def _eeelib_toggle_label(self) -> str:
        n = self._eeelib_count
        if self._show_eeelib_records:
            return tr(f"Скрыть {n} записей", f"Hide {n} records")
        return tr(f"Показать все {n} записей", f"Show all {n} records")

    def _toggle_eeelib_records(self) -> None:
        self._show_eeelib_records = not self._show_eeelib_records
        if self._eeelib_table is not None and _qt_valid(self._eeelib_table):
            self._eeelib_table.setVisible(self._show_eeelib_records)
        if self._btn_eeelib_toggle is not None and _qt_valid(self._btn_eeelib_toggle):
            self._btn_eeelib_toggle.setText(self._eeelib_toggle_label())

    @staticmethod
    def _build_eeelib_table(recs: list[dict[str, Any]]) -> QFrame:
        wrap = QFrame()
        wrap.setObjectName("ResultStrip")
        vlay = QVBoxLayout(wrap)
        vlay.setContentsMargins(0, 4, 0, 4)
        vlay.setSpacing(0)

        hdr = QFrame()
        hdr.setObjectName("TableHead")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(12, 5, 12, 5)
        hl.setSpacing(10)
        for text_h, stretch, fix_w in (
            ("ID", 0, 28),
            (tr("АДРЕС", "VADDR"), 0, 62),
            (tr("СМЕЩ.", "OFFSET"), 0, 62),
            (tr("ФЛАГИ", "FLAGS"), 0, 108),
            ("CRC-32", 0, 118),
            (tr("ДАННЫЕ (HEX)", "DATA (HEX)"), 1, 0),
        ):
            lbl = group_label(text_h)
            if fix_w:
                lbl.setFixedWidth(fix_w)
            hl.addWidget(lbl, stretch)
        vlay.addWidget(hdr)

        for idx, rec in enumerate(recs):
            row_f = QFrame()
            row_f.setObjectName("TableRow")
            if idx == len(recs) - 1:
                row_f.setProperty("last", True)
            rl = QHBoxLayout(row_f)
            rl.setContentsMargins(12, 4, 12, 4)
            rl.setSpacing(10)

            c_id = QLabel(f"{int(rec.get('id', idx)):02d}")
            c_id.setFont(mono_font(10))
            c_id.setFixedWidth(28)
            set_tone(c_id, "muted")

            c_va = QLabel(str(rec.get("vaddr_hex") or "—"))
            c_va.setFont(mono_font(10, bold=True))
            c_va.setFixedWidth(62)

            c_off = QLabel(str(rec.get("compact_offset_hex") or "—"))
            c_off.setFont(mono_font(10))
            c_off.setFixedWidth(62)
            set_tone(c_off, "muted")

            fl_txt = str(rec.get("flags_label") or tr("НЕТ", "MISSING"))
            c_fl = QLabel(fl_txt)
            c_fl.setFont(mono_font(10))
            c_fl.setFixedWidth(108)
            set_tone(c_fl, "muted")

            crc_ok = bool(rec.get("crc_ok"))
            crc_hex = str(rec.get("crc_hex") or "")
            c_crc = QLabel(f"{'OK' if crc_ok else tr('ОШБ', 'FAIL')} {crc_hex}".strip())
            c_crc.setFont(mono_font(10))
            c_crc.setFixedWidth(118)
            set_tone(c_crc, "ok" if crc_ok else "err")

            full_hex = str(rec.get("data_hex") or "")
            short_hex = full_hex if len(full_hex) <= 44 else (full_hex[:42] + "…")
            c_data = QLabel(short_hex or "—")
            c_data.setFont(mono_font(10))
            c_data.setToolTip(full_hex)
            set_tone(c_data, "muted")
            c_data.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

            rl.addWidget(c_id)
            rl.addWidget(c_va)
            rl.addWidget(c_off)
            rl.addWidget(c_fl)
            rl.addWidget(c_crc)
            rl.addWidget(c_data, 1)
            vlay.addWidget(row_f)

        return wrap

    # ────────────────────────────── Page 4: Fault Codes (DTC) ──────────────────────────────

    def _build_page_dtc(self, lay: QVBoxLayout) -> None:
        # ── Card 1: Live UDS DTCs ──
        sec = self._compact_section(
            tr("Память ошибок 2B ELV (UDS)", "2B ELV Fault Memory (UDS)"),
            tr(
                "Активные и сохранённые ошибки блока по диагностическому протоколу UDS (19 02 / 14 FF FF FF).",
                "Active and stored control unit faults via UDS diagnostics (19 02 / 14 FF FF FF).",
            ),
        )

        if self._dtcs is None:
            sec.head.addWidget(status_readout(tr("Не опрошено", "Not polled"), "muted"))
            sec.body.addWidget(
                hint(
                    tr(
                        "Ошибки ещё не считывались. Нажмите «Считать ошибки» вверху справа.",
                        "Fault codes have not been read yet. Click “Read fault codes” at the top right.",
                    )
                )
            )
        elif not self._dtcs:
            sec.head.addWidget(status_readout(tr("Ошибок нет", "No faults"), "ok"))
            ok_box = Callout("ok")
            ok_box.label.setText(
                tr(
                    "<b>В памяти блока 2B ELV нет активных или сохранённых неисправностей.</b>",
                    "<b>No active or stored fault codes in 2B ELV memory.</b>",
                )
            )
            sec.body.addWidget(ok_box)
        else:
            n_active = sum(1 for d in self._dtcs if _is_dtc_active(d))
            n_stored = len(self._dtcs) - n_active
            summary_txt = tr(
                f"Найдено: {len(self._dtcs)} (активных: {n_active}, в памяти: {n_stored})",
                f"Found: {len(self._dtcs)} ({n_active} active, {n_stored} stored)",
            )
            sec.head.addWidget(status_readout(summary_txt, "err" if n_active else "warn"))

            table_wrap = QFrame()
            table_wrap.setObjectName("ResultStrip")
            tlay = QVBoxLayout(table_wrap)
            tlay.setContentsMargins(0, 4, 0, 4)
            tlay.setSpacing(0)

            hdr = QFrame()
            hdr.setObjectName("TableHead")
            hl = QHBoxLayout(hdr)
            hl.setContentsMargins(14, 5, 14, 6)
            hl.setSpacing(12)
            for h_txt, stretch, fix_w in (
                (tr("КОД ODIS", "ODIS CODE"), 0, 88),
                ("UDS", 0, 74),
                (tr("СТАТУС", "STATUS"), 0, 142),
                (tr("ОПИСАНИЕ", "DESCRIPTION"), 1, 0),
            ):
                lbl_h = group_label(h_txt)
                if fix_w:
                    lbl_h.setFixedWidth(fix_w)
                hl.addWidget(lbl_h, stretch)
            tlay.addWidget(hdr)

            for idx, item in enumerate(self._dtcs):
                row_f = QFrame()
                row_f.setObjectName("TableRow")
                if idx == len(self._dtcs) - 1:
                    row_f.setProperty("last", True)
                rl = QHBoxLayout(row_f)
                rl.setContentsMargins(14, 8, 14, 8)
                rl.setSpacing(12)

                disp_code, desc_txt, st_detail = _localize_elv_dtc(item)
                raw_code = str(item.get("code_hex") or item.get("code") or "")
                st_hex = str(item.get("status_hex") or "")
                active = _is_dtc_active(item)

                c0 = QLabel(disp_code)
                c0.setFont(mono_font(12, bold=True))
                c0.setFixedWidth(88)
                c0.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

                c1 = QLabel(raw_code)
                c1.setFont(mono_font(11))
                c1.setFixedWidth(74)
                set_tone(c1, "muted")
                c1.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

                st_txt = (tr("Активна", "Active") if active else tr("В памяти", "Stored")) + (f" · {st_hex}" if st_hex else "")
                c2 = status_readout(st_txt, "err" if active else "warn")
                c2.setFixedWidth(142)
                c2.setAlignment(Qt.AlignmentFlag.AlignCenter)
                if st_detail:
                    c2.setToolTip(st_detail)

                desc_box = QVBoxLayout()
                desc_box.setContentsMargins(0, 0, 0, 0)
                desc_box.setSpacing(2)
                c3 = QLabel(desc_txt)
                c3.setWordWrap(True)
                c3.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                desc_box.addWidget(c3)
                if st_detail:
                    c3_sub = QLabel(st_detail)
                    c3_sub.setObjectName("Hint")
                    c3_sub.setWordWrap(True)
                    desc_box.addWidget(c3_sub)

                rl.addWidget(c0, 0, Qt.AlignmentFlag.AlignTop)
                rl.addWidget(c1, 0, Qt.AlignmentFlag.AlignTop)
                rl.addWidget(c2, 0, Qt.AlignmentFlag.AlignTop)
                rl.addLayout(desc_box, 1)
                tlay.addWidget(row_f)

            sec.body.addWidget(table_wrap)

        lay.addWidget(sec)

        # ── Card 2: Stored DTC Slots from Data Flash (Blocks 9..28) ──
        stored = (self._dflash_parsed or {}).get("stored_dtcs") or []
        if stored:
            sec_st = self._compact_section(
                tr("История ошибок в Data Flash (Блоки 9..28)", "Stored Fault History in Data Flash (Blocks 9..28)"),
                tr(
                    "Ошибки, сохранённые во внутренней энергонезависимой памяти дампа DFLASH.",
                    "Fault entries stored inside the non-volatile DFLASH dump.",
                ),
            )
            sec_st.head.addWidget(
                status_readout(tr(f"Записей: {len(stored)}", f"Entries: {len(stored)}"), "warn"),
                0,
                Qt.AlignmentFlag.AlignVCenter,
            )

            s_wrap = QFrame()
            s_wrap.setObjectName("ResultStrip")
            slay = QVBoxLayout(s_wrap)
            slay.setContentsMargins(0, 4, 0, 4)
            slay.setSpacing(0)

            shdr = QFrame()
            shdr.setObjectName("TableHead")
            shl = QHBoxLayout(shdr)
            shl.setContentsMargins(14, 5, 14, 6)
            shl.setSpacing(12)
            for h_txt, stretch, fix_w in (
                (tr("СЛОТ / АДРЕС", "SLOT / VADDR"), 0, 108),
                (tr("КОД ODIS", "ODIS CODE"), 0, 88),
                ("UDS · ST", 0, 114),
                (tr("ОПИСАНИЕ", "DESCRIPTION"), 1, 0),
            ):
                lbl_h = group_label(h_txt)
                if fix_w:
                    lbl_h.setFixedWidth(fix_w)
                shl.addWidget(lbl_h, stretch)
            slay.addWidget(shdr)

            for idx, d in enumerate(stored):
                row_f = QFrame()
                row_f.setObjectName("TableRow")
                if idx == len(stored) - 1:
                    row_f.setProperty("last", True)
                rl = QHBoxLayout(row_f)
                rl.setContentsMargins(14, 7, 14, 7)
                rl.setSpacing(12)

                s_disp, s_desc, _s_st = _localize_elv_dtc(d)

                c_sl = QLabel(f"#{int(d.get('slot', idx)):02d} · {d.get('vaddr_hex', '—')}")
                c_sl.setFont(mono_font(10))
                c_sl.setFixedWidth(108)
                set_tone(c_sl, "muted")

                c_disp = QLabel(s_disp)
                c_disp.setFont(mono_font(12, bold=True))
                c_disp.setFixedWidth(88)
                c_disp.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

                c_code = QLabel(f"{d.get('code_hex', '')} · {d.get('status_hex', '')}".strip(" ·"))
                c_code.setFont(mono_font(11))
                c_code.setFixedWidth(114)
                set_tone(c_code, "muted")

                c_desc = QLabel(s_desc)
                c_desc.setWordWrap(True)
                c_desc.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

                rl.addWidget(c_sl, 0, Qt.AlignmentFlag.AlignTop)
                rl.addWidget(c_disp, 0, Qt.AlignmentFlag.AlignTop)
                rl.addWidget(c_code, 0, Qt.AlignmentFlag.AlignTop)
                rl.addWidget(c_desc, 1)
                slay.addWidget(row_f)

            sec_st.body.addWidget(s_wrap)
            lay.addWidget(sec_st)

    # ────────────────────────────── Cluster Helpers & Offline Actions ──────────────────────────────

    def _sync_cluster_from_open_workspace(self) -> None:
        self._sync_drafts()
        if not self._refresh_cluster_from_provider(force=True):
            QMessageBox.information(
                self,
                "ContiTool",
                tr(
                    "Дамп приборной панели 17 FPK_E не открыт. Откройте его во вкладке приборной панели или нажмите «Загрузить Dflash.bin…».",
                    "No 17 FPK_E cluster dump is currently open. Open one in the cluster tab or click “Load Dflash.bin…”.",
                ),
            )
            return
        self._apply_cluster_material_to_form()

    def _apply_cluster_material_to_form(self) -> None:
        self._sync_drafts()
        if not self._cluster_material:
            return
        cm = self._cluster_material
        if cm.get("vin"):
            self._draft_vin = str(cm["vin"]).strip().upper()
        if cm.get("power_class") is not None:
            self._draft_power_class = f"{int(cm['power_class']):02X}"

        slot_a_crc_bad = cm.get("slot_a_crc_ok") is False
        if cm.get("slot_a_hex") and not slot_a_crc_bad:
            self._draft_new_k5 = str(cm["slot_a_hex"]).upper()

        self._refresh_all()

        if slot_a_crc_bad:
            QMessageBox.warning(
                self,
                tr("Ошибка CRC ключа в дампе приборки", "Cluster Key CRC Error"),
                tr(
                    "В дампе 17 FPK_E не сошлась контрольная сумма (CRC) ключа Slot A (K_5).\n"
                    "Подставлены только VIN и PowerClass — ключ K_5 не заполнен во избежание записи повреждённых данных.",
                    "The 17 FPK_E dump has an invalid Slot A (K_5) CRC.\n"
                    "Only VIN and PowerClass were filled — K_5 was skipped to avoid writing corrupted key data.",
                ),
            )
            self.note.emit(
                tr(
                    "Из 17 FPK_E подставлены VIN и PowerClass; ключ K_5 пропущен (ошибка CRC).",
                    "Filled VIN and PowerClass from 17 FPK_E; K_5 skipped (invalid CRC).",
                )
            )
        else:
            self.note.emit(
                tr(
                    "Поля привязки заполнены из дампа приборной панели 17 FPK_E.",
                    "Adaptation fields populated from 17 FPK_E cluster dump.",
                )
            )

    def action_load_cluster_dflash(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            tr("Выбрать Dflash.bin приборной панели 17 FPK_E", "Select 17 FPK_E Instrument Cluster Dflash.bin"),
            "",
            "Binary (*.bin *.raw);;All (*)",
        )
        if not path:
            return
        try:
            raw = Path(path).read_bytes()
            mat = elv_extract_cluster_material(raw)
        except OSError as exc:
            QMessageBox.warning(
                self,
                tr("Ошибка чтения файла", "File Read Error"),
                tr(f"Не удалось прочитать файл:\n{exc}", f"Failed to read file:\n{exc}"),
            )
            return
        except Exception as exc:
            QMessageBox.warning(self, tr("Ошибка разбора FPK_E", "FPK_E Parse Error"), str(exc))
            return

        self._cluster_material = mat
        self._cluster_source_manual = True
        self._cluster_dflash_sha = hashlib.sha256(raw).hexdigest()
        self._apply_cluster_material_to_form()

    def action_open_dflash_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            tr("Открыть дамп Data Flash ELV (32 КБ или 64 КБ)", "Open ELV Data Flash dump (32 KB or 64 KB)"),
            "",
            "Binary (*.bin *.raw);;All (*)",
        )
        if not path:
            return
        p = Path(path)
        try:
            self.open_from_dflash_file(p)
        except OSError as exc:
            QMessageBox.warning(
                self,
                tr("Ошибка чтения файла", "File Read Error"),
                tr(f"Не удалось открыть файл:\n{exc}", f"Could not open file:\n{exc}"),
            )
            return
        except Exception as exc:
            QMessageBox.warning(self, tr("Ошибка разбора DFLASH ELV", "ELV DFLASH Parse Error"), str(exc))
            return
        self.note.emit(tr(f"Открыт DFLASH ELV: {p.name}", f"Loaded ELV DFLASH: {p.name}"))

    def action_save_dflash(self) -> None:
        if self._dflash_bytes is None:
            return
        default_name = (
            f"elv_dflash_{'32k' if len(self._dflash_bytes) == ELV_DFLASH_COMPACT_SIZE else '64k'}.bin"
        )
        out, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить Data Flash ELV", "Save ELV Data Flash"),
            default_name,
            "Binary (*.bin)",
        )
        if not out:
            return
        try:
            Path(out).write_bytes(self._dflash_bytes)
        except OSError as exc:
            QMessageBox.warning(
                self,
                tr("Ошибка сохранения файла", "File Save Error"),
                tr(f"Не удалось сохранить Data Flash:\n{exc}", f"Could not save Data Flash:\n{exc}"),
            )
            return
        self.note.emit(tr(f"Data Flash сохранён: {out}", f"Data Flash saved: {out}"))

    def action_export_json(self) -> None:
        out, _ = QFileDialog.getSaveFileName(
            self,
            tr("Экспорт отчёта ELV в JSON", "Export ELV Report JSON"),
            "elv_report.json",
            "JSON (*.json)",
        )
        if not out:
            return
        payload = {
            "ecu_kind": "elv",
            "diag_addr": "2B",
            "passport": self._passport,
            "status": self._status,
            "dflash_parsed": self._dflash_parsed,
            "verify_02f9": self._verify_02f9,
            "dtcs": self._dtcs,
        }
        try:
            Path(out).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(
                self,
                tr("Ошибка сохранения отчёта", "Report Save Error"),
                tr(f"Не удалось записать JSON-отчёт:\n{exc}", f"Could not write JSON report:\n{exc}"),
            )
            return
        self.note.emit(tr(f"Отчёт ELV сохранён: {out}", f"ELV report saved: {out}"))

    # ────────────────────────────── Form Validation & Session Creation ──────────────────────────────

    def _create_session_dir(self, kind: str, *, dumps: bool) -> Path | None:
        try:
            return new_session(self.conn.out_dir, self._elv_unit_name(), kind, dumps=dumps)
        except OSError as exc:
            QMessageBox.warning(
                self,
                tr("Ошибка создания папки сессии", "Session Folder Error"),
                tr(
                    f"Не удалось создать папку для сохранения бэкапа и отчёта:\n{exc}",
                    f"Could not create folder for backup and report:\n{exc}",
                ),
            )
            return None

    def _parse_adapt_form(self, *, require_idac_check: bool = True) -> tuple[str, str, int, int, int, str | None, str | None]:
        self._sync_drafts()
        vin = self._draft_vin.strip().upper()
        if len(vin) != 17 or not all(0x20 <= ord(c) < 0x7F for c in vin):
            raise ValueError(
                tr(
                    "VIN должен содержать ровно 17 латинских букв/цифр (ASCII).",
                    "VIN must be exactly 17 printable ASCII characters.",
                )
            )
        new_k5 = _validate_hex_exact(
            self._draft_new_k5,
            16,
            tr("Новый ключ K_5 / Slot A", "New K_5 / Slot A key"),
        )
        pc_txt = self._draft_power_class.strip()
        if not pc_txt:
            raise ValueError(
                tr("Укажите PowerClass в HEX (например 6F или 76).", "Enter PowerClass in hex (e.g. 6F or 76).")
            )
        pc = _parse_hex_byte(pc_txt, "PowerClass")
        cfg = _parse_hex_byte(self._draft_cfg.strip() or "80", "Config")
        brand = _parse_hex_byte(self._draft_brand.strip() or "01", "Brand")

        cur_k5_raw = _clean_hex(self._draft_cur_k5)
        cur_k5 = (
            _validate_hex_exact(cur_k5_raw, 16, tr("Текущий ключ K_5 защёлки", "Current ELV K_5 key"))
            if cur_k5_raw
            else None
        )

        off_idac_raw = _clean_hex(self._draft_offline_idac)
        if off_idac_raw and require_idac_check:
            off_idac = _validate_hex_exact(off_idac_raw, 2, tr("ID приборки (IDac)", "Cluster ID (IDac)"))
        else:
            off_idac = off_idac_raw.upper() or None

        return vin, new_k5, pc, cfg, brand, cur_k5, off_idac

    def _check_gateway_cur_k5_available(self, cur_k5: str | None) -> bool:
        if self._via_gateway and not self._gateway_bridge and cur_k5 is None:
            QMessageBox.warning(
                self,
                tr("Требуется текущий ключ K_5", "Current K_5 Key Required"),
                tr(
                    "При работе через шлюз J533 без RAM-моста программа не может автоматически считать "
                    "текущий ключ K_5 из Data Flash.\n\n"
                    "Введите текущий ключ K_5 защёлки (32 HEX) вручную или подключите ELV напрямую к шине Komfort CAN.",
                    "Via a J533 gateway without RAM-Bridge, ContiTool cannot auto-read the current K_5 from Data Flash.\n\n"
                    "Enter the current ELV K_5 key (32 hex) manually or connect ELV directly to Komfort CAN.",
                ),
            )
            return False
        return True

    # ────────────────────────────── Live CAN & Offline Write Actions ──────────────────────────────

    def action_read_status(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        via_gw, gw_br, gw_ch = self._via_gateway, self._gateway_bridge, self._gateway_channel
        gen = self._session_gen

        def _done(res: dict[str, Any]) -> None:
            if not _qt_valid(self) or not self._is_open or self._session_gen != gen:
                return
            self.open_from_read_result(
                res,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
            )

        self.runner.run_task(
            tr("Опрос статуса ELV (2B)", "Poll ELV (2B) Status"),
            lambda rep: can_elv_status(
                port,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                reporter=rep,
            ),
            on_success=_done,
        )

    def action_read_dflash(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        if self._via_gateway and not self._gateway_bridge:
            QMessageBox.warning(
                self,
                tr("Чтение DFLASH недоступно", "DFLASH Read Unavailable"),
                self._bridge_blocked_tip(),
            )
            return
        port, iface = self.conn.port, self.conn.interface
        via_gw, gw_br, gw_ch = self._via_gateway, self._gateway_bridge, self._gateway_channel
        s_dir = self._create_session_dir("elv_dflash", dumps=True)
        if s_dir is None:
            return
        gen = self._session_gen

        def _task(rep: Any) -> dict[str, Any]:
            res = can_elv_read_dflash(
                port,
                out_dir=s_dir,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                reporter=rep,
            )
            res["session_dir"] = str(s_dir)
            return res

        def _done(res: dict[str, Any]) -> None:
            if not _qt_valid(self) or not self._is_open or self._session_gen != gen:
                return
            self.open_from_read_result(
                res,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
            )

        self.runner.run_task(
            tr("Чтение 32 КБ Data Flash ELV", "Read 32 KB ELV Data Flash"),
            _task,
            on_success=_done,
        )

    def action_can_adapt(self) -> None:
        if self.runner.is_busy:
            return
        try:
            vin, new_k5, pc, cfg, brand, cur_k5, _ = self._parse_adapt_form(require_idac_check=False)
        except ValueError as exc:
            QMessageBox.warning(self, tr("Проверьте поля привязки", "Check Adaptation Fields"), str(exc))
            return
        if not self._check_gateway_cur_k5_available(cur_k5):
            return
        if not ensure_ready(self.conn, self):
            return

        uses_bridge = bool(self._via_gateway and self._gateway_bridge and cur_k5 is None)
        dlg = ElvConfirmWriteDialog(
            title=tr("Привязка ELV к автомобилю (2E 02E2)", "Adapt ELV to Vehicle (2E 02E2)"),
            subtitle=tr(
                "Запись новых VIN, ключа K_5 и PowerClass по CAN (привязка приборки IDac сбросится в автообучение).",
                "Write new VIN, K_5 key, and PowerClass over CAN (cluster IDac resets to auto-learn).",
            ),
            summary_html=(
                f"<b>VIN:</b> <code>{html.escape(vin)}</code><br>"
                f"<b>{tr('Новый ключ K_5 / Slot A', 'New K_5 / Slot A')}:</b> <code>{html.escape(new_k5)}</code><br>"
                f"<b>PowerClass / Config / Brand:</b> <code>0x{pc:02X}</code> / <code>0x{cfg:02X}</code> / <code>0x{brand:02X}</code>"
            ),
            action_label=tr("Привязать по CAN", "Adapt over CAN"),
            via_gateway=self._via_gateway,
            uses_bridge=uses_bridge,
            is_02e2=True,
            parent=self,
        )
        if not run_dialog(dlg) or self.runner.is_busy:
            return

        port, iface = self.conn.port, self.conn.interface
        via_gw, gw_br, gw_ch = self._via_gateway, self._gateway_bridge, self._gateway_channel
        s_dir = self._create_session_dir("elv_adapt", dumps=False)
        if s_dir is None:
            return
        gen = self._session_gen

        def _task(rep: Any) -> dict[str, Any]:
            res = can_elv_adapt(
                port,
                new_vin=vin,
                new_k5=new_k5,
                new_power_class=pc,
                current_k5=cur_k5,
                cfg_byte=cfg,
                brand_byte=brand,
                backup_dir=s_dir,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                reporter=rep,
            )
            res["session_dir"] = str(s_dir)
            return res

        def _done(res: dict[str, Any]) -> None:
            if not _qt_valid(self) or not self._is_open or self._session_gen != gen:
                return
            if isinstance(res.get("post_passport"), dict):
                self._passport = dict(res["post_passport"])
            if isinstance(res.get("post_status"), dict):
                self._status = dict(res["post_status"])
            if isinstance(res.get("verify_02f9"), dict):
                self._verify_02f9 = dict(res["verify_02f9"])

            if res.get("ok"):
                self._draft_cur_k5 = new_k5
                self._refresh_all()
                self.changed.emit()
                self.note.emit(tr("ELV успешно привязана к автомобилю (2E 02E2).", "ELV adapted to vehicle successfully (2E 02E2)."))
            else:
                if (self._verify_02f9 or {}).get("match"):
                    self._draft_cur_k5 = new_k5
                self._refresh_all()
                self.changed.emit()
                mode_after = elv_mode_label(self._status.get("mode"))
                msg = tr(
                    f"Запись 2E 02E2 выполнена, но проверка после записи не пройдена.\n"
                    f"Текущий режим: {mode_after}. Проверьте статус и повторите чтение DFLASH.",
                    f"2E 02E2 write finished, but post-write verification did not pass.\n"
                    f"Current mode: {mode_after}. Check ECU status and re-read DFLASH.",
                )
                self.note.emit(msg.replace("\n", " "))
                QMessageBox.warning(self, tr("Проверка после привязки не пройдена", "Post-Adaptation Verification Failed"), msg)

        self.runner.run_task(
            tr("Привязка ELV (2E 02E2)", "Adapt ELV (2E 02E2)"),
            _task,
            on_success=_done,
        )

    def action_offline_adapt(self) -> None:
        if self._dflash_bytes is None:
            return
        try:
            vin, new_k5, pc, cfg, brand, _, off_idac = self._parse_adapt_form(require_idac_check=True)
            rebuilt = elv_adapt_dflash(
                self._dflash_bytes,
                vin=vin,
                k5=new_k5,
                power_class=pc,
                idac=off_idac,
                config_byte=cfg,
                brand_byte=brand,
            )
        except Exception as exc:
            QMessageBox.warning(self, tr("Ошибка сборки DFLASH", "DFLASH Rebuild Error"), str(exc))
            return

        suffix = "64k" if len(rebuilt) == ELV_DFLASH_RAW64K_SIZE else "32k"
        out, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить адаптированный DFLASH ELV", "Save Adapted ELV DFLASH"),
            f"elv_adapted_{vin}_{suffix}.bin",
            "Binary (*.bin)",
        )
        if not out:
            return
        try:
            Path(out).write_bytes(rebuilt)
        except OSError as exc:
            QMessageBox.warning(
                self,
                tr("Ошибка сохранения файла", "File Save Error"),
                tr(f"Не удалось сохранить файл:\n{exc}", f"Could not save file:\n{exc}"),
            )
            return
        self.note.emit(tr(f"Адаптированный DFLASH сохранён: {out}", f"Adapted DFLASH saved: {out}"))

    def action_can_virginize(self) -> None:
        if self.runner.is_busy:
            return
        self._sync_drafts()
        try:
            cur_k5_raw = _clean_hex(self._draft_cur_k5)
            cur_k5 = (
                _validate_hex_exact(cur_k5_raw, 16, tr("Текущий ключ K_5 защёлки", "Current ELV K_5 key"))
                if cur_k5_raw
                else None
            )
            vir_k5_raw = _clean_hex(self._draft_virgin_k5)
            vir_k5 = (
                _validate_hex_exact(vir_k5_raw, 16, tr("Транспортный ключ Virgin K_5", "Virgin transport K_5"))
                if vir_k5_raw
                else None
            )
        except ValueError as exc:
            QMessageBox.warning(self, tr("Проверьте ключи", "Check Key Fields"), str(exc))
            return

        if not self._check_gateway_cur_k5_available(cur_k5):
            return
        if not ensure_ready(self.conn, self):
            return

        uses_bridge = bool(self._via_gateway and self._gateway_bridge and cur_k5 is None)
        vir_disp = html.escape(vir_k5) if vir_k5 else tr("сохранить текущий K_5", "keep current K_5")
        dlg = ElvConfirmWriteDialog(
            title=tr("Сброс ELV в Virgin (Mode 2 → Mode 1)", "Virginize ELV (Mode 2 → Mode 1)"),
            subtitle=tr(
                "Сброс по CAN (2E 02E2): VIN станет '---', PowerClass = 0x00, Mode = 1, IDac = 0x00.",
                "Factory reset over CAN (2E 02E2): VIN becomes '---', PowerClass = 0x00, Mode = 1, IDac = 0x00.",
            ),
            summary_html=tr(
                f"<b>Транспортный ключ Virgin K_5:</b> <code>{vir_disp}</code>",
                f"<b>Virgin transport K_5:</b> <code>{vir_disp}</code>",
            ),
            action_label=tr("Сбросить в Virgin", "Virginize ELV"),
            via_gateway=self._via_gateway,
            uses_bridge=uses_bridge,
            is_02e2=True,
            danger=True,
            parent=self,
        )
        if not run_dialog(dlg) or self.runner.is_busy:
            return

        port, iface = self.conn.port, self.conn.interface
        via_gw, gw_br, gw_ch = self._via_gateway, self._gateway_bridge, self._gateway_channel
        s_dir = self._create_session_dir("elv_virginize", dumps=False)
        if s_dir is None:
            return
        gen = self._session_gen

        def _task(rep: Any) -> dict[str, Any]:
            res = can_elv_virginize(
                port,
                current_k5=cur_k5,
                virgin_k5=vir_k5,
                backup_dir=s_dir,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                reporter=rep,
            )
            res["session_dir"] = str(s_dir)
            return res

        def _done(res: dict[str, Any]) -> None:
            if not _qt_valid(self) or not self._is_open or self._session_gen != gen:
                return
            if isinstance(res.get("post_passport"), dict):
                self._passport = dict(res["post_passport"])
            if isinstance(res.get("post_status"), dict):
                self._status = dict(res["post_status"])
            if isinstance(res.get("verify_02f9"), dict):
                self._verify_02f9 = dict(res["verify_02f9"])

            if res.get("ok"):
                if res.get("virgin_k5_hex"):
                    self._draft_cur_k5 = str(res["virgin_k5_hex"]).upper()
                self._refresh_all()
                self.changed.emit()
                self.note.emit(tr("ELV сброшена в состояние новой (Virgin, Mode 1).", "ELV reset to Virgin state (Mode 1)."))
            else:
                if (self._verify_02f9 or {}).get("match") and res.get("virgin_k5_hex"):
                    self._draft_cur_k5 = str(res["virgin_k5_hex"]).upper()
                self._refresh_all()
                self.changed.emit()
                mode_after = elv_mode_label(self._status.get("mode"))
                msg = tr(
                    f"Команда сброса Virgin выполнена, но проверка после записи не подтвердила Mode 1.\n"
                    f"Текущий режим: {mode_after}.",
                    f"Virgin reset command completed, but post-write verification did not confirm Mode 1.\n"
                    f"Current mode: {mode_after}.",
                )
                self.note.emit(msg.replace("\n", " "))
                QMessageBox.warning(self, tr("Проверка Virgin не пройдена", "Virgin Verification Failed"), msg)

        self.runner.run_task(
            tr("Сброс ELV в Virgin (2E 02E2)", "Virginize ELV (2E 02E2)"),
            _task,
            on_success=_done,
        )

    def action_offline_virginize(self) -> None:
        if self._dflash_bytes is None:
            return
        self._sync_drafts()
        try:
            vir_k5_raw = _clean_hex(self._draft_virgin_k5)
            vir_k5 = (
                _validate_hex_exact(vir_k5_raw, 16, tr("Транспортный ключ Virgin K_5", "Virgin transport K_5"))
                if vir_k5_raw
                else None
            )
            rebuilt = elv_virginize_dflash(self._dflash_bytes, virgin_k5=vir_k5)
        except Exception as exc:
            QMessageBox.warning(self, tr("Ошибка сборки Virgin DFLASH", "Virgin DFLASH Error"), str(exc))
            return

        suffix = "64k" if len(rebuilt) == ELV_DFLASH_RAW64K_SIZE else "32k"
        out, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить Virgin DFLASH ELV", "Save Virgin ELV DFLASH"),
            f"elv_virgin_{suffix}.bin",
            "Binary (*.bin)",
        )
        if not out:
            return
        try:
            Path(out).write_bytes(rebuilt)
        except OSError as exc:
            QMessageBox.warning(
                self,
                tr("Ошибка сохранения файла", "File Save Error"),
                tr(f"Не удалось сохранить файл:\n{exc}", f"Could not save file:\n{exc}"),
            )
            return
        self.note.emit(tr(f"Virgin DFLASH сохранён: {out}", f"Virgin DFLASH saved: {out}"))

    def action_can_reset_idac(self) -> None:
        if self.runner.is_busy:
            return
        self._sync_drafts()
        try:
            cur_k5_raw = _clean_hex(self._draft_cur_k5)
            cur_k5 = (
                _validate_hex_exact(cur_k5_raw, 16, tr("Текущий ключ K_5 защёлки", "Current ELV K_5 key"))
                if cur_k5_raw
                else None
            )
        except ValueError as exc:
            QMessageBox.warning(self, tr("Проверьте ключ K_5", "Check K_5 Key"), str(exc))
            return

        if not self._check_gateway_cur_k5_available(cur_k5):
            return
        if not ensure_ready(self.conn, self):
            return

        uses_bridge = bool(self._via_gateway and self._gateway_bridge and cur_k5 is None)
        dlg = ElvConfirmWriteDialog(
            title=tr("Отвязать ELV от приборной панели (2E 02E1)", "Unlink ELV from Cluster (2E 02E1)"),
            subtitle=tr(
                "Сбросит статус обучения приборки (0xAA → 0x00), не меняя VIN, ключ K_5 и PowerClass.",
                "Resets cluster learning status (0xAA → 0x00) without modifying VIN, K_5, or PowerClass.",
            ),
            summary_html=tr(
                "Отправляет <code>22 02E0</code> → <code>2E 02E1 [CRC16] 04 80</code> в режиме Adapted (Mode 2).",
                "Sends <code>22 02E0</code> → <code>2E 02E1 [CRC16] 04 80</code> in Adapted mode (Mode 2).",
            ),
            action_label=tr("Сбросить привязку приборки", "Reset cluster link"),
            via_gateway=self._via_gateway,
            uses_bridge=uses_bridge,
            is_02e2=False,
            parent=self,
        )
        if not run_dialog(dlg) or self.runner.is_busy:
            return

        port, iface = self.conn.port, self.conn.interface
        via_gw, gw_br, gw_ch = self._via_gateway, self._gateway_bridge, self._gateway_channel
        s_dir = self._create_session_dir("elv_reset_idac", dumps=False)
        if s_dir is None:
            return
        gen = self._session_gen

        def _task(rep: Any) -> dict[str, Any]:
            res = can_elv_reset_idac(
                port,
                current_k5=cur_k5,
                backup_dir=s_dir,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                reporter=rep,
            )
            res["session_dir"] = str(s_dir)
            return res

        def _done(res: dict[str, Any]) -> None:
            if not _qt_valid(self) or not self._is_open or self._session_gen != gen:
                return
            if isinstance(res.get("post_passport"), dict):
                self._passport = dict(res["post_passport"])
            if isinstance(res.get("post_status"), dict):
                self._status = dict(res["post_status"])
            self._refresh_all()
            self.changed.emit()

            if res.get("ok"):
                self.note.emit(tr("Привязка приборки (IDac) сброшена в автообучение.", "Cluster link (IDac) reset to auto-learn."))
            else:
                msg = tr(
                    "Команда 2E 02E1 выполнена, но флаг привязки приборки (DID 0x02EE) остался активным.",
                    "2E 02E1 command completed, but the cluster-locked flag (DID 0x02EE) remained set.",
                )
                self.note.emit(msg)
                QMessageBox.warning(self, tr("Проверка сброса IDac не пройдена", "IDac Reset Verification Failed"), msg)

        self.runner.run_task(
            tr("Сброс привязки приборки ELV (2E 02E1)", "Reset ELV Cluster Link (2E 02E1)"),
            _task,
            on_success=_done,
        )

    def action_check_bootloader(self, enter_programming: bool = False) -> None:
        if self.runner.is_busy:
            return
        self._sync_drafts()

        if enter_programming and self._via_gateway and not self._gateway_bridge:
            QMessageBox.warning(
                self,
                tr("Тест загрузчика недоступен", "Bootloader Test Unavailable"),
                self._bridge_blocked_tip(),
            )
            return

        cur_k5: str | None = self.current_k5_hex or None
        if cur_k5 is None:
            cur_k5_raw = _clean_hex(self._draft_cur_k5)
            if cur_k5_raw:
                try:
                    cur_k5 = _validate_hex_exact(cur_k5_raw, 16, tr("Текущий ключ K_5 защёлки", "Current ELV K_5 key"))
                except ValueError as exc:
                    QMessageBox.warning(self, tr("Проверьте ключ K_5", "Check K_5 Key"), str(exc))
                    return

        if not ensure_ready(self.conn, self):
            return

        if enter_programming:
            ans = QMessageBox.question(
                self,
                tr("Тест входа в загрузчик (FBL)", "Test Bootloader Entry (FBL)"),
                tr(
                    "Программа переведёт защёлку ELV в сессию программирования (10 02), "
                    "проверит разблокировку SecurityAccess (27 11/12) и перезапустит блок обратно в рабочий режим (11 02).\n\n"
                    "Продолжить?",
                    "ContiTool will switch the ELV into Programming Session (10 02), "
                    "verify bootloader SecurityAccess (27 11/12), and reset the ECU back to normal mode (11 02).\n\n"
                    "Continue?",
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if ans != QMessageBox.StandardButton.Yes or self.runner.is_busy:
                return

        port, iface = self.conn.port, self.conn.interface
        via_gw, gw_br, gw_ch = self._via_gateway, self._gateway_bridge, self._gateway_channel
        b34 = (self._dflash_parsed or {}).get("block34") or {}
        b04 = (self._dflash_parsed or {}).get("block04") or {}
        pc = b34.get("power_class")
        idac = b04.get("idac_hex") or None
        gen = self._session_gen

        def _done(res: dict[str, Any]) -> None:
            if not _qt_valid(self) or not self._is_open or self._session_gen != gen:
                return
            self._bootloader_check = dict(res)
            self._refresh_all()
            self.note.emit(tr("Проверка загрузчика ELV завершена.", "ELV bootloader check completed."))

        self.runner.run_task(
            tr("Проверка загрузчика ELV", "ELV Bootloader Check"),
            lambda rep: can_elv_check_bootloader(
                port,
                current_k5=cur_k5,
                power_class=pc,
                idac=idac,
                enter_programming=enter_programming,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                reporter=rep,
            ),
            on_success=_done,
        )

    def action_clear_dtc(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        via_gw, gw_br, gw_ch = self._via_gateway, self._gateway_bridge, self._gateway_channel
        gen = self._session_gen

        def _done(res: dict[str, Any]) -> None:
            if not _qt_valid(self) or not self._is_open or self._session_gen != gen:
                return
            self._dtcs = list(res.get("dtcs") or [])
            self._refresh_all()
            self.note.emit(tr("Ошибки 2B ELV очищены.", "2B ELV fault codes cleared."))

        self.runner.run_task(
            tr("Очистка ошибок ELV", "Clear ELV DTCs"),
            lambda rep: can_elv_clear_dtc(
                port,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                reporter=rep,
            ),
            on_success=_done,
        )
