"""Working screen for Continental VAG FPK_E (Kombi, RH850/D1L) instrument clusters."""

from __future__ import annotations

from collections.abc import Callable
import contextlib
import json
import os
from pathlib import Path
import secrets as _py_secrets
import shutil
from typing import Any

from PySide6.QtCore import QRectF, QSize, Qt, QTimer, Signal
from shiboken6 import isValid as _qt_valid
from PySide6.QtGui import QColor, QGuiApplication, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractButton,
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
    QScrollArea,
    QSizePolicy,
    QSlider,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from contitool.can.fpke import (
    FPKE_CAN_PRESETS,
    FPKE_MFL_BUTTONS,
    FPKE_NATIVE_INTERFACES,
    can_fpke_full_read,
    can_fpke_read_region,
    can_fpke_run_level8_action,
    can_fpke_write_dflash,
    close_active_fpke_link,
    fpke_coil_poll_transponder,
    fpke_extract_live_s0_s1_from_coil,
    fpke_finish_coil_key_learning,
    fpke_learn_next_key_on_coil,
    fpke_prepare_additive_coil_learning,
    fpke_run_procedure,
    fpke_start_coil_key_learning,
    get_active_fpke_link,
    open_or_reuse_fpke_link,
)
from contitool.core.fpke import (
    analyze_fpke_dflash,
    analyze_fpke_extra_area,
    apply_fpke_dflash_edits,
    compare_fpke_immo_passports,
    detect_fpke_files,
    extract_fpke_immo_passport,
    format_fpke_immo_comparison,
    format_fpke_report,
    format_fpke_transfer_plan,
    fpke_derive_k_ffb,
    fpke_s0_s1_from_slots,
    fpke_slots_from_s0_s1,
    fpke_verify_s0_s1,
    is_fpke_dflash,
    plan_fpke_a_to_b_transfer,
    summarize_fpke_dflash_changes,
    transfer_fpke_donor_to_target,
)
from contitool.gui import theme
from contitool.gui.can_session import parse_hex, parse_id
from contitool.gui.connection import CanConnection, PathLabel, ensure_ready
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
    pill,
    run_dialog,
    set_pill,
    status_readout,
    vdivider,
)
from contitool.gui.worker import OperationRunner
from contitool.gui.workspace import _remember_recent
from contitool.i18n import subscribe_lang_change, tr
from contitool.storage import new_session, unit_of_ident

FPKE_GROUPS = (
    ("analysis", ("secrets", "cp", "keys", "transfer")),
    ("can", ("read", "can_ctrl", "extra")),
)

REQUIRED_DUMPS = (
    ("dflash", "DataFlash"),
    ("extra", "Extra Area"),
)

OPTIONAL_DUMPS = (
    ("cflash", "CodeFlash"),
    ("uflash", "Uflash"),
    ("bflash", "Bflash"),
)


def _fpke_nav_title(key: str) -> str:
    return {
        "secrets": tr("Иммобилайзер", "Immobilizer"),
        "cp": tr("Защита компонентов", "Component protection"),
        "keys": tr("Ключи и пробег", "Keys & odometer"),
        "transfer": tr("Перенос из донора", "Donor transfer"),
        "read": tr("Чтение памяти", "Memory read"),
        "can_ctrl": tr("Управление по CAN", "CAN control"),
        "extra": tr("Процессор и FD11", "MCU & FD11 access"),
    }[key]


def _human_protection_mode(raw_mode: str) -> str:
    if raw_mode == "Command Protection":
        return tr("Защита команд", "Command protection")
    if raw_mode == "ID Code Protection":
        return tr("Защита по ID-коду", "ID code protection")
    return raw_mode or "—"


class _FpkeNavRow(QWidget):
    """Function name on the left with quiet semantic status text on the right."""

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


class FpkeScreen(QWidget):
    """Dedicated workspace for Continental FPK_E instrument clusters: CP/IKA & immo data, vehicle keys, MCU config, CAN read."""

    changed = Signal()
    close_requested = Signal()
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
        self.is_open = False
        self.source = ""  # "can" or "disk"
        self.via_gateway: bool = False
        self.gateway_bridge: bool = False
        self.gateway_channel: int = 0
        self.folder: Path | None = None
        self.files: dict[str, Path] = {}
        self.ident_items: list[dict[str, str]] = []
        self.dflash_info: dict[str, Any] | None = None
        self.extra_info: dict[str, Any] | None = None
        self.extra_raw: bytes | None = None
        self.idauth_info: dict[str, Any] | None = None
        self._key = "secrets"

        self._opt_stream = False
        self._opt_uflash = False
        self._opt_bflash = False
        self._opt_cflash = False
        self._wake_seconds: float = 4.0
        self._can_status_msg = ""
        self._can_status_tone = "muted"
        self._last_dtcs: list[dict[str, Any]] | None = None
        self._active_can_panel: _FpkeCanControlPanel | None = None

        self._orig_dflash_path: Path | None = None
        self._orig_dflash_bytes: bytes | None = None
        self._working_dflash_path: Path | None = None
        self._working_dflash_bytes: bytes | None = None
        self._cflash_bytes: bytes | None = None
        self._page_commit_fn: Callable[[bool], bool] | None = None

        self._donor_path: Path | None = None
        self._donor_dflash: bytes | None = None
        self._donor_cflash: bytes | None = None
        self._donor_passport: dict[str, Any] | None = None
        self._xfer_immo = True
        self._xfer_keys = True
        self._xfer_odo = True
        self._xfer_cp = False

        # Backward-compatible aliases for tests & external callers
        self._recipient_path: Path | None = None
        self._recipient_dflash: bytes | None = None
        self._recipient_cflash: bytes | None = None
        self._swap_ab: bool = False
        self._cached_s0_hex: str = ""
        self._cached_s1_hex: str = ""

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

        self.write_bar = self._build_write_bar()
        outer.addWidget(self.write_bar)

        conn.changed.connect(self._on_conn_or_busy)
        runner.busy_changed.connect(self._on_busy_changed)
        self._unsub = subscribe_lang_change(lambda _l: self.refresh())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.refresh()

    # ────────────────────────────── Public State API ──────────────────────────────

    @property
    def part_number(self) -> str:
        vals = {item.get("did", ""): item.get("value", "").strip() for item in self.ident_items}
        if vals.get("F187"):
            return vals["F187"]
        meta = (self.dflash_info or {}).get("metadata") or {}
        if meta.get("part_number"):
            return str(meta["part_number"])
        if vals.get("F191"):
            return vals["F191"]
        return "83A920700E"

    def _memory_blocker(self) -> str | None:
        """What stops level-8 memory work here: `"adapter"`, `"gateway"` or None.

        Direct CAN needs a native adapter. Through a gateway the selected adapter must carry the J533 bridge (native,
        or a VAS 6154 / VNCI: the gateway then sends the level-8 stream for it), and the scan must have found the
        gateway able to run it."""
        usable = (*FPKE_NATIVE_INTERFACES, "dpdu") if self.via_gateway else FPKE_NATIVE_INTERFACES
        if (self.conn.interface or "slcan") not in usable:
            return "adapter"
        if self.via_gateway and not self.gateway_bridge:
            return "gateway"
        return None

    def _write_blocked(self) -> bool:
        """Tell the user why a DataFlash write cannot run on this connection; True when it cannot."""
        blocker = self._memory_blocker()
        iface = self.conn.interface or "slcan"
        if blocker == "adapter":
            QMessageBox.warning(
                self,
                tr("Неподдерживаемый адаптер", "Unsupported adapter"),
                tr(
                    f"Выбран адаптер «{iface}». Для записи приборной панели FPK через шлюз J533 нужен адаптер с "
                    "произвольным raw CAN (CANable / SLCAN / candleLight или VAS 6154 / VNCI).",
                    f"Adapter “{iface}” is selected. Writing to an FPK cluster through the J533 gateway requires an "
                    "adapter with arbitrary raw CAN (CANable / SLCAN / candleLight, or a VAS 6154 / VNCI).",
                )
                if self.via_gateway
                else tr(
                    f"Выбран адаптер «{iface}». Для записи приборной панели FPK требуется нативный CAN-адаптер (CANable / SLCAN / candleLight).",
                    f"Adapter “{iface}” is selected. Writing to an FPK cluster requires a native CAN adapter (CANable / SLCAN / candleLight).",
                ),
            )
        elif blocker == "gateway":
            QMessageBox.warning(
                self,
                tr("RAM-мост недоступен", "RAM bridge unavailable"),
                tr(
                    "Запись DataFlash приборной панели через шлюз требует шлюз Continental 3Q0 907 530 с поддержкой "
                    "прозрачного RAM-моста, либо прямое подключение к CAN приборной панели (T18).",
                    "Writing cluster DataFlash through a gateway requires a Continental 3Q0 907 530 gateway with "
                    "transparent RAM-bridging, or a direct connection to the cluster CAN bus (T18).",
                ),
            )
        return blocker is not None

    @property
    def is_dflash_modified(self) -> bool:
        return (
            self._orig_dflash_bytes is not None
            and self._working_dflash_bytes is not None
            and self._working_dflash_bytes != self._orig_dflash_bytes
        )

    def open_from_ident(self, ident: dict[str, Any]) -> None:
        self.is_open = True
        self.source = "can"
        self.via_gateway = bool(ident.get("via_gateway", False))
        self.gateway_bridge = bool(
            ident.get("gateway_bridge", ident.get("bridge_available", False))
        )
        self.gateway_channel = int(ident.get("gateway_channel") or 0)
        self.ident_items = list(ident.get("ident") or [])
        self._key = "read"
        self.select("read")
        self.refresh()
        self.changed.emit()

    def open_from_files(
        self,
        detected: dict[str, Path],
        *,
        folder: Path | None = None,
        source: str = "disk",
        via_gateway: bool | None = None,
        gateway_bridge: bool | None = None,
        gateway_channel: int | None = None,
    ) -> None:
        self.is_open = True
        self.source = source
        if via_gateway is not None:
            self.via_gateway = bool(via_gateway)
        elif source != "can":
            self.via_gateway = False
        if gateway_bridge is not None:
            self.gateway_bridge = bool(gateway_bridge)
        elif source != "can":
            self.gateway_bridge = False
        if gateway_channel is not None:
            self.gateway_channel = int(gateway_channel)
        elif source != "can":
            self.gateway_channel = 0
        self.folder = folder or next((p.parent for p in detected.values()), None)
        self.files = dict(detected)
        self.dflash_info = None
        self.extra_info = None
        self.extra_raw = None
        self._orig_dflash_path = None
        self._orig_dflash_bytes = None
        self._working_dflash_path = None
        self._working_dflash_bytes = None
        self._cflash_bytes = None
        if source != "can":
            self.ident_items = []
            self.idauth_info = None
        if self.folder is not None and self.folder.is_dir():
            _remember_recent(self.folder)

        if "cflash" in detected and detected["cflash"].is_file():
            try:
                self._cflash_bytes = detected["cflash"].read_bytes()
            except OSError:
                self._cflash_bytes = None

        if "report" in detected and detected["report"].is_file():
            try:
                rep = json.loads(detected["report"].read_text(encoding="utf-8"))
                if not self.ident_items and isinstance(rep.get("ident"), list):
                    self.ident_items = list(rep["ident"])
                if isinstance(rep.get("idauth"), dict):
                    self.idauth_info = rep["idauth"]
                if not self.dflash_info and isinstance(rep.get("secrets"), dict):
                    self.dflash_info = rep["secrets"]
                if not self.extra_info and isinstance(rep.get("extra_analysis"), dict):
                    self.extra_info = rep["extra_analysis"]
                if source == "can" and via_gateway is None and "via_gateway" in rep:
                    self.via_gateway = bool(rep.get("via_gateway"))
                if source == "can" and gateway_bridge is None and "gateway_bridged" in rep:
                    self.gateway_bridge = bool(rep.get("gateway_bridged"))
            except Exception:
                pass

        if "dflash" in detected and detected["dflash"].is_file():
            try:
                df_raw = detected["dflash"].read_bytes()
                self._orig_dflash_path = detected["dflash"]
                self._orig_dflash_bytes = df_raw
                self._working_dflash_path = detected["dflash"]
                self._working_dflash_bytes = df_raw
                edit_cand = detected["dflash"].parent / "ContiTool_edited" / detected["dflash"].name
                if edit_cand.is_file():
                    with contextlib.suppress(Exception):
                        edit_raw = edit_cand.read_bytes()
                        if is_fpke_dflash(edit_raw) and edit_raw != df_raw:
                            self._working_dflash_path = edit_cand
                            self._working_dflash_bytes = edit_raw
                            self.files["dflash"] = edit_cand
                self.dflash_info = analyze_fpke_dflash(self._working_dflash_bytes, self._cflash_bytes)
            except Exception as exc:
                self.note.emit(tr(f"Ошибка разбора DataFlash: {exc}", f"DataFlash parse error: {exc}"))

        if "extra" in detected and detected["extra"].is_file():
            try:
                ex_raw = detected["extra"].read_bytes()
                self.extra_raw = ex_raw
                self.extra_info = analyze_fpke_extra_area(ex_raw)
            except Exception as exc:
                self.note.emit(tr(f"Ошибка разбора Extra Area: {exc}", f"Extra Area parse error: {exc}"))

        if self.dflash_info is not None:
            self._key = "secrets"
            self.select("secrets")
        elif self.extra_info is not None:
            self._key = "extra"
            self.select("extra")
        else:
            self._key = "read"
            self.select("read")

        self.refresh()
        self.changed.emit()

    def close_kombi(self) -> None:
        close_active_fpke_link()
        self.is_open = False
        self.source = ""
        self.via_gateway = False
        self.gateway_bridge = False
        self.gateway_channel = 0
        self.folder = None
        self.files.clear()
        self.ident_items.clear()
        self.dflash_info = None
        self.extra_info = None
        self.extra_raw = None
        self.idauth_info = None
        self._orig_dflash_path = None
        self._orig_dflash_bytes = None
        self._working_dflash_path = None
        self._working_dflash_bytes = None
        self._cflash_bytes = None
        self._donor_path = None
        self._donor_dflash = None
        self._donor_cflash = None
        self._donor_passport = None
        self._can_status_msg = ""
        self._can_status_tone = "muted"
        self._last_dtcs = None
        self._active_can_panel = None
        self._recipient_path = None
        self._recipient_dflash = None
        self._recipient_cflash = None
        self._swap_ab = False
        self.changed.emit()

    def _commit_dflash_bytes(self, new_df: bytes, log_msg: str) -> None:
        """Save modified DataFlash into a non-destructive working copy (`ContiTool_edited/Dflash.bin`) and refresh UI."""
        self._working_dflash_bytes = new_df
        if self.folder is not None and self.folder.is_dir():
            edit_dir = self.folder / "ContiTool_edited"
            edit_dir.mkdir(parents=True, exist_ok=True)
            out_name = self._orig_dflash_path.name if self._orig_dflash_path else "Dflash.bin"
            work_path = edit_dir / out_name
            work_path.write_bytes(new_df)
            self._working_dflash_path = work_path
            self.files["dflash"] = work_path
        self.dflash_info = analyze_fpke_dflash(new_df, self._cflash_bytes)
        self.refresh()
        self.changed.emit()
        if log_msg:
            self.note.emit(log_msg)

    def revert_dflash_edits(self) -> None:
        """Restore the original unmodified DataFlash dump."""
        if self._orig_dflash_bytes is None:
            return
        old_work = self._working_dflash_path
        self._working_dflash_bytes = self._orig_dflash_bytes
        if self._orig_dflash_path is not None:
            self._working_dflash_path = self._orig_dflash_path
            self.files["dflash"] = self._orig_dflash_path
            if old_work is not None and old_work != self._orig_dflash_path and old_work.parent.name == "ContiTool_edited":
                with contextlib.suppress(OSError):
                    old_work.unlink()
        self.dflash_info = analyze_fpke_dflash(self._orig_dflash_bytes, self._cflash_bytes)
        self.refresh()
        self.changed.emit()
        self.note.emit(tr("Откат выполнен: возвращён исходный дамп DataFlash.", "Reverted to original DataFlash dump."))

    def save_edited_dflash_as(self) -> None:
        """Export the current working DataFlash dump to a user-chosen `.bin` file."""
        df_bytes, _ = self._own_dflash_and_cflash()
        if df_bytes is None:
            return
        default_dir = self.folder or Path.home()
        dest, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить дамп DataFlash (64 КБ)", "Save DataFlash dump (64 KB)"),
            str(default_dir / f"{self.part_number}_Dflash_edited.bin"),
            "DataFlash 64 KB (*.bin);;All files (*)",
        )
        if not dest:
            return
        out_path = Path(dest)
        out_path.write_bytes(df_bytes)
        self.note.emit(tr(f"Дамп DataFlash сохранён: {out_path}", f"DataFlash dump saved: {out_path}"))

    def _record_can_status(self, msg: str, tone: str) -> None:
        self._can_status_msg = msg
        self._can_status_tone = tone
        if self._active_can_panel is not None and _qt_valid(self._active_can_panel):
            self._active_can_panel.apply_external_status(msg, tone)

    def _record_can_dtcs(self, dtcs: list[dict[str, Any]]) -> None:
        self._last_dtcs = list(dtcs)
        if self._active_can_panel is not None and _qt_valid(self._active_can_panel):
            self._active_can_panel.apply_external_dtcs(self._last_dtcs)

    def open_can_control_dialog(self) -> None:
        dlg = FpkeCanDialog(
            self.conn,
            self.runner,
            part_number=self.part_number,
            initial_msg=self._can_status_msg,
            initial_tone=self._can_status_tone,
            initial_dtcs=self._last_dtcs or [],
            status_sink=self._record_can_status,
            dtcs_sink=self._record_can_dtcs,
            via_gateway=self.via_gateway,
            gateway_bridge=self.gateway_bridge,
            gateway_channel=self.gateway_channel,
            parent=self,
        )
        dlg.note.connect(self.note.emit)
        run_dialog(dlg)
        if _qt_valid(self) and self.is_open:
            self._on_conn_or_busy()

    def export_backup(self) -> None:
        if not self.files:
            return
        dest = QFileDialog.getExistingDirectory(
            self,
            tr("Папка для экспорта бэкапа", "Folder to export backup"),
            str(self.folder.parent if self.folder else Path.home()),
        )
        if not dest:
            return
        target_dir = Path(dest)
        copied = 0
        for kind in ("dflash", "extra", "cflash", "uflash", "bflash", "report"):
            src = self._orig_dflash_path if (kind == "dflash" and self._orig_dflash_path) else self.files.get(kind)
            if src is not None and src.is_file():
                shutil.copy2(src, target_dir / src.name)
                copied += 1
        if copied:
            self.note.emit(
                tr(f"Экспортировано файлов: {copied} → {target_dir}", f"Exported {copied} file(s) → {target_dir}")
            )

    def _own_dflash_and_cflash(self) -> tuple[bytes | None, bytes | None]:
        if self._working_dflash_bytes is not None:
            return self._working_dflash_bytes, self._cflash_bytes
        df_path = self.files.get("dflash")
        if df_path is None or not df_path.is_file():
            return None, None
        cf_path = self.files.get("cflash")
        cf_bytes = cf_path.read_bytes() if (cf_path is not None and cf_path.is_file()) else None
        return df_path.read_bytes(), cf_bytes

    def export_immo_passport(self) -> None:
        df_bytes, cf_bytes = self._own_dflash_and_cflash()
        if df_bytes is None:
            return
        default_dir = self.folder or Path.home()
        dest, _ = QFileDialog.getSaveFileName(
            self,
            tr("Экспорт Immo-паспорта (JSON)", "Export Immo passport (JSON)"),
            str(default_dir / f"{self.part_number}_immo_passport.json"),
            "JSON (*.json)",
        )
        if not dest:
            return
        passport = extract_fpke_immo_passport(df_bytes, cf_bytes)
        out_path = Path(dest)
        out_path.write_text(json.dumps(passport, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self.note.emit(tr(f"Immo-паспорт сохранён: {out_path}", f"Immo passport saved: {out_path}"))

    def compare_immo_with_file(self, other_path: Path | None = None) -> None:
        df_a, cf_a = self._own_dflash_and_cflash()
        if df_a is None:
            return
        if other_path is None and self._donor_passport is not None:
            passport_a = extract_fpke_immo_passport(df_a, cf_a)
            cmp_res = compare_fpke_immo_passports(self._donor_passport, passport_a)
            txt = format_fpke_immo_comparison(cmp_res, self._donor_passport, passport_a)
            run_dialog(
                TextResultDialog(
                    self,
                    tr("Сверка паспорта иммобилайзера", "Immobilizer passport comparison"),
                    txt,
                    self.part_number,
                )
            )
            return
        if other_path is None:
            picked, _ = QFileDialog.getOpenFileName(
                self,
                tr("Выберите второй дамп DataFlash или Immo-паспорт JSON для сверки", "Select second DataFlash dump or Immo passport JSON"),
                str(self.folder.parent if self.folder else Path.home()),
                "DataFlash / Immo JSON (*.bin *.json);;All files (*)",
            )
            if not picked:
                return
            other_path = Path(picked)
        try:
            passport_a = extract_fpke_immo_passport(df_a, cf_a)
            if other_path.suffix.lower() == ".json":
                passport_b = json.loads(other_path.read_text(encoding="utf-8"))
            else:
                raw_b = other_path.read_bytes()
                sib_cf = detect_fpke_files([other_path.parent]).get("cflash")
                cf_b = sib_cf.read_bytes() if (sib_cf is not None and sib_cf.is_file()) else None
                passport_b = extract_fpke_immo_passport(raw_b, cf_b)
            cmp_res = compare_fpke_immo_passports(passport_a, passport_b)
            txt = format_fpke_immo_comparison(cmp_res, passport_a, passport_b)
        except Exception as exc:
            QMessageBox.warning(self, tr("Ошибка сверки", "Comparison error"), str(exc))
            return
        run_dialog(
            TextResultDialog(
                self,
                tr("Сверка паспорта иммобилайзера", "Immobilizer passport comparison"),
                txt,
                self.part_number,
            )
        )

    def set_donor_source(self, path: Path) -> None:
        """Load a donor cluster source (either a 64 KB `Dflash.bin` or an exported `immo_passport.json`)."""
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or "immo" not in data:
                raise ValueError(
                    tr(
                        f"Файл «{path.name}» не является паспортом иммобилайзера ContiTool JSON.",
                        f"File “{path.name}” is not a ContiTool Immo passport JSON.",
                    )
                )
            self._donor_path = path
            self._donor_dflash = None
            self._donor_cflash = None
            self._donor_passport = data
        else:
            raw = path.read_bytes()
            if not is_fpke_dflash(raw):
                raise ValueError(
                    tr(
                        f"Файл «{path.name}» не является корректным 64 КБ дампом DataFlash FPK_E.",
                        f"File “{path.name}” is not a valid 64 KB FPK_E DataFlash dump.",
                    )
                )
            sib = detect_fpke_files([path.parent])
            cf_path = sib.get("cflash")
            cf_bytes = cf_path.read_bytes() if (cf_path is not None and cf_path.is_file()) else None
            self._donor_path = path
            self._donor_dflash = raw
            self._donor_cflash = cf_bytes
            self._donor_passport = extract_fpke_immo_passport(raw, cf_bytes)
            self._recipient_path = path
            self._recipient_dflash = raw
            self._recipient_cflash = cf_bytes
        self._swap_ab = False
        self._refresh_nav()
        self._render_page()

    def set_recipient_dflash(self, path: Path) -> None:
        """Backward-compatible helper that loads a partner 64 KB DataFlash dump."""
        self.set_donor_source(path)

    def pick_donor_source(self) -> None:
        picked, _ = QFileDialog.getOpenFileName(
            self,
            tr(
                "Выберите дамп DataFlash (64 КБ) или Immo-паспорт (.json) старой панели приборов (Донора)",
                "Select 64 KB DataFlash dump or Immo passport (.json) of the old donor cluster",
            ),
            str(self.folder.parent if self.folder else Path.home()),
            "DataFlash / Immo JSON (*.bin *.json);;All files (*)",
        )
        if not picked:
            return
        try:
            self.set_donor_source(Path(picked))
            self.note.emit(tr(f"Загружен донор: {picked}", f"Loaded donor source: {picked}"))
        except Exception as exc:
            QMessageBox.warning(self, tr("Неверный файл", "Invalid file"), str(exc))

    def pick_recipient_dflash(self) -> None:
        self.pick_donor_source()

    def swap_transfer_roles(self) -> None:
        if self._donor_dflash is None:
            return
        self._swap_ab = not self._swap_ab
        self._render_page()

    def _current_transfer_plan(self) -> dict[str, Any] | None:
        df_open, cf_open = self._own_dflash_and_cflash()
        if df_open is None or self._donor_dflash is None:
            return None
        if self._swap_ab:
            return plan_fpke_a_to_b_transfer(
                df_open,
                self._donor_dflash,
                donor_cflash=cf_open,
                recipient_cflash=self._donor_cflash,
            )
        return plan_fpke_a_to_b_transfer(
            self._donor_dflash,
            df_open,
            donor_cflash=self._donor_cflash,
            recipient_cflash=cf_open,
        )

    def apply_donor_transfer_to_current(self) -> bool:
        """Apply checked donor transfer categories into the currently open DataFlash working copy."""
        df_open, cf_open = self._own_dflash_and_cflash()
        if df_open is None or self._donor_passport is None:
            return False
        if not any((self._xfer_immo, self._xfer_keys, self._xfer_odo, self._xfer_cp)):
            QMessageBox.information(
                self,
                tr("Ничего не выбрано", "Nothing selected"),
                tr("Отметьте хотя бы один блок данных для переноса.", "Select at least one data group to transfer."),
            )
            return False
        try:
            new_df, summary = transfer_fpke_donor_to_target(
                self._donor_passport,
                df_open,
                copy_immo=self._xfer_immo,
                copy_keys=self._xfer_keys,
                copy_odometer=self._xfer_odo,
                copy_cp=self._xfer_cp,
                target_cflash=cf_open,
            )
        except Exception as exc:
            QMessageBox.warning(self, tr("Ошибка переноса", "Transfer error"), str(exc))
            return False

        parts: list[str] = []
        if summary["copied_sections"]["immo"]:
            parts.append(f"Immo (VIN {summary.get('vin') or '—'}, PC {summary.get('power_class_hex') or '—'})")
        if summary["copied_sections"]["keys"]:
            parts.append(tr(f"ключи ({summary.get('learned_keys', 0)})", f"keys ({summary.get('learned_keys', 0)})"))
        if summary["copied_sections"]["odometer"]:
            parts.append(tr(f"пробег ({summary.get('odometer_km')} км)", f"odometer ({summary.get('odometer_km')} km)"))
        if summary["copied_sections"]["cp"]:
            parts.append("CP (IKA/GFA)")
        msg = tr(
            f"Перенос из донора выполнен: {', '.join(parts)}",
            f"Donor transfer applied: {', '.join(parts)}",
        )
        self._commit_dflash_bytes(new_df, msg)
        return True

    def apply_and_write_donor_transfer(self) -> None:
        """Transfer selected donor fields into the working dump and immediately write them to the cluster over CAN."""
        if self.apply_donor_transfer_to_current():
            self.write_dflash_to_ecu()

    def show_transfer_plan_dialog(self) -> None:
        plan = self._current_transfer_plan()
        if plan is None:
            return
        run_dialog(
            TextResultDialog(
                self,
                tr("План переноса данных", "Transfer plan report"),
                format_fpke_transfer_plan(plan),
                self.part_number,
            )
        )

    def export_transfer_plan(self) -> None:
        plan = self._current_transfer_plan()
        if plan is None:
            return
        da_pn = (plan.get("donor_a") or {}).get("part_number") or "Donor"
        rb_pn = (plan.get("recipient_b") or {}).get("part_number") or "Target"
        default_dir = self.folder or Path.home()
        dest, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить план переноса (JSON)", "Save transfer plan (JSON)"),
            str(default_dir / f"{da_pn}_to_{rb_pn}_transfer_plan.json"),
            "JSON (*.json)",
        )
        if not dest:
            return
        out_path = Path(dest)
        out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self.note.emit(tr(f"План переноса сохранён: {out_path}", f"Transfer plan saved: {out_path}"))

    def show_report(self) -> None:
        if not self.is_open:
            return
        txt = format_fpke_report(
            dflash_info=self.dflash_info,
            extra_info=self.extra_info,
            ident=self.ident_items,
            idauth_info=self.idauth_info,
        )
        run_dialog(
            TextResultDialog(
                self,
                tr("Подробный отчёт", "Full report"),
                txt,
                self.part_number,
            )
        )

    # ────────────────────────────── Layout Builders ──────────────────────────────

    def _build_write_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("WriteBar")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(24, 6, 24, 6)
        lay.setSpacing(10)
        self.lbl_write_bar = QLabel()
        self.lbl_write_bar.setObjectName("FieldLabel")
        self.lbl_write_bar.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        lay.addWidget(self.lbl_write_bar, 1)
        self.btn_revert_df = button("", "GhostBtn", slot=self.revert_dflash_edits)
        self.btn_save_df = button("", slot=self.save_edited_dflash_as)
        self.btn_write_ecu = button("", "PrimaryBtn", slot=self.write_dflash_to_ecu)
        for b in (self.btn_revert_df, self.btn_save_df, self.btn_write_ecu):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            lay.addWidget(b)
        bar.setVisible(False)
        return bar

    def _refresh_write_bar(self) -> None:
        modified = self.is_dflash_modified
        self.write_bar.setVisible(modified)
        if not modified:
            return
        busy = self.runner.is_busy
        short_desc = "DataFlash"
        tip_lines: list[str] = []
        if self._orig_dflash_bytes is not None and self._working_dflash_bytes is not None:
            with contextlib.suppress(Exception):
                chg = summarize_fpke_dflash_changes(
                    self._orig_dflash_bytes,
                    self._working_dflash_bytes,
                    self._cflash_bytes,
                )
                if chg.get("short_summary"):
                    short_desc = str(chg["short_summary"])
                tip_lines = list(chg.get("lines") or [])
        self.lbl_write_bar.setText(
            tr(
                f"Не записано в блок: {short_desc}",
                f"Pending write to ECU: {short_desc}",
            )
        )
        self.lbl_write_bar.setToolTip("\n".join(tip_lines))
        self.btn_revert_df.setText(tr("Отменить", "Discard"))
        self.btn_revert_df.setEnabled(not busy)
        self.btn_save_df.setText(tr("Сохранить дамп…", "Save dump…"))
        self.btn_save_df.setEnabled(not busy)
        self.btn_write_ecu.setText(tr("Записать в блок", "Write to ECU"))
        self.btn_write_ecu.setEnabled(not busy)

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
        self.lbl_folder = PathLabel()
        self.lbl_folder.setObjectName("Hint")
        self.lbl_folder.setFont(mono_font(12))

        head.addWidget(self.lbl_pn, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.lbl_sys, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.sep_source, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.pill_source, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addWidget(self.lbl_folder, 1, Qt.AlignmentFlag.AlignVCenter)
        head.addSpacing(8)

        self.btn_can_ctrl = button("", slot=self.open_can_control_dialog)
        self.btn_restore = button("", slot=self.restore_dflash_from_file)
        self.btn_export = button("", slot=self.export_backup)
        self.btn_report = button("", slot=self.show_report)
        self.btn_close = button("", "GhostBtn", slot=self.close_requested.emit)
        for b in (self.btn_can_ctrl, self.btn_restore, self.btn_export, self.btn_report, self.btn_close):
            b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            head.addWidget(b)
        body.addLayout(head)

        body.addWidget(divider())

        self.grid_id = QGridLayout()
        self.grid_id.setHorizontalSpacing(22)
        self.grid_id.setVerticalSpacing(2)
        body.addLayout(self.grid_id)

        self.grid_mcu_id = QGridLayout()
        self.grid_mcu_id.setContentsMargins(0, 0, 0, 0)
        self.grid_mcu_id.setHorizontalSpacing(28)
        self.grid_mcu_id.setVerticalSpacing(2)
        body.addLayout(self.grid_mcu_id)
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
        self.nav_rows: dict[str, _FpkeNavRow] = {}
        self._nav_items: dict[str, QListWidgetItem] = {}
        self._group_labels: dict[str, QLabel] = {}
        for group, keys in FPKE_GROUPS:
            head = QListWidgetItem(self.nav)
            head.setFlags(Qt.ItemFlag.NoItemFlags)
            head.setSizeHint(QSize(0, 24))
            lbl = group_label()
            lbl.setContentsMargins(12, 6, 0, 0)
            self.nav.setItemWidget(head, lbl)
            self._group_labels[group] = lbl
            for key in keys:
                item = QListWidgetItem(self.nav)
                item.setData(Qt.ItemDataRole.UserRole, key)
                item.setSizeHint(QSize(0, 30))
                nav_row = _FpkeNavRow()
                self.nav.setItemWidget(item, nav_row)
                self.nav_rows[key] = nav_row
                self._nav_items[key] = item
        self.nav.currentItemChanged.connect(self._on_nav)
        lay.addWidget(self.nav, 1)

        self.nav_dumps = QFrame()
        self.nav_dumps.setObjectName("NavDumps")
        nd_lay = QVBoxLayout(self.nav_dumps)
        nd_lay.setContentsMargins(16, 8, 16, 10)
        nd_lay.setSpacing(4)
        self.lbl_dumps_hdr = group_label()
        nd_lay.addWidget(self.lbl_dumps_hdr)
        self.dumps_list = QVBoxLayout()
        self.dumps_list.setContentsMargins(0, 1, 0, 0)
        self.dumps_list.setSpacing(3)
        nd_lay.addLayout(self.dumps_list)
        lay.addWidget(self.nav_dumps)
        return pane

    def _build_page_area(self) -> QWidget:
        self.page_area = QScrollArea()
        self.page_area.setWidgetResizable(True)
        self.page_area.setFrameShape(QFrame.Shape.NoFrame)
        self.page_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        return self.page_area

    def select(self, key: str) -> None:
        if key in self._nav_items:
            self.nav.setCurrentItem(self._nav_items[key])

    def _on_nav(self, item: QListWidgetItem | None, _prev: QListWidgetItem | None) -> None:
        key = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if key:
            self._key = key
            for k, nav_row in self.nav_rows.items():
                nav_row.set_active(k == key)
            self._render_page()

    # ────────────────────────────── Refresh & Rendering ──────────────────────────────

    @staticmethod
    def _fmt_dump_size(path: Path) -> str:
        try:
            n = path.stat().st_size
        except OSError:
            return "—"
        if n >= 1024 * 1024 and n % (512 * 1024) == 0:
            return f"{n / (1024 * 1024):.1f} MB"
        if n >= 1024:
            return f"{n // 1024} KB"
        return f"{n} B"

    @staticmethod
    def _dump_ledger_row(name: str, val: str, tone: str = "muted", tip: str = "") -> QWidget:
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

    def refresh(self) -> None:
        if not self.is_open or not _qt_valid(self):
            return
        self._refresh_identity()
        self._refresh_nav()
        self._refresh_write_bar()
        self._render_page()

    def _on_busy_changed(self, _busy: bool) -> None:
        self._on_conn_or_busy()

    def _on_conn_or_busy(self) -> None:
        if not self.is_open or not _qt_valid(self):
            return
        self._refresh_identity()
        self._refresh_nav()
        self._refresh_write_bar()
        if (
            self._key == "can_ctrl"
            and self._active_can_panel is not None
            and _qt_valid(self._active_can_panel)
        ):
            self._active_can_panel.sync_state()
            return
        self._render_page()

    def _refresh_identity(self) -> None:
        vals = {item.get("did", ""): item.get("value", "").strip() for item in self.ident_items}
        meta = (self.dflash_info or {}).get("metadata") or {}

        self.lbl_pn.setText(self.part_number)
        sys_txt = vals.get("F197") or tr("Приборная панель FPK_E", "FPK_E instrument cluster")
        self.lbl_sys.setText(sys_txt)

        is_can = self.source == "can"
        if self.via_gateway:
            self.pill_source.setText(
                tr("Через шлюз J533 (RAM-мост ch0)", "Via J533 gateway (RAM-Bridge ch0)")
                if self.gateway_bridge
                else tr("Через шлюз J533 (UDS)", "Via J533 gateway (UDS)")
            )
            set_tone(self.pill_source, "ok" if self.gateway_bridge else "info")
        else:
            self.pill_source.setText(
                tr("Считан по CAN", "Read over CAN") if is_can else tr("Открыт из файлов", "Opened from files")
            )
            set_tone(self.pill_source, "info" if is_can else "muted")
        self.lbl_folder.setVisible(bool(self.folder))
        if self.folder:
            self.lbl_folder.set_path(self.folder.name)
            self.lbl_folder.setToolTip(str(self.folder))
        else:
            self.lbl_folder.set_path("")

        self.btn_can_ctrl.setText(tr("Управление по CAN", "CAN control"))
        self.btn_can_ctrl.setToolTip(
            tr("Открыть отдельное окно управления по CAN", "Open standalone CAN control window")
        )
        self.btn_restore.setText(tr("Залить бэкап…", "Write backup…"))
        self.btn_restore.setToolTip(
            tr(
                "Записать сохранённый 64 КБ дамп DataFlash в приборную панель по CAN",
                "Write a saved 64 KB DataFlash backup dump to the cluster over CAN",
            )
        )
        self.btn_restore.setEnabled(not self.runner.is_busy)
        self.btn_export.setText(tr("Экспорт бэкапа", "Export backup"))
        self.btn_export.setToolTip(
            tr("Копирует считанные дампы в выбранную папку", "Copies the dumps to a folder you pick")
        )
        self.btn_export.setEnabled(bool(self.files))
        self.btn_report.setText(tr("Подробный отчёт", "Full report"))
        self.btn_report.setEnabled(bool(self.dflash_info or self.extra_info or self.ident_items))
        self.btn_close.setText(tr("Закрыть", "Close"))

        clear_layout(self.grid_id)
        clear_layout(self.grid_mcu_id)
        for c in range(8):
            self.grid_id.setColumnStretch(c, 0)
        for c in range(4):
            self.grid_mcu_id.setColumnStretch(c, 0)

        top_fields: list[tuple[str, str]] = []
        sw_ver = vals.get("F189") or meta.get("sw_version_eel") or ""
        hw_pn = vals.get("F191") or ""
        hw_ver = vals.get("F1A3") or ""
        vin = meta.get("vin") or vals.get("F190") or ""
        fazit = vals.get("F17C") or ""

        if sw_ver:
            top_fields.append((tr("ВЕРСИЯ ПО", "SOFTWARE"), str(sw_ver)))
        if hw_pn:
            top_fields.append((tr("ОБОРУДОВАНИЕ", "HARDWARE"), f"{hw_pn} / {hw_ver}" if hw_ver else hw_pn))
        if vin:
            top_fields.append(("VIN", str(vin)))
        if meta.get("power_class"):
            top_fields.append(("POWER CLASS", str(meta["power_class"])))
        if meta.get("odometer_km") is not None:
            km_str = f"{int(meta['odometer_km']):,}".replace(",", " ")
            top_fields.append((tr("ПРОБЕГ", "ODOMETER"), tr(f"{km_str} км", f"{km_str} km")))
        if fazit:
            top_fields.append(("FAZIT", fazit))
        if not top_fields:
            top_fields.append((tr("ВАРИАНТ ODX", "ODX VARIANT"), vals.get("F19E") or "EV_DashBoard"))

        for col, (k, v) in enumerate(top_fields):
            lbl_k = QLabel(k)
            lbl_k.setObjectName("GroupLabel")
            lbl_v = QLabel(v)
            lbl_v.setFont(mono_font(12))
            lbl_v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.grid_id.addWidget(lbl_k, 0, col)
            self.grid_id.addWidget(lbl_v, 1, col)
        self.grid_id.setColumnStretch(len(top_fields), 1)

        mcu_fields: list[tuple[str, str]] = []
        if self.extra_info:
            mcu_fields.append(("IDCODE", self.extra_info.get("idcode_spaced", "—")))
            mcu_fields.append(
                (tr("ЗАЩИТА ПРОЦЕССОРА", "MCU PROTECTION"), _human_protection_mode(self.extra_info.get("protection_mode", "")))
            )
        self.grid_mcu_id.setContentsMargins(0, 6 if (top_fields and mcu_fields) else 0, 0, 0)
        for col, (k, v) in enumerate(mcu_fields):
            lbl_k = QLabel(k)
            lbl_k.setObjectName("GroupLabel")
            lbl_v = QLabel(v)
            lbl_v.setFont(mono_font(11))
            lbl_v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.grid_mcu_id.addWidget(lbl_k, 0, col)
            self.grid_mcu_id.addWidget(lbl_v, 1, col)
        self.grid_mcu_id.setColumnStretch(len(mcu_fields), 1)

    def _refresh_nav(self) -> None:
        self._group_labels["analysis"].setText(tr("ОСНОВНОЕ", "MAIN"))
        self._group_labels["can"].setText(tr("СЕРВИС", "SERVICE"))

        for key, nav_row in self.nav_rows.items():
            nav_row.lbl_name.setText(_fpke_nav_title(key))
            nav_row.set_active(key == self._key)

        if self.dflash_info:
            immo_cfg = self.dflash_info.get("immo_config") or {}
            pc_hex = immo_cfg.get("power_class_hex")
            if immo_cfg.get("personalized"):
                set_pill(self.nav_rows["secrets"].pill, pc_hex or tr("ок", "ok"), "ok")
            else:
                set_pill(self.nav_rows["secrets"].pill, tr("чистый", "blank"), "warn")

            cp_st = self.dflash_info.get("component_protection_state") or {}
            if cp_st.get("active"):
                set_pill(self.nav_rows["cp"].pill, "SAFE CP", "err")
            elif cp_st.get("adapted") or any(it["key_id"] == "ika_cp3" for it in self.dflash_info.get("items", [])):
                set_pill(self.nav_rows["cp"].pill, tr("адаптир.", "adapted"), "ok")
            else:
                set_pill(self.nav_rows["cp"].pill, "—", "muted")

            tp = self.dflash_info.get("transponder_records") or {}
            learned = tp.get("learned_keys", 0)
            set_pill(
                self.nav_rows["keys"].pill,
                tr(f"ключей: {learned}", f"{learned} keys"),
                "ok" if learned else "muted",
            )
            set_pill(
                self.nav_rows["transfer"].pill,
                tr("донор", "donor") if self._donor_passport is not None else "",
                "info" if self._donor_passport is not None else "muted",
            )
        else:
            set_pill(self.nav_rows["secrets"].pill, "—", "muted")
            set_pill(self.nav_rows["cp"].pill, "—", "muted")
            set_pill(self.nav_rows["keys"].pill, "—", "muted")
            set_pill(self.nav_rows["transfer"].pill, "", "muted")

        has_fd11 = bool(
            self.dflash_info and any(it["key_id"].startswith("fd11_") for it in self.dflash_info.get("items", []))
        )
        if self.extra_info:
            idauth_ok = bool(self.idauth_info and self.idauth_info.get("idst_after_idcode") == "00000000")
            set_pill(
                self.nav_rows["extra"].pill,
                tr("проверен", "verified") if idauth_ok else tr("загружено", "loaded"),
                "ok",
            )
        elif has_fd11:
            set_pill(self.nav_rows["extra"].pill, "FD11", "ok")
        else:
            set_pill(self.nav_rows["extra"].pill, "—", "muted")

        blocker = self._memory_blocker() if self.conn.interface else None
        set_pill(
            self.nav_rows["read"].pill,
            {"adapter": tr("нужен SLCAN", "SLCAN needed"), "gateway": tr("нет RAM-моста", "no RAM bridge")}.get(
                blocker or "", ""
            ),
            "warn" if blocker else "muted",
        )
        active_link = get_active_fpke_link()
        kl15_on = bool(active_link and active_link.is_keepalive_running())
        set_pill(
            self.nav_rows["can_ctrl"].pill,
            tr("KL15 ВКЛ", "KL15 ON") if kl15_on else (tr("связь", "linked") if active_link else ""),
            "ok" if kl15_on else ("info" if active_link else "muted"),
        )

        self.lbl_dumps_hdr.setText(tr("ФАЙЛЫ ПАМЯТИ", "MEMORY DUMPS"))
        clear_layout(self.dumps_list)
        for kind, label in REQUIRED_DUMPS:
            p = self.files.get(kind)
            if p is not None and p.is_file():
                sz_txt = self._fmt_dump_size(p)
                if kind == "dflash" and self.is_dflash_modified:
                    sz_txt = f"{sz_txt} • {tr('изм.', 'mod.')}"
                    self.dumps_list.addWidget(self._dump_ledger_row(label, sz_txt, "info", str(p)))
                else:
                    self.dumps_list.addWidget(self._dump_ledger_row(label, sz_txt, "muted", str(p)))
            else:
                self.dumps_list.addWidget(
                    self._dump_ledger_row(label, tr("нет", "missing"), "warn", tr("Файл не загружен", "File not loaded"))
                )
        for kind, label in OPTIONAL_DUMPS:
            p = self.files.get(kind)
            if p is not None and p.is_file():
                self.dumps_list.addWidget(self._dump_ledger_row(label, self._fmt_dump_size(p), "muted", str(p)))

    def _render_page(self) -> None:
        self._active_can_panel = None
        self._page_commit_fn = None
        page = QWidget()
        page.setObjectName("PageCanvas")
        outer = QHBoxLayout(page)
        outer.setContentsMargins(24, 6, 24, 4)
        outer.setSpacing(0)

        column = QWidget()
        column.setMaximumWidth(960)
        lay = QVBoxLayout(column)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        head_row = QHBoxLayout()
        head_row.setContentsMargins(0, 0, 0, 0)
        head_row.setSpacing(8)
        title = QLabel(_fpke_nav_title(self._key))
        title.setObjectName("PageTitle")
        head_row.addWidget(title)
        head_row.addStretch(1)
        if self._key == "secrets" and self.dflash_info:
            btn_cmp = button(
                tr("Сверить с файлом…", "Compare with file…"),
                "GhostBtn",
                slot=lambda: self.compare_immo_with_file(),
            )
            btn_immo_json = button(
                tr("Экспорт паспорта JSON…", "Export passport JSON…"),
                "GhostBtn",
                slot=self.export_immo_passport,
            )
            head_row.addWidget(btn_cmp)
            head_row.addWidget(btn_immo_json)
        elif self._key == "keys" and self.dflash_info:
            btn_coil_learn = button(
                tr("Обучение через катушку…", "Learn via LF coil…"),
                "GhostBtn",
                slot=self.open_coil_key_learn_dialog,
            )
            head_row.addWidget(btn_coil_learn)
        elif self._key == "transfer" and self.dflash_info:
            btn_pick_donor = button(
                tr("Выбрать донора…", "Select donor…")
                if self._donor_passport is None
                else tr("Сменить донора…", "Change donor…"),
                "GhostBtn" if self._donor_passport is not None else "",
                slot=self.pick_donor_source,
            )
            head_row.addWidget(btn_pick_donor)
            if self._donor_dflash is not None:
                btn_save_plan = button(
                    tr("Экспорт плана JSON…", "Export plan JSON…"),
                    "GhostBtn",
                    slot=self.export_transfer_plan,
                )
                head_row.addWidget(btn_save_plan)
        elif self._key == "can_ctrl":
            btn_pop = button(
                tr("В отдельном окне…", "Open in window…"),
                "GhostBtn",
                slot=self.open_can_control_dialog,
            )
            head_row.addWidget(btn_pop)
        lay.addLayout(head_row)

        if self._key == "secrets":
            self._build_secrets_page(lay)
        elif self._key == "cp":
            self._build_cp_page(lay)
        elif self._key == "keys":
            self._build_keys_page(lay)
        elif self._key == "transfer":
            self._build_transfer_page(lay)
        elif self._key == "extra":
            self._build_extra_page(lay)
        elif self._key == "read":
            self._build_read_page(lay)
        elif self._key == "can_ctrl":
            self._build_can_ctrl_page(lay)

        lay.addStretch(1)
        outer.addWidget(column, 1)
        outer.addStretch(0)
        self.page_area.setWidget(page)

    def _copy_hex(self, hex_value: str, label: str) -> None:
        cleaned = hex_value.strip().upper()
        if not cleaned or cleaned == "—":
            return
        cb = QGuiApplication.clipboard()
        if cb is not None:
            cb.setText(cleaned)
            self.note.emit(tr(f"Скопировано в буфер обмена: {label}", f"Copied to clipboard: {label}"))

    @staticmethod
    def _empty_dflash_callout(lay: QVBoxLayout) -> None:
        empty = Callout("info")
        empty.label.setText(
            tr(
                "Дамп <b>DataFlash</b> ещё не загружен. Перейдите в раздел <b>«Чтение памяти»</b> и нажмите <b>«Считать блок»</b>.",
                "No <b>DataFlash</b> dump is loaded yet. Open <b>“Memory read”</b> and click <b>“Read the ECU”</b>.",
            )
        )
        lay.addWidget(empty)

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
        """Architectural form cell: uppercase GroupLabel + optional right badge above a recessed input row."""
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

    # ────────────────────────────── Page 1: Immobilizer (Immo 4.0) ──────────────────────────────

    def _build_k_ffb_calculator_card(self, lay: QVBoxLayout, initial_kc: str = "") -> None:
        """Standalone K_ffb = AES128_ECB_ENC(K_c, C16) calculator card when no DataFlash dump is loaded yet."""
        sec_calc = _FpkeCanControlPanel._compact_section(Section())
        sec_calc.set_text(
            tr("Калькулятор ключа радиоканала K_ffb", "Radio channel secret K_ffb calculator"),
            tr(
                "Расчёт 16-байтного секрета радиоканала брелоков K_ffb = AES-128-ECB(K_c, C16) из мастер-ключа панели приборов CS / K_c (EEL 0x68+0x28, ROM C16 @ 0x19DA90) для блока 09 BCM.",
                "Derive the 16-byte remote key radio-channel secret K_ffb = AES-128-ECB(K_c, C16) from the cluster master key CS / K_c (EEL 0x68+0x28, ROM C16 @ 0x19DA90) for 09 BCM.",
            ),
        )
        row_calc = QHBoxLayout()
        row_calc.setSpacing(10)

        ed_kc_in = QLineEdit(initial_kc)
        ed_kc_in.setFont(mono_font(12, bold=True))
        ed_kc_in.setMinimumWidth(0)
        ed_kc_in.setPlaceholderText("32 HEX (16 B, EEL 0x68+0x28)")
        btn_cp_kc_in = button(
            tr("Копировать", "Copy"),
            "GhostBtn",
            slot=lambda: self._copy_hex(ed_kc_in.text(), "CS / Kc"),
        )
        c_kc_in, b_kc_in = self._field_box(
            tr("СЕКРЕТ ИММОБИЛАЙЗЕРА CS / KC (16 БАЙТ)", "IMMOBILIZER SECRET CS / KC (16 BYTES)"),
            ed_kc_in,
            trailing=(btn_cp_kc_in,),
            tip="EEL 0x68 + 0x28..0x37 (16 bytes)",
        )
        self._bind_hex_validator(ed_kc_in, b_kc_in, 16)

        ed_kffb_out = QLineEdit()
        ed_kffb_out.setReadOnly(True)
        ed_kffb_out.setFont(mono_font(12, bold=True))
        ed_kffb_out.setMinimumWidth(0)
        ed_kffb_out.setPlaceholderText("AES-128-ECB(K_c, C16)")
        btn_cp_kffb_out = button(
            tr("Копировать", "Copy"),
            "GhostBtn",
            slot=lambda: self._copy_hex(ed_kffb_out.text(), "K_ffb"),
        )
        c_kffb_out, b_kffb_out = self._field_box(
            tr("КЛЮЧ РАДИОКАНАЛА K_FFB (16 БАЙТ, ДЛЯ 09 BCM)", "RADIO CHANNEL KEY K_FFB (16 BYTES, FOR 09 BCM)"),
            ed_kffb_out,
            trailing=(btn_cp_kffb_out,),
            tip="K_ffb = AES128_ECB_ENC(K_c, e7ad3585e2f937e81c75df6e47f11a71)",
        )

        def _sync_standalone_kffb(txt: str) -> None:
            raw = "".join(txt.split()).replace("0x", "").replace("0X", "").upper()
            if len(raw) == 32 and all(c in "0123456789ABCDEF" for c in raw) and raw != "FF" * 16:
                derived = fpke_derive_k_ffb(raw).hex().upper()
                ed_kffb_out.setText(derived)
                b_kffb_out.setText("AES_Kc(C16)")
                set_tone(b_kffb_out, "ok")
                btn_cp_kffb_out.setEnabled(True)
            else:
                ed_kffb_out.setText("")
                b_kffb_out.setText(tr("нужен K_c", "needs K_c"))
                set_tone(b_kffb_out, "muted")
                btn_cp_kffb_out.setEnabled(False)
            b_kffb_out.setVisible(True)

        ed_kc_in.textChanged.connect(_sync_standalone_kffb)
        _sync_standalone_kffb(ed_kc_in.text())

        row_calc.addWidget(c_kc_in, 1)
        row_calc.addWidget(c_kffb_out, 1)
        sec_calc.body.addLayout(row_calc)
        lay.addWidget(sec_calc)

    def _build_secrets_page(self, lay: QVBoxLayout) -> None:
        if not self.dflash_info:
            self._empty_dflash_callout(lay)
            self._build_k_ffb_calculator_card(lay)
            return

        by_id = {it["key_id"]: it for it in self.dflash_info.get("items", [])}
        meta = self.dflash_info.get("metadata") or {}
        immo_cfg = self.dflash_info.get("immo_config") or {}
        slots = self.dflash_info.get("slot_secrets") or {}

        # ── Card 1: Vehicle Identity & Master Secret (CS) ──
        sec_immo = _FpkeCanControlPanel._compact_section(Section())
        sec_immo.set_text(
            tr("Паспорт иммобилайзера", "Immobilizer passport"),
        )
        pers = bool(immo_cfg.get("personalized"))
        st_lbl = status_readout(
            tr("Персонализирован", "Personalized") if pers else tr("Чистый / не привязан", "Virgin / blank"),
            "ok" if pers else "warn",
        )
        sec_immo.head.addWidget(st_lbl, 0, Qt.AlignmentFlag.AlignVCenter)

        # Row 1: [VIN (17 chars) | Power Class (1 B) | Immo Mode | Key Reader Path]
        row1 = QHBoxLayout()
        row1.setSpacing(10)

        cur_vin = str(meta.get("vin") or "")
        ed_vin = QLineEdit(cur_vin)
        ed_vin.setFont(mono_font(12, bold=True))
        ed_vin.setMaxLength(17)
        ed_vin.setMinimumWidth(0)
        ed_vin.setPlaceholderText(tr("17 символов (A–Z, 0–9)", "17 chars (A–Z, 0–9)"))
        c_vin, b_vin = self._field_box(
            tr("VIN АВТОМОБИЛЯ", "VEHICLE VIN"),
            ed_vin,
            tip="EEL 0x68 + 0x17 (DID F190, 17 ASCII bytes)",
        )

        def _upd_vin(txt: str) -> None:
            s = txt.strip().upper()
            if not s:
                set_tone(ed_vin, "")
                b_vin.setText(tr("пусто", "empty"))
                set_tone(b_vin, "muted")
                b_vin.setVisible(True)
                return
            ok = len(s) == 17 and all(("0" <= c <= "9") or ("A" <= c <= "Z") for c in s)
            set_tone(ed_vin, "" if ok else "err")
            b_vin.setText(f"{len(s)}/17")
            set_tone(b_vin, "ok" if ok else "err")
            b_vin.setVisible(True)

        ed_vin.textChanged.connect(_upd_vin)
        _upd_vin(cur_vin)

        cur_pc = str(immo_cfg.get("power_class_byte") or "")
        ed_pc = QLineEdit(cur_pc)
        ed_pc.setFont(mono_font(12, bold=True))
        ed_pc.setMaxLength(4)
        ed_pc.setMinimumWidth(0)
        ed_pc.setPlaceholderText("4C")
        c_pc, b_pc = self._field_box(
            "POWER CLASS",
            ed_pc,
            tip=tr("Класс мощности двигателя (EEL 0x68+0x40, DID 02ED байт 3)", "Engine PowerClass (EEL 0x68+0x40, DID 02ED byte 3)"),
        )
        self._bind_hex_validator(ed_pc, b_pc, 1)

        cmb_mode = QComboBox()
        cmb_mode.setMinimumWidth(0)
        mode_options = (
            (1, tr("1 — Рабочий", "1 — Normal")),
            (0, tr("0 — Заводской", "0 — Virgin")),
            (2, tr("2 — Без ключей", "2 — No keys")),
            (3, tr("3 — Обучение", "3 — Learning")),
            (4, tr("4 — Дообучение (4)", "4 — Add-key (4)")),
            (5, tr("5 — Дообучение (5)", "5 — Add-key (5)")),
        )
        cur_mode = immo_cfg.get("immo_mode")
        cur_mode_val = 1 if cur_mode is None else int(cur_mode)
        for m_val, m_txt in mode_options:
            cmb_mode.addItem(m_txt, m_val)
            if m_val == cur_mode_val:
                cmb_mode.setCurrentIndex(cmb_mode.count() - 1)
        c_mode, _ = self._field_box(
            tr("РЕЖИМ ИММО", "IMMO MODE"),
            cmb_mode,
            tip="EEL 0x68 + 0x4B",
        )

        cmb_kpath = QComboBox()
        cmb_kpath.setMinimumWidth(0)
        cmb_kpath.addItem(tr("Катушка замка", "Local coil"), False)
        cmb_kpath.addItem(tr("KESSY по CAN", "KESSY over CAN"), True)
        cmb_kpath.setCurrentIndex(1 if immo_cfg.get("key_over_can") else 0)
        c_kpath, _ = self._field_box(
            tr("ОПРОС КЛЮЧА", "KEY READER"),
            cmb_kpath,
            tip="EEL 0x68 + 0x4D bit 7 (0x80)",
        )

        row1.addWidget(c_vin, 4)
        row1.addWidget(c_pc, 2)
        row1.addWidget(c_mode, 3)
        row1.addWidget(c_kpath, 3)
        sec_immo.body.addLayout(row1)

        # Row 2: [CS / Kc (16 B) + Copy | VDO CS+ Slot A (4 B) | VDO CS+ Slot B (4 B)]
        row2 = QHBoxLayout()
        row2.setSpacing(10)

        raw_kc = (by_id.get("kc") or {}).get("hex", "").upper()
        cur_kc = "" if raw_kc == "FF" * 16 else raw_kc
        ed_kc = QLineEdit(cur_kc)
        ed_kc.setFont(mono_font(12, bold=True))
        ed_kc.setMinimumWidth(0)
        ed_kc.setPlaceholderText("32 HEX (16 B)")
        btn_copy_kc = button(tr("Копировать", "Copy"), "GhostBtn", slot=lambda: self._copy_hex(ed_kc.text(), "CS / Kc"))
        c_kc, b_kc = self._field_box(
            tr("СЕКРЕТ ИММОБИЛАЙЗЕРА CS / KC (16 БАЙТ)", "IMMOBILIZER SECRET CS / KC (16 BYTES)"),
            ed_kc,
            trailing=(btn_copy_kc,),
            tip="EEL 0x68 + 0x28..0x37 (16 bytes)",
        )
        self._bind_hex_validator(ed_kc, b_kc, 16)

        raw_crc_a = (slots.get("A_crc32_le") or "").upper()
        ed_crc_a = QLineEdit("" if raw_crc_a == "FFFFFFFF" else raw_crc_a)
        ed_crc_a.setFont(mono_font(12))
        ed_crc_a.setMinimumWidth(0)
        ed_crc_a.setPlaceholderText("8 HEX")
        c_crc_a, b_crc_a = self._field_box(
            tr("VDO CS+ (СЛОТ A)", "VDO CS+ (SLOT A)"),
            ed_crc_a,
            tip="EEL 0x68 + 0x38..0x3B (CRC-32 LE)",
        )
        self._bind_hex_validator(ed_crc_a, b_crc_a, 4)

        raw_crc_b = (slots.get("B_crc32_le") or "").upper()
        ed_crc_b = QLineEdit("" if raw_crc_b == "FFFFFFFF" else raw_crc_b)
        ed_crc_b.setFont(mono_font(12))
        ed_crc_b.setMinimumWidth(0)
        ed_crc_b.setPlaceholderText("8 HEX")
        c_crc_b, b_crc_b = self._field_box(
            tr("VDO CS+ (СЛОТ B)", "VDO CS+ (SLOT B)"),
            ed_crc_b,
            tip="EEL 0x68 + 0x3C..0x3F (CRC-32 LE)",
        )
        self._bind_hex_validator(ed_crc_b, b_crc_b, 4)

        ed_k_ffb = QLineEdit()
        ed_k_ffb.setReadOnly(True)
        ed_k_ffb.setFont(mono_font(12, bold=True))
        ed_k_ffb.setMinimumWidth(0)
        ed_k_ffb.setPlaceholderText("AES-128-ECB(K_c, C16)")
        btn_copy_k_ffb = button(
            tr("Копировать", "Copy"),
            "GhostBtn",
            slot=lambda: self._copy_hex(ed_k_ffb.text(), "K_ffb"),
        )
        c_k_ffb, b_k_ffb = self._field_box(
            tr("КЛЮЧ РАДИОКАНАЛА K_FFB (09 BCM)", "RADIO CHANNEL KEY K_FFB (09 BCM)"),
            ed_k_ffb,
            trailing=(btn_copy_k_ffb,),
            tip="K_ffb = AES128_ECB_ENC(K_c, C16 @ 0x19DA90: e7ad3585e2f937e81c75df6e47f11a71)",
        )

        def _sync_live_k_ffb(txt: str) -> None:
            raw = "".join(txt.split()).replace("0x", "").replace("0X", "").upper()
            if len(raw) == 32 and all(c in "0123456789ABCDEF" for c in raw) and raw != "FF" * 16:
                derived = fpke_derive_k_ffb(raw).hex().upper()
                ed_k_ffb.setText(derived)
                b_k_ffb.setText("AES_Kc(C16)")
                set_tone(b_k_ffb, "ok")
                btn_copy_k_ffb.setEnabled(True)
            else:
                ed_k_ffb.setText("")
                b_k_ffb.setText(tr("нужен K_c", "needs K_c"))
                set_tone(b_k_ffb, "muted")
                btn_copy_k_ffb.setEnabled(False)
            b_k_ffb.setVisible(True)

        ed_kc.textChanged.connect(_sync_live_k_ffb)
        _sync_live_k_ffb(ed_kc.text())

        row2.addWidget(c_kc, 5)
        row2.addWidget(c_k_ffb, 5)
        row2.addWidget(c_crc_a, 2)
        row2.addWidget(c_crc_b, 2)
        sec_immo.body.addLayout(row2)
        lay.addWidget(sec_immo)

        # ── Card 2: Partner Modules & MAC Synchronization Codes (EEL 0x66) ──
        sec_mac = _FpkeCanControlPanel._compact_section(Section())
        sec_mac.set_text(
            tr("Привязанные блоки (MAC)", "Partner modules (MAC)"),
        )
        lbl_mac4 = QLabel()
        lbl_mac4.setFont(mono_font(12, bold=True))
        set_tone(lbl_mac4, "info")
        btn_copy_mac4 = button(
            tr("Копировать", "Copy"),
            "GhostBtn",
            slot=lambda: self._copy_hex(lbl_mac4.property("raw_mac4") or "", "MAC4"),
        )
        sec_mac.head.addWidget(lbl_mac4, 0, Qt.AlignmentFlag.AlignVCenter)
        sec_mac.head.addWidget(btn_copy_mac4, 0, Qt.AlignmentFlag.AlignVCenter)

        nodes_row = QHBoxLayout()
        nodes_row.setSpacing(8)

        # Node 0: Cluster (DASH)
        dash_tile = QFrame()
        dash_tile.setObjectName("ResultStrip")
        dt_lay = QVBoxLayout(dash_tile)
        dt_lay.setContentsMargins(9, 6, 9, 7)
        dt_lay.setSpacing(4)
        dt_top = QHBoxLayout()
        dt_top.setSpacing(4)
        lbl_dash_t = QLabel(tr("Панель приборов", "Cluster"))
        lbl_dash_t.setObjectName("FieldLabel")
        lbl_dash_t.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        lbl_dash_tag = QLabel("DASH")
        lbl_dash_tag.setFont(mono_font(10))
        set_tone(lbl_dash_tag, "info")
        dt_top.addWidget(lbl_dash_t, 1)
        dt_top.addWidget(lbl_dash_tag, 0)
        dt_lay.addLayout(dt_top)

        ed_mac_dash = QLineEdit(immo_cfg.get("cluster_mac_id") or "")
        ed_mac_dash.setFont(mono_font(12, bold=True))
        ed_mac_dash.setMaxLength(4)
        ed_mac_dash.setMinimumWidth(0)
        ed_mac_dash.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        ed_mac_dash.setPlaceholderText("A001")
        dt_lay.addWidget(ed_mac_dash)
        nodes_row.addWidget(dash_tile, 1)

        by_pcode = {p["code"]: p for p in immo_cfg.get("partners", [])}
        partner_controls: dict[str, tuple[QCheckBox, QLineEdit, int]] = {}
        for p_idx, code, short_tag, title_ru, title_en, ph in (
            (0, "MSG_1", "ECU", "Двигатель", "Engine", "E001"),
            (1, "GSG", "TCU", "Коробка", "Gearbox", "E002"),
            (5, "ELV", "ELV", "Руль", "Steering", "E005"),
        ):
            p_info = by_pcode.get(code) or {}
            tile = QFrame()
            tile.setObjectName("ResultStrip")
            t_lay = QVBoxLayout(tile)
            t_lay.setContentsMargins(9, 6, 9, 7)
            t_lay.setSpacing(4)
            p_top = QHBoxLayout()
            p_top.setSpacing(4)
            chk = QCheckBox(tr(title_ru, title_en))
            chk.setChecked(bool(p_info.get("adapted")))
            lbl_ptag = QLabel(short_tag)
            lbl_ptag.setFont(mono_font(10))
            set_tone(lbl_ptag, "muted")
            p_top.addWidget(chk)
            p_top.addStretch(1)
            p_top.addWidget(lbl_ptag)
            ed_m = QLineEdit(p_info.get("mac_id_hex") or "")
            ed_m.setFont(mono_font(12, bold=True))
            ed_m.setMaxLength(4)
            ed_m.setMinimumWidth(0)
            ed_m.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
            ed_m.setPlaceholderText(ph)
            t_lay.addLayout(p_top)
            t_lay.addWidget(ed_m)
            nodes_row.addWidget(tile, 1)
            partner_controls[code] = (chk, ed_m, p_idx)

        def _sync_mac4_banner() -> None:
            d_hex = ed_mac_dash.text().strip().upper()
            e_hex = partner_controls["MSG_1"][1].text().strip().upper()
            comb = f"{d_hex}{e_hex}" if (len(d_hex) == 4 and len(e_hex) == 4) else ""
            lbl_mac4.setProperty("raw_mac4", comb)
            lbl_mac4.setText(f"MAC4: {comb}" if comb else "MAC4: —")
            btn_copy_mac4.setEnabled(bool(comb))

        ed_mac_dash.textChanged.connect(lambda _t: _sync_mac4_banner())
        partner_controls["MSG_1"][1].textChanged.connect(lambda _t: _sync_mac4_banner())
        _sync_mac4_banner()

        sec_mac.body.addLayout(nodes_row)

        def _save_immo_changes(silent_if_unchanged: bool = False) -> bool:
            df_cur, cf_cur = self._own_dflash_and_cflash()
            if df_cur is None:
                return False
            base_mask = int(immo_cfg.get("partners_mask") or 0)
            for _code, (chk_w, _ed_w, bit_idx) in partner_controls.items():
                if chk_w.isChecked():
                    base_mask |= 1 << bit_idx
                else:
                    base_mask &= ~(1 << bit_idx)
            pmacs = {code: ed_w.text().strip() for code, (_chk_w, ed_w, _b) in partner_controls.items()}
            try:
                new_df = apply_fpke_dflash_edits(
                    df_cur,
                    vin=ed_vin.text(),
                    cs_hex=ed_kc.text(),
                    crc_a_hex=ed_crc_a.text(),
                    crc_b_hex=ed_crc_b.text(),
                    power_class=ed_pc.text(),
                    immo_mode=int(cmb_mode.currentData()),
                    key_over_can=bool(cmb_kpath.currentData()),
                    partners_mask=base_mask,
                    clear_lockouts=True,
                    mac_dash_hex=ed_mac_dash.text(),
                    partner_macs=pmacs,
                    cflash=cf_cur,
                )
            except Exception as exc:
                QMessageBox.warning(self, tr("Ошибка проверки полей", "Validation error"), str(exc))
                return False
            if silent_if_unchanged and new_df == df_cur:
                return True
            self._commit_dflash_bytes(
                new_df,
                ""
                if silent_if_unchanged
                else tr(
                    "Данные иммобилайзера и MAC сохранены в рабочую копию дампа.",
                    "Immobilizer and MAC fields saved to working dump.",
                ),
            )
            return True

        self._page_commit_fn = _save_immo_changes
        btn_write_immo = button(
            tr("Записать в блок", "Write to ECU"),
            "PrimaryBtn",
            slot=lambda: self.write_dflash_to_ecu() if _save_immo_changes(True) else None,
        )
        btn_write_immo.setEnabled(not self.runner.is_busy)
        btn_apply_immo = button(
            tr("В дамп", "Apply to dump"),
            slot=lambda: _save_immo_changes(False),
        )
        btn_reset_immo = button(
            tr("Сбросить поля", "Reset fields"),
            "GhostBtn",
            slot=self._render_page,
        )
        sec_mac.add_footer(btn_write_immo, btn_apply_immo, btn_reset_immo)
        lay.addWidget(sec_mac)

    # ────────────────────────────── Page 2: Component Protection (CP) ──────────────────────────────

    def _build_cp_page(self, lay: QVBoxLayout) -> None:
        if not self.dflash_info:
            self._empty_dflash_callout(lay)
            return

        by_id = {it["key_id"]: it for it in self.dflash_info.get("items", [])}
        cp_st = self.dflash_info.get("component_protection_state") or {}

        sec_cp = _FpkeCanControlPanel._compact_section(Section())
        sec_cp.set_text(
            tr("Защита компонентов (CP)", "Component Protection (CP)"),
            tr(
                "Индивидуальный ключ IKA (/3, 00BE) связывает панель приборов со шлюзом J533; ключ слота /1 (GFA, 00BD) используется для обмена с узлом 0x0E (BCM 09, радиоканал ключей) и проверки 0x29E→0x29F.",
                "The 16-byte IKA (/3, 00BE) key binds the cluster to the J533 gateway; the /1 slot key (GFA, 00BD) is used for channel 3 node 0x0E (BCM 09, remote key sync) and 0x29E→0x29F.",
            ),
        )
        err_cnt = cp_st.get("error_counter")
        if cp_st.get("active"):
            cp_txt, cp_tone = tr(f"Блокировка SAFE CP (ошибок: {err_cnt})", f"SAFE CP active (errors: {err_cnt})"), "err"
        elif cp_st.get("adapted"):
            cp_txt, cp_tone = tr(f"Адаптирована (ошибок: {err_cnt or 0})", f"Adapted (errors: {err_cnt or 0})"), "ok"
        else:
            cp_txt, cp_tone = tr("Статус не заполнен", "Status not set"), "muted"
        sec_cp.head.addWidget(status_readout(cp_txt, cp_tone), 0, Qt.AlignmentFlag.AlignVCenter)

        raw_ika = (by_id.get("ika_cp3") or {}).get("hex", "").upper()
        ed_ika = QLineEdit("" if raw_ika == "FF" * 16 else raw_ika)
        ed_ika.setFont(mono_font(12, bold=True))
        ed_ika.setMinimumWidth(0)
        ed_ika.setPlaceholderText("32 HEX (16 B)")
        btn_gen_ika = button(
            tr("Сгенерировать", "Generate"),
            "GhostBtn",
            slot=lambda: ed_ika.setText(_py_secrets.token_hex(16).upper()),
        )
        btn_cp_ika = button(
            tr("Копировать", "Copy"),
            "GhostBtn",
            slot=lambda: self._copy_hex(ed_ika.text(), "IKA"),
        )
        c_ika, b_ika = self._field_box(
            tr("КЛЮЧ IKA ДЛЯ ШЛЮЗА J533 (16 БАЙТ)", "IKA KEY FOR J533 GATEWAY (16 BYTES)"),
            ed_ika,
            trailing=(btn_gen_ika, btn_cp_ika),
            tip="EEL 0x6B + 0x02..0x11 (CP /3 working key)",
        )
        self._bind_hex_validator(ed_ika, b_ika, 16)
        sec_cp.body.addWidget(c_ika)

        raw_gfa = (by_id.get("cp1_bank_0") or {}).get("hex", "").upper()
        ed_gfa = QLineEdit("" if raw_gfa == "FF" * 16 else raw_gfa)
        ed_gfa.setFont(mono_font(12))
        ed_gfa.setMinimumWidth(0)
        ed_gfa.setPlaceholderText("32 HEX (16 B)")
        btn_gen_gfa = button(
            tr("Сгенерировать", "Generate"),
            "GhostBtn",
            slot=lambda: ed_gfa.setText(_py_secrets.token_hex(16).upper()),
        )
        btn_cp_gfa = button(
            tr("Копировать", "Copy"),
            "GhostBtn",
            slot=lambda: self._copy_hex(ed_gfa.text(), "GFA"),
        )
        c_gfa, b_gfa = self._field_box(
            tr("КЛЮЧ СЛОТА /1 — GFA / УЗЕЛ 0x0E (BCM 09, 16 БАЙТ)", "CP /1 KEY — GFA / NODE 0x0E (BCM 09, 16 BYTES)"),
            ed_gfa,
            trailing=(btn_gen_gfa, btn_cp_gfa),
            tip="EEL 0x6B + 0x12..0x21 (UDS 00BD: 0x17F8140E & 0x29E/0x29F)",
        )
        self._bind_hex_validator(ed_gfa, b_gfa, 16)
        sec_cp.body.addWidget(c_gfa)

        chk_reset_cp = QCheckBox(
            tr(
                "Сбросить счётчик ошибок SAFE CP и отметить как адаптированную",
                "Reset SAFE CP error counter and mark cluster as adapted",
            )
        )
        chk_reset_cp.setChecked(bool(cp_st.get("active")))
        sec_cp.body.addWidget(chk_reset_cp)

        if cp_st.get("prng_0") or cp_st.get("record_2_first_10"):
            diag_strip = QFrame()
            diag_strip.setObjectName("ResultStrip")
            ds_lay = QHBoxLayout(diag_strip)
            ds_lay.setContentsMargins(10, 6, 10, 6)
            ds_lay.setSpacing(16)
            lbl_prng = QLabel(f"PRNG: {(cp_st.get('prng_0') or '—').upper()}")
            lbl_prng.setFont(mono_font(11))
            set_tone(lbl_prng, "muted")
            lbl_rec2 = QLabel(f"CP STATUS: {(cp_st.get('record_2_first_10') or '—').upper()}")
            lbl_rec2.setFont(mono_font(11))
            set_tone(lbl_rec2, "muted")
            ds_lay.addWidget(lbl_prng)
            ds_lay.addWidget(lbl_rec2)
            ds_lay.addStretch(1)
            sec_cp.body.addWidget(diag_strip)

        def _save_cp_changes(silent_if_unchanged: bool = False) -> bool:
            df_cur, cf_cur = self._own_dflash_and_cflash()
            if df_cur is None:
                return False
            try:
                new_df = apply_fpke_dflash_edits(
                    df_cur,
                    ika_key_hex=ed_ika.text(),
                    gfa_key_hex=ed_gfa.text(),
                    reset_cp_counter=chk_reset_cp.isChecked(),
                    cflash=cf_cur,
                )
            except Exception as exc:
                QMessageBox.warning(self, tr("Ошибка проверки ключей CP", "CP validation error"), str(exc))
                return False
            if silent_if_unchanged and new_df == df_cur:
                return True
            self._commit_dflash_bytes(
                new_df,
                ""
                if silent_if_unchanged
                else tr(
                    "Ключи защиты компонентов сохранены в рабочую копию дампа.",
                    "Component Protection keys saved to working dump.",
                ),
            )
            return True

        self._page_commit_fn = _save_cp_changes
        btn_write_cp = button(
            tr("Записать в блок", "Write to ECU"),
            "PrimaryBtn",
            slot=lambda: self.write_dflash_to_ecu() if _save_cp_changes(True) else None,
        )
        btn_write_cp.setEnabled(not self.runner.is_busy)
        btn_apply_cp = button(
            tr("В дамп", "Apply to dump"),
            slot=lambda: _save_cp_changes(False),
        )
        btn_reset_cp = button(tr("Сбросить поля", "Reset fields"), "GhostBtn", slot=self._render_page)
        sec_cp.add_footer(btn_write_cp, btn_apply_cp, btn_reset_cp)
        lay.addWidget(sec_cp)

    # ────────────────────────────── Page 3: Keys & Odometer ──────────────────────────────

    def _build_keys_page(self, lay: QVBoxLayout) -> None:
        if not self.dflash_info:
            self._empty_dflash_callout(lay)
            self._build_k_ffb_calculator_card(lay)
            return

        tp = self.dflash_info.get("transponder_records") or {}
        meta = self.dflash_info.get("metadata") or {}
        odo = self.dflash_info.get("odometer") or {}
        immo_cfg = self.dflash_info.get("immo_config") or {}
        learned = int(tp.get("learned_keys", 0))
        allowed = int(tp.get("allowed_keys", 8) or 8)
        xor_fl = int(tp.get("session_xor_flags", 0))

        # ── Card 1: Odometer & Long Coding ──
        sec_odo = _FpkeCanControlPanel._compact_section(Section())
        sec_odo.set_text(
            tr("Пробег и кодирование", "Odometer & coding"),
        )
        odo_ok = bool(odo.get("unanimous"))
        odo_badge = status_readout(
            tr("3 из 3 копий совпадают", "3 of 3 copies match")
            if odo_ok
            else tr("Голосование 2 из 3", "2-of-3 majority vote"),
            "ok" if odo_ok else "warn",
        )
        sec_odo.head.addWidget(odo_badge, 0, Qt.AlignmentFlag.AlignVCenter)

        odo_row = QHBoxLayout()
        odo_row.setSpacing(10)

        spn_odo = QSpinBox()
        spn_odo.setRange(0, 999_998)
        spn_odo.setSingleStep(2)
        spn_odo.setSuffix(tr(" км", " km"))
        spn_odo.setFont(mono_font(12, bold=True))
        spn_odo.setMinimumWidth(0)
        spn_odo.setValue(int(odo.get("odometer_km") or 0))
        c_odo, _ = self._field_box(
            tr("ПРОБЕГ (КМ)", "ODOMETER (KM)"),
            spn_odo,
            badge_text=tr("шаг 2 км", "2 km step"),
            badge_tone="muted",
        )

        cur_cod = str(meta.get("coding_hex") or "")
        ed_coding = QLineEdit(cur_cod)
        ed_coding.setFont(mono_font(12))
        ed_coding.setMinimumWidth(0)
        ed_coding.setPlaceholderText(tr("40 HEX-символов (20 байт)", "40 hex chars (20 bytes)"))
        btn_cp_cod = button(
            tr("Копировать", "Copy"),
            "GhostBtn",
            slot=lambda: self._copy_hex(ed_coding.text(), "Coding"),
        )
        c_cod, b_cod = self._field_box(
            tr("ДЛИННОЕ КОДИРОВАНИЕ (20 БАЙТ)", "LONG CODING (20 BYTES)"),
            ed_coding,
            trailing=(btn_cp_cod,),
            tip="EEL 0x30 + 11..30 (DID 0x0600, 20 bytes)",
        )
        if cur_cod:
            self._bind_hex_validator(ed_coding, b_cod, 20, allow_empty=True)

        cur_k_ffb = str(immo_cfg.get("k_ffb_hex") or "").upper()
        ed_keys_kffb = QLineEdit(cur_k_ffb)
        ed_keys_kffb.setReadOnly(True)
        ed_keys_kffb.setFont(mono_font(12, bold=True))
        ed_keys_kffb.setMinimumWidth(0)
        ed_keys_kffb.setPlaceholderText("AES-128-ECB(K_c, C16)")
        btn_cp_keys_kffb = button(
            tr("Копировать", "Copy"),
            "GhostBtn",
            slot=lambda: self._copy_hex(ed_keys_kffb.text(), "K_ffb"),
        )
        btn_cp_keys_kffb.setEnabled(bool(cur_k_ffb))
        c_keys_kffb, _ = self._field_box(
            tr("КЛЮЧ РАДИОКАНАЛА K_FFB (09 BCM)", "RADIO CHANNEL KEY K_FFB (09 BCM)"),
            ed_keys_kffb,
            badge_text="AES_Kc(C16)" if cur_k_ffb else tr("нет K_c", "no K_c"),
            badge_tone="ok" if cur_k_ffb else "muted",
            trailing=(btn_cp_keys_kffb,),
            tip="K_ffb = AES128_ECB_ENC(K_c, C16 @ 0x19DA90: e7ad3585e2f937e81c75df6e47f11a71)",
        )

        odo_row.addWidget(c_odo, 2)
        odo_row.addWidget(c_cod, 4)
        odo_row.addWidget(c_keys_kffb, 4)
        sec_odo.body.addLayout(odo_row)
        lay.addWidget(sec_odo)

        # ── Card 2: 8 Transponder Key Slots ──
        sec_tp = _FpkeCanControlPanel._compact_section(Section())
        sec_tp.set_text(
            tr("Ключи (8 слотов)", "Keys (8 slots)"),
        )

        cnt_bar = QHBoxLayout()
        cnt_bar.setSpacing(6)
        lbl_lrn = group_label(tr("ОБУЧЕНО:", "LEARNED:"))
        spn_learned = QSpinBox()
        spn_learned.setRange(0, 8)
        spn_learned.setValue(learned)
        spn_learned.setFont(mono_font(11, bold=True))
        spn_learned.setFixedWidth(56)

        lbl_alw = group_label(tr("РАЗРЕШЕНО:", "ALLOWED:"))
        spn_allowed = QSpinBox()
        spn_allowed.setRange(0, 8)
        spn_allowed.setValue(allowed)
        spn_allowed.setFont(mono_font(11))
        spn_allowed.setFixedWidth(56)

        lbl_xor = QLabel(f"XOR: 0x{xor_fl:X}")
        lbl_xor.setFont(mono_font(11))
        set_tone(lbl_xor, "muted")

        cnt_bar.addWidget(lbl_lrn)
        cnt_bar.addWidget(spn_learned)
        cnt_bar.addSpacing(4)
        cnt_bar.addWidget(lbl_alw)
        cnt_bar.addWidget(spn_allowed)
        cnt_bar.addSpacing(4)
        cnt_bar.addWidget(lbl_xor)
        sec_tp.head.addLayout(cnt_bar)

        key_grid = QGridLayout()
        key_grid.setHorizontalSpacing(10)
        key_grid.setVerticalSpacing(6)
        key_edits: list[QLineEdit] = []
        key_badges: list[QLabel] = []
        key_slots_data = list(tp.get("key_ids") or [])

        for slot_idx in range(8):
            k_info = key_slots_data[slot_idx] if slot_idx < len(key_slots_data) else {}
            disp_id = (k_info.get("display_id") or "") if k_info.get("present") else ""
            ed_k = QLineEdit(disp_id)
            ed_k.setFont(mono_font(12, bold=bool(disp_id)))
            ed_k.setMaxLength(8)
            ed_k.setMinimumWidth(0)
            ed_k.setPlaceholderText(tr("Свободен", "Empty"))
            cell_w, b_lbl = self._field_box(
                tr(f"КЛЮЧ {slot_idx + 1}", f"KEY {slot_idx + 1}"),
                ed_k,
                tip=f"EEL 0x67 slot {slot_idx + 1} (4-byte u32 LE transponder ID)",
            )
            key_edits.append(ed_k)
            key_badges.append(b_lbl)
            r_i, c_i = divmod(slot_idx, 4)
            key_grid.addWidget(cell_w, r_i, c_i)

        def _refresh_key_badges() -> None:
            lrn_cnt = spn_learned.value()
            for idx, (ed_k, b_lbl) in enumerate(zip(key_edits, key_badges)):
                raw = ed_k.text().strip().upper()
                if not raw or raw == "FFFFFFFF":
                    set_tone(ed_k, "")
                    b_lbl.setText(tr("пуст", "free"))
                    set_tone(b_lbl, "muted")
                    b_lbl.setVisible(True)
                    continue
                valid_hex = len(raw) == 8 and all(c in "0123456789ABCDEF" for c in raw)
                if not valid_hex:
                    set_tone(ed_k, "err")
                    b_lbl.setText(f"{len(raw)}/8")
                    set_tone(b_lbl, "err")
                elif idx < lrn_cnt:
                    set_tone(ed_k, "")
                    b_lbl.setText(tr("активен", "active"))
                    set_tone(b_lbl, "ok")
                else:
                    set_tone(ed_k, "")
                    b_lbl.setText(tr("резерв", "spare"))
                    set_tone(b_lbl, "warn")
                b_lbl.setVisible(True)

        for ed_k in key_edits:
            ed_k.textChanged.connect(lambda _t: _refresh_key_badges())
        spn_learned.valueChanged.connect(lambda _v: _refresh_key_badges())
        _refresh_key_badges()

        sec_tp.body.addLayout(key_grid)

        def _save_keys_and_odo(silent_if_unchanged: bool = False) -> bool:
            df_cur, cf_cur = self._own_dflash_and_cflash()
            if df_cur is None:
                return False
            cod_txt = ed_coding.text().strip()
            try:
                new_df = apply_fpke_dflash_edits(
                    df_cur,
                    odometer_km=spn_odo.value(),
                    coding_hex=cod_txt if cod_txt else None,
                    key_display_ids=[e.text().strip() for e in key_edits],
                    learned_keys=spn_learned.value(),
                    allowed_keys=spn_allowed.value(),
                    session_xor_flags=xor_fl,
                    cflash=cf_cur,
                )
            except Exception as exc:
                QMessageBox.warning(self, tr("Ошибка проверки полей", "Validation error"), str(exc))
                return False
            if silent_if_unchanged and new_df == df_cur:
                return True
            self._commit_dflash_bytes(
                new_df,
                ""
                if silent_if_unchanged
                else tr(
                    "Ключи и пробег сохранены в рабочую копию дампа.",
                    "Keys and odometer saved to working dump.",
                ),
            )
            return True

        self._page_commit_fn = _save_keys_and_odo
        btn_write_keys = button(
            tr("Записать в блок", "Write to ECU"),
            "PrimaryBtn",
            slot=lambda: self.write_dflash_to_ecu() if _save_keys_and_odo(True) else None,
        )
        btn_write_keys.setEnabled(not self.runner.is_busy)
        btn_apply_keys = button(
            tr("В дамп", "Apply to dump"),
            slot=lambda: _save_keys_and_odo(False),
        )
        btn_coil_wizard = button(
            tr("Через катушку…", "Via LF coil…"),
            "GhostBtn",
            slot=self.open_coil_key_learn_dialog,
        )
        btn_reset_keys = button(tr("Сбросить", "Reset"), "GhostBtn", slot=self._render_page)
        sec_tp.add_footer(btn_write_keys, btn_apply_keys, btn_coil_wizard, btn_reset_keys)
        lay.addWidget(sec_tp)

    # ────────────────────────────── Page 4: Donor -> Target Transfer ──────────────────────────────

    def _build_transfer_page(self, lay: QVBoxLayout) -> None:
        if not self.dflash_info:
            self._empty_dflash_callout(lay)
            return

        df_target, cf_target = self._own_dflash_and_cflash()
        target_passport = extract_fpke_immo_passport(df_target, cf_target) if df_target else None
        donor_passport = self._donor_passport

        # ── Top 2-Column Row: [1. DONOR (OLD CLUSTER)]  -->  [2. TARGET (OPEN CLUSTER)] ──
        pair_row = QHBoxLayout()
        pair_row.setSpacing(10)

        # Left Card: Donor (Source)
        sec_donor = _FpkeCanControlPanel._compact_section(Section())
        sec_donor.set_text(
            tr("1. Донор", "1. Donor"),
        )
        if donor_passport is None:
            sec_donor.head.addWidget(status_readout(tr("Не выбран", "Not loaded"), "warn"), 0, Qt.AlignmentFlag.AlignVCenter)
            lbl_empty_d = QLabel(
                tr(
                    "Загрузите дамп DataFlash (64 КБ) или сохранённый Immo-паспорт (.json) родной панели приборов автомобиля, "
                    "из которой нужно перенести иммобилайзер, ключи и пробег.",
                    "Load the 64 KB DataFlash dump or exported Immo passport (.json) of the car's original cluster "
                    "to transfer its immobilizer identity, keys, and mileage.",
                )
            )
            lbl_empty_d.setObjectName("Hint")
            lbl_empty_d.setWordWrap(True)
            sec_donor.body.addWidget(lbl_empty_d)
            btn_load_donor = button(
                tr("Выбрать донора…", "Select donor…"),
                "PrimaryBtn",
                slot=self.pick_donor_source,
            )
            sec_donor.add_footer(btn_load_donor)
        else:
            im_d = donor_passport.get("immo") or {}
            meta_d = donor_passport.get("cluster_metadata") or {}
            cnt_d = im_d.get("counts") or {}
            d_pn = meta_d.get("part_number") or (self._donor_path.name if self._donor_path else "Донор")
            sec_donor.head.addWidget(
                status_readout(str(d_pn), "info"),
                0,
                Qt.AlignmentFlag.AlignVCenter,
            )
            d_grid = QGridLayout()
            d_grid.setHorizontalSpacing(12)
            d_grid.setVerticalSpacing(3)
            d_odo = meta_d.get("odometer_km")
            d_odo_str = f"{int(d_odo):,} км".replace(",", " ") if d_odo is not None else "—"
            d_rows = (
                ("VIN", im_d.get("vin") or "—"),
                ("PC / MAC4", f"{im_d.get('power_class_hex') or '—'}   •   {im_d.get('mac4') or '—'}"),
                ("CS / KC", (im_d.get("cs") or "—")[:16] + ("…" if im_d.get("cs") else "")),
                (
                    tr("КЛЮЧИ / КМ", "KEYS / KM"),
                    tr(
                        f"{cnt_d.get('learned_keys', 0)}/{cnt_d.get('allowed_keys', 8)} кл.   •   {d_odo_str}",
                        f"{cnt_d.get('learned_keys', 0)}/{cnt_d.get('allowed_keys', 8)} keys   •   {d_odo_str}",
                    ),
                ),
            )
            for r_i, (k_txt, v_txt) in enumerate(d_rows):
                lk = group_label(k_txt.upper())
                lv = QLabel(str(v_txt))
                lv.setFont(mono_font(11, bold=(r_i == 0)))
                lv.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
                lv.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                d_grid.addWidget(lk, r_i, 0)
                d_grid.addWidget(lv, r_i, 1)
            d_grid.setColumnStretch(1, 1)
            sec_donor.body.addLayout(d_grid)

        # Right Card: Target (Currently Open Cluster)
        sec_target = _FpkeCanControlPanel._compact_section(Section())
        sec_target.set_text(
            tr("2. Цель (этот блок)", "2. Target (this unit)"),
        )
        sec_target.head.addWidget(
            status_readout(self.part_number, "ok"),
            0,
            Qt.AlignmentFlag.AlignVCenter,
        )
        im_t = (target_passport or {}).get("immo") or {}
        meta_t = (target_passport or {}).get("cluster_metadata") or {}
        cnt_t = im_t.get("counts") or {}
        t_odo = meta_t.get("odometer_km")
        t_odo_str = f"{int(t_odo):,} км".replace(",", " ") if t_odo is not None else "—"
        t_grid = QGridLayout()
        t_grid.setHorizontalSpacing(12)
        t_grid.setVerticalSpacing(3)
        t_rows = (
            ("VIN", im_t.get("vin") or "—"),
            ("PC / MAC4", f"{im_t.get('power_class_hex') or '—'}   •   {im_t.get('mac4') or '—'}"),
            (
                tr("ПРОШИВКА", "SOFTWARE"),
                tr(
                    f"SW {meta_t.get('sw_version_eel') or '—'} (сохраняется)",
                    f"SW {meta_t.get('sw_version_eel') or '—'} (preserved)",
                ),
            ),
            (
                tr("КЛЮЧИ / КМ", "KEYS / KM"),
                tr(
                    f"{cnt_t.get('learned_keys', 0)}/{cnt_t.get('allowed_keys', 8)} кл.   •   {t_odo_str}",
                    f"{cnt_t.get('learned_keys', 0)}/{cnt_t.get('allowed_keys', 8)} keys   •   {t_odo_str}",
                ),
            ),
        )
        for r_i, (k_txt, v_txt) in enumerate(t_rows):
            lk = group_label(k_txt.upper())
            lv = QLabel(str(v_txt))
            lv.setFont(mono_font(11, bold=(r_i == 0)))
            lv.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            lv.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            t_grid.addWidget(lk, r_i, 0)
            t_grid.addWidget(lv, r_i, 1)
        t_grid.setColumnStretch(1, 1)
        sec_target.body.addLayout(t_grid)

        pair_row.addWidget(sec_donor, 1)
        pair_row.addWidget(sec_target, 1)
        lay.addLayout(pair_row)

        # ── Bottom Card: 3. Selective Transfer Checklist & Action ──
        sec_apply = _FpkeCanControlPanel._compact_section(Section())
        sec_apply.body.setSpacing(4)
        sec_apply.set_text(
            tr("3. Что перенести в текущий дамп", "3. Data to transfer into current dump"),
        )
        sec_apply.head.addWidget(
            status_readout(
                tr("Калибровки и кодировка цели сохраняются", "Target calibration & coding preserved"),
                "muted",
            ),
            0,
            Qt.AlignmentFlag.AlignVCenter,
        )

        im_d = (donor_passport or {}).get("immo") or {}
        meta_d = (donor_passport or {}).get("cluster_metadata") or {}
        cnt_d = im_d.get("counts") or {}
        cp_d = (donor_passport or {}).get("component_protection_separate") or {}

        def _xfer_option_row(
            checked: bool,
            title_txt: str,
            preview_txt: str,
            on_toggle: Callable[[bool], None],
        ) -> QWidget:
            strip = QFrame()
            strip.setObjectName("ResultStrip")
            rl = QHBoxLayout(strip)
            rl.setContentsMargins(10, 3, 10, 3)
            rl.setSpacing(10)
            chk = QCheckBox(title_txt)
            chk.setChecked(checked)
            chk.toggled.connect(on_toggle)
            lbl_p = QLabel(preview_txt)
            lbl_p.setFont(mono_font(11))
            lbl_p.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            set_tone(lbl_p, "info" if donor_passport is not None else "muted")
            lbl_p.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            rl.addWidget(chk, 0)
            rl.addWidget(lbl_p, 1)
            return strip

        prev_immo = (
            f"→ VIN: {im_d.get('vin') or '—'}  •  PC: {im_d.get('power_class_hex') or '—'}  •  MAC4: {im_d.get('mac4') or '—'}"
            if donor_passport
            else tr("VIN, CS/Kc, Power Class, VDO CS+, MAC (DASH / ECU / TCU / ELV)", "VIN, CS/Kc, Power Class, VDO CS+, MAC IDs")
        )
        sec_apply.body.addWidget(
            _xfer_option_row(
                self._xfer_immo,
                tr("Иммобилайзер (VIN, CS, Power Class, MAC)", "Immobilizer (VIN, CS, Power Class, MAC)"),
                prev_immo,
                lambda v: setattr(self, "_xfer_immo", bool(v)),
            )
        )

        active_d_keys = [k for k in (im_d.get("keys") or []) if k]
        prev_keys = (
            tr(
                f"{cnt_t.get('learned_keys', 0)} кл. → {cnt_d.get('learned_keys', 0)}/{cnt_d.get('allowed_keys', 8)} ({', '.join(active_d_keys[:3]) or '—'})",
                f"{cnt_t.get('learned_keys', 0)} keys → {cnt_d.get('learned_keys', 0)}/{cnt_d.get('allowed_keys', 8)} ({', '.join(active_d_keys[:3]) or '—'})",
            )
            if donor_passport
            else tr("8 слотов ID транспондеров и счётчики ключей", "8 transponder ID slots and key counters")
        )
        sec_apply.body.addWidget(
            _xfer_option_row(
                self._xfer_keys,
                tr("Ключи автомобиля (8 слотов и счётчики)", "Vehicle keys (8 slots & counters)"),
                prev_keys,
                lambda v: setattr(self, "_xfer_keys", bool(v)),
            )
        )

        d_odo_val = meta_d.get("odometer_km")
        d_odo_preview = f"{int(d_odo_val):,} км".replace(",", " ") if d_odo_val is not None else "—"
        prev_odo = (
            f"{t_odo_str}  →  {d_odo_preview}"
            if donor_passport
            else tr("Синхронизация 3 копий пробега и сброс ошибок счётчика", "Synchronize 3 odometer copies & clear error counter")
        )
        sec_apply.body.addWidget(
            _xfer_option_row(
                self._xfer_odo,
                tr("Пробег со старой панели приборов", "Odometer from donor cluster"),
                prev_odo,
                lambda v: setattr(self, "_xfer_odo", bool(v)),
            )
        )

        prev_cp = (
            f"IKA: {(cp_d.get('ika_cp3') or '—')[:16]}…  •  SAFE CP → 0"
            if donor_passport
            else tr("Опционально: ключи IKA (J533) и GFA /1 (BCM 09 / 0x0E)", "Optional: IKA (J533) and GFA /1 (BCM 09 / 0x0E) keys")
        )
        sec_apply.body.addWidget(
            _xfer_option_row(
                self._xfer_cp,
                tr("Защита компонентов (ключи IKA / GFA)", "Component Protection (IKA / GFA keys)"),
                prev_cp,
                lambda v: setattr(self, "_xfer_cp", bool(v)),
            )
        )

        btn_write_xfer = button(
            tr("Перенести и записать", "Transfer & write"),
            "PrimaryBtn",
            slot=self.apply_and_write_donor_transfer,
        )
        btn_write_xfer.setEnabled(donor_passport is not None and not self.runner.is_busy)
        btn_exec_xfer = button(
            tr("В дамп", "To dump"),
            slot=self.apply_donor_transfer_to_current,
        )
        btn_exec_xfer.setEnabled(donor_passport is not None)
        footer_btns: list[QWidget] = [btn_write_xfer, btn_exec_xfer]
        if donor_passport is not None:
            btn_cmp_pair = button(
                tr("Сверить…", "Compare…"),
                "GhostBtn",
                slot=lambda: self.compare_immo_with_file(),
            )
            footer_btns.append(btn_cmp_pair)
        if self._donor_dflash is not None:
            btn_plan_rep = button(
                tr("План…", "Plan…"),
                "GhostBtn",
                slot=self.show_transfer_plan_dialog,
            )
            footer_btns.append(btn_plan_rep)
        foot_lay = sec_apply.add_footer(*footer_btns)
        sec_apply.body.setContentsMargins(14, 3, 14, 4)
        foot_lay.setContentsMargins(14, 2, 14, 10)
        lay.addWidget(sec_apply)

    # ────────────────────────────── Page 5: MCU & FD11 Access ──────────────────────────────

    def _build_extra_page(self, lay: QVBoxLayout) -> None:
        by_id = {it["key_id"]: it for it in (self.dflash_info or {}).get("items", [])}
        has_fd11 = "fd11_l0_6" in by_id or "fd11_l7" in by_id

        if not self.extra_info and not has_fd11:
            empty = Callout("info")
            empty.label.setText(
                tr(
                    "Область конфигурации <b>Extra Area</b> и ключи <b>FD11</b> ещё не загружены.",
                    "The <b>Extra Area</b> MCU configuration and <b>FD11</b> keys are not loaded yet.",
                )
            )
            lay.addWidget(empty)
            return

        if self.extra_info:
            ex = self.extra_info
            sec_ex = _FpkeCanControlPanel._compact_section(Section())
            sec_ex.set_text(
                tr("Параметры защиты процессора RH850 (Extra Area)", "RH850 MCU security parameters (Extra Area)"),
            )
            grid = QGridLayout()
            grid.setHorizontalSpacing(20)
            grid.setVerticalSpacing(4)

            rows_data: list[tuple[str, str, str]] = [
                ("IDCODE", ex.get("idcode_spaced", "—"), ""),
            ]
            if self.idauth_info and self.idauth_info.get("idst_after_idcode") is not None:
                ok = self.idauth_info["idst_after_idcode"] == "00000000"
                rows_data.append(
                    (
                        tr("Аппаратная проверка IDCODE", "Hardware IDCODE check"),
                        tr("подтверждён процессором", "verified by MCU") if ok else tr("отклонён", "rejected"),
                        "ok" if ok else "err",
                    )
                )
            rows_data.extend(
                [
                    (tr("Режим защиты", "Protection mode"), _human_protection_mode(ex.get("protection_mode", "")), ""),
                    (
                        tr("Последовательное программирование", "Serial programming"),
                        tr("разрешено", "enabled") if ex.get("serial_programming_enabled") else tr("запрещено", "disabled"),
                        "ok" if ex.get("serial_programming_enabled") else "warn",
                    ),
                    (
                        tr("Слово защиты и OPBT0", "Security word & OPBT0"),
                        f"{ex.get('security_raw', '—')}   •   OPBT0: {ex.get('opbt0', '—')}",
                        "",
                    ),
                ]
            )

            for r, (k, v, tone) in enumerate(rows_data):
                lbl_k = QLabel(k)
                lbl_k.setObjectName("FieldKey")
                lbl_v = QLabel(str(v))
                if r == 0 or v.startswith("0x"):
                    lbl_v.setFont(mono_font(12, bold=(r == 0)))
                lbl_v.setWordWrap(True)
                lbl_v.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
                lbl_v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                if tone:
                    set_tone(lbl_v, tone)
                grid.addWidget(lbl_k, r, 0)
                grid.addWidget(lbl_v, r, 1)
            grid.setColumnStretch(1, 1)
            sec_ex.body.addLayout(grid)
            lay.addWidget(sec_ex)

        if has_fd11 and self.dflash_info:
            sec_fd = _FpkeCanControlPanel._compact_section(Section())
            sec_fd.set_text(
                tr("Диагностический доступ поставщика FD11 (EEL 0x63)", "Continental FD11 vendor diagnostic access (EEL 0x63)"),
            )
            fd_grid = QGridLayout()
            fd_grid.setHorizontalSpacing(16)
            fd_grid.setVerticalSpacing(4)
            fd_rows: list[tuple[str, str, bool | None]] = []
            if "fd11_l0_6" in by_id:
                im = by_id["fd11_l0_6"]
                fd_rows.append((tr("Ключ FD11 (уровни 0..6)", "FD11 key (levels 0..6)"), im["hex"].upper(), im.get("crc_valid")))
            if "fd11_l7" in by_id:
                im = by_id["fd11_l7"]
                fd_rows.append((tr("Ключ FD11 (уровень 7)", "FD11 key (level 7)"), im["hex"].upper(), im.get("crc_valid")))
            fd11_id = self.dflash_info.get("fd11_identifier")
            if fd11_id:
                fd_rows.append((tr("Идентификатор FD11", "FD11 identifier"), fd11_id.upper(), None))

            for r, (label, val_hex, crc_ok) in enumerate(fd_rows):
                lk = QLabel(label)
                lk.setObjectName("FieldKey")
                lv = QLabel(val_hex)
                lv.setFont(mono_font(12, bold=(r == 0)))
                lv.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                fd_grid.addWidget(lk, r, 0)
                fd_grid.addWidget(lv, r, 1)
                if crc_ok is not None:
                    lc = QLabel(tr("CRC верна", "CRC valid") if crc_ok else tr("ошибка CRC", "CRC error"))
                    lc.setObjectName("Hint")
                    set_tone(lc, "ok" if crc_ok else "err")
                    fd_grid.addWidget(lc, r, 2, Qt.AlignmentFlag.AlignLeft)
            fd_grid.setColumnStretch(2, 1)
            sec_fd.body.addLayout(fd_grid)
            lay.addWidget(sec_fd)

    # ────────────────────────────── Page 4: Memory Read ──────────────────────────────

    def _build_read_page(self, lay: QVBoxLayout) -> None:
        busy = self.runner.is_busy
        iface = self.conn.interface or "slcan"
        blocker = self._memory_blocker()
        native_ok = blocker is None

        if blocker:
            warn = Callout("err")
            if blocker == "gateway":
                warn.label.setText(
                    tr(
                        "<b>Чтение памяти уровня 8 через этот шлюз недоступно.</b> "
                        "Для прозрачного RAM-моста требуется шлюз Continental 3Q0 907 530 и адаптер с произвольным "
                        "raw CAN (CANable / SLCAN / candleLight или VNCI, принимающий в RawMode все идентификаторы), "
                        "либо прямое подключение к CAN приборной панели (T18).",
                        "<b>Level-8 memory access is unavailable through this gateway.</b> "
                        "Transparent RAM-bridging requires a Continental 3Q0 907 530 gateway and an adapter with "
                        "arbitrary raw CAN (CANable / SLCAN / candleLight, or a VNCI whose RawMode receives every "
                        "identifier), or a direct connection to the cluster CAN bus (T18).",
                    )
                )
            elif self.via_gateway:
                warn.label.setText(
                    tr(
                        f"<b>Выбран адаптер «{iface}».</b> Для чтения приборной панели через шлюз J533 нужен адаптер "
                        "с произвольным raw CAN (CANable / SLCAN / candleLight или VAS 6154 / VNCI).",
                        f"<b>Adapter “{iface}” is selected.</b> Reading this instrument cluster through the J533 gateway "
                        "requires an adapter with arbitrary raw CAN (CANable / SLCAN / candleLight, or a VAS 6154 / VNCI).",
                    )
                )
            else:
                warn.label.setText(
                    tr(
                        f"<b>Выбран адаптер «{iface}».</b> Для чтения приборной панели требуется нативный CAN-адаптер "
                        "(CANable / SLCAN / candleLight).",
                        f"<b>Adapter “{iface}” is selected.</b> Reading this instrument cluster requires a native CAN adapter "
                        "(CANable / SLCAN / candleLight).",
                    )
                )
            lay.addWidget(warn)

        sec_full = Section()
        sec_full.set_text(
            tr("Чтение памяти блока", "Read ECU memory"),
            tr(
                "Считывает DataFlash (64 КБ) и конфигурацию процессора Extra Area (256 Б). В память блока ничего не записывается.",
                "Reads DataFlash (64 KB) and the MCU configuration Extra Area (256 B). Nothing is written to flash.",
            ),
        )
        if self.via_gateway and native_ok:
            gw_badge = status_readout(
                tr(
                    f"Через шлюз J533 (RAM-мост ch{self.gateway_channel})",
                    f"Via J533 gateway (RAM-Bridge ch{self.gateway_channel})",
                ),
                "ok",
            )
            gw_badge.setToolTip(
                tr(
                    "На время чтения или записи памяти шлюз J533 автоматически переводится в прозрачный двунаправленный "
                    "CAN-мост (Diagnosis CAN ↔ Komfort CAN), а по завершении возвращается в штатный режим.",
                    "During memory read or write, the J533 gateway automatically acts as a transparent bidirectional "
                    "CAN bridge (Diagnosis CAN ↔ Komfort CAN) and returns to Application mode on completion.",
                )
            )
            sec_full.head.addWidget(gw_badge, 0, Qt.AlignmentFlag.AlignVCenter)

        opts = QGridLayout()
        opts.setHorizontalSpacing(24)
        opts.setVerticalSpacing(6)

        chk_stream = QCheckBox(tr("Ускоренное чтение по CAN", "Fast CAN streaming"))
        chk_stream.setChecked(self._opt_stream)
        chk_stream.toggled.connect(lambda v: setattr(self, "_opt_stream", bool(v)))

        chk_uf = QCheckBox(tr("Uflash (32 КБ)", "Uflash (32 KB)"))
        chk_uf.setChecked(self._opt_uflash)
        chk_uf.toggled.connect(lambda v: setattr(self, "_opt_uflash", bool(v)))

        chk_bf = QCheckBox(tr("Bflash (96 КБ)", "Bflash (96 KB)"))
        chk_bf.setChecked(self._opt_bflash)
        chk_bf.toggled.connect(lambda v: setattr(self, "_opt_bflash", bool(v)))

        chk_cf = QCheckBox(tr("CodeFlash (2 МБ)", "CodeFlash (2 MB)"))
        chk_cf.setChecked(self._opt_cflash)
        chk_cf.toggled.connect(lambda v: setattr(self, "_opt_cflash", bool(v)))

        opts.addWidget(chk_stream, 0, 0)
        opts.addWidget(chk_uf, 0, 1)
        opts.addWidget(chk_bf, 1, 0)
        opts.addWidget(chk_cf, 1, 1)
        opts.setColumnStretch(2, 1)
        sec_full.body.addLayout(opts)

        btn_full = button(
            tr("Считать блок", "Read the ECU"),
            "PrimaryBtn",
            slot=self._run_full_read,
        )
        btn_full.setEnabled(not busy and native_ok)
        btn_write_cur = button(
            tr("Записать в блок", "Write to ECU"),
            slot=self.write_dflash_to_ecu,
        )
        btn_write_cur.setEnabled(not busy and native_ok and self.dflash_info is not None)
        btn_restore_file = button(
            tr("Залить бэкап…", "Write backup…"),
            "GhostBtn",
            slot=self.restore_dflash_from_file,
        )
        btn_restore_file.setEnabled(not busy and native_ok)
        sec_full.add_footer(btn_full, btn_write_cur, btn_restore_file)
        lay.addWidget(sec_full)

        sec_ind = Section()
        sec_ind.set_text(tr("Отдельные области памяти", "Individual memory areas"))
        btn_df = button(
            tr("DataFlash (64 КБ)", "DataFlash (64 KB)"),
            slot=lambda: self._run_region_read("dflash", use_stream=False),
        )
        btn_ex = button(
            tr("Extra Area (256 Б)", "Extra Area (256 B)"),
            slot=lambda: self._run_region_read("extra", use_stream=False),
        )
        btn_uf = button(
            tr("Uflash (32 КБ)", "Uflash (32 KB)"),
            slot=lambda: self._run_region_read("uflash", use_stream=self._opt_stream),
        )
        btn_bf = button(
            tr("Bflash (96 КБ)", "Bflash (96 KB)"),
            slot=lambda: self._run_region_read("bflash", use_stream=self._opt_stream),
        )
        btn_cf = button(
            tr("CodeFlash (2 МБ)", "CodeFlash (2 MB)"),
            slot=lambda: self._run_region_read("cflash", use_stream=self._opt_stream),
        )
        for b in (btn_df, btn_ex, btn_uf, btn_bf, btn_cf):
            b.setEnabled(not busy and native_ok)
        ind_grid = QGridLayout()
        ind_grid.setHorizontalSpacing(8)
        ind_grid.setVerticalSpacing(8)
        ind_grid.addWidget(btn_df, 0, 0)
        ind_grid.addWidget(btn_ex, 0, 1)
        ind_grid.addWidget(btn_uf, 0, 2)
        ind_grid.addWidget(btn_bf, 1, 0)
        ind_grid.addWidget(btn_cf, 1, 1)
        ind_grid.setColumnStretch(3, 1)
        sec_ind.body.addLayout(ind_grid)
        lay.addWidget(sec_ind)

    # ────────────────────────────── Actions ──────────────────────────────

    def _run_full_read(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        ident_list = list(self.ident_items or [{"did": "F187", "value": self.part_number}])
        sdir = new_session(
            self.conn.out_dir,
            unit_of_ident(ident_list),
            "fpke_read",
            dumps=True,
        )
        use_stream = self._opt_stream
        read_uf = self._opt_uflash
        read_bf = self._opt_bflash
        read_cf = self._opt_cflash

        via_gw = self.via_gateway
        gw_bridge = self.gateway_bridge
        gw_ch = self.gateway_channel

        def task(rep: Any) -> dict[str, Any]:
            return can_fpke_full_read(
                port,
                interface=iface,
                session_dir=sdir,
                use_stream=use_stream,
                read_uflash=read_uf,
                read_bflash=read_bf,
                read_cflash=read_cf,
                ident=ident_list,
                keep_open=not via_gw,
                via_gateway=via_gw,
                gateway_bridge=gw_bridge,
                gateway_channel=gw_ch,
                reporter=rep,
            )

        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self) or not self.is_open:
                return
            out_folder = Path(str(res.get("session_dir", sdir)))
            detected = detect_fpke_files([out_folder])
            self.idauth_info = res.get("idauth")
            self.open_from_files(
                detected,
                folder=out_folder,
                source="can",
                via_gateway=via_gw,
                gateway_bridge=gw_bridge,
                gateway_channel=gw_ch,
            )

        self.runner.run_task(
            tr("Чтение памяти блока", "Reading the ECU memory"),
            task,
            on_success=lambda res: QTimer.singleShot(0, lambda: done(res)),
        )

    def _run_region_read(self, mode: str, *, use_stream: bool = False) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface = self.conn.port, self.conn.interface
        sdir = new_session(
            self.conn.out_dir,
            unit_of_ident(self.ident_items or [{"did": "F187", "value": self.part_number}]),
            f"fpke_{mode}",
            dumps=True,
        )
        via_gw = self.via_gateway
        gw_bridge = self.gateway_bridge
        gw_ch = self.gateway_channel

        def task(rep: Any) -> dict[str, Any]:
            return can_fpke_read_region(
                port,
                mode=mode,
                interface=iface,
                session_dir=sdir,
                use_stream=use_stream,
                keep_open=not via_gw,
                via_gateway=via_gw,
                gateway_bridge=gw_bridge,
                gateway_channel=gw_ch,
                reporter=rep,
            )

        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self) or not self.is_open:
                return
            out_folder = Path(str(res.get("session_dir", sdir)))
            detected = detect_fpke_files([out_folder])
            merged = dict(self.files)
            merged.update(detected)
            self.open_from_files(
                merged,
                folder=out_folder,
                source="can",
                via_gateway=via_gw,
                gateway_bridge=gw_bridge,
                gateway_channel=gw_ch,
            )

        self.runner.run_task(
            tr(f"Чтение области {mode.upper()}", f"Reading {mode.upper()} area"),
            task,
            on_success=lambda res: QTimer.singleShot(0, lambda: done(res)),
        )

    def _adopt_written_session(self, res: dict[str, Any], fallback_dir: Path) -> None:
        if not _qt_valid(self) or not self.is_open:
            return
        old_work = self._working_dflash_path
        if old_work is not None and old_work != self._orig_dflash_path and old_work.parent.name == "ContiTool_edited":
            with contextlib.suppress(OSError):
                old_work.unlink()
        out_folder = Path(str(res.get("session_dir", fallback_dir)))
        rb_path = out_folder / "Dflash.bin"
        if not rb_path.is_file():
            rb_path = out_folder / "Dflash_readback.bin"
        if rb_path.is_file():
            rb_bytes = rb_path.read_bytes()
            self._orig_dflash_path = rb_path
            self._orig_dflash_bytes = rb_bytes
            self._working_dflash_path = rb_path
            self._working_dflash_bytes = rb_bytes
            self.files["dflash"] = rb_path
            self.dflash_info = analyze_fpke_dflash(rb_bytes, self._cflash_bytes)
        ex_path = out_folder / "ExtraArea.bin"
        if ex_path.is_file():
            ex_bytes = ex_path.read_bytes()
            self.extra_raw = ex_bytes
            self.extra_info = analyze_fpke_extra_area(ex_bytes)
            self.files["extra"] = ex_path
        if isinstance(res.get("idauth"), dict):
            self.idauth_info = res["idauth"]
        new_ident = res.get("ident")
        if isinstance(new_ident, list) and new_ident:
            by_did = {it.get("did"): dict(it) for it in self.ident_items if it.get("did")}
            for it in new_ident:
                if isinstance(it, dict) and it.get("did"):
                    by_did[it["did"]] = dict(it)
            if self.ident_items:
                seen: set[str] = set()
                merged_ident: list[dict[str, str]] = []
                for it in self.ident_items:
                    d = it.get("did", "")
                    if d in by_did:
                        merged_ident.append(by_did[d])
                        seen.add(d)
                for d, it in by_did.items():
                    if d and d not in seen:
                        merged_ident.append(it)
                self.ident_items = merged_ident
            else:
                self.ident_items = list(new_ident)
        self.folder = out_folder
        self.source = "can"
        self.refresh()
        self.changed.emit()
        blks = int(res.get("blocks_written", 0))
        erased = int(res.get("blocks_erased", 0))
        short_s = res.get("short_summary") or "DataFlash"
        self.note.emit(
            tr(
                f"Запись в приборную панель завершена и проверена: {short_s} ({blks} бл., стёрто {erased}).",
                f"Cluster write completed & verified: {short_s} ({blks} blocks, erased {erased}).",
            )
        )

    def write_dflash_to_ecu(self, *, confirm: bool = True) -> None:
        """Commit any pending form edits on the current tab and write the working DataFlash to the cluster over CAN."""
        if self.runner.is_busy:
            return
        if self._page_commit_fn is not None:
            if not self._page_commit_fn(True):
                return
        cand_bytes, cf_bytes = self._own_dflash_and_cflash()
        if cand_bytes is None:
            QMessageBox.information(
                self,
                tr("Нет данных для записи", "No DataFlash loaded"),
                tr("Сначала считайте приборную панель или откройте дамп DataFlash.", "Read the cluster or open a DataFlash dump first."),
            )
            return

        orig_bytes = self._orig_dflash_bytes if self._orig_dflash_bytes is not None else cand_bytes
        chg = summarize_fpke_dflash_changes(orig_bytes, cand_bytes, cf_bytes)
        full_rewrite = not bool(chg.get("changed"))

        if not ensure_ready(self.conn, self):
            return
        if self._write_blocked():
            return
        iface = self.conn.interface or "slcan"

        if confirm:
            bullets = "\n".join(f"  • {line}" for line in (chg.get("lines") or []))
            if not bullets:
                bullets = tr(
                    "  • Полная перезапись текущего образа DataFlash (64 КБ)",
                    "  • Full rewrite of current DataFlash image (64 KB)",
                )
            prompt_txt = tr(
                f"Записать следующие изменения в приборную панель {self.part_number} по CAN?\n\n"
                f"{bullets}\n\n"
                "Перед записью ContiTool автоматически сохранит резервную копию текущего DataFlash "
                "(Dflash_before.bin), выполнит побайтовую проверку и перезапустит панель. "
                "Не отключайте питание +12 В до завершения.",
                f"Write the following changes to instrument cluster {self.part_number} over CAN?\n\n"
                f"{bullets}\n\n"
                "ContiTool will automatically save a live DataFlash backup (Dflash_before.bin) before writing, "
                "verify every written block, and reboot the cluster. Keep +12 V power connected.",
            )
            ans = QMessageBox.question(
                self,
                tr("Запись в приборную панель", "Write to instrument cluster"),
                prompt_txt,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        port = self.conn.port
        ident_list = list(self.ident_items or [{"did": "F187", "value": self.part_number}])
        sdir = new_session(
            self.conn.out_dir,
            unit_of_ident(ident_list),
            "fpke_write",
            dumps=True,
        )

        via_gw = self.via_gateway
        gw_bridge = self.gateway_bridge
        gw_ch = self.gateway_channel

        def task(rep: Any) -> dict[str, Any]:
            return can_fpke_write_dflash(
                port,
                cand_bytes,
                interface=iface,
                base_dflash=None if full_rewrite else orig_bytes,
                cflash_bytes=cf_bytes,
                session_dir=sdir,
                wake_seconds=self._wake_seconds,
                full_rewrite=full_rewrite,
                reset_after=True,
                keep_open=not via_gw,
                via_gateway=via_gw,
                gateway_bridge=gw_bridge,
                gateway_channel=gw_ch,
                reporter=rep,
            )

        self.runner.run_task(
            tr("Запись изменений в приборную панель", "Writing changes to instrument cluster"),
            task,
            on_success=lambda res: QTimer.singleShot(0, lambda: self._adopt_written_session(res, sdir)),
        )

    def restore_dflash_from_file(self, path: Path | None = None, *, confirm: bool = True) -> None:
        """Write a saved 64 KiB DataFlash backup file to the cluster over CAN (`full_rewrite=True`)."""
        if self.runner.is_busy:
            return
        if path is None:
            picked, _ = QFileDialog.getOpenFileName(
                self,
                tr("Выберите бэкап DataFlash (64 КБ) для записи в приборную панель", "Select DataFlash backup (64 KB) to write to cluster"),
                str(self.folder.parent if self.folder else self.conn.out_dir),
                "DataFlash 64 KB (*.bin);;All files (*)",
            )
            if not picked:
                return
            path = Path(picked)

        try:
            raw = path.read_bytes()
        except OSError as exc:
            QMessageBox.warning(self, tr("Ошибка чтения файла", "File read error"), str(exc))
            return
        if not is_fpke_dflash(raw):
            QMessageBox.warning(
                self,
                tr("Некорректный файл DataFlash", "Invalid DataFlash file"),
                tr(
                    f"Файл «{path.name}» ({len(raw)} Б) не является валидным 64 КБ дампом DataFlash FPK_E.",
                    f"File “{path.name}” ({len(raw)} B) is not a valid 64 KB FPK_E DataFlash dump.",
                ),
            )
            return

        if not ensure_ready(self.conn, self):
            return
        if self._write_blocked():
            return
        iface = self.conn.interface or "slcan"

        _, cf_bytes = self._own_dflash_and_cflash()
        if confirm:
            prompt_txt = tr(
                f"Записать бэкап DataFlash из файла «{path.name}» ({path.parent.name}) в приборную панель {self.part_number}?\n\n"
                "Перед записью текущий DataFlash панели будет автоматически сохранён в Dflash_before.bin.",
                f"Write DataFlash backup from “{path.name}” ({path.parent.name}) to cluster {self.part_number}?\n\n"
                "The cluster's current DataFlash will be backed up to Dflash_before.bin before writing.",
            )
            ans = QMessageBox.question(
                self,
                tr("Залить бэкап DataFlash", "Write DataFlash backup"),
                prompt_txt,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        port = self.conn.port
        ident_list = list(self.ident_items or [{"did": "F187", "value": self.part_number}])
        sdir = new_session(
            self.conn.out_dir,
            unit_of_ident(ident_list),
            "fpke_restore",
            dumps=True,
        )

        via_gw = self.via_gateway
        gw_bridge = self.gateway_bridge
        gw_ch = self.gateway_channel

        def task(rep: Any) -> dict[str, Any]:
            return can_fpke_write_dflash(
                port,
                raw,
                interface=iface,
                base_dflash=None,
                cflash_bytes=cf_bytes,
                session_dir=sdir,
                wake_seconds=self._wake_seconds,
                full_rewrite=True,
                reset_after=True,
                keep_open=not via_gw,
                via_gateway=via_gw,
                gateway_bridge=gw_bridge,
                gateway_channel=gw_ch,
                reporter=rep,
            )

        self.runner.run_task(
            tr("Запись бэкапа DataFlash в приборную панель", "Writing DataFlash backup to cluster"),
            task,
            on_success=lambda res: QTimer.singleShot(0, lambda: self._adopt_written_session(res, sdir)),
        )

    def _build_can_ctrl_page(self, lay: QVBoxLayout) -> None:
        panel = _FpkeCanControlPanel(
            self.conn,
            self.runner,
            self,
            part_number=self.part_number,
            initial_msg=self._can_status_msg,
            initial_tone=self._can_status_tone,
            initial_dtcs=self._last_dtcs or [],
            status_sink=self._record_can_status,
            dtcs_sink=self._record_can_dtcs,
            via_gateway=self.via_gateway,
            gateway_bridge=self.gateway_bridge,
            gateway_channel=self.gateway_channel,
        )
        panel.note.connect(self.note.emit)
        panel.state_changed.connect(self._refresh_nav)
        self._active_can_panel = panel
        lay.addWidget(panel)

    def open_coil_key_learn_dialog(self) -> None:
        if not self.dflash_info:
            return

        def _on_s0_s1_cached(s0_hex: str, s1_hex: str) -> None:
            self._cached_s0_hex = s0_hex
            self._cached_s1_hex = s1_hex

        def _on_learned_keys_synced(learned_ids: list[str], learned_cnt: int, allowed_cnt: int) -> None:
            df_cur, cf_cur = self._own_dflash_and_cflash()
            if df_cur is None or not learned_ids:
                return
            padded_ids = list(learned_ids[:8]) + [""] * max(0, 8 - len(learned_ids))
            with contextlib.suppress(Exception):
                new_df = apply_fpke_dflash_edits(
                    df_cur,
                    key_display_ids=padded_ids,
                    learned_keys=learned_cnt,
                    allowed_keys=allowed_cnt,
                    slot_s0_hex="FF" * 16,
                    slot_s1_hex="FF" * 16,
                    immo_mode=1,
                    cflash=cf_cur,
                )
                self._commit_dflash_bytes(
                    new_df,
                    tr(
                        f"Список обученных через катушку ключей ({learned_cnt} шт.) синхронизирован с рабочей копией дампа.",
                        f"Coil-learned key list ({learned_cnt} keys) synchronized with working dump.",
                    ),
                )

        dlg = FpkeCoilKeyLearnDialog(
            self.conn,
            self.runner,
            dflash_info=self.dflash_info,
            part_number=self.part_number,
            initial_s0_hex=self._cached_s0_hex,
            initial_s1_hex=self._cached_s1_hex,
            on_s0_s1_cached=_on_s0_s1_cached,
            on_learned_keys_synced=_on_learned_keys_synced,
            via_gateway=self.via_gateway,
            gateway_bridge=self.gateway_bridge,
            gateway_channel=self.gateway_channel,
            parent=self.window(),
        )
        dlg.note.connect(self.note.emit)
        run_dialog(dlg)


class _ToggleSwitch(QAbstractButton):
    """Crisp antialiased vector toggle switch for continuous bench signals (KL15, drive simulation)."""

    def __init__(self, active_color: str = theme.OK, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._active_color = active_color
        self.setCheckable(True)
        self.setFixedSize(40, 22)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def sizeHint(self) -> QSize:  # noqa: N802 (Qt override)
        return QSize(40, 22)

    def paintEvent(self, _event: Any) -> None:  # noqa: N802 (Qt override)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        if not self.isEnabled():
            p.setOpacity(0.45)

        on = self.isChecked()
        hover = self.underMouse()
        track = QRectF(1.0, 1.0, self.width() - 2.0, self.height() - 2.0)
        radius = track.height() / 2.0

        bg = QColor(self._active_color if on else ("#292D37" if hover else "#1F222A"))
        border = QColor(self._active_color if on else ("#4A5060" if hover else "#343946"))
        p.setPen(QPen(border, 1.1))
        p.setBrush(bg)
        p.drawRoundedRect(track, radius, radius)

        knob_d = track.height() - 4.4
        knob_x = (track.right() - knob_d - 2.2) if on else (track.left() + 2.2)
        knob_y = track.center().y() - knob_d / 2.0
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#FFFFFF" if on else "#B8BEC9"))
        p.drawEllipse(QRectF(knob_x, knob_y, knob_d, knob_d))
        p.end()


class FpkeDtcDialog(Dialog):
    """Structured human-readable trouble-code viewer for Continental FPK_E instrument clusters."""

    cleared = Signal(str)

    def __init__(
        self,
        dtcs: list[dict[str, Any]],
        *,
        part_number: str = "83A920700E",
        clear_callback: Callable[[], str | None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        active = [d for d in dtcs if d.get("active")]
        stored = [d for d in dtcs if not d.get("active")]
        subtitle = tr(
            f"{part_number} • Активных: {len(active)}, в памяти: {len(stored)}",
            f"{part_number} • Active: {len(active)}, stored: {len(stored)}",
        )
        super().__init__(parent, tr("Ошибки блока", "Fault codes"), subtitle, width=720)
        self._dtcs = list(dtcs)
        self._clear_callback = clear_callback
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.body.setContentsMargins(22, 16, 22, 14)
        self.body.setSpacing(10)

        if active:
            self.body.addWidget(
                self._build_dtc_group(
                    tr("Активные — неисправность присутствует сейчас", "Active — fault present now"),
                    active,
                    is_active=True,
                )
            )
        if stored:
            self.body.addWidget(
                self._build_dtc_group(
                    tr("Сохранённые — неисправность была ранее", "Stored — fault occurred earlier"),
                    stored,
                    is_active=False,
                )
            )

        btn_copy = button(tr("Копировать", "Copy"), slot=self._copy_all)
        left_btns: list[QWidget] = [btn_copy]
        if clear_callback is not None:
            self.btn_clear = button(tr("Сбросить ошибки", "Clear codes"), "DangerBtn", slot=self._on_clear)
            left_btns.append(self.btn_clear)
        self.finish(*left_btns, cancel_text=tr("Закрыть", "Close"))
        self.resize(740, min(580, max(340, self.height() + 8)))
        self._fit_screen()

    @staticmethod
    def _build_dtc_group(title: str, items: list[dict[str, Any]], *, is_active: bool) -> QWidget:
        sec = Section()
        sec.head.setContentsMargins(16, 10, 16, 4)
        sec.body.setContentsMargins(0, 2, 0, 8)
        sec.body.setSpacing(0)
        sec.set_text(title)

        for idx, item in enumerate(items):
            row_f = QFrame()
            row_f.setObjectName("TableRow")
            if idx == len(items) - 1:
                row_f.setProperty("last", True)
            rl = QHBoxLayout(row_f)
            rl.setContentsMargins(16, 7, 16, 7)
            rl.setSpacing(12)

            lbl_code = QLabel(str(item.get("display") or item.get("code") or "—"))
            lbl_code.setFont(mono_font(12, bold=True))
            lbl_code.setFixedWidth(78)
            lbl_code.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            set_tone(lbl_code, "warn" if is_active else "muted")

            lbl_desc = QLabel(str(item.get("description") or "—"))
            lbl_desc.setWordWrap(True)
            lbl_desc.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            lbl_desc.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

            raw_code = str(item.get("code") or "").replace("0x", "")
            st_lbl = QLabel(raw_code)
            st_lbl.setFont(mono_font(11))
            set_tone(st_lbl, "muted")
            if item.get("status_text"):
                row_f.setToolTip(f"{item['status_text']} ({item.get('code', '')})")

            rl.addWidget(lbl_code, 0, Qt.AlignmentFlag.AlignTop)
            rl.addWidget(lbl_desc, 1)
            rl.addWidget(st_lbl, 0, Qt.AlignmentFlag.AlignTop)
            sec.body.addWidget(row_f)
        return sec

    def format_plain_text(self) -> str:
        lines: list[str] = []
        for d in self._dtcs:
            tag = tr("Активна", "Active") if d.get("active") else tr("В памяти", "Stored")
            disp = d.get("display") or d.get("code") or "—"
            desc = d.get("description") or ""
            lines.append(f"[{tag}] {disp} ({d.get('code', '')}) — {desc}")
        return "\n".join(lines)

    def _copy_all(self) -> None:
        cb = QGuiApplication.clipboard()
        if cb is not None:
            cb.setText(self.format_plain_text())

    def _on_clear(self) -> None:
        if self._clear_callback is None:
            return
        msg = self._clear_callback()
        if msg:
            self.cleared.emit(msg)
            self.accept()


class _FpkeCanControlPanel(QWidget):
    """Structured bench console for FPK_E: KL15 & gauge generator, spatial MFL steering pad, CAN sender, and inspector procedures."""

    note = Signal(str)
    state_changed = Signal()

    def __init__(
        self,
        conn: CanConnection,
        runner: OperationRunner,
        parent: QWidget | None = None,
        *,
        part_number: str = "83A920700E",
        initial_msg: str = "",
        initial_tone: str = "muted",
        initial_dtcs: list[dict[str, Any]] | None = None,
        status_sink: Callable[[str, str], None] | None = None,
        dtcs_sink: Callable[[list[dict[str, Any]]], None] | None = None,
        via_gateway: bool = False,
        gateway_bridge: bool = False,
        gateway_channel: int = 0,
    ) -> None:
        super().__init__(parent)
        self.conn = conn
        self.runner = runner
        self._part_number = part_number
        self._last_msg = initial_msg
        self._last_tone = initial_tone
        self._status_sink = status_sink
        self._dtcs_sink = dtcs_sink
        self._last_dtcs: list[dict[str, Any]] = list(initial_dtcs or [])
        self._proc_buttons: list[QWidget] = []
        self._mfl_buttons: list[QWidget] = []
        self.via_gateway = bool(via_gateway)
        self.gateway_bridge = bool(gateway_bridge)
        self.gateway_channel = int(gateway_channel)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(7)

        lay.addWidget(self._build_bench_bar())

        mid = QHBoxLayout()
        mid.setContentsMargins(0, 0, 0, 0)
        mid.setSpacing(7)
        mid.addWidget(self._build_mfl_pad(), 0)
        mid.addWidget(self._build_packet_sender(), 1)
        lay.addLayout(mid)

        lay.addWidget(self._build_procedures_section())

        self._sweep_timer = QTimer(self)
        self._sweep_timer.setInterval(120)
        self._sweep_timer.timeout.connect(self._sync_sweep_readouts)
        self.runner.busy_changed.connect(self._on_runner_busy)

        self.sync_state()

    @staticmethod
    def _compact_section(sec: Section) -> Section:
        sec.head.setContentsMargins(14, 7, 14, 2)
        sec.body.setContentsMargins(14, 3, 14, 9)
        sec.body.setSpacing(6)
        return sec

    def _on_runner_busy(self, _busy: bool) -> None:
        self.sync_state()

    def sync_state(self) -> None:
        if not _qt_valid(self):
            return
        busy = self.runner.is_busy
        for b in self._proc_buttons:
            if _qt_valid(b):
                b.setEnabled(not busy)
        if _qt_valid(self.btn_send_pkt):
            self.btn_send_pkt.setEnabled(not busy)
        self._refresh_ui()

    def apply_external_status(self, text: str, tone: str) -> None:
        if not _qt_valid(self) or not _qt_valid(self.lbl_status):
            return
        self._last_msg = text
        self._last_tone = tone
        self.lbl_status.setText(text)
        set_tone(self.lbl_status, tone)
        self.strip_result.setVisible(bool(text))

    def apply_external_dtcs(self, dtcs: list[dict[str, Any]]) -> None:
        if not _qt_valid(self) or not _qt_valid(self.btn_dtc_details):
            return
        self._last_dtcs = list(dtcs)
        self.btn_dtc_details.setVisible(bool(self._last_dtcs))

    def _ensure_link(self):
        link = get_active_fpke_link(self.conn.port or None, self.conn.interface or None)
        if link is not None and link.via_gateway == self.via_gateway:
            return link
        if not ensure_ready(self.conn, self):
            return None
        if not _qt_valid(self):
            return None
        try:
            return open_or_reuse_fpke_link(
                self.conn.port,
                interface=self.conn.interface or "slcan",
                via_gateway=self.via_gateway,
            )
        except Exception as exc:
            self._set_status(str(exc), "err")
            return None

    def _set_status(self, text: str, tone: str = "info") -> None:
        self._last_msg = text
        self._last_tone = tone
        if self._status_sink is not None:
            self._status_sink(text, tone)
        if not _qt_valid(self) or not _qt_valid(self.lbl_status):
            return
        self.lbl_status.setText(text)
        set_tone(self.lbl_status, tone)
        self.strip_result.setVisible(bool(text))
        if text:
            self.note.emit(text)
        self._refresh_ui()
        self.state_changed.emit()

    # ── 1. Top Bench Power & Live Signal Generator Bar ──

    def _build_bench_bar(self) -> QWidget:
        sec = Section()
        sec.hide_head()
        sec.body.setContentsMargins(16, 10, 16, 10)
        sec.body.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(10)

        self.sw_kl15 = _ToggleSwitch(theme.OK)
        self.sw_kl15.clicked.connect(self._on_kl15_toggled)
        self.lbl_kl15_title = QLabel(tr("Зажигание (KL15)", "Ignition (KL15)"))
        self.lbl_kl15_title.setObjectName("FieldLabel")

        top.addWidget(self.sw_kl15, 0, Qt.AlignmentFlag.AlignVCenter)
        top.addWidget(self.lbl_kl15_title, 0, Qt.AlignmentFlag.AlignVCenter)

        sep1 = vdivider()
        sep1.setFixedHeight(18)
        top.addSpacing(6)
        top.addWidget(sep1, 0, Qt.AlignmentFlag.AlignVCenter)
        top.addSpacing(6)

        self.sw_drive = _ToggleSwitch(theme.ACCENT)
        self.sw_drive.clicked.connect(self._on_drive_toggled)
        self.lbl_drv_title = QLabel(tr("Эмуляция движения", "Drive simulation"))
        self.lbl_drv_title.setObjectName("FieldLabel")

        top.addWidget(self.sw_drive, 0, Qt.AlignmentFlag.AlignVCenter)
        top.addWidget(self.lbl_drv_title, 0, Qt.AlignmentFlag.AlignVCenter)
        top.addStretch(1)

        self.lbl_access_state = QLabel()
        self.lbl_access_state.setObjectName("StatusReadout")
        top.addWidget(self.lbl_access_state, 0, Qt.AlignmentFlag.AlignVCenter)
        sec.body.addLayout(top)

        sec.body.addWidget(divider())

        gauges = QHBoxLayout()
        gauges.setSpacing(8)

        lbl_spd = group_label(tr("СКОРОСТЬ", "SPEED"))
        self.sld_speed = QSlider(Qt.Orientation.Horizontal)
        self.sld_speed.setRange(0, 240)
        self.sld_speed.setSingleStep(5)
        self.sld_speed.setPageStep(20)
        self.sld_speed.setValue(0)
        self.sld_speed.setMinimumWidth(48)
        self.sld_speed.sliderMoved.connect(self._on_manual_gauge_moved)
        self.sld_speed.valueChanged.connect(self._update_gauge_labels)
        self.lbl_spd_val = QLabel("0 " + tr("км/ч", "km/h"))
        self.lbl_spd_val.setFont(mono_font(12, bold=True))
        self.lbl_spd_val.setFixedWidth(62)
        self.lbl_spd_val.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        sep2 = vdivider()
        sep2.setFixedHeight(14)

        lbl_rpm = group_label(tr("ТАХОМЕТР", "RPM"))
        self.sld_rpm = QSlider(Qt.Orientation.Horizontal)
        self.sld_rpm.setRange(0, 7000)
        self.sld_rpm.setSingleStep(100)
        self.sld_rpm.setPageStep(500)
        self.sld_rpm.setValue(800)
        self.sld_rpm.setMinimumWidth(48)
        self.sld_rpm.sliderMoved.connect(self._on_manual_gauge_moved)
        self.sld_rpm.valueChanged.connect(self._update_gauge_labels)
        self.lbl_rpm_val = QLabel("800 " + tr("об/м", "RPM"))
        self.lbl_rpm_val.setFont(mono_font(12, bold=True))
        self.lbl_rpm_val.setFixedWidth(68)
        self.lbl_rpm_val.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        self.btn_auto_sweep = button(tr("Автопрогон", "Auto sweep"), "Chip", slot=self._on_auto_sweep_clicked)
        self.btn_auto_sweep.setCheckable(True)
        self.btn_auto_sweep.setChecked(True)
        self.btn_auto_sweep.setCursor(Qt.CursorShape.PointingHandCursor)

        gauges.addWidget(lbl_spd)
        gauges.addWidget(self.sld_speed, 1)
        gauges.addWidget(self.lbl_spd_val)
        gauges.addWidget(sep2, 0, Qt.AlignmentFlag.AlignVCenter)
        gauges.addWidget(lbl_rpm)
        gauges.addWidget(self.sld_rpm, 1)
        gauges.addWidget(self.lbl_rpm_val)
        gauges.addWidget(self.btn_auto_sweep)
        sec.body.addLayout(gauges)
        return sec

    def _update_gauge_labels(self) -> None:
        self.lbl_spd_val.setText(f"{self.sld_speed.value()} " + tr("км/ч", "km/h"))
        self.lbl_rpm_val.setText(f"{self.sld_rpm.value()} " + tr("об/м", "RPM"))

    def _on_kl15_toggled(self, checked: bool) -> None:
        if not checked:
            link = get_active_fpke_link()
            if link is not None:
                link.set_kl15(False)
            self._sweep_timer.stop()
            self._set_status(tr("Зажигание KL15 выключено.", "KL15 ignition turned OFF."), "muted")
            return
        link = self._ensure_link()
        if not _qt_valid(self):
            return
        if link is None:
            self.sw_kl15.setChecked(False)
            return
        link.set_kl15(True)
        self._set_status(tr("Зажигание KL15 включено.", "KL15 ignition turned ON."), "ok")

    def _on_drive_toggled(self, checked: bool) -> None:
        if not checked:
            link = get_active_fpke_link()
            if link is not None:
                link.stop_drive_simulation()
            self._sweep_timer.stop()
            self._set_status(tr("Эмуляция движения остановлена.", "Drive simulation stopped."), "muted")
            return
        link = self._ensure_link()
        if not _qt_valid(self):
            return
        if link is None:
            self.sw_drive.setChecked(False)
            return
        auto = self.btn_auto_sweep.isChecked()
        link.set_drive_targets(
            speed_kmh=float(self.sld_speed.value()),
            rpm=float(self.sld_rpm.value()),
            auto_sweep=auto,
        )
        link.start_drive_simulation(auto_sweep=auto)
        if auto:
            self._sweep_timer.start()
        self._set_status(tr("Эмуляция движения запущена.", "Drive simulation started."), "ok")

    def _on_manual_gauge_moved(self, _val: int) -> None:
        if self.btn_auto_sweep.isChecked():
            self.btn_auto_sweep.setChecked(False)
        self._update_gauge_labels()
        link = get_active_fpke_link()
        if link is not None:
            link.set_drive_targets(
                speed_kmh=float(self.sld_speed.value()),
                rpm=float(self.sld_rpm.value()),
                auto_sweep=False,
            )

    def _on_auto_sweep_clicked(self) -> None:
        auto = self.btn_auto_sweep.isChecked()
        link = get_active_fpke_link()
        if link is not None:
            link.set_drive_targets(
                speed_kmh=float(self.sld_speed.value()),
                rpm=float(self.sld_rpm.value()),
                auto_sweep=auto,
            )
            if link.is_drive_simulation_running() and auto:
                self._sweep_timer.start()
            else:
                self._sweep_timer.stop()

    def _sync_sweep_readouts(self) -> None:
        if not _qt_valid(self):
            return
        link = get_active_fpke_link()
        if link is None or not link.is_drive_simulation_running() or not link.sim_auto_sweep:
            self._sweep_timer.stop()
            return
        self.sld_speed.blockSignals(True)
        self.sld_rpm.blockSignals(True)
        self.sld_speed.setValue(int(round(link.sim_speed_kmh)))
        self.sld_rpm.setValue(int(round(link.sim_rpm)))
        self.sld_speed.blockSignals(False)
        self.sld_rpm.blockSignals(False)
        self._update_gauge_labels()

    # ── 2A. Spatial Steering-Wheel Controller ──

    def _build_mfl_pad(self) -> QWidget:
        sec = self._compact_section(Section())
        sec.setFixedWidth(232)
        sec.set_text(tr("Кнопки руля", "Steering buttons"))

        def mfl_btn(label: str, code: int, ev: int, kind: str = "", tip: str = "") -> QWidget:
            b = button(label, kind, slot=lambda c=code, e=ev, t=tip or label: self._send_mfl(c, e, t))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            if tip:
                b.setToolTip(tip)
            self._mfl_buttons.append(b)
            return b

        btn_assist = mfl_btn(
            tr("Ассистенты", "Assistants"),
            0x04,
            0x01,
            "Chip",
            tip=tr("Меню ассистентов водителя", "Driver assistants menu"),
        )
        sec.head.addWidget(btn_assist, 0, Qt.AlignmentFlag.AlignVCenter)

        well = QFrame()
        well.setObjectName("DpadWell")
        pad = QGridLayout(well)
        pad.setContentsMargins(6, 5, 6, 5)
        pad.setHorizontalSpacing(5)
        pad.setVerticalSpacing(4)

        btn_up = mfl_btn("▲", 0x06, 0x0F, tip=tr("Вверх", "Up"))
        btn_back = mfl_btn(tr("Назад", "Back"), 0x01, 0x01)
        btn_ok = mfl_btn("OK", 0x07, 0x01, "PrimaryBtn")
        btn_menu = mfl_btn(tr("Меню", "Menu"), 0x02, 0x01)
        btn_down = mfl_btn("▼", 0x06, 0x01, tip=tr("Вниз", "Down"))

        pad.addWidget(btn_up, 0, 1)
        pad.addWidget(btn_back, 1, 0)
        pad.addWidget(btn_ok, 1, 1)
        pad.addWidget(btn_menu, 1, 2)
        pad.addWidget(btn_down, 2, 1)
        for col in range(3):
            pad.setColumnStretch(col, 1)
        sec.body.addWidget(well)
        return sec

    # ── 2B. Clean CAN Packet Sender ──

    def _build_packet_sender(self) -> QWidget:
        sec = self._compact_section(Section())
        sec.set_text(tr("CAN-пакет", "CAN packet"))

        self.cmb_preset = QComboBox()
        self.cmb_preset.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.cmb_preset.setMinimumContentsLength(10)
        for _key, cid, ext, hex_str, ru_lbl, en_lbl in FPKE_CAN_PRESETS:
            self.cmb_preset.addItem(tr(ru_lbl, en_lbl), (cid, ext, hex_str))
        self.cmb_preset.currentIndexChanged.connect(self._on_preset_selected)
        sec.body.addSpacing(4)
        sec.body.addWidget(self.cmb_preset)
        sec.body.addSpacing(4)

        send_row = QHBoxLayout()
        send_row.setSpacing(6)
        lbl_id = QLabel("ID")
        lbl_id.setFont(mono_font(11))
        set_tone(lbl_id, "muted")

        self.ed_can_id = QLineEdit("3C0")
        self.ed_can_id.setFont(mono_font(12))
        self.ed_can_id.setFixedWidth(74)
        self.ed_can_id.setPlaceholderText("ID")
        self.ed_can_id.returnPressed.connect(self._send_selected_packet)

        self.ed_can_data = QLineEdit("00 00 03 00")
        self.ed_can_data.setFont(mono_font(12))
        self.ed_can_data.setMinimumWidth(84)
        self.ed_can_data.setPlaceholderText("00 00 03 00")
        self.ed_can_data.returnPressed.connect(self._send_selected_packet)

        self.btn_send_pkt = button(tr("Отправить", "Send"), "PrimaryBtn", slot=self._send_selected_packet)
        self.btn_send_pkt.setCursor(Qt.CursorShape.PointingHandCursor)

        send_row.addWidget(lbl_id)
        send_row.addWidget(self.ed_can_id)
        send_row.addWidget(self.ed_can_data, 1)
        send_row.addWidget(self.btn_send_pkt)
        sec.body.addLayout(send_row)
        sec.body.addStretch(1)

        self._on_preset_selected(0)
        return sec

    def _on_preset_selected(self, idx: int) -> None:
        item = self.cmb_preset.itemData(idx)
        if isinstance(item, tuple) and len(item) == 3:
            cid, ext, hex_str = item
            self.ed_can_id.setText(f"{cid:08X}" if ext else f"{cid:03X}")
            self.ed_can_data.setText(hex_str)

    def _send_mfl(self, code: int, event: int, title: str) -> None:
        link = self._ensure_link()
        if link is None or not _qt_valid(self):
            return
        try:
            link.send_mfl_button(code, event, hold_s=0.15)
            self._set_status(
                tr(f"Нажата кнопка руля: {title}", f"Steering button pressed: {title}"),
                "ok",
            )
        except Exception as exc:
            self._set_status(str(exc), "err")

    def _send_selected_packet(self) -> None:
        link = self._ensure_link()
        if link is None or not _qt_valid(self):
            return
        try:
            arb_id, extended = parse_id(self.ed_can_id.text())
            data = parse_hex(self.ed_can_data.text(), 8)
            link.send_frame(arb_id, data, extended=extended)
            id_fmt = f"0x{arb_id:08X}" if extended else f"0x{arb_id:03X}"
            self._set_status(
                tr(
                    f"Отправлено {id_fmt}: {data.hex(' ').upper()}",
                    f"Sent {id_fmt}: {data.hex(' ').upper()}",
                ),
                "ok",
            )
        except Exception as exc:
            self._set_status(str(exc), "err")

    # ── 3. Clean 3-Column Procedures Deck ──

    def _build_procedures_section(self) -> QWidget:
        sec = Section()
        sec.head.setContentsMargins(14, 8, 14, 2)
        sec.body.setContentsMargins(14, 6, 14, 12)
        sec.body.setSpacing(8)
        sec.set_text(tr("Процедуры", "Procedures"))

        deck_frame = QFrame()
        deck_frame.setObjectName("ProcDeck")
        deck = QHBoxLayout(deck_frame)
        deck.setContentsMargins(0, 0, 0, 0)
        deck.setSpacing(8)

        groups = (
            (
                tr("ОШИБКИ БЛОКА", "FAULT CODES"),
                (
                    ("read_dtc", tr("Считать", "Read"), ""),
                    ("clear_dtc", tr("Сбросить", "Clear"), "GhostBtn"),
                ),
            ),
            (
                tr("ИММОБИЛАЙЗЕР", "IMMOBILIZER"),
                (
                    ("immo_status", tr("Статус", "Status"), ""),
                    ("key_poll", tr("Ключи", "Keys"), "GhostBtn"),
                ),
            ),
            (
                tr("СЕРВИС", "SERVICE"),
                (
                    ("ensure_level8", tr("Уровень 8", "Level 8"), ""),
                    ("ecu_reset", tr("Перезагрузить", "Reset"), "DangerBtn"),
                ),
            ),
        )

        self._proc_buttons.clear()
        for idx, (grp_title, actions) in enumerate(groups):
            if idx > 0:
                sep = vdivider()
                sep.setFixedHeight(42)
                deck.addWidget(sep, 0, Qt.AlignmentFlag.AlignVCenter)

            col = QVBoxLayout()
            col.setContentsMargins(0, 0, 0, 0)
            col.setSpacing(6)
            col.addWidget(group_label(grp_title))

            btn_row = QHBoxLayout()
            btn_row.setContentsMargins(0, 0, 0, 0)
            btn_row.setSpacing(5)
            for proc_id, btn_txt, btn_kind in actions:
                b = button(btn_txt, btn_kind, slot=lambda pid=proc_id, t=btn_txt: self._run_proc(pid, t))
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
                self._proc_buttons.append(b)
                btn_row.addWidget(b)
            btn_row.addStretch(1)
            col.addLayout(btn_row)
            deck.addLayout(col, 1)

        sec.body.addWidget(deck_frame)

        self.strip_result = QFrame()
        self.strip_result.setObjectName("ResultStrip")
        sl = QHBoxLayout(self.strip_result)
        sl.setContentsMargins(10, 5, 10, 5)
        sl.setSpacing(8)
        self.lbl_status = QLabel(self._last_msg)
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.lbl_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        set_tone(self.lbl_status, self._last_tone)
        sl.addWidget(self.lbl_status, 1)

        self.btn_dtc_details = button(tr("Список…", "List…"), "Chip", slot=self.show_dtc_dialog)
        self.btn_dtc_details.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_dtc_details.setVisible(bool(self._last_dtcs))
        sl.addWidget(self.btn_dtc_details, 0, Qt.AlignmentFlag.AlignVCenter)

        self.strip_result.setVisible(bool(self._last_msg))
        sec.body.addWidget(self.strip_result)
        return sec

    def _clear_dtcs_sync(self) -> str | None:
        link = self._ensure_link()
        if link is None:
            return None
        try:
            res = fpke_run_procedure(link, "clear_dtc")
            msg = str(res.get("summary") or tr("Ошибки блока сброшены.", "Fault codes cleared."))
            self._last_dtcs = []
            if self._dtcs_sink is not None:
                self._dtcs_sink([])
            if _qt_valid(self) and _qt_valid(self.btn_dtc_details):
                self.btn_dtc_details.setVisible(False)
            self._set_status(msg, "ok")
            return msg
        except Exception as exc:
            self._set_status(str(exc), "err")
            return None

    def show_dtc_dialog(self) -> None:
        if not self._last_dtcs or not _qt_valid(self):
            return
        dlg = FpkeDtcDialog(
            self._last_dtcs,
            part_number=self._part_number,
            clear_callback=self._clear_dtcs_sync,
            parent=self.window(),
        )
        run_dialog(dlg)

    def _run_proc(self, proc_id: str, title: str) -> None:
        if self.runner.is_busy:
            return
        needs_l8 = proc_id == "ensure_level8"
        if self.via_gateway and needs_l8:
            if not ensure_ready(self.conn, self) or not _qt_valid(self):
                return
            port = self.conn.port
            iface = self.conn.interface or "slcan"
            via_gw = self.via_gateway
            gw_br = self.gateway_bridge
            gw_ch = self.gateway_channel

            def task(rep: Any) -> dict[str, Any]:
                return can_fpke_run_level8_action(
                    port,
                    lambda lnk, r: fpke_run_procedure(lnk, proc_id, reporter=r),
                    interface=iface,
                    via_gateway=via_gw,
                    gateway_bridge=gw_br,
                    gateway_channel=gw_ch,
                    reporter=rep,
                )
        else:
            link = self._ensure_link()
            if link is None or not _qt_valid(self):
                return

            def task(rep: Any) -> dict[str, Any]:
                return fpke_run_procedure(link, proc_id, reporter=rep)

        sink = self._status_sink
        dtcs_sink = self._dtcs_sink

        def done(res: dict[str, Any]) -> None:
            summary = str(res.get("summary", title))
            dtcs = list(res.get("dtcs") or []) if proc_id == "read_dtc" else []
            tone = "warn" if (proc_id == "read_dtc" and dtcs) else "ok"
            if proc_id in ("read_dtc", "clear_dtc") and dtcs_sink is not None:
                dtcs_sink(dtcs if proc_id == "read_dtc" else [])
            if sink is not None:
                sink(summary, tone)
            if not _qt_valid(self):
                return
            if proc_id == "read_dtc":
                self._last_dtcs = dtcs
                if _qt_valid(self.btn_dtc_details):
                    self.btn_dtc_details.setVisible(bool(dtcs))
            elif proc_id == "clear_dtc":
                self._last_dtcs = []
                if _qt_valid(self.btn_dtc_details):
                    self.btn_dtc_details.setVisible(False)
            self._set_status(summary, tone)
            if (
                proc_id == "read_dtc"
                and dtcs
                and self.window().isVisible()
                and os.environ.get("QT_QPA_PLATFORM") != "offscreen"
            ):
                self.show_dtc_dialog()

        self.runner.run_task(
            title,
            task,
            on_success=lambda res: QTimer.singleShot(0, lambda: done(res)),
        )

    def _refresh_ui(self) -> None:
        if not _qt_valid(self) or not _qt_valid(self.sw_kl15):
            return
        link = get_active_fpke_link()
        direct_only = not self.via_gateway
        gw_tip = (
            tr(
                "Доступно только при прямом подключении к CAN приборной панели (T18). Через шлюз J533 работают UDS-процедуры.",
                "Available only on a direct connection to the cluster CAN bus (T18). UDS procedures work via J533 gateway.",
            )
            if not direct_only
            else ""
        )
        for ctrl in (self.sw_kl15, self.sw_drive, self.sld_speed, self.sld_rpm, self.btn_auto_sweep, *self._mfl_buttons):
            if _qt_valid(ctrl):
                ctrl.setEnabled(direct_only and not self.runner.is_busy)
                if not direct_only:
                    ctrl.setToolTip(gw_tip)

        kl15_on = bool(direct_only and link and link.is_keepalive_running())
        drv_on = bool(direct_only and link and link.is_drive_simulation_running())
        lvl8_on = bool(link and link.level8_active)

        self.sw_kl15.blockSignals(True)
        self.sw_kl15.setChecked(kl15_on)
        self.sw_kl15.blockSignals(False)

        self.sw_drive.blockSignals(True)
        self.sw_drive.setChecked(drv_on)
        self.sw_drive.blockSignals(False)

        if link is not None and drv_on and link.sim_auto_sweep and not self._sweep_timer.isActive():
            self._sweep_timer.start()

        if self.via_gateway:
            self.lbl_access_state.setText(
                tr("Через шлюз J533 (RAM-мост)", "Via J533 gateway (RAM-Bridge)")
                if self.gateway_bridge
                else tr("Через шлюз J533 (UDS)", "Via J533 gateway (UDS)")
            )
            set_tone(self.lbl_access_state, "ok" if self.gateway_bridge else "info")
            self.lbl_access_state.setVisible(True)
        elif lvl8_on:
            self.lbl_access_state.setText(tr("● Уровень 8", "● Level 8"))
            set_tone(self.lbl_access_state, "ok")
            self.lbl_access_state.setVisible(True)
        elif link is not None:
            self.lbl_access_state.setText(tr("● Подключено", "● Connected"))
            set_tone(self.lbl_access_state, "info")
            self.lbl_access_state.setVisible(True)
        else:
            self.lbl_access_state.setText("")
            self.lbl_access_state.setVisible(False)


class FpkeCanDialog(Dialog):
    """Dedicated standalone window for FPK_E CAN packet control, KL15 toggle, and service procedures."""

    note = Signal(str)

    def __init__(
        self,
        conn: CanConnection,
        runner: OperationRunner,
        *,
        part_number: str = "83A920700E",
        initial_msg: str = "",
        initial_tone: str = "muted",
        initial_dtcs: list[dict[str, Any]] | None = None,
        status_sink: Callable[[str, str], None] | None = None,
        dtcs_sink: Callable[[list[dict[str, Any]]], None] | None = None,
        via_gateway: bool = False,
        gateway_bridge: bool = False,
        gateway_channel: int = 0,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(
            parent,
            tr("Управление по CAN", "CAN control"),
            part_number,
            width=740,
        )
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.body.setContentsMargins(20, 14, 20, 14)
        self.body.setSpacing(8)
        self.panel = _FpkeCanControlPanel(
            conn,
            runner,
            self,
            part_number=part_number,
            initial_msg=initial_msg,
            initial_tone=initial_tone,
            initial_dtcs=initial_dtcs,
            status_sink=status_sink,
            dtcs_sink=dtcs_sink,
            via_gateway=via_gateway,
            gateway_bridge=gateway_bridge,
            gateway_channel=gateway_channel,
        )
        self.panel.note.connect(self.note.emit)
        self.panel.state_changed.connect(self._adjust_for_result)
        self.body.addWidget(self.panel)
        self.finish(cancel_text=tr("Закрыть", "Close"))
        self.resize(self.width(), self.height() + 26)
        self._fit_screen()

    def _adjust_for_result(self) -> None:
        if not _qt_valid(self) or not _qt_valid(self.panel):
            return
        if self.panel.strip_result.isVisible():
            self.fit_height()
            self.resize(self.width(), self.height() + 6)
            self._fit_screen()


class FpkeCoilKeyLearnDialog(Dialog):
    """Step-by-step wizard for learning blank Megamos AES transponders via the stock 125 kHz LF coil."""

    note = Signal(str)

    def __init__(
        self,
        conn: CanConnection,
        runner: OperationRunner,
        *,
        dflash_info: dict[str, Any],
        part_number: str = "83A920700E",
        initial_s0_hex: str = "",
        initial_s1_hex: str = "",
        on_s0_s1_cached: Callable[[str, str], None] | None = None,
        on_learned_keys_synced: Callable[[list[str], int, int], None] | None = None,
        via_gateway: bool = False,
        gateway_bridge: bool = False,
        gateway_channel: int = 0,
        parent: QWidget | None = None,
    ) -> None:
        self.via_gateway = bool(via_gateway)
        self.gateway_bridge = bool(gateway_bridge)
        self.gateway_channel = int(gateway_channel)
        by_id = {it["key_id"]: it for it in dflash_info.get("items", [])}
        meta = dflash_info.get("metadata") or {}
        immo_cfg = dflash_info.get("immo_config") or {}
        slots = dflash_info.get("slot_secrets") or {}
        tp = dflash_info.get("transponder_records") or {}

        self._vin = str(meta.get("vin") or "")
        self._kc_hex = str((by_id.get("kc") or {}).get("hex") or "").upper()
        self._power_class = int(immo_cfg.get("power_class") or 0)
        self._partner_mask = int(immo_cfg.get("partners_mask") or 0x01)
        self._key_flags = int(immo_cfg.get("key_transport_raw") or 0x00)
        self._status_5302 = int(immo_cfg.get("identity_counter") or 0x00)
        self._expected_crc_a = str(slots.get("A_crc32_le") or "").upper()
        self._expected_crc_b = str(slots.get("B_crc32_le") or "").upper()
        cur_learned = int(tp.get("learned_keys") or 0)
        self._existing_key_ids = [
            str(k.get("display_id") or "").upper()
            for k in (tp.get("key_ids") or [])[:cur_learned]
            if k.get("present") and k.get("display_id")
        ]

        subtitle = tr(
            f"{part_number} • Штатная катушка 125 кГц (Megamos AES) • VIN: {self._vin or '—'} • P_class: 0x{self._power_class:02X}",
            f"{part_number} • Stock 125 kHz LF coil (Megamos AES) • VIN: {self._vin or '—'} • P_class: 0x{self._power_class:02X}",
        )
        super().__init__(
            parent,
            tr("Обучение ключей через штатную катушку", "Key learning via stock LF coil"),
            subtitle,
            width=760,
        )
        self.conn = conn
        self.runner = runner
        self._on_s0_s1_cached = on_s0_s1_cached
        self._on_learned_keys_synced = on_learned_keys_synced
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.body.setContentsMargins(18, 6, 18, 6)
        self.body.setSpacing(6)

        def _tight_card(sec: Section) -> Section:
            sec = _FpkeCanControlPanel._compact_section(sec)
            sec.head.setContentsMargins(14, 7, 14, 3)
            sec.body.setContentsMargins(14, 2, 14, 8)
            sec.body.setSpacing(5)
            return sec

        # ── Live Coil & Immo Status Strip ──
        self.strip_status = QFrame()
        self.strip_status.setObjectName("ResultStrip")
        st_lay = QHBoxLayout(self.strip_status)
        st_lay.setContentsMargins(12, 5, 12, 5)
        st_lay.setSpacing(10)
        self.lbl_live_status = QLabel(
            tr(
                f"Дамп: обучено {cur_learned} кл. • CRC A/B: {self._expected_crc_a or '—'} / {self._expected_crc_b or '—'}",
                f"Dump: {cur_learned} learned key(s) • CRC A/B: {self._expected_crc_a or '—'} / {self._expected_crc_b or '—'}",
            )
        )
        self.lbl_live_status.setWordWrap(True)
        set_tone(self.lbl_live_status, "info")
        self.btn_poll_coil = button(
            tr("Опросить катушку (02E4)", "Poll LF coil (02E4)"),
            "GhostBtn",
            slot=self.run_poll_coil,
        )
        st_lay.addWidget(self.lbl_live_status, 1)
        st_lay.addWidget(self.btn_poll_coil, 0)
        self.body.addWidget(self.strip_status)

        # ── Step 1: Slot Secret S0 / S1 (32 B) ──
        sec_s01 = _tight_card(Section())
        sec_s01.set_text(
            tr("Шаг 1. Секрет слотов S0 / S1 (32 байта)", "Step 1. Slot secret S0 / S1 (32 bytes)"),
        )
        self.lbl_crc_state = status_readout(tr("Ожидание S0/S1", "Awaiting S0/S1"), "warn")
        sec_s01.head.addWidget(self.lbl_crc_state, 0, Qt.AlignmentFlag.AlignVCenter)

        lbl_s01_hint = QLabel(
            tr(
                "Приложите рабочий ключ (Ключ 1) к штатной катушке при включённом KL15 и нажмите "
                "«Считать S0 / S1 с рабочего ключа», либо введите 32 байта вручную.",
                "Hold a working key (Key 1) at the stock LF coil with ignition ON and click "
                "“Extract S0 / S1 from working key”, or enter the 32 bytes manually.",
            )
        )
        lbl_s01_hint.setObjectName("Hint")
        lbl_s01_hint.setWordWrap(True)
        sec_s01.body.addWidget(lbl_s01_hint)

        raw_s0 = initial_s0_hex or str(slots.get("S0") or "").upper()
        raw_s1 = initial_s1_hex or str(slots.get("S1") or "").upper()
        if raw_s0 in ("FF" * 16, "00" * 16):
            raw_s0 = ""
        if raw_s1 in ("FF" * 16, "00" * 16):
            raw_s1 = ""

        s01_row = QHBoxLayout()
        s01_row.setSpacing(10)
        self.ed_s0 = QLineEdit(raw_s0)
        self.ed_s0.setFont(mono_font(11))
        self.ed_s0.setMinimumWidth(0)
        self.ed_s0.setPlaceholderText("32 HEX (16 B S0)")
        c_s0, b_s0 = FpkeScreen._field_box("S0 (RAM 0xFEDF2D44 / EEL 0x69)", self.ed_s0)
        FpkeScreen._bind_hex_validator(self.ed_s0, b_s0, 16, allow_empty=False)

        self.ed_s1 = QLineEdit(raw_s1)
        self.ed_s1.setFont(mono_font(11))
        self.ed_s1.setMinimumWidth(0)
        self.ed_s1.setPlaceholderText("32 HEX (16 B S1)")
        c_s1, b_s1 = FpkeScreen._field_box("S1 (RAM 0xFEDF2D54 / EEL 0x69)", self.ed_s1)
        FpkeScreen._bind_hex_validator(self.ed_s1, b_s1, 16, allow_empty=False)

        s01_row.addWidget(c_s0, 1)
        s01_row.addWidget(c_s1, 1)
        sec_s01.body.addLayout(s01_row)

        self.lbl_slots_preview = QLabel("")
        self.lbl_slots_preview.setFont(mono_font(10))
        set_tone(self.lbl_slots_preview, "muted")
        sec_s01.body.addWidget(self.lbl_slots_preview)

        self.btn_extract_s01 = button(
            tr("Считать S0 / S1 с рабочего ключа в катушке (RAM)", "Extract S0 / S1 from working key in coil (RAM)"),
            "PrimaryBtn",
            slot=self.run_extract_s0_s1,
        )
        sec_s01.add_footer(self.btn_extract_s01)
        self.body.addWidget(sec_s01)

        # ── Step 2: Open Learning Session (Method A: Additive RAM Mode 4 / Method B: Full 2E 02F7) ──
        sec_02f7 = _tight_card(Section())
        sec_02f7.set_text(
            tr(
                "Шаг 2. Вход в режим обучения (Способ А без удаления старых / 2E 02F7)",
                "Step 2. Enter learning mode (Method A keep old keys / 2E 02F7)",
            ),
        )
        lbl_02f7_warn = QLabel(
            tr(
                "Способ А (рекомендуется) через ОЗУ включает режим 5 и сохраняет старые ключи — прикладывать нужно только новую болванку. "
                "Способ Б (2E 02F7) очищает 0x67 (нужно приложить все ключи).",
                "Method A (recommended) activates mode 5 in RAM and keeps existing keys — only place the new blank key. "
                "Method B (2E 02F7) clears 0x67 (all keys must be presented).",
            )
        )
        lbl_02f7_warn.setObjectName("Hint")
        lbl_02f7_warn.setWordWrap(True)
        sec_02f7.body.addWidget(lbl_02f7_warn)

        cfg_row = QHBoxLayout()
        cfg_row.setSpacing(12)
        lbl_cnt = group_label(tr("ИТОГОВОЕ ЧИСЛО КЛЮЧЕЙ (1–8):", "TARGET TOTAL KEYS (1–8):"))
        self.spn_target_keys = QSpinBox()
        self.spn_target_keys.setRange(1, 8)
        self.spn_target_keys.setValue(min(8, max(1, cur_learned + 1)))
        self.spn_target_keys.setFont(mono_font(12, bold=True))
        self.spn_target_keys.setFixedWidth(68)
        lbl_kc_info = QLabel(f"CS/K_c: {self._kc_hex[:12]}… • P_class: 0x{self._power_class:02X}")
        lbl_kc_info.setFont(mono_font(10))
        set_tone(lbl_kc_info, "muted")
        cfg_row.addWidget(lbl_cnt)
        cfg_row.addWidget(self.spn_target_keys)
        cfg_row.addSpacing(8)
        cfg_row.addWidget(lbl_kc_info, 1)
        sec_02f7.body.addLayout(cfg_row)

        self.btn_prepare_additive = button(
            tr("1А. Дописать новый (сохранить старые — Режим 5)", "1A. Add new key (keep existing — Mode 5)"),
            "PrimaryBtn",
            slot=self.run_prepare_additive_mode4,
        )
        self.btn_start_02f7 = button(
            tr("1Б. Перезаписать все (2E 02F7)", "1B. Overwrite all (2E 02F7)"),
            "GhostBtn",
            slot=self.run_start_learning_02f7,
        )
        sec_02f7.add_footer(self.btn_prepare_additive, self.btn_start_02f7)
        self.body.addWidget(sec_02f7)

        # ── Step 3: Learn Keys on Coil & Finish (2E 02E1 40 00 -> 80 00) ──
        sec_learn = _tight_card(Section())
        sec_learn.set_text(
            tr("Шаг 3. Привязка ключей на катушке и завершение (2E 02E1)", "Step 3. Bind keys on LF coil & finish (2E 02E1)"),
        )
        lbl_lrn_hint = QLabel(
            tr(
                "По очереди прикладывайте каждый ключ к катушке и нажимайте «2. Обучить ключ в катушке (40 00)». "
                "В чистую болванку Megamos AES (бит 1 в 0x01F = 1) панель приборов запишет K_c, слоты A/B и метку 0x9911 (~3–5 с).",
                "Place each key on the coil one by one and click “2. Learn key in coil (40 00)”. "
                "For a blank Megamos AES chip (bit 1 of 0x01F = 1), the cluster writes K_c, slots A/B, and marker 0x9911 (~3–5 s).",
            )
        )
        lbl_lrn_hint.setObjectName("Hint")
        lbl_lrn_hint.setWordWrap(True)
        sec_learn.body.addWidget(lbl_lrn_hint)

        self.chk_sync_ch3 = QCheckBox(
            tr(
                "При завершении передать очередь 0x6A узлу 0x0E (BCM 09, радиоканал) по каналу 3 (80 01 — в автомобиле)",
                "Send queue 0x6A to node 0x0E (BCM 09, remote key sync) on channel 3 upon finish (80 01 — in vehicle)",
            )
        )
        self.chk_sync_ch3.setChecked(False)
        sec_learn.body.addWidget(self.chk_sync_ch3)

        self.btn_learn_key = button(
            tr("2. Обучить ключ в катушке (40 00)", "2. Learn key in coil (40 00)"),
            "PrimaryBtn",
            slot=self.run_learn_next_key,
        )
        self.btn_finish_learn = button(
            tr("3. Завершить обучение (80 00)", "3. Finish learning (80 00)"),
            "GhostBtn",
            slot=self.run_finish_learning,
        )
        sec_learn.add_footer(self.btn_learn_key, self.btn_finish_learn)
        self.body.addWidget(sec_learn)

        self.ed_s0.textChanged.connect(lambda _t: self._update_s01_validation())
        self.ed_s1.textChanged.connect(lambda _t: self._update_s01_validation())
        self._update_s01_validation()

        self.finish(cancel_text=tr("Закрыть", "Close"))
        self.resize(self.width(), self.height() + 26)
        self._fit_screen()

    def _clean_hex(self, txt: str) -> str:
        return "".join(txt.split()).replace("0x", "").replace("0X", "").upper()

    def _update_s01_validation(self) -> None:
        s0_h = self._clean_hex(self.ed_s0.text())
        s1_h = self._clean_hex(self.ed_s1.text())
        if len(s0_h) != 32 or len(s1_h) != 32 or not all(c in "0123456789ABCDEF" for c in s0_h + s1_h):
            self.lbl_crc_state.setText(tr("Не заданы S0/S1", "S0/S1 missing"))
            set_tone(self.lbl_crc_state, "warn")
            self.lbl_slots_preview.setText(
                tr(
                    f"Ожидаемые CRC-32 (0x68): A={self._expected_crc_a or '—'} • B={self._expected_crc_b or '—'}",
                    f"Expected CRC-32 (0x68): A={self._expected_crc_a or '—'} • B={self._expected_crc_b or '—'}",
                )
            )
            self.btn_prepare_additive.setEnabled(False)
            self.btn_start_02f7.setEnabled(False)
            return

        ver = fpke_verify_s0_s1(
            bytes.fromhex(s0_h),
            bytes.fromhex(s1_h),
            self._expected_crc_a or None,
            self._expected_crc_b or None,
        )
        self.lbl_slots_preview.setText(
            f"Slot A: {ver['slot_a_hex']} (CRC: {ver['crc_a_le_hex']})  •  "
            f"Slot B: {ver['slot_b_hex']} (CRC: {ver['crc_b_le_hex']})"
        )
        if ver["valid"]:
            self.lbl_crc_state.setText(tr("CRC A/B совпали с 0x68", "CRC A/B match 0x68"))
            set_tone(self.lbl_crc_state, "ok")
            self.btn_prepare_additive.setEnabled(True)
            self.btn_start_02f7.setEnabled(True)
            if self._on_s0_s1_cached is not None:
                self._on_s0_s1_cached(s0_h, s1_h)
        else:
            self.lbl_crc_state.setText(tr("CRC A/B НЕ совпадают!", "CRC A/B mismatch!"))
            set_tone(self.lbl_crc_state, "err")
            self.btn_prepare_additive.setEnabled(False)
            self.btn_start_02f7.setEnabled(False)

    def _ensure_link(self) -> Any | None:
        if not ensure_ready(self.conn, self):
            return None
        try:
            return open_or_reuse_fpke_link(
                self.conn.port,
                interface=self.conn.interface,
                via_gateway=self.via_gateway,
            )
        except Exception as exc:
            self._set_status(str(exc), "err")
            return None

    def _run_l8_task(
        self,
        title: str,
        fn: Callable[[Any, Any], dict[str, Any]],
        on_done: Callable[[dict[str, Any]], None],
        *,
        needs_level8: bool = True,
    ) -> None:
        if self.runner.is_busy:
            return
        if self.via_gateway and needs_level8:
            if not ensure_ready(self.conn, self):
                return
            port = self.conn.port
            iface = self.conn.interface or "slcan"
            via_gw = self.via_gateway
            gw_br = self.gateway_bridge
            gw_ch = self.gateway_channel

            def task(rep: Any) -> dict[str, Any]:
                return can_fpke_run_level8_action(
                    port,
                    fn,
                    interface=iface,
                    via_gateway=via_gw,
                    gateway_bridge=gw_br,
                    gateway_channel=gw_ch,
                    reporter=rep,
                )
        else:
            link = self._ensure_link()
            if link is None:
                return

            def task(rep: Any) -> dict[str, Any]:
                return fn(link, rep)

        self.runner.run_task(
            title,
            task,
            on_success=lambda res: QTimer.singleShot(0, lambda: on_done(res)),
        )

    def _set_status(self, msg: str, tone: str = "info") -> None:
        if not _qt_valid(self) or not _qt_valid(self.lbl_live_status):
            return
        self.lbl_live_status.setText(msg)
        set_tone(self.lbl_live_status, tone)
        self.note.emit(msg)

    def run_poll_coil(self) -> None:
        if self.runner.is_busy:
            return
        link = self._ensure_link()
        if link is None:
            return

        def task(rep: Any) -> dict[str, Any]:
            return fpke_coil_poll_transponder(link, reporter=rep)

        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self):
                return
            ids = ", ".join(res.get("learned_key_ids") or [])
            summary = str(res.get("summary") or "")
            if ids:
                summary += f" • ID: {ids}"
            self._set_status(summary, "ok" if res.get("coil_key_id") else "info")

        self.runner.run_task(
            tr("Опрос штатной катушки LF (02E4 / 02ED)", "Polling stock LF coil (02E4 / 02ED)"),
            task,
            on_success=lambda res: QTimer.singleShot(0, lambda: done(res)),
        )

    def run_extract_s0_s1(self) -> None:
        exp_a = self._expected_crc_a or None
        exp_b = self._expected_crc_b or None

        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self):
                return
            self.ed_s0.setText(str(res.get("s0_hex") or ""))
            self.ed_s1.setText(str(res.get("s1_hex") or ""))
            self._update_s01_validation()
            self._set_status(str(res.get("summary") or ""), "ok")

        self._run_l8_task(
            tr("Чтение S0 / S1 из ОЗУ панели приборов", "Extracting S0 / S1 from cluster RAM"),
            lambda lnk, rep: fpke_extract_live_s0_s1_from_coil(
                lnk,
                expected_crc_a_le=exp_a,
                expected_crc_b_le=exp_b,
                reporter=rep,
            ),
            done,
        )

    def run_prepare_additive_mode4(self) -> None:
        s0_h = self._clean_hex(self.ed_s0.text())
        s1_h = self._clean_hex(self.ed_s1.text())
        target_n = self.spn_target_keys.value()
        existing_ids = list(self._existing_key_ids)

        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self):
                return
            self._set_status(str(res.get("summary") or ""), "ok")

        self._run_l8_task(
            tr(
                "Активация режима дообучения 5 в ОЗУ (без удаления старых ключей)",
                "Activating additive learning mode 5 in RAM (keeping existing keys)",
            ),
            lambda lnk, rep: fpke_prepare_additive_coil_learning(
                lnk,
                s0_hex=s0_h,
                s1_hex=s1_h,
                kc_hex=self._kc_hex,
                allowed_keys=target_n,
                existing_key_display_ids=existing_ids,
                expected_crc_a_le=self._expected_crc_a or None,
                expected_crc_b_le=self._expected_crc_b or None,
                reporter=rep,
            ),
            done,
        )

    def run_start_learning_02f7(self) -> None:
        s0_h = self._clean_hex(self.ed_s0.text())
        s1_h = self._clean_hex(self.ed_s1.text())
        target_n = self.spn_target_keys.value()

        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self):
                return
            self._set_status(str(res.get("summary") or ""), "ok")

        self._run_l8_task(
            tr("Открытие режима обучения ключей (2E 02F7)", "Opening key learning session (2E 02F7)"),
            lambda lnk, rep: fpke_start_coil_key_learning(
                lnk,
                vin=self._vin,
                s0_hex=s0_h,
                s1_hex=s1_h,
                kc_hex=self._kc_hex,
                power_class=self._power_class,
                allowed_keys=target_n,
                partner_mask=self._partner_mask,
                key_flags=self._key_flags,
                status_5302=self._status_5302,
                expected_crc_a_le=self._expected_crc_a or None,
                expected_crc_b_le=self._expected_crc_b or None,
                reporter=rep,
            ),
            done,
            needs_level8=False,
        )

    def run_learn_next_key(self) -> None:
        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self):
                return
            self._set_status(str(res.get("summary") or ""), "ok")

        self._run_l8_task(
            tr("Обучение ключа в штатной катушке (2E 02E1 40 00)", "Learning key in stock LF coil (2E 02E1 40 00)"),
            lambda lnk, rep: fpke_learn_next_key_on_coil(lnk, param=0x00, reporter=rep),
            done,
            needs_level8=False,
        )

    def run_finish_learning(self) -> None:
        sync_ch3 = self.chk_sync_ch3.isChecked()

        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self):
                return
            self._set_status(str(res.get("summary") or ""), "ok")
            learned_ids = list(res.get("learned_key_ids") or [])
            learned_cnt = int(res.get("learned_keys") or len(learned_ids))
            if learned_ids and self._on_learned_keys_synced is not None:
                self._on_learned_keys_synced(learned_ids, learned_cnt, learned_cnt)

        self._run_l8_task(
            tr("Завершение обучения ключей (2E 02E1 80 00)", "Finishing key learning (2E 02E1 80 00)"),
            lambda lnk, rep: fpke_finish_coil_key_learning(lnk, sync_channel3=sync_ch3, reporter=rep),
            done,
            needs_level8=bool((self._key_flags & 0x80) and self.gateway_bridge),
        )
