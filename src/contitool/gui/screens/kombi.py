"""Working screen for Continental VAG MQB 17 Kombi VDD (`EV_DashBoardVDDMQBAB`, V850E2/Dx4 `uPD70F3526`, SL 7)."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid as _qt_valid

from contitool.can.fpke import FPKE_NATIVE_INTERFACES, atomic_write, get_active_fpke_link
from contitool.can.kombi import can_kombi_full_read, can_kombi_write_dflash
from contitool.core.fpke import detect_fpke_files, extract_fpke_immo_passport, is_fpke_dflash
from contitool.core.kombi import (
    KOMBI_EEL_LOGICAL_SIZE,
    analyze_kombi_dflash,
    apply_kombi_dflash_edits,
    detect_kombi_files,
    extract_kombi_immo_passport,
    format_kombi_report,
    format_kombi_transfer_plan,
    is_kombi_dflash,
    kombi_support_info,
    normalize_kombi_dflash_input,
    plan_kombi_a_to_b_transfer,
    summarize_kombi_dflash_changes,
    transfer_kombi_donor_to_target,
)
from contitool.gui.connection import CanConnection, ensure_ready
from contitool.gui.screens.fpke import FpkeScreen, _FpkeCanControlPanel, _fpke_nav_title
from contitool.gui.theme import mono_font
from contitool.gui.widgets.page import (
    Callout,
    Section,
    button,
    clear_layout,
    set_pill,
    status_readout,
)
from contitool.gui.worker import OperationRunner
from contitool.gui.workspace import _remember_recent
from contitool.i18n import tr
from contitool.storage import new_session, unit_of_ident

KOMBI_REQUIRED_DUMPS = (
    ("dflash", "DataFlash (EEL)"),
    ("eel_logical", "EelLogical (132 blk)"),
)

KOMBI_OPTIONAL_DUMPS = (
    ("cflash", "CodeFlash (3 MB)"),
)


def _kombi_nav_title(key: str) -> str:
    if key == "extra":
        return tr("Ключи FD11 (SL 7)", "FD11 keys (SL 7)")
    return _fpke_nav_title(key)


class KombiScreen(FpkeScreen):
    """Dedicated screen for Continental V850E2 `17 Kombi VDD` (`5NA 920 740 B`, `SW 0310`, Supplier Level 7)."""

    def __init__(
        self,
        conn: CanConnection,
        runner: OperationRunner,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(conn, runner, parent)
        # Hide the RH850-only Engineering Bootloader ('boot') nav item on V850E2 Kombi
        if "boot" in self._nav_items:
            self._nav_items["boot"].setHidden(True)

    def _is_kombi_mode(self) -> bool:
        return True

    def _supports_coil_key_learn(self) -> bool:
        return True

    def _analyze_dflash(self, df_bytes: bytes, cf_bytes: bytes | None = None) -> dict[str, Any]:
        return analyze_kombi_dflash(df_bytes, cf_bytes)

    def _apply_dflash_edits(self, df_bytes: bytes, **kwargs: Any) -> bytes:
        return apply_kombi_dflash_edits(df_bytes, **kwargs)

    def _extract_immo_passport(self, df_bytes: bytes, cf_bytes: bytes | None = None) -> dict[str, Any]:
        return extract_kombi_immo_passport(df_bytes, cf_bytes)

    def _summarize_dflash_changes(
        self,
        before_bytes: bytes,
        after_bytes: bytes,
        cf_bytes: bytes | None = None,  # noqa: ARG002
    ) -> dict[str, Any]:
        return summarize_kombi_dflash_changes(before_bytes, after_bytes)

    def _transfer_donor(
        self,
        donor_passport: dict[str, Any],
        target_df: bytes,
        **kwargs: Any,
    ) -> tuple[bytes, dict[str, Any]]:
        return transfer_kombi_donor_to_target(donor_passport, target_df, **kwargs)

    def _format_transfer_plan(self, plan: dict[str, Any]) -> str:
        return format_kombi_transfer_plan(plan)

    def _format_report(self) -> str:
        return format_kombi_report(
            dflash_info=self.dflash_info,
            ident=self.ident_items,
        )

    def set_donor_source(self, path: Path) -> None:
        """Load a donor cluster source (Kombi `Dflash.bin` / `EelLogical.bin`, `FPK_E` `Dflash.bin`, or `immo_passport.json`)."""
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
            if is_kombi_dflash(raw):
                norm = normalize_kombi_dflash_input(raw)
                sib = detect_kombi_files([path.parent])
                cf_path = sib.get("cflash")
                cf_bytes = cf_path.read_bytes() if (cf_path is not None and cf_path.is_file()) else None
                self._donor_path = path
                self._donor_dflash = norm
                self._donor_cflash = cf_bytes
                self._donor_passport = extract_kombi_immo_passport(norm, cf_bytes)
            elif is_fpke_dflash(raw):
                sib = detect_fpke_files([path.parent])
                cf_path = sib.get("cflash")
                cf_bytes = cf_path.read_bytes() if (cf_path is not None and cf_path.is_file()) else None
                self._donor_path = path
                self._donor_dflash = raw
                self._donor_cflash = cf_bytes
                self._donor_passport = extract_fpke_immo_passport(raw, cf_bytes)
            else:
                raise ValueError(
                    tr(
                        f"Файл «{path.name}» ({len(raw)} Б) не является валидным дампом DataFlash Kombi (65 536 Б / {KOMBI_EEL_LOGICAL_SIZE} Б) или FPK_E.",
                        f"File “{path.name}” ({len(raw)} B) is not a valid Kombi (65,536 B / {KOMBI_EEL_LOGICAL_SIZE} B) or FPK_E DataFlash dump.",
                    )
                )
            self._recipient_path = path
            self._recipient_dflash = self._donor_dflash
            self._recipient_cflash = self._donor_cflash
        self._swap_ab = False
        self._refresh_nav()
        self._render_page()

    def _current_transfer_plan(self) -> dict[str, Any] | None:
        df_open, cf_open = self._own_dflash_and_cflash()
        if df_open is None or self._donor_passport is None:
            return None
        target_passport = extract_kombi_immo_passport(df_open, cf_open)
        if self._swap_ab:
            return plan_kombi_a_to_b_transfer(target_passport, self._donor_passport)
        return plan_kombi_a_to_b_transfer(self._donor_passport, target_passport)

    def _support_info(self) -> dict[str, Any]:
        meta = (self.dflash_info or {}).get("metadata") or {}
        return kombi_support_info(
            self.ident_items,
            f187=meta.get("part_number"),
            f189=meta.get("sw_version_eel"),
        )

    def _nav_title(self, key: str) -> str:
        return _kombi_nav_title(key)

    def _memory_blocker(self) -> str | None:
        """Kombi SL 7 uses pure 11-bit UDS (`0x714 -> 0x77E`) and works through any gateway without a 29-bit RAM bridge."""
        iface = self.conn.interface or "slcan"
        if iface not in FPKE_NATIVE_INTERFACES:
            return "adapter"
        return None

    def open_from_files(
        self,
        detected: dict[str, Path],
        *,
        folder: Path | None = None,
        source: str = "files",
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
        self._session_gen += 1
        self.folder = folder or next((p.parent for p in detected.values()), None)
        self.files = dict(detected)
        self.dflash_info = None
        self.extra_info = None
        self.extra_raw = None
        self._orig_dflash_path = None
        self._orig_dflash_bytes = None
        self._working_dflash_path = None
        self._working_dflash_bytes = None
        self._orig_cflash_path = None
        self._orig_cflash_bytes = None
        self._working_cflash_path = None
        self._cflash_dirty = False
        self._fbl_key_file = None
        self._set_cflash_bytes(None)
        if source != "can":
            self.ident_items = []
            self.idauth_info = None
        if self.folder is not None and self.folder.is_dir():
            _remember_recent(self.folder)

        if "cflash" in detected and detected["cflash"].is_file():
            with contextlib.suppress(OSError):
                cf_path = detected["cflash"]
                cf_raw = cf_path.read_bytes()
                self._orig_cflash_path = cf_path
                self._orig_cflash_bytes = cf_raw
                self._working_cflash_path = cf_path
                self._cflash_bytes = cf_raw

        if "report" in detected and detected["report"].is_file():
            with contextlib.suppress(Exception):
                rep = json.loads(detected["report"].read_text(encoding="utf-8"))
                if not self.ident_items and isinstance(rep.get("ident"), list):
                    self.ident_items = list(rep["ident"])
                if not self.dflash_info and isinstance(rep.get("secrets"), dict):
                    self.dflash_info = rep["secrets"]
                if source == "can" and via_gateway is None and "via_gateway" in rep:
                    self.via_gateway = bool(rep.get("via_gateway"))

        df_file = detected.get("dflash") or detected.get("eel_logical")
        if df_file is not None and df_file.is_file():
            try:
                raw_in = df_file.read_bytes()
                df_raw = normalize_kombi_dflash_input(raw_in)
                self._orig_dflash_path = df_file
                self._orig_dflash_bytes = df_raw
                self._working_dflash_path = df_file
                self._working_dflash_bytes = df_raw
                edit_cand = df_file.parent / "ContiTool_edited" / "Dflash.bin"
                if edit_cand.is_file():
                    with contextlib.suppress(Exception):
                        edit_raw = normalize_kombi_dflash_input(edit_cand.read_bytes())
                        if edit_raw != df_raw:
                            self._working_dflash_path = edit_cand
                            self._working_dflash_bytes = edit_raw
                            self.files["dflash"] = edit_cand
                self.dflash_info = analyze_kombi_dflash(self._working_dflash_bytes, self._cflash_bytes)
            except Exception as exc:
                self.note.emit(tr(f"Ошибка разбора DataFlash Kombi: {exc}", f"Kombi DataFlash parse error: {exc}"))

        if self.dflash_info is not None:
            self._key = "secrets"
            self.select("secrets")
        else:
            self._key = "read"
            self.select("read")

        self.refresh()
        self.changed.emit()

    def _refresh_identity(self) -> None:
        super()._refresh_identity()
        vals = {item.get("did", ""): item.get("value", "").strip() for item in self.ident_items}
        sys_txt = vals.get("F197") or "KOMBI VDD (V850E2)"
        odx_txt = vals.get("F19E") or ""
        if "VDD" in odx_txt.upper() and "VDD" not in sys_txt.upper():
            sys_txt = f"{sys_txt} • {odx_txt}"
        self.lbl_sys.setText(sys_txt)
        if self.via_gateway:
            self.pill_source.setText(tr("Через шлюз J533 (UDS SL 7)", "Via J533 gateway (UDS SL 7)"))

    def _refresh_nav(self) -> None:
        super()._refresh_nav()
        for key, nav_row in self.nav_rows.items():
            nav_row.lbl_name.setText(_kombi_nav_title(key))
            nav_row.set_active(key == self._key)

        has_fd11 = bool(
            self.dflash_info and any(it["key_id"].startswith("fd11_") for it in self.dflash_info.get("items", []))
        )
        if has_fd11:
            set_pill(self.nav_rows["extra"].pill, "SL 7", "ok")
        else:
            set_pill(self.nav_rows["extra"].pill, "—", "muted")

        clear_layout(self.dumps_list)
        for kind, label in KOMBI_REQUIRED_DUMPS:
            p = self.files.get(kind)
            if p is not None and p.is_file():
                is_edited = (
                    kind == "dflash"
                    and self._orig_dflash_bytes is not None
                    and self._working_dflash_bytes is not None
                    and self._working_dflash_bytes != self._orig_dflash_bytes
                )
                sz_lbl = self._fmt_dump_size(p)
                if is_edited:
                    val = tr(f"{sz_lbl} • изменён", f"{sz_lbl} • edited")
                    tone = "warn"
                else:
                    val = f"{sz_lbl} ✓"
                    tone = "ok"
                self.dumps_list.addWidget(self._dump_ledger_row(label, val, tone, str(p)))
            else:
                self.dumps_list.addWidget(
                    self._dump_ledger_row(label, tr("не считан", "not read"), "muted")
                )
        for kind, label in KOMBI_OPTIONAL_DUMPS:
            p = self.files.get(kind)
            if p is not None and p.is_file():
                self.dumps_list.addWidget(
                    self._dump_ledger_row(label, f"{self._fmt_dump_size(p)} ✓", "ok", str(p))
                )

    def _build_read_page(self, lay: QVBoxLayout) -> None:
        busy = self.runner.is_busy
        iface = self.conn.interface or "slcan"
        native_ok = iface in FPKE_NATIVE_INTERFACES

        if not native_ok:
            warn = Callout("", "warn")
            warn.label.setText(
                tr(
                    f"<b>Выбран адаптер «{iface}».</b> Для чтения приборной панели Kombi VDD требуется нативный CAN-адаптер "
                    "(CANable / SLCAN / candleLight).",
                    f"<b>Adapter “{iface}” is selected.</b> Reading this Kombi VDD instrument cluster requires a native CAN adapter "
                    "(CANable / SLCAN / candleLight).",
                )
            )
            lay.addWidget(warn)

        sec_full = Section()
        sec_full.set_text(
            tr("Чтение памяти Kombi VDD (Supplier Level 7)", "Read Kombi VDD memory (Supplier Level 7)"),
            tr(
                "Извлекает индивидуальный 16-байтовый ключ FD11 Supplier Level 7 через буфер подгрузки NVM "
                "(0xFEDD5508 / 0xFEDD5530), авторизуется на уровень SL 7 (6E FD 11 07) и считывает все 132 блока "
                "EEL DataFlash (0x0001..0x0084, включая закрытые блоки WFS5 / иммо / SHE / CP 0x0063..0x006F). "
                "Работает как напрямую по Komfort CAN, так и через любой шлюз J533 по штатному 11-битному UDS.",
                "Extracts the personalized 16-byte FD11 Supplier Level 7 key via the NVM staging buffer "
                "(0xFEDD5508 / 0xFEDD5530), authenticates to SL 7 (6E FD 11 07), and reads all 132 EEL DataFlash "
                "blocks (0x0001..0x0084, including WFS5 / immo / SHE / CP blocks 0x0063..0x006F). "
                "Works both directly on Komfort CAN and behind any J533 gateway over standard 11-bit UDS.",
            ),
        )
        if self.via_gateway and native_ok:
            gw_badge = status_readout(
                tr("Через шлюз J533 (штатный 11-бит UDS SL 7)", "Via J533 gateway (standard 11-bit UDS SL 7)"),
                "ok",
            )
            sec_full.head.addWidget(gw_badge, 0, Qt.AlignmentFlag.AlignVCenter)

        opts = QGridLayout()
        opts.setHorizontalSpacing(24)
        opts.setVerticalSpacing(6)
        chk_cf = QCheckBox(tr("CodeFlash (3 МБ, 0x00000000..0x002FFFFF)", "CodeFlash (3 MB, 0x00000000..0x002FFFFF)"))
        chk_cf.setChecked(self._opt_cflash)
        chk_cf.toggled.connect(lambda v: setattr(self, "_opt_cflash", bool(v)))
        opts.addWidget(chk_cf, 0, 0)
        opts.setColumnStretch(1, 1)
        sec_full.body.addLayout(opts)

        btn_full = button(
            tr("Считать блок (SL 7)", "Read ECU (SL 7)"),
            "PrimaryBtn",
            slot=self._run_full_read,
        )
        btn_full.setEnabled(not busy and native_ok)
        btn_write_cur = button(
            tr("Записать в блок (SL 7)", "Write to ECU (SL 7)"),
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
            gateway_bridge=False,
            gateway_channel=self.gateway_channel,
            kombi_mode=True,
        )
        panel.note.connect(self.note.emit)
        panel.state_changed.connect(self._refresh_nav)
        self._active_can_panel = panel
        lay.addWidget(panel)

    def _build_extra_page(self, lay: QVBoxLayout) -> None:
        items = (self.dflash_info or {}).get("items") or []
        fd11_id = (self.dflash_info or {}).get("fd11_identifier") or "—"
        sec = Section()
        sec.set_text(
            tr("Ключи поставщика FD11 (EEL 0x0063 / 0x0064)", "FD11 Supplier Keys (EEL 0x0063 / 0x0064)"),
            tr(
                "Индивидуальные AES-128 ключи панели приборов Kombi VDD, извлечённые через буфер подгрузки NVM "
                "0xFEDD5508..0xFEDD5543 (NVM Block 0x5C, flg_e = 0x24) на уровне Supplier Level 7.",
                "Personalized AES-128 supplier keys of the Kombi VDD cluster extracted via the NVM staging buffer "
                "0xFEDD5508..0xFEDD5543 (NVM Block 0x5C, flg_e = 0x24) at Supplier Level 7.",
            ),
        )
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(8)

        rows: list[tuple[str, str, bool | None]] = [
            (tr("Идентификатор FD11 (0x0063+0x02, 15 Б)", "FD11 Identifier (0x0063+0x02, 15 B)"), fd11_id.upper(), True),
        ]
        for it in items:
            kid = str(it.get("key_id", ""))
            if kid.startswith(("fd11_", "aux_63", "aux_64")):
                rows.append((str(it.get("name", kid)), str(it.get("hex", "")).upper(), it.get("crc_valid")))

        for r_idx, (lbl_txt, val_txt, crc_ok) in enumerate(rows):
            lbl = QLabel(lbl_txt)
            lbl.setObjectName("Hint")
            val = QLabel(val_txt or "—")
            val.setFont(mono_font(12))
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(lbl, r_idx, 0)
            grid.addWidget(val, r_idx, 1)
            if crc_ok is not None:
                badge = status_readout("CRC32 OK" if crc_ok else "CRC32 ERR", "ok" if crc_ok else "err")
                grid.addWidget(badge, r_idx, 2)
        grid.setColumnStretch(1, 1)
        sec.body.addLayout(grid)
        lay.addWidget(sec)

    def _run_full_read(self) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        gen = self._session_gen
        port, iface = self.conn.port, self.conn.interface
        ident_list = list(self.ident_items or [{"did": "F187", "value": self.part_number}])
        try:
            sdir = new_session(
                self.conn.out_dir,
                unit_of_ident(ident_list),
                "kombi_read",
                dumps=True,
            )
        except OSError as exc:
            QMessageBox.warning(self, tr("Ошибка создания папки сессии", "Session directory error"), str(exc))
            return
        read_cf = self._opt_cflash
        via_gw = self.via_gateway

        def task(rep: Any) -> dict[str, Any]:
            return can_kombi_full_read(
                port,
                interface=iface,
                session_dir=sdir,
                read_cflash=read_cf,
                ident=ident_list,
                keep_open=not via_gw,
                via_gateway=via_gw,
                reporter=rep,
            )

        def done(res: dict[str, Any]) -> None:
            if not _qt_valid(self) or not self.is_open or self._session_gen != gen:
                return
            out_folder = Path(str(res.get("session_dir", sdir)))
            detected = detect_kombi_files([out_folder])
            self.open_from_files(
                detected,
                folder=out_folder,
                source="can",
                via_gateway=via_gw,
                gateway_bridge=False,
                gateway_channel=self.gateway_channel,
            )

        self.runner.run_task(
            tr("Чтение DataFlash Kombi (SL 7)", "Reading Kombi DataFlash (SL 7)"),
            task,
            on_success=lambda res: QTimer.singleShot(0, lambda r=res: done(r)),
        )

    def write_dflash_to_ecu(self, *, confirm: bool = True) -> None:
        if self.runner.is_busy:
            return
        if self._page_commit_fn is not None:
            if not self._page_commit_fn(True):
                return
        cand_bytes, _cf_bytes = self._own_dflash_and_cflash()
        if cand_bytes is None:
            QMessageBox.information(
                self,
                tr("Нет данных для записи", "No DataFlash loaded"),
                tr("Сначала считайте приборную панель Kombi или откройте дамп DataFlash.", "Read the Kombi cluster or open a DataFlash dump first."),
            )
            return

        orig_bytes = self._orig_dflash_bytes if self._orig_dflash_bytes is not None else cand_bytes
        chg = summarize_kombi_dflash_changes(orig_bytes, cand_bytes)
        if not ensure_ready(self.conn, self):
            return
        if self._write_blocked():
            return
        iface = self.conn.interface or "slcan"

        if confirm:
            tot_ids = int(((self.dflash_info or {}).get("pool") or {}).get("total_ids", 132) or 132)
            bullets = "\n".join(f"  • {line}" for line in (chg.get("lines") or []))
            if not bullets:
                bullets = tr("  • Перезапись изменённых блоков EEL DataFlash (SL 7)", "  • Rewrite modified EEL DataFlash blocks (SL 7)")
            prompt_txt = tr(
                f"Записать следующие изменения в приборную панель Kombi {self.part_number} на уровне SL 7 (UDS 0x3D)?\n\n"
                f"{bullets}\n\n"
                f"Перед записью ContiTool автоматически сохранит резервную копию всех {tot_ids} блоков EEL "
                "(Dflash_before.bin), выполнит контрольное чтение и перезапустит панель.",
                f"Write the following changes to Kombi cluster {self.part_number} at SL 7 (UDS 0x3D)?\n\n"
                f"{bullets}\n\n"
                f"ContiTool will automatically back up all {tot_ids} EEL blocks (Dflash_before.bin) before writing, "
                "verify every written record, and reboot the cluster.",
            )
            ans = QMessageBox.question(
                self,
                tr("Запись в приборную панель Kombi (SL 7)", "Write to Kombi cluster (SL 7)"),
                prompt_txt,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        gen = self._session_gen
        port = self.conn.port
        ident_list = list(self.ident_items or [{"did": "F187", "value": self.part_number}])
        try:
            sdir = new_session(
                self.conn.out_dir,
                unit_of_ident(ident_list),
                "kombi_write",
                dumps=True,
            )
        except OSError as exc:
            QMessageBox.warning(self, tr("Ошибка создания папки сессии", "Session directory error"), str(exc))
            return

        via_gw = self.via_gateway

        def task(rep: Any) -> dict[str, Any]:
            return can_kombi_write_dflash(
                port,
                cand_bytes,
                interface=iface,
                base_dflash=orig_bytes,
                session_dir=sdir,
                wake_seconds=self._wake_seconds,
                reset_after=True,
                keep_open=not via_gw,
                via_gateway=via_gw,
                reporter=rep,
            )

        self.runner.run_task(
            tr("Запись изменений в Kombi (SL 7)", "Writing changes to Kombi (SL 7)"),
            task,
            on_success=lambda res: QTimer.singleShot(
                0, lambda r=res: self._adopt_written_session(r, sdir, expected_gen=gen)
            ),
        )

    def restore_dflash_from_file(self, path: Path | None = None, *, confirm: bool = True) -> None:
        if self.runner.is_busy:
            return
        if path is None:
            picked, _ = QFileDialog.getOpenFileName(
                self,
                tr("Выберите бэкап DataFlash Kombi (Dflash.bin / EelLogical.bin)", "Select Kombi DataFlash backup (Dflash.bin / EelLogical.bin)"),
                str(self.folder.parent if self.folder else self.conn.out_dir),
                "Kombi DataFlash (*.bin);;All files (*)",
            )
            if not picked:
                return
            path = Path(picked)

        try:
            raw = path.read_bytes()
        except OSError as exc:
            QMessageBox.warning(self, tr("Ошибка чтения файла", "File read error"), str(exc))
            return
        if not is_kombi_dflash(raw):
            QMessageBox.warning(
                self,
                tr("Некорректный файл DataFlash Kombi", "Invalid Kombi DataFlash file"),
                tr(
                    f"Файл «{path.name}» ({len(raw)} Б) не является валидным дампом DataFlash Kombi (65 536 Б или {KOMBI_EEL_LOGICAL_SIZE} Б).",
                    f"File “{path.name}” ({len(raw)} B) is not a valid Kombi DataFlash dump (65,536 B or {KOMBI_EEL_LOGICAL_SIZE} B).",
                ),
            )
            return

        if not ensure_ready(self.conn, self):
            return
        if self._write_blocked():
            return
        iface = self.conn.interface or "slcan"

        if confirm:
            prompt_txt = tr(
                f"Записать бэкап DataFlash из файла «{path.name}» в приборную панель Kombi {self.part_number} на уровне SL 7?\n\n"
                "Перед записью текущий DataFlash панели будет автоматически сохранён в Dflash_before.bin.",
                f"Write DataFlash backup from “{path.name}” to Kombi cluster {self.part_number} at SL 7?\n\n"
                "The cluster's current DataFlash will be backed up to Dflash_before.bin before writing.",
            )
            ans = QMessageBox.question(
                self,
                tr("Залить бэкап DataFlash Kombi", "Write Kombi DataFlash backup"),
                prompt_txt,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        gen = self._session_gen
        port = self.conn.port
        ident_list = list(self.ident_items or [{"did": "F187", "value": self.part_number}])
        try:
            sdir = new_session(
                self.conn.out_dir,
                unit_of_ident(ident_list),
                "kombi_restore",
                dumps=True,
            )
        except OSError as exc:
            QMessageBox.warning(self, tr("Ошибка создания папки сессии", "Session directory error"), str(exc))
            return

        via_gw = self.via_gateway

        def task(rep: Any) -> dict[str, Any]:
            return can_kombi_write_dflash(
                port,
                raw,
                interface=iface,
                base_dflash=None,
                session_dir=sdir,
                wake_seconds=self._wake_seconds,
                reset_after=True,
                keep_open=not via_gw,
                via_gateway=via_gw,
                reporter=rep,
            )

        self.runner.run_task(
            tr("Запись бэкапа DataFlash в Kombi (SL 7)", "Writing DataFlash backup to Kombi (SL 7)"),
            task,
            on_success=lambda res: QTimer.singleShot(
                0, lambda r=res: self._adopt_written_session(r, sdir, expected_gen=gen)
            ),
        )
