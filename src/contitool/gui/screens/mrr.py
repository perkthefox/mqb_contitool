"""Working screen for VAG MQB 13 ACC Radar / J428 (Bosch MRR1Plus 3Q0 & MRRevo14F 5Q0/3QF)."""

from __future__ import annotations

from collections.abc import Callable
import contextlib
import json
from pathlib import Path
import secrets as _py_secrets
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication
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
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid as _qt_valid

from contitool.can.bridge import BRIDGE_NATIVE_INTERFACES
from contitool.can.ecus import DiscoveredEcu, can_uds_clear_dtc, can_uds_read_dtc
from contitool.can.mrr import (
    can_mrr_activate_swap,
    can_mrr_deactivate_cp,
    can_mrr_flash_frf,
    can_mrr_read_keys,
    can_mrr_read_memory,
    can_mrr_reset_cp_counter,
    can_mrr_restore_cp_stock,
    can_mrr_restore_swap_stock,
    can_mrr_status,
    can_mrr_swap_status,
    can_mrr_write_keys,
)
from contitool.core.bcm import bcm_extract_cluster_ffb_material
from contitool.core.fpke import is_fpke_dflash
from contitool.core.kombi import is_kombi_dflash
from contitool.core.mrr import (
    MRR_APP_BASE,
    MRR_BOOT_BASE,
    MRR_BOOT_SIZE,
    MRR_DFLASH_ADDR,
    MRR_DFLASH_SIZE,
    MRR_GEN1_SWAP_PACKAGES,
    MRR_GEN2_SWAP_GROUPS,
    MRR_GEN2_SWAP_PRESETS,
    MRR_SRAM_ADDR,
    MRR_UDS_RX_ID,
    MRR_UDS_TX_ID,
    MrrFrfImage,
    mrr_describe_gen2_swap_groups,
    mrr_detect_profile,
    mrr_frf_compatibility,
    mrr_get_swap_patch_stats,
    mrr_inspect_cflash_cp_state,
    mrr_inspect_cflash_swap_state,
    mrr_parse_dflash_fee,
    mrr_read_frf,
    mrr_support_info,
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
from contitool.gui.workspace import _remember_recent
from contitool.i18n import subscribe_lang_change, tr
from contitool.storage import new_session, unit_name

MRR_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("main", ("cp_keys", "memory")),
    ("service", ("status", "dtc")),
)

_PROFILE_CHOICES: tuple[tuple[str, str], ...] = (
    ("0130", "0130 · 3Q0 907 572 A (MPC5674K, 1.5 MiB)"),
    ("0192", "0192 · 3Q0 907 572 B (MPC5674K, 1.5 MiB)"),
    ("0194", "0194 · 3Q0 907 572 B/C (MPC5674K, 1.5 MiB)"),
    ("0196", "0196 · 3Q0 907 572 C (MPC5674K, 1.5 MiB)"),
    ("0682", "0682 · 3QF 907 561 D (MPC5675K, 2.0 MiB)"),
    ("X720", "X720 · 5Q0 907 572 M (MPC5675K, 2.0 MiB)"),
    ("0771", "0771 · 5Q0 907 572 R (MPC5675K, 2.0 MiB)"),
    ("0780", "0780 · 5Q0 907 572 S (MPC5675K, 2.0 MiB)"),
)

_CP_DTC_DISPLAY_CODES = frozenset({"U110100", "U110000", "U111400"})


def _mrr_nav_title(key: str) -> str:
    return {
        "cp_keys": tr("Защита компонентов", "Component protection"),
        "memory": tr("Память и FRF", "Memory & FRF"),
        "status": tr("Паспорт и статус", "Passport & status"),
        "dtc": tr("Ошибки (DTC)", "Fault codes (DTC)"),
    }[key]


def _human_patch_state(state: str | None) -> tuple[str, str]:
    if state == "cp_disabled":
        return tr("CP OFF (патч)", "CP OFF (patched)"), "ok"
    if state == "stock":
        return tr("Заводской сток", "Factory stock"), "info"
    if state == "partial":
        return tr("Частичный патч", "Partial patch"), "warn"
    if state == "unsupported_sw":
        return tr("ПО не проверено", "Unverified SW"), "warn"
    if state == "unknown":
        return tr("Байты не совпали", "Bytes mismatch"), "err"
    return tr("Не считано", "Not read"), "muted"


def _human_swap_state(state: str | None) -> tuple[str, str]:
    if state == "swap_activated":
        return tr("SWaP ON (патч)", "SWaP ON (patched)"), "ok"
    if state == "stock":
        return tr("Заводской сток", "Factory stock"), "info"
    if state == "partial":
        return tr("Частичный патч", "Partial patch"), "warn"
    if state == "unsupported_sw":
        return tr("ПО не проверено", "Unverified SW"), "warn"
    if state == "unknown":
        return tr("Байты не совпали", "Bytes mismatch"), "err"
    return tr("Не считано", "Not read"), "muted"


def _fmt_size_kib(n_bytes: int) -> str:
    if n_bytes >= 1024 * 1024 and n_bytes % (512 * 1024) == 0:
        mb = n_bytes / (1024 * 1024)
        return tr(f"{mb:.1f} МиБ", f"{mb:.1f} MiB")
    if n_bytes >= 1024:
        return tr(f"{n_bytes // 1024} КиБ", f"{n_bytes // 1024} KiB")
    return tr(f"{n_bytes} Б", f"{n_bytes} B")


class MrrFlashCpDialog(Dialog):
    """Architectural confirmation dialog before erasing & programming C90FL Code Flash sectors on 13 ACC Radar."""

    def __init__(
        self,
        *,
        restore_stock: bool,
        profile: dict[str, Any],
        part_number: str,
        session_dir: Path | None = None,
        via_gateway: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        title = (
            tr("Вернуть заводскую проверку CP", "Restore factory CP check")
            if restore_stock
            else tr("Деактивация защиты компонентов (CP)", "Component Protection (CP) deactivation")
        )
        subtitle = tr(
            f"13 ACC Radar · {part_number} · профиль ПО {profile['sw']} ({profile['mcu']})",
            f"13 ACC Radar · {part_number} · SW profile {profile['sw']} ({profile['mcu']})",
        )
        super().__init__(parent, title, subtitle, width=640)
        self.body.setSpacing(10)

        sectors = profile.get("cp_affected_sectors") or ()
        sec_list = ", ".join(
            f"<code>0x{addr:08X}</code> ({_fmt_size_kib(sz)})" for addr, sz in sectors
        ) or "—"
        n_pts = len(profile.get("patches") or ())

        if restore_stock:
            what_html = tr(
                f"<b>Что сделает программа:</b> считает текущие секторы Code Flash ({sec_list}), сохранит их бэкап, "
                f"вернёт исходные заводские байты в <b>{n_pts} точках</b> проверки CP, прошьёт секторы с проверкой "
                "SHA-256 и выполнит перезагрузку (<code>UDS 11 02</code>).",
                f"<b>What ContiTool will do:</b> read the target Code Flash sectors ({sec_list}), save a backup, "
                f"restore original factory bytes at all <b>{n_pts} CP check sites</b>, program & verify via SHA-256, "
                "and reboot the radar (<code>UDS 11 02</code>).",
            )
        else:
            what_html = tr(
                f"<b>Что сделает программа:</b> считает целевые секторы Code Flash ({sec_list}), сохранит полный бэкап, "
                f"применит <b>{n_pts}-точечный патч</b> отключения CP, прошьёт секторы с проверкой SHA-256, "
                "обнулит счётчик <code>0x03DE</code>, очистит DTC и перезагрузит радар (<code>UDS 11 02</code>).",
                f"<b>What ContiTool will do:</b> read the target Code Flash sectors ({sec_list}), save a full backup, "
                f"apply the <b>{n_pts}-site CP-disable patch</b>, program & verify via SHA-256, "
                "zero counter <code>0x03DE</code>, clear DTCs, and reboot the radar (<code>UDS 11 02</code>).",
            )
        lbl_what = hint(what_html)
        lbl_what.setTextFormat(Qt.TextFormat.RichText)
        self.body.addWidget(lbl_what)

        bkp_box = Callout("info")
        bkp_target_ru = f"папку <code>{session_dir.name}</code>" if session_dir is not None else "папку сессии <code>writes/</code>"
        bkp_target_en = f"<code>{session_dir.name}</code>" if session_dir is not None else "a new <code>writes/</code> session folder"
        bkp_box.label.setText(
            tr(
                f"<b>Автоматический бэкап:</b> исходные секторы будут сохранены перед стиранием в {bkp_target_ru}.",
                f"<b>Automatic backup:</b> original sectors will be saved before erasing into {bkp_target_en}.",
            )
        )
        self.body.addWidget(bkp_box)

        if via_gateway:
            gw_box = Callout("warn")
            gw_box.label.setText(
                tr(
                    "<b>Работа в автомобиле через RAM-мост шлюза J533:</b> заглушите двигатель, включите зажигание "
                    "(<b>KL15 ON</b>) и подключите зарядное устройство АКБ. На время прошивки мост J533 временно "
                    "приостанавливает другие шины автомобиля (появятся предупреждения на приборной панели). "
                    "По завершении очистите ошибки связи (<code>U112100</code>).",
                    "<b>In-vehicle flashing via J533 gateway RAM-Bridge:</b> turn the engine OFF, switch ignition ON "
                    "(<b>KL15 ON</b>), and connect a battery charger. During flashing, the J533 bridge temporarily "
                    "pauses other vehicle buses (dashboard warnings will appear). Clear communication DTCs "
                    "(<code>U112100</code>) afterwards.",
                )
            )
            self.body.addWidget(gw_box)

        warn_box = Callout("warn")
        warn_box.label.setText(
            tr(
                "<b>Не отключайте питание +12 В и CAN-адаптер</b> до завершения прошивки и перезагрузки радара. "
                "Запись выполняется через HIS-драйвер с обслуживанием сторожевого таймера SBC.",
                "<b>Keep +12 V power and CAN adapter connected</b> until flashing and reboot finish. "
                "Programming runs via the HIS Flash driver with active SBC watchdog servicing.",
            )
        )
        self.body.addWidget(warn_box)

        ok_text = (
            tr("Вернуть заводской сток CP", "Restore stock CP")
            if restore_stock
            else tr("Прошить патч CP OFF", "Flash CP OFF patch")
        )
        self.btn_ok = button(ok_text, "DangerBtn" if restore_stock else "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)


class MrrFlashSwapDialog(Dialog):
    """Architectural confirmation dialog before flashing the direct Code Flash SWaP / FSC activation patch."""

    def __init__(
        self,
        *,
        restore_stock: bool,
        profile: dict[str, Any],
        part_number: str,
        session_dir: Path | None = None,
        package_index: int = 6,
        groups: tuple[int, int, int, int] = (8, 3, 4, 7),
        via_gateway: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        title = (
            tr("Вернуть заводскую проверку SWaP / FSC", "Restore factory SWaP / FSC evaluation")
            if restore_stock
            else tr("Прямая активация функций SWaP / FSC (Code Flash)", "Direct SWaP / FSC Feature Activation (Code Flash)")
        )
        subtitle = tr(
            f"13 ACC Radar · {part_number} · профиль ПО {profile['sw']} ({profile['mcu']})",
            f"13 ACC Radar · {part_number} · SW profile {profile['sw']} ({profile['mcu']})",
        )
        super().__init__(parent, title, subtitle, width=640)
        self.body.setSpacing(10)

        sectors = profile.get("swap_affected_sectors") or ()
        sec_list = ", ".join(
            f"<code>0x{addr:08X}</code> ({_fmt_size_kib(sz)})" for addr, sz in sectors
        ) or "—"
        swap_cfg = profile.get("swap_config") or {}
        gen = int(swap_cfg.get("generation") or (1 if profile.get("mcu") == "MPC5674K" else 2))
        n_pts, _n_bytes = mrr_get_swap_patch_stats(profile)
        sec_word_ru = "секторы" if len(sectors) > 1 else "сектор"
        sec_word_en = "sectors" if len(sectors) > 1 else "sector"

        if restore_stock:
            what_html = tr(
                f"<b>Что сделает программа:</b> считает {sec_word_ru} Code Flash ({sec_list}), сохранит бэкап, "
                f"вернёт исходные заводские байты в <b>{n_pts} точках</b> логики SWaP/FSC и <code>22 3C 00</code>, "
                f"прошьёт {sec_word_ru} с проверкой SHA-256 и выполнит перезагрузку радара (<code>UDS 11 02</code>).",
                f"<b>What ContiTool will do:</b> read the target Code Flash {sec_word_en} ({sec_list}), save a backup, "
                f"restore original factory bytes at all <b>{n_pts} SWaP/FSC &amp; 22 3C 00 sites</b>, program &amp; verify via SHA-256, "
                "and reboot the radar (<code>UDS 11 02</code>).",
            )
        elif gen == 1:
            pkg = MRR_GEN1_SWAP_PACKAGES.get(package_index, MRR_GEN1_SWAP_PACKAGES[6])
            pkg_title = tr(pkg["title_ru"], pkg["title_en"])
            what_html = tr(
                f"<b>Что сделает программа:</b> считает {sec_word_ru} Code Flash ({sec_list}), сохранит полный бэкап и "
                f"применит {n_pts}-точечный патч <code>SWaP_MainFunction</code> + <code>UDS 22 3C 00</code> (Поколение 1 · 3Q0):<br>"
                f"• Активный пакет: <b>FS-ID 0x{pkg['fsid_hex']}</b> (уровень <b>{pkg['level']}</b> — {pkg_title})<br>"
                f"• Диагностика <code>22 3C 00</code> (ODIS / VCDS / ContiTool) покажет <code>0x{pkg['fsid_hex']}</code> активным (<code>0xFF</code>)<br>"
                "• Блокировка ошибок Dem (FSC), проверка SHA-256 и сброс <code>11 02</code>.",
                f"<b>What ContiTool will do:</b> read the Code Flash {sec_word_en} ({sec_list}), save a full backup, and "
                f"apply the {n_pts}-site <code>SWaP_MainFunction</code> + <code>UDS 22 3C 00</code> patch (Generation 1 · 3Q0):<br>"
                f"• Active package: <b>FS-ID 0x{pkg['fsid_hex']}</b> (level <b>{pkg['level']}</b> — {pkg_title})<br>"
                f"• UDS <code>22 3C 00</code> diagnostics (ODIS / VCDS / ContiTool) will report <code>0x{pkg['fsid_hex']}</code> active (<code>0xFF</code>)<br>"
                "• Suppress FSC Dem faults, verify SHA-256, and reboot (<code>11 02</code>).",
            )
        else:
            grp_info = mrr_describe_gen2_swap_groups(groups)
            fsid_str = ", ".join(f"<code>{f}</code>" for f in grp_info["active_fsids"]) or tr("нет", "none")
            b12_13 = grp_info["coding_byte12_13_hex"]
            what_html = tr(
                f"<b>Что сделает программа:</b> считает {sec_word_ru} Code Flash ({sec_list}), сохранит полный бэкап и "
                f"применит {n_pts}-точечный патч координатора SWaP + стаб <code>UDS 22 3C 00</code> (Поколение 2 · 5Q0/3QF):<br>"
                f"• Группы (g0..g3): <b>{groups[0]}, {groups[1]}, {groups[2]}, {groups[3]}</b> "
                f"(Coding 0x0600 Byte 12..13 = <code>{b12_13}</code>)<br>"
                f"• Активные FS-ID (NvM 0x42 и UDS <code>22 3C 00</code>): {fsid_str}<br>"
                "• Прошивка с проверкой SHA-256, очистка DTC и перезагрузка (<code>UDS 11 02</code>).",
                f"<b>What ContiTool will do:</b> read the Code Flash {sec_word_en} ({sec_list}), save a full backup, and "
                f"apply the {n_pts}-site SWaP coordinator + <code>UDS 22 3C 00</code> stub patch (Generation 2 · 5Q0/3QF):<br>"
                f"• Groups (g0..g3): <b>{groups[0]}, {groups[1]}, {groups[2]}, {groups[3]}</b> "
                f"(Coding 0x0600 Byte 12..13 = <code>{b12_13}</code>)<br>"
                f"• Active FS-IDs (NvM 0x42 &amp; UDS <code>22 3C 00</code>): {fsid_str}<br>"
                "• Program &amp; verify via SHA-256, clear DTCs, and reboot (<code>UDS 11 02</code>).",
            )
        lbl_what = hint(what_html)
        lbl_what.setTextFormat(Qt.TextFormat.RichText)
        self.body.addWidget(lbl_what)

        bkp_box = Callout("info")
        bkp_target_ru = f"папку <code>{session_dir.name}</code>" if session_dir is not None else "папку сессии <code>writes/</code>"
        bkp_target_en = f"<code>{session_dir.name}</code>" if session_dir is not None else "a new <code>writes/</code> session folder"
        bkp_box.label.setText(
            tr(
                f"<b>Автоматический бэкап:</b> исходные {sec_word_ru} будут сохранены перед стиранием в {bkp_target_ru}.",
                f"<b>Automatic backup:</b> original {sec_word_en} will be saved before erasing into {bkp_target_en}.",
            )
        )
        self.body.addWidget(bkp_box)

        if via_gateway:
            gw_box = Callout("warn")
            gw_box.label.setText(
                tr(
                    "<b>Работа в автомобиле через RAM-мост шлюза J533:</b> заглушите двигатель, включите зажигание "
                    "(<b>KL15 ON</b>) и подключите зарядное устройство АКБ. На время прошивки мост J533 временно "
                    "приостанавливает другие шины автомобиля (появятся предупреждения на приборной панели). "
                    "По завершении очистите ошибки связи (<code>U112100</code>).",
                    "<b>In-vehicle flashing via J533 gateway RAM-Bridge:</b> turn the engine OFF, switch ignition ON "
                    "(<b>KL15 ON</b>), and connect a battery charger. During flashing, the J533 bridge temporarily "
                    "pauses other vehicle buses (dashboard warnings will appear). Clear communication DTCs "
                    "(<code>U112100</code>) afterwards.",
                )
            )
            self.body.addWidget(gw_box)

        warn_box = Callout("warn")
        warn_box.label.setText(
            tr(
                "<b>Не отключайте питание +12 В и CAN-адаптер</b> до завершения прошивки и перезагрузки радара. "
                "Запись выполняется через HIS-драйвер с обслуживанием сторожевого таймера SBC.",
                "<b>Keep +12 V power and CAN adapter connected</b> until flashing and reboot finish. "
                "Programming runs via the HIS Flash driver with active SBC watchdog servicing.",
            )
        )
        self.body.addWidget(warn_box)

        ok_text = (
            tr("Вернуть заводской сток SWaP", "Restore stock SWaP")
            if restore_stock
            else tr("Прошить активацию SWaP / FSC", "Flash SWaP / FSC activation")
        )
        self.btn_ok = button(ok_text, "DangerBtn" if restore_stock else "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)


class MrrFlashFrfDialog(Dialog):
    """Confirmation dialog before flashing a factory-signed ODIS FRF / ODX-F over pure UDS 10 02."""

    def __init__(
        self,
        *,
        frf: MrrFrfImage,
        part_number: str,
        current_sw: str = "",
        warnings: list[str] | None = None,
        recovery_mode: bool = False,
        via_gateway: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        title = tr("Прошивка заводского FRF / ODX-F (UDS 10 02)", "Flash Factory FRF / ODX-F (UDS 10 02)")
        cur_txt = f"{part_number} ({current_sw})" if current_sw else part_number
        subtitle = tr(
            f"13 ACC Radar · {cur_txt} → {frf.part_number} {frf.sw_version} ({frf.mcu})",
            f"13 ACC Radar · {cur_txt} → {frf.part_number} {frf.sw_version} ({frf.mcu})",
        )
        super().__init__(parent, title, subtitle, width=660)
        self.body.setSpacing(10)

        fmt_txt = "LZSS 0xA0" if frf.app.data_format == 0xA0 else "RAW 0x00"
        what_html = tr(
            f"<b>Что сделает программа (чистый UDS <code>0x757 → 0x7C1</code>):</b> переведёт радар в загрузчик "
            f"<code>FBLv (10 02)</code>, пройдёт <code>SA2 (27 11/12)</code>, запишет <code>2E F1 5A</code>, "
            f"загрузит и проверит по RSA-1024 драйвер <code>DB_99ERASEROUTI</code> ({_fmt_size_kib(frf.driver.uncompressed_size)}), "
            f"сотрёт блок <code>0x10</code>, прошьёт <code>DB_10FLASHDATA</code> ({len(frf.app.stream) // 1024} КиБ {fmt_txt} → "
            f"{_fmt_size_kib(frf.app.uncompressed_size)}), подтвердит подпись RSA-1024 + CRC-32 (<code>31 01 02 02</code>) "
            "и перезагрузит блок (<code>11 01</code>).",
            f"<b>What ContiTool will do (pure UDS <code>0x757 → 0x7C1</code>):</b> enter <code>FBLv (10 02)</code>, "
            f"authenticate <code>SA2 (27 11/12)</code>, write <code>2E F1 5A</code>, upload & RSA-1024 verify "
            f"<code>DB_99ERASEROUTI</code> ({_fmt_size_kib(frf.driver.uncompressed_size)}), erase logical block "
            f"<code>0x10</code>, stream <code>DB_10FLASHDATA</code> ({len(frf.app.stream) // 1024} KiB {fmt_txt} → "
            f"{_fmt_size_kib(frf.app.uncompressed_size)}), verify RSA-1024 + CRC-32 (<code>31 01 02 02</code>), "
            "and reset the radar (<code>11 01</code>).",
        )
        lbl_what = hint(what_html)
        lbl_what.setTextFormat(Qt.TextFormat.RichText)
        self.body.addWidget(lbl_what)

        info_box = Callout("info")
        route_ru = (
            "Работает напрямую через штатную UDS-маршрутизацию шлюза J533 (RAM-мост не требуется)."
            if via_gateway
            else "Выполняется по штатному протоколу UDS ODIS (без XCP и патчей)."
        )
        route_en = (
            "Runs natively through J533 gateway UDS routing (no RAM-Bridge required)."
            if via_gateway
            else "Runs via standard ODIS UDS programming protocol (no XCP or patches)."
        )
        info_box.label.setText(
            tr(
                f"<b>Подпись RSA-1024 проверена заранее:</b> драйвер и приложение подписаны заводским ключом Bosch FBLv. "
                f"Память <code>DFLASH0</code> (ключи IKA/GFA, кодировка, калибровка антенны) <b>не стирается</b>. "
                f"Любые ранее записанные патчи CP / SWaP в Code Flash будут заменены на заводское ПО. {route_ru}",
                f"<b>RSA-1024 signatures pre-verified:</b> both driver and app verify against the Bosch FBLv key. "
                f"<code>DFLASH0</code> (IKA/GFA keys, coding, antenna alignment) is <b>preserved</b>. "
                f"Any prior Code Flash CP / SWaP patches will be replaced with factory firmware. {route_en}",
            )
        )
        self.body.addWidget(info_box)

        if recovery_mode:
            rec_box = Callout("info")
            rec_box.label.setText(
                tr(
                    "<b>Режим восстановления FBLv:</b> опрос паспорта приложения пропускается; вход в <code>10 02</code> выполняется напрямую.",
                    "<b>FBLv recovery mode:</b> application passport read is optional; entering <code>10 02</code> directly.",
                )
            )
            self.body.addWidget(rec_box)

        warn_lines = list(warnings or [])
        if warn_lines:
            w_box = Callout("warn")
            w_box.label.setText(
                tr("<b>Обратите внимание:</b><br>", "<b>Please note:</b><br>")
                + "<br>".join(f"• {w}" for w in warn_lines)
            )
            self.body.addWidget(w_box)

        pwr_box = Callout("warn")
        pwr_box.label.setText(
            tr(
                "<b>Не отключайте питание +12 В и CAN-адаптер</b> до завершения прошивки и перезагрузки (обычно ~1–2 мин). "
                "При обрыве радар останется в загрузчике FBLv — восстановить его можно повторной прошивкой FRF с галочкой восстановления.",
                "<b>Keep +12 V power and CAN adapter connected</b> until flashing and reboot complete (~1–2 min). "
                "If interrupted, the radar stays in FBLv and can be recovered by re-flashing an FRF with recovery mode enabled.",
            )
        )
        self.body.addWidget(pwr_box)

        ok_text = (
            tr("Подтвердить и прошить FRF", "Confirm & flash FRF")
            if warn_lines
            else tr("Прошить FRF / ODX-F", "Flash FRF / ODX-F")
        )
        self.btn_ok = button(ok_text, "PrimaryBtn", slot=self.accept)
        self.finish(ok=self.btn_ok)


class _MrrNavRow(QWidget):
    """Unified ContiTool sidebar row: page name on left, quiet semantic status pill on right."""

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


class MrrScreen(QWidget):
    """Unified architectural workspace for 13 ACC Radar (Bosch MRR1Plus 3Q0 & MRRevo14F 5Q0/3QF)."""

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
        self._session_gen: int = 0
        self._offline_mode = False
        self._via_gateway = False
        self._gateway_bridge = False
        self._gateway_channel = 2
        self._key = "cp_keys"
        self._last_rendered_key = ""
        self._show_patch_points = False
        self._show_swap_points = False
        self._cp_points_table: QFrame | None = None
        self._btn_cp_points: QPushButton | None = None
        self._cp_points_count: int = 0
        self._swap_points_table: QFrame | None = None
        self._btn_swap_points: QPushButton | None = None
        self._swap_points_count: int = 0

        self._passport: dict[str, Any] = {}
        self._status: dict[str, Any] = {}
        self._swap_uds: dict[str, Any] = {}
        self._profile: dict[str, Any] = mrr_detect_profile()
        self._profile_override: str = ""
        self._ika_hex: str = ""
        self._gfa_hex: str = ""
        self._ecu_boot_sum_hex: str = ""
        self._cflash_cp: dict[str, Any] = {}
        self._cflash_swap: dict[str, Any] = {}
        self._dflash_fee: dict[str, Any] = {}
        self._sram_mirrors: dict[str, Any] = {}
        self._last_mem_report: dict[str, Any] = {}
        self._dtcs: list[dict[str, Any]] | None = None

        # Persistent form drafts (None = inherit from extracted radar key; "" = explicitly cleared by user)
        self._draft_cur_ika: str | None = None
        self._draft_new_ika: str = ""
        self._draft_new_gfa: str | None = None
        self._draft_write_reset: bool = True
        self._draft_swap_gen1_pkg: int = 6
        self._draft_swap_gen2_groups: list[int] = [8, 3, 4, 7]

        self._can_action_buttons: list[tuple[QPushButton, bool, bool]] = []

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
        self.runner.busy_changed.connect(self._on_busy_changed)
        self._unsub = subscribe_lang_change(self._on_lang_changed)
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.select("cp_keys")
        self.refresh()

    # ────────────────────────────── Public State API ──────────────────────────────

    @property
    def is_open(self) -> bool:
        return self._is_open

    @property
    def part_number(self) -> str:
        pn = self._passport.get("part_number") or self._passport.get("hw_part_number")
        if pn:
            return str(pn)
        if self._profile_override or self._profile.get("verified"):
            return str(self._profile.get("unit") or "13 ACC")
        return tr("Радар 13 ACC", "13 ACC Radar")

    @property
    def via_gateway(self) -> bool:
        return self._via_gateway

    @property
    def gateway_bridge(self) -> bool:
        return self._gateway_bridge

    @property
    def gateway_channel(self) -> int:
        return self._gateway_channel

    def _reset_session_state(self) -> None:
        self._session_gen += 1
        self._passport = {}
        self._status = {}
        self._swap_uds = {}
        self._profile_override = ""
        self._profile = mrr_detect_profile()
        self._ika_hex = ""
        self._gfa_hex = ""
        self._ecu_boot_sum_hex = ""
        self._cflash_cp = {}
        self._cflash_swap = {}
        self._dflash_fee = {}
        self._sram_mirrors = {}
        self._last_mem_report = {}
        self._selected_frf: MrrFrfImage | None = None
        self._selected_frf_path: Path | None = None
        self._frf_recovery_mode = False
        self._last_frf_report: dict[str, Any] = {}
        self._dtcs = None
        self._draft_cur_ika = None
        self._draft_new_ika = ""
        self._draft_new_gfa = None
        self._draft_write_reset = True
        self._draft_swap_gen1_pkg = 6
        self._draft_swap_gen2_groups = [8, 3, 4, 7]
        self._show_patch_points = False
        self._show_swap_points = False
        self._cp_points_table = None
        self._btn_cp_points = None
        self._cp_points_count = 0
        self._swap_points_table = None
        self._btn_swap_points = None
        self._swap_points_count = 0

    def _unit_folder_name(self) -> str:
        hw_pn = str(self._passport.get("hw_part_number") or self._passport.get("part_number") or "")
        fazit = str(self._passport.get("fazit") or "")
        u = unit_name(hw_pn, fazit)
        if u != "unknown":
            return u
        if hw_pn:
            fallback = unit_name(hw_pn, "MRR")
            if fallback != "unknown":
                return fallback
        return f"mrr_{self._profile.get('sw', 'unknown')}"

    def _mrr_session_dir(self, kind: str, *, dumps: bool = False) -> Path | None:
        try:
            return new_session(self.conn.out_dir, self._unit_folder_name(), kind, dumps=dumps)
        except OSError as exc:
            QMessageBox.warning(
                self,
                tr("Ошибка создания папки сессии", "Session folder error"),
                str(exc),
            )
            return None

    def _callback_valid(self, expected_gen: int | None) -> bool:
        if not _qt_valid(self) or not self._is_open:
            return False
        if expected_gen is not None and self._session_gen != expected_gen:
            return False
        return True

    def select(self, key: str) -> None:
        if key in self._nav_items:
            self.nav.setCurrentItem(self._nav_items[key])

    def open_from_discovered(
        self,
        ecu: DiscoveredEcu | None = None,
        *,
        via_gateway: bool = False,
        gateway_bridge: bool = False,
        gateway_channel: int = 2,
        auto_read: bool = True,
    ) -> None:
        self._reset_session_state()
        self._is_open = True
        self._offline_mode = False
        if ecu is not None:
            self._via_gateway = bool(ecu.via_gateway)
            self._gateway_bridge = bool(ecu.bridge_available)
            self._gateway_channel = 2 if ecu.gateway_channel is None else int(ecu.gateway_channel)
            self._passport = {
                "part_number": ecu.part_number,
                "sw_version": ecu.sw_version,
                "hw_part_number": ecu.hw_number,
                "hw_version": ecu.hw_version,
                "fazit": ecu.fazit,
                "system_name": ecu.system_name,
                "vin": ecu.vin,
            }
            self._profile = mrr_detect_profile(self._passport)
        else:
            self._via_gateway = bool(via_gateway)
            self._gateway_bridge = bool(gateway_bridge)
            self._gateway_channel = int(gateway_channel)
        self._key = "cp_keys"
        self.select("cp_keys")
        self.refresh()
        self.changed.emit()
        if auto_read and self._can_enabled():
            # When connected via a vehicle gateway, open over pure UDS first so we never abruptly halt other vehicle buses
            # with J533CanBridge before the user explicitly requests XCP key/memory read.
            use_xcp_on_open = (not self._via_gateway) and self._xcp_available()
            gen = self._session_gen
            QTimer.singleShot(
                0,
                lambda g=gen, x=use_xcp_on_open: self._callback_valid(g) and (self.action_read_keys() if x else self.action_read_status()),
            )

    def open_from_status_result(
        self,
        res: dict[str, Any],
        *,
        gateway_bridge: bool = False,
        gateway_channel: int = 2,
    ) -> None:
        self._reset_session_state()
        self._is_open = True
        self._offline_mode = False
        self._via_gateway = bool(res.get("via_gateway", False))
        self._gateway_bridge = bool(gateway_bridge or res.get("gateway_bridged", False))
        self._gateway_channel = int(gateway_channel)
        self._key = "cp_keys"
        self.select("cp_keys")
        self._on_status_read(res)

    def open_offline(self, file_path: Path | None = None) -> None:
        """Open the 13 ACC Radar workspace offline (from local mrr_keys.json, mrr_read_report.json, Dflash.bin, or CodeFlash)."""
        self._reset_session_state()
        self._is_open = True
        self._offline_mode = True
        self._via_gateway = False
        self._gateway_bridge = False
        self._gateway_channel = 2
        if file_path is not None and file_path.is_file():
            try:
                if file_path.suffix.lower() == ".json":
                    data = json.loads(file_path.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        self._apply_live_result(data, keep_offline=True)
                        if isinstance(data.get("regions"), list):
                            self._last_mem_report = dict(data)
                else:
                    self._load_offline_dump_file(file_path)
                _remember_recent(file_path.parent)
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                self.note.emit(tr(f"Ошибка загрузки файла MRR: {exc}", f"Error loading MRR file: {exc}"))
        self._key = "cp_keys"
        self.select("cp_keys")
        self.refresh()
        self.changed.emit()

    def _load_offline_dump_file(self, path: Path) -> None:
        """Load local MRR Dflash.bin and/or CodeFlash/Application binary directly into workspace state."""
        raw = path.read_bytes()
        sibling_dflash: Path | None = None
        sibling_cflash: Path | None = None
        if len(raw) == MRR_DFLASH_SIZE:
            fee = mrr_parse_dflash_fee(raw)
            self._apply_dflash_fee(fee)
            for cand in ("Cflash.bin", "Application.bin"):
                p_cf = path.parent / cand
                if p_cf.is_file():
                    sibling_cflash = p_cf
                    break
        else:
            self._apply_cflash_bytes(raw)
            p_df = path.parent / "Dflash.bin"
            if p_df.is_file() and p_df.stat().st_size == MRR_DFLASH_SIZE:
                sibling_dflash = p_df
        if sibling_dflash is not None:
            with contextlib.suppress(OSError, ValueError):
                self._apply_dflash_fee(mrr_parse_dflash_fee(sibling_dflash.read_bytes()))
        if sibling_cflash is not None:
            with contextlib.suppress(OSError, ValueError):
                self._apply_cflash_bytes(sibling_cflash.read_bytes())

    def _apply_dflash_fee(self, fee: dict[str, Any]) -> None:
        self._dflash_fee = dict(fee)
        if fee.get("ika_hex"):
            self._ika_hex = str(fee["ika_hex"]).lower()
            self._draft_cur_ika = self._ika_hex.upper()
        if fee.get("gfa_hex"):
            self._gfa_hex = str(fee["gfa_hex"]).lower()
            if self._draft_new_gfa is None:
                self._draft_new_gfa = self._gfa_hex.upper()
        if fee.get("ecu_boot_sum_hex"):
            self._ecu_boot_sum_hex = str(fee["ecu_boot_sum_hex"]).lower()

    def _apply_cflash_bytes(self, raw: bytes) -> None:
        cp_rep = mrr_inspect_cflash_cp_state(raw, profile=self._selected_sw_profile())
        self._cflash_cp = cp_rep
        if cp_rep.get("sw") and not self._passport.get("sw_version"):
            self._passport.setdefault("sw_version", str(cp_rep["sw"]))
        if cp_rep.get("unit") and not self._passport.get("part_number"):
            self._passport.setdefault("part_number", str(cp_rep["unit"]))
        if cp_rep.get("fazit") and not self._passport.get("fazit"):
            self._passport.setdefault("fazit", str(cp_rep["fazit"]))
        with contextlib.suppress(ValueError):
            sw_rep = mrr_inspect_cflash_swap_state(raw, profile=self._selected_sw_profile())
            self._cflash_swap = sw_rep
            if sw_rep.get("swap_patch_state") == "swap_activated":
                pkg_idx = sw_rep.get("package_index")
                if pkg_idx is not None and int(pkg_idx) in MRR_GEN1_SWAP_PACKAGES and int(pkg_idx) != 3:
                    self._draft_swap_gen1_pkg = int(pkg_idx)
                grps = sw_rep.get("groups")
                if isinstance(grps, (list, tuple)) and len(grps) == 4:
                    self._draft_swap_gen2_groups = [int(x) for x in grps]

    def close_mrr(self) -> None:
        self._is_open = False
        self._offline_mode = False
        self._via_gateway = False
        self._gateway_bridge = False
        self._gateway_channel = 2
        self._key = "cp_keys"
        self._reset_session_state()
        self.changed.emit()

    def set_routing(self, *, via_gateway: bool, gateway_bridge: bool, gateway_channel: int = 2) -> None:
        self._via_gateway = bool(via_gateway)
        self._gateway_bridge = bool(gateway_bridge)
        self._gateway_channel = int(gateway_channel)
        self.refresh()

    def _selected_sw_profile(self) -> str | None:
        return self._profile_override or None

    def _can_enabled(self) -> bool:
        return bool(self.conn.ready and not self.conn.busy_reason() and not self.runner.is_busy)

    def _xcp_available(self) -> bool:
        iface = self.conn.interface or "slcan"
        if self._via_gateway:
            return bool(self._gateway_bridge) and iface in (*BRIDGE_NATIVE_INTERFACES, "dpdu")
        return iface in BRIDGE_NATIVE_INTERFACES

    def _snapshot_routing(self) -> tuple[str, str, bool, bool, int, str | None]:
        return (
            self.conn.port,
            self.conn.interface,
            self._via_gateway,
            self._gateway_bridge,
            self._gateway_channel,
            self._selected_sw_profile(),
        )

    # ────────────────────────────── Layout Builders ──────────────────────────────

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

        self.btn_poll_top = button("", slot=self.action_smart_poll)
        self.btn_export_top = button("", slot=self.action_export_json)
        self.btn_term_top = button("", slot=lambda: self.open_terminal_requested.emit("mrr"))
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
        self.nav_rows: dict[str, _MrrNavRow] = {}
        self._nav_items: dict[str, QListWidgetItem] = {}
        self._group_labels: dict[str, QLabel] = {}
        for group, keys in MRR_GROUPS:
            head = QListWidgetItem(self.nav)
            head.setFlags(Qt.ItemFlag.NoItemFlags)
            head.setSizeHint(QSize(0, 24))
            lbl = group_label()
            lbl.setContentsMargins(12, 7, 0, 0)
            self.nav.setItemWidget(head, lbl)
            self._group_labels[group] = lbl
            for key in keys:
                item = QListWidgetItem(self.nav)
                item.setData(Qt.ItemDataRole.UserRole, key)
                item.setSizeHint(QSize(0, 32))
                nav_row = _MrrNavRow()
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

    # ────────────────────────────── Architectural Helpers ──────────────────────────────

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
        """Architectural form cell matching BcmScreen & FpkeScreen."""
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
                badge.setText(tr("авто / пусто", "auto / empty") if allow_empty else f"0/{expected_bytes * 2}")
                set_tone(badge, "muted" if allow_empty else "err")
                if badge.parent() is not None:
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
            if badge.parent() is not None:
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

    def _register_can_btn(
        self,
        btn: QPushButton,
        *,
        needs_xcp: bool = False,
        needs_flash_write: bool = False,
    ) -> QPushButton:
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._can_action_buttons.append((btn, needs_xcp, needs_flash_write))
        self._apply_btn_enabled(btn, needs_xcp=needs_xcp, needs_flash_write=needs_flash_write)
        return btn

    def _apply_btn_enabled(self, btn: QPushButton, *, needs_xcp: bool, needs_flash_write: bool) -> None:
        can_ok = self._can_enabled()
        xcp_ok = can_ok and self._xcp_available()
        if needs_flash_write:
            prof_ok = bool(self._profile.get("verified") and self._profile.get("flash_write_supported"))
            btn.setEnabled(xcp_ok and prof_ok)
        elif needs_xcp:
            btn.setEnabled(xcp_ok)
        else:
            btn.setEnabled(can_ok)

    def _copy_text(self, value: str, label: str) -> None:
        cleaned = value.strip()
        if not cleaned or cleaned == "—":
            return
        cb = QGuiApplication.clipboard()
        if cb is not None:
            cb.setText(cleaned)
            self.note.emit(tr(f"Скопировано в буфер обмена: {label}", f"Copied to clipboard: {label}"))

    # ────────────────────────────── Reactive Updates ──────────────────────────────

    def _on_conn_or_busy(self) -> None:
        if not self._is_open or not _qt_valid(self):
            return
        self._refresh_identity()
        self._sync_action_buttons()

    def _on_busy_changed(self, _busy: bool) -> None:
        if not self._is_open or not _qt_valid(self):
            return
        self._refresh_identity()
        self._sync_action_buttons()

    def _on_lang_changed(self, _lang: str) -> None:
        if not _qt_valid(self):
            return
        self.refresh()

    def _sync_action_buttons(self) -> None:
        alive: list[tuple[QPushButton, bool, bool]] = []
        for btn, needs_xcp, needs_flash_write in self._can_action_buttons:
            if _qt_valid(btn):
                self._apply_btn_enabled(btn, needs_xcp=needs_xcp, needs_flash_write=needs_flash_write)
                alive.append((btn, needs_xcp, needs_flash_write))
        self._can_action_buttons = alive

    def refresh(self) -> None:
        if not _qt_valid(self):
            return
        self._profile = mrr_detect_profile(self._passport, sw_version=self._profile_override or "")
        self._refresh_identity()
        self._refresh_nav()
        self._render_page()

    def _refresh_identity(self) -> None:
        p = self._passport
        prof = self._profile
        busy = self.runner.is_busy
        can_ok = self._can_enabled()

        self.lbl_pn.setText(self.part_number)
        sys_raw = p.get("system_name") or prof.get("family") or "MRR"
        self.lbl_sys.setText(tr(f"Радар ACC (13) · {sys_raw}", f"ACC Radar (13) · {sys_raw}"))

        if self._offline_mode:
            self.pill_source.setText(tr("Локальные файлы (офлайн)", "Local files (offline)"))
            set_tone(self.pill_source, "muted")
        elif self._via_gateway:
            if self._xcp_available():
                self.pill_source.setText(
                    tr(
                        f"Через шлюз J533 (RAM-мост ch{self._gateway_channel})",
                        f"Via J533 gateway (RAM-Bridge ch{self._gateway_channel})",
                    )
                )
                set_tone(self.pill_source, "ok")
            else:
                self.pill_source.setText(tr("Через шлюз J533 (только UDS)", "Via J533 gateway (UDS only)"))
                set_tone(self.pill_source, "warn")
        elif self._xcp_available():
            self.pill_source.setText(tr("Прямой Extended CAN (UDS + XCP)", "Direct Extended CAN (UDS + XCP)"))
            set_tone(self.pill_source, "info")
        else:
            self.pill_source.setText(tr("Прямой CAN (только UDS)", "Direct CAN (UDS only)"))
            set_tone(self.pill_source, "warn")

        self.btn_poll_top.setText(tr("Опросить радар", "Poll radar"))
        self.btn_poll_top.setEnabled(can_ok)
        self.btn_poll_top.setToolTip(
            tr(
                "Считать паспорт, статус CP, 7 точек Code Flash, ключи IKA/GFA (DFLASH0) и ошибки DTC",
                "Read passport, CP status, 7 Code Flash sites, IKA/GFA keys (DFLASH0), and DTCs",
            )
            if self._xcp_available()
            else tr(
                "Считать паспорт, статус защиты компонентов и ошибки DTC по UDS",
                "Read passport, Component Protection status, and DTCs over UDS",
            )
        )
        self.btn_export_top.setText(tr("Экспорт JSON", "Export JSON"))
        self.btn_export_top.setEnabled(bool(self._passport or self._status or self._ika_hex or self._gfa_hex))
        self.btn_term_top.setText(tr("CAN-терминал", "CAN terminal"))
        self.btn_term_top.setEnabled(not busy)
        self.btn_close_top.setText(tr("Закрыть", "Close"))
        self.btn_close_top.setEnabled(not busy)

        clear_layout(self.grid_id)
        for c in range(8):
            self.grid_id.setColumnStretch(c, 0)

        top_fields: list[tuple[str, str]] = []
        sw_val = p.get("sw_version") or (prof["sw"] if prof.get("verified") else "")
        if sw_val:
            top_fields.append((tr("ВЕРСИЯ ПО", "SOFTWARE"), str(sw_val)))
        hw_pn = p.get("hw_part_number") or ""
        hw_v = p.get("hw_version") or ""
        if hw_pn:
            top_fields.append((tr("ОБОРУДОВАНИЕ", "HARDWARE"), f"{hw_pn} / {hw_v}" if hw_v else hw_pn))
        if p.get("fazit"):
            top_fields.append(("FAZIT", str(p["fazit"])))
        if p.get("asam_odx"):
            top_fields.append(("ASAM / ODX", str(p["asam_odx"])))
        prof_lbl = f"{prof['sw']} · {prof['mcu']}" if prof.get("verified") else f"{prof['mcu']} · {_fmt_size_kib(int(prof['cflash_size']))}"
        top_fields.append((tr("ПРОФИЛЬ / МК", "PROFILE / MCU"), prof_lbl))
        top_fields.append(("CAN UDS", "0x757 → 0x7C1"))

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
        st = self._status
        prof = self._profile
        patch_state = self._cflash_cp.get("cp_patch_state")
        cp_active = st.get("cp_active")
        cp_cnt = st.get("cp_counter")

        self._group_labels["main"].setText(tr("ОСНОВНОЕ", "MAIN"))
        self._group_labels["service"].setText(tr("СЕРВИС", "SERVICE"))

        for key, nav_row in self.nav_rows.items():
            nav_row.lbl_name.setText(_mrr_nav_title(key))
            nav_row.set_active(key == self._key)

        # CP pill
        if patch_state == "cp_disabled":
            set_pill(self.nav_rows["cp_keys"].pill, "CP OFF", "ok")
        elif patch_state == "partial":
            set_pill(self.nav_rows["cp_keys"].pill, tr("частично", "partial"), "warn")
        elif patch_state == "unknown":
            set_pill(self.nav_rows["cp_keys"].pill, tr("ошибка", "mismatch"), "err")
        elif cp_active is True:
            set_pill(self.nav_rows["cp_keys"].pill, tr("CP активна", "CP active"), "err")
        elif patch_state == "stock":
            set_pill(self.nav_rows["cp_keys"].pill, tr("сток", "stock"), "ok")
        elif self._ika_hex and self._gfa_hex:
            set_pill(self.nav_rows["cp_keys"].pill, "IKA + GFA", "info")
        else:
            set_pill(self.nav_rows["cp_keys"].pill, "—", "muted")

        # Memory pill
        if self._last_mem_report.get("regions"):
            set_pill(self.nav_rows["memory"].pill, tr("дамп есть", "saved"), "info")
        else:
            set_pill(self.nav_rows["memory"].pill, _fmt_size_kib(int(prof["cflash_size"])), "muted")

        # Status pill
        if cp_cnt is not None:
            if cp_active is True and patch_state != "cp_disabled":
                set_pill(self.nav_rows["status"].pill, f"03DE={cp_cnt}", "err")
            else:
                set_pill(self.nav_rows["status"].pill, tr("в норме", "ok"), "ok")
        elif self._passport:
            set_pill(self.nav_rows["status"].pill, str(self._passport.get("sw_version") or "UDS"), "info")
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

        # Bottom summary ledger
        self.lbl_state_hdr.setText(tr("ДАННЫЕ 13 ACC", "13 ACC DATA"))
        clear_layout(self.state_list)

        if patch_state == "cp_disabled":
            p_txt = f"CP OFF ({self._cflash_cp.get('patched_points', 7)}/{self._cflash_cp.get('total_points', 7)})"
            p_tone = "ok"
        elif patch_state == "stock":
            p_txt = tr(
                f"сток (0/{self._cflash_cp.get('total_points', 7)})",
                f"stock (0/{self._cflash_cp.get('total_points', 7)})",
            )
            p_tone = "warn" if cp_active is True else "info"
        elif patch_state == "partial":
            p_txt = tr(
                f"частично ({self._cflash_cp.get('patched_points', 0)}/{self._cflash_cp.get('total_points', 7)})",
                f"partial ({self._cflash_cp.get('patched_points', 0)}/{self._cflash_cp.get('total_points', 7)})",
            )
            p_tone = "warn"
        elif patch_state == "unsupported_sw":
            p_txt, p_tone = tr("не проверен", "unverified"), "warn"
        elif patch_state == "unknown":
            p_txt, p_tone = tr("не совпали", "mismatch"), "err"
        else:
            p_txt, p_tone = tr("не считан", "not read"), "muted"
        self.state_list.addWidget(self._ledger_row(tr("Патч CP Flash", "CP Flash patch"), p_txt, p_tone))

        swap_state = self._cflash_swap.get("swap_patch_state")
        if swap_state == "swap_activated":
            sw_txt = f"SWaP ON ({self._cflash_swap.get('patched_points', 0)}/{self._cflash_swap.get('total_points', 0)})"
            sw_tone = "ok"
        elif swap_state == "stock":
            sw_txt = tr(
                f"сток (0/{self._cflash_swap.get('total_points', 0)})",
                f"stock (0/{self._cflash_swap.get('total_points', 0)})",
            )
            sw_tone = "info"
        elif swap_state == "partial":
            sw_txt = tr(
                f"частично ({self._cflash_swap.get('patched_points', 0)}/{self._cflash_swap.get('total_points', 0)})",
                f"partial ({self._cflash_swap.get('patched_points', 0)}/{self._cflash_swap.get('total_points', 0)})",
            )
            sw_tone = "warn"
        elif swap_state == "unsupported_sw":
            sw_txt, sw_tone = tr("не проверен", "unverified"), "warn"
        elif swap_state == "unknown":
            sw_txt, sw_tone = tr("не совпали", "mismatch"), "err"
        else:
            sw_txt, sw_tone = tr("не считан", "not read"), "muted"
        self.state_list.addWidget(self._ledger_row(tr("Патч SWaP/FSC", "SWaP/FSC patch"), sw_txt, sw_tone))

        if self._swap_uds:
            u_act = int(self._swap_uds.get("active_count") or 0)
            u_rej = int(self._swap_uds.get("rejected_count") or 0)
            if u_rej > 0:
                u_txt, u_tone = tr(f"отклонено ({u_rej})", f"rejected ({u_rej})"), "err"
            elif u_act > 0:
                u_txt, u_tone = tr(f"активно ({u_act})", f"active ({u_act})"), "ok"
            else:
                u_txt, u_tone = tr("пусто (0)", "empty (0)"), "muted"
        else:
            u_txt, u_tone = "—", "muted"
        self.state_list.addWidget(self._ledger_row("SWaP (3C00)", u_txt, u_tone))

        if cp_cnt is not None:
            cnt_tone = "ok" if cp_cnt == 0 else ("err" if cp_cnt > 0x1E else "info")
            cnt_txt = f"0x{cp_cnt:04X} ({cp_cnt})"
        else:
            cnt_txt, cnt_tone = "—", "muted"
        self.state_list.addWidget(self._ledger_row(tr("Счётчик 03DE", "Counter 03DE"), cnt_txt, cnt_tone))

        if self._ika_hex:
            ika_txt = tr("заводской", "virgin") if self._dflash_fee.get("ika_virgin") else tr("считан", "read")
            ika_tone = "warn" if self._dflash_fee.get("ika_virgin") else "ok"
        elif st.get("ika_virgin") is True:
            ika_txt, ika_tone = tr("заводской", "virgin"), "warn"
        elif st.get("ika_personalized") is True:
            ika_txt, ika_tone = tr("обучен", "learned"), "info"
        else:
            ika_txt, ika_tone = tr("нет", "none"), "muted"
        self.state_list.addWidget(
            self._ledger_row("IKA (00BE)", ika_txt, ika_tone, self._ika_hex.upper() if self._ika_hex else "")
        )

        if self._gfa_hex:
            gfa_txt, gfa_tone = tr("считан", "read"), "ok"
        elif st.get("gfa_learned") is True:
            gfa_txt, gfa_tone = tr("обучен", "learned"), "info"
        elif st.get("gfa_missing") is True:
            gfa_txt, gfa_tone = tr("не обучен", "missing"), "warn"
        else:
            gfa_txt, gfa_tone = tr("нет", "none"), "muted"
        self.state_list.addWidget(
            self._ledger_row("GFA (00BD)", gfa_txt, gfa_tone, self._gfa_hex.upper() if self._gfa_hex else "")
        )

        if "xcp_gate_enabled" in st:
            xg_txt = tr("открыт", "open") if st["xcp_gate_enabled"] else tr("закрыт", "closed")
            xg_tone = "ok" if st["xcp_gate_enabled"] else "muted"
        else:
            xg_txt, xg_tone = "—", "muted"
        self.state_list.addWidget(self._ledger_row("XcpGate (0902)", xg_txt, xg_tone))

    def _render_page(self) -> None:
        self._can_action_buttons = []
        self._cp_points_table = None
        self._btn_cp_points = None
        self._cp_points_count = 0
        self._swap_points_table = None
        self._btn_swap_points = None
        self._swap_points_count = 0

        vbar = self.page_area.verticalScrollBar()
        saved_scroll = vbar.value() if self._last_rendered_key == self._key else 0

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
        head_row.setSpacing(10)
        title = QLabel(_mrr_nav_title(self._key))
        title.setObjectName("PageTitle")
        head_row.addWidget(title)
        head_row.addStretch(1)

        if self._key == "memory":
            if self._xcp_available():
                fast_ok = bool(self._profile.get("verified") and self._profile.get("fast_driver_supported"))
                mode_lbl = (
                    tr("Fast CAN 0x77E · ~25 КиБ/с", "Fast CAN 0x77E · ~25 KiB/s")
                    if fast_ok
                    else tr("XCP SHORT_UPLOAD (0xF4)", "XCP SHORT_UPLOAD (0xF4)")
                )
                head_row.addWidget(status_readout(mode_lbl, "ok" if fast_ok else "info"))
            else:
                head_row.addWidget(status_readout(tr("XCP недоступен (только UDS)", "XCP unavailable (UDS only)"), "warn"))
        elif self._key == "status":
            lbl_p = QLabel(tr("Профиль ПО:", "SW profile:"))
            lbl_p.setObjectName("Hint")
            self.cmb_profile = QComboBox()
            self.cmb_profile.setMinimumWidth(250)
            self.cmb_profile.addItem(tr("Автоопределение (по DID F189)", "Auto-detect (from DID F189)"), "")
            for code, desc in _PROFILE_CHOICES:
                self.cmb_profile.addItem(desc, code)
            idx_p = self.cmb_profile.findData(self._profile_override)
            if idx_p >= 0:
                self.cmb_profile.setCurrentIndex(idx_p)
            self.cmb_profile.currentIndexChanged.connect(
                lambda _i, c=self.cmb_profile: self._on_profile_changed(str(c.currentData() or ""))
            )
            head_row.addWidget(lbl_p)
            head_row.addWidget(self.cmb_profile)

        lay.addLayout(head_row)

        sup_info = mrr_support_info(self._passport)
        if sup_info["warning"]:
            sup_tone = sup_info["tone"] if sup_info["tone"] in ("warn", "info") else "warn"
            sup_box = Callout(sup_tone)
            sup_box.label.setText(sup_info["warning"])
            lay.addWidget(sup_box)

        if self._key == "cp_keys":
            self._build_cp_keys_page(lay)
        elif self._key == "memory":
            self._build_memory_page(lay)
        elif self._key == "status":
            self._build_status_page(lay)
        elif self._key == "dtc":
            self._build_dtc_page(lay)

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

    # ────────────────────────────── Page 1: Component Protection & Keys ──────────────────────────────

    def _build_cp_keys_page(self, lay: QVBoxLayout) -> None:
        st = self._status
        prof = self._profile
        cp_cnt = st.get("cp_counter")
        cp_active = st.get("cp_active")
        patch_state = self._cflash_cp.get("cp_patch_state")
        patched_pts = int(self._cflash_cp.get("patched_points", 0) or 0)
        total_pts = int(self._cflash_cp.get("total_points", 7) or 7)
        points = list(self._cflash_cp.get("points") or [])
        flash_write_ok = bool(prof.get("verified") and prof.get("flash_write_supported"))

        # ── Card 1: Live CP Overview & Code Flash Patch ──
        sec_cp = self._compact_section(
            tr("Статус защиты компонентов и патч Code Flash", "Component Protection Status & Code Flash Patch"),
            tr(
                "Отключение CP через 7 точек в Code Flash или штатная привязка к автомобилю по ключам IKA / GFA (ниже).",
                "Bypass CP via the 7-site Code Flash patch or pair to the vehicle using standard UDS IKA / GFA keys (below).",
            ),
        )
        badge_txt, badge_tone = _human_patch_state(patch_state)
        if patch_state == "stock" and cp_active is True:
            badge_txt, badge_tone = tr("CP активна (сток)", "CP active (stock)"), "err"
        sec_cp.head.addWidget(status_readout(badge_txt, badge_tone), 0, Qt.AlignmentFlag.AlignVCenter)

        # 4-column architectural KPI strip
        if patch_state == "cp_disabled":
            cf_val, cf_tone = f"CP OFF ({patched_pts}/{total_pts})", "ok"
        elif patch_state == "stock":
            cf_val, cf_tone = tr(f"Сток (0/{total_pts})", f"Stock (0/{total_pts})"), ("warn" if cp_active else "info")
        elif patch_state == "partial":
            cf_val, cf_tone = tr(f"Частичный ({patched_pts}/{total_pts})", f"Partial ({patched_pts}/{total_pts})"), "warn"
        elif patch_state == "unsupported_sw":
            cf_val, cf_tone = tr("ПО не проверено", "Unverified SW"), "warn"
        elif patch_state == "unknown":
            cf_val, cf_tone = tr("Не совпали", "Mismatch"), "err"
        else:
            cf_val, cf_tone = tr("Не считано", "Not read"), "muted"

        if cp_cnt is None:
            cnt_val, cnt_tone = "—", "muted"
        elif cp_cnt >= 0x23:
            cnt_val, cnt_tone = tr(f"0x{cp_cnt:04X} ({cp_cnt} · блок.)", f"0x{cp_cnt:04X} ({cp_cnt} · lock)"), "err"
        elif cp_cnt > 0x1E:
            cnt_val, cnt_tone = tr(f"0x{cp_cnt:04X} ({cp_cnt} · CP!)", f"0x{cp_cnt:04X} ({cp_cnt} · CP!)"), "err"
        elif cp_cnt == 0:
            cnt_val, cnt_tone = tr("0x0000 (норма)", "0x0000 (OK)"), "ok"
        else:
            cnt_val, cnt_tone = f"0x{cp_cnt:04X} ({cp_cnt})", "info"

        if st.get("ika_virgin") is True or self._dflash_fee.get("ika_virgin") is True:
            ika_st_val, ika_st_tone = tr("Заводской (virgin)", "Factory (virgin)"), "warn"
        elif st.get("ika_personalized") is True or self._ika_hex:
            ika_st_val, ika_st_tone = tr("Персонализирован", "Personalized"), "ok"
        else:
            ika_st_val, ika_st_tone = "—", "muted"

        if st.get("gfa_learned") is True or self._dflash_fee.get("gfa_learned") is True:
            gfa_st_val, gfa_st_tone = tr("Обучен", "Learned"), "ok"
        elif st.get("gfa_missing") is True:
            gfa_st_val, gfa_st_tone = tr("Не обучен", "Not learned"), "warn"
        elif self._gfa_hex:
            gfa_st_val, gfa_st_tone = tr("Считан", "Read"), "info"
        else:
            gfa_st_val, gfa_st_tone = "—", "muted"

        sec_cp.body.addWidget(
            self._metric_strip(
                [
                    (tr("ПАТЧ CODE FLASH", "CODE FLASH PATCH"), cf_val, cf_tone),
                    (tr("СЧЁТЧИК 0x03DE", "COUNTER 0x03DE"), cnt_val, cnt_tone),
                    (tr("СТАТУС IKA", "IKA STATE"), ika_st_val, ika_st_tone),
                    (tr("СТАТУС GFA", "GFA STATE"), gfa_st_val, gfa_st_tone),
                ]
            )
        )

        # Contextual callout & footer actions
        cp_footer_btns: list[QPushButton] = []

        if not patch_state:
            box = Callout("info")
            if self._xcp_available():
                box.label.setText(
                    tr(
                        "<b>Флеш-память радара ещё не считана.</b> Нажмите «Считать данные радара», чтобы проверить "
                        "7 точек патча CP в Code Flash, вычитать <code>DFLASH0</code> и извлечь ключи <b>IKA / GFA</b>.",
                        "<b>Radar flash has not been read yet.</b> Click “Read radar data” to inspect the 7 Code Flash "
                        "CP sites, dump <code>DFLASH0</code>, and extract <b>IKA / GFA</b> keys.",
                    )
                )
                btn_read = self._register_can_btn(
                    button(tr("Считать данные радара (XCP)", "Read radar data (XCP)"), "PrimaryBtn", slot=self.action_read_keys),
                    needs_xcp=True,
                )
                cp_footer_btns.append(btn_read)
            else:
                box.label.setText(
                    tr(
                        "<b>Доступен только UDS</b> (без XCP / RAM-моста J533 ch2). Вы можете опрашивать статус/DTC и "
                        "записывать ключи <b>IKA / GFA</b> ниже (при известном текущем IKA).",
                        "<b>UDS-only link</b> (no XCP / J533 ch2 RAM bridge). You can poll status/DTCs and write "
                        "<b>IKA / GFA</b> keys below (if the current IKA is known).",
                    )
                )
                btn_poll = self._register_can_btn(
                    button(tr("Опросить статус UDS", "Poll UDS status"), "PrimaryBtn", slot=self.action_read_status),
                    needs_xcp=False,
                )
                cp_footer_btns.append(btn_poll)
            sec_cp.body.addWidget(box)

        elif patch_state == "cp_disabled":
            box = Callout("ok")
            box.label.setText(
                tr(
                    f"<b>Защита компонентов отключена в Code Flash ({patched_pts}/{total_pts} точек).</b> "
                    "Радар работает без привязки к шлюзу J533. При необходимости можно вернуть заводскую прошивку CP.",
                    f"<b>Component Protection is bypassed in Code Flash ({patched_pts}/{total_pts} sites).</b> "
                    "The radar operates without J533 pairing. You can restore stock CP verification at any time.",
                )
            )
            sec_cp.body.addWidget(box)
            btn_restore = self._register_can_btn(
                button(tr("Вернуть заводской сток CP…", "Restore factory stock CP…"), slot=self.action_restore_cp_stock),
                needs_xcp=True,
                needs_flash_write=True,
            )
            cp_footer_btns.append(btn_restore)

        elif patch_state == "stock":
            box = Callout("warn" if cp_active else "info")
            if cp_active:
                box.label.setText(
                    tr(
                        f"<b>Установлена заводская прошивка (0/{total_pts} точек патча) — защита компонентов АКТИВНА.</b> "
                        "Для снятия CP либо привяжите радар к авто по <b>GFA</b> (форма ниже, без прошивки Flash), "
                        "либо установите патч деактивации CP в Code Flash.",
                        f"<b>Factory stock firmware detected (0/{total_pts} patch sites) — Component Protection is ACTIVE.</b> "
                        "To clear CP, either pair the radar via vehicle <b>GFA</b> below (zero flash writes) "
                        "or flash the Code Flash CP-disable patch.",
                    )
                )
            else:
                box.label.setText(
                    tr(
                        f"<b>Установлена заводская прошивка (0/{total_pts} точек патча), активной ошибки CP нет.</b> "
                        "При переносе радара в другой автомобиль вы можете привязать его по GFA ниже или отключить CP патчем.",
                        f"<b>Factory stock firmware detected (0/{total_pts} patch sites), no active CP fault.</b> "
                        "When moving the radar to another car, pair it via GFA below or install the CP-disable patch.",
                    )
                )
            sec_cp.body.addWidget(box)
            btn_off = self._register_can_btn(
                button(tr("Деактивировать CP (Code Flash)…", "Deactivate CP (Code Flash)…"), "PrimaryBtn", slot=self.action_deactivate_cp),
                needs_xcp=True,
                needs_flash_write=True,
            )
            cp_footer_btns.append(btn_off)

        elif patch_state == "partial":
            box = Callout("warn")
            box.label.setText(
                tr(
                    f"<b>Обнаружен частичный патч Code Flash ({patched_pts}/{total_pts} точек).</b> "
                    "Завершите установку полного патча CP OFF или восстановите заводской сток.",
                    f"<b>Partial Code Flash patch detected ({patched_pts}/{total_pts} sites).</b> "
                    "Complete the full CP OFF patch or restore factory stock.",
                )
            )
            sec_cp.body.addWidget(box)
            cp_footer_btns.append(
                self._register_can_btn(
                    button(tr("Завершить патч CP OFF…", "Finish CP OFF patch…"), "PrimaryBtn", slot=self.action_deactivate_cp),
                    needs_xcp=True,
                    needs_flash_write=True,
                )
            )
            cp_footer_btns.append(
                self._register_can_btn(
                    button(tr("Вернуть заводской сток…", "Restore stock…"), slot=self.action_restore_cp_stock),
                    needs_xcp=True,
                    needs_flash_write=True,
                )
            )

        else:
            # unsupported_sw or unknown byte mismatch
            box = Callout("err" if patch_state == "unknown" else "warn")
            if patch_state == "unsupported_sw":
                box.label.setText(
                    tr(
                        f"<b>Патчи CP и SWaP для ПО «{prof['sw']}» не проверялись</b> и отключены для безопасности. "
                        "Чтение памяти, ключи <b>IKA / GFA</b>, штатная привязка по UDS и прошивка FRF работают.",
                        f"<b>CP & SWaP patches for SW “{prof['sw']}” are unverified</b> and disabled for safety. "
                        "Memory reads, <b>IKA / GFA</b> keys, standard UDS pairing, and FRF flashing remain available.",
                    )
                )
            else:
                box.label.setText(
                    tr(
                        f"<b>Байты в 7 контрольных точках Code Flash не соответствуют профилю {prof['sw']}.</b> "
                        "Проверьте выбранный профиль ПО во вкладке «Паспорт и статус». Живая прошивка заблокирована.",
                        f"<b>Bytes at the 7 Code Flash sites do not match profile {prof['sw']}.</b> "
                        "Verify the selected SW profile on the “Passport & status” tab. Live flashing is blocked.",
                    )
                )
            sec_cp.body.addWidget(box)

        # Secondary utility actions on Card 1
        if patch_state:
            if (cp_cnt is None or cp_cnt > 0 or cp_active) and prof.get("verified") and prof.get("sram_auth_success_trigger_addr"):
                btn_rst = self._register_can_btn(
                    button(tr("Сбросить счётчик CP (03DE → 0)", "Reset CP counter (03DE → 0)"), slot=self.action_reset_cp_counter),
                    needs_xcp=True,
                )
                cp_footer_btns.append(btn_rst)
            btn_reread = self._register_can_btn(
                button(tr("Перечитать Flash", "Re-read Flash"), "GhostBtn", slot=self.action_read_keys),
                needs_xcp=True,
            )
            cp_footer_btns.append(btn_reread)

        # Collapsible 7-point patch verification table (toggled in-place without page rebuild)
        if points:
            btn_pts = button(
                tr(f"Скрыть {len(points)} точек Code Flash", f"Hide {len(points)} Code Flash sites")
                if self._show_patch_points
                else tr(f"Показать {len(points)} точек Code Flash", f"Inspect {len(points)} Code Flash sites"),
                "GhostBtn",
                slot=self._toggle_patch_points,
            )
            btn_pts.setCursor(Qt.CursorShape.PointingHandCursor)
            cp_footer_btns.append(btn_pts)
            tbl_cp = self._build_patch_points_table(points)
            sec_cp.body.addWidget(tbl_cp)
            tbl_cp.setVisible(self._show_patch_points)
            self._cp_points_table = tbl_cp
            self._btn_cp_points = btn_pts
            self._cp_points_count = len(points)

        sec_cp.add_footer(*cp_footer_btns)
        lay.addWidget(sec_cp)

        # ── Card 1B: Direct Code Flash SWaP / FSC Feature Activation (Gen 1 & Gen 2) ──
        self._build_swap_card(lay)

        # ── Card 2: Extracted Radar Keys (DFLASH0 Fee + SRAM) ──
        sec_keys = self._compact_section(
            tr("Ключи радара (DFLASH0 Fee / SRAM)", "Radar Keys (DFLASH0 Fee / SRAM)"),
            tr(
                "Расшифровка слотов AUTOSAR Fee 0x2A..0x2D и 0x40 (AES-128-ECB под ECU_BOOT_SUM) без записи во Flash.",
                "Decrypts AUTOSAR Fee slots 0x2A..0x2D & 0x40 (AES-128-ECB under ECU_BOOT_SUM) with zero flash writes.",
            ),
        )
        if self._ika_hex and self._gfa_hex:
            sec_keys.head.addWidget(status_readout(tr("IKA и GFA считаны", "IKA & GFA loaded"), "ok"))
        elif self._ika_hex:
            sec_keys.head.addWidget(status_readout(tr("Считан только IKA", "IKA loaded"), "info"))
        else:
            sec_keys.head.addWidget(status_readout(tr("Ключи не считаны", "Not read yet"), "muted"))

        self.ed_read_ika = QLineEdit(self._ika_hex.upper())
        self.ed_read_ika.setFont(mono_font(12, bold=True))
        self.ed_read_ika.setReadOnly(True)
        self.ed_read_ika.setCursorPosition(0)
        self.ed_read_ika.setPlaceholderText(tr("Нажмите «Считать IKA + GFA» или откройте Dflash.bin…", "Click “Read IKA + GFA” or open Dflash.bin…"))
        btn_cp_ika = button(tr("Копировать", "Copy"), "InlineBtn", slot=lambda: self._copy_text(self.ed_read_ika.text(), "IKA"))
        btn_cp_ika.setEnabled(bool(self._ika_hex))
        c_ika, _ = self._field_box(
            tr("ИНДИВИДУАЛЬНЫЙ КЛЮЧ IKA (16 Б · SLOT 0 / DID 0x00BE)", "INDIVIDUAL KEY IKA (16 B · SLOT 0 / DID 0x00BE)"),
            self.ed_read_ika,
            badge_text="16 B" if self._ika_hex else "",
            badge_tone="ok" if self._ika_hex else "muted",
            trailing=(btn_cp_ika,),
        )
        sec_keys.body.addWidget(c_ika)

        self.ed_read_gfa = QLineEdit(self._gfa_hex.upper())
        self.ed_read_gfa.setFont(mono_font(12))
        self.ed_read_gfa.setReadOnly(True)
        self.ed_read_gfa.setCursorPosition(0)
        self.ed_read_gfa.setPlaceholderText(tr("Групповой ключ автомобиля GFA…", "Vehicle group key GFA…"))
        btn_cp_gfa = button(tr("Копировать", "Copy"), "InlineBtn", slot=lambda: self._copy_text(self.ed_read_gfa.text(), "GFA"))
        btn_cp_gfa.setEnabled(bool(self._gfa_hex))
        c_gfa, _ = self._field_box(
            tr("ГРУППОВОЙ КЛЮЧ АВТО GFA (16 Б · SLOT 3 / DID 0x00BD)", "VEHICLE GROUP KEY GFA (16 B · SLOT 3 / DID 0x00BD)"),
            self.ed_read_gfa,
            badge_text="16 B" if self._gfa_hex else "",
            badge_tone="ok" if self._gfa_hex else "muted",
            trailing=(btn_cp_gfa,),
        )
        sec_keys.body.addWidget(c_gfa)

        if self._ecu_boot_sum_hex:
            self.ed_read_bsum = QLineEdit(self._ecu_boot_sum_hex.upper())
            self.ed_read_bsum.setFont(mono_font(11))
            self.ed_read_bsum.setReadOnly(True)
            self.ed_read_bsum.setCursorPosition(0)
            btn_cp_bs = button(tr("Копировать", "Copy"), "InlineBtn", slot=lambda: self._copy_text(self.ed_read_bsum.text(), "ECU_BOOT_SUM"))
            c_bs, _ = self._field_box(
                tr("МАСТЕР-КЛЮЧ DFLASH ECU_BOOT_SUM (16 Б · FEE 0x40)", "DFLASH MASTER KEY ECU_BOOT_SUM (16 B · FEE 0x40)"),
                self.ed_read_bsum,
                badge_text="16 B",
                badge_tone="muted",
                trailing=(btn_cp_bs,),
            )
            sec_keys.body.addWidget(c_bs)

        btn_rd_keys = self._register_can_btn(
            button(
                tr("Считать IKA + GFA по CAN (XCP)", "Read IKA + GFA over CAN (XCP)"),
                "PrimaryBtn" if not self._ika_hex else "",
                slot=self.action_read_keys,
            ),
            needs_xcp=True,
        )
        btn_from_file = button(tr("Из файла Dflash.bin…", "From Dflash.bin…"), slot=self.action_extract_keys_from_file)
        btn_from_file.setCursor(Qt.CursorShape.PointingHandCursor)
        sec_keys.add_footer(btn_rd_keys, btn_from_file)
        lay.addWidget(sec_keys)

        # ── Card 3: Standard UDS Pairing (2E 00BE / 00BD) ──
        sec_write = self._compact_section(
            tr("Привязка к автомобилю — запись IKA / GFA по UDS", "Vehicle Pairing — Write IKA / GFA over UDS"),
            tr(
                "Штатные 34-байтные контейнеры KS по UDS (0x757 → 0x7C1). Работает на всех версиях ПО без модификации Flash.",
                "Standard 34-byte KS containers over UDS (0x757 → 0x7C1). Works on all SW versions with zero flash modification.",
            ),
        )
        sec_write.head.addWidget(status_readout(tr("Все версии ПО · UDS", "All SW versions · UDS"), "info"))

        cur_ika_init = (self._ika_hex.upper() if self._draft_cur_ika is None else self._draft_cur_ika)
        self.ed_cur_ika = QLineEdit(cur_ika_init)
        self.ed_cur_ika.setFont(mono_font(12))
        self.ed_cur_ika.setPlaceholderText(
            tr("32 HEX (пусто = авточтение текущего IKA по XCP)", "32 HEX (blank = auto-read current IKA via XCP)")
        )
        self.ed_cur_ika.textChanged.connect(lambda t: setattr(self, "_draft_cur_ika", t))
        btn_use_ika = button(
            tr("Из считанного", "Use read IKA"),
            "InlineBtn",
            slot=lambda: self.ed_cur_ika.setText(self._ika_hex.upper()),
        )
        btn_use_ika.setEnabled(bool(self._ika_hex))
        c_cur, b_cur = self._field_box(
            tr("ТЕКУЩИЙ IKA РАДАРА (ШИФРУЕТ КОНТЕЙНЕР)", "CURRENT RADAR IKA (ENCRYPTS CONTAINER)"),
            self.ed_cur_ika,
            trailing=(btn_use_ika,),
            tip=tr(
                "Текущий рабочий IKA радара, которым шифруется контейнер 2E 00BE / 00BD. Если оставить пустым, ContiTool считает его по XCP.",
                "Current working radar IKA used to encrypt the 2E 00BE / 00BD container. Leave empty to auto-read via XCP.",
            ),
        )
        self._bind_hex_validator(self.ed_cur_ika, b_cur, 16, allow_empty=True)
        sec_write.body.addWidget(c_cur)

        self.ed_new_ika = QLineEdit(self._draft_new_ika)
        self.ed_new_ika.setFont(mono_font(12))
        self.ed_new_ika.setPlaceholderText(
            tr("Пусто = не менять IKA (записать только GFA)", "Blank = keep current IKA (write GFA only)")
        )
        self.ed_new_ika.textChanged.connect(lambda t: setattr(self, "_draft_new_ika", t))
        btn_gen_ika = button(
            tr("Сгенерировать", "Generate"),
            "InlineBtn",
            slot=lambda: self.ed_new_ika.setText(_py_secrets.token_hex(16).upper()),
        )
        btn_same_ika = button(
            tr("Текущий IKA", "Current IKA"),
            "InlineBtn",
            slot=lambda: self.ed_new_ika.setText(self.ed_cur_ika.text().strip().upper()),
        )
        c_new_ika, b_new_ika = self._field_box(
            tr("НОВЫЙ IKA (DID 0x00BE, ОПЦИОНАЛЬНО)", "NEW IKA (DID 0x00BE, OPTIONAL)"),
            self.ed_new_ika,
            trailing=(btn_gen_ika, btn_same_ika),
            tip=tr(
                "При записи 2E 00BE радар стирает GFA в FF×16, поэтому при смене IKA рекомендуется сразу записать и GFA (00BD).",
                "Writing 2E 00BE erases GFA to FF×16; always follow with GFA (00BD) when changing IKA.",
            ),
        )
        self._bind_hex_validator(self.ed_new_ika, b_new_ika, 16, allow_empty=True)
        sec_write.body.addWidget(c_new_ika)

        new_gfa_init = (self._gfa_hex.upper() if self._draft_new_gfa is None else self._draft_new_gfa)
        self.ed_new_gfa = QLineEdit(new_gfa_init)
        self.ed_new_gfa.setFont(mono_font(12))
        self.ed_new_gfa.setPlaceholderText("32 HEX (16 B)")
        self.ed_new_gfa.textChanged.connect(lambda t: setattr(self, "_draft_new_gfa", t))
        btn_gfa_17 = button(
            tr("Из 17 FPK_E (/1)", "From 17 FPK_E (/1)"),
            "InlineBtn",
            slot=self.action_fill_gfa_from_cluster,
        )
        c_new_gfa, b_new_gfa = self._field_box(
            tr("ЦЕЛЕВОЙ GFA АВТОМОБИЛЯ (DID 0x00BD)", "TARGET VEHICLE GFA (DID 0x00BD)"),
            self.ed_new_gfa,
            trailing=(btn_gfa_17,),
            tip=tr(
                "Групповой ключ автомобиля GFA (совпадает со слотом /1 в панели приборов 17 FPK_E и в 09 BCM).",
                "Vehicle group key GFA (matches slot /1 in 17 FPK_E cluster and 09 BCM).",
            ),
        )
        self._bind_hex_validator(self.ed_new_gfa, b_new_gfa, 16, allow_empty=True)
        sec_write.body.addWidget(c_new_gfa)

        self.chk_wr_reset = QCheckBox(
            tr("Выполнить сброс радара (UDS 11 02) и очистить DTC после записи", "Reboot radar (UDS 11 02) & clear DTCs after write")
        )
        self.chk_wr_reset.setChecked(self._draft_write_reset)
        self.chk_wr_reset.toggled.connect(lambda v: setattr(self, "_draft_write_reset", bool(v)))
        sec_write.body.addWidget(self.chk_wr_reset)

        wr_note = Callout("info")
        wr_note.label.setText(
            tr(
                "Запись нового <b>IKA (00BE)</b> стирает <b>GFA</b> в радаре — используйте <b>«Записать IKA + GFA»</b>, "
                "чтобы сразу прописать <code>00BD</code> под новым IKA. Если в машине меняется только радар, достаточно «Записать GFA (00BD)».",
                "Writing a new <b>IKA (00BE)</b> erases <b>GFA</b> in the radar — use <b>“Write IKA + GFA”</b> "
                "to immediately restore <code>00BD</code> under the new IKA. For a radar swap, “Write GFA (00BD)” alone is enough.",
            )
        )
        sec_write.body.addWidget(wr_note)

        btn_wr_gfa = self._register_can_btn(
            button(tr("Записать GFA (00BD)", "Write GFA (00BD)"), "PrimaryBtn", slot=lambda: self.action_write_keys(include_ika=False)),
            needs_xcp=False,
        )
        btn_wr_both = self._register_can_btn(
            button(tr("Записать IKA + GFA (00BE → 00BD)", "Write IKA + GFA (00BE → 00BD)"), slot=lambda: self.action_write_keys(include_ika=True)),
            needs_xcp=False,
        )
        sec_write.add_footer(btn_wr_gfa, btn_wr_both)
        lay.addWidget(sec_write)

    def _build_swap_card(self, lay: QVBoxLayout) -> None:
        prof = self._profile
        swap_cfg = prof.get("swap_config") or {}
        gen = int(swap_cfg.get("generation") or (1 if prof.get("mcu") == "MPC5674K" else 2))
        swap_state = self._cflash_swap.get("swap_patch_state")
        exp_pts, exp_bytes = mrr_get_swap_patch_stats(prof)
        patched_pts = int(self._cflash_swap.get("patched_points", 0) or 0)
        total_pts = int(self._cflash_swap.get("total_points", exp_pts) or exp_pts)
        points = list(self._cflash_swap.get("points") or [])

        sec_swap = self._compact_section(
            tr("Активация функций SWaP / FSC (Code Flash)", "SWaP / FSC Feature Activation (Code Flash)"),
            tr(
                "Прямой патч логики SWaP в Code Flash без подписи сертификатов FSC (Поколение 1: пакет 10003x00 · Поколение 2: 4 группы 1000900x..1000930x).",
                "Direct Code Flash SWaP patch without FSC certificate signing (Gen 1: package 10003x00 · Gen 2: 4 groups 1000900x..1000930x).",
            ),
        )
        badge_txt, badge_tone = _human_swap_state(swap_state)
        sec_swap.head.addWidget(status_readout(badge_txt, badge_tone), 0, Qt.AlignmentFlag.AlignVCenter)

        if swap_state == "swap_activated":
            sw_val, sw_tone = f"SWaP ON ({patched_pts}/{total_pts})", "ok"
        elif swap_state == "stock":
            sw_val, sw_tone = tr(f"Сток (0/{total_pts})", f"Stock (0/{total_pts})"), "info"
        elif swap_state == "partial":
            sw_val, sw_tone = tr(f"Частичный ({patched_pts}/{total_pts})", f"Partial ({patched_pts}/{total_pts})"), "warn"
        elif swap_state == "unsupported_sw":
            sw_val, sw_tone = tr("ПО не проверено", "Unverified SW"), "warn"
        elif swap_state == "unknown":
            sw_val, sw_tone = tr("Не совпали", "Mismatch"), "err"
        else:
            sw_val, sw_tone = tr("Не считано", "Not read"), "muted"

        sec_tuples = prof.get("swap_affected_sectors") or ()
        if sec_tuples:
            sec_addr_txt = " + ".join(f"0x{a:06X}" for a, _ in sec_tuples)
        else:
            sec_addr_txt = "0x140000" if gen == 1 else "0x060000"
        gen_val = tr(f"Пок. {gen} · {sec_addr_txt}", f"Gen {gen} · {sec_addr_txt}")

        active_fsids = list(self._cflash_swap.get("active_fsids") or [])
        if swap_state == "swap_activated" and active_fsids:
            if gen == 1:
                fsid_val = f"0x{active_fsids[0]}"
            else:
                fsid_val = ", ".join(f[-4:] for f in active_fsids)
            fsid_tone = "ok"
        elif gen == 1:
            sel_pkg = MRR_GEN1_SWAP_PACKAGES.get(self._draft_swap_gen1_pkg, MRR_GEN1_SWAP_PACKAGES[6])
            fsid_val = tr(f"Цель: 0x{sel_pkg['fsid_hex']}", f"Target: 0x{sel_pkg['fsid_hex']}")
            fsid_tone = "info"
        else:
            g_tup = (
                int(self._draft_swap_gen2_groups[0]),
                int(self._draft_swap_gen2_groups[1]),
                int(self._draft_swap_gen2_groups[2]),
                int(self._draft_swap_gen2_groups[3]),
            )
            g_desc = mrr_describe_gen2_swap_groups(g_tup)
            short_list = ", ".join(f[-4:] for f in g_desc["active_fsids"]) or tr("нет", "none")
            fsid_val = tr(f"Цель: {short_list}", f"Target: {short_list}")
            fsid_tone = "info"

        if gen == 1:
            lvl = (
                self._cflash_swap.get("feature_level")
                if swap_state == "swap_activated"
                else MRR_GEN1_SWAP_PACKAGES.get(self._draft_swap_gen1_pkg, MRR_GEN1_SWAP_PACKAGES[6])["level"]
            )
            lvl_val = tr(f"Уровень {lvl}", f"Level {lvl}")
            lvl_tone = "ok" if swap_state == "swap_activated" else "info"
        else:
            b12_13 = (
                self._cflash_swap.get("coding_byte12_13_hex")
                if swap_state == "swap_activated"
                else mrr_describe_gen2_swap_groups(tuple(self._draft_swap_gen2_groups))["coding_byte12_13_hex"]
            )
            lvl_val = f"0600[12..13] = {b12_13}"
            lvl_tone = "ok" if swap_state == "swap_activated" else "info"

        sec_swap.body.addWidget(
            self._metric_strip(
                [
                    (tr("ПАТЧ SWAP / FSC", "SWAP / FSC PATCH"), sw_val, sw_tone),
                    (tr("ПОКОЛЕНИЕ / СЕКТОР", "GEN / SECTOR"), gen_val, "info"),
                    (tr("АКТИВНЫЕ FS-ID", "ACTIVE FS-ID"), fsid_val, fsid_tone),
                    (tr("УРОВЕНЬ / КОДИРОВКА", "LEVEL / CODING"), lvl_val, lvl_tone),
                ]
            )
        )

        if self._swap_uds:
            sec_swap.body.addWidget(self._build_swap_uds_panel(self._swap_uds, swap_patch_state=swap_state))

        if gen == 1:
            self.cmb_swap_gen1_pkg = QComboBox()
            for idx_k in (6, 5, 4, 2, 1, 0):
                p_meta = MRR_GEN1_SWAP_PACKAGES[idx_k]
                title_p = tr(p_meta["title_ru"], p_meta["title_en"])
                self.cmb_swap_gen1_pkg.addItem(
                    f"0x{p_meta['fsid_hex']} — {title_p}",
                    idx_k,
                )
            cur_i = self.cmb_swap_gen1_pkg.findData(self._draft_swap_gen1_pkg)
            if cur_i >= 0:
                self.cmb_swap_gen1_pkg.setCurrentIndex(cur_i)
            self.cmb_swap_gen1_pkg.currentIndexChanged.connect(
                lambda _i, c=self.cmb_swap_gen1_pkg: self._on_swap_gen1_pkg_changed(
                    int(6 if c.currentData() is None else c.currentData())
                )
            )
            cell_pkg, _ = self._field_box(
                tr("ЦЕЛЕВОЙ НАБОР ФУНКЦИЙ SWAP (ПОКОЛЕНИЕ 1 · 3Q0 0130..0196)", "TARGET SWAP FEATURE PACKAGE (GEN 1 · 3Q0 0130..0196)"),
                self.cmb_swap_gen1_pkg,
                badge_text=tr(f"{exp_pts} точек · {exp_bytes} Б", f"{exp_pts} sites · {exp_bytes} B"),
                badge_tone="info",
            )
            sec_swap.body.addWidget(cell_pkg)
        else:
            self.cmb_swap_gen2_preset = QComboBox()
            cur_tuple = tuple(int(x) for x in self._draft_swap_gen2_groups[:4])
            matched_preset = "custom"
            for pr in MRR_GEN2_SWAP_PRESETS:
                self.cmb_swap_gen2_preset.addItem(tr(pr["title_ru"], pr["title_en"]), pr["id"])
                if tuple(pr["groups"]) == cur_tuple:
                    matched_preset = str(pr["id"])
            self.cmb_swap_gen2_preset.addItem(
                tr("Пользовательская комбинация групп (g0..g3)", "Custom 4-group combination (g0..g3)"),
                "custom",
            )
            p_idx = self.cmb_swap_gen2_preset.findData(matched_preset)
            if p_idx >= 0:
                self.cmb_swap_gen2_preset.setCurrentIndex(p_idx)
            self.cmb_swap_gen2_preset.currentIndexChanged.connect(
                lambda _i, c=self.cmb_swap_gen2_preset: self._on_swap_gen2_preset_changed(str(c.currentData() or "custom"))
            )
            cell_preset, _ = self._field_box(
                tr("ПРЕСЕТ АКТИВАЦИИ SWAP / FSC (ПОКОЛЕНИЕ 2 · 5Q0/3QF)", "SWAP / FSC ACTIVATION PRESET (GEN 2 · 5Q0/3QF)"),
                self.cmb_swap_gen2_preset,
                badge_text=tr(f"{exp_pts} точек · {exp_bytes} Б", f"{exp_pts} sites · {exp_bytes} B"),
                badge_tone="info",
            )
            sec_swap.body.addWidget(cell_preset)

            grp_grid = QGridLayout()
            grp_grid.setHorizontalSpacing(12)
            grp_grid.setVerticalSpacing(8)
            grp_grid.setColumnStretch(0, 1)
            grp_grid.setColumnStretch(1, 1)
            self._swap_gen2_combos: list[QComboBox] = []
            for g_idx, g_meta in enumerate(MRR_GEN2_SWAP_GROUPS):
                cmb_g = QComboBox()
                for var_code, (_fsid_int, ru_lbl, en_lbl) in g_meta["variants"].items():
                    cmb_g.addItem(tr(ru_lbl, en_lbl), int(var_code))
                v_i = cmb_g.findData(int(self._draft_swap_gen2_groups[g_idx]))
                if v_i >= 0:
                    cmb_g.setCurrentIndex(v_i)
                cmb_g.currentIndexChanged.connect(
                    lambda _i, gi=g_idx, c=cmb_g: self._on_swap_gen2_group_changed(gi, int(c.currentData() or 0))
                )
                self._swap_gen2_combos.append(cmb_g)
                cell_g, _ = self._field_box(
                    tr(g_meta["title_ru"], g_meta["title_en"]),
                    cmb_g,
                )
                grp_grid.addWidget(cell_g, g_idx // 2, g_idx % 2)
            sec_swap.body.addLayout(grp_grid)

        swap_footer_btns: list[QPushButton] = []
        if swap_state == "partial":
            act_lbl = tr("Обновить SWaP + 3C00…", "Update SWaP + 3C00…")
        elif swap_state == "swap_activated":
            act_lbl = tr("Обновить SWaP / FSC…", "Update SWaP / FSC…")
        else:
            act_lbl = tr("Активировать SWaP / FSC…", "Activate SWaP / FSC…")
        btn_act_swap = self._register_can_btn(
            button(
                act_lbl,
                "PrimaryBtn",
                slot=self.action_activate_swap,
            ),
            needs_xcp=True,
            needs_flash_write=True,
        )
        swap_footer_btns.append(btn_act_swap)

        btn_uds_swap = self._register_can_btn(
            button(
                tr("Проверить 22 3C 00", "Check UDS 22 3C 00"),
                slot=self.action_read_swap_uds,
            ),
            needs_xcp=False,
        )
        swap_footer_btns.append(btn_uds_swap)

        if swap_state in ("swap_activated", "partial"):
            btn_rst_swap = self._register_can_btn(
                button(tr("Вернуть сток SWaP…", "Restore stock SWaP…"), slot=self.action_restore_swap_stock),
                needs_xcp=True,
                needs_flash_write=True,
            )
            swap_footer_btns.append(btn_rst_swap)

        if points:
            btn_sw_pts = button(
                tr(f"Скрыть {len(points)} точек", f"Hide {len(points)} sites")
                if self._show_swap_points
                else tr(f"Точки SWaP ({len(points)})", f"SWaP sites ({len(points)})"),
                "GhostBtn",
                slot=self._toggle_swap_points,
            )
            btn_sw_pts.setCursor(Qt.CursorShape.PointingHandCursor)
            swap_footer_btns.append(btn_sw_pts)
            tbl_sw = self._build_patch_points_table(points)
            sec_swap.body.addWidget(tbl_sw)
            tbl_sw.setVisible(self._show_swap_points)
            self._swap_points_table = tbl_sw
            self._btn_swap_points = btn_sw_pts
            self._swap_points_count = len(points)

        sec_swap.add_footer(*swap_footer_btns)
        lay.addWidget(sec_swap)

    @staticmethod
    def _build_swap_uds_panel(swap_uds: dict[str, Any], *, swap_patch_state: str | None = None) -> QFrame:
        wrap = QFrame()
        wrap.setObjectName("ResultStrip")
        vlay = QVBoxLayout(wrap)
        vlay.setContentsMargins(0, 6, 0, 6)
        vlay.setSpacing(4)

        features = list(swap_uds.get("features") or [])
        n_act = int(swap_uds.get("active_count") or 0)
        n_rej = int(swap_uds.get("rejected_count") or 0)

        top = QHBoxLayout()
        top.setContentsMargins(12, 0, 12, 2)
        top.setSpacing(10)
        top.addWidget(group_label(tr("СОСТОЯНИЕ SWAP / FEC ПО CAN (UDS 22 3C 00)", "LIVE SWAP / FEC STATUS OVER CAN (UDS 22 3C 00)")))
        top.addStretch(1)
        if n_rej > 0:
            ro_sum = status_readout(
                tr(f"активно: {n_act}, отклонено: {n_rej}", f"active: {n_act}, rejected: {n_rej}"),
                "err",
            )
        elif n_act > 0:
            ro_sum = status_readout(tr(f"активно: {n_act}", f"active: {n_act}"), "ok")
        elif features:
            ro_sum = status_readout(tr(f"не активированы ({len(features)})", f"inactive ({len(features)})"), "muted")
        else:
            ro_sum = status_readout(tr("нет сертификатов (00..00)", "no certificates (00..00)"), "muted")
        top.addWidget(ro_sum)
        vlay.addLayout(top)

        if features:
            hdr = QFrame()
            hdr.setObjectName("TableHead")
            hl = QHBoxLayout(hdr)
            hl.setContentsMargins(12, 4, 12, 4)
            hl.setSpacing(10)
            for text_h, stretch, fix_w in (
                ("FS-ID", 0, 92),
                (tr("ФУНКЦИЯ", "FEATURE"), 1, 0),
                (tr("СТАТУС (3C00)", "STATUS (3C00)"), 0, 192),
            ):
                lbl = group_label(text_h)
                if fix_w:
                    lbl.setFixedWidth(fix_w)
                hl.addWidget(lbl, stretch)
            vlay.addWidget(hdr)

            for idx, feat in enumerate(features):
                row_f = QFrame()
                row_f.setObjectName("TableRow")
                if idx == len(features) - 1:
                    row_f.setProperty("last", True)
                rl = QHBoxLayout(row_f)
                rl.setContentsMargins(12, 5, 12, 5)
                rl.setSpacing(10)

                c_id = QLabel(f"0x{feat.get('fsid_hex', '00000000')}")
                c_id.setFont(mono_font(11, bold=True))
                c_id.setFixedWidth(92)
                c_id.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

                name_col = QVBoxLayout()
                name_col.setContentsMargins(0, 0, 0, 0)
                name_col.setSpacing(1)
                c_name = QLabel(tr(str(feat.get("name_ru") or "—"), str(feat.get("name_en") or "—")))
                c_name.setWordWrap(True)
                name_col.addWidget(c_name)
                reason = tr(str(feat.get("reason_ru") or ""), str(feat.get("reason_en") or ""))
                if reason:
                    c_why = QLabel(reason)
                    c_why.setObjectName("Hint")
                    c_why.setWordWrap(True)
                    set_tone(c_why, "err")
                    name_col.addWidget(c_why)

                st_lbl = tr(str(feat.get("label_ru") or "—"), str(feat.get("label_en") or "—"))
                st_hex = str(feat.get("status_hex") or "")
                st_tone = str(feat.get("tone") or "muted")
                c_st = status_readout(f"{st_lbl} · {st_hex}" if st_hex else st_lbl, st_tone)
                c_st.setFixedWidth(192)
                c_st.setAlignment(Qt.AlignmentFlag.AlignCenter)
                if reason:
                    c_st.setToolTip(reason)

                rl.addWidget(c_id, 0, Qt.AlignmentFlag.AlignTop)
                rl.addLayout(name_col, 1)
                rl.addWidget(c_st, 0, Qt.AlignmentFlag.AlignTop)
                vlay.addWidget(row_f)
        else:
            empty_msg = (
                tr(
                    "Штатный DID 0x3C00 пуст (нет NvM-сертификатов FSC). Функции активируются прямым патчем Code Flash независимо от 0x3C00.",
                    "Standard DID 0x3C00 is empty (no NvM FSC certificates). Features are activated directly by the Code Flash patch independently of 0x3C00.",
                )
                if swap_patch_state == "swap_activated"
                else tr(
                    "В DID 0x3C00 нет установленных сертификатов SWaP / FeC (ответ 00 00 00 00 00).",
                    "No SWaP / FeC certificates are stored in DID 0x3C00 (response 00 00 00 00 00).",
                )
            )
            lbl_empty = QLabel(empty_msg)
            lbl_empty.setObjectName("Hint")
            lbl_empty.setWordWrap(True)
            lbl_empty.setContentsMargins(12, 2, 12, 2)
            vlay.addWidget(lbl_empty)

        meta_parts: list[str] = []
        if swap_uds.get("fes_vcrn_hex"):
            v_hex = str(swap_uds["fes_vcrn_hex"]).upper()
            v_txt = tr(f"{v_hex} (заводской)", f"{v_hex} (virgin)") if swap_uds.get("fes_vcrn_virgin") else v_hex
            meta_parts.append(f"VCRN 3C0A: {v_txt}")
        if swap_uds.get("rsa_key_kind"):
            rk = str(swap_uds["rsa_key_kind"])
            if rk == "dev_x720":
                rk_lbl = "Dev (X720)"
            elif rk == "series_0780":
                rk_lbl = "Series (0771/0780)"
            else:
                rk_lbl = f"{str(swap_uds.get('rsa_modulus_prefix_hex') or '').upper()[:12]}…"
            meta_parts.append(f"RSA 3C05: {rk_lbl}")
        if swap_uds.get("coding_byte12_13_hex"):
            grps = swap_uds.get("coding_groups") or []
            g_str = f" ({','.join(str(x) for x in grps)})" if len(grps) == 4 else ""
            meta_parts.append(f"Coding 0600[12..13]: {swap_uds['coding_byte12_13_hex']}{g_str}")
        if meta_parts:
            lbl_meta = QLabel("  ·  ".join(meta_parts))
            lbl_meta.setFont(mono_font(10))
            set_tone(lbl_meta, "muted")
            lbl_meta.setContentsMargins(12, 2, 12, 0)
            lbl_meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            vlay.addWidget(lbl_meta)

        if swap_patch_state == "partial":
            lbl_partial = QLabel(
                tr(
                    "Обнаружен частичный или устаревший патч SWaP (требуется обновление ответа UDS 22 3C 00). "
                    "Нажмите «Обновить SWaP + 3C00…», чтобы диагностика корректно отображала активный набор.",
                    "Partial or legacy SWaP patch detected (UDS 22 3C 00 stub needs update). "
                    "Click “Update SWaP + 3C00…” so standard diagnostics displays the active set cleanly.",
                )
            )
            lbl_partial.setObjectName("Hint")
            lbl_partial.setWordWrap(True)
            lbl_partial.setContentsMargins(12, 2, 12, 2)
            set_tone(lbl_partial, "warn")
            vlay.addWidget(lbl_partial)

        return wrap

    @staticmethod
    def _build_patch_points_table(points: list[dict[str, Any]]) -> QFrame:
        wrap = QFrame()
        wrap.setObjectName("ResultStrip")
        vlay = QVBoxLayout(wrap)
        vlay.setContentsMargins(0, 4, 0, 4)
        vlay.setSpacing(0)

        hdr = QFrame()
        hdr.setObjectName("TableHead")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(12, 4, 12, 5)
        hl.setSpacing(10)
        for text_h, stretch, fix_w in (
            (tr("АДРЕС", "ADDRESS"), 0, 92),
            (tr("ТОЧКА ПАТЧА", "PATCH SITE"), 1, 0),
            (tr("БАЙТЫ", "BYTES"), 0, 120),
            (tr("СОСТОЯНИЕ", "STATE"), 0, 82),
        ):
            lbl = group_label(text_h)
            if fix_w:
                lbl.setFixedWidth(fix_w)
            hl.addWidget(lbl, stretch)
        vlay.addWidget(hdr)

        for idx, pt in enumerate(points):
            row_f = QFrame()
            row_f.setObjectName("TableRow")
            if idx == len(points) - 1:
                row_f.setProperty("last", True)
            rl = QHBoxLayout(row_f)
            rl.setContentsMargins(12, 5, 12, 5)
            rl.setSpacing(10)

            c_addr = QLabel(str(pt.get("physical_address") or "—"))
            c_addr.setFont(mono_font(11))
            c_addr.setFixedWidth(92)
            set_tone(c_addr, "muted")

            c_name = QLabel(str(pt.get("name") or "—"))
            c_name.setWordWrap(True)

            actual = str(pt.get("actual_hex") or "").upper()
            short_hex = actual if len(actual) <= 14 else (actual[:12] + "…")
            c_bytes = QLabel(short_hex or "—")
            c_bytes.setFont(mono_font(10))
            c_bytes.setFixedWidth(120)
            c_bytes.setToolTip(actual)
            set_tone(c_bytes, "muted")

            p_st = str(pt.get("state") or "unknown")
            if p_st == "cp_disabled":
                c_st = status_readout("CP OFF", "ok")
            elif p_st == "swap_activated":
                c_st = status_readout("SWaP ON", "ok")
            elif p_st == "stock":
                c_st = status_readout(tr("сток", "stock"), "info")
            elif p_st == "legacy":
                c_st = status_readout(tr("устар.", "legacy"), "warn")
            else:
                c_st = status_readout(tr("иное", "other"), "err")
            c_st.setFixedWidth(82)
            c_st.setAlignment(Qt.AlignmentFlag.AlignCenter)

            rl.addWidget(c_addr)
            rl.addWidget(c_name, 1)
            rl.addWidget(c_bytes)
            rl.addWidget(c_st)
            vlay.addWidget(row_f)
        return wrap

    # ────────────────────────────── Page 2: Memory & FRF ──────────────────────────────

    def _build_memory_page(self, lay: QVBoxLayout) -> None:
        prof = self._profile
        fast_ok = bool(prof.get("verified") and prof.get("fast_driver_supported"))

        # ── Card 1: Factory ODIS FRF / ODX-F Flashing over pure UDS 10 02 ──
        lay.addWidget(self._build_frf_card())

        # ── Card 2: Live Memory Backup over CAN ──
        sec_live = self._compact_section(
            tr("Чтение памяти радара по CAN (XCP)", "Live Radar Memory Backup over CAN (XCP)"),
            tr(
                "Автоматическое открытие XcpGate (DID 0x0902 bit 3) и разблокировка XCP LFSR-7. Память радара не изменяется.",
                "Automatically opens XcpGate (DID 0x0902 bit 3) and unlocks XCP LFSR-7. Radar memory is not modified.",
            ),
        )
        sec_live.head.addWidget(
            status_readout(
                f"{prof['mcu']} · {_fmt_size_kib(int(prof['cflash_size']))}",
                "info",
            )
        )

        # Structured 2-column memory map cards (never overflows horizontally)
        mem_grid = QGridLayout()
        mem_grid.setHorizontalSpacing(10)
        mem_grid.setVerticalSpacing(8)
        mem_grid.setColumnStretch(0, 1)
        mem_grid.setColumnStretch(1, 1)
        regions = (
            (
                "dflash",
                tr("DFLASH0 (Fee / ключи)", "DFLASH0 (Fee / keys)"),
                f"0x{MRR_DFLASH_ADDR:08X}",
                _fmt_size_kib(MRR_DFLASH_SIZE),
                tr("Ключи IKA / GFA, счётчик CP", "IKA / GFA keys, CP counter"),
            ),
            (
                "boot",
                tr("Bootloader", "Bootloader"),
                f"0x{MRR_BOOT_BASE:08X}",
                _fmt_size_kib(MRR_BOOT_SIZE),
                tr("Загрузчик и ECU_BOOT_SUM", "Bootloader & ECU_BOOT_SUM"),
            ),
            (
                "app",
                tr("Application", "Application"),
                f"0x{MRR_APP_BASE:08X}",
                _fmt_size_kib(int(prof["app_size"])),
                tr("Основная прошивка ПО", "Main application firmware"),
            ),
            (
                "cflash",
                tr("Полный Code Flash", "Full Code Flash"),
                f"0x{MRR_BOOT_BASE:08X}",
                _fmt_size_kib(int(prof["cflash_size"])),
                tr("Bootloader + Application", "Bootloader + Application"),
            ),
            (
                "sram",
                tr("SRAM (ОЗУ)", "SRAM (RAM)"),
                f"0x{MRR_SRAM_ADDR:08X}",
                _fmt_size_kib(int(prof["sram_size"])),
                tr("Рабочие зеркала и стек", "Live mirrors & runtime state"),
            ),
        )

        for idx, (reg_code, title_r, addr_r, sz_r, sub_r) in enumerate(regions):
            tile = QFrame()
            tile.setObjectName("MetaStrip")
            tile.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            tl = QHBoxLayout(tile)
            tl.setContentsMargins(12, 8, 10, 8)
            tl.setSpacing(10)

            info_col = QVBoxLayout()
            info_col.setContentsMargins(0, 0, 0, 0)
            info_col.setSpacing(2)

            row_top = QHBoxLayout()
            row_top.setContentsMargins(0, 0, 0, 0)
            row_top.setSpacing(8)
            lbl_t = QLabel(title_r)
            lbl_t.setObjectName("FieldLabel")
            lbl_t.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            lbl_sz = QLabel(sz_r)
            lbl_sz.setFont(mono_font(10))
            set_tone(lbl_sz, "info")
            row_top.addWidget(lbl_t, 1)
            row_top.addWidget(lbl_sz, 0)
            info_col.addLayout(row_top)

            lbl_m = QLabel(f"{addr_r} · {sub_r}")
            lbl_m.setObjectName("Hint")
            lbl_m.setWordWrap(True)
            lbl_m.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            info_col.addWidget(lbl_m)
            tl.addLayout(info_col, 1)

            btn_r = self._register_can_btn(
                button(tr("Считать", "Read"), "InlineBtn", slot=lambda r=reg_code: self.action_read_memory(r)),
                needs_xcp=True,
            )
            btn_r.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            tl.addWidget(btn_r, 0, Qt.AlignmentFlag.AlignVCenter)
            mem_grid.addWidget(tile, idx // 2, idx % 2)
        sec_live.body.addLayout(mem_grid)

        if not fast_ok:
            slow_note = Callout("info")
            slow_note.label.setText(
                tr(
                    f"Для профиля <b>{prof['sw']}</b> чтение выполняется стандартным XCP <code>SHORT_UPLOAD</code> "
                    "с автопропуском пустых 1 КиБ блоков <code>0xFF</code> (DFLASH0 ~25 с, полный Code Flash — несколько минут).",
                    f"For profile <b>{prof['sw']}</b>, reading uses standard XCP <code>SHORT_UPLOAD</code> "
                    "with 1 KiB blank-<code>0xFF</code> skipping (DFLASH0 ~25 s, full Code Flash takes several minutes).",
                )
            )
            sec_live.body.addWidget(slow_note)

        # Inline Last Live Read Summary
        if self._last_mem_report.get("regions"):
            sec_live.body.addWidget(self._build_last_read_summary(self._last_mem_report))

        btn_full = self._register_can_btn(
            button(tr("Полный бэкап (CodeFlash + DFLASH0 + SRAM)", "Full backup (CodeFlash + DFLASH0 + SRAM)"), "PrimaryBtn", slot=lambda: self.action_read_memory("all")),
            needs_xcp=True,
        )
        btn_df_fast = self._register_can_btn(
            button(tr("Быстро: DFLASH0 (64 КиБ)", "Quick: DFLASH0 (64 KiB)"), slot=lambda: self.action_read_memory("dflash")),
            needs_xcp=True,
        )
        sec_live.add_footer(btn_full, btn_df_fast)
        lay.addWidget(sec_live)

    def _build_last_read_summary(self, rep: dict[str, Any]) -> QFrame:
        wrap = QFrame()
        wrap.setObjectName("ResultStrip")
        vlay = QVBoxLayout(wrap)
        vlay.setContentsMargins(12, 8, 12, 8)
        vlay.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(8)
        lbl_h = group_label(tr("ПОСЛЕДНЕЕ ЧТЕНИЕ ПАМЯТИ", "LAST MEMORY READ"))
        top.addWidget(lbl_h, 0, Qt.AlignmentFlag.AlignVCenter)
        mode_s = str(rep.get("mode") or "")
        elapsed = rep.get("total_elapsed_sec")
        if mode_s or elapsed is not None:
            meta_lbl = QLabel(tr(f"{mode_s} · {elapsed} с", f"{mode_s} · {elapsed}s") if elapsed is not None else mode_s)
            meta_lbl.setFont(mono_font(10))
            set_tone(meta_lbl, "muted")
            top.addWidget(meta_lbl, 0, Qt.AlignmentFlag.AlignVCenter)
        top.addStretch(1)

        s_dir = rep.get("session_dir")
        if s_dir and Path(str(s_dir)).exists():
            btn_dir = button(
                tr("Открыть папку", "Open folder"),
                "InlineBtn",
                slot=lambda d=str(s_dir): QDesktopServices.openUrl(QUrl.fromLocalFile(d)),
            )
            btn_dir.setCursor(Qt.CursorShape.PointingHandCursor)
            top.addWidget(btn_dir)
        btn_raw = button(
            tr("Отчёт JSON…", "JSON report…"),
            "GhostBtn",
            slot=lambda r=rep: self._show_json_dialog(tr("Отчёт чтения памяти", "Memory read report"), r),
        )
        btn_raw.setCursor(Qt.CursorShape.PointingHandCursor)
        top.addWidget(btn_raw)
        vlay.addLayout(top)

        for idx, reg in enumerate(rep.get("regions") or []):
            r_frame = QFrame()
            r_frame.setObjectName("TableRow")
            if idx == len(rep["regions"]) - 1:
                r_frame.setProperty("last", True)
            rl = QHBoxLayout(r_frame)
            rl.setContentsMargins(0, 4, 0, 4)
            rl.setSpacing(10)
            fname = Path(str(reg["file"])).name if reg.get("file") else str(reg.get("name") or "—")
            lbl_n = QLabel(fname)
            lbl_n.setFont(mono_font(11, bold=True))
            lbl_sz = QLabel(_fmt_size_kib(int(reg.get("length", 0))))
            lbl_sz.setFont(mono_font(11))
            set_tone(lbl_sz, "muted")
            bps = int(reg.get("bytes_per_sec") or 0)
            lbl_spd = QLabel(
                tr(f"{bps / 1024:.1f} КиБ/с", f"{bps / 1024:.1f} KiB/s")
                if bps >= 1024
                else tr(f"{bps} Б/с", f"{bps} B/s")
            )
            lbl_spd.setFont(mono_font(10))
            set_tone(lbl_spd, "ok" if bps >= 10240 else "muted")
            sha = str(reg.get("sha256") or "")
            lbl_sha = QLabel(f"SHA {sha[:10]}…")
            lbl_sha.setFont(mono_font(10))
            lbl_sha.setToolTip(sha)
            set_tone(lbl_sha, "muted")
            rl.addWidget(lbl_n)
            rl.addWidget(lbl_sz)
            rl.addStretch(1)
            rl.addWidget(lbl_spd)
            rl.addWidget(lbl_sha)
            vlay.addWidget(r_frame)
        return wrap

    def _build_frf_card(self) -> Section:
        sec_frf = self._compact_section(
            tr("Прошивка заводского FRF / ODX-F (UDS 10 02)", "Factory FRF / ODX-F Flashing (UDS 10 02)"),
            tr(
                "Штатная прошивка подписанных контейнеров ODIS (.frf / .odx) для 3Q0 (MPC5674K) и 5Q0/3QF (MPC5675K) по чистому UDS — работает напрямую и через шлюз J533 без XCP и RAM-моста.",
                "Standard ODIS programming (.frf / .odx) for 3Q0 (MPC5674K) and 5Q0/3QF (MPC5675K) over pure UDS — works directly and through J533 gateway without XCP or RAM-Bridge.",
            ),
        )
        frf = self._selected_frf
        hard_errs: list[str] = []
        soft_warns: list[str] = []
        if frf is not None:
            hard_errs, soft_warns = mrr_frf_compatibility(
                frf,
                self._passport,
                recovery_mode=self._frf_recovery_mode,
            )
            badge_txt = f"{frf.part_number} · {frf.sw_version} · {frf.mcu}"
            badge_tone = "err" if hard_errs else ("warn" if soft_warns else "ok")
        else:
            badge_txt = tr("UDS 10 02 · без XCP", "UDS 10 02 · no XCP")
            badge_tone = "info"
        sec_frf.head.addWidget(status_readout(badge_txt, badge_tone))

        # File selection strip
        pick_row = QHBoxLayout()
        pick_row.setContentsMargins(0, 0, 0, 0)
        pick_row.setSpacing(8)
        file_box = QFrame()
        file_box.setObjectName("MetaStrip")
        fb_lay = QHBoxLayout(file_box)
        fb_lay.setContentsMargins(12, 7, 10, 7)
        fb_lay.setSpacing(8)
        if self._selected_frf_path is not None:
            lbl_file = QLabel(self._selected_frf_path.name)
            lbl_file.setFont(mono_font(11, bold=True))
            lbl_file.setToolTip(str(self._selected_frf_path))
        elif frf is not None:
            lbl_file = QLabel(frf.name)
            lbl_file.setFont(mono_font(11, bold=True))
        else:
            lbl_file = QLabel(tr("Выберите заводской файл .frf или .odx…", "Select a factory .frf or .odx container…"))
            lbl_file.setObjectName("Hint")
        lbl_file.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        fb_lay.addWidget(lbl_file, 1)
        if frf is not None:
            btn_clr = button(tr("Сбросить", "Clear"), "GhostBtn", slot=self.action_clear_frf)
            btn_clr.setCursor(Qt.CursorShape.PointingHandCursor)
            fb_lay.addWidget(btn_clr, 0)
        pick_row.addWidget(file_box, 1)

        btn_pick = button(tr("Выбрать FRF / ODX…", "Choose FRF / ODX…"), slot=self.action_choose_frf)
        btn_pick.setCursor(Qt.CursorShape.PointingHandCursor)
        pick_row.addWidget(btn_pick, 0)
        sec_frf.body.addLayout(pick_row)

        if frf is not None:
            eng_tag = tr(" (инж.)", " (eng)") if frf.is_engineering else ""
            fmt_tag = "A0" if frf.app.data_format == 0xA0 else "RAW"
            rsa_ok = frf.driver.rsa_valid and frf.app.rsa_valid
            sec_frf.body.addWidget(
                self._metric_strip(
                    [
                        (
                            tr("ДЕТАЛЬ / ПО", "PART / SW"),
                            f"{frf.part_number or '—'} · {frf.sw_version}{eng_tag}",
                            "info" if not frf.is_engineering else "warn",
                        ),
                        (
                            tr("ПОКОЛЕНИЕ / МК", "GEN / MCU"),
                            f"{frf.family} · {frf.mcu}",
                            "err" if hard_errs else "info",
                        ),
                        (
                            tr("ДАННЫЕ (0x10)", "PAYLOAD (0x10)"),
                            f"{len(frf.app.stream) // 1024} → {frf.app.uncompressed_size // 1024} КиБ ({fmt_tag})",
                            "muted",
                        ),
                        (
                            tr("ПОДПИСЬ FBLV", "FBLV SIGNATURE"),
                            tr("RSA-1024 + CRC OK", "RSA-1024 + CRC OK") if rsa_ok else tr("ОШИБКА RSA", "RSA INVALID"),
                            "ok" if rsa_ok else "err",
                        ),
                    ]
                )
            )
            if hard_errs:
                c_err = Callout("err")
                c_err.label.setText(
                    tr("<b>Прошивка заблокирована:</b><br>", "<b>Flashing blocked:</b><br>")
                    + "<br>".join(f"• {e}" for e in hard_errs)
                )
                sec_frf.body.addWidget(c_err)
            elif soft_warns:
                c_warn = Callout("warn")
                c_warn.label.setText("<br>".join(f"• {w}" for w in soft_warns))
                sec_frf.body.addWidget(c_warn)
            else:
                lbl_ok = QLabel(
                    tr(
                        "Контейнер проверен (RSA-1024, CRC-32, МК совпадает). DFLASH0 (ключи IKA/GFA, кодировка, калибровка) сохраняется.",
                        "Container verified (RSA-1024, CRC-32, MCU matches). DFLASH0 (IKA/GFA keys, coding, alignment) is preserved.",
                    )
                )
                lbl_ok.setObjectName("Hint")
                lbl_ok.setWordWrap(True)
                sec_frf.body.addWidget(lbl_ok)

        chk_rec = QCheckBox(
            tr(
                "Режим восстановления из загрузчика (если радар уже в FBLv после обрыва прошивки)",
                "Bootloader recovery mode (if radar is already stuck in FBLv after an interrupted flash)",
            )
        )
        chk_rec.setChecked(self._frf_recovery_mode)
        chk_rec.toggled.connect(self._on_frf_recovery_toggled)
        sec_frf.body.addWidget(chk_rec)

        if self._last_frf_report.get("complete"):
            sec_frf.body.addWidget(self._build_last_frf_summary(self._last_frf_report))

        btn_flash = button(
            tr("Прошить FRF / ODX-F по UDS…", "Flash FRF / ODX-F over UDS…"),
            "PrimaryBtn",
            slot=self.action_flash_frf,
        )
        if hard_errs:
            btn_flash.setEnabled(False)
        else:
            self._register_can_btn(btn_flash, needs_xcp=False)
        sec_frf.add_footer(btn_flash)
        return sec_frf

    def _build_last_frf_summary(self, rep: dict[str, Any]) -> QFrame:
        wrap = QFrame()
        wrap.setObjectName("ResultStrip")
        rl = QHBoxLayout(wrap)
        rl.setContentsMargins(12, 8, 12, 8)
        rl.setSpacing(10)
        frf_meta = rep.get("frf") or {}
        p_before = rep.get("passport_before") or {}
        p_after = rep.get("passport_after") or {}
        app_up = rep.get("application_upload") or {}
        old_sw = p_before.get("sw_version") or "—"
        new_sw = p_after.get("sw_version") or frf_meta.get("sw_version") or "—"
        pn_after = p_after.get("part_number") or frf_meta.get("part_number") or "—"
        elapsed = app_up.get("elapsed_sec")
        lbl = QLabel(
            tr(
                f"Последняя прошивка FRF: {pn_after} · ПО {old_sw} → {new_sw} · RSA OK"
                + (f" · {elapsed} с" if elapsed is not None else ""),
                f"Last FRF flash: {pn_after} · SW {old_sw} → {new_sw} · RSA OK"
                + (f" · {elapsed}s" if elapsed is not None else ""),
            )
        )
        lbl.setFont(mono_font(10))
        set_tone(lbl, "ok")
        rl.addWidget(lbl, 1)
        btn_json = button(
            tr("Отчёт JSON…", "JSON report…"),
            "GhostBtn",
            slot=lambda r=rep: self._show_json_dialog(tr("Отчёт прошивки FRF / ODX-F", "FRF / ODX-F Flash Report"), r),
        )
        btn_json.setCursor(Qt.CursorShape.PointingHandCursor)
        rl.addWidget(btn_json, 0)
        return wrap

    # ────────────────────────────── Page 3: Passport & Status ──────────────────────────────

    @staticmethod
    def _kv_cell(k_txt: str, v_txt: str, tone: str = "") -> QWidget:
        """Compact vertical label+value pair with tight internal rhythm (Gestalt proximity)."""
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(2)
        lk = group_label(k_txt)
        lv = QLabel(str(v_txt))
        lv.setFont(mono_font(12, bold=(tone in ("ok", "warn", "err"))))
        if tone in ("ok", "warn", "err", "info", "muted"):
            set_tone(lv, tone)
        lv.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(lk)
        v.addWidget(lv)
        return w

    def _build_status_page(self, lay: QVBoxLayout) -> None:
        p = self._passport
        st = self._status
        prof = self._profile
        patch_state = self._cflash_cp.get("cp_patch_state")

        # ── Card 1: Component Protection (KS) & XcpGate Diagnostics ──
        sec_ks = self._compact_section(
            tr("Защита компонентов (KS) и XcpGate", "Component Protection (KS) & XcpGate"),
            tr(
                "Диагностические регистры UDS 0x03DE, 0x0440, 0x043F, 0x02E0, 0x02F9 и канал адаптации XcpGate 0x0902.",
                "UDS diagnostic registers 0x03DE, 0x0440, 0x043F, 0x02E0, 0x02F9 and XcpGate adaptation DID 0x0902.",
            ),
        )
        cp_cnt = st.get("cp_counter")
        if patch_state == "cp_disabled":
            sec_ks.head.addWidget(status_readout(tr("CP отключена патчем", "CP bypassed by patch"), "ok"))
        elif st.get("cp_active") is True:
            sec_ks.head.addWidget(status_readout(tr(f"CP активна (03DE={cp_cnt})", f"CP active (03DE={cp_cnt})"), "err"))
        elif cp_cnt is not None:
            sec_ks.head.addWidget(status_readout(tr(f"CP в норме (03DE={cp_cnt})", f"CP OK (03DE={cp_cnt})"), "ok"))
        else:
            sec_ks.head.addWidget(status_readout(tr("Не опрошен", "Not polled"), "muted"))

        g_ks = QGridLayout()
        g_ks.setHorizontalSpacing(22)
        g_ks.setVerticalSpacing(12)
        if cp_cnt is None:
            cnt_desc, cnt_tone = "—", "muted"
        elif cp_cnt >= 0x23:
            cnt_desc, cnt_tone = tr(f"0x{cp_cnt:04X} ({cp_cnt} · блок.)", f"0x{cp_cnt:04X} ({cp_cnt} · lock)"), "err"
        elif cp_cnt > 0x1E:
            cnt_desc, cnt_tone = tr(f"0x{cp_cnt:04X} ({cp_cnt} · CP!)", f"0x{cp_cnt:04X} ({cp_cnt} · CP!)"), "err"
        elif cp_cnt == 0:
            cnt_desc, cnt_tone = tr("0x0000 (0 · норма)", "0x0000 (0 · OK)"), "ok"
        else:
            cnt_desc, cnt_tone = f"0x{cp_cnt:04X} ({cp_cnt})", "info"

        ika_desc, ika_tone = (
            (tr("Заводской (virgin)", "Factory (virgin)"), "warn")
            if st.get("ika_virgin")
            else (tr("Персонализирован", "Personalized"), "ok")
        ) if "ika_virgin" in st else ("—", "muted")

        gfa_desc, gfa_tone = (
            (tr("Обучен", "Learned"), "ok")
            if st.get("gfa_learned")
            else (tr("Не обучен", "Not learned"), "warn")
        ) if "gfa_learned" in st else ("—", "muted")

        xg_desc, xg_tone = (
            (tr(f"Открыт (0x{st['xcp_gate_byte']:02X}, bit 3)", f"Open (0x{st['xcp_gate_byte']:02X}, bit 3)"), "ok")
            if st.get("xcp_gate_enabled")
            else (tr(f"Закрыт (0x{st['xcp_gate_byte']:02X})", f"Closed (0x{st['xcp_gate_byte']:02X})"), "muted")
        ) if "xcp_gate_byte" in st else ("—", "muted")

        ks_triples = [
            (tr("СЧЁТЧИК ОШИБОК CP (0x03DE)", "CP COUNTER (0x03DE)"), cnt_desc, cnt_tone),
            (tr("СОСТОЯНИЕ IKA (0x0440)", "IKA STATE (0x0440)"), ika_desc, ika_tone),
            (tr("СОСТОЯНИЕ GFA (0x0440)", "GFA STATE (0x0440)"), gfa_desc, gfa_tone),
            (tr("XCP GATE (0x0902)", "XCP GATE (0x0902)"), xg_desc, xg_tone),
            (tr("KS VCRN (0x02F9)", "KS VCRN (0x02F9)"), (st.get("ks_vcrn_hex") or "—").upper(), ""),
            (tr("ОПЦИИ KS (0x043F)", "KS OPTIONS (0x043F)"), (st.get("ks_options_hex") or "—").upper(), ""),
        ]
        for idx, (k_txt, v_txt, tone) in enumerate(ks_triples):
            r, c = divmod(idx, 3)
            g_ks.addWidget(self._kv_cell(k_txt, v_txt, tone), r, c)
        sec_ks.body.addLayout(g_ks)

        raw_dids = dict(st.get("raw_status_dids") or {})
        if not raw_dids:
            if cp_cnt is not None:
                raw_dids["03DE"] = f"{cp_cnt:04x}"
            if st.get("ks_info_hex"):
                raw_dids["0440"] = str(st["ks_info_hex"])
            if st.get("ks_options_hex"):
                raw_dids["043F"] = str(st["ks_options_hex"])
            if st.get("ks_nonce_hex"):
                raw_dids["02E0"] = str(st["ks_nonce_hex"])
            if st.get("ks_vcrn_hex"):
                raw_dids["02F9"] = str(st["ks_vcrn_hex"])
            if "xcp_gate_byte" in st:
                raw_dids["0902"] = f"{int(st['xcp_gate_byte']):02x}"
        if raw_dids:
            strip = QFrame()
            strip.setObjectName("ResultStrip")
            sl = QHBoxLayout(strip)
            sl.setContentsMargins(10, 5, 10, 5)
            sl.setSpacing(14)
            for tag in ("03DE", "0440", "043F", "02E0", "02F9", "0902"):
                if tag in raw_dids:
                    lbl = QLabel(f"{tag}: {str(raw_dids[tag]).upper()}")
                    lbl.setFont(mono_font(10))
                    set_tone(lbl, "muted")
                    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                    sl.addWidget(lbl)
            sl.addStretch(1)
            sec_ks.body.addWidget(strip)

        btn_poll_uds = self._register_can_btn(
            button(tr("Опросить статус UDS", "Poll UDS status"), "PrimaryBtn", slot=self.action_read_status),
            needs_xcp=False,
        )
        btn_poll_xcp = self._register_can_btn(
            button(tr("Полный опрос (UDS + XCP)", "Full poll (UDS + XCP)"), slot=self.action_read_keys),
            needs_xcp=True,
        )
        sec_ks.add_footer(btn_poll_uds, btn_poll_xcp)
        lay.addWidget(sec_ks)

        # ── Card 2: UDS Passport & Long Coding ──
        sec_pp = self._compact_section(
            tr("Паспорт блока управления 13 ACC (UDS)", "13 ACC Control Unit Passport (UDS)"),
        )
        g_pp = QGridLayout()
        g_pp.setHorizontalSpacing(22)
        g_pp.setVerticalSpacing(12)
        fw_supported = bool(prof.get("verified") and prof.get("flash_write_supported"))
        pp_triples = [
            (tr("НОМЕР ДЕТАЛИ (F187)", "PART NUMBER (F187)"), p.get("part_number") or "—", ""),
            (tr("ВЕРСИЯ ПО (F189)", "SW VERSION (F189)"), p.get("sw_version") or "—", ""),
            (
                tr("ОБОРУДОВАНИЕ (F191 / F1A3)", "HARDWARE (F191 / F1A3)"),
                f"{p.get('hw_part_number') or '—'} / {p.get('hw_version') or '—'}",
                "",
            ),
            (tr("СИСТЕМА (F197)", "SYSTEM NAME (F197)"), p.get("system_name") or prof.get("family") or "—", ""),
            ("FAZIT (F17C)", p.get("fazit") or "—", ""),
            ("ASAM / ODX (F19E)", p.get("asam_odx") or prof.get("odx_name") or "—", ""),
            (
                tr("ПРОФИЛЬ / ПРОЦЕССОР", "PROFILE / MCU"),
                f"{prof['sw']} · {prof['mcu']} ({_fmt_size_kib(int(prof['cflash_size']))})"
                + ("" if prof.get("verified") else tr(" · не проверен", " · unverified")),
                "info" if prof.get("verified") else "warn",
            ),
            ("VIN (F190)", p.get("vin") or "—", ""),
            (
                tr("ЗАПИСЬ FLASH ПО XCP", "LIVE XCP FLASH WRITE"),
                tr("поддерживается", "supported")
                if fw_supported
                else tr("офлайн-патч / UDS IKA+GFA", "offline patch / UDS IKA+GFA"),
                "ok" if fw_supported else "muted",
            ),
        ]
        for idx, (k_txt, v_txt, tone) in enumerate(pp_triples):
            r, c = divmod(idx, 3)
            g_pp.addWidget(self._kv_cell(k_txt, str(v_txt), tone), r, c)
        sec_pp.body.addLayout(g_pp)

        coding_hex = str(p.get("coding") or "").upper()
        if coding_hex:
            spaced_coding = " ".join(coding_hex[i : i + 2] for i in range(0, len(coding_hex), 2))
            ed_cod = QLineEdit(spaced_coding)
            ed_cod.setReadOnly(True)
            ed_cod.setFont(mono_font(11))
            btn_cp_cod = button(
                tr("Копировать", "Copy"),
                "InlineBtn",
                slot=lambda v=coding_hex: self._copy_text(v, tr("Кодировка 0600", "Coding 0600")),
            )
            c_cod, _ = self._field_box(
                tr("ДЛИННАЯ КОДИРОВКА (DID 0x0600)", "LONG CODING (DID 0x0600)"),
                ed_cod,
                badge_text=f"{len(coding_hex) // 2} B",
                badge_tone="muted",
                trailing=(btn_cp_cod,),
            )
            sec_pp.body.addWidget(c_cod)

        lay.addWidget(sec_pp)

        # ── Card 3: DFLASH0 Fee Telemetry (when available) ──
        if self._dflash_fee:
            fee = self._dflash_fee
            sec_fee = self._compact_section(
                tr("Структура DFLASH0 (AUTOSAR Fee)", "DFLASH0 Telemetry (AUTOSAR Fee)"),
            )
            g_fee = QGridLayout()
            g_fee.setHorizontalSpacing(22)
            g_fee.setVerticalSpacing(12)
            fee_triples = [
                (tr("АКТИВНЫЙ КЛАСТЕР", "ACTIVE CLUSTER"), str(fee.get("active_cluster_offset") or "—"), ""),
                (tr("ЗАПИСЕЙ В КАТАЛОГЕ", "DIRECTORY ENTRIES"), str(fee.get("directory_entry_count") or 0), ""),
                (tr("ШИФРОВАНИЕ", "ENCRYPTION"), str(fee.get("encryption_scheme") or "—"), "info"),
                (
                    tr("КОПИИ СЛОТОВ", "SLOT COPIES"),
                    tr("совпадают", "identical") if fee.get("copies_match") else tr("отличаются", "differ"),
                    "ok" if fee.get("copies_match") else "warn",
                ),
                (tr("ЗАПИСЕЙ 00BE / 00BD", "WRITES 00BE / 00BD"), f"{fee.get('cnt_00be', 0)} / {fee.get('cnt_00bd', 0)}", ""),
                (
                    "SHADOW SECRET",
                    tr("обнаружен", "present") if fee.get("shadow_secret_present") else tr("нет", "absent"),
                    "info" if fee.get("shadow_secret_present") else "muted",
                ),
            ]
            for idx, (k_txt, v_txt, tone) in enumerate(fee_triples):
                r, c = divmod(idx, 3)
                g_fee.addWidget(self._kv_cell(k_txt, v_txt, tone), r, c)
            sec_fee.body.addLayout(g_fee)
            lay.addWidget(sec_fee)

    # ────────────────────────────── Page 4: Fault Codes (DTC) ──────────────────────────────

    def _build_dtc_page(self, lay: QVBoxLayout) -> None:
        sec = self._compact_section(
            tr("Регистратор событий 13 ACC Radar (UDS 19 02 / 14 FF FF FF)", "13 ACC Radar Event Memory (UDS 19 02 / 14 FF FF FF)"),
            tr(
                "Расшифровка по официальной базе ODIS Engineering VW37X / VW48X (BV_AdaptCruisContrUDS — 576 кодов, RU / EN).",
                "Decoded via official ODIS Engineering VW37X / VW48X (BV_AdaptCruisContrUDS — 576 codes, RU / EN).",
            ),
        )

        if self._dtcs is None:
            sec.head.addWidget(status_readout(tr("Не опрошено", "Not read"), "muted"))
            lbl = QLabel(tr("Ошибки ещё не считывались. Нажмите «Считать DTC» для опроса регистратора событий.", "Fault codes have not been read yet. Click “Read DTCs” to query the event memory."))
            lbl.setObjectName("Hint")
            lbl.setWordWrap(True)
            sec.body.addWidget(lbl)
        elif not self._dtcs:
            sec.head.addWidget(status_readout(tr("Ошибок нет", "No faults"), "ok"))
            ok_box = Callout("ok")
            ok_box.label.setText(
                tr(
                    "<b>В памяти 13 ACC Radar нет активных или сохранённых неисправностей.</b>",
                    "<b>No active or stored fault codes in 13 ACC Radar memory.</b>",
                )
            )
            sec.body.addWidget(ok_box)
        else:
            n_active = sum(1 for d in self._dtcs if d.get("active"))
            n_stored = len(self._dtcs) - n_active
            summary_txt = tr(
                f"Найдено: {len(self._dtcs)} (активных: {n_active}, в памяти: {n_stored})",
                f"Found: {len(self._dtcs)} ({n_active} active, {n_stored} stored)",
            )
            sec.head.addWidget(status_readout(summary_txt, "err" if n_active else "warn"))

            has_cp_dtc = any(str(d.get("display") or "") in _CP_DTC_DISPLAY_CODES for d in self._dtcs)
            if has_cp_dtc:
                cp_strip = QFrame()
                cp_strip.setObjectName("MetaStrip")
                csl = QHBoxLayout(cp_strip)
                csl.setContentsMargins(12, 7, 10, 7)
                csl.setSpacing(10)
                lbl_cp = QLabel(
                    tr(
                        "Обнаружена ошибка защиты компонентов (CP). Снимите её через привязку GFA или патч Code Flash.",
                        "Component Protection (CP) fault detected. Clear it via vehicle GFA pairing or the Code Flash patch.",
                    )
                )
                lbl_cp.setWordWrap(True)
                set_tone(lbl_cp, "warn")
                btn_go_cp = button(
                    tr("Защита компонентов →", "Component protection →"),
                    "InlineBtn",
                    slot=lambda: self.select("cp_keys"),
                )
                btn_go_cp.setCursor(Qt.CursorShape.PointingHandCursor)
                csl.addWidget(lbl_cp, 1)
                csl.addWidget(btn_go_cp, 0, Qt.AlignmentFlag.AlignVCenter)
                sec.body.addWidget(cp_strip)

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
                (tr("КОД ODIS", "ODIS CODE"), 0, 86),
                ("UDS", 0, 76),
                (tr("СТАТУС", "STATUS"), 0, 126),
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

                disp_code = str(item.get("display") or item.get("code") or "—")
                raw_code = str(item.get("code") or "")
                st_byte = str(item.get("status") or "")
                st_detail = str(item.get("status_text") or "")
                is_active = bool(item.get("active"))

                c0 = QLabel(disp_code)
                c0.setFont(mono_font(12, bold=True))
                c0.setFixedWidth(86)
                c0.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                if disp_code in _CP_DTC_DISPLAY_CODES:
                    set_tone(c0, "err" if is_active else "warn")

                c1 = QLabel(raw_code)
                c1.setFont(mono_font(11))
                c1.setFixedWidth(76)
                set_tone(c1, "muted")
                c1.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

                st_badge_txt = (
                    tr("активна", "active") if is_active else tr("в памяти", "stored")
                ) + (f" · {st_byte}" if st_byte else "")
                c2 = status_readout(st_badge_txt, "err" if is_active else "warn")
                c2.setFixedWidth(126)
                c2.setAlignment(Qt.AlignmentFlag.AlignCenter)
                if st_detail:
                    c2.setToolTip(st_detail)

                desc_col = QVBoxLayout()
                desc_col.setContentsMargins(0, 0, 0, 0)
                desc_col.setSpacing(2)
                c3 = QLabel(str(item.get("description") or "—"))
                c3.setWordWrap(True)
                c3.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                desc_col.addWidget(c3)
                if st_detail:
                    c3_sub = QLabel(st_detail)
                    c3_sub.setObjectName("Hint")
                    c3_sub.setWordWrap(True)
                    desc_col.addWidget(c3_sub)

                rl.addWidget(c0, 0, Qt.AlignmentFlag.AlignTop)
                rl.addWidget(c1, 0, Qt.AlignmentFlag.AlignTop)
                rl.addWidget(c2, 0, Qt.AlignmentFlag.AlignTop)
                rl.addLayout(desc_col, 1)
                tlay.addWidget(row_f)

            sec.body.addWidget(table_wrap)

        btn_rd = self._register_can_btn(
            button(tr("Считать DTC", "Read DTCs"), "PrimaryBtn", slot=self.action_read_dtc),
            needs_xcp=False,
        )
        btn_clr = self._register_can_btn(
            button(
                tr("Сбросить DTC (14 FF FF FF)", "Clear DTCs (14 FF FF FF)"),
                "DangerBtn" if self._dtcs else "GhostBtn",
                slot=self.action_clear_dtc,
            ),
            needs_xcp=False,
        )
        footer_btns: list[QWidget] = [btn_rd, btn_clr]
        if self._dtcs:
            btn_copy = button(tr("Копировать список", "Copy list"), "InlineBtn", slot=self._copy_dtcs_text)
            btn_copy.setCursor(Qt.CursorShape.PointingHandCursor)
            footer_btns.append(btn_copy)
        sec.add_footer(*footer_btns)
        lay.addWidget(sec)

    # ────────────────────────────── Actions & Handlers ──────────────────────────────

    def _toggle_patch_points(self) -> None:
        self._show_patch_points = not self._show_patch_points
        if self._cp_points_table is not None and _qt_valid(self._cp_points_table):
            self._cp_points_table.setVisible(self._show_patch_points)
            if self._btn_cp_points is not None and _qt_valid(self._btn_cp_points):
                n = self._cp_points_count
                self._btn_cp_points.setText(
                    tr(f"Скрыть {n} точек Code Flash", f"Hide {n} Code Flash sites")
                    if self._show_patch_points
                    else tr(f"Показать {n} точек Code Flash", f"Inspect {n} Code Flash sites")
                )
            return
        self._render_page()

    def _toggle_swap_points(self) -> None:
        self._show_swap_points = not self._show_swap_points
        if self._swap_points_table is not None and _qt_valid(self._swap_points_table):
            self._swap_points_table.setVisible(self._show_swap_points)
            if self._btn_swap_points is not None and _qt_valid(self._btn_swap_points):
                n = self._swap_points_count
                self._btn_swap_points.setText(
                    tr(f"Скрыть {n} точек", f"Hide {n} sites")
                    if self._show_swap_points
                    else tr(f"Точки SWaP ({n})", f"SWaP sites ({n})")
                )
            return
        self._render_page()

    def _on_swap_gen1_pkg_changed(self, pkg_idx: int) -> None:
        if pkg_idx in MRR_GEN1_SWAP_PACKAGES and pkg_idx != 3:
            self._draft_swap_gen1_pkg = int(pkg_idx)
            self._render_page()

    def _on_swap_gen2_preset_changed(self, preset_id: str) -> None:
        for pr in MRR_GEN2_SWAP_PRESETS:
            if pr["id"] == preset_id:
                self._draft_swap_gen2_groups = [int(x) for x in pr["groups"]]
                self._render_page()
                return

    def _on_swap_gen2_group_changed(self, group_idx: int, variant_val: int) -> None:
        if 0 <= group_idx < 4:
            self._draft_swap_gen2_groups[group_idx] = int(variant_val)
            self._render_page()

    def _on_profile_changed(self, code: str) -> None:
        self._profile_override = code
        self.refresh()

    def _show_json_dialog(self, title: str, data: dict[str, Any]) -> None:
        run_dialog(
            TextResultDialog(
                self,
                title,
                json.dumps(data, ensure_ascii=False, indent=2),
                self.part_number,
            )
        )

    def _apply_live_result(self, res: dict[str, Any], *, keep_offline: bool = False) -> None:
        if isinstance(res.get("passport"), dict) and res["passport"]:
            self._passport = dict(res["passport"])
            if not keep_offline:
                self._offline_mode = False
        if isinstance(res.get("status"), dict) and res["status"]:
            self._status = dict(res["status"])
        if isinstance(res.get("swap_uds"), dict) and res["swap_uds"]:
            self._swap_uds = dict(res["swap_uds"])
        if res.get("dtcs") is not None:
            self._dtcs = list(res.get("dtcs") or [])
        if isinstance(res.get("cflash_cp"), dict) and res["cflash_cp"]:
            self._cflash_cp = dict(res["cflash_cp"])
        if isinstance(res.get("cflash_swap"), dict) and res["cflash_swap"]:
            self._cflash_swap = dict(res["cflash_swap"])
            if self._cflash_swap.get("swap_patch_state") == "swap_activated":
                pkg_idx = self._cflash_swap.get("package_index")
                if pkg_idx is not None and int(pkg_idx) in MRR_GEN1_SWAP_PACKAGES and int(pkg_idx) != 3:
                    self._draft_swap_gen1_pkg = int(pkg_idx)
                grps = self._cflash_swap.get("groups")
                if isinstance(grps, (list, tuple)) and len(grps) == 4:
                    self._draft_swap_gen2_groups = [int(x) for x in grps]
        if res.get("ika_hex"):
            self._ika_hex = str(res["ika_hex"]).lower()
            self._draft_cur_ika = self._ika_hex.upper()
        if res.get("gfa_hex"):
            self._gfa_hex = str(res["gfa_hex"]).lower()
            if self._draft_new_gfa is None:
                self._draft_new_gfa = self._gfa_hex.upper()
        if res.get("ecu_boot_sum_hex"):
            self._ecu_boot_sum_hex = str(res["ecu_boot_sum_hex"]).lower()
        if isinstance(res.get("dflash_fee"), dict) and res["dflash_fee"]:
            self._dflash_fee = dict(res["dflash_fee"])
        if isinstance(res.get("sram_mirrors"), dict) and res["sram_mirrors"]:
            self._sram_mirrors = dict(res["sram_mirrors"])

    def action_smart_poll(self) -> None:
        if self._xcp_available():
            self.action_read_keys()
        else:
            self.action_read_status()

    def action_read_status(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface, via_gw, _gw_br, gw_ch, sw_prof = self._snapshot_routing()
        gen = self._session_gen

        def task(rep: Any) -> dict[str, Any]:
            return can_mrr_status(
                port,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=False,
                gateway_channel=gw_ch,
                sw_profile=sw_prof,
                reporter=rep,
            )

        self.runner.run_task(
            tr("Чтение паспорта и статуса 13 ACC Radar", "Reading 13 ACC Radar passport & status"),
            task,
            on_success=lambda res, g=gen: self._on_status_read(res, expected_gen=g),
        )

    def _on_status_read(self, res: dict[str, Any], *, expected_gen: int | None = None) -> None:
        if not self._callback_valid(expected_gen):
            return
        self._apply_live_result(res)
        self.refresh()
        self.changed.emit()

    def action_read_swap_uds(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface, via_gw, _gw_br, gw_ch, sw_prof = self._snapshot_routing()
        gen = self._session_gen

        def task(rep: Any) -> dict[str, Any]:
            return can_mrr_swap_status(
                port,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=False,
                gateway_channel=gw_ch,
                sw_profile=sw_prof,
                include_metadata=True,
                reporter=rep,
            )

        self.runner.run_task(
            tr("Проверка состояния SWaP / FeC по UDS (22 3C 00)", "Checking SWaP / FeC status via UDS (22 3C 00)"),
            task,
            on_success=lambda res, g=gen: self._on_swap_uds_read(res, expected_gen=g),
        )

    def _on_swap_uds_read(self, res: dict[str, Any], *, expected_gen: int | None = None) -> None:
        if not self._callback_valid(expected_gen):
            return
        self._apply_live_result(res)
        sw_uds = self._swap_uds
        if sw_uds:
            n_act = int(sw_uds.get("active_count") or 0)
            n_rej = int(sw_uds.get("rejected_count") or 0)
            self.note.emit(
                tr(
                    f"SWaP/FeC (UDS 22 3C 00): активно {n_act}, отклонено {n_rej}.",
                    f"SWaP/FeC (UDS 22 3C 00): {n_act} active, {n_rej} rejected.",
                )
            )
        self.refresh()
        self.changed.emit()

    def action_read_keys(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface, via_gw, gw_br, gw_ch, sw_prof = self._snapshot_routing()
        s_dir = self._mrr_session_dir("mrr_keys", dumps=True)
        if s_dir is None:
            return
        gen = self._session_gen

        def task(rep: Any) -> dict[str, Any]:
            return can_mrr_read_keys(
                port,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                sw_profile=sw_prof,
                session_dir=s_dir,
                reporter=rep,
            )

        self.runner.run_task(
            tr("Чтение Code Flash (статус CP), DFLASH0 и ключей IKA/GFA", "Reading Code Flash (CP patch status), DFLASH0 & IKA/GFA keys"),
            task,
            on_success=lambda res, g=gen: self._on_keys_read(res, expected_gen=g),
        )

    def _on_keys_read(self, res: dict[str, Any], *, expected_gen: int | None = None) -> None:
        if not self._callback_valid(expected_gen):
            return
        self._apply_live_result(res)
        s_dir = res.get("session_dir")
        if s_dir and Path(str(s_dir)).is_dir():
            _remember_recent(Path(str(s_dir)))
        self.refresh()
        self.changed.emit()

    def action_export_json(self) -> None:
        safe_pn = self.part_number.replace(" ", "_").replace("/", "_")
        path_str, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить данные 13 ACC Radar в JSON", "Save 13 ACC Radar data to JSON"),
            str(self.conn.out_dir / f"mrr_{safe_pn}_report.json"),
            "JSON (*.json)",
        )
        if not path_str:
            return
        payload = {
            "ecu_kind": "mrr",
            "passport": self._passport,
            "profile": self._profile.get("sw"),
            "profile_verified": bool(self._profile.get("verified", False)),
            "ika_hex": self._ika_hex,
            "gfa_hex": self._gfa_hex,
            "ecu_boot_sum_hex": self._ecu_boot_sum_hex,
            "status": self._status,
            "swap_uds": self._swap_uds,
            "cflash_cp": self._cflash_cp,
            "cflash_swap": self._cflash_swap,
            "dflash_fee": self._dflash_fee,
            "dtcs": self._dtcs,
        }
        try:
            Path(path_str).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, tr("Ошибка сохранения", "Save error"), str(exc))
            return
        self.note.emit(tr(f"Данные 13 ACC Radar сохранены: {path_str}", f"13 ACC Radar data saved: {path_str}"))

    def action_extract_keys_from_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            tr("Открыть дамп Dflash.bin (64 КиБ) радара", "Open radar Dflash.bin (64 KiB) dump"),
            str(self.conn.out_dir),
            "Binary (*.bin *.raw);;All Files (*)",
        )
        if not path:
            return
        try:
            raw = Path(path).read_bytes()
            if len(raw) != MRR_DFLASH_SIZE:
                QMessageBox.warning(
                    self,
                    tr("Неверный размер файла", "Invalid file size"),
                    tr(
                        f"Ожидался дамп DFLASH0 размером 65536 байт (64 КиБ), получено {len(raw)} байт.",
                        f"Expected 65536-byte (64 KiB) DFLASH0 dump, got {len(raw)} bytes.",
                    ),
                )
                return
            fee = mrr_parse_dflash_fee(raw)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, tr("Ошибка разбора Dflash.bin", "Dflash.bin parse error"), str(exc))
            return

        self._dflash_fee = fee
        if fee.get("ika_hex"):
            self._ika_hex = str(fee["ika_hex"]).lower()
            self._draft_cur_ika = self._ika_hex.upper()
        if fee.get("gfa_hex"):
            self._gfa_hex = str(fee["gfa_hex"]).lower()
            self._draft_new_gfa = self._gfa_hex.upper()
        if fee.get("ecu_boot_sum_hex"):
            self._ecu_boot_sum_hex = str(fee["ecu_boot_sum_hex"]).lower()
        self.note.emit(
            tr(
                f"Извлечены ключи из {Path(path).name}: IKA={(self._ika_hex or '—').upper()}, GFA={(self._gfa_hex or '—').upper()}",
                f"Extracted keys from {Path(path).name}: IKA={(self._ika_hex or '—').upper()}, GFA={(self._gfa_hex or '—').upper()}",
            )
        )
        self.refresh()

    def action_fill_gfa_from_cluster(self) -> None:
        mat = None
        try:
            if self._cluster_provider is not None:
                src = self._cluster_provider()
                if src and src.get("dflash_bytes"):
                    mat = bcm_extract_cluster_ffb_material(src["dflash_bytes"], src.get("cflash_bytes"))
            if mat is None:
                path, _ = QFileDialog.getOpenFileName(
                    self,
                    tr(
                        "Выберите DataFlash (Dflash.bin / EelLogical.bin) панели приборов 17 FPK_E / Kombi",
                        "Select 17 FPK_E / Kombi cluster DataFlash (Dflash.bin / EelLogical.bin)",
                    ),
                    str(self.conn.out_dir),
                    "Binary (*.bin *.raw);;All Files (*)",
                )
                if not path:
                    return
                raw = Path(path).read_bytes()
                if not (is_kombi_dflash(raw) or is_fpke_dflash(raw)):
                    QMessageBox.warning(
                        self,
                        tr("Ошибка чтения дампа 17 FPK_E / Kombi", "17 FPK_E / Kombi dump error"),
                        tr(
                            "Выбранный файл не распознан как DataFlash панели приборов 17 FPK_E (64 КиБ) или 17 Kombi VDD (64 / 32 КиБ / EEL 9 533 / 8 334 Б).",
                            "The selected file is not a recognised 17 FPK_E (64 KiB) or 17 Kombi VDD (64 / 32 KiB / EEL 9,533 / 8,334 B) cluster DataFlash dump.",
                        ),
                    )
                    return
                mat = bcm_extract_cluster_ffb_material(raw)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, tr("Ошибка чтения дампа 17 FPK_E / Kombi", "17 FPK_E / Kombi dump error"), str(exc))
            return

        gfa_hex = str((mat or {}).get("gfa_hex") or "")
        if gfa_hex:
            self._draft_new_gfa = gfa_hex.upper()
            if hasattr(self, "ed_new_gfa") and _qt_valid(self.ed_new_gfa):
                self.ed_new_gfa.setText(self._draft_new_gfa)
            self.note.emit(
                tr(
                    f"Подставлен GFA из панели приборов 17: {self._draft_new_gfa}",
                    f"Loaded GFA from 17 cluster: {self._draft_new_gfa}",
                )
            )
        else:
            QMessageBox.information(
                self,
                "ContiTool",
                tr(
                    "В выбранном дампе панели приборов 17 не найден групповой ключ GFA (слот /1).",
                    "No vehicle group key GFA (slot /1) found in the selected 17 cluster dump.",
                ),
            )

    @staticmethod
    def _clean_hex_key16(raw_txt: str) -> tuple[bool, str]:
        cleaned = "".join(raw_txt.split()).replace("0x", "").replace("0X", "")
        if not cleaned:
            return True, ""
        ok = len(cleaned) == 32 and all(c in "0123456789abcdefABCDEF" for c in cleaned)
        return ok, cleaned.upper()

    def action_write_keys(self, *, include_ika: bool | None = None) -> None:
        if self.runner.is_busy or not ensure_ready(self.conn, self):
            return
        cur_ika_raw = (
            self.ed_cur_ika.text()
            if hasattr(self, "ed_cur_ika") and _qt_valid(self.ed_cur_ika)
            else (self._draft_cur_ika or "")
        ).strip()
        new_ika_raw = (
            self.ed_new_ika.text()
            if hasattr(self, "ed_new_ika") and _qt_valid(self.ed_new_ika)
            else self._draft_new_ika
        ).strip()
        new_gfa_raw = (
            self.ed_new_gfa.text()
            if hasattr(self, "ed_new_gfa") and _qt_valid(self.ed_new_gfa)
            else (self._draft_new_gfa or "")
        ).strip()

        cur_ok, cur_ika_txt = self._clean_hex_key16(cur_ika_raw)
        if not cur_ok:
            QMessageBox.warning(
                self,
                tr("Некорректный текущий IKA", "Invalid current IKA"),
                tr(
                    "Текущий IKA радара должен содержать ровно 32 hex-символа (16 байт) либо быть пустым.",
                    "Current radar IKA must be exactly 32 hex characters (16 bytes) or left blank.",
                ),
            )
            return

        new_ika_ok, new_ika_txt = self._clean_hex_key16(new_ika_raw)
        if include_ika is not False and not new_ika_ok:
            QMessageBox.warning(
                self,
                tr("Некорректный новый IKA", "Invalid new IKA"),
                tr(
                    "Новый IKA (DID 0x00BE) должен содержать ровно 32 hex-символа (16 байт).",
                    "New IKA (DID 0x00BE) must be exactly 32 hex characters (16 bytes).",
                ),
            )
            return

        new_gfa_ok, new_gfa_txt = self._clean_hex_key16(new_gfa_raw)
        if not new_gfa_ok:
            QMessageBox.warning(
                self,
                tr("Некорректный GFA", "Invalid GFA"),
                tr(
                    "Целевой групповой ключ GFA (DID 0x00BD) должен содержать ровно 32 hex-символа (16 байт).",
                    "Target vehicle group key GFA (DID 0x00BD) must be exactly 32 hex characters (16 bytes).",
                ),
            )
            return

        cur_ika = cur_ika_txt or None
        if include_ika is False:
            new_ika = None
            new_gfa = new_gfa_txt or None
            if not new_gfa:
                QMessageBox.warning(
                    self,
                    tr("GFA не указан", "GFA not specified"),
                    tr("Укажите целевой групповой ключ GFA (32 hex) для записи в DID 0x00BD.", "Enter the target vehicle group key GFA (32 hex) to write to DID 0x00BD."),
                )
                return
        elif include_ika is True:
            new_ika = new_ika_txt or None
            new_gfa = new_gfa_txt or None
            if not new_ika:
                QMessageBox.warning(
                    self,
                    tr("Новый IKA не указан", "New IKA not specified"),
                    tr("Укажите новый 16-байтный IKA (32 hex) для записи в DID 0x00BE.", "Enter a new 16-byte IKA (32 hex) to write to DID 0x00BE."),
                )
                return
        else:
            new_ika = new_ika_txt or None
            new_gfa = new_gfa_txt or None
            if not new_ika and not new_gfa:
                QMessageBox.warning(
                    self,
                    tr("Ключи не указаны", "No keys specified"),
                    tr("Укажите новый IKA (00BE) и/или групповой ключ GFA (00BD) для записи.", "Enter a new IKA (00BE) and/or vehicle group key GFA (00BD) to write."),
                )
                return

        if cur_ika is None and not self._xcp_available():
            QMessageBox.warning(
                self,
                tr("Требуется текущий IKA", "Current IKA required"),
                tr(
                    "Без XCP / RAM-моста программа не может автоматически считать текущий IKA радара. "
                    "Укажите текущий IKA (32 hex) вручную.",
                    "Without XCP / RAM-Bridge, ContiTool cannot auto-read the radar's current IKA. "
                    "Please enter the current IKA (32 hex) manually.",
                ),
            )
            return

        if new_ika and not new_gfa:
            ans = QMessageBox.warning(
                self,
                tr("GFA не указан", "GFA not specified"),
                tr(
                    "Запись нового IKA (2E 00BE) без GFA сотрёт текущий GFA радара в FF×16 (активируется CP). "
                    "Рекомендуется указать GFA автомобиля сразу.\n\nПродолжить и записать только IKA?",
                    "Writing a new IKA (2E 00BE) without GFA clears the radar's GFA to FF×16 (CP becomes active). "
                    "Entering the vehicle GFA is recommended.\n\nContinue and write IKA only?",
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        if new_ika and new_gfa:
            confirm_body = tr(
                f"Записать новый IKA (2E 00BE) и групповой ключ GFA (2E 00BD) в NvM радара 13 ACC?\n\n"
                f"Новый IKA: {new_ika}\nНовый GFA: {new_gfa}\n\n"
                "Запись 00BE изменяет активный ключ шифрования радара — обязательно сохраните новый IKA!",
                f"Write new IKA (2E 00BE) and group key GFA (2E 00BD) to 13 ACC Radar NvM?\n\n"
                f"New IKA: {new_ika}\nNew GFA: {new_gfa}\n\n"
                "Writing 00BE changes the radar's active encryption key — make sure you save the new IKA!",
            )
        elif new_ika:
            confirm_body = tr(
                f"Записать новый IKA (2E 00BE) в NvM радара 13 ACC?\n\nНовый IKA: {new_ika}\n"
                "Внимание: GFA будет очищен в FF×16!",
                f"Write new IKA (2E 00BE) to 13 ACC Radar NvM?\n\nNew IKA: {new_ika}\n"
                "Warning: GFA will be cleared to FF×16!",
            )
        else:
            confirm_body = tr(
                f"Записать групповой ключ GFA (2E 00BD) в NvM радара 13 ACC?\n\nНовый GFA: {new_gfa}",
                f"Write group key GFA (2E 00BD) to 13 ACC Radar NvM?\n\nNew GFA: {new_gfa}",
            )
        if (
            QMessageBox.question(
                self,
                tr("Подтверждение записи в 13 ACC Radar", "Confirm 13 ACC Radar NvM Write"),
                confirm_body,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return

        port, iface, via_gw, gw_br, gw_ch, sw_prof = self._snapshot_routing()
        do_rst = self._draft_write_reset
        gen = self._session_gen

        self.runner.run_task(
            tr("Запись IKA / GFA в 13 ACC Radar", "Writing IKA / GFA to 13 ACC Radar"),
            lambda rep: can_mrr_write_keys(
                port,
                current_ika=cur_ika,
                new_ika=new_ika,
                new_gfa=new_gfa,
                reset_after=do_rst,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                sw_profile=sw_prof,
                reporter=rep,
            ),
            on_success=lambda res, g=gen: self._on_keys_written(res, expected_gen=g),
        )

    def _on_keys_written(self, res: dict[str, Any], *, expected_gen: int | None = None) -> None:
        if not self._callback_valid(expected_gen):
            return
        if isinstance(res.get("dflash_fee"), dict) and res["dflash_fee"]:
            self._dflash_fee = dict(res["dflash_fee"])
        status_after = res.get("status_after") if isinstance(res.get("status_after"), dict) else {}
        if status_after:
            self._status = dict(status_after)
        if res.get("active_ika_hex"):
            self._ika_hex = str(res["active_ika_hex"]).lower()
            self._draft_cur_ika = self._ika_hex.upper()
            if res.get("ika_written"):
                self._draft_new_ika = ""
            if self._dflash_fee:
                self._dflash_fee["ika_hex"] = self._ika_hex
                if "ika_virgin" in status_after:
                    self._dflash_fee["ika_virgin"] = bool(status_after["ika_virgin"])
                elif res.get("ika_written"):
                    self._dflash_fee["ika_virgin"] = False
        if res.get("active_gfa_hex"):
            self._gfa_hex = str(res["active_gfa_hex"]).lower()
            self._draft_new_gfa = self._gfa_hex.upper()
            if self._dflash_fee:
                self._dflash_fee["gfa_hex"] = self._gfa_hex
                self._dflash_fee["gfa_learned"] = True
        elif res.get("gfa_cleared"):
            self._gfa_hex = ""
            self._draft_new_gfa = ""
            if self._dflash_fee:
                self._dflash_fee["gfa_hex"] = ""
                self._dflash_fee["gfa_learned"] = False
        if res.get("dtcs") is not None:
            self._dtcs = list(res.get("dtcs") or [])
        self.note.emit(
            tr(
                "Ключи IKA / GFA записаны в 13 ACC Radar.",
                "IKA / GFA keys written to 13 ACC Radar.",
            )
        )
        self.refresh()
        self.changed.emit()

    def action_reset_cp_counter(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface, via_gw, gw_br, gw_ch, sw_prof = self._snapshot_routing()
        gen = self._session_gen
        self.runner.run_task(
            tr("Сброс счётчика CP (03DE → 0) и ошибок DTC", "Resetting CP counter (03DE → 0) & clearing DTCs"),
            lambda rep: can_mrr_reset_cp_counter(
                port,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                sw_profile=sw_prof,
                reporter=rep,
            ),
            on_success=lambda res, g=gen: self._on_cp_counter_reset(res, expected_gen=g),
        )

    def _on_cp_counter_reset(self, res: dict[str, Any], *, expected_gen: int | None = None) -> None:
        if not self._callback_valid(expected_gen):
            return
        if isinstance(res.get("status_after"), dict) and res["status_after"]:
            self._status = dict(res["status_after"])
        if res.get("dtcs") is not None:
            self._dtcs = list(res.get("dtcs") or [])
        self.refresh()
        self.changed.emit()

    def action_deactivate_cp(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        if not run_dialog(
            MrrFlashCpDialog(
                restore_stock=False,
                profile=self._profile,
                part_number=self.part_number,
                session_dir=None,
                via_gateway=self._via_gateway,
                parent=self,
            )
        ):
            return
        s_dir = self._mrr_session_dir("mrr_cp_off", dumps=False)
        if s_dir is None:
            return
        port, iface, via_gw, gw_br, gw_ch, sw_prof = self._snapshot_routing()
        gen = self._session_gen
        self.runner.run_task(
            tr("Деактивация CP в 13 ACC Radar", "Deactivating CP on 13 ACC Radar"),
            lambda rep: can_mrr_deactivate_cp(
                port,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                sw_profile=sw_prof,
                session_dir=s_dir,
                reporter=rep,
            ),
            on_success=lambda res, g=gen: self._on_cp_flashed(res, expected_gen=g),
        )

    def action_restore_cp_stock(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        if not run_dialog(
            MrrFlashCpDialog(
                restore_stock=True,
                profile=self._profile,
                part_number=self.part_number,
                session_dir=None,
                via_gateway=self._via_gateway,
                parent=self,
            )
        ):
            return
        s_dir = self._mrr_session_dir("mrr_cp_restore", dumps=False)
        if s_dir is None:
            return
        port, iface, via_gw, gw_br, gw_ch, sw_prof = self._snapshot_routing()
        gen = self._session_gen
        self.runner.run_task(
            tr("Восстановление заводского CP в 13 ACC Radar", "Restoring stock CP on 13 ACC Radar"),
            lambda rep: can_mrr_restore_cp_stock(
                port,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                sw_profile=sw_prof,
                session_dir=s_dir,
                reporter=rep,
            ),
            on_success=lambda res, g=gen: self._on_cp_flashed(res, expected_gen=g),
        )

    def _on_cp_flashed(self, res: dict[str, Any], *, expected_gen: int | None = None) -> None:
        if not self._callback_valid(expected_gen):
            return
        if isinstance(res.get("status_after"), dict) and res["status_after"]:
            self._status = dict(res["status_after"])
        if isinstance(res.get("cflash_cp"), dict) and res["cflash_cp"]:
            self._cflash_cp = dict(res["cflash_cp"])
        if res.get("dtcs") is not None:
            self._dtcs = list(res.get("dtcs") or [])
        self.refresh()
        self.changed.emit()

    def action_activate_swap(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        pkg_idx = int(self._draft_swap_gen1_pkg)
        grp_tup = (
            int(self._draft_swap_gen2_groups[0]),
            int(self._draft_swap_gen2_groups[1]),
            int(self._draft_swap_gen2_groups[2]),
            int(self._draft_swap_gen2_groups[3]),
        )
        if not run_dialog(
            MrrFlashSwapDialog(
                restore_stock=False,
                profile=self._profile,
                part_number=self.part_number,
                session_dir=None,
                package_index=pkg_idx,
                groups=grp_tup,
                via_gateway=self._via_gateway,
                parent=self,
            )
        ):
            return
        s_dir = self._mrr_session_dir("mrr_swap_on", dumps=False)
        if s_dir is None:
            return
        port, iface, via_gw, gw_br, gw_ch, sw_prof = self._snapshot_routing()
        gen = self._session_gen
        self.runner.run_task(
            tr("Активация функций SWaP / FSC в 13 ACC Radar", "Activating SWaP / FSC features on 13 ACC Radar"),
            lambda rep: can_mrr_activate_swap(
                port,
                package_index=pkg_idx,
                groups=grp_tup,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                sw_profile=sw_prof,
                session_dir=s_dir,
                reporter=rep,
            ),
            on_success=lambda res, g=gen: self._on_swap_flashed(res, expected_gen=g),
        )

    def action_restore_swap_stock(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        if not run_dialog(
            MrrFlashSwapDialog(
                restore_stock=True,
                profile=self._profile,
                part_number=self.part_number,
                session_dir=None,
                via_gateway=self._via_gateway,
                parent=self,
            )
        ):
            return
        s_dir = self._mrr_session_dir("mrr_swap_restore", dumps=False)
        if s_dir is None:
            return
        port, iface, via_gw, gw_br, gw_ch, sw_prof = self._snapshot_routing()
        gen = self._session_gen
        self.runner.run_task(
            tr("Восстановление заводского SWaP / FSC в 13 ACC Radar", "Restoring stock SWaP / FSC on 13 ACC Radar"),
            lambda rep: can_mrr_restore_swap_stock(
                port,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                sw_profile=sw_prof,
                session_dir=s_dir,
                reporter=rep,
            ),
            on_success=lambda res, g=gen: self._on_swap_flashed(res, expected_gen=g),
        )

    def _on_swap_flashed(self, res: dict[str, Any], *, expected_gen: int | None = None) -> None:
        if not self._callback_valid(expected_gen):
            return
        if isinstance(res.get("status_after"), dict) and res["status_after"]:
            self._status = dict(res["status_after"])
        if isinstance(res.get("cflash_swap"), dict) and res["cflash_swap"]:
            self._cflash_swap = dict(res["cflash_swap"])
        if isinstance(res.get("swap_uds"), dict) and res["swap_uds"]:
            self._swap_uds = dict(res["swap_uds"])
        if res.get("dtcs") is not None:
            self._dtcs = list(res.get("dtcs") or [])
        self.refresh()
        self.changed.emit()

    def action_read_memory(self, region: str) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface, via_gw, gw_br, gw_ch, sw_prof = self._snapshot_routing()
        s_dir = self._mrr_session_dir(f"mrr_{region}", dumps=True)
        if s_dir is None:
            return
        gen = self._session_gen
        self.runner.run_task(
            tr(f"Чтение памяти 13 ACC Radar ({region})", f"Reading 13 ACC Radar memory ({region})"),
            lambda rep: can_mrr_read_memory(
                port,
                region=region,
                fast=True,
                interface=iface,
                via_gateway=via_gw,
                gateway_bridge=gw_br,
                gateway_channel=gw_ch,
                sw_profile=sw_prof,
                session_dir=s_dir,
                reporter=rep,
            ),
            on_success=lambda res, g=gen: self._on_memory_read(res, expected_gen=g),
        )

    def _on_memory_read(self, res: dict[str, Any], *, expected_gen: int | None = None) -> None:
        if not self._callback_valid(expected_gen):
            return
        self._last_mem_report = dict(res)
        if isinstance(res.get("passport"), dict) and res["passport"]:
            self._passport = dict(res["passport"])
            self._offline_mode = False
        fee = res.get("dflash_fee")
        if isinstance(fee, dict):
            self._apply_dflash_fee(fee)
        if isinstance(res.get("cflash_cp"), dict) and res["cflash_cp"]:
            self._cflash_cp = dict(res["cflash_cp"])
        if isinstance(res.get("cflash_swap"), dict) and res["cflash_swap"]:
            self._cflash_swap = dict(res["cflash_swap"])
        s_dir = res.get("session_dir")
        if s_dir:
            p_dir = Path(str(s_dir))
            if p_dir.is_dir():
                _remember_recent(p_dir)
            self.note.emit(tr(f"Дамп сохранён в: {s_dir}", f"Dump saved to: {s_dir}"))
        self.refresh()
        self.changed.emit()

    def _on_frf_recovery_toggled(self, checked: bool) -> None:
        self._frf_recovery_mode = bool(checked)
        if self._key == "memory":
            self._render_page()

    def load_frf_file(self, path: Path) -> MrrFrfImage:
        """Load, decrypt, and validate an MRR `.frf` or `.odx`/`.odx-f` container into screen state."""
        img = mrr_read_frf(path.read_bytes(), path.name)
        self._selected_frf = img
        self._selected_frf_path = path
        self.refresh()
        return img

    def action_choose_frf(self) -> bool:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            tr("Выбрать заводскую прошивку радара 13 ACC (.frf / .odx)", "Select 13 ACC Radar firmware (.frf / .odx)"),
            str(self._selected_frf_path.parent) if self._selected_frf_path else "",
            tr("Файлы прошивок ODIS (*.frf *.odx *.odx-f);;Все файлы (*)", "ODIS Flash Containers (*.frf *.odx *.odx-f);;All Files (*)"),
        )
        if not path_str:
            return False
        path = Path(path_str)
        try:
            img = self.load_frf_file(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self,
                tr("Не удалось открыть FRF / ODX", "Could not open FRF / ODX"),
                str(exc),
            )
            return False
        self.note.emit(
            tr(
                f"Выбран {img.kind}: {img.part_number} · ПО {img.sw_version} ({img.mcu}, RSA-1024 OK)",
                f"Selected {img.kind}: {img.part_number} · SW {img.sw_version} ({img.mcu}, RSA-1024 OK)",
            )
        )
        return True

    def action_clear_frf(self) -> None:
        self._selected_frf = None
        self._selected_frf_path = None
        self.refresh()

    def action_flash_frf(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        if self._selected_frf is None:
            if not self.action_choose_frf() or self._selected_frf is None:
                return
        frf = self._selected_frf
        recovery = bool(self._frf_recovery_mode)
        hard_errs, soft_warns = mrr_frf_compatibility(frf, self._passport, recovery_mode=recovery)
        if hard_errs:
            QMessageBox.critical(
                self,
                tr("Прошивка несовместима", "Incompatible Firmware"),
                "\n".join(hard_errs),
            )
            return
        if not run_dialog(
            MrrFlashFrfDialog(
                frf=frf,
                part_number=self.part_number,
                current_sw=str(self._passport.get("sw_version") or ""),
                warnings=soft_warns,
                recovery_mode=recovery,
                via_gateway=self._via_gateway,
                parent=self,
            )
        ):
            return
        s_dir = self._mrr_session_dir("mrr_frf", dumps=False)
        if s_dir is None:
            return
        port, iface, via_gw, _gw_br, _gw_ch, sw_prof = self._snapshot_routing()
        allow_mis = bool(soft_warns)
        gen = self._session_gen
        self.runner.run_task(
            tr(
                f"Прошивка {frf.part_number} {frf.sw_version} ({frf.kind}) в 13 ACC Radar",
                f"Flashing {frf.part_number} {frf.sw_version} ({frf.kind}) to 13 ACC Radar",
            ),
            lambda rep: can_mrr_flash_frf(
                port,
                frf,
                allow_mismatch=allow_mis,
                recovery_mode=recovery,
                interface=iface,
                via_gateway=via_gw,
                sw_profile=sw_prof,
                session_dir=s_dir,
                reporter=rep,
            ),
            on_success=lambda res, g=gen: self._on_frf_flashed(res, expected_gen=g),
        )

    def _on_frf_flashed(self, res: dict[str, Any], *, expected_gen: int | None = None) -> None:
        if not self._callback_valid(expected_gen):
            return
        self._last_frf_report = dict(res)
        self._profile_override = ""
        if isinstance(res.get("passport_after"), dict) and res["passport_after"]:
            self._passport = dict(res["passport_after"])
            self._profile = mrr_detect_profile(self._passport)
            self._offline_mode = False
        if isinstance(res.get("status_after"), dict) and res["status_after"]:
            self._status = dict(res["status_after"])
        if isinstance(res.get("swap_uds"), dict) and res["swap_uds"]:
            self._swap_uds = dict(res["swap_uds"])
        if res.get("dtcs") is not None:
            self._dtcs = list(res.get("dtcs") or [])
        # Flashing a stock FRF replaces Code Flash application, invalidating cached patch inspections.
        self._cflash_cp = {}
        self._cflash_swap = {}
        new_sw = self._passport.get("sw_version") or (res.get("frf") or {}).get("sw_version") or "—"
        self.note.emit(
            tr(
                f"Заводской FRF успешно прошит: {self.part_number} · ПО {new_sw}",
                f"Factory FRF flashed successfully: {self.part_number} · SW {new_sw}",
            )
        )
        self.refresh()
        self.changed.emit()

    def action_read_dtc(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface, via_gw, _gw_br, _gw_ch, _sw_prof = self._snapshot_routing()
        gen = self._session_gen
        self.runner.run_task(
            tr("Чтение ошибок DTC (13 ACC Radar)", "Reading DTCs (13 ACC Radar)"),
            lambda rep: can_uds_read_dtc(
                port,
                MRR_UDS_TX_ID,
                MRR_UDS_RX_ID,
                interface=iface,
                ecu_kind="mrr",
                via_gateway=via_gw,
                reporter=rep,
            ),
            on_success=lambda res, g=gen: self._on_dtc_read(res, expected_gen=g),
        )

    def action_clear_dtc(self) -> None:
        if not ensure_ready(self.conn, self):
            return
        port, iface, via_gw, _gw_br, _gw_ch, _sw_prof = self._snapshot_routing()
        gen = self._session_gen

        def task(rep: Any) -> dict[str, Any]:
            can_uds_clear_dtc(
                port,
                MRR_UDS_TX_ID,
                MRR_UDS_RX_ID,
                interface=iface,
                ecu_kind="mrr",
                via_gateway=via_gw,
                reporter=rep,
            )
            return can_uds_read_dtc(
                port,
                MRR_UDS_TX_ID,
                MRR_UDS_RX_ID,
                interface=iface,
                ecu_kind="mrr",
                via_gateway=via_gw,
                reporter=rep,
            )

        self.runner.run_task(
            tr("Сброс и перепроверка ошибок DTC (13 ACC Radar)", "Clearing & re-reading DTCs (13 ACC Radar)"),
            task,
            on_success=lambda res, g=gen: self._on_dtc_read(res, expected_gen=g),
        )

    def _on_dtc_read(self, res: dict[str, Any], *, expected_gen: int | None = None) -> None:
        if not self._callback_valid(expected_gen):
            return
        self._dtcs = list(res.get("dtcs") or [])
        self.refresh()

    def _copy_dtcs_text(self) -> None:
        if not self._dtcs:
            return
        lines = [f"13 ACC Radar — {self.part_number}"]
        for d in self._dtcs:
            tag = tr("Активна", "Active") if d.get("active") else tr("В памяти", "Stored")
            lines.append(f"[{tag}] {d.get('display')} ({d.get('code')}, {d.get('status')}) — {d.get('description')}")
        self._copy_text("\n".join(lines), tr("список DTC", "DTC list"))
