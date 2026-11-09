"""Terminal formatting, Unicode report renderers, and real-time CLI progress display."""

from __future__ import annotations

import os
import re
import sys
import time
from typing import TextIO

from contitool import __version__
from contitool.core.analyzer import (
    CflashSummary,
    DflashDatasetSummary,
    DflashSwapSummary,
    SlotState,
    UflashSummary,
    check_fec_dataset_support,
)
from contitool.core.constants import (
    AUTHOR_CREDIT,
    AUTHOR_DRIVE2_URL,
    AUTHOR_SITE_URL,
    AUTHOR_TG_URL,
    KNOWN_GATEWAY_FECS,
    MASTER_SLOT,
    SLAVE_SLOTS,
    STOCK_FBL_MODULUS,
    STOCK_SWAP_MODULUS,
    T20_BENCH_PINS,
)
from contitool.i18n import get_lang, tr
from contitool.progress import LogEntry, OperationReporter, ProgressSnapshot, StepSnapshot

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def visible_len(text: str) -> str | int:
    return len(strip_ansi(text))


def pad_ansi(text: str, width: int, align: str = "left") -> str:
    pad = max(0, width - len(strip_ansi(text)))
    if align == "right":
        return (" " * pad) + text
    if align == "center":
        left = pad // 2
        return (" " * left) + text + (" " * (pad - left))
    return text + (" " * pad)


class Style:
    """Lightweight ANSI color helper with clean plain-text fallback."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        if enabled and os.name == "nt":
            os.system("")

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def magenta(self, text: str) -> str:
        return self._wrap("35", text)

    def badge_ok(self, text: str) -> str:
        return self._wrap("1;32", f"✓ {text}")

    def badge_warn(self, text: str) -> str:
        return self._wrap("1;33", f"⚠ {text}")

    def badge_err(self, text: str) -> str:
        return self._wrap("1;31", f"✗ {text}")


def format_bytes_human(num_bytes: int | float) -> str:
    val = float(num_bytes)
    if val >= 1024 * 1024:
        return f"{val / (1024 * 1024):.2f} MB"
    if val >= 1024:
        return f"{val / 1024:.1f} KB"
    return f"{int(val)} B"


def format_eta(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "--:--"
    sec = int(round(seconds))
    mins, rem = divmod(sec, 60)
    if mins >= 60:
        hrs, mins = divmod(mins, 60)
        return f"{hrs:d}:{mins:02d}:{rem:02d}"
    return f"{mins:02d}:{rem:02d}"


class CliProgressDisplay:
    """Real-time terminal observer that renders step headers, logs, and a live progress bar."""

    def __init__(self, stream: TextIO | None = None, *, color: bool | None = None) -> None:
        self.stream = stream or sys.stderr
        is_tty = hasattr(self.stream, "isatty") and self.stream.isatty()
        if color is None:
            color = is_tty and ("NO_COLOR" not in os.environ)
        self.is_tty = is_tty
        self.style = Style(bool(color))
        self._bar_visible = False
        self._last_non_tty_pct = -10

    def _clear_bar_line(self) -> None:
        if self._bar_visible and self.is_tty:
            self.stream.write("\r\033[2K")
            self.stream.flush()
            self._bar_visible = False

    def on_step(self, snap: StepSnapshot) -> None:
        self._clear_bar_line()
        self._last_non_tty_pct = -10
        prefix = self.style.cyan(f"[{snap.index}/{snap.total}]")
        self.stream.write(f"\n{prefix} {self.style.bold(snap.title)}\n")
        self.stream.flush()

    def on_log(self, entry: LogEntry) -> None:
        if entry.level == "step":
            return
        self._clear_bar_line()
        ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
        st = self.style
        tag_map = {
            "info": st.cyan("INFO"),
            "success": st.green(" OK "),
            "warning": st.yellow("WARN"),
            "error": st.red("ERR "),
            "can": st.magenta("CAN "),
        }
        tag = tag_map.get(entry.level, st.dim("LOG "))
        self.stream.write(f"  {st.dim(ts)} [{tag}] {entry.message}\n")
        self.stream.flush()

    def on_progress(self, snap: ProgressSnapshot) -> None:
        pct = snap.percent
        if not self.is_tty:
            bucket = int(pct // 20) * 20
            if bucket > self._last_non_tty_pct and (bucket > 0 or pct >= 100.0):
                self._last_non_tty_pct = bucket
                self.stream.write(f"  ... {pct:5.1f}% ({snap.current:,}/{snap.total:,} {snap.unit})\n")
                self.stream.flush()
            return

        bar_w = 24
        filled = int(round((pct / 100.0) * bar_w))
        filled = max(0, min(bar_w, filled))
        bar = "█" * filled + "░" * (bar_w - filled)
        parts = [f"[{self.style.cyan(bar)}] {self.style.bold(f'{pct:5.1f}%')}"]
        if snap.unit in ("B", "bytes", "Б"):
            parts.append(f"{format_bytes_human(snap.current)} / {format_bytes_human(snap.total)}")
        elif snap.total > 1:
            parts.append(f"{snap.current}/{snap.total}")
        if snap.speed_bps > 0:
            parts.append(f"{snap.speed_bps / 1024.0:.1f} KB/s")
        if snap.eta_sec is not None:
            parts.append(f"ETA {format_eta(snap.eta_sec)}")
        if snap.detail:
            parts.append(self.style.dim(snap.detail[:34]))
        line = "  " + " • ".join(parts)
        self.stream.write("\r\033[2K" + line)
        self.stream.flush()
        self._bar_visible = True
        if pct >= 100.0:
            self.stream.write("\n")
            self.stream.flush()
            self._bar_visible = False

    def finish(self) -> None:
        if self._bar_visible and self.is_tty:
            self.stream.write("\n")
            self.stream.flush()
            self._bar_visible = False

    def create_reporter(self) -> OperationReporter:
        return OperationReporter(
            on_step=self.on_step,
            on_progress=self.on_progress,
            on_log=self.on_log,
        )


def format_startup_banner(style: Style) -> str:
    w = 96
    top = "╔" + ("═" * (w - 2)) + "╗"
    sep = "╟" + ("─" * (w - 2)) + "╢"
    bot = "╚" + ("═" * (w - 2)) + "╝"

    def _row(txt: str, align: str = "center") -> str:
        return f"║ {pad_ansi(txt, w - 4, align)} ║"

    lines = [
        style.cyan(top),
        _row(style.bold(f"ContiTool v{__version__} — Continental VAG MQB Gateway J533 (RH850/F1L)")),
        _row(f"{style.cyan(AUTHOR_CREDIT)}  •  {AUTHOR_SITE_URL}  •  {AUTHOR_TG_URL}"),
        style.cyan(sep),
        _row(
            style.yellow(
                tr(
                    "БЕСПЛАТНЫЙ ИНСТРУМЕНТ СООБЩЕСТВА — СТРОГО НЕ ДЛЯ ПРОДАЖИ! (FREE • NOT FOR SALE)",
                    "FREE COMMUNITY RESEARCH TOOL — STRICTLY NOT FOR SALE!",
                )
            )
        ),
        _row(
            style.dim(
                tr(
                    "Предоставляется «КАК ЕСТЬ» (AS IS) без каких-либо гарантий. Всегда сохраняйте бэкап дампов!",
                    "Provided 'AS IS' without warranty of any kind. Always keep a verified full backup!",
                )
            )
        ),
        _row(
            style.dim(
                tr(
                    "Не знаете, зачем это вам, или сомневаетесь в адаптере — не пользуйтесь. Лучше блок на столе.",
                    "If you do not know why you need it or doubt your adapter, do not use it. Bench, not car.",
                )
            )
        ),
        _row(
            style.dim(
                tr(
                    "В машине — на свой риск, автор не отвечает. Проблемы — в GitHub Issues, не в личку.",
                    "In a car it is at your own risk. Problems go to GitHub Issues, not to the author's DMs.",
                )
            )
        ),
        style.cyan(bot),
    ]
    return "\n".join(lines)


def _rsa_label(mod: bytes, stock_mod: bytes) -> str:
    if not mod or len(mod) != 128:
        return "—"
    if mod == stock_mod:
        return f"STOCK VAG ({mod[:6].hex().upper()}…)"
    return f"CUSTOM ({mod[:8].hex().upper()}…)"


def format_cflash_report(summary: CflashSummary, style: Style | None = None, path_label: str = "") -> str:
    st = style or Style(False)
    crc_badge = (
        st.badge_ok(f"0x{summary.crc_stored:04X} == 0x{summary.crc_calc:04X}")
        if summary.crc_ok
        else st.badge_err(f"0x{summary.crc_stored:04X} != 0x{summary.crc_calc:04X}")
        if summary.crc_range_count
        else st.badge_err(tr("нет таблицы CRC — приложение стёрто (блок в загрузчике) или повреждено",
                             "no CRC table — application erased (unit in its bootloader) or damaged"))
    )
    cp_map = {
        "STOCK": st.dim(tr("STOCK (штатный KSCHUTZ 0x40)", "STOCK (factory KSCHUTZ 0x40)")),
        "HYBRID": st.badge_ok(tr("HYBRID (гибридный трамплин CP)", "HYBRID (selective CP trampoline)")),
        "GLOBAL_PLAIN": st.badge_warn(tr("GLOBAL_PLAIN (стендовый 0x10)", "GLOBAL_PLAIN (bench 0x10)")),
    }
    hook_loc = f" @ 0x{summary.hook_vaddr:06X}" if summary.hook_vaddr is not None else ""
    cp_str = cp_map.get(summary.hook_mode, st.yellow(summary.hook_mode)) + hook_loc

    mask_str = (
        st.badge_ok(tr("ОТКЛЮЧЕНА (дооснащение в пустые банки разрешено)", "BYPASSED (empty-bank retrofit enabled)"))
        if summary.mask_bypassed
        else st.dim(tr("ШТАТНАЯ (проверка маски 95640 активна)", "STOCK (95640 mask check active)"))
    )
    eng_unlocked_all = (
        summary.eng_gate_unlocked and summary.ccp_blacklist_bypassed and summary.a167_branch_bypassed
    )
    eng_str = (
        st.badge_ok(tr("АКТИВЕН (Feature 0x80/81/83 + CCP + RAM-Loader)", "UNLOCKED (Feature 0x80/81/83 + CCP + RAM-Loader)"))
        if eng_unlocked_all
        else st.dim(tr("ЗАКРЫТ (заводской серийный режим)", "STOCK (factory locked)"))
    )

    lines = [
        st.bold(tr("═══ CodeFlash / Прошивка приложения ═══", "═══ CodeFlash / Application Firmware ═══")),
    ]
    if path_label:
        lines.append(f"  {tr('Файл', 'File')}:              {path_label}")
    lines.extend(
        [
            f"  {tr('Номер блока / HW', 'Part Number / HW')}:  {st.bold(summary.hw_pn or '—')}  ({summary.hw_ver or '—'})",
            f"  FAZIT:             {summary.fazit or '—'}",
            f"  SHA-256:           {summary.sha256[:24]}…",
            f"  App CRC-16:        {crc_badge}",
            f"  {tr('Режим CP (KSCHUTZ)', 'CP Mode (KSCHUTZ)')}: {cp_str}",
            f"  {tr('Маска 95640 EEPROM', '95640 EEPROM Mask')}: {mask_str}",
            f"  {tr('Инженерный режим', 'Engineering Mode')}:  {eng_str}",
            f"  SWaP RSA-1024:     {_rsa_label(summary.swap_rsa_mod, STOCK_SWAP_MODULUS)}",
            f"  FBL ODX RSA-1024:  {_rsa_label(summary.fbl_rsa_mod, STOCK_FBL_MODULUS)}",
        ]
    )
    return "\n".join(lines)


def format_uflash_report(summary: UflashSummary, style: Style | None = None, path_label: str = "") -> str:
    st = style or Style(False)
    rsa_str = (
        st.badge_ok(tr("ИНЖЕНЕРНЫЙ RSA-FREE FBL (+0x342A пропатчен)", "ENGINEERING RSA-FREE FBL (+0x342A patched)"))
        if summary.rsa_bypassed
        else st.dim(tr("ЗАВОДСКАЯ ПРОВЕРКА RSA-1024 АКТИВНА", "STOCK RSA-1024 CHECK ACTIVE"))
    )
    lines = [
        st.bold(tr("═══ Загрузчик Uflash (32 КБ @ 0x01000000) ═══", "═══ Uflash Bootloader (32 KB @ 0x01000000) ═══")),
    ]
    if path_label:
        lines.append(f"  {tr('Файл', 'File')}:          {path_label}")
    lines.extend(
        [
            f"  {tr('Сигнатура FBL', 'FBL Signature')}: {st.badge_ok('OK') if summary.signature_found else st.badge_warn('CUSTOM')}",
            f"  {tr('Статус RSA', 'RSA Status')}:    {rsa_str}",
            f"  SHA-256:       {summary.sha256}",
        ]
    )
    return "\n".join(lines)


def format_dflash_report(
    slots: list[SlotState],
    swap_summary: DflashSwapSummary | None = None,
    style: Style | None = None,
    path_label: str = "",
    dataset_summary: DflashDatasetSummary | None = None,
) -> str:
    st = style or Style(False)
    lines = [
        st.bold(
            tr(
                "═══ DataFlash (64 КБ) — 12 банков Component Protection + Master #0 ═══",
                "═══ DataFlash (64 KB) — 12 Component Protection Banks + Master #0 ═══",
            )
        ),
    ]
    if path_label:
        lines.append(f"  {tr('Файл', 'File')}: {path_label}")
    header = (
        f"  {'#':>2}  {'VAG':<4}  {'Offset':<8}  {tr('Статус', 'State'):<14}  "
        f"{'CRC-32':<10}  {tr('Ключ (16 Б) / Заголовок', 'Key (16 B) / Header'):<34}  {tr('Блок VAG', 'VAG ECU')}"
    )
    lines.append(st.dim(header))
    lines.append("  " + ("─" * 106))

    for s in slots:
        spec = s.spec
        ecu = spec.ecu_addr
        name = spec.short
        if s.kind == "PLAIN":
            st_col = st.green(pad_ansi("PLAIN (IKA)", 14))
        elif s.kind == "SHE":
            st_col = st.cyan(pad_ansi(tr("SHE (Завод)", "SHE (Stock)"), 14))
        elif s.kind == "EMPTY":
            st_col = st.dim(pad_ansi("EMPTY (FF)", 14))
        else:
            st_col = st.yellow(pad_ansi(s.kind[:14], 14))

        crc_col = (
            st.dim("    —     ")
            if s.empty
            else (st.green(f"0x{s.crc_stored:08X}") if s.crc_ok else st.red(f"0x{s.crc_stored:08X}!"))
        )
        key_preview = s.first16_hex.upper() if not s.empty else ("—" * 16)
        lines.append(
            f"  {spec.slot:>2}  {ecu:<4}  0x{spec.off1:04X}    {st_col}  "
            f"{pad_ansi(crc_col, 10)}  {key_preview:<34}  {name}"
        )

    if dataset_summary is not None:
        lines.append("")
        lines.append(
            st.bold(
                tr(
                    "═══ Параметризация ZDC (0x0000..0x303F) и совместимость FeC ═══",
                    "═══ ZDC Parameterization (0x0000..0x303F) & FeC Compatibility ═══",
                )
            )
        )
        valid_cnt = sum(1 for b in dataset_summary.blocks if b.crc_ok)
        pn_str = dataset_summary.dataset_pn or "—"
        ver_str = f" ({dataset_summary.dataset_ver})" if dataset_summary.dataset_ver else ""
        tag_str = f" [{dataset_summary.maingw_tag}]" if dataset_summary.maingw_tag else ""
        lines.append(f"  {tr('Датасет (F1A0/F1A1)', 'Dataset (F1A0/F1A1)')}: {pn_str}{ver_str}{tag_str}")
        lines.append(
            f"  {tr('Блоки ZDC CRC OK', 'Valid ZDC Blocks')}:   {valid_cnt} / {len(dataset_summary.blocks)}"
        )
        sup_hex = ", ".join(f"0x{c:08X}" for c in dataset_summary.supported_fecs) or "—"
        lines.append(f"  {tr('Поддерживаемые FeC', 'Supported FeCs')}:   {sup_hex}")
        for blk in dataset_summary.blocks:
            bst = (
                st.dim("EMPTY")
                if blk.empty
                else (
                    st.green(f"OK {('[' + blk.version_tag + '] ') if blk.version_tag else ''}0x{blk.crc_stored:08X}")
                    if blk.crc_ok
                    else st.red(f"ERR 0x{blk.crc_stored:08X}")
                )
            )
            lines.append(f"    • ZDC #{blk.idx} @ 0x{blk.offset:04X} ({blk.size:>4} B)  {pad_ansi(bst, 24)}  {blk.label}")

    if swap_summary is not None:
        lines.append("")
        lines.append(
            st.bold(
                tr(
                    "═══ SWaP / FeC и идентификаторы в DataFlash ═══",
                    "═══ DataFlash SWaP / FeC & Vehicle Identity ═══",
                )
            )
        )
        lines.append(f"  VIN:               {swap_summary.vin or '—'}")
        lines.append(f"  VCRN (DID 0x3C03): {swap_summary.vcrn.hex().upper() if swap_summary.vcrn else '—'}")
        lines.append(f"  SWaP RSA NvM 0x7C: {_rsa_label(swap_summary.swap_rsa_mod, STOCK_SWAP_MODULUS)}")
        lines.append(
            f"  {tr('Сертификаты FSC', 'Active FSCs')}:   "
            f"{len(swap_summary.active_fscs)} ({tr('свободно слотов', 'free slots')}: {swap_summary.free_slots})"
        )
        for fsc in swap_summary.active_fscs:
            fec_names = KNOWN_GATEWAY_FECS.get(fsc.fec_code)
            desc = (fec_names[1] if get_lang() == "en" else fec_names[0]) if fec_names else "Custom FeC"
            kind_tag = "[Multi-FSC]" if fsc.factory_eol else "[RSA-FSC]"
            ds_badge = ""
            if dataset_summary is not None:
                sup = check_fec_dataset_support(dataset_summary, fsc.fec_code)
                ds_badge = (
                    f"  {st.badge_ok(tr('Датасет ОК', 'Dataset OK'))}"
                    if sup.supported
                    else f"  {st.badge_warn('Unsupported Dataset')}"
                )
            lines.append(
                f"    • #{fsc.slot_idx:02d} @ 0x{fsc.dflash_off:04X}: FeC 0x{fsc.fec_code:08X} {kind_tag} ({desc}){ds_badge}"
            )

    return "\n".join(lines)


def format_banks_table(style: Style | None = None) -> str:
    st = style or Style(False)
    lines = [
        st.bold(
            tr(
                "═══ Справочник всех 12 ведомых банков CP + Мастер-банк #0 (Continental J533) ═══",
                "═══ Reference Table of All 12 Slave CP Banks + Master Bank #0 (Continental J533) ═══",
            )
        ),
        st.dim(
            f"  {'#':>2}  {'VAG':<4}  {'NvM':<6}  {'Primary/Mirror':<15}  {'CP CAN TX / RX':<21}  {tr('Блок VAG', 'VAG ECU')}"
        ),
        "  " + ("─" * 102),
    ]
    for spec in (MASTER_SLOT, *SLAVE_SLOTS):
        can_pair = f"0x{spec.cp_tx:08X}/0x{spec.cp_rx:08X}" if spec.slot > 0 else "Master Key (NvM)"
        offs = f"0x{spec.off1:04X}/0x{spec.off2:04X}"
        lines.append(
            f"  {spec.slot:>2}  {spec.ecu_addr:<4}  0x{spec.nvm_id:02X}    "
            f"{offs:<15}  {can_pair:<21}  {spec.short} — {spec.details}"
        )
    return "\n".join(lines)


def format_guide_text(style: Style | None = None) -> str:
    st = style or Style(False)
    lines = [
        st.bold(
            tr(
                "═══ Краткое руководство ContiTool (для начинающих и опытных) ═══",
                "═══ ContiTool Quick-Start Guide (Beginner & Bench Reference) ═══",
            )
        ),
        "",
        st.cyan(
            tr(
                "1. ПОЛНАЯ ЗАМЕНА ПРОГРАММАТОРА ПО CAN (+ ПРАВИЛО 64 КБ ДЛЯ СТОРОННИХ ДАМПОВ):",
                "1. FULL BENCH PROGRAMMER REPLACEMENT OVER CAN (+ 64 KB EXTERNAL DUMP RULE):",
            )
        ),
        tr(
            "   ContiTool читает и записывает ВСЕ области памяти шлюза напрямую по Diagnosis CAN:\n"
            "   CodeFlash 1.5 МБ (включая бут-сектор 0x0000..0xBFFF), DataFlash 64 КБ и Uflash 32 КБ!\n"
            "   Если открываете сторонний дамп со стендового программатора: несмотря на маркировку R7F7010343AFP,\n"
            "   внутри распаяно 64 КБ DataFlash (банки CP лежат в 0xC000..0xFFFF) — снимайте профиль R7F7010543 (64 КБ)!",
            "   ContiTool reads and writes ALL gateway flash regions directly over Diagnosis CAN:\n"
            "   CodeFlash 1.5 MB (including boot blocks 0x0000..0xBFFF), DataFlash 64 KB, and Uflash 32 KB!\n"
            "   If importing an external dump: despite package marking R7F7010343AFP, silicon has 64 KB DataFlash\n"
            "   (CP banks live in 0xC000..0xFFFF) — always use profile R7F7010543 (64 KB Dflash)!",
        ),
        "",
        st.cyan(
            tr(
                "2. ПОДКЛЮЧЕНИЕ НА СТОЛЕ К РАЗЪЁМУ J533 T20 (Diagnosis CAN 500 кбит/с):",
                "2. J533 T20 BENCH WIRING (Diagnosis CAN 500 kbit/s):",
            )
        ),
    ]
    for pin, sig, desc_ru, desc_en in T20_BENCH_PINS:
        desc = desc_ru if get_lang() == "ru" else desc_en
        lines.append(f"   • Pin {pin:>2} ({sig:<12}) — {desc}")
    lines.extend(
        [
            st.yellow(
                tr(
                    "   ⚠ ОБЯЗАТЕЛЬНО: включите терминатор в адаптере или установите резистор 120 Ом между Pin 19 (CAN-H) и Pin 9 (CAN-L)!",
                    "   ⚠ MANDATORY: turn on the adapter's terminator or fit a 120 Ohm resistor between Pin 19 (CAN-H) and Pin 9 (CAN-L)!",
                )
            ),
            "",
            st.cyan(
                tr(
                    "3. ГДЕ БРАТЬ 16-БАЙТНЫЙ ОТКРЫТЫЙ КЛЮЧ IKA ВЕДОМОГО БЛОКА:",
                    "3. WHERE TO GET THE 16-BYTE PLAINTEXT IKA KEY OF A SLAVE ECU:",
                )
            ),
            tr(
                "   • Способ А (родной ключ донора): вычитайте открытый 16Б ключ IKA из дампа ведомого блока (5F, 17, 47, 3C…).\n"
                "   • Способ Б (свой парный ключ): сгенерируйте случайный 16Б ключ в ContiTool и пропишите его в оба блока.\n"
                "   • НИКОГДА не пишите 00..00 (GFA) и не копируйте первые 16Б SHE M1 (00..00E5)!",
                "   • Option A (donor's native key): extract the 16B plaintext IKA key from the slave ECU dump (5F, 17, 47, 3C…).\n"
                "   • Option B (custom paired key): generate a random 16B key in ContiTool and write it to both ECUs.\n"
                "   • NEVER write 00..00 (GFA) or copy the 16B SHE M1 header (00..00E5)!",
            ),
            "",
            st.dim(f"{AUTHOR_CREDIT} • {AUTHOR_SITE_URL} • {AUTHOR_DRIVE2_URL} • {AUTHOR_TG_URL}"),
        ]
    )
    return "\n".join(lines)
