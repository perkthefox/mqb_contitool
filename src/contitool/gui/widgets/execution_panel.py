"""Operation journal (short and detailed views) plus the status-bar readout of the running operation."""

from __future__ import annotations

import dataclasses
import html
from pathlib import Path
import re
import time

from PySide6.QtCore import QSettings, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from contitool.cli.formatting import format_bytes_human, format_eta
from contitool.gui import theme
from contitool.gui.theme import mono_font, set_tone, ui_font
from contitool.gui.widgets.page import button, vdivider
from contitool.gui.worker import OperationRunner
from contitool.i18n import subscribe_lang_change, tr
from contitool.progress import LogEntry, ProgressSnapshot, StepSnapshot

# Addresses (`@ 0x0000C21C`) and bracketed raw bytes (`(UDS 19 02 FF)`, `(0x6F0)`) — kept in the detailed log only.
# Pattern-based; if a step title ever needs both a plain and a technical form, give StepSnapshot two fields.
_TECH = re.compile(
    r"\s*@\s*\+?0x[0-9A-Fa-f]+"
    r"|\s*\((?=[^()]*(?:0x[0-9A-Fa-f]|\b[0-9A-F]{2} [0-9A-F]{2}\b))[^()]*\)"
)

_FULL_STYLE = {
    "step": (theme.INFO, "STEP", theme.TEXT),
    "info": (theme.TEXT_MUTED, "INFO", theme.TEXT_SECONDARY),
    "success": (theme.OK, "OK", theme.OK),
    "warning": (theme.WARN, "WARN", theme.WARN),
    "error": (theme.ERR, "ERR", theme.ERR),
    "can": (theme.CAN, "CAN", theme.CAN),
}
_MAX_ITEMS = 200


def plain_step(text: str) -> str:
    """Step title without addresses and raw UDS bytes, for the short journal."""
    return _TECH.sub("", text).strip()


def _duration(sec: float) -> str:
    if sec < 10:
        return tr(f"{sec:.1f} с".replace(".", ","), f"{sec:.1f} s")
    return format_eta(sec)


@dataclasses.dataclass
class _Op:
    title: str
    started: float  # wall clock, for the timestamp
    lines: list[tuple[str, str]] = dataclasses.field(default_factory=list)  # (step | warning | error, text)
    state: str = "running"  # running | ok | err | cancel
    elapsed: float = 0.0


@dataclasses.dataclass
class _Note:
    at: float
    text: str


class ExecutionPanel(QFrame):
    """Journal docked under the working screen; `status_widget` goes into the window's status bar."""

    def __init__(self, runner: OperationRunner, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Console")
        self.runner = runner
        self._started_mono: float | None = None
        self._last_snap: ProgressSnapshot | None = None
        self._open_target: Path | None = None
        self._items: list[_Op | _Note] = []
        self._op: _Op | None = None
        self._title = ""
        self._step_text = ""
        self._state = "idle"  # idle | running | ok | err | cancel

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        hdr_bar = QFrame()
        hdr_bar.setObjectName("ConsoleHeader")
        hdr_bar.setFixedHeight(34)
        hdr = QHBoxLayout(hdr_bar)
        hdr.setContentsMargins(18, 0, 18, 0)
        hdr.setSpacing(8)
        self.lbl_title = QLabel()
        self.lbl_title.setObjectName("GroupLabel")
        hdr.addWidget(self.lbl_title, 0, Qt.AlignmentFlag.AlignVCenter)
        hdr.addSpacing(6)
        self.btn_short = QPushButton()
        self.btn_full = QPushButton()
        group = QButtonGroup(self)
        for b, pos in ((self.btn_short, "left"), (self.btn_full, "right")):
            b.setObjectName("SegBtn")
            b.setProperty("pos", pos)
            b.setCheckable(True)
            group.addButton(b)
            hdr.addWidget(b, 0, Qt.AlignmentFlag.AlignVCenter)
        hdr.addStretch(1)
        self.btn_open_dir = button("", "GhostBtn", slot=self._on_open_target)
        self.btn_open_dir.setVisible(False)
        self.btn_copy = button("", "GhostBtn", slot=self._on_copy_logs)
        self.btn_clear = button("", "GhostBtn", slot=self.clear_logs)
        self.btn_hide = button("", "GhostBtn")
        for b in (self.btn_open_dir, self.btn_copy, self.btn_clear, self.btn_hide):
            hdr.addWidget(b, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addWidget(hdr_bar)

        self.txt_short = QTextBrowser()
        self.txt_short.setOpenLinks(False)
        self.txt_short.setFont(ui_font(12))
        self.txt_full = QPlainTextEdit()
        self.txt_full.setReadOnly(True)
        self.txt_full.setFont(mono_font(12))
        self.txt_full.setMaximumBlockCount(20000)
        self.txt_full.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.views = QStackedWidget()
        self.views.addWidget(self.txt_short)
        self.views.addWidget(self.txt_full)
        self.views.setMinimumHeight(60)
        lay.addWidget(self.views, 1)

        detailed = str(QSettings().value("log/detailed", "false")).lower() == "true"
        (self.btn_full if detailed else self.btn_short).setChecked(True)
        self.views.setCurrentWidget(self.txt_full if detailed else self.txt_short)
        self.btn_short.toggled.connect(self._on_view_toggled)

        self.status_widget = self._build_status()

        self._clock = QTimer(self)
        self._clock.setInterval(250)
        self._clock.timeout.connect(self._refresh_metrics_label)

        runner.operation_started.connect(self._on_started)
        runner.step_changed.connect(self._on_step)
        runner.progress_changed.connect(self._on_progress)
        runner.log_added.connect(self._on_log)
        runner.operation_finished.connect(self._on_finished)

        self._unsub = subscribe_lang_change(self._on_lang_changed)
        self.retranslate_ui()

    def _on_lang_changed(self, _lang: str) -> None:
        self.retranslate_ui()

    def _build_status(self) -> QWidget:
        w = QFrame()
        w.setObjectName("StatusStrip")
        w.setFixedHeight(32)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(18, 0, 18, 0)
        lay.setSpacing(10)
        self.lbl_status = QLabel()
        self.lbl_status.setObjectName("FieldLabel")
        lay.addWidget(self.lbl_status, 0, Qt.AlignmentFlag.AlignVCenter)
        self.lbl_step = QLabel()
        self.lbl_step.setObjectName("Hint")
        self.lbl_step.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        lay.addWidget(self.lbl_step, 1, Qt.AlignmentFlag.AlignVCenter)
        self.lbl_metrics = QLabel()
        self.lbl_metrics.setFont(mono_font(12))
        set_tone(self.lbl_metrics, "muted")
        lay.addWidget(self.lbl_metrics, 0, Qt.AlignmentFlag.AlignVCenter)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedWidth(160)
        self.progress_bar.setVisible(False)
        lay.addWidget(self.progress_bar, 0, Qt.AlignmentFlag.AlignVCenter)
        self.btn_stop = button("", "DangerBtn", slot=self.runner.cancel_current)
        self.btn_stop.setVisible(False)
        lay.addWidget(self.btn_stop, 0, Qt.AlignmentFlag.AlignVCenter)
        self.status_divider = vdivider()
        self.status_divider.setFixedHeight(14)
        lay.addWidget(self.status_divider, 0, Qt.AlignmentFlag.AlignVCenter)
        self.btn_toggle_log = button("", "StatusBtn")
        self.btn_toggle_log.setCheckable(True)
        lay.addWidget(self.btn_toggle_log, 0, Qt.AlignmentFlag.AlignVCenter)
        return w

    # ────────────────────────────── text ──────────────────────────────
    def retranslate_ui(self) -> None:
        self.lbl_title.setText(tr("ЖУРНАЛ ОПЕРАЦИЙ", "OPERATION LOG"))
        self.btn_short.setText(tr("Кратко", "Summary"))
        self.btn_full.setText(tr("Подробно", "Detailed"))
        self.btn_full.setToolTip(tr("Полный технический лог: адреса, UDS, CAN", "Full technical log: addresses, UDS, CAN"))
        self.btn_open_dir.setText(tr("Открыть папку", "Open folder"))
        self.btn_copy.setText(tr("Копировать", "Copy"))
        self.btn_copy.setToolTip(tr("Копирует подробный лог", "Copies the detailed log"))
        self.btn_clear.setText(tr("Очистить", "Clear"))
        self.btn_hide.setText(tr("Скрыть", "Hide"))
        self.btn_toggle_log.setText(tr("Журнал", "Log"))
        self.btn_toggle_log.setToolTip(tr("Показать или скрыть журнал операций (Ctrl+J)", "Show or hide the operation log (Ctrl+J)"))
        self.btn_stop.setText(tr("Остановить", "Stop"))
        self._apply_status()
        self._render_short()

    def _apply_status(self) -> None:
        labels = {
            "idle": ("muted", tr("Готов к работе", "Ready")),
            "running": ("info", tr("Выполняется", "Running")),
            "ok": ("ok", tr("Готово", "Done")),
            "err": ("err", tr("Ошибка", "Failed")),
            "cancel": ("warn", tr("Остановлено", "Stopped")),
        }
        tone, text = labels[self._state]
        self.lbl_status.setText(text)
        set_tone(self.lbl_status, tone)
        set_tone(self.progress_bar, tone)
        self.lbl_step.setText(self._step_text)
        self.lbl_step.setToolTip(self._step_text)

    def _on_view_toggled(self, short: bool) -> None:
        self.views.setCurrentWidget(self.txt_short if short else self.txt_full)
        QSettings().setValue("log/detailed", not short)

    # ────────────────────────────── runner events ──────────────────────────────
    def _on_started(self, title: str) -> None:
        self._state = "running"
        self._title = title
        self._started_mono = time.monotonic()
        self._last_snap = None
        self._open_target = None
        self.btn_open_dir.setVisible(False)
        self.btn_stop.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self._step_text = title
        self._apply_status()
        self._clock.start()
        self._refresh_metrics_label()

        self._op = _Op(title, time.time())
        self._add_item(self._op)
        self._full_line(f"<b style='color:{theme.TEXT}'>── {html.escape(title)}</b>", blank_before=True)

    def _on_step(self, snap: StepSnapshot) -> None:
        clean = plain_step(snap.title)
        self._step_text = f"{self._title} — {clean}" if self._title else clean
        self._apply_status()
        if self._op is not None:
            self._op.lines.append(("step", clean))
            self._render_short()

    def _on_progress(self, snap: ProgressSnapshot) -> None:
        self._last_snap = snap
        self.progress_bar.setValue(int(round(snap.percent * 10.0)))
        self._refresh_metrics_label()

    def _refresh_metrics_label(self) -> None:
        if self._started_mono is None:
            self.lbl_metrics.setText("")
            return
        parts: list[str] = []
        snap = self._last_snap
        if snap is not None and self._state == "running":
            parts.append(f"{snap.percent:.0f}%")
            if snap.unit in ("B", "bytes", "Б"):
                parts.append(f"{format_bytes_human(snap.current)} / {format_bytes_human(snap.total)}")
            if snap.speed_bps > 0:
                parts.append(f"{snap.speed_bps / 1024.0:.1f} KB/s")
            if snap.eta_sec is not None:
                parts.append(tr(f"осталось {format_eta(snap.eta_sec)}", f"{format_eta(snap.eta_sec)} left"))
        parts.append(format_eta(time.monotonic() - self._started_mono))
        self.lbl_metrics.setText("    ".join(parts))

    def _on_log(self, entry: LogEntry) -> None:
        ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp)) + f".{int(entry.timestamp * 1000) % 1000:03d}"
        tag_col, tag, msg_col = _FULL_STYLE.get(entry.level, _FULL_STYLE["info"])
        weight = "600" if entry.level == "step" else "400"
        self._full_line(
            f"<span style='color:{theme.TEXT_MUTED}'>{ts}</span>&nbsp;&nbsp;"
            f"<span style='color:{tag_col}'>{tag.ljust(4).replace(' ', '&nbsp;')}</span>&nbsp;&nbsp;"
            f"<span style='color:{msg_col}; font-weight:{weight}'>{html.escape(entry.message)}</span>"
        )
        if entry.level in ("warning", "error") and self._op is not None:
            self._op.lines.append((entry.level, entry.message))
            self._render_short()

    def _on_finished(self, ok: bool, summary: str, target_path: object) -> None:
        self._clock.stop()
        self.btn_stop.setVisible(False)
        self._state = "ok" if ok else ("cancel" if self.runner.was_cancelled else "err")
        self._step_text = self._title if ok else summary
        self._apply_status()
        if ok:
            self.progress_bar.setValue(1000)
        if isinstance(target_path, Path):
            folder = target_path if target_path.is_dir() else target_path.parent
            if folder.exists():
                self._open_target = folder
                self.btn_open_dir.setVisible(True)
        self._refresh_metrics_label()

        elapsed = time.monotonic() - (self._started_mono or time.monotonic())
        if self._op is not None:
            self._op.state, self._op.elapsed = self._state, elapsed
            if self._state == "cancel" and self._op.lines and self._op.lines[-1] == ("warning", summary):
                self._op.lines.pop()  # "stopped" is already in the header
            self._op = None
            self._render_short()
        col, word = {
            "ok": (theme.OK, tr("Готово", "Done")),
            "err": (theme.ERR, tr("Ошибка", "Failed")),
            "cancel": (theme.WARN, tr("Остановлено", "Stopped")),
        }[self._state]
        self._full_line(f"<span style='color:{col}'>── {word} ({_duration(elapsed)})</span>")

    # ────────────────────────────── journal ──────────────────────────────
    def _add_item(self, item: _Op | _Note) -> None:
        self._items.append(item)
        del self._items[:-_MAX_ITEMS]
        self._render_short()

    def _full_line(self, html_line: str, blank_before: bool = False) -> None:
        if blank_before and not self.txt_full.document().isEmpty():
            self.txt_full.appendPlainText("")
        self.txt_full.appendHtml(html_line)
        sb = self.txt_full.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _render_short(self) -> None:
        mono = mono_font().family()
        muted, secondary = theme.TEXT_MUTED, theme.TEXT_SECONDARY
        states = {
            "running": (theme.INFO, tr("выполняется", "running")),
            "ok": (theme.OK, tr("готово", "done")),
            "err": (theme.ERR, tr("ошибка", "failed")),
            "cancel": (theme.WARN, tr("остановлено", "stopped")),
        }
        if not self._items:
            idle = html.escape(
                tr(
                    "Журнал операций пуст — ход чтения, записи и диагностики отображается здесь.",
                    "Operation log is empty — read, write, and diagnostic progress appears here.",
                )
            )
            self.txt_short.setHtml(f"<div style='color:{muted}; padding-top:2px'>{idle}</div>")
            return
        rows: list[str] = []
        for it in self._items:
            ts = time.strftime("%H:%M:%S", time.localtime(it.started if isinstance(it, _Op) else it.at))
            time_cell = f"<td width='70' style=\"color:{muted}; font-family:'{mono}'\">{ts}</td>"
            if isinstance(it, _Note):
                rows.append(f"<tr>{time_cell}<td colspan='2' style='color:{secondary}'>{html.escape(it.text)}</td></tr>")
                continue
            col, word = states[it.state]
            right = f"<span style='color:{col}'>{word}</span>"
            if it.state != "running":
                right += f"<span style='color:{muted}'>&nbsp;&nbsp;{_duration(it.elapsed)}</span>"
            rows.append(
                f"<tr>{time_cell}<td style='color:{theme.TEXT}; font-weight:600'>{html.escape(it.title)}</td>"
                f"<td align='right'>{right}</td></tr>"
            )
            last_step = max((i for i, (k, _t) in enumerate(it.lines) if k == "step"), default=-1)
            for i, (kind, text) in enumerate(it.lines):
                if kind == "step":
                    mark, mcol, tcol = "✓", theme.OK, secondary
                    if i == last_step and it.state != "ok":
                        mark, mcol, tcol = {
                            "running": ("›", theme.INFO, theme.TEXT),
                            "err": ("✕", theme.ERR, theme.TEXT),
                            "cancel": ("–", theme.WARN, theme.TEXT),
                        }[it.state]
                elif kind == "warning":
                    mark, mcol, tcol = "!", theme.WARN, theme.WARN
                else:
                    mark, mcol, tcol = "✕", theme.ERR, theme.ERR
                rows.append(
                    f"<tr><td></td><td colspan='2'><span style='color:{mcol}; font-weight:600'>{mark}</span>"
                    f"&nbsp;&nbsp;<span style='color:{tcol}'>{html.escape(text)}</span></td></tr>"
                )
            rows.append("<tr><td colspan='3' style='font-size:4px'>&nbsp;</td></tr>")
        self.txt_short.setHtml(f"<table width='100%' cellspacing='0' cellpadding='2'>{''.join(rows)}</table>")
        sb = self.txt_short.verticalScrollBar()
        sb.setValue(sb.maximum())

    # ────────────────────────────── actions ──────────────────────────────
    def _on_open_target(self) -> None:
        if self._open_target is not None and self._open_target.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._open_target)))

    def _on_copy_logs(self) -> None:
        cb = QGuiApplication.clipboard()
        if cb is not None:
            cb.setText(self.txt_full.toPlainText())

    def note(self, message: str) -> None:
        """A standalone line not tied to a running operation."""
        now = time.time()
        self._add_item(_Note(now, message))
        self._on_log(LogEntry(level="info", message=message, timestamp=now))

    def clear_logs(self) -> None:
        self._items.clear()
        self.txt_full.clear()
        self._render_short()
