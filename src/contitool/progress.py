"""Unified real-time progress, step, and log reporting for ALL ContiTool operations.

Every offline and live CAN function accepts an optional `OperationReporter` so that both the
Desktop GUI (via QThread signals) and the CLI display real-time step-by-step visibility,
transfer speeds, ETAs, and structured logs without ever freezing the screen.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
import contextlib
import dataclasses
import threading
import time
from typing import Literal

from contitool.i18n import tr

LogLevel = Literal["info", "success", "warning", "error", "step", "can"]


class OperationCancelledError(BaseException):
    """Raised when the user requests cancellation of a running operation.

    A BaseException, like KeyboardInterrupt, on purpose: the CAN code treats `RuntimeError` / `Exception` as "the
    link failed" and answers with a retry, a reset or a fallback path. As a RuntimeError, "Cancel" was taken for a
    link failure — the RAM-loader entry, for one, went on to its second attempt. Cleanup still runs in `finally`;
    the GUI worker catches this by name."""


@dataclasses.dataclass(frozen=True)
class ProgressSnapshot:
    """Point-in-time progress state emitted to GUI/CLI observers."""

    current: int
    total: int
    percent: float
    unit: str = ""
    speed_bps: float = 0.0
    elapsed_sec: float = 0.0
    eta_sec: float | None = None
    detail: str = ""


@dataclasses.dataclass(frozen=True)
class StepSnapshot:
    """Active workflow step state."""

    index: int
    total: int
    title: str


@dataclasses.dataclass(frozen=True)
class LogEntry:
    """Timestamped log entry emitted during an operation."""

    timestamp: float
    level: LogLevel
    message: str


class OperationReporter:
    """Thread-safe event sink for steps, progress bars, logs, and cooperative cancellation."""

    def __init__(
        self,
        *,
        on_step: Callable[[StepSnapshot], None] | None = None,
        on_progress: Callable[[ProgressSnapshot], None] | None = None,
        on_log: Callable[[LogEntry], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self._on_step = on_step
        self._on_progress = on_progress
        self._on_log = on_log
        self._cancel_event = cancel_event or threading.Event()
        self._started_at = time.monotonic()
        self._stage_started_at = self._started_at
        self._writing = 0  # > 0 while a flash write runs: see uninterruptible()
        self._cancel_deferred = False

    def cancel(self) -> None:
        """Request cooperative cancellation at the next safe checkpoint."""
        self._cancel_event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def check_cancelled(self) -> None:
        if not self._cancel_event.is_set():
            return
        if self._writing:
            if not self._cancel_deferred:
                self._cancel_deferred = True
                self.warning(tr("Идёт запись — прервать её на середине нельзя. Операция остановится, как только "
                                "запись закончится.",
                                "A write is in progress and cannot be stopped halfway. The operation stops as soon "
                                "as the write is done."))
            return
        raise OperationCancelledError("Операция остановлена пользователем / Operation cancelled by user")

    @contextlib.contextmanager
    def uninterruptible(self) -> Iterator[None]:
        """A flash write: a cancel request waits until it is done, then takes effect.

        Stopped halfway, a write leaves the ECU worse than either end: an erased application keeps it in its
        bootloader, a half-written boot area pairs new blocks with old ones."""
        self._writing += 1
        try:
            yield
        finally:
            self._writing -= 1
        self.check_cancelled()

    def reset_stage_timer(self) -> None:
        self._stage_started_at = time.monotonic()

    def step(self, index: int, total: int, title: str) -> None:
        self.check_cancelled()
        self._stage_started_at = time.monotonic()
        snap = StepSnapshot(index=index, total=max(1, total), title=title)
        if self._on_step is not None:
            self._on_step(snap)
        self.log(f"[{index}/{max(1, total)}] {title}", level="step")

    def progress(
        self,
        current: int,
        total: int,
        *,
        unit: str = "",
        detail: str = "",
    ) -> None:
        self.check_cancelled()
        now = time.monotonic()
        elapsed = max(0.001, now - self._stage_started_at)
        safe_total = max(1, total)
        clamped = max(0, min(current, safe_total))
        pct = (clamped / safe_total) * 100.0
        speed = clamped / elapsed if unit in ("B", "bytes", "Б") and clamped > 0 else 0.0
        eta: float | None = None
        if 0 < clamped < safe_total and elapsed >= 0.25:
            rate = clamped / elapsed
            if rate > 0:
                eta = (safe_total - clamped) / rate
        snap = ProgressSnapshot(
            current=clamped,
            total=safe_total,
            percent=pct,
            unit=unit,
            speed_bps=speed,
            elapsed_sec=now - self._started_at,
            eta_sec=eta,
            detail=detail,
        )
        if self._on_progress is not None:
            self._on_progress(snap)

    def log(self, message: str, *, level: LogLevel = "info") -> None:
        entry = LogEntry(timestamp=time.time(), level=level, message=message)
        if self._on_log is not None:
            self._on_log(entry)

    def info(self, message: str) -> None:
        self.log(message, level="info")

    def success(self, message: str) -> None:
        self.log(message, level="success")

    def warning(self, message: str) -> None:
        self.log(message, level="warning")

    def error(self, message: str) -> None:
        self.log(message, level="error")

    def can_log(self, message: str) -> None:
        self.log(message, level="can")


NULL_REPORTER = OperationReporter()
