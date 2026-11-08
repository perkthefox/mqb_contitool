"""QThread worker and OperationRunner coordinator for non-blocking, real-time GUI execution."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import threading
import time
import traceback
from typing import Any

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot

from contitool.i18n import tr
from contitool.progress import (
    LogEntry,
    OperationCancelledError,
    OperationReporter,
    ProgressSnapshot,
    StepSnapshot,
)
from contitool.report import Failure


class OperationWorker(QThread):
    """Background worker executing `task(reporter)` and streaming events via Qt Signals."""

    step_emitted = Signal(object)       # StepSnapshot
    progress_emitted = Signal(object)   # ProgressSnapshot
    log_emitted = Signal(object)        # LogEntry
    succeeded = Signal(object)          # Any task return value
    cancelled = Signal(str)
    failed = Signal(str, str)           # (user_message, full_traceback)

    def __init__(
        self,
        title: str,
        task_fn: Callable[[OperationReporter], Any],
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.title = title
        self._task_fn = task_fn
        self._cancel_event = threading.Event()
        self.reporter = OperationReporter(
            on_step=lambda s: self.step_emitted.emit(s),
            on_progress=lambda p: self.progress_emitted.emit(p),
            on_log=lambda e: self.log_emitted.emit(e),
            cancel_event=self._cancel_event,
        )

    def request_cancel(self) -> None:
        self._cancel_event.set()

    def run(self) -> None:
        try:
            self.reporter.info(
                tr(f"Запуск операции: {self.title}", f"Starting operation: {self.title}")
            )
            result = self._task_fn(self.reporter)
            self.succeeded.emit(result)
        except OperationCancelledError as exc:
            self.reporter.warning(str(exc))
            self.cancelled.emit(str(exc))
        except Exception as exc:
            tb = traceback.format_exc()
            self.reporter.error(str(exc))
            self.failed.emit(str(exc), tb)


class OperationRunner(QObject):
    """Single-flight operation manager connecting every GUI page to the live ExecutionPanel."""

    busy_changed = Signal(bool)
    operation_started = Signal(str)
    step_changed = Signal(object)
    progress_changed = Signal(object)
    log_added = Signal(object)
    operation_finished = Signal(bool, str, object)  # (ok, summary_text, open_target_path_or_None)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._worker: OperationWorker | None = None
        self._active_title: str = ""
        self._on_success: Callable[[Any], None] | None = None
        self._resolve_path: Callable[[Any], Path | None] | None = None
        self.was_cancelled = False  # how the last operation ended, for operation_finished(False, ...) listeners
        self.started_at = 0.0  # wall clock of the last operation start
        self.last_failure: Failure | None = None  # what the problem report is about

    @property
    def is_busy(self) -> bool:
        return self._worker is not None and self._worker.isRunning()

    def cancel_current(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.request_cancel()

    def run_task(
        self,
        title: str,
        task_fn: Callable[[OperationReporter], Any],
        *,
        on_success: Callable[[Any], None] | None = None,
        resolve_path: Callable[[Any], Path | None] | None = None,
    ) -> bool:
        if self.is_busy:
            return False

        worker = OperationWorker(title, task_fn, self)
        self._worker = worker
        self._active_title = title
        self._on_success = on_success
        self._resolve_path = resolve_path
        self.started_at = time.time()
        self.busy_changed.emit(True)
        self.operation_started.emit(title)

        worker.step_emitted.connect(self.step_changed.emit, Qt.ConnectionType.QueuedConnection)
        worker.progress_emitted.connect(self.progress_changed.emit, Qt.ConnectionType.QueuedConnection)
        worker.log_emitted.connect(self.log_added.emit, Qt.ConnectionType.QueuedConnection)
        worker.succeeded.connect(self._on_worker_ok, Qt.ConnectionType.QueuedConnection)
        worker.cancelled.connect(self._on_worker_cancel, Qt.ConnectionType.QueuedConnection)
        worker.failed.connect(self._on_worker_fail, Qt.ConnectionType.QueuedConnection)
        worker.start()
        return True

    @Slot(object)
    def _on_worker_ok(self, res: Any) -> None:
        title = self._active_title
        on_success = self._on_success
        resolve_path = self._resolve_path
        target_path: Path | None = None
        if resolve_path is not None:
            try:
                target_path = resolve_path(res)
            except Exception:
                target_path = None
        elif isinstance(res, dict) and res.get("session_dir"):
            target_path = Path(str(res["session_dir"]))
        elif isinstance(res, Path):
            target_path = res

        try:
            if on_success is not None:
                on_success(res)
        finally:  # a failing UI callback must never leave the runner stuck "busy"
            self._cleanup_worker()
            self.was_cancelled = False
            self.operation_finished.emit(True, title, target_path)

    @Slot(str)
    def _on_worker_cancel(self, msg: str) -> None:
        self._cleanup_worker()
        self.was_cancelled = True
        self.operation_finished.emit(False, msg, None)

    @Slot(str, str)
    def _on_worker_fail(self, msg: str, tb: str) -> None:
        self.last_failure = Failure(self._active_title, msg, tb, self.started_at)
        self._cleanup_worker()
        self.was_cancelled = False
        self.operation_finished.emit(False, msg, None)

    def _cleanup_worker(self) -> None:
        self._on_success = None
        self._resolve_path = None
        if self._worker is not None:
            self._worker.wait(2000)
            self._worker.deleteLater()
            self._worker = None
        self.busy_changed.emit(False)
