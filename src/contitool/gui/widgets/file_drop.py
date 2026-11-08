"""Dump file field: label, path + Browse (drag & drop anywhere on the field), and a detection status line."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtGui import QDragEnterEvent, QDragLeaveEvent, QDropEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from contitool.core import DetectedDumpFile, clean_user_path, detect_dump_file
from contitool.gui.theme import set_tone
from contitool.i18n import subscribe_lang_change, tr


class DumpFileSelector(QFrame):
    """File picker supporting Drag & Drop + Browse with live dump-type verification."""

    file_changed = Signal(object)  # Emits DetectedDumpFile | None

    def __init__(
        self,
        *,
        title_ru: str,
        title_en: str,
        hint_ru: str = "",
        hint_en: str = "",
        expected_kinds: tuple[str, ...] | None = None,
        dialog_filter: str = "Binary & Key Files (*.bin *.raw *.fsc *.json *.pem);;All Files (*)",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self._title_ru = title_ru
        self._title_en = title_en
        self._hint_ru = hint_ru
        self._hint_en = hint_en
        self._expected_kinds = expected_kinds
        self._dialog_filter = dialog_filter
        self._detected: DetectedDumpFile | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(8)
        self.lbl_title = QLabel()
        self.lbl_title.setObjectName("FieldLabel")
        top.addWidget(self.lbl_title)
        top.addStretch(1)
        self.lbl_hint = QLabel()
        self.lbl_hint.setObjectName("Hint")
        top.addWidget(self.lbl_hint)
        lay.addLayout(top)

        row = QHBoxLayout()
        row.setSpacing(6)
        self.ed_path = QLineEdit()
        self.ed_path.setMinimumWidth(120)
        self.ed_path.setAcceptDrops(False)  # let the whole field handle file drops (and validate them)
        self.ed_path.editingFinished.connect(self._on_manual_edit)
        row.addWidget(self.ed_path, 1)

        self.btn_browse = QPushButton()
        self.btn_browse.clicked.connect(self._on_browse)
        row.addWidget(self.btn_browse)

        self.btn_clear = QPushButton("✕")
        self.btn_clear.setObjectName("GhostBtn")
        self.btn_clear.clicked.connect(self.clear)
        row.addWidget(self.btn_clear)
        lay.addLayout(row)

        self.lbl_badge = QLabel()
        self.lbl_badge.setWordWrap(True)
        lay.addWidget(self.lbl_badge)

        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.retranslate_ui()

    def retranslate_ui(self) -> None:
        self.lbl_title.setText(tr(self._title_ru, self._title_en))
        self.lbl_hint.setText(tr(self._hint_ru, self._hint_en))
        self.lbl_hint.setVisible(bool(self._hint_ru or self._hint_en))
        self.ed_path.setPlaceholderText(tr("Перетащите файл или выберите…", "Drop a file or browse…"))
        self.btn_browse.setText(tr("Обзор…", "Browse…"))
        self.btn_clear.setToolTip(tr("Очистить", "Clear"))
        self._refresh_badge()

    @property
    def current_path(self) -> Path | None:
        raw = self.ed_path.text().strip()
        return clean_user_path(raw) if raw else None

    @property
    def detected(self) -> DetectedDumpFile | None:
        return self._detected

    def is_valid_selection(self) -> bool:
        if self._detected is None or not self._detected.valid:
            return False
        if self._expected_kinds and self._detected.kind not in self._expected_kinds:
            return False
        return True

    def set_path(self, path: str | Path | None) -> None:
        if path is None or not str(path).strip():
            self.clear()
            return
        p = clean_user_path(path)
        self.ed_path.setText(str(p))
        self._evaluate_path(p)

    def clear(self) -> None:
        self.ed_path.clear()
        self._detected = None
        self._refresh_badge()
        self.file_changed.emit(None)

    def _on_browse(self) -> None:
        start_dir = str(self.current_path.parent) if self.current_path else str(Path.cwd())
        chosen, _ = QFileDialog.getOpenFileName(
            self,
            tr(self._title_ru, self._title_en),
            start_dir,
            self._dialog_filter,
        )
        if chosen:
            self.set_path(chosen)

    def _on_manual_edit(self) -> None:
        raw = self.ed_path.text().strip()
        if not raw:
            self.clear()
        else:
            self._evaluate_path(clean_user_path(raw))

    def _evaluate_path(self, p: Path) -> None:
        det = detect_dump_file(p)
        self._detected = det
        self._refresh_badge()
        self.file_changed.emit(det)

    def _refresh_badge(self) -> None:
        det = self._detected
        if det is None:
            set_tone(self.lbl_badge, "muted")
            self.lbl_badge.setText(tr("Файл не выбран", "No file selected"))
        elif not det.valid:
            set_tone(self.lbl_badge, "err")
            self.lbl_badge.setText(f"✗  {det.summary_text}")
        elif self._expected_kinds and det.kind not in self._expected_kinds:
            set_tone(self.lbl_badge, "err")
            exp_str = " / ".join(self._expected_kinds)
            self.lbl_badge.setText(
                tr(
                    f"✗  Не тот тип файла ({det.summary_text}). Ожидается: {exp_str}",
                    f"✗  Wrong file type ({det.summary_text}). Expected: {exp_str}",
                )
            )
        else:
            set_tone(self.lbl_badge, "ok")
            self.lbl_badge.setText(f"✓  {det.summary_text}")
        self.lbl_badge.setToolTip(str(self.current_path or ""))

    def _set_drag_highlight(self, on: bool) -> None:
        self.ed_path.setProperty("drag", "true" if on else "false")
        self.ed_path.style().unpolish(self.ed_path)
        self.ed_path.style().polish(self.ed_path)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            self._set_drag_highlight(True)
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:
        self._set_drag_highlight(False)
        super().dragLeaveEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:
        self._set_drag_highlight(False)
        urls = event.mimeData().urls()
        if urls:
            local = urls[0].toLocalFile()
            if local:
                self.set_path(local)
                event.acceptProposedAction()
                return
        super().dropEvent(event)
