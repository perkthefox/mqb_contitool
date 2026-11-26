"""Pick the backup files to write back into the ECU they were taken from."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QFileDialog, QGridLayout, QLabel, QWidget

from contitool.can import backup_identity
from contitool.core.analyzer import detect_dump_file
from contitool.gui.widgets.page import Callout, Dialog, button, hint
from contitool.gui.workspace import KINDS, NAMES, kind_of, other_ecu_dflash_label
from contitool.i18n import tr


class RestoreDialog(Dialog):
    def __init__(self, parent: QWidget | None = None, start_dir: str = "") -> None:
        super().__init__(
            parent,
            tr("Залить бэкап в блок", "Write a backup to the ECU"),
            tr(
                "Укажите файлы бэкапа, снятого с этого же блока. Тип файла определяется по содержимому.",
                "Pick the files of a backup taken from this very ECU. The file type is detected from its content.",
            ),
        )
        self.files: dict[str, Path] = {}
        self._dir = start_dir
        self.body.addWidget(button(tr("Выбрать файлы бэкапа…", "Choose backup files…"), slot=self._pick), 0, Qt.AlignmentFlag.AlignLeft)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(6)
        self.boxes: dict[str, QCheckBox] = {}
        self._paths: dict[str, QLabel] = {}
        for row, kind in enumerate(KINDS):
            box = QCheckBox(NAMES[kind])
            box.toggled.connect(lambda _on: self._refresh_ok())
            self.boxes[kind] = box
            self._paths[kind] = path = hint()
            grid.addWidget(box, row, 0)
            grid.addWidget(path, row, 1)
        grid.setColumnStretch(1, 1)
        self.body.addLayout(grid)
        self.lbl_ident = hint()
        self.lbl_rejected = hint()
        self.body.addWidget(self.lbl_ident)
        self.body.addWidget(self.lbl_rejected)
        self.lbl_rejected.hide()

        note = Callout("warn")
        note.label.setText(
            tr(
                "• Перед записью проверяются <b>FAZIT</b> и <b>VCRN</b> — бэкап чужого блока будет отклонён.<br>"
                "• Записываются только отличающиеся блоки памяти, после чего выполняется проверка чтением.<br>"
                "• Не отключайте питание +12 В (Pin 1 и 14) до завершения операции.",
                "• <b>FAZIT</b> and <b>VCRN</b> are verified first — a backup from another ECU is rejected.<br>"
                "• Only changed blocks are written, followed by readback verification.<br>"
                "• Keep +12 V power (Pin 1 and 14) stable until finished.",
            )
        )
        self.body.addWidget(note)

        self.ok = button(tr("Залить в блок", "Write to ECU"), "PrimaryBtn", slot=self.accept)
        self._refresh()  # before finish(): the dialog is sized without the hidden hints
        self.finish(ok=self.ok)

    @property
    def kinds(self) -> list[str]:
        return [k for k, box in self.boxes.items() if box.isChecked() and k in self.files]

    def add_files(self, paths: list[Path]) -> list[str]:
        """Sort the picked files by content; returns the names of files that are not gateway dumps."""
        rejected = []
        for p in paths:
            kind = kind_of(detect_dump_file(p))
            if kind in ("dflash", "uflash"):
                try:
                    if other_ecu_dflash_label(p.read_bytes()) is not None:
                        kind = None
                except OSError:
                    kind = None
            if kind is None:
                rejected.append(p.name)
                continue
            self.files[kind] = p
            self.boxes[kind].setChecked(True)
        self.lbl_rejected.setText(
            tr(f"Не дампы шлюза, пропущены: {', '.join(rejected)}", f"Not gateway dumps, skipped: {', '.join(rejected)}")
        )
        self.lbl_rejected.setVisible(bool(rejected))
        self._refresh()
        return rejected

    def _pick(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, tr("Файлы бэкапа", "Backup files"), self._dir, tr("Дампы (*.bin);;Все файлы (*)", "Dumps (*.bin);;All files (*)")
        )
        if paths:
            self._dir = str(Path(paths[0]).parent)
            self.add_files([Path(p) for p in paths])

    def _refresh(self) -> None:
        for kind, box in self.boxes.items():
            p = self.files.get(kind)
            box.setEnabled(p is not None)
            self._paths[kind].setText(str(p) if p else tr("не выбран", "not chosen"))
        if self.files:
            cf, df = self.files.get("cflash"), self.files.get("dflash")
            ident = backup_identity(cf.read_bytes() if cf else None, df.read_bytes() if df else None)
            self.lbl_ident.setText(f"FAZIT: {ident['fazit'] or '—'}    VCRN: {ident['vcrn'] or '—'}")
        self.lbl_ident.setVisible(bool(self.files))
        self._refresh_ok()

    def _refresh_ok(self) -> None:
        self.ok.setEnabled(bool(self.kinds))
