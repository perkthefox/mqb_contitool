"""Offered after anything goes wrong: a report archive with the logs, and a prefilled GitHub issue."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QApplication, QCheckBox, QFileDialog, QLabel, QWidget

from contitool.gui.connection import CanConnection
from contitool.gui.theme import set_tone
from contitool.gui.widgets.page import Callout, Dialog, button, hint
from contitool.i18n import tr
from contitool.report import GITHUB_ATTACH_LIMIT, Failure, build_report_zip, environment, issue_body, issue_url


class ProblemReportDialog(Dialog):
    def __init__(
        self, parent: QWidget | None, failure: Failure, conn: CanConnection, log_text: str = "",
        dumps: dict[str, Path] | None = None,
    ) -> None:
        what = failure.title or "ContiTool"
        super().__init__(
            parent,
            tr("Что-то пошло не так", "Something went wrong"),
            tr(f"«{what}» — ошибка:", f"“{what}” failed:") if failure.message else "",
        )
        self.failure, self.conn, self.log_text, self.dumps = failure, conn, log_text, dumps or {}
        self.report_path: Path | None = None
        if failure.message:
            err = QLabel(failure.message.strip())
            err.setWordWrap(True)
            err.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            set_tone(err, "err")
            self.body.addWidget(err)
        self.body.addWidget(hint(tr(
            "Если причина непонятна, сообщите о проблеме на GitHub. ContiTool соберёт архив: журнал программы, файлы "
            "этой операции (без дампов памяти), журналы драйвера D-PDU и описание системы, — и откроет страницу нового "
            "issue с уже заполненным текстом. Останется перетащить архив в описание и дописать, что вы делали.",
            "If the cause is unclear, report it on GitHub. ContiTool collects an archive — the program log, the files of "
            "this operation (no memory dumps), the D-PDU driver logs and a system summary — and opens a new issue with "
            "the text filled in. Drag the archive into the description and add what you were doing.",
        )))
        note = Callout("warn")
        note.label.setText(tr(
            "Сырые журналы в архиве могут содержать идентификаторы блока и автомобиля — просмотрите архив перед "
            "публикацией.<br>Автору в личные сообщения не пишите: только Issues на GitHub.",
            "Raw logs in the archive may contain ECU and vehicle identifiers — review it before publishing.<br>"
            "Please do not message the author directly: use GitHub Issues only.",
        ))
        self.body.addWidget(note)
        self.chk_dumps = QCheckBox(tr("Приложить дампы памяти", "Attach the memory dumps"))
        self.body.addWidget(self.chk_dumps)
        dumps_note = hint(tr(
            "Загруженные в программе дампы и дампы этой операции (бэкапы перед записью, сверки). В них VIN, FAZIT, "
            "VCRN и данные SWaP — в публичном issue их увидит любой. Прикладывайте, только если без них не разобраться.",
            "The dumps loaded in the program and this operation's dumps (backups before a write, readbacks). They "
            "carry VIN, FAZIT, VCRN and SWaP data — anyone can see them in a public issue. Attach them only when the "
            "problem cannot be understood without.",
        ))
        dumps_note.setWordWrap(True)
        self.body.addWidget(dumps_note)
        self.lbl_status = hint()
        self.lbl_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_status.hide()
        self.body.addWidget(self.lbl_status)

        self.btn_create = button(tr("Создать отчёт…", "Create report…"), "PrimaryBtn", slot=self.create)
        self.finish(button(tr("Скопировать текст", "Copy text"), "GhostBtn", slot=self.copy_text),
                    ok=self.btn_create, cancel_text=tr("Закрыть", "Close"))

    def _env(self) -> dict[str, str]:
        return environment(self.conn.interface, self.conn.port, self.conn.title)

    def copy_text(self) -> None:
        QGuiApplication.clipboard().setText(issue_body(self.failure, self._env(), self.log_text))
        self._status(tr("Текст скопирован в буфер обмена.", "Text copied to the clipboard."))

    def create(self, dest: Path | None = None, *, open_browser: bool = True) -> Path | None:
        if dest is None:
            stamp = time.strftime("%Y%m%d_%H%M%S")
            chosen, _f = QFileDialog.getSaveFileName(
                self, tr("Сохранить отчёт", "Save report"), str(self.conn.out_dir / f"contitool_report_{stamp}.zip"), "ZIP (*.zip)"
            )
            if not chosen:
                return None
            dest = Path(chosen)
        env = self._env()
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self.report_path = build_report_zip(dest, self.failure, env, self.log_text, self.conn.out_dir,
                                                dumps=self.dumps if self.chk_dumps.isChecked() else None)
        except OSError as exc:
            self._status(tr(f"Не удалось сохранить архив: {exc}", f"Could not save the archive: {exc}"), "err")
            return None
        finally:
            QApplication.restoreOverrideCursor()
        size = dest.stat().st_size
        if size > GITHUB_ATTACH_LIMIT:
            self._status(tr(
                f"Архив сохранён: {dest}<br>Он {size / 2**20:.0f} МБ, а GitHub принимает до 25 МБ — создайте отчёт без дампов.",
                f"Archive saved: {dest}<br>It is {size / 2**20:.0f} MB and GitHub takes up to 25 MB — create the report without dumps.",
            ), "warn")
        else:
            self._status(tr(
                f"Архив сохранён и выделен в папке: {dest}<br>Перетащите его в описание issue на открывшейся странице GitHub.",
                f"Archive saved and selected in its folder: {dest}<br>Drag it into the issue description on the GitHub page that opened.",
            ), "ok")
        if open_browser:
            QDesktopServices.openUrl(QUrl(issue_url(self.failure, env, self.log_text)))
            _reveal(dest)
        return self.report_path

    def _status(self, text: str, tone: str = "") -> None:
        self.lbl_status.setText(text)
        set_tone(self.lbl_status, tone)
        self.lbl_status.show()
        self.fit_height()


def _reveal(path: Path) -> None:
    """Open the file's folder with the file selected, ready to drag into the browser."""
    try:
        if sys.platform == "win32":
            subprocess.Popen(["explorer", f"/select,{path}"])  # noqa: S603, S607
            return
        if sys.platform == "darwin":
            subprocess.Popen(["open", "-R", str(path)])  # noqa: S603, S607
            return
    except OSError:
        pass
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))
