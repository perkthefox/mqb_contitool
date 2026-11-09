"""Asks GitHub for the newest release in the background and offers it.

QtNetwork rather than urllib: it takes the system's certificate store (Schannel, Keychain), which a frozen Python
on macOS does not find on its own."""

from __future__ import annotations

import json
import time

from PySide6.QtCore import QObject, QSettings, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest
from PySide6.QtWidgets import QMessageBox, QWidget

from contitool import __version__
from contitool.i18n import tr
from contitool.updates import CHECK_EVERY, RELEASES_API, Release, newer_release

_LAST, _SKIP = "updates/last_check", "updates/skip"


class UpdateChecker(QObject):
    def __init__(self, window: QWidget) -> None:
        super().__init__(window)
        self._win = window
        self._net = QNetworkAccessManager(self)
        self._busy = False

    def check(self, *, manual: bool) -> None:
        """`manual`: from the menu — always asks, and says so when there is nothing new or GitHub cannot be reached.
        Otherwise at most once per CHECK_EVERY, silent unless a release the user has not skipped is out."""
        if self._busy or (not manual and time.time() - float(QSettings().value(_LAST, 0) or 0) < CHECK_EVERY):
            return
        self._busy = True
        req = QNetworkRequest(QUrl(RELEASES_API))
        req.setRawHeader(b"Accept", b"application/vnd.github+json")
        req.setRawHeader(b"User-Agent", f"ContiTool/{__version__}".encode())
        req.setTransferTimeout(10_000)
        reply = self._net.get(req)
        reply.finished.connect(lambda: self._done(reply, manual))

    def _done(self, reply: QNetworkReply, manual: bool) -> None:
        self._busy = False
        reply.deleteLater()
        try:
            if reply.error() != QNetworkReply.NetworkError.NoError:
                raise ValueError(reply.errorString())
            data = json.loads(bytes(reply.readAll().data()))
        except ValueError as exc:
            if manual:
                QMessageBox.warning(self._win, tr("Проверка обновлений", "Checking for updates"),
                                    tr(f"Не удалось связаться с GitHub: {exc}", f"Could not reach GitHub: {exc}"))
            return
        QSettings().setValue(_LAST, time.time())
        release = newer_release(data, __version__)
        if release is None:
            if manual:
                QMessageBox.information(self._win, tr("Проверка обновлений", "Checking for updates"),
                                        tr(f"У вас последняя версия ContiTool ({__version__}).",
                                           f"You have the latest ContiTool ({__version__})."))
            return
        if manual or QSettings().value(_SKIP, "") != release.version:
            self._offer(release)

    def _offer(self, release: Release) -> None:
        box = QMessageBox(self._win)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle(tr("Обновление ContiTool", "ContiTool update"))
        box.setText(tr(f"Вышла ContiTool {release.version} — у вас {__version__}.",
                       f"ContiTool {release.version} is out — you have {__version__}."))
        box.setInformativeText(tr(
            "Скачайте архив, распакуйте его в новую папку и запускайте оттуда: настройки подхватятся сами.",
            "Download the archive, unpack it into a new folder and run it from there: your settings carry over.",
        ))
        download = box.addButton(tr("Скачать", "Download"), QMessageBox.ButtonRole.AcceptRole)
        notes = box.addButton(tr("Что нового", "What's new"), QMessageBox.ButtonRole.ActionRole)
        skip = box.addButton(tr("Пропустить эту версию", "Skip this version"), QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(tr("Позже", "Later"), QMessageBox.ButtonRole.RejectRole)
        box.exec()
        clicked = box.clickedButton()
        if clicked is download:
            QDesktopServices.openUrl(QUrl(release.download))
        elif clicked is notes:
            QDesktopServices.openUrl(QUrl(release.page))
        elif clicked is skip:
            QSettings().setValue(_SKIP, release.version)
