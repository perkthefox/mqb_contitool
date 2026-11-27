"""Shown when the app starts: who should not use it, why not in a working car, and who answers for a bricked ECU."""

from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QCheckBox, QLabel, QWidget

from contitool import __version__
from contitool.gui.widgets.page import Callout, Dialog, button, run_dialog
from contitool.i18n import tr
from contitool.report import ISSUES_PAGE

_SETTING = "disclaimer/accepted_version"


class DisclaimerDialog(Dialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, tr("Прочитайте перед началом работы", "Read this before you start"), width=720)

        risk = Callout("err")
        risk.label.setText(tr(
            "<b>ContiTool читает и перезаписывает память ЭБУ MQB (J533, FPK_E / Kombi, BCM, MRR, ELV) напрямую.</b> Ошибка, обрыв связи или просадка "
            "питания во время записи могут необратимо вывести блок из строя («кирпич»).",
            "<b>ContiTool reads and rewrites VAG MQB ECU memory (J533, FPK_E / Kombi, BCM, MRR, ELV) directly.</b> A mistake, a dropped link or a "
            "power dip during a write can damage the ECU for good (a “brick”).",
        ))
        self.body.addWidget(risk)

        if "-" in __version__:
            testing = Callout("warn")
            testing.label.setText(tr(
                f"<b>Релиз-кандидат {__version__}:</b> это предварительная тестовая сборка, а не основной релиз. "
                "Часть функций может не работать, вести себя криво или быть сломана — особенно на новых блоках "
                "(FPK_E, Kombi VDD, BCM, MRR, ELV) и неподтверждённых версиях ПО. Обязательно сохраняйте полный бэкап до любых изменений!",
                f"<b>Release Candidate {__version__}:</b> this is an early preview build, not the main stable release. "
                "Features may not work, misbehave, or be broken — especially on newly added ECUs "
                "(FPK_E, Kombi VDD, BCM, MRR, ELV) and unverified software versions. Always save a full backup before making any changes!",
            ))
            self.body.addWidget(testing)

        self.body.addWidget(self._text(tr(
            "<b>Не используйте программу, если:</b><br>"
            "• не понимаете, для чего она нужна, или не работали с ODIS / VCTool;<br>"
            "• есть сомнения в исправности адаптера, проводки или питания;<br>"
            "• используется дешёвый китайский адаптер — он не считается безопасным.",
            "<b>Do NOT use this program if:</b><br>"
            "• you are unsure why you need it or lack experience with ODIS / VCTool;<br>"
            "• you have any doubt about the adapter, wiring, or power supply;<br>"
            "• you are using a cheap clone adapter — it is not considered safe.",
        )))

        self.body.addWidget(self._text(tr(
            "<b>Только на стенде.</b> Работайте со снятым блоком и стабилизированным питанием +12 В. "
            "В автомобиле просадка напряжения или сбой записи могут обездвижить машину и вывести блок из строя.",
            "<b>Bench use only.</b> Work with the ECU removed on a regulated +12 V supply. "
            "In a vehicle, a voltage sag or write dropout can immobilize the car and brick the ECU.",
        )))

        self.body.addWidget(self._text(tr(
            "<b>Ответственность.</b> Вы используете программу на свой страх и риск; автор не несёт ответственности "
            f'за повреждённый блок или автомобиль. Вопросы и баги — только через <a href="{ISSUES_PAGE}">GitHub Issues</a>.<br>'
            "Бесплатный инструмент, не для продажи, предоставляется «как есть» без гарантий.",
            "<b>Liability.</b> Use at your own risk; the author assumes no liability for a damaged ECU or car. "
            f'Report issues via <a href="{ISSUES_PAGE}">GitHub Issues</a> only (no direct messages).<br>'
            "Free community tool, not for sale, provided “as is” without warranty.",
        )))

        self.chk_agree = QCheckBox(tr(
            "Я прочитал(а) всё выше, понимаю риски и беру ответственность на себя",
            "I have read all of the above, understand the risks and take responsibility",
        ))
        self.chk_quiet = QCheckBox(tr("Не показывать до следующей версии", "Do not show again until the next version"))
        self.body.addWidget(self.chk_agree)
        self.body.addWidget(self.chk_quiet)

        self.btn_ok = button(tr("Продолжить", "Continue"), "PrimaryBtn", slot=self.accept)
        self.btn_ok.setEnabled(False)
        self.chk_agree.toggled.connect(self.btn_ok.setEnabled)
        self.finish(ok=self.btn_ok, cancel_text=tr("Выйти", "Quit"))

    @staticmethod
    def _text(html: str) -> QLabel:
        lbl = QLabel(html)
        lbl.setWordWrap(True)
        lbl.setOpenExternalLinks(True)
        return lbl

    def accept(self) -> None:
        if not self.chk_agree.isChecked():
            return
        if self.chk_quiet.isChecked():
            QSettings().setValue(_SETTING, __version__)
        super().accept()


def confirm_disclaimer(parent: QWidget | None = None) -> bool:
    """True when the user may go on: accepted now, or chose not to see it again for this version."""
    if str(QSettings().value(_SETTING, "")) == __version__:
        return True
    return bool(run_dialog(DisclaimerDialog(parent)))
