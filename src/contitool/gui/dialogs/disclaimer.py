"""Shown when the app starts: who should not use it, why not in a working car, and who answers for a bricked ECU."""

from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QButtonGroup, QCheckBox, QHBoxLayout, QLabel, QPushButton, QWidget

from contitool import __version__
from contitool.gui.widgets.page import Callout, Dialog, button, run_dialog
from contitool.i18n import get_lang, set_lang, subscribe_lang_change, tr
from contitool.report import ISSUES_PAGE

_SETTING = "disclaimer/accepted_version"
_LANG_SETTING = "ui/language"


class DisclaimerDialog(Dialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, tr("Прочитайте перед началом работы", "Read this before you start"), width=720)

        # Inline RU / EN switcher right in the header so first-time users can pick a language before accepting.
        self._lang_buttons: dict[str, QPushButton] = {}
        lang_group = QButtonGroup(self)
        lang_wrap = QWidget()
        lang_lay = QHBoxLayout(lang_wrap)
        lang_lay.setContentsMargins(0, 0, 0, 0)
        lang_lay.setSpacing(0)
        for code, pos in (("ru", "left"), ("en", "right")):
            b = QPushButton(code.upper())
            b.setObjectName("SegBtn")
            b.setProperty("pos", pos)
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _c=False, c=code: self._select_lang(c))
            lang_group.addButton(b)
            lang_lay.addWidget(b)
            self._lang_buttons[code] = b
        self._title_row.addWidget(lang_wrap, 0, Qt.AlignmentFlag.AlignVCenter)

        self._risk = Callout("err")
        self.body.addWidget(self._risk)

        self._testing: Callout | None = None
        if "-" in __version__:
            self._testing = Callout("warn")
            self.body.addWidget(self._testing)

        self._lbl_dont = self._text("")
        self._lbl_bench = self._text("")
        self._lbl_liability = self._text("")
        self.body.addWidget(self._lbl_dont)
        self.body.addWidget(self._lbl_bench)
        self.body.addWidget(self._lbl_liability)

        self.chk_agree = QCheckBox()
        self.chk_quiet = QCheckBox()
        self.body.addWidget(self.chk_agree)
        self.body.addWidget(self.chk_quiet)

        self.btn_ok = button("", "PrimaryBtn", slot=self.accept)
        self.btn_ok.setEnabled(False)
        self.chk_agree.toggled.connect(self.btn_ok.setEnabled)

        self._retranslate(resize=False)
        self.finish(ok=self.btn_ok, cancel_text=tr("Выйти", "Quit"))
        self._unsub = subscribe_lang_change(lambda _l: self._retranslate(resize=True))

    @staticmethod
    def _select_lang(code: str) -> None:
        chosen = set_lang(code)
        QSettings().setValue(_LANG_SETTING, chosen)

    def _retranslate(self, *, resize: bool) -> None:
        title = tr("Прочитайте перед началом работы", "Read this before you start")
        self.setWindowTitle(title)
        self._lbl_title.setText(title)
        self._lang_buttons[get_lang()].setChecked(True)

        self._risk.label.setText(tr(
            "<b>ContiTool читает и перезаписывает память ЭБУ MQB (J533, FPK_E / Kombi, BCM, MRR, ELV) напрямую.</b> Ошибка, обрыв связи или просадка "
            "питания во время записи могут необратимо вывести блок из строя («кирпич»).",
            "<b>ContiTool reads and rewrites VAG MQB ECU memory (J533, FPK_E / Kombi, BCM, MRR, ELV) directly.</b> A mistake, a dropped link or a "
            "power dip during a write can damage the ECU for good (a “brick”).",
        ))
        if self._testing is not None:
            self._testing.label.setText(tr(
                f"<b>Релиз-кандидат {__version__}:</b> это предварительная тестовая сборка, а не основной релиз. "
                "Часть функций может не работать, вести себя криво или быть сломана — особенно на новых блоках "
                "(FPK_E, Kombi VDD, BCM, MRR, ELV) и неподтверждённых версиях ПО. Обязательно сохраняйте полный бэкап до любых изменений!",
                f"<b>Release Candidate {__version__}:</b> this is an early preview build, not the main stable release. "
                "Features may not work, misbehave, or be broken — especially on newly added ECUs "
                "(FPK_E, Kombi VDD, BCM, MRR, ELV) and unverified software versions. Always save a full backup before making any changes!",
            ))
        self._lbl_dont.setText(tr(
            "<b>Не используйте программу, если:</b><br>"
            "• не понимаете, для чего она нужна, или не работали с ODIS / VCTool;<br>"
            "• есть сомнения в исправности адаптера, проводки или питания;<br>"
            "• используется дешёвый китайский адаптер — он не считается безопасным.",
            "<b>Do NOT use this program if:</b><br>"
            "• you are unsure why you need it or lack experience with ODIS / VCTool;<br>"
            "• you have any doubt about the adapter, wiring, or power supply;<br>"
            "• you are using a cheap clone adapter — it is not considered safe.",
        ))
        self._lbl_bench.setText(tr(
            "<b>Только на стенде.</b> Работайте со снятым блоком и стабилизированным питанием +12 В. "
            "В автомобиле просадка напряжения или сбой записи могут обездвижить машину и вывести блок из строя.",
            "<b>Bench use only.</b> Work with the ECU removed on a regulated +12 V supply. "
            "In a vehicle, a voltage sag or write dropout can immobilize the car and brick the ECU.",
        ))
        self._lbl_liability.setText(tr(
            "<b>Ответственность.</b> Вы используете программу на свой страх и риск; автор не несёт ответственности "
            f'за повреждённый блок или автомобиль. Вопросы и баги — только через <a href="{ISSUES_PAGE}">GitHub Issues</a>.<br>'
            "Бесплатный инструмент, не для продажи, предоставляется «как есть» без гарантий.",
            "<b>Liability.</b> Use at your own risk; the author assumes no liability for a damaged ECU or car. "
            f'Report issues via <a href="{ISSUES_PAGE}">GitHub Issues</a> only (no direct messages).<br>'
            "Free community tool, not for sale, provided “as is” without warranty.",
        ))
        self.chk_agree.setText(tr(
            "Я прочитал(а) всё выше, понимаю риски и беру ответственность на себя",
            "I have read all of the above, understand the risks and take responsibility",
        ))
        self.chk_quiet.setText(tr("Не показывать до следующей версии", "Do not show again until the next version"))
        self.btn_ok.setText(tr("Продолжить", "Continue"))
        if self._btn_cancel is not None:
            self._btn_cancel.setText(tr("Выйти", "Quit"))
        if resize:
            self.fit_height()

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

    def done(self, result: int) -> None:
        self._unsub()
        super().done(result)


def confirm_disclaimer(parent: QWidget | None = None) -> bool:
    """True when the user may go on: accepted now, or chose not to see it again for this version."""
    if str(QSettings().value(_SETTING, "")) == __version__:
        return True
    return bool(run_dialog(DisclaimerDialog(parent)))
