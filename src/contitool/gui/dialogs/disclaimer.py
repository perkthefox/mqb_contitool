"""Shown when the app starts: who should not use it, why not in a working car, and who answers for a bricked ECU."""

from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QButtonGroup, QCheckBox, QHBoxLayout, QLabel, QPushButton, QWidget

from contitool import __version__
from contitool.gui.widgets.page import Callout, Dialog, button, run_dialog
from contitool.i18n import get_lang, set_lang, subscribe_lang_change, tr
from contitool.report import ISSUES_PAGE

_SETTING = "disclaimer/accepted_version"


class DisclaimerDialog(Dialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, "", width=720)

        self._risk = Callout("err")
        self._usage = self._text()
        self._bench = self._text()
        self._liability = self._text()
        self.chk_agree = QCheckBox()
        self.chk_quiet = QCheckBox()
        for widget in (self._risk, self._usage, self._bench, self._liability, self.chk_agree, self.chk_quiet):
            self.body.addWidget(widget)

        language = QWidget()
        lang_layout = QHBoxLayout(language)
        lang_layout.setContentsMargins(0, 0, 0, 0)
        lang_layout.setSpacing(0)
        lang_group = QButtonGroup(language)
        self._lang_buttons: dict[str, QPushButton] = {}
        for code, pos in (("ru", "left"), ("en", "right")):
            b = button(code.upper(), "SegBtn")
            b.setProperty("pos", pos)
            b.setCheckable(True)
            b.setAutoDefault(False)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _checked, lang=code: set_lang(lang))
            lang_group.addButton(b)
            lang_layout.addWidget(b)
            self._lang_buttons[code] = b

        self.btn_ok = button("", "PrimaryBtn", slot=self.accept)
        self.btn_ok.setEnabled(False)
        self.chk_agree.toggled.connect(self.btn_ok.setEnabled)
        self._btn_quit = self.finish(language, ok=self.btn_ok)
        self._retranslate(get_lang())
        subscribe_lang_change(self._retranslate)

    def _retranslate(self, lang: str) -> None:
        self._lang_buttons[lang].setChecked(True)
        title = tr("Прочитайте перед началом работы", "Read this before you start")
        self.setWindowTitle(title)
        self.lbl_title.setText(title)

        self._risk.label.setText(tr(
            "<b>ContiTool читает и перезаписывает память шлюза J533 напрямую.</b> Ошибка, обрыв связи или просадка "
            "питания во время записи могут необратимо вывести блок из строя («кирпич»).",
            "<b>ContiTool reads and rewrites the memory of the J533 gateway directly.</b> A mistake, a dropped link or a "
            "power dip during a write can damage the ECU for good (a “brick”).",
        ))
        self._usage.setText(tr(
            "<b>Этой программой пользоваться НЕ НУЖНО, если:</b><br>"
            "• вы не понимаете, зачем она вам «нужна»;<br>"
            "• вы не умеете работать с ODIS или VCTool;<br>"
            "• есть ХОТЬ КАКИЕ-ТО, даже малейшие подозрения на неисправность адаптера, проводки или питания;<br>"
            "• у вас дешёвый китайский адаптер — даже если программа с ним «дружит», безопасным он не считается.",
            "<b>Do NOT use this program if:</b><br>"
            "• you do not know why you “need” it;<br>"
            "• you cannot work with ODIS or VCTool;<br>"
            "• you have ANY, even the slightest doubt that the adapter, the wiring or the power supply is sound;<br>"
            "• you have a cheap Chinese adapter — even if the program “gets along” with it, it is not considered safe.",
        ))

        self._bench.setText(tr(
            "<b>Почему не в рабочей машине.</b> Работайте со снятым шлюзом на столе и со стабилизированным блоком питания. "
            "В машине шлюз связывает все блоки между собой: пока он в загрузчике или если запись сорвётся, блоки "
            "перестают видеть друг друга — машина может не завестись и не поехать, и вы останетесь с ней там, где "
            "стоите. Кроме того, за время записи напряжение бортсети проседает, а любая просадка или обрыв во время "
            "записи — прямой путь к кирпичу.",
            "<b>Why not in a working car.</b> Work with the gateway removed, on a bench, with a regulated power supply. "
            "In a car the gateway connects all the modules: while it sits in its bootloader, or if a write fails, the "
            "modules stop seeing each other — the car may not start or drive, and you are stuck wherever it stands. "
            "Besides, the car's voltage sags during a long write, and any dip or dropout during a write is a straight "
            "road to a brick.",
        ))

        self._liability.setText(tr(
            "<b>Ответственность.</b> Если вы подключаете программу к автомобилю, вы делаете это на свой страх и риск: "
            "автор не несёт <b>никакой</b> ответственности за испорченный блок или автомобиль. Писать об этом автору "
            f'в личные сообщения не нужно — <a href="{ISSUES_PAGE}">создайте Issue на GitHub</a> и ждите ответа.<br>'
            "Программа бесплатная, не для продажи и предоставляется «как есть», без каких-либо гарантий.",
            "<b>Liability.</b> If you connect the program to a car, you do it at your own risk: the author takes "
            "<b>no</b> responsibility whatsoever for a damaged ECU or car. Do not message the author about it — "
            f'<a href="{ISSUES_PAGE}">open an issue on GitHub</a> and wait for an answer.<br>'
            "The program is free, not for sale, and provided “as is”, without warranty of any kind.",
        ))

        self.chk_agree.setText(tr(
            "Я прочитал(а) всё выше, понимаю риски и беру ответственность на себя",
            "I have read all of the above, understand the risks and take responsibility",
        ))
        self.chk_quiet.setText(tr("Не показывать до следующей версии", "Do not show again until the next version"))
        self.btn_ok.setText(tr("Продолжить", "Continue"))
        self._btn_quit.setText(tr("Выйти", "Quit"))
        self.fit_height()
        self._scroll.verticalScrollBar().setValue(0)

    @staticmethod
    def _text() -> QLabel:
        lbl = QLabel()
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
