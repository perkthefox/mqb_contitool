"""Bench reference: wiring, the 64 KB programmer rule, and where the module key comes from."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QScrollArea, QVBoxLayout, QWidget

from contitool.gui.widgets.page import Callout, Dialog, group_label
from contitool.gui.widgets.pinout_card import PinoutCard
from contitool.i18n import tr


def _text() -> QLabel:
    lbl = QLabel()
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.TextFormat.RichText)
    return lbl


class GuideDialog(Dialog):
    """Everything someone needs before touching the ECU on the bench."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            tr("Памятка по стенду", "Bench guide"),
            tr(
                "Как подключить шлюз по Diagnosis CAN, откуда берётся ключ модуля и как работать с внешними дампами.",
                "How to wire the gateway over Diagnosis CAN, where the module key comes from, and how to handle external dumps.",
            ),
            width=1200,  # wide enough for the T20 diagram and its legend
        )
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QScrollArea.Shape.NoFrame)
        content = QWidget()
        area.setWidget(content)
        body = QVBoxLayout(content)
        body.setContentsMargins(0, 0, 10, 0)
        body.setSpacing(14)

        body.addWidget(PinoutCard())

        body.addWidget(group_label(tr("ЧТЕНИЕ ПРОГРАММАТОРОМ", "READING WITH A PROGRAMMER")))
        rule = Callout("err")
        rule.label.setText(
            tr(
                "<b>Выбирайте профиль с DataFlash 64 КБ.</b><br>"
                "На корпусе микроконтроллера шлюзов 3Q0 907 530 указано <b>R7F7010343AFP</b>, но внутри "
                "распаяны полные <b>64 КБ DataFlash (65 536 байт)</b>. Ключи модулей и данные функций лежат "
                "в верхней половине — <b>0xC000..0xFFFF</b>.<br>"
                "Профиль R7F7010343AFP читает только первые 32 КБ, и они теряются. Выбирайте пресет блока "
                "<b>3Q0907530</b> или профиль <b>R7F7010543 / R7F7010563</b>.<br>"
                "При чтении по CAN ContiTool всегда считывает все 64 КБ.",
                "<b>Pick a profile with 64 KB DataFlash.</b><br>"
                "3Q0 907 530 microcontrollers are marked <b>R7F7010343AFP</b>, but the silicon carries a full "
                "<b>64 KB DataFlash (65,536 bytes)</b>. Module keys and feature data live in the upper half — "
                "<b>0xC000..0xFFFF</b>.<br>"
                "The R7F7010343AFP profile reads only the first 32 KB and loses them. Use the <b>3Q0907530</b> "
                "preset or profile <b>R7F7010543 / R7F7010563</b>.<br>"
                "Reading over CAN, ContiTool always takes all 64 KB.",
            )
        )
        body.addWidget(rule)

        body.addWidget(group_label(tr("КЛЮЧ МОДУЛЯ (IKA)", "MODULE KEY (IKA)")))
        ika = _text()
        ika.setText(
            tr(
                "Адаптацию проверяет сам модуль — магнитола, приборная панель, усилитель и другие. "
                "Он сравнивает ответ шлюза со своим 16-байтным ключом <b>IKA</b>, поэтому ключ должен совпадать "
                "с обеих сторон.<br><br>"
                "<b>Ключ донора.</b> Прочитайте открытый ключ IKA из дампа самого модуля и укажите его при адаптации.<br>"
                "<b>Своя пара.</b> Нажмите «Сгенерировать» в окне адаптации и запишите один и тот же ключ "
                "и в шлюз, и в слот IKA модуля.<br><br>"
                "Не подходят 16 нулей (<code>00..00</code>) и строка <code>000000000000000000000000000000E5</code> — "
                "это заголовок зашифрованного контейнера, а не ключ.",
                "Pairing is enforced by the module itself — infotainment, instrument cluster, amplifier and others. "
                "It compares the gateway's answer against its own 16-byte <b>IKA</b> key, so the key must match "
                "on both sides.<br><br>"
                "<b>Donor key.</b> Read the plaintext IKA key from the module's own dump and enter it when binding.<br>"
                "<b>Your own pair.</b> Click “Generate” in the binding window and write the same key into both "
                "the gateway and the module's IKA slot.<br><br>"
                "All zeros (<code>00..00</code>) and the string <code>000000000000000000000000000000E5</code> are not "
                "keys — the latter is an encrypted container header.",
            )
        )
        body.addWidget(ika)

        body.addWidget(group_label(tr("ПОРЯДОК РАБОТЫ", "ORDER OF WORK")))
        order = _text()
        order.setText(
            tr(
                "1. Подключите блок по схеме выше и настройте адаптер.<br>"
                "2. Считайте блок — ContiTool сохранит полную копию памяти и откроет её.<br>"
                "3. Внесите нужные изменения: они пишутся в копии файлов, оригинал бэкапа не трогается.<br>"
                "4. Нажмите «Записать в блок». Каждая записываемая область сначала читается из блока, после записи — проверяется чтением.<br><br>"
                "Все три области памяти (<b>CodeFlash</b> включая область загрузчика, <b>DataFlash</b> 64 КБ и <b>Uflash</b> 32 КБ) "
                "читаются и записываются по CAN, программатор не нужен.",
                "1. Wire the ECU as shown above and set up the adapter.<br>"
                "2. Read the ECU — ContiTool saves a full memory copy and opens it.<br>"
                "3. Make your changes: they go into copies of the files, the backup itself is never touched.<br>"
                "4. Click “Write to ECU”. Each area to be written is read from the ECU first and verified by reading it back after.<br><br>"
                "All three memory regions (<b>CodeFlash</b> including boot blocks, <b>DataFlash</b> 64 KB, and <b>Uflash</b> 32 KB) "
                "are read and written over CAN; no programmer is needed.",
            )
        )
        body.addWidget(order)

        body.addWidget(group_label(tr("ЧАСТЫЕ ВОПРОСЫ", "FAQ")))
        faq = _text()
        faq.setText(tr(
            "<b>VNCI не подключается, хотя драйвер поддерживается.</b><br>"
            "Переподключите адаптер или нажмите «Проверить связь» несколько раз подряд. При подключении драйвер D-PDU сам "
            "перепрошивает адаптер под свою версию (около 30 секунд), и ContiTool принимает это за ошибку связи CAN. "
            "Если не помогло — перезагрузите компьютер.<br><br>"
            "<b>Дешёвый китайский адаптер «работает» — значит, им можно пользоваться?</b><br>"
            "Нет. Любые дешёвые китайские адаптеры не считаются безопасными, даже если программа с ними «дружит». "
            "Адаптер за 2 доллара повышает шанс окирпичивания на 99,9 %.<br><br>"
            "<b>Во время первичного чтения связь оборвалась, и шлюз не выходит на связь.</b><br>"
            "Выключите зажигание на несколько секунд и включите снова, в крайнем случае снимите клемму аккумулятора. "
            "На столе — снимите питание +12 В на несколько секунд. И вообще, на живой машине лучше с этим не играть.<br><br>"
            "<b>Нужен ли ODIS, чтобы работать с VAS 6154 / VNCI?</b><br>"
            "Нет. Драйвер D-PDU 27.2 идёт вместе с ContiTool (папка <code>dpdu/</code> рядом с программой). В системе нужен "
            "только USB-драйвер самого адаптера — дополнение для VAS 6154 из пакета «VW D-PDU API»; сам ODIS не "
            "требуется.<br><br>"
            "<b>На компьютере несколько драйверов D-PDU — какой возьмёт программа?</b><br>"
            "Все найденные показываются отдельными строками в окне «Подключение» с версией каждого. По умолчанию выбирается "
            "драйвер 27.2 из комплекта ContiTool, но можно выбрать любой другой — выбор запоминается. На драйверах 30 и новее "
            "работа сейчас нестабильна: адаптер зависает посреди прошивки по UDS, поэтому для них нужна отдельная "
            "галочка.<br><br>"
            "<b>Драйвер перепрошивает адаптер — это нормально?</b><br>"
            "Да. При подключении драйвер D-PDU сам записывает в VAS 6154 / VNCI прошивку своей версии (около 30 секунд) — "
            "дождитесь окончания и не отключайте адаптер. Это безопасно: ODIS при следующем подключении так же запишет в "
            "адаптер свою версию. Пока работает ContiTool, ODIS и VCTool должны быть закрыты.<br><br>"
            "<b>Нужен драйвер другой версии.</b><br>"
            "Скопируйте папку установленного драйвера в <code>dpdu/</code> рядом с ContiTool, к лежащей там "
            "<code>VW_PDUAPI_27.2</code> — программа найдёт её сама. Запись в реестр и права администратора не нужны, нужна "
            "64-разрядная сборка.<br><br>"
            "<b>Как сообщить о проблеме?</b><br>"
            "После ошибки ContiTool сам предложит отчёт (или «Справка → Сообщить о проблеме…»): соберёт архив с журналами "
            "и откроет страницу нового issue на GitHub. В личные сообщения автору не пишите.",
            "<b>The VNCI does not connect although the driver is supported.</b><br>"
            "Reconnect the adapter or press “Check link” a few times. On connect the D-PDU driver itself reflashes the "
            "adapter to its own version (about 30 seconds), and ContiTool takes that for a CAN link error. "
            "If that does not help, restart the computer.<br><br>"
            "<b>My cheap Chinese adapter “works” — so I can use it?</b><br>"
            "No. Cheap Chinese adapters are not considered safe, even if the program “gets along” with them. "
            "A $2 adapter raises the chance of a brick by 99.9%.<br><br>"
            "<b>The link dropped during the first read and the gateway no longer answers.</b><br>"
            "Switch the ignition off for a few seconds and back on; as a last resort disconnect the battery terminal. "
            "On the bench, cut the +12 V supply for a few seconds. And in general, better not play with this on a live car.<br><br>"
            "<b>Do I need ODIS to use a VAS 6154 / VNCI?</b><br>"
            "No. D-PDU driver 27.2 comes with ContiTool (the <code>dpdu/</code> folder next to the program). The system only "
            "needs the adapter's own USB driver — the VAS 6154 add-on of the VW D-PDU API package; ODIS itself is not "
            "required.<br><br>"
            "<b>Several D-PDU drivers are installed — which one does ContiTool use?</b><br>"
            "Every one it finds is its own row in the Connection window with its version. The driver 27.2 that comes with "
            "ContiTool is picked by default, but you can choose any other and the choice is remembered. On drivers 30 and "
            "newer work is unstable at the moment: the adapter hangs partway through a UDS flash, so those need a separate "
            "tick.<br><br>"
            "<b>The driver reflashes the adapter — is that normal?</b><br>"
            "Yes. On connect the D-PDU driver itself writes firmware of its version into the VAS 6154 / VNCI (about 30 "
            "seconds) — let it finish and do not unplug the adapter. This is safe: ODIS writes its own version back into the "
            "adapter the next time it connects. ODIS and VCTool must stay closed while ContiTool is working.<br><br>"
            "<b>I need a driver of another version.</b><br>"
            "Copy the installed driver's folder into <code>dpdu/</code> next to ContiTool, beside the "
            "<code>VW_PDUAPI_27.2</code> that is there — it is found automatically. No registry entry and no administrator "
            "rights needed; it must be the 64-bit build.<br><br>"
            "<b>How do I report a problem?</b><br>"
            "After an error ContiTool offers a report itself (or Help → Report a problem…): it collects an archive with "
            "the logs and opens a new issue on GitHub. Please do not message the author directly.",
        ))
        body.addWidget(faq)
        body.addStretch(1)

        self.body.addWidget(area, 1)
        self.finish(cancel_text=tr("Закрыть", "Close"))
        self.resize(1200, 780)
