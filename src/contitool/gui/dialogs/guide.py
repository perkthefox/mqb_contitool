"""Bench reference: wiring diagrams (J533 T20 & Kombi T18), programmer rule, IKA keys, and FAQ."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QWidget,
)

from contitool.gui.widgets.page import Callout, Dialog, group_label, row
from contitool.gui.widgets.pinout_card import KombiPinoutCard, PinoutCard
from contitool.i18n import tr


def _text() -> QLabel:
    lbl = QLabel()
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.TextFormat.RichText)
    lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    return lbl


class GuideDialog(Dialog):
    """Everything someone needs before touching the ECU or cluster on the bench."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            tr("Справка", "Help"),
            tr(
                "Схемы подключения на стенде, чтение памяти и работа с ключами адаптации.",
                "Bench wiring diagrams, memory reading, and module pairing keys.",
            ),
            width=960,
        )
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        track = QFrame()
        track.setObjectName("ModeTrack")
        track_lay = QHBoxLayout(track)
        track_lay.setContentsMargins(2, 2, 2, 2)
        track_lay.setSpacing(2)

        self.pinout_stack = QStackedWidget()
        self.card_j533 = PinoutCard()
        self.card_kombi = KombiPinoutCard()
        self.pinout_stack.addWidget(self.card_j533)
        self.pinout_stack.addWidget(self.card_kombi)

        tabs = QButtonGroup(self)
        self.btn_tab_j533 = QPushButton(tr("Шлюз J533 (T20)", "J533 gateway (T20)"))
        self.btn_tab_kombi = QPushButton(tr("Приборная панель (T18)", "Instrument cluster (T18)"))
        for idx, b in enumerate((self.btn_tab_j533, self.btn_tab_kombi)):
            b.setObjectName("TabBtn")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _c=False, i=idx: self.pinout_stack.setCurrentIndex(i))
            tabs.addButton(b)
            track_lay.addWidget(b)

        # Auto-select Kombi tab if Kombi screen is currently open in the main window
        win = parent.window() if parent is not None else None
        kombi_active = bool(win is not None and getattr(getattr(win, "fpke_screen", None), "is_open", False))
        (self.btn_tab_kombi if kombi_active else self.btn_tab_j533).setChecked(True)
        self.pinout_stack.setCurrentIndex(1 if kombi_active else 0)

        self.body.addLayout(row(group_label(tr("СХЕМА ПОДКЛЮЧЕНИЯ НА СТЕНДЕ", "BENCH WIRING DIAGRAM")), 1, track))
        self.body.addWidget(self.pinout_stack)

        self.body.addWidget(group_label(tr("ЧТЕНИЕ ПРОГРАММАТОРОМ (ШЛЮЗ J533)", "READING WITH A PROGRAMMER (J533 GATEWAY)")))
        rule = Callout("err")
        rule.label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
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
        self.body.addWidget(rule)

        self.body.addWidget(group_label(tr("КЛЮЧ МОДУЛЯ (IKA)", "MODULE KEY (IKA)")))
        ika = _text()
        ika.setText(
            tr(
                "Адаптацию проверяет сам модуль — магнитола, приборная панель, усилитель и другие. "
                "Он сравнивает ответ шлюза со своим 16-байтным ключом <b>IKA</b>, поэтому ключ должен совпадать "
                "с обеих сторон.<br><br>"
                "<b>Ключ донора.</b> Прочитайте открытый ключ IKA из дампа самого модуля (например, считав панель приборов "
                "FPK_E по CAN в ContiTool) и укажите его при адаптации шлюза.<br>"
                "<b>Своя пара.</b> Нажмите «Сгенерировать» в окне адаптации и запишите один и тот же ключ "
                "и в шлюз, и в слот IKA модуля.<br><br>"
                "Не подходят 16 нулей (<code>00..00</code>) и строка <code>000000000000000000000000000000E5</code> — "
                "это заголовок зашифрованного контейнера, а не ключ.",
                "Pairing is enforced by the module itself — infotainment, instrument cluster, amplifier and others. "
                "It compares the gateway's answer against its own 16-byte <b>IKA</b> key, so the key must match "
                "on both sides.<br><br>"
                "<b>Donor key.</b> Read the plaintext IKA key from the module's own dump (for example by reading an "
                "FPK_E cluster over CAN in ContiTool) and enter it when binding the gateway.<br>"
                "<b>Your own pair.</b> Click “Generate” in the binding window and write the same key into both "
                "the gateway and the module's IKA slot.<br><br>"
                "All zeros (<code>00..00</code>) and the string <code>000000000000000000000000000000E5</code> are not "
                "keys — the latter is an encrypted container header.",
            )
        )
        self.body.addWidget(ika)

        self.body.addWidget(group_label(tr("ПОРЯДОК РАБОТЫ", "ORDER OF WORK")))
        order = _text()
        order.setText(
            tr(
                "1. Подключите блок по схеме выше и настройте адаптер.<br>"
                "2. Нажмите «Считать блок» — ContiTool автоматически определит по UDS шлюз J533 или панель приборов Kombi FPK_E.<br>"
                "3. Для шлюза J533 программа сохранит полную копию памяти и откроет её; изменения пишутся в копии файлов.<br>"
                "4. Для панели приборов Kombi FPK_E откроется отдельный экран чтения по нативному CAN и просмотра ключей IKA/CP, иммо и транспондеров.",
                "1. Wire the unit as shown above and set up the adapter.<br>"
                "2. Click “Read the ECU” — ContiTool automatically detects over UDS whether a J533 gateway or Kombi FPK_E cluster is connected.<br>"
                "3. For J533 gateways, ContiTool saves a full backup and opens it; edits go into copies without touching the original.<br>"
                "4. For Kombi FPK_E clusters, ContiTool opens the dedicated cluster screen for native CAN reading and IKA/CP, immo, and transponder inspection.",
            )
        )
        self.body.addWidget(order)

        self.body.addWidget(group_label(tr("ЧАСТЫЕ ВОПРОСЫ", "FAQ")))
        faq = _text()
        faq.setText(tr(
            "<b>Какой адаптер нужен для панели приборов Kombi FPK_E?</b><br>"
            "Только нативный CAN-адаптер (CANable / SLCAN / candleLight, SocketCAN, PCAN, Kvaser, Vector). "
            "Чтение панели приборов через VNCI / VAS 6154 (D-PDU / J2534) не поддерживается.<br><br>"
            "<b>VNCI не подключается к шлюзу, хотя драйвер поддерживается.</b><br>"
            "Переподключите адаптер или нажмите «Проверить связь» несколько раз подряд. При подключении драйвер D-PDU сам "
            "перепрошивает адаптер под свою версию (около 30 секунд), и ContiTool принимает это за ошибку связи CAN. "
            "Если не помогло — перезагрузите компьютер.<br><br>"
            "<b>Дешёвый китайский адаптер «работает» — значит, им можно пользоваться?</b><br>"
            "Нет. Любые дешёвые китайские адаптеры не считаются безопасными, даже если программа с ними «дружит». "
            "Адаптер за 2 доллара повышает шанс окирпичивания на 99,9 %.<br><br>"
            "<b>Во время первичного чтения связь оборвалась, и блок не выходит на связь.</b><br>"
            "Выключите зажигание на несколько секунд и включите снова, в крайнем случае снимите клемму аккумулятора. "
            "На столе — снимите питание +12 В на несколько секунд. И вообще, на живой машине лучше с этим не играть.<br><br>"
            "<b>Нужен ли ODIS, чтобы работать с VAS 6154 / VNCI на шлюзе J533?</b><br>"
            "Нет. Драйвер D-PDU 27.2 идёт вместе с ContiTool (папка <code>dpdu/</code> рядом с программой). В системе нужен "
            "только USB-драйвер самого адаптера — дополнение для VAS 6154 из пакета «VW D-PDU API»; сам ODIS не "
            "требуется.<br><br>"
            "<b>Как сообщить о проблеме?</b><br>"
            "После ошибки ContiTool сам предложит отчёт (или «Справка → Сообщить о проблеме…»): соберёт архив с журналами "
            "и откроет страницу нового issue на GitHub. В личные сообщения автору не пишите.",
            "<b>Which adapter is required for Kombi FPK_E instrument clusters?</b><br>"
            "Only a native CAN adapter (CANable / SLCAN / candleLight, SocketCAN, PCAN, Kvaser, Vector). "
            "Reading FPK_E via VNCI / VAS 6154 (D-PDU / J2534) is not supported.<br><br>"
            "<b>The VNCI does not connect to the gateway although the driver is supported.</b><br>"
            "Reconnect the adapter or press “Check link” a few times. On connect the D-PDU driver itself reflashes the "
            "adapter to its own version (about 30 seconds), and ContiTool takes that for a CAN link error. "
            "If that does not help, restart the computer.<br><br>"
            "<b>My cheap Chinese adapter “works” — so I can use it?</b><br>"
            "No. Cheap Chinese adapters are not considered safe, even if the program “gets along” with them. "
            "A $2 adapter raises the chance of a brick by 99.9%.<br><br>"
            "<b>The link dropped during the first read and the unit no longer answers.</b><br>"
            "Switch the ignition off for a few seconds and back on; as a last resort disconnect the battery terminal. "
            "On the bench, cut the +12 V supply for a few seconds.<br><br>"
            "<b>Do I need ODIS to use a VAS 6154 / VNCI on a J533 gateway?</b><br>"
            "No. D-PDU driver 27.2 comes with ContiTool (the <code>dpdu/</code> folder next to the program). The system only "
            "needs the adapter's own USB driver — the VAS 6154 add-on of the VW D-PDU API package; ODIS itself is not "
            "required.<br><br>"
            "<b>How do I report a problem?</b><br>"
            "After an error ContiTool offers a report itself (or Help → Report a problem…): it collects an archive with "
            "the logs and opens a new issue on GitHub. Please do not message the author directly.",
        ))
        self.body.addWidget(faq)
        self.body.addStretch(1)

        self.finish(cancel_text=tr("Закрыть", "Close"))
        self.resize(960, 720)
        self._fit_screen()
