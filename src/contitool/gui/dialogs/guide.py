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

from contitool.gui.widgets.page import Callout, Dialog, Section, group_label, row
from contitool.gui.widgets.pinout_card import ElvPinoutCard, KombiPinoutCard, PinoutCard
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
        self.card_elv = ElvPinoutCard()
        self.pinout_stack.addWidget(self.card_j533)
        self.pinout_stack.addWidget(self.card_kombi)
        self.pinout_stack.addWidget(self.card_elv)

        tabs = QButtonGroup(self)
        self.btn_tab_j533 = QPushButton(tr("Шлюз J533 (T20)", "J533 gateway (T20)"))
        self.btn_tab_kombi = QPushButton(tr("Приборная панель (T18)", "Instrument cluster (T18)"))
        self.btn_tab_elv = QPushButton(tr("Защёлка руля ELV (T4)", "Steering lock ELV (T4)"))
        for idx, b in enumerate((self.btn_tab_j533, self.btn_tab_kombi, self.btn_tab_elv)):
            b.setObjectName("TabBtn")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _c=False, i=idx: self.pinout_stack.setCurrentIndex(i))
            tabs.addButton(b)
            track_lay.addWidget(b)

        # Auto-select the tab matching the currently active ECU in the main window (fpke -> T18; elv -> T4; j533/bcm/mrr -> T20)
        win = parent.window() if parent is not None else None
        active_screen = getattr(win, "_active_screen", "") if win is not None else ""
        tab_idx = 0
        if active_screen == "fpke":
            tab_idx = 1
        elif active_screen == "elv":
            tab_idx = 2
        elif active_screen in ("j533", "bcm", "mrr", "bus"):
            tab_idx = 0
        elif active_screen == "start":
            start_scr = getattr(win, "start_screen", None)
            sel_fn = getattr(start_scr, "selected_target_kind", None)
            sel_kind = sel_fn() if callable(sel_fn) else ""
            if sel_kind == "fpke":
                tab_idx = 1
            elif sel_kind == "elv":
                tab_idx = 2
        else:
            is_fpke_fn = getattr(win, "_is_fpke_active", None)
            if callable(is_fpke_fn) and is_fpke_fn():
                tab_idx = 1
        (self.btn_tab_j533, self.btn_tab_kombi, self.btn_tab_elv)[tab_idx].setChecked(True)
        self.pinout_stack.setCurrentIndex(tab_idx)

        self.body.addLayout(row(group_label(tr("СХЕМА ПОДКЛЮЧЕНИЯ НА СТЕНДЕ", "BENCH WIRING DIAGRAM")), 1, track))
        self.body.addWidget(self.pinout_stack)

        self.body.addWidget(group_label(tr("ЧТЕНИЕ ПРОГРАММАТОРОМ (ШЛЮЗ J533)", "PROGRAMMER READ (J533 GATEWAY)")))
        rule = Callout("err")
        rule.label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        rule.label.setText(
            tr(
                "<b>Выбирайте профиль с DataFlash 64 КБ.</b> На корпусе указано <b>R7F7010343AFP</b>, но внутри "
                "<b>64 КБ DataFlash</b> (ключи и функции лежат в <b>0xC000..0xFFFF</b>). Профиль R7F7010343AFP читает только 32 КБ — "
                "выбирайте пресет <b>3Q0907530</b> или <b>R7F7010543 / R7F7010563</b>. По CAN всегда читаются все 64 КБ.",
                "<b>Pick a 64 KB DataFlash profile.</b> The chip is marked <b>R7F7010343AFP</b>, but holds "
                "<b>64 KB DataFlash</b> (keys and features live in <b>0xC000..0xFFFF</b>). R7F7010343AFP reads only 32 KB — "
                "use preset <b>3Q0907530</b> or <b>R7F7010543 / R7F7010563</b>. Over CAN all 64 KB are always read.",
            )
        )
        self.body.addWidget(rule)

        def _card_block(title_ru: str, title_en: str, html_ru: str, html_en: str) -> Section:
            sec = Section()
            sec.set_text(tr(title_ru, title_en))
            lbl = _text()
            lbl.setText(tr(html_ru, html_en))
            sec.body.addWidget(lbl)
            return sec

        self.body.addWidget(
            _card_block(
                "Ключ адаптации модуля (IKA)",
                "Module pairing key (IKA)",
                "Модуль сверяет ответ шлюза со своим 16-байтным ключом <b>IKA</b> — ключ должен совпадать с обеих сторон:<br>"
                "• <b>Ключ донора:</b> считайте открытый IKA из дампа модуля (например, FPK_E по CAN) и введите в шлюз.<br>"
                "• <b>Своя пара:</b> сгенерируйте ключ и запишите его в оба блока.<br>"
                "• Не подходят <code>00..00</code> и <code>000000000000000000000000000000E5</code> (заголовок контейнера).",
                "The module checks the gateway against its own 16-byte <b>IKA</b> key — both sides must match:<br>"
                "• <b>Donor key:</b> read plaintext IKA from the module's dump (e.g. FPK_E over CAN) and enter it in J533.<br>"
                "• <b>Custom pair:</b> generate a key and write it to both units.<br>"
                "• <code>00..00</code> and <code>000000000000000000000000000000E5</code> (container header) are not valid keys.",
            )
        )

        self.body.addWidget(
            _card_block(
                "Порядок работы",
                "Workflow",
                "1. Подключите блок по схеме выше и выберите адаптер.<br>"
                "2. Нажмите «Сканировать шину» или «Считать блок» — тип блока (J533 / FPK_E / BCM / 13 ACC / 2B ELV) определится автоматически.<br>"
                "3. Исходные дампы не перезаписываются — все правки идут в рабочую копию.",
                "1. Wire the unit as shown above and configure your adapter.<br>"
                "2. Click “Scan CAN bus” or “Read ECU” — J533 / FPK_E / BCM / 13 ACC / 2B ELV are detected automatically.<br>"
                "3. Original backups are never overwritten — all edits go into working copies.",
            )
        )

        self.body.addWidget(
            _card_block(
                "Частые вопросы",
                "FAQ",
                "<b>Адаптер для FPK_E:</b> только нативный CAN (CANable / SLCAN / candleLight, SocketCAN, PCAN, Kvaser, Vector) — или через RAM-мост шлюза J533.<br><br>"
                "<b>VNCI не подключается к шлюзу:</b> драйвер D-PDU перепрошивает VCI (~30 с) при первом подключении — повторите «Проверить связь».<br><br>"
                "<b>Обрыв связи при чтении:</b> снимите питание +12 В на несколько секунд и подайте снова.<br><br>"
                "<b>Нужен ли ODIS для VAS 6154 / VNCI?</b> Нет — драйвер D-PDU 27.2 встроен в ContiTool, нужен только USB-драйвер адаптера.<br><br>"
                "<b>Сообщить об ошибке:</b> «Справка → Сообщить о проблеме…» — создаст архив логов и откроет GitHub Issue.",
                "<b>Adapter for FPK_E:</b> native CAN (CANable / SLCAN / candleLight, SocketCAN, PCAN, Kvaser, Vector) — or via the J533 RAM-Bridge.<br><br>"
                "<b>VNCI fails to connect:</b> D-PDU reflashes the VCI (~30 s) on first connect — click “Check link” again.<br><br>"
                "<b>Link dropped during read:</b> cycle +12 V power off for a few seconds and back on.<br><br>"
                "<b>Is ODIS needed for VAS 6154 / VNCI?</b> No — D-PDU driver 27.2 is bundled; only the adapter USB driver is needed.<br><br>"
                "<b>Report a bug:</b> Help → Report a problem… builds a log archive and opens a GitHub Issue.",
            )
        )
        self.body.addStretch(1)

        self.finish(cancel_text=tr("Закрыть", "Close"))
        self.resize(960, 720)
        self._fit_screen()
