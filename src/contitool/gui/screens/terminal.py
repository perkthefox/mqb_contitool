"""CAN terminal: send your own CAN frames or UDS requests through the adapter and watch the bus."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import time

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSettings, QSortFilterProxyModel, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from contitool.gui import theme
from contitool.gui.can_session import CanSession, TraceRow, parse_hex, parse_id
from contitool.gui.connection import CanConnection, ConnectionDialog, ensure_ready
from contitool.gui.theme import mono_font, set_tone
from contitool.gui.widgets.page import Section, button, hint, run_dialog, vdivider
from contitool.gui.worker import OperationRunner
from contitool.i18n import subscribe_lang_change, tr
from contitool.report import Failure

BITRATES = (125_000, 250_000, 500_000, 1_000_000)
_HISTORY_MAX = 20


def _uds_presets() -> list[str]:
    return [
        "10 03  # " + tr("расширенная сессия", "extended session"),
        "3E 00  # TesterPresent",
        "22 F1 87  # " + tr("номер детали", "part number"),
        "22 F1 89  # " + tr("версия ПО", "software version"),
        "22 F1 8C  # " + tr("серийный номер", "serial number"),
        "22 F1 90  # VIN",
        "19 02 FF  # " + tr("ошибки (DTC)", "trouble codes (DTC)"),
    ]


class TraceModel(QAbstractTableModel):
    """Everything seen in this session, oldest first. Trimmed in chunks once it grows past CAP."""

    CAP = 20_000

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.rows: list[TraceRow] = []

    @staticmethod
    def headers() -> list[str]:
        return [tr("Время, с", "Time, s"), tr("Тип", "Type"), "ID", "DLC", tr("Данные", "Data"), tr("Примечание", "Note")]

    @staticmethod
    def cells(r: TraceRow) -> list[str]:
        kind = {
            "rx": "Rx",
            "tx": "Tx",
            "uds-req": "UDS →",
            "uds-resp": "UDS ←",
            "error": tr("Ошибка", "Error"),
        }[r.kind]
        ident = "" if r.arb_id is None else (f"{r.arb_id:08X}" if r.extended else f"{r.arb_id:03X}")
        dlc = "" if r.kind == "error" else str(len(r.data))
        return [f"{r.t:.3f}", kind, ident, dlc, r.data.hex(" ").upper(), r.note]

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008, N802 (Qt override)
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008, N802 (Qt override)
        return 0 if parent.isValid() else 6

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.headers()[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        r = self.rows[index.row()]
        col = index.column()
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return self.cells(r)[col]
        if role == Qt.ItemDataRole.ForegroundRole:
            if col == 0:
                return QColor(theme.TEXT_MUTED)
            if r.kind == "error":
                return QColor(theme.ERR)
            if col == 5:
                if r.kind == "uds-resp":
                    return QColor(theme.WARN if r.data[:1] == b"\x7f" else theme.OK)
                return QColor(theme.TEXT_MUTED)
            return QColor({"tx": theme.INFO, "uds-req": theme.CAN, "uds-resp": theme.CAN}.get(r.kind, theme.TEXT))
        if role == Qt.ItemDataRole.TextAlignmentRole and col in (0, 3):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def append(self, new: list[TraceRow]) -> None:
        first = len(self.rows)
        self.beginInsertRows(QModelIndex(), first, first + len(new) - 1)
        self.rows.extend(new)
        self.endInsertRows()
        if len(self.rows) > self.CAP:
            drop = len(self.rows) - self.CAP + self.CAP // 4
            self.beginRemoveRows(QModelIndex(), 0, drop - 1)
            del self.rows[:drop]
            self.endRemoveRows()

    def clear(self) -> None:
        self.beginResetModel()
        self.rows = []
        self.endResetModel()

    def retranslate(self) -> None:
        self.headerDataChanged.emit(Qt.Orientation.Horizontal, 0, 5)
        if self.rows:
            self.dataChanged.emit(self.index(0, 1), self.index(len(self.rows) - 1, 1))


# The gateway sends this every 0.5 s on Diagnosis CAN; hidden until the user clears the filter
DEFAULT_TRACE_FILTER = "-17F00010"


def parse_id_filter(text: str) -> tuple[set[int], set[int]]:
    """"710, 77A" shows only these IDs; "-17F00010" hides one. Both kinds may be mixed. ValueError on bad input."""
    show: set[int] = set()
    hide: set[int] = set()
    for part in text.replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        (hide if part.startswith("-") else show).add(parse_id(part.lstrip("-"))[0])
    return show, hide


class _IdFilter(QSortFilterProxyModel):
    """Shows only the listed IDs (if any) and hides the excluded ones; errors always stay visible."""

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.show_ids: set[int] = set()
        self.hide_ids: set[int] = set()

    def set_ids(self, show: set[int], hide: set[int]) -> None:
        self.show_ids, self.hide_ids = show, hide
        self.invalidate()

    def filterAcceptsRow(self, source_row: int, _parent: QModelIndex) -> bool:  # noqa: N802 (Qt override)
        r = self.sourceModel().rows[source_row]
        if r.arb_id is None:
            return True
        if r.arb_id in self.hide_ids:
            return False
        return not self.show_ids or r.arb_id in self.show_ids


class TerminalScreen(QWidget):
    """Connection bar, live trace, and a send line for raw frames or UDS requests."""

    problem = Signal(object)  # Failure: the link closed with an error

    def __init__(self, conn: CanConnection, runner: OperationRunner, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.conn = conn
        self.runner = runner
        self.session: CanSession | None = None
        self._closing: list[CanSession] = []  # stopped sessions whose thread has not ended yet
        self._state = "off"  # off | connecting | on | err
        self._error = ""
        self._rx = self._tx = 0

        body = QVBoxLayout(self)
        body.setContentsMargins(28, 20, 28, 20)
        body.setSpacing(14)
        body.addWidget(self._build_link_bar())
        body.addWidget(self._build_trace(), 1)
        body.addWidget(self._build_send())

        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._drain)

        conn.changed.connect(self._refresh_link)
        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.retranslate_ui()

    # ────────────────────────────── layout ──────────────────────────────
    def _build_link_bar(self) -> QWidget:
        sec = Section()
        sec.hide_head()
        sec.body.setContentsMargins(14, 10, 14, 10)
        row = QHBoxLayout()
        row.setSpacing(10)
        self.btn_connect = button("", "PrimaryBtn", slot=self._on_connect_clicked)
        self.btn_connect.setMinimumWidth(120)
        self.lbl_link = QLabel()
        self.lbl_link.setObjectName("FieldLabel")
        self.cmb_bitrate = QComboBox()
        saved = int(QSettings().value("terminal/bitrate", 500_000))
        for br in BITRATES:
            self.cmb_bitrate.addItem("", br)
        self.cmb_bitrate.setCurrentIndex(max(0, self.cmb_bitrate.findData(saved)))
        self.cmb_bitrate.currentIndexChanged.connect(
            lambda _i: QSettings().setValue("terminal/bitrate", self.cmb_bitrate.currentData())
        )
        self.btn_settings = button("", "GhostBtn", slot=lambda: run_dialog(ConnectionDialog(self.conn, self)))
        self.lbl_state = QLabel()
        self.lbl_state.setObjectName("StatusReadout")
        sep = vdivider()
        sep.setFixedHeight(14)
        self.lbl_counts = QLabel()
        self.lbl_counts.setFont(mono_font(12))
        set_tone(self.lbl_counts, "muted")
        for w in (self.btn_connect, self.lbl_link, self.cmb_bitrate, self.btn_settings):
            row.addWidget(w)
        row.addStretch(1)
        row.addWidget(self.lbl_state)
        row.addSpacing(8)
        row.addWidget(sep, 0, Qt.AlignmentFlag.AlignVCenter)
        row.addSpacing(8)
        row.addWidget(self.lbl_counts)
        sec.body.addLayout(row)
        return sec

    def _build_trace(self) -> QWidget:
        self.sec_trace = Section()
        self.sec_trace.body.setSpacing(10)
        self.ed_filter = QLineEdit()
        self.ed_filter.setFixedWidth(220)
        self.ed_filter.setClearButtonEnabled(True)
        self.ed_filter.textChanged.connect(self._apply_filter)
        self.btn_pause = button("", "GhostBtn")
        self.btn_pause.setCheckable(True)
        self.btn_clear = button("", "GhostBtn", slot=self._clear)
        self.btn_save = button("", "GhostBtn", slot=self._save)
        for w in (self.ed_filter, self.btn_pause, self.btn_clear, self.btn_save):
            self.sec_trace.head.addWidget(w)

        self.model = TraceModel(self)
        self.proxy = _IdFilter(self)
        self.proxy.setSourceModel(self.model)
        self.ed_filter.setText(str(QSettings().value("terminal/filter", DEFAULT_TRACE_FILTER)))
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setFont(mono_font(12))
        self.table.horizontalHeader().setFont(QApplication.font())
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        hdr = self.table.horizontalHeader()
        hdr.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        hdr.setStretchLastSection(True)
        for col, width in enumerate((84, 70, 84, 44, 330)):
            self.table.setColumnWidth(col, width)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        copy = QAction(self.table)
        copy.setShortcut(QKeySequence.StandardKey.Copy)
        copy.triggered.connect(self._copy_selection)
        self.table.addAction(copy)
        self.act_hide_id = QAction(self.table)
        self.act_hide_id.triggered.connect(self._hide_selected_id)
        self.table.addAction(self.act_hide_id)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        self.sec_trace.body.addWidget(self.table, 1)
        return self.sec_trace

    def _build_send(self) -> QWidget:
        self.sec_send = Section()
        self.sec_send.body.setSpacing(8)
        row = QHBoxLayout()
        row.setSpacing(8)

        self.btn_mode_frame = QPushButton()
        self.btn_mode_uds = QPushButton()
        group = QButtonGroup(self)
        for b, pos in ((self.btn_mode_frame, "left"), (self.btn_mode_uds, "right")):
            b.setObjectName("SegBtn")
            b.setProperty("pos", pos)
            b.setCheckable(True)
            group.addButton(b)
            row.addWidget(b)
        row.addSpacing(8)

        self.pages = QStackedWidget()
        # raw frame: ID + up to 8 bytes
        self.ed_id = self._id_edit("710")
        self.cmb_frame = self._data_combo()
        self.lbl_id = QLabel()
        self.lbl_data_frame = QLabel()
        self.pages.addWidget(self._fields(self.lbl_id, self.ed_id, self.lbl_data_frame, self.cmb_frame))
        # UDS request over ISO-TP: request ID, response ID, service bytes
        self.ed_tx = self._id_edit("710")
        self.ed_rx = self._id_edit("77A")
        self.cmb_uds = self._data_combo()
        self.lbl_tx, self.lbl_rx, self.lbl_data_uds = QLabel(), QLabel(), QLabel()
        self.pages.addWidget(self._fields(self.lbl_tx, self.ed_tx, self.lbl_rx, self.ed_rx, self.lbl_data_uds, self.cmb_uds))
        row.addWidget(self.pages, 1)

        self.btn_send = button("", "PrimaryBtn", slot=self._send)
        self.btn_send.setMinimumWidth(110)
        row.addWidget(self.btn_send)
        self.sec_send.body.addLayout(row)

        self.lbl_msg = hint()
        self.sec_send.body.addWidget(self.lbl_msg)

        mode = str(QSettings().value("terminal/mode", "uds"))
        (self.btn_mode_uds if mode == "uds" else self.btn_mode_frame).setChecked(True)
        self.btn_mode_uds.toggled.connect(self._on_mode)
        self._on_mode(self.btn_mode_uds.isChecked(), save=False)
        return self.sec_send

    def _id_edit(self, value: str) -> QLineEdit:
        ed = QLineEdit(value)
        ed.setFont(mono_font(13))
        ed.setFixedWidth(84)
        ed.returnPressed.connect(self._send)
        return ed

    def _data_combo(self) -> QComboBox:
        cmb = QComboBox()
        cmb.setEditable(True)
        cmb.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        cmb.setFont(mono_font(13))
        cmb.setMaxVisibleItems(16)
        cmb.lineEdit().returnPressed.connect(self._send)
        return cmb

    @staticmethod
    def _fields(*items: QWidget) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        for it in items:
            lay.addWidget(it, 1 if isinstance(it, QComboBox) else 0)
        return w

    # ────────────────────────────── text & state ──────────────────────────────
    def retranslate_ui(self) -> None:
        self.btn_settings.setText(tr("Адаптер…", "Adapter…"))
        for i, br in enumerate(BITRATES):
            self.cmb_bitrate.setItemText(i, tr(f"{br // 1000} кбит/с", f"{br // 1000} kbit/s"))
        self.sec_trace.set_text(tr("Трафик", "Traffic"))
        self.ed_filter.setPlaceholderText(tr("Фильтр ID: 710, 77A или -17F00010", "Filter IDs: 710, 77A or -17F00010"))
        self.ed_filter.setToolTip(
            tr(
                "Через запятую: ID — показывать только их, -ID — скрыть. По умолчанию скрыт 17F00010: "
                "блок шлёт его каждые 0,5 с.",
                "Comma-separated: ID shows only those, -ID hides one. 17F00010 is hidden by default: "
                "the ECU sends it every 0.5 s.",
            )
        )
        self.act_hide_id.setText(tr("Скрыть этот ID", "Hide this ID"))
        self.btn_pause.setText(tr("Пауза", "Pause"))
        self.btn_pause.setToolTip(tr("Не показывать новые кадры; ответы UDS по-прежнему видны", "Stop showing new frames; UDS replies still appear"))
        self.btn_clear.setText(tr("Очистить", "Clear"))
        self.btn_save.setText(tr("Сохранить…", "Save…"))
        self.sec_send.set_text(tr("Отправка", "Send"))
        self.btn_mode_frame.setText(tr("CAN-кадр", "CAN frame"))
        self.btn_mode_uds.setText(tr("UDS-запрос", "UDS request"))
        self.lbl_id.setText("ID")
        self.lbl_data_frame.setText(tr("Данные", "Data"))
        self.lbl_tx.setText(tr("Запрос", "Request"))
        self.lbl_rx.setText(tr("Ответ", "Reply"))
        self.lbl_data_uds.setText(tr("Сервис", "Service"))
        self.cmb_frame.lineEdit().setPlaceholderText("02 10 03")
        self.cmb_uds.lineEdit().setPlaceholderText("22 F1 90")
        self.btn_send.setText(tr("Отправить", "Send"))
        self.model.retranslate()
        self._load_history(self.cmb_frame, "frame")
        self._load_history(self.cmb_uds, "uds")
        self._refresh_link()
        self._apply_state()
        if not self.lbl_msg.property("tone"):
            self._show_mode_hint()

    def _refresh_link(self) -> None:
        if self.conn.port or self.conn.title:
            self.lbl_link.setText(self.conn.display())
        else:
            self.lbl_link.setText(tr("Адаптер не настроен", "Adapter not set up"))

    def _apply_state(self) -> None:
        tone, text = {
            "off": ("muted", tr("Отключено", "Disconnected")),
            "connecting": ("info", tr("Подключение…", "Connecting…")),
            "on": ("ok", tr("Подключено", "Connected")),
            "err": ("err", tr("Ошибка подключения", "Connection failed")),
        }[self._state]
        self.lbl_state.setText(text)
        set_tone(self.lbl_state, tone)
        self.lbl_state.setToolTip(self._error)
        live = self.session is not None
        self.btn_connect.setText(tr("Отключиться", "Disconnect") if live else tr("Подключиться", "Connect"))
        self.btn_connect.setObjectName("" if live else "PrimaryBtn")
        self.btn_connect.style().unpolish(self.btn_connect)
        self.btn_connect.style().polish(self.btn_connect)
        self.cmb_bitrate.setEnabled(not live)
        self.btn_settings.setEnabled(not live)
        self.btn_send.setEnabled(self._state == "on")
        self.btn_send.setToolTip("" if self._state == "on" else tr("Сначала подключитесь к адаптеру", "Connect to the adapter first"))
        self._refresh_counts()

    def _refresh_counts(self) -> None:
        self.lbl_counts.setText(f"Rx {self._rx}    Tx {self._tx}")

    def _say(self, text: str, tone: str = "") -> None:
        self.lbl_msg.setText(text)
        set_tone(self.lbl_msg, tone)

    def _show_mode_hint(self) -> None:
        if self.btn_mode_uds.isChecked():
            self._say(
                tr(
                    "Запрос уходит по ISO-TP, ответ собирается целиком; «ожидание» (7F xx 78) обрабатывается само. "
                    "После # можно писать комментарий.",
                    "The request goes over ISO-TP and the reply is reassembled; “pending” (7F xx 78) is handled for you. "
                    "Text after # is a comment.",
                )
            )
        else:
            self._say(
                tr(
                    "До 8 байт данных. ID длиннее трёх знаков или больше 7FF отправляется как 29-битный.",
                    "Up to 8 data bytes. An ID longer than three digits or above 7FF is sent as 29-bit.",
                )
            )

    def _on_mode(self, uds: bool, save: bool = True) -> None:
        self.pages.setCurrentIndex(1 if uds else 0)
        if save:
            QSettings().setValue("terminal/mode", "uds" if uds else "frame")
        self._show_mode_hint()

    def prefill_uds(self, request: str) -> None:
        """Put a ready UDS request (e.g. a SWaP certificate) into the send line for the gateway."""
        self.btn_mode_uds.setChecked(True)
        self.ed_tx.setText("710")
        self.ed_rx.setText("77A")
        self.cmb_uds.setEditText(request)
        self._say(
            tr(
                "Запрос подставлен — подключитесь и нажмите «Отправить». Если блок ответит отказом "
                "serviceNotSupportedInActiveSession, сначала отправьте 10 03.",
                "The request is filled in — connect and press Send. If the ECU replies "
                "serviceNotSupportedInActiveSession, send 10 03 first.",
            ),
            "info",
        )

    # ────────────────────────────── history ──────────────────────────────
    @staticmethod
    def _history(mode: str) -> list[str]:
        raw = QSettings().value(f"terminal/history_{mode}", []) or []
        return [raw] if isinstance(raw, str) else [str(x) for x in raw]

    def _load_history(self, cmb: QComboBox, mode: str) -> None:
        text = cmb.currentText()
        items = self._history(mode)
        if mode == "uds":
            items += [p for p in _uds_presets() if p not in items]
        cmb.clear()
        cmb.addItems(items)
        cmb.setEditText(text)

    def _remember(self, cmb: QComboBox, mode: str, text: str) -> None:
        items = [text] + [i for i in self._history(mode) if i != text]
        QSettings().setValue(f"terminal/history_{mode}", items[:_HISTORY_MAX])
        self._load_history(cmb, mode)

    # ────────────────────────────── session ──────────────────────────────
    def _on_connect_clicked(self) -> None:
        if self.session is not None:
            self.disconnect_bus()
        elif ensure_ready(self.conn, self):
            self.connect_bus()

    def connect_bus(self, bus: Any | None = None) -> None:
        """Open the adapter (or an already open python-can `bus`, used by tests) and start receiving."""
        if self.session is not None:
            return
        s = CanSession(self.conn.port, self.conn.interface, int(self.cmb_bitrate.currentData()), bus=bus, parent=self)
        s.opened.connect(self._on_opened)
        s.closed.connect(self._on_closed)
        self.session = s
        self._opened_at = time.time()
        self._state, self._error = "connecting", ""
        self._apply_state()
        s.start()
        self._timer.start()

    def holds_adapter(self) -> bool:
        return self.session is not None or bool(self._closing)

    def disconnect_bus(self) -> None:
        s, self.session = self.session, None
        if s is None:
            return
        s.stop()  # waits a few seconds; opening a VCI or a 7F 78 wait can take longer
        self._drain(s)
        if s.isRunning():  # deleting a running QThread aborts the app: let it end, the adapter stays "in use" till then
            self._closing.append(s)
            s.finished.connect(lambda s=s: (self._closing.remove(s), s.deleteLater()))
        else:
            s.deleteLater()
        self._timer.stop()
        self._state = "off"
        self._apply_state()

    def _on_opened(self) -> None:
        if self.sender() is self.session:
            self._state = "on"
            self._apply_state()

    def _on_closed(self, error: str) -> None:
        s = self.sender()
        if s is None or s is not self.session:
            return  # stopped by disconnect_bus() (the session may already be gone), already handled
        self._drain(s)
        self.session = None
        s.wait()  # `closed` is the last thing run() does: a short wait; deleting a running QThread aborts the app
        s.deleteLater()
        self._timer.stop()
        self._state, self._error = ("err", error) if error else ("off", "")
        self._apply_state()
        if error:
            self._say(error, "err")
            self.problem.emit(Failure(tr("CAN-терминал", "CAN terminal"), error, started=self._opened_at))

    def _drain(self, session: CanSession | None = None) -> None:
        s = session or self.session
        if s is None:
            return
        batch: list[TraceRow] = []
        while s.rows:
            r = s.rows.popleft()
            if r.kind == "rx":
                self._rx += 1
            elif r.kind == "tx":
                self._tx += 1
            if self.btn_pause.isChecked() and r.kind in ("rx", "tx"):
                continue
            batch.append(r)
        if batch:
            sb = self.table.verticalScrollBar()
            at_end = sb.value() >= sb.maximum() - 2
            self.model.append(batch)
            if at_end:
                self.table.scrollToBottom()
            last = next((r for r in reversed(batch) if r.kind in ("uds-resp", "error")), None)
            if last is not None:
                tone = "err" if last.kind == "error" else ("warn" if last.data[:1] == b"\x7f" else "ok")
                self._say(last.note, tone)
        self._refresh_counts()

    # ────────────────────────────── actions ──────────────────────────────
    def _send(self) -> None:
        if self.session is None or self._state != "on":
            self._say(tr("Сначала подключитесь к адаптеру.", "Connect to the adapter first."), "err")
            return
        try:
            if self.btn_mode_uds.isChecked():
                text = self.cmb_uds.currentText().strip()
                payload = parse_hex(text, 4095)
                if not payload:
                    raise ValueError(tr("Введите байты запроса, например 22 F1 90", "Enter the request bytes, e.g. 22 F1 90"))
                tx, _ = parse_id(self.ed_tx.text())
                rx, _ = parse_id(self.ed_rx.text())
                if tx > 0x7FF or rx > 0x7FF:  # 0710 stays what it always was here: 11-bit 0x710
                    raise ValueError(tr("UDS-запрос идёт только с 11-битными ID (не больше 7FF); "
                                        "29-битный ID отправьте кадром",
                                        "UDS requests use 11-bit IDs only (at most 7FF); "
                                        "send a 29-bit ID as a raw frame"))
                self.session.send_uds(tx, rx, payload)
                self._remember(self.cmb_uds, "uds", text)
                self._say(tr("Ждём ответ…", "Waiting for the reply…"), "info")
            else:
                text = self.cmb_frame.currentText().strip()
                data = parse_hex(text, 8)
                arb_id, extended = parse_id(self.ed_id.text())
                self.session.send_frame(arb_id, data, extended)
                if text:
                    self._remember(self.cmb_frame, "frame", text)
                self._say("")
        except ValueError as exc:
            self._say(str(exc), "err")

    def _apply_filter(self, text: str) -> None:
        try:
            show, hide = parse_id_filter(text)
        except ValueError:
            set_tone(self.ed_filter, "err")
            return
        set_tone(self.ed_filter, "")
        self.proxy.set_ids(show, hide)
        QSettings().setValue("terminal/filter", text)

    def _hide_selected_id(self) -> None:
        """Context menu: add the selected row's ID to the exclusions."""
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        r = self.model.rows[self.proxy.mapToSource(rows[0]).row()]
        if r.arb_id is None:
            return
        ident = f"-{r.arb_id:08X}" if r.extended else f"-{r.arb_id:03X}"
        text = self.ed_filter.text().strip()
        self.ed_filter.setText(f"{text}, {ident}" if text else ident)

    def _clear(self) -> None:
        self.model.clear()
        self._rx = self._tx = 0
        self._refresh_counts()

    def _save(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить трафик", "Save traffic"),
            str(self.conn.out_dir / "can_trace.txt"),
            "Text (*.txt *.log);;All Files (*)",
        )
        if path:
            lines = ["\t".join(TraceModel.headers())] + ["\t".join(TraceModel.cells(r)) for r in self.model.rows]
            Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _copy_selection(self) -> None:
        rows = sorted({self.proxy.mapToSource(i).row() for i in self.table.selectionModel().selectedRows()})
        if rows:
            QGuiApplication.clipboard().setText("\n".join("\t".join(TraceModel.cells(self.model.rows[r])) for r in rows))
