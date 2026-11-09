"""CAN adapter settings (persisted) plus the per-session CAN termination confirmation, and their dialog."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import time
from typing import Any

from PySide6.QtCore import QObject, QSettings, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QSizePolicy,
    QListWidgetItem,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from contitool.can import SUPPORTED_CAN_INTERFACES, FoundAdapter, can_identify, discover_adapters, unsupported_ecu_reason
from contitool.can import dpdu
from contitool.gui.theme import set_tone
from contitool.gui.widgets.page import Dialog, button, group_label, hint, row, run_dialog
from contitool.gui.widgets.pinout_card import PinoutCard
from contitool.gui.worker import OperationWorker
from contitool.i18n import tr
from contitool.report import Failure
from contitool.storage import runs_root


BUILTIN_TERMINATION = ("dpdu", "j2534")  # VAS 6154 / VNCI and J2534 pass-thru adapters terminate CAN themselves


class CanConnection(QObject):
    """Where and how to talk to the bench gateway. `ready` gates every CAN operation."""

    changed = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        s = QSettings()
        self.interface = str(s.value("can/interface", "slcan"))
        self.port = str(s.value("can/port", ""))
        self.title = str(s.value("can/title", ""))
        self.out_dir = runs_root()  # always next to the program (storage.py); no longer a setting
        self.wiring_confirmed = False  # asked again every session on purpose
        self.in_use: Callable[[], str] = lambda: ""  # set by the main window: why the adapter is taken right now

    def busy_reason(self) -> str:
        """Why no new CAN link may open now (an operation, the terminal, a link check still running), or ""."""
        if any(w.isRunning() for w in _ORPHANS if w.objectName() == "link-check"):
            return tr("Ещё идёт проверка связи — подождите несколько секунд.", "A link check is still running — wait a few seconds.")
        return self.in_use()

    @property
    def ready(self) -> bool:
        return (bool(self.port) or self.interface in BUILTIN_TERMINATION) and (
            self.wiring_confirmed or self.interface in BUILTIN_TERMINATION
        )

    def update(self, interface: str, port: str, out_dir: Path, wiring_confirmed: bool, title: str = "") -> None:
        if (interface, port) != (self.interface, self.port):
            dpdu.close_session()  # a D-PDU link kept open belongs to the adapter that was picked before
        self.interface, self.port, self.out_dir, self.wiring_confirmed = interface, port, out_dir, wiring_confirmed
        self.title = title
        s = QSettings()
        s.setValue("can/interface", interface)
        s.setValue("can/port", port)
        s.setValue("can/title", title)
        self.changed.emit()

    def adapter_name(self) -> str:
        for code, en_name, ru_name in SUPPORTED_CAN_INTERFACES:
            if code == self.interface:
                return tr(ru_name, en_name).split(" (")[0]
        return self.interface

    def display(self) -> str:
        """Short label for the header chip: "CANable2 · cu.usbmodem…", "VAS6154A"."""
        port = self.port.replace("\\", "/").rsplit("/", 1)[-1]
        if self.title:
            return self.title if self.title == self.port else f"{self.title} · {port}"
        return f"{self.adapter_name()} · {port}" if port else self.adapter_name()


_ORPHANS: set[OperationWorker] = set()  # threads of closed dialogs, kept alive until they end


def _let_finish(worker: OperationWorker | None) -> None:
    """Never block the GUI on a closing dialog and never destroy a running thread: detach it, drop it when it ends."""
    if worker is None or not worker.isRunning():
        return
    for sig in (worker.succeeded, worker.failed):
        try:
            sig.disconnect()
        except (RuntimeError, TypeError):
            pass
    worker.setParent(None)
    _ORPHANS.add(worker)
    worker.finished.connect(lambda w=worker: (_ORPHANS.discard(w), w.deleteLater()))


DIALOG_SIZE = (720, 760)  # the dialog keeps it; texts come and go with the adapter, the body scrolls


def _link(text: str, slot: Any) -> Any:
    b = button(text, "LinkBtn", slot=slot)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


class _ClickLabel(QLabel):
    clicked = Signal()

    def mousePressEvent(self, event: Any) -> None:  # noqa: N802 - Qt naming
        self.clicked.emit()
        super().mousePressEvent(event)


class WrapCheckBox(QWidget):
    """A checkbox whose text wraps to the dialog's width (a QCheckBox never wraps and widens the whole dialog);
    clicking the text toggles it, as with a plain checkbox."""

    toggled = Signal(bool)

    def __init__(self) -> None:
        super().__init__()
        self.box = QCheckBox()
        self.label = _ClickLabel()
        self.label.setWordWrap(True)
        self.label.clicked.connect(lambda: self.box.isEnabled() and self.box.toggle())
        self.box.toggled.connect(self.toggled.emit)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        lay.addWidget(self.box, 0, Qt.AlignmentFlag.AlignTop)
        lay.addWidget(self.label, 1)

    def setText(self, text: str) -> None:  # noqa: N802 - QCheckBox API
        self.label.setText(text)

    def text(self) -> str:
        return self.label.text()

    def setChecked(self, on: bool) -> None:  # noqa: N802 - QCheckBox API
        self.box.setChecked(on)

    def isChecked(self) -> bool:  # noqa: N802 - QCheckBox API
        return self.box.isChecked()


class PathLabel(QLabel):
    """A long folder path shortened in the middle to the width it gets (the full one is in the tooltip), so it never
    widens the dialog."""

    def __init__(self) -> None:
        super().__init__()
        self._full = ""
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

    def set_path(self, path: str) -> None:
        self._full = path
        self.setToolTip(path)
        self._elide()

    def resizeEvent(self, event: Any) -> None:  # noqa: N802 - Qt naming
        super().resizeEvent(event)
        self._elide()

    def _elide(self) -> None:
        self.setText(self.fontMetrics().elidedText(self._full, Qt.TextElideMode.ElideMiddle, max(60, self.width())))


class ConnectionDialog(Dialog):
    """Found adapters as a list (one is picked for you), manual entry folded away, a link check, the terminator box."""

    def __init__(self, conn: CanConnection, parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            tr("Подключение к блоку", "ECU connection"),
            tr(
                "Шлюз на стенде подключается к адаптеру по шине Diagnosis CAN (500 кбит/с) через разъём T20.",
                "The bench gateway talks to the adapter over Diagnosis CAN (500 kbit/s) via the T20 connector.",
            ),
            width=DIALOG_SIZE[0],
        )
        self.conn = conn
        self._check: OperationWorker | None = None
        self._scan: OperationWorker | None = None
        self._first_scan = True

        self.body.addLayout(row(group_label(tr("Адаптер", "Adapter")), 1,
                                button(tr("Обновить", "Refresh"), "GhostBtn", slot=self.refresh)))
        self.list = QListWidget()
        self.list.setObjectName("Adapters")
        self.list.currentItemChanged.connect(lambda *_a: self._picked())
        self.list.itemClicked.connect(lambda *_a: self._toggle_manual(False))
        self.body.addWidget(self.list)

        # Manual entry: for adapters the search cannot see (gs_usb, a port behind a hub, a remote can0…)
        self.btn_manual = _link("", self._toggle_manual)
        self.manual = QWidget()
        lay = QVBoxLayout(self.manual)
        lay.setContentsMargins(0, 0, 0, 0)
        self.cmb_iface = QComboBox()
        for code, en_name, ru_name in SUPPORTED_CAN_INTERFACES:
            self.cmb_iface.addItem(tr(ru_name, en_name), code)
        self.ed_port = QLineEdit()
        self.ed_port.setPlaceholderText(tr("Порт: COM4, /dev/cu.usbmodem…, can0", "Port: COM4, /dev/cu.usbmodem…, can0"))
        self.ed_port.textChanged.connect(lambda *_a: self._picked())
        lay.addLayout(row(self.cmb_iface, self.ed_port, 0))
        self.manual.setVisible(False)
        self._manual_open = False  # isVisible() is False for every child until the dialog is shown
        self.body.addLayout(row(self.btn_manual))
        self.body.addWidget(self.manual)

        self.btn_check = button(tr("Проверить связь", "Check link"), slot=self._check_link)
        self.lbl_check = hint()
        self.lbl_check.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.btn_report = _link(tr("Сообщить о проблеме…", "Report a problem…"), self._report_check)
        self.btn_report.hide()
        self._check_failure: Failure | None = None
        self.body.addLayout(row(self.btn_check, self.lbl_check, 0, self.btn_report))

        self.chk_120ohm = WrapCheckBox()
        self._term_confirmed = conn.wiring_confirmed  # what the user ticked for an adapter without its own terminator
        self.chk_120ohm.setChecked(conn.wiring_confirmed)
        self.chk_120ohm.toggled.connect(self._term_toggled)
        self.body.addWidget(self.chk_120ohm)
        self.lbl_term_help = hint(tr(
            "На каждом конце шины CAN нужен резистор 120 Ом: без него сигнал отражается и кадры теряются. На "
            "столе шина состоит только из шлюза и адаптера, поэтому включите терминатор в адаптере (обычно "
            "это перемычка или переключатель) или поставьте резистор 120 Ом между CAN-H и "
            "CAN-L.<br><b>Галочка — только напоминание: ContiTool ничего не измеряет.</b>",
            "Each end of a CAN bus needs a 120 Ω resistor: without it the signal reflects and frames get "
            "lost. On the bench the bus is just the gateway and the adapter, so switch on the adapter's "
            "terminator (usually a jumper or a switch) or fit a 120 Ω resistor between CAN-H and "
            "CAN-L.<br><b>The checkbox is only a reminder: ContiTool measures nothing.</b>",
        ))
        self.body.addWidget(self.lbl_term_help)
        self.chk_driver = WrapCheckBox()  # a D-PDU driver version ContiTool was not checked with
        self.chk_driver.toggled.connect(lambda *_a: self._sync())
        self.body.addWidget(self.chk_driver)
        self.lbl_vnci = hint(tr(
            "<b>Обновите прошивку адаптера.</b> VAS 6154 / VNCI со старой прошивкой может не давать сырой "
            "канал CAN, без которого не работает чтение памяти. Драйвер D-PDU обновляет прошивку сам при "
            "первом подключении (около 30 секунд); не отключайте адаптер до конца.",
            "<b>Update the adapter firmware.</b> A VAS 6154 / VNCI on old firmware may refuse the raw CAN "
            "channel that memory reads need. The D-PDU driver updates the firmware itself on the first "
            "connect (about 30 seconds); do not unplug the adapter until it finishes.",
        ))
        self.body.addWidget(self.lbl_vnci)
        self.btn_pinout = _link("", self._toggle_pinout)
        self.body.addLayout(row(self.btn_pinout))
        self.pinout_card = PinoutCard(stacked=True)
        self.pinout_card.setVisible(False)
        self.body.addWidget(self.pinout_card)

        self.out_dir = conn.out_dir
        self.lbl_outdir = PathLabel()
        self.lbl_outdir.setObjectName("Hint")
        self.body.addWidget(group_label(tr("Папка с дампами и сессиями", "Dumps and sessions folder")))
        out_row = row(self.lbl_outdir, button(tr("Открыть", "Open"), "GhostBtn", slot=self._open_outdir), 0)
        out_row.setStretchFactor(self.lbl_outdir, 1)
        self.body.addLayout(out_row)
        self.body.addStretch(1)  # the dialog keeps its size: spare room goes below, not between the rows
        self._show_outdir()

        self.btn_ok = button(tr("Готово", "Done"), "PrimaryBtn", slot=self._save)
        self.finish(ok=self.btn_ok)
        # One size that holds the opened wiring diagram: what is taller scrolls, nothing is ever wider.
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.resize(*DIALOG_SIZE)
        self._fit_screen()

        self._toggle_pinout(False)
        self._toggle_manual(self._manual_open)
        self.refresh()

    # ---------------------------------------------------------------- adapter list
    def refresh(self) -> None:
        """Search in the background: vendor libraries (PCAN, Kvaser, Vector) can take a while to load."""
        if self._scan is not None:
            return
        self.list.clear()
        item = QListWidgetItem(tr("Поиск адаптеров…", "Looking for adapters…"))
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.list.addItem(item)
        self.list.setFixedHeight(52)
        self._scan = OperationWorker(tr("Поиск адаптеров", "Adapter search"), lambda _rep: discover_adapters(), self)
        self._scan.succeeded.connect(self._show_found)
        self._scan.failed.connect(lambda _msg, _tb: self._show_found([]))
        self._scan.start()
        self._sync()

    def _show_found(self, found: list[FoundAdapter]) -> None:
        if self._scan is not None:
            self._scan.wait()
        self._scan = None
        self.list.clear()
        for a in found:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, a)
            if a.problem:
                item.setFlags(Qt.ItemFlag.NoItemFlags)
            card = QWidget()
            lay = QVBoxLayout(card)
            lay.setContentsMargins(10, 6, 10, 6)
            lay.setSpacing(1)
            title = QLabel(a.title)
            title.setObjectName("AdapterTitle")
            detail = QLabel(a.problem or a.detail)
            detail.setObjectName("Hint")
            set_tone(detail, "warn" if a.problem else "")
            set_tone(title, "muted" if a.problem else "")
            lay.addWidget(title)
            lay.addWidget(detail)
            item.setSizeHint(card.sizeHint())
            self.list.addItem(item)
            self.list.setItemWidget(item, card)
        if not found:
            item = QListWidgetItem(tr("Адаптеры не найдены — подключите адаптер и нажмите «Обновить»",
                                      "No adapters found — plug one in and press Refresh"))
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.list.addItem(item)
        usable = [i for i in range(self.list.count()) if self.list.item(i).flags() & Qt.ItemFlag.ItemIsEnabled]
        saved = [i for i in usable if self._adapter(self.list.item(i)).channel == self.conn.port]
        if saved or usable:
            self.list.setCurrentRow((saved or usable)[0])
        self.list.setFixedHeight(min(5, max(1, self.list.count())) * 46 + 6)
        if self._first_scan and self.list.currentItem() is None and self.conn.port:  # saved adapter not found
            self.cmb_iface.setCurrentIndex(max(0, self.cmb_iface.findData(self.conn.interface)))
            self.ed_port.setText(self.conn.port)
            self._toggle_manual(True)
        self._first_scan = False
        self._sync()

    @staticmethod
    def _adapter(item: QListWidgetItem | None) -> FoundAdapter | None:
        return None if item is None else item.data(Qt.ItemDataRole.UserRole)

    def selection(self) -> tuple[str, str, str]:
        """(interface, port, title) — manual entry wins while it is open and filled in."""
        if self._manual_open and (self.ed_port.text().strip() or self.cmb_iface.currentData() in ("j2534", "dpdu")):
            return str(self.cmb_iface.currentData()), self.ed_port.text().strip(), ""
        a = self._adapter(self.list.currentItem())
        return (a.interface, a.channel, a.title) if a else ("", "", "")

    def _toggle_manual(self, show: bool | None = None) -> None:
        show = not self._manual_open if show is None else show
        self._manual_open = show
        self.manual.setVisible(show)
        self.btn_manual.setText(tr("Нет в списке? Указать вручную ", "Not listed? Enter manually ") + ("▾" if show else "▸"))
        self._sync()

    def _toggle_pinout(self, show: bool | None = None) -> None:
        show = self.pinout_card.isHidden() if show is None else show
        self.pinout_card.setVisible(show)
        self.btn_pinout.setText(tr("Схема подключения T20 ", "T20 wiring diagram ") + ("▾" if show else "▸"))

    def _unverified_driver(self) -> str | None:
        """Version of the picked D-PDU driver when it needs the user's go-ahead, else None."""
        a = None if self._manual_open else self._adapter(self.list.currentItem())
        if a is None or a.interface != "dpdu" or dpdu.driver_supported(a.driver):
            return None
        return a.driver

    def _accept_driver(self) -> None:
        drv = self._unverified_driver()
        if drv is not None and self.chk_driver.isChecked():
            dpdu.accepted_drivers.add(drv)

    def _picked(self) -> None:
        if self._check is None:
            self.lbl_check.clear()  # the last result was for another adapter
            self.btn_report.hide()
        self._sync()

    def _term_toggled(self, on: bool) -> None:
        if not self.chk_120ohm.isHidden():
            self._term_confirmed = on
        self._sync()

    def _sync(self) -> None:
        iface, port, _title = self.selection()
        builtin = iface in BUILTIN_TERMINATION  # VAS 6154 / VNCI and J2534 terminate the bus themselves: nothing to ask
        self.chk_120ohm.setText(tr(
            "Терминатор CAN включён (в адаптере или резистор 120 Ом между Pin 19 CAN-H и Pin 9 CAN-L), "
            "питание +12 В стабильное",
            "CAN termination is on (in the adapter or a 120 Ω resistor between Pin 19 CAN-H and Pin 9 CAN-L),"
            " +12 V supply is stable",
        ))
        self.chk_120ohm.setVisible(not builtin)
        self.lbl_term_help.setVisible(not builtin)
        self.chk_120ohm.blockSignals(True)
        self.chk_120ohm.setChecked(builtin or self._term_confirmed)
        self.chk_120ohm.blockSignals(False)
        self.lbl_vnci.setVisible(iface == "dpdu")  # only the VAS 6154 / VNCI path depends on adapter firmware
        drv = self._unverified_driver()
        self.chk_driver.setVisible(drv is not None)
        self.chk_driver.setText(tr(
            f"Разрешить непроверенный драйвер D-PDU {drv or '?'}: при подключении он перепрошьёт VCI под свою "
            "версию",
            f"Allow the unverified D-PDU driver {drv or '?'}: on connect it reflashes the VCI to its own "
            "version",
        ))
        self.chk_driver.setToolTip(tr(f"Проверены: {', '.join(dpdu.SUPPORTED_DRIVERS)}",
                                      f"Verified: {', '.join(dpdu.SUPPORTED_DRIVERS)}"))
        driver_ok = drv is None or self.chk_driver.isChecked()
        picked = bool(iface) and (bool(port) or iface in ("j2534", "dpdu")) and driver_ok
        busy = self._check is not None
        taken = self.conn.busy_reason()
        self.btn_check.setEnabled(picked and not busy and not taken)
        self.btn_check.setToolTip(taken)
        ok = picked and self.chk_120ohm.isChecked() and not busy
        self.btn_ok.setEnabled(ok)
        self.btn_ok.setToolTip(
            "" if ok else tr("Выберите адаптер и подтвердите, что CAN-терминатор включён (и драйвер D-PDU, если спрошено)",
                             "Pick an adapter and confirm the CAN terminator is on (and the D-PDU driver, if asked)")
        )

    # ---------------------------------------------------------------- link check
    def _check_link(self) -> None:
        iface, port, _title = self.selection()
        taken = self.conn.busy_reason()
        if taken:  # a flash or the terminal holds the adapter: a second link would steal its frames
            self._check_done(taken, "warn")
            return
        self._accept_driver()
        set_tone(self.lbl_check, "")
        self.lbl_check.setText(tr("Проверяю связь с блоком…", "Checking the link to the ECU…"))
        self._check = OperationWorker(
            tr("Проверка связи", "Link check"), lambda rep: can_identify(port, interface=iface, reporter=rep), self
        )
        self._check.setObjectName("link-check")
        self._check.succeeded.connect(self._check_ok)
        started = time.time()

        def failed(msg: str, tb: str) -> None:
            self._check_failure = Failure(tr("Проверка связи", "Link check"), msg, tb, started)
            self._check_done(msg, "err")

        self._check.failed.connect(failed)
        self._check.start()
        self._sync()

    def _check_ok(self, res: dict[str, Any]) -> None:
        values = {i["did"]: i["value"] for i in res.get("ident", [])}
        found = ", ".join(filter(None, (values.get("F187"), values.get("F197"), values.get("F189") and f"SW {values['F189']}")))
        unsupported = res.get("unsupported") or unsupported_ecu_reason(res.get("ident", []))
        if unsupported:
            msg = "⚠ " + tr("Блок отвечает, но не поддерживается", "ECU answers, but is not supported")
            self._check_done(msg + (f": {found}" if found else "") + f" — {unsupported}", "warn")
            return
        if res.get("adapter_warning"):
            msg = "⚠ " + tr("Блок отвечает", "ECU answers") + (f": {found}" if found else "")
            self._check_done(f"{msg}\n{res['adapter_warning']}", "warn")
            return
        if res.get("in_fbl"):
            msg = "✓ " + tr("Блок отвечает (в режиме загрузчика FBL)", "ECU answers (in FBL bootloader mode)")
            self._check_done(msg + (f": {found}" if found else ""), "warn")
            return
        self._check_done("✓ " + tr("Блок отвечает", "ECU answers") + (f": {found}" if found else ""), "ok")

    def _check_done(self, text: str, tone: str) -> None:
        if self._check is not None:
            self._check.wait()
        self._check = None
        self.lbl_check.setText(text)
        set_tone(self.lbl_check, tone)
        self.btn_report.setVisible(tone == "err" and self._check_failure is not None)
        self._sync()

    def _report_check(self) -> None:
        from contitool.gui.dialogs.problem_report import ProblemReportDialog  # it imports this module

        if self._check_failure is not None:
            run_dialog(ProblemReportDialog(self, self._check_failure, self.conn))

    # ---------------------------------------------------------------- folder & save
    def _show_outdir(self) -> None:
        self.lbl_outdir.set_path(str(self.out_dir))

    def _open_outdir(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.out_dir)))

    def _save(self) -> None:
        iface, port, title = self.selection()
        self._accept_driver()
        self.conn.update(iface, port, self.out_dir, self.chk_120ohm.isChecked(), title)
        self.accept()

    def done(self, result: int) -> None:  # accept() and reject() both end here
        _let_finish(self._check)
        _let_finish(self._scan)
        self._check = self._scan = None
        super().done(result)


def ensure_ready(conn: CanConnection, parent: QWidget) -> bool:
    """Open the connection dialog if the adapter is not set up yet. True when CAN work may start."""
    taken = conn.busy_reason()
    if taken:
        QMessageBox.information(parent, tr("Адаптер занят", "Adapter busy"), taken)
        return False
    if not conn.ready:
        run_dialog(ConnectionDialog(conn, parent))
    return conn.ready
