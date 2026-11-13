"""Start screen: read the ECU over CAN, or open dump files already on disk."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from contitool.gui.theme import mono_font, ui_font
from contitool.gui.widgets.page import Section, button, clear_layout, group_label, hint
from contitool.gui.workspace import recent_folders
from contitool.i18n import subscribe_lang_change, tr

_COLUMN_WIDTH = 840


class _RecentRow(QFrame):
    """Folder name on the left, path underneath, monospace date + subtle arrow on the right; whole row opens it."""

    clicked = Signal()

    def __init__(self, folder: Path, *, is_last: bool = False) -> None:
        super().__init__()
        self.setObjectName("ListRow")
        if is_last:
            self.setProperty("last", True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(str(folder))
        lay = QHBoxLayout(self)
        lay.setContentsMargins(18, 10, 18, 10)
        lay.setSpacing(16)
        text = QVBoxLayout()
        text.setSpacing(2)
        name = QLabel(folder.name)
        name.setObjectName("FieldLabel")
        path = hint()
        path.setFont(mono_font(11))
        path.setWordWrap(False)
        path.setText(path.fontMetrics().elidedText(str(folder.parent), Qt.TextElideMode.ElideMiddle, 560))
        text.addWidget(name)
        text.addWidget(path)
        lay.addLayout(text, 1)
        try:
            when = datetime.fromtimestamp(folder.stat().st_mtime).strftime("%d.%m.%Y")
        except OSError:
            when = ""
        if when:
            stamp = QLabel(when)
            stamp.setFont(mono_font(11))
            stamp.setObjectName("Hint")
            lay.addWidget(stamp, 0, Qt.AlignmentFlag.AlignVCenter)
        arrow = QLabel("›")
        arrow.setObjectName("Hint")
        lay.addWidget(arrow, 0, Qt.AlignmentFlag.AlignVCenter)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001 (Qt override)
        if self.rect().contains(event.position().toPoint()):
            self.clicked.emit()


class StartScreen(QWidget):
    """Shown until a gateway is loaded. Files can also be dropped anywhere on it."""

    read_can_requested = Signal()
    restore_requested = Signal()
    open_files_requested = Signal()
    open_folder_requested = Signal(str)  # "" = ask for a folder
    files_dropped = Signal(list)  # list[Path]
    wiring_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(36, 48, 36, 28)
        outer.addStretch(1)
        column = QWidget()
        column.setMaximumWidth(_COLUMN_WIDTH)
        outer.addWidget(column, 100)
        outer.addStretch(1)

        body = QVBoxLayout(column)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(6)

        self.lbl_title = QLabel()
        self.lbl_title.setObjectName("PageTitle")
        self.lbl_title.setFont(ui_font(23, bold=True))
        self.lbl_sub = hint()
        body.addWidget(self.lbl_title)
        body.addWidget(self.lbl_sub)
        body.addSpacing(22)

        self.tile_can = Section()
        self.lbl_can_eyebrow = group_label()
        self.tile_can.body.insertWidget(0, self.lbl_can_eyebrow)
        self.tile_can.head.setContentsMargins(20, 18, 20, 2)
        self.btn_read = button("", "PrimaryBtn", slot=self.read_can_requested.emit)
        self.btn_restore = button("", slot=self.restore_requested.emit)
        self.btn_wiring = button("", "GhostBtn", slot=self.wiring_requested.emit)

        self.tile_files = Section()
        self.lbl_files_eyebrow = group_label()
        self.tile_files.body.insertWidget(0, self.lbl_files_eyebrow)
        self.tile_files.head.setContentsMargins(20, 18, 20, 2)
        self.btn_folder = button("", slot=lambda: self.open_folder_requested.emit(""))
        self.btn_files = button("", slot=self.open_files_requested.emit)

        tiles = QHBoxLayout()
        tiles.setSpacing(16)
        for tile, eyebrow, actions in (
            (self.tile_can, self.lbl_can_eyebrow, (self.btn_read, self.btn_restore, self.btn_wiring)),
            (self.tile_files, self.lbl_files_eyebrow, (self.btn_folder, self.btn_files)),
        ):
            # Put eyebrow above title inside head area visually: move eyebrow into _outer at index 0
            tile.body.removeWidget(eyebrow)
            eyebrow.setContentsMargins(20, 16, 20, 0)
            tile._outer.insertWidget(0, eyebrow)
            tile.head.setContentsMargins(20, 4, 20, 2)
            tile.body.addStretch(1)
            for b in actions:
                b.setCursor(Qt.CursorShape.PointingHandCursor)
            foot_lay = tile.add_footer(*actions)
            tile.body.setContentsMargins(20, 6, 20, 12)
            foot_lay.setContentsMargins(20, 4, 20, 18)
            tiles.addWidget(tile, 1)
        body.addLayout(tiles)

        body.addSpacing(24)
        self.recent_wrap = QWidget()
        rw_lay = QVBoxLayout(self.recent_wrap)
        rw_lay.setContentsMargins(0, 0, 0, 0)
        rw_lay.setSpacing(8)
        self.lbl_recent = group_label()
        rw_lay.addWidget(self.lbl_recent)
        self.recent_box = QFrame()
        self.recent_box.setObjectName("RecentBox")
        self.recent_list = QVBoxLayout(self.recent_box)
        self.recent_list.setContentsMargins(0, 0, 0, 0)
        self.recent_list.setSpacing(0)
        rw_lay.addWidget(self.recent_box)
        body.addWidget(self.recent_wrap)

        body.addStretch(1)

        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.retranslate_ui()

    def refresh_recent(self) -> None:
        clear_layout(self.recent_list)
        folders = recent_folders()[:5]
        self.recent_wrap.setVisible(bool(folders))
        for idx, folder in enumerate(folders):
            r = _RecentRow(folder, is_last=(idx == len(folders) - 1))
            r.clicked.connect(lambda f=folder: self.open_folder_requested.emit(str(f)))
            self.recent_list.addWidget(r)

    def retranslate_ui(self) -> None:
        self.lbl_title.setText(tr("Открыть блок", "Open an ECU"))
        self.lbl_sub.setText(
            tr(
                "Шлюз VAG MQB J533 — Continental 3Q0 907 530 (Renesas RH850/F1L)",
                "VAG MQB J533 gateway — Continental 3Q0 907 530 (Renesas RH850/F1L)",
            )
        )
        self.lbl_can_eyebrow.setText(tr("ПОДКЛЮЧЕНИЕ ПО CAN (500 КБИТ/С)", "CAN CONNECTION (500 KBIT/S)"))
        self.lbl_files_eyebrow.setText(tr("ЛОКАЛЬНЫЕ ФАЙЛЫ (.BIN / .RAW)", "LOCAL FILES (.BIN / .RAW)"))
        self.tile_can.set_text(
            tr("Блок на стенде или в авто", "ECU on bench or car"),
            tr(
                "Полная копия памяти по CAN: CodeFlash, DataFlash, Uflash, внешняя EEPROM и OPBT. После чтения блок откроется сам.",
                "Full memory backup over CAN: CodeFlash, DataFlash, Uflash, external EEPROM and OPBT. Opens once read.",
            ),
        )
        self.tile_files.set_text(
            tr("Дампы на диске", "Dumps on disk"),
            tr(
                "Папка с CodeFlash, DataFlash и Uflash или отдельные файлы. Папку или файлы .bin можно также перетащить прямо в окно.",
                "A folder with CodeFlash, DataFlash and Uflash, or separate files. Drop a folder or .bin files anywhere in this window.",
            ),
        )
        self.btn_read.setText(tr("Считать блок", "Read the ECU"))
        self.btn_restore.setText(tr("Залить бэкап…", "Write backup…"))
        self.btn_restore.setToolTip(
            tr(
                "Восстановить блок из ранее сохранённого бэкапа (в том числе если блок остался в загрузчике FBL)",
                "Write a previously saved backup back into this ECU (including when stuck in FBL bootloader)",
            )
        )
        self.btn_wiring.setText(tr("Схема", "Wiring"))
        self.btn_wiring.setToolTip(tr("Схема подключения к блоку на стенде", "ECU bench wiring diagram"))
        self.btn_folder.setText(tr("Открыть папку…", "Open folder…"))
        self.btn_files.setText(tr("Выбрать файлы…", "Choose files…"))
        self.lbl_recent.setText(tr("НЕДАВНИЕ БЛОКИ", "RECENT ECUS"))
        self.refresh_recent()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        paths = [Path(u.toLocalFile()) for u in event.mimeData().urls() if u.toLocalFile()]
        if paths:
            self.files_dropped.emit(paths)
            event.acceptProposedAction()
