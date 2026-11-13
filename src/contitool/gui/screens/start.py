"""Start screen: hero header, bench CAN & offline dump feature cards, and recent gateway workspaces."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from contitool.gui import theme
from contitool.gui.theme import build_app_icon, glyph_pixmap, mono_font, tile_badge_pixmap
from contitool.gui.widgets.page import Section, button, clear_layout, divider, group_label, hint, pill
from contitool.gui.workspace import recent_folders
from contitool.i18n import subscribe_lang_change, tr

_COLUMN_WIDTH = 880


class _RecentRow(QFrame):
    """Folder card with folder icon, gateway folder name, elided parent path, and date pill."""

    clicked = Signal()

    def __init__(self, folder: Path) -> None:
        super().__init__()
        self.setObjectName("ListRow")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(str(folder))
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 9, 14, 9)
        lay.setSpacing(12)

        ico = QLabel()
        ico.setPixmap(glyph_pixmap("folder", theme.INFO, 18))
        lay.addWidget(ico, 0, Qt.AlignmentFlag.AlignVCenter)

        text = QVBoxLayout()
        text.setSpacing(2)
        name = QLabel(folder.name)
        name.setObjectName("FieldLabel")
        path = hint()
        path.setWordWrap(False)
        path.setText(path.fontMetrics().elidedText(str(folder.parent), Qt.TextElideMode.ElideMiddle, 540))
        text.addWidget(name)
        text.addWidget(path)
        lay.addLayout(text, 1)

        try:
            when = datetime.fromtimestamp(folder.stat().st_mtime).strftime("%d.%m.%Y")
        except OSError:
            when = ""
        if when:
            stamp = pill(when, "muted")
            stamp.setFont(mono_font(11))
            lay.addWidget(stamp, 0, Qt.AlignmentFlag.AlignVCenter)

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
        outer.setContentsMargins(32, 28, 32, 22)
        outer.addStretch(1)
        column = QWidget()
        column.setMaximumWidth(_COLUMN_WIDTH)
        outer.addWidget(column, 100)
        outer.addStretch(1)

        body = QVBoxLayout(column)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(16)

        # ── Hero Banner ──
        hero = QFrame()
        hero.setObjectName("HeroBanner")
        h_lay = QHBoxLayout(hero)
        h_lay.setContentsMargins(22, 18, 22, 18)
        h_lay.setSpacing(16)

        emblem = QLabel()
        emblem.setPixmap(build_app_icon().pixmap(QSize(46, 46)))
        h_lay.addWidget(emblem, 0, Qt.AlignmentFlag.AlignVCenter)

        hero_text = QVBoxLayout()
        hero_text.setSpacing(4)
        self.lbl_title = QLabel()
        self.lbl_title.setObjectName("PageTitle")
        self.lbl_sub = hint()
        hero_text.addWidget(self.lbl_title)
        hero_text.addWidget(self.lbl_sub)
        h_lay.addLayout(hero_text, 1)

        tags = QVBoxLayout()
        tags.setSpacing(6)
        tags.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        tag_row1 = QHBoxLayout()
        tag_row1.setSpacing(6)
        tag_row1.addStretch(1)
        self._pill_mcu = pill("RH850/F1L", "info")
        self._pill_can = pill("CAN 500 kbps", "ok")
        tag_row1.addWidget(self._pill_mcu)
        tag_row1.addWidget(self._pill_can)
        tags.addLayout(tag_row1)

        tag_row2 = QHBoxLayout()
        tag_row2.setSpacing(6)
        tag_row2.addStretch(1)
        self._pill_part = pill("3Q0 907 530", "muted")
        self._pill_part.setFont(mono_font(11, bold=True))
        self._pill_ext = pill("M95640 + OPBT", "muted")
        tag_row2.addWidget(self._pill_part)
        tag_row2.addWidget(self._pill_ext)
        tags.addLayout(tag_row2)
        h_lay.addLayout(tags)
        body.addWidget(hero)

        # ── Two Primary Workflow Cards ──
        self.tile_can = Section()
        self.tile_can.setObjectName("FeatureTile")
        self.tile_can.body.setContentsMargins(22, 20, 22, 20)
        self.tile_can.body.setSpacing(12)
        can_badge = QLabel()
        can_badge.setPixmap(tile_badge_pixmap("can", theme.ACCENT, 40))
        self.tile_can.head.insertWidget(0, can_badge)
        self.tile_can.head.setSpacing(12)
        self.lbl_can_meta = QLabel()
        self.lbl_can_meta.setFont(mono_font(11))
        self.lbl_can_meta.setProperty("tone", "muted")

        self.btn_read = button("", "PrimaryBtn", slot=self.read_can_requested.emit)
        self.btn_restore = button("", "GhostBtn", slot=self.restore_requested.emit)
        self.btn_wiring = button("", "GhostBtn", slot=self.wiring_requested.emit)

        self.tile_files = Section()
        self.tile_files.setObjectName("FeatureTile")
        self.tile_files.body.setContentsMargins(22, 20, 22, 20)
        self.tile_files.body.setSpacing(12)
        files_badge = QLabel()
        files_badge.setPixmap(tile_badge_pixmap("files", theme.OK, 40))
        self.tile_files.head.insertWidget(0, files_badge)
        self.tile_files.head.setSpacing(12)
        self.lbl_files_meta = QLabel()
        self.lbl_files_meta.setFont(mono_font(11))
        self.lbl_files_meta.setProperty("tone", "muted")

        self.btn_folder = button("", slot=lambda: self.open_folder_requested.emit(""))
        self.btn_files = button("", "GhostBtn", slot=self.open_files_requested.emit)

        tiles = QHBoxLayout()
        tiles.setSpacing(16)
        for tile, meta_lbl, actions in (
            (self.tile_can, self.lbl_can_meta, (self.btn_read, self.btn_restore, self.btn_wiring)),
            (self.tile_files, self.lbl_files_meta, (self.btn_folder, self.btn_files)),
        ):
            tile.body.addWidget(meta_lbl)
            tile.body.addStretch(1)
            tile.body.addWidget(divider())
            buttons = QHBoxLayout()
            buttons.setSpacing(8)
            for b in actions:
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                buttons.addWidget(b)
            buttons.addStretch(1)
            tile.body.addLayout(buttons)
            tiles.addWidget(tile, 1)
        body.addLayout(tiles)

        # ── Recent Workspaces ──
        recent_block = QVBoxLayout()
        recent_block.setSpacing(6)
        self.lbl_recent = group_label()
        recent_block.addWidget(self.lbl_recent)
        self.recent_list = QVBoxLayout()
        self.recent_list.setSpacing(6)
        recent_block.addLayout(self.recent_list)
        body.addLayout(recent_block)
        body.addStretch(1)

        self._unsub = subscribe_lang_change(lambda _l: self.retranslate_ui())
        self.destroyed.connect(lambda *_a, u=self._unsub: u())
        self.retranslate_ui()

    def refresh_recent(self) -> None:
        clear_layout(self.recent_list)
        folders = recent_folders()
        self.lbl_recent.setVisible(bool(folders))
        for folder in folders[:5]:
            r = _RecentRow(folder)
            r.clicked.connect(lambda f=folder: self.open_folder_requested.emit(str(f)))
            self.recent_list.addWidget(r)

    def retranslate_ui(self) -> None:
        self.lbl_title.setText(tr("Открыть блок", "Open an ECU"))
        self.lbl_sub.setText(
            tr(
                "Инженерный комплекс для шлюзов VAG MQB J533 Continental (3Q0 907 530 · Renesas RH850/F1L)",
                "Engineering suite for VAG MQB J533 Continental gateways (3Q0 907 530 · Renesas RH850/F1L)",
            )
        )
        self._pill_can.setText(tr("CAN 500 кбит/с", "CAN 500 kbps"))
        self.tile_can.set_text(
            tr("Блок на стенде или авто", "ECU over CAN"),
            tr(
                "Полная копия памяти по CAN: CodeFlash, DataFlash, Uflash, внешняя EEPROM и OPBT. После чтения блок откроется сам.",
                "Full memory backup over CAN: CodeFlash, DataFlash, Uflash, external EEPROM and OPBT. Opens automatically once read.",
            ),
        )
        self.lbl_can_meta.setText("CodeFlash 1.5M · DataFlash 64K · Uflash 32K · EEPROM 8K · OPBT")
        self.tile_files.set_text(
            tr("Дампы на диске", "Dumps on disk"),
            tr(
                "Папка с дампами CodeFlash, DataFlash и Uflash или отдельные файлы. Папку или файлы можно просто перетащить в окно.",
                "A folder with CodeFlash, DataFlash and Uflash dumps, or individual files. Drag & drop anywhere into this window.",
            ),
        )
        self.lbl_files_meta.setText(tr("Drag & Drop · Cflash / Dflash / Uflash / Eeprom / Opbt", "Drag & Drop · Cflash / Dflash / Uflash / Eeprom / Opbt"))
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
        self.lbl_recent.setText(tr("НЕДАВНИЕ БЛОКИ", "RECENT GATEWAYS"))
        self.refresh_recent()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        paths = [Path(u.toLocalFile()) for u in event.mimeData().urls() if u.toLocalFile()]
        if paths:
            self.files_dropped.emit(paths)
            event.acceptProposedAction()
