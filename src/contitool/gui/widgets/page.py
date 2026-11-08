"""Small shared building blocks: sections, status pills, callouts, dialog frame, and layout helpers."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from contitool.gui.theme import mono_font, set_tone
from contitool.i18n import tr


class Section(QFrame):
    """Bordered surface with a title row (actions on the right), optional description, and body."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Section")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(20, 16, 20, 18)
        self.body.setSpacing(12)

        self.head = QHBoxLayout()
        self.head.setSpacing(8)
        self.lbl_title = QLabel()
        self.lbl_title.setObjectName("SectionTitle")
        self.head.addWidget(self.lbl_title)
        self.head.addStretch(1)
        self.body.addLayout(self.head)

        self.lbl_desc = QLabel()
        self.lbl_desc.setObjectName("Hint")
        self.lbl_desc.setWordWrap(True)
        self.lbl_desc.setVisible(False)
        self.body.addWidget(self.lbl_desc)

    def hide_head(self) -> None:
        """For sections whose heading is carried by their own content."""
        self.lbl_title.setVisible(False)
        self.body.removeItem(self.head)

    def set_text(self, title: str, desc: str = "") -> None:
        self.lbl_title.setText(title)
        self.lbl_desc.setText(desc)
        self.lbl_desc.setVisible(bool(desc))


class Callout(QFrame):
    """Tinted note with a coloured left rule; tone = info | ok | warn | err."""

    def __init__(self, tone: str = "info", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Callout")
        set_tone(self, tone)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        self.label = QLabel()
        self.label.setWordWrap(True)
        self.label.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(self.label)


def pill(text: str = "", tone: str = "muted") -> QLabel:
    """Rounded status badge; change later with set_pill()."""
    lbl = QLabel()
    lbl.setObjectName("Pill")
    set_pill(lbl, text, tone)
    return lbl


def set_pill(lbl: QLabel, text: str, tone: str) -> None:
    lbl.setText(text)
    set_tone(lbl, tone)
    lbl.setVisible(bool(text))


def group_label(text: str = "") -> QLabel:
    """Small uppercase caption separating groups of controls."""
    lbl = QLabel(text)
    lbl.setObjectName("GroupLabel")
    return lbl


def hint(text: str = "") -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("Hint")
    lbl.setWordWrap(True)
    return lbl


def clear_layout(layout: QLayout) -> None:
    """Remove and destroy every widget in a layout. Taking an item out is not enough: the
    widget keeps its parent and stays painted on top of whatever replaces it."""
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w is not None:
            w.setParent(None)
            w.deleteLater()
        elif item.layout() is not None:
            clear_layout(item.layout())


def divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    return line


def button(text: str, kind: str = "", slot=None) -> QPushButton:  # noqa: ANN001
    """QPushButton with an optional style kind (PrimaryBtn / DangerBtn / GhostBtn) and click handler."""
    b = QPushButton(text)
    if kind:
        b.setObjectName(kind)
    if slot is not None:
        b.clicked.connect(lambda _c=False: slot())
    return b


def row(*items: QWidget | QLayout | int, spacing: int = 8) -> QHBoxLayout:
    """Horizontal row; an int item inserts a stretch with that factor. Ends with a stretch unless one was given."""
    lay = QHBoxLayout()
    lay.setSpacing(spacing)
    for it in items:
        if isinstance(it, int):
            lay.addStretch(it)
        elif isinstance(it, QLayout):
            lay.addLayout(it)
        else:
            lay.addWidget(it)
    if not any(isinstance(it, int) for it in items):
        lay.addStretch(1)
    return lay


class Dialog(QDialog):
    """Modal dialog frame: title, optional subtitle, body, and a bottom button row (built per open, current language)."""

    def __init__(self, parent: QWidget | None, title: str, subtitle: str = "", width: int = 640) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self._min_width = width
        self.resize(width, 10)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(24, 20, 24, 20)
        self.body.setSpacing(14)
        lbl = QLabel(title)
        lbl.setObjectName("PageTitle")
        self.body.addWidget(lbl)
        if subtitle:
            self.body.addWidget(hint(subtitle))
        self.buttons = QHBoxLayout()
        self.buttons.setSpacing(8)

    def finish(self, *left: QWidget, ok: QPushButton | None = None, cancel_text: str = "") -> None:
        """Append the button row: `left` widgets, stretch, Cancel/Close, then the primary `ok` button."""
        self.body.addSpacing(4)
        for w in left:
            self.buttons.addWidget(w)
        self.buttons.addStretch(1)
        self.buttons.addWidget(button(cancel_text or tr("Отмена", "Cancel"), slot=self.reject))
        if ok is not None:
            ok.setDefault(True)
            self.buttons.addWidget(ok)
        self.body.addLayout(self.buttons)
        self.adjustSize()  # grow to fit the content the subclass just added
        self.resize(max(self.width(), self._min_width), self.height())


def run_dialog(dlg: QDialog) -> int:
    """exec() and then free the dialog: a parented dialog otherwise lives (and follows language switches) forever.
    Deletion waits for the event loop, so the caller can still read the dialog's fields right after this returns."""
    try:
        return dlg.exec()
    finally:
        dlg.deleteLater()


class TextResultDialog(Dialog):
    """Read-only monospace result with a Copy button (signatures, certificates, reports)."""

    def __init__(
        self,
        parent: QWidget | None,
        title: str,
        text: str,
        subtitle: str = "",
        width: int = 760,
        actions: tuple[QPushButton, ...] = (),
    ) -> None:
        super().__init__(parent, title, subtitle, width)
        self.txt = QPlainTextEdit(text)
        self.txt.setReadOnly(True)
        self.txt.setFont(mono_font(12))
        self.txt.setMinimumHeight(320)
        self.body.addWidget(self.txt, 1)
        copy = button(tr("Копировать", "Copy"), slot=lambda: QGuiApplication.clipboard().setText(text))
        self.finish(copy, *actions, cancel_text=tr("Закрыть", "Close"))
        self.resize(width, 560)
