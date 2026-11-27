"""Application settings dialog (update channel selector: stable vs candidate)."""

from __future__ import annotations

from PySide6.QtWidgets import QButtonGroup, QRadioButton, QVBoxLayout, QWidget

from contitool import __version__
from contitool.gui.update_check import get_update_channel, set_update_channel
from contitool.gui.widgets.page import Callout, Dialog, Section, button, hint
from contitool.i18n import tr
from contitool.updates import CHANNEL_CANDIDATE, CHANNEL_STABLE


class SettingsDialog(Dialog):
    """Settings dialog for selecting the ContiTool auto-update channel (`stable` or `candidate`)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            parent,
            tr("Настройки", "Settings"),
            tr(
                f"ContiTool {__version__} · параметры программы и обновлений",
                f"ContiTool {__version__} · application and update preferences",
            ),
            width=560,
        )
        self.initial_channel = get_update_channel()
        self.selected_channel = self.initial_channel
        self.check_now_requested = False

        sec = Section()
        sec.set_text(
            tr("Канал автообновлений", "Auto-update channel"),
            tr(
                "Выберите, какие релизы ContiTool будет предлагать при проверке обновлений на GitHub.",
                "Choose which GitHub releases ContiTool offers when checking for updates.",
            ),
        )

        self._group = QButtonGroup(self)

        self.rb_stable = QRadioButton(tr("stable — Стабильные релизы", "stable — Stable releases"))
        self._group.addButton(self.rb_stable)
        lbl_stable = hint(
            tr(
                "Проверенные основные релизы из ветки main. Рекомендуется для ежедневной работы.",
                "Verified main releases built from main. Recommended for everyday work.",
            )
        )
        lbl_stable.setContentsMargins(24, 0, 0, 6)

        self.rb_candidate = QRadioButton(tr("candidate — Кандидат-релизы (RC)", "candidate — Release candidates (RC)"))
        self._group.addButton(self.rb_candidate)
        lbl_cand = hint(
            tr(
                "Предварительные сборки новых версий (например, 2.3.0-rc1) до выхода в main, а также финальные релизы, "
                "когда они выйдут.",
                "Early release candidates ahead of main (such as 2.3.0-rc1), plus final stable releases once they ship.",
            )
        )
        lbl_cand.setContentsMargins(24, 0, 0, 2)

        box_lay = QVBoxLayout()
        box_lay.setContentsMargins(0, 2, 0, 2)
        box_lay.setSpacing(2)
        box_lay.addWidget(self.rb_stable)
        box_lay.addWidget(lbl_stable)
        box_lay.addWidget(self.rb_candidate)
        box_lay.addWidget(lbl_cand)
        sec.body.addLayout(box_lay)
        self.body.addWidget(sec)

        self.warn_candidate = Callout("warn")
        self.warn_candidate.label.setText(
            tr(
                "<b>Канал candidate содержит ранние тестовые сборки.</b> Часть функций может не работать, "
                "вести себя криво или быть сломана — работайте на столе и всегда сохраняйте полные бэкапы. "
                "Вернуться на стабильный канал можно в любой момент.",
                "<b>The candidate channel delivers early preview builds.</b> Features may fail, misbehave, or be "
                "broken — work on a bench and always keep full backups. You can switch back to stable at any time.",
            )
        )
        self.body.addWidget(self.warn_candidate)

        if self.initial_channel == CHANNEL_CANDIDATE:
            self.rb_candidate.setChecked(True)
        else:
            self.rb_stable.setChecked(True)
        self.rb_stable.toggled.connect(self._sync_ui)
        self.rb_candidate.toggled.connect(self._sync_ui)
        self._sync_ui()

        self.btn_check = button(
            tr("Проверить обновления сейчас", "Check for updates now"),
            "GhostBtn",
            slot=self._save_and_check,
        )
        self.btn_save = button(tr("Сохранить", "Save"), "PrimaryBtn", slot=self._save_only)
        self.finish(self.btn_check, ok=self.btn_save)

    def _current_choice(self) -> str:
        return CHANNEL_CANDIDATE if self.rb_candidate.isChecked() else CHANNEL_STABLE

    def _sync_ui(self) -> None:
        self.warn_candidate.setVisible(self.rb_candidate.isChecked())

    def _save_only(self) -> None:
        self.selected_channel = set_update_channel(self._current_choice())
        self.check_now_requested = False
        self.accept()

    def _save_and_check(self) -> None:
        self.selected_channel = set_update_channel(self._current_choice())
        self.check_now_requested = True
        self.accept()
