from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QWidget

from oscprecon.gui.task_manager import TaskManager
from oscprecon.gui.theme import icons, tokens


class TaskStatusBar(QWidget):
    # why: a strip showing every running recon task, each with its OWN prominent Stop button, so any
    # in-flight scan (main recon or a per-panel/service scan) is visible and individually stoppable,
    # the operator never gets stuck watching a long scan they can't kill (§23 Phase 5).
    def __init__(
        self, manager: TaskManager, theme_name: str = "dark", parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setObjectName("taskBar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._manager = manager
        self._theme = theme_name
        self._row = QHBoxLayout(self)
        self._row.setContentsMargins(tokens.SPACE_SM, 3, tokens.SPACE_SM, 3)
        self._row.setSpacing(tokens.SPACE_SM)
        manager.changed.connect(self.refresh)
        self.restyle(theme_name)
        self.refresh()

    def restyle(self, theme_name: str) -> None:
        self._theme = theme_name
        pal = tokens.palette(theme_name)
        # a warm-tinted bar when work is running so it reads as "active", muted when idle
        self.setStyleSheet(
            f'#taskBar[running="true"] {{ background:{pal.selection};'
            f" border:1px solid {pal.warning}; border-radius:{tokens.RADIUS_SM}px; }}"
            f"#taskBar QLabel {{ color:{pal.text}; }}"
            f"#taskBar QLabel#taskIdle {{ color:{pal.text_muted}; }}"
            f"#taskBar QFrame#taskChip {{ background:{pal.surface};"
            f" border:1px solid {pal.warning}; border-radius:{tokens.RADIUS_SM}px; }}"
            "#taskBar QPushButton {"
            f" color:#ffffff; background:{pal.warning}; border:none; font-weight:700;"
            f" border-radius:{tokens.RADIUS_SM}px; padding:2px {tokens.SPACE_SM}px; }}"
            f"#taskBar QPushButton:hover {{ background:{pal.error}; }}"
        )
        self.refresh()

    def _clear(self) -> None:
        while self._row.count():
            item = self._row.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()

    def _set_running(self, running: bool) -> None:
        # a dynamic property drives the QSS active/idle look; re-polish so it repaints
        self.setProperty("running", "true" if running else "false")
        style = self.style()
        if style is not None:
            style.unpolish(self)
            style.polish(self)

    def refresh(self) -> None:
        self._clear()
        tasks = self._manager.tasks()
        if not tasks:
            self._set_running(False)
            idle = QLabel("idle")
            idle.setObjectName("taskIdle")
            self._row.addWidget(idle)
            self._row.addStretch(1)
            return
        self._set_running(True)
        pal = tokens.palette(self._theme)
        spinner = QLabel("●")
        spinner.setStyleSheet(f"color:{pal.warning}; font-weight:700;")
        self._row.addWidget(spinner)
        self._row.addWidget(QLabel(f"{len(tasks)} scan{'s' if len(tasks) != 1 else ''} running:"))
        for task in tasks:
            # each scan is its own bordered chip (label + its Stop) so pairs never blur together
            chip = QFrame()
            chip.setObjectName("taskChip")
            chip_row = QHBoxLayout(chip)
            chip_row.setContentsMargins(tokens.SPACE_SM, 1, 3, 1)
            chip_row.setSpacing(tokens.SPACE_XS)
            chip_row.addWidget(QLabel(task.label))
            button = QPushButton(" Stop")
            button.setIcon(icons.get_icon("stop", "#ffffff", tokens.ICON_SM))
            button.setIconSize(QSize(tokens.ICON_SM, tokens.ICON_SM))
            button.setToolTip(f"Stop {task.label}")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda _checked=False, worker=task.worker: self._cancel(worker))
            chip_row.addWidget(button)
            self._row.addWidget(chip)
        if len(tasks) > 1:
            stop_all = QPushButton(" Stop all")
            stop_all.setIcon(icons.get_icon("stop", "#ffffff", tokens.ICON_SM))
            stop_all.setToolTip("Stop every running scan")
            stop_all.setCursor(Qt.CursorShape.PointingHandCursor)
            stop_all.clicked.connect(self._manager.cancel_all)
            self._row.addWidget(stop_all)
        self._row.addStretch(1)

    def _cancel(self, worker: object) -> None:
        self._manager.cancel(worker)
