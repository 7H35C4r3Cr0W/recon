from PySide6.QtCore import QEvent
from PySide6.QtWidgets import QApplication, QPushButton
from pytestqt.qtbot import QtBot

from oscprecon.gui.task_manager import TaskManager
from oscprecon.gui.widgets.task_status_bar import TaskStatusBar


class _FakeWorker:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


def _stop_buttons(bar: TaskStatusBar) -> list[QPushButton]:
    QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)  # reap old rows
    return list(bar.findChildren(QPushButton))


def test_task_bar_shows_stop_per_running_scan(qtbot: QtBot) -> None:
    mgr = TaskManager(4)
    bar = TaskStatusBar(mgr, "dark")
    qtbot.addWidget(bar)
    assert bar.property("running") in (False, "false")  # idle
    assert not _stop_buttons(bar)

    w1, w2 = _FakeWorker(), _FakeWorker()
    mgr.add(w1, "nmap -sCV", exclusive=True)
    mgr.add(w2, "feroxbuster :80")
    assert bar.property("running") == "true"
    buttons = _stop_buttons(bar)
    assert len(buttons) == 3  # one Stop per task + Stop all

    # each per-task Stop cancels its worker; Stop-all cancels everything
    buttons[0].click()
    assert w1.cancelled
    buttons[-1].click()  # Stop all
    assert w2.cancelled


def test_task_bar_returns_to_idle_when_scans_finish(qtbot: QtBot) -> None:
    mgr = TaskManager(4)
    bar = TaskStatusBar(mgr, "dark")
    qtbot.addWidget(bar)
    w = _FakeWorker()
    mgr.add(w, "nmap")
    assert bar.property("running") == "true"
    mgr.remove(w)
    assert bar.property("running") == "false"
    assert not _stop_buttons(bar)
