from pathlib import Path

from PySide6.QtCore import QThread
from PySide6.QtWidgets import QPushButton
from pytestqt.qtbot import QtBot

from oscprecon.gui.main_window import CancellableThread, MainWindow
from oscprecon.gui.task_manager import TaskManager
from oscprecon.gui.widgets.task_status_bar import TaskStatusBar
from oscprecon.models import Target
from oscprecon.profile import Profile


class _DummyWorker(QThread):
    def __init__(self) -> None:
        super().__init__()
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


class _BlockingWorker(CancellableThread):
    # a real in-flight worker: blocks in run() until its cancel Event is set (5s safety net)
    def run(self) -> None:
        self._cancel.wait(timeout=5.0)


def test_cancel_button_stops_a_real_inflight_worker(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.5")))
    worker = _BlockingWorker()
    window._launch(worker, "smb full")  # starts the thread; it blocks in run()
    assert window._tasks.active_count == 1

    buttons = window._task_bar.findChildren(QPushButton)
    assert len(buttons) == 1  # the ✕ for the running task
    buttons[0].click()  # cancel -> worker._cancel.set() -> run() returns -> finished -> _release
    qtbot.waitUntil(lambda: window._tasks.active_count == 0, timeout=5000)
    assert window._run_button.isEnabled() is True  # drained, exclusive nmap available again


def test_close_event_cancels_inflight_workers(qtbot: QtBot, tmp_path: Path) -> None:
    from PySide6.QtGui import QCloseEvent

    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.5")))
    worker = _BlockingWorker()
    window._launch(worker, "smb full")  # starts; blocks in run() until cancelled
    assert window._tasks.active_count == 1

    window.closeEvent(
        QCloseEvent()
    )  # must cancel first, then wait — not block for the 5s safety net
    assert worker._cancel.is_set()  # cancellation actually fired (else run() only exits on timeout)
    assert not worker.isRunning()


def test_status_bar_lists_tasks_with_working_cancel(qtbot: QtBot) -> None:
    manager = TaskManager()
    bar = TaskStatusBar(manager)
    qtbot.addWidget(bar)
    worker = _DummyWorker()
    manager.add(worker, "smb full")

    buttons = bar.findChildren(QPushButton)
    assert len(buttons) == 1  # one ✕ per running task
    buttons[0].click()
    assert worker.cancelled is True


def test_recon_handler_gated_at_capacity(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.5")))
    # fill the manager to its bound with unstarted dummies (no real subprocess)
    for i in range(window._tasks.max_concurrency):
        window._tasks.add(_DummyWorker(), f"filler-{i}")
    assert window._tasks.can_start() is False

    window._on_smb_recon("full")  # must be refused — no new worker launched
    assert window._tasks.active_count == window._tasks.max_concurrency


def test_nmap_exclusive_blocked_while_a_task_runs(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.5")))
    window._tasks.add(_DummyWorker(), "http:80")  # one parallel task running
    window._refresh_busy()
    assert window._run_button.isEnabled() is False  # full-recon (exclusive) must wait

    window._on_run()  # nmap refused while another task runs
    assert not any(task.exclusive for task in window._tasks.tasks())


def test_release_drains_and_reenables(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.5")))
    worker = _DummyWorker()
    window._tasks.add(worker, "smb full")
    window._refresh_busy()
    assert window._run_button.isEnabled() is False

    window._release(worker)
    assert window._tasks.active_count == 0
    assert window._run_button.isEnabled() is True  # exclusive nmap available again


def test_post_run_refresh_preserves_notes_and_tree_selection(qtbot: QtBot, tmp_path: Path) -> None:
    from oscprecon.models import DiscoveredService, Proto

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    prof.set_services(
        [
            DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at=""),
            DiscoveredService(port=80, proto=Proto.TCP, service="http", discovered_at=""),
        ]
    )
    window._set_profile(prof)

    # user is mid-edit in the notes pane, cursor parked mid-text, and has a service selected
    window._notes_pane._editor.setPlainText("root:root works on 445\nnext: check 80")
    window._notes_pane._editor.textCursor().setPosition(5)
    tree = window._service_tree
    tree.setCurrentItem(tree.topLevelItem(0).child(0))
    selected_before = tree.currentItem().text(0)

    # a background service worker finishes (discovered_services unchanged) -> post-run refresh
    window._post_run_refresh()

    assert window._notes_pane._editor.toPlainText() == "root:root works on 445\nnext: check 80"
    assert tree.currentItem() is not None
    assert tree.currentItem().text(0) == selected_before  # selection not churned
