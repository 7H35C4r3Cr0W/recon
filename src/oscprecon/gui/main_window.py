from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon import config
from oscprecon.models import Target
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile


class NewProfileDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New Scan Profile")
        self._name = QLineEdit()
        self._ip = QLineEdit()
        self._box = QComboBox()
        self._box.addItem("(none)")

        form = QFormLayout()
        form.addRow("Profile name:", self._name)
        form.addRow("Target IP / host:", self._ip)
        form.addRow("Box (optional):", self._box)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str]:
        return self._name.text().strip(), self._ip.text().strip()


class NmapWorker(QThread):
    line = Signal(str)
    done = Signal(int)
    failed = Signal(str)

    def __init__(self, profile: Profile, udp_full: bool = False) -> None:
        super().__init__()
        self._profile = profile
        self._udp_full = udp_full

    def run(self) -> None:
        try:
            orch = Orchestrator(self._profile, on_line=self.line.emit, udp_full=self._udp_full)
            orch.run_nmap()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(len(self._profile.discovered_services))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("oscp-recon")
        self.resize(900, 600)
        self._profile: Profile | None = None
        self._worker: NmapWorker | None = None
        self._recent_menu: QMenu
        self._new_action: QAction
        self._open_action: QAction
        self._save_action: QAction

        self._target_label = QLabel("No profile loaded.")
        self._run_button = QPushButton("Run nmap")
        self._run_button.setEnabled(False)
        self._run_button.clicked.connect(self._on_run)
        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self._target_label)
        layout.addWidget(self._run_button)
        layout.addWidget(self._output)
        self.setCentralWidget(central)

        self._build_menus()
        self._load_last_profile()

    def _build_menus(self) -> None:
        file_menu = self.menuBar().addMenu("&File")

        self._new_action = QAction("New Scan Profile...", self)
        self._new_action.setShortcut("Ctrl+N")
        self._new_action.triggered.connect(self._on_new)
        file_menu.addAction(self._new_action)

        self._open_action = QAction("Open Scan Profile...", self)
        self._open_action.setShortcut("Ctrl+O")
        self._open_action.triggered.connect(self._on_open)
        file_menu.addAction(self._open_action)

        self._recent_menu = file_menu.addMenu("Recent Profiles")
        self._rebuild_recent_menu()

        file_menu.addSeparator()
        self._save_action = QAction("Save", self)
        self._save_action.setShortcut("Ctrl+S")
        self._save_action.triggered.connect(self._on_save)
        file_menu.addAction(self._save_action)

        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def _rebuild_recent_menu(self) -> None:
        self._recent_menu.clear()
        recents = config.recent_profiles()
        if not recents:
            empty = QAction("(none)", self)
            empty.setEnabled(False)
            self._recent_menu.addAction(empty)
            return
        for path in recents:
            action = QAction(path, self)
            action.triggered.connect(
                lambda _checked=False, target=path: self._open_path(Path(target))
            )
            self._recent_menu.addAction(action)

    def _set_profile(self, profile: Profile) -> None:
        self._profile = profile
        target = profile.target
        label = f"{profile.profile_name} — {target.ip}"
        if target.hostname:
            label += f" ({target.hostname})"
        self._target_label.setText(label)
        self.setWindowTitle(f"oscp-recon — {profile.profile_name}")
        self._run_button.setEnabled(True)
        config.add_recent(profile.directory)
        self._rebuild_recent_menu()

    @staticmethod
    def _safe_load(path: Path) -> Profile | None:
        try:
            return Profile.load(path)
        except (OSError, ValueError, KeyError):
            return None

    def _load_last_profile(self) -> None:
        for path in config.recent_profiles():
            candidate = Path(path)
            if not (candidate / "profile.json").exists():
                continue
            profile = self._safe_load(candidate)
            if profile is None:
                self._output.appendPlainText(f"[skipped corrupt] {candidate}")
                continue
            self._set_profile(profile)
            self._output.appendPlainText(f"[restored] {candidate}")
            return

    def _on_new(self) -> None:
        dialog = NewProfileDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        name, ip = dialog.values()
        if not name or not ip:
            QMessageBox.warning(
                self, "Missing input", "Both a profile name and a target are required."
            )
            return
        try:
            profile = Profile.create(config.workspace_root(), name, Target(ip=ip))
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid target", str(exc))
            return
        self._output.clear()
        self._set_profile(profile)
        self._output.appendPlainText(f"[created] {profile.directory}")

    def _on_open(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Open Scan Profile", str(config.workspace_root())
        )
        if chosen:
            self._open_path(Path(chosen))

    def _open_path(self, path: Path) -> None:
        if not (path / "profile.json").exists():
            QMessageBox.warning(self, "Not a profile", f"{path} has no profile.json.")
            return
        profile = self._safe_load(path)
        if profile is None:
            QMessageBox.warning(self, "Corrupt profile", f"{path}/profile.json could not be read.")
            return
        self._output.clear()
        self._set_profile(profile)
        self._output.appendPlainText(f"[opened] {path}")

    def _on_save(self) -> None:
        if self._profile is not None:
            self._profile.save()
            self._output.appendPlainText("[saved]")

    def _set_busy(self, busy: bool) -> None:
        # why: the worker thread mutates and saves the shared Profile during a scan; locking
        # these entry points prevents a concurrent save from racing profile.json.
        self._new_action.setEnabled(not busy)
        self._open_action.setEnabled(not busy)
        self._save_action.setEnabled(not busy)
        self._recent_menu.setEnabled(not busy)
        self._run_button.setEnabled(not busy and self._profile is not None)

    def closeEvent(self, event: QCloseEvent) -> None:
        # why: destroying the window while the QThread runs aborts the process and can truncate
        # profile.json — wait for the in-flight scan to finish first.
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait()
        super().closeEvent(event)

    def _on_run(self) -> None:
        if self._profile is None or self._worker is not None:
            return
        self._set_busy(True)
        self._output.appendPlainText("[nmap] starting…")
        worker = NmapWorker(self._profile)
        worker.line.connect(self._output.appendPlainText)
        worker.done.connect(self._on_run_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_run_done(self, count: int) -> None:
        self._output.appendPlainText(f"[nmap] done — {count} services")
        self._finish_worker()

    def _on_run_failed(self, message: str) -> None:
        self._output.appendPlainText(f"[error] {message}")
        self._finish_worker()

    def _finish_worker(self) -> None:
        if self._worker is not None:
            self._worker.wait()
            self._worker = None
        if self._profile is not None:
            self._set_profile(self._profile)
        self._set_busy(False)
