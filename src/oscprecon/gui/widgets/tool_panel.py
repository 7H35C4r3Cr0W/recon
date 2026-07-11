from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from oscprecon.gui.widgets.http_panel import HttpPanel
from oscprecon.models import DiscoveredService
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef, expand_hint

_COMMAND_ROLE = Qt.ItemDataRole.UserRole


class ToolPanel(QWidget):
    run_requested = Signal(str)
    http_run_requested = Signal(str, str, str, int)
    http_dry_run_requested = Signal(str)
    http_add_report_requested = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._target = ""

        self._header = QLabel("No service selected.")
        self._header.setStyleSheet("font-weight: bold;")

        # generic page: tool hints + ad-hoc command
        self._hints = QListWidget()
        self._hints.itemClicked.connect(self._on_hint_activated)
        self._hints.itemActivated.connect(self._on_hint_activated)
        hints_box = QGroupBox("Tool hints (click to load — never auto-run)")
        QVBoxLayout(hints_box).addWidget(self._hints)
        self._command = QLineEdit()
        self._command.setPlaceholderText("select a tool hint above, or type a command")
        self._run_button = QPushButton("Run")
        self._run_button.clicked.connect(self._emit_run)
        self._copy_button = QPushButton("Copy")
        self._copy_button.clicked.connect(self._copy_command)
        command_row = QHBoxLayout()
        command_row.addWidget(self._command, stretch=1)
        command_row.addWidget(self._run_button)
        command_row.addWidget(self._copy_button)
        generic = QWidget()
        generic_layout = QVBoxLayout(generic)
        generic_layout.addWidget(hints_box, stretch=1)
        generic_layout.addLayout(command_row)

        # http page: the command builder
        self._http = HttpPanel()
        self._http.run_requested.connect(self.http_run_requested)
        self._http.dry_run_requested.connect(self.http_dry_run_requested)
        self._http.add_report_requested.connect(self.http_add_report_requested)

        self._stack = QStackedWidget()
        self._stack.addWidget(generic)
        self._stack.addWidget(self._http)

        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addWidget(self._header)
        layout.addWidget(self._stack, stretch=2)
        layout.addWidget(self._output, stretch=1)

    def set_target(self, target: str) -> None:
        self._target = target

    def set_profile(self, profile: Profile) -> None:
        self._http.set_profile(profile)

    def show_service(self, service: DiscoveredService | None, ref: ServiceRef | None) -> None:
        self._hints.clear()
        if service is None:
            self._header.setText("No service selected.")
            self._stack.setCurrentIndex(0)
            return
        label = ref.label if ref is not None else service.service
        self._header.setText(f"{service.port}/{service.proto.value} — {label}")
        if ref is not None and ref.module == "http":
            self._http.configure(service, ref)
            self._stack.setCurrentWidget(self._http)
            return
        self._stack.setCurrentIndex(0)
        if ref is None:
            return
        for hint in ref.tools:
            expanded = expand_hint(
                hint.name, target=self._target, port=service.port, proto=service.proto.value
            )
            item = QListWidgetItem(f"{expanded}\n    {hint.purpose}")
            item.setData(_COMMAND_ROLE, expanded)
            self._hints.addItem(item)

    def set_running(self, running: bool) -> None:
        # why: the http builder persists into the shared Profile on every control change; disable it
        # during a scan so a UI edit can't race the worker thread's profile.save().
        self._run_button.setEnabled(not running)
        self._http.setEnabled(not running)

    def append_output(self, text: str) -> None:
        self._output.appendPlainText(text)

    def clear_output(self) -> None:
        self._output.clear()

    def _on_hint_activated(self, item: QListWidgetItem) -> None:
        command = item.data(_COMMAND_ROLE)
        if isinstance(command, str):
            self._command.setText(command)

    def _emit_run(self) -> None:
        command = self._command.text().strip()
        if command:
            self.run_requested.emit(command)

    def _copy_command(self) -> None:
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(self._command.text())
