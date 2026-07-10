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
    QVBoxLayout,
    QWidget,
)

from oscprecon.models import DiscoveredService
from oscprecon.references import ServiceRef, expand_hint

_COMMAND_ROLE = Qt.ItemDataRole.UserRole


class ToolPanel(QWidget):
    run_requested = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._target = ""

        self._header = QLabel("No service selected.")
        self._header.setStyleSheet("font-weight: bold;")

        self._hints = QListWidget()
        self._hints.itemClicked.connect(self._on_hint_activated)
        self._hints.itemActivated.connect(self._on_hint_activated)
        hints_box = QGroupBox("Tool hints (click to load — never auto-run)")
        hints_layout = QVBoxLayout(hints_box)
        hints_layout.addWidget(self._hints)

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

        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addWidget(self._header)
        layout.addWidget(hints_box)
        layout.addLayout(command_row)
        layout.addWidget(self._output, stretch=1)

    def set_target(self, target: str) -> None:
        self._target = target

    def show_service(self, service: DiscoveredService | None, ref: ServiceRef | None) -> None:
        self._hints.clear()
        if service is None:
            self._header.setText("No service selected.")
            return
        label = ref.label if ref is not None else service.service
        self._header.setText(f"{service.port}/{service.proto.value} — {label}")
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
        self._run_button.setEnabled(not running)

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
