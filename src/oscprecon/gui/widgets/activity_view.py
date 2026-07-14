from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oscprecon import audit
from oscprecon.gui.theme import tokens
from oscprecon.profile import Profile

# Read-only activity/audit surface: the append-only audit.jsonl (§6a) rendered newest-first. Secrets
# are already redacted at write time by the Auditor; this view only displays what is on disk.


def _summarize(details: dict[str, Any]) -> str:
    if not details:
        return ""
    parts = []
    for key, value in details.items():
        text = str(value)
        if len(text) > 60:
            text = text[:57] + "…"
        parts.append(f"{key}={text}")
    return ", ".join(parts)


class ActivityView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._profile: Profile | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            tokens.SPACE_MD, tokens.SPACE_MD, tokens.SPACE_MD, tokens.SPACE_MD
        )
        self._summary = QLabel("No project loaded.")
        self._summary.setStyleSheet(f"color:{tokens.DARK.text_muted};")
        layout.addWidget(self._summary)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Time", "Actor", "Action", "Details"])
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._table)

    def set_profile(self, profile: Profile | None) -> None:
        self._profile = profile
        self.reload()

    def reload(self) -> None:
        self._table.setUpdatesEnabled(False)  # batch the repaint over the bulk fill
        self._table.setRowCount(0)
        if self._profile is None:
            self._summary.setText("No project loaded.")
            self._table.setUpdatesEnabled(True)
            return
        entries = list(reversed(audit.load_entries(self._profile.directory)))  # newest first
        for entry in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(str(entry.get("ts", ""))))
            self._table.setItem(row, 1, QTableWidgetItem(str(entry.get("actor", ""))))
            self._table.setItem(row, 2, QTableWidgetItem(str(entry.get("action", ""))))
            details = entry.get("details", {})
            summary = _summarize(details if isinstance(details, dict) else {})
            self._table.setItem(row, 3, QTableWidgetItem(summary))
        self._table.resizeColumnsToContents()
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.setUpdatesEnabled(True)
        plural = "event" if len(entries) == 1 else "events"
        self._summary.setText(f"{len(entries)} {plural} (audit trail, newest first)")
