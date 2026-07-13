from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oscprecon import finding_severity
from oscprecon import findings as findings_mod
from oscprecon.gui.theme import tokens
from oscprecon.profile import Profile

# Read-only findings surface: everything parsed into findings.json, grouped in one place, with the
# same conservative category the graph uses (finding_severity). A dedicated, richer findings view
# (filter/group/search) is a later chunk; this is the honest nav destination for now.

_CATEGORY_COLOR = {
    finding_severity.INFO: tokens.DARK.text_muted,
    finding_severity.REFERENCE: tokens.DARK.secondary,
    finding_severity.ACCESS: tokens.DARK.warning,
    finding_severity.EXPOSURE: tokens.DARK.warning,
    finding_severity.RELAY_RISK: tokens.DARK.error,
}


class FindingsView(QWidget):
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

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Category", "Module", "Kind", "Value", "Detail"])
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._table)

    def set_profile(self, profile: Profile | None) -> None:
        self._profile = profile
        self.reload()

    def reload(self) -> None:
        self._table.setRowCount(0)
        if self._profile is None:
            self._summary.setText("No project loaded.")
            return
        rows = findings_mod.load_findings(self._profile.directory)
        notable = 0
        for finding in rows:
            kind = str(finding.get("kind", ""))
            value = str(finding.get("value", ""))
            detail = str(finding.get("detail", ""))
            module = str(finding.get("module", ""))
            category = finding_severity.classify(kind, value, detail)
            if finding_severity.is_notable(category):
                notable += 1
            row = self._table.rowCount()
            self._table.insertRow(row)
            cat_item = QTableWidgetItem(category)
            cat_item.setForeground(QColor(_CATEGORY_COLOR.get(category, tokens.DARK.text_muted)))
            self._table.setItem(row, 0, cat_item)
            self._table.setItem(row, 1, QTableWidgetItem(module))
            self._table.setItem(row, 2, QTableWidgetItem(kind))
            self._table.setItem(row, 3, QTableWidgetItem(value))
            self._table.setItem(row, 4, QTableWidgetItem(detail))
        self._table.resizeColumnsToContents()
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        plural = "finding" if len(rows) == 1 else "findings"
        self._summary.setText(
            f"{len(rows)} {plural} · {notable} notable "
            "(an open port / version / reference is not a confirmed vuln)"
        )
        self._table.setTextElideMode(Qt.TextElideMode.ElideRight)
