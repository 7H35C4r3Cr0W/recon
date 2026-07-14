from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oscprecon import finding_severity
from oscprecon import findings as findings_mod
from oscprecon.gui.theme import tokens
from oscprecon.profile import Profile

# Read-only findings surface: everything parsed into findings.json in one place, carrying the same
# conservative category the graph uses (finding_severity), with search + category filtering. Rows
# are loaded once into `_all`; filtering re-populates the table from memory (no disk re-read).

_CATEGORY_COLOR = {
    finding_severity.INFO: tokens.DARK.text_muted,
    finding_severity.REFERENCE: tokens.DARK.secondary,
    finding_severity.ACCESS: tokens.DARK.warning,
    finding_severity.EXPOSURE: tokens.DARK.warning,
    finding_severity.RELAY_RISK: tokens.DARK.error,
}
_ALL_CATEGORIES = "All categories"
_NOTABLE_ONLY = "Notable only"


class FindingsView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._profile: Profile | None = None
        self._all: list[dict[str, str]] = []  # classified rows, loaded once per reload()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            tokens.SPACE_MD, tokens.SPACE_MD, tokens.SPACE_MD, tokens.SPACE_MD
        )

        self._filter = QLineEdit()
        self._filter.setPlaceholderText("Search findings (module / kind / value / detail)…")
        self._filter.setClearButtonEnabled(True)
        self._filter.textChanged.connect(self._apply)
        self._filter.setAccessibleName("Findings search")
        self._category = QComboBox()
        self._category.addItems(
            [
                _ALL_CATEGORIES,
                _NOTABLE_ONLY,
                finding_severity.RELAY_RISK,
                finding_severity.EXPOSURE,
                finding_severity.ACCESS,
                finding_severity.REFERENCE,
                finding_severity.INFO,
            ]
        )
        self._category.currentIndexChanged.connect(self._apply)
        self._category.setAccessibleName("Findings category filter")
        top = QHBoxLayout()
        top.addWidget(self._filter, stretch=1)
        top.addWidget(QLabel("Category:"))
        top.addWidget(self._category)
        layout.addLayout(top)

        self._summary = QLabel("No project loaded.")
        self._summary.setStyleSheet(f"color:{tokens.DARK.text_muted};")
        layout.addWidget(self._summary)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Category", "Module", "Kind", "Value", "Detail"])
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSortingEnabled(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._table)

    def focus_search(self) -> None:
        self._filter.setFocus()
        self._filter.selectAll()

    def set_profile(self, profile: Profile | None) -> None:
        self._profile = profile
        self.reload()

    def reload(self) -> None:
        self._all = []
        if self._profile is not None:
            for finding in findings_mod.load_findings(self._profile.directory):
                kind = str(finding.get("kind", ""))
                value = str(finding.get("value", ""))
                detail = str(finding.get("detail", ""))
                self._all.append(
                    {
                        "module": str(finding.get("module", "")),
                        "kind": kind,
                        "value": value,
                        "detail": detail,
                        "category": finding_severity.classify(kind, value, detail),
                    }
                )
        self._apply()

    def _matches(self, row: dict[str, str], needle: str, category: str) -> bool:
        if category == _NOTABLE_ONLY and not finding_severity.is_notable(row["category"]):
            return False
        if category not in (_ALL_CATEGORIES, _NOTABLE_ONLY) and row["category"] != category:
            return False
        if needle:
            hay = " ".join(row[k] for k in ("module", "kind", "value", "detail")).lower()
            if needle not in hay:
                return False
        return True

    def _apply(self, *_: Any) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        if self._profile is None:
            self._summary.setText("No project loaded.")
            self._table.setSortingEnabled(True)
            return
        needle = self._filter.text().strip().lower()
        category = self._category.currentText()
        shown = 0
        notable = sum(1 for r in self._all if finding_severity.is_notable(r["category"]))
        for row in self._all:
            if not self._matches(row, needle, category):
                continue
            r = self._table.rowCount()
            self._table.insertRow(r)
            cat_item = QTableWidgetItem(row["category"])
            cat_item.setForeground(
                QColor(_CATEGORY_COLOR.get(row["category"], tokens.DARK.text_muted))
            )
            self._table.setItem(r, 0, cat_item)
            self._table.setItem(r, 1, QTableWidgetItem(row["module"]))
            self._table.setItem(r, 2, QTableWidgetItem(row["kind"]))
            self._table.setItem(r, 3, QTableWidgetItem(row["value"]))
            self._table.setItem(r, 4, QTableWidgetItem(row["detail"]))
            shown += 1
        self._table.resizeColumnsToContents()
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.setSortingEnabled(True)
        filtered = "" if shown == len(self._all) else f" (of {len(self._all)})"
        plural = "finding" if shown == 1 else "findings"
        self._summary.setText(
            f"{shown}{filtered} {plural} · {notable} notable "
            "(an open port / version / reference is not a confirmed vuln)"
        )
