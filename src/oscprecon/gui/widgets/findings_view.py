from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from oscprecon import finding_severity
from oscprecon import findings as findings_mod
from oscprecon.gui.dialogs.manual_finding import ManualFindingDialog
from oscprecon.gui.theme import styles, tokens
from oscprecon.profile import Profile

# Findings surface: everything parsed into findings.json in one place, carrying the same
# conservative category the graph uses (finding_severity), with search + category filtering. Rows
# are loaded once into `_all`; filtering re-populates the table from memory (no disk re-read).
# Operator-entered findings (§ manual findings) live here too — added / edited / deleted from this
# view, marked ✎, and shown with their PoC in the detail pane below the table.

# category -> palette FIELD (resolved against the active theme, so the colours adapt light/dark)
_CATEGORY_FIELD = {
    finding_severity.INFO: "text_muted",
    finding_severity.REFERENCE: "secondary",
    finding_severity.ACCESS: "warning",
    finding_severity.EXPOSURE: "warning",
    finding_severity.RELAY_RISK: "error",
}
_ALL_CATEGORIES = "All categories"
_NOTABLE_ONLY = "Notable only"
_MINE_ONLY = "My findings"
_ROW_ROLE = Qt.ItemDataRole.UserRole


class FindingsView(QWidget):
    changed = Signal(str)  # 'finding-added' | 'finding-edited' | 'finding-deleted'

    def __init__(self, theme_name: str = "dark", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._profile: Profile | None = None
        self._theme = theme_name
        self._all: list[dict[str, Any]] = []  # classified rows, loaded once per reload()

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
                _MINE_ONLY,
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

        # add / edit / delete YOUR OWN findings — the ones no parser can see [user request]
        actions = QHBoxLayout()
        self._summary = QLabel("No project loaded.")
        self._add_btn = QPushButton("＋ Add finding")
        self._add_btn.setToolTip(
            "Record something you found yourself — host, port, PoC and notes (Ctrl+Shift+F)"
        )
        self._add_btn.clicked.connect(self.add_finding)
        self._edit_btn = QPushButton("Edit")
        self._edit_btn.setToolTip("Edit the selected finding (your own findings only)")
        self._edit_btn.clicked.connect(self._edit_selected)
        self._edit_btn.setEnabled(False)
        self._delete_btn = QPushButton("Delete")
        self._delete_btn.setToolTip("Delete the selected finding (your own findings only)")
        self._delete_btn.clicked.connect(self._delete_selected)
        self._delete_btn.setEnabled(False)
        actions.addWidget(self._summary, stretch=1)
        actions.addWidget(self._add_btn)
        actions.addWidget(self._edit_btn)
        actions.addWidget(self._delete_btn)
        layout.addLayout(actions)

        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels(
            ["Category", "Module", "Kind", "Host", "Port", "Value", "Detail"]
        )
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSortingEnabled(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setTextElideMode(Qt.TextElideMode.ElideRight)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)  # Value — the finding itself
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)  # Detail
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.itemDoubleClicked.connect(lambda _item: self._edit_selected())
        layout.addWidget(self._table, stretch=3)

        # the full record of the selected finding — where PoC / notes / references are readable
        self._detail_view = QTextBrowser()
        self._detail_view.setOpenExternalLinks(False)
        self._detail_view.setMaximumHeight(190)
        self._detail_view.setVisible(False)
        layout.addWidget(self._detail_view, stretch=1)

        self._restyle()

    def focus_search(self) -> None:
        self._filter.setFocus()
        self._filter.selectAll()

    def set_theme(self, theme_name: str) -> None:
        self._theme = theme_name
        self._restyle()
        self._apply()  # re-render category/summary colours for the new theme

    def _restyle(self) -> None:
        pal = tokens.palette(self._theme)
        self._add_btn.setStyleSheet(styles.accent_button())
        self._detail_view.setStyleSheet(
            f"QTextBrowser {{ background: {pal.surface}; color: {pal.text};"
            f" border: 1px solid {pal.border}; border-radius: {tokens.RADIUS_SM}px;"
            f" padding: {tokens.SPACE_SM}px; }}"
        )

    def set_profile(self, profile: Profile | None) -> None:
        self._profile = profile
        self.reload()

    def reload(self) -> None:
        self._all = []
        if self._profile is not None:
            for finding in findings_mod.load_findings(self._profile.directory):
                port = finding.get("port")
                self._all.append(
                    {
                        "module": str(finding.get("module", "")),
                        "kind": str(finding.get("kind", "")),
                        "value": str(finding.get("value", "")),
                        "detail": str(finding.get("detail", "")),
                        "host": str(finding.get("host", "") or finding.get("vhost", "")),
                        "port": "" if port in (None, "") else str(port),
                        "category": finding_severity.category_of(finding),
                        "manual": bool(finding.get("manual")),
                        "raw": finding,
                    }
                )
        self._apply()

    def _matches(self, row: dict[str, Any], needle: str, category: str) -> bool:
        if category == _MINE_ONLY and not row["manual"]:
            return False
        if category == _NOTABLE_ONLY and not finding_severity.is_notable(str(row["category"])):
            return False
        if (
            category not in (_ALL_CATEGORIES, _NOTABLE_ONLY, _MINE_ONLY)
            and row["category"] != category
        ):
            return False
        if needle:
            hay = " ".join(
                str(row[k]) for k in ("module", "kind", "value", "detail", "host", "port")
            ).lower()
            # a hand-written finding is searchable by its PoC / reference text too
            if row["manual"]:
                raw = row["raw"]
                hay += f" {raw.get('poc', '')} {raw.get('reference', '')}".lower()
            if needle not in hay:
                return False
        return True

    def _apply(self, *_: Any) -> None:
        pal = tokens.palette(self._theme)
        self._summary.setStyleSheet(f"color:{pal.text_muted};")
        self._table.setUpdatesEnabled(False)  # one repaint after the bulk fill, not per row
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        if self._profile is None:
            self._summary.setText("No project loaded.")
            self._add_btn.setEnabled(False)
            self._table.setSortingEnabled(True)
            self._table.setUpdatesEnabled(True)
            self._update_buttons()
            return
        self._add_btn.setEnabled(not self._profile.read_only)
        needle = self._filter.text().strip().lower()
        category = self._category.currentText()
        shown = 0
        notable = 0  # count over the SHOWN rows so it can't contradict the filtered total
        mine = 0
        for row in self._all:
            if not self._matches(row, needle, category):
                continue
            r = self._table.rowCount()
            self._table.insertRow(r)
            label = str(row["category"])
            cat_item = QTableWidgetItem(f"✎ {label}" if row["manual"] else label)
            cat_item.setForeground(
                QColor(getattr(pal, _CATEGORY_FIELD.get(str(row["category"]), "text_muted")))
            )
            if row["manual"]:
                cat_item.setToolTip("Your own finding — double-click to edit")
            cat_item.setData(_ROW_ROLE, row)
            self._table.setItem(r, 0, cat_item)
            for column, key in (
                (1, "module"),
                (2, "kind"),
                (3, "host"),
                (5, "value"),
                (6, "detail"),
            ):
                self._table.setItem(r, column, QTableWidgetItem(str(row[key])))
            port_item = QTableWidgetItem()
            # numeric sort: ports must order 22 < 80 < 8080, not as strings
            port_item.setData(
                Qt.ItemDataRole.DisplayRole,
                int(row["port"]) if str(row["port"]).isdigit() else str(row["port"]),
            )
            self._table.setItem(r, 4, port_item)
            shown += 1
            if finding_severity.is_notable(str(row["category"])):
                notable += 1
            if row["manual"]:
                mine += 1
        self._table.resizeColumnsToContents()
        head = self._table.horizontalHeader()
        head.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        head.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self._table.setSortingEnabled(True)
        self._table.setUpdatesEnabled(True)
        filtered = "" if shown == len(self._all) else f" (of {len(self._all)})"
        plural = "finding" if shown == 1 else "findings"
        yours = f" · {mine} yours" if mine else ""
        self._summary.setText(
            f"{shown}{filtered} {plural} · {notable} notable{yours} "
            "(an open port / version / reference is not a confirmed vuln)"
        )
        self._update_buttons()

    # --- selection + detail pane ----------------------------------------------------------------
    def _selected_row(self) -> dict[str, Any] | None:
        items = self._table.selectedItems()
        if not items:
            return None
        first = self._table.item(items[0].row(), 0)
        data = first.data(_ROW_ROLE) if first is not None else None
        return data if isinstance(data, dict) else None

    def _on_selection_changed(self) -> None:
        self._update_buttons()
        row = self._selected_row()
        if row is None:
            self._detail_view.setVisible(False)
            return
        raw = row["raw"]
        parts = [f"<b>{_escape(str(raw.get('value', '')))}</b>"]
        meta = [
            f"category: {row['category']}",
            f"kind: {row['kind'] or '—'}",
            f"module: {row['module'] or '—'}",
        ]
        if row["host"]:
            meta.append(f"host: {row['host']}")
        if row["port"]:
            meta.append(f"port: {row['port']}")
        if raw.get("added_at"):
            meta.append(f"added: {raw['added_at']}")
        parts.append(f"<div style='opacity:0.7'>{_escape(' · '.join(meta))}</div>")
        if row["detail"]:
            parts.append(f"<p>{_escape(str(row['detail'])).replace(chr(10), '<br>')}</p>")
        if raw.get("poc"):
            parts.append(
                "<p><b>PoC / repro</b></p>"
                f"<pre style='white-space:pre-wrap'>{_escape(str(raw['poc']))}</pre>"
            )
        if raw.get("reference"):
            parts.append(f"<p>reference: {_escape(str(raw['reference']))}</p>")
        if raw.get("note") and not row["detail"]:
            parts.append(f"<p>{_escape(str(raw['note']))}</p>")
        self._detail_view.setHtml("".join(parts))
        self._detail_view.setVisible(True)

    def _update_buttons(self) -> None:
        row = self._selected_row()
        editable = (
            row is not None
            and bool(row["manual"])
            and self._profile is not None
            and not self._profile.read_only
        )
        self._edit_btn.setEnabled(editable)
        self._delete_btn.setEnabled(editable)

    # --- add / edit / delete --------------------------------------------------------------------
    def add_finding(self) -> None:
        if self._profile is None:
            return
        if self._profile.read_only:
            QMessageBox.information(
                self, "Read-only", "This project is open read-only — findings can't be added."
            )
            return
        dialog = ManualFindingDialog(self, self._profile)
        if dialog.exec() != int(ManualFindingDialog.DialogCode.Accepted):
            return
        findings_mod.add_manual_finding(self._profile.directory, dialog.finding())
        self.reload()
        self.changed.emit("finding-added")

    def _edit_selected(self) -> None:
        row = self._selected_row()
        if row is None or not row["manual"] or self._profile is None or self._profile.read_only:
            return
        raw = row["raw"]
        dialog = ManualFindingDialog(self, self._profile, raw)
        if dialog.exec() != int(ManualFindingDialog.DialogCode.Accepted):
            return
        findings_mod.update_manual_finding(
            self._profile.directory, str(raw.get("id", "")), dialog.finding()
        )
        self.reload()
        self.changed.emit("finding-edited")

    def _delete_selected(self) -> None:
        row = self._selected_row()
        if row is None or not row["manual"] or self._profile is None or self._profile.read_only:
            return
        raw = row["raw"]
        confirm = QMessageBox.question(
            self,
            "Delete finding",
            f"Delete your finding “{raw.get('value', '')}”?\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        findings_mod.delete_manual_finding(self._profile.directory, str(raw.get("id", "")))
        self.reload()
        self.changed.emit("finding-deleted")


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
