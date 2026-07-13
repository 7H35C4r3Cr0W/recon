from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QPoint, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oscprecon import config
from oscprecon.gui.workspace.index_worker import WorkspaceIndexWorker
from oscprecon.profile import Profile
from oscprecon.workspace import STATUSES, ProfileSummary, all_views, health
from oscprecon.workspace.views import SavedView

_COLUMNS = ("Profile", "Target", "Status", "Tags", "Last activity", "Svc", "Find", "Cred", "Report")
_DIR_ROLE = Qt.ItemDataRole.UserRole


class WorkspaceDashboard(QWidget):
    """Home view: a searchable/filterable table of every profile in the workspace. Never shows a
    secret value — only counts. Scans off-thread via a cancellable worker."""

    open_requested = Signal(object)  # directory (Path)
    create_requested = Signal()
    details_requested = Signal(object)  # directory (Path)
    status_message = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._summaries: list[ProfileSummary] = []
        self._index_worker: WorkspaceIndexWorker | None = None

        new_btn = QPushButton("New Profile…")
        new_btn.clicked.connect(self.create_requested.emit)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        self._filter = QLineEdit()
        self._filter.setPlaceholderText("Filter by name / target / tag / status…")
        self._filter.setClearButtonEnabled(True)
        self._filter.textChanged.connect(self._apply_filters)
        self._view_combo = QComboBox()
        self._view_combo.currentIndexChanged.connect(self._apply_filters)
        self._show_archived = QCheckBox("Show archived")
        self._show_archived.toggled.connect(self._apply_filters)

        top = QHBoxLayout()
        top.addWidget(new_btn)
        top.addWidget(refresh_btn)
        top.addWidget(self._filter, stretch=1)
        top.addWidget(QLabel("View:"))
        top.addWidget(self._view_combo)
        top.addWidget(self._show_archived)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        self._table.itemActivated.connect(self._on_activated)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setAccessibleName("Workspace profiles")
        header = self._table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)

        self._empty = QLabel(
            "No profiles yet.\n\nUse “New Profile…” to create your first scan profile,\n"
            "or set the workspace root in Preferences."
        )
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty.setAccessibleName("Empty workspace guidance")
        self._stack = QStackedWidget()
        self._stack.addWidget(self._table)  # 0
        self._stack.addWidget(self._empty)  # 1

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self._stack, stretch=1)

        self._reload_views()

    # --- data loading (off-thread) ---
    def refresh(self) -> None:
        if self._index_worker is not None and self._index_worker.isRunning():
            self._index_worker.cancel()
            self._index_worker.wait()
        worker = WorkspaceIndexWorker(config.workspace_root())
        worker.done.connect(self._on_index_done)
        worker.failed.connect(
            lambda msg: self.status_message.emit(f"[workspace] scan failed: {msg}")
        )
        self._index_worker = worker
        worker.start()

    def _on_index_done(self, summaries: object) -> None:
        self._summaries = summaries if isinstance(summaries, list) else []
        self._reload_views()
        self._apply_filters()
        warn = sum(1 for s in self._summaries if s.corrupt or s.warnings)
        suffix = f" ({warn} need attention)" if warn else ""
        self.status_message.emit(f"[workspace] {len(self._summaries)} profiles{suffix}")

    def _reload_views(self) -> None:
        current = self._view_combo.currentText()
        self._view_combo.blockSignals(True)
        self._view_combo.clear()
        self._view_combo.addItem("All profiles")
        for view in all_views():
            self._view_combo.addItem(view.name)
        idx = self._view_combo.findText(current)
        self._view_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._view_combo.blockSignals(False)

    # --- filtering + population ---
    def _selected_view(self) -> SavedView | None:
        name = self._view_combo.currentText()
        return next((v for v in all_views() if v.name == name), None)

    def _visible_summaries(self) -> list[ProfileSummary]:
        needle = self._filter.text().strip().lower()
        view = self._selected_view()
        out: list[ProfileSummary] = []
        for summary in self._summaries:
            hide_archived = summary.archived and not self._show_archived.isChecked()
            if hide_archived and not (view is not None and view.archived):
                continue
            if view is not None and not view.matches(summary, self._service_names(summary)):
                continue
            if needle and not self._text_match(summary, needle):
                continue
            out.append(summary)
        return out

    @staticmethod
    def _text_match(summary: ProfileSummary, needle: str) -> bool:
        haystack = " ".join(
            [summary.name, summary.display_title, summary.target, summary.status, *summary.tags]
        ).lower()
        return needle in haystack

    @staticmethod
    def _service_names(summary: ProfileSummary) -> set[str]:
        try:
            data = json.loads((summary.directory / "profile.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError, UnicodeError):
            return set()
        services = data.get("discovered_services") if isinstance(data, dict) else None
        if not isinstance(services, list):
            return set()
        return {str(s.get("service", "")).lower() for s in services if isinstance(s, dict)}

    def _apply_filters(self) -> None:
        visible = self._visible_summaries()
        self._stack.setCurrentIndex(1 if not self._summaries else 0)
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for summary in visible:
            self._add_row(summary)
        self._table.setSortingEnabled(True)

    def _add_row(self, summary: ProfileSummary) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        pin = "📌 " if summary.pinned else ""
        warn = " ⚠" if (summary.corrupt or summary.warnings) else ""
        lock = " 🔒" if summary.locked else ""
        cells = [
            f"{pin}{summary.display_title or summary.name}{warn}{lock}",
            summary.target,
            "archived" if summary.archived else summary.status,
            ", ".join(summary.tags),
            summary.last_activity_at[:19].replace("T", " "),
            str(summary.service_count),
            str(summary.finding_count),
            str(summary.credential_count),  # count only — never a secret
            "✓" if summary.has_report else "",
        ]
        for col, text in enumerate(cells):
            item = QTableWidgetItem(text)
            if col == 0:
                item.setData(_DIR_ROLE, str(summary.directory))
                if summary.warnings:
                    item.setToolTip("; ".join(summary.warnings))
            self._table.setItem(row, col, item)

    # --- row actions ---
    def _row_dir(self, row: int) -> Path | None:
        item = self._table.item(row, 0)
        if item is None:
            return None
        value = item.data(_DIR_ROLE)
        return Path(str(value)) if value else None

    def _selected_dirs(self) -> list[Path]:
        rows = sorted({idx.row() for idx in self._table.selectedIndexes()})
        return [d for d in (self._row_dir(r) for r in rows) if d is not None]

    def _on_activated(self, item: QTableWidgetItem) -> None:
        directory = self._row_dir(item.row())
        if directory is not None:
            self.open_requested.emit(directory)

    def _on_context_menu(self, pos: QPoint) -> None:
        dirs = self._selected_dirs()
        if not dirs:
            return
        menu = QMenu(self)
        act_open = menu.addAction("Open")
        act_details = menu.addAction("Show details / health")
        menu.addSeparator()
        act_pin = menu.addAction("Toggle pin")
        act_tag = menu.addAction("Add tag…")
        act_status = menu.addAction("Change status…")
        act_archive = menu.addAction("Archive / restore")
        menu.addSeparator()
        act_folder = menu.addAction("Open folder")
        viewport = self._table.viewport()
        chosen = menu.exec(viewport.mapToGlobal(pos)) if viewport is not None else None
        if chosen is None:
            return
        if chosen is act_open:
            self.open_requested.emit(dirs[0])
        elif chosen is act_details:
            self._show_details(dirs[0])
        elif chosen is act_folder:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(dirs[0])))
        elif chosen is act_pin:
            self._mutate(dirs, lambda p: p.set_pinned(not p.organization_meta().pinned))
        elif chosen is act_archive:
            self._mutate(dirs, lambda p: p.set_archived(not p.organization_meta().archived))
        elif chosen is act_tag:
            tag, ok = QInputDialog.getText(self, "Add tag", "Tag:")
            if ok and tag.strip():
                self._mutate(dirs, lambda p, t=tag: p.add_tag(t))
        elif chosen is act_status:
            status, ok = QInputDialog.getItem(
                self, "Change status", "Status:", list(STATUSES), 0, False
            )
            if ok and status:
                self._mutate(dirs, lambda p, s=status: p.set_status(s))

    def _mutate(self, dirs: list[Path], op: object) -> None:
        changed = 0
        for directory in dirs:
            try:
                profile = Profile.load(directory)
                op(profile)  # type: ignore[operator]
                changed += 1
            except Exception as exc:  # boundary: one failure must not abort the rest
                self.status_message.emit(f"[workspace] {directory.name}: {exc}")
        if changed:
            self.status_message.emit(f"[workspace] updated {changed} profile(s)")
            self.refresh()

    def _show_details(self, directory: Path) -> None:
        summary = next((s for s in self._summaries if s.directory == directory), None)
        issues = health.check_profile(directory, workspace_root=config.workspace_root())
        lines = []
        if summary is not None:
            lines += [
                f"Target: {summary.target}",
                f"Status: {summary.status}   Tags: {', '.join(summary.tags) or '—'}",
                f"Services: {summary.service_count}   Findings: {summary.finding_count}   "
                f"Credentials: {summary.credential_count}",
                f"Report: {'yes' if summary.has_report else 'no'}   "
                f"Notes: {'yes' if summary.has_notes else 'no'}   "
                f"Graph: {'yes' if summary.has_graph else 'no'}",
                "",
            ]
        lines.append("Health:")
        lines += [f"  [{i.severity}] {i.message}" for i in issues] or ["  no issues"]
        box = QMessageBox(self)
        box.setWindowTitle(f"Details — {directory.name}")
        box.setText("\n".join(lines))  # plain text (never rich) so previews can't render markup
        self.details_requested.emit(directory)
        box.exec()

    def shutdown(self) -> None:
        if self._index_worker is not None and self._index_worker.isRunning():
            self._index_worker.cancel()
            self._index_worker.wait()
