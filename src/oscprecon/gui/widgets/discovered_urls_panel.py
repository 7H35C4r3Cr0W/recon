from __future__ import annotations

import csv
from urllib.parse import urlsplit

from PySide6.QtCore import QPoint, Qt, QUrl
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oscprecon import findings as findings_mod
from oscprecon.gui.theme import tokens
from oscprecon.models import DiscoveredService
from oscprecon.modules.http import default_url, is_tls
from oscprecon.modules.http.parsers import is_source_disclosure
from oscprecon.profile import Profile

# Clean, sortable "site map" of what a content-discovery run found on the current web port — the
# excel-sheet view the raw feroxbuster/gobuster stream can't give: one row per URL, real columns,
# clickable to open in the browser, exportable to CSV. Reads the accumulated http findings
# (persisted across runs) so it grows as you dir-bust; the raw output pane is untouched. A live
# Filter box and a "hide static assets" toggle make the interesting URLs easy to find in a sea of
# js/css/image rows (the operator's real pain — "finding sites in the raw output is a pain").
_COLUMNS = ("Status", "Method", "Lines", "Words", "Bytes", "URL")
_URL_COL = 5
_URL_ROLE = int(Qt.ItemDataRole.UserRole)

# a discovered path whose extension is a static web asset (script/style/image/font/media) — noise
# when you are hunting for app endpoints, so the "hide static assets" toggle drops these rows.
_STATIC_EXT = frozenset(
    {
        "js", "mjs", "cjs", "jsx", "ts", "map",
        "css", "scss", "less",
        "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tif", "tiff",
        "woff", "woff2", "ttf", "eot", "otf",
        "mp4", "webm", "mp3", "ogg", "wav", "avi", "mov",
    }
)  # fmt: skip


def _is_static_asset(url: str) -> bool:
    path = (urlsplit(url).path or "").lower().rstrip("/")
    name = path.rsplit("/", 1)[-1]
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    return ext in _STATIC_EXT


class DiscoveredUrlsPanel(QWidget):
    def __init__(self, theme_name: str = "dark") -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._host_ip = ""  # a pivoted host's IP; "" = the entry target
        self._port = 0
        self._tls = False
        self._theme = theme_name
        self._flagged_total = 0

        self._count = QLabel("")
        self._count.setWordWrap(True)
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self.refresh)
        self._export_btn = QPushButton("Export CSV")
        self._export_btn.setToolTip("Save the shown rows as a .csv (opens in Excel / LibreOffice)")
        self._export_btn.clicked.connect(self._export_csv)
        self._export_btn.setEnabled(False)
        top = QHBoxLayout()
        top.addWidget(self._count, stretch=1)
        top.addWidget(self._refresh_btn)
        top.addWidget(self._export_btn)

        # find-a-site controls: a live substring filter (URL / status / method) + a noise toggle
        self._filter = QLineEdit()
        self._filter.setClearButtonEnabled(True)
        self._filter.setPlaceholderText("Filter URLs… (e.g. .php, admin, 200, login)")
        self._filter.textChanged.connect(self._apply_visibility)
        self._hide_static = QCheckBox("Hide static assets (js/css/img/fonts)")
        self._hide_static.setToolTip(
            "Hide script/style/image/font/media rows so app endpoints stand out"
        )
        self._hide_static.toggled.connect(self._apply_visibility)
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        filter_row.addWidget(self._filter, stretch=1)
        filter_row.addWidget(self._hide_static)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(list(_COLUMNS))
        self._table.setSortingEnabled(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.cellDoubleClicked.connect(self._open_row)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_menu)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(_URL_COL, QHeaderView.ResizeMode.Stretch)

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addLayout(filter_row)
        layout.addWidget(self._table, stretch=1)
        self._set_count_text(0, 0, 0)

    # --- wiring -------------------------------------------------------------------------------
    def set_theme(self, theme_name: str) -> None:
        self._theme = theme_name
        self.refresh()

    def set_profile(self, profile: Profile | None) -> None:
        self._profile = profile
        self.refresh()

    def configure(self, service: DiscoveredService, host_ip: str = "") -> None:
        self._port = service.port
        self._host_ip = host_ip
        self._tls = is_tls(service.service, service.port)
        self.refresh()

    # --- data ---------------------------------------------------------------------------------
    def refresh(self) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        rows = self._collect_rows()
        pal = tokens.palette(self._theme)
        for status, method, lines, words, size, url, is_src in rows:
            r = self._table.rowCount()
            self._table.insertRow(r)
            self._table.setItem(r, 0, self._status_item(status, pal))
            self._table.setItem(r, 1, QTableWidgetItem(method))
            self._table.setItem(r, 2, self._num_item(lines))
            self._table.setItem(r, 3, self._num_item(words))
            self._table.setItem(r, 4, self._num_item(size))
            self._table.setItem(r, _URL_COL, self._url_item(url, pal, is_src))
        self._table.setSortingEnabled(True)
        # deterministic, recon-useful default: 200s first (found pages), then the rest by status.
        # The user can re-sort by any column.
        self._table.sortItems(0, Qt.SortOrder.AscendingOrder)
        self._flagged_total = sum(1 for row in rows if row[6])
        self._export_btn.setEnabled(bool(rows))
        self._apply_visibility()

    def _passes(self, status: str, method: str, url: str) -> bool:
        # visibility predicate shared by the table (hide/show) and the CSV export (cleaned view).
        if self._hide_static.isChecked() and _is_static_asset(url):
            return False
        needle = self._filter.text().strip().lower()
        return not needle or needle in f"{status} {method} {url}".lower()

    def _apply_visibility(self) -> None:
        visible = 0
        flagged_visible = 0
        for r in range(self._table.rowCount()):
            status_item = self._table.item(r, 0)
            method_item = self._table.item(r, 1)
            status = status_item.text() if status_item else ""
            method = method_item.text() if method_item else ""
            url = self._row_url(r)
            show = self._passes(status, method, url)
            self._table.setRowHidden(r, not show)
            if show:
                visible += 1
                item = self._table.item(r, _URL_COL)
                if item is not None and item.text().startswith("⚠"):
                    flagged_visible += 1
        self._set_count_text(self._table.rowCount(), visible, flagged_visible)

    def _collect_rows(self) -> list[tuple[int, str, int, int, int, str, bool]]:
        # one row per discovered URL on the CURRENT web port — the dir-buster findings (status +
        # path), not the whatweb fingerprint note. Deduped by (status, path); newest run wins. The
        # trailing bool marks a source/backup/VCS disclosure (.swp/.bak/.git/~) — flagged loud.
        if self._profile is None or self._port == 0:
            return []
        host = self._host_ip or self._profile.target.host
        base = default_url(host, self._port, self._tls).rstrip("/")
        by_key: dict[tuple[int, str], tuple[int, str, int, int, int, str, bool]] = {}
        for f in findings_mod.load_findings(self._profile.directory):
            if f.get("module") != "http" or f.get("port") != self._port:
                continue
            status = _int(f.get("status"))
            path = str(f.get("path") or "")
            if not status or not path:
                continue
            if str(f.get("note") or "").startswith("whatweb"):  # a fingerprint, not a found URL
                continue
            by_key[(status, path)] = (
                status,
                str(f.get("method") or ""),
                _int(f.get("lines")),
                _int(f.get("words")),
                _int(f.get("size")),
                base + path,
                is_source_disclosure(path),
            )
        return sorted(by_key.values(), key=lambda r: (r[0], r[_URL_COL]))

    # --- table items --------------------------------------------------------------------------
    @staticmethod
    def _num_item(value: int) -> QTableWidgetItem:
        item = QTableWidgetItem()
        item.setData(Qt.ItemDataRole.DisplayRole, value)  # int -> numeric sort, not string sort
        item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return item

    def _status_item(self, status: int, pal: tokens.Palette) -> QTableWidgetItem:
        item = self._num_item(status)
        colour = {2: pal.success, 3: pal.accent, 4: pal.warning, 5: pal.error}.get(status // 100)
        if colour:
            item.setForeground(QBrush(QColor(colour)))
        return item

    def _url_item(self, url: str, pal: tokens.Palette, is_src: bool = False) -> QTableWidgetItem:
        # source/backup/VCS disclosures (login.php.swp, .git/, *.bak) get a ⚠ + warning colour so
        # they stand out among ordinary 200s; the plain URL still opens/copies via the role.
        item = QTableWidgetItem(f"⚠ {url}" if is_src else url)
        item.setData(_URL_ROLE, url)
        item.setForeground(QBrush(QColor(pal.warning if is_src else pal.accent)))
        item.setToolTip(
            "⚠ source / backup / VCS disclosure — download and read it (may leak source or "
            "credentials). Double-click to open."
            if is_src
            else "Double-click to open in the browser"
        )
        return item

    # --- interactions -------------------------------------------------------------------------
    def _row_url(self, row: int) -> str:
        item = self._table.item(row, _URL_COL)
        return str(item.data(_URL_ROLE)) if item is not None else ""

    def _open_row(self, row: int, _col: int) -> None:
        url = self._row_url(row)
        if url:
            QDesktopServices.openUrl(QUrl(url))

    def _show_menu(self, pos: QPoint) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        url = self._row_url(row)
        if not url:
            return
        menu = QMenu(self)
        open_action = menu.addAction("Open in browser")
        copy_action = menu.addAction("Copy URL")
        viewport = self._table.viewport()
        chosen = menu.exec(viewport.mapToGlobal(pos)) if viewport is not None else None
        if chosen == open_action:
            QDesktopServices.openUrl(QUrl(url))
        elif chosen == copy_action:
            clip = QGuiApplication.clipboard()
            if clip is not None:
                clip.setText(url)

    def _export_csv(self) -> None:
        if self._profile is None:
            return
        default = str(self._profile.directory / f"discovered-urls-{self._port}.csv")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export discovered URLs", default, "CSV (*.csv)"
        )
        if not path:
            return
        # export the CLEANED view: only rows the current filter + hide-static toggle keep, so the
        # exported sheet matches what the operator is looking at.
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(_COLUMNS)
            for status, method, lines, words, size, url, _is_src in self._collect_rows():
                if self._passes(str(status), method, url):
                    writer.writerow([status, method, lines, words, size, url])

    def _set_count_text(self, total: int, visible: int, flagged_visible: int) -> None:
        if total == 0:
            self._count.setText(
                "No discovered URLs yet — run feroxbuster / gobuster in Content discovery."
            )
            return
        flagged = (
            f"  —  ⚠ {flagged_visible} source/backup file(s) flagged" if flagged_visible else ""
        )
        shown = f"{visible}" if visible == total else f"{visible} of {total} (filtered)"
        self._count.setText(
            f"{shown} discovered URL(s) on port {self._port} — double-click a row to open it in "
            f"the browser, or Export CSV.{flagged}"
        )


def _int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return 0
    return 0
