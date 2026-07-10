from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon import wordlists

_PATH_ROLE = Qt.ItemDataRole.UserRole


class _IndexWorker(QThread):
    ready = Signal(object)  # list[wordlists.Wordlist]

    def __init__(self, paths: Iterable[Path] | None) -> None:
        super().__init__()
        self._paths = list(paths) if paths is not None else None

    def run(self) -> None:
        try:
            result = wordlists.index_wordlists(self._paths)
        except Exception:  # boundary: never let indexing crash the worker
            result = []
        self.ready.emit(result)


class WordlistPicker(QWidget):
    wordlist_chosen = Signal(str)
    indexed = Signal()

    def __init__(self, paths: Iterable[Path] | None = None) -> None:
        super().__init__()
        self._paths = list(paths) if paths is not None else None
        self._all: list[wordlists.Wordlist] = []
        self._worker: _IndexWorker | None = None

        self._search = QLineEdit()
        self._search.setPlaceholderText("filter wordlists…")
        self._search.textChanged.connect(self._refresh)
        self._category = QComboBox()
        self._category.addItem("all")
        self._category.currentTextChanged.connect(self._refresh)
        top = QHBoxLayout()
        top.addWidget(self._search, stretch=1)
        top.addWidget(self._category)

        self._list = QListWidget()
        self._list.itemActivated.connect(self._on_activated)

        self._favorite_button = QPushButton("★ toggle favorite")
        self._favorite_button.clicked.connect(self._toggle_favorite)
        buttons = QHBoxLayout()
        buttons.addWidget(self._favorite_button)
        buttons.addStretch(1)

        self._status = QLabel("indexing…")

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self._list, stretch=1)
        layout.addLayout(buttons)
        layout.addWidget(self._status)

        self.reindex()

    def reindex(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return  # already indexing — don't orphan the running thread by overwriting the slot
        self._status.setText("indexing…")
        worker = _IndexWorker(self._paths)
        worker.ready.connect(self._on_indexed)
        self._worker = worker
        worker.start()

    def shutdown(self) -> None:
        # why: the index worker walks the whole wordlist corpus and is often still running when the
        # dialog closes — wait for it so the QThread is never destroyed while running (SIGABRT).
        worker = self._worker
        if worker is not None and worker.isRunning():
            worker.wait()
        self._worker = None

    def closeEvent(self, event: QCloseEvent) -> None:
        self.shutdown()
        super().closeEvent(event)

    def selected_path(self) -> str | None:
        item = self._list.currentItem()
        if item is None:
            return None
        path = item.data(_PATH_ROLE)
        return path if isinstance(path, str) else None

    def _on_indexed(self, result: object) -> None:
        if self._worker is not None:
            self._worker.wait()
            self._worker = None
        self._all = result if isinstance(result, list) else []
        categories = sorted({w.category for w in self._all})
        self._category.blockSignals(True)
        self._category.clear()
        self._category.addItem("all")
        for category in categories:
            self._category.addItem(category)
        self._category.blockSignals(False)
        self._status.setText(f"{len(self._all)} wordlists")
        self._refresh()
        self.indexed.emit()

    def _matches(self, wordlist: wordlists.Wordlist) -> bool:
        category = self._category.currentText()
        if category != "all" and wordlist.category != category:
            return False
        text = self._search.text().strip().lower()
        if not text:
            return True
        return text in wordlist.name.lower() or text in str(wordlist.path).lower()

    def _refresh(self) -> None:
        self._list.clear()
        favorites = set(wordlists.favorites())
        visible = [w for w in self._all if self._matches(w)]
        visible.sort(key=lambda w: (str(w.path) not in favorites, w.name.lower()))
        for wordlist in visible:
            star = "★ " if str(wordlist.path) in favorites else "  "
            size_kb = wordlist.size_bytes / 1024
            item = QListWidgetItem(
                f"{star}{wordlist.name}   [{wordlist.category}]  "
                f"{wordlist.line_count} lines, {size_kb:.0f} KB"
            )
            item.setData(_PATH_ROLE, str(wordlist.path))
            self._list.addItem(item)

    def _on_activated(self, item: QListWidgetItem) -> None:
        path = item.data(_PATH_ROLE)
        if isinstance(path, str):
            self.wordlist_chosen.emit(path)

    def _toggle_favorite(self) -> None:
        path = self.selected_path()
        if path is None:
            return
        if wordlists.is_favorite(path):
            wordlists.remove_favorite(path)
        else:
            wordlists.add_favorite(path)
        self._refresh()
