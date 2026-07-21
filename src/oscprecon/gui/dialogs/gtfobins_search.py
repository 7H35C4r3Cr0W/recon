from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from oscprecon.gui.theme import styles, tokens
from oscprecon.references import gtfobins

_BIN_ROLE = Qt.ItemDataRole.UserRole


class GtfobinsDialog(QDialog):
    """Offline GTFOBins lookup. Search a binary you found (a SUID file, a sudo entry, a cap_setuid
    binary) and copy the exact abuse technique — grouped by function (shell / sudo / suid /
    capabilities / file-read / file-write / reverse-shell / …). Reference-only; Nabu never runs
    these — you copy the one you need into your foothold shell."""

    def __init__(self, initial: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("GTFOBins — Unix binary abuse lookup")
        self.resize(880, 560)

        intro = QLabel(
            "Found a SUID binary, a <b>sudo -l</b> entry, or a <b>cap_setuid</b> file? Search it "
            "here and copy the exact break-out. Offline reference — nothing runs; you paste it in "
            'your shell. Data: <a href="https://gtfobins.github.io/">GTFOBins</a>.'
        )
        intro.setWordWrap(True)
        intro.setOpenExternalLinks(True)

        self._filter = QLineEdit()
        self._filter.setPlaceholderText("search a binary or technique… (e.g. find, sudo, tar)")
        self._filter.textChanged.connect(self._apply_filter)

        self._list = QListWidget()
        self._list.setMinimumWidth(220)
        self._list.currentItemChanged.connect(self._on_select)

        self._title = QLabel("")
        self._title.setStyleSheet("font-size: 16px; font-weight: 700;")
        self._link = QLabel("")
        self._link.setOpenExternalLinks(True)
        self._cards_host = QWidget()
        self._cards = QVBoxLayout(self._cards_host)
        self._cards.setContentsMargins(0, 0, 0, 0)
        cards_scroll = QScrollArea()
        cards_scroll.setWidgetResizable(True)
        cards_scroll.setWidget(self._cards_host)

        right = QVBoxLayout()
        right.addWidget(self._title)
        right.addWidget(self._link)
        right.addWidget(cards_scroll, stretch=1)
        right_box = QWidget()
        right_box.setLayout(right)

        left = QVBoxLayout()
        left.setContentsMargins(0, 0, 0, 0)
        left.addWidget(self._filter)
        left.addWidget(self._list, stretch=1)
        left_box = QWidget()
        left_box.setLayout(left)

        body = QHBoxLayout()
        body.addWidget(left_box)
        body.addWidget(right_box, stretch=1)

        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(close)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(body, stretch=1)
        layout.addLayout(buttons)

        self._reload(initial)
        if initial:
            self._filter.setText(initial)

    def _reload(self, query: str) -> None:
        self._list.clear()
        for binary in gtfobins.search(query):
            item = QListWidgetItem(f"{binary.name}   ·   {', '.join(binary.functions)}")
            item.setData(_BIN_ROLE, binary.name)
            item.setToolTip(", ".join(binary.functions))
            self._list.addItem(item)
        if self._list.count():
            self._list.setCurrentRow(0)
        else:
            self._show_binary(None)

    def _apply_filter(self, text: str) -> None:
        self._reload(text)

    def _on_select(self, current: QListWidgetItem | None, _prev: object = None) -> None:
        name = current.data(_BIN_ROLE) if current is not None else None
        self._show_binary(gtfobins.get(name) if isinstance(name, str) else None)

    def _clear_cards(self) -> None:
        while self._cards.count():
            item = self._cards.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()

    def _show_binary(self, binary: gtfobins.Binary | None) -> None:
        self._clear_cards()
        if binary is None:
            self._title.setText("No match")
            self._link.setText("")
            return
        self._title.setText(binary.name)
        self._link.setText(f'<a href="{binary.url}">View on GTFOBins ↗</a>')
        for tech in binary.techniques:
            self._cards.addWidget(self._technique_card(tech))
        self._cards.addStretch(1)

    def _technique_card(self, tech: gtfobins.Technique) -> QWidget:
        pal = tokens.active_palette()
        card = QFrame()
        card.setFrameShape(QFrame.Shape.StyledPanel)
        card.setStyleSheet(
            f"QFrame {{ background:{pal.surface_alt}; border:1px solid {pal.border};"
            f" border-radius:{tokens.RADIUS_SM}px; }}"
        )
        outer = QVBoxLayout(card)
        head = QLabel(f"<b>{tech.func}</b>")
        head.setStyleSheet(f"color:{pal.accent};")
        outer.addWidget(head)
        body = QPlainTextEdit(tech.code)
        body.setReadOnly(True)
        body.setFont(QFont("monospace"))
        body.setFixedHeight(46)
        row = QHBoxLayout()
        row.addWidget(body, stretch=1)
        copy = QPushButton("Copy")
        copy.clicked.connect(lambda _=False, code=tech.code, b=copy: self._copy(code, b))
        row.addWidget(copy, alignment=Qt.AlignmentFlag.AlignTop)
        outer.addLayout(row)
        return card

    @staticmethod
    def _copy(text: str, button: QPushButton) -> None:
        clip = QGuiApplication.clipboard()
        if clip is not None:
            clip.setText(text)
        styles.flash_copied(button)
