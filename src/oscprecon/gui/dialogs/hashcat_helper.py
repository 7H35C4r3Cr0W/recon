from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
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

from oscprecon.gui.theme import styles
from oscprecon.references import hashcat as hc

_MODE_ROLE = Qt.ItemDataRole.UserRole


class HashcatHelperDialog(QDialog):
    """Hashcat mode helper — a DECISION AID for "which -m is this hash, and what's the command?".
    Search the hash type (apr1, ntlm, kerberos, sha512crypt, a -m number…), pick it, choose the
    attack mode + wordlist/mask, and copy the ready-to-run hashcat command. Display-only — Nabu
    never runs hashcat; you copy and run it."""

    def __init__(self, initial: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Hashcat mode helper")
        self.resize(920, 600)

        intro = QLabel(
            "Not sure which <b>-m</b> a hash is, or how to phrase the crack? Search the type, pick "
            "it, choose the attack + wordlist/mask, and copy the command. Reference only — nothing "
            'runs. Modes: <a href="https://hashcat.net/wiki/doku.php?id=example_hashes">hashcat</a>.'
        )
        intro.setWordWrap(True)
        intro.setOpenExternalLinks(True)

        self._filter = QLineEdit()
        self._filter.setPlaceholderText("search hash type… (apr1, ntlm, kerberos, 1800, shadow)")
        self._filter.textChanged.connect(self._apply_filter)

        self._list = QListWidget()
        self._list.setMinimumWidth(340)
        self._list.currentItemChanged.connect(self._rebuild)

        # right: the command builder
        self._attack = QComboBox()
        for a, name, _ in hc.ATTACK_MODES:
            self._attack.addItem(f"-a {a}  {name}", a)
        self._hashfile = QLineEdit("hash.txt")
        self._wordlist = QLineEdit("/usr/share/wordlists/rockyou.txt")
        self._mask = QLineEdit("?a?a?a?a?a?a")
        self._rules = QLineEdit()
        self._rules.setPlaceholderText("optional, e.g. /usr/share/hashcat/rules/best64.rule")
        for w in (self._attack, self._hashfile, self._wordlist, self._mask, self._rules):
            (w.currentIndexChanged if isinstance(w, QComboBox) else w.textChanged).connect(
                self._rebuild
            )

        form = QFormLayout()
        form.addRow("Attack mode:", self._attack)
        form.addRow("Hash file:", self._hashfile)
        form.addRow("Wordlist:", self._wordlist)
        form.addRow("Mask:", self._mask)
        form.addRow("Rules:", self._rules)

        self._picked = QLabel("← pick a hash type")
        self._picked.setWordWrap(True)
        self._picked.setStyleSheet("font-weight: 700;")
        self._command = QPlainTextEdit()
        self._command.setReadOnly(True)
        self._command.setFont(QFont("monospace"))
        self._command.setFixedHeight(60)
        self._copy = QPushButton("Copy command")
        self._copy.setStyleSheet(styles.accent_button())
        self._copy.clicked.connect(self._copy_command)

        charset = QLabel("Masks:  " + "   ".join(f"{c} {d[:16]}" for c, d in hc.CHARSETS[:6]))
        charset.setStyleSheet("color: #7f8c9a; font-size: 11px;")

        right = QVBoxLayout()
        right.addWidget(self._picked)
        right.addLayout(form)
        right.addWidget(QLabel("<b>Command (copy & run):</b>"))
        right.addWidget(self._command)
        right.addWidget(self._copy)
        right.addWidget(charset)
        right.addStretch(1)
        right_host = QWidget()
        right_host.setLayout(right)

        body = QHBoxLayout()
        left = QVBoxLayout()
        left.addWidget(self._filter)
        left.addWidget(self._list, stretch=1)
        left_host = QWidget()
        left_host.setLayout(left)
        body.addWidget(left_host)
        body.addWidget(right_host, stretch=1)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(body)

        self._populate(initial)
        self._filter.setText(initial)

    def _populate(self, query: str) -> None:
        self._list.clear()
        cat = ""
        for m in hc.search(query):
            if m.category != cat:
                cat = m.category
                header = QListWidgetItem(f"── {cat} ──")
                header.setFlags(Qt.ItemFlag.NoItemFlags)
                self._list.addItem(header)
            item = QListWidgetItem(f"-m {m.mode:<6} {m.name}")
            item.setData(_MODE_ROLE, m.mode)
            self._list.addItem(item)
        # auto-select the first real (non-header) row so the builder shows something
        for i in range(self._list.count()):
            if self._list.item(i).data(_MODE_ROLE) is not None:
                self._list.setCurrentRow(i)
                break

    def _apply_filter(self, text: str) -> None:
        self._populate(text)

    def _selected_mode(self) -> hc.HashMode | None:
        item = self._list.currentItem()
        if item is None:
            return None
        mode = item.data(_MODE_ROLE)
        if not isinstance(mode, int):
            return None
        return next((m for m in hc.load_modes() if m.mode == mode), None)

    def _rebuild(self, *_: object) -> None:
        m = self._selected_mode()
        if m is None:
            self._picked.setText("← pick a hash type")
            self._command.setPlainText("")
            return
        self._picked.setText(f"-m {m.mode} — {m.name}   ({m.category})")
        self._command.setPlainText(
            hc.build_command(
                m.mode,
                attack=self._attack.currentData() or "0",
                hashfile=self._hashfile.text().strip() or "hash.txt",
                wordlist=self._wordlist.text().strip(),
                mask=self._mask.text().strip(),
                rules=self._rules.text().strip(),
            )
        )

    def _copy_command(self) -> None:
        clip = QGuiApplication.clipboard()
        if clip is not None:
            clip.setText(self._command.toPlainText())
        styles.flash_copied(self._copy)
