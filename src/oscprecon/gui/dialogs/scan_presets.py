from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oscprecon.manual_commands import ManualCommand, expand

_PRESET_ROLE = Qt.ItemDataRole.UserRole


class ScanPresetsDialog(QDialog):
    """A browsable nmap-preset chooser, GROUPED BY CATEGORY. Pick a category (Fast / Full TCP /
    Stealth / UDP / AD / …), then a scan under it — its note ("what it's for") plus the exact
    command appear on the right, so you always see WHY before you Load or Run it. A filter narrows.

    Recon-only (§8): every preset is plain nmap. `mode()` is 'load' (pre-fill the command builder),
    'run' (execute this nmap scan against the entry target), or None (cancelled)."""

    def __init__(
        self, presets: list[ManualCommand], target: str, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Nmap scan options")
        self.resize(820, 520)
        self._presets = presets
        self._target = target
        self._mode: str | None = None
        self._command = ""

        intro = QLabel(
            "Pick a scan for the situation — grouped by category, with a note on what each is for. "
            "<b>Load into builder</b> pre-fills the command (review, then Run); "
            "<b>Run scan ▸</b> runs this nmap scan against the target now."
        )
        intro.setWordWrap(True)

        self._filter = QLineEdit()
        self._filter.setPlaceholderText("filter scans… (e.g. stealth, udp, full, web)")
        self._filter.textChanged.connect(self._apply_filter)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setMinimumWidth(340)
        self._build_tree()
        self._tree.currentItemChanged.connect(self._on_selection)

        self._desc = QLabel("")
        self._desc.setWordWrap(True)
        self._desc.setStyleSheet("font-weight: 600; font-size: 14px;")
        self._why = QLabel("")
        self._why.setWordWrap(True)
        self._why.setStyleSheet("color: palette(mid);")
        self._cmd = QPlainTextEdit()
        self._cmd.setReadOnly(True)
        self._cmd.setMaximumHeight(80)
        self._cmd.setStyleSheet("font-family: monospace;")

        right = QVBoxLayout()
        right.addWidget(self._desc)
        right.addWidget(self._why)
        right.addWidget(QLabel("Command:"))
        right.addWidget(self._cmd)
        right.addStretch(1)
        right_box = QWidget()
        right_box.setLayout(right)

        left = QVBoxLayout()
        left.setContentsMargins(0, 0, 0, 0)
        left.addWidget(self._filter)
        left.addWidget(self._tree)
        left_box = QWidget()
        left_box.setLayout(left)

        top = QHBoxLayout()
        top.addWidget(left_box)
        top.addWidget(right_box, stretch=1)

        self._load_btn = QPushButton("Load into builder")
        self._load_btn.clicked.connect(lambda: self._finish("load"))
        self._run_btn = QPushButton("Run scan ▸")
        self._run_btn.clicked.connect(lambda: self._finish("run"))
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(cancel)
        buttons.addWidget(self._load_btn)
        buttons.addWidget(self._run_btn)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(top, stretch=1)
        layout.addLayout(buttons)

        self._select_first_preset()

    def _build_tree(self) -> None:
        # group presets under their category header, preserving YAML order; uncategorised fall under
        # "Other" so nothing is ever hidden.
        by_cat: dict[str, list[ManualCommand]] = {}
        order: list[str] = []
        for preset in self._presets:
            cat = preset.category or "Other"
            if cat not in by_cat:
                by_cat[cat] = []
                order.append(cat)
            by_cat[cat].append(preset)
        for cat in order:
            parent = QTreeWidgetItem([cat])
            parent.setFirstColumnSpanned(True)
            flags = parent.flags() & ~Qt.ItemFlag.ItemIsSelectable  # header isn't a choice
            parent.setFlags(flags)
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            self._tree.addTopLevelItem(parent)
            for preset in by_cat[cat]:
                child = QTreeWidgetItem([preset.description])
                child.setToolTip(0, preset.why)
                child.setData(0, _PRESET_ROLE, preset)
                parent.addChild(child)
        self._tree.expandAll()

    def _select_first_preset(self) -> None:
        for i in range(self._tree.topLevelItemCount()):
            parent = self._tree.topLevelItem(i)
            if parent is not None and parent.childCount() > 0:
                self._tree.setCurrentItem(parent.child(0))
                return
        self._set_enabled(False)

    def _current_preset(self) -> ManualCommand | None:
        item = self._tree.currentItem()
        data = item.data(0, _PRESET_ROLE) if item is not None else None
        return data if isinstance(data, ManualCommand) else None

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        for i in range(self._tree.topLevelItemCount()):
            parent = self._tree.topLevelItem(i)
            if parent is None:
                continue
            shown = 0
            for j in range(parent.childCount()):
                child = parent.child(j)
                preset = child.data(0, _PRESET_ROLE) if child is not None else None
                hay = ""
                if isinstance(preset, ManualCommand):
                    hay = f"{parent.text(0)} {preset.description} {preset.why} {preset.command}"
                match = needle in hay.lower()
                if child is not None:
                    child.setHidden(not match)
                if match:
                    shown += 1
            parent.setHidden(shown == 0)

    def _set_enabled(self, on: bool) -> None:
        self._load_btn.setEnabled(on)
        self._run_btn.setEnabled(on)

    def _on_selection(self, current: QTreeWidgetItem | None, _prev: object = None) -> None:
        preset = self._current_preset()
        if preset is None:
            self._set_enabled(False)
            return
        self._set_enabled(True)
        self._desc.setText(preset.description)
        self._why.setText(preset.why)
        self._command = expand(preset.command, target=self._target)
        self._cmd.setPlainText(self._command)

    def _finish(self, mode: str) -> None:
        if self._current_preset() is None:
            return
        self._mode = mode
        self.accept()

    def mode(self) -> str | None:
        return self._mode

    def command(self) -> str:
        return self._command
