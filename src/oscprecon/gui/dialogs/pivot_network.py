from __future__ import annotations

import contextlib
from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon import pivot
from oscprecon.models import DiscoveredHost


class AddPivotNetworkDialog(QDialog):
    """Ingest a scan you ran across a pivot (ligolo-ng etc.) and fold the hosts into the topology.

    Nabu never runs the pivot scan — the user owns the tunnel. This just parses pasted / loaded
    nmap output (or a bare IP list) and returns the discovered hosts, tagged with the pivot host
    they were reached through so the graph can wire the spider-web.
    """

    def __init__(self, host_ips: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add pivoted network")
        self.resize(560, 460)
        self._hosts: list[DiscoveredHost] = []

        intro = QLabel(
            "Paste the output of a scan you ran across your pivot (e.g. "
            "<code>nmap -sV 10.10.5.0/24</code> through ligolo-ng), or a plain list of live IPs. "
            "Nabu parses it and adds the hosts to this project's topology graph."
        )
        intro.setWordWrap(True)

        self._pivot_source = QComboBox()
        self._pivot_source.addItems(host_ips)  # the host we reached the new network THROUGH
        self._pivot_source.setEditable(False)

        self._text = QPlainTextEdit()
        self._text.setPlaceholderText(
            "Nmap scan report for 10.10.5.23\n"
            "445/tcp  open  microsoft-ds  Windows Server 2019\n"
            "...\n\n— or just —\n\n10.10.5.23\n10.10.5.40\n172.16.8.10"
        )

        load = QPushButton("Load from file…")
        load.clicked.connect(self._load_file)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Add hosts")
        self._buttons.accepted.connect(self._on_accept)
        self._buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(QLabel("Pivoted in through:"))
        layout.addWidget(self._pivot_source)
        layout.addWidget(QLabel("Scan output / IP list:"))
        layout.addWidget(self._text, stretch=1)
        layout.addWidget(load)
        layout.addWidget(self._buttons)

    def _load_file(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(
            self, "Load scan output", "", "Text / nmap output (*.txt *.nmap *.gnmap);;All files (*)"
        )
        if chosen:
            with contextlib.suppress(OSError):
                text = Path(chosen).read_text(encoding="utf-8", errors="replace")
                self._text.setPlainText(text)

    def _on_accept(self) -> None:
        source = self._pivot_source.currentText().strip()
        self._hosts = pivot.parse_pivot_input(self._text.toPlainText(), pivot_source=source)
        self.accept()

    def hosts(self) -> list[DiscoveredHost]:
        return self._hosts
