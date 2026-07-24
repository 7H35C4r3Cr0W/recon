from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oscprecon import hosts
from oscprecon.profile import Profile

# Hosts Manager — the "clean and easy" /etc/hosts workflow. Recon on real engagements constantly
# turns up subdomains, vhosts and AD/DC names that must be mapped to an IP before they resolve; this
# dialog auto-collects every discovered (ip, hostname) for the profile, shows what's already mapped,
# and adds the checked ones in ONE action (writes /etc/hosts as root, else copies a sudo line).


class HostsManagerDialog(QDialog):
    def __init__(self, profile: Profile, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._profile = profile
        self.setWindowTitle("Hosts — add discovered names to /etc/hosts")
        self.setMinimumWidth(560)
        root = QVBoxLayout(self)

        root.addWidget(
            QLabel(
                "Discovered hostnames for this box (subdomains, vhosts, AD/DC names). Check the "
                "ones to map and press <b>Add checked → /etc/hosts</b>. Mapped ones are marked."
            )
        )

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Add", "IP", "Hostname", "Source"])
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self._table)

        # add a manual entry (an IP/name recon didn't capture)
        manual = QHBoxLayout()
        self._m_ip = QLineEdit()
        self._m_ip.setPlaceholderText("IP (e.g. 10.10.10.5)")
        self._m_host = QLineEdit()
        self._m_host.setPlaceholderText("hostname (e.g. internal.corp.local)")
        add_row_btn = QPushButton("Add row")
        add_row_btn.clicked.connect(self._add_manual_row)
        manual.addWidget(self._m_ip)
        manual.addWidget(self._m_host)
        manual.addWidget(add_row_btn)
        root.addLayout(manual)

        buttons = QHBoxLayout()
        self._status = QLabel("")
        buttons.addWidget(self._status)
        buttons.addStretch(1)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        self._add_btn = QPushButton("Add checked → /etc/hosts")
        self._add_btn.setDefault(True)
        self._add_btn.clicked.connect(self._on_add_checked)
        buttons.addWidget(close_btn)
        buttons.addWidget(self._add_btn)
        root.addLayout(buttons)

        self._reload()

    def _reload(self) -> None:
        self._table.setRowCount(0)
        mapped = hosts.current_mappings()
        for cand in hosts.collect_profile_hosts(self._profile):
            already = cand.hostname.lower() in mapped.get(cand.ip, set())
            self._append_row(
                cand.ip, cand.hostname, cand.source, checked=not already, already=already
            )

    def _append_row(
        self, ip: str, hostname: str, source: str, *, checked: bool, already: bool
    ) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        cb = QCheckBox()
        cb.setChecked(checked and not already)
        cb.setEnabled(not already)
        holder = QWidget()
        lay = QHBoxLayout(holder)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(cb)
        self._table.setCellWidget(row, 0, holder)
        self._table.setItem(row, 1, QTableWidgetItem(ip))
        self._table.setItem(row, 2, QTableWidgetItem(hostname))
        self._table.setItem(row, 3, QTableWidgetItem("in /etc/hosts" if already else source))
        holder.setProperty("nabu_cb", cb)

    def _checkbox(self, row: int) -> QCheckBox | None:
        holder = self._table.cellWidget(row, 0)
        cb = holder.property("nabu_cb") if holder is not None else None
        return cb if isinstance(cb, QCheckBox) else None

    def _add_manual_row(self) -> None:
        ip = self._m_ip.text().strip()
        host = self._m_host.text().strip()
        if not ip or not host:
            QMessageBox.warning(self, "Hosts", "Enter both an IP and a hostname.")
            return
        self._append_row(ip, host, "manual", checked=True, already=False)
        self._m_ip.clear()
        self._m_host.clear()

    def _checked_entries(self) -> list[tuple[str, str]]:
        entries: list[tuple[str, str]] = []
        for row in range(self._table.rowCount()):
            cb = self._checkbox(row)
            ip_item = self._table.item(row, 1)
            host_item = self._table.item(row, 2)
            if cb is not None and cb.isChecked() and ip_item and host_item:
                entries.append((ip_item.text(), host_item.text()))
        return entries

    def _on_add_checked(self) -> None:
        entries = self._checked_entries()
        if not entries:
            self._status.setText("Nothing checked to add.")
            return
        try:
            results = hosts.add_many(entries)
        except OSError:
            cmd = hosts.sudo_append_many(entries)
            clip = QGuiApplication.clipboard()
            if clip is not None:
                clip.setText(cmd)
            QMessageBox.information(
                self,
                "Hosts — needs root",
                "Nabu isn't running as root, so it can't edit /etc/hosts directly.\n\n"
                "A command to add all checked entries has been copied to your clipboard — paste it "
                "in a terminal:\n\n"
                f"  {cmd}",
            )
            return
        added = sum(1 for r in results if r.changed)
        self._reload()
        self._status.setText(f"Added {added} new mapping(s) ({len(entries)} checked).")
