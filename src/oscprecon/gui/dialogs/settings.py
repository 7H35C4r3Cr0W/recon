from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from oscprecon import config
from oscprecon.config import (
    CONCURRENCY_RANGE,
    FONT_SIZE_RANGE,
    HACKTRICKS_CACHE_DAYS_RANGE,
    SCAN_PROFILES,
    THEMES,
    Settings,
)
from oscprecon.references import live_hacktricks

# Mandatory, non-negotiable protections (CLAUDE.md §2) surfaced in the Privacy tab as locked-on
# controls — the settings UI must never offer a way to switch these off.
_MANDATORY_PROTECTIONS = (
    "Never index or display credential secrets (creds.json values)",
    "Exclude password wordlists (Passwords/, rockyou) from every picker",
    "Redact secrets in reports and the audit log (password=<redacted len=N>)",
)

_REPORT_GUARANTEES = (
    "Secrets are redacted — reports record only field names, source, and length.",
    "The prior report.md is archived to report-archive/ before every overwrite.",
    "Single-file Obsidian frontmatter (YAML) is emitted so reports drop into a vault.",
)


class SettingsDialog(QDialog):
    applied = Signal(object)  # emits the normalized Settings after a successful save

    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        self.resize(560, 440)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_workspace_tab(), "Workspace")
        self._tabs.addTab(self._build_appearance_tab(), "Appearance")
        self._tabs.addTab(self._build_tool_paths_tab(), "Tool paths")
        self._tabs.addTab(self._build_scan_tab(), "Scan")
        self._tabs.addTab(self._build_references_tab(), "References")
        self._tabs.addTab(self._build_reports_tab(), "Reports")
        self._tabs.addTab(self._build_privacy_tab(), "Privacy")
        self._tabs.addTab(self._build_performance_tab(), "Performance")
        self._tabs.addTab(self._build_advanced_tab(), "Advanced")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.RestoreDefaults
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        restore = buttons.button(QDialogButtonBox.StandardButton.RestoreDefaults)
        restore.clicked.connect(self._restore_defaults)

        layout = QVBoxLayout(self)
        layout.addWidget(self._tabs)
        layout.addWidget(buttons)

        self._populate(settings)

    # ----- tab construction -------------------------------------------------

    def _build_workspace_tab(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        self._workspace_edit = QLineEdit()
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_workspace)
        row = QHBoxLayout()
        row.addWidget(self._workspace_edit, stretch=1)
        row.addWidget(browse)
        container = QWidget()
        container.setLayout(row)
        form.addRow("Workspace root:", container)
        hint = QLabel("Profiles live directly under this folder. Created on save if missing.")
        hint.setWordWrap(True)
        form.addRow("", hint)
        return page

    def _build_appearance_tab(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        self._theme_combo = QComboBox()
        for name in THEMES:
            self._theme_combo.addItem(name.capitalize(), name)
        form.addRow("Theme:", self._theme_combo)

        self._font_override = QCheckBox("Override application font size")
        self._font_override.toggled.connect(self._on_font_override_toggled)
        self._font_size = QSpinBox()
        self._font_size.setRange(*FONT_SIZE_RANGE)
        form.addRow(self._font_override, self._font_size)
        note = QLabel("Off = use the system/Qt default font size.")
        note.setWordWrap(True)
        form.addRow("", note)
        return page

    def _build_tool_paths_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("Wordlist search paths:"))
        self._wordlist_list = QListWidget()
        layout.addWidget(self._wordlist_list, stretch=1)
        row = QHBoxLayout()
        add = QPushButton("Add…")
        add.clicked.connect(self._browse_wordlist_path)
        remove = QPushButton("Remove")
        remove.clicked.connect(self._remove_wordlist_path)
        row.addWidget(add)
        row.addWidget(remove)
        row.addStretch(1)
        layout.addLayout(row)
        note = QLabel("Password wordlists are always filtered out and never shown in pickers (§2).")
        note.setWordWrap(True)
        layout.addWidget(note)
        return page

    def _build_scan_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        row.addWidget(QLabel("Default scan profile:"))
        self._scan_profile = QComboBox()
        for name in SCAN_PROFILES:
            self._scan_profile.addItem(name.capitalize(), name)
        row.addWidget(self._scan_profile)
        row.addStretch(1)
        layout.addLayout(row)
        profile_note = QLabel(
            "quick = top-1000 TCP only · default = top-1000 → full -p- → UDP top-100 · "
            "full = default + the slow full UDP sweep · exam = speed-tuned, tight, exam-legal "
            "(no --script vuln). Override per-run from Scan → Run recon with profile."
        )
        profile_note.setWordWrap(True)
        layout.addWidget(profile_note)
        self._udp_full = QCheckBox("Also run a full UDP port sweep on 'Run Full Recon'")
        layout.addWidget(self._udp_full)
        note = QLabel(
            "Default UDP scan is the top-100 ports. Full UDP (nmap -sU -p-) is thorough but very "
            "slow — enable only when you can spare the time. The full profile includes it already."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self._spray_enabled = QCheckBox("Enable Spray mode (credential brute / spraying)")
        layout.addWidget(self._spray_enabled)
        spray_note = QLabel(
            "OFF by default. OSCP-legal against your OWN authorized targets (§ 2a). When on, it "
            "unlocks hydra/medusa/netexec list-spray and password wordlists against the active "
            "target. Never spray the exam VPN / control panel or any out-of-scope host."
        )
        spray_note.setWordWrap(True)
        layout.addWidget(spray_note)
        layout.addStretch(1)
        return page

    def _build_references_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self._ht_live = QCheckBox("Enable live HackTricks fetching")
        layout.addWidget(self._ht_live)
        intro = QLabel(
            "OFF by default. When on, the reference pane can fetch the single canonical HackTricks "
            "page mapped to a service (HTTPS, allow-listed host only) and cache it for offline "
            "viewing. Your target IP, banners, findings, and credentials are NEVER sent — only the "
            "mapped page URL is requested; local context just picks which local sections to show."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self._ht_auto = QCheckBox("Automatically refresh stale pages when a service is selected")
        layout.addWidget(self._ht_auto)
        self._ht_prefer = QCheckBox("Prefer a live-cached page over the vendored offline snapshot")
        layout.addWidget(self._ht_prefer)
        days_row = QHBoxLayout()
        days_row.addWidget(QLabel("Consider a cached page fresh for (days):"))
        self._ht_days = QSpinBox()
        self._ht_days.setRange(*HACKTRICKS_CACHE_DAYS_RANGE)
        days_row.addWidget(self._ht_days)
        days_row.addStretch(1)
        layout.addLayout(days_row)
        cache_row = QHBoxLayout()
        clear = QPushButton("Clear live HackTricks cache")
        clear.clicked.connect(self._clear_hacktricks_cache)
        cache_row.addWidget(clear)
        cache_row.addStretch(1)
        layout.addLayout(cache_row)
        self._ht_cache_loc = QLabel(f"Cache location: {live_hacktricks.cache_root()}")
        self._ht_cache_loc.setWordWrap(True)
        self._ht_cache_loc.setStyleSheet("color: gray;")
        layout.addWidget(self._ht_cache_loc)
        footer = QLabel(
            "The vendored offline snapshot always remains available as the reliable fallback. "
            "Clearing the cache only removes downloaded pages — it never touches project data."
        )
        footer.setWordWrap(True)
        layout.addWidget(footer)
        layout.addStretch(1)
        return page

    def _clear_hacktricks_cache(self) -> None:
        removed = live_hacktricks.clear_cache()
        QMessageBox.information(
            self, "HackTricks cache", f"Cleared {removed} cached page(s). Project data untouched."
        )

    def _build_reports_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("Report behaviour (fixed):"))
        for line in _REPORT_GUARANTEES:
            item = QLabel(f"• {line}")
            item.setWordWrap(True)
            layout.addWidget(item)
        layout.addStretch(1)
        return page

    def _build_privacy_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        heading = QLabel("Mandatory protections — always on, cannot be disabled:")
        heading.setWordWrap(True)
        layout.addWidget(heading)
        for text in _MANDATORY_PROTECTIONS:
            box = QCheckBox(text)
            box.setChecked(True)
            box.setEnabled(False)  # locked: no setting may switch these off
            layout.addWidget(box)
        footer = QLabel("Enforced by CLAUDE.md §2. These are not configurable by design.")
        footer.setWordWrap(True)
        layout.addWidget(footer)
        layout.addStretch(1)
        return page

    def _build_performance_tab(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        self._concurrency = QSpinBox()
        self._concurrency.setRange(*CONCURRENCY_RANGE)
        form.addRow("Max concurrent recon workers:", self._concurrency)
        note = QLabel("Caps how many tools run at once so an exam box isn't hammered.")
        note.setWordWrap(True)
        form.addRow("", note)
        return page

    def _build_advanced_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        path_row = QHBoxLayout()
        self._config_path = QLineEdit(str(config.config_dir() / "prefs.json"))
        self._config_path.setReadOnly(True)
        open_folder = QPushButton("Open folder")
        open_folder.clicked.connect(self._open_config_folder)
        path_row.addWidget(QLabel("Config file:"))
        path_row.addWidget(self._config_path, stretch=1)
        path_row.addWidget(open_folder)
        layout.addLayout(path_row)
        reset = QPushButton("Reset all settings to defaults")
        reset.clicked.connect(self._restore_defaults)
        layout.addWidget(reset)
        layout.addStretch(1)
        return page

    # ----- populate / collect ----------------------------------------------

    def _populate(self, settings: Settings) -> None:
        self._workspace_edit.setText(settings.workspace_root)
        idx = self._theme_combo.findData(settings.theme)
        self._theme_combo.setCurrentIndex(idx if idx >= 0 else 0)
        override = settings.font_size > 0
        self._font_override.setChecked(override)
        self._font_size.setEnabled(override)
        self._font_size.setValue(settings.font_size if override else FONT_SIZE_RANGE[0])
        self._wordlist_list.clear()
        self._wordlist_list.addItems(settings.wordlist_paths)
        prof_idx = self._scan_profile.findData(settings.scan_profile)
        self._scan_profile.setCurrentIndex(prof_idx if prof_idx >= 0 else 0)
        self._udp_full.setChecked(settings.nmap_udp_full)
        self._spray_enabled.setChecked(settings.spray_enabled)
        self._ht_live.setChecked(settings.hacktricks_live_enabled)
        self._ht_auto.setChecked(settings.hacktricks_auto_refresh)
        self._ht_prefer.setChecked(settings.hacktricks_prefer_live)
        self._ht_days.setValue(settings.hacktricks_cache_days)
        self._concurrency.setValue(settings.max_concurrency)

    def selected_settings(self) -> Settings:
        paths = [self._wordlist_list.item(i).text() for i in range(self._wordlist_list.count())]
        font = self._font_size.value() if self._font_override.isChecked() else 0
        return Settings(
            workspace_root=self._workspace_edit.text(),
            wordlist_paths=paths,
            theme=str(self._theme_combo.currentData()),
            font_size=font,
            max_concurrency=self._concurrency.value(),
            nmap_udp_full=self._udp_full.isChecked(),
            scan_profile=str(self._scan_profile.currentData()),
            spray_enabled=self._spray_enabled.isChecked(),
            hacktricks_live_enabled=self._ht_live.isChecked(),
            hacktricks_auto_refresh=self._ht_auto.isChecked(),
            hacktricks_prefer_live=self._ht_prefer.isChecked(),
            hacktricks_cache_days=self._ht_days.value(),
        ).normalized()

    # ----- actions ----------------------------------------------------------

    def _on_font_override_toggled(self, checked: bool) -> None:
        self._font_size.setEnabled(checked)

    def _restore_defaults(self) -> None:
        self._populate(config.default_settings())

    def _browse_workspace(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Workspace root", self._workspace_edit.text()
        )
        if chosen:
            self._workspace_edit.setText(chosen)

    def _browse_wordlist_path(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Add wordlist path")
        if chosen:
            self.add_wordlist_path(chosen)

    def add_wordlist_path(self, path: str) -> None:
        existing = {self._wordlist_list.item(i).text() for i in range(self._wordlist_list.count())}
        if path and path not in existing:
            self._wordlist_list.addItem(path)

    def _remove_wordlist_path(self) -> None:
        for item in self._wordlist_list.selectedItems():
            self._wordlist_list.takeItem(self._wordlist_list.row(item))

    def _open_config_folder(self) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(config.config_dir())))

    def _on_accept(self) -> None:
        settings = self.selected_settings()
        root = settings.workspace_root
        try:
            path = Path(root)
            if not path.exists():
                answer = QMessageBox.question(
                    self,
                    "Create workspace?",
                    f"The workspace folder does not exist:\n{root}\n\nCreate it now?",
                )
                if answer != QMessageBox.StandardButton.Yes:
                    return  # keep the dialog open so the user can fix the path
                path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(self, "Invalid workspace", f"Could not use that folder:\n{exc}")
            return
        config.save_settings(settings)
        self.applied.emit(settings)
        self.accept()
