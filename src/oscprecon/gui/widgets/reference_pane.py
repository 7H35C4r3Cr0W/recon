from __future__ import annotations

import os
import time
from typing import Any

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from oscprecon import hacktricks
from oscprecon.gui.theme import styles, tokens
from oscprecon.models import DiscoveredService
from oscprecon.references import ExploitHit, ServiceRef, sections
from oscprecon.references.live_hacktricks import LiveResult

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView

    _WEBVIEW_IMPORTED = True
except ImportError:  # pragma: no cover - QtWebEngine ships with PySide6-Addons
    _WEBVIEW_IMPORTED = False

_URL_ROLE = Qt.ItemDataRole.UserRole
_LABEL_ROLE = Qt.ItemDataRole.UserRole + 1

# finding-aware jump: module -> finding-kind -> a heading/keyword that exists in the vendored page.
# Keys are REAL parser finding kinds; keywords are verified against the cleaned page by
# test_finding_sections_keywords_exist — a runtime miss is a no-op, never an error. The kinds come
# from each module's parser (e.g. smb emits auth/share/policy/signing; ldap emits bind/...).
_FINDING_SECTIONS: dict[str, dict[str, str]] = {
    "smb": {
        "auth": "Server Enumeration",
        "share": "Shared Folders Enumeration",
        "policy": "Password Policy",
        "signing": "What is NTLM",
    },
    "ftp": {"auth": "Anonymous login", "banner": "Banner Grabbing"},
    "ssh": {
        "algo-weak": "Weak Cipher Algorithms",
        "auth": "Username Enumeration",
        "banner": "Banner Grabbing",
        "hostkey": "Public SSH key",
    },
    "ldap": {
        "bind": "Anonymous Access",
        "naming-context": "Anonymous LDAP enumeration",
        "user": "LDAP anonymous binds",
    },
    "snmp": {
        "community": "Community Strings",
        "interface": "Enumerating SNMP",
        "process": "Enumerating SNMP",
        "user": "Enumerating SNMP",
    },
    "smtp": {
        "banner": "Banner Grabbing",
        "ntlm": "NTLM Auth",
        "open-relay": "Open Relay",
        "verb": "VRFY",
    },
    "nfs": {"access": "Mounting", "export": "Showmount", "world-readable": "Showmount"},
    "dns": {"recursion": "Recursion", "zone-transfer": "Zone Transfer"},
    "mssql": {"instance": "Enumeration"},
    "mongodb": {"access": "Basic Information", "database": "databases"},
    "redis": {"access": "Manual Enumeration"},
    "kerberos": {"spn": "GetUserSPNs", "user": "Usernames"},
}

# a light document stylesheet so the offline render reads less raw (mdBook-ish) — structure only, no
# hardcoded text colours, so it stays legible under both the light and dark themes.
_OFFLINE_CSS = (
    "h2, h3, h4 { margin-top: 12px; }"
    "pre, code { font-family: monospace; }"
    "blockquote { border-left: 3px solid #7fd1b9; padding-left: 8px; }"
    "th, td { border: 1px solid #888888; padding: 3px 6px; }"
)


def _webview_enabled() -> bool:
    # why: QtWebEngine can't init in headless/no-GPU test runs; an env flag lets those force the
    # link-label fallback instead of risking a Chromium crash.
    return _WEBVIEW_IMPORTED and not os.environ.get("OSCPRECON_DISABLE_WEBVIEW")


class ReferencePane(QWidget):
    page_visited = Signal(str, str)
    refresh_requested = Signal()  # user asked for a live refresh of the current page

    def __init__(self) -> None:
        super().__init__()

        # live-reference state
        self._current_ref: ServiceRef | None = None
        self._current_findings: list[dict[str, Any]] = []  # so live content can re-apply the jump
        self._current_product = ""
        self._offline_markdown = ""  # the vendored copy, kept so "Use offline copy" can revert
        self._live_enabled = False

        self._label = QLabel("Select a service to see references.")
        self._label.setWordWrap(True)
        self._link = QLabel("")
        self._link.setWordWrap(True)
        self._link.setOpenExternalLinks(True)

        # a colour-coded tier badge (OFFLINE/CACHED/LIVE) + a muted detail line, so the source of
        # the reference is obvious at a glance. Offline is the reliable default (§14a).
        self._source_badge = QLabel("")
        self._source_badge.setVisible(False)
        self._source_state = QLabel("")
        self._source_state.setWordWrap(True)
        self._source_state.setStyleSheet("color: gray;")
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.setEnabled(False)
        self._refresh_btn.setToolTip("Enable live HackTricks in Preferences → References")
        self._refresh_btn.clicked.connect(lambda: self.refresh_requested.emit())
        self._use_offline_btn = QPushButton("Use offline copy")
        self._use_offline_btn.setVisible(False)
        self._use_offline_btn.clicked.connect(self._restore_offline)

        self._web: QWebEngineView | None = None
        if _webview_enabled():
            try:
                self._web = QWebEngineView()
            except Exception:  # boundary: headless/no-GPU envs can't create the web view
                self._web = None

        web_widget: QWidget
        if self._web is not None:
            web_widget = self._web
        else:
            web_widget = QLabel("Web view unavailable — open the link above in a browser.")
            web_widget.setStyleSheet("color: gray;")

        # Offline vendored HackTricks (§2a): rendered natively (no WebEngine, works with no net).
        self._offline = QTextBrowser()
        self._offline.setOpenExternalLinks(True)
        self._offline.document().setDefaultStyleSheet(_OFFLINE_CSS)

        self._find = QLineEdit()
        self._find.setPlaceholderText("Find in HackTricks page…")
        self._find.returnPressed.connect(self._find_next)
        self._jump_hint = QLabel("")
        self._jump_hint.setWordWrap(True)
        self._jump_hint.setStyleSheet("color: gray; font-style: italic;")

        self._tabs = QTabWidget()
        self._offline_index = self._tabs.addTab(self._offline, "Offline")
        self._live_index = self._tabs.addTab(web_widget, "Live page")

        state_row = QHBoxLayout()
        state_row.addWidget(self._source_badge)
        state_row.addWidget(self._source_state, stretch=1)
        state_row.addWidget(self._use_offline_btn)
        state_row.addWidget(self._refresh_btn)

        hacktricks_box = QGroupBox("HackTricks")
        hacktricks_layout = QVBoxLayout(hacktricks_box)
        hacktricks_layout.addWidget(self._label)
        hacktricks_layout.addWidget(self._link)
        hacktricks_layout.addLayout(state_row)
        hacktricks_layout.addWidget(self._find)
        hacktricks_layout.addWidget(self._jump_hint)
        hacktricks_layout.addWidget(self._tabs, stretch=1)

        self._exploits = QListWidget()
        self._exploits.itemClicked.connect(self._on_exploit_activated)
        self._exploits.itemActivated.connect(self._on_exploit_activated)
        exploits_box = QGroupBox("Exploit-DB (searchsploit — lookup only)")
        exploits_layout = QVBoxLayout(exploits_box)
        exploits_layout.addWidget(self._exploits)

        layout = QVBoxLayout(self)
        layout.addWidget(hacktricks_box, stretch=3)
        layout.addWidget(exploits_box, stretch=1)

    def _set_source(self, badge: str, detail: str, kind: str) -> None:
        # kind -> token colour: info=offline, muted=cached, accent=live, warning=degraded
        self._source_badge.setVisible(bool(badge))
        if badge:
            self._source_badge.setText(f" {badge} ")
            self._source_badge.setStyleSheet(styles.badge(kind, tokens.DARK))
        self._source_state.setText(detail)

    def show_service(
        self,
        service: DiscoveredService | None,
        ref: ServiceRef | None,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        self._exploits.clear()
        self._jump_hint.setText("")
        self._use_offline_btn.setVisible(False)
        if service is None or ref is None:
            self._current_ref = None
            self._current_findings = []
            self._current_product = ""
            self._offline_markdown = ""
            self._label.setText("No reference mapping for this service.")
            self._link.setText("")
            self._set_source("", "", "muted")
            self._refresh_btn.setEnabled(False)
            self._offline.setMarkdown("")
            self._load(QUrl("about:blank"))
            return
        self._current_ref = ref
        self._current_findings = findings or []
        self._current_product = service.product
        self._label.setText(f"{ref.label} — {service.port}/{service.proto.value}")
        self._link.setText(f'<a href="{ref.hacktricks}">{ref.hacktricks}</a>')
        self._show_offline(ref, findings or [], service.product)
        self._load(QUrl(ref.hacktricks))
        self.page_visited.emit(ref.label, ref.hacktricks)
        if service.product:
            self._placeholder("searching Exploit-DB…")
        else:
            self._placeholder("no product/version — Exploit-DB skipped")

    def show_exploits(self, hits: list[ExploitHit]) -> None:
        self._exploits.clear()
        if not hits:
            self._placeholder("no Exploit-DB matches")
            return
        for hit in hits:
            item = QListWidgetItem(f"EDB-{hit.edb_id}  {hit.title}")
            item.setData(_URL_ROLE, hit.url)
            item.setData(_LABEL_ROLE, f"EDB-{hit.edb_id}")
            self._exploits.addItem(item)

    def _show_offline(
        self, ref: ServiceRef, findings: list[dict[str, Any]], product: str = ""
    ) -> None:
        # render the vendored offline page (if any) and default to it; the live link stays visible
        # above and the Live tab is a click away. Offline-first is the exam-friendly default.
        page = hacktricks.page_for_module(ref.module)
        if page is None:
            self._offline_markdown = ""
            self._offline.setMarkdown(
                "_No offline HackTricks page for this service — use the **Live page** tab or the "
                "link above._"
            )
            self._tabs.setTabText(self._offline_index, "Offline")
            self._tabs.setCurrentIndex(self._live_index)
            self._set_source("NO OFFLINE", "use the Live page tab or the link above", "warning")
            self._refresh_btn.setEnabled(self._live_enabled)
            return
        self._offline_markdown = hacktricks.clean_markdown(page.markdown)
        self._offline.setMarkdown(self._offline_markdown)
        self._tabs.setTabText(self._offline_index, f"Offline · {page.title}")
        self._tabs.setCurrentIndex(self._offline_index)
        self._set_source("OFFLINE", "vendored snapshot", "info")
        self._refresh_btn.setEnabled(self._live_enabled)
        self._apply_finding_jump(ref.module, findings, product)

    def _apply_finding_jump(
        self, module: str, findings: list[dict[str, Any]], product: str = "", markdown: str = ""
    ) -> None:
        # relevance priority (§14a): a finding-kind heading first, then the detected product's own
        # section, else leave at the top. Selection is LOCAL — never a server query. `markdown` is
        # the text actually rendered (live content differs from the vendored offline copy).
        source = markdown or self._offline_markdown
        section = self._section_for_findings(module, findings)
        if section and self._jump_to(section):
            self._jump_hint.setText(f"↳ jumped to “{section}” — from your findings")
            return
        if product:
            picks = sections.relevant_sections(source, keywords=[], product=product)
            top = picks[0] if picks else None
            hit = top and top.heading and product.lower() in (top.heading + top.body).lower()
            if hit and top is not None and self._jump_to(top.heading):
                self._jump_hint.setText(f"↳ jumped to “{top.heading}” — matches {product}")
                return
        self._offline.moveCursor(QTextCursor.MoveOperation.Start)

    # ----- live HackTricks -------------------------------------------------

    def set_live_enabled(self, enabled: bool) -> None:
        self._live_enabled = enabled
        self._refresh_btn.setEnabled(enabled and self._current_ref is not None)

    def current_ref_url(self) -> str:
        return self._current_ref.hacktricks if self._current_ref is not None else ""

    def apply_live_result(self, result: LiveResult) -> None:
        # A late result for a page we're no longer showing must not clobber the current one.
        if self._current_ref is None or result.url != self._current_ref.hacktricks:
            return
        if result.state in ("live-refreshed", "live-cached") and result.markdown:
            self._offline.setMarkdown(result.markdown)
            if self._current_ref is not None:  # re-apply the finding-aware jump to the live content
                self._apply_finding_jump(
                    self._current_ref.module,
                    self._current_findings,
                    self._current_product,
                    markdown=result.markdown,
                )
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(result.fetched_at))
            live = result.state == "live-refreshed"
            badge = "LIVE" if live else "CACHED"
            note = f" · offline shown ({result.error})" if result.error else ""
            self._set_source(badge, f"{when}{note}", "accent" if live else "muted")
            # "Use offline copy" only makes sense when there IS a vendored offline copy to revert to
            self._use_offline_btn.setVisible(bool(self._offline_markdown))
        elif "failed" in result.error.lower():
            # a real fetch failure: don't claim an offline copy exists when it doesn't
            if self._offline_markdown:
                self._set_source("OFFLINE", f"live fetch failed ({result.error})", "warning")
            else:
                self._set_source("NO OFFLINE", f"live fetch failed ({result.error})", "warning")
        # a "disabled" / "no cache" result is expected and left silent (offline stays shown).

    def _restore_offline(self) -> None:
        if self._offline_markdown:
            self._offline.setMarkdown(self._offline_markdown)
            self._offline.moveCursor(QTextCursor.MoveOperation.Start)
        self._set_source("OFFLINE", "vendored snapshot", "info")
        self._use_offline_btn.setVisible(False)

    @staticmethod
    def _section_for_findings(module: str, findings: list[dict[str, Any]]) -> str:
        mapping = _FINDING_SECTIONS.get(module, {})
        for finding in findings:
            section = mapping.get(str(finding.get("kind", "")))
            if section:
                return section
        return ""

    def _jump_to(self, keyword: str) -> bool:
        self._offline.moveCursor(QTextCursor.MoveOperation.Start)
        return self._offline.find(keyword)

    def _find_next(self) -> None:
        text = self._find.text().strip()
        if not text:
            return
        if not self._offline.find(text):  # not found ahead → wrap to the top and retry
            self._offline.moveCursor(QTextCursor.MoveOperation.Start)
            self._offline.find(text)

    def focus_find(self) -> None:
        self._find.setFocus()
        self._find.selectAll()

    def offline_text(self) -> str:
        """The rendered offline page as plain text (for tests / search)."""
        return self._offline.toPlainText()

    def _placeholder(self, text: str) -> None:
        item = QListWidgetItem(text)
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        self._exploits.addItem(item)

    def _load(self, url: QUrl) -> None:
        if self._web is not None:
            self._web.setUrl(url)

    def _on_exploit_activated(self, item: QListWidgetItem) -> None:
        url = item.data(_URL_ROLE)
        if isinstance(url, str) and url:
            self._load(QUrl(url))
            label = item.data(_LABEL_ROLE)
            self.page_visited.emit(str(label) if isinstance(label, str) else "exploit-db", url)
