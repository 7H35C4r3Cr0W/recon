from __future__ import annotations

import os

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtWidgets import (
    QGroupBox,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oscprecon.models import DiscoveredService
from oscprecon.references import ExploitHit, ServiceRef

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView

    _WEBVIEW_IMPORTED = True
except ImportError:  # pragma: no cover - QtWebEngine ships with PySide6-Addons
    _WEBVIEW_IMPORTED = False

_URL_ROLE = Qt.ItemDataRole.UserRole
_LABEL_ROLE = Qt.ItemDataRole.UserRole + 1


def _webview_enabled() -> bool:
    # why: QtWebEngine can't init in headless/no-GPU test runs; an env flag lets those force the
    # link-label fallback instead of risking a Chromium crash.
    return _WEBVIEW_IMPORTED and not os.environ.get("OSCPRECON_DISABLE_WEBVIEW")


class ReferencePane(QWidget):
    page_visited = Signal(str, str)

    def __init__(self) -> None:
        super().__init__()

        self._label = QLabel("Select a service to see references.")
        self._label.setWordWrap(True)
        self._link = QLabel("")
        self._link.setWordWrap(True)
        self._link.setOpenExternalLinks(True)

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

        hacktricks_box = QGroupBox("HackTricks")
        hacktricks_layout = QVBoxLayout(hacktricks_box)
        hacktricks_layout.addWidget(self._label)
        hacktricks_layout.addWidget(self._link)
        hacktricks_layout.addWidget(web_widget, stretch=1)

        self._exploits = QListWidget()
        self._exploits.itemClicked.connect(self._on_exploit_activated)
        self._exploits.itemActivated.connect(self._on_exploit_activated)
        exploits_box = QGroupBox("Exploit-DB (searchsploit — lookup only)")
        exploits_layout = QVBoxLayout(exploits_box)
        exploits_layout.addWidget(self._exploits)

        layout = QVBoxLayout(self)
        layout.addWidget(hacktricks_box, stretch=3)
        layout.addWidget(exploits_box, stretch=1)

    def show_service(self, service: DiscoveredService | None, ref: ServiceRef | None) -> None:
        self._exploits.clear()
        if service is None or ref is None:
            self._label.setText("No reference mapping for this service.")
            self._link.setText("")
            self._load(QUrl("about:blank"))
            return
        self._label.setText(f"{ref.label} — {service.port}/{service.proto.value}")
        self._link.setText(f'<a href="{ref.hacktricks}">{ref.hacktricks}</a>')
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
