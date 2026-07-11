from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QUrl, Signal, Slot
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from oscprecon.gui.graph_data import build_elements
from oscprecon.profile import Profile

try:
    from PySide6.QtWebChannel import QWebChannel
    from PySide6.QtWebEngineWidgets import QWebEngineView

    _WEBVIEW_IMPORTED = True
except ImportError:  # pragma: no cover - QtWebEngine ships with PySide6-Addons
    _WEBVIEW_IMPORTED = False

_HTML_INDEX = Path(__file__).parent.parent / "graph_html" / "index.html"
_VALID_STATUS = frozenset({"new", "investigating", "done", "dead-end"})


def _webview_enabled() -> bool:
    return _WEBVIEW_IMPORTED and not os.environ.get("OSCPRECON_DISABLE_WEBVIEW")


class GraphBridge(QObject):
    """QWebChannel bridge: serves graph data to the JS and persists edits back to graph.json."""

    node_selected = Signal(str)  # node id

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None

    def set_profile(self, profile: Profile | None) -> None:
        self._profile = profile

    @Slot(result=str)
    def get_data(self) -> str:
        if self._profile is None:
            return json.dumps({"nodes": [], "edges": []})
        return json.dumps(build_elements(self._profile))

    @Slot(str)
    def node_clicked(self, node_id: str) -> None:
        self.node_selected.emit(node_id)

    @Slot(str, str)
    def set_status(self, node_id: str, status: str) -> None:
        if status in _VALID_STATUS:
            self._update_override(node_id, "status", status)

    @Slot(str, str)
    def add_note(self, node_id: str, note: str) -> None:
        self._update_override(node_id, "note", note)

    @Slot(str)
    def save_positions(self, positions_json: str) -> None:
        if self._profile is None:
            return
        try:
            positions = json.loads(positions_json)
        except json.JSONDecodeError:
            return
        if not isinstance(positions, dict):
            return
        graph = self._profile.load_graph()
        overrides = graph["node_overrides"]
        for node_id, position in positions.items():
            if isinstance(position, list) and len(position) == 2:
                slot = overrides.setdefault(node_id, {})
                if isinstance(slot, dict):
                    slot["position"] = [position[0], position[1]]
        self._profile.save_graph(graph)

    @Slot(str, str, str)
    def add_user_edge(self, source: str, target: str, label: str) -> None:
        if self._profile is None:
            return
        graph = self._profile.load_graph()
        graph["user_edges"].append({"from": source, "to": target, "label": label})
        self._profile.save_graph(graph)

    def _update_override(self, node_id: str, key: str, value: Any) -> None:
        if self._profile is None:
            return
        graph = self._profile.load_graph()
        slot = graph["node_overrides"].setdefault(node_id, {})
        if isinstance(slot, dict):
            slot[key] = value
            self._profile.save_graph(graph)


class GraphView(QWidget):
    node_selected = Signal(str)  # forwarded from the bridge

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._bridge = GraphBridge()
        self._bridge.node_selected.connect(self.node_selected)
        self._web: QWebEngineView | None = None

        if _webview_enabled():
            try:
                self._web = QWebEngineView()
                channel = QWebChannel(self._web)
                channel.registerObject("bridge", self._bridge)
                page = self._web.page()
                if page is not None:
                    page.setWebChannel(channel)
                self._web.setUrl(QUrl.fromLocalFile(str(_HTML_INDEX)))
            except Exception:  # boundary: headless/no-GPU envs can't create the web view
                self._web = None

        layout = QVBoxLayout(self)
        if self._web is not None:
            layout.addWidget(self._web)
        else:
            fallback = QLabel(
                "Graph view unavailable — QtWebEngine could not start in this environment."
            )
            fallback.setStyleSheet("color: gray;")
            layout.addWidget(fallback)

    def set_profile(self, profile: Profile) -> None:
        self._profile = profile
        self._bridge.set_profile(profile)
        self.reload()

    def reload(self) -> None:
        if self._web is not None:
            self._web.reload()  # re-runs app.js, which re-fetches via bridge.get_data()
