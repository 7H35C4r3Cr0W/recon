from __future__ import annotations

import base64
import contextlib
import json
import os
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Qt, QUrl, Signal, Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from oscprecon.gui.graph_data import build_elements
from oscprecon.profile import Profile

try:
    from PySide6.QtWebChannel import QWebChannel
    from PySide6.QtWebEngineWidgets import QWebEngineView

    _WEBVIEW_IMPORTED = True
except ImportError:  # pragma: no cover - QtWebEngine ships with PySide6-Addons
    _WEBVIEW_IMPORTED = False

_HTML_INDEX = Path(__file__).parent.parent / "graph_html" / "index.html"
_STATUSES = ("new", "investigating", "done", "dead-end")
_VALID_STATUS = frozenset(_STATUSES)


def _webview_enabled() -> bool:
    return _WEBVIEW_IMPORTED and not os.environ.get("OSCPRECON_DISABLE_WEBVIEW")


class GraphBridge(QObject):
    """QWebChannel bridge: serves graph data to the JS and persists edits back to graph.json."""

    node_selected = Signal(str, object)  # (node id, data dict)
    export_requested = Signal(str, str)  # (format, data — png base64-uri or raw svg)

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

    @Slot(str, str)
    def node_clicked(self, node_id: str, data_json: str) -> None:
        try:
            data = json.loads(data_json)
        except json.JSONDecodeError:
            data = {}
        self.node_selected.emit(node_id, data if isinstance(data, dict) else {})

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

    @Slot(str, str)
    def export_image(self, image_format: str, data: str) -> None:
        self.export_requested.emit(image_format, data)

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


class GraphDetail(QWidget):
    """Sidebar showing the clicked node's detail + native status/note controls (§16)."""

    status_changed = Signal(str, str)  # (node id, status)
    note_saved = Signal(str, str)  # (node id, note)
    open_service = Signal(int, str)  # (port, proto)

    def __init__(self) -> None:
        super().__init__()
        self._node_id = ""
        self._service: tuple[int, str] | None = None

        self._title = QLabel("Click a node to see its detail.")
        self._title.setWordWrap(True)
        self._title.setStyleSheet("font-weight: bold;")
        self._info = QLabel("")
        self._info.setWordWrap(True)
        self._info.setStyleSheet("color: gray;")

        status_box = QGroupBox("Status")
        status_row = QHBoxLayout(status_box)
        for status in _STATUSES:
            button = QPushButton(status)
            button.clicked.connect(lambda _=False, s=status: self._emit_status(s))
            status_row.addWidget(button)

        self._note = QTextEdit()
        self._note.setPlaceholderText("Add a note (saved to graph.json, shown in the report)…")
        self._save_note = QPushButton("Save note")
        self._save_note.clicked.connect(self._emit_note)
        note_box = QGroupBox("Note")
        note_layout = QVBoxLayout(note_box)
        note_layout.addWidget(self._note)
        note_layout.addWidget(self._save_note)

        self._open = QPushButton("Open service tooling →")
        self._open.clicked.connect(self._emit_open)
        self._open.setVisible(False)

        layout = QVBoxLayout(self)
        layout.addWidget(self._title)
        layout.addWidget(self._info)
        layout.addWidget(status_box)
        layout.addWidget(note_box, stretch=1)
        layout.addWidget(self._open)
        self._set_controls_enabled(False)

    def show_node(self, node_id: str, data: dict[str, Any]) -> None:
        self._node_id = node_id
        self._title.setText(str(data.get("label", node_id)))
        self._info.setText(self._describe(data))
        self._note.setPlainText(str(data.get("note", "")))
        node_type = str(data.get("type", ""))
        is_service = node_type == "service"
        self._open.setVisible(is_service)
        if is_service and isinstance(data.get("port"), int):
            self._service = (int(data["port"]), str(data.get("proto", "")))
        else:
            self._service = None
        self._set_controls_enabled(True)

    @staticmethod
    def _describe(data: dict[str, Any]) -> str:
        node_type = str(data.get("type", "node"))
        bits = [f"type: {node_type}"]
        if node_type == "service":
            bits.append(f"{data.get('port', '?')}/{data.get('proto', '?')}")
        if data.get("module"):
            bits.append(f"module: {data['module']}")
        if data.get("source"):
            bits.append(f"source: {data['source']}")
        if data.get("detail"):
            bits.append(str(data["detail"]))
        if data.get("status"):
            bits.append(f"status: {data['status']}")
        return "  ·  ".join(bits)

    def _set_controls_enabled(self, enabled: bool) -> None:
        self._note.setEnabled(enabled)
        self._save_note.setEnabled(enabled)

    def _emit_status(self, status: str) -> None:
        if self._node_id:
            self.status_changed.emit(self._node_id, status)

    def _emit_note(self) -> None:
        if self._node_id:
            self.note_saved.emit(self._node_id, self._note.toPlainText())

    def _emit_open(self) -> None:
        if self._service is not None:
            self.open_service.emit(self._service[0], self._service[1])


class GraphView(QWidget):
    service_open_requested = Signal(int, str)  # (port, proto) — jump to the three-pane tooling

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._bridge = GraphBridge()
        self._bridge.node_selected.connect(self._on_node_selected)
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

        self._bridge.export_requested.connect(self._on_export)
        self._detail = GraphDetail()
        self._detail.status_changed.connect(self._on_status_changed)
        self._detail.note_saved.connect(self._on_note_saved)
        self._detail.open_service.connect(self.service_open_requested)

        graph_widget: QWidget
        if self._web is not None:
            graph_widget = self._web
        else:
            fallback = QLabel(
                "Graph view unavailable — QtWebEngine could not start in this environment."
            )
            fallback.setStyleSheet("color: gray;")
            graph_widget = fallback

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._detail)
        splitter.addWidget(graph_widget)
        splitter.setSizes([260, 780])
        QHBoxLayout(self).addWidget(splitter)

    def set_profile(self, profile: Profile) -> None:
        self._profile = profile
        self._bridge.set_profile(profile)
        self.reload()

    def reload(self) -> None:
        if self._web is not None:
            self._web.reload()  # re-runs app.js, which re-fetches via bridge.get_data()

    def _on_node_selected(self, node_id: str, data: object) -> None:
        self._detail.show_node(node_id, data if isinstance(data, dict) else {})

    def _on_status_changed(self, node_id: str, status: str) -> None:
        self._bridge.set_status(node_id, status)
        self.reload()

    def _on_note_saved(self, node_id: str, note: str) -> None:
        self._bridge.add_note(node_id, note)
        self.reload()

    def _on_export(self, image_format: str, data: str) -> None:
        is_svg = image_format == "svg"
        ext = "svg" if is_svg else "png"
        caption = f"Export graph as {ext.upper()}"
        chosen, _ = QFileDialog.getSaveFileName(self, caption, f"graph.{ext}", f"*.{ext}")
        if not chosen:
            return
        with contextlib.suppress(OSError, ValueError):
            self._write_image(image_format, data, Path(chosen))

    @staticmethod
    def _write_image(image_format: str, data: str, path: Path) -> None:
        if image_format == "svg":
            path.write_text(data, encoding="utf-8")
            return
        marker = "base64,"
        index = data.find(marker)
        payload = data[index + len(marker) :] if index != -1 else data
        path.write_bytes(base64.b64decode(payload))
