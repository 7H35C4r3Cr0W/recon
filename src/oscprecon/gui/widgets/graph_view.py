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
    QStackedWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
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
        try:
            return json.dumps(build_elements(self._profile))
        except Exception:  # boundary: a bad/removed profile must return empty, never break the slot
            return json.dumps({"nodes": [], "edges": []})

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
        elif not status:  # empty status = toggle-off; clear the override so the ring disappears
            self._update_override(node_id, "status", None)

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
            if value is None:
                slot.pop(key, None)  # clear (e.g. toggling a status off)
            else:
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
        self._status = ""  # the node's current status, so clicking it again toggles it off
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
        self._status = str(data.get("status", ""))
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
        if not self._node_id:
            return
        # click the already-active status again to clear it (toggle off)
        new_status = "" if status == self._status else status
        self._status = new_status
        self.status_changed.emit(self._node_id, new_status)

    def _emit_note(self) -> None:
        if self._node_id:
            self.note_saved.emit(self._node_id, self._note.toPlainText())

    def _emit_open(self) -> None:
        if self._service is not None:
            self.open_service.emit(self._service[0], self._service[1])


class ReconSummaryTree(QWidget):
    """A native (no-WebEngine) tree of the scan: target → services → findings, plus credentials.

    This is the guarantee that the Graph view ALWAYS shows the recon data — ports, IP, services,
    findings — even when the Cytoscape canvas can't render (headless, no-GPU VM, render-process
    crash). Clicking a row drives the same detail/status/note panel as clicking a graph node, so
    the user can mark status and add notes with or without the web canvas. It reads the exact same
    build_elements() output the graph uses, so the two never disagree.
    """

    node_activated = Signal(str, object)  # (node id, data dict) — mirrors GraphBridge.node_selected

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None

        title = QLabel("Recon summary")
        title.setStyleSheet("font-weight: bold;")
        hint = QLabel(
            "Every discovered service from your scan. Click one to set status / add a note."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: gray; font-size: 11px;")

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setAccessibleName("Recon summary")
        self._tree.itemClicked.connect(self._on_item)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(title)
        layout.addWidget(hint)
        layout.addWidget(self._tree, stretch=1)

    def set_profile(self, profile: Profile | None) -> None:
        self._profile = profile
        self.reload()

    def reload(self) -> None:
        self._tree.clear()
        if self._profile is None:
            return
        try:
            elements = build_elements(self._profile)
        except Exception:  # boundary: a bad profile must never blank the whole view
            return
        nodes = {n["data"]["id"]: n["data"] for n in elements["nodes"]}
        target = nodes.get("target")
        if target is None:
            return

        children: dict[str, list[str]] = {}
        for edge in elements["edges"]:
            data = edge["data"]
            children.setdefault(str(data["source"]), []).append(str(data["target"]))

        meta = {(svc.port, svc.proto.value): svc for svc in self._profile.discovered_services}
        root = self._add(None, target)
        root.setExpanded(True)

        service_ids = sorted(
            # entry-host services only (ids "service-…"); pivoted-host services ("hostservice-…")
            # are listed under their host in the Pivoted networks section below.
            (
                nid
                for nid, d in nodes.items()
                if d.get("type") == "service" and nid.startswith("service-")
            ),
            key=lambda i: (int(nodes[i].get("port") or 0), str(nodes[i].get("proto", ""))),
        )
        placed: set[str] = set()
        for sid in service_ids:
            svc_item = self._add(root, nodes[sid], label=self._service_label(nodes[sid], meta))
            svc_item.setExpanded(True)
            for tid in children.get(sid, []):
                child = nodes.get(tid)
                if child is not None and child.get("type") == "finding":
                    self._add(svc_item, child)
                    placed.add(tid)

        loose = [
            nodes[tid]
            for tid in children.get("target", [])
            if tid in nodes and nodes[tid].get("type") == "finding" and tid not in placed
        ]
        if loose:
            group = QTreeWidgetItem(root, ["Other findings"])
            group.setExpanded(True)
            for data in loose:
                self._add(group, data)

        creds = [d for d in nodes.values() if d.get("type") == "credential"]
        if creds:
            group = QTreeWidgetItem(root, ["Credentials (redacted)"])
            group.setExpanded(True)
            for data in creds:
                self._add(group, data)

        self._add_pivot_networks(nodes)

        if root.childCount() == 0 and self._tree.topLevelItemCount() == 1:
            QTreeWidgetItem(
                root, ["No services discovered yet — run Full Recon to scan the target."]
            )

    def _add_pivot_networks(self, nodes: dict[str, dict[str, Any]]) -> None:
        # the pivot topology as a tree: subnet → host (with pivot source) → its services. A
        # top-level sibling of the entry target so the whole engagement reads top-to-bottom. Uses
        # the graph node ids so a status/note set here persists to the same node the canvas would.
        if self._profile is None or not self._profile.discovered_hosts:
            return
        by_subnet: dict[str, list[Any]] = {}
        for host in self._profile.discovered_hosts:
            by_subnet.setdefault(host.subnet or "unknown", []).append(host)

        section = QTreeWidgetItem(
            [f"Pivoted networks ({len(self._profile.discovered_hosts)} hosts)"]
        )
        self._tree.addTopLevelItem(section)
        section.setExpanded(True)
        for subnet in sorted(by_subnet):
            hosts = sorted(by_subnet[subnet], key=lambda h: h.ip)
            subnet_item = QTreeWidgetItem(section, [f"{subnet}  ({len(hosts)} hosts)"])
            subnet_item.setExpanded(True)
            for host in hosts:
                host_data = nodes.get(f"host-{host.ip}")
                label = host.ip + (f" ({host.hostname})" if host.hostname else "")
                if host.pivot_source:
                    label += f"  ← via {host.pivot_source}"
                if host_data is not None and host_data.get("status"):
                    label += f"  [{host_data['status']}]"
                host_item = self._add(
                    subnet_item, host_data or {"id": f"host-{host.ip}"}, label=label
                )
                host_item.setExpanded(True)
                for svc in sorted(host.services, key=lambda s: (s.port, s.proto.value)):
                    sid = f"hostservice-{host.ip}-{svc.port}-{svc.proto.value}"
                    text = f"{svc.port}/{svc.proto.value} {svc.service}".strip()
                    extra = " ".join(p for p in (svc.product, svc.version) if p)
                    self._add(
                        host_item,
                        nodes.get(sid) or {"id": sid},
                        label=f"{text}  {extra}".strip() if extra else text,
                    )

    @staticmethod
    def _service_label(data: dict[str, Any], meta: dict[tuple[int, str], Any]) -> str:
        base = str(data.get("label", data.get("id", "")))
        svc = meta.get((int(data.get("port") or 0), str(data.get("proto", ""))))
        extra = " ".join(p for p in (getattr(svc, "product", ""), getattr(svc, "version", "")) if p)
        label = f"{base}  {extra}".strip() if extra else base
        status = data.get("status")
        return f"{label}  [{status}]" if status else label

    def _add(
        self, parent: QTreeWidgetItem | None, data: dict[str, Any], *, label: str | None = None
    ) -> QTreeWidgetItem:
        text = label if label is not None else self._label(data)
        item = QTreeWidgetItem([text]) if parent is None else QTreeWidgetItem(parent, [text])
        if parent is None:
            self._tree.addTopLevelItem(item)
        item.setData(0, Qt.ItemDataRole.UserRole, (str(data["id"]), data))
        note = data.get("note")
        if isinstance(note, str) and note:
            item.setToolTip(0, note)
        return item

    @staticmethod
    def _label(data: dict[str, Any]) -> str:
        if data.get("type") == "target":
            return str(data.get("label", "target")).replace("\n", "  ·  ")
        base = str(data.get("label", data.get("id", "")))
        status = data.get("status")
        return f"{base}  [{status}]" if status else base

    def _on_item(self, item: QTreeWidgetItem, _column: int) -> None:
        payload = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(payload, tuple) and len(payload) == 2:
            self.node_activated.emit(payload[0], payload[1])


class GraphView(QWidget):
    service_open_requested = Signal(int, str)  # (port, proto) — jump to the three-pane tooling

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._bridge = GraphBridge()
        self._bridge.node_selected.connect(self._on_node_selected)
        self._web: QWebEngineView | None = None
        self._loaded = False  # the web page has finished its initial load at least once

        if _webview_enabled():
            try:
                self._web = QWebEngineView()
                channel = QWebChannel(self._web)
                channel.registerObject("bridge", self._bridge)
                page = self._web.page()
                if page is not None:
                    page.setWebChannel(channel)
                    page.renderProcessTerminated.connect(self._on_render_terminated)
                self._web.loadFinished.connect(self._on_load_finished)
                self._web.setUrl(QUrl.fromLocalFile(str(_HTML_INDEX)))
            except Exception:  # boundary: headless/no-GPU envs can't create the web view
                self._web = None

        self._bridge.export_requested.connect(self._on_export)

        # native, always-available surface — lists the scan even when the canvas can't render
        self._summary = ReconSummaryTree()
        self._summary.node_activated.connect(self._on_node_selected)

        self._detail = GraphDetail()
        self._detail.status_changed.connect(self._on_status_changed)
        self._detail.note_saved.connect(self._on_note_saved)
        self._detail.open_service.connect(self.service_open_requested)

        # right side: the web canvas, with a native fallback message swapped in when it can't render
        self._canvas_stack = QStackedWidget()
        self._fallback = QLabel(
            "Graph canvas unavailable in this environment.\n\n"
            "The recon summary on the left lists every discovered service, and status / notes "
            "work there."
        )
        self._fallback.setWordWrap(True)
        self._fallback.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._fallback.setStyleSheet("color: gray; padding: 24px;")
        if self._web is not None:
            self._canvas_stack.addWidget(self._web)
        self._canvas_stack.addWidget(self._fallback)
        self._canvas_stack.setCurrentWidget(self._web if self._web is not None else self._fallback)

        left = QSplitter(Qt.Orientation.Vertical)
        left.addWidget(self._summary)
        left.addWidget(self._detail)
        left.setSizes([320, 360])

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(self._canvas_stack)
        splitter.setSizes([300, 740])
        QHBoxLayout(self).addWidget(splitter)

    def set_profile(self, profile: Profile) -> None:
        self._profile = profile
        self._bridge.set_profile(profile)
        self.reload()

    def clear_profile(self) -> None:
        # drop the profile so a deleted/closed project leaves no ghost in the canvas or summary
        self._profile = None
        self._bridge.set_profile(None)
        self.reload()

    def reload(self) -> None:
        # keep the native summary in sync no matter what the canvas does — a single reload here (not
        # also in set_profile) so a streamed-host refresh doesn't rebuild the tree twice.
        self._summary.set_profile(self._profile)
        if self._web is None:
            return
        # push fresh data into the live page rather than reloading the whole page — a full reload
        # reinitialises the Chromium page + bridge and blanks the canvas on any hiccup. If the page
        # hasn't finished its first load yet, boot()/loadFinished will fetch once it does.
        if self._loaded:
            page = self._web.page()
            if page is not None:
                page.runJavaScript("window.oscpRefresh && window.oscpRefresh();")

    def _on_load_finished(self, ok: bool) -> None:
        if not ok:
            # the local page itself failed to load — fall back to the native summary + message
            self._canvas_stack.setCurrentWidget(self._fallback)
            return
        self._loaded = True
        if self._web is not None:
            self._canvas_stack.setCurrentWidget(self._web)
            page = self._web.page()
            if page is not None:
                # guarantee the just-loaded page shows the current profile even if boot() raced
                # set_profile() (page finished loading before the profile was assigned)
                page.runJavaScript("window.oscpRefresh && window.oscpRefresh();")

    def _on_render_terminated(self, *_args: object) -> None:
        # the Chromium render process crashed (common on tiny-/dev/shm VMs) — the canvas is now
        # blank; surface the native fallback so the user still sees their scan + a clear reason.
        self._canvas_stack.setCurrentWidget(self._fallback)

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
