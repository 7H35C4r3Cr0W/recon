import base64
import json
from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon.gui.main_window import MainWindow
from oscprecon.gui.widgets.graph_view import (
    GraphBridge,
    GraphDetail,
    GraphView,
    ReconSummaryTree,
)
from oscprecon.models import Credential, DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def _profile(tmp_path: Path) -> Profile:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    prof.set_services([DiscoveredService(445, Proto.TCP, "microsoft-ds")])
    findings_mod.add_findings(
        prof.directory,
        [{"module": "smb", "kind": "share", "value": "IT", "detail": "", "discovered_at": "t"}],
    )
    return prof


def test_bridge_get_data(qtbot: QtBot, tmp_path: Path) -> None:
    bridge = GraphBridge()
    assert json.loads(bridge.get_data()) == {"nodes": [], "edges": []}  # no profile yet
    bridge.set_profile(_profile(tmp_path))
    ids = {n["data"]["id"] for n in json.loads(bridge.get_data())["nodes"]}
    assert "target" in ids and "service-445-tcp" in ids


def test_bridge_node_clicked_emits_id_and_data(qtbot: QtBot) -> None:
    bridge = GraphBridge()
    got: list[tuple[str, object]] = []
    bridge.node_selected.connect(lambda nid, data: got.append((nid, data)))
    bridge.node_clicked("service-445-tcp", '{"type": "service", "port": 445}')
    assert got == [("service-445-tcp", {"type": "service", "port": 445})]
    bridge.node_clicked("x", "not json")  # malformed -> empty dict, still emits
    assert got[-1] == ("x", {})


def test_bridge_persists_status_note_position(qtbot: QtBot, tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    bridge = GraphBridge()
    bridge.set_profile(prof)
    bridge.set_status("service-445-tcp", "investigating")
    bridge.set_status("service-445-tcp", "bogus")  # invalid -> ignored
    bridge.add_note("service-445-tcp", "readable IT share")
    bridge.save_positions(json.dumps({"service-445-tcp": [120, 240]}))
    override = prof.load_graph()["node_overrides"]["service-445-tcp"]
    assert override["status"] == "investigating"
    assert override["note"] == "readable IT share"
    assert override["position"] == [120, 240]


def test_bridge_write_slots_noop_on_read_only(qtbot: QtBot, tmp_path: Path) -> None:
    # regression: a read-only profile (locked by another window) raised ReadOnlyError out of the
    # graph bridge slots (save_graph). Every write must silently no-op instead of crashing.
    prof = _profile(tmp_path)
    prof.read_only = True
    bridge = GraphBridge()
    bridge.set_profile(prof)
    bridge.set_status("service-445-tcp", "investigating")  # must not raise
    bridge.add_note("service-445-tcp", "x")
    bridge.save_positions(json.dumps({"service-445-tcp": [1, 2]}))
    bridge.add_user_edge("service-445-tcp", "target", "pivot")
    graph = prof.load_graph()
    assert graph["node_overrides"] == {} and graph["user_edges"] == []  # nothing persisted


def test_bridge_add_user_edge_and_bad_json(qtbot: QtBot, tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    bridge = GraphBridge()
    bridge.set_profile(prof)
    bridge.add_user_edge("service-445-tcp", "target", "pivot")
    assert prof.load_graph()["user_edges"] == [
        {"from": "service-445-tcp", "to": "target", "label": "pivot"}
    ]
    bridge.save_positions("not json")  # malformed -> no-op, no crash
    assert "service-445-tcp" not in prof.load_graph()["node_overrides"]


def test_bridge_add_user_edge_dedups_same_pair(qtbot: QtBot, tmp_path: Path) -> None:
    # relating the same two nodes twice must not accumulate overlapping edges (which also caused the
    # live cy.add to throw on a duplicate id and strand link mode). Direction-insensitive.
    prof = _profile(tmp_path)
    bridge = GraphBridge()
    bridge.set_profile(prof)
    bridge.add_user_edge("service-445-tcp", "target", "")
    bridge.add_user_edge("service-445-tcp", "target", "")  # same pair -> ignored
    bridge.add_user_edge("target", "service-445-tcp", "")  # reversed -> still the same pair
    assert prof.load_graph()["user_edges"] == [
        {"from": "service-445-tcp", "to": "target", "label": ""}
    ]


def test_bridge_empty_note_clears_instead_of_orphaning(qtbot: QtBot, tmp_path: Path) -> None:
    # saving a note then clearing it must drop the override, not leave an orphan {"note": ""} [#34]
    prof = _profile(tmp_path)
    bridge = GraphBridge()
    bridge.set_profile(prof)
    bridge.add_note("service-445-tcp", "weird share names")
    assert prof.load_graph()["node_overrides"]["service-445-tcp"]["note"] == "weird share names"
    bridge.add_note("service-445-tcp", "   ")  # whitespace-only = clear
    assert "service-445-tcp" not in prof.load_graph()["node_overrides"]


def test_graph_view_constructs_fallback(qtbot: QtBot, tmp_path: Path) -> None:
    # conftest sets OSCPRECON_DISABLE_WEBVIEW=1 -> fallback path (no QWebEngineView)
    view = GraphView()
    qtbot.addWidget(view)
    view.set_profile(_profile(tmp_path))  # must not raise on the fallback path
    assert view._web is None


def test_main_window_graph_toggle(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    assert window._central_stack.currentWidget() is window._dashboard  # home view with no profile
    window._graph_action.setChecked(True)
    assert window._central_stack.currentIndex() == 1
    window._graph_action.setChecked(False)
    assert window._central_stack.currentIndex() == 0
    window._dashboard.shutdown()


def test_graph_service_open_switches_back_and_selects(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(_profile(tmp_path))
    window._graph_action.setChecked(True)
    window._on_graph_service_open(445, "tcp")  # the "Open service tooling" action
    assert window._graph_action.isChecked() is False  # back to the three-pane so detail shows
    assert window._central_stack.currentIndex() == 0


def test_graph_detail_shows_node_and_emits(qtbot: QtBot) -> None:
    detail = GraphDetail()
    qtbot.addWidget(detail)
    statuses: list[tuple[str, str]] = []
    notes: list[tuple[str, str]] = []
    opens: list[tuple[int, str]] = []
    detail.status_changed.connect(lambda nid, s: statuses.append((nid, s)))
    detail.note_saved.connect(lambda nid, n: notes.append((nid, n)))
    detail.open_service.connect(lambda p, pr: opens.append((p, pr)))
    detail.show_node(
        "service-445-tcp",
        {"label": "445/tcp smb", "type": "service", "port": 445, "proto": "tcp", "note": "hi"},
    )
    assert detail._note.toPlainText() == "hi"
    detail._emit_status("investigating")
    detail._note.setPlainText("readable share")
    detail._emit_note()
    detail._emit_open()
    assert statuses == [("service-445-tcp", "investigating")]
    assert notes == [("service-445-tcp", "readable share")]
    assert opens == [(445, "tcp")]


def test_bridge_export_image_emits(qtbot: QtBot) -> None:
    bridge = GraphBridge()
    got: list[tuple[str, str]] = []
    bridge.export_requested.connect(lambda fmt, data: got.append((fmt, data)))
    bridge.export_image("png", "data:image/png;base64,AAA")
    assert got == [("png", "data:image/png;base64,AAA")]


def test_write_image_png_decodes_and_svg_is_text(tmp_path: Path) -> None:
    png = tmp_path / "g.png"
    payload = b"\x89PNG-not-really"
    GraphView._write_image(
        "png", "data:image/png;base64," + base64.b64encode(payload).decode(), png
    )
    assert png.read_bytes() == payload  # base64 data-uri is stripped + decoded to bytes
    svg = tmp_path / "g.svg"
    GraphView._write_image("svg", "<svg><rect/></svg>", svg)
    assert svg.read_text(encoding="utf-8") == "<svg><rect/></svg>"  # svg written verbatim


_GRAPH_HTML = Path(__file__).resolve().parents[2] / "src" / "oscprecon" / "gui" / "graph_html"


def test_graph_search_never_indexes_credential_secrets() -> None:
    # the search hay must be built from label/type/port/module/source only — NEVER the secret field,
    # so a redacted-but-still-present secret can never be surfaced by typing in the search box.
    app_js = (_GRAPH_HTML / "app.js").read_text()
    hay = app_js.split("function applySearch", 1)[1].split("function ", 1)[0]
    assert 'n.data("secret")' not in hay
    assert "secret" not in hay.lower()


def test_graph_has_legend_and_reference_is_visually_distinct() -> None:
    index_html = (_GRAPH_HTML / "index.html").read_text()
    app_js = (_GRAPH_HTML / "app.js").read_text()
    assert 'id="legend"' in index_html  # chunk-9 legend
    assert "confirmed vuln" in index_html.lower()  # conservative framing stated to the user
    assert 'node[category="reference"]' in app_js  # references coloured apart from findings/danger


def test_graph_view_persists_status_and_note_via_detail(qtbot: QtBot, tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    view = GraphView()
    qtbot.addWidget(view)
    view.set_profile(prof)
    view._on_status_changed("service-445-tcp", "done")
    view._on_note_saved("service-445-tcp", "note here")
    override = prof.load_graph()["node_overrides"]["service-445-tcp"]
    assert override["status"] == "done"
    assert override["note"] == "note here"


def test_status_button_toggles_off_on_second_click(qtbot: QtBot, tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    view = GraphView()
    qtbot.addWidget(view)
    view.set_profile(prof)
    detail = view._detail
    detail.show_node("service-445-tcp", {"type": "service", "label": "445/tcp", "port": 445})

    detail._emit_status("done")  # first click -> set
    assert prof.load_graph()["node_overrides"]["service-445-tcp"]["status"] == "done"
    detail._emit_status("done")  # same status again -> toggle OFF (ring cleared)
    assert "status" not in prof.load_graph()["node_overrides"].get("service-445-tcp", {})
    detail._emit_status("investigating")  # a different status after clearing -> set, not toggle
    assert prof.load_graph()["node_overrides"]["service-445-tcp"]["status"] == "investigating"


def test_bridge_clears_status_on_empty(qtbot: QtBot, tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    bridge = GraphBridge()
    bridge.set_profile(prof)
    bridge.set_status("service-445-tcp", "new")
    assert prof.load_graph()["node_overrides"]["service-445-tcp"]["status"] == "new"
    bridge.set_status("service-445-tcp", "")  # empty = toggle-off -> key removed
    assert "status" not in prof.load_graph()["node_overrides"].get("service-445-tcp", {})


def _rich_profile(tmp_path: Path) -> Profile:
    prof = Profile.create(tmp_path, "rich", Target(ip="10.10.10.5", hostname="box.htb"))
    prof.set_services(
        [
            DiscoveredService(22, Proto.TCP, "ssh", product="OpenSSH", version="8.4p1"),
            DiscoveredService(445, Proto.TCP, "microsoft-ds"),
        ]
    )
    findings_mod.add_findings(
        prof.directory,
        [{"module": "smb", "kind": "share", "value": "IT", "detail": "READ", "discovered_at": "t"}],
    )
    prof.add_credential(
        Credential(username="svc", secret="S3cret!", domain="box.htb", source="smb-anon-enum")
    )
    return prof


def test_recon_summary_tree_lists_target_services_findings_creds(
    qtbot: QtBot, tmp_path: Path
) -> None:
    tree = ReconSummaryTree()
    qtbot.addWidget(tree)
    tree.set_profile(_rich_profile(tmp_path))
    texts: list[str] = []

    def walk(item: object) -> None:
        texts.append(item.text(0))  # type: ignore[attr-defined]
        for i in range(item.childCount()):  # type: ignore[attr-defined]
            walk(item.child(i))  # type: ignore[attr-defined]

    root = tree._tree.topLevelItem(0)
    walk(root)
    blob = "\n".join(texts)
    assert "10.10.10.5" in blob and "box.htb" in blob  # target ip + hostname shown
    assert "22/tcp ssh" in blob and "OpenSSH 8.4p1" in blob  # product + version surfaced
    assert "445/tcp microsoft-ds" in blob
    assert "share: IT" in blob  # finding nested under its service
    assert "svc@box.htb" in blob  # credential shown
    assert "S3cret!" not in blob  # secret never reaches the tree


def test_recon_summary_click_activates_node(qtbot: QtBot, tmp_path: Path) -> None:
    tree = ReconSummaryTree()
    qtbot.addWidget(tree)
    tree.set_profile(_rich_profile(tmp_path))
    got: list[tuple[str, object]] = []
    tree.node_activated.connect(lambda nid, data: got.append((nid, data)))
    # find the 445 service row and click it
    root = tree._tree.topLevelItem(0)
    svc = next(root.child(i) for i in range(root.childCount()) if "445" in root.child(i).text(0))
    tree._on_item(svc, 0)
    assert got and got[0][0] == "service-445-tcp"
    assert isinstance(got[0][1], dict) and got[0][1]["type"] == "service"


def test_graph_fallback_shows_native_summary_and_status_works(qtbot: QtBot, tmp_path: Path) -> None:
    # conftest disables the webview -> the native summary IS the graph. Selecting a service there
    # and setting a status must persist exactly as a canvas node click would (no WebEngine needed).
    prof = _rich_profile(tmp_path)
    view = GraphView()
    qtbot.addWidget(view)
    assert view._web is None
    assert view._canvas_stack.currentWidget() is view._fallback
    view.set_profile(prof)
    root = view._summary._tree.topLevelItem(0)
    svc = next(root.child(i) for i in range(root.childCount()) if "445" in root.child(i).text(0))
    view._summary._on_item(svc, 0)  # drives the shared detail panel
    view._on_status_changed("service-445-tcp", "investigating")
    assert prof.load_graph()["node_overrides"]["service-445-tcp"]["status"] == "investigating"


def _pivot_profile(tmp_path: Path) -> Profile:
    from oscprecon.models import DiscoveredHost

    prof = Profile.create(tmp_path, "ctf", Target(ip="10.10.10.5"))
    prof.set_services([DiscoveredService(80, Proto.TCP, "http")])
    prof.add_hosts(
        [
            DiscoveredHost(
                ip="10.10.5.23",
                hostname="dc01",
                pivot_source="10.10.10.5",
                services=[DiscoveredService(445, Proto.TCP, "smb", product="Windows")],
            ),
            DiscoveredHost(ip="172.16.8.10", pivot_source="10.10.5.23"),
        ]
    )
    return prof


def test_recon_summary_shows_pivot_topology(qtbot: QtBot, tmp_path: Path) -> None:
    tree = ReconSummaryTree()
    qtbot.addWidget(tree)
    tree.set_profile(_pivot_profile(tmp_path))
    texts: list[str] = []

    def walk(item: object) -> None:
        texts.append(item.text(0))  # type: ignore[attr-defined]
        for i in range(item.childCount()):  # type: ignore[attr-defined]
            walk(item.child(i))  # type: ignore[attr-defined]

    for i in range(tree._tree.topLevelItemCount()):
        walk(tree._tree.topLevelItem(i))
    blob = "\n".join(texts)
    assert "Pivoted networks (2 hosts)" in blob
    assert "10.10.5.0/24" in blob and "172.16.8.0/24" in blob
    assert "10.10.5.23 (dc01)  ← via 10.10.10.5" in blob  # host with pivot source + hostname
    assert "445/tcp smb  Windows" in blob  # pivoted host's service with product


def test_recon_summary_pivot_host_click_uses_host_node_id(qtbot: QtBot, tmp_path: Path) -> None:
    tree = ReconSummaryTree()
    qtbot.addWidget(tree)
    tree.set_profile(_pivot_profile(tmp_path))
    got: list[tuple[str, object]] = []
    tree.node_activated.connect(lambda nid, data: got.append((nid, data)))

    def find(item: object, needle: str) -> object:
        if needle in item.text(0):  # type: ignore[attr-defined]
            return item
        for i in range(item.childCount()):  # type: ignore[attr-defined]
            hit = find(item.child(i), needle)  # type: ignore[attr-defined]
            if hit is not None:
                return hit
        return None

    for i in range(tree._tree.topLevelItemCount()):
        host_item = find(tree._tree.topLevelItem(i), "10.10.5.23")
        if host_item is not None:
            tree._on_item(host_item, 0)
            break
    assert got and got[0][0] == "host-10.10.5.23"  # status/notes persist to the host node id


def test_graph_app_js_exposes_refresh_and_overlay() -> None:
    # the refresh contract graph_view.py depends on: an in-place refresh hook (not a full reload)
    # and a visible empty/error overlay so a blank canvas always explains itself.
    app_js = (_GRAPH_HTML / "app.js").read_text()
    index_html = (_GRAPH_HTML / "index.html").read_text()
    assert "window.oscpRefresh" in app_js
    assert "setOverlay" in app_js
    assert 'id="cy-overlay"' in index_html


def test_icon_nodes_and_hover_are_wired_and_secret_safe() -> None:
    app_js = (_GRAPH_HTML / "app.js").read_text()
    index_html = (_GRAPH_HTML / "index.html").read_text()
    # BloodHound-style icon nodes: an ICON map + per-type background-image (inline SVG data URIs)
    assert "var ICON" in app_js
    assert "background-image" in app_js and "data:image/svg+xml" in app_js
    for glyph in ("target", "host", "service", "finding", "credential"):
        assert f"{glyph}:" in app_js.split("var ICON", 1)[1].split("];", 1)[0]
    # hover peek exists and is built safely (textContent, never innerHTML)
    assert 'id="node-tip"' in index_html
    tip = app_js.split("function showTip", 1)[1].split("function hideTip", 1)[0]
    assert "innerHTML" not in tip  # no HTML injection from banner text
    assert "secret" not in tip.lower()  # the tooltip must never surface a credential secret


def test_corner_glyph_badges_are_wired_and_secret_safe() -> None:
    app_js = (_GRAPH_HTML / "app.js").read_text()
    index_html = (_GRAPH_HTML / "index.html").read_text()
    # BloodHound-style corner glyphs: a BADGE set + a compositor that layers them onto a node
    assert "var BADGE" in app_js and "STATUS_BADGE" in app_js
    assert "function applyGlyphs" in app_js
    assert "cy.nodes().forEach(applyGlyphs)" in app_js
    for kind in ("danger", "winOs", "nixOs", "done", "investigating", "dead-end", "note"):
        assert kind in app_js
    # layered via background-image arrays with per-corner positions (slice to the next top-level fn)
    glyph = app_js.split("function applyGlyphs", 1)[1].split("function render", 1)[0]
    assert "background-position-x" in glyph and "background-position-y" in glyph
    assert "secret" not in glyph.lower()  # a glyph must never derive from a credential secret
    assert "Corner glyphs" in index_html  # documented in the legend


def test_graph_render_reapplies_filter_and_preserves_view() -> None:
    # a rebuild starts every node visible; render() must re-apply the declutter filter + search, and
    # preserve prior node positions + camera so a streamed-host refresh doesn't teleport/snap.
    app_js = (_GRAPH_HTML / "app.js").read_text()
    render = app_js.split("function render", 1)[1].split("function refresh", 1)[0]
    assert "applyFilter()" in render  # re-apply the node-type declutter after rebuild
    assert "applySearch(search.value)" in render  # re-apply the search highlight
    assert "prevPos" in render and "prevPan" in render  # keep positions + camera across a refresh


def test_fcose_layout_is_vendored_offline_and_wired() -> None:
    # the compound-aware pivot layout must ship offline (no runtime CDN) and be loaded in dep order.
    for name in ("layout-base.js", "cose-base.js", "cytoscape-fcose.js"):
        assert (_GRAPH_HTML / name).is_file(), f"{name} not vendored"
    index_html = (_GRAPH_HTML / "index.html").read_text()
    # dependency order matters: layout-base -> cose-base -> cytoscape-fcose
    assert (
        index_html.index("layout-base.js")
        < index_html.index("cose-base.js")
        < index_html.index("cytoscape-fcose.js")
    )
    app_js = (_GRAPH_HTML / "app.js").read_text()
    assert "cytoscapeFcose" in app_js and "fcose" in app_js  # registered + used as a layout
