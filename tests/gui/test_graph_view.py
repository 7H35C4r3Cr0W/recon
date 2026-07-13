import base64
import json
from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon.gui.main_window import MainWindow
from oscprecon.gui.widgets.graph_view import GraphBridge, GraphDetail, GraphView
from oscprecon.models import DiscoveredService, Proto, Target
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
