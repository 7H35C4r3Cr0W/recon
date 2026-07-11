from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon import references
from oscprecon.gui.main_window import MainWindow, _slug
from oscprecon.gui.widgets.reference_pane import ReferencePane
from oscprecon.gui.widgets.service_tree import ServiceTree
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import ExploitHit


def _services() -> list[DiscoveredService]:
    return [
        DiscoveredService(22, Proto.TCP, "ssh", "OpenSSH", "8.4"),
        DiscoveredService(445, Proto.TCP, "microsoft-ds", "Samba", "4.6"),
        DiscoveredService(161, Proto.UDP, "snmp"),
    ]


def test_service_tree_groups_and_emits(qtbot: QtBot) -> None:
    tree = ServiceTree()
    qtbot.addWidget(tree)
    tree.populate(_services())
    assert tree.topLevelItemCount() == 2  # TCP group + UDP group
    tcp_group = tree.topLevelItem(0)
    assert tcp_group is not None and tcp_group.childCount() == 2
    with qtbot.waitSignal(tree.service_selected, timeout=1000) as blocker:
        tree.setCurrentItem(tcp_group.child(0))
    assert isinstance(blocker.args[0], DiscoveredService)
    assert blocker.args[0].port == 22


def test_tool_panel_populates_hints_and_expands(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_target("10.10.10.5")
    # mysql uses the generic hints page (it has no dedicated builder/recon panel)
    svc = DiscoveredService(3306, Proto.TCP, "mysql")
    panel.show_service(svc, references.match(svc))
    assert panel._hints.count() >= 1
    panel._on_hint_activated(panel._hints.item(0))
    assert "10.10.10.5" in panel._command.text()


def test_tool_panel_emits_run_requested(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel._command.setText("nmap -p 80 10.10.10.5")
    with qtbot.waitSignal(panel.run_requested, timeout=1000) as blocker:
        panel._emit_run()
    assert blocker.args[0] == "nmap -p 80 10.10.10.5"


def test_tool_panel_ignores_empty_run(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel._command.setText("   ")
    with qtbot.assertNotEmitted(panel.run_requested):
        panel._emit_run()


def test_reference_pane_shows_hacktricks(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    svc = DiscoveredService(445, Proto.TCP, "microsoft-ds")
    pane.show_service(svc, references.match(svc))
    assert "pentesting-smb" in pane._link.text()


def test_main_window_selection_updates_panes(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "htb-test", Target(ip="10.10.10.100"))
    prof.set_services(_services())
    window._set_profile(prof)
    assert window._service_tree.topLevelItemCount() == 2
    tcp = window._service_tree.topLevelItem(0)
    assert tcp is not None
    window._service_tree.setCurrentItem(tcp.child(1))  # 445 (sorted 22, 445)
    assert "445" in window._reference_pane._label.text()
    # 445 is SMB → the tool panel switches to the dedicated SMB page
    assert window._tool_panel._stack.currentWidget() is window._tool_panel._smb


def test_reference_pane_emits_page_visited(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    svc = DiscoveredService(445, Proto.TCP, "microsoft-ds", "Samba", "4.6")
    with qtbot.waitSignal(pane.page_visited, timeout=1000) as blocker:
        pane.show_service(svc, references.match(svc))
    assert blocker.args[1].startswith("https://book.hacktricks.wiki/")


def test_reference_pane_show_exploits(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_exploits(
        [ExploitHit("50973", "nginx DoS", "https://www.exploit-db.com/exploits/50973", "")]
    )
    assert pane._exploits.count() == 1
    assert "50973" in pane._exploits.item(0).text()


def test_main_window_edb_stale_result_ignored(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._edb_request_id = 5
    hit = ExploitHit("1", "title", "https://www.exploit-db.com/exploits/1", "")
    window._on_edb_done([hit], 4)  # stale id -> ignored
    assert window._reference_pane._exploits.count() == 0
    window._on_edb_done([hit], 5)  # current id -> shown
    assert window._reference_pane._exploits.count() == 1


def test_slug() -> None:
    assert _slug("nmap -p 80 x") == "nmap"
    assert _slug("smbclient -L //x/") == "smbclient"
    assert _slug("") == "command"


def test_page_visit_buffered_during_scan(qtbot: QtBot, tmp_path: Path) -> None:
    from PySide6.QtCore import QThread

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "buf", Target(ip="10.0.0.1"))
    window._set_profile(prof)
    window._worker = QThread()  # simulate a scan in progress
    window._on_page_visited("smb", "https://book.hacktricks.wiki/smb")
    assert prof.references_visited == []  # buffered, not recorded yet
    assert window._pending_visits == [("smb", "https://book.hacktricks.wiki/smb")]
    window._finish_worker()  # joins the (unstarted) worker and drains the buffer
    assert any(v["url"] == "https://book.hacktricks.wiki/smb" for v in prof.references_visited)
    assert window._pending_visits == []
