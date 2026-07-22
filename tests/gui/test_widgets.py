from pathlib import Path

from PySide6.QtGui import QFont
from pytestqt.qtbot import QtBot

from oscprecon import references
from oscprecon.gui.main_window import MainWindow, _slug
from oscprecon.gui.widgets.reference_pane import ReferencePane
from oscprecon.gui.widgets.service_tree import ServiceTree
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredHost, DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import EdbSearch, ExploitHit


def _services() -> list[DiscoveredService]:
    return [
        DiscoveredService(22, Proto.TCP, "ssh", "OpenSSH", "8.4"),
        DiscoveredService(445, Proto.TCP, "microsoft-ds", "Samba", "4.6"),
        DiscoveredService(161, Proto.UDP, "snmp"),
    ]


def test_service_tree_empty_message(qtbot: QtBot) -> None:
    tree = ServiceTree()
    qtbot.addWidget(tree)
    # an empty tree carries a helpful placeholder, not a silent blank box
    assert tree.topLevelItemCount() == 0
    assert "No services yet" in tree._empty_message
    tree.set_empty_message("Scan complete — 0 open ports found.")
    assert tree._empty_message == "Scan complete — 0 open ports found."
    tree.populate(_services())  # a real result replaces the empty state
    assert tree.topLevelItemCount() == 2


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


def test_service_tree_entry_host_header_shows_ip(qtbot: QtBot) -> None:
    # the entry host's services sit under a single IP-labelled node, not a bare "TCP (n)" — so the
    # target IP/hostname is always visible at the top of the recon tree.
    tree = ServiceTree()
    qtbot.addWidget(tree)
    services = [DiscoveredService(22, Proto.TCP, "ssh"), DiscoveredService(80, Proto.TCP, "http")]
    tree.populate(services, [], target=Target(ip="10.10.110.100", hostname="DANTE-WEB-NIX01"))
    assert tree.topLevelItemCount() == 1  # one entry-host node, not two proto groups
    entry = tree.topLevelItem(0)
    assert entry is not None
    assert "10.10.110.100" in entry.text(0) and "DANTE-WEB-NIX01" in entry.text(0)
    tcp_group = entry.child(0)  # TCP group nested under the entry host
    assert tcp_group is not None and tcp_group.childCount() == 2


def test_service_tree_shows_pivot_topology(qtbot: QtBot) -> None:
    tree = ServiceTree()
    qtbot.addWidget(tree)
    hosts = [
        DiscoveredHost(
            ip="10.10.5.10",
            hostname="dc01",
            pivot_source="10.129.33.39",
            os_guess="Windows",
            services=[DiscoveredService(445, Proto.TCP, "smb")],
        ),
        DiscoveredHost(ip="172.16.8.10", pivot_source="10.10.5.10"),
    ]
    tree.populate([DiscoveredService(80, Proto.TCP, "http")], hosts)
    labels = []

    def walk(item: object) -> None:
        labels.append(item.text(0))  # type: ignore[attr-defined]
        for i in range(item.childCount()):  # type: ignore[attr-defined]
            walk(item.child(i))  # type: ignore[attr-defined]

    for i in range(tree.topLevelItemCount()):
        walk(tree.topLevelItem(i))
    blob = "\n".join(labels)
    assert "TCP (1)" in blob  # entry services still shown
    assert "Pivoted networks (2)" in blob
    assert "10.10.5.0/24 (1)" in blob and "172.16.8.0/24 (1)" in blob
    assert "10.10.5.10 (dc01)" in blob and "172.16.8.10" in blob
    # a pivoted host's service is a real DiscoveredService item (selectable for its reference)
    pivot_root = tree.topLevelItem(tree.topLevelItemCount() - 1)
    subnet0 = pivot_root.child(0)
    host0 = subnet0.child(0)
    assert host0.child(0).data(0, tree_service_role()) is not None


def tree_service_role() -> int:
    from oscprecon.gui.widgets.service_tree import _SERVICE_ROLE

    return int(_SERVICE_ROLE)


def _find(tree: ServiceTree, prefix: str) -> object:
    def walk(item: object) -> object:
        if item.text(0).startswith(prefix):  # type: ignore[attr-defined]
            return item
        for i in range(item.childCount()):  # type: ignore[attr-defined]
            hit = walk(item.child(i))  # type: ignore[attr-defined]
            if hit is not None:
                return hit
        return None

    for i in range(tree.topLevelItemCount()):
        hit = walk(tree.topLevelItem(i))
        if hit is not None:
            return hit
    return None


def _pivot_hosts() -> list[DiscoveredHost]:
    return [
        DiscoveredHost(
            ip="10.10.5.10", pivot_source="x", services=[DiscoveredService(445, Proto.TCP, "smb")]
        ),
        DiscoveredHost(ip="172.16.8.10", pivot_source="y"),
    ]


def test_service_tree_collapse_persists_across_refresh(qtbot: QtBot) -> None:
    tree = ServiceTree()
    qtbot.addWidget(tree)
    hosts = _pivot_hosts()
    tree.populate([DiscoveredService(80, Proto.TCP, "http")], hosts)
    subnet = _find(tree, "10.10.5.0/24")
    subnet.setExpanded(False)  # type: ignore[attr-defined]  # user folds this /24 shut
    hosts.append(DiscoveredHost(ip="10.10.5.23", pivot_source="x"))  # a streaming scan adds a host
    tree.populate([DiscoveredService(80, Proto.TCP, "http")], hosts, force=True)
    assert _find(tree, "10.10.5.0/24").isExpanded() is False  # type: ignore[attr-defined]
    assert _find(tree, "172.16.8.0/24").isExpanded() is True  # type: ignore[attr-defined]  # others open


def test_service_tree_emits_host_selected(qtbot: QtBot) -> None:
    tree = ServiceTree()
    qtbot.addWidget(tree)
    tree.populate([DiscoveredService(80, Proto.TCP, "http")], _pivot_hosts())
    got: list[object] = []
    tree.host_selected.connect(got.append)
    tree.setCurrentItem(_find(tree, "10.10.5.10"))
    assert isinstance(got[-1], DiscoveredHost) and got[-1].ip == "10.10.5.10"


def test_service_tree_reset_view_state_clears_collapse(qtbot: QtBot) -> None:
    tree = ServiceTree()
    qtbot.addWidget(tree)
    tree.populate([], _pivot_hosts())
    _find(tree, "10.10.5.0/24").setExpanded(False)  # type: ignore[attr-defined]
    assert tree._collapsed  # a subnet is remembered as collapsed
    tree.reset_view_state()  # a new project must not inherit the prior one's collapse state
    assert tree._collapsed == set()


def test_service_tree_host_and_subnet_roles(qtbot: QtBot) -> None:
    from oscprecon.gui.widgets.service_tree import _HOST_ROLE, _SUBNET_ROLE

    tree = ServiceTree()
    qtbot.addWidget(tree)
    tree.populate([], _pivot_hosts())
    host_item = _find(tree, "10.10.5.10")
    subnet_item = _find(tree, "10.10.5.0/24")
    assert isinstance(host_item.data(0, _HOST_ROLE), DiscoveredHost)  # type: ignore[attr-defined]
    assert subnet_item.data(0, _SUBNET_ROLE) == "10.10.5.0/24"  # type: ignore[attr-defined]


def test_tool_panel_targets_pivot_host_not_entry(qtbot: QtBot, tmp_path: object) -> None:
    # regression: a service under a pivoted host built every command against the ENTRY target.
    # With host_ip passed through show_service, the panels must target that host instead.
    from pathlib import Path

    from oscprecon.profile import Profile

    panel = ToolPanel()
    qtbot.addWidget(panel)
    prof = Profile.create(Path(str(tmp_path)), "dante", Target(ip="10.10.110.100"))
    panel.set_profile(prof)
    svc = DiscoveredService(80, Proto.TCP, "http")
    ref = references.match(svc)
    panel.show_service(svc, ref, host_ip="172.16.1.5")
    assert panel._http._url.text() == "http://172.16.1.5/"  # the pivot host, not the entry
    assert "pivot host 172.16.1.5" in panel._header.text()
    panel.show_service(svc, ref, host_ip="")  # an entry-target service still uses the entry IP
    assert panel._http._url.text() == "http://10.10.110.100/"
    # a generic hint also honours the pivot host
    gref = references.ServiceRef(
        label="Generic",
        hacktricks="https://book.hacktricks.wiki/x",
        module="genericsvc",
        tools=[references.ToolHint(name="nmap -sV {target}", purpose="version scan")],
    )
    panel.show_service(DiscoveredService(9999, Proto.TCP, "genericsvc"), gref, host_ip="172.16.1.5")
    panel._on_hint_activated(panel._hints.item(0))
    assert "172.16.1.5" in panel._command.text()


def test_tool_panel_populates_hints_and_expands(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_target("10.10.10.5")
    # a ref with tool hints but no dedicated panel falls back to the generic hints page. Built
    # synthetically so the test never breaks when a real service later gains a module.
    ref = references.ServiceRef(
        label="Generic",
        hacktricks="https://book.hacktricks.wiki/x",
        module="genericsvc",
        tools=[references.ToolHint(name="nmap -sV {target}", purpose="version scan")],
    )
    panel.show_service(DiscoveredService(9999, Proto.TCP, "genericsvc"), ref)
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
    # entry host is a single top-level node (IP shown) with the TCP/UDP groups nested under it
    assert window._service_tree.topLevelItemCount() == 1
    entry = window._service_tree.topLevelItem(0)
    assert entry is not None and "10.10.10.100" in entry.text(0)
    tcp = entry.child(0)
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
    hit = ExploitHit(
        "44908",
        "Redis 5.0 - Denial of Service",
        "https://www.exploit-db.com/exploits/44908",
        "",
        type="dos",
        platform="linux",
        date="2018-06-20",
        cve="CVE-2018-12453",
        version_match=True,
    )
    pane.show_exploits(EdbSearch([hit], "redis 5.0", "version"))
    assert pane._exploits.count() == 1
    text = pane._exploits.item(0).text()
    assert "EDB-44908" in text and "dos" in text and "★" in text  # id + type badge + match marker
    assert not pane._edb_header.isHidden() and "redis 5.0" in pane._edb_header.text()
    assert "CVE-2018-12453" in pane._exploits.item(0).toolTip()  # CVE surfaced in the tooltip
    assert pane._exploits.item(0).font().weight() >= QFont.Weight.DemiBold  # match is emphasised


def test_reference_pane_show_exploits_product_scope(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    hit = ExploitHit("49765", "MariaDB 10.2 - OS Command Execution", "url", "")
    pane.show_exploits(EdbSearch([hit], "mariadb", "product"))
    assert "product-wide" in pane._edb_header.text()  # fallback labelled, not mistaken for a match


def test_reference_pane_show_exploits_none(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_exploits(EdbSearch([], "", "none"))
    assert pane._edb_header.isHidden()
    assert "skipped" in pane._exploits.item(0).text()


def test_main_window_edb_stale_result_ignored(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "edb", Target(ip="10.0.0.1"))
    window._set_profile(prof)
    prof.read_only = True  # skip the disk persist; assert only the UI-show gate here
    window._edb_request_id = 5
    hit = ExploitHit("1", "title", "https://www.exploit-db.com/exploits/1", "")
    search = EdbSearch([hit], "apache 2.4", "version")
    ctx = ("80/tcp http", "apache", "2.4")
    window._on_edb_done(search, 4, prof, ctx)  # stale id -> not shown
    assert window._reference_pane._exploits.count() == 0
    window._on_edb_done(search, 5, prof, ctx)  # current id -> shown
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
    worker = QThread()
    window._tasks.add(worker, "nmap", exclusive=True)  # simulate a run in progress
    window._on_page_visited("smb", "https://book.hacktricks.wiki/smb")
    assert prof.references_visited == []  # buffered, not recorded yet
    # each buffered visit is tagged with its originating profile dir (finding #7)
    assert window._pending_visits == [
        ("smb", "https://book.hacktricks.wiki/smb", str(prof.directory))
    ]
    window._tasks.remove(worker)
    window._post_run_refresh()  # drains the buffer once the run clears
    assert any(v["url"] == "https://book.hacktricks.wiki/smb" for v in prof.references_visited)
    assert window._pending_visits == []
