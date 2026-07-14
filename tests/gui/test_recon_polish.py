from dataclasses import fields

from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtWidgets import QPushButton
from pytestqt.qtbot import QtBot

from oscprecon.gui.simple_recon import SIMPLE_SPECS
from oscprecon.gui.theme import tokens
from oscprecon.gui.theme.tokens import Palette
from oscprecon.gui.widgets.dns_panel import DnsPanel
from oscprecon.gui.widgets.ftp_panel import FtpPanel
from oscprecon.gui.widgets.ldap_panel import LdapPanel
from oscprecon.gui.widgets.service_tree import _PROTO_COLOR, _SERVICE_ROLE, ServiceTree
from oscprecon.gui.widgets.simple_recon_panel import SimpleReconPanel
from oscprecon.gui.widgets.smb_panel import SmbPanel
from oscprecon.gui.widgets.ssh_panel import SshPanel
from oscprecon.gui.workspace.dashboard import _STATUS_COLOR, WorkspaceDashboard
from oscprecon.models import DiscoveredService, Proto
from oscprecon.workspace import STATUSES


def test_dashboard_empty_state_is_illustrated(qtbot: QtBot) -> None:
    dash = WorkspaceDashboard()
    qtbot.addWidget(dash)
    dash._apply_filters()  # 0 summaries -> empty page (index 1)
    assert dash._stack.currentIndex() == 1
    empty = dash._empty
    assert empty.findChildren(QSvgWidget), "empty state should show the illustration"
    buttons = [b.text() for b in empty.findChildren(QPushButton)]
    assert any("New Project" in t for t in buttons)  # clear primary call-to-action
    dash.shutdown()


def test_status_color_map_covers_every_status() -> None:
    # a new workspace status must not silently render uncoloured — the map has to cover them all
    palette_fields = {f.name for f in fields(Palette)}
    for status in (*STATUSES, "archived"):
        assert status in _STATUS_COLOR, status
        assert _STATUS_COLOR[status] in palette_fields  # maps to a real token


def test_service_tree_colours_tcp_and_udp_apart(qtbot: QtBot) -> None:
    tree = ServiceTree()
    qtbot.addWidget(tree)
    tree.populate(
        [
            DiscoveredService(22, Proto.TCP, "ssh"),
            DiscoveredService(161, Proto.UDP, "snmp"),
        ]
    )
    leaves = {}
    for i in range(tree.topLevelItemCount()):
        group = tree.topLevelItem(i)
        for j in range(group.childCount()):
            leaf = group.child(j)
            svc = leaf.data(0, _SERVICE_ROLE)
            leaves[svc.proto] = leaf.foreground(0).color()
    assert leaves[Proto.TCP] == _PROTO_COLOR[Proto.TCP]
    assert leaves[Proto.UDP] == _PROTO_COLOR[Proto.UDP]
    assert leaves[Proto.TCP] != leaves[Proto.UDP]  # visibly distinct


def test_flagship_tier1_buttons_are_ranked_primary(qtbot: QtBot) -> None:
    # the primary Tier-1 recon action in each service panel carries the accent primary style, so it
    # reads apart from the secondary/manual actions
    smb = SmbPanel()
    ftp = FtpPanel()
    ssh = SshPanel()
    dns = DnsPanel()
    ldap = LdapPanel()
    simple = SimpleReconPanel(next(iter(SIMPLE_SPECS.values())))
    for widget in (smb, ftp, ssh, dns, ldap, simple):
        qtbot.addWidget(widget)
    primary = [smb._full, ftp._full, ssh._recon, dns._recon, ldap._recon, simple._recon]
    for button in primary:
        assert tokens.DARK.accent in button.styleSheet()  # gold primary CTA
    # a secondary Tier-1 action is NOT styled primary (visual ranking holds)
    assert tokens.DARK.accent not in smb._null.styleSheet()
