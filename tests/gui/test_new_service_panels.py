import pytest
from pytestqt.qtbot import QtBot

from oscprecon import references
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredService, Proto

# Each newly-added read-only service, with a representative (port, proto, nmap-service) that a scan
# would produce. Proves the whole chain works end-to-end: services.yaml maps the port -> module, and
# tool_panel surfaces that module's SimpleReconPanel (not the generic hints fallback).
_NEW_SERVICES = [
    ("rdp", 3389, Proto.TCP, "ms-wbt-server"),
    ("vnc", 5900, Proto.TCP, "vnc"),
    ("finger", 79, Proto.TCP, "finger"),
    ("x11", 6001, Proto.TCP, "X11"),
    ("ajp", 8009, Proto.TCP, "ajp13"),
    ("ipmi", 623, Proto.UDP, "asf-rmcp"),
    ("sip", 5060, Proto.UDP, "sip"),
    ("oracle", 1521, Proto.TCP, "oracle-tns"),
    ("elasticsearch", 9200, Proto.TCP, "wap-wsp"),
    ("couchdb", 5984, Proto.TCP, "couchdb"),
    ("docker", 2375, Proto.TCP, "docker"),
    ("kubernetes", 6443, Proto.TCP, "sun-sr-https"),
    ("memcached", 11211, Proto.TCP, "memcache"),
    ("winrm", 5985, Proto.TCP, "wsman"),
    ("rsync", 873, Proto.TCP, "rsync"),
    ("msrpc", 135, Proto.TCP, "msrpc"),
    ("imap", 143, Proto.TCP, "imap"),
    ("pop3", 110, Proto.TCP, "pop3"),
    ("telnet", 23, Proto.TCP, "telnet"),
    ("ipp", 631, Proto.TCP, "ipp"),
    ("iscsi", 3260, Proto.TCP, "iscsi"),
    ("svn", 3690, Proto.TCP, "svnserve"),
    ("ident", 113, Proto.TCP, "ident"),
    ("mdns", 5353, Proto.UDP, "mdns"),
    ("upnp", 1900, Proto.UDP, "upnp"),
    ("rmi", 1099, Proto.TCP, "java-rmi"),
    ("openvpn", 1194, Proto.UDP, "openvpn"),
    ("rpcbind", 111, Proto.TCP, "rpcbind"),
    ("etcd", 2379, Proto.TCP, "etcd"),
]


@pytest.mark.parametrize(("module", "port", "proto", "svc_name"), _NEW_SERVICES)
def test_new_service_opens_its_recon_panel(
    qtbot: QtBot, module: str, port: int, proto: Proto, svc_name: str
) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_target("10.10.10.5")
    svc = DiscoveredService(port, proto, svc_name)
    ref = references.match(svc)
    assert ref is not None, f"{svc_name}:{port} has no services.yaml reference"
    assert ref.module == module, f"{svc_name}:{port} resolved to {ref.module}, expected {module}"

    panel.show_service(svc, ref)
    assert module in panel._simple, f"no SimpleReconPanel registered for {module}"
    assert panel._stack.currentWidget() is panel._simple[module]  # its panel is the one shown


def test_every_new_service_has_a_tier1_button(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    for module, *_ in _NEW_SERVICES:
        recon_panel = panel._simple[module]
        assert recon_panel._recon.text().strip(), f"{module} panel has no Tier-1 button label"
