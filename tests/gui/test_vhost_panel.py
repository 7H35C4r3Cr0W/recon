from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.gui.widgets.vhost_panel import VhostPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef


def _ref(module: str = "http") -> ServiceRef:
    return ServiceRef(
        label="HTTP", hacktricks="https://book.hacktricks.wiki/x", module=module, tools=[]
    )


def _profile(tmp_path: Path) -> Profile:
    return Profile.create(tmp_path, "b", Target(ip="10.10.10.5", hostname="example.com"))


def test_vhost_panel_builds_ffuf(qtbot: QtBot, tmp_path: Path) -> None:
    panel = VhostPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    preview = panel._preview.toPlainText()
    assert preview.startswith('ffuf -u http://10.10.10.5/ -H "Host: FUZZ.example.com"')
    assert "subdomains-top1million-5000.txt" in preview


def test_vhost_tool_translation(qtbot: QtBot, tmp_path: Path) -> None:
    panel = VhostPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel._tool.setCurrentText("dnsrecon")
    panel._refresh()
    assert panel._preview.toPlainText().startswith("dnsrecon -d example.com -t brt")


def test_vhost_run_requested(qtbot: QtBot, tmp_path: Path) -> None:
    panel = VhostPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    with qtbot.waitSignal(panel.run_requested, timeout=1000) as blocker:
        panel._on_run()
    command, output_rel, tool, domain = blocker.args
    assert tool == "ffuf"
    assert domain == "example.com"
    # the wordlist is part of the path so two sweeps can run at once
    assert output_rel.startswith("vhost/ffuf") and output_rel.endswith(".json")
    assert "Host: FUZZ.example.com" in command


def test_wildcard_detect_requested(qtbot: QtBot, tmp_path: Path) -> None:
    panel = VhostPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    with qtbot.waitSignal(panel.wildcard_detect_requested, timeout=1000) as blocker:
        panel._on_detect_wildcard()
    command, output_rel = blocker.args
    assert "%{size_download}" in command
    assert output_rel == "vhost/wildcard-probe.txt"


def test_add_vhosts_dedup_and_enumerate(qtbot: QtBot, tmp_path: Path) -> None:
    panel = VhostPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel.add_vhosts(["admin.example.com", "dev.example.com"])
    panel.add_vhosts(["admin.example.com"])  # duplicate ignored
    assert panel._vhosts.count() == 2
    panel._vhosts.setCurrentRow(0)
    with qtbot.waitSignal(panel.enumerate_as_http_requested, timeout=1000) as blocker:
        panel._on_enumerate()
    assert blocker.args[0] == "admin.example.com"


def test_vhost_rejects_injection_domain(qtbot: QtBot, tmp_path: Path) -> None:
    panel = VhostPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel._domain.setText('example.com" -x http://evil')  # flag-injection attempt
    with (
        qtbot.assertNotEmitted(panel.run_requested),  # must NOT run
        qtbot.waitSignal(panel.validation_failed, timeout=1000),
    ):
        panel._on_run()


def test_tool_panel_shows_vhost_tab_and_enumerate(qtbot: QtBot, tmp_path: Path) -> None:
    tp = ToolPanel()
    qtbot.addWidget(tp)
    tp.set_profile(_profile(tmp_path))
    tp.show_service(DiscoveredService(80, Proto.TCP, "http"), _ref())
    assert tp._stack.currentWidget() is tp._web_tabs
    assert tp._web_tabs.count() == 3  # content discovery + discovered URLs + vhosts
    assert [tp._web_tabs.tabText(i) for i in range(3)] == [
        "Content discovery",
        "Discovered URLs",
        "Vhosts",
    ]
    tp.enumerate_http("admin.example.com")
    assert tp._web_tabs.currentWidget() is tp._http
    assert "admin.example.com" in tp._http._url.text()
