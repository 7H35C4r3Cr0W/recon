from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon.gui.widgets.http_panel import HttpPanel
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef

SECTION9 = (
    "feroxbuster -u http://10.129.95.192/ "
    "-w /usr/share/seclists/Discovery/Web-Content/big.txt "
    "-x php,phps,asp,aspx,jsp,cfm,js,css,html,htm,txt,log,bak,backup,old,swp,zip,tar,"
    "tar.gz,tgz,7z,rar,sql,sqlite,xml,json,conf,config,ini,inc "
    "-d 4 -t 100 --timeout 25 --rate-limit 40 -k "
    "-s 200,204,301,302,307,401,403,404,500 -o ferox_10.129.95.192.txt"
)


def _ref(module: str = "http", label: str = "HTTP") -> ServiceRef:
    return ServiceRef(
        label=label, hacktricks="https://book.hacktricks.wiki/x", module=module, tools=[]
    )


def test_http_panel_reproduces_section_9_via_controls(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.129.95.192"))
    panel = HttpPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.configure(DiscoveredService(80, Proto.TCP, "http"), _ref())

    panel._tool.setCurrentText("feroxbuster")
    panel._wide_net.setChecked(False)
    panel._custom_exts.setText(
        "php,phps,asp,aspx,jsp,cfm,js,css,html,htm,txt,log,bak,backup,old,swp,zip,tar,"
        "tar.gz,tgz,7z,rar,sql,sqlite,xml,json,conf,config,ini,inc"
    )
    panel._threads.setValue(100)
    panel._depth.setValue(4)
    panel._timeout.setValue(25)
    panel._rate_enabled.setChecked(True)
    panel._rate.setValue(40)
    panel._skip_tls.setChecked(True)
    panel._status_preset.setCurrentText("All informative")
    panel._output.setText("ferox_10.129.95.192.txt")
    panel._refresh()

    assert panel._preview.toPlainText() == SECTION9


def test_default_controls_are_wide_net_and_big_txt(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = HttpPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.configure(DiscoveredService(80, Proto.TCP, "http"), _ref())
    preview = panel._preview.toPlainText()
    assert preview.startswith("feroxbuster -u http://10.10.10.5/")
    assert "big.txt" in preview
    assert "-t 40" in preview and "-d 2" in preview and "-k" in preview
    # wide net on by default => many extensions
    assert "-x php," in preview and "bak" in preview and "json" in preview


def test_extension_multiselect_and_custom(qtbot: QtBot) -> None:
    panel = HttpPanel()
    qtbot.addWidget(panel)
    panel._wide_net.setChecked(False)
    panel._group_boxes["Scripts"].setChecked(True)
    panel._custom_exts.setText("abc xyz")
    exts = panel._current_extensions()
    assert "js" in exts  # from Scripts group
    assert "abc" in exts and "xyz" in exts  # custom
    assert "php" not in exts  # Web stack not selected


def test_tool_translation_in_preview(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = HttpPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.configure(DiscoveredService(80, Proto.TCP, "http"), _ref())
    panel._tool.setCurrentText("ffuf")
    panel._refresh()
    assert "ffuf -u http://10.10.10.5/FUZZ" in panel._preview.toPlainText()


def test_run_requested_emits_command_and_target(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.5"))
    panel = HttpPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.configure(DiscoveredService(8080, Proto.TCP, "http-proxy"), _ref())
    with qtbot.waitSignal(panel.run_requested, timeout=1000) as blocker:
        panel._on_run()
    command, output_rel, tool, port = blocker.args
    assert tool == "feroxbuster"
    assert port == 8080
    assert output_rel == "http/8080/feroxbuster-big.txt"
    assert command.startswith("feroxbuster -u http://10.0.0.5:8080/")


def test_settings_persist_to_profile(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.5"))
    panel = HttpPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel._threads.setValue(120)
    assert prof.module_settings["http"]["threads"] == 120
    # a fresh panel restores them
    panel2 = HttpPanel()
    qtbot.addWidget(panel2)
    panel2.set_profile(prof)
    assert panel2._threads.value() == 120


def test_tool_panel_switches_to_http_builder(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.5"))
    tp = ToolPanel()
    qtbot.addWidget(tp)
    tp.set_profile(prof)
    tp.show_service(DiscoveredService(80, Proto.TCP, "http"), _ref(module="http"))
    assert tp._stack.currentWidget() is tp._web_tabs  # http builder now lives in the tab widget
    assert tp._web_tabs.currentWidget() is tp._http
    tp.show_service(DiscoveredService(22, Proto.TCP, "ssh"), _ref(module="ssh", label="SSH"))
    assert tp._stack.currentIndex() == 0


def test_custom_output_sticks_within_session(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.5"))
    panel = HttpPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.configure(DiscoveredService(80, Proto.TCP, "http"), _ref())
    panel._output.setText("http/80/custom.txt")
    panel._threads.setValue(55)  # a non-output change must NOT clobber the custom output
    assert panel._output.text() == "http/80/custom.txt"


def test_contained_path_rejects_escapes(tmp_path: Path) -> None:
    from oscprecon.gui.main_window import _contained_path

    assert _contained_path(tmp_path, "http/80/x.txt") is not None
    assert _contained_path(tmp_path, "/etc/passwd") is None
    assert _contained_path(tmp_path, "../../etc/passwd") is None
