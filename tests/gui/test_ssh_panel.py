from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon import shell
from oscprecon.gui import main_window as mw
from oscprecon.gui.widgets.ssh_panel import _COMMAND_ROLE, SshPanel
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "ssh"


def _ssh_ref() -> ServiceRef:
    return ServiceRef(label="SSH", hacktricks="https://x", module="ssh", tools=[])


def test_recon_button_emits_port(qtbot: QtBot) -> None:
    panel = SshPanel()
    qtbot.addWidget(panel)
    panel.configure(DiscoveredService(2222, Proto.TCP, "ssh"))  # non-default port
    captured: list[int] = []
    panel.recon_requested.connect(captured.append)
    panel._recon.click()
    assert captured == [2222]


def test_manual_followups_expand_and_stay_legal(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = SshPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    assert panel._manual.count() > 0
    commands = [panel._manual.item(i).data(_COMMAND_ROLE) for i in range(panel._manual.count())]
    joined = " ".join(commands)
    assert "10.10.10.5" in joined
    assert "--passwords" not in joined
    assert "rockyou" not in joined
    for tool in ("hydra", "medusa", "ncrack", "sshpass"):
        assert tool not in joined


def test_manual_followups_honor_non_default_port(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = SshPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.configure(DiscoveredService(2222, Proto.TCP, "ssh"))
    commands = [panel._manual.item(i).data(_COMMAND_ROLE) for i in range(panel._manual.count())]
    joined = " ".join(commands)
    assert "-p 2222" in joined  # the port reaches every follow-up
    assert "root@10.10.10.5" in joined  # host stays bare — ssh uses -p, not host:port
    assert "10.10.10.5:2222" not in joined  # no ftp-style host:port fold slipped in


def test_tool_panel_switches_to_ssh_page(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_target("10.10.10.5")
    panel.set_profile(prof)
    panel.show_service(DiscoveredService(22, Proto.TCP, "ssh"), _ssh_ref())
    assert panel._stack.currentWidget() is panel._ssh
    panel.set_ssh_summary(["Banner: OpenSSH 7.6p1"])
    assert panel._ssh._summary.count() == 1


def test_tool_panel_forwards_ssh_signals(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.show_service(DiscoveredService(22, Proto.TCP, "ssh"), _ssh_ref())
    ports: list[int] = []
    manual: list[str] = []
    panel.ssh_recon_requested.connect(ports.append)
    panel.run_requested.connect(manual.append)
    panel._ssh._recon.click()
    panel._ssh._on_manual_activated(panel._ssh._manual.item(0))
    assert ports == [22]
    assert manual and "10.10.10.5" in manual[0]


def _fake_run_factory() -> object:
    nmap = (_FIXTURES / "nmap-ssh.txt").read_text(encoding="utf-8")

    def fake_run(
        shell_line: str,
        output_file: Path,
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        on_line: object | None = None,
    ) -> object:
        text = nmap if shell_line.startswith("nmap") else ""
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    return fake_run


def test_ssh_worker_parses_and_writes_findings(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    monkeypatch.setattr(shell, "run", _fake_run_factory())

    worker = mw.SshReconWorker(prof, 22)
    result = worker._drive()

    assert any("Banner: OpenSSH 7.6p1" in line for line in result.summary)
    assert any("Auth methods" in line and "password" in line for line in result.summary)
    assert any("Password auth enabled" in line for line in result.summary)

    stored = findings_mod.load_findings(prof.directory)
    kinds = {f.get("kind") for f in stored}
    assert {"banner", "hostkey", "algo-weak", "auth"} <= kinds


def test_ssh_worker_handles_empty_output(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))

    def blank_run(
        shell_line: str,
        output_file: Path,
        *,
        cwd: Path | None = None,
        timeout: object | None = None,
        on_line: object | None = None,
    ) -> object:
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("", encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    monkeypatch.setattr(shell, "run", blank_run)
    result = mw.SshReconWorker(prof, 22)._drive()
    assert result.summary == ["No SSH findings."]
    assert findings_mod.load_findings(prof.directory) == []  # nothing written on empty parse
