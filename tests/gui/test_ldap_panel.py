from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon import shell
from oscprecon.gui.widgets.ldap_panel import _COMMAND_ROLE, LdapPanel
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef
from oscprecon.service_enum import LdapEnum

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "ldap"


def _ldap_ref() -> ServiceRef:
    return ServiceRef(label="LDAP", hacktricks="https://x", module="ldap", tools=[])


def _profile(tmp_path: Path) -> Profile:
    return Profile.create(tmp_path, "b", Target(ip="10.10.10.5", hostname="example.htb"))


def test_recon_button_emits_basedn_and_port(qtbot: QtBot, tmp_path: Path) -> None:
    panel = LdapPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))  # seeds base DN from hostname
    panel.configure(DiscoveredService(389, Proto.TCP, "ldap"))
    captured: list[tuple[str, int]] = []
    panel.recon_requested.connect(lambda basedn, port, _a: captured.append((basedn, port)))
    panel._recon.click()
    assert captured == [("DC=example,DC=htb", 389)]  # derived from example.htb


def test_invalid_basedn_blocks_recon(qtbot: QtBot, tmp_path: Path) -> None:
    panel = LdapPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel._basedn.setText('DC=x" evil')
    recon: list[tuple[str, int]] = []
    failures: list[str] = []
    panel.recon_requested.connect(lambda b, p, _a: recon.append((b, p)))
    panel.validation_failed.connect(failures.append)
    panel._recon.click()
    assert recon == []
    assert failures and "invalid base DN" in failures[0]


def test_manual_followups_expand_and_stay_legal(qtbot: QtBot, tmp_path: Path) -> None:
    panel = LdapPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    assert panel._manual.count() > 0
    commands = [panel._manual.item(i).data(_COMMAND_ROLE) for i in range(panel._manual.count())]
    joined = " ".join(commands)
    assert "10.10.10.5" in joined
    assert "DC=example,DC=htb" in joined  # sanitized base DN reaches every follow-up
    assert "-x" in joined  # anonymous binds
    for tool in ("hydra", "medusa", "--passwords", "rockyou"):
        assert tool not in joined


def test_manual_followups_reject_hostile_basedn(qtbot: QtBot, tmp_path: Path) -> None:
    panel = LdapPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel._basedn.setText('DC=x" -H ldap://evil')  # tries to smuggle a second -H
    commands = [panel._manual.item(i).data(_COMMAND_ROLE) for i in range(panel._manual.count())]
    joined = " ".join(commands)
    assert "evil" not in joined  # hostile base DN dropped before it reaches a command
    assert 'DC=x"' not in joined


def test_tool_panel_switches_to_ldap_page(qtbot: QtBot, tmp_path: Path) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_target("10.10.10.5")
    panel.set_profile(_profile(tmp_path))
    panel.show_service(DiscoveredService(389, Proto.TCP, "ldap"), _ldap_ref())
    assert panel._stack.currentWidget() is panel._ldap
    panel.set_ldap_summary(["Anonymous bind: allowed"])
    assert panel._ldap._summary.count() == 1


def test_tool_panel_forwards_ldap_signals(qtbot: QtBot, tmp_path: Path) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel.show_service(DiscoveredService(389, Proto.TCP, "ldap"), _ldap_ref())
    recon: list[tuple[str, int]] = []
    manual: list[str] = []
    panel.ldap_recon_requested.connect(lambda b, p, _a: recon.append((b, p)))
    panel.run_requested.connect(manual.append)
    panel._ldap._recon.click()
    panel._ldap._on_manual_activated(panel._ldap._manual.item(0))
    assert recon == [("DC=example,DC=htb", 389)]
    assert manual and "10.10.10.5" in manual[0]


def _fake_run_factory() -> object:
    def fake_run(
        shell_line: str,
        output_file: Path,
        *,
        cwd: Path | None = None,
        timeout: object | None = None,
        cancel: object | None = None,
        on_line: object | None = None,
    ) -> object:
        if shell_line.startswith("nmap"):
            text = (_FIXTURES / "nmap-ldap.txt").read_text(encoding="utf-8")
        elif "-s base" in shell_line:
            text = (_FIXTURES / "rootdse.txt").read_text(encoding="utf-8")
        elif "objectClass=person" in shell_line:
            text = (_FIXTURES / "users.txt").read_text(encoding="utf-8")
        else:
            text = ""
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    return fake_run


def test_ldap_worker_two_phase_discovers_basedn_and_users(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = _profile(tmp_path)
    monkeypatch.setattr(shell, "run", _fake_run_factory())

    # pass no base DN — the worker must discover it from the root DSE naming contexts
    result = LdapEnum(prof, "", 389).run()

    assert result.creds and result.creds[0].source == "ldap-anon-enum"
    assert any("Anonymous bind: allowed" in line for line in result.summary)
    assert any("Base DN used: DC=example,DC=htb" in line for line in result.summary)
    assert any("Users (4)" in line for line in result.summary)

    stored = findings_mod.load_findings(prof.directory)
    values = {f.get("value") for f in stored}
    assert "jsmith" in values  # user surfaced from the discovered-base-DN search
    assert "DC=example,DC=htb" in values


def test_ldap_worker_denied_bind_writes_no_cred(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = _profile(tmp_path)

    def blank_run(
        shell_line: str,
        output_file: Path,
        *,
        cwd: Path | None = None,
        timeout: object | None = None,
        cancel: object | None = None,
        on_line: object | None = None,
    ) -> object:
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("", encoding="utf-8")  # nothing came back — anonymous bind refused
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    monkeypatch.setattr(shell, "run", blank_run)
    result = LdapEnum(prof, "", 389).run()
    assert result.creds == []
    assert any("Anonymous bind: denied" in line for line in result.summary)
