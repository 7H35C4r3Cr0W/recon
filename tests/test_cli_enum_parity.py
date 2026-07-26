"""`nabu-cli enum` and the GUI service panels must run the SAME recon, not two depths of it.

The CLI used to run only each module's FIRST phase: `enum smb` stopped after the null/guest probe
while the SMB panel went on to the follow-ups (users, password policy, RID cycling), walked every
readable share and peeked at small files. Same command name, visibly different work, and nothing
said so. Both sides now drive `oscprecon.service_enum`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import oscprecon.cli as cli_mod
from oscprecon import shell
from oscprecon.cli import app
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile

runner = CliRunner()
_SMB_FIXTURES = Path(__file__).parent / "fixtures" / "smb"


def _smb_box(tmp_path: Path) -> Profile:
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.5", hostname="active.htb"))
    profile.set_services(
        [DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at="")]
    )
    profile.save()
    return profile


def _fake_smb_run() -> Any:
    shares = (_SMB_FIXTURES / "netexec-shares.txt").read_text(encoding="utf-8")
    users = (_SMB_FIXTURES / "netexec-users.txt").read_text(encoding="utf-8")
    seen: list[str] = []

    def fake_run(shell_line: str, output_file: Path, **_kw: Any) -> Any:
        seen.append(shell_line)
        if "--shares" in shell_line and "-u '' " in shell_line:
            text = shares
        elif "--shares" in shell_line and "guest" in shell_line:
            text = "SMB 10.10.10.5 445 DC01 [-] active.htb\\guest: STATUS_ACCESS_DENIED"
        elif "--users" in shell_line:
            text = users
        else:
            text = ""
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    fake_run.seen = seen  # type: ignore[attr-defined]
    return fake_run


def test_cli_enum_smb_runs_the_followup_phase_not_just_the_first_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the headline gap: follow-ups only run when the null/guest probe AUTHENTICATED, so a CLI that
    # stopped after phase one could never reach them.
    _smb_box(tmp_path)
    fake = _fake_smb_run()
    monkeypatch.setattr(shell, "run", fake)
    result = runner.invoke(app, ["enum", "smb", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    ran = " ".join(fake.seen)
    assert "--users" in ran, "the follow-up phase never ran"
    assert "--pass-pol" in ran or "--rid-brute" in ran


def test_cli_enum_smb_records_the_anonymous_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a working null session is a credential the later modules consume (§11) — the CLI never
    # recorded it, so headless recon left the vault empty where the GUI filled it.
    profile = _smb_box(tmp_path)
    monkeypatch.setattr(shell, "run", _fake_smb_run())
    result = runner.invoke(app, ["enum", "smb", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    reloaded = Profile.load(profile.directory)
    sources = {c.source for c in reloaded.credentials()}
    assert "smb-anon-enum" in sources


def test_cli_enum_smb_summary_matches_the_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the CLI prints the engine's own summary — the same lines the SMB panel shows, including the
    # pattern-library suggestion the CLI previously had no way to produce.
    _smb_box(tmp_path)
    monkeypatch.setattr(shell, "run", _fake_smb_run())
    result = runner.invoke(app, ["enum", "smb", "-p", "box", "--workspace", str(tmp_path)])
    assert "null session OK" in result.output
    assert "Shares" in result.output


def test_every_sequenced_service_routes_through_the_shared_engine() -> None:
    # if a service is driven by a conditional SEQUENCE it must be in _ENGINE_SERVICES, or the CLI
    # silently falls back to the flat first-phase driver and the gap reopens.
    assert {"smb", "ftp", "ssh", "dns", "ldap"} == cli_mod._ENGINE_SERVICES
    for name in cli_mod._ENGINE_SERVICES:
        assert name in cli_mod._FULL_ENUM_MODULES


def test_the_engines_are_qt_free() -> None:
    # `nabu-cli` must never pull PySide6 in — the engine is imported by the CLI and merely WRAPPED
    # by the workers. Checked by import, in a clean interpreter: a stray `from PySide6 …` anywhere
    # in the engine's import graph would cost every headless run a Qt load.
    import subprocess
    import sys

    probe = (
        "import oscprecon.service_enum, sys; "
        "sys.exit(1 if any(m.startswith('PySide6') for m in sys.modules) else 0)"
    )
    assert subprocess.run([sys.executable, "-c", probe], check=False).returncode == 0


def test_the_gui_workers_delegate_rather_than_reimplement() -> None:
    # the whole point of the extraction: if a worker grows its own _drive again, the two sides can
    # drift apart exactly as they did before.
    import inspect

    from oscprecon.gui.workers import service_recon

    source = inspect.getsource(service_recon)
    assert "_drive" not in source
    for engine in ("SmbEnum", "FtpEnum", "SshEnum", "DnsEnum", "LdapEnum"):
        assert engine in source


def test_enum4linux_null_session_alone_unlocks_the_followups(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # netexec and enum4linux routinely disagree on a Windows/Samba box: netexec gets
    # STATUS_ACCESS_DENIED while enum4linux's RPC null session goes through. Gating the follow-ups
    # and the share walk on netexec ALONE meant the operator was told "Anonymous access: none"
    # while the findings pane showed a working null session and a READ share nobody walked.
    from oscprecon.service_enum import SmbEnum

    profile = _smb_box(tmp_path)
    e4l = (
        "[+] Got domain/workgroup name: WORKGROUP\n"
        "[*] Check for anonymous access (null session)\n"
        "[+] Server allows authentication via username '' and password ''\n"
    )
    seen: list[str] = []

    def fake_run(shell_line: str, output_file: Path, **_kw: Any) -> Any:
        seen.append(shell_line)
        text = e4l if "enum4linux" in shell_line else ""
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    monkeypatch.setattr(shell, "run", fake_run)
    result = SmbEnum(profile, "full").run()

    assert any("--users" in line for line in seen), (
        "enum4linux's null session must unlock follow-ups"
    )
    assert any("session OK" in line for line in result.summary)
    assert result.creds and result.creds[0].source == "smb-anon-enum"
