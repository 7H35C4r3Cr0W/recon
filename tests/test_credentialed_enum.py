"""End to end: a credential in the vault re-runs the SAME enumeration authenticated.

Covers the whole path the operator actually walks — find a password during http enum, add it to the
vault, then point SMB/LDAP recon at it from either front-end. The engine, the CLI flag and the GUI
"Run as" picker must all reach the same authenticated commands, and the anonymous default must be
untouched.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oscprecon import service_enum, shell
from oscprecon.cli import app
from oscprecon.models import Credential, DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.recon_auth import ReconAuth

runner = CliRunner()
_SMB_FIXTURES = Path(__file__).parent / "fixtures" / "smb"


def _box(tmp_path: Path, *, with_cred: bool = True) -> Profile:
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.5", hostname="active.htb"))
    profile.set_services(
        [DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at="")]
    )
    if with_cred:
        profile.add_credential(
            Credential(
                username="svc_account",
                secret="Ticketmaster1968",
                domain="active.htb",
                source="http-config-leak",
            )
        )
    profile.save()
    return profile


def _recorder(authenticated_ok: bool = True) -> Any:
    shares = (_SMB_FIXTURES / "netexec-shares.txt").read_text(encoding="utf-8")
    seen: list[str] = []

    def fake_run(shell_line: str, output_file: Path, **_kw: Any) -> Any:
        seen.append(shell_line)
        if "--shares" in shell_line and "svc_account" in shell_line:
            text = (
                shares if authenticated_ok else "SMB 10.10.10.5 445 DC01 [-] STATUS_LOGON_FAILURE"
            )
        elif "--shares" in shell_line:
            text = "SMB 10.10.10.5 445 DC01 [-] STATUS_ACCESS_DENIED"
        else:
            text = ""
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    fake_run.seen = seen  # type: ignore[attr-defined]
    return fake_run


# --- the engine ---------------------------------------------------------------------------------


def test_a_credential_replaces_the_anonymous_phases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # asking whether guest works is pointless once you hold a real account, and running both would
    # mix two identities' share lists into one findings set
    profile = _box(tmp_path)
    fake = _recorder()
    monkeypatch.setattr(shell, "run", fake)
    monkeypatch.setattr(service_enum.shell, "run", fake)

    auth = ReconAuth.from_credential(profile.credentials()[0])
    result = service_enum.SmbEnum(profile, "full", auth=auth).run()

    joined = " ".join(fake.seen)  # type: ignore[attr-defined]
    assert "svc_account" in joined
    assert "-u 'guest'" not in joined
    assert "enum4linux-ng" not in joined  # the anonymous sweep is skipped
    assert any("Authenticated as" in line for line in result.summary)


def test_the_anonymous_default_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _box(tmp_path)
    fake = _recorder()
    monkeypatch.setattr(shell, "run", fake)
    monkeypatch.setattr(service_enum.shell, "run", fake)

    service_enum.SmbEnum(profile, "full").run()  # no auth passed

    joined = " ".join(fake.seen)  # type: ignore[attr-defined]
    assert "svc_account" not in joined  # a vault credential is never used unless chosen
    assert "-u '' -p '' --shares" in joined
    assert "enum4linux-ng -A" in joined


def test_a_rejected_credential_says_so_and_records_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _box(tmp_path)
    fake = _recorder(authenticated_ok=False)
    monkeypatch.setattr(shell, "run", fake)
    monkeypatch.setattr(service_enum.shell, "run", fake)

    lines: list[str] = []
    auth = ReconAuth.from_credential(profile.credentials()[0])
    result = service_enum.SmbEnum(profile, "full", lines.append, auth=auth).run()

    assert any("REJECTED" in line for line in lines)  # §24: never a silent failure
    assert not result.creds
    assert any("credential rejected" in line for line in result.summary)


def test_a_successful_authenticated_run_records_the_working_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _box(tmp_path)
    fake = _recorder()
    monkeypatch.setattr(shell, "run", fake)
    monkeypatch.setattr(service_enum.shell, "run", fake)

    auth = ReconAuth.from_credential(profile.credentials()[0])
    result = service_enum.SmbEnum(profile, "full", auth=auth).run()

    assert [c.source for c in result.creds] == ["smb-authenticated-enum"]
    assert result.creds[0].secret == "Ticketmaster1968"  # §6: never redacted


# --- the CLI ------------------------------------------------------------------------------------


def test_cli_enum_as_uses_the_vault_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _box(tmp_path)
    fake = _recorder()
    monkeypatch.setattr(shell, "run", fake)
    monkeypatch.setattr(service_enum.shell, "run", fake)

    result = runner.invoke(
        app, ["enum", "smb", "-p", "box", "--as", "svc_account", "--workspace", str(tmp_path)]
    )

    assert result.exit_code == 0, result.output
    assert "-u 'svc_account' -p 'Ticketmaster1968'" in " ".join(fake.seen)  # type: ignore[attr-defined]


def test_cli_enum_as_accepts_user_at_domain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _box(tmp_path)
    fake = _recorder()
    monkeypatch.setattr(shell, "run", fake)
    monkeypatch.setattr(service_enum.shell, "run", fake)

    result = runner.invoke(
        app,
        [
            "enum",
            "smb",
            "-p",
            "box",
            "--as",
            "svc_account@active.htb",
            "--workspace",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "svc_account" in " ".join(fake.seen)  # type: ignore[attr-defined]


def test_cli_enum_as_an_unknown_user_lists_what_is_available(tmp_path: Path) -> None:
    _box(tmp_path)
    result = runner.invoke(
        app, ["enum", "smb", "-p", "box", "--as", "nobody", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "no vault credential for 'nobody'" in result.output
    assert "svc_account" in result.output  # says what you COULD use


def test_cli_enum_as_never_takes_a_secret_from_the_command_line(tmp_path: Path) -> None:
    # a password on the command line lands in shell history and in `ps` — the flag names a vault
    # entry, it does not accept a secret
    _box(tmp_path, with_cred=False)
    result = runner.invoke(
        app,
        ["enum", "smb", "-p", "box", "--as", "admin:Password1", "--workspace", str(tmp_path)],
    )
    assert result.exit_code == 2
    assert "no vault credential" in result.output


def test_cli_enum_as_is_refused_where_it_would_do_nothing(tmp_path: Path) -> None:
    _box(tmp_path)
    result = runner.invoke(
        app, ["enum", "http", "-p", "box", "--as", "svc_account", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "--as is not supported" in result.output


# --- the read-only single-shape services (winrm / mssql / rdp / mysql / postgresql) ---------------


def test_only_services_with_an_authenticated_pass_expose_one() -> None:
    from oscprecon.gui.simple_recon import SIMPLE_SPECS

    wired = {k for k, s in SIMPLE_SPECS.items() if s.auth_steps_fn is not None}
    assert wired == {"winrm", "mssql", "rdp", "mysql", "postgresql"}
    # a service with nothing to offer authenticated must not grow a control that does nothing
    assert SIMPLE_SPECS["ntp"].auth_steps_fn is None


@pytest.mark.parametrize("service", ["winrm", "mssql", "rdp", "mysql", "postgresql"])
def test_every_authenticated_step_clears_the_recon_policy(service: str) -> None:
    import shlex

    from oscprecon.gui.simple_recon import SIMPLE_SPECS

    build = SIMPLE_SPECS[service].auth_steps_fn
    assert build is not None
    auth = ReconAuth(username="svc", secret="P@ss w0rd", domain="corp.htb", kind="cred")
    for command, tool in build(Target(ip="10.10.10.5"), 0, auth):
        assert shell.policy_violation(shlex.split(command.shell_line)) is None, command.shell_line
        assert tool  # every authenticated step is parsed, not just streamed
        assert "as-svc" in command.output_file


def test_the_authenticated_pass_adds_to_the_fingerprint_it_does_not_replace_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # unlike SMB (where a credential replaces the anonymous phases), these services have no
    # anonymous phase to duplicate — the banner is still worth having
    from oscprecon.gui.workers.simple import SimpleReconWorker

    profile = _box(tmp_path)
    worker = SimpleReconWorker(
        profile, "winrm", 5985, ReconAuth.from_credential(profile.credentials()[0])
    )
    lines = [c.shell_line for c, _t in worker._steps(profile.target)]
    assert any("curl" in line for line in lines)  # the unauthenticated endpoint check survives
    assert any("-u 'svc_account'" in line for line in lines)


def test_an_anonymous_selection_runs_the_plain_pass(tmp_path: Path) -> None:
    from oscprecon.gui.workers.simple import SimpleReconWorker

    profile = _box(tmp_path)
    worker = SimpleReconWorker(profile, "winrm", 5985, ReconAuth.null())
    lines = [c.shell_line for c, _t in worker._steps(profile.target)]
    assert not any("svc_account" in line for line in lines)


def test_netexec_login_verdicts_are_parsed_into_findings() -> None:
    from oscprecon.modules.winrm import parse_winrm_tool

    pwned = parse_winrm_tool(
        "winrm-login",
        "WINRM       10.10.10.5      5985   DC01             "
        "[+] corp.local\\svc:Passw0rd (Pwn3d!)\n",
    )
    assert [(f.kind, f.value) for f in pwned] == [("auth", "corp.local\\svc")]
    assert "Pwn3d" in pwned[0].detail  # a WinRM shell is the most useful thing recon can say

    denied = parse_winrm_tool(
        "winrm-login",
        "WINRM       10.10.10.5      5985   DC01             "
        "[-] corp.local\\svc:Passw0rd (STATUS_LOGON_FAILURE)\n",
    )
    assert [(f.kind, f.detail) for f in denied] == [("auth-denied", "STATUS_LOGON_FAILURE")]


def test_cli_enum_as_works_for_a_simple_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _box(tmp_path)
    seen: list[str] = []

    def fake_run(shell_line: str, output_file: Path, **_kw: Any) -> Any:
        seen.append(shell_line)
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("", encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    monkeypatch.setattr(shell, "run", fake_run)

    result = runner.invoke(
        app, ["enum", "winrm", "-p", "box", "--as", "svc_account", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert any("netexec winrm" in line and "svc_account" in line for line in seen)


def test_the_wired_service_list_is_honest(tmp_path: Path) -> None:
    # ssh recon is key/algorithm enumeration and dns recon is protocol queries — neither has an
    # authenticated pass, so --as must be refused there, and the message must not name them either
    _box(tmp_path)
    for service in ("ssh", "dns", "ntp", "http"):
        result = runner.invoke(
            app, ["enum", service, "-p", "box", "--as", "svc_account", "--workspace", str(tmp_path)]
        )
        assert result.exit_code == 2, service
        assert "--as is not supported" in result.output
        assert "ssh" not in result.output.partition("wired for:")[2]
        assert "dns" not in result.output.partition("wired for:")[2]


def test_as_guest_never_becomes_a_default_credential_guess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `--as guest` against mysql/winrm/… would build `-u guest -p ''` — a GUESS at a well-known
    # account, which is §11 Tier 2 and never runs automatically. Only a held credential qualifies.
    _box(tmp_path)
    seen: list[str] = []

    def fake_run(shell_line: str, output_file: Path, **_kw: Any) -> Any:
        seen.append(shell_line)
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("", encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    monkeypatch.setattr(shell, "run", fake_run)

    result = runner.invoke(
        app, ["enum", "winrm", "-p", "box", "--as", "guest", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert not any("guest" in line for line in seen)


def test_a_dead_anonymous_pass_points_at_the_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the most common wasted step: anonymous got nowhere while a working credential sat in the vault
    profile = _box(tmp_path)
    fake = _recorder()
    monkeypatch.setattr(shell, "run", fake)
    monkeypatch.setattr(service_enum.shell, "run", fake)

    result = service_enum.SmbEnum(profile, "full").run()

    hint = [line for line in result.summary if "re-run authenticated" in line]
    assert hint and "svc_account" in hint[0]


def test_no_such_hint_when_the_run_was_already_authenticated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _box(tmp_path)
    fake = _recorder()
    monkeypatch.setattr(shell, "run", fake)
    monkeypatch.setattr(service_enum.shell, "run", fake)

    auth = ReconAuth.from_credential(profile.credentials()[0])
    result = service_enum.SmbEnum(profile, "full", auth=auth).run()

    assert not [line for line in result.summary if "re-run authenticated" in line]


def test_no_such_hint_when_the_vault_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _box(tmp_path, with_cred=False)
    fake = _recorder()
    monkeypatch.setattr(shell, "run", fake)
    monkeypatch.setattr(service_enum.shell, "run", fake)

    result = service_enum.SmbEnum(profile, "full").run()

    assert not [line for line in result.summary if "re-run authenticated" in line]
