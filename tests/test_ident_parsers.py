from oscprecon.models import Target
from oscprecon.modules.ident import IdentModule, parse_ident_info, parse_ident_tool

_NMAP = """22/tcp  open ssh
| auth-owners:
|_  root
80/tcp  open http
| auth-owners:
|_  www-data
113/tcp open ident oidentd
"""


def test_parses_service_owners() -> None:
    users = {f.value for f in parse_ident_info(_NMAP) if f.kind == "user"}
    assert users == {"root", "www-data"}


def test_parses_ident_banner() -> None:
    values = {f.kind: f.value for f in parse_ident_info(_NMAP)}
    assert "oidentd" in values["version"]


def test_owners_deduped() -> None:
    text = "| auth-owners:\n|_  root\n| auth-owners:\n|_  root\n"
    users = [f for f in parse_ident_info(text) if f.kind == "user"]
    assert len(users) == 1


def test_recon_step_scans_common_ports_with_auth_owners() -> None:
    step = IdentModule().recon_steps(Target(ip="10.10.10.31"))[0]
    assert "auth-owners" in step.command.shell_line
    assert "113,21,22" in step.command.shell_line  # ident port + common port set


def test_missing_sentinel_skipped() -> None:
    assert parse_ident_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_ident_tool("nope", _NMAP) == []
    assert parse_ident_tool("ident-info", _NMAP)
