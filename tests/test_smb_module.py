from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.smb import (
    SmbModule,
    anon_credential,
    backslash_unc,
    escaped_unc,
    forward_unc,
    to_backslash_command,
    to_escaped_command,
)
from oscprecon.recon_auth import ReconAuth


def _target() -> Target:
    return Target(ip="10.10.10.5", hostname="active.htb")


def test_triggers() -> None:
    module = SmbModule()
    smb = ScanResults(
        target=_target(), services=[DiscoveredService(445, Proto.TCP, "microsoft-ds")]
    )
    assert module.triggers(smb) is True
    netbios = ScanResults(
        target=_target(), services=[DiscoveredService(139, Proto.TCP, "netbios-ssn")]
    )
    assert module.triggers(netbios) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_banner_null_guest_steps() -> None:
    module = SmbModule()
    target = _target()
    banner = [s.command.shell_line for s in module.banner_steps(target)]
    assert any("smb-os-discovery" in c for c in banner)
    assert "netexec smb 10.10.10.5" in banner
    null = [s.command.shell_line for s in module.null_session_steps(target)]
    assert "smbclient -L //10.10.10.5/ -N" in null
    assert "netexec smb 10.10.10.5 -u '' -p '' --shares" in null
    assert "enum4linux-ng -A 10.10.10.5" in null
    guest = [s.command.shell_line for s in module.guest_steps(target)]
    assert "netexec smb 10.10.10.5 -u 'guest' -p '' --shares" in guest


def test_followup_steps_never_use_lists() -> None:
    lines = [s.command.shell_line for s in SmbModule().followup_steps(_target(), ReconAuth.null())]
    assert "netexec smb 10.10.10.5 -u '' -p '' --users" in lines
    assert any("--rid-brute 10000" in c for c in lines)
    assert any("rpcclient -U '' -N 10.10.10.5" in c for c in lines)
    joined = " ".join(lines)
    assert "--passwords" not in joined
    assert ".txt" not in joined  # never a wordlist file (Tier-3)


def test_share_steps() -> None:
    module = SmbModule()
    target = _target()
    null_share = module.share_steps(target, "Replication", ReconAuth.null())[0].command.shell_line
    assert null_share == "smbclient //10.10.10.5/Replication -N -c 'ls'"
    guest_share = module.share_steps(target, "Users", ReconAuth.guest())[0].command.shell_line
    assert "-U 'guest%'" in guest_share


def test_unc_helpers() -> None:
    assert forward_unc("10.10.10.5", "IT") == "//10.10.10.5/IT"
    assert backslash_unc("10.10.10.5", "IT") == r"\\10.10.10.5\IT"
    assert escaped_unc("10.10.10.5", "IT") == r"\\\\10.10.10.5\\IT"


def test_unc_command_transforms() -> None:
    cmd = "smbclient //10.10.10.5/Replication -N -c 'ls'"
    assert to_backslash_command(cmd) == r"smbclient \\10.10.10.5\Replication -N -c 'ls'"
    assert to_escaped_command(cmd) == r"smbclient \\\\10.10.10.5\\Replication -N -c 'ls'"
    # a command without a UNC path is left untouched
    assert to_backslash_command("netexec smb 10.10.10.5 --shares") == (
        "netexec smb 10.10.10.5 --shares"
    )


def test_anon_credential() -> None:
    null = anon_credential(_target(), "null")
    assert null.username == "anonymous"
    assert null.secret == ""
    assert null.source == "smb-anon-enum"
    assert null.domain == "active.htb"
    assert anon_credential(_target(), "guest").username == "guest"


def test_commands_batch_and_parse() -> None:
    module = SmbModule()
    assert len(module.commands(_target(), [])) == 7  # 2 banner + 3 null + 2 guest
    findings = module.parse(
        {"netexec-shares": "SMB 10.0.0.1 445 H [+] d\\:\nSMB 10.0.0.1 445 H (signing:False)"}
    )
    kinds = {f.fields["kind"] for f in findings}
    assert "auth" in kinds
    assert "signing" in kinds
    suggestion = module.suggest(findings)
    assert suggestion
    assert "signing disabled" in suggestion[0].lower()
