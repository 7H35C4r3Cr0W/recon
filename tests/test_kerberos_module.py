import shlex
from pathlib import Path

import oscprecon.modules.kerberos as kmod
from oscprecon import shell
from oscprecon.manual_commands import expand, load_manual_commands
from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.kerberos import KerberosModule

_MANUAL = Path(kmod.__file__).parent / "manual_commands.yaml"
_FIX = Path(__file__).parent / "fixtures" / "kerberos"


def test_triggers_on_port_88() -> None:
    tgt = Target(ip="10.10.10.5")
    sr = ScanResults(target=tgt, services=[DiscoveredService(88, Proto.TCP, "kerberos-sec")])
    assert KerberosModule().triggers(sr)
    sr2 = ScanResults(target=tgt, services=[DiscoveredService(80, Proto.TCP, "http")])
    assert not KerberosModule().triggers(sr2)


def test_tier1_is_credential_free_version_scan() -> None:
    cmds = KerberosModule().commands(Target(ip="10.10.10.5"), [])
    assert len(cmds) == 1
    assert cmds[0].shell_line == "nmap -sV -p 88 10.10.10.5"
    assert cmds[0].output_file == "kerberos/nmap-sv.txt"


def test_parse_nmap_produces_findings_and_dc_suggestion() -> None:
    module = KerberosModule()
    findings = module.parse({"nmap-kerberos": (_FIX / "nmap-sv.txt").read_text(encoding="utf-8")})
    kinds = {f.fields["kind"] for f in findings}
    assert {"service", "server-time"} <= kinds
    assert any("Domain Controller" in tip for tip in module.suggest(findings))


def test_manual_commands_are_enum_only_and_policy_clean() -> None:
    cmds = load_manual_commands(_MANUAL)
    assert len(cmds) >= 5
    for command in cmds:
        filled = expand(
            command.command, target="10.10.10.5", domain="htb.local", user="u", password="p"
        )
        assert shell.policy_violation(shlex.split(filled)) is None, filled
        low = filled.lower()
        # enumeration only: no list-driven user brute, no ticket dump, no cracking tools
        for banned in ("-usersfile", "-request", "hashcat", " john ", "--passwords", "rockyou"):
            assert banned not in low, f"{banned!r} in {filled}"


def test_asrep_manual_targets_a_single_user_not_a_list() -> None:
    # the established stance: AS-REP checks ONE known user (edit USER), never a username list
    cmds = load_manual_commands(_MANUAL)
    asrep = [c for c in cmds if "GetNPUsers" in c.command]
    assert asrep and all("-usersfile" not in c.command for c in asrep)
    assert any("USER" in c.command for c in asrep)  # single-user placeholder present
