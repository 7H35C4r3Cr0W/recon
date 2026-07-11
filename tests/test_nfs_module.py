import shlex
from pathlib import Path

import yaml

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.nfs import NfsModule, anon_credential

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "nfs" / "manual_commands.yaml"
)


def _target() -> Target:
    return Target(ip="10.10.10.180", hostname="nfs.htb")


def test_triggers() -> None:
    module = NfsModule()
    for svc_name in ("nfs", "nfs_acl"):
        svc = ScanResults(target=_target(), services=[DiscoveredService(2049, Proto.TCP, svc_name)])
        assert module.triggers(svc) is True
    by_port = ScanResults(target=_target(), services=[DiscoveredService(2049, Proto.TCP, "")])
    assert module.triggers(by_port) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_recon_step_commands() -> None:
    module = NfsModule()
    steps = module.recon_steps(_target())
    assert [s.tool for s in steps] == ["showmount", "nmap-nfs"]
    assert steps[0].command.shell_line == "showmount -e 10.10.10.180"
    assert steps[1].command.shell_line == (
        "nmap -sV --script nfs-showmount,nfs-ls,nfs-statfs -p 2049 10.10.10.180"
    )
    for step in steps:
        assert "brute" not in step.command.shell_line
        assert shlex.split(step.command.shell_line)[0] in {"showmount", "nmap"}
    assert len(module.commands(_target(), [])) == 2


def test_non_default_port() -> None:
    step = NfsModule().recon_steps(_target(), port=2050)[1]
    assert "-p 2050 10.10.10.180" in step.command.shell_line


def test_parse_and_suggest() -> None:
    module = NfsModule()
    findings = module.parse(
        {
            "nmap-nfs": "2049/tcp open nfs_acl 3\n"
            "| nfs-showmount:\n"
            "|_  /opt/backups *\n"
            "| nfs-ls: Volume /opt/backups\n"
            "|   access: Read Lookup Modify Extend Delete NoExecute\n"
            "|_  rw-------   1000 1000 1675 2026-01-10T22:13:37 id_rsa\n"
        }
    )
    kinds = {f.fields["kind"] for f in findings}
    assert {"export", "world-readable", "access", "file"} <= kinds
    joined = " ".join(module.suggest(findings)).lower()
    assert "world-readable" in joined and "mount" in joined and "-o ro" in joined
    assert "writable" in joined
    assert "id_rsa" in joined


def test_suggest_quiet_when_locked_down() -> None:
    module = NfsModule()
    findings = module.parse({"showmount": "Export list for 10.10.10.180:\n/home 10.11.1.0/24\n"})
    joined = " ".join(module.suggest(findings)).lower()
    assert "world-readable" not in joined  # restricted export only
    assert "writable" not in joined


def test_anon_credential() -> None:
    cred = anon_credential(_target())
    assert cred.source == "nfs-anon-enum"
    assert cred.username == "anonymous"
    assert cred.secret == ""


def test_manual_mounts_are_read_only() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        if "mount -t nfs" in command:
            # every real NFS mount we suggest must be read-only (-o ro,...)
            opts = command.split("-o", 1)[1].split()[0]
            assert "ro" in opts.split(",")
        # no credential brute / list flags anywhere in the NFS follow-ups
        assert "--passwords" not in command and "--continue-on-success" not in command
