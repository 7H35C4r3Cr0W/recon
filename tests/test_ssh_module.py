import shlex

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.ssh import SshModule


def _target() -> Target:
    return Target(ip="10.10.10.5", hostname="box.htb")


def test_triggers() -> None:
    module = SshModule()
    ssh = ScanResults(target=_target(), services=[DiscoveredService(22, Proto.TCP, "ssh")])
    assert module.triggers(ssh) is True
    alt = ScanResults(target=_target(), services=[DiscoveredService(2222, Proto.TCP, "ssh")])
    assert module.triggers(alt) is True  # matched by service name, not just port
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_recon_step_command() -> None:
    module = SshModule()
    step = module.recon_steps(_target())[0]
    assert step.command.shell_line == (
        "nmap -sV --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey -p 22 10.10.10.5"
    )
    assert step.tool == "nmap-ssh"
    assert step.command.output_file == "ssh/nmap-ssh.txt"
    # a single recon batch; the nmap line stays one clean argv (no brute script slips in)
    assert len(module.commands(_target(), [])) == 1
    assert "brute" not in step.command.shell_line
    assert shlex.split(step.command.shell_line)[0] == "nmap"


def test_non_default_port() -> None:
    step = SshModule().recon_steps(_target(), port=2222)[0]
    assert "-p 2222 10.10.10.5" in step.command.shell_line


def test_parse_and_suggest() -> None:
    module = SshModule()
    findings = module.parse(
        {
            "nmap-ssh": "22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu\n"
            "|   aes256-cbc\n"
            "|   Supported authentication methods:\n"
            "|     publickey\n"
            "|_    password\n"
        }
    )
    kinds = {f.fields["kind"] for f in findings}
    assert {"banner", "algo-weak", "auth"} <= kinds
    suggestions = module.suggest(findings)
    joined = " ".join(suggestions).lower()
    assert "password authentication enabled" in joined
    assert "weak ssh algorithms" in joined
    assert "exploit-db" in joined  # banner -> lookup hint (no CVE-specific advice)


def test_suggest_quiet_when_hardened() -> None:
    module = SshModule()
    findings = module.parse(
        {
            "nmap-ssh": "22/tcp open  ssh     OpenSSH 9.6p1\n"
            "|   Supported authentication methods:\n"
            "|_    publickey\n"
        }
    )
    joined = " ".join(module.suggest(findings)).lower()
    assert "password authentication enabled" not in joined
    assert "weak ssh algorithms" not in joined
