import shlex

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.smtp import SmtpModule


def _target() -> Target:
    return Target(ip="10.10.10.5", hostname="example.htb")


def test_triggers() -> None:
    module = SmtpModule()
    for port in (25, 465, 587):
        svc = ScanResults(target=_target(), services=[DiscoveredService(port, Proto.TCP, "smtp")])
        assert module.triggers(svc) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_recon_step_command() -> None:
    module = SmtpModule()
    step = module.recon_steps(_target())[0]
    assert step.command.shell_line == (
        "nmap -sV --script smtp-commands,smtp-open-relay,smtp-ntlm-info -p 25 10.10.10.5"
    )
    assert step.tool == "nmap-smtp"
    assert "brute" not in step.command.shell_line
    assert shlex.split(step.command.shell_line)[0] == "nmap"
    assert len(module.commands(_target(), [])) == 1


def test_non_default_port() -> None:
    step = SmtpModule().recon_steps(_target(), port=587)[0]
    assert "-p 587 10.10.10.5" in step.command.shell_line


def test_parse_and_suggest() -> None:
    module = SmtpModule()
    findings = module.parse(
        {
            "nmap-smtp": "25/tcp open smtp Postfix\n"
            "| smtp-commands: mail Hello, VRFY, EXPN\n"
            "| smtp-open-relay: Server is an open relay (16/16 tests)\n"
            "|   DNS_Domain_Name: example.htb\n"
        }
    )
    kinds = {f.fields["kind"] for f in findings}
    assert {"banner", "verb", "open-relay", "ntlm"} <= kinds
    joined = " ".join(module.suggest(findings)).lower()
    assert "enabled" in joined and ("vrfy" in joined or "expn" in joined)
    assert "open relay" in joined
    assert "ntlm leak" in joined


def test_suggest_quiet_when_locked_down() -> None:
    module = SmtpModule()
    findings = module.parse(
        {
            "nmap-smtp": "25/tcp open smtp Postfix\n"
            "| smtp-commands: mail Hello, SIZE 100, STARTTLS\n"
            "|_smtp-open-relay: Server doesn't seem to be an open relay, all tests failed\n"
        }
    )
    joined = " ".join(module.suggest(findings)).lower()
    assert "enumerate valid users" not in joined  # no VRFY/EXPN
    assert "open relay" not in joined  # relay denied
