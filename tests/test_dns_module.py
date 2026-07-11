import shlex

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.dns import DnsModule, normalize_domain


def _target() -> Target:
    return Target(ip="10.10.10.5", hostname="example.htb")


def test_triggers() -> None:
    module = DnsModule()
    dns = ScanResults(target=_target(), services=[DiscoveredService(53, Proto.UDP, "domain")])
    assert module.triggers(dns) is True
    tcp = ScanResults(target=_target(), services=[DiscoveredService(53, Proto.TCP, "domain")])
    assert module.triggers(tcp) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_recon_steps_without_domain() -> None:
    steps = DnsModule().recon_steps(_target())
    tools = [s.tool for s in steps]
    assert tools == ["dig-version", "nmap-dns"]  # no AXFR / dnsrecon without a zone


def test_recon_steps_with_domain() -> None:
    steps = DnsModule().recon_steps(_target(), "example.htb")
    tools = [s.tool for s in steps]
    assert tools == ["dig-version", "nmap-dns", "dig-axfr", "dnsrecon"]
    axfr = next(s for s in steps if s.tool == "dig-axfr")
    assert axfr.command.shell_line == "dig @10.10.10.5 example.htb AXFR"
    dnsrecon = next(s for s in steps if s.tool == "dnsrecon")
    assert dnsrecon.command.shell_line == "dnsrecon -n 10.10.10.5 -d example.htb -t std"


def test_hostile_domain_is_rejected_not_injected() -> None:
    # a domain that could smuggle a flag / second host is dropped, so no AXFR step is built
    assert normalize_domain("-x http://evil") is None
    assert normalize_domain("a b; rm -rf /") is None
    assert normalize_domain("") is None
    steps = DnsModule().recon_steps(_target(), "-x evil")
    assert [s.tool for s in steps] == ["dig-version", "nmap-dns"]
    # every built command stays a clean argv
    for step in DnsModule().recon_steps(_target(), "example.htb"):
        assert len(shlex.split(step.command.shell_line)) >= 3


def test_no_brute_scripts_in_commands() -> None:
    joined = " ".join(
        s.command.shell_line for s in DnsModule().recon_steps(_target(), "example.htb")
    )
    assert "brute" not in joined  # subdomain brute (dns-brute / -t brt) belongs to vhost
    assert "dnsenum" not in joined


def test_non_default_port() -> None:
    step = next(s for s in DnsModule().recon_steps(_target(), port=5353) if s.tool == "nmap-dns")
    assert "-p 5353 10.10.10.5" in step.command.shell_line


def test_parse_and_suggest() -> None:
    module = DnsModule()
    findings = module.parse(
        {
            "dig-axfr": "admin.example.htb. 604800 IN A 10.10.10.10\n",
            "nmap-dns": "|_dns-recursion: Recursion appears to be enabled\n",
        }
    )
    kinds = {f.fields["kind"] for f in findings}
    assert {"record", "zone-transfer", "recursion"} <= kinds
    joined = " ".join(module.suggest(findings)).lower()
    assert "zone transfer succeeded" in joined
    assert "recursion enabled" in joined


def test_suggest_quiet_when_locked_down() -> None:
    module = DnsModule()
    findings = module.parse({"dig-axfr": "; Transfer failed.\n"})
    joined = " ".join(module.suggest(findings)).lower()
    assert "zone transfer succeeded" not in joined
