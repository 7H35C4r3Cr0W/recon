from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.vhost import (
    VhostModule,
    VhostScanSettings,
    build_command,
    default_output,
    wildcard_probe_command,
)


def test_ffuf_vhost_command() -> None:
    settings = VhostScanSettings(
        tool="ffuf", target="10.10.10.5", domain="example.com", wordlist="/w.txt", filter_size=281
    )
    cmd = build_command(settings)
    assert cmd.startswith('ffuf -u http://10.10.10.5/ -H "Host: FUZZ.example.com" -w /w.txt')
    assert "-fs 281" in cmd


def test_tool_translations() -> None:
    base = {"target": "10.10.10.5", "domain": "example.com", "wordlist": "/w.txt"}
    gv = build_command(VhostScanSettings(tool="gobuster-vhost", **base))
    # hits the target IP directly (not the domain URL) so it works without /etc/hosts
    assert gv.startswith(
        "gobuster vhost -u http://10.10.10.5/ -w /w.txt --append-domain --domain example.com"
    )
    gd = build_command(VhostScanSettings(tool="gobuster-dns", **base))
    assert gd.startswith("gobuster dns --domain example.com -w /w.txt")  # --domain, not -d
    gd_resolver = build_command(
        VhostScanSettings(tool="gobuster-dns", dns_server="1.1.1.1", **base)
    )
    assert "--resolver 1.1.1.1" in gd_resolver  # --resolver, not -r
    dr = build_command(VhostScanSettings(tool="dnsrecon", **base))
    assert dr == "dnsrecon -d example.com -t brt -D /w.txt"
    wf = build_command(VhostScanSettings(tool="wfuzz", **base))
    assert 'wfuzz -c -w /w.txt -H "Host: FUZZ.example.com"' in wf


def test_wildcard_probe() -> None:
    cmd = wildcard_probe_command("http", "10.10.10.5", "example.com")
    assert "%{size_download}" in cmd
    assert "Host: zzq-nonexistent-wildcard-probe.example.com" in cmd


def test_triggers() -> None:
    module = VhostModule()
    with_http_domain = ScanResults(
        target=Target(ip="10.10.10.5", hostname="example.com"),
        services=[DiscoveredService(80, Proto.TCP, "http")],
    )
    assert module.triggers(with_http_domain) is True
    no_domain = ScanResults(
        target=Target(ip="10.10.10.5"), services=[DiscoveredService(80, Proto.TCP, "http")]
    )
    assert module.triggers(no_domain) is False
    no_http = ScanResults(
        target=Target(ip="10.10.10.5", hostname="example.com"),
        services=[DiscoveredService(22, Proto.TCP, "ssh")],
    )
    assert module.triggers(no_http) is False


def test_commands_and_default_output() -> None:
    module = VhostModule()
    cmds = module.commands(Target(ip="10.10.10.5", hostname="example.com"), [])
    assert len(cmds) == 1
    assert "Host: FUZZ.example.com" in cmds[0].shell_line
    assert cmds[0].output_file == "vhost/ffuf.json"
    assert module.commands(Target(ip="10.10.10.5"), []) == []  # no domain -> no auto command
    # the wordlist is part of the path so two sweeps with different lists can run at once
    assert default_output("ffuf", "/w.txt") == "vhost/ffuf-w.json"
    assert default_output("ffuf", "/other.txt") != default_output("ffuf", "/w.txt")
    assert default_output("dnsrecon", "/w.txt") == "vhost/dnsrecon-w.txt"


def test_parse_dispatch() -> None:
    module = VhostModule()
    findings = module.parse(
        {"ffuf:example.com": '{"results":[{"input":{"FUZZ":"admin"},"status":200,"length":10}]}'}
    )
    assert findings
    assert findings[0].title == "admin.example.com"
    assert findings[0].fields["vhost"] == "admin.example.com"
