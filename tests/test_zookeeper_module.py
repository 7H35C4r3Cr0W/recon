from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.zookeeper import ZookeeperModule


def _scan(port: int, service: str) -> ScanResults:
    return ScanResults(Target(ip="10.0.0.1"), [DiscoveredService(port, Proto.TCP, service)])


def test_triggers_on_port_or_service_name() -> None:
    module = ZookeeperModule()
    assert module.triggers(_scan(2181, "unknown"))
    assert module.triggers(_scan(9999, "zookeeper"))
    assert not module.triggers(_scan(22, "ssh"))


def test_recon_step_is_popen_safe_nmap() -> None:
    command = ZookeeperModule().recon_steps(Target(ip="10.0.0.1"), 2181)[0].command
    assert command.shell_line == "nmap -sV -p 2181 10.0.0.1"
    # the AUTO path stays Popen-safe: no shell pipe, no raw nc (those are Tier-2 copy-only)
    assert "|" not in command.shell_line and "nc " not in command.shell_line


def test_parse_and_suggest() -> None:
    module = ZookeeperModule()
    findings = module.parse({"nmap-zookeeper": "2181/tcp open zookeeper Zookeeper 3.4.6\n"})
    assert any(f.fields["kind"] == "version" and f.fields["value"] == "3.4.6" for f in findings)
    assert module.suggest(findings)  # a next-step is offered once ZooKeeper answers
