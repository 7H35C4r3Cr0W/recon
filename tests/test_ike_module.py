import shlex
from pathlib import Path

import yaml

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.ike import IkeModule

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "ike" / "manual_commands.yaml"
)


def _target() -> Target:
    return Target(ip="10.10.10.180", hostname="vpn.htb")


def test_triggers() -> None:
    module = IkeModule()
    svc = ScanResults(target=_target(), services=[DiscoveredService(500, Proto.UDP, "isakmp")])
    assert module.triggers(svc) is True
    by_port = ScanResults(target=_target(), services=[DiscoveredService(500, Proto.UDP, "")])
    assert module.triggers(by_port) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_recon_step_commands() -> None:
    module = IkeModule()
    steps = module.recon_steps(_target())
    assert [s.tool for s in steps] == ["ike-scan", "ike-scan-aggressive"]
    assert steps[0].command.shell_line == "ike-scan -M 10.10.10.180"
    assert steps[1].command.shell_line == "ike-scan -M -A 10.10.10.180"
    for step in steps:
        assert shlex.split(step.command.shell_line)[0] == "ike-scan"
        assert "-P" not in shlex.split(step.command.shell_line)  # no PSK-hash capture for cracking
    assert len(module.commands(_target(), [])) == 2


def test_parse_and_suggest_aggressive() -> None:
    module = IkeModule()
    findings = module.parse(
        {"ike-scan-aggressive": "10.10.10.180\tAggressive Mode Handshake returned SA=(Enc=3DES)\n"}
    )
    joined = " ".join(module.suggest(findings)).lower()
    assert "aggressive mode" in joined
    assert "out of scope" in joined  # never suggests offline PSK cracking


def test_suggest_main_only_and_empty() -> None:
    module = IkeModule()
    main = module.parse({"ike-scan": "10.10.10.180\tMain Mode Handshake returned SA=(Enc=3DES)\n"})
    joined = " ".join(module.suggest(main)).lower()
    assert "vpn present" in joined and "aggressive mode is enabled" not in joined
    assert module.suggest(module.parse({"ike-scan": "0 returned handshake\n"})) == []


def test_manual_commands_are_recon_only() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        assert shlex.split(command)[0] in {"ike-scan", "nmap"}
        # no PSK-hash capture / cracking flags
        assert "-P" not in shlex.split(command) and "--pskcrack" not in command
        assert "--passwords" not in command


def test_suggest_ipsec_tunnel_firewall_bypass() -> None:
    # HTB Conceal: TCP is all filtered but IKE answers → suggest establishing a transport-mode
    # tunnel, with the ipsec.conf cipher line derived from the discovered transform.
    module = IkeModule()
    raw = (
        "10.10.10.116  Main Mode Handshake returned HDR=(CKY-R=ee3) "
        "SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds "
        "LifeDuration(4)=0x00007080)"
    )
    tips = module.suggest(module.parse({"ike-scan": raw}))
    tunnel = [t for t in tips if "transport-mode tunnel" in t]
    assert tunnel, tips
    # the cipher line is derived from ike-scan's transform (Enc/Hash/Group -> strongswan syntax)
    assert "ike=3des-sha1-modp1024" in tunnel[0]
    assert "esp=3des-sha1" in tunnel[0]


def test_strongswan_lines_maps_common_transforms() -> None:
    from oscprecon.modules.ike import _strongswan_lines

    assert _strongswan_lines("Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK") == (
        "3des-sha1-modp1024",
        "3des-sha1",
    )
    # real ike-scan AES: the key length is a SEPARATE KeyLength attribute, not Enc=AES256
    assert _strongswan_lines("Enc=AES KeyLength=256 Hash=SHA256 Group=14 Auth=PSK") == (
        "aes256-sha256-modp2048",
        "aes256-sha256",
    )
    # a bare Enc=AES (no KeyLength) stays aes (strongswan reads it as aes128) — don't guess a length
    assert _strongswan_lines("Enc=AES Hash=SHA1 Group=2 Auth=PSK") == (
        "aes-sha1-modp1024",
        "aes-sha1",
    )


def test_strongswan_lines_uses_authoritative_dh_group_name() -> None:
    from oscprecon.modules.ike import _strongswan_lines

    # DH keyword encodes the modulus SIZE, not the IANA number: 15->modp3072, 19->ecp256
    assert _strongswan_lines("Enc=3DES Hash=SHA1 Group=15:modp3072 Auth=PSK")[0] == (
        "3des-sha1-modp3072"
    )
    assert _strongswan_lines("Enc=3DES Hash=SHA1 Group=15 Auth=PSK")[0] == "3des-sha1-modp3072"
    assert _strongswan_lines("Enc=AES KeyLength=128 Hash=SHA256 Group=19:ecp256 Auth=PSK")[0] == (
        "aes128-sha256-ecp256"
    )
    # an unmapped group is DROPPED, never emitted as an invalid modp<number> keyword
    assert _strongswan_lines("Enc=3DES Hash=SHA1 Group=99 Auth=PSK") == ("3des-sha1", "3des-sha1")
