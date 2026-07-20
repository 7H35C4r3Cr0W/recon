from pathlib import Path

from oscprecon.models import Target
from oscprecon.modules.nmap import NmapModule
from oscprecon.profile import Profile
from oscprecon.reporter import Reporter

VERSIONED = """PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 aa:bb:cc:dd:ee:ff (RSA)
80/tcp  open  http         nginx 1.18.0
|_http-title: Welcome to nginx
445/tcp open  microsoft-ds Samba smbd 4.6.2
"""


def test_parser_captures_nse_script_output() -> None:
    by_port = {s.port: s for s in NmapModule().discovered_services({"v.txt": VERSIONED})}
    assert by_port[22].product == "OpenSSH"
    assert by_port[22].version == "8.4p1"
    assert "ssh-hostkey:" in by_port[22].nmap_scripts_output
    assert "3072 aa:bb:cc:dd:ee:ff (RSA)" in by_port[22].nmap_scripts_output
    assert "http-title: Welcome to nginx" in by_port[80].nmap_scripts_output
    assert by_port[445].nmap_scripts_output == ""  # no scripts under 445 -> empty, not garbage


def test_script_output_merges_in_from_the_versioned_scan() -> None:
    bare = "22/tcp open ssh\n"  # a discovery sweep has no product/version/scripts
    merged = {
        s.port: s for s in NmapModule().discovered_services({"bare.txt": bare, "v.txt": VERSIONED})
    }
    assert merged[22].product == "OpenSSH"  # filled from the versioned scan
    assert "ssh-hostkey:" in merged[22].nmap_scripts_output


AD_SAMPLE = """PORT      STATE SERVICE       VERSION
445/tcp   open  microsoft-ds  Windows Server 2019
| smb-os-discovery:
|   OS: Windows Server 2019
49667/tcp open  msrpc         Microsoft Windows RPC
Host script results:
| smb2-security-mode:
|_  Message signing enabled and required
| clock-skew: mean: 2h00m00s
"""


def test_host_script_results_not_glued_to_the_last_port() -> None:
    # nmap's host-level "Host script results:" block must not be mis-attributed to the last port row
    by_port = {s.port: s for s in NmapModule().discovered_services({"ad.txt": AD_SAMPLE})}
    assert "clock-skew" not in by_port[49667].nmap_scripts_output
    assert "smb2-security-mode" not in by_port[49667].nmap_scripts_output
    assert by_port[49667].nmap_scripts_output == ""  # ephemeral RPC port carries no host scripts
    assert "smb-os-discovery" in by_port[445].nmap_scripts_output  # per-port script stays put


def test_report_shows_product_version_and_script_detail(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    profile.set_services(NmapModule().discovered_services({"v.txt": VERSIONED}))
    profile.save()
    md = Reporter(profile).render()
    assert "OpenSSH" in md and "1.18.0" in md  # product/version in the report
    assert "ssh-hostkey" in md  # the NSE detail block is surfaced
    assert "```text" in md  # rendered as a fenced code block


def test_service_state_round_trips_through_save_load(tmp_path: Path) -> None:
    # the nmap port state (open vs open|filtered) must survive a save/load so the exploit-tab
    # presence filter can trust it. An older profile.json without the field loads as "open".
    udp = "PORT       STATE         SERVICE\n139/udp open|filtered netbios-ssn\n161/udp open snmp\n"
    profile = Profile.create(tmp_path, "st", Target(ip="10.10.10.5"))
    profile.set_services(NmapModule().discovered_services({"u.txt": udp}))
    profile.save()
    loaded = Profile.load(profile.directory).discovered_services
    reloaded = {(s.port, s.proto.value): s for s in loaded}
    assert reloaded[(139, "udp")].state == "open|filtered"
    assert reloaded[(161, "udp")].state == "open"
