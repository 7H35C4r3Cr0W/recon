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


def test_report_shows_product_version_and_script_detail(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    profile.set_services(NmapModule().discovered_services({"v.txt": VERSIONED}))
    profile.save()
    md = Reporter(profile).render()
    assert "OpenSSH" in md and "1.18.0" in md  # product/version in the report
    assert "ssh-hostkey" in md  # the NSE detail block is surfaced
    assert "```text" in md  # rendered as a fenced code block
