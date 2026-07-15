from pathlib import Path

from oscprecon import pivot
from oscprecon.models import DiscoveredHost, DiscoveredService, Proto, Target, subnet_of
from oscprecon.profile import Profile

_NMAP = """Starting Nmap 7.94
Nmap scan report for 10.10.5.23
Host is up (0.0011s latency).
PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds  Windows Server 2019 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Nmap scan report for dc02.corp.local (10.10.5.40)
Host is up (0.0009s latency).
22/tcp   open  ssh           OpenSSH 8.2p1
Nmap scan report for 10.10.5.99
Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap scan report for 172.16.8.10
Host is up.
Nmap done: 4 IP addresses (3 hosts up) scanned
"""


def test_subnet_of() -> None:
    assert subnet_of("10.10.5.23") == "10.10.5.0/24"
    assert subnet_of("172.16.8.10") == "172.16.8.0/24"
    assert subnet_of("not-an-ip") == ""


def test_parse_nmap_hosts_multi_host_with_services() -> None:
    hosts = pivot.parse_nmap_hosts(_NMAP, pivot_source="10.10.10.5")
    by_ip = {h.ip: h for h in hosts}
    assert set(by_ip) == {"10.10.5.23", "10.10.5.40", "172.16.8.10"}  # .99 down -> dropped
    assert by_ip["10.10.5.40"].hostname == "dc02.corp.local"  # hostname (ip) form parsed
    assert by_ip["10.10.5.23"].subnet == "10.10.5.0/24"
    assert all(h.pivot_source == "10.10.10.5" for h in hosts)
    ports = sorted(s.port for s in by_ip["10.10.5.23"].services)
    assert ports == [445, 3389]
    assert by_ip["172.16.8.10"].services == []  # ping-sweep host, no services


def test_parse_nmap_hosts_rejects_injection_in_host_tokens() -> None:
    # ip/hostname reach command lines later — a shell-metachar or flag token must never survive.
    adv = (
        "Nmap scan report for $(id) (10.0.0.1)\n445/tcp open smb\n"
        "Nmap scan report for -oG/tmp/x (10.0.0.2)\n80/tcp open http\n"
        "Nmap scan report for --flag-only\n22/tcp open ssh\n"  # no valid ip -> whole host dropped
        "Nmap scan report for 10.0.0.5\n23/tcp open telnet\n"
    )
    hosts = pivot.parse_nmap_hosts(adv)
    assert [h.ip for h in hosts] == ["10.0.0.1", "10.0.0.2", "10.0.0.5"]  # --flag-only skipped
    assert all(h.hostname == "" for h in hosts)  # the $(id) / -oG hostnames were stripped
    for h in hosts:  # every surviving token is a clean, validate_host-approved value
        assert " " not in h.ip and not h.ip.startswith("-")


def test_nmap_host_stream_emits_hosts_incrementally() -> None:
    stream = pivot.NmapHostStream(pivot_source="10.129.33.39")
    emitted = []
    for line in _NMAP.splitlines():
        host = stream.feed_line(line)
        if host is not None:
            emitted.append(host)
    last = stream.finish()
    if last is not None:
        emitted.append(last)
    ips = [h.ip for h in emitted]
    assert ips == ["10.10.5.23", "10.10.5.40", "172.16.8.10"]  # .99 down never emitted
    first = next(h for h in emitted if h.ip == "10.10.5.23")
    assert sorted(s.port for s in first.services) == [445, 3389]  # its services arrived before emit
    assert all(h.pivot_source == "10.129.33.39" for h in emitted)


def test_nmap_host_stream_emits_current_host_at_eof_without_nmap_done() -> None:
    stream = pivot.NmapHostStream()
    out = []
    for line in "Nmap scan report for 10.0.0.7\n22/tcp open ssh\n".splitlines():
        host = stream.feed_line(line)
        if host is not None:
            out.append(host)
    assert out == []  # not completed until finish() (no next report / Nmap done line)
    last = stream.finish()
    assert last is not None and last.ip == "10.0.0.7"


def test_parse_host_lines_only_accepts_real_ips() -> None:
    text = "10.10.5.23\nHost is up\n10.10.5.40  # a comment\ngarbage\n10.10.5.23\n"
    hosts = pivot.parse_host_lines(text, pivot_source="10.0.0.1")
    assert [h.ip for h in hosts] == ["10.10.5.23", "10.10.5.40"]  # prose/dupes/junk rejected


def test_parse_pivot_input_dispatches_by_format() -> None:
    assert len(pivot.parse_pivot_input(_NMAP)) == 3  # nmap format
    assert len(pivot.parse_pivot_input("10.0.0.5\n10.0.0.6")) == 2  # bare list


def test_profile_add_hosts_roundtrip_and_upsert(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "ctf", Target(ip="10.10.10.5"))
    added = prof.add_hosts(
        [
            DiscoveredHost(ip="10.10.5.23", pivot_source="10.10.10.5"),
            DiscoveredHost(ip="10.10.10.5"),  # == entry target -> skipped
        ]
    )
    assert added == 1
    prof.save()
    reloaded = Profile.load(prof.directory)
    assert [h.ip for h in reloaded.discovered_hosts] == ["10.10.5.23"]
    assert reloaded.schema_version == 2
    # re-scan the same host with services -> upsert (no duplicate), services updated
    again = reloaded.add_hosts(
        [DiscoveredHost(ip="10.10.5.23", services=[DiscoveredService(445, Proto.TCP, "smb")])]
    )
    assert again == 0
    assert len(reloaded.discovered_hosts) == 1
    assert [s.port for s in reloaded.discovered_hosts[0].services] == [445]


def test_remove_host_and_subnet(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "ctf", Target(ip="10.129.33.39"))
    prof.add_hosts(
        [
            DiscoveredHost(ip="10.10.5.10", pivot_source="10.129.33.39"),
            DiscoveredHost(ip="10.10.5.23", pivot_source="10.129.33.39"),
            DiscoveredHost(ip="172.16.8.10", pivot_source="10.10.5.10"),
        ]
    )
    assert prof.remove_host("10.10.5.23") is True
    assert prof.remove_host("9.9.9.9") is False  # not present
    assert [h.ip for h in prof.discovered_hosts] == ["10.10.5.10", "172.16.8.10"]
    assert prof.remove_subnet("10.10.5.0/24") == 1  # removes the remaining 10.10.5.x host
    assert [h.ip for h in prof.discovered_hosts] == ["172.16.8.10"]
    prof.save()
    assert [h.ip for h in Profile.load(prof.directory).discovered_hosts] == ["172.16.8.10"]


def test_known_host_ips(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "ctf", Target(ip="10.10.10.5"))
    prof.add_hosts([DiscoveredHost(ip="10.10.5.23"), DiscoveredHost(ip="172.16.8.10")])
    assert prof.known_host_ips() == ["10.10.10.5", "10.10.5.23", "172.16.8.10"]


def test_v1_profile_loads_with_empty_hosts(tmp_path: Path) -> None:
    # an old v1 profile.json (no discovered_hosts key) must load unchanged
    prof = Profile.create(tmp_path, "old", Target(ip="10.10.10.9"))
    import json

    raw = json.loads(prof.profile_json_path.read_text())
    raw["schema_version"] = 1
    del raw["discovered_hosts"]
    prof.profile_json_path.write_text(json.dumps(raw))
    reloaded = Profile.load(prof.directory)
    assert reloaded.discovered_hosts == []
