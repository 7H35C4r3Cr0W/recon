from pathlib import Path

from oscprecon import audit
from oscprecon import edb as edb_mod
from oscprecon import findings as findings_mod
from oscprecon.models import DiscoveredHost, DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import ExploitHit
from oscprecon.reporter import Reporter, _finding_line


def test_report_pivot_topology_section(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "ctf", Target(ip="10.129.33.39", hostname="ignition.htb"))
    prof.add_hosts(
        [
            DiscoveredHost(
                ip="10.10.5.10",
                hostname="dc01.corp.local",
                pivot_source="10.129.33.39",
                os_guess="Windows",
                services=[
                    DiscoveredService(445, Proto.TCP, "smb", product="Windows", version="10")
                ],
            ),
            DiscoveredHost(ip="172.16.8.10", pivot_source="10.10.5.10"),
        ]
    )
    report = Reporter(prof).render()
    assert "## Pivot topology" in report
    assert "### 10.10.5.0/24 — 1 host(s)" in report
    assert "### 172.16.8.0/24 — 1 host(s)" in report
    assert "**10.10.5.10** (dc01.corp.local) — Windows — via `10.129.33.39`" in report
    # the service bullet is on its own indented line (not glued to the host line)
    assert "\n  - 445/tcp smb — Windows 10" in report
    assert "**172.16.8.10** — via `10.10.5.10`" in report
    assert "_no services enumerated_" in report  # host with 0 services


def test_report_pivot_topology_empty(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "solo", Target(ip="10.0.0.1"))
    report = Reporter(prof).render()
    assert "## Pivot topology" in report
    assert "No pivoted hosts recorded" in report


def test_report_graph_annotations(tmp_path: Path) -> None:
    # a note dropped on a graph node (graph.json node_overrides) must appear in report.md — the
    # graph detail panel promises it does, so guard the wire-up.
    prof = Profile.create(tmp_path, "annot", Target(ip="10.10.10.9", hostname="active.htb"))
    prof.set_services([DiscoveredService(445, Proto.TCP, "microsoft-ds")])
    graph = prof.load_graph()
    graph["node_overrides"]["target"] = {
        "note": "SMB signing disabled — relay candidate",
        "status": "investigating",
    }
    graph["node_overrides"]["service-445-tcp"] = {"note": "anon share READ ok"}
    prof.save_graph(graph)
    report = Reporter(prof).render()
    assert "## Graph annotations" in report
    assert "SMB signing disabled — relay candidate" in report
    assert "investigating" in report
    assert "anon share READ ok" in report


def test_report_graph_annotations_empty(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "noannot", Target(ip="10.0.0.2"))
    report = Reporter(prof).render()
    assert "## Graph annotations" in report
    assert "No graph notes yet" in report


def test_finding_line_kind_value_detail_shape() -> None:
    line = _finding_line({"module": "smb", "kind": "share", "value": "IT", "detail": "READ"})
    assert line == "**share** — IT (READ)"


def test_finding_line_http_shape() -> None:
    line = _finding_line(
        {"module": "http", "port": 8080, "path": "/admin", "status": 301, "redirect_to": "/login"}
    )
    assert "[8080]" in line
    assert "`/admin`" in line
    assert "301" in line
    assert "/login" in line


def test_finding_line_note_only_shape() -> None:
    assert _finding_line({"module": "vhost", "note": "dev.corp.local"}) == "dev.corp.local"


def test_report_renders_edb_references(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    edb_mod.add_edb(
        prof.directory,
        service="22/tcp ssh",
        product="OpenSSH",
        version="7.2",
        hits=[
            ExploitHit(
                edb_id="40136",
                title="OpenSSH 7.2 - Username Enumeration",
                url="https://www.exploit-db.com/exploits/40136",
                path="linux/remote/40136.py",
            )
        ],
    )
    report = Reporter(prof).render()
    assert "## Exploit-DB references" in report
    assert "### 22/tcp ssh" in report
    assert "[EDB-40136](https://www.exploit-db.com/exploits/40136)" in report
    assert "Lookup only" in report  # the §14 callout is present
    assert "40136.py" not in report  # the local PoC path is never surfaced


def test_report_edb_empty_placeholder(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    report = Reporter(prof).render()
    assert "## Exploit-DB references" in report
    assert "No Exploit-DB matches recorded" in report


def test_report_renders_per_service_findings(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    findings_mod.add_findings(
        prof.directory,
        [
            {"module": "smb", "kind": "share", "value": "IT", "detail": "READ"},
            {"module": "smb", "kind": "auth", "value": "null session", "detail": "anon login"},
            {"module": "http", "port": 80, "path": "/robots.txt", "status": 200},
        ],
    )
    report = Reporter(prof).render()
    assert "## Per-service findings" in report
    assert "### smb" in report
    assert "#smb" in report  # Obsidian tag per module
    assert "**share** — IT (READ)" in report
    assert "**auth** — null session (anon login)" in report
    assert "### http" in report
    assert "/robots.txt" in report and "200" in report
    # section order §18: services -> findings -> suggestions
    assert report.index("## Discovered services") < report.index("## Per-service findings")
    assert report.index("## Per-service findings") < report.index("## Suggested next steps")


def test_report_findings_placeholder_when_empty(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    report = Reporter(prof).render()
    assert "_No service findings yet" in report


def test_report_renders_audit_trail(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    audit.record(prof.directory, "b", "run", details={"label": "smb full"})
    audit.record(prof.directory, "b", "credential-added", details={"username": "svc"})
    report = Reporter(prof).render()
    assert "## Audit trail" in report
    assert "run" in report and "smb full" in report
    assert "credential-added" in report
    assert report.index("## Command log") < report.index("## Audit trail")  # appendix last


def test_report_audit_placeholder_when_empty(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    report = Reporter(prof).render()
    assert "_No audit events recorded yet._" in report


def test_audit_summary_neutralizes_newlines(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    # a pasted multi-line value must not break the markdown table row / inject a heading
    audit.record(prof.directory, "b", "add-to-report", details={"command": "curl x\n# ROOTED"})
    report = Reporter(prof).render()
    trail = report[report.index("## Audit trail") :]
    assert "\n# ROOTED" not in trail  # no injected H1
    row = next(line for line in trail.splitlines() if "add-to-report" in line)
    assert "# ROOTED" in row  # the text survives, collapsed onto the single table row


def test_report_links_hacktricks_per_service(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    prof.set_services(
        [DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at="")]
    )
    report = Reporter(prof).render()
    assert "**HackTricks:**" in report
    assert "book.hacktricks.wiki" in report  # a real reference URL was matched for SMB
