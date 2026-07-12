from pathlib import Path

from oscprecon import findings as findings_mod
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.reporter import Reporter, _finding_line


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


def test_report_links_hacktricks_per_service(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    prof.set_services(
        [DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at="")]
    )
    report = Reporter(prof).render()
    assert "**HackTricks:**" in report
    assert "book.hacktricks.wiki" in report  # a real reference URL was matched for SMB
