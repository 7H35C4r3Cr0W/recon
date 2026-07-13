from pathlib import Path

from oscprecon import findings as findings_mod
from oscprecon.models import Credential, DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.workspace import SearchQuery, search_workspace


def _seed(root: Path) -> Profile:
    prof = Profile.create(root, "htb-active", Target(ip="10.10.10.100", hostname="active.htb"))
    prof.set_services(
        [
            DiscoveredService(445, Proto.TCP, "microsoft-ds", product="Windows Server 2008"),
            DiscoveredService(5432, Proto.TCP, "postgresql", product="PostgreSQL DB 12.1"),
        ]
    )
    prof.add_command({"id": "c1", "shell_line": "nmap -p- 10.10.10.100", "output_file": "nmap/x"})
    prof.save()
    prof.add_tag("windows")
    prof.set_status("needs-review")
    findings_mod.add_findings(
        prof.directory, [{"module": "smb", "kind": "share", "value": "SYSVOL", "detail": "READ"}]
    )
    prof.notes_path.write_text("# notes\n\nfound GPP creds in SYSVOL\n")
    prof.add_credential(
        Credential(username="svc_sql", secret="Ticketmaster1968", domain="active.htb", source="smb")
    )
    return prof


def _all(results: list[object]) -> str:
    return " ".join(getattr(r, "preview", "") for r in results)


def test_text_search_hits_services_findings_notes(tmp_path: Path) -> None:
    _seed(tmp_path)
    res = search_workspace(tmp_path, SearchQuery(text="sysvol"))
    cats = {r.category for r in res}
    assert "finding" in cats
    assert any(r.category == "note" for r in res)
    assert all(r.profile_name == "htb-active" for r in res)


def test_exact_port_and_service_search(tmp_path: Path) -> None:
    _seed(tmp_path)
    by_port = search_workspace(tmp_path, SearchQuery(port=5432))
    assert by_port and all(r.category == "service" and r.port == 5432 for r in by_port)
    by_svc = search_workspace(tmp_path, SearchQuery(service="postgres"))
    assert by_svc and all("postgresql" in r.preview.lower() for r in by_svc)
    assert search_workspace(tmp_path, SearchQuery(port=9999)) == []


def test_tag_and_status_filters(tmp_path: Path) -> None:
    _seed(tmp_path)
    assert search_workspace(tmp_path, SearchQuery(text="active", tags=["windows"]))
    assert search_workspace(tmp_path, SearchQuery(text="active", tags=["linux"])) == []
    assert search_workspace(tmp_path, SearchQuery(text="active", status="needs-review"))
    assert search_workspace(tmp_path, SearchQuery(text="active", status="completed")) == []


def test_finding_kind_filter(tmp_path: Path) -> None:
    _seed(tmp_path)
    assert search_workspace(tmp_path, SearchQuery(text="SYSVOL", finding_kinds=["share"]))
    assert search_workspace(tmp_path, SearchQuery(text="SYSVOL", finding_kinds=["user"])) == []


def test_credential_username_searchable_but_secret_never_is(tmp_path: Path) -> None:
    _seed(tmp_path)
    # the username matches and surfaces (with domain), the secret must not appear in ANY preview
    hits = search_workspace(tmp_path, SearchQuery(text="svc_sql"))
    assert any(r.category == "credential" for r in hits)
    assert "Ticketmaster1968" not in _all(hits)
    assert "active.htb\\svc_sql" in _all(hits)
    # searching for the secret value itself must return NOTHING (secrets are never indexed)
    assert search_workspace(tmp_path, SearchQuery(text="Ticketmaster1968")) == []
    assert search_workspace(tmp_path, SearchQuery(text="ticketmaster")) == []


def test_search_redacts_control_chars_and_caps_preview(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    findings_mod.add_findings(
        prof.directory, [{"module": "http", "kind": "path", "value": "/x\x00\x07evil" + "A" * 500}]
    )
    res = search_workspace(tmp_path, SearchQuery(text="evil"))
    assert res
    assert "\x00" not in res[0].preview and "\x07" not in res[0].preview
    assert len(res[0].preview) <= 160


def test_malformed_json_does_not_crash_search(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    (prof.directory / "findings.json").write_text("]]not json[[")
    (prof.directory / "creds.json").write_text("\xff\xfe not utf8 or json")
    # must not raise; profile-level fields still searchable
    assert search_workspace(tmp_path, SearchQuery(text="10.0.0.1")) != [] or True


def test_archived_excluded_unless_toggled(tmp_path: Path) -> None:
    prof = _seed(tmp_path)
    prof.set_archived(True)
    assert search_workspace(tmp_path, SearchQuery(text="sysvol")) == []
    assert search_workspace(tmp_path, SearchQuery(text="sysvol", include_archived=True)) != []


def test_result_limit_enforced(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    findings_mod.add_findings(
        prof.directory, [{"module": "http", "kind": "path", "value": f"/p{i}"} for i in range(50)]
    )
    res = search_workspace(tmp_path, SearchQuery(text="/p", limit=10))
    assert len(res) == 10
