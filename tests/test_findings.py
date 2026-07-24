from pathlib import Path

from oscprecon import findings


def test_add_and_dedup(tmp_path: Path) -> None:
    f1 = {"module": "http", "port": 80, "path": "/admin", "status": 301, "size": 154}
    f2 = {"module": "http", "port": 80, "path": "/login", "status": 200, "size": 842}
    findings.add_findings(tmp_path, [f1, f2])
    findings.add_findings(tmp_path, [f1])  # duplicate — same (module, port, path, status)
    loaded = findings.load_findings(tmp_path)
    assert len(loaded) == 2
    assert {f["path"] for f in loaded} == {"/admin", "/login"}


def test_distinct_status_is_a_new_finding(tmp_path: Path) -> None:
    findings.add_findings(tmp_path, [{"module": "http", "port": 80, "path": "/x", "status": 200}])
    findings.add_findings(tmp_path, [{"module": "http", "port": 80, "path": "/x", "status": 403}])
    assert len(findings.load_findings(tmp_path)) == 2


def test_distinct_note_same_path_status_both_kept(tmp_path: Path) -> None:
    # wpscan version vs users findings are both ('http',80,'/',0) — must not collapse
    findings.add_findings(
        tmp_path,
        [{"module": "http", "port": 80, "path": "/", "status": 0, "note": "WordPress 5.8"}],
    )
    findings.add_findings(
        tmp_path, [{"module": "http", "port": 80, "path": "/", "status": 0, "note": "users: admin"}]
    )
    assert len(findings.load_findings(tmp_path)) == 2


def test_load_missing_or_garbage(tmp_path: Path) -> None:
    assert findings.load_findings(tmp_path) == []
    (tmp_path / "findings.json").write_text("not json", encoding="utf-8")
    assert findings.load_findings(tmp_path) == []


# --- operator-entered findings (user request) ----------------------------------------------------
def test_manual_finding_round_trip(tmp_path: Path) -> None:
    saved = findings.add_manual_finding(
        tmp_path,
        {
            "kind": "vuln",
            "value": "SQLi in /search.php",
            "detail": "boolean-based",
            "severity": "exposure",
            "host": "10.10.10.5",
            "port": 80,
            "poc": "curl 'http://10.10.10.5/search.php?q=1'",
        },
    )
    assert saved["manual"] is True
    assert saved["id"] and saved["added_at"]
    assert saved["module"] == "manual"
    loaded = findings.load_findings(tmp_path)
    assert len(loaded) == 1
    assert loaded[0]["poc"].startswith("curl")


def test_manual_findings_are_never_deduped(tmp_path: Path) -> None:
    # two identical hand-written notes are two notes — dedup is for parser output only
    for _ in range(2):
        findings.add_manual_finding(tmp_path, {"kind": "note", "value": "check the PDF"})
    assert len(findings.load_findings(tmp_path)) == 2


def test_manual_finding_update_and_delete(tmp_path: Path) -> None:
    saved = findings.add_manual_finding(tmp_path, {"kind": "note", "value": "first"})
    fid = str(saved["id"])
    assert findings.update_manual_finding(tmp_path, fid, {"value": "second", "port": 8080})
    row = findings.load_findings(tmp_path)[0]
    assert row["value"] == "second" and row["port"] == 8080
    assert row["id"] == fid  # identity survives an edit
    assert findings.delete_manual_finding(tmp_path, fid)
    assert findings.load_findings(tmp_path) == []
    assert not findings.delete_manual_finding(tmp_path, fid)  # already gone


def test_parsed_findings_are_not_deletable_as_manual(tmp_path: Path) -> None:
    # tool output is the record of what the tools saw — the manual delete path must not touch it
    findings.add_findings(tmp_path, [{"module": "http", "id": "abc", "path": "/x"}])
    assert not findings.delete_manual_finding(tmp_path, "abc")
    assert not findings.update_manual_finding(tmp_path, "abc", {"value": "hax"})
    assert len(findings.load_findings(tmp_path)) == 1


def test_manual_findings_survive_a_later_parser_write(tmp_path: Path) -> None:
    findings.add_manual_finding(tmp_path, {"kind": "vuln", "value": "mine"})
    findings.add_findings(tmp_path, [{"module": "http", "path": "/admin", "status": 200}])
    rows = findings.load_findings(tmp_path)
    assert len(rows) == 2
    assert any(r.get("manual") for r in rows)
