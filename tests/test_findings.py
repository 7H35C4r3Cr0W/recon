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
