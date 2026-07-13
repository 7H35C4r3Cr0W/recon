from pathlib import Path
from typing import Any

from oscprecon.patterns import engine

FIX = Path(__file__).parent / "fixtures"


def test_load_patterns_parses_match_suggest_source() -> None:
    rules = engine.load_patterns(FIX / "patterns")
    assert len(rules) == 2
    first = rules[0]
    assert first.service == "smb"
    assert first.match["detail_contains"] == "signing: disabled"
    assert first.source == "tests/fixture-smb.md"
    # a {text, command} suggest item survives loading
    assert any(isinstance(s, dict) and "command" in s for s in first.suggest)


def test_provenance_gate_flags_missing_source() -> None:
    assert engine.check_provenance(FIX / "patterns") == []  # good fixture: all sourced
    errors = engine.check_provenance(FIX / "patterns_bad")
    assert errors and "missing a `# source:`" in errors[0]


def test_forbidden_gate_flags_exploit_content() -> None:
    assert engine.check_forbidden(FIX / "patterns") == []
    errors = engine.check_forbidden(FIX / "patterns_forbidden")
    assert errors and "cve-" in errors[0].lower()


def test_forbidden_gate_flags_spray_markers(tmp_path: Path) -> None:
    # the §2 spray markers (--continue-on-success, patator, crowbar) must trip the content gate
    d = tmp_path / "patterns"
    d.mkdir()
    (d / "x.yaml").write_text(
        "- match: {service: smb}\n"
        "  suggest:\n"
        '    - text: "spray the box"\n'
        '      command: "netexec smb {target} -u u.txt -p p.txt --continue-on-success"\n'
        "# source: tests/x.md\n",
        encoding="utf-8",
    )
    errors = engine.check_forbidden(d)
    assert errors and "continue-on-success" in errors[0].lower()


def test_suggest_for_matches_and_interpolates() -> None:
    findings: list[dict[str, Any]] = [
        {"module": "smb", "kind": "note", "value": "x", "detail": "message signing: disabled"},
        {"module": "smb", "kind": "share", "value": "SYSVOL", "detail": "readable"},
        {"module": "http", "kind": "path", "value": "/admin", "detail": ""},
    ]
    rules = engine.load_patterns(FIX / "patterns")
    suggestions = engine.suggest_for(
        findings, target="10.10.10.5", domain="active.htb", rules=rules
    )
    texts = [s.text for s in suggestions]
    assert any("relay candidate" in t for t in texts)  # signing-disabled pattern fired
    commands = [s.command_template for s in suggestions if s.command_template]
    assert any(
        "netexec smb 10.10.10.5" in c for c in commands
    )  # {target} interpolated into command
    assert any("Readable share SYSVOL on 10.10.10.5" in t for t in texts)  # {value}+{target}
    assert all("/admin" not in t for t in texts)  # the http finding matched no smb pattern
    assert all(s.source_box for s in suggestions)  # every suggestion cites its source


def test_suggest_matches_http_shape_finding() -> None:
    # http findings are {port, path, note} (no kind/value/detail); match note, interpolate path/port
    rules = [
        engine.PatternRule(
            service="http",
            match={"service": "http", "field": "note", "value": "WordPress"},
            suggest=[
                {
                    "text": "WordPress at {path}",
                    "command": "wpscan --url http://{target}:{port}{path} -e u",
                }
            ],
            source="notes.md",
        )
    ]
    findings: list[dict[str, Any]] = [
        {"module": "http", "port": 8080, "path": "/blog/", "status": 200, "note": "WordPress 6.1"}
    ]
    suggestions = engine.suggest_for(findings, target="10.0.0.1", rules=rules)
    assert suggestions and suggestions[0].text == "WordPress at /blog/"
    assert suggestions[0].command_template == "wpscan --url http://10.0.0.1:8080/blog/ -e u"
    # detail_contains also searches the note field now
    rules2 = [
        engine.PatternRule("http", {"service": "http", "detail_contains": "wordpress"}, ["x"], "n")
    ]
    assert engine.suggest_for(findings, target="10.0.0.1", rules=rules2)


def test_suggest_for_dedups_identical() -> None:
    findings: list[dict[str, Any]] = [
        {"module": "smb", "kind": "share", "value": "IT", "detail": "readable"},
        {"module": "smb", "kind": "share", "value": "IT", "detail": "readable"},
    ]
    rules = engine.load_patterns(FIX / "patterns")
    suggestions = engine.suggest_for(findings, target="10.0.0.1", rules=rules)
    assert len([s for s in suggestions if "Readable share IT" in s.text]) == 1


def test_shipped_patterns_pass_gates() -> None:
    # the real patterns/ dir must ALWAYS pass both gates (enforced as entries land)
    assert engine.check_provenance() == []
    assert engine.check_forbidden() == []


def test_shipped_patterns_fire_on_findings() -> None:
    # the shipped smb/http patterns must load + fire on the real finding shapes, all sourced
    findings: list[dict[str, Any]] = [
        {"module": "smb", "kind": "auth", "value": "authenticated", "detail": "null"},
        {"module": "smb", "kind": "share", "value": "IT", "detail": "READ"},
        {"module": "http", "port": 80, "path": "/", "status": 200, "note": "WordPress 6.1"},
        {"module": "mysql", "kind": "version", "value": "5.5.20-log", "detail": ""},
        {"module": "mssql", "kind": "version", "value": "Microsoft SQL Server 2019", "detail": ""},
    ]
    suggestions = engine.suggest_for(findings, target="10.10.10.5")  # loads shipped patterns/
    commands = " ".join(s.command_template or "" for s in suggestions)
    assert "smbmap -H 10.10.10.5" in commands
    assert "wpscan --url http://10.10.10.5:80/" in commands
    # DB-service patterns must fire + interpolate {target} (not just pass the provenance gate)
    assert "nmap -p 3306 --script mysql-empty-password 10.10.10.5" in commands
    assert "netexec mssql 10.10.10.5" in commands
    assert suggestions and all(s.source_box for s in suggestions)
