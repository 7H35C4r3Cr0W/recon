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


def test_suggest_for_dedups_identical() -> None:
    findings: list[dict[str, Any]] = [
        {"module": "smb", "kind": "share", "value": "IT", "detail": "readable"},
        {"module": "smb", "kind": "share", "value": "IT", "detail": "readable"},
    ]
    rules = engine.load_patterns(FIX / "patterns")
    suggestions = engine.suggest_for(findings, target="10.0.0.1", rules=rules)
    assert len([s for s in suggestions if "Readable share IT" in s.text]) == 1


def test_shipped_patterns_pass_gates() -> None:
    # the real patterns/ dir must ALWAYS pass both gates (currently empty; enforced as entries land)
    assert engine.check_provenance() == []
    assert engine.check_forbidden() == []
