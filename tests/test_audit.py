import json
from pathlib import Path

import pytest

from oscprecon import audit


def test_record_appends_jsonl_entry(tmp_path: Path) -> None:
    audit.record(tmp_path, "htb-active", "run-command", details={"shell_line": "nmap -p- x"})
    audit.record(tmp_path, "htb-active", "profile-saved")

    entries = audit.load_entries(tmp_path)
    assert len(entries) == 2  # append-only
    first = entries[0]
    assert first["action"] == "run-command"
    assert first["actor"] == "user"
    assert first["profile"] == "htb-active"
    assert first["details"]["shell_line"] == "nmap -p- x"
    assert "ts" in first


def test_record_redacts_secret_values(tmp_path: Path) -> None:
    audit.record(
        tmp_path,
        "b",
        "credential-added",
        details={"username": "svc", "secret": "Ticketmaster1968", "source": "smb"},
    )
    text = audit.audit_path(tmp_path).read_text(encoding="utf-8")
    assert "Ticketmaster1968" not in text  # the plaintext secret never reaches the trail
    entry = audit.load_entries(tmp_path)[0]
    assert entry["details"]["secret"] == "<redacted len=16>"
    assert entry["details"]["username"] == "svc"  # non-secret fields survive


def test_record_is_best_effort_on_bad_details(tmp_path: Path) -> None:
    # a non-JSON-serialisable value must not raise — audit is best-effort (§6a)
    audit.record(tmp_path, "b", "weird", details={"obj": object()})
    entries = audit.load_entries(tmp_path)
    assert len(entries) == 1  # written via default=str, not dropped


def test_record_never_raises_on_bad_path(tmp_path: Path) -> None:
    # audit_path parent is a FILE, so mkdir/open fail — record must swallow it
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    audit.record(blocker / "sub", "b", "action")  # must not raise


def test_rotation_moves_live_file_when_oversized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit, "_MAX_BYTES", 200)
    for i in range(50):
        audit.record(tmp_path, "b", "tick", details={"i": i, "pad": "x" * 40})
    archived = list((tmp_path / "audit-archive").glob("audit-*.jsonl"))
    assert archived  # at least one rotation happened
    # the live file still exists and holds the most recent entries
    assert audit.audit_path(tmp_path).exists()
    live = audit.load_entries(tmp_path)
    assert live and live[-1]["details"]["i"] == 49


def test_load_entries_skips_corrupt_lines(tmp_path: Path) -> None:
    path = audit.audit_path(tmp_path)
    path.write_text(
        json.dumps({"action": "ok"}) + "\nnot json\n" + json.dumps({"action": "ok2"}) + "\n",
        encoding="utf-8",
    )
    actions = [e["action"] for e in audit.load_entries(tmp_path)]
    assert actions == ["ok", "ok2"]
