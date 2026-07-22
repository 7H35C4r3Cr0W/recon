import json
from pathlib import Path

import pytest

from oscprecon import audit


@pytest.fixture(autouse=True)
def _redaction_on(monkeypatch: pytest.MonkeyPatch) -> None:
    # These tests exercise the secret-MASKING capability. The shipping default is
    # shell.REDACT_SECRETS=False (owner policy 2026-07-22: never redact loot), so enable it
    # here to verify the masking logic still works when a build opts in.
    from oscprecon import shell

    monkeypatch.setattr(shell, "REDACT_SECRETS", True)


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


def test_record_scrubs_credentials_embedded_in_a_command(tmp_path: Path) -> None:
    # regression: a whole command can hide a cred (impacket user:pass@host, -p …); the key-name
    # redactor never touches the `command` value, so it reached audit.jsonl + report.md in cleartext
    audit.record(
        tmp_path,
        "b",
        "run-command",
        details={
            "module": "smb",
            "command": "impacket-secretsdump 'CORP/svc:SuperSecret123@10.10.10.10'",
        },
    )
    text = audit.audit_path(tmp_path).read_text(encoding="utf-8")
    assert "SuperSecret123" not in text
    entry = audit.load_entries(tmp_path)[0]
    assert "<redacted len=" in entry["details"]["command"]
    assert entry["details"]["module"] == "smb"  # non-secret detail survives
    # a netexec Tier-2 -p is masked; nmap ports are NOT (nmap is not a credential tool)
    assert "RealPass" not in audit._redact({"command": "netexec smb x -u a -p RealPass"})["command"]
    assert audit._redact({"command": "nmap -p 80,443 x"})["command"] == "nmap -p 80,443 x"


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
