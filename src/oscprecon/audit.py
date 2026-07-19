from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("oscprecon.audit")

# why: §6a — an append-only, one-JSON-object-per-line audit trail of every GUI action, for a
# complete exam audit record. Writes are best-effort (must never block or crash the UI) and the
# live file rotates into audit-archive/ once it passes this size.
_MAX_BYTES = 5 * 1024 * 1024
# why: §6a/§6 — the secret VALUE is never written; only field names + a redacted length.
_REDACT_KEYS = frozenset({"secret", "password", "pass", "cpassword", "secret_value"})
# command strings are scrubbed by value (not by key name) — a cred can hide inside the command
_COMMAND_KEYS = frozenset({"command", "shell_line"})


def audit_path(profile_dir: Path) -> Path:
    return Path(profile_dir) / "audit.jsonl"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _redact(details: dict[str, Any]) -> dict[str, Any]:
    from oscprecon import shell  # local import: shell is heavy-ish and only needed for command keys

    out: dict[str, Any] = {}
    for key, value in details.items():
        if key.lower() in _REDACT_KEYS and isinstance(value, str):
            out[key] = f"<redacted len={len(value)}>"
        elif key.lower() in _COMMAND_KEYS and isinstance(value, str):
            # a whole command can embed a vault credential (impacket user:pass@host, -p …); the
            # key-name redactor above never touches it, so it would reach audit.jsonl + report.md
            # in cleartext. Scrub the command string itself (§6/§18).
            out[key] = shell.redact_command(value)
        else:
            out[key] = value
    return out


def _rotate_if_needed(path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size < _MAX_BYTES:
        return
    archive = path.parent / "audit-archive"
    archive.mkdir(exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    path.replace(archive / f"audit-{stamp}.jsonl")


def record(
    profile_dir: Path,
    profile_name: str,
    action: str,
    *,
    actor: str = "user",
    details: dict[str, Any] | None = None,
) -> None:
    # why: §6a — audit is best-effort, so a serialization or I/O failure here must never propagate
    # to the UI; log it and move on. This is the one place a broad except is correct.
    try:
        path = audit_path(profile_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        _rotate_if_needed(path)
        entry = {
            "ts": _now_iso(),
            "actor": actor,
            "action": action,
            "profile": profile_name,
            "details": _redact(details or {}),
        }
        line = json.dumps(entry, default=str)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except Exception as exc:  # noqa: BLE001 — best-effort boundary (§6a)
        logger.warning("audit write failed: %s", exc)


def load_entries(profile_dir: Path) -> list[dict[str, Any]]:
    path = audit_path(profile_dir)
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                entries.append(obj)
    except OSError:
        return []
    return entries


@dataclass
class Auditor:
    # why: binds a profile's dir + name so call sites read `self._audit.record("run-command", …)`
    # without repeating both every time.
    profile_dir: Path
    profile_name: str

    def record(
        self, action: str, *, actor: str = "user", details: dict[str, Any] | None = None
    ) -> None:
        record(self.profile_dir, self.profile_name, action, actor=actor, details=details)
