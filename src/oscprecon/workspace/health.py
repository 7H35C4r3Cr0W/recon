from __future__ import annotations

import json
import os
import shutil
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_EXPECTED_DIRS = ("nmap", "references", "manual")


@dataclass
class HealthIssue:
    code: str
    severity: str  # "error" | "warning" | "info"
    message: str
    repairable: bool = False


def _load(path: Path) -> tuple[object, bool]:
    # (data, corrupt). corrupt=True means present-but-unreadable.
    if not path.exists():
        return None, False
    try:
        return json.loads(path.read_text(encoding="utf-8")), False
    except (OSError, json.JSONDecodeError, ValueError, UnicodeError):
        return None, True


def check_profile(directory: Path, *, workspace_root: Path | None = None) -> list[HealthIssue]:
    """Read-only health scan. Never modifies the profile."""
    directory = Path(directory)
    issues: list[HealthIssue] = []

    def add(code: str, severity: str, message: str, repairable: bool = False) -> None:
        issues.append(HealthIssue(code, severity, message, repairable))

    # profile path escaping the workspace root
    if workspace_root is not None:
        try:
            resolved = directory.resolve()
            root = Path(workspace_root).resolve()
            if resolved != root and root not in resolved.parents:
                add("path-escape", "error", f"profile path is outside the workspace: {resolved}")
        except OSError:
            pass

    profile_json = directory / "profile.json"
    raw, corrupt = _load(profile_json)
    if not profile_json.exists():
        if (directory / "profile.json.tmp").exists():
            add("interrupted-create", "error", "only profile.json.tmp exists (interrupted create)")
        else:
            add("missing-profile-json", "error", "profile.json is missing")
        return issues  # nothing more can be checked safely
    if corrupt or not isinstance(raw, dict):
        add("corrupt-profile-json", "error", "profile.json is corrupt or truncated")
        return issues
    profile: dict[str, object] = raw

    # target validity
    target = profile.get("target")
    ip = target.get("ip") if isinstance(target, dict) else None
    if not ip:
        add("invalid-target", "warning", "profile has no target IP")

    # other JSON files corrupt/truncated
    for name in ("findings.json", "creds.json", "graph.json"):
        _, bad = _load(directory / name)
        if bad:
            add(f"corrupt-{name}", "error", f"{name} is corrupt or truncated")
    # audit.jsonl: count malformed lines (never let one bad line hide the rest)
    audit = directory / "audit.jsonl"
    if audit.exists():
        bad_lines = 0
        try:
            for line in audit.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    bad_lines += 1
        except OSError:
            bad_lines = -1
        if bad_lines:
            add("malformed-audit-lines", "warning", f"{bad_lines} malformed audit.jsonl line(s)")

    # stale temp files from interrupted writes
    stale = _stale_temp_files(directory)
    if stale:
        add("stale-temp-files", "warning", f"{len(stale)} interrupted-write temp file(s)", True)

    # missing expected directories
    missing = [d for d in _EXPECTED_DIRS if not (directory / d).is_dir()]
    if missing:
        add("missing-dirs", "info", f"missing expected dirs: {', '.join(missing)}")

    # output files referenced by command history but missing on disk
    history = profile.get("command_history")
    if isinstance(history, list):
        missing_outputs = 0
        for rec in history:
            if not isinstance(rec, dict):
                add("malformed-command-record", "warning", "a command_history record is malformed")
                continue
            out = rec.get("output_file")
            if isinstance(out, str) and out and not (directory / out).exists():
                missing_outputs += 1
        if missing_outputs:
            add("missing-output-files", "info", f"{missing_outputs} command output file(s) missing")

    # findings referencing a port with no matching discovered service
    services = profile.get("discovered_services")
    ports = (
        {s.get("port") for s in services if isinstance(s, dict)}
        if isinstance(services, list)
        else set()
    )
    fdata, _ = _load(directory / "findings.json")
    if isinstance(fdata, list):
        orphan = 0
        for finding in fdata:
            if not isinstance(finding, dict):
                add("malformed-finding-record", "warning", "a findings.json record is malformed")
                continue
            port = finding.get("port")
            if isinstance(port, int) and ports and port not in ports:
                orphan += 1
        if orphan:
            add("orphan-findings", "info", f"{orphan} finding(s) reference an unknown service port")

    # world-readable / group-readable credential file (must be 0600)
    creds_file = directory / "creds.json"
    if creds_file.exists():
        try:
            mode = stat.S_IMODE(creds_file.stat().st_mode)
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                add(
                    "creds-permissions",
                    "error",
                    f"creds.json is {oct(mode)} (should be 0600)",
                    True,
                )
        except OSError:
            pass

    return issues


def _stale_temp_files(directory: Path) -> list[Path]:
    try:
        return sorted(p for p in directory.glob("*.tmp") if p.is_file())
    except OSError:
        return []


# --- safe, deterministic repairs (opt-in; back up user data + audited by the caller) ---


def repair_creds_permissions(directory: Path) -> bool:
    """Reset creds.json to 0600. No backup needed (permission-only, not a content change)."""
    creds_file = Path(directory) / "creds.json"
    if not creds_file.exists():
        return False
    try:
        os.chmod(creds_file, 0o600)
    except OSError:
        return False
    return True


def repair_remove_stale_temp(directory: Path) -> list[str]:
    """Move interrupted-write *.tmp files into a timestamped backup dir, then remove them from the
    profile root. Returns the names moved (never silently deletes: they land in health-backup/)."""
    directory = Path(directory)
    stale = _stale_temp_files(directory)
    if not stale:
        return []
    backup = directory / "health-backup" / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    backup.mkdir(parents=True, exist_ok=True)
    moved: list[str] = []
    for path in stale:
        try:
            shutil.move(str(path), str(backup / path.name))
            moved.append(path.name)
        except OSError:
            continue
    return moved
