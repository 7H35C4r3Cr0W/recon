from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from oscprecon.audit import audit_path

# action slug -> human-readable verb. Unknown actions fall back to a spaced slug.
_DESCRIPTIONS: dict[str, str] = {
    "profile-created": "Profile created",
    "profile-opened": "Profile opened",
    "profile-closed": "Profile closed",
    "profile-saved": "Profile saved",
    "profile-exported": "Exported to Obsidian vault",
    "run": "Scan started",
    "run-finished": "Scan finished",
    "dry-run": "Dry-run (command shown, not executed)",
    "add-to-report": "Command queued for the report",
    "credential-added": "Credential added",
    "status-changed": "Status changed",
    "tags-changed": "Tags changed",
    "pinned-changed": "Pin toggled",
    "archived-changed": "Archived / restored",
    "report-generated": "Report generated",
    "repair": "Repair action performed",
    "bulk-action": "Bulk action",
}
# only these detail keys are ever shown — never dump raw details (belt-and-braces vs secret leak).
_SAFE_DETAIL_KEYS = ("label", "module", "status", "username", "domain", "source", "target", "dest")


@dataclass
class ActivityEvent:
    timestamp: str
    date: str  # YYYY-MM-DD
    profile: str
    event_type: str
    description: str


def _describe(action: str, details: dict[str, object]) -> str:
    base = _DESCRIPTIONS.get(action, action.replace("-", " ").capitalize())
    extras = [
        f"{key}={details[key]}"
        for key in _SAFE_DETAIL_KEYS
        if isinstance(details.get(key), str | int | bool) and str(details.get(key))
    ]
    return f"{base} ({', '.join(extras)})" if extras else base


def load_activity(profile_dir: Path, *, limit: int = 200) -> tuple[list[ActivityEvent], int]:
    """Human-readable events for one profile, newest first, plus a malformed-line count. A single
    corrupt audit line is skipped (counted), never hides the rest of the history."""
    path = audit_path(profile_dir)
    events: list[ActivityEvent] = []
    malformed = 0
    if not path.exists():
        return events, malformed
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return events, malformed
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            malformed += 1
            continue
        if not isinstance(obj, dict):
            malformed += 1
            continue
        ts = str(obj.get("ts", ""))
        details = obj.get("details")
        events.append(
            ActivityEvent(
                timestamp=ts,
                date=ts[:10],
                profile=str(obj.get("profile", profile_dir.name)),
                event_type=str(obj.get("action", "")),
                description=_describe(
                    str(obj.get("action", "")), details if isinstance(details, dict) else {}
                ),
            )
        )
    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events[:limit], malformed


def load_workspace_activity(
    root: Path,
    *,
    event_types: list[str] | None = None,
    profiles: list[str] | None = None,
    text: str = "",
    limit: int = 300,
) -> tuple[list[ActivityEvent], int]:
    """Aggregate recent activity across the workspace, newest first, plus total malformed lines."""
    from oscprecon.workspace.index import scan_workspace

    all_events: list[ActivityEvent] = []
    malformed_total = 0
    for summary in scan_workspace(root):
        if profiles and summary.name not in profiles:
            continue
        events, malformed = load_activity(summary.directory, limit=limit)
        malformed_total += malformed
        all_events.extend(events)
    if event_types:
        allowed = set(event_types)
        all_events = [e for e in all_events if e.event_type in allowed]
    if text:
        low = text.lower()
        all_events = [
            e for e in all_events if low in e.description.lower() or low in e.profile.lower()
        ]
    all_events.sort(key=lambda e: e.timestamp, reverse=True)
    return all_events[:limit], malformed_total
