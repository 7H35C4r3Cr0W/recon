from __future__ import annotations

import contextlib
import json
from pathlib import Path

from oscprecon.workspace.models import Organization, ProfileSummary


def _dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _read_dict(path: Path) -> dict[str, object] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError, UnicodeError):
        return None
    return data if isinstance(data, dict) else None


def _count_records(path: Path) -> int | None:
    # len of a findings/creds JSON (a list, or {"entries": [...]}); None if missing/corrupt.
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError, UnicodeError):
        return None
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict) and isinstance(data.get("entries"), list):
        return len(data["entries"])
    return None


def _has_notes(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    body = "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("#")).strip()
    return bool(body)  # any content beyond the auto "# <name> — notes" heading


def _has_graph(path: Path) -> bool:
    data = _read_dict(path)
    if data is None:
        return False
    return bool(data.get("user_edges")) or bool(data.get("node_overrides"))


def _has_report(path: Path) -> bool:
    try:
        return path.exists() and path.stat().st_size > 0
    except OSError:
        return False


def summarize_profile(directory: Path) -> ProfileSummary:
    directory = Path(directory)
    summary = ProfileSummary(name=directory.name, directory=directory)
    with contextlib.suppress(OSError):
        summary.locked = (directory / ".lock").exists()

    profile_json = directory / "profile.json"
    raw = _read_dict(profile_json) if profile_json.exists() else None
    if raw is None:
        summary.corrupt = True
        if not profile_json.exists():
            if (directory / "profile.json.tmp").exists():
                summary.warnings.append("interrupted create (only profile.json.tmp present)")
            else:
                summary.warnings.append("missing profile.json")
        else:
            summary.warnings.append("corrupt profile.json")
        return summary  # cannot read metadata safely — surface a warning row, don't hide it

    target = _dict(raw.get("target"))
    ip = str(target.get("ip", "") or "")
    hostname = str(target.get("hostname") or "")
    summary.target = ip + (f" ({hostname})" if hostname else "")
    summary.platform = str(target.get("platform") or "")
    if not ip:
        summary.warnings.append("no target IP")

    org = Organization.from_dict(raw.get("organization"))
    summary.status = org.status
    summary.tags = org.tags
    summary.pinned = org.pinned
    summary.archived = org.archived
    fallback_title = f"{directory.name} — {ip}" if ip else directory.name
    summary.display_title = org.display_name or fallback_title

    status = _dict(raw.get("status"))
    summary.created_at = str(status.get("started_at", "") or "")
    summary.last_activity_at = str(status.get("last_active", "") or "")
    summary.last_opened_at = str(status.get("last_opened_at", "") or "")

    services = raw.get("discovered_services")
    summary.service_count = len(services) if isinstance(services, list) else 0

    history = raw.get("command_history")
    if isinstance(history, list):
        for rec in history:
            if not isinstance(rec, dict):
                continue
            code = rec.get("exit_code")
            if code == 0:
                summary.commands_completed += 1
            elif code is not None:
                summary.commands_failed += 1  # non-zero incl. -9 (cancelled)

    findings_count = _count_records(directory / "findings.json")
    if findings_count is None:
        summary.warnings.append("corrupt findings.json")
    summary.finding_count = findings_count or 0
    creds_count = _count_records(directory / "creds.json")
    if creds_count is None:
        summary.warnings.append("corrupt creds.json")
    summary.credential_count = creds_count or 0

    summary.has_notes = _has_notes(directory / "notes.md")
    summary.has_report = _has_report(directory / "report.md")
    summary.has_graph = _has_graph(directory / "graph.json")
    return summary


def _within(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def _is_profile_dir(directory: Path) -> bool:
    try:
        return (directory / "profile.json").exists() or (directory / "profile.json.tmp").exists()
    except OSError:
        return False


def sort_summaries(summaries: list[ProfileSummary]) -> list[ProfileSummary]:
    # pinned first, then non-archived before archived, then most-recent activity, then name.
    ordered = sorted(summaries, key=lambda s: s.name.lower())
    ordered = sorted(ordered, key=lambda s: s.last_activity_at, reverse=True)
    return sorted(ordered, key=lambda s: (not s.pinned, s.archived))


def scan_workspace(root: Path, *, include_archived: bool = True) -> list[ProfileSummary]:
    """Discover profiles directly under `root` and return lightweight summaries. Never raises: a
    profile that cannot be read becomes a corrupt/warning row rather than hiding or crashing."""
    root = Path(root)
    summaries: list[ProfileSummary] = []
    try:
        entries = list(root.iterdir())
    except OSError:
        return summaries
    root_resolved = root.resolve()
    for entry in entries:
        try:
            if not entry.is_dir():
                continue
            resolved = entry.resolve()
        except OSError:
            continue
        # symlink-escape guard: a symlinked dir must resolve back inside the workspace root
        if entry.is_symlink() and not _within(resolved, root_resolved):
            continue
        if not _is_profile_dir(entry):
            continue  # ignore unrelated folders (no profile.json / .tmp)
        try:
            summaries.append(summarize_profile(entry))
        except Exception:  # boundary: one bad profile must not kill the whole scan
            summaries.append(
                ProfileSummary(
                    name=entry.name, directory=entry, corrupt=True, warnings=["unreadable profile"]
                )
            )
    ordered = sort_summaries(summaries)
    if not include_archived:
        ordered = [s for s in ordered if not s.archived]
    return ordered
