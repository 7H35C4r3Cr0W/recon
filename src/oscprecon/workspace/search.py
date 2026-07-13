from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from oscprecon.workspace.index import scan_workspace
from oscprecon.workspace.models import ProfileSummary, normalize_tag

# search categories — a credential result carries only username/domain, NEVER the secret value.
CATEGORIES = (
    "profile",
    "tag",
    "status",
    "service",
    "finding",
    "note",
    "report",
    "command",
    "credential",
)

_PREVIEW_MAX = 160
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _safe(text: object) -> str:
    # single-line, control-chars stripped, length-capped — safe to show as PLAIN text (the GUI must
    # not render it as rich text/markdown/html).
    line = _CONTROL.sub(" ", " ".join(str(text or "").split()))
    return line[:_PREVIEW_MAX]


@dataclass
class SearchResult:
    profile_name: str
    directory: Path
    category: str
    preview: str
    location: str = ""
    port: int | None = None


@dataclass
class SearchQuery:
    text: str = ""
    port: int | None = None
    service: str = ""
    tags: list[str] = field(default_factory=list)
    status: str = ""
    finding_kinds: list[str] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)
    include_archived: bool = False
    limit: int = 200

    def is_empty(self) -> bool:
        return not (
            self.text or self.port is not None or self.service or self.tags or self.finding_kinds
        )


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _matches_text(needle: str, *fields: object) -> bool:
    if not needle:
        return True
    low = needle.lower()
    return any(low in str(f or "").lower() for f in fields)


def _profile_passes_filters(summary: ProfileSummary, query: SearchQuery) -> bool:
    if query.profiles and summary.name not in query.profiles:
        return False
    if query.status and summary.status != query.status:
        return False
    if query.tags:
        have = {t.lower() for t in summary.tags}
        if not all((normalize_tag(t) or "").lower() in have for t in query.tags):
            return False
    return True


def _search_profile(summary: ProfileSummary, query: SearchQuery, budget: int) -> list[SearchResult]:
    directory = summary.directory
    out: list[SearchResult] = []

    def add(category: str, preview: object, location: str = "", port: int | None = None) -> None:
        out.append(SearchResult(summary.name, directory, category, _safe(preview), location, port))

    text_only = query.text and query.port is None and not query.service and not query.finding_kinds

    # profile name / target / status / tags (cheap, from the summary)
    if text_only or (query.text and not query.service and query.port is None):
        if _matches_text(query.text, summary.name, summary.display_title, summary.target):
            add("profile", summary.display_title or summary.name, "profile.json")
        for tag in summary.tags:
            if _matches_text(query.text, tag):
                add("tag", tag, "profile.json")
        if _matches_text(query.text, summary.status):
            add("status", summary.status, "profile.json")

    raw = _load_json(directory / "profile.json")
    profile = raw if isinstance(raw, dict) else {}

    # services (name / port / product / version)
    services = profile.get("discovered_services")
    if isinstance(services, list):
        for svc in services:
            if not isinstance(svc, dict):
                continue
            port = svc.get("port")
            name = svc.get("service", "")
            if query.port is not None and port != query.port:
                continue
            if query.service and query.service.lower() not in str(name).lower():
                continue
            if (
                query.port is not None
                or query.service
                or _matches_text(query.text, name, svc.get("product"), svc.get("version"), port)
            ):
                label = f"{port}/{svc.get('proto', 'tcp')}"
                preview = f"{label} {name} {svc.get('product', '')} {svc.get('version', '')}"
                add("service", preview, label, port if isinstance(port, int) else None)

    # findings (kind / value / detail) — recon facts, no secrets
    fdata = _load_json(directory / "findings.json")
    if isinstance(fdata, list) and (query.text or query.finding_kinds):
        for finding in fdata:
            if not isinstance(finding, dict):
                continue
            kind = str(finding.get("kind", ""))
            if query.finding_kinds and kind not in query.finding_kinds:
                continue
            if _matches_text(
                query.text, kind, finding.get("value"), finding.get("detail"), finding.get("module")
            ):
                preview = f"{finding.get('module', '')} {kind}: {finding.get('value', '')}"
                add("finding", preview, "findings.json")

    if text_only:
        # command history (shell_line + output_file), notes headings, report headings
        history = profile.get("command_history")
        if isinstance(history, list):
            for rec in history:
                if isinstance(rec, dict) and _matches_text(
                    query.text, rec.get("shell_line"), rec.get("output_file")
                ):
                    add("command", rec.get("shell_line", ""), "command_history")
        for name, path in (("note", directory / "notes.md"), ("report", directory / "report.md")):
            try:
                text = (directory / path.name).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                if query.text.lower() in line.lower() and line.strip():
                    add(name, line, path.name)
                    break  # one hit per doc is enough for a preview

        # credentials — username + domain ONLY. The secret value is never read or shown.
        cdata = _load_json(directory / "creds.json")
        entries = cdata.get("entries") if isinstance(cdata, dict) else None
        if isinstance(entries, list):
            for cred in entries:
                if not isinstance(cred, dict):
                    continue
                username = str(cred.get("username", ""))
                domain = str(cred.get("domain", ""))
                if _matches_text(query.text, username, domain):
                    who = f"{domain}\\{username}" if domain else username
                    add("credential", f"{who} (source: {cred.get('source', '')})", "creds.json")

    return out[:budget]


def search_workspace(root: Path, query: SearchQuery) -> list[SearchResult]:
    """Cross-profile search. Grouped by profile then category. Never reads/returns secret values;
    credential results carry only username + domain."""
    if query.is_empty():
        return []
    results: list[SearchResult] = []
    for summary in scan_workspace(root, include_archived=query.include_archived):
        if summary.corrupt:
            continue  # a warning row can't be searched
        if not _profile_passes_filters(summary, query):
            continue
        remaining = query.limit - len(results)
        if remaining <= 0:
            break
        results.extend(_search_profile(summary, query, remaining))
    return results[: query.limit]
