"""Read-only engine facade used by the FastAPI ``api`` process.

The ``api`` container drops all Linux capabilities and **runs no tools** — it only reads engine
state (reports, findings, services, graph, activity) and creates/loads Profiles. All tool execution
happens in the ``worker`` container via :mod:`nabu_agent.engine.tools` / ``shell_gateway``. Keeping
that split here means a compromised web tier still cannot launch a scan.

Every function returns JSON-serialisable data (never a raw engine object) so the HTTP layer stays
decoupled from ``oscprecon`` internals.
"""

from __future__ import annotations

import re
from typing import Any

from oscprecon import audit as engine_audit
from oscprecon import findings as findings_mod
from oscprecon import graph_data
from oscprecon.finding_severity import ALL_CATEGORIES, NOTABLE_CATEGORIES, category_of, rank
from oscprecon.profile import Profile
from oscprecon.reporter import Reporter

from .errors import ProjectNotFound
from .schemas import to_service_dto
from .settings import EngineSettings, load_engine_settings
from .workspace import AgentWorkspace, project_root, workspace_for


def _workspace(project_id: str, scope: str, hostname: str | None,
               settings: EngineSettings | None = None) -> AgentWorkspace:
    return workspace_for(project_id, scope, hostname, settings or load_engine_settings())


def create_project_profile(project_id: str, scope: str, hostname: str | None = None) -> str:
    """Create the on-disk engine Profile for a new project. Returns the profile directory path.

    Wraps ``Profile.create`` via the workspace mapping (which runs ``Target`` validation, so a bad
    scope raises :class:`InvalidTarget` before any folder is written)."""
    prof = _workspace(project_id, scope, hostname).create()
    return str(prof.directory)


def load_profile(project_id: str, scope: str, hostname: str | None = None) -> Profile:
    """Load the existing Profile (raises :class:`ProjectNotFound` if never created)."""
    return _workspace(project_id, scope, hostname).open()


_HEADING_RE = re.compile(r"^(#{1,6})(\s)")


def _demote_headings(md: str, levels: int = 2) -> str:
    """Push every markdown heading down ``levels`` so an embedded per-host report nests cleanly
    under the combined report's own headers (a leading ``#`` never fights the section header)."""
    out = []
    for line in md.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            line = "#" * min(6, len(m.group(1)) + levels) + m.group(2) + line[m.end():]
        out.append(line)
    return "\n".join(out)


def render_combined_report(project_id: str) -> str:
    """Aggregate EVERY per-host Profile under a project into ONE report: a cross-host summary
    (services + findings + top severity per host), an aggregate severity tally, suggested next steps
    (the notable findings across all hosts, strongest first), then each host's full rendered report.
    Read-only. CIDR/range 'sweep' Profiles (target contains '/') are skipped. Raises ProjectNotFound
    if the workspace holds no per-host Profile yet (caller falls back to the 'no report' message)."""
    root = project_root(project_id)
    if not root.exists():
        raise ProjectNotFound(project_id)

    profiles: list[Profile] = []
    for d in sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.name):
        if not (d / "profile.json").is_file():
            continue
        try:
            prof = Profile.load(d)
        except Exception:  # a half-written or foreign dir must not sink the whole report
            continue
        if "/" in (getattr(prof.target, "ip", "") or ""):  # the CIDR/range sweep Profile, not a host
            continue
        profiles.append(prof)
    if not profiles:
        raise ProjectNotFound(project_id)

    rows = [(prof.target.ip, len(prof.discovered_services),
             findings_mod.load_findings(prof.directory)) for prof in profiles]
    with_results = [(h, ns, f) for (h, ns, f) in rows if ns or f]
    empty = [h for (h, ns, f) in rows if not ns and not f]

    def _top_cat(findings: list[dict[str, Any]]) -> str:
        return min((category_of(f) for f in findings), key=rank) if findings else "-"

    total_findings = sum(len(f) for _, _, f in rows)
    agg: dict[str, int] = {}
    for _, _, findings in rows:
        for f in findings:
            agg[category_of(f)] = agg.get(category_of(f), 0) + 1

    L: list[str] = ["# Combined Recon Report", ""]
    L.append(f"_{len(with_results)} host(s) with results, {len(profiles)} scanned "
             f"· {total_findings} finding(s)_")
    if empty:
        shown = ", ".join(f"`{h}`" for h in empty[:20]) + (" …" if len(empty) > 20 else "")
        L += ["", f"> {len(empty)} additional host(s) responded but exposed nothing notable: {shown}"]
    L += ["", "## Summary", "", "| Host | Services | Findings | Top severity |",
          "|------|---------:|---------:|--------------|"]
    for host, ns, findings in with_results:
        L.append(f"| `{host}` | {ns} | {len(findings)} | {_top_cat(findings)} |")
    L.append("")

    if agg:
        L += ["### Findings by severity (all hosts)", ""]
        L += [f"- **{cat}**: {agg[cat]}" for cat in reversed(ALL_CATEGORIES) if agg.get(cat)]
        L.append("")

    notable = sorted(
        ((rank(category_of(f)), host, category_of(f), f)
         for host, _ns, findings in with_results for f in findings
         if category_of(f) in NOTABLE_CATEGORIES),
        key=lambda x: x[0])
    L += ["## Suggested next steps", ""]
    if notable:
        for _r, host, cat, f in notable[:50]:
            port = f.get("port")
            where = f"`{host}`" + (f":{port}" if port else "")
            val = str(f.get("value", "")).strip() or str(f.get("kind", "finding"))
            L.append(f"- {where} — **{cat}**: {val}")
    else:
        L.append("- No notable weaknesses surfaced yet. Review the per-host detail below and "
                 "consider deeper enumeration on the services listed.")
    L.append("")

    L.append("---")
    by_host = {prof.target.ip: prof for prof in profiles}
    for host, _ns, _findings in with_results:
        L += ["", f"## Host: {host}", ""]
        try:
            body = _demote_headings(Reporter(by_host[host]).render(), 2)
        except Exception as exc:  # one host's template error must not sink the combined report
            body = f"_report render failed for {host}: {exc}_"
        L += [body, "", "---"]
    return "\n".join(L)


def render_report(project_id: str, scope: str, hostname: str | None = None) -> str:
    """``Reporter(profile).render()`` — the clean report markdown, zero side effects."""
    return Reporter(load_profile(project_id, scope, hostname)).render()


def list_services(project_id: str, scope: str, hostname: str | None = None) -> list[dict[str, Any]]:
    prof = load_profile(project_id, scope, hostname)
    return [to_service_dto(s) for s in prof.discovered_services]


def list_findings(project_id: str, scope: str, hostname: str | None = None) -> list[dict[str, Any]]:
    """Findings from ``findings.json``, each tagged with its severity category + rank."""
    prof = load_profile(project_id, scope, hostname)
    rows = findings_mod.load_findings(prof.directory)
    for row in rows:
        cat = category_of(row)
        row["_category"] = cat
        row["_rank"] = rank(cat)
    return rows


def build_graph(project_id: str, scope: str, hostname: str | None = None) -> dict[str, Any]:
    """Cytoscape.js elements for the discovery graph (``graph_data.build_elements``)."""
    prof = load_profile(project_id, scope, hostname)
    try:
        return graph_data.build_elements(prof)
    except Exception:  # pragma: no cover - build_elements is defensive but never fatal to the API
        return {"nodes": [], "edges": []}


def activity(project_id: str, scope: str, hostname: str | None = None, *, limit: int = 200) -> list[dict[str, Any]]:
    """The engine's per-project audit trail (``audit.jsonl``), newest last, capped at ``limit``."""
    prof = load_profile(project_id, scope, hostname)
    entries = engine_audit.load_entries(prof.directory)
    return entries[-limit:]


__all__ = [
    "create_project_profile", "load_profile", "render_report", "render_combined_report",
    "list_services", "list_findings", "build_graph", "activity",
    "ProjectNotFound",
]
