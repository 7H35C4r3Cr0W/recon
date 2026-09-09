"""Read-only engine facade used by the FastAPI ``api`` process.

The ``api`` container drops all Linux capabilities and **runs no tools** — it only reads engine
state (reports, findings, services, graph, activity) and creates/loads Profiles. All tool execution
happens in the ``worker`` container via :mod:`nabu_agent.engine.tools` / ``shell_gateway``. Keeping
that split here means a compromised web tier still cannot launch a scan.

Every function returns JSON-serialisable data (never a raw engine object) so the HTTP layer stays
decoupled from ``oscprecon`` internals.
"""

from __future__ import annotations

from typing import Any

from oscprecon import audit as engine_audit
from oscprecon import findings as findings_mod
from oscprecon import graph_data
from oscprecon.finding_severity import category_of, rank
from oscprecon.profile import Profile
from oscprecon.reporter import Reporter

from .errors import ProjectNotFound
from .schemas import to_service_dto
from .settings import EngineSettings, load_engine_settings
from .workspace import AgentWorkspace, workspace_for


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
    "create_project_profile", "load_profile", "render_report",
    "list_services", "list_findings", "build_graph", "activity",
    "ProjectNotFound",
]
