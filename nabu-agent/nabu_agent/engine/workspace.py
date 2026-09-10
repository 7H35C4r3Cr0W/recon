"""Per-agent WORKSPACE <-> oscprecon Profile-folder mapping.

Design
------
A Nabu Agent *project* is the unit of authorized engagement. Its authoritative metadata
(owner, assigned scope, RBAC, immutable action log) lives in Postgres. Its *recon state*
(profile.json, findings.json, creds.json, audit.jsonl, report.md, per-service tool output)
lives in an oscprecon **Profile folder** on disk — the exact on-disk shape the engine reads
and writes. This module is the only place that translates between the two.

Mapping
-------
    Postgres project row (GUID pk, scope_ip, hostname, owner, ...)
        │  project_id (GUID)  ──► profile folder name (the GUID, slug-safe)
        ▼
    <NABU_AGENT_WORKSPACE_ROOT>/<project_id>/   ← one oscprecon Profile per project
        profile.json  findings.json  creds.json  audit.jsonl  graph.json  notes.md
        report.md     nmap/  smb/  ftp/  ...        (engine-managed subtrees)

- The workspace root is Nabu-Agent-owned (config, default /var/lib/nabu-agent/workspaces),
  NOT the classic ~/oscprecon, so desktop Nabu and the platform never share folders.
- Profile.target.ip is kept EQUAL to the Postgres row's assigned scope; that equality is the
  scope-lock the guard enforces before every tool run.
- The many per-service agents that fan out for one target all operate on the SAME Profile.
  Concurrency: the engine gives in-process safety (profile RLock; findings threading.Lock +
  fcntl.flock). Because Nabu Agent owns the folder (no GUI sharing), that is sufficient WITHIN
  one process. Across uvicorn workers we add a per-project async lock (Redis) at the API layer
  and route blocking engine calls through a threadpool — see the guard.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from oscprecon.models import Target
from oscprecon.profile import Profile

from .errors import InvalidTarget, ProjectNotFound
from .settings import EngineSettings, load_engine_settings


@dataclass(frozen=True)
class AgentWorkspace:
    """Resolves a project GUID to its on-disk oscprecon Profile folder."""

    project_id: str
    scope_target: str          # the assigned IP or CIDR from the Postgres project row
    hostname: str | None
    settings: EngineSettings

    @property
    def directory(self) -> Path:
        return self.settings.workspace_root / self.project_id

    def exists(self) -> bool:
        return (self.directory / "profile.json").is_file()

    # -- lifecycle -----------------------------------------------------------------

    def create(self) -> Profile:
        """Create the engine Profile for a brand-new project.

        Wraps Profile.create(workspace_root, name, Target). The Target constructor runs
        validate_host_or_range on the scope; a bad scope raises InvalidTarget here, before
        any folder is written.
        """
        try:
            target = Target(ip=self.scope_target, hostname=self.hostname)
        except ValueError as exc:  # models.Target.__post_init__ validation
            raise InvalidTarget(str(exc)) from exc
        return Profile.create(self.settings.workspace_root, self.project_id, target)

    def open(self) -> Profile:
        """Load the existing Profile. Raises ProjectNotFound if never created."""
        if not self.exists():
            raise ProjectNotFound(self.project_id)
        return Profile.load(self.directory)

    def open_or_create(self) -> Profile:
        return self.open() if self.exists() else self.create()


def workspace_for(
    project_id: str,
    scope_target: str,
    hostname: str | None = None,
    settings: EngineSettings | None = None,
) -> AgentWorkspace:
    """Factory used by the service/repository layer.

    ``scope_target`` and ``hostname`` come from the authoritative Postgres project row, never
    from agent/LLM input — that is what makes the scope-lock trustworthy.
    """
    return AgentWorkspace(
        project_id=project_id,
        scope_target=scope_target,
        hostname=hostname,
        settings=settings or load_engine_settings(),
    )
