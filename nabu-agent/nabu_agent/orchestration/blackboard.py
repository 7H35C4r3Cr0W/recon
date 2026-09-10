"""The shared run state / blackboard, grounded in the oscprecon Profile.

Sits ON TOP of the engine adapter (nabu_agent.engine.*); it never touches
oscprecon directly. TWO LAYERS of state:

1. Durable engine truth  -> the oscprecon Profile FOLDER, resolved by
   engine.workspace.workspace_for(project_id, scope_target).open()/create().
   discovered_services, findings.json, creds.json, edb.json, audit.jsonl,
   report.md -- authoritative recon state.

2. Orchestration state    -> Postgres (runs / agent_tasks / checkpoints /
   run_events; see models/run.py) + Redis (per-run pub/sub for live progress,
   Arq queues, cancel flag).

CROSS-PROCESS WRITE DISCIPLINE (load-bearing, from the engine map §2f/§6b):
  * findings.json  is fcntl.flock-protected across processes -> parallel enum
    agents in SEPARATE Arq worker processes MAY write it directly and safely.
  * profile.json   is guarded only by an in-process RLock + an advisory .lock
    file, so concurrent worker PROCESSES calling merge_services/add_credential/
    save() would race, and a worker opening a Profile whose .lock is held gets a
    read_only Profile (ReadOnlyProject on write).

  DECISION -- single-writer Profile per run: the SUPERVISOR job owns the one
  writable Profile handle. Service/research agents open the Profile READ-ONLY
  (or read the Postgres service mirror captured at FAN_OUT), write their
  tool-output rows straight to findings.json (fcntl-safe), and emit
  credential/service/host DELTAS back to the supervisor via Redis. The
  supervisor is the sole caller of merge_services / add_credential / add_hosts +
  save(). This removes the profile.json cross-process race by construction.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# from nabu_agent.engine.workspace import AgentWorkspace, workspace_for
# from nabu_agent.engine.schemas import ServiceDTO, to_service_dto
# from nabu_agent.engine import guard
# from oscprecon import findings as ef          # findings store (fcntl cross-proc safe)


@dataclass
class ServiceDelta:
    """Emitted by a worker over Redis; applied to profile.json by the supervisor."""
    host: str
    services: list[dict[str, Any]]     # ServiceDTO rows


@dataclass
class CredentialDelta:
    host: str
    username: str
    secret: str
    secret_type: str
    domain: str
    source: str


class ReadBlackboard:
    """Read-only view any worker may open safely (Profile.load; may be read_only)."""

    def __init__(self, project_id: str, scope_target: str, hostname: str | None = None) -> None:
        self.project_id = project_id
        self.scope_target = scope_target
        self.hostname = hostname
        # self._ws = workspace_for(project_id, scope_target, hostname)

    def services(self) -> list[dict[str, Any]]:
        """profile.discovered_services -> [ServiceDTO]. Snapshot for fan-out."""
        raise NotImplementedError

    def findings(self) -> list[dict[str, Any]]:
        """ef.load_findings(profile.directory)."""
        raise NotImplementedError

    def write_findings(self, rows: list[dict[str, Any]]) -> None:
        """ef.add_findings(profile.directory, rows) -- CROSS-PROCESS SAFE.

        Build rows with ef.from_parsed(...); never serialize models.Finding.
        Safe from any worker even while the supervisor holds the writable Profile.
        """
        raise NotImplementedError


class WriteBlackboard(ReadBlackboard):
    """SUPERVISOR-ONLY writable handle: the single writer of profile.json."""

    def apply_service_delta(self, delta: ServiceDelta) -> None:
        """profile.merge_services(...) (monotonic union by (port,proto)) + save()."""
        raise NotImplementedError

    def apply_credential(self, delta: CredentialDelta) -> None:
        """profile.add_credential(Credential(...)); replace_credential when a spray
        result updates tested_against (cred_key ignores tested_against)."""
        raise NotImplementedError

    def apply_hosts(self, hosts: list[dict[str, Any]]) -> int:
        """profile.add_hosts([DiscoveredHost(...)]) + save() for range pivots."""
        raise NotImplementedError

    def audit(self, action: str, *, actor: str = "system", details: dict | None = None) -> None:
        """guard.audit(profile, action, actor=, details=) -> oscprecon.audit.record."""
        raise NotImplementedError
