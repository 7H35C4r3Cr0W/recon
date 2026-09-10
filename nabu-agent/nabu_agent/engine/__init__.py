"""The engine adapter — the ONLY part of ``nabu_agent`` that imports the classic ``oscprecon``
engine. Everything else in the platform reaches recon capability through this package.

Public surface:

* :data:`TOOLS` — the registry of agent tools advertised to the LLM tool-call layer and the gating
  UI. **No spray/exploit tool is registered** — attack actions are reachable only through the
  human-gated :func:`shell_gateway.execute_gated_action`, never as an agent tool.
* the eight tool functions in :mod:`nabu_agent.engine.tools`.
* :mod:`nabu_agent.engine.shell_gateway` — the single ``shell.run`` chokepoint.
* :mod:`nabu_agent.engine.gateway` — the read-only facade the FastAPI ``api`` process uses.

The engine is a **read-only** dependency: this package never modifies ``src/oscprecon`` and never
imports ``oscprecon.gui.*`` (a policy-invariant test asserts PySide6 is never imported).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import tools
from .errors import (
    AttackGateClosed,
    AutonomyViolation,
    EngineAdapterError,
    InvalidTarget,
    ProjectNotFound,
    ReadOnlyProject,
    ScopeViolation,
    ToolBlocked,
    ToolMissing,
)
from .schemas import CatalogActionDTO, ServiceDTO, ShellResultDTO


@dataclass(frozen=True)
class ToolSpec:
    """Describes one agent tool: whether it executes a real tool and whether it mutates state.

    ``executes`` tools run a wrapped binary through the chokepoint; ``mutates`` tools change the
    Profile on disk. Display-only tools (catalog/research/report render) are neither and are always
    safe for an agent to call. Used to build the LLM tool schema and to decide which calls need the
    per-project write lock.
    """

    name: str
    fn: Callable[..., object]
    executes: bool
    mutates: bool
    summary: str


TOOLS: dict[str, ToolSpec] = {
    "check_alive": ToolSpec("check_alive", tools.check_alive, executes=True, mutates=False,
                            summary="Host-liveness pre-flight (nmap -sn) for the project scope."),
    "run_scan": ToolSpec("run_scan", tools.run_scan, executes=True, mutates=True,
                         summary="Staged nmap battery; discovers open ports/services."),
    "list_discovered_services": ToolSpec("list_discovered_services", tools.list_discovered_services,
                                         executes=False, mutates=False,
                                         summary="Read back discovered ports/services (no exec)."),
    "enum_service": ToolSpec("enum_service", tools.enum_service, executes=True, mutates=True,
                             summary="Tier-1 per-service enumeration; writes findings/creds."),
    "catalog_actions_for": ToolSpec("catalog_actions_for", tools.catalog_actions_for,
                                    executes=False, mutates=False,
                                    summary="DISPLAY-ONLY decision-aid catalog, evidence-ranked."),
    "research_finding": ToolSpec("research_finding", tools.research_finding, executes=True,
                                 mutates=True,
                                 summary="HackTricks/EDB/GTFOBins/patterns research for a finding."),
    "suggest_next_steps": ToolSpec("suggest_next_steps", tools.suggest_next_steps, executes=False,
                                   mutates=False,
                                   summary="Pattern-based next steps with provenance (no exec)."),
    "generate_report": ToolSpec("generate_report", tools.generate_report, executes=False,
                                mutates=False,
                                summary="Render the clean report markdown (no side effects)."),
}

__all__ = [
    "TOOLS", "ToolSpec", "tools",
    "ServiceDTO", "ShellResultDTO", "CatalogActionDTO",
    "EngineAdapterError", "ProjectNotFound", "ScopeViolation", "InvalidTarget",
    "ToolBlocked", "ToolMissing", "ReadOnlyProject", "AttackGateClosed", "AutonomyViolation",
]
