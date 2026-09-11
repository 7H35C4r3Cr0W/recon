"""ToolDispatcher — routes a SafetyGate-approved tool call to the engine, through the recon path only.

Explicit per-tool handlers (never a generic kwargs splat) so the LLM cannot spoof an engine argument
it shouldn't set — there is no exploit/spray parameter anywhere on this path. The project → Profile
resolution uses the scope from the caller (DB-sourced), never LLM input, so the scope-lock holds.
Blocking engine calls run in a threadpool.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from typing import Any

import structlog

from nabu_agent.engine import tools as etools
from nabu_agent.engine.errors import EngineAdapterError
from nabu_agent.engine.workspace import workspace_for

_slog = structlog.get_logger("nabu_agent.agents.dispatch")

OnLine = Callable[[str], None] | None


class ToolError(Exception):
    """A tool call failed — returned to the model as a tool result so it can adapt (never crashes the loop)."""


async def dispatch(tool_name: str, arguments: dict[str, Any], *, project_id: str, target: str,
                   on_line: OnLine = None, cancel: threading.Event | None = None) -> dict[str, Any]:
    args = arguments or {}
    try:
        if tool_name == "catalog_actions_for":
            # stateless, display-only: evidence is assembled server-side from the profile so the LLM
            # only names a service (it can't inflate presence/scores).
            profile = await asyncio.to_thread(workspace_for(project_id, target).open_or_create)
            evidence = _evidence_from_profile(profile)
            return await asyncio.to_thread(
                etools.catalog_actions_for, str(args.get("service", "")), evidence,
                limit=int(args.get("limit", 12)))

        profile = await asyncio.to_thread(workspace_for(project_id, target).open_or_create)

        if tool_name == "list_discovered_services":
            return await asyncio.to_thread(etools.list_discovered_services, profile)
        if tool_name == "suggest_next_steps":
            return await asyncio.to_thread(etools.suggest_next_steps, profile)
        if tool_name == "generate_report":
            return await asyncio.to_thread(etools.generate_report, profile, persist=False)
        if tool_name == "enum_service":
            service = str(args.get("service", ""))
            if not service:
                raise ToolError("enum_service requires a 'service' name")
            return await asyncio.to_thread(
                etools.enum_service, profile, service, "full",
                port=int(args.get("port", 0)), on_line=on_line, cancel=cancel)
        if tool_name == "research_finding":
            return await asyncio.to_thread(etools.research_finding, profile, dict(args.get("finding", {})),
                                           on_line=on_line)
        raise ToolError(f"unknown or non-dispatchable tool: {tool_name!r}")
    except ToolError:
        raise
    except EngineAdapterError as exc:
        raise ToolError(f"{getattr(exc, 'code', 'engine_error')}: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - any tool/engine/IO failure is DATA fed back to the model,
        # never a crash that kills the whole run (e.g. a missing tool, unwritable workspace, parse error).
        _slog.warning("tool-unexpected-error", tool=tool_name, exc_info=True)  # operator-visible, not model-only
        raise ToolError(f"tool {tool_name} failed: {exc}") from exc


def _evidence_from_profile(profile: Any) -> dict[str, Any]:
    """Build the catalog-ranking evidence blob from the profile's own discovered state (not the LLM)."""
    import oscprecon.findings as ef

    services = [(int(s.port), str(s.service)) for s in profile.discovered_services]
    fingerprints = [f"{s.product} {s.version}".strip() for s in profile.discovered_services if s.product]
    findings = ef.load_findings(profile.directory)
    creds = [{"secret_type": c.secret_type} for c in profile.credentials()]
    return {"services": services, "fingerprints": fingerprints, "findings": findings,
            "credentials": creds, "command_history": [], "values": {"target": profile.target.ip}}
