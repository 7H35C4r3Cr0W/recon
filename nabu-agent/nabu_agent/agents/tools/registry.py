"""ToolRegistry — the LLM tool schemas, filtered to a role's allowlist. No spray/exploit tool is ever
exposed (attack actions are reachable only through the human-gated executor)."""

from __future__ import annotations

from nabu_agent.engine import TOOLS
from nabu_agent.llm.base import ToolSpec as LLMToolSpec

# JSON-Schema parameters per tool (what the model is allowed to pass — deliberately minimal).
_PARAMS: dict[str, dict] = {
    "list_discovered_services": {"type": "object", "properties": {}, "additionalProperties": False},
    "suggest_next_steps": {"type": "object", "properties": {}, "additionalProperties": False},
    "generate_report": {"type": "object", "properties": {}, "additionalProperties": False},
    "enum_service": {
        "type": "object",
        "properties": {
            "service": {"type": "string", "description": "service name, e.g. smb/http/ssh"},
            "port": {"type": "integer", "description": "discovered port for this service"},
        },
        "required": ["service"], "additionalProperties": False,
    },
    "catalog_actions_for": {
        "type": "object",
        "properties": {
            "service": {"type": "string", "description": "service key to look up decision-aid actions for"},
            "limit": {"type": "integer"},
        },
        "required": ["service"], "additionalProperties": False,
    },
    "research_finding": {
        "type": "object",
        "properties": {"finding": {"type": "object",
                                    "description": "a finding row {kind,value,port,service,product,version}"}},
        "required": ["finding"], "additionalProperties": False,
    },
}


def schemas_for_role(allowed: frozenset[str]) -> list[LLMToolSpec]:
    """LLM tool schemas for the tools a role may call (intersection of the role allowlist, the engine
    TOOLS registry, and the tools we've defined params for)."""
    out: list[LLMToolSpec] = []
    for name, spec in TOOLS.items():
        if name in allowed and name in _PARAMS:
            out.append(LLMToolSpec(name=name, description=spec.summary, parameters=_PARAMS[name]))
    return out
