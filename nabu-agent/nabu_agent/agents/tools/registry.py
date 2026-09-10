"""ToolRegistry — unifies engine.TOOLS into the LLM tool-schema list per role (Phase 3).

Builds the OpenAI tool/function schema (name, description, JSON-Schema params) from the engine's
ToolSpec registry, filtered to a role's allowlist. No spray/exploit tool is ever exposed.
"""

from __future__ import annotations

from nabu_agent.engine import TOOLS
from nabu_agent.llm.base import ToolSpec as LLMToolSpec


def schemas_for_role(allowed: frozenset[str]) -> list[LLMToolSpec]:
    """Return LLM tool schemas for the tools a role may call. Param schemas filled in Phase 3."""
    return [
        LLMToolSpec(name=name, description=spec.summary, parameters={"type": "object", "properties": {}})
        for name, spec in TOOLS.items() if name in allowed
    ]
