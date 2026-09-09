"""ToolDispatcher — routes a validated tool call to the engine, through the recon chokepoint only.

NEVER sets exploit/spray (there is no parameter). Parses+validates the model's JSON arguments,
resolves the project → Profile (scope from the DB, not the LLM), and calls the engine tool. Blocking
engine calls run in a threadpool. Wired in Phase 3.
"""

from __future__ import annotations


async def dispatch(tool_name: str, arguments: dict, *, project_id: str, run_id: str) -> dict:
    raise NotImplementedError
