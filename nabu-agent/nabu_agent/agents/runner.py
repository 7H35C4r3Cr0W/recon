"""AgentRunner — the LLM tool-calling loop (Phase 3).

assemble context → call provider (stream to the event bus) → on finish_reason=="tool_calls":
validate each call against the role's ToolRegistry → SafetyGate.check → dispatch through the engine
chokepoint (run_recon_tool) → append the tool result as an untrusted-data message → repeat, bounded
by the BudgetPolicy. A turn whose tool call has been dispatched is never replayed on retry.
"""

from __future__ import annotations


class AgentRunner:
    def __init__(self, role: str, run_id: str) -> None:
        self.role = role
        self.run_id = run_id

    async def run(self, context: dict) -> dict:
        raise NotImplementedError
