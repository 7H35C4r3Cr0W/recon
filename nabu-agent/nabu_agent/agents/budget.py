"""Token / step / wall-clock budgets. A run-level ceiling is reserved ATOMICALLY (Redis DECRBY
before an agent starts) so concurrent agents cannot collectively overspend; per-agent ceilings cap
any single agent. Over-budget → the agent stops cleanly with ``stopped_reason='budget'``.
"""

from __future__ import annotations

from dataclasses import dataclass

from nabu_agent.llm.errors import LLMBudgetExceeded


@dataclass(frozen=True)
class BudgetPolicy:
    max_tokens_per_agent: int = 60_000
    max_steps_per_agent: int = 12
    agent_wall_clock_s: int = 900


class BudgetStore:
    """Run-level atomic token reservation, backed by Redis (DECRBY). Wired in Phase 3."""

    def __init__(self, run_id: str, run_ceiling_tokens: int) -> None:
        self.run_id = run_id
        self.run_ceiling = run_ceiling_tokens

    async def reserve(self, tokens: int) -> None:
        """Atomically debit the run-level ceiling before an agent starts; raise if exhausted."""
        raise NotImplementedError

    @staticmethod
    def check_agent(spent_tokens: int, steps: int, policy: BudgetPolicy) -> None:
        """Per-agent guard — raises :class:`LLMBudgetExceeded` when a ceiling is crossed."""
        if spent_tokens > policy.max_tokens_per_agent:
            raise LLMBudgetExceeded("per-agent token ceiling exceeded")
        if steps > policy.max_steps_per_agent:
            raise LLMBudgetExceeded("per-agent step ceiling exceeded")
