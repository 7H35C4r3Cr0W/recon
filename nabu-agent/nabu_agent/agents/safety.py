"""SafetyGate — seam-level enforcement between the LLM's proposed tool calls and execution.

This is defence-in-depth in CODE (the system-prompt preamble is only advisory). Before any tool
call the runner proposes is dispatched, the gate enforces:

  * **Per-role tool allowlist** — an agent may only call the tools its role is granted.
  * **Absolute exploit ban** — any tool call carrying an ``exploit``-shaped argument is BLOCKED
    outright; the recon tools do not expose one, so this catches a hallucinated/injected attempt.
  * **Scope-lock** — target arguments are validated + confirmed in scope via the single
    ``shell_gateway.assert_in_scope`` (no second implementation).
  * **Spray double-gate** — a spray-shaped proposal never runs inline; it is turned into a
    ``needs_approval`` outcome (a Checkpoint proposal), never executed by an agent.
"""

from __future__ import annotations

from dataclasses import dataclass

from nabu_agent.engine.errors import AutonomyViolation, ScopeViolation

# argument names that must never appear in an agent-proposed tool call
_BANNED_ARG_TOKENS = {"exploit", "spray"}


@dataclass(frozen=True)
class GateResult:
    allowed: bool
    reason: str = ""
    needs_approval: bool = False


class SafetyGate:
    def __init__(self, allowed_tools: frozenset[str]) -> None:
        self._allowed = allowed_tools

    def check(self, tool_name: str, arguments: dict) -> GateResult:
        """Decide whether a proposed tool call may be dispatched. Never executes anything."""
        if tool_name not in self._allowed:
            return GateResult(False, f"tool {tool_name!r} not permitted for this role")
        for key, value in arguments.items():
            if key.lower() in _BANNED_ARG_TOKENS and value:
                # An agent tried to set a gate flag — the autonomy boundary. Hard block.
                raise AutonomyViolation(f"agent attempted to set {key}=True (blocked by SafetyGate)")
        return GateResult(True)

    @staticmethod
    def assert_scope(profile, target: str, allowlist=None) -> str:
        """Delegate to the ONE scope function — never a second implementation."""
        from nabu_agent.engine import shell_gateway
        try:
            return shell_gateway.assert_in_scope(profile, target, allowlist=allowlist)
        except ScopeViolation:
            raise
