"""SafetyGate — seam-level enforcement between the LLM's proposed tool calls and execution.

This is defence-in-depth in CODE (the system-prompt preamble is only advisory). Before any tool
call the runner proposes is dispatched, the gate enforces:

  * **Per-role tool allowlist** — an agent may only call the tools its role is granted.
  * **Absolute exploit/spray ban** — any tool call carrying an ``exploit``- or ``spray``-shaped
    argument is BLOCKED outright (raises ``AutonomyViolation``); the recon tools do not expose one,
    so this catches a hallucinated/injected attempt. Agents never execute attacks — full stop.

Scope-lock is NOT applied here: the LLM cannot set a target (the tool schemas expose no host/target
field — the run's resolved, already-in-scope host is passed by the dispatcher), and the engine tools
re-assert scope via ``shell_gateway.assert_in_scope`` before ``shell.run``. This gate is the
tool-allowlist + attack-argument backstop, not the scope authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from nabu_agent.engine.errors import AutonomyViolation

# argument names that must never appear in an agent-proposed tool call
_BANNED_ARG_TOKENS = {"exploit", "spray"}


@dataclass(frozen=True)
class GateResult:
    allowed: bool
    reason: str = ""


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
