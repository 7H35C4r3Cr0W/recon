"""Typed errors for the engine adapter.

These map to stable API error codes so the agent/LLM layer and the HTTP layer can
branch on *why* a tool refused, without catching engine internals.
"""

from __future__ import annotations


class EngineAdapterError(Exception):
    """Base class for all adapter-raised errors. Carries a stable ``code``."""

    code = "engine_error"


class ProjectNotFound(EngineAdapterError):
    code = "project_not_found"


class ScopeViolation(EngineAdapterError):
    """Target is not the project's assigned, validated scope.

    This is the scope-lock. It is raised BEFORE any tool is built or executed.
    """

    code = "scope_violation"


class InvalidTarget(EngineAdapterError):
    """Target failed engine validation (models.validate_host* raised)."""

    code = "invalid_target"


class ToolBlocked(EngineAdapterError):
    """shell.run refused the command via the policy gate (exit 126 / .blocked)."""

    code = "tool_blocked"


class ToolMissing(EngineAdapterError):
    """Required binary not on PATH (exit 127 / .missing_tool)."""

    code = "tool_missing"


class ReadOnlyProject(EngineAdapterError):
    """The engine Profile is read-only (its .lock is held elsewhere)."""

    code = "read_only_project"


class AttackGateClosed(EngineAdapterError):
    """An attack path (spray/exploit) was requested but is not human-gated open.

    The recon adapter NEVER opens this gate itself; it exists so the separate,
    human-gated attack endpoint can raise a consistent error.
    """

    code = "attack_gate_closed"


class AutonomyViolation(EngineAdapterError):
    """An agent path attempted something only a confirmed human may do (spray / exploit).

    Distinct from AttackGateClosed: this is raised when the *autonomy boundary* itself is crossed
    (an agent tried to set a gate flag), whereas AttackGateClosed means a human-gated action was
    requested without a valid approved checkpoint.
    """

    code = "autonomy_violation"


class CheckpointNotApproved(EngineAdapterError):
    """A gated action referenced a checkpoint that is not human-approved."""

    code = "checkpoint_not_approved"
