"""Human-in-the-loop gate for spray / exploit follow-ups.

CARDINAL RULE (from the engine safety posture): recon is fully automated; any
attack (spray/exploit) is gated behind an explicit human decision. Agents may
PROPOSE actions (from exploit.suggested_action_ids / patterns.suggest_for) but
never execute them and never auto-set exploit=True.

A proposal becomes a Checkpoint in `awaiting_approval`. approve() enforces the
double gate before execute_approved_action may run:
  1. App-wide toggle ON: config.spray_enabled (spray) or the per-action human
     confirm for exploit (exploit=True bypasses the whole policy gate, so it is
     ONLY ever carried by an explicit, operator-confirmed checkpoint).
  2. Per-run, per-action operator approval, with the exact creds chosen, and the
     target re-validated == the project's assigned scope.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC
from enum import StrEnum


class CheckpointKind(StrEnum):
    SPRAY = "spray"
    EXPLOIT = "exploit"


class CheckpointStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    EXPIRED = "expired"


@dataclass
class Checkpoint:
    id: str
    run_id: str
    kind: CheckpointKind
    target: str                      # must re-validate == profile.target before run
    action_id: str                   # exploit action id, or spray service key
    rationale: str                   # why the agent surfaced it (Scored.reasons / Suggestion)
    requires: tuple[str, ...] = ()    # advisory tags: creds/hash/domain/dc
    credential_ref: str | None = None # which vault cred the operator chose (spray)
    status: CheckpointStatus = CheckpointStatus.PROPOSED
    approved_by: str | None = None
    approved_at: str | None = None
    # For exploit only: the explicit operator confirmation that authorizes
    # exploit=True through shell.run. Never set by an agent.
    exploit_confirmed: bool = False
    audit_slug: str = field(default="")


def approve(cp: Checkpoint, *, operator: str, spray_enabled: bool) -> Checkpoint:
    """Gate 1 + gate 2. Returns the checkpoint marked APPROVED with the human approver stamped.

    The caller (``routers/runs.py``) persists the returned row to Postgres and then enqueues
    ``execute_approved_action``; ``shell_gateway.execute_gated_action`` independently re-verifies
    ``status == "approved"`` and re-validates the target against scope before any flag is set.
    Raises ``PermissionError`` if a precondition is unmet (the gate stays closed).
    """
    from datetime import datetime

    if cp.status is not CheckpointStatus.PROPOSED:
        raise PermissionError(f"checkpoint {cp.id} is {cp.status}, not proposed")
    if cp.kind is CheckpointKind.SPRAY and not spray_enabled:
        raise PermissionError("spray requires config.spray_enabled to be ON")
    if cp.kind is CheckpointKind.EXPLOIT and not cp.exploit_confirmed:
        raise PermissionError("exploit requires an explicit per-action human confirmation")
    cp.status = CheckpointStatus.APPROVED
    cp.approved_by = operator
    cp.approved_at = datetime.now(UTC).isoformat()
    return cp


def reject(cp: Checkpoint, *, operator: str) -> Checkpoint:
    """Mark a proposed checkpoint rejected. The run continues without the attack action."""
    from datetime import datetime

    cp.status = CheckpointStatus.REJECTED
    cp.approved_by = operator
    cp.approved_at = datetime.now(UTC).isoformat()
    return cp
