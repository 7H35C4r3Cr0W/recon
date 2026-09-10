"""Platform audit log — WHO did WHAT in the app.

Distinct from the engine's per-project ``audit.jsonl`` (WHAT ran against a target). This trail
records logins/logouts/failures, project/scope/settings/member changes, run start/cancel, checkpoint
decisions, downloads, and every DENIED authorization. Rows land in the Postgres ``audit_log`` table
(see ``db/models.py``); this module is the thin writer the routers call.

record() writes rows via its own short-lived session; the slug vocabulary is fixed here so the
timeline is consistent across the app.
"""

from __future__ import annotations

import contextlib
from typing import Any

import structlog

_log = structlog.get_logger("nabu_agent.audit")

# kebab slugs (kept stable — the UI + reports group on them)
LOGIN = "login"
LOGIN_FAILED = "login-failed"
LOGOUT = "logout"
PROJECT_CREATED = "project-created"
PROJECT_UPDATED = "project-updated"
PROJECT_DELETED = "project-deleted"
SCOPE_ADDED = "scope-added"
SCOPE_REMOVED = "scope-removed"
SCOPE_PROMOTED = "scope-promoted"
SETTINGS_CHANGED = "settings-changed"
MEMBER_CHANGED = "member-changed"
USER_CREATED = "user-created"
USER_UPDATED = "user-updated"
RUN_STARTED = "run-started"
RUN_CANCELLED = "run-cancelled"
CHECKPOINT_DECIDED = "checkpoint-decided"
ARTIFACT_DOWNLOADED = "artifact-downloaded"
AUTHZ_DENIED = "authz-denied"


async def record(
    *,
    actor_user_id: str | None,
    action: str,
    result: str = "success",
    object_type: str | None = None,
    object_id: str | None = None,
    project_id: str | None = None,
    actor_ip: str | None = None,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Append one row to the platform ``audit_log`` table. BEST-EFFORT — it opens its OWN short-lived
    session and commits independently (so the trail is durable even if the request's own transaction
    later rolls back) and NEVER raises: a broken audit write must not break the action it records."""
    from nabu_agent.db.models import AuditLog
    from nabu_agent.db.session import sessionmaker

    try:
        async with sessionmaker()() as db:
            db.add(AuditLog(actor_user_id=actor_user_id, action=action, result=result,
                            object_type=object_type, object_id=object_id, project_id=project_id,
                            actor_ip=actor_ip, request_id=request_id, details=details or {}))
            await db.commit()
    except Exception:  # audit must never break the request it is recording
        with contextlib.suppress(Exception):
            _log.warning("audit-write-failed", action=action, actor=actor_user_id, exc_info=True)
