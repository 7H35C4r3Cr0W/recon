"""Platform audit log — WHO did WHAT in the app.

Distinct from the engine's per-project ``audit.jsonl`` (WHAT ran against a target). This trail
records logins/logouts/failures, project/scope/settings/member changes, run start/cancel, checkpoint
decisions, downloads, and every DENIED authorization. Rows land in the Postgres ``audit_log`` table
(see ``db/models.py``); this module is the thin writer the routers call.

Bodies are wired to the DB session in Phase 1; the slug vocabulary is fixed here so the timeline is
consistent across the app.
"""

from __future__ import annotations

from typing import Any

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
RUN_STARTED = "run-started"
RUN_CANCELLED = "run-cancelled"
CHECKPOINT_DECIDED = "checkpoint-decided"
ARTIFACT_DOWNLOADED = "artifact-downloaded"
AUTHZ_DENIED = "authz-denied"


async def record(
    session: Any,
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
    """Append one row to the platform ``audit_log`` table (best-effort; never fails the request).

    Wired to the SQLAlchemy session in Phase 1 (``INSERT INTO audit_log ...``). The signature is the
    contract every router codes against.
    """
    raise NotImplementedError
