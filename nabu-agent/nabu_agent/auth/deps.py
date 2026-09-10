"""FastAPI auth dependencies: current-user resolution, RBAC guards, CSRF.

These are the decorators routers depend on. ``require_project_role`` also loads the project's gate
flags so a spray/exploit run can be refused early (RBAC is necessary, not sufficient). Wired Phase 2.
"""

from __future__ import annotations

from nabu_agent.rbac import Perm, ProjectRole, Role


async def get_current_user() -> str:
    """Resolve the session cookie → user id, or raise 401. Wired in Phase 2."""
    raise NotImplementedError


def require_role(role: Role):  # noqa: ANN201 - FastAPI dependency factory
    """Dependency factory asserting a minimum global role."""
    async def _dep() -> str:
        raise NotImplementedError
    return _dep


def require_project_role(perm: Perm, min_role: ProjectRole = ProjectRole.VIEWER):  # noqa: ANN201
    """Dependency factory asserting the caller has ``perm`` on the path's project."""
    async def _dep() -> str:
        raise NotImplementedError
    return _dep


async def csrf_protect() -> None:
    """Double-submit CSRF check for unsafe methods. Wired in Phase 2."""
    raise NotImplementedError
