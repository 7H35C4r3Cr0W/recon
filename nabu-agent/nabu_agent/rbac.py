"""Role-based access control.

Two levels: a global :class:`Role` (admin / operator / viewer) and a per-project
:class:`ProjectRole` (owner / operator / viewer). One static capability matrix; ``can()`` is the
single decision point. Note the hard rule: creating a spray/exploit RUN needs the RIGHT role AND
the per-project gate toggle AND a human-approved checkpoint — RBAC is necessary, not sufficient
(the gate + checkpoint are enforced in ``routers/runs.py`` and ``engine/shell_gateway.py``).
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class ProjectRole(StrEnum):
    OWNER = "owner"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Perm(StrEnum):
    PROJECT_CREATE = "project.create"
    PROJECT_EDIT = "project.edit"
    PROJECT_VIEW = "project.view"
    SCOPE_EDIT = "scope.edit"
    RUN_START = "run.start"
    RUN_CANCEL = "run.cancel"
    RUN_VIEW = "run.view"
    CHECKPOINT_DECIDE = "checkpoint.decide"     # approve/reject a spray/exploit gate
    CREDS_VIEW = "creds.view"
    SETTINGS_EDIT = "settings.edit"             # incl. flipping spray/exploit gates
    USER_ADMIN = "user.admin"
    AUDIT_VIEW = "audit.view"


# Per-project capabilities by project role.
_PROJECT_MATRIX: dict[ProjectRole, frozenset[Perm]] = {
    ProjectRole.OWNER: frozenset(Perm),
    ProjectRole.OPERATOR: frozenset({
        Perm.PROJECT_VIEW, Perm.SCOPE_EDIT, Perm.RUN_START, Perm.RUN_CANCEL, Perm.RUN_VIEW,
        Perm.CHECKPOINT_DECIDE, Perm.CREDS_VIEW, Perm.AUDIT_VIEW,
    }),
    ProjectRole.VIEWER: frozenset({Perm.PROJECT_VIEW, Perm.RUN_VIEW, Perm.AUDIT_VIEW}),
}


def can(project_role: ProjectRole, perm: Perm, *, global_role: Role = Role.OPERATOR) -> bool:
    """True if the (project role, global role) pair grants ``perm``.

    A global ADMIN is granted everything; USER_ADMIN + SETTINGS_EDIT at the *global* scope require
    the admin global role regardless of project role.
    """
    if global_role is Role.ADMIN:
        return True
    if perm in {Perm.USER_ADMIN}:
        return False
    return perm in _PROJECT_MATRIX.get(project_role, frozenset())
