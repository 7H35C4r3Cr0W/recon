"""Authentication providers. LocalProvider (argon2) ships working for the MVP; OIDCProvider is
scaffolded for Phase 4. Selection is by ``Settings.oidc_issuer`` (empty → local)."""

from __future__ import annotations

from dataclasses import dataclass

import structlog
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher()
_log = structlog.get_logger("nabu_agent.auth")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(hash_: str, password: str) -> bool:
    """True iff the password matches. A genuine mismatch returns False silently; any OTHER failure
    (corrupt stored hash, argon2 backend error) is logged before failing closed, so a subsystem
    fault is visible instead of masquerading as 'wrong password'."""
    try:
        return _ph.verify(hash_, password)
    except VerifyMismatchError:
        return False
    except Exception:  # corrupt hash / backend failure — fail closed, but make it visible
        _log.warning("password-verify-error", exc_info=True)
        return False


@dataclass(frozen=True)
class AuthResult:
    user_id: str
    email: str
    display_name: str
    is_new: bool = False


class OIDCProvider:
    name = "oidc"

    async def authenticate(self, *, code: str, state: str) -> AuthResult:  # pragma: no cover
        raise NotImplementedError("OIDC wired in Phase 4")
