"""Authentication providers. LocalProvider (argon2) ships working for the MVP; OIDCProvider is
scaffolded for Phase 4. Selection is by ``Settings.oidc_issuer`` (empty → local)."""

from __future__ import annotations

from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(hash_: str, password: str) -> bool:
    try:
        return _ph.verify(hash_, password)
    except (VerifyMismatchError, Exception):
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
