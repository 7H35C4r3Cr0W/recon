"""Pluggable authentication providers.

``AuthProvider`` is the seam; two implementations ship:
  * ``OIDCProvider`` — Authlib authorization-code flow against the org IdP, JIT-provisioning users
    keyed on (issuer, subject); the first provisioned user becomes global admin.
  * ``LocalProvider`` — argon2-hashed local accounts (sufficient for the MVP / air-gapped installs).

Which is active is chosen by ``Settings.oidc_issuer`` (empty → local only). Bodies wired in Phase 2.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class AuthResult:
    user_id: str
    email: str
    display_name: str
    is_new: bool


class AuthProvider(Protocol):
    name: str

    async def authenticate(self, **kwargs: str) -> AuthResult: ...


class LocalProvider:
    name = "local"

    async def authenticate(self, *, email: str, password: str) -> AuthResult:  # noqa: D401
        """Verify an argon2 password hash against the users table. Wired in Phase 2."""
        raise NotImplementedError


class OIDCProvider:
    name = "oidc"

    async def authenticate(self, *, code: str, state: str) -> AuthResult:
        """Exchange the authorization code, validate the ID token, JIT-provision the user."""
        raise NotImplementedError
