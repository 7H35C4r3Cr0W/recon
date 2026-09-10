"""OpenID Connect (SSO) login via Authlib.

Standard authorization-code flow against the org IdP: the browser is redirected to the IdP, comes
back with a code, we exchange it for tokens, validate the ID token, and JIT-provision a local user
keyed on (issuer, subject). Discovery is automatic from ``<issuer>/.well-known/openid-configuration``.

The transient OAuth state/nonce live in a short-lived signed cookie (Starlette SessionMiddleware,
added in main.py) for the redirect round-trip; the durable post-login session is our own Redis
session (auth/sessions.py). Local password login keeps working alongside this.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.db.models import User
from nabu_agent.settings import get_settings

_log = structlog.get_logger("nabu_agent.oidc")
_oauth = None


def is_configured() -> bool:
    return bool(get_settings().oidc_issuer)


def get_oauth():
    """Cached Authlib OAuth registry with the 'oidc' client registered from settings."""
    global _oauth
    if _oauth is None:
        from authlib.integrations.starlette_client import OAuth

        s = get_settings()
        oauth = OAuth()
        oauth.register(
            name="oidc",
            client_id=s.oidc_client_id,
            client_secret=s.oidc_client_secret.get_secret_value(),
            server_metadata_url=f"{s.oidc_issuer.rstrip('/')}/.well-known/openid-configuration",
            client_kwargs={"scope": s.oidc_scopes},
        )
        _oauth = oauth
    return _oauth


def client():
    """The registered OIDC client (mockable seam for tests)."""
    return get_oauth().create_client("oidc")


async def provision_user(db: AsyncSession, *, issuer: str, subject: str, email: str,
                         name: str = "") -> User:
    """Find-or-create the local user for an OIDC identity, keyed on (issuer, subject).

    First provisioned user becomes a global admin when ``oidc_first_user_admin`` is on (so an SSO-only
    deployment has an initial admin). Idempotent; updates last_login_at.
    """
    user = (await db.execute(select(User).where(
        User.oidc_issuer == issuer, User.oidc_subject == subject))).scalar_one_or_none()
    if user is None and email:
        # link an existing local account with the same email, if any (avoids a duplicate)
        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if user is not None:
            user.oidc_issuer, user.oidc_subject = issuer, subject
    if user is None:
        any_user = (await db.execute(select(User).limit(1))).scalar_one_or_none()
        role = "admin" if (any_user is None and get_settings().oidc_first_user_admin) else "viewer"
        user = User(email=email or f"{subject}@{issuer}", display_name=name or email or subject,
                    role=role, auth_source="oidc", oidc_issuer=issuer, oidc_subject=subject)
        db.add(user)
        _log.info("oidc-user-provisioned", email=user.email, role=role, issuer=issuer)
    user.last_login_at = datetime.now(UTC)
    if not user.is_active:
        user.is_active = True
    await db.commit()
    return user
