"""Encrypt/decrypt secrets kept in the DB — currently the admin-entered LLM API key.

Symmetric (Fernet), keyed off ``NABU_SESSION_SECRET`` (already required in production), so there is
no extra secret to manage and the key never leaves the process. The plaintext is never logged and
never returned by the API. If the session secret changes, previously-stored ciphertext no longer
decrypts (``decrypt`` returns "" and the admin simply re-enters the key) — safe by design.
"""
from __future__ import annotations

import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

_DEV_FALLBACK = "nabu-dev-insecure-config-key"  # only used when no session secret is set (dev/tests)


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    from nabu_agent.settings import get_settings

    secret = get_settings().session_secret.get_secret_value() or _DEV_FALLBACK
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    """Return the Fernet token for ``plaintext`` (empty string in → empty string out)."""
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    """Return the plaintext for a Fernet ``token``; "" if empty or undecryptable (never raises)."""
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return ""


def reset_cache() -> None:
    """Drop the cached Fernet (call after the session secret changes; used by tests)."""
    _fernet.cache_clear()
