"""Resolve a vault credential by the opaque id the API exposes, and map it onto catalog placeholder
names for the gated attack path. The plaintext secret is read from the on-disk vault (creds.json)
only at execute time — it is NEVER stored on a checkpoint and NEVER emitted to the event stream.
"""
from __future__ import annotations

import hashlib
from typing import Any


def credential_cid(cred: Any) -> str:
    """The opaque, stable id the creds API exposes (sha1 of the engine's identity key, truncated).
    Kept identical to ``routers/creds.py`` so an id from the vault list resolves back here."""
    from oscprecon.creds import cred_key

    return hashlib.sha1("|".join(cred_key(cred)).encode()).hexdigest()[:12]


def resolve_credential(profile: Any, ref: str | None) -> Any | None:
    """The vault credential whose id == ``ref`` (or None). Reads creds.json via the profile."""
    if not ref:
        return None
    for cred in profile.credentials():
        if credential_cid(cred) == ref:
            return cred
    return None


def credential_values(cred: Any, *, redact: bool = False) -> dict[str, str]:
    """Map a credential onto the catalog placeholder names (``{user}``/``{password}``/``{hash}``/
    ``{domain}`` …). With ``redact=True`` the secret is replaced by an ALWAYS-ON mask so the value
    can be shown in a preview without leaking the plaintext — deliberately not the engine's
    ``creds.redact`` (which is a no-op unless a global report flag is set; this platform's API never
    exposes secret values). The mask is non-empty, so the template fills identically either way —
    preview and execution agree on what's runnable."""
    shown = f"<{(cred.secret_type or 'secret').lower()}:redacted>" if redact else cred.secret
    vals: dict[str, str] = {"user": cred.username, "username": cred.username}
    if cred.domain:
        vals["domain"] = cred.domain
    if (cred.secret_type or "password").lower() in ("hash", "ntlm", "nthash", "nt"):
        vals.update({"hash": shown, "ntlm": shown, "nthash": shown})
    else:
        vals.update({"password": shown, "pass": shown})
    vals["secret"] = shown
    return {k: v for k, v in vals.items() if v}
