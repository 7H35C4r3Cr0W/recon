from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from oscprecon.models import Credential

SCHEMA_VERSION = 1


def redact(secret: str) -> str:
    # Owner policy (2026-07-22): NEVER redact by default — the credential IS the deliverable, so
    # reports/exports show the full value. Only masks when shell.REDACT_SECRETS is flipped on.
    from oscprecon import shell

    if not shell.REDACT_SECRETS:
        return secret
    return f"<redacted len={len(secret)}>"


def _to_dict(cred: Credential) -> dict[str, Any]:
    return {
        "username": cred.username,
        "domain": cred.domain,
        "secret_type": cred.secret_type,
        "secret": cred.secret,
        "source": cred.source,
        "tested_against": list(cred.tested_against),
        "notes": cred.notes,
    }


def _from_dict(data: dict[str, Any]) -> Credential:
    tested = data.get("tested_against", [])
    return Credential(
        username=str(data.get("username", "")),
        secret=str(data.get("secret", "")),
        secret_type=str(data.get("secret_type", "password")),
        domain=str(data.get("domain", "")),
        source=str(data.get("source", "")),
        tested_against=[str(t) for t in tested] if isinstance(tested, list) else [],
        notes=str(data.get("notes", "")),
    )


def load_creds(path: Path) -> list[Credential]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    entries = data.get("entries", [])
    if not isinstance(entries, list):
        return []
    return [_from_dict(entry) for entry in entries if isinstance(entry, dict)]


def save_creds(path: Path, credentials: list[Credential]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "entries": [_to_dict(cred) for cred in credentials],
    }
    data = json.dumps(payload, indent=2).encode("utf-8")
    # why: the TEMP file holds the plaintext secret first — use a per-writer UNIQUE temp (mkstemp
    # creates at 0600, not the process umask which is often world-readable); a fixed <name>.tmp
    # shared by two concurrent writers interleaves bytes and corrupts creds.json behind the atomic
    # replace. Force 0600, write, atomically replace. On ANY failure, drop the partial temp and
    # re-raise: the prior valid creds.json is left untouched.
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, data)
        finally:
            os.close(fd)
        os.replace(tmp_name, path)  # atomic — only swaps in once the full write succeeded
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def cred_key(cred: Credential) -> tuple[str, str, str, str]:
    # identity of a stored credential — dedup + in-place edit key (username, domain, secret, source)
    return (cred.username, cred.domain, cred.secret, cred.source)


_key = cred_key  # internal alias (kept for existing call sites)


def add_credential(path: Path, cred: Credential) -> list[Credential]:
    credentials = load_creds(path)
    if any(_key(existing) == _key(cred) for existing in credentials):
        return credentials
    credentials.append(cred)
    save_creds(path, credentials)
    return credentials


def delete_credential(path: Path, cred: Credential) -> list[Credential]:
    # why: the vault is user-editable (add/edit/delete) for the spray workflow (§2a). Edit = the GUI
    # deletes then re-adds. Matches on the identity key so an exact entry is removed.
    remaining = [existing for existing in load_creds(path) if _key(existing) != _key(cred)]
    save_creds(path, remaining)
    return remaining
