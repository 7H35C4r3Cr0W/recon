from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from oscprecon.models import Credential

SCHEMA_VERSION = 1


def redact(secret: str) -> str:
    # why: reports/logs must never carry plaintext secrets (§6) — length only.
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
    # why: secrets on disk are chmod 600 and written atomically (temp + replace) so a reader
    # never sees a half-written file and the mode is set before the file becomes visible.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _key(cred: Credential) -> tuple[str, str, str, str]:
    return (cred.username, cred.domain, cred.secret, cred.source)


def add_credential(path: Path, cred: Credential) -> list[Credential]:
    credentials = load_creds(path)
    if any(_key(existing) == _key(cred) for existing in credentials):
        return credentials
    credentials.append(cred)
    save_creds(path, credentials)
    return credentials
