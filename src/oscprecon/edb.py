from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oscprecon.references import ExploitHit

# why: lookup-only per §14. We persist the Exploit-DB *reference* (EDB-ID, title, canonical URL) so
# the report can cite what searchsploit surfaced — NEVER the local PoC path or the exploit content.
# There is no "run"/"copy" path from this store; it is a citation record, nothing more.


def edb_path(profile_dir: Path) -> Path:
    return Path(profile_dir) / "edb.json"


def load_edb(profile_dir: Path) -> list[dict[str, Any]]:
    path = edb_path(profile_dir)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def _key(entry: dict[str, Any]) -> tuple[Any, ...]:
    # the searchsploit query is (product, version); re-selecting a service must not duplicate hits.
    return (entry.get("edb_id"), entry.get("product"), entry.get("version"))


def add_edb(
    profile_dir: Path, *, service: str, product: str, version: str, hits: list[ExploitHit]
) -> list[dict[str, Any]]:
    existing = load_edb(profile_dir)
    seen = {_key(entry) for entry in existing}
    stamp = datetime.now(UTC).isoformat()
    changed = False
    for hit in hits:
        entry = {
            "service": service,
            "product": product,
            "version": version,
            "edb_id": hit.edb_id,
            "title": hit.title,
            "url": hit.url,  # canonical exploit-db.com page — lookup only, no PoC path stored
            "discovered_at": stamp,
        }
        if _key(entry) in seen:
            continue
        seen.add(_key(entry))
        existing.append(entry)
        changed = True
    if changed:
        path = edb_path(profile_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        tmp.replace(path)
    return existing
