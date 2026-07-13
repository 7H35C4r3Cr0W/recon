from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

# why: offline access to the vendored HackTricks network-services snapshot (CLAUDE.md § 2a / § 27).
# Pure file reads — NO network at runtime. `references/hacktricks/refresh.py` (maintainer-run) is
# the only fetcher; this loader serves what was vendored, plus the live URL to link out to.

_DIR = Path(__file__).parent / "references" / "hacktricks"
_INDEX = _DIR / "index.json"


@dataclass(frozen=True)
class HacktricksPage:
    module: str
    title: str
    url: str  # the live HackTricks page — always surfaced so the user can view it themselves
    markdown: str  # the vendored offline content


def load_index() -> dict[str, dict[str, str]]:
    try:
        data = json.loads(_INDEX.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): value for key, value in data.items() if isinstance(value, dict)}


def available_modules() -> list[str]:
    return sorted(load_index())


def page_for_module(module: str) -> HacktricksPage | None:
    entry = load_index().get(module)
    if entry is None:
        return None
    try:
        markdown = (_DIR / str(entry.get("file", ""))).read_text(encoding="utf-8")
    except OSError:
        return None
    return HacktricksPage(
        module=module,
        title=str(entry.get("title", module)),
        url=str(entry.get("url", "")),
        markdown=markdown,
    )
