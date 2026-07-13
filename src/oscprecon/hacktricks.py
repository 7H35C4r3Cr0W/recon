from __future__ import annotations

import json
import re
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


# mdBook / HackTricks markdown that Qt's CommonMark renderer shows as literal noise. We normalise it
# to plain markdown for a cleaner offline render; the loader still returns raw text, so this is a
# presentation-only pass applied at the render boundary.
_CALLOUT_RE = re.compile(r"^(\s*>\s*)\[!(\w+)\]\s*$", re.MULTILINE)
_SUMMARY_RE = re.compile(r"<summary>(.*?)</summary>", re.DOTALL | re.IGNORECASE)
_DETAILS_RE = re.compile(r"</?details>", re.IGNORECASE)
_FIGURE_RE = re.compile(r"<figure>.*?</figure>", re.DOTALL | re.IGNORECASE)
_IMG_RE = re.compile(r"<img[^>]*>", re.IGNORECASE)


def clean_markdown(md: str) -> str:
    # GitHub callouts (> [!TIP]) -> a bold label line so the note reads instead of showing "[!TIP]".
    md = _CALLOUT_RE.sub(lambda m: f"{m.group(1)}**{m.group(2).capitalize()}**", md)
    # collapsible blocks: keep the summary as a bold heading, drop the non-rendering <details> tags.
    md = _SUMMARY_RE.sub(lambda m: f"\n**{m.group(1).strip()}**\n", md)
    md = _DETAILS_RE.sub("", md)
    # offline: external figures/images can't load with no network -> remove them.
    md = _FIGURE_RE.sub("", md)
    md = _IMG_RE.sub("", md)
    return md


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
