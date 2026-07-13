from __future__ import annotations

import re
from dataclasses import dataclass

# Local, deterministic section extraction over a HackTricks markdown page (vendored OR live-cached).
# The selection uses only LOCAL service context (finding kinds, product, version) to CHOOSE which
# already-fetched sections to surface — nothing is ever sent to a server (CLAUDE.md §14a).

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_GENERAL_HINTS = ("enumeration", "basic information")


@dataclass(frozen=True)
class Section:
    level: int
    heading: str
    body: str  # the heading line's content plus everything down to the next heading


def split_sections(markdown: str) -> list[Section]:
    # Fence-aware: a heading inside a ``` code block never starts a new section, so code isn't cut.
    sections: list[Section] = []
    lines = markdown.splitlines()
    in_fence = False
    cur_level = 0
    cur_heading = ""
    cur_body: list[str] = []
    preamble: list[str] = []

    def flush() -> None:
        if cur_heading or cur_body:
            sections.append(Section(cur_level, cur_heading, "\n".join(cur_body).strip()))

    for line in lines:
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            (cur_body if cur_heading or sections else preamble).append(line)
            continue
        match = None if in_fence else _HEADING_RE.match(line)
        if match is not None:
            if cur_heading or cur_body:
                flush()
            elif preamble and any(p.strip() for p in preamble):
                sections.append(Section(0, "", "\n".join(preamble).strip()))
            preamble = []
            cur_level = len(match.group(1))
            cur_heading = match.group(2).strip()
            cur_body = [line]
        elif cur_heading:
            cur_body.append(line)
        else:
            preamble.append(line)
    if cur_heading or cur_body:
        flush()
    elif preamble and any(p.strip() for p in preamble):
        sections.append(Section(0, "", "\n".join(preamble).strip()))
    return sections


def relevant_sections(
    markdown: str,
    *,
    keywords: list[str],
    product: str = "",
    version: str = "",
    limit: int = 4,
) -> list[Section]:
    # Priority (CLAUDE.md §14a): finding-kind headings -> product -> version -> service-general ->
    # page start. Deterministic (document order within each tier); never merges unrelated sections.
    sections = split_sections(markdown)
    if not sections:
        return []
    picked: list[Section] = []
    seen: set[tuple[int, str]] = set()

    def add(section: Section) -> None:
        key = (section.level, section.heading)
        if key not in seen:
            seen.add(key)
            picked.append(section)

    for keyword in keywords:
        low = keyword.lower()
        for section in sections:
            if low and low in section.heading.lower():
                add(section)
    if product:
        low = product.lower()
        for section in sections:
            if low in section.heading.lower() or low in section.body.lower():
                add(section)
    if version:
        for section in sections:
            if version in section.body:
                add(section)
    for section in sections:
        if any(hint in section.heading.lower() for hint in _GENERAL_HINTS):
            add(section)
    if not picked:
        add(sections[0])
    return picked[:limit]
