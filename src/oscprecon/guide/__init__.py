"""User-facing documentation ("the guide"), bundled with the package.

One source of truth for both surfaces: the GUI Help → Documentation dialog and the `nabu-cli docs`
command read the same ordered manifest + markdown pages. Engine-level and GUI-free (no Qt), so the
CLI can use it headless. Pages live in `guide/pages/*.md` and ship in the wheel.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_PAGES_DIR = Path(__file__).parent / "pages"


@dataclass(frozen=True)
class Topic:
    id: str  # slug + markdown filename stem
    title: str  # display title (TOC entry / CLI list)
    summary: str  # one-line description (CLI list + TOC tooltip)


# ordered table of contents — the single source of truth for the GUI TOC and the CLI listing
TOPICS: tuple[Topic, ...] = (
    Topic("overview", "Overview", "What Nabu is and what it does"),
    Topic("getting-started", "Getting started", "Install, first scan, and the workspace"),
    Topic("recon", "The recon workflow", "Staged nmap, the three panes, and service modules"),
    Topic("graph", "The attack-surface graph", "Reading and driving the BloodHound-style graph"),
    Topic(
        "exploitation",
        "Exploitation & spraying",
        "The human-confirmed attack surface and cred spray",
    ),
    Topic(
        "reports", "Reports, vault & Obsidian", "report.md, the credential vault, and vault export"
    ),
    Topic("safety", "Safety & OSCP compliance", "Why the default mode is exam-legal"),
    Topic("shortcuts", "Keyboard shortcuts", "Every keybinding in the GUI"),
)

_BY_ID = {t.id: t for t in TOPICS}


def topics() -> tuple[Topic, ...]:
    """The ordered guide table of contents."""
    return TOPICS


def get(topic_id: str) -> Topic | None:
    return _BY_ID.get(topic_id)


def load(topic_id: str) -> str:
    """Markdown source for a topic. Raises KeyError for an unknown id."""
    topic = _BY_ID.get(topic_id)
    if topic is None:
        raise KeyError(topic_id)
    return (_PAGES_DIR / f"{topic.id}.md").read_text(encoding="utf-8")


def resolve(query: str) -> Topic | None:
    """Find a topic by exact id, then by a case-insensitive title/id prefix (for the CLI)."""
    q = query.strip().lower()
    if q in _BY_ID:
        return _BY_ID[q]
    for topic in TOPICS:
        if topic.id.startswith(q) or topic.title.lower().startswith(q):
            return topic
    return None
