from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# user-controlled workspace status (orthogonal to profile.status.state lifecycle timestamps).
# "archived" is a separate boolean, not a status — an archived profile keeps its status.
STATUSES: tuple[str, ...] = ("new", "active", "needs-review", "blocked", "completed")
DEFAULT_STATUS = "active"

_MAX_TAG_LEN = 40
_MAX_TAGS = 30
_MAX_DISPLAY_NAME = 120


def normalize_status(value: object) -> str:
    slug = str(value or "").strip().lower().replace(" ", "-")
    return slug if slug in STATUSES else DEFAULT_STATUS


def normalize_tag(value: object) -> str | None:
    # collapse whitespace, trim, cap length; an empty tag is rejected (returns None).
    tag = " ".join(str(value or "").split())
    if not tag:
        return None
    return tag[:_MAX_TAG_LEN]


def normalize_tags(values: object) -> list[str]:
    # dedup case-insensitively while preserving the first display form; cap the count.
    out: list[str] = []
    seen: set[str] = set()
    if not isinstance(values, list):
        return out
    for raw in values:
        tag = normalize_tag(raw)
        if tag is None:
            continue
        key = tag.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(tag)
        if len(out) >= _MAX_TAGS:
            break
    return out


def normalize_display_name(value: object) -> str:
    return " ".join(str(value or "").split())[:_MAX_DISPLAY_NAME]


@dataclass
class Organization:
    """User-controlled organizational metadata stored under profile.json `organization`."""

    status: str = DEFAULT_STATUS
    tags: list[str] = field(default_factory=list)
    pinned: bool = False
    archived: bool = False
    display_name: str = ""

    @classmethod
    def from_dict(cls, data: object) -> Organization:
        # tolerant: unknown fields ignored, wrong types coerced to safe defaults.
        if not isinstance(data, dict):
            return cls()
        return cls(
            status=normalize_status(data.get("status")),
            tags=normalize_tags(data.get("tags")),
            pinned=bool(data.get("pinned", False)),
            archived=bool(data.get("archived", False)),
            display_name=normalize_display_name(data.get("display_name", "")),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "tags": list(self.tags),
            "pinned": self.pinned,
            "archived": self.archived,
            "display_name": self.display_name,
        }


@dataclass
class ProfileSummary:
    """Lightweight dashboard row — no raw tool-output files read. NEVER holds secrets."""

    name: str
    directory: Path
    target: str = ""
    display_title: str = ""
    created_at: str = ""
    last_opened_at: str = ""
    last_activity_at: str = ""
    status: str = DEFAULT_STATUS
    tags: list[str] = field(default_factory=list)
    pinned: bool = False
    archived: bool = False
    platform: str = ""
    service_count: int = 0
    finding_count: int = 0
    credential_count: int = 0
    commands_completed: int = 0
    commands_failed: int = 0
    has_notes: bool = False
    has_report: bool = False
    has_graph: bool = False
    corrupt: bool = False
    locked: bool = False
    warnings: list[str] = field(default_factory=list)
