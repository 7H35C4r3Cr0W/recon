from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from oscprecon import config
from oscprecon.workspace.index import scan_workspace
from oscprecon.workspace.models import ProfileSummary, normalize_status, normalize_tags


@dataclass
class SavedView:
    """A workspace filter. Contains ONLY filter configuration — never profile data or secrets."""

    name: str
    statuses: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    pinned: bool | None = None
    archived: bool | None = None
    has_report: bool | None = None
    has_credentials: bool | None = None
    has_failed_commands: bool | None = None
    platform: str = ""
    service: str = ""

    def matches(self, summary: ProfileSummary, service_names: set[str]) -> bool:
        if self.statuses and summary.status not in self.statuses:
            return False
        if self.tags:
            have = {t.lower() for t in summary.tags}
            if not all(t.lower() in have for t in self.tags):
                return False
        if self.pinned is not None and summary.pinned != self.pinned:
            return False
        if self.archived is not None and summary.archived != self.archived:
            return False
        if self.has_report is not None and summary.has_report != self.has_report:
            return False
        if (
            self.has_credentials is not None
            and (summary.credential_count > 0) != self.has_credentials
        ):
            return False
        if self.has_failed_commands is not None and (
            (summary.commands_failed > 0) != self.has_failed_commands
        ):
            return False
        if self.platform and self.platform.lower() not in summary.platform.lower():
            return False
        if self.service:
            needle = self.service.lower()
            return any(needle in name for name in service_names)
        return True


BUILTIN_VIEWS: tuple[SavedView, ...] = (
    SavedView("All active", statuses=["new", "active", "needs-review", "blocked"], archived=False),
    SavedView("Pinned", pinned=True),
    SavedView("Needs review", statuses=["needs-review"], archived=False),
    SavedView("Confirmed credentials", has_credentials=True, archived=False),
    SavedView("Missing a report", has_report=False, archived=False),
    SavedView("Failed scans", has_failed_commands=True, archived=False),
    SavedView("Windows targets", platform="windows", archived=False),
    SavedView("PostgreSQL targets", service="postgresql", archived=False),
    SavedView("Archived", archived=True),
)


def _views_path() -> Path:
    return config.config_dir() / "saved_views.json"


def _view_from_dict(data: object) -> SavedView | None:
    if not isinstance(data, dict) or not str(data.get("name", "")).strip():
        return None
    raw_statuses = data.get("statuses")
    return SavedView(
        name=str(data["name"]).strip()[:80],
        # a hand-edited saved_views.json could have `statuses` as a non-list — iterating it would
        # raise TypeError out of load_user_views (whose contract is a safe fallback), so guard it.
        statuses=(
            [normalize_status(s) for s in raw_statuses if isinstance(s, str)]
            if isinstance(raw_statuses, list)
            else []
        ),
        tags=normalize_tags(data.get("tags")),
        pinned=data.get("pinned") if isinstance(data.get("pinned"), bool) else None,
        archived=data.get("archived") if isinstance(data.get("archived"), bool) else None,
        has_report=data.get("has_report") if isinstance(data.get("has_report"), bool) else None,
        has_credentials=(
            data.get("has_credentials") if isinstance(data.get("has_credentials"), bool) else None
        ),
        has_failed_commands=(
            data.get("has_failed_commands")
            if isinstance(data.get("has_failed_commands"), bool)
            else None
        ),
        platform=str(data.get("platform", "") or ""),
        service=str(data.get("service", "") or ""),
    )


def load_user_views() -> list[SavedView]:
    """User-defined views only (built-ins excluded). Corrupt file -> empty (safe fallback)."""
    path = _views_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError, UnicodeError):
        return []
    raw = data.get("views") if isinstance(data, dict) else data
    if not isinstance(raw, list):
        return []
    out: list[SavedView] = []
    for item in raw:
        view = _view_from_dict(item)
        if view is not None:
            out.append(view)
    return out


def save_user_views(views: list[SavedView]) -> None:
    payload = {"views": [asdict(v) for v in views], "default": get_default_name()}
    tmp = _views_path().with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(_views_path())


def all_views() -> list[SavedView]:
    """Built-ins first, then user views (a user view may shadow a built-in by name)."""
    user = load_user_views()
    user_names = {v.name.lower() for v in user}
    builtins = [v for v in BUILTIN_VIEWS if v.name.lower() not in user_names]
    return [*builtins, *user]


def create_view(view: SavedView) -> bool:
    if not view.name.strip():
        return False
    user = load_user_views()
    if any(v.name.lower() == view.name.lower() for v in user):
        return False
    user.append(view)
    save_user_views(user)
    return True


def update_view(name: str, view: SavedView) -> bool:
    user = load_user_views()
    for i, existing in enumerate(user):
        if existing.name.lower() == name.lower():
            user[i] = view
            save_user_views(user)
            return True
    return False


def rename_view(old: str, new: str) -> bool:
    new = new.strip()[:80]
    user = load_user_views()
    if not new or any(v.name.lower() == new.lower() for v in user):
        return False
    for view in user:
        if view.name.lower() == old.lower():
            view.name = new
            save_user_views(user)
            return True
    return False


def delete_view(name: str) -> bool:
    user = load_user_views()
    kept = [v for v in user if v.name.lower() != name.lower()]
    if len(kept) == len(user):
        return False
    save_user_views(kept)
    return True


def restore_defaults() -> None:
    save_user_views([])  # user views cleared -> only built-ins remain


def get_default_name() -> str:
    prefs = config.load_prefs()
    return prefs.get("default_saved_view", "")


def set_default(name: str) -> None:
    prefs = config.load_prefs()
    prefs["default_saved_view"] = name
    config.save_prefs(prefs)


def apply_view(view: SavedView, root: Path) -> list[ProfileSummary]:
    summaries = scan_workspace(root)
    result: list[ProfileSummary] = []
    for summary in summaries:
        names = _service_names(summary.directory) if view.service else set()
        if view.matches(summary, names):
            result.append(summary)
    return result


def _service_names(directory: Path) -> set[str]:
    try:
        data = json.loads((directory / "profile.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError, UnicodeError):
        return set()
    services = data.get("discovered_services") if isinstance(data, dict) else None
    if not isinstance(services, list):
        return set()
    return {str(s.get("service", "")).lower() for s in services if isinstance(s, dict)}
