from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from oscprecon import config

DEFAULT_WORDLIST_PATHS: tuple[Path, ...] = (
    Path("/usr/share/seclists"),
    Path("/usr/share/wordlists"),
    Path.home() / "wordlists",
)

# why: password brute force is out of scope (§2/§13) — password lists must never be surfaced.
# 'password' is matched as a substring of ANY path part (catches Passwords/, Default-Passwords/,
# and *-passwords.txt outside a Passwords dir); metasploit/ is skipped; rockyou* by name.
_EXCLUDED_NAME_SUBSTRINGS = ("password",)
_EXCLUDED_DIR_PARTS = {"metasploit"}
_EXCLUDED_FILE_PREFIXES = ("rockyou",)

_TEXT_SUFFIXES = {".txt", ".lst", ".list", ".words", ".dic"}

_CATEGORY_HINTS: tuple[tuple[str, str], ...] = (
    ("web-content", "web-content"),
    ("web_content", "web-content"),
    ("subdomain", "dns"),
    ("vhost", "dns"),
    ("dns", "dns"),
    ("username", "usernames"),
    ("fuzzing", "fuzzing"),
    ("discovery", "discovery"),
)


@dataclass(frozen=True)
class Wordlist:
    path: Path
    name: str
    category: str
    size_bytes: int
    line_count: int


def wordlist_paths() -> list[Path]:
    raw = config.load_prefs().get("wordlist_paths")
    if raw:
        return [Path(part) for part in raw.split(os.pathsep) if part]
    return list(DEFAULT_WORDLIST_PATHS)


def is_excluded(path: Path) -> bool:
    for part in path.parts:
        lower = part.lower()
        if lower in _EXCLUDED_DIR_PARTS:
            return True
        if any(sub in lower for sub in _EXCLUDED_NAME_SUBSTRINGS):
            return True
    name = path.name.lower()
    return any(name.startswith(prefix) for prefix in _EXCLUDED_FILE_PREFIXES)


def _category_for(path: Path) -> str:
    lowered = str(path).lower()
    for needle, category in _CATEGORY_HINTS:
        if needle in lowered:
            return category
    return "other"


def _count_lines(path: Path) -> int:
    count = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            count += chunk.count(b"\n")
    return count


def index_wordlists(paths: Iterable[Path] | None = None) -> list[Wordlist]:
    search = list(paths) if paths is not None else wordlist_paths()
    seen: set[Path] = set()
    results: list[Wordlist] = []
    for base in search:
        if not base.exists():
            continue
        for entry in sorted(base.rglob("*")):
            if not entry.is_file() or entry.suffix.lower() not in _TEXT_SUFFIXES:
                continue
            resolved = entry.resolve()
            # why: check the symlink target too — an innocently-named link into Passwords/
            # must not slip a password list through.
            if is_excluded(entry) or is_excluded(resolved):
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                size = entry.stat().st_size
                lines = _count_lines(entry)
            except OSError:
                continue
            results.append(Wordlist(entry, entry.name, _category_for(entry), size, lines))
    return results


def _favorites_path() -> Path:
    return config.config_dir() / "favorites.json"


def favorites() -> list[str]:
    path = _favorites_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return [str(p) for p in data] if isinstance(data, list) else []


def add_favorite(path: str | Path) -> None:
    entry = str(path)
    items = [p for p in favorites() if p != entry]
    items.insert(0, entry)
    _favorites_path().write_text(json.dumps(items, indent=2), encoding="utf-8")


def remove_favorite(path: str | Path) -> None:
    entry = str(path)
    _favorites_path().write_text(
        json.dumps([p for p in favorites() if p != entry], indent=2), encoding="utf-8"
    )


def is_favorite(path: str | Path) -> bool:
    return str(path) in set(favorites())
