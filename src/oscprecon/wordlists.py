from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from oscprecon import config
from oscprecon.config import DEFAULT_WORDLIST_PATHS  # re-export: canonical roots live in config now

__all__ = ["DEFAULT_WORDLIST_PATHS"]  # (extended implicitly by the module's public functions)

# why: password brute force is out of scope (§2/§13) — password lists MUST NEVER be surfaced.
# Two layers: (1) an affirmative allowlist — only files whose path maps to a known recon
# category (below) are shown, so an unknown/uncategorized list is WITHHELD, not shown; a
# substring denylist alone cannot guarantee "never" (it missed fasttrack.txt / wifite.txt).
# (2) a denylist as defence-in-depth against known password lists.
_EXCLUDED_NAME_SUBSTRINGS = ("password", "passwd")
_EXCLUDED_DIR_PARTS = {"metasploit", "dict"}
_EXCLUDED_FILE_PREFIXES = (
    "rockyou",
    "fasttrack",
    "wifite",
    "wordlist-probable",
    "probable-",
    "darkweb",
    "brutespray",
)

_TEXT_SUFFIXES = {".txt", ".lst", ".list", ".words", ".dic"}

# why: reading multi-hundred-MB lists to count lines on every index is far too slow — skip it
# above this size; such entries report line_count == -1 ("large").
_LARGE_FILE_BYTES = 5 * 1024 * 1024

# path substring -> recon category. ONLY these categories are surfaced (see index_wordlists);
# 'other' (no hint matched) is treated as not-a-recon-list and withheld.
_CATEGORY_HINTS: tuple[tuple[str, str], ...] = (
    ("web-content", "web-content"),
    ("web_content", "web-content"),
    ("webcontent", "web-content"),
    ("dirbuster", "web-content"),
    ("dirb", "web-content"),
    ("directory", "web-content"),
    ("directories", "web-content"),
    ("api", "web-content"),
    ("subdomain", "dns"),
    ("vhost", "dns"),
    ("dns", "dns"),
    ("username", "usernames"),
    ("fuzzing", "fuzzing"),
    ("fuzz", "fuzzing"),
    ("discovery", "discovery"),
)

# why: match each needle at a token boundary (a leading '.') after collapsing non-alphanumeric runs
# to '.', so a short needle like "api" hits "api-list" but NOT "capital"/"therapist"/"rapid".
_NORM_HINTS: tuple[tuple[str, str], ...] = tuple(
    ("." + re.sub(r"[^a-z0-9]+", ".", needle), category) for needle, category in _CATEGORY_HINTS
)


@dataclass(frozen=True)
class Wordlist:
    path: Path
    name: str
    category: str
    size_bytes: int
    line_count: int


def wordlist_paths() -> list[Path]:
    return [Path(part) for part in config.load_settings().wordlist_paths]


def is_excluded(path: Path, *, allow_passwords: bool = False) -> bool:
    for part in path.parts:
        lower = part.lower()
        if lower in _EXCLUDED_DIR_PARTS:
            return True
        if not allow_passwords and any(sub in lower for sub in _EXCLUDED_NAME_SUBSTRINGS):
            return True
    if allow_passwords:
        return False  # Spray mode (§2a): password lists are surfaced, not filtered
    name = path.name.lower()
    return any(name.startswith(prefix) for prefix in _EXCLUDED_FILE_PREFIXES)


def _is_password_list(path: Path) -> bool:
    # a file is a "password list" iff the default filter would exclude it for being password-ish.
    for part in path.parts:
        if any(sub in part.lower() for sub in _EXCLUDED_NAME_SUBSTRINGS):
            return True
    return path.name.lower().startswith(_EXCLUDED_FILE_PREFIXES)


def _category_for(path: Path) -> str:
    norm = "." + re.sub(r"[^a-z0-9]+", ".", str(path).lower())
    for token, category in _NORM_HINTS:
        if token in norm:
            return category
    return "other"


def _count_lines(path: Path) -> int:
    count = 0
    last = b"\n"
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            count += chunk.count(b"\n")
            last = chunk[-1:]
    if last not in (b"\n", b""):
        count += 1  # a final line with no trailing newline still counts
    return count


def index_wordlists(
    paths: Iterable[Path] | None = None, *, include_passwords: bool | None = None
) -> list[Wordlist]:
    # include_passwords defaults to the Spray-mode gate (§2a): password lists are surfaced ONLY when
    # the user has opted into Spray mode; the default (recon-only) behaviour is unchanged.
    if include_passwords is None:
        include_passwords = config.spray_enabled()
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
            # must not slip a password list through (unless Spray mode is on).
            if is_excluded(entry, allow_passwords=include_passwords) or is_excluded(
                resolved, allow_passwords=include_passwords
            ):
                continue
            if resolved in seen:
                continue
            category = _category_for(entry)
            if category == "other":
                if include_passwords and _is_password_list(entry):
                    category = "passwords"  # Spray mode surfaces password lists
                else:
                    continue  # affirmative allowlist: withhold anything not a known recon category
            seen.add(resolved)
            try:
                size = entry.stat().st_size
                lines = -1 if size > _LARGE_FILE_BYTES else _count_lines(entry)
            except OSError:
                continue
            results.append(Wordlist(entry, entry.name, category, size, lines))
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
