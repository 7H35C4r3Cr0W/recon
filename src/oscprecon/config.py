from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

APP_NAME = "oscprecon"
DEFAULT_WORKSPACE = Path.home() / "oscprecon"
RECENT_LIMIT = 10

# why: canonical default wordlist search roots — kept here (not in wordlists.py) so config stays the
# single source of settings truth without importing the GUI-adjacent wordlist indexer.
DEFAULT_WORDLIST_PATHS: tuple[Path, ...] = (
    Path("/usr/share/seclists"),
    Path("/usr/share/wordlists"),
    Path.home() / "wordlists",
)

# Settings validation bounds + enums (config stays GUI-free; theme.py owns the palette application).
THEMES = ("light", "dark", "htb")
DEFAULT_THEME = "light"
# Scan profiles govern the nmap discovery battery (see modules/nmap.py):
#   quick   — top-1000 TCP only (fast triage, no full -p-, no UDP)
#   default — top-1000 -> full -p- -> UDP top-100 (the standard battery)
#   full    — default battery + always the slow full UDP sweep
#   exam    — speed-tuned tight/fast: top-1000 + rate-boosted -p- + UDP top-100, exam-legal
SCAN_PROFILES = ("quick", "default", "full", "exam")
DEFAULT_SCAN_PROFILE = "default"
DEFAULT_MAX_CONCURRENCY = 4
CONCURRENCY_RANGE = (1, 16)
FONT_SIZE_RANGE = (8, 24)  # 0 = "use the Qt default, don't override"
# Live HackTricks fetch/cache (owner-approved, §14a) — OFF by default; the vendored offline snapshot
# stays the reliable fallback. cache_days = how long a cached page is considered fresh.
DEFAULT_HACKTRICKS_CACHE_DAYS = 14
HACKTRICKS_CACHE_DAYS_RANGE = (1, 365)


def config_dir() -> Path:
    raw = os.environ.get("XDG_CONFIG_HOME")
    base = Path(raw) if raw else Path.home() / ".config"
    directory = base / APP_NAME
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def cache_dir() -> Path:
    # why: rebuildable, NON-authoritative XDG cache (live HackTricks pages) — never project data.
    raw = os.environ.get("XDG_CACHE_HOME")
    base = Path(raw) if raw else Path.home() / ".cache"
    directory = base / APP_NAME
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def state_dir() -> Path:
    # why: XDG state home — the spec's log location (diagnostic, non-authoritative).
    raw = os.environ.get("XDG_STATE_HOME")
    base = Path(raw) if raw else Path.home() / ".local" / "state"
    directory = base / APP_NAME
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _prefs_path() -> Path:
    return config_dir() / "prefs.json"


def _recent_path() -> Path:
    return config_dir() / "recent.json"


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _write_json_atomic(path: Path, obj: Any) -> None:
    # why: mirror profile.json/creds.json — a crash mid-write must not truncate the config file.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_prefs() -> dict[str, str]:
    data = _read_json(_prefs_path(), {})
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def save_prefs(prefs: dict[str, str]) -> None:
    _write_json_atomic(_prefs_path(), prefs)


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


def _parse_int(raw: object, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return _clamp(value, lo, hi)


def _parse_bool(raw: object, default: bool) -> bool:
    text = str(raw).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off", ""):
        return False
    return default


@dataclass
class Settings:
    workspace_root: str
    wordlist_paths: list[str]
    theme: str
    font_size: int  # 0 = don't override the Qt default
    max_concurrency: int
    nmap_udp_full: bool
    scan_profile: str = DEFAULT_SCAN_PROFILE
    # opt-in, OFF BY DEFAULT (CLAUDE.md §2a): unlocks OSCP-legal credential spraying (hydra/medusa/
    # netexec list-spray + password wordlists). With this false the tool is strictly recon-only.
    spray_enabled: bool = False
    # Live HackTricks fetch/cache (§14a) — OFF by default; offline vendored pages stay the fallback.
    hacktricks_live_enabled: bool = False
    hacktricks_auto_refresh: bool = False  # auto-refresh stale cached pages when live is on
    hacktricks_prefer_live: bool = False  # prefer a fresh live-cached page over vendored offline
    hacktricks_cache_days: int = DEFAULT_HACKTRICKS_CACHE_DAYS

    def normalized(self) -> Settings:
        font = self.font_size
        if font != 0:
            font = _clamp(font, *FONT_SIZE_RANGE)
        return Settings(
            workspace_root=self.workspace_root.strip() or str(DEFAULT_WORKSPACE),
            wordlist_paths=[p for p in (s.strip() for s in self.wordlist_paths) if p],
            theme=self.theme if self.theme in THEMES else DEFAULT_THEME,
            font_size=font,
            max_concurrency=_clamp(self.max_concurrency, *CONCURRENCY_RANGE),
            nmap_udp_full=bool(self.nmap_udp_full),
            scan_profile=self.scan_profile
            if self.scan_profile in SCAN_PROFILES
            else DEFAULT_SCAN_PROFILE,
            spray_enabled=bool(self.spray_enabled),
            hacktricks_live_enabled=bool(self.hacktricks_live_enabled),
            hacktricks_auto_refresh=bool(self.hacktricks_auto_refresh),
            hacktricks_prefer_live=bool(self.hacktricks_prefer_live),
            hacktricks_cache_days=_clamp(self.hacktricks_cache_days, *HACKTRICKS_CACHE_DAYS_RANGE),
        )

    def to_prefs(self) -> dict[str, str]:
        # NOTE: settings never hold secrets — only paths, a theme name, and numeric knobs.
        return {
            "workspace_root": self.workspace_root,
            "wordlist_paths": os.pathsep.join(self.wordlist_paths),
            "theme": self.theme,
            "font_size": str(self.font_size),
            "max_concurrency": str(self.max_concurrency),
            "nmap_udp_full": "true" if self.nmap_udp_full else "false",
            "scan_profile": self.scan_profile,
            "spray_enabled": "true" if self.spray_enabled else "false",
            "hacktricks_live_enabled": "true" if self.hacktricks_live_enabled else "false",
            "hacktricks_auto_refresh": "true" if self.hacktricks_auto_refresh else "false",
            "hacktricks_prefer_live": "true" if self.hacktricks_prefer_live else "false",
            "hacktricks_cache_days": str(self.hacktricks_cache_days),
        }


def default_settings() -> Settings:
    return Settings(
        workspace_root=str(DEFAULT_WORKSPACE),
        wordlist_paths=[str(p) for p in DEFAULT_WORDLIST_PATHS],
        theme=DEFAULT_THEME,
        font_size=0,
        max_concurrency=DEFAULT_MAX_CONCURRENCY,
        nmap_udp_full=False,
        scan_profile=DEFAULT_SCAN_PROFILE,
        spray_enabled=False,
        hacktricks_live_enabled=False,
        hacktricks_auto_refresh=False,
        hacktricks_prefer_live=False,
        hacktricks_cache_days=DEFAULT_HACKTRICKS_CACHE_DAYS,
    )


def load_settings() -> Settings:
    prefs = load_prefs()
    base = default_settings()
    raw_paths = prefs.get("wordlist_paths")
    paths = [p for p in raw_paths.split(os.pathsep) if p] if raw_paths else base.wordlist_paths
    return Settings(
        workspace_root=prefs.get("workspace_root") or base.workspace_root,
        wordlist_paths=paths,
        theme=prefs.get("theme", base.theme),
        font_size=_parse_int(prefs.get("font_size"), base.font_size, 0, FONT_SIZE_RANGE[1]),
        max_concurrency=_parse_int(
            prefs.get("max_concurrency"), base.max_concurrency, *CONCURRENCY_RANGE
        ),
        nmap_udp_full=_parse_bool(prefs.get("nmap_udp_full"), base.nmap_udp_full),
        scan_profile=prefs.get("scan_profile", base.scan_profile),
        spray_enabled=_parse_bool(prefs.get("spray_enabled"), base.spray_enabled),
        hacktricks_live_enabled=_parse_bool(
            prefs.get("hacktricks_live_enabled"), base.hacktricks_live_enabled
        ),
        hacktricks_auto_refresh=_parse_bool(
            prefs.get("hacktricks_auto_refresh"), base.hacktricks_auto_refresh
        ),
        hacktricks_prefer_live=_parse_bool(
            prefs.get("hacktricks_prefer_live"), base.hacktricks_prefer_live
        ),
        hacktricks_cache_days=_parse_int(
            prefs.get("hacktricks_cache_days"),
            base.hacktricks_cache_days,
            *HACKTRICKS_CACHE_DAYS_RANGE,
        ),
    ).normalized()


def spray_enabled() -> bool:
    """True when the user has opted into Spray mode (§2a). The single gate the engine reads."""
    return load_settings().spray_enabled


def save_settings(settings: Settings) -> None:
    prefs = load_prefs()  # preserve unrelated keys (recent handling lives elsewhere)
    prefs.update(settings.normalized().to_prefs())
    save_prefs(prefs)


def reset_settings() -> None:
    save_settings(default_settings())


def workspace_root() -> Path:
    return Path(load_settings().workspace_root)


def recent_profiles() -> list[str]:
    data = _read_json(_recent_path(), [])
    if not isinstance(data, list):
        return []
    return [str(p) for p in data]


def add_recent(profile_dir: Path) -> None:
    entry = str(Path(profile_dir).resolve())
    items = [p for p in recent_profiles() if p != entry]
    items.insert(0, entry)
    del items[RECENT_LIMIT:]
    _write_json_atomic(_recent_path(), items)
