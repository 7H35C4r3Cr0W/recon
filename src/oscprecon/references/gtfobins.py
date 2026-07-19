from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

# Offline GTFOBins reference loader (see gtfobins.yaml). Lookup-only: Nabu never runs these — it
# surfaces the exact copy-paste technique for a binary you found (SUID/sudo/capabilities/…) so you
# don't have to leave the tool to look it up. Each binary links back to its GTFOBins page.

_DATA = Path(__file__).parent / "gtfobins.yaml"
_PAGE = "https://gtfobins.github.io/gtfobins/{bin}/"


@dataclass(frozen=True)
class Technique:
    func: str  # shell · sudo · suid · capabilities · file-read · file-write · reverse-shell · …
    code: str


@dataclass(frozen=True)
class Binary:
    name: str
    techniques: list[Technique] = field(default_factory=list)

    @property
    def url(self) -> str:
        return _PAGE.format(bin=self.name)

    @property
    def functions(self) -> list[str]:
        seen: list[str] = []
        for t in self.techniques:
            if t.func not in seen:
                seen.append(t.func)
        return seen


@lru_cache(maxsize=1)
def load_gtfobins() -> list[Binary]:
    try:
        data = yaml.safe_load(_DATA.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(data, list):
        return []
    out: list[Binary] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("bin", "")).strip()
        if not name:
            continue
        techniques: list[Technique] = []
        for fn in entry.get("functions", []) or []:
            if isinstance(fn, dict) and fn.get("code"):
                techniques.append(Technique(func=str(fn.get("func", "")), code=str(fn["code"])))
        out.append(Binary(name=name, techniques=techniques))
    return out


def get(name: str) -> Binary | None:
    key = name.strip().lower()
    return next((b for b in load_gtfobins() if b.name == key), None)


def search(query: str) -> list[Binary]:
    """Binaries whose name, a function, or a technique matches `query` (case-insensitive substring).
    An empty query returns everything (sorted by name)."""
    needle = query.strip().lower()
    bins = load_gtfobins()
    if not needle:
        return sorted(bins, key=lambda b: b.name)
    # exact-name matches first, then function/name/code substring matches
    exact = [b for b in bins if b.name == needle]
    rest = [
        b
        for b in bins
        if b not in exact
        and (
            needle in b.name
            or any(needle in t.func for t in b.techniques)
            or any(needle in t.code.lower() for t in b.techniques)
        )
    ]
    return exact + sorted(rest, key=lambda b: b.name)
