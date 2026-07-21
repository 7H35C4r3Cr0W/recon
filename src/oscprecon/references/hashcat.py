from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

# Hashcat hash-mode DECISION AID (see hashcat_modes.yaml). Display-only: Nabu never runs hashcat —
# it answers "which -m is this hash, and what's the command?" so the operator doesn't leave the tool
# to hunt the mode. Search by name/mode/category, then build a ready-to-run hashcat command.

_DATA = Path(__file__).parent / "hashcat_modes.yaml"

# attack modes (-a) and mask charsets — the other half of "how do I phrase this crack".
ATTACK_MODES: tuple[tuple[str, str, str], ...] = (
    ("0", "Straight (dictionary)", "hash + wordlist [+ -r rules]"),
    ("1", "Combination", "hash + wordlist + wordlist"),
    ("3", "Brute-force / mask", "hash + mask (e.g. ?u?l?l?l?d?d?d?d)"),
    ("6", "Hybrid wordlist + mask", "hash + wordlist + mask"),
    ("7", "Hybrid mask + wordlist", "hash + mask + wordlist"),
)
CHARSETS: tuple[tuple[str, str], ...] = (
    ("?l", "abcdefghijklmnopqrstuvwxyz"),
    ("?u", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("?d", "0123456789"),
    ("?h", "0-9 a-f (lower hex)"),
    ("?H", "0-9 A-F (upper hex)"),
    ("?s", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("?a", "?l?u?d?s (all printable)"),
    ("?b", "0x00-0xff (raw bytes)"),
)


@dataclass(frozen=True)
class HashMode:
    mode: int  # the -m number
    name: str  # searchable label (e.g. "Apache apr1 $apr1$ / .htpasswd")
    category: str


@lru_cache(maxsize=1)
def load_modes() -> list[HashMode]:
    try:
        data = yaml.safe_load(_DATA.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    out: list[HashMode] = []
    for group in data if isinstance(data, list) else []:
        if not isinstance(group, dict):
            continue
        cat = str(group.get("category", ""))
        for m in group.get("modes", []) or []:
            if isinstance(m, dict) and "mode" in m and "name" in m:
                try:
                    out.append(HashMode(int(m["mode"]), str(m["name"]), cat))
                except (TypeError, ValueError):
                    continue
    return out


def search(query: str) -> list[HashMode]:
    """Modes matching the query in name/category/mode-number (case-insensitive). '' returns all."""
    q = query.strip().lower()
    modes = load_modes()
    if not q:
        return modes
    return [
        m
        for m in modes
        if q in m.name.lower()
        or q in m.category.lower()
        or q == str(m.mode)
        # numeric substring only for 2+ digits, so a partial like "173" finds 17300 but a bare
        # "0"/"1" doesn't flood every mode that merely contains that digit.
        or (q.isdigit() and len(q) >= 2 and q in str(m.mode))
    ]


def build_command(
    mode: int,
    attack: str = "0",
    hashfile: str = "hash.txt",
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    mask: str = "?a?a?a?a?a?a",
    rules: str = "",
    extra: str = "",
) -> str:
    """Assemble a hashcat command for the chosen mode + attack mode. Display-only — copy and run."""
    parts = ["hashcat", "-m", str(mode), "-a", attack, hashfile]
    if attack in ("0", "1"):  # dictionary / combination
        parts.append(wordlist)
        if attack == "1":
            parts.append(wordlist)
    elif attack == "3":  # brute-force / mask
        parts.append(mask)
    elif attack in ("6", "7"):  # hybrid
        parts += [wordlist, mask] if attack == "6" else [mask, wordlist]
    if rules.strip() and attack == "0":
        parts += ["-r", rules.strip()]
    if extra.strip():
        parts.append(extra.strip())
    return " ".join(parts)
