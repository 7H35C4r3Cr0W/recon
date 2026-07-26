from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from functools import lru_cache
from pathlib import Path

# What an `--script <selector>` expression actually SELECTS.
#
# The §2 gate used to judge a selector by its text: refuse anything containing "brute", refuse a
# glob that expands onto a brute script. That was safe but far too blunt — it also refused
# `smb-* and vuln`, which selects zero brute scripts precisely BECAUSE of the conjunction, and which
# is the form that catches vulnerability scripts whose filename has no "vuln" in it
# (smb-double-pulsar-backdoor, ftp-vsftpd-backdoor, clamav-exec…). Judging the text meant the tool
# could only offer the narrow `smb-vuln-*` family, and the operator lost checks they should have.
#
# So evaluate the expression the way nmap does: over the installed script database, name + category
# per script. `selected()` returns exactly the scripts nmap would run, and the policy asks a real
# question — "does this selection contain a credential attack?" — instead of a lexical one.
#
# Grammar (nmap's, as documented in scripting.xml): a selector is a comma-separated list of terms;
# each term is a boolean expression over `and` / `or` / `not` and parentheses, whose atoms are a
# category name, a script filename (with or without .nse), a filename glob, `all`, or a directory
# path. Directories are refused upstream — this module treats an atom containing "/" as unmatchable
# so a path can never quietly select the whole script tree.

_SCRIPT_DB = Path("/usr/share/nmap/scripts/script.db")
_DB_ENTRY = re.compile(r'Entry\s*{\s*filename\s*=\s*"([^"]+)"\s*,\s*categories\s*=\s*{([^}]*)}')
_TOKEN = re.compile(r"\(|\)|,|\s+|[^\s(),]+")


@dataclass(frozen=True)
class Script:
    name: str  # stem, no .nse
    categories: frozenset[str]


# a small offline fallback so the evaluator is deterministic on a dev/CI box with no nmap: enough
# shape to exercise the grammar and the brute rule, never presented as complete coverage.
_FALLBACK: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("smb-brute", ("brute", "intrusive")),
    ("smb-os-discovery", ("default", "discovery", "safe")),
    ("smb-vuln-ms17-010", ("vuln", "safe")),
    ("smb-double-pulsar-backdoor", ("vuln", "safe", "malware")),
    ("ftp-brute", ("brute", "intrusive")),
    ("ftp-anon", ("default", "auth", "safe")),
    ("ftp-vsftpd-backdoor", ("exploit", "intrusive", "malware", "vuln")),
    ("dicom-brute", ("auth", "brute")),
    ("http-slowloris", ("dos", "intrusive")),
    ("vulners", ("vuln", "safe", "external")),
)


@lru_cache(maxsize=4)
def load_scripts(db: Path | None = None) -> tuple[Script, ...]:
    path = db if db is not None else _SCRIPT_DB
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    scripts = [
        Script(
            name=name[:-4] if name.endswith(".nse") else name,
            categories=frozenset(c.strip().strip('"') for c in cats.split(",") if c.strip()),
        )
        for name, cats in _DB_ENTRY.findall(text)
    ]
    if scripts:
        return tuple(scripts)
    return tuple(Script(n, frozenset(c)) for n, c in _FALLBACK)


class SelectorError(ValueError):
    """The expression is not something nmap would accept."""


def _tokenize(expression: str) -> list[str]:
    return [t for t in (m.group(0) for m in _TOKEN.finditer(expression)) if not t.isspace()]


def _matches(atom: str, script: Script) -> bool:
    low = atom.lower()
    if low == "all":
        return True
    if "/" in atom:
        # a directory selector: refuse to model it as a match. It selects everything inside, and the
        # policy blocks it outright — never let it evaluate to "selects nothing" and slip through.
        raise SelectorError("a directory selector is not allowed here")
    if low in script.categories:
        return True
    target = atom[:-4] if atom.endswith(".nse") else atom
    return fnmatch(script.name, target)


def _parse(tokens: list[str], script: Script, pos: int = 0) -> tuple[bool, int]:
    value, pos = _parse_or(tokens, script, pos)
    return value, pos


def _parse_or(tokens: list[str], script: Script, pos: int) -> tuple[bool, int]:
    value, pos = _parse_and(tokens, script, pos)
    while pos < len(tokens) and tokens[pos].lower() == "or":
        right, pos = _parse_and(tokens, script, pos + 1)
        value = value or right
    return value, pos


def _parse_and(tokens: list[str], script: Script, pos: int) -> tuple[bool, int]:
    value, pos = _parse_not(tokens, script, pos)
    while pos < len(tokens) and tokens[pos].lower() == "and":
        right, pos = _parse_not(tokens, script, pos + 1)
        value = value and right
    return value, pos


def _parse_not(tokens: list[str], script: Script, pos: int) -> tuple[bool, int]:
    if pos < len(tokens) and tokens[pos].lower() == "not":
        value, pos = _parse_not(tokens, script, pos + 1)
        return (not value), pos
    return _parse_atom(tokens, script, pos)


def _parse_atom(tokens: list[str], script: Script, pos: int) -> tuple[bool, int]:
    if pos >= len(tokens):
        raise SelectorError("expression ended early")
    token = tokens[pos]
    if token == "(":
        value, pos = _parse_or(tokens, script, pos + 1)
        if pos >= len(tokens) or tokens[pos] != ")":
            raise SelectorError("unbalanced parentheses")
        return value, pos + 1
    if token in (")", ","):
        raise SelectorError(f"unexpected {token!r}")
    return _matches(token, script), pos + 1


def _evaluate_term(term: str, script: Script) -> bool:
    tokens = _tokenize(term)
    if not tokens:
        return False
    value, pos = _parse(tokens, script)
    if pos != len(tokens):
        raise SelectorError(f"trailing tokens in {term!r}")
    return value


def selected(selector: str, db: Path | None = None) -> list[str]:
    """The scripts nmap would run for this `--script` value, sorted.

    A selector is a COMMA-SEPARATED list of expressions and a script runs if ANY of them selects it
    — so the comma is a union, not part of the boolean grammar (`a and b, c` is `(a and b) or c`).
    """
    scripts = load_scripts(db)
    terms = [t for t in _split_terms(selector) if t.strip()]
    if not terms:
        return []
    hits = {s.name for s in scripts for term in terms if _evaluate_term(term, s)}
    return sorted(hits)


def _split_terms(selector: str) -> list[str]:
    # split on commas that are not inside parentheses
    terms: list[str] = []
    depth = 0
    current: list[str] = []
    for char in selector:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            terms.append("".join(current))
            current = []
            continue
        current.append(char)
    terms.append("".join(current))
    return terms
