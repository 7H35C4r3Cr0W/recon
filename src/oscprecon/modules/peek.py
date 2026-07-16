from __future__ import annotations

import re

# Shared bounded content-peek helpers for FTP + SMB (§12: reads are triage, not bulk exfil). Only
# small, text-like files are ever fetched, capped in number by the caller.

PEEK_MAX_BYTES = 8192  # only peek files the listing already shows as this small
PEEK_MAX_FILES = 8  # at most this many peeks per walk, so it's never a download storm

_TEXT_EXT = frozenset(
    {
        "txt",
        "log",
        "conf",
        "config",
        "cfg",
        "cnf",
        "ini",
        "xml",
        "json",
        "yaml",
        "yml",
        "md",
        "csv",
        "sh",
        "bash",
        "php",
        "html",
        "htm",
        "js",
        "py",
        "sql",
        "env",
        "properties",
        "inc",
        "bak",
        "old",
        "asp",
        "aspx",
        "jsp",
        "pl",
        "rb",
    }
)

# never auto-peek secret material: a private-key / password-hash file's head would land unredacted
# in findings.json + report + graph, breaking the 'secrets never logged / always redacted' rule.
# The file still shows up in the directory listing by name — we just don't dump its contents.
_SENSITIVE_EXT = frozenset(
    {"pem", "pub", "key", "ppk", "p12", "pfx", "htpasswd", "htaccess", "kdbx"}
)
_SENSITIVE_NAMES = frozenset(
    {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "shadow",
        "sam",
        "ntds.dit",
        ".htpasswd",  # dotfiles: extension() resolves these to "" so match the whole name
        ".htaccess",
        "htpasswd",
        "htaccess",
    }
)

_NON_PRINTABLE = re.compile(r"[^\x09\x0a\x0d\x20-\x7e]")  # keep tab/LF/CR + printable ASCII


def extension(name: str) -> str:
    head, dot, ext = name.rpartition(".")
    return ext.lower() if dot and head else ""  # "" for no-ext and dotfiles (.bashrc)


def is_sensitive(name: str) -> bool:
    # a secret-bearing file we must never dump the head of (key material, password/hash stores)
    return extension(name) in _SENSITIVE_EXT or name.strip().lower() in _SENSITIVE_NAMES


def is_text_like(name: str) -> bool:
    # a known text extension, or NO extension (often a config/script) — worth a peek, unless it is
    # known secret material.
    if is_sensitive(name):
        return False
    ext = extension(name)
    return ext == "" or ext in _TEXT_EXT


def is_peekable(name: str, is_dir: bool, size: int) -> bool:
    # small (from the listing), non-dir, text-like; size 0/unknown is skipped so we never fetch
    # something we can't bound.
    if is_dir or size <= 0 or size > PEEK_MAX_BYTES:
        return False
    return is_text_like(name)


def peek_snippet(text: str, limit: int = 60) -> str:
    """A safe, bounded preview of a small file's content for quick triage.

    Strips control/non-printable bytes and collapses whitespace so nothing hostile or noisy reaches
    the UI; caps the length; and calls out binary content instead of showing garbage.
    """
    stripped = _NON_PRINTABLE.sub("", text)
    if text and len(stripped) < len(text) * 0.7:  # >30% non-printable -> treat as binary
        return "(binary or non-text content)"
    collapsed = " ".join(stripped.split())
    if not collapsed:
        return "(empty)"
    return collapsed[:limit] + ("…" if len(collapsed) > limit else "")
