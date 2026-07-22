from __future__ import annotations

import re

# Shared bounded content-peek helpers for FTP + SMB (§12: reads are triage, not bulk exfil). Only
# small files are ever fetched, capped in number by the caller. The rule is "peek anything that
# might hold readable data" — NOT a narrow text-extension allowlist (that missed real recon loot
# like Archetype's prod.dtsConfig). We fetch any small file except (a) known-binary/media/archive
# types, whose head is just noise, and (b) secret material, whose head must never be dumped. The
# binary-content guard in peek_snippet() is the final backstop for a binary file we didn't denylist.

PEEK_MAX_BYTES = 8192  # only peek files the listing already shows as this small
PEEK_MAX_FILES = 8  # at most this many peeks per walk, so it's never a download storm

# Known-binary / media / archive / compiled extensions — peeking these yields garbage the
# binary-guard would only label "(binary or non-text content)", so skip the fetch entirely. Anything
# NOT in here (any config, log, script, no-extension file, or unknown extension) is worth a peek.
_BINARY_EXT = frozenset(
    {
        # images
        "jpg",
        "jpeg",
        "png",
        "gif",
        "bmp",
        "ico",
        "tif",
        "tiff",
        "webp",
        "heic",
        "psd",
        # archives / compressed
        "zip",
        "tar",
        "gz",
        "tgz",
        "bz2",
        "tbz2",
        "xz",
        "7z",
        "rar",
        "lz",
        "lzma",
        "z",
        "jar",
        "war",
        "ear",
        "cab",
        "arj",
        "iso",
        "deb",
        "rpm",
        "apk",
        "pkg",
        "xpi",
        "crx",
        # executables / libraries / compiled
        "exe",
        "dll",
        "so",
        "bin",
        "msi",
        "msu",
        "dmg",
        "com",
        "scr",
        "cpl",
        "drv",
        "ocx",
        "sys",
        "o",
        "a",
        "lib",
        "obj",
        "pyc",
        "pyo",
        "class",
        "elf",
        "wasm",
        "swf",
        # audio / video
        "mp3",
        "wav",
        "flac",
        "ogg",
        "oga",
        "aac",
        "wma",
        "m4a",
        "opus",
        "mid",
        "midi",
        "mp4",
        "avi",
        "mkv",
        "mov",
        "wmv",
        "flv",
        "webm",
        "mpg",
        "mpeg",
        "m4v",
        "3gp",
        # binary documents / office (zip-container or binary formats)
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "odt",
        "ods",
        "odp",
        # fonts
        "ttf",
        "otf",
        "woff",
        "woff2",
        "eot",
        # databases / disk images
        "db",
        "sqlite",
        "sqlite3",
        "mdb",
        "accdb",
        "vhd",
        "vhdx",
        "vmdk",
        "ova",
        "img",
        "qcow2",
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


def is_data_bearing(name: str) -> bool:
    # worth a peek: not secret material, and not a known-binary/media/archive type. Any config,
    # log, script, no-extension file, or unfamiliar extension qualifies — the point is to read
    # data, not to guess a text-extension allowlist.
    if is_sensitive(name):
        return False
    return extension(name) not in _BINARY_EXT


# why: a peeked filename is attacker-controlled (from the target's share/FTP listing) and is
# interpolated into a client's own command interpreter — smbclient's `-c` string splits on ';' and
# honours a leading '!' as a shell escape, regardless of shell.run's argv-safe Popen. Never peek a
# name carrying command-control metacharacters: it is still listed, we only skip the content read.
_PEEK_UNSAFE_CHARS = frozenset(';`!"\\|&$<>\n\r\t\x00')


def has_unsafe_peek_chars(name: str) -> bool:
    return any(c in _PEEK_UNSAFE_CHARS for c in name)


def is_peekable(name: str, is_dir: bool, size: int) -> bool:
    # small (from the listing), non-dir, data-bearing; size 0/unknown is skipped so we never fetch
    # something we can't bound.
    if is_dir or size <= 0 or size > PEEK_MAX_BYTES:
        return False
    if has_unsafe_peek_chars(name):
        return False
    return is_data_bearing(name)


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
