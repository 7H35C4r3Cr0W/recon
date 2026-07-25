from __future__ import annotations

import hashlib
import re
import threading
from pathlib import Path

# Output-path arbitration for PARALLEL runs.
#
# Once two scans can run at once, an output filename that depends only on "which tool + which port"
# stops being unique: two feroxbuster runs on :80 with different wordlists/extensions, or a preset
# nmap scan alongside a custom one, both resolve to the same file. The second run then truncates the
# first, and the first run's done-handler parses the SECOND run's partial output into findings under
# the first run's identity. Silent, and wrong in a way that looks like a parser bug.
#
# Two mechanisms:
#   * derive a DISTINCT path per distinct command (scan_output / disambiguate), so the common case
#     simply doesn't collide;
#   * a live CLAIM registry for the paths that still can (a hand-typed output file, a rerun of the
#     identical command) — the second launch is refused with a message naming the owner, rather than
#     quietly interleaving. §24: no silent failures.

_ACTIVE: dict[Path, str] = {}
_LOCK = threading.Lock()

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(text: str, limit: int = 24) -> str:
    return _SLUG_RE.sub("-", text.strip().lower()).strip("-")[:limit] or "run"


def digest(text: str, length: int = 8) -> str:
    return hashlib.sha1(text.encode("utf-8"), usedforsecurity=False).hexdigest()[:length]


def claim(path: Path, tag: str) -> str | None:
    """Reserve `path` for the task `tag`. Returns the CURRENT owner's tag if already claimed."""
    resolved = _resolve(path)
    with _LOCK:
        owner = _ACTIVE.get(resolved)
        if owner is not None and owner != tag:
            return owner
        _ACTIVE[resolved] = tag
        return None


def release(path: Path) -> None:
    with _LOCK:
        _ACTIVE.pop(_resolve(path), None)


def release_tag(tag: str) -> None:
    # a finished task drops every path it held (a run can own an output file AND a structured -o
    # sidecar); called from one place on worker completion so a crash can't leak a claim forever.
    with _LOCK:
        for path in [p for p, owner in _ACTIVE.items() if owner == tag]:
            del _ACTIVE[path]


def owner_of(path: Path) -> str | None:
    with _LOCK:
        return _ACTIVE.get(_resolve(path))


def active_paths() -> dict[Path, str]:
    with _LOCK:
        return dict(_ACTIVE)


def _resolve(path: Path) -> Path:
    # compare on an absolute, symlink-free path so "nmap/x.txt" and "./nmap/x.txt" are one key.
    # strict=False: the file usually does not exist yet — that is the point of claiming it.
    try:
        return Path(path).resolve(strict=False)
    except OSError:
        return Path(path).absolute()


def scan_output(nmap_dir: Path, command: str, target: str = "") -> Path:
    """A distinct output file per distinct nmap command.

    Both the preset-scan and custom-scan paths used to hardcode `tcp-versioned.txt` for a
    single-host project, so a `--script vuln` preset and the versioned battery scan overwrote each
    other's output — and each parsed the other's file. Keying on the command makes a re-run of the
    SAME command reuse its file (so `--resume` and the history stay meaningful) while any different
    command gets its own.
    """
    stem = _slug(target) if target else _slug(command.split()[-1] if command.split() else "scan")
    return Path(nmap_dir) / f"scan-{stem}-{digest(command)}.txt"


def disambiguate(rel: str, settings: str) -> str:
    """Add a short settings digest to a relative output path when the settings are non-default.

    `settings` is any stable string describing what makes this run different (extensions, status
    codes, threads, depth). Empty settings leave the path untouched, so existing filenames — and the
    tests that assert them — are unchanged for a plain run.
    """
    if not settings.strip():
        return rel
    path = Path(rel)
    return str(path.with_name(f"{path.stem}-{digest(settings, 6)}{path.suffix}"))


def for_port(rel: str, port: int) -> str:
    """Nest a module's output under the port it was run against — `snmp/x.txt` -> `snmp/161/x.txt`.

    Idempotent: a path that already carries a numeric port segment is returned unchanged, so this
    can be applied on both the GUI and CLI paths without double-nesting.
    """
    if not port:
        return rel
    parts = Path(rel).parts
    if len(parts) < 2 or parts[1].isdigit():
        return rel
    return str(Path(parts[0]) / str(port) / Path(*parts[1:]))
