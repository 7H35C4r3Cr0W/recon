from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

# why: a project archive is a portable copy of one <workspace>/<name>/ folder (§19). Import is the
# dangerous direction — a hostile .tar.gz can carry ../ traversal, absolute paths, symlinks or
# device nodes. We validate EVERY member before extracting, reject links/specials, and confirm the
# result is a real profile. Export is benign (the user's own copy) but drops transient state.

# transient process-state that must not travel in an archive (a stale lock would confuse import).
_TRANSIENT_NAMES = frozenset({".lock"})
_TRANSIENT_SUFFIXES = frozenset({".tmp"})
# rename-artifacts from a crashed stale-lock recovery (.lock.stale.<pid>) — never put in an export.
_TRANSIENT_PREFIXES = (".lock.stale.", ".import-")

# why: refuse a decompression bomb — a tiny .tar.gz can declare gigabytes of content and fill the
# disk on extract. A real recon profile is far below this; the cap only stops pathological archives.
_MAX_TOTAL_BYTES = 2 * 1024**3
# ...and cap the member COUNT: a bomb can declare ~0 bytes yet millions of empty files, exhausting
# inodes / making extraction pathologically slow. A real profile has well under this many files.
_MAX_MEMBERS = 200_000


class ProjectArchiveError(Exception):
    """An invalid export target, or an unsafe / malformed project archive on import."""


class ProjectExistsError(ProjectArchiveError):
    """Import would clobber an existing profile; retry with overwrite=True to replace it."""


def find_profiles_by_ip(workspace_root: Path, ip: str) -> list[Path]:
    # scan <workspace>/*/profile.json and return every dir whose target.ip matches — fast recovery
    # when the profile name is forgotten. Corrupt/partial profiles are skipped, never raised.
    wanted = ip.strip()
    matches: list[Path] = []
    if not wanted:
        return matches
    try:
        entries = sorted(p for p in workspace_root.iterdir() if p.is_dir())
    except OSError:
        return matches
    for directory in entries:
        meta = directory / "profile.json"
        if not meta.is_file():
            continue
        try:
            raw = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        target = raw.get("target") if isinstance(raw, dict) else None
        if isinstance(target, dict) and str(target.get("ip", "")) == wanted:
            matches.append(directory)
    return matches


def delete_project(profile_dir: Path, workspace_root: Path) -> None:
    # Permanently remove one <workspace_root>/<name>/ folder. Guarded: the target must be a direct
    # child directory of workspace_root — never the root itself, a parent, an unrelated path, or a
    # symlink pointing outside — so a wrong path can never rmtree the wrong tree. Destructive and
    # irreversible; the caller confirms with the user first. A corrupt profile (no profile.json) is
    # still deletable so the workspace can be cleaned up.
    original = Path(profile_dir)
    workspace_root = workspace_root.resolve()
    if original.is_symlink():
        # delete the LINK entry itself, never rmtree its target — resolve() would redirect the
        # delete to a DIFFERENT real project when 'link' points at another in-workspace folder.
        raise ProjectArchiveError(f"{original} is a symlink, not a real project directory")
    profile_dir = original.resolve()
    if profile_dir == workspace_root or profile_dir.parent != workspace_root:
        raise ProjectArchiveError(f"{profile_dir} is not a project inside {workspace_root}")
    if not profile_dir.is_dir():
        raise ProjectArchiveError(f"{profile_dir} is not a directory")
    shutil.rmtree(profile_dir)


def export_project_archive(profile_dir: Path, dest: Path) -> Path:
    # pack <profile_dir> into <dest>/<name>.tar.gz (or into `dest` itself when it names a .tar.gz).
    # Includes creds.json verbatim — the caller is responsible for warning the user (§19).
    profile_dir = profile_dir.resolve()
    if not (profile_dir / "profile.json").is_file():
        raise ProjectArchiveError(f"{profile_dir} is not a profile (no profile.json)")
    name = profile_dir.name
    archive = dest / f"{name}.tar.gz" if dest.is_dir() else dest
    archive.parent.mkdir(parents=True, exist_ok=True)

    def _drop_transient(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        base = PurePosixPath(info.name).name
        if base in _TRANSIENT_NAMES or PurePosixPath(base).suffix in _TRANSIENT_SUFFIXES:
            return None
        if base.startswith(_TRANSIENT_PREFIXES):
            return None
        return info

    with tarfile.open(archive, "w:gz") as tar:
        tar.add(profile_dir, arcname=name, filter=_drop_transient)
    return archive


def import_project_archive(archive: Path, workspace_root: Path, *, overwrite: bool = False) -> Path:
    # extract into <workspace_root>/<name>/ and return that dir. Refuses to clobber an existing
    # profile unless overwrite=True. Raises ProjectArchiveError / ProjectExistsError on any problem.
    if not archive.is_file():
        raise ProjectArchiveError(f"no such archive: {archive}")
    if not tarfile.is_tarfile(archive):
        raise ProjectArchiveError(f"not a readable tar archive: {archive}")
    workspace_root = workspace_root.resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        if not members:
            raise ProjectArchiveError("archive is empty")
        name = _validate_members(members, workspace_root)
        dest = workspace_root / name
        if dest.exists() and not overwrite:
            raise ProjectExistsError(f"a profile named '{name}' already exists at {dest}")
        # why: extract to a staging dir first, confirm it's a real profile, THEN swap into place —
        # a hostile or non-profile archive never leaves partial files in the workspace, and an
        # overwrite only removes the existing profile once the replacement is known good.
        staging = Path(tempfile.mkdtemp(dir=workspace_root, prefix=".import-"))
        try:
            _extract(tar, members, staging)
            extracted = staging / name
            if not (extracted / "profile.json").is_file():
                raise ProjectArchiveError(f"archive '{name}' is not a profile (no profile.json)")
            if dest.exists():
                shutil.rmtree(dest)  # overwrite: replace only now that the new copy is validated
            shutil.move(str(extracted), str(dest))
        except tarfile.TarError as exc:
            raise ProjectArchiveError(f"failed to extract archive: {exc}") from exc
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    return dest


def _validate_members(members: list[tarfile.TarInfo], root: Path) -> str:
    root = root.resolve()
    if len(members) > _MAX_MEMBERS:
        raise ProjectArchiveError(
            f"archive has too many entries ({len(members)}); refusing (inode-exhaustion bomb)"
        )
    tops: set[str] = set()
    total = 0
    for member in members:
        raw = member.name
        if not raw or raw.startswith(("/", "\\")) or "\\" in raw:
            raise ProjectArchiveError(f"unsafe path in archive: {raw!r}")
        parts = PurePosixPath(raw).parts
        if any(part == ".." for part in parts):
            raise ProjectArchiveError(f"path traversal in archive: {raw!r}")
        if member.issym() or member.islnk():
            raise ProjectArchiveError(f"archive contains a link ({raw!r}); refusing")
        if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
            raise ProjectArchiveError(f"archive contains a special file ({raw!r}); refusing")
        target = (root / raw).resolve()
        if target != root and root not in target.parents:
            raise ProjectArchiveError(f"member escapes the workspace: {raw!r}")
        total += max(0, member.size)
        if total > _MAX_TOTAL_BYTES:
            raise ProjectArchiveError(
                "archive is too large to import (possible decompression bomb)"
            )
        if parts:  # a "." (current-dir) member has empty parts — skip it, don't IndexError
            tops.add(parts[0])
    tops.discard(".")
    if len(tops) != 1:
        raise ProjectArchiveError(
            f"archive must contain exactly one top-level profile folder, found {sorted(tops)}"
        )
    name = next(iter(tops))
    if name in ("", ".", "..") or "/" in name or "\\" in name:
        raise ProjectArchiveError(f"unsafe profile name in archive: {name!r}")
    return name


def _extract(tar: tarfile.TarFile, members: list[tarfile.TarInfo], dest: Path) -> None:
    # members are already validated; the data filter is belt-and-suspenders where available.
    try:
        tar.extractall(dest, members=members, filter="data")
    except TypeError:
        tar.extractall(dest, members=members)  # Python < 3.11.4 has no filter kwarg
