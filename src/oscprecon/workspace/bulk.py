from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from oscprecon import audit, vault_export
from oscprecon.profile import Profile
from oscprecon.reporter import Reporter
from oscprecon.workspace import health, locks

# a bulk op receives a loaded, writable Profile and returns (ok, message). It must be read-only-safe
# (never a scan / credential attempt / command execution / deletion).
BulkOp = Callable[[Profile], "tuple[bool, str]"]


@dataclass
class BulkResult:
    profile: str
    ok: bool
    message: str


def _safe_load(directory: Path) -> Profile | None:
    try:
        return Profile.load(directory)
    except Exception:  # boundary: a corrupt/unreadable profile is skipped, not fatal
        return None


def run_bulk(
    directories: list[Path],
    op: BulkOp,
    *,
    action: str = "bulk-action",
    cancel: threading.Event | None = None,
    skip_locked: bool = True,
) -> list[BulkResult]:
    """Apply `op` to each profile. Never stops on the first failure; skips locked/corrupt profiles;
    cancellable between profiles; audits each outcome. Returns a per-profile result."""
    results: list[BulkResult] = []
    for directory in directories:
        directory = Path(directory)
        name = directory.name
        if cancel is not None and cancel.is_set():
            results.append(BulkResult(name, False, "cancelled"))
            continue
        info, _malformed = locks.read_lock(directory)
        if (
            skip_locked
            and info is not None
            and not locks.is_stale(info)
            and not locks.is_ours(info)
        ):
            results.append(BulkResult(name, False, "skipped (locked by another instance)"))
            continue
        profile = _safe_load(directory)
        if profile is None:
            results.append(BulkResult(name, False, "skipped (corrupt / unreadable)"))
            continue
        try:
            ok, message = op(profile)
        except Exception as exc:  # boundary: one failure must not abort the batch
            ok, message = False, f"failed: {exc}"
        results.append(BulkResult(name, ok, message))
        # best-effort audit of the outcome (never propagates)
        audit.record(directory, profile.profile_name, action, details={"ok": ok, "op": action})
    return results


# --- op factories (all read-only-safe organizational actions) ---


def add_tag(tag: str) -> BulkOp:
    def op(profile: Profile) -> tuple[bool, str]:
        added = profile.add_tag(tag)
        return True, (f"added tag '{tag}'" if added else f"tag '{tag}' already present")

    return op


def remove_tag(tag: str) -> BulkOp:
    def op(profile: Profile) -> tuple[bool, str]:
        removed = profile.remove_tag(tag)
        return True, (f"removed tag '{tag}'" if removed else f"tag '{tag}' not present")

    return op


def set_status(status: str) -> BulkOp:
    def op(profile: Profile) -> tuple[bool, str]:
        profile.set_status(status)
        return True, f"status -> {profile.organization_meta().status}"

    return op


def set_archived(archived: bool) -> BulkOp:
    def op(profile: Profile) -> tuple[bool, str]:
        profile.set_archived(archived)
        return True, ("archived" if archived else "restored")

    return op


def generate_report() -> BulkOp:
    def op(profile: Profile) -> tuple[bool, str]:
        path = Reporter(profile).write()
        return True, f"report -> {path.name}"

    return op


def export_project(dest_root: Path) -> BulkOp:
    def op(profile: Profile) -> tuple[bool, str]:
        out = vault_export.export_vault(profile, Path(dest_root))
        return True, f"exported -> {out.name}"

    return op


def health_check() -> BulkOp:
    def op(profile: Profile) -> tuple[bool, str]:
        issues = health.check_profile(profile.directory)
        errors = sum(1 for i in issues if i.severity == "error")
        warnings = sum(1 for i in issues if i.severity == "warning")
        return errors == 0, f"{errors} error(s), {warnings} warning(s)"

    return op
