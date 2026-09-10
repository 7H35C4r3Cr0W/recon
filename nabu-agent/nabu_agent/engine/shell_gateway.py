"""THE single ``shell.run`` chokepoint for the whole platform.

This module is the *only* place in ``nabu_agent`` that imports and calls the classic engine's
``oscprecon.shell.run``. A policy-invariant test (``tests/policy_invariants/test_single_chokepoint.py``)
asserts this structurally: no other module calls ``shell.run``, nothing uses ``subprocess`` /
``os.system`` / ``shell=True``, and ``exploit=True`` appears nowhere except in
:func:`execute_gated_action`.

It layers three carried-over invariants ON TOP of the engine's own ``policy_violation`` allow-list
(which still runs inside ``shell.run`` — this is defence in depth, never a replacement):

1. **Scope-lock** — :func:`assert_in_scope` validates a target with the engine's own validators
   *and* confirms it is inside the project's authorized scope, before ``shell.run`` sees it.
2. **No blind auto-exploit** — :func:`run_recon_tool` hard-wires ``spray=False, exploit=False`` and
   exposes **no parameter** to raise them, so no agent/tool-dispatch path can reach the policy
   bypass. The only place ``exploit=True`` / ``spray=True`` can be set is
   :func:`execute_gated_action`, which refuses unless handed a human-approved checkpoint.
3. **Audit** — every executed / state-changing call is recorded with the engine's kebab slugs.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol

# --- read-only imports from the classic engine (never edited from here) ---
# NOTE: import the audit MODULE under an alias — the public helper below is named `audit`, and a
# bare `from oscprecon import audit` would be shadowed by that def (a real bug caught in review).
from oscprecon import audit as engine_audit
from oscprecon import shell
from oscprecon.models import validate_host_or_range
from oscprecon.profile import Profile

from .errors import (
    AttackGateClosed,
    ScopeViolation,
    ToolBlocked,
    ToolMissing,
)
from .schemas import ShellResultDTO, to_shell_dto

OnLine = Callable[[str], None] | None


# --------------------------------------------------------------------------- scope-lock


def _within(target: str, scope: str) -> bool:
    """True iff ``target`` is the scope host or a member of the scope CIDR."""
    try:
        net = ipaddress.ip_network(scope, strict=False)
    except ValueError:
        return target == scope  # scope is a hostname → require exact match
    try:
        return ipaddress.ip_address(target) in net
    except ValueError:
        return False


def assert_in_scope(profile: Profile, target: str, *, allowlist: Sequence[str] | None = None) -> str:
    """Validate ``target`` and confirm it is authorized for this project.

    Uses the engine's own validators so the argv-injection guard (rejects leading ``-`` /
    whitespace) is byte-for-byte identical to the classic tool. "Authorized" means the target
    equals — or is inside — the project's assigned scope (``profile.target.ip``) or any entry in
    the optional ``allowlist`` (the DB ``scope_targets`` rows; a promoted pivot must be added there
    explicitly by a human first). Anything else — the VPN gateway, a control panel, a neighbour that
    happened to answer — is a hard :class:`ScopeViolation` and the tool never runs.
    """
    try:
        validated = validate_host_or_range(target)
    except ValueError as exc:
        raise ScopeViolation(f"target {target!r} failed validation: {exc}") from exc

    scopes = [profile.target.ip, *(allowlist or [])]
    for scope in scopes:
        if validated == scope or _within(validated, scope):
            return validated
    raise ScopeViolation(f"target {target!r} is outside the project scope {scopes!r}")


# --------------------------------------------------------------------------- recon chokepoint


def run_recon_tool(
    profile: Profile,
    shell_line: str,
    output_file: Path,
    *,
    on_line: OnLine = None,
    cancel: threading.Event | None = None,
    timeout: float | None = None,
    audit_slug: str | None = None,
    actor: str = "system",
) -> ShellResultDTO:
    """Execute one engine-built recon command through the imported ``shell.run``.

    RECON ONLY. ``spray`` / ``exploit`` are hard-wired ``False`` and there is deliberately **no
    parameter** to raise them — this is what makes the "no blind auto-exploit" invariant structural
    rather than a convention. A per-step ``timeout`` is mandated so the engine's own
    ``threading.Timer`` ``killpg`` fires independently of orchestration liveness.

    ``shell.run`` never raises; blocked (exit 126) / missing-tool (exit 127) are returned as fields.
    Wrap with :func:`raise_for_result` if you want them as typed errors.
    """
    result = shell.run(
        shell_line,
        output_file,
        cwd=profile.directory,
        timeout=timeout,
        cancel=cancel,
        on_line=on_line,
        spray=False,
        exploit=False,
    )
    if audit_slug:
        audit(profile, audit_slug, actor=actor, details={
            "shell_line": _redact(shell_line),
            "exit_code": result.exit_code,
            "blocked": result.blocked,
            "missing_tool": result.missing_tool,
        })
    return to_shell_dto(result)


def raise_for_result(dto: ShellResultDTO) -> ShellResultDTO:
    """Turn a blocked/missing ``ShellResult`` into a typed error; pass real runs through.

    exit 126 + ``blocked`` → :class:`ToolBlocked` (policy gate refused; nothing executed).
    exit 127 + ``missing_tool`` → :class:`ToolMissing` (binary not on PATH).
    A non-zero exit from a tool that *ran* is not an error here — tool output is data.
    """
    if dto["blocked"]:
        raise ToolBlocked(dto["blocked"])
    if dto["missing_tool"]:
        raise ToolMissing(dto["missing_tool"])
    return dto


# --------------------------------------------------------------------------- human-gated attack path


class _CheckpointLike(Protocol):
    """The subset of an approved checkpoint this module verifies (duck-typed to avoid importing
    the orchestration layer, which sits *above* the engine adapter)."""

    status: str  # must == "approved"
    approved_by: str | None  # must be a real human user id
    kind: str  # "spray" | "exploit"
    target: str
    exploit_confirmed: bool


def execute_gated_action(
    checkpoint: _CheckpointLike,
    profile: Profile,
    shell_line: str,
    output_file: Path,
    *,
    on_line: OnLine = None,
    cancel: threading.Event | None = None,
    timeout: float | None = None,
    allowlist: Sequence[str] | None = None,
) -> ShellResultDTO:
    """The **sole** place ``spray=True`` / ``exploit=True`` may be set (the whole engine policy gate
    is bypassed on ``exploit=True``, so this path is the one, human-owned door to it).

    It refuses unless handed a checkpoint that a human has already approved (``status == "approved"``
    with a non-null ``approved_by``), re-validates the target against scope, and only then calls the
    engine chokepoint with the gate flags. The checkpoint id is server-minted and verified against
    Postgres by the caller (``routers/runs.py``) before this runs — it is never forwarded from the
    LLM/agent layer.
    """
    if getattr(checkpoint, "status", "") != "approved" or not getattr(checkpoint, "approved_by", None):
        raise AttackGateClosed("gated action requires a human-approved checkpoint")

    kind = getattr(checkpoint, "kind", "")
    if kind == "exploit" and not getattr(checkpoint, "exploit_confirmed", False):
        raise AttackGateClosed("exploit requires an explicit per-action human confirmation")

    # Re-validate scope at execution time (defence in depth against a stale/forged target).
    assert_in_scope(profile, checkpoint.target, allowlist=allowlist)

    spray = kind == "spray"
    exploit = kind == "exploit"
    result = shell.run(
        shell_line,
        output_file,
        cwd=profile.directory,
        timeout=timeout,
        cancel=cancel,
        on_line=on_line,
        spray=spray,
        exploit=exploit,  # the ONE exploit=... site in the whole codebase
    )
    audit(profile, "spray" if spray else "run-command", actor=checkpoint.approved_by, details={
        "shell_line": _redact(shell_line),
        "kind": kind,
        "exit_code": result.exit_code,
        "blocked": result.blocked,
        "gated": True,
    })
    return to_shell_dto(result)


# --------------------------------------------------------------------------- audit


def audit(profile: Profile, action: str, *, details: dict[str, Any] | None = None, actor: str = "system") -> None:
    """Record a state-changing / executed action with the engine's kebab slugs (best-effort;
    ``engine_audit.record`` swallows all exceptions — never gate logic on it)."""
    engine_audit.record(profile.directory, profile.profile_name, action, actor=actor, details=details or {})


def _redact(shell_line: str) -> str:
    """Use the engine's own command redactor when present (ships OFF by owner policy, but the hook
    exists); fall back to the raw line."""
    redactor = getattr(shell, "redact_command", None)
    return redactor(shell_line) if callable(redactor) else shell_line
