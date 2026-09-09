"""Run lifecycle state machine for Nabu Agent.

The supervisor drives one Run through these states. Recon states are fully
automated; the ONLY human gate is `awaiting_approval`, reached only when a
follow-up spray/exploit action has been proposed and needs explicit operator
sign-off (see checkpoints.py). Recon never enters `awaiting_approval`.

Engine coupling: state transitions are orchestration-only. The authoritative
recon truth lives in the oscprecon Profile folder (profile.discovered_services,
findings.json, creds.json, edb.json, audit.jsonl). This enum mirrors *where the
run is*, not *what was found*.
"""
from __future__ import annotations

from enum import StrEnum


class RunState(StrEnum):
    QUEUED = "queued"                 # accepted, not yet picked up by a worker
    VALIDATING = "validating"         # scope lock: validate_host(_or_range) + confirm == profile.target
    ALIVE_CHECK = "alive_check"       # build_alive_command / parse_alive (pre-flight, cap up-hosts)
    SCANNING = "scanning"             # Orchestrator.run_nmap (or NmapModule two-phase)
    FAN_OUT = "fan_out"               # supervisor reads discovered_services -> builds task graph
    ENRICHING = "enriching"           # per-service enum + vuln agents, parallel, capped
    RESEARCHING = "researching"       # research agents, parallel (may overlap ENRICHING)
    SYNTHESIZING = "synthesizing"     # writer/synthesis agent -> Reporter.render + LLM narrative
    REPORT_READY = "report_ready"     # report.md + next-steps produced; run may end here
    AWAITING_APPROVAL = "awaiting_approval"  # HUMAN GATE: a spray/exploit action was proposed
    EXECUTING_APPROVED = "executing_approved"  # an operator-approved attack action is running
    DONE = "done"                     # terminal success
    PARTIAL = "partial"               # terminal: scan+synth ok, >=1 agent failed/skipped
    FAILED = "failed"                 # terminal: unrecoverable (bad scope, scan produced nothing usable)
    CANCELLED = "cancelled"           # terminal: operator cancelled


TERMINAL: frozenset[RunState] = frozenset(
    {RunState.DONE, RunState.PARTIAL, RunState.FAILED, RunState.CANCELLED}
)

# Automated recon happy-path forward edges. AWAITING_APPROVAL is entered only by
# an explicit operator request to act on a proposed attack action, never by the
# recon pipeline itself.
_FORWARD: dict[RunState, frozenset[RunState]] = {
    RunState.QUEUED: frozenset({RunState.VALIDATING, RunState.CANCELLED}),
    RunState.VALIDATING: frozenset({RunState.ALIVE_CHECK, RunState.FAILED, RunState.CANCELLED}),
    RunState.ALIVE_CHECK: frozenset({RunState.SCANNING, RunState.FAILED, RunState.CANCELLED}),
    RunState.SCANNING: frozenset({RunState.FAN_OUT, RunState.FAILED, RunState.CANCELLED}),
    RunState.FAN_OUT: frozenset({RunState.ENRICHING, RunState.SYNTHESIZING, RunState.CANCELLED}),
    RunState.ENRICHING: frozenset({RunState.RESEARCHING, RunState.SYNTHESIZING, RunState.CANCELLED}),
    RunState.RESEARCHING: frozenset({RunState.SYNTHESIZING, RunState.CANCELLED}),
    RunState.SYNTHESIZING: frozenset({RunState.REPORT_READY, RunState.PARTIAL, RunState.CANCELLED}),
    RunState.REPORT_READY: frozenset(
        {RunState.DONE, RunState.PARTIAL, RunState.AWAITING_APPROVAL}
    ),
    RunState.AWAITING_APPROVAL: frozenset(
        {RunState.EXECUTING_APPROVED, RunState.DONE, RunState.PARTIAL, RunState.CANCELLED}
    ),
    RunState.EXECUTING_APPROVED: frozenset(
        {RunState.REPORT_READY, RunState.PARTIAL, RunState.FAILED, RunState.CANCELLED}
    ),
}


def can_transition(src: RunState, dst: RunState) -> bool:
    if src in TERMINAL:
        return False
    return dst in _FORWARD.get(src, frozenset())
