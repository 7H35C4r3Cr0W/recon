"""Unit: the run state machine's forward-only transitions."""
from __future__ import annotations

from nabu_agent.orchestration.states import TERMINAL, RunState, can_transition


def test_happy_path_transitions() -> None:
    assert can_transition(RunState.QUEUED, RunState.VALIDATING)
    assert can_transition(RunState.SCANNING, RunState.FAN_OUT)
    assert can_transition(RunState.REPORT_READY, RunState.DONE)


def test_terminal_states_are_dead_ends() -> None:
    for t in TERMINAL:
        assert not can_transition(t, RunState.QUEUED)


def test_recon_never_auto_enters_approval() -> None:
    # Only report_ready may branch to awaiting_approval (a human/agent-proposal step), never scanning.
    assert not can_transition(RunState.SCANNING, RunState.AWAITING_APPROVAL)
    assert can_transition(RunState.REPORT_READY, RunState.AWAITING_APPROVAL)
