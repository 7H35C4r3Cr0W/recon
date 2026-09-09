"""INVARIANT (behavioural): the scope lock refuses out-of-scope targets, and a gated action refuses
an unapproved checkpoint — both BEFORE ``shell.run`` is reached."""
from __future__ import annotations

import pathlib
from dataclasses import dataclass

import pytest

pytestmark = pytest.mark.invariant

try:
    from nabu_agent.engine import shell_gateway as gw
    from nabu_agent.engine.errors import AttackGateClosed, ScopeViolation
    _HAVE_ENGINE = True
except Exception:
    _HAVE_ENGINE = False


@dataclass
class _Target:
    ip: str
    hostname: str | None = None


@dataclass
class _Profile:
    directory: pathlib.Path
    profile_name: str
    target: _Target


@dataclass
class _Checkpoint:
    status: str
    approved_by: str | None
    kind: str
    target: str
    exploit_confirmed: bool = False


def _profile(tmp_path, ip):
    return _Profile(directory=tmp_path, profile_name="p", target=_Target(ip=ip))


@pytest.mark.skipif(not _HAVE_ENGINE, reason="engine not installed")
def test_out_of_scope_refused(monkeypatch, tmp_path) -> None:
    ran = {"v": False}
    monkeypatch.setattr(gw.shell, "run", lambda *a, **k: ran.__setitem__("v", True))
    with pytest.raises(ScopeViolation):
        gw.assert_in_scope(_profile(tmp_path, "10.10.10.5"), "10.10.10.99")
    assert ran["v"] is False


@pytest.mark.skipif(not _HAVE_ENGINE, reason="engine not installed")
def test_in_scope_cidr_member_allowed(tmp_path) -> None:
    assert gw.assert_in_scope(_profile(tmp_path, "10.10.10.0/24"), "10.10.10.42") == "10.10.10.42"


@pytest.mark.skipif(not _HAVE_ENGINE, reason="engine not installed")
def test_gated_action_refuses_unapproved_checkpoint(monkeypatch, tmp_path) -> None:
    ran = {"v": False}
    monkeypatch.setattr(gw.shell, "run", lambda *a, **k: ran.__setitem__("v", True))
    cp = _Checkpoint(status="proposed", approved_by=None, kind="exploit", target="10.10.10.5")
    with pytest.raises(AttackGateClosed):
        gw.execute_gated_action(cp, _profile(tmp_path, "10.10.10.5"), "id 10.10.10.5",
                                tmp_path / "o.txt")
    assert ran["v"] is False
