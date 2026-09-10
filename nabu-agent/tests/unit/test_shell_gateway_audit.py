"""Regression: the shell_gateway audit helper must call the engine's audit.record (a name-collision
between the imported `audit` module and the local `def audit` previously made it crash — caught in
review). Also proves run_recon_tool records an audit row on its recon path."""
from __future__ import annotations

import pathlib
from dataclasses import dataclass

import pytest

try:
    from nabu_agent.engine import shell_gateway as gw
    _HAVE = True
except Exception:
    _HAVE = False

pytestmark = pytest.mark.skipif(not _HAVE, reason="engine not installed")


@dataclass
class _Target:
    ip: str
    hostname: str | None = None


@dataclass
class _Profile:
    directory: pathlib.Path
    profile_name: str
    target: _Target


def _profile(tmp_path):
    return _Profile(directory=tmp_path, profile_name="p", target=_Target(ip="10.10.10.5"))


def test_audit_helper_calls_engine_record(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(gw.engine_audit, "record", lambda *a, **k: calls.append((a, k)))
    gw.audit(_profile(tmp_path), "scan", details={"x": 1}, actor="tester")
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[2] == "scan" and kwargs["actor"] == "tester"


def test_run_recon_tool_audits_and_returns_dto(monkeypatch, tmp_path):
    class _R:
        shell_line = "nmap -sn 10.10.10.5"; exit_code = 0
        output_file = tmp_path / "o.txt"; duration_s = 0.1
        blocked = None; missing_tool = None; cancelled = False
    recorded = []
    monkeypatch.setattr(gw.shell, "run", lambda *a, **k: _R())
    monkeypatch.setattr(gw.engine_audit, "record", lambda *a, **k: recorded.append(a[2]))
    dto = gw.run_recon_tool(_profile(tmp_path), "nmap -sn 10.10.10.5", tmp_path / "o.txt",
                            audit_slug="scan")
    assert dto["exit_code"] == 0 and dto["blocked"] is None
    assert recorded == ["scan"]
