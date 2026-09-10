"""LLM-driven 'agent' run, end-to-end, with a SCRIPTED fake provider (via build_provider) and MOCKED
engine tools. Proves: with NABU_LLM_BASE_URL configured, the brain drives enumeration through the
AgentRunner and the run streams live map events (host → services → LLM agent → report → done). On the
internal network, swapping the fake for the real endpoint is a config change only."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.asyncio


@pytest.fixture
def brain_and_engine(monkeypatch, tmp_path):
    from nabu_agent.llm import factory
    from nabu_agent.llm.base import ChatResponse, ToolCall, Usage
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine import workspace as ews
    from nabu_agent.settings import get_settings

    svc = SimpleNamespace(port=445, proto="tcp", service="smb", product="Samba", version="4.15",
                          nmap_scripts_output="", state="open")
    profile = SimpleNamespace(directory=tmp_path, profile_name="p",
                              target=SimpleNamespace(ip="10.10.10.5", hostname=None),
                              discovered_services=[svc], credentials=lambda: [])
    fake_ws = SimpleNamespace(open=lambda: profile, open_or_create=lambda: profile, exists=lambda: True)
    monkeypatch.setattr(ews, "workspace_for", lambda *a, **k: fake_ws)
    from nabu_agent.agents.tools import dispatch as _td
    monkeypatch.setattr(_td, "workspace_for", lambda *a, **k: fake_ws)

    monkeypatch.setattr(etools, "run_scan", lambda p, sp="default", **k: (k.get("on_line") and k["on_line"]("[scan] 445/tcp open — Samba"), {"services": []})[1])
    monkeypatch.setattr(etools, "list_discovered_services", lambda p: {"services": [
        {"port": 445, "proto": "tcp", "service": "smb", "product": "Samba"}]})
    monkeypatch.setattr(etools, "enum_service", lambda p, s, m="full", **k: {"service": s, "summary": ["null session ok"], "credentials_added": 0, "findings_added": 1})
    monkeypatch.setattr(etools, "generate_report", lambda p, **k: {"markdown": "# report", "path": str(tmp_path / "r.md")})

    class FakeProvider:
        model = "fake-gpt"
        _script = [
            ChatResponse(content="", tool_calls=[ToolCall(id="c1", name="enum_service", arguments='{"service":"smb","port":445}')],
                         finish_reason="tool_calls", usage=Usage(total_tokens=30), model="fake-gpt"),
            ChatResponse(content="SMB allows a null session; signing not required.", tool_calls=[],
                         finish_reason="stop", usage=Usage(total_tokens=20), model="fake-gpt"),
        ]
        async def chat(self, request):
            return self._script.pop(0)
        def stream(self, request):
            raise NotImplementedError
        def count_tokens(self, messages, tools=()):
            return 10

    monkeypatch.setattr(factory, "build_provider", lambda settings: FakeProvider())
    monkeypatch.setenv("NABU_LLM_BASE_URL", "http://fake.internal/v1")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def test_agent_run_streams_live_map(client, brain_and_engine):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Agent"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    # llm health reflects the configured brain
    assert (await client.get("/api/llm/health")).json()["configured"] is True
    rr = await client.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5", "kind": "agent"})
    assert rr.status_code == 200, rr.text
    run_id = rr.json()["run_id"]

    types, node_ids = set(), set()
    for _ in range(60):
        await asyncio.sleep(0.1)
        for e in (await client.get(f"/api/runs/{run_id}/events")).json()["events"]:
            types.add(e["type"])
            if e["data"].get("node_id"): node_ids.add(e["data"]["node_id"])
        if "done" in types:
            break
    assert "done" in types, f"agent run did not finish; types={types}"
    assert f"host-10.10.10.5" in node_ids
    assert f"agent-llm-{run_id}" in node_ids  # the LLM agent node appeared + moved on the map
    assert f"report-{run_id}" in node_ids
    assert (await client.get(f"/api/runs/{run_id}")).json()["state"] == "done"
