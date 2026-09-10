"""LLM-driven 'agent' run with the FULL roster (planner → enum agents → research agents → reporter),
end to end, with a stateless SCRIPTED fake provider and mocked engine tools. Proves every role's node
appears on the live map and the run finishes. Swapping the fake for a real endpoint is config-only."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.asyncio


class _SmartProvider:
    """Stateless per-call fake: if a tool result is already in the conversation, finish; otherwise
    call the first offered tool with minimal valid args. Handles every role, concurrently."""
    model = "fake-gpt"
    _ARGS = {"enum_service": '{"service":"smb","port":445}',
             "catalog_actions_for": '{"service":"smb"}',
             "research_finding": '{"finding":{"service":"smb","port":445}}'}

    async def chat(self, request):
        from nabu_agent.llm.base import ChatResponse, ToolCall, Usage
        if any(getattr(m.role, "value", m.role) == "tool" for m in request.messages):
            return ChatResponse(content="assessment complete.", tool_calls=[], finish_reason="stop",
                                usage=Usage(total_tokens=10), model=self.model)
        if request.tools:
            name = request.tools[0].name
            return ChatResponse(content="", tool_calls=[ToolCall(id="c", name=name,
                                arguments=self._ARGS.get(name, "{}"))],
                                finish_reason="tool_calls", usage=Usage(total_tokens=10), model=self.model)
        return ChatResponse(content="done", tool_calls=[], finish_reason="stop",
                            usage=Usage(total_tokens=5), model=self.model)

    def stream(self, request):
        raise NotImplementedError

    def count_tokens(self, messages, tools=()):
        return 10


@pytest.fixture
def brain_and_engine(monkeypatch, tmp_path):
    from nabu_agent.agents.tools import dispatch as td
    from nabu_agent.engine import gateway, tools as etools, workspace as ews
    from nabu_agent.llm import factory
    from nabu_agent.settings import get_settings
    import oscprecon.findings as ef

    svcs = [SimpleNamespace(port=445, proto="tcp", service="smb", product="Samba", version="4.15",
                            nmap_scripts_output="", state="open"),
            SimpleNamespace(port=80, proto="tcp", service="http", product="nginx", version="1.18",
                            nmap_scripts_output="", state="open")]
    profile = SimpleNamespace(directory=tmp_path, profile_name="p",
                              target=SimpleNamespace(ip="10.10.10.5", hostname=None),
                              discovered_services=svcs, credentials=lambda: [])
    ws = SimpleNamespace(open=lambda: profile, open_or_create=lambda: profile, exists=lambda: True)
    monkeypatch.setattr(ews, "workspace_for", lambda *a, **k: ws)
    monkeypatch.setattr(td, "workspace_for", lambda *a, **k: ws)
    monkeypatch.setattr(ef, "load_findings", lambda d: [])

    dto = [{"port": 445, "proto": "tcp", "service": "smb", "product": "Samba"},
           {"port": 80, "proto": "tcp", "service": "http", "product": "nginx"}]
    monkeypatch.setattr(etools, "run_scan", lambda p, sp="default", **k: {"services": []})
    monkeypatch.setattr(etools, "list_discovered_services", lambda p: {"services": dto})
    monkeypatch.setattr(etools, "enum_service", lambda p, s, m="full", **k: {"service": s, "summary": [], "credentials_added": 0, "findings_added": 0})
    monkeypatch.setattr(etools, "research_finding", lambda p, f, **k: {"reference": None, "edb": []})
    monkeypatch.setattr(etools, "suggest_next_steps", lambda p: {"next_steps": []})
    monkeypatch.setattr(etools, "catalog_actions_for", lambda s, e, **k: {"service": s, "actions": []})
    monkeypatch.setattr(etools, "generate_report", lambda p, **k: {"markdown": "# report", "path": str(tmp_path / "r.md")})
    monkeypatch.setattr(gateway, "list_services", lambda pid, scope, host: dto)
    monkeypatch.setattr(gateway, "list_findings", lambda pid, scope, host: [])

    monkeypatch.setattr(factory, "build_provider", lambda settings: _SmartProvider())
    monkeypatch.setenv("NABU_LLM_BASE_URL", "http://fake.internal/v1")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def test_agent_run_full_roster(client, brain_and_engine):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Agents"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    assert (await client.get("/api/llm/health")).json()["configured"] is True
    run_id = (await client.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5", "kind": "agent"})).json()["run_id"]

    types, node_ids, states = set(), set(), set()
    for _ in range(100):
        await asyncio.sleep(0.1)
        for e in (await client.get(f"/api/runs/{run_id}/events")).json()["events"]:
            types.add(e["type"])
            if e["data"].get("node_id"): node_ids.add(e["data"]["node_id"])
            if e["data"].get("node_state"): states.add(e["data"]["node_state"])
        if "done" in types:
            break
    assert "done" in types, f"agent run did not finish; types={types}"
    # every role node appeared on the live map
    assert f"agent-planner-{run_id}" in node_ids
    assert {"agent-enum-445", "agent-enum-80"} <= node_ids       # one enum agent per service
    assert {"agent-research-445", "agent-research-80"} <= node_ids  # one research agent per service
    assert f"agent-report-{run_id}" in node_ids
    assert {"active", "done"} <= states
    assert (await client.get(f"/api/runs/{run_id}")).json()["state"] in {"done", "partial"}
