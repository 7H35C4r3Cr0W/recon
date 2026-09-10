"""Host tier for the LLM 'agent' kind — a CIDR run alive-sweeps and fans out the FULL roster
(planner -> enum -> research -> reporter) PER host, each host its own host-scoped subtree, with a
stateless scripted fake provider + mocked engine tools. Proves the per-host roster nodes appear with
no cross-host collision and the run finishes."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.asyncio


class _SmartProvider:
    """Stateless per-call fake: finish once a tool result is in the conversation, else call the first
    offered tool with minimal valid args."""
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


def _setup(monkeypatch, tmp_path, live_hosts):
    import oscprecon.findings as ef
    from nabu_agent.agents.tools import dispatch as td
    from nabu_agent.engine import gateway
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine import workspace as ews
    from nabu_agent.llm import factory
    from nabu_agent.settings import get_settings

    profile = SimpleNamespace(directory=tmp_path, profile_name="p",
                              target=SimpleNamespace(ip="10.10.10.5", hostname=None),
                              discovered_services=[], credentials=lambda: [])
    ws = SimpleNamespace(open=lambda: profile, open_or_create=lambda: profile, exists=lambda: True)
    monkeypatch.setattr(ews, "workspace_for", lambda *a, **k: ws)
    monkeypatch.setattr(td, "workspace_for", lambda *a, **k: ws)
    monkeypatch.setattr(ef, "load_findings", lambda d: [])

    def _alive(p, t=None, **k):
        if t and "/" in t:
            return {"up": True, "count": len(live_hosts), "hosts": list(live_hosts)}
        return {"up": True, "count": 1, "hosts": [t]}
    monkeypatch.setattr(etools, "check_alive", _alive)

    dto = [{"port": 445, "proto": "tcp", "service": "smb", "product": "Samba"},
           {"port": 80, "proto": "tcp", "service": "http", "product": "nginx"}]
    monkeypatch.setattr(etools, "run_scan", lambda p, sp="default", **k: {"services": []})
    monkeypatch.setattr(etools, "list_discovered_services", lambda p: {"services": dto})
    monkeypatch.setattr(etools, "enum_service",
                        lambda p, s, m="full", **k: {"service": s, "summary": [], "credentials_added": 0, "findings_added": 0})
    monkeypatch.setattr(etools, "research_finding", lambda p, f, **k: {"reference": None, "edb": []})
    monkeypatch.setattr(etools, "suggest_next_steps", lambda p: {"next_steps": []})
    monkeypatch.setattr(etools, "catalog_actions_for", lambda s, e, **k: {"service": s, "actions": []})
    monkeypatch.setattr(etools, "generate_report", lambda p, **k: {"markdown": "# report", "path": str(tmp_path / "r.md")})
    monkeypatch.setattr(gateway, "list_services", lambda pid, scope, host: dto)
    monkeypatch.setattr(gateway, "list_findings", lambda pid, scope, host: [])
    monkeypatch.setattr(factory, "build_provider", lambda settings: _SmartProvider())
    monkeypatch.setenv("NABU_LLM_BASE_URL", "http://fake.internal/v1")
    get_settings.cache_clear()


async def test_cidr_agent_roster_fans_out_per_host(client, monkeypatch, tmp_path):
    hosts = ["10.10.10.5", "10.10.10.6"]
    _setup(monkeypatch, tmp_path, hosts)
    try:
        await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
        pid = (await client.post("/api/projects", json={"display_name": "CIDR-agent"})).json()["id"]
        await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.0/24"})
        rr = await client.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.0/24", "kind": "agent"})
        assert rr.status_code == 200, rr.text
        run_id = rr.json()["run_id"]

        node_ids, types, edges = set(), set(), set()
        for _ in range(200):
            await asyncio.sleep(0.1)
            for e in (await client.get(f"/api/runs/{run_id}/events")).json()["events"]:
                types.add(e["type"])
                if e["data"].get("node_id"):
                    node_ids.add(e["data"]["node_id"])
                for edge in (e["data"].get("edges") or []):
                    edges.add((edge["source"], edge["target"]))
            if "done" in types:
                break
        assert "done" in types, f"agent CIDR run did not finish; types={types}"
    finally:
        from nabu_agent.settings import get_settings
        get_settings.cache_clear()

    # every host got its OWN full roster subtree — no cross-host node collisions
    for h in hosts:
        assert f"host-{h}" in node_ids, f"missing host node for {h}"
        assert f"agent-planner-{h}" in node_ids, f"missing planner for {h}"
        assert {f"agent-enum-{h}-445", f"agent-enum-{h}-80"} <= node_ids, f"missing enum agents for {h}"
        assert {f"agent-research-{h}-445", f"agent-research-{h}-80"} <= node_ids, f"missing research for {h}"
        assert f"agent-report-{h}" in node_ids, f"missing reporter for {h}"
        # hand-off edges are host-local (planner -> that host's enum; that host's enum -> its reporter)
        assert (f"agent-planner-{h}", f"agent-enum-{h}-445") in edges
        assert (f"agent-enum-{h}-445", f"agent-report-{h}") in edges
    assert len([n for n in node_ids if n.startswith("agent-planner-")]) == 2
