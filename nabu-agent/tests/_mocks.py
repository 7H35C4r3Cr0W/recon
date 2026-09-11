"""Shared test doubles for the engine seam + the LLM provider, so every integration test mocks recon
the same way instead of re-monkeypatching the same eight functions inline. Keeps the mock behaviour
in ONE place (a drift there was silently diverging per-file copies)."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

_DEFAULT_SERVICES = [{"port": 445, "proto": "tcp", "service": "smb", "product": "Samba"}]


def _slug(target: str) -> str:
    return "".join(c if (c.isalnum() or c in ".-") else "_" for c in target)


def install_recon_mocks(monkeypatch, tmp_path, *, live_hosts: list[str],
                        services: list[dict] | None = None,
                        findings: list[dict] | None = None) -> None:
    """Patch the engine seam for a recon run: each (project, target) gets its OWN per-target Profile
    dir under ``tmp_path``; ``check_alive`` on a CIDR returns ``live_hosts`` (a single host returns
    itself); scan/enum/report are no-ops; ``list_discovered_services`` and ``load_findings`` return
    the given rows. No nmap, no live targets."""
    import oscprecon.findings as ef
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine import workspace as ews

    svcs = list(services if services is not None else _DEFAULT_SERVICES)
    finds = list(findings if findings is not None else [])

    class _Prof:
        def __init__(self, scope: str) -> None:
            self.directory = tmp_path / _slug(scope)
            self.directory.mkdir(parents=True, exist_ok=True)
            self.profile_name = scope

    monkeypatch.setattr(ews, "workspace_for",
                        lambda pid, scope, *a, **k: SimpleNamespace(open_or_create=lambda: _Prof(scope)))

    def _alive(profile, target=None, **k) -> dict[str, Any]:
        if target and "/" in target:
            return {"up": True, "count": len(live_hosts), "hosts": list(live_hosts)}
        return {"up": True, "count": 1, "hosts": [target]}

    monkeypatch.setattr(etools, "check_alive", _alive)
    monkeypatch.setattr(etools, "run_scan", lambda p, sp="default", **k: {"services": []})
    monkeypatch.setattr(etools, "list_discovered_services", lambda p: {"services": list(svcs)})
    monkeypatch.setattr(etools, "enum_service",
                        lambda p, s, m="full", **k: {"service": s, "summary": [], "findings_added": len(finds)})
    monkeypatch.setattr(etools, "generate_report", lambda p, **k: {"markdown": "# r"})
    monkeypatch.setattr(ef, "load_findings", lambda d: list(finds))


class SmartProvider:
    """Stateless scripted fake LLM: finish once a tool result is in the conversation, else call the
    first offered tool with minimal valid args. Handles every role, concurrently. Swapping the fake
    for a real endpoint is config-only (NABU_LLM_*)."""
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

    async def aclose(self):
        return None

    def stream(self, request):
        raise NotImplementedError

    def count_tokens(self, messages, tools=()):
        return 10
