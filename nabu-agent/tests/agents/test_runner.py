"""AgentRunner drives the tool-calling loop against a SCRIPTED fake provider (no real LLM). Proves:
the loop dispatches allowed tools, feeds results back, terminates on a final answer; and the
SafetyGate blocks a tool the role isn't allowed / any exploit-shaped argument."""
from __future__ import annotations

import json

import pytest

from nabu_agent.agents.runner import AgentRunner
from nabu_agent.agents.safety import SafetyGate
from nabu_agent.engine.errors import AutonomyViolation
from nabu_agent.llm.base import ChatRequest, ChatResponse, Message, ToolCall, ToolSpec, Usage



class FakeProvider:
    """Returns a scripted sequence of ChatResponses (tool_calls then a final answer)."""
    model = "fake-1"

    def __init__(self, script: list[ChatResponse]):
        self._script = script
        self.calls: list[ChatRequest] = []

    async def chat(self, request: ChatRequest) -> ChatResponse:
        self.calls.append(request)
        return self._script.pop(0)

    def stream(self, request):  # pragma: no cover - unused here
        raise NotImplementedError

    def count_tokens(self, messages, tools=()) -> int:
        return 10


@pytest.mark.asyncio
async def test_runner_dispatches_then_finishes(monkeypatch):
    # mock the engine dispatch so no real Profile/tools are needed
    from nabu_agent.agents.tools import dispatch as td

    async def fake_dispatch(name, args, *, project_id, target, on_line=None, cancel=None):
        return {"tool": name, "args": args, "ok": True}
    monkeypatch.setattr(td, "dispatch", fake_dispatch)

    script = [
        ChatResponse(content="", tool_calls=[ToolCall(id="c1", name="list_discovered_services", arguments="{}")],
                     finish_reason="tool_calls", usage=Usage(total_tokens=20), model="fake-1"),
        ChatResponse(content="", tool_calls=[ToolCall(id="c2", name="enum_service", arguments='{"service":"smb","port":445}')],
                     finish_reason="tool_calls", usage=Usage(total_tokens=20), model="fake-1"),
        ChatResponse(content="Enumerated SMB; signing not required.", tool_calls=[],
                     finish_reason="stop", usage=Usage(total_tokens=15), model="fake-1"),
    ]
    runner = AgentRunner("enum_writer", FakeProvider(script), project_id="p1", target="10.10.10.5")
    result = await runner.run({"target": "10.10.10.5", "services": [{"port": 445, "service": "smb"}]})
    assert "SMB" in result["content"]
    assert result["steps"] == 2  # two tool rounds before the final answer


def test_safety_gate_blocks_disallowed_and_exploit_args():
    gate = SafetyGate(frozenset({"enum_service", "list_discovered_services"}))
    # a tool outside the role allowlist is refused (not raised, returned as not-allowed)
    assert not gate.check("generate_report", {}).allowed
    # an exploit-shaped argument is a hard AutonomyViolation
    with pytest.raises(AutonomyViolation):
        gate.check("enum_service", {"exploit": True})
    # a normal call is allowed
    assert gate.check("enum_service", {"service": "smb"}).allowed
