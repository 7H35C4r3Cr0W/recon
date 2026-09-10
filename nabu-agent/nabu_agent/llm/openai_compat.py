"""Default brain adapter — speaks the OpenAI-compatible Chat Completions + tool-calling API.

Point ``NABU_LLM_BASE_URL`` at the internally-hosted endpoint (GPT-5.1 today) and this adapter does
the rest: bearer auth, function/tool schemas, non-streaming :meth:`chat`, and SSE :meth:`stream`
with tool-call delta reassembly by ``index`` (servers vary — some send the tool name on the first
delta only, arguments as fragments; we accumulate defensively). No vendor SDK dependency — just
``httpx``. To swap the brain, register another adapter in :mod:`nabu_agent.llm.factory`.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence

import httpx

from . import tokens
from .base import (
    ChatChunk,
    ChatRequest,
    ChatResponse,
    LLMProvider,
    Message,
    ToolCall,
    ToolSpec,
    Usage,
)
from .config import LLMSettings
from .errors import LLMBadResponse, LLMRateLimited, LLMServerError, LLMTimeout


def _message_to_wire(m: Message) -> dict:
    wire: dict = {"role": m.role.value}
    if m.content:
        wire["content"] = m.content
    if m.tool_calls:
        wire["tool_calls"] = [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.name, "arguments": tc.arguments}}
            for tc in m.tool_calls
        ]
    if m.tool_call_id:
        wire["tool_call_id"] = m.tool_call_id
    if m.name:
        wire["name"] = m.name
    return wire


def _tool_to_wire(t: ToolSpec) -> dict:
    return {"type": "function",
            "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}


def _body(req: ChatRequest, settings: LLMSettings, *, stream: bool) -> dict:
    body: dict = {
        "model": settings.model,
        "messages": [_message_to_wire(m) for m in req.messages],
        "temperature": req.temperature if req.temperature is not None else settings.temperature,
        "top_p": req.top_p if req.top_p is not None else settings.top_p,
        "max_tokens": req.max_output_tokens or settings.max_output_tokens,
        "stream": stream,
    }
    if req.tools:
        body["tools"] = [_tool_to_wire(t) for t in req.tools]
        body["tool_choice"] = req.tool_choice
    if req.stop:
        body["stop"] = list(req.stop)
    return body


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, settings: LLMSettings, client: httpx.AsyncClient) -> None:
        self._settings = settings
        self._client = client
        self._url = settings.require_base_url().rstrip("/") + "/chat/completions"

    @property
    def model(self) -> str:
        return self._settings.model

    def count_tokens(self, messages: Sequence[Message], tools: Sequence[ToolSpec] = ()) -> int:
        return tokens.count_messages(messages, tools)

    async def chat(self, request: ChatRequest) -> ChatResponse:
        try:
            resp = await self._client.post(self._url, json=_body(request, self._settings, stream=False))
        except httpx.TimeoutException as exc:
            raise LLMTimeout(str(exc)) from exc
        except httpx.HTTPError as exc:
            raise LLMServerError(str(exc)) from exc
        self._raise_for_status(resp)
        try:
            data = resp.json()
            choice = data["choices"][0]
            msg = choice["message"]
            calls = [
                ToolCall(id=c["id"], name=c["function"]["name"], arguments=c["function"].get("arguments", ""))
                for c in (msg.get("tool_calls") or [])
            ]
            u = data.get("usage") or {}
            usage = Usage(
                prompt_tokens=u.get("prompt_tokens", 0),
                completion_tokens=u.get("completion_tokens", 0),
                total_tokens=u.get("total_tokens", 0),
                estimated=not bool(u),
            )
            return ChatResponse(
                content=msg.get("content") or "",
                tool_calls=calls,
                finish_reason=choice.get("finish_reason", "stop"),
                usage=usage,
                model=data.get("model", self._settings.model),
                raw=data,
            )
        except (KeyError, IndexError, ValueError) as exc:
            raise LLMBadResponse(f"unparseable completion: {exc}") from exc

    async def stream(self, request: ChatRequest) -> AsyncIterator[ChatChunk]:
        body = _body(request, self._settings, stream=True)
        try:
            async with self._client.stream("POST", self._url, json=body) as resp:
                self._raise_for_status(resp)
                async for line in resp.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    payload = line[len("data:"):].strip()
                    if payload == "[DONE]":
                        return
                    try:
                        data = json.loads(payload)
                        choice = data["choices"][0]
                        delta = choice.get("delta", {})
                    except (json.JSONDecodeError, KeyError, IndexError):
                        continue
                    text = delta.get("content") or ""
                    tc_delta = None
                    if delta.get("tool_calls"):
                        # OpenAI sends a list; take the first fragment and expose it by index.
                        frag = delta["tool_calls"][0]
                        tc_delta = {
                            "index": frag.get("index", 0),
                            "id": frag.get("id"),
                            "name": (frag.get("function") or {}).get("name"),
                            "arguments_fragment": (frag.get("function") or {}).get("arguments", ""),
                        }
                    yield ChatChunk(
                        delta_text=text,
                        tool_call_delta=tc_delta,
                        finish_reason=choice.get("finish_reason"),
                    )
        except httpx.TimeoutException as exc:
            raise LLMTimeout(str(exc)) from exc
        except httpx.HTTPError as exc:
            raise LLMServerError(str(exc)) from exc

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        if resp.status_code == 429:
            ra = resp.headers.get("retry-after")
            raise LLMRateLimited("rate limited", retry_after=float(ra) if ra and ra.isdigit() else None)
        if resp.status_code >= 500:
            raise LLMServerError(f"upstream {resp.status_code}")
        if resp.status_code >= 400:
            raise LLMBadResponse(f"client error {resp.status_code}: {resp.text[:200]}")


def reassemble_tool_calls(chunks: list[ChatChunk]) -> list[ToolCall]:
    """Fold streamed ``tool_call_delta`` fragments (accumulated by index) into whole ToolCalls.

    Defensive against servers that send the id/name only on the first fragment and arguments as a
    stream of partial JSON strings. Validate ``arguments`` as JSON at the dispatch boundary.
    """
    by_index: dict[int, dict] = {}
    for ch in chunks:
        d = ch.tool_call_delta
        if not d:
            continue
        slot = by_index.setdefault(d["index"], {"id": None, "name": None, "arguments": ""})
        if d.get("id"):
            slot["id"] = d["id"]
        if d.get("name"):
            slot["name"] = d["name"]
        slot["arguments"] += d.get("arguments_fragment") or ""
    return [
        ToolCall(id=s["id"] or f"call_{i}", name=s["name"] or "", arguments=s["arguments"])
        for i, s in sorted(by_index.items())
    ]
