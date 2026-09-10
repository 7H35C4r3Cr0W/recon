"""The LLM "brain" seam — a provider-agnostic interface the agent layer talks to.

The owner attaches the brain: an internally-hosted, **OpenAI-compatible** endpoint (GPT-5.1 today).
This module defines the *contract* only — pure schema + a ``Protocol``, no I/O and no vendor SDK. The
default implementation lives in :mod:`nabu_agent.llm.openai_compat`; alternatives register with
:func:`nabu_agent.llm.factory.build_provider`. Swapping the brain is a config change
(``NABU_LLM_PROVIDER`` / ``NABU_LLM_BASE_URL`` / ``NABU_LLM_MODEL``), never a code change.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass(frozen=True)
class ToolSpec:
    """An OpenAI-style function/tool the model may call. ``parameters`` is a JSON Schema object."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    """A tool call the model requested. ``arguments`` is the raw JSON string the model emitted
    (parsed + validated by the dispatcher, never trusted verbatim)."""

    id: str
    name: str
    arguments: str


@dataclass
class Message:
    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None  # set on role=="tool" messages (the call being answered)
    name: str | None = None


@dataclass(frozen=True)
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated: bool = False  # True when the server omitted usage and we counted locally


@dataclass(frozen=True)
class ChatRequest:
    messages: Sequence[Message]
    tools: Sequence[ToolSpec] = ()
    temperature: float | None = None
    top_p: float | None = None
    max_output_tokens: int | None = None
    tool_choice: str = "auto"  # "auto" | "none" | "required"
    stop: Sequence[str] | None = None


@dataclass(frozen=True)
class ChatResponse:
    content: str
    tool_calls: list[ToolCall]
    finish_reason: str  # "stop" | "tool_calls" | "length" | "content_filter" | ...
    usage: Usage
    model: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ChatChunk:
    """One streamed delta. Either a text fragment or a (partial) tool-call fragment."""

    delta_text: str = ""
    tool_call_delta: dict[str, Any] | None = None  # {index, id?, name?, arguments_fragment?}
    finish_reason: str | None = None
    usage: Usage | None = None


@runtime_checkable
class LLMProvider(Protocol):
    """The 4-method contract every brain adapter implements."""

    @property
    def model(self) -> str:
        """The model id this provider is configured for (e.g. ``gpt-5.1``)."""
        ...

    async def chat(self, request: ChatRequest) -> ChatResponse:
        """One non-streaming completion (tool-calling aware)."""
        ...

    def stream(self, request: ChatRequest) -> AsyncIterator[ChatChunk]:
        """Stream a completion as :class:`ChatChunk` deltas (text + tool-call fragments)."""
        ...

    def count_tokens(self, messages: Sequence[Message], tools: Sequence[ToolSpec] = ()) -> int:
        """Best-effort local token estimate (for budgeting when the server omits usage)."""
        ...
