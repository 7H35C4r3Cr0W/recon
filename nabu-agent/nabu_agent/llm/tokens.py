"""Token counting + context fitting. Uses tiktoken when available, else a chars/4 heuristic.

Kept dependency-light: tiktoken is optional (the internal model may not map to a known encoding),
so we degrade gracefully rather than fail — budgets stay best-effort with an ``estimated`` flag.
"""

from __future__ import annotations

from collections.abc import Sequence

from .base import Message, ToolSpec

try:  # optional
    import tiktoken

    _ENC = tiktoken.get_encoding("cl100k_base")
except Exception:  # pragma: no cover - tiktoken absent or model unknown
    _ENC = None


def count_text(text: str) -> int:
    if _ENC is not None:
        return len(_ENC.encode(text))
    return max(1, len(text) // 4)  # rough heuristic


def count_messages(messages: Sequence[Message], tools: Sequence[ToolSpec] = ()) -> int:
    total = 0
    for m in messages:
        total += count_text(m.content) + 4  # per-message overhead
        for tc in m.tool_calls:
            total += count_text(tc.name) + count_text(tc.arguments)
    for t in tools:
        total += count_text(t.name) + count_text(t.description) + count_text(str(t.parameters))
    return total


def fit_context(messages: list[Message], budget_tokens: int, tools: Sequence[ToolSpec] = ()) -> list[Message]:
    """Trim from the OLDEST non-system message until the estimate fits the budget.

    System messages (role guidance + safety preamble) are never dropped. Returns a new list.
    """
    kept = list(messages)
    while count_messages(kept, tools) > budget_tokens and len(kept) > 1:
        # drop the first non-system message
        for i, m in enumerate(kept):
            if m.role.value != "system":
                del kept[i]
                break
        else:
            break
    return kept
