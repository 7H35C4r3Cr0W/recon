"""Retry / backoff for the LLM HTTP call ONLY.

Cardinal rule (design §8): a turn whose tool call has already been DISPATCHED is never replayed —
that would double-run a scan. Retries here apply to the provider HTTP request before any tool
side-effect. Honors ``Retry-After`` on 429; exponential backoff + full jitter on 5xx/network.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

from .config import LLMSettings
from .errors import LLMError, LLMRateLimited

T = TypeVar("T")


def _delay(attempt: int, settings: LLMSettings, retry_after: float | None) -> float:
    if retry_after is not None:
        return min(retry_after, settings.backoff_max_s)
    base = settings.backoff_base_s * (2 ** attempt)
    return min(base, settings.backoff_max_s) * (0.5 + random.random() / 2)  # full jitter


async def with_retries(fn: Callable[[], Awaitable[T]], settings: LLMSettings) -> T:
    """Call ``fn`` with retries on *retriable* LLMErrors; re-raise fatal ones immediately."""
    last: LLMError | None = None
    for attempt in range(settings.max_retries + 1):
        try:
            return await fn()
        except LLMError as exc:
            if not exc.retriable or attempt == settings.max_retries:
                raise
            last = exc
            retry_after = getattr(exc, "retry_after", None) if isinstance(exc, LLMRateLimited) else None
            await asyncio.sleep(_delay(attempt, settings, retry_after))
    assert last is not None  # unreachable
    raise last
