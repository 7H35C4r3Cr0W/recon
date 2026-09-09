"""Error hierarchy for the brain seam. Retriable vs fatal drives the backoff in retry.py."""

from __future__ import annotations


class LLMError(Exception):
    """Base for all provider errors."""

    retriable = False


class LLMConfigError(LLMError):
    """Misconfiguration (missing base_url/api_key, unknown provider)."""


class LLMTimeout(LLMError):
    retriable = True


class LLMRateLimited(LLMError):
    """HTTP 429. Carries an optional ``retry_after`` (seconds)."""

    retriable = True

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class LLMServerError(LLMError):
    """HTTP 5xx / network error."""

    retriable = True


class LLMBadResponse(LLMError):
    """Malformed body / unparseable tool-call arguments."""


class LLMBudgetExceeded(LLMError):
    """A per-agent or per-run token/step ceiling was hit; the agent stops cleanly."""
