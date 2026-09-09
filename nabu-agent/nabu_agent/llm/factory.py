"""Build an :class:`LLMProvider` from config. The one place the concrete brain is chosen.

``build_provider(settings)`` dispatches on ``settings.provider`` (default ``openai_compatible``).
Registering another adapter is a one-liner in :data:`_REGISTRY` — no other code changes — which is
what keeps the brain swappable. A shared ``httpx.AsyncClient`` (built with the configured timeouts,
TLS, bearer + extra headers) is reused across calls.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from .base import LLMProvider
from .config import LLMSettings
from .errors import LLMConfigError
from .openai_compat import OpenAICompatibleProvider


def _client_for(settings: LLMSettings) -> httpx.AsyncClient:
    headers = {"Content-Type": "application/json", **settings.extra_headers}
    key = settings.api_key.get_secret_value()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    if settings.organization:
        headers["OpenAI-Organization"] = settings.organization
    verify: bool | str = settings.ca_bundle or settings.tls_verify
    timeout = httpx.Timeout(
        settings.timeout_total_s,
        connect=settings.timeout_connect_s,
        read=settings.timeout_read_s,
    )
    return httpx.AsyncClient(headers=headers, timeout=timeout, verify=verify, http2=True)


def _build_openai_compatible(settings: LLMSettings) -> LLMProvider:
    return OpenAICompatibleProvider(settings, _client_for(settings))


# provider name -> builder. Add {"vllm": ..., "ollama": ..., "azure": ...} here to swap the brain.
_REGISTRY: dict[str, Callable[[LLMSettings], LLMProvider]] = {
    "openai_compatible": _build_openai_compatible,
}


def build_provider(settings: LLMSettings) -> LLMProvider:
    settings.require_base_url()
    try:
        builder = _REGISTRY[settings.provider]
    except KeyError as exc:
        raise LLMConfigError(
            f"unknown NABU_LLM_PROVIDER {settings.provider!r}; known: {sorted(_REGISTRY)}"
        ) from exc
    return builder(settings)


def register_provider(name: str, builder: Callable[[LLMSettings], LLMProvider]) -> None:
    """Register an additional brain adapter (e.g. a bespoke internal protocol)."""
    _REGISTRY[name] = builder
