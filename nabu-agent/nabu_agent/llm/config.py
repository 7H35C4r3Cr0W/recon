"""LLM connection + tuning config — the single owner of the ``NABU_LLM_*`` env keys.

The root :class:`nabu_agent.settings.Settings` COMPOSES this sub-model; it never redeclares these
fields. This is the one place the owner points the platform at the internal endpoint.
"""

from __future__ import annotations

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NABU_LLM_", env_file=".env", extra="ignore")

    provider: str = "openai_compatible"          # dispatch key for build_provider()
    base_url: str = ""                             # e.g. https://llm.internal.example/v1  (REQUIRED)
    api_key: SecretStr = SecretStr("")             # from the secret store; never logged
    model: str = "gpt-5.1"
    organization: str = ""

    temperature: float = 0.2
    top_p: float = 1.0
    max_output_tokens: int = 4096
    context_window: int = 128_000
    stream: bool = True

    # httpx timeouts (seconds) + retry/backoff.
    timeout_connect_s: float = 10.0
    timeout_read_s: float = 120.0
    timeout_total_s: float = 180.0
    max_retries: int = 3
    backoff_base_s: float = 0.5
    backoff_max_s: float = 20.0

    # TLS to the internal endpoint (self-signed / internal CA supported).
    tls_verify: bool = True
    ca_bundle: str = ""

    extra_headers: dict[str, str] = Field(default_factory=dict)

    def require_base_url(self) -> str:
        if not self.base_url:
            raise ValueError("NABU_LLM_BASE_URL is required (point it at the internal endpoint)")
        return self.base_url
