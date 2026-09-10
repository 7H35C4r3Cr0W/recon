"""Root platform configuration (``NABU_`` prefix), composing the LLM sub-model.

Single source of config truth for the ``api`` + ``worker`` processes. Mirrors the engine's safety
toggles so the platform default is **recon-only**: ``spray_enabled`` / ``exploit_enabled`` default
False and are per-project gates, never agent-settable behaviour. The LLM connection lives in its own
:class:`~nabu_agent.llm.config.LLMSettings` (``NABU_LLM_`` prefix) — this model references it, never
redeclares its fields.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from nabu_agent.llm.config import LLMSettings


class Autonomy(StrEnum):
    RECON_ONLY = "recon_only"                   # agents scan + enum; never spray/exploit
    RECON_PLUS_SUGGEST = "recon_plus_suggest"   # agents also SURFACE ranked actions; still no exec


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NABU_", env_file=".env", extra="ignore")

    env: str = "production"
    bind: str = "127.0.0.1"                      # internal interface only; never 0.0.0.0 in prod
    workspace: str = "/workspace"               # engine Profiles/findings/audit live here

    database_url: str = "postgresql+asyncpg://nabu:@postgres:5432/nabu"
    redis_url: str = "redis://redis:6379/0"

    session_secret: SecretStr = SecretStr("")   # REQUIRED in prod; startup asserts non-empty
    session_ttl_min: int = 480
    oidc_issuer: str = ""                       # optional org IdP; empty → local accounts only

    # SAFETY — recon-only default. These are GATES, not agent-settable behaviour.
    spray_enabled: bool = False
    exploit_enabled: bool = False               # never wired to an agent path regardless
    autonomy: Autonomy = Autonomy.RECON_ONLY

    # When True, runs execute on the Arq worker pool (production/docker); when False they run
    # in-process in the api (dev/tests). docker-compose sets NABU_USE_ARQ=true.
    use_arq: bool = False

    log_level: str = "INFO"
    log_format: str = "json"

    # the swappable brain (reads NABU_LLM_* on its own)
    llm: LLMSettings = Field(default_factory=LLMSettings)

    def assert_production_ready(self) -> None:
        if self.env == "production" and not self.session_secret.get_secret_value():
            raise ValueError("NABU_SESSION_SECRET is required in production")


@lru_cache
def get_settings() -> Settings:
    return Settings()
