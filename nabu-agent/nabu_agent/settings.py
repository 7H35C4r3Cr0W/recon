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
    # OIDC / SSO (optional). When oidc_issuer is set, "Sign in with SSO" is offered and users are
    # JIT-provisioned on first login. Discovery uses <issuer>/.well-known/openid-configuration.
    oidc_issuer: str = ""                       # empty → local accounts only
    oidc_client_id: str = ""
    oidc_client_secret: SecretStr = SecretStr("")
    oidc_scopes: str = "openid email profile"
    oidc_redirect_url: str = ""                 # optional override; else derived from the request
    oidc_first_user_admin: bool = True          # first JIT-provisioned user becomes global admin

    # SAFETY — recon-only default. These are GATES, not agent-settable behaviour.
    spray_enabled: bool = False
    exploit_enabled: bool = False               # never wired to an agent path regardless
    autonomy: Autonomy = Autonomy.RECON_ONLY

    # When True, runs execute on the Arq worker pool (production/docker); when False they run
    # in-process in the api (dev/tests). docker-compose sets NABU_USE_ARQ=true.
    use_arq: bool = False
    # A non-terminal run whose heartbeat is older than this is reaped (worker likely died). The
    # executor beats every ~10s, so this is many missed beats of margin.
    run_stale_after_s: int = 120

    # Data retention / quotas (housekeeping cron + admin trigger).
    retention_enabled: bool = True
    retention_run_events_days: int = 30          # drop finished runs' event stream after N days
    max_runs_per_project: int = 200              # keep only the newest N runs per project

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
