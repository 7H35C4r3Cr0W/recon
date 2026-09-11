"""DB-backed LLM ("brain") configuration the admin edits from the UI.

The platform reads its LLM config from ``NABU_LLM_*`` env by default. This service lets an admin
override it at runtime from a form — saved to the ``app_settings`` table and applied on the NEXT
provider build (no restart). The API key is stored ENCRYPTED (``config_store``) and never returned.

``effective_llm_settings()`` is the single resolver everything that builds a provider uses: env
defaults with the saved override merged on top (saved wins per field).
"""
from __future__ import annotations

from typing import Any

from pydantic import SecretStr
from sqlalchemy import select

from nabu_agent import config_store
from nabu_agent.db.models import AppSetting
from nabu_agent.db.session import sessionmaker
from nabu_agent.llm.config import LLMSettings
from nabu_agent.settings import get_settings

_KEY = "llm"
# Fields an admin may set from the form (non-secret). The api key is handled separately (encrypted).
EDITABLE: tuple[str, ...] = (
    "provider", "base_url", "model", "organization",
    "temperature", "max_output_tokens", "context_window", "timeout_read_s", "tls_verify",
)


async def load_saved() -> dict[str, Any] | None:
    """The raw saved override dict (includes ``api_key_enc``), or None if nothing is saved."""
    async with sessionmaker()() as db:
        row = (await db.execute(select(AppSetting).where(AppSetting.key == _KEY))).scalar_one_or_none()
        return dict(row.value) if row and row.value else None


async def save(values: dict[str, Any], *, api_key: str | None, updated_by: str | None) -> None:
    """Persist the admin's LLM override. Only whitelisted fields are stored. ``api_key``: a non-empty
    string sets/replaces the (encrypted) key; None or "" leaves any previously-saved key untouched."""
    from datetime import UTC, datetime

    clean = {k: values[k] for k in EDITABLE if k in values and values[k] is not None}
    async with sessionmaker()() as db:
        row = (await db.execute(select(AppSetting).where(AppSetting.key == _KEY))).scalar_one_or_none()
        current = dict(row.value) if row and row.value else {}
        current.update(clean)
        if api_key:  # replace the encrypted key only when a new one is provided
            current["api_key_enc"] = config_store.encrypt(api_key)
        if row is None:
            row = AppSetting(key=_KEY, value=current, updated_by=updated_by)
            db.add(row)
        else:
            row.value = current
            row.updated_by = updated_by
            row.updated_at = datetime.now(UTC)
        await db.commit()


async def clear() -> None:
    """Delete the saved override (revert to the NABU_LLM_* env config)."""
    async with sessionmaker()() as db:
        row = (await db.execute(select(AppSetting).where(AppSetting.key == _KEY))).scalar_one_or_none()
        if row is not None:
            await db.delete(row)
            await db.commit()


def _merge(base: LLMSettings, saved: dict[str, Any] | None, *, overrides: dict[str, Any] | None = None) -> LLMSettings:
    update: dict[str, Any] = {}
    if saved:
        update.update({k: saved[k] for k in EDITABLE if k in saved and saved[k] not in (None, "")})
        enc = saved.get("api_key_enc")
        if enc:
            update["api_key"] = SecretStr(config_store.decrypt(enc))
    if overrides:  # an ephemeral, unsaved override (e.g. "test THESE values before saving")
        for k in EDITABLE:
            if overrides.get(k) not in (None, ""):
                update[k] = overrides[k]
        if overrides.get("api_key"):
            update["api_key"] = SecretStr(str(overrides["api_key"]))
    return base.model_copy(update=update) if update else base


async def effective_llm_settings(overrides: dict[str, Any] | None = None) -> LLMSettings:
    """The LLM settings actually used to build a provider: env defaults, the saved DB override merged
    on top, then an optional ephemeral ``overrides`` (unsaved values, for test-before-save)."""
    return _merge(get_settings().llm, await load_saved(), overrides=overrides)


async def status() -> dict[str, Any]:
    """Non-secret status for the admin UI. ``source`` is 'saved' (DB override present), 'env' (only
    env configured), or 'none'. The api key is reported as a bool only, never returned."""
    saved = await load_saved()
    eff = _merge(get_settings().llm, saved)
    source = "saved" if saved else ("env" if get_settings().llm.base_url else "none")
    return {
        "source": source,
        "saved": bool(saved),
        "configured": bool(eff.base_url),
        "provider": eff.provider,
        "base_url": eff.base_url,
        "model": eff.model,
        "organization": eff.organization or "",
        "has_api_key": bool(eff.api_key.get_secret_value()),
        "temperature": eff.temperature,
        "max_output_tokens": eff.max_output_tokens,
        "context_window": eff.context_window,
        "timeout_read_s": eff.timeout_read_s,
        "tls_verify": eff.tls_verify,
    }
