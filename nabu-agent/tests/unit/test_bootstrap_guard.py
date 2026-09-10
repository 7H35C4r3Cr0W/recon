"""Bootstrap refuses to seed a weak/default admin password in production (a wide-open admin account
is the worst bootstrap). Dev/test may use the default."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_prod_refuses_weak_admin_password(monkeypatch):
    monkeypatch.setenv("NABU_ENV", "production")
    monkeypatch.setenv("NABU_ADMIN_PASSWORD", "changeme")
    from nabu_agent.db import session
    from nabu_agent.settings import get_settings
    get_settings.cache_clear()
    session.configure("sqlite+aiosqlite:///:memory:")
    from nabu_agent.bootstrap import _main
    try:
        with pytest.raises(SystemExit):
            await _main()
    finally:
        get_settings.cache_clear()
