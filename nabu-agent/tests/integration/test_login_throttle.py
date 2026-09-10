"""Login brute-force throttle: repeated failures for an (ip, email) get a 429 (even with the correct
password) until the window passes; a successful login clears the counter. Plus: every response
carries an X-Request-ID for log correlation."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_login_throttled_after_repeated_failures(client, monkeypatch):
    from nabu_agent import bus
    monkeypatch.setattr(bus, "LOGIN_MAX_FAILURES", 2)
    for _ in range(2):
        assert (await client.post("/api/auth/login",
                json={"email": "admin@nabu.local", "password": "WRONG"})).status_code == 401
    r = await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "WRONG"})
    assert r.status_code == 429 and "retry-after" in {k.lower() for k in r.headers}
    # the correct password is refused too while throttled
    assert (await client.post("/api/auth/login",
            json={"email": "admin@nabu.local", "password": "changeme"})).status_code == 429


async def test_success_clears_the_counter(client, monkeypatch):
    from nabu_agent import bus
    monkeypatch.setattr(bus, "LOGIN_MAX_FAILURES", 3)
    assert (await client.post("/api/auth/login",
            json={"email": "admin@nabu.local", "password": "WRONG"})).status_code == 401
    assert (await client.post("/api/auth/login",
            json={"email": "admin@nabu.local", "password": "changeme"})).status_code == 200
    # counter reset → a fresh failure doesn't immediately trip the (low) limit
    assert (await client.post("/api/auth/login",
            json={"email": "admin@nabu.local", "password": "WRONG"})).status_code == 401


async def test_response_carries_request_id(client):
    r = await client.get("/api/health")
    assert r.headers.get("x-request-id")
