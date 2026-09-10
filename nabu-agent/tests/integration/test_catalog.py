"""Catalog (display-only decision aids): the stateless service reference + the per-project catalog /
suggestions. Requires auth; returns empty (not 501) before any recon has run."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_service_catalog_reference(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    r = await client.get("/api/catalog/services/smb")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "smb"
    assert isinstance(body["actions"], list) and "label" in body


async def test_catalog_requires_auth(client):
    assert (await client.get("/api/catalog/services/smb")).status_code == 401   # no session


async def test_project_catalog_empty_before_run(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Cat"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    assert (await client.get(f"/api/projects/{pid}/catalog")).json() == {"services": []}
    assert (await client.get(f"/api/projects/{pid}/suggestions")).json() == {"next_steps": []}
