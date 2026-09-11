"""Map notes: an operator pins a free-text note to a node on the live recon map; it persists per
project (keyed by the stable node id) and survives across runs. Empty text clears it."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_map_notes_roundtrip(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Notes"})).json()["id"]

    # no notes yet → empty map
    assert (await client.get(f"/api/projects/{pid}/map-notes")).json() == {}

    # upsert a note on a service node
    node = "service-10.10.10.5-445"
    r = await client.put(f"/api/projects/{pid}/map-notes/{node}",
                         json={"text": "SMB signing disabled — relay candidate"})
    assert r.status_code == 200 and r.json()["text"].startswith("SMB signing")

    notes = (await client.get(f"/api/projects/{pid}/map-notes")).json()
    assert notes[node].startswith("SMB signing")

    # update in place
    await client.put(f"/api/projects/{pid}/map-notes/{node}", json={"text": "confirmed via nxc"})
    assert (await client.get(f"/api/projects/{pid}/map-notes")).json()[node] == "confirmed via nxc"

    # empty/whitespace text clears the note
    await client.put(f"/api/projects/{pid}/map-notes/{node}", json={"text": "   "})
    assert (await client.get(f"/api/projects/{pid}/map-notes")).json() == {}


async def test_map_regions_roundtrip(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Regions"})).json()["id"]

    assert (await client.get(f"/api/projects/{pid}/map-regions")).json() == []

    rid = "rg-abc"
    members = ["host-10.10.10.5", "service-10.10.10.5-445"]
    r = await client.put(f"/api/projects/{pid}/map-regions/{rid}",
                         json={"title": "AD tier", "note": "DCSync path", "color": "#f38ba8", "members": members})
    assert r.status_code == 200 and r.json()["members"] == members

    rows = (await client.get(f"/api/projects/{pid}/map-regions")).json()
    assert len(rows) == 1 and rows[0]["title"] == "AD tier" and rows[0]["color"] == "#f38ba8"

    # update in place (fewer members)
    await client.put(f"/api/projects/{pid}/map-regions/{rid}",
                     json={"title": "AD tier ok", "members": ["host-10.10.10.5"]})
    rows2 = (await client.get(f"/api/projects/{pid}/map-regions")).json()
    assert rows2[0]["title"] == "AD tier ok" and rows2[0]["members"] == ["host-10.10.10.5"]

    # delete
    await client.delete(f"/api/projects/{pid}/map-regions/{rid}")
    assert (await client.get(f"/api/projects/{pid}/map-regions")).json() == []
