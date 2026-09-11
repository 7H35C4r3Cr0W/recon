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
