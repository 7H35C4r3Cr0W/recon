"""WebSocket-path integration: a real WS client drives /ws/runs/{id} — auth handshake, live tail of
a demo run to a terminal 'done', and replay+terminal-close on connecting to an already-finished run.
Uses httpx-ws over the in-process ASGI app so everything stays on one event loop."""
from __future__ import annotations

import asyncio
import contextlib

import httpx
import pytest
from httpx_ws import aconnect_ws
from httpx_ws.transport import ASGIWebSocketTransport

pytestmark = pytest.mark.asyncio


def _client(app):
    return httpx.AsyncClient(transport=ASGIWebSocketTransport(app), base_url="http://test")


async def _login_and_start(c, creds):
    await c.post("/api/auth/login", json=creds)
    pid = (await c.post("/api/projects", json={"display_name": "WS"})).json()["id"]
    await c.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    return (await c.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5", "kind": "demo"})).json()["run_id"]


async def test_ws_unauthenticated_rejected(app_ctx):
    app, _ = app_ctx
    async with _client(app) as c:
        rejected = False
        try:
            async with aconnect_ws("/ws/runs/nope", c):
                pass
        except Exception:
            rejected = True
        assert rejected  # no session cookie → handshake closed (4401)


async def test_ws_live_tail_to_done(app_ctx):
    app, creds = app_ctx
    async with _client(app) as c:
        run_id = await _login_and_start(c, creds)
        types = set()
        async with aconnect_ws(f"/ws/runs/{run_id}", c) as ws:
            for _ in range(400):
                try:
                    ev = await asyncio.wait_for(ws.receive_json(), timeout=20)
                except Exception:
                    break
                types.add(ev["type"])
                if ev["type"] == "done":
                    break
        assert "done" in types
        assert {"run.status", "task.created", "log.line"} <= types


async def test_ws_reconnect_to_finished_run_terminates(app_ctx):
    app, creds = app_ctx
    async with _client(app) as c:
        run_id = await _login_and_start(c, creds)
        for _ in range(150):
            await asyncio.sleep(0.1)
            evs = (await c.get(f"/api/runs/{run_id}/events")).json()["events"]
            if any(e["type"] == "done" for e in evs):
                break
        # connecting to a finished run must replay + close (not hang)
        saw_done = False
        async with aconnect_ws(f"/ws/runs/{run_id}", c) as ws:
            for _ in range(200):
                try:
                    ev = await asyncio.wait_for(ws.receive_json(), timeout=10)
                except Exception:
                    break
                if ev["type"] == "done":
                    saw_done = True
                    break
        assert saw_done
