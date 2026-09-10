"""WebSocket routes. /ws/runs/{id}: cookie-auth handshake → replay persisted run_events by seq →
tail the Redis run channel live. This is the feed the BloodHound-style map + log pane consume."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from nabu_agent import bus
from nabu_agent.auth import sessions
from nabu_agent.db.session import sessionmaker
from nabu_agent.services import runs as runs_svc

router = APIRouter()


@router.websocket("/ws/runs/{run_id}")
async def ws_run(websocket: WebSocket, run_id: str) -> None:
    sid = websocket.cookies.get(sessions.COOKIE_NAME)
    if not await sessions.resolve_session(sid):
        await websocket.close(code=4401)  # unauthenticated
        return
    await websocket.accept()

    last_seq = 0
    # 1) replay everything persisted so a mid-run (re)connect reconciles to the same map
    async with sessionmaker()() as db:
        for ev in await runs_svc.replay_events(db, run_id, after=0):
            await websocket.send_json(ev)
            last_seq = max(last_seq, ev["seq"])

    # 2) tail live events (skip any we already replayed), with a heartbeat
    async def heartbeat() -> None:
        try:
            while True:
                await asyncio.sleep(20)
                await websocket.send_json({"type": "heartbeat", "run_id": run_id, "seq": 0, "ts": 0, "data": {}})
        except Exception:
            pass

    hb = asyncio.create_task(heartbeat())
    try:
        async for ev in bus.subscribe(run_id):
            if ev.get("seq", 0) > last_seq:
                await websocket.send_json(ev)
                last_seq = ev["seq"]
                if ev.get("type") == "done":
                    break
    except WebSocketDisconnect:
        pass
    finally:
        hb.cancel()
        with_close = getattr(websocket, "client_state", None)
        try:
            await websocket.close()
        except Exception:
            pass
