"""WebSocket routes. /ws/runs/{id}: cookie-auth handshake → subscribe to Redis FIRST (so no event is
missed) → replay persisted run_events by seq → flush buffered live events (dedup by seq) → tail live.
This is the feed the BloodHound-style map + log pane consume."""
from __future__ import annotations

import asyncio
import contextlib

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from nabu_agent import bus
from nabu_agent.auth import sessions
from nabu_agent.db.models import Project, ProjectMember, Run, User
from nabu_agent.db.session import sessionmaker
from nabu_agent.services import runs as runs_svc

router = APIRouter()


async def _authorize(user_id: str, run_id: str) -> bool:
    """The user must be a member (or owner, or global admin) of the run's project."""
    async with sessionmaker()() as db:
        run = (await db.execute(select(Run).where(Run.id == run_id))).scalar_one_or_none()
        if run is None:
            return False
        user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if user and user.role == "admin":
            return True
        proj = (await db.execute(select(Project).where(Project.id == run.project_id))).scalar_one_or_none()
        if proj and proj.owner_id == user_id:
            return True
        member = (await db.execute(select(ProjectMember).where(
            ProjectMember.project_id == run.project_id, ProjectMember.user_id == user_id))).scalar_one_or_none()
        return member is not None


@router.websocket("/ws/runs/{run_id}")
async def ws_run(websocket: WebSocket, run_id: str) -> None:
    sid = websocket.cookies.get(sessions.COOKIE_NAME)
    user_id = await sessions.resolve_session(sid)
    if not user_id or not await _authorize(user_id, run_id):
        await websocket.close(code=4401)  # unauthenticated / not a project member
        return
    await websocket.accept()

    # 1) subscribe FIRST so nothing published during replay is lost; buffer while we snapshot.
    pubsub = await bus.open_subscription(run_id)
    buffered: list[dict] = []

    async def _spool() -> None:
        with contextlib.suppress(Exception):
            async for ev in bus.listen(pubsub):
                buffered.append(ev)

    spool = asyncio.create_task(_spool())

    last_seq = 0
    try:
        # 2) replay the durable backlog
        async with sessionmaker()() as db:
            for ev in await runs_svc.replay_events(db, run_id, after=0):
                await websocket.send_json(ev)
                last_seq = max(last_seq, ev["seq"])

        # 3) flush anything that arrived during replay (dedup by seq), then tail live
        heartbeat = asyncio.create_task(_heartbeat(websocket, run_id))
        try:
            done = False
            while not done:
                # drain the buffer
                pending, buffered[:] = buffered[:], []
                for ev in pending:
                    if ev.get("seq", 0) > last_seq:
                        await websocket.send_json(ev)
                        last_seq = ev["seq"]
                        if ev.get("type") == "done":
                            done = True
                if done:
                    break
                await asyncio.sleep(0.15)
        finally:
            heartbeat.cancel()
    except WebSocketDisconnect:
        pass
    finally:
        spool.cancel()
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe(bus.events_channel(run_id))
            await pubsub.aclose()
        with contextlib.suppress(Exception):
            await websocket.close()


async def _heartbeat(websocket: WebSocket, run_id: str) -> None:
    with contextlib.suppress(Exception):
        while True:
            await asyncio.sleep(20)
            await websocket.send_json({"type": "heartbeat", "run_id": run_id, "seq": 0, "ts": 0, "data": {}})
