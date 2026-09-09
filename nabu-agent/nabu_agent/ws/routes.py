"""WebSocket routes: /ws/runs/{run_id} (live agent-task tree) and /ws/projects/{id} (project deltas).

Client→server ops limited to {"op":"ping"} and {"op":"approve"|"reject", checkpoint_id, note} — every
other mutation goes through REST. Handshake auth reuses the session cookie. Bodies wired in Phase 2.
"""

from __future__ import annotations

from fastapi import APIRouter, WebSocket

router = APIRouter()


@router.websocket("/ws/runs/{run_id}")
async def ws_run(websocket: WebSocket, run_id: str) -> None:
    await websocket.accept()
    await websocket.send_json({"type": "run.status", "run_id": run_id,
                               "data": {"note": "scaffold: live stream wired in Phase 2"}})
    await websocket.close()


@router.websocket("/ws/projects/{project_id}")
async def ws_project(websocket: WebSocket, project_id: str) -> None:
    await websocket.accept()
    await websocket.close()
