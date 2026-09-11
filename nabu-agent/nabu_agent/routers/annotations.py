"""Map annotations — per-node operator notes on the live recon map, persisted per project so a note
pinned to a stable node id (``host-`` / ``service-`` / ``finding-``) survives across runs of the
same project. Reads need project membership; writes need operator (RUN_START) — same bar as the
finding-triage notes."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth.deps import get_current_user, require_project_member, require_project_perm
from nabu_agent.db.models import MapNote, User
from nabu_agent.db.session import get_db
from nabu_agent.rbac import Perm

router = APIRouter(tags=["annotations"])


class NoteBody(BaseModel):
    text: str = ""


@router.get("/projects/{project_id}/map-notes")
async def list_map_notes(project_id: str, db: AsyncSession = Depends(get_db),
                         _auth: str = Depends(require_project_member)) -> dict[str, str]:
    rows = (await db.execute(select(MapNote).where(MapNote.project_id == project_id))).scalars().all()
    return {r.node_id: r.text for r in rows}


@router.put("/projects/{project_id}/map-notes/{node_id}")
async def put_map_note(project_id: str, node_id: str, body: NoteBody,
                       db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user),
                       _auth: str = Depends(require_project_perm(Perm.RUN_START))) -> dict[str, str]:
    text = body.text.strip()
    row = (await db.execute(select(MapNote).where(
        MapNote.project_id == project_id, MapNote.node_id == node_id))).scalar_one_or_none()
    if not text:  # empty text = clear the note
        if row is not None:
            await db.delete(row)
            await db.commit()
        return {"node_id": node_id, "text": ""}
    if row is None:
        db.add(MapNote(project_id=project_id, node_id=node_id, text=text, updated_by=user.id))
    else:
        row.text = text
        row.updated_by = user.id
    await db.commit()
    return {"node_id": node_id, "text": text}
