"""Map annotations — per-node operator notes on the live recon map, persisted per project so a note
pinned to a stable node id (``host-`` / ``service-`` / ``finding-``) survives across runs of the
same project. Reads need project membership; writes need operator (RUN_START) — same bar as the
finding-triage notes."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent import audit
from nabu_agent.auth.deps import get_current_user, require_project_member, require_project_perm
from nabu_agent.db.models import MapNote, MapRegion, User
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
    node_id = node_id[:200]  # bound to the column width so an over-long id can't 500 (Postgres)
    row = (await db.execute(select(MapNote).where(
        MapNote.project_id == project_id, MapNote.node_id == node_id))).scalar_one_or_none()
    if not text:  # empty text = clear the note
        if row is not None:
            await db.delete(row)
            await db.commit()
            await audit.record(actor_user_id=user.id, action=audit.MAP_ANNOTATION_DELETED,
                               object_type="map-note", object_id=node_id, project_id=project_id)
        return {"node_id": node_id, "text": ""}
    if row is None:
        db.add(MapNote(project_id=project_id, node_id=node_id, text=text, updated_by=user.id))
    else:
        row.text = text
        row.updated_by = user.id
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.MAP_ANNOTATED, object_type="map-note",
                       object_id=node_id, project_id=project_id, details={"chars": len(text)})
    return {"node_id": node_id, "text": text}


class RegionBody(BaseModel):
    title: str = ""
    note: str = ""
    color: str = "#89b4fa"
    members: list[str] = []


@router.get("/projects/{project_id}/map-regions")
async def list_map_regions(project_id: str, db: AsyncSession = Depends(get_db),
                           _auth: str = Depends(require_project_member)) -> list[dict]:
    rows = (await db.execute(select(MapRegion).where(MapRegion.project_id == project_id))).scalars().all()
    return [{"id": r.id, "title": r.title, "note": r.note, "color": r.color, "members": r.members} for r in rows]


@router.put("/projects/{project_id}/map-regions/{region_id}")
async def put_map_region(project_id: str, region_id: str, body: RegionBody,
                         db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user),
                         _auth: str = Depends(require_project_perm(Perm.RUN_START))) -> dict:
    # bound to the column widths so an over-long value can't 500 (Postgres) or silently truncate
    region_id = region_id[:64]
    title = body.title[:200]
    color = body.color[:16]
    members = [str(m)[:200] for m in body.members][:500]
    row = (await db.execute(select(MapRegion).where(
        MapRegion.project_id == project_id, MapRegion.id == region_id))).scalar_one_or_none()
    if row is None:
        db.add(MapRegion(id=region_id, project_id=project_id, title=title, note=body.note,
                         color=color, members=members, updated_by=user.id))
    else:
        row.title, row.note, row.color, row.members = title, body.note, color, members
        row.updated_by = user.id
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.MAP_ANNOTATED, object_type="map-region",
                       object_id=region_id, project_id=project_id, details={"members": len(members)})
    return {"id": region_id, "title": title, "note": body.note, "color": color, "members": members}


@router.delete("/projects/{project_id}/map-regions/{region_id}")
async def delete_map_region(project_id: str, region_id: str, db: AsyncSession = Depends(get_db),
                            user: User = Depends(get_current_user),
                            _auth: str = Depends(require_project_perm(Perm.RUN_START))) -> dict:
    row = (await db.execute(select(MapRegion).where(
        MapRegion.project_id == project_id, MapRegion.id == region_id))).scalar_one_or_none()
    if row is not None:
        await db.delete(row)
        await db.commit()
        await audit.record(actor_user_id=user.id, action=audit.MAP_ANNOTATION_DELETED,
                           object_type="map-region", object_id=region_id, project_id=project_id)
    return {"deleted": region_id}
