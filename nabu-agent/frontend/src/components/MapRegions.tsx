import { useEffect, useRef, useState } from "react";
import type { Core } from "cytoscape";

export interface Region { id: string; title: string; note: string; color: string; members: string[]; }
export const REGION_COLORS = ["#89b4fa", "#a6e3a1", "#f9e2af", "#fab387", "#cba6f7", "#f38ba8"];

// One region box: controlled title/note synced from props (so server/cross-client edits refresh),
// saved on blur, and the colour-cycle carries the CURRENT edits so it never reverts them.
function RegionBox({ r, rect, onSave, onDelete }: {
  r: Region;
  rect: { left: number; top: number; width: number; height: number };
  onSave: (r: Region) => void;
  onDelete: (id: string) => void;
}) {
  const [title, setTitle] = useState(r.title);
  const [note, setNote] = useState(r.note);
  useEffect(() => { setTitle(r.title); }, [r.title]);
  useEffect(() => { setNote(r.note); }, [r.note]);
  return (
    <div style={{ position: "absolute", ...rect, border: `1.5px solid ${r.color}`, borderRadius: 10,
      background: `color-mix(in srgb, ${r.color} 8%, transparent)` }}>
      <div style={{ position: "absolute", top: -13, left: 10, display: "flex", alignItems: "center", gap: 7,
        pointerEvents: "auto", background: `color-mix(in srgb, ${r.color} 22%, var(--panel))`,
        border: `1px solid ${r.color}`, borderRadius: 8, padding: "3px 8px", maxWidth: "88%" }}>
        <span title="cycle colour"
          onClick={() => onSave({ ...r, title, note, color: REGION_COLORS[(REGION_COLORS.indexOf(r.color) + 1) % REGION_COLORS.length] })}
          style={{ width: 9, height: 9, borderRadius: "50%", background: r.color, cursor: "pointer", flex: "0 0 auto" }} />
        <input value={title} spellCheck={false} placeholder="region" maxLength={200}
          onChange={(e) => setTitle(e.target.value)}
          onBlur={() => { if (title !== r.title) onSave({ ...r, title, note }); }}
          style={{ font: "600 11px/1.3 var(--sans)", color: "var(--ink)", background: "none", border: 0, outline: "none", minWidth: 40, maxWidth: 200 }} />
        <button title="remove region" onClick={() => onDelete(r.id)}
          style={{ pointerEvents: "auto", background: "none", border: 0, color: r.color, cursor: "pointer", fontSize: 12, lineHeight: 1, padding: "0 1px" }}>✕</button>
      </div>
      <textarea value={note} spellCheck={false} placeholder="notes on this area…"
        onChange={(e) => setNote(e.target.value)}
        onBlur={() => { if (note !== r.note) onSave({ ...r, title, note }); }}
        style={{ position: "absolute", left: 8, bottom: 8, width: "64%", maxWidth: 240, height: 56, overflow: "auto",
          pointerEvents: "auto", background: "color-mix(in srgb, var(--panel) 88%, transparent)",
          border: `1px solid color-mix(in srgb, ${r.color} 40%, var(--line))`, borderRadius: 8,
          color: "var(--ink-2)", fontFamily: "var(--mono)", fontSize: 10.5, padding: "7px 8px", resize: "none", lineHeight: 1.5 }} />
    </div>
  );
}

// Group-anchored region boxes: each region is the bounding box of its MEMBER nodes, so it follows the
// nodes as the map re-lays-out (never drifts) and survives across runs. Kept glued to the camera; the
// per-frame reposition is rAF-coalesced so a continuous pan re-renders at most once per frame.
export function MapRegions({ cy, regions, onSave, onDelete }: {
  cy: Core | null;
  regions: Region[];
  onSave: (r: Region) => void;
  onDelete: (id: string) => void;
}) {
  const [, setTick] = useState(0);
  const rafRef = useRef<number | null>(null);
  useEffect(() => {
    if (!cy) return;
    const bump = () => {
      if (rafRef.current != null) return;
      rafRef.current = requestAnimationFrame(() => { rafRef.current = null; setTick((t) => t + 1); });
    };
    cy.on("pan zoom drag layoutstop", bump);
    return () => {
      cy.off("pan zoom drag layoutstop", bump);
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
  }, [cy]);
  if (!cy) return null;
  const z = cy.zoom();
  const pan = cy.pan();
  const PAD = 22;
  return (
    <div style={{ position: "absolute", inset: 0, overflow: "hidden", pointerEvents: "none", zIndex: 3, borderRadius: 11 }}>
      {regions.map((r) => {
        let eles = cy.collection();
        for (const id of r.members) {
          const n = cy.getElementById(id);
          if (n.nonempty()) eles = eles.union(n);
        }
        if (eles.empty()) return null; // no member currently on the map → hide the region
        const bb = eles.boundingBox();
        const rect = {
          left: (bb.x1 - PAD) * z + pan.x, top: (bb.y1 - PAD) * z + pan.y,
          width: (bb.w + 2 * PAD) * z, height: (bb.h + 2 * PAD) * z,
        };
        return <RegionBox key={r.id} r={r} rect={rect} onSave={onSave} onDelete={onDelete} />;
      })}
    </div>
  );
}
