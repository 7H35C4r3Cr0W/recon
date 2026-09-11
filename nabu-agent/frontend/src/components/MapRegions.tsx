import { useEffect, useState } from "react";
import type { Core } from "cytoscape";

export interface Region { id: string; title: string; note: string; color: string; members: string[]; }
export const REGION_COLORS = ["#89b4fa", "#a6e3a1", "#f9e2af", "#fab387", "#cba6f7", "#f38ba8"];

// Group-anchored region boxes: each region is the bounding box of its MEMBER nodes, so it follows the
// nodes as the map re-lays-out (never drifts) and survives across runs (members are stable node ids).
// Rendered as an HTML overlay over the cytoscape canvas, kept glued to the camera.
export function MapRegions({ cy, regions, onSave, onDelete }: {
  cy: Core | null;
  regions: Region[];
  onSave: (r: Region) => void;
  onDelete: (id: string) => void;
}) {
  const [, setTick] = useState(0);
  useEffect(() => {
    if (!cy) return;
    const bump = () => setTick((t) => t + 1);
    cy.on("pan zoom drag layoutstop", bump);
    return () => { cy.off("pan zoom drag layoutstop", bump); };
  }, [cy]);
  if (!cy) return null;
  const z = cy.zoom();
  const pan = cy.pan();
  const PAD = 22;
  const cycle = (c: string) => REGION_COLORS[(REGION_COLORS.indexOf(c) + 1) % REGION_COLORS.length];
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
        const left = (bb.x1 - PAD) * z + pan.x;
        const top = (bb.y1 - PAD) * z + pan.y;
        const width = (bb.w + 2 * PAD) * z;
        const height = (bb.h + 2 * PAD) * z;
        return (
          <div key={r.id} style={{
            position: "absolute", left, top, width, height,
            border: `1.5px solid ${r.color}`, borderRadius: 10,
            background: `color-mix(in srgb, ${r.color} 8%, transparent)`,
          }}>
            <div style={{
              position: "absolute", top: -13, left: 10, display: "flex", alignItems: "center", gap: 7,
              pointerEvents: "auto", background: `color-mix(in srgb, ${r.color} 22%, var(--panel))`,
              border: `1px solid ${r.color}`, borderRadius: 8, padding: "3px 8px", maxWidth: "88%",
            }}>
              <span title="cycle colour" onClick={() => onSave({ ...r, color: cycle(r.color) })}
                style={{ width: 9, height: 9, borderRadius: "50%", background: r.color, cursor: "pointer", flex: "0 0 auto" }} />
              <input defaultValue={r.title} spellCheck={false} placeholder="region"
                onBlur={(e) => { if (e.target.value !== r.title) onSave({ ...r, title: e.target.value }); }}
                style={{ font: "600 11px/1.3 var(--sans)", color: "var(--ink)", background: "none", border: 0, outline: "none", minWidth: 40, maxWidth: 200 }} />
              <button title="remove region" onClick={() => onDelete(r.id)}
                style={{ pointerEvents: "auto", background: "none", border: 0, color: r.color, cursor: "pointer", fontSize: 12, lineHeight: 1, padding: "0 1px" }}>✕</button>
            </div>
            <textarea defaultValue={r.note} spellCheck={false} placeholder="notes on this area…"
              onBlur={(e) => { if (e.target.value !== r.note) onSave({ ...r, note: e.target.value }); }}
              style={{
                position: "absolute", left: 8, bottom: 8, width: "64%", maxWidth: 240, height: 56, overflow: "auto",
                pointerEvents: "auto", background: "color-mix(in srgb, var(--panel) 88%, transparent)",
                border: `1px solid color-mix(in srgb, ${r.color} 40%, var(--line))`, borderRadius: 8,
                color: "var(--ink-2)", fontFamily: "var(--mono)", fontSize: 10.5, padding: "7px 8px", resize: "none", lineHeight: 1.5,
              }} />
          </div>
        );
      })}
    </div>
  );
}
