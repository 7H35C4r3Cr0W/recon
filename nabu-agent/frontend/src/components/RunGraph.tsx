import { useEffect, useRef } from "react";
import cytoscape, { Core, ElementDefinition } from "cytoscape";
import { NODE_COLORS } from "../lib/nodeColors";

// Renders the run graph and animates node colour by data.state. `active` nodes glow green.
export function RunGraph({ elements }: { elements: ElementDefinition[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({
      container: ref.current,
      elements: [],
      style: [
        {
          selector: "node",
          style: {
            "background-color": ((n: any) =>
              NODE_COLORS[(n.data("state") || "queued") as keyof typeof NODE_COLORS] || "#8394a0") as any,
            label: "data(label)",
            color: "#cddbe3",
            "font-size": 10,
            "font-family": "monospace",
            "text-valign": "bottom",
            "text-margin-y": 5,
            "text-outline-color": "#070a0e",
            "text-outline-width": 2,
            width: 38,
            height: 38,
            "border-width": 2,
            "border-color": "#070a0e",
            "transition-property": "background-color border-color shadow-blur",
            "transition-duration": "0.25s",
          } as any,
        },
        { selector: 'node[kind="run"]', style: { shape: "round-rectangle", width: 52, height: 34, "font-size": 11 } },
        { selector: 'node[kind="host"]', style: { shape: "hexagon", width: 48, height: 48, "font-size": 11 } },
        { selector: 'node[kind="service"]', style: { shape: "round-rectangle" } },
        { selector: 'node[kind="finding"]', style: { shape: "diamond", width: 30, height: 30 } },
        { selector: 'node[kind="report"]', style: { shape: "star", width: 46, height: 46 } },
        {
          selector: 'node[state="active"]',
          style: {
            "border-color": "#3ad9c0", "border-width": 4,
            "shadow-blur": 30, "shadow-color": "#3ad9c0", "shadow-opacity": 0.95,
          } as any,
        },
        {
          selector: 'node[state="done"]',
          style: { "shadow-blur": 14, "shadow-color": "#54b9f2", "shadow-opacity": 0.4 } as any,
        },
        {
          selector: 'node[state="error"]',
          style: { "border-color": "#f27a7a", "border-width": 3,
                   "shadow-blur": 20, "shadow-color": "#f27a7a", "shadow-opacity": 0.7 } as any,
        },
        {
          selector: 'node[state="stuck"]',
          style: { "border-color": "#f2b636", "border-width": 3,
                   "shadow-blur": 20, "shadow-color": "#f2b636", "shadow-opacity": 0.7 } as any,
        },
        {
          selector: "edge",
          style: {
            width: 1.4,
            "line-color": "#2e3d48",
            "target-arrow-color": "#2e3d48",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
          },
        },
        {
          // labeled hand-off edges (planner→enum, enum→finding/research, agents→report) stand out
          selector: "edge[label]",
          style: {
            label: "data(label)",
            "font-size": 8,
            "font-family": "monospace",
            color: "#6b7d88",
            "text-rotation": "autorotate",
            "text-background-color": "#0c1116",
            "text-background-opacity": 0.85,
            "text-background-padding": "1px",
            "line-color": "#35d0ba",
            "target-arrow-color": "#35d0ba",
            "line-opacity": 0.6,
          } as any,
        },
      ],
      wheelSensitivity: 0.3,
    });
    cyRef.current = cy;
    return () => cy.destroy();
  }, []);

  // live update: upsert elements into the existing graph + re-run layout
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      for (const el of elements) {
        const id = (el.data as any).id;
        const existing = cy.getElementById(id);
        if (existing.nonempty()) existing.data(el.data as any);
        else cy.add(el);
      }
    });
    cy.layout({ name: "breadthfirst", directed: true, spacingFactor: 1.25, padding: 20 }).run();
  }, [elements]);

  return <div ref={ref} style={{
    width: "100%", height: "100%", borderRadius: 11, border: "1px solid var(--line)",
    background: "radial-gradient(700px 420px at 30% 15%, #10201f 0%, transparent 60%), var(--sunk)",
  }} />;
}
