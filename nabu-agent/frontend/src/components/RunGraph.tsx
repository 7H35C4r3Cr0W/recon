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
            color: "#cfe0e6",
            "font-size": 10,
            "font-family": "monospace",
            "text-valign": "bottom",
            "text-margin-y": 4,
            width: 34,
            height: 34,
            "border-width": 2,
            "border-color": "#0e141a",
          },
        },
        { selector: 'node[kind="run"]', style: { shape: "round-rectangle", width: 46, height: 30 } },
        { selector: 'node[kind="host"]', style: { shape: "hexagon", width: 44, height: 44 } },
        { selector: 'node[kind="finding"]', style: { shape: "diamond" } },
        { selector: 'node[kind="report"]', style: { shape: "star" } },
        {
          selector: 'node[state="active"]',
          style: {
            "border-color": "#35d0ba",
            "border-width": 4,
            "shadow-blur": 24,
            "shadow-color": "#2f9e57",
            "shadow-opacity": 0.9,
          } as any,
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#2e3d48",
            "target-arrow-color": "#2e3d48",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
          },
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

  return <div ref={ref} style={{ width: "100%", height: "100%", background: "#0c1116", borderRadius: 10 }} />;
}
