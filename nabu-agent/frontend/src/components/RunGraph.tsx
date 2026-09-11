import { useEffect, useRef } from "react";
import cytoscape, { Core, ElementDefinition } from "cytoscape";
import { NODE_COLORS } from "../lib/nodeColors";

// BloodHound-style run graph (mirrors the classic Nabu GUI's cytoscape view): a force-directed
// layout of coloured discs by node KIND, with a live STATE ring — active nodes pulse green while the
// run is "digging". Node/edge palette follows the GUI (Catppuccin dark).
const KIND_COLOR: Record<string, string> = {
  run: "#1e3a8a", target: "#1e3a8a", host: "#74c7ec", service: "#89b4fa",
  finding: "#f9e2af", report: "#cba6f7", agent: "#89b4fa", attack: "#f38ba8",
};

export function RunGraph({ elements, layoutName = "cose", fitNonce = 0 }:
  { elements: ElementDefinition[]; layoutName?: "cose" | "breadthfirst"; fitNonce?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const layoutTimer = useRef<number | null>(null);
  const pulseTimer = useRef<number | null>(null);

  const runLayout = (cy: Core) => {
    const opts = layoutName === "breadthfirst"
      ? { name: "breadthfirst", directed: true, spacingFactor: 1.3, padding: 30, animate: true, animationDuration: 350 }
      : { name: "cose", padding: 40, animate: true, animationDuration: 500, nodeRepulsion: 9000,
          idealEdgeLength: 95, nodeOverlap: 16, gravity: 0.25, componentSpacing: 110 };
    cy.layout(opts as cytoscape.LayoutOptions).run();
  };

  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({
      container: ref.current,
      elements: [],
      style: [
        {
          selector: "node",
          style: {
            "background-color": ((n: cytoscape.NodeSingular) => KIND_COLOR[(n.data("kind") as string) || "agent"] || "#89b4fa") as any,
            label: "data(label)", color: "#cdd6f4", "font-size": 10, "font-family": "monospace",
            "text-valign": "bottom", "text-margin-y": 6, "text-max-width": "120px",
            "text-outline-color": "#0b1116", "text-outline-width": 2,
            width: 36, height: 36, "border-width": 2, "border-color": "#0b1116",
            "overlay-color": "#39c46a", "overlay-opacity": 0, "overlay-padding": 6,
            "transition-property": "border-color border-width", "transition-duration": "0.25s",
          } as any,
        },
        { selector: 'node[kind="run"], node[kind="target"]', style: { width: 54, height: 54, "font-size": 12, shape: "round-rectangle" } },
        { selector: 'node[kind="host"]', style: { shape: "hexagon", width: 46, height: 46, "font-size": 11 } },
        { selector: 'node[kind="service"]', style: { shape: "ellipse" } },
        { selector: 'node[kind="finding"]', style: { shape: "diamond", width: 30, height: 30 } },
        { selector: 'node[kind="report"]', style: { shape: "star", width: 46, height: 46 } },
        { selector: 'node[kind="attack"]', style: { shape: "diamond", width: 40, height: 40 } },
        // live STATE ring (thick so it reads when zoomed out) — the GUI's status-ring idea
        { selector: 'node[state="done"]', style: { "border-color": NODE_COLORS.done, "border-width": 5 } as any },
        { selector: 'node[state="active"]', style: { "border-color": "#39c46a", "border-width": 5, "overlay-opacity": 0.18 } as any },
        { selector: 'node[state="stuck"]', style: { "border-color": NODE_COLORS.stuck, "border-width": 5 } as any },
        { selector: 'node[state="error"]', style: { "border-color": NODE_COLORS.error, "border-width": 5 } as any },
        {
          selector: "edge",
          style: { width: 1.6, "line-color": "#5b6b7d", "target-arrow-color": "#5b6b7d",
                   "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8 },
        },
        {
          selector: "edge[label]",
          style: {
            label: "data(label)", "font-size": 8, "font-family": "monospace", color: "#8598ac",
            "text-rotation": "autorotate", "text-background-color": "#0b1116",
            "text-background-opacity": 0.85, "text-background-padding": "1px",
            "line-color": "#3ad9c0", "target-arrow-color": "#3ad9c0", "line-opacity": 0.55,
          } as any,
        },
      ],
      wheelSensitivity: 0.3,
    });
    cyRef.current = cy;

    // pulsating-green "digging" halo: ping-pong the active nodes' green overlay so they visibly
    // throb where the run is currently working. Honours reduced-motion.
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (!reduce) {
      let grow = true;
      pulseTimer.current = window.setInterval(() => {
        const active = cy.$('node[state="active"]');
        if (active.length === 0) return;
        grow = !grow;
        active.animate({ style: { "overlay-padding": grow ? 17 : 6, "overlay-opacity": grow ? 0.32 : 0.12 } },
                       { duration: 780, easing: "ease-in-out-sine" });
      }, 820);
    }
    return () => {
      if (layoutTimer.current !== null) clearTimeout(layoutTimer.current);
      if (pulseTimer.current !== null) clearInterval(pulseTimer.current);
      cy.destroy();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // live update: upsert immediately, debounce the (expensive) relayout so a burst settles into one.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      for (const el of elements) {
        const id = (el.data as { id?: string }).id;
        const existing = cy.getElementById(id as string);
        if (existing.nonempty()) existing.data(el.data);
        else cy.add(el);
      }
    });
    if (layoutTimer.current !== null) clearTimeout(layoutTimer.current);
    layoutTimer.current = window.setTimeout(() => runLayout(cy), 160);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [elements, layoutName]);

  // parent-driven "fit to screen"
  useEffect(() => {
    const cy = cyRef.current;
    if (cy && fitNonce) cy.animate({ fit: { eles: cy.elements(), padding: 40 } }, { duration: 350 });
  }, [fitNonce]);

  return <div ref={ref} style={{
    width: "100%", height: "100%", borderRadius: 11, border: "1px solid var(--line)",
    background: "radial-gradient(900px 520px at 32% 12%, #10201f 0%, transparent 60%), var(--sunk)",
  }} />;
}
