import { useEffect, useRef } from "react";
import cytoscape, { Core, ElementDefinition } from "cytoscape";
import { NODE_COLORS } from "../lib/nodeColors";

// BloodHound-style run graph (mirrors the classic Nabu GUI + SpecterOps BloodHound's Sigma view):
// a force-directed spread of coloured discs with a TYPE GLYPH, a live STATE ring, a pulsating-green
// "digging" halo on active nodes, and BloodHound's signature hover-to-highlight-neighbourhood
// (everything else dims) + click-to-select. Palette follows the GUI (Catppuccin dark).
const KIND_COLOR: Record<string, string> = {
  run: "#1e3a8a", target: "#1e3a8a", host: "#74c7ec", service: "#89b4fa",
  finding: "#f9e2af", report: "#cba6f7", agent: "#89b4fa", attack: "#f38ba8",
};
const glyph = (inner: string) =>
  "data:image/svg+xml;utf8," + encodeURIComponent(
    `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#0b1116' stroke-width='2.1' stroke-linecap='round' stroke-linejoin='round'>${inner}</svg>`);
const ICON: Record<string, string> = {
  target: glyph("<circle cx='12' cy='12' r='8'/><circle cx='12' cy='12' r='3'/><path d='M12 1v3M12 20v3M1 12h3M20 12h3'/>"),
  host: glyph("<rect x='3' y='4' width='18' height='12' rx='1.5'/><path d='M9 20h6M12 16v4'/>"),
  service: glyph("<rect x='4' y='5' width='16' height='4' rx='1'/><rect x='4' y='12' width='16' height='4' rx='1'/><path d='M7 7h.01M7 14h.01'/>"),
  agent: glyph("<rect x='5' y='7' width='14' height='11' rx='2'/><path d='M12 7V4M9 12h.01M15 12h.01M9 15h6'/>"),
};

export function RunGraph({ elements, layoutName = "cose", fitNonce = 0, onSelect }:
  { elements: ElementDefinition[]; layoutName?: "cose" | "breadthfirst"; fitNonce?: number;
    onSelect?: (n: { id: string; label: string; kind: string; state: string } | null) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const layoutTimer = useRef<number | null>(null);
  const pulseTimer = useRef<number | null>(null);

  const runLayout = (cy: Core) => {
    const opts = layoutName === "breadthfirst"
      ? { name: "breadthfirst", directed: true, spacingFactor: 1.35, padding: 34, animate: true,
          animationDuration: 350, nodeDimensionsIncludeLabels: true }
      : { name: "cose", padding: 50, animate: true, animationDuration: 500, nodeDimensionsIncludeLabels: true,
          nodeRepulsion: 14000, idealEdgeLength: 130, nodeOverlap: 28, gravity: 0.2,
          componentSpacing: 150, randomize: false };
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
            width: 38, height: 38, "border-width": 2, "border-color": "#0b1116",
            "background-fit": "none", "background-width": "54%", "background-height": "54%", "background-clip": "none",
            "overlay-color": "#39c46a", "overlay-opacity": 0, "overlay-padding": 6,
            "transition-property": "opacity border-color border-width", "transition-duration": "0.2s",
          } as any,
        },
        { selector: 'node[kind="run"], node[kind="target"]', style: { width: 56, height: 56, "font-size": 12, "background-image": ICON.target } as any },
        { selector: 'node[kind="host"]', style: { width: 48, height: 48, "font-size": 11, "background-image": ICON.host } as any },
        { selector: 'node[kind="service"]', style: { "background-image": ICON.service } as any },
        { selector: 'node[kind="agent"]', style: { "background-image": ICON.agent } as any },
        { selector: 'node[kind="finding"]', style: { shape: "diamond", width: 32, height: 32 } },
        { selector: 'node[kind="report"]', style: { shape: "star", width: 48, height: 48 } },
        { selector: 'node[kind="attack"]', style: { shape: "diamond", width: 42, height: 42 } },
        { selector: 'node[state="done"]', style: { "border-color": NODE_COLORS.done, "border-width": 5 } as any },
        { selector: 'node[state="active"]', style: { "border-color": "#39c46a", "border-width": 5, "overlay-opacity": 0.18 } as any },
        { selector: 'node[state="stuck"]', style: { "border-color": NODE_COLORS.stuck, "border-width": 5 } as any },
        { selector: 'node[state="error"]', style: { "border-color": NODE_COLORS.error, "border-width": 5 } as any },
        // BloodHound-style focus: fade everything not in the hovered/selected node's neighbourhood
        { selector: ".faded", style: { opacity: 0.12, "text-opacity": 0.12 } as any },
        { selector: "node.hl", style: { "border-color": "#3ad9c0", "border-width": 5 } as any },
        {
          selector: "edge",
          style: { width: 1.6, "line-color": "#5b6b7d", "target-arrow-color": "#5b6b7d",
                   "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8 },
        },
        { selector: "edge.hl", style: { "line-color": "#3ad9c0", "target-arrow-color": "#3ad9c0", width: 2.4, "line-opacity": 0.95 } as any },
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

    // hover → highlight the node + its neighbourhood, dim the rest (BloodHound's signature)
    cy.on("mouseover", "node", (e) => {
      const nb = e.target.closedNeighborhood();
      cy.elements().addClass("faded");
      nb.removeClass("faded").addClass("hl");
    });
    cy.on("mouseout", "node", () => cy.elements().removeClass("faded hl"));
    // click a node → select (parent shows details); click blank → clear
    cy.on("tap", "node", (e) => onSelect?.({
      id: e.target.id(), label: e.target.data("label"), kind: e.target.data("kind"), state: e.target.data("state") }));
    cy.on("tap", (e) => { if (e.target === cy) onSelect?.(null); });

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

  useEffect(() => {
    const cy = cyRef.current;
    if (cy && fitNonce) cy.animate({ fit: { eles: cy.elements(), padding: 45 } }, { duration: 350 });
  }, [fitNonce]);

  return <div ref={ref} style={{
    width: "100%", height: "100%", borderRadius: 11, border: "1px solid var(--line)",
    background: "radial-gradient(900px 520px at 32% 12%, #10201f 0%, transparent 60%), var(--sunk)",
  }} />;
}
