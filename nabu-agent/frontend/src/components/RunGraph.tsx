import { useEffect, useRef } from "react";
import cytoscape, { Core, ElementDefinition } from "cytoscape";
import { NODE_COLORS } from "../lib/nodeColors";
import { shortestPath, pathNext } from "../lib/graphPath";

// BloodHound-style run graph (mirrors the classic Nabu GUI + SpecterOps BloodHound's Sigma view):
// a force-directed spread of coloured discs with a TYPE GLYPH, a live STATE ring, a pulsating-green
// "digging" halo on active nodes, and BloodHound's signature hover-to-highlight-neighbourhood
// (everything else dims) + click-to-select. Palette follows the GUI (Catppuccin dark).
const KIND_COLOR: Record<string, string> = {
  run: "#1e3a8a", target: "#1e3a8a", host: "#74c7ec", service: "#89b4fa",
  finding: "#f9e2af", report: "#cba6f7", agent: "#fab387", attack: "#f38ba8",  // agents: distinct peach + a box shape
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

// copy text to the clipboard, with an execCommand fallback for non-secure contexts
function fallbackCopy(text: string) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select(); document.execCommand("copy"); document.body.removeChild(ta);
  } catch { /* clipboard unavailable */ }
}
function copyToClipboard(text: string) {
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
  else fallbackCopy(text);
}

export function RunGraph({ elements, layoutName = "cose", fitNonce = 0, onSelect, search = "", hiddenKinds, selectedId, exportNonce = 0, notedIds, onCy }:
  { elements: ElementDefinition[]; layoutName?: "cose" | "breadthfirst"; fitNonce?: number;
    onSelect?: (n: { id: string; label: string; kind: string; state: string; hops?: number } | null) => void;
    search?: string; hiddenKinds?: string[]; selectedId?: string | null; exportNonce?: number;
    notedIds?: string[]; onCy?: (cy: Core | null) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const layoutTimer = useRef<number | null>(null);
  const pulseTimer = useRef<number | null>(null);
  const selectedRef = useRef<string | null>(null);
  const pathARef = useRef<string | null>(null);   // first endpoint of a shift-click A→B selection
  const currentPathRef = useRef<string[]>([]);     // node ids of the pinned path (copy-as-text)
  const laidOutRef = useRef(false);                // fit only on the first layout / layout-name change
  const layoutNameRef = useRef(layoutName);        // so incremental relayouts keep the operator's pan/zoom

  const runLayout = (cy: Core, fit = true) => {
    const opts = layoutName === "breadthfirst"
      ? { name: "breadthfirst", directed: true, spacingFactor: 1.35, padding: 34, animate: true,
          animationDuration: 350, fit, nodeDimensionsIncludeLabels: true }
      : { name: "cose", padding: 50, animate: true, animationDuration: 500, fit,
          nodeDimensionsIncludeLabels: true, nodeRepulsion: 14000, idealEdgeLength: 130,
          nodeOverlap: 28, gravity: 0.2, componentSpacing: 150, randomize: false };
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
        // agents get their OWN shape (round-rectangle "worker box") + peach fill so they're never
        // confused with circular blue services — plus the agent glyph.
        { selector: 'node[kind="agent"]', style: { shape: "round-rectangle", width: 42, height: 30, "background-image": ICON.agent } as any },
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
        // click-to-highlight attack path (target root → clicked node): path pops gold, rest dims
        { selector: ".offpath", style: { opacity: 0.1, "text-opacity": 0.1 } as any },
        { selector: "node.onpath", style: { "border-color": "#f2b636", "border-width": 6 } as any },
        { selector: "node.path-a", style: { "border-color": "#3ad9c0", "border-width": 6 } as any },
        // a node with an operator note: dashed gold ring so it's spotted at a glance
        { selector: "node.noted", style: { "border-color": "#f9e2af", "border-width": 4, "border-style": "dashed" } as any },
        { selector: "edge.onpath", style: { "line-color": "#f2b636", "target-arrow-color": "#f2b636", width: 3.2, opacity: 1 } as any },
        // search highlight + node-type filter
        { selector: ".search-dim", style: { opacity: 0.12, "text-opacity": 0.12 } as any },
        { selector: "node.search-hit", style: { "border-color": "#3ad9c0", "border-width": 5 } as any },
        { selector: ".type-hidden", style: { display: "none" } as any },
        {
          selector: "edge",
          style: { width: 1.6, "line-color": "#5b6b7d", "target-arrow-color": "#5b6b7d",
                   "target-arrow-shape": "triangle", "curve-style": "unbundled-bezier",
                   "control-point-distances": "36", "control-point-weights": "0.5",
                   "arrow-scale": 0.8, opacity: 0.85 } as any,
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
    onCy?.(cy); // hand the instance up so an overlay (regions) can read bboxes + camera

    // hover → highlight the node + its neighbourhood, dim the rest (BloodHound's signature).
    // Suppressed while an attack path is pinned by a click, so the two don't fight.
    cy.on("mouseover", "node", (e) => {
      if (selectedRef.current) return;
      const nb = e.target.closedNeighborhood();
      cy.elements().addClass("faded");
      nb.removeClass("faded").addClass("hl");
    });
    cy.on("mouseout", "node", () => { if (!selectedRef.current) cy.elements().removeClass("faded hl"); });

    // click a node → select (parent shows details) AND pin the attack path from the target root to
    // it in gold, everything else dimmed (BloodHound "shortest path" adapted to the rooted recon
    // graph); click blank → clear both.
    const pinPath = (node: cytoscape.NodeSingular): number | undefined => {
      cy.elements().removeClass("faded hl onpath offpath path-a");
      const root = cy.nodes().filter((n) => {
        const k = n.data("kind") as string; return k === "run" || k === "target"; }).first();
      if (root.empty()) return undefined;
      const ids = shortestPath(
        // visible edges only, so a path never routes through type-filtered (hidden) nodes/edges
        cy.edges(":visible").map((ed) => ({ source: ed.source().id(), target: ed.target().id() })),
        root.id(), node.id());
      if (ids.length === 0) return undefined;
      currentPathRef.current = ids;
      const onPath = new Set(ids);
      const next = pathNext(ids);
      cy.elements().addClass("offpath");
      cy.nodes().forEach((n) => { if (onPath.has(n.id())) n.removeClass("offpath").addClass("onpath"); });
      cy.edges().forEach((ed) => {
        if (next.get(ed.source().id()) === ed.target().id()) ed.removeClass("offpath").addClass("onpath"); });
      return ids.length - 1;
    };
    // undirected shortest path between two nodes (visible edges), for the shift-click A→B feature
    const undirectedPath = (aId: string, bId: string): string[] => {
      const vis = cy.edges(":visible").map((ed) => ({ source: ed.source().id(), target: ed.target().id() }));
      const both = vis.flatMap((e) => [e, { source: e.target, target: e.source }]);
      return shortestPath(both, aId, bId);
    };
    // highlight an explicit ordered id list; edges match in either direction (relationship, not arrow)
    const pinPathIds = (ids: string[]) => {
      cy.elements().removeClass("faded hl onpath offpath path-a");
      currentPathRef.current = ids;
      const onPath = new Set(ids);
      const pair = new Set<string>();
      for (let i = 0; i < ids.length - 1; i++) { pair.add(ids[i] + "|" + ids[i + 1]); pair.add(ids[i + 1] + "|" + ids[i]); }
      cy.elements().addClass("offpath");
      cy.nodes().forEach((n) => { if (onPath.has(n.id())) n.removeClass("offpath").addClass("onpath"); });
      cy.edges().forEach((ed) => {
        if (pair.has(ed.source().id() + "|" + ed.target().id())) ed.removeClass("offpath").addClass("onpath"); });
    };
    cy.on("tap", "node", (e) => {
      const oe = e.originalEvent as MouseEvent | undefined;
      if (oe && oe.shiftKey) {
        // shift-click two nodes → trace the path between them (BloodHound "path A→B")
        if (!pathARef.current) {
          pathARef.current = e.target.id();
          cy.elements().removeClass("faded hl onpath offpath path-a");
          e.target.addClass("path-a");
        } else {
          const ids = undirectedPath(pathARef.current, e.target.id());
          if (ids.length >= 2) {
            pinPathIds(ids);
            selectedRef.current = e.target.id();
            // keep the drawer/selectedId in sync with the pinned endpoint
            onSelect?.({ id: e.target.id(), label: e.target.data("label"), kind: e.target.data("kind"), state: e.target.data("state") });
          }
          pathARef.current = null;
        }
        return;
      }
      pathARef.current = null;   // a plain click cancels any in-progress shift-click A→B start
      selectedRef.current = e.target.id();
      const hops = pinPath(e.target);
      onSelect?.({ id: e.target.id(), label: e.target.data("label"), kind: e.target.data("kind"), state: e.target.data("state"), hops });
    });
    cy.on("tap", (e) => {
      if (e.target === cy) { onSelect?.(null); selectedRef.current = null; pathARef.current = null; currentPathRef.current = []; cy.elements().removeClass("faded hl onpath offpath path-a"); }
    });

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
      onCy?.(null);
      cy.destroy();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      for (const el of elements) {
        const d = el.data as { id?: string; source?: string; target?: string };
        const existing = cy.getElementById(d.id as string);
        if (existing.nonempty()) { existing.data(el.data); continue; }
        // an edge whose source/target node isn't present yet would make cytoscape throw (and abort
        // the whole batch, freezing the live map) — skip it; it's retried on the next render once
        // the endpoint node arrives.
        if (d.source !== undefined || d.target !== undefined) {
          if (cy.getElementById(d.source as string).empty() || cy.getElementById(d.target as string).empty()) continue;
        }
        cy.add(el);
      }
    });
    if (layoutTimer.current !== null) clearTimeout(layoutTimer.current);
    // fit only on the first layout or an explicit layout-name switch — never on an incremental
    // element add, so a mid-run scan doesn't yank the operator's pan/zoom (Fit button / fitNonce
    // is the explicit way to re-fit).
    const shouldFit = !laidOutRef.current || layoutNameRef.current !== layoutName;
    laidOutRef.current = true;
    layoutNameRef.current = layoutName;
    layoutTimer.current = window.setTimeout(() => runLayout(cy, shouldFit), 160);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [elements, layoutName]);

  useEffect(() => {
    const cy = cyRef.current;
    if (cy && fitNonce) cy.animate({ fit: { eles: cy.elements(), padding: 45 } }, { duration: 350 });
  }, [fitNonce]);

  // search: highlight matches by label/kind, dim the rest (BloodHound-style)
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const q = search.trim().toLowerCase();
    cy.nodes().removeClass("search-hit search-dim");
    if (!q) return;
    cy.nodes().forEach((n) => {
      const hay = `${n.data("label") ?? ""} ${n.data("kind") ?? ""}`.toLowerCase();
      n.addClass(hay.includes(q) ? "search-hit" : "search-dim");
    });
  }, [search, elements]);

  // node-type filter: hide whole kinds to declutter (an edge is hidden when either end is)
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const hidden = new Set(hiddenKinds ?? []);
    cy.nodes().forEach((n) => { n.toggleClass("type-hidden", hidden.has(n.data("kind") as string)); });
    cy.edges().forEach((ed) => {
      ed.toggleClass("type-hidden", ed.source().hasClass("type-hidden") || ed.target().hasClass("type-hidden"));
    });
  }, [hiddenKinds, elements]);

  // Escape clears a pinned attack path / selection
  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      const cy = cyRef.current;
      if (!cy) return;
      if (ev.key === "Escape") {
        // don't clear the map / close the drawer while the operator is typing a note (would lose the draft)
        const el = document.activeElement as HTMLElement | null;
        const tag = (el?.tagName || "").toLowerCase();
        if (tag === "input" || tag === "textarea" || el?.isContentEditable) return;
        selectedRef.current = null; pathARef.current = null; currentPathRef.current = [];
        cy.elements().removeClass("faded hl onpath offpath path-a");
        onSelect?.(null);
      } else if ((ev.key === "c" || ev.key === "C") && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
        const tag = (document.activeElement?.tagName || "").toLowerCase();
        if (tag === "input" || tag === "textarea") return;
        const ids = currentPathRef.current;
        if (ids.length < 2) return;
        const text = ids.map((id) => (cy.getElementById(id).data("label") as string) || id).join(" -> ");
        copyToClipboard(text);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // mark nodes that carry an operator note (dashed gold ring)
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const noted = new Set(notedIds ?? []);
    cy.nodes().forEach((n) => { n.toggleClass("noted", noted.has(n.id())); });
  }, [notedIds, elements]);

  // export the current map as a PNG (parity with the desktop graph's export)
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !exportNonce) return;
    try {
      const bg = getComputedStyle(document.documentElement).getPropertyValue("--sunk").trim() || "#070a0e";
      const png = cy.png({ output: "blob", full: true, scale: 2, bg }) as Blob;
      const url = URL.createObjectURL(png);
      const a = document.createElement("a");
      a.href = url;
      a.download = "nabu-recon-map.png";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { /* export unavailable */ }
  }, [exportNonce]);

  // when the selection is cleared externally (drawer ✕), drop the pinned path + re-enable hover-focus
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    if (selectedId == null && selectedRef.current != null) {
      selectedRef.current = null; pathARef.current = null; currentPathRef.current = [];
      cy.elements().removeClass("faded hl onpath offpath path-a");
    }
  }, [selectedId]);

  return <div ref={ref} style={{
    width: "100%", height: "100%", borderRadius: 11, border: "1px solid var(--line)",
    background: "radial-gradient(900px 520px at 32% 12%, #10201f 0%, transparent 60%), var(--sunk)",
  }} />;
}
