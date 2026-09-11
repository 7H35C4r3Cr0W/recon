import { useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import type { Core, ElementDefinition } from "cytoscape";
import { RunGraph } from "../components/RunGraph";
import { MapRegions, REGION_COLORS, type Region } from "../components/MapRegions";
import { connectRun, RunEvent } from "../ws/client";
import { NODE_COLORS, NodeState } from "../lib/nodeColors";
import { api } from "../api/client";

interface NodeRec { id: string; label: string; kind: string; state: NodeState; parent?: string; meta?: Record<string, string | number>; }

// per-node "meat" surfaced in the detail drawer, in display order
const DETAIL_ROWS: [string, string][] = [
  ["port", "Port"], ["proto", "Proto"], ["service", "Service"], ["product", "Product"],
  ["version", "Version"], ["finding_kind", "Kind"], ["severity", "Severity"], ["detail", "Detail"],
];
const META_KEYS = ["port", "proto", "service", "product", "version", "severity", "finding_kind", "detail"];

// The recon lifecycle as a phase stepper. Each engine run-state maps to one visible phase.
const PHASES = ["Queued", "Scanning", "Enumerating", "Researching", "Reporting", "Done"] as const;
const STATE_PHASE: Record<string, number> = {
  queued: 0, validating: 1, alive_check: 1, scanning: 1,
  fan_out: 2, enriching: 2, executing_approved: 2,
  researching: 3, synthesizing: 4, report_ready: 4, awaiting_approval: 4,
  done: 5, partial: 5, failed: 5, cancelled: 5,
};
const TERMINAL = new Set(["done", "partial", "failed", "cancelled"]);

// The live run view: a full-screen BloodHound-style map whose nodes recolour + pulse as agents move,
// with a phase stepper, view controls, and a live log.
export function RunLive() {
  const { runId, projectId } = useParams();
  const [nodes, setNodes] = useState<Record<string, NodeRec>>({});
  const [edges, setEdges] = useState<Record<string, { source: string; target: string; label?: string }>>({});
  const [logs, setLogs] = useState<string[]>([]);
  const [status, setStatus] = useState<string>("connecting…");
  const [phase, setPhase] = useState<string>("queued");
  const [layoutName, setLayoutName] = useState<"cose" | "breadthfirst">("cose");
  const [fitNonce, setFitNonce] = useState(0);
  const [exportNonce, setExportNonce] = useState(0);
  const [showLog, setShowLog] = useState(true);
  const [search, setSearch] = useState("");
  const [hiddenKinds, setHiddenKinds] = useState<string[]>([]);
  const [selected, setSelected] = useState<{ id: string; label: string; kind: string; state: string; hops?: number } | null>(null);
  const [pending, setPending] = useState<{ id: string; message: string } | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [noteDraft, setNoteDraft] = useState("");
  const [cyInstance, setCyInstance] = useState<Core | null>(null);
  const [regions, setRegions] = useState<Region[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const lastSeqRef = useRef(0);

  async function decide(action: "approve" | "reject") {
    if (!pending || !runId) return;
    try { await api(`/runs/${runId}/checkpoints/${pending.id}/${action}`, { method: "POST" }); setPending(null); }
    catch (err) { setLogs((l) => [...l, `[approval] ${action} failed: ${String(err)}`]); }
  }
  async function cancelRun() {
    if (!runId) return;
    try { await api(`/runs/${runId}/cancel`, { method: "POST" }); setLogs((l) => [...l, "[run] cancel requested"]); }
    catch (err) { setLogs((l) => [...l, `[run] cancel failed: ${String(err)}`]); }
  }
  // persist an operator note on a map node (empty text clears it); keyed by the stable node id
  async function saveNote(nodeId: string, text: string) {
    if (!projectId) return;
    try {
      await api(`/projects/${projectId}/map-notes/${encodeURIComponent(nodeId)}`,
                { method: "PUT", body: JSON.stringify({ text }) });
      setNotes((n) => {
        const next = { ...n };
        if (text.trim()) next[nodeId] = text.trim(); else delete next[nodeId];
        return next;
      });
    } catch (err) { setLogs((l) => [...l, `[note] save failed: ${String(err)}`]); }
  }
  // regions: group-anchored boxes over a set of member nodes, persisted per project
  async function saveRegion(r: Region) {
    if (!projectId) return;
    try {
      await api(`/projects/${projectId}/map-regions/${encodeURIComponent(r.id)}`,
                { method: "PUT", body: JSON.stringify({ title: r.title, note: r.note, color: r.color, members: r.members }) });
      setRegions((rs) => {  // API-first, so a failed save never leaves an unpersisted region on the map
        const i = rs.findIndex((x) => x.id === r.id);
        if (i >= 0) { const c = rs.slice(); c[i] = r; return c; }
        return [...rs, r];
      });
    } catch (err) { setLogs((l) => [...l, `[region] save failed: ${String(err)}`]); }
  }
  async function deleteRegion(id: string) {
    if (!projectId) return;
    try {
      await api(`/projects/${projectId}/map-regions/${encodeURIComponent(id)}`, { method: "DELETE" });
      setRegions((rs) => rs.filter((r) => r.id !== id));
    } catch (err) { setLogs((l) => [...l, `[region] delete failed: ${String(err)}`]); }
  }
  function addRegionFromSearch() {
    const q = search.trim().toLowerCase();
    if (!q) { setLogs((l) => [...l, "[region] type a search first — Region groups the matching nodes"]); return; }
    const members = Object.values(nodes).filter((n) => `${n.label} ${n.kind}`.toLowerCase().includes(q)).map((n) => n.id);
    if (!members.length) { setLogs((l) => [...l, "[region] no nodes match that search"]); return; }
    const id = (typeof crypto !== "undefined" && crypto.randomUUID) ? crypto.randomUUID() : `rg-${Date.now()}`;
    saveRegion({ id, title: search.trim(), note: "", color: REGION_COLORS[regions.length % REGION_COLORS.length], members });
  }

  useEffect(() => {
    if (!runId) return;
    const conn = connectRun(runId, (e: RunEvent) => apply(e), setStatus);
    return () => conn.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  function apply(e: RunEvent) {
    if (typeof e.seq === "number" && e.seq > 0) {
      if (e.seq <= lastSeqRef.current) return;
      lastSeqRef.current = e.seq;
    }
    const d = e.data || {};
    if (typeof d.state === "string") setPhase(d.state);
    if (e.type === "log.line") {
      const add: string[] = [];
      if (Array.isArray(d.lines)) add.push(...(d.lines as unknown[]).map(String));
      else if (d.line) add.push(String(d.line));
      if (d.suppressed) add.push(`… ${d.suppressed} lines suppressed (rate-limited)`);
      if (add.length) setLogs((l) => [...l, ...add]);
    }
    if (e.type === "done") { setStatus("done"); setPending(null); setPhase((p) => (TERMINAL.has(p) ? p : String(d.state || "done"))); }
    if (e.type === "approval.required" && d.checkpoint_id) {
      setStatus("awaiting approval");
      setPending({ id: String(d.checkpoint_id), message: String(d.message || "approval required") });
    }
    const nodeId = d.node_id as string | undefined;
    if (nodeId) {
      setNodes((prev) => {
        const cur = prev[nodeId] || { id: nodeId, label: nodeId, kind: "agent", state: "queued" as NodeState };
        const meta = { ...(cur.meta || {}) };
        for (const k of META_KEYS) {
          const v = d[k];
          if (v != null && v !== "") meta[k] = v as string | number;
        }
        return { ...prev, [nodeId]: {
          ...cur, label: (d.label as string) || cur.label, kind: (d.kind as string) || cur.kind,
          state: (d.node_state as NodeState) || cur.state, parent: (d.parent as string) || cur.parent, meta } };
      });
      if (d.parent) {
        const eid = `${d.parent}->${nodeId}`;
        setEdges((prev) => (prev[eid] ? prev : { ...prev, [eid]: { source: d.parent as string, target: nodeId } }));
      }
    }
    if (Array.isArray(d.edges)) {
      setEdges((prev) => {
        const next = { ...prev };
        for (const edge of d.edges as Array<{ source: string; target: string; label?: string }>) {
          if (edge && edge.source && edge.target) next[`${edge.source}->${edge.target}`] = edge;
        }
        return next;
      });
    }
  }

  useEffect(() => { logRef.current?.scrollTo(0, logRef.current.scrollHeight); }, [logs]);

  // load persisted node notes for this project, and keep the drawer's editor synced to the selection
  useEffect(() => {
    if (!projectId) return;
    api<Record<string, string>>(`/projects/${projectId}/map-notes`).then(setNotes).catch(() => {});
    api<Region[]>(`/projects/${projectId}/map-regions`).then(setRegions).catch(() => {});
  }, [projectId]);
  useEffect(() => { setNoteDraft(selected ? notes[selected.id] || "" : ""); }, [selected, notes]);

  const elements: ElementDefinition[] = useMemo(() => {
    const els: ElementDefinition[] = [];
    for (const n of Object.values(nodes)) els.push({ data: { id: n.id, label: n.label, kind: n.kind, state: n.state } });
    for (const [id, e] of Object.entries(edges)) els.push({ data: { id, source: e.source, target: e.target, label: e.label || "" } });
    return els;
  }, [nodes, edges]);

  const counts = Object.values(nodes).reduce<Record<string, number>>((a, n) => { a[n.state] = (a[n.state] || 0) + 1; return a; }, {});
  const phaseIdx = STATE_PHASE[phase] ?? 0;
  const terminal = TERMINAL.has(phase);

  return (
    <div className="live-wrap">
      <header className="live-head">
        <span className="brand"><span className="dot" /> NABU·AGENT</span>
        <span className="mono muted">run {runId}</span>
        <span className="legend">
          {(["active", "done", "stuck", "error", "queued"] as NodeState[]).map((s) => (
            <span key={s} className="lg" style={{ color: NODE_COLORS[s] }}>
              <span className="d" style={{ background: NODE_COLORS[s] }} /> {s} {counts[s] || 0}
            </span>
          ))}
          <span className="rec" style={{ color: status === "live" ? "var(--accent)" : "var(--gold)" }}>
            <span className="d" style={{ background: "currentColor" }} /> {status}
          </span>
        </span>
      </header>

      {/* phase stepper — the current phase pulses green ("digging") */}
      <div className="phases">
        {PHASES.map((p, i) => {
          const cls = i < phaseIdx || (terminal && i === phaseIdx) ? "done"
            : i === phaseIdx ? (terminal ? "done" : "active") : "todo";
          return (
            <span key={p} className={`ph ${cls}`}>
              <span className="pnum">{i < phaseIdx || (terminal && i <= phaseIdx) ? "✓" : i + 1}</span>{p}
            </span>
          );
        })}
        <span className="phase-tag mono">{phase}</span>
      </div>

      {pending && (
        <div role="alert" className="approve-bar">
          <b>⏸ Approval required</b>
          <span style={{ color: "var(--ink-2)" }}>{pending.message}</span>
          <span style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <button className="btn-approve" onClick={() => decide("approve")}>Approve</button>
            <button className="btn-reject" onClick={() => decide("reject")}>Reject</button>
          </span>
        </div>
      )}

      {/* controls toolbar for the recon flow view */}
      <div className="map-controls">
        <span className="grp">
          <span className="lbl">layout</span>
          <button className={`seg ${layoutName === "cose" ? "on" : ""}`} onClick={() => setLayoutName("cose")}>Force (BloodHound)</button>
          <button className={`seg ${layoutName === "breadthfirst" ? "on" : ""}`} onClick={() => setLayoutName("breadthfirst")}>Hierarchy</button>
        </span>
        <button className="seg" onClick={() => setFitNonce((n) => n + 1)}>⤢ Fit</button>
        <button className="seg" onClick={() => setExportNonce((n) => n + 1)}>⬇ PNG</button>
        <button className="seg" onClick={addRegionFromSearch} title="group the current search matches into a region">▢ Region</button>
        <input className="input" style={{ maxWidth: 190, padding: "6px 10px", fontSize: 12 }} value={search}
          onChange={(e) => setSearch(e.target.value)} placeholder="search nodes… (dc01 · 445 · svc_)" aria-label="search nodes" />
        <span className="grp">
          <span className="lbl">show</span>
          {["agent", "service", "finding", "report", "attack"].map((k) => (
            <button key={k} className={`seg ${hiddenKinds.includes(k) ? "" : "on"}`}
              onClick={() => setHiddenKinds((h) => (h.includes(k) ? h.filter((x) => x !== k) : [...h, k]))}>{k}</button>
          ))}
        </span>
        <button className="seg" onClick={() => setShowLog((v) => !v)}>{showLog ? "Hide log" : "Show log"}</button>
        <span className="mono muted" style={{ marginLeft: "auto", fontSize: 10.5 }}>shift-click 2 nodes → path · C copies · Esc clears</span>
        {!terminal && <button className="seg danger" onClick={cancelRun}>■ Cancel run</button>}
      </div>

      <div className="map-body" style={{ gridTemplateColumns: showLog ? "1fr 380px" : "1fr" }}>
        <div style={{ position: "relative", minHeight: 0 }}>
          <RunGraph elements={elements} layoutName={layoutName} fitNonce={fitNonce} onSelect={setSelected} search={search} hiddenKinds={hiddenKinds} selectedId={selected?.id ?? null} exportNonce={exportNonce} notedIds={Object.keys(notes)} onCy={setCyInstance} />
          <MapRegions cy={cyInstance} regions={regions} onSave={saveRegion} onDelete={deleteRegion} />
          {selected && (
            <div className="node-drawer">
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="dk mono">{selected.kind}</span>
                <button className="x" onClick={() => setSelected(null)}>✕</button>
              </div>
              <div className="dv mono">{selected.label}</div>
              <div className="ds"><span className="d" style={{ background: NODE_COLORS[selected.state as NodeState] || "#8394a0" }} />{selected.state}</div>
              <div className="mono muted" style={{ fontSize: 10, marginTop: 6 }}>{selected.id}</div>
              {(() => {
                const m = nodes[selected.id]?.meta;
                const rows = m ? DETAIL_ROWS.filter(([k]) => m[k] != null && m[k] !== "") : [];
                if (!rows.length) return null;
                return (
                  <div style={{ marginTop: 8, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
                    {rows.map(([k, label]) => (
                      <div key={k} style={{ display: "flex", gap: 8, fontFamily: "var(--mono)", fontSize: 11, padding: "3px 0" }}>
                        <span style={{ color: "var(--muted)", flex: "0 0 62px", textTransform: "uppercase", fontSize: 9.5 }}>{label}</span>
                        <span style={{ color: k === "severity" ? "var(--gold)" : "var(--ink)", flex: 1, wordBreak: "break-word" }}>{String(m![k])}</span>
                      </div>
                    ))}
                  </div>
                );
              })()}
              {typeof selected.hops === "number" && (
                <div className="mono" style={{ fontSize: 10, marginTop: 6, color: "var(--gold)" }}>
                  attack path: {selected.hops} hop{selected.hops === 1 ? "" : "s"} from the entry
                </div>
              )}
              <div style={{ marginTop: 10, borderTop: "1px solid var(--line)", paddingTop: 9 }}>
                <div className="mono muted" style={{ fontSize: 9.5, letterSpacing: ".12em", textTransform: "uppercase", marginBottom: 5 }}>📌 note</div>
                <textarea className="input" style={{ width: "100%", minHeight: 46, fontSize: 11, resize: "vertical" }}
                  value={noteDraft} onChange={(e) => setNoteDraft(e.target.value)} placeholder="add a note on this node…" />
                <div style={{ display: "flex", gap: 7, marginTop: 6 }}>
                  <button className="seg on" style={{ flex: 1 }} onClick={() => saveNote(selected.id, noteDraft)}>Save</button>
                  <button className="seg" style={{ flex: 1 }} onClick={() => { setNoteDraft(""); saveNote(selected.id, ""); }}>Clear</button>
                </div>
              </div>
            </div>
          )}
          {/* node-type key — swatch SHAPE mirrors the real node shape (circle/box/diamond/star) so it
              teaches the map's visual language, not just its colours. Keep in sync with RunGraph. */}
          <div className="type-legend">
            {([["target/host", "#74c7ec", "circle"], ["service", "#89b4fa", "circle"], ["agent", "#fab387", "box"],
               ["finding", "#f9e2af", "diamond"], ["attack", "#f38ba8", "diamond"], ["report", "#cba6f7", "star"]] as [string, string, string][]).map(([l, c, s]) => (
              <span key={l} className="tl"><span className={`sw ${s}`} style={{ background: c }} />{l}</span>
            ))}
          </div>
        </div>
        {showLog && (
          <div ref={logRef} className="logpane">
            <div className="lead" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span>live action log</span>
              <button className="seg" style={{ padding: "2px 8px", fontSize: 12 }} title="collapse log"
                onClick={() => setShowLog(false)}>›</button>
            </div>
            {logs.length === 0 ? <div className="ln muted">waiting for the run to start…</div>
              : logs.map((l, i) => <div key={i} className="ln">{l}</div>)}
          </div>
        )}
      </div>
    </div>
  );
}
