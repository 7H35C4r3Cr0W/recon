import { useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import type { ElementDefinition } from "cytoscape";
import { RunGraph } from "../components/RunGraph";
import { connectRun, RunEvent } from "../ws/client";
import { NODE_COLORS, NodeState } from "../lib/nodeColors";

interface NodeRec { id: string; label: string; kind: string; state: NodeState; parent?: string; }

// The live run view: a BloodHound-style map whose nodes recolour as agents move, beside a live log.
export function RunLive() {
  const { runId } = useParams();
  const [nodes, setNodes] = useState<Record<string, NodeRec>>({});
  const [edges, setEdges] = useState<Record<string, { source: string; target: string; label?: string }>>({});
  const [logs, setLogs] = useState<string[]>([]);
  const [status, setStatus] = useState<string>("connecting…");
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!runId) return;
    const ws = connectRun(runId, (e: RunEvent) => apply(e));
    ws.onopen = () => setStatus("live");
    ws.onclose = () => setStatus((s) => (s === "done" ? "done" : "disconnected"));
    return () => ws.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  function apply(e: RunEvent) {
    const d = e.data || {};
    if (e.type === "log.line") {
      const add: string[] = [];
      if (Array.isArray(d.lines)) add.push(...(d.lines as unknown[]).map(String));
      else if (d.line) add.push(String(d.line));
      if (d.suppressed) add.push(`\u2026 ${d.suppressed} lines suppressed (rate-limited)`);
      if (add.length) setLogs((l) => [...l, ...add]);
    }
    if (e.type === "done") setStatus("done");
    const nodeId = d.node_id as string | undefined;
    if (nodeId) {
      setNodes((prev) => {
        const cur = prev[nodeId] || { id: nodeId, label: nodeId, kind: "agent", state: "queued" as NodeState };
        return {
          ...prev,
          [nodeId]: {
            ...cur,
            label: (d.label as string) || cur.label,
            kind: (d.kind as string) || cur.kind,
            state: (d.node_state as NodeState) || cur.state,
            parent: (d.parent as string) || cur.parent,
          },
        };
      });
      if (d.parent) {
        const eid = `${d.parent}->${nodeId}`;
        setEdges((prev) => (prev[eid] ? prev : { ...prev, [eid]: { source: d.parent as string, target: nodeId } }));
      }
    }
    // richer hand-off edges: planner→enum, enum→finding, enum→research, agents→report, …
    if (Array.isArray(d.edges)) {
      setEdges((prev) => {
        const next = { ...prev };
        for (const e of d.edges as Array<{ source: string; target: string; label?: string }>) {
          if (e && e.source && e.target) next[`${e.source}->${e.target}`] = e;
        }
        return next;
      });
    }
  }

  useEffect(() => { logRef.current?.scrollTo(0, logRef.current.scrollHeight); }, [logs]);

  const elements: ElementDefinition[] = useMemo(() => {
    const els: ElementDefinition[] = [];
    for (const n of Object.values(nodes))
      els.push({ data: { id: n.id, label: n.label, kind: n.kind, state: n.state } });
    for (const [id, e] of Object.entries(edges))
      els.push({ data: { id, source: e.source, target: e.target, label: e.label || "" } });
    return els;
  }, [nodes, edges]);

  const counts = Object.values(nodes).reduce<Record<string, number>>((a, n) => {
    a[n.state] = (a[n.state] || 0) + 1; return a;
  }, {});

  return (
    <div style={{ fontFamily: "system-ui", height: "100vh", display: "flex", flexDirection: "column", background: "#0c1116", color: "#e7eef2" }}>
      <header style={{ display: "flex", alignItems: "center", gap: 16, padding: "10px 18px", borderBottom: "1px solid #233039" }}>
        <b style={{ fontFamily: "monospace" }}>NABU · AGENT</b>
        <span style={{ color: "#8394a0" }}>run {runId}</span>
        <span style={{ marginLeft: "auto", display: "flex", gap: 12, fontFamily: "monospace", fontSize: 12 }}>
          {(["active", "done", "stuck", "error", "queued"] as NodeState[]).map((s) => (
            <span key={s} style={{ color: NODE_COLORS[s] }}>● {s} {counts[s] || 0}</span>
          ))}
          <span style={{ color: status === "live" ? "#35d0ba" : "#b7791f" }}>◗ {status}</span>
        </span>
      </header>
      <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 380px", gap: 10, padding: 10, minHeight: 0 }}>
        <RunGraph elements={elements} />
        <div ref={logRef} style={{ overflowY: "auto", background: "#0e141a", border: "1px solid #233039", borderRadius: 10, padding: 12, fontFamily: "monospace", fontSize: 12, lineHeight: 1.6 }}>
          <div style={{ color: "#8394a0", marginBottom: 6 }}>live action log</div>
          {logs.map((l, i) => <div key={i} style={{ color: "#b7c4cc" }}>{l}</div>)}
        </div>
      </div>
    </div>
  );
}
