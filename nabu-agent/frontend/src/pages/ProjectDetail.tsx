import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";

interface ScopeT { id: string; target: string; kind: string; }

export function ProjectDetail() {
  const { projectId } = useParams();
  const nav = useNavigate();
  const [scope, setScope] = useState<ScopeT[]>([]);
  const [target, setTarget] = useState("");
  const [runTarget, setRunTarget] = useState("");
  const [kind, setKind] = useState("demo");
  const [err, setErr] = useState("");

  async function load() {
    try { setScope((await api<{ scope: ScopeT[] }>(`/projects/${projectId}/scope`)).scope); }
    catch (e) { setErr(String(e)); }
  }
  useEffect(() => { load(); }, [projectId]);

  async function addScope(e: React.FormEvent) {
    e.preventDefault();
    try { await api(`/projects/${projectId}/scope`, { method: "POST", body: JSON.stringify({ target }) }); setTarget(""); load(); }
    catch (e) { setErr(String(e)); }
  }

  async function startRun(e: React.FormEvent) {
    e.preventDefault();
    try {
      const r = await api<{ run_id: string }>(`/projects/${projectId}/runs`, {
        method: "POST", body: JSON.stringify({ target: runTarget, kind }),
      });
      nav(`/projects/${projectId}/runs/${r.run_id}`);
    } catch (e) { setErr(String(e)); }
  }

  return (
    <main style={{ fontFamily: "system-ui", padding: 24, maxWidth: 720, margin: "0 auto" }}>
      <h1>Project</h1>
      {err && <p style={{ color: "crimson" }}>{err}</p>}
      <section>
        <h3>Authorized scope</h3>
        <form onSubmit={addScope} style={{ display: "flex", gap: 8 }}>
          <input placeholder="IP or CIDR (e.g. 10.10.10.0/24)" value={target} onChange={(e) => setTarget(e.target.value)} style={{ flex: 1, padding: 8 }} />
          <button type="submit">Add to scope</button>
        </form>
        <ul>{scope.map((s) => <li key={s.id}>{s.target} <span style={{ color: "#888" }}>({s.kind})</span></li>)}</ul>
      </section>
      <section>
        <h3>Run recon</h3>
        <form onSubmit={startRun} style={{ display: "flex", gap: 8 }}>
          <input placeholder="Target in scope (e.g. 10.10.10.5)" value={runTarget} onChange={(e) => setRunTarget(e.target.value)} style={{ flex: 1, padding: 8 }} />
          <select value={kind} onChange={(e) => setKind(e.target.value)} style={{ padding: 8 }}>
            <option value="demo">demo (no tools/LLM — animated)</option>
            <option value="scan">scan (real recon, no LLM)</option>
            <option value="agent">agent (LLM-driven — needs NABU_LLM_BASE_URL)</option>
          </select>
          <button type="submit">Start run ▸</button>
        </form>
        <p style={{ color: "#888", fontSize: 13 }}>The run opens the live BloodHound-style map — agents light up green (active), teal (done), yellow (stuck), red (error).</p>
      </section>
    </main>
  );
}
