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
    <div style={{ maxWidth: 720 }}>
      <h1>Project</h1>
      {err && <p className="err">{err}</p>}

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Authorized scope</h3>
        <form onSubmit={addScope} className="row">
          <input className="input" style={{ flex: 1 }} placeholder="IP or CIDR (e.g. 10.10.10.0/24)" value={target} onChange={(e) => setTarget(e.target.value)} />
          <button className="btn" type="submit">Add to scope</button>
        </form>
        <ul className="list" style={{ marginTop: 10 }}>
          {scope.map((s) => <li key={s.id} className="row"><span className="pill">{s.kind}</span> <span className="mono">{s.target}</span></li>)}
        </ul>
      </div>

      <div className="card">
        <h3>Run recon</h3>
        <form onSubmit={startRun} className="row">
          <input className="input" style={{ flex: 1 }} placeholder="Target in scope (e.g. 10.10.10.5)" value={runTarget} onChange={(e) => setRunTarget(e.target.value)} />
          <select className="select" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="demo">demo (animated)</option>
            <option value="scan">scan (real recon)</option>
            <option value="agent">agent (LLM-driven)</option>
          </select>
          <button className="btn btn-primary" type="submit">Start run ▸</button>
        </form>
        <p className="muted" style={{ fontSize: 13 }}>Opens the live map — agents light up green (active), teal (done), yellow (stuck), red (error).</p>
      </div>
    </div>
  );
}
