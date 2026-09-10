import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";

interface ScopeT { id: string; target: string; kind: string; }
interface RunT { id: string; state: string; target: string; kind: string; }
interface ActT { ts: string | null; action: string; result: string; actor_user_id: string | null; }
interface MemberT { user_id: string; email: string | null; role: string; }

export function ProjectDetail() {
  const { projectId } = useParams();
  const nav = useNavigate();
  const [scope, setScope] = useState<ScopeT[]>([]);
  const [runs, setRuns] = useState<RunT[]>([]);
  const [activity, setActivity] = useState<ActT[]>([]);
  const [members, setMembers] = useState<MemberT[]>([]);
  const [target, setTarget] = useState("");
  const [runTarget, setRunTarget] = useState("");
  const [kind, setKind] = useState("demo");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRole, setMemberRole] = useState("operator");
  const [err, setErr] = useState("");

  async function addMember(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api(`/projects/${projectId}/members`, { method: "POST",
        body: JSON.stringify({ email: memberEmail, role: memberRole }) });
      setMemberEmail(""); load();
    } catch (e) { setErr(String(e)); }
  }
  async function removeMember(uid: string) {
    try { await api(`/projects/${projectId}/members/${uid}`, { method: "DELETE" }); load(); }
    catch (e) { setErr(String(e)); }
  }

  async function load() {
    try {
      setScope((await api<{ scope: ScopeT[] }>(`/projects/${projectId}/scope`)).scope);
      setRuns((await api<{ runs: RunT[] }>(`/projects/${projectId}/runs`)).runs);
      setActivity((await api<{ activity: ActT[] }>(`/projects/${projectId}/activity`)).activity ?? []);
      setMembers((await api<{ members: MemberT[] }>(`/projects/${projectId}/members`)).members ?? []);
    } catch (e) { setErr(String(e)); }
  }
  useEffect(() => { load(); }, [projectId]);

  async function addScope(e: React.FormEvent) {
    e.preventDefault();
    try { await api(`/projects/${projectId}/scope`, { method: "POST", body: JSON.stringify({ target }) }); setTarget(""); load(); }
    catch (e) { setErr(String(e)); }
  }

  async function del() {
    if (!confirm("Delete this project? This removes all its runs, findings, and on-disk recon data.")) return;
    try { await api(`/projects/${projectId}`, { method: "DELETE" }); nav("/projects"); }
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

      <div className="card" style={{ marginTop: 12 }}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h3 style={{ margin: 0 }}>Runs</h3>
          <Link className="btn" to={`/projects/${projectId}/report`}>Report &amp; outputs ▸</Link>
        </div>
        {runs.length === 0 ? (
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>No runs yet — start one above.</p>
        ) : (
          <ul className="list" style={{ marginTop: 10 }}>
            {runs.map((r) => (
              <li key={r.id} className="row" style={{ justifyContent: "space-between" }}>
                <span className="row" style={{ gap: 8 }}>
                  <span className={`pill st-${r.state}`}>{r.state}</span>
                  <span className="pill">{r.kind}</span>
                  <span className="mono">{r.target}</span>
                </span>
                <Link className="btn" to={`/projects/${projectId}/runs/${r.id}`}>Open map ▸</Link>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <h3>Team</h3>
        <form onSubmit={addMember} className="row" style={{ marginBottom: 10 }}>
          <input className="input" style={{ flex: 1 }} placeholder="teammate email"
                 value={memberEmail} onChange={(e) => setMemberEmail(e.target.value)} />
          <select className="select" value={memberRole} onChange={(e) => setMemberRole(e.target.value)}>
            <option value="operator">operator</option>
            <option value="viewer">viewer</option>
            <option value="owner">owner</option>
          </select>
          <button className="btn" type="submit">Add member</button>
        </form>
        <ul className="list">
          {members.map((m) => (
            <li key={m.user_id} className="row" style={{ justifyContent: "space-between" }}>
              <span className="row" style={{ gap: 8 }}>
                <span className="pill">{m.role}</span>
                <span className="mono" style={{ fontSize: 12 }}>{m.email ?? m.user_id.slice(0, 8)}</span>
              </span>
              {m.role !== "owner" && (
                <button className="btn" style={{ borderColor: "var(--red)", color: "var(--red)" }}
                        onClick={() => removeMember(m.user_id)}>Remove</button>
              )}
            </li>
          ))}
        </ul>
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <h3>Activity</h3>
        {activity.length === 0 ? (
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>No activity recorded yet.</p>
        ) : (
          <ul className="list" style={{ marginTop: 4 }}>
            {activity.slice(0, 12).map((a, i) => (
              <li key={i} className="row" style={{ gap: 8, fontFamily: "var(--mono)", fontSize: 12 }}>
                <span className="muted" style={{ minWidth: 128 }}>{a.ts ? new Date(a.ts).toLocaleString() : ""}</span>
                <span className={"pill " + (a.result === "denied" ? "st-failed" : "")}>{a.action}</span>
                <span className="muted">{a.actor_user_id ? a.actor_user_id.slice(0, 8) : "—"}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div style={{ marginTop: 16 }}>
        <button className="btn" style={{ borderColor: "var(--red)", color: "var(--red)" }} onClick={del}>
          Delete project
        </button>
      </div>
    </div>
  );
}
