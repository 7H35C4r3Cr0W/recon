import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";

interface Project { id: string; slug: string; display_name: string; status: string; }

export function Projects() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [name, setName] = useState("");
  const [err, setErr] = useState("");

  async function load() {
    try { setProjects((await api<{ projects: Project[] }>("/projects")).projects); }
    catch (e) { setErr(String(e)); }
  }
  useEffect(() => { load(); }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    try { await api("/projects", { method: "POST", body: JSON.stringify({ display_name: name }) }); setName(""); load(); }
    catch (e) { setErr(String(e)); }
  }

  return (
    <div>
      <h1>Projects</h1>
      <form onSubmit={create} className="row" style={{ marginBottom: 16, maxWidth: 520 }}>
        <input className="input" style={{ flex: 1 }} placeholder="New engagement name" value={name} onChange={(e) => setName(e.target.value)} />
        <button className="btn btn-primary" type="submit">Create</button>
      </form>
      {err && <p className="err">{err}</p>}
      <div className="grid">
        {projects.map((p) => (
          <Link key={p.id} to={`/projects/${p.id}`} className="card" style={{ display: "block" }}>
            <h3>{p.display_name}</h3>
            <span className="pill">{p.status}</span>
          </Link>
        ))}
      </div>
      {projects.length === 0 && <p className="muted">No projects yet — create one above.</p>}
    </div>
  );
}
