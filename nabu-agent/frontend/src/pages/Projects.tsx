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
    <main style={{ fontFamily: "system-ui", padding: 24, maxWidth: 720, margin: "0 auto" }}>
      <h1>Projects</h1>
      <form onSubmit={create} style={{ display: "flex", gap: 8, margin: "12px 0" }}>
        <input placeholder="New engagement name" value={name} onChange={(e) => setName(e.target.value)} style={{ flex: 1, padding: 8 }} />
        <button type="submit">Create</button>
      </form>
      {err && <p style={{ color: "crimson" }}>{err}</p>}
      <ul style={{ listStyle: "none", padding: 0 }}>
        {projects.map((p) => (
          <li key={p.id} style={{ padding: "10px 12px", border: "1px solid #ddd", borderRadius: 8, marginBottom: 8 }}>
            <Link to={`/projects/${p.id}`}><b>{p.display_name}</b></Link> <span style={{ color: "#888" }}>· {p.status}</span>
          </li>
        ))}
      </ul>
    </main>
  );
}
