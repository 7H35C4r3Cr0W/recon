import { useEffect, useState } from "react";
import { api } from "../api/client";

interface U {
  id: string; email: string; display_name: string; role: string;
  auth_source: string; is_active: boolean;
}

export function Users() {
  const [users, setUsers] = useState<U[]>([]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("operator");
  const [err, setErr] = useState("");

  async function load() {
    try { setUsers((await api<{ users: U[] }>("/users")).users); }
    catch (e) { setErr(String(e)); }
  }
  useEffect(() => { load(); }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    try {
      await api("/users", { method: "POST", body: JSON.stringify({ email, password, role }) });
      setEmail(""); setPassword(""); load();
    } catch (e) { setErr(String(e)); }
  }
  async function setActive(id: string, is_active: boolean) {
    try {
      if (is_active) await api(`/users/${id}`, { method: "PATCH", body: JSON.stringify({ is_active: true }) });
      else await api(`/users/${id}`, { method: "DELETE" });
      load();
    } catch (e) { setErr(String(e)); }
  }
  async function setRoleFor(id: string, r: string) {
    try { await api(`/users/${id}`, { method: "PATCH", body: JSON.stringify({ role: r }) }); load(); }
    catch (e) { setErr(String(e)); }
  }

  return (
    <div style={{ maxWidth: 760 }}>
      <h1 className="pt">Users</h1>
      <p className="psub">Create login accounts and set global roles · admin only</p>
      {err && <p className="err">{err}</p>}

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Add a user</h3>
        <form onSubmit={create} className="row" style={{ flexWrap: "wrap" }}>
          <input className="input" style={{ flex: 2, minWidth: 180 }} placeholder="email"
                 value={email} onChange={(e) => setEmail(e.target.value)} />
          <input className="input" style={{ flex: 1, minWidth: 120 }} type="password" placeholder="temp password"
                 value={password} onChange={(e) => setPassword(e.target.value)} />
          <select className="select" value={role} onChange={(e) => setRole(e.target.value)}>
            {["operator", "viewer", "admin"].map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <button className="btn btn-primary" type="submit">Create</button>
        </form>
      </div>

      <div className="card">
        <h3>Accounts ({users.length})</h3>
        <ul className="list">
          {users.map((u) => (
            <li key={u.id} className="row" style={{ justifyContent: "space-between", opacity: u.is_active ? 1 : 0.5 }}>
              <span className="row" style={{ gap: 8 }}>
                <span className="mono" style={{ fontSize: 12 }}>{u.email}</span>
                <span className="pill">{u.auth_source}</span>
                {!u.is_active && <span className="pill st-failed">disabled</span>}
              </span>
              <span className="row" style={{ gap: 8 }}>
                <select className="select" value={u.role} onChange={(e) => setRoleFor(u.id, e.target.value)}>
                  {["operator", "viewer", "admin"].map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
                <button className="btn" onClick={() => setActive(u.id, !u.is_active)}>
                  {u.is_active ? "Disable" : "Enable"}
                </button>
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
