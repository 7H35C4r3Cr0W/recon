import { useEffect, useState } from "react";
import { api } from "../api/client";

export function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");
  const [oidc, setOidc] = useState(false);
  useEffect(() => { api<{ oidc: boolean }>("/auth/providers").then((p) => setOidc(p.oidc)).catch(() => {}); }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
      location.assign("/");
    } catch (err) {
      setMsg(String(err));
    }
  }
  return (
    <div className="centerpane">
      <div className="brand" style={{ fontSize: 20, marginBottom: 18 }}><span className="dot" /> NABU·AGENT</div>
      <div className="card">
        <h3>Sign in</h3>
        <form onSubmit={submit} className="stack">
          <input className="input" placeholder="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          <input className="input" placeholder="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <button className="btn btn-primary" type="submit">Sign in</button>
        </form>
        {oidc && (
          <p style={{ marginTop: 14 }}>
            <a href="/api/auth/oidc/login"><button type="button" className="btn" style={{ width: "100%" }}>Sign in with SSO</button></a>
          </p>
        )}
        {msg && <p className="err">{msg}</p>}
      </div>
    </div>
  );
}
