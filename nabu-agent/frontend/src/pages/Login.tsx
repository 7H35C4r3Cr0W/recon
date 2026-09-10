import { useEffect, useState } from "react";
import { api } from "../api/client";

// MVP local login (Phase 2 wires the session cookie + OIDC button).
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
      location.assign("/projects");
    } catch (err) {
      setMsg(String(err));
    }
  }
  return (
    <main style={{ fontFamily: "system-ui", padding: 24, maxWidth: 360 }}>
      <h1>Nabu Agent</h1>
      <form onSubmit={submit}>
        <input placeholder="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <input placeholder="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit">Sign in</button>
      </form>
      {oidc && (
        <p style={{ marginTop: 16 }}>
          <a href="/api/auth/oidc/login"><button type="button">Sign in with SSO</button></a>
        </p>
      )}
      {msg && <p style={{ color: "crimson" }}>{msg}</p>}
    </main>
  );
}
