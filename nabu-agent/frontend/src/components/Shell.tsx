import { useEffect, useState } from "react";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api/client";

// The authenticated app layout: top bar (brand + user + logout) and a left nav (Feed / Projects /
// Help) with a live unread badge. Renders the active page in <Outlet/>.
export function Shell() {
  const loc = useLocation();
  const nav = useNavigate();
  const [email, setEmail] = useState<string>("");
  const [role, setRole] = useState<string>("");
  const [unread, setUnread] = useState(0);

  useEffect(() => {
    api<{ email: string; role: string }>("/auth/me")
      .then((u) => { setEmail(u.email); setRole(u.role); })
      .catch(() => nav("/login"));
  }, [nav]);

  useEffect(() => {
    let live = true;
    const tick = () =>
      api<{ unread_count: number }>("/feed").then((f) => live && setUnread(f.unread_count)).catch(() => {});
    tick();
    const id = setInterval(tick, 6000);
    return () => { live = false; clearInterval(id); };
  }, []);

  async function logout() {
    await api("/auth/logout", { method: "POST" }).catch(() => {});
    nav("/login");
  }

  const on = (p: string) => (p === "/" ? loc.pathname === "/" : loc.pathname.startsWith(p));
  return (
    <div className="shell">
      <div className="topbar">
        <div className="brand"><span className="dot" /> NABU·AGENT <small>recon platform</small></div>
        <div className="grow" />
        <div className="userbox"><span className="muted">{email}</span><button className="btn" onClick={logout}>Sign out</button></div>
      </div>
      <nav className="sidebar nav">
        <div className="navlabel">Workspace</div>
        <Link to="/" className={on("/") ? "on" : ""}>
          <span className="ic">◎</span> Feed {unread > 0 && <span className="badge">{unread}</span>}
        </Link>
        <Link to="/projects" className={on("/projects") ? "on" : ""}><span className="ic">▤</span> Projects</Link>
        <Link to="/help" className={on("/help") ? "on" : ""}><span className="ic">?</span> Help</Link>
        <Link to="/health" className={on("/health") ? "on" : ""}><span className="ic">✧</span> Health</Link>
        {role === "admin" && (
          <>
            <div className="navlabel">Admin</div>
            <Link to="/admin/llm" className={on("/admin/llm") ? "on" : ""}><span className="ic">⚡</span> LLM setup</Link>
          </>
        )}
        <div className="grow" />
        <div className="navlabel" style={{ opacity: .7 }}>v0.1 · dark</div>
      </nav>
      <div className="content"><Outlet /></div>
    </div>
  );
}
