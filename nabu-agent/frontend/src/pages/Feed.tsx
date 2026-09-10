import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";

interface FeedItem {
  run_id: string; project_id: string; project: string; state: string; run_kind: string;
  target: string; findings: number; attention: boolean; live: boolean; ts: string | null;
}

// The front page: a live "what's happening" feed of the user's recent runs across projects.
export function Feed() {
  const [items, setItems] = useState<FeedItem[]>([]);
  const [err, setErr] = useState("");
  const nav = useNavigate();

  useEffect(() => {
    let live = true;
    const tick = () =>
      api<{ items: FeedItem[] }>("/feed").then((f) => live && setItems(f.items)).catch((e) => setErr(String(e)));
    tick();
    const id = setInterval(tick, 5000);
    return () => { live = false; clearInterval(id); };
  }, []);

  return (
    <div>
      <h1>Feed</h1>
      <p className="muted" style={{ marginTop: -8 }}>Live activity across your projects · refreshes automatically</p>
      {err && <p className="err">{err}</p>}
      {items.length === 0 && <p className="muted">No activity yet. Create a project and start a run.</p>}
      <ul className="list">
        {items.map((i) => (
          <li key={i.run_id}
              className={"feed-item " + (i.attention ? "attn" : i.live ? "live" : "")}
              style={{ cursor: "pointer" }}
              onClick={() => nav(`/projects/${i.project_id}/runs/${i.run_id}`)}>
            <span className={"pill st-" + i.state}>{i.state}</span>
            <span className="t">{i.project} · <span className="muted">{i.run_kind}</span> · {i.target}</span>
            {i.findings > 0 && <span className="pill">{i.findings} findings</span>}
            {i.attention && <span className="pill st-awaiting_approval">needs attention</span>}
            <span className="meta">{i.ts ? new Date(i.ts).toLocaleString() : ""}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
