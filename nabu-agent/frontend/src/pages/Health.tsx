import { useEffect, useState } from "react";
import { api } from "../api/client";

// Real page: pings readiness so a fresh deploy is verifiable from the browser.
export function Health() {
  const [state, setState] = useState<{ ready?: boolean; checks?: Record<string, boolean>; error?: string }>({});
  useEffect(() => {
    api<{ ready: boolean; checks: Record<string, boolean> }>("/health/ready")
      .then(setState)
      .catch((e) => setState({ error: String(e) }));
  }, []);
  return (
    <main style={{ fontFamily: "system-ui", padding: 24 }}>
      <h1>Nabu Agent — readiness</h1>
      {state.error && <p style={{ color: "crimson" }}>{state.error}</p>}
      {state.checks && (
        <ul>
          {Object.entries(state.checks).map(([k, v]) => (
            <li key={k}>{v ? "✅" : "❌"} {k}</li>
          ))}
        </ul>
      )}
      <p>{state.ready === undefined ? "checking…" : state.ready ? "ready" : "not ready"}</p>
    </main>
  );
}
