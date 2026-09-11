// The human-gated spray/exploit panel (Phase A). An operator PROPOSES an executable catalog action;
// a human APPROVES it behind the double gate (platform switch + per-project toggle + this approval,
// plus an exploit confirmation / a chosen credential). Approval runs it through the one gated door.
// Danger-styled on purpose: recon is calm teal; the attack path is amber→red and un-missable.
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client";

interface Action { id: string; title: string; category: string; command: string; unfilled: string[]; tool: string; runs_on: string; executable: boolean; }
interface ServiceCat { service: string; label: string; actions: Action[]; }
interface Cred { id: string; username: string; secret_type: string; domain: string; }
interface Gate { platform_enabled: boolean; project_enabled: boolean; needs_exploit_confirm: boolean; needs_credential: boolean; }
interface Checkpoint {
  id: string; kind: string; status: string; target: string; action_id: string;
  service?: string; command?: string | null; credential_ref?: string | null; gate?: Gate;
}

const ACTIVE = new Set(["proposed", "executing"]);
// display-only kind inference (the backend enforces the real gate regardless)
const kindOf = (a: Action) => /spray|password|brute|kerbero|as-?rep|credential/i.test(`${a.category} ${a.title} ${a.tool}`) ? "spray" : "exploit";

export function AttackGate({ projectId }: { projectId: string }) {
  const [target, setTarget] = useState("");
  const [runId, setRunId] = useState<string | null>(null);
  const [services, setServices] = useState<ServiceCat[]>([]);
  const [creds, setCreds] = useState<Cred[]>([]);
  const [cps, setCps] = useState<Checkpoint[]>([]);
  const [confirm, setConfirm] = useState<Record<string, boolean>>({});
  const [chosenCred, setChosenCred] = useState<Record<string, string>>({});
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const runRef = useRef<string | null>(null);

  const loadCheckpoints = useCallback(async (rid: string) => {
    const r = await api<{ checkpoints: Checkpoint[] }>(`/runs/${rid}/checkpoints`).catch(() => ({ checkpoints: [] }));
    setCps((r.checkpoints || []).filter((c) => c.kind === "spray" || c.kind === "exploit"));
  }, []);

  const load = useCallback(async () => {
    const scope = await api<{ scope: { target: string; is_entry?: boolean }[] }>(`/projects/${projectId}/scope`).catch(() => ({ scope: [] }));
    const entry = (scope.scope || []).find((s) => s.is_entry) || (scope.scope || [])[0];
    setTarget(entry?.target || "");
    const runs = await api<{ runs: { id: string }[] }>(`/projects/${projectId}/runs`).catch(() => ({ runs: [] }));
    const rid = (runs.runs || [])[0]?.id || null;   // newest run (list is newest-first)
    runRef.current = rid; setRunId(rid);
    const cat = await api<{ services: ServiceCat[] }>(`/projects/${projectId}/catalog`).catch(() => ({ services: [] }));
    setServices(cat.services || []);
    const cr = await api<{ credentials: Cred[] }>(`/projects/${projectId}/credentials`).catch(() => ({ credentials: [] }));
    setCreds(cr.credentials || []);
    if (rid) await loadCheckpoints(rid);
  }, [projectId, loadCheckpoints]);

  useEffect(() => { load(); }, [load]);

  // live-poll while any proposal is still proposed/executing
  useEffect(() => {
    if (!runId || !cps.some((c) => ACTIVE.has(c.status))) return;
    const t = setInterval(() => { if (runRef.current) loadCheckpoints(runRef.current); }, 1800);
    return () => clearInterval(t);
  }, [runId, cps, loadCheckpoints]);

  async function propose(service: string, a: Action) {
    if (!runId) return;
    setErr(""); setBusy(true);
    try {
      await api(`/runs/${runId}/attack-proposals`, {
        method: "POST",
        body: JSON.stringify({ kind: kindOf(a), target, service, action_id: a.id }),
      });
      await loadCheckpoints(runId);
    } catch (e) { setErr(String(e)); } finally { setBusy(false); }
  }

  async function decide(cp: Checkpoint, action: "approve" | "reject") {
    if (!runId) return;
    setErr(""); setBusy(true);
    try {
      const body = action === "approve"
        ? JSON.stringify({ exploit_confirmed: !!confirm[cp.id], credential_ref: chosenCred[cp.id] || cp.credential_ref || null })
        : undefined;
      await api(`/runs/${runId}/checkpoints/${cp.id}/${action}`, { method: "POST", body });
      await loadCheckpoints(runId);
    } catch (e) { setErr(String(e)); } finally { setBusy(false); }
  }

  const runnable = services.flatMap((s) => s.actions.filter((a) => a.executable && (a.unfilled?.length ?? 0) === 0).map((a) => ({ s, a })));

  function canApprove(cp: Checkpoint): boolean {
    const g = cp.gate;
    if (!g || !g.platform_enabled || !g.project_enabled) return false;
    if (g.needs_exploit_confirm && !confirm[cp.id]) return false;
    if (g.needs_credential && !(chosenCred[cp.id] || cp.credential_ref)) return false;
    return true;
  }

  return (
    <div>
      <p className="atk-note">
        Recon is automated; <b>attacks never are</b>. Propose an action below, then a human approves it
        behind the double gate before it runs through the single gated executor.
        {runId ? <> <span className="atk-run">· attached to the latest run</span></> : null}
      </p>
      {err && <p className="err">{err}</p>}

      {!runId && <p className="muted" style={{ fontSize: 13 }}>Run recon on an in-scope target first — then runnable actions appear here.</p>}

      {runId && (
        <>
          {/* proposals awaiting a decision / running / done */}
          {cps.length > 0 && (
            <>
              <div className="atk-sub">gated proposals</div>
              <div className="atk-grid">
                {cps.map((cp) => {
                  const g = cp.gate;
                  const proposed = cp.status === "proposed";
                  return (
                    <div key={cp.id} className="atk-row danger">
                      <div className="atk-top">
                        <span className="row" style={{ gap: 9 }}>
                          <span className={`atk-kind ${cp.kind}`}>{cp.kind}</span>
                          <span className="mono" style={{ fontSize: 12 }}>{cp.target}</span>
                          <span className="muted mono" style={{ fontSize: 11 }}>{cp.action_id}</span>
                        </span>
                        <span className={`atk-status ${cp.status}`}>{cp.status}</span>
                      </div>
                      {cp.command && <div className="atk-cmd">{cp.command}</div>}
                      {g && (
                        <div className="atk-gatebar">
                          <span className={`g ${g.platform_enabled ? "on" : "off"}`}><span className="lamp" />platform {g.platform_enabled ? "on" : "off"}</span>
                          <span className={`g ${g.project_enabled ? "on" : "off"}`}><span className="lamp" />project {g.project_enabled ? "on" : "off"}</span>
                        </div>
                      )}
                      {proposed && (
                        <div className="atk-controls">
                          {g?.needs_exploit_confirm && (
                            <label><input type="checkbox" checked={!!confirm[cp.id]}
                              onChange={(e) => setConfirm((m) => ({ ...m, [cp.id]: e.target.checked }))} />
                              I confirm this exploit against {cp.target}</label>
                          )}
                          {g?.needs_credential && (
                            <label>credential
                              <select className="select" value={chosenCred[cp.id] || ""}
                                onChange={(e) => setChosenCred((m) => ({ ...m, [cp.id]: e.target.value }))}>
                                <option value="">choose…</option>
                                {creds.map((c) => <option key={c.id} value={c.id}>{c.domain ? `${c.domain}\\` : ""}{c.username} ({c.secret_type})</option>)}
                              </select>
                            </label>
                          )}
                          <button className="btn-danger" disabled={busy || !canApprove(cp)} onClick={() => decide(cp, "approve")}>Approve &amp; run</button>
                          <button className="btn" disabled={busy} onClick={() => decide(cp, "reject")}>Reject</button>
                          {g && (!g.platform_enabled || !g.project_enabled) && (
                            <span className="muted" style={{ fontSize: 11 }}>
                              {!g.platform_enabled ? "disabled platform-wide · " : ""}
                              {!g.project_enabled ? "enable in project Settings" : ""}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </>
          )}

          {/* the catalog of runnable actions to propose */}
          <div className="atk-sub">runnable actions {target && <span className="atk-run">· {target}</span>}</div>
          {runnable.length === 0 ? (
            <p className="muted" style={{ fontSize: 13 }}>No runnable actions for the discovered services yet.</p>
          ) : (
            <div className="atk-grid">
              {runnable.map(({ s, a }) => (
                <div key={`${s.service}:${a.id}`} className="atk-row">
                  <div className="atk-top">
                    <span className="atk-title">{a.title}</span>
                    <span className="row" style={{ gap: 8 }}>
                      <span className={`atk-kind ${kindOf(a)}`}>{kindOf(a)}</span>
                      <button className="btn" disabled={busy} onClick={() => propose(s.service, a)}>Propose</button>
                    </span>
                  </div>
                  <div className="atk-cmd">{a.command}</div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
