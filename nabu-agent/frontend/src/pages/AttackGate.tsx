// The human-gated spray/exploit panel (Phase A + C). An operator PROPOSES an executable catalog
// action — filling its placeholders from a chosen vault credential and/or operator params — then a
// human APPROVES it behind the double gate (platform switch + per-project toggle + this approval,
// plus an exploit confirmation). Approval runs it through the one gated door. Danger-styled on
// purpose: recon is calm teal; the attack path is amber→red and un-missable.
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
// placeholders a credential fills; everything else is an operator param
const CRED_PH = new Set(["user", "username", "password", "pass", "hash", "ntlm", "nthash", "domain", "secret"]);
// display-only kind inference (the backend enforces the real gate regardless)
const kindOf = (a: Action) => /spray|password|brute|kerbero|as-?rep|credential/i.test(`${a.category} ${a.title} ${a.tool}`) ? "spray" : "exploit";

export function AttackGate({ projectId }: { projectId: string }) {
  const [target, setTarget] = useState("");
  const [runId, setRunId] = useState<string | null>(null);
  const [services, setServices] = useState<ServiceCat[]>([]);
  const [creds, setCreds] = useState<Cred[]>([]);
  const [cps, setCps] = useState<Checkpoint[]>([]);
  const [confirm, setConfirm] = useState<Record<string, boolean>>({});
  const [proposeCred, setProposeCred] = useState<Record<string, string>>({});
  const [params, setParams] = useState<Record<string, Record<string, string>>>({});
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
    const rid = (runs.runs || [])[0]?.id || null;
    runRef.current = rid; setRunId(rid);
    const cat = await api<{ services: ServiceCat[] }>(`/projects/${projectId}/catalog`).catch(() => ({ services: [] }));
    setServices(cat.services || []);
    const cr = await api<{ credentials: Cred[] }>(`/projects/${projectId}/credentials`).catch(() => ({ credentials: [] }));
    setCreds(cr.credentials || []);
    if (rid) await loadCheckpoints(rid);
  }, [projectId, loadCheckpoints]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!runId || !cps.some((c) => ACTIVE.has(c.status))) return;
    const t = setInterval(() => { if (runRef.current) loadCheckpoints(runRef.current); }, 1800);
    return () => clearInterval(t);
  }, [runId, cps, loadCheckpoints]);

  async function propose(service: string, a: Action, key: string) {
    if (!runId) return;
    setErr(""); setBusy(true);
    try {
      const pn = (a.unfilled || []).filter((p) => !CRED_PH.has(p));
      const body = {
        kind: kindOf(a), target, service, action_id: a.id,
        credential_ref: proposeCred[key] || null,
        params: Object.fromEntries(pn.map((p) => [p, params[key]?.[p] || ""])),
      };
      await api(`/runs/${runId}/attack-proposals`, { method: "POST", body: JSON.stringify(body) });
      await loadCheckpoints(runId);
    } catch (e) { setErr(String(e)); } finally { setBusy(false); }
  }

  async function decide(cp: Checkpoint, action: "approve" | "reject", dryRun = false) {
    if (!runId) return;
    setErr(""); setBusy(true);
    try {
      const body = action === "approve"
        ? JSON.stringify({ exploit_confirmed: !!confirm[cp.id], dry_run: dryRun }) : undefined;
      await api(`/runs/${runId}/checkpoints/${cp.id}/${action}`, { method: "POST", body });
      await loadCheckpoints(runId);
    } catch (e) { setErr(String(e)); } finally { setBusy(false); }
  }

  function canApprove(cp: Checkpoint): boolean {
    const g = cp.gate;
    if (!g || !g.platform_enabled || !g.project_enabled) return false;
    if (g.needs_exploit_confirm && !confirm[cp.id]) return false;
    return true;
  }

  const executable = services.flatMap((s) => s.actions.filter((a) => a.executable).map((a) => ({ s, a })));

  return (
    <div>
      <p className="atk-note">
        Recon is automated; <b>attacks never are</b>. Fill an action's inputs, propose it, then a human
        approves it behind the double gate before it runs through the single gated executor.
        {runId ? <> <span className="atk-run">· attached to the latest run</span></> : null}
      </p>
      {err && <p className="err">{err}</p>}
      {!runId && <p className="muted" style={{ fontSize: 13 }}>Run recon on an in-scope target first — then runnable actions appear here.</p>}

      {runId && (
        <>
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
                          <button className="btn-danger" disabled={busy || !canApprove(cp)} onClick={() => decide(cp, "approve")}>Approve &amp; run</button>
                          <button className="btn" disabled={busy || !canApprove(cp)} title="resolve + show the exact command without running it" onClick={() => decide(cp, "approve", true)}>Dry run</button>
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

          <div className="atk-sub">runnable actions {target && <span className="atk-run">· {target}</span>}</div>
          {executable.length === 0 ? (
            <p className="muted" style={{ fontSize: 13 }}>No runnable actions for the discovered services yet.</p>
          ) : (
            <div className="atk-grid">
              {executable.map(({ s, a }) => {
                const key = `${s.service}:${a.id}`;
                const needs = a.unfilled || [];
                const credNeeds = needs.filter((p) => CRED_PH.has(p));
                const paramNeeds = needs.filter((p) => !CRED_PH.has(p));
                const ready = paramNeeds.every((p) => (params[key]?.[p] || "").trim()) && (credNeeds.length === 0 || proposeCred[key]);
                return (
                  <div key={key} className="atk-row">
                    <div className="atk-top">
                      <span className="atk-title">{a.title}</span>
                      <span className="row" style={{ gap: 8 }}>
                        <span className={`atk-kind ${kindOf(a)}`}>{kindOf(a)}</span>
                        <button className="btn" disabled={busy || !ready} onClick={() => propose(s.service, a, key)}>Propose</button>
                      </span>
                    </div>
                    <div className="atk-cmd">{a.command}</div>
                    {(credNeeds.length > 0 || paramNeeds.length > 0) && (
                      <div className="atk-controls">
                        {credNeeds.length > 0 && (
                          <label>credential
                            <select className="select" value={proposeCred[key] || ""}
                              onChange={(e) => setProposeCred((m) => ({ ...m, [key]: e.target.value }))}>
                              <option value="">choose…</option>
                              {creds.map((c) => <option key={c.id} value={c.id}>{c.domain ? `${c.domain}\\` : ""}{c.username} ({c.secret_type})</option>)}
                            </select>
                          </label>
                        )}
                        {paramNeeds.map((p) => (
                          <label key={p} className="mono" style={{ fontSize: 11 }}>{p}
                            <input className="input" style={{ width: 130, marginLeft: 6 }} value={params[key]?.[p] || ""}
                              onChange={(e) => setParams((m) => ({ ...m, [key]: { ...(m[key] || {}), [p]: e.target.value } }))} />
                          </label>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}
    </div>
  );
}
