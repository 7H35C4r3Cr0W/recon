import { useEffect, useState } from "react";
import { api } from "../api/client";

interface Cfg {
  source: string; saved: boolean; configured: boolean; provider: string; base_url: string;
  model: string; organization: string; has_api_key: boolean; temperature: number;
  max_output_tokens: number; context_window: number; timeout_read_s: number; tls_verify: boolean;
  env_prefix: string; required_env: string[];
}
interface TestResult {
  ok: boolean; configured: boolean; latency_ms?: number; model?: string; finish_reason?: string;
  content?: string; error?: string;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number; estimated: boolean };
}

type Form = {
  base_url: string; model: string; api_key: string; organization: string; provider: string;
  temperature: number; max_output_tokens: number; context_window: number; timeout_read_s: number; tls_verify: boolean;
};
const blankForm = (c?: Cfg | null): Form => ({
  base_url: c?.base_url ?? "", model: c?.model ?? "gpt-5.1", api_key: "", organization: c?.organization ?? "",
  provider: c?.provider ?? "openai_compatible", temperature: c?.temperature ?? 0.2,
  max_output_tokens: c?.max_output_tokens ?? 4096, context_window: c?.context_window ?? 128000,
  timeout_read_s: c?.timeout_read_s ?? 120, tls_verify: c?.tls_verify ?? true,
});

const STEPS = [
  ["Get your endpoint", "From whoever runs the internal model, get its OpenAI-compatible base URL (ends in /v1), an API key, and the model id."],
  ["Enter it below", "Paste the Base URL, Model, and API key. TLS/timeouts have sane defaults under Advanced."],
  ["Test the connection", "Hit Test — it sends one tiny prompt and reports latency + token usage, so you know it works before committing."],
  ["Save & attach", "Save applies it immediately — agent runs pick it up on their next run. No restart, no editing files."],
];

export function LlmSetup() {
  const [cfg, setCfg] = useState<Cfg | null>(null);
  const [form, setForm] = useState<Form>(blankForm());
  const [adv, setAdv] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<TestResult | null>(null);

  async function load() {
    try { const c = await api<Cfg>("/admin/llm/config"); setCfg(c); setForm(blankForm(c)); }
    catch (e) { setErr(String(e)); }
  }
  useEffect(() => { load(); }, []);

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));

  async function testFire() {
    setTesting(true); setResult(null); setErr(""); setMsg("");
    try {
      setResult(await api<TestResult>("/admin/llm/test", { method: "POST", body: JSON.stringify({
        prompt: "Reply with the single word: OK",
        base_url: form.base_url || undefined, api_key: form.api_key || undefined,
        model: form.model || undefined, organization: form.organization || undefined, tls_verify: form.tls_verify,
      }) }));
    } catch (e) { setResult({ ok: false, configured: true, error: String(e) }); }
    finally { setTesting(false); }
  }

  async function save() {
    setBusy(true); setErr(""); setMsg("");
    try {
      await api("/admin/llm/config", { method: "PUT", body: JSON.stringify({
        base_url: form.base_url, model: form.model, api_key: form.api_key || null,
        organization: form.organization, provider: form.provider, temperature: form.temperature,
        max_output_tokens: form.max_output_tokens, context_window: form.context_window,
        timeout_read_s: form.timeout_read_s, tls_verify: form.tls_verify,
      }) });
      setMsg("Saved — the brain is attached. Agent runs will use it on their next run.");
      await load();
    } catch (e) { setErr(String(e)); } finally { setBusy(false); }
  }

  async function clearSaved() {
    setBusy(true); setErr(""); setMsg("");
    try { await api("/admin/llm/config", { method: "DELETE" }); setMsg("Cleared — reverted to the environment config."); await load(); }
    catch (e) { setErr(String(e)); } finally { setBusy(false); }
  }

  const pill = (ok: boolean, on: string, off: string) => (
    <span className="pill" style={{ color: ok ? "var(--accent-2)" : "var(--gold)",
      borderColor: ok ? "var(--accent-2)" : "var(--gold)" }}>{ok ? on : off}</span>
  );
  const src = cfg?.source === "saved" ? "saved in the UI" : cfg?.source === "env" ? "from environment" : "not configured";

  return (
    <div style={{ maxWidth: 780 }}>
      <h1 className="pt">Connect the LLM brain</h1>
      <p className="psub">Attach your internal OpenAI-compatible model from here — no editing files, no
        restart. Test it first, then save. Admin only.</p>
      {err && <p className="err">{err}</p>}
      {msg && <p style={{ color: "var(--accent-2)", fontSize: 13 }}>{msg}</p>}

      {/* status */}
      <div className="card" style={{ marginBottom: 14 }}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h3 style={{ margin: 0 }}>Current status</h3>
          <span className="row" style={{ gap: 8 }}>
            {cfg && pill(cfg.configured, "configured", "not set")}
            {cfg && pill(cfg.has_api_key, "key set", "no key")}
            {cfg && <span className="pill" style={{ color: "var(--ink-2)" }}>{src}</span>}
          </span>
        </div>
        {cfg && (
          <div className="mono" style={{ fontSize: 12.5, color: "var(--ink-2)", marginTop: 8 }}>
            {cfg.base_url || "—"} · {cfg.model}
          </div>
        )}
      </div>

      {/* steps */}
      <div className="card" style={{ marginBottom: 14 }}>
        <h3>How to attach it</h3>
        <ol style={{ margin: "6px 0 0", paddingLeft: 18 }}>
          {STEPS.map(([t, d]) => (
            <li key={t} className="ink2" style={{ marginBottom: 6 }}>
              <b style={{ color: "var(--ink)" }}>{t}.</b> {d}
            </li>
          ))}
        </ol>
      </div>

      {/* form */}
      <div className="card" style={{ marginBottom: 14 }}>
        <h3>Connection</h3>
        <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 10, marginTop: 8 }}>
          <label className="fld"><span>Base URL <span className="req">required</span></span>
            <input className="input" placeholder="https://llm.internal.corp/v1" value={form.base_url}
              onChange={(e) => set("base_url", e.target.value)} /></label>
          <div className="row" style={{ gap: 10 }}>
            <label className="fld" style={{ flex: 1 }}><span>Model</span>
              <input className="input" placeholder="gpt-5.1" value={form.model}
                onChange={(e) => set("model", e.target.value)} /></label>
            <label className="fld" style={{ flex: 1 }}><span>Organization <span className="opt">optional</span></span>
              <input className="input" placeholder="(none)" value={form.organization}
                onChange={(e) => set("organization", e.target.value)} /></label>
          </div>
          <label className="fld"><span>API key {cfg?.has_api_key && <span className="opt">leave blank to keep current</span>}</span>
            <input className="input" type="password" autoComplete="new-password"
              placeholder={cfg?.has_api_key ? "•••••••• (unchanged)" : "sk-…"} value={form.api_key}
              onChange={(e) => set("api_key", e.target.value)} /></label>

          <button className="linkish" onClick={() => setAdv((v) => !v)}>{adv ? "▾ hide advanced" : "▸ advanced (TLS, timeouts, sizes)"}</button>
          {adv && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <label className="fld"><span>Temperature</span><input className="input" type="number" step="0.1"
                value={form.temperature} onChange={(e) => set("temperature", Number(e.target.value))} /></label>
              <label className="fld"><span>Max output tokens</span><input className="input" type="number"
                value={form.max_output_tokens} onChange={(e) => set("max_output_tokens", Number(e.target.value))} /></label>
              <label className="fld"><span>Context window</span><input className="input" type="number"
                value={form.context_window} onChange={(e) => set("context_window", Number(e.target.value))} /></label>
              <label className="fld"><span>Read timeout (s)</span><input className="input" type="number"
                value={form.timeout_read_s} onChange={(e) => set("timeout_read_s", Number(e.target.value))} /></label>
              <label className="row" style={{ gap: 8, gridColumn: "1 / -1", fontSize: 13, color: "var(--ink-2)" }}>
                <input type="checkbox" checked={form.tls_verify} onChange={(e) => set("tls_verify", e.target.checked)} />
                Verify TLS (uncheck only for an internal self-signed endpoint)</label>
            </div>
          )}
        </div>

        <div className="row" style={{ gap: 10, marginTop: 14, flexWrap: "wrap" }}>
          <button className="btn" disabled={testing || !form.base_url} onClick={testFire}>
            {testing ? "Testing…" : "Test connection"}</button>
          <button className="btn primary" disabled={busy || !form.base_url} onClick={save}>
            {busy ? "Saving…" : "Save & attach"}</button>
          {cfg?.saved && <button className="btn" disabled={busy} onClick={clearSaved}>Clear saved config</button>}
        </div>
      </div>

      {/* test result */}
      {result && (
        <div className="card" style={{ marginBottom: 14, borderColor: result.ok ? "var(--accent-2)" : "var(--red)" }}>
          <h3>{result.ok ? "✓ Connection OK" : "✗ Test failed"}</h3>
          {result.ok ? (
            <div className="mono" style={{ fontSize: 12.5, color: "var(--ink-2)", display: "grid",
              gridTemplateColumns: "140px 1fr", gap: "4px 12px" }}>
              <span className="muted">latency</span><span>{result.latency_ms} ms</span>
              <span className="muted">model</span><span>{result.model}</span>
              <span className="muted">tokens</span><span>prompt {result.usage?.prompt_tokens} · completion {result.usage?.completion_tokens} · total {result.usage?.total_tokens}{result.usage?.estimated ? " (estimated)" : ""}</span>
              <span className="muted">reply</span><span>{result.content}</span>
            </div>
          ) : <p className="err" style={{ margin: 0 }}>{result.error}</p>}
        </div>
      )}

      {/* env alternative */}
      <details className="card">
        <summary style={{ cursor: "pointer", color: "var(--ink-2)" }}>Prefer environment variables? (alternative)</summary>
        <p className="ink2" style={{ fontSize: 13, marginTop: 8 }}>You can also set these on the api + worker
          services (then restart). The UI config above takes precedence when saved.</p>
        <pre className="mono" style={{ fontSize: 12, background: "var(--sunk)", border: "1px solid var(--line)",
          borderRadius: 8, padding: 12, overflowX: "auto" }}>{`NABU_LLM_BASE_URL=https://llm.internal.corp/v1
NABU_LLM_API_KEY=sk-…
NABU_LLM_MODEL=gpt-5.1`}</pre>
      </details>
    </div>
  );
}
