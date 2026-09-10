import { useEffect, useState } from "react";
import { api } from "../api/client";

interface Cfg {
  provider: string; configured: boolean; base_url: string; model: string;
  organization: string | null; has_api_key: boolean; temperature: number;
  max_output_tokens: number; context_window: number; timeout_read_s: number;
  tls_verify: boolean; env_prefix: string; required_env: string[];
}
interface TestResult {
  ok: boolean; configured: boolean; latency_ms?: number; model?: string; finish_reason?: string;
  content?: string; error?: string;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number; estimated: boolean };
}

const ENV_EXAMPLE = `# api + worker service environment (docker-compose.yml or .env)
NABU_LLM_BASE_URL=https://llm.internal.corp/v1     # your OpenAI-compatible endpoint (required)
NABU_LLM_API_KEY=sk-…                               # kept as a secret; never logged or returned
NABU_LLM_MODEL=gpt-5.1                              # the model id to call
# optional:
# NABU_LLM_ORGANIZATION=…      NABU_LLM_TEMPERATURE=0.2      NABU_LLM_MAX_OUTPUT_TOKENS=4096
# NABU_LLM_TIMEOUT_READ_S=120  NABU_LLM_TLS_VERIFY=true      NABU_LLM_CA_BUNDLE=/etc/ssl/corp-ca.pem`;

export function LlmSetup() {
  const [cfg, setCfg] = useState<Cfg | null>(null);
  const [err, setErr] = useState("");
  const [prompt, setPrompt] = useState("Reply with the single word: OK");
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<TestResult | null>(null);

  useEffect(() => {
    api<Cfg>("/admin/llm/config").then(setCfg).catch((e) => setErr(String(e)));
  }, []);

  async function testFire() {
    setTesting(true); setResult(null);
    try { setResult(await api<TestResult>("/admin/llm/test", { method: "POST", body: JSON.stringify({ prompt }) })); }
    catch (e) { setResult({ ok: false, configured: true, error: String(e) }); }
    finally { setTesting(false); }
  }

  const badge = (ok: boolean, on: string, off: string) => (
    <span className="pill" style={{ color: ok ? "var(--accent-2)" : "var(--gold)",
      borderColor: ok ? "var(--accent-2)" : "var(--gold)" }}>{ok ? on : off}</span>
  );

  return (
    <div style={{ maxWidth: 760 }}>
      <h1 className="pt">Connect the LLM brain</h1>
      <p className="psub">Wire your internal OpenAI-compatible model, then test-fire it. Admin only.</p>
      {err && <p className="err">{err}</p>}

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Current status</h3>
        {!cfg ? <p className="muted">Loading…</p> : (
          <div style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: "6px 12px", fontFamily: "var(--mono)", fontSize: 13 }}>
            <span className="muted">endpoint</span><span>{badge(cfg.configured, "configured", "not set")} <span className="mono">{cfg.base_url || "—"}</span></span>
            <span className="muted">model</span><span className="mono">{cfg.model}</span>
            <span className="muted">api key</span><span>{badge(cfg.has_api_key, "set", "missing")}</span>
            <span className="muted">provider</span><span className="mono">{cfg.provider}</span>
            <span className="muted">read timeout</span><span className="mono">{cfg.timeout_read_s}s · TLS verify {String(cfg.tls_verify)}</span>
          </div>
        )}
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Setup — 3 steps</h3>
        <ol style={{ margin: 0, paddingLeft: 20, fontSize: 13, lineHeight: 1.7 }}>
          <li>Set the environment variables on the <b>api</b> and <b>worker</b> services (prefix <span className="mono">{cfg?.env_prefix ?? "NABU_LLM_"}</span>):
            <pre style={{ background: "var(--sunk)", border: "1px solid var(--line)", borderRadius: 8,
              padding: 12, overflowX: "auto", fontSize: 12, marginTop: 8 }}>{ENV_EXAMPLE}</pre>
            The endpoint must speak the OpenAI Chat Completions API (<span className="mono">POST {"{base_url}"}/chat/completions</span>).
          </li>
          <li>Restart the api + worker so they pick up the new environment.</li>
          <li>Click <b>Test connection</b> below — a green result with latency and token counts means agent runs are ready to go.</li>
        </ol>
      </div>

      <div className="card">
        <h3>Test connection</h3>
        <div className="row" style={{ marginBottom: 10 }}>
          <input className="input" style={{ flex: 1 }} value={prompt} onChange={(e) => setPrompt(e.target.value)} />
          <button className="btn btn-primary" onClick={testFire} disabled={testing}>
            {testing ? "Testing…" : "Test connection ▸"}
          </button>
        </div>
        {result && (
          <div style={{ border: "1px solid", borderColor: result.ok ? "var(--accent-2)" : "var(--red)",
            borderRadius: 10, padding: "12px 14px", background: "var(--sunk)" }}>
            <div style={{ fontFamily: "var(--mono)", fontWeight: 700, color: result.ok ? "var(--accent-2)" : "var(--red)" }}>
              {result.ok ? "✓ connection OK" : "✗ test failed"}
            </div>
            {result.ok ? (
              <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: "4px 12px",
                fontFamily: "var(--mono)", fontSize: 12.5, marginTop: 8 }}>
                <span className="muted">latency</span><span>{result.latency_ms} ms</span>
                <span className="muted">model</span><span>{result.model}</span>
                <span className="muted">tokens</span><span>
                  prompt {result.usage?.prompt_tokens} · completion {result.usage?.completion_tokens} ·
                  total {result.usage?.total_tokens}{result.usage?.estimated ? " (estimated)" : ""}
                </span>
                <span className="muted">finish</span><span>{result.finish_reason}</span>
                <span className="muted">reply</span><span style={{ wordBreak: "break-word" }}>{result.content}</span>
              </div>
            ) : (
              <p className="mono" style={{ fontSize: 12.5, color: "var(--ink-2)", margin: "8px 0 0" }}>{result.error}</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
