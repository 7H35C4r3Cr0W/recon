// In-app help guide — easy to read, dark themed.
export function Help() {
  return (
    <div style={{ maxWidth: 820 }}>
      <h1>Help &amp; guide</h1>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>What is Nabu Agent?</h3>
        <p className="ink2">A team platform for authorized recon. You create a scoped engagement
        (project), point it at an IP or range, and a supervisor fans out a team of agents — one per
        service, plus research and a report writer — that enumerate the target and hand back a clean
        report with next steps. It's built on the classic Nabu recon engine; every tool runs through a
        single, allow-listed chokepoint.</p>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Getting started</h3>
        <ol className="ink2">
          <li>Sign in (local account or your org SSO).</li>
          <li><b>Projects → Create</b> a project.</li>
          <li>Open it and <b>add an authorized scope</b> target (an IP like <code>10.10.10.5</code> or a
          range like <code>10.10.10.0/24</code>). Runs are refused for anything outside scope.</li>
          <li><b>Start a run</b> and watch the live map + log.</li>
        </ol>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Run kinds</h3>
        <ul className="ink2">
          <li><b>demo</b> — an animated walkthrough; no tools or LLM needed. Great for a first look.</li>
          <li><b>scan</b> — real recon (nmap + per-service enumeration), no LLM.</li>
          <li><b>agent</b> — the LLM drives recon: a <b>planner</b>, one <b>enum agent per service</b>,
          <b> research agents</b>, and a <b>report writer</b>. Requires the LLM endpoint to be configured.</li>
        </ul>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>The live map colours</h3>
        <ul className="ink2">
          <li><span className="pill st-scanning">green</span> active — where the run is working now</li>
          <li><span className="pill st-done">teal</span> done — finished successfully</li>
          <li><span className="pill st-awaiting_approval">yellow</span> stuck — blocked or needs a human</li>
          <li><span className="pill st-failed">red</span> error — a step failed</li>
          <li><span className="pill st-queued">grey</span> queued — created, not started</li>
        </ul>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Attaching the LLM (admin)</h3>
        <p className="ink2">Point the platform at your internally-hosted, OpenAI-compatible endpoint via
        config: <code>NABU_LLM_BASE_URL</code>, <code>NABU_LLM_API_KEY</code>, <code>NABU_LLM_MODEL</code>.
        Then <b>agent</b> runs work. No code change — the provider is swappable.</p>
      </div>

      <div className="card">
        <h3>Safety</h3>
        <p className="ink2">Recon is automated; <b>attacks are never automatic</b>. Any spray/exploit is
        only ever proposed and must be approved by a human. Every target is checked against the project's
        authorized scope before anything runs, and every action is audited.</p>
      </div>
    </div>
  );
}
