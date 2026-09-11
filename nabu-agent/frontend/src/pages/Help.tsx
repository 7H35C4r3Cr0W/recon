// In-app help guide — visual-first, dark hacker-artsy theme. Diagrams are plain HTML/CSS (no libs),
// theme-aware via the design tokens, and honour prefers-reduced-motion.
import type { ReactNode } from "react";

const A = () => <span className="farrow">→</span>;
const Ad = () => <span className="farrow danger">⇢</span>;

function Node({ cls = "", title, sub }: { cls?: string; title: ReactNode; sub?: ReactNode }) {
  return <div className={`fnode ${cls}`}><b>{title}</b>{sub && <small>{sub}</small>}</div>;
}

// colours mirror the live map (see legend below)
const C = { active: "var(--accent-2)", done: "var(--accent)", wait: "var(--gold)", err: "var(--red)", queued: "var(--grey)" };

// 1 — how a run flows (the agent chain), with the human-gated attack branch
function RunFlow() {
  return (
    <div className="diagram">
      <div className="diagram-cap">how a run flows</div>
      <div className="flow">
        <Node cls="accent" title="Scope" sub="IP or CIDR you own" />
        <A />
        <Node cls="accent" title="Supervisor" sub="plans + fans out" />
        <A />
        <div className="fstack">
          <span className="lbl">per host — a team of agents</span>
          <Node title="Enum agent × service" sub="one per open port" />
          <Node title="Research" sub="context + CVEs" />
          <Node title="Report writer" sub="drafts findings" />
        </div>
        <A />
        <Node cls="accent" title="Report" sub="findings + next steps" />
      </div>
      <div className="flow" style={{ marginTop: 16 }}>
        <Node title="A service finding" sub="e.g. SMB signing off" />
        <Ad />
        <Node cls="danger" title="⚠ Attack proposed" sub="spray / exploit — never auto-run" />
        <Ad />
        <Node cls="gate" title="🔒 Human approval" sub="toggle ON + a person confirms" />
        <Ad />
        <Node cls="danger" title="Runs via the one door" sub="the sole gated executor" />
      </div>
    </div>
  );
}

// 2 — the run lifecycle
function Lifecycle() {
  const steps: [string, string][] = [
    ["Queued", C.queued], ["Scanning", C.active], ["Awaiting approval", C.wait],
    ["Executing approved", C.active], ["Report ready", C.done],
  ];
  return (
    <div className="diagram">
      <div className="diagram-cap">anatomy of a run</div>
      <div className="life">
        {steps.map(([label, color], i) => (
          <span key={label} style={{ display: "contents" }}>
            <span className="step"><span className="dot" style={{ background: color }} />{label}</span>
            {i < steps.length - 1 && <span className="sep">→</span>}
          </span>
        ))}
      </div>
      <p className="ink2" style={{ fontSize: 12, margin: "12px 2px 0" }}>
        Most runs go straight through. <b>Awaiting approval</b> only appears when a big fan-out or an
        attack needs a person to say yes — the run pauses there until someone decides.
      </p>
    </div>
  );
}

// 3 — live map colour legend (glowing orbs, not just words)
function MapLegend() {
  const items: [string, string, string, boolean][] = [
    ["active", C.active, "where the run is working right now", true],
    ["done", C.done, "finished successfully", false],
    ["stuck", C.wait, "blocked or needs a human decision", false],
    ["error", C.err, "a step failed", false],
    ["queued", C.queued, "created, not started yet", false],
  ];
  return (
    <div className="diagram">
      <div className="diagram-cap">live map — what the colours mean</div>
      <div className="legend">
        {items.map(([name, color, meaning, pulse]) => (
          <div className="item" key={name}>
            <span className={`orb ${pulse ? "pulse" : ""}`}
                  style={{ background: color, boxShadow: `0 0 12px color-mix(in srgb, ${color} 55%, transparent)` }} />
            <span><b>{name}</b><small>{meaning}</small></span>
          </div>
        ))}
      </div>
    </div>
  );
}

// 4 — the safety gate (danger-styled)
function SafetyGate() {
  return (
    <div className="diagram">
      <div className="diagram-cap">the safety gate — two locks, no auto-attacks</div>
      <div className="flow">
        <Node cls="gate" title="Gate 1 · toggle" sub="owner turns spray/exploit ON for the project" />
        <Ad />
        <Node cls="gate" title="Gate 2 · a person" sub="approves this exact action; exploits need a 2nd confirm" />
        <Ad />
        <Node cls="danger" title="Then — and only then" sub="scope re-checked, command rebuilt server-side, it runs" />
      </div>
      <p className="ink2" style={{ fontSize: 12, margin: "12px 2px 0" }}>
        Turning the toggle on does <b>nothing</b> by itself. Every attack still needs a human to approve
        that specific step. Recon is automated; attacks never are.
      </p>
    </div>
  );
}

export function Help() {
  return (
    <div style={{ maxWidth: 860 }}>
      <h1>Help &amp; guide</h1>
      <p className="ink2" style={{ marginTop: -2 }}>The short, visual version — how a run works, what
      the colours mean, and where a human stays in charge.</p>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>What is Nabu Agent?</h3>
        <p className="ink2">A team platform for authorized recon. You create a scoped engagement
        (project), point it at an IP or range, and a supervisor fans out a team of agents — one per
        service, plus research and a report writer — that enumerate the target and hand back a clean
        report with next steps. It's built on the classic Nabu recon engine; every tool runs through a
        single, allow-listed chokepoint.</p>
        <RunFlow />
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
        <Lifecycle />
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>The live map colours</h3>
        <MapLegend />
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Working the live map</h3>
        <ul className="ink2">
          <li><b>Click a node</b> — opens its detail (ports · protocol · product · severity) and pins the
          <b> attack path</b> from the entry to it in gold, dimming everything else.</li>
          <li><b>Shift-click two nodes</b> — traces the shortest path <b>between</b> them; press <b>C</b> to
          copy a pinned path as text (<code>node → node → …</code>).</li>
          <li><b>Double-click a node</b> — jumps to its note. Notes persist per project and mark the node
          with a dashed gold ring.</li>
          <li><b>Search</b> highlights matching nodes and dims the rest; <b>Filter</b> hides whole node
          kinds to declutter a busy graph.</li>
          <li><b>▢ Region</b> — groups the current search matches into a labelled, colour-coded region you
          can annotate. Regions follow their nodes as the map re-lays-out and persist across runs.</li>
          <li><b>⬇ PNG</b> exports the map · <b>Fit</b> re-frames · <b>Esc</b> or a click on empty canvas
          clears a pinned path.</li>
        </ul>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Attaching the LLM (admin)</h3>
        <p className="ink2">Point the platform at your internally-hosted, OpenAI-compatible endpoint via
        config: <code>NABU_LLM_BASE_URL</code>, <code>NABU_LLM_API_KEY</code>, <code>NABU_LLM_MODEL</code>.
        Then <b>agent</b> runs work. No code change — the provider is swappable. See <b>Admin → LLM setup</b>
        for a guided setup + a one-click test that reports latency and token usage.</p>
      </div>

      <div className="card">
        <h3>Safety</h3>
        <p className="ink2">Recon is automated; <b>attacks are never automatic</b>. Any spray/exploit is
        only ever proposed and must be approved by a human. Every target is checked against the project's
        authorized scope before anything runs, and every action is audited.</p>
        <SafetyGate />
      </div>
    </div>
  );
}
