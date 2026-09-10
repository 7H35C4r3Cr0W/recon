# Nabu Agent — HANDOFF & Progress Tracker

> **This file is the single source of truth for "where we are."** Read it first when a session
> resets. It tracks the plan as clean, measured steps with live status, so if work stops mid-way
> the next session (or the next engineer) can resume exactly where we left off. Update the
> **Current position** block and tick the step boxes as you go.

- **Product:** **Nabu Agent** — an internally-hosted, agent-driven automation of the classic **Nabu**
  (`oscprecon`) recon tool. New product; lives in this folder (`nabu-agent/`) only.
- **Golden rule:** `src/oscprecon` (classic Nabu) is a **read-only dependency** and is **never
  modified**. All new code lives under `nabu-agent/`.
- **Brain / body split:** the owner attaches the **brain** — an internally-hosted, **OpenAI-compatible**
  LLM (GPT-5.1 today). This project builds the **body**: a provider-agnostic `LLMProvider` layer whose
  default adapter is OpenAI-compatible (`base_url`/`api_key`/`model` via config → the internal
  endpoint), plus the agent orchestration, web platform, engine adapter, and reporting.
- **Stack (locked):** FastAPI (async) + Postgres + Redis + Arq workers · React + Vite + TypeScript SPA
  (live progress over WebSocket) · Docker Compose. Engine reached **only** through the read-only
  adapter seam (`nabu_agent/engine/`).
- **Repo:** `git@github.com:7H35C4r3Cr0W/recon.git` · latest on **`main`** (PRs #1 scaffold, #2 Phase-2 MVP merged).

---

## Current position

```
DATE:        2026-09-09
BRANCH:      nabu-agent-arq (off main; PRs #1-#5 merged). This branch = Arq worker + fan-out + fixes.
PHASE:       Body done + on the Arq worker with concurrent per-service fan-out.
STATUS:      Login → project → scope → run (demo|scan|agent) → live BloodHound map (multiple agents
             green at once) + logs → report. Runs execute on the Arq worker pool in prod
             (NABU_USE_ARQ=true); in-process for dev/tests. LLM seam wired (kind=agent).
             28/28 tests pass (incl. fan-out concurrency, arq dispatch gate, run-failure reliability,
             authz, invariants); ruff clean; frontend builds; engine headless + untouched.
             THREE adversarial review rounds; all confirmed findings fixed. Heartbeat + stale-run REAPER
             added (killed runs are marked failed + emit a terminal event); app-wide error handler +
             structured error logs added. OIDC/SSO login wired (Authlib authorization-code + JIT
             provisioning; local login still works; SSO button on the login page).
ATTACH BRAIN: set NABU_LLM_BASE_URL (+ API_KEY, MODEL) → kind="agent". No code change.
KNOWN LIMITATIONS (documented, not blockers):
  - the engine on_line→WS log bridge has no backpressure under an extremely chatty scan.
  - real-scan process-group cancel + Reporter.write atomicity live in the read-only engine.
NEXT UP (optional hardening): WS-path integration test; per-agent map
  nodes from LLM tool calls; artifact retention/quotas.
HOW TO TEST: cd nabu-agent && PYTHONPATH=. .venv-agent/bin/python -m pytest -q -o asyncio_mode=auto
```

### Live-visualization requirements (owner, 2026-09-09) — build into Phase 2
The run view is a **BloodHound-style flow-chart map** (like the classic Nabu graph), showing the
**agents in motion**, with a **live action log** and **color-coded node states** updated in real time
and persisted onto the map so anyone watching sees it live:
- **glowing green** = active / where the run currently is · **yellow** = stuck/blocked/needs-approval
  · **red** = error/failed · (plus: grey = queued, blue/teal = done).
- Nodes = the run graph: target → discovered services → per-service agents → findings → report; edges
  show hand-offs. As agents transition (`task.updated`, `finding.added`, `run.status`), the map
  re-colours the node live and the log pane appends the action line.
- Implemented with **Cytoscape.js** in the SPA (same library the desktop GUI vendored), driven by the
  canonical WebSocket `Event` envelope. The state colour is carried in `event.data.node_state`; the
  frontend keeps a node-state map keyed by `task_id`/`node_id` and restyles on each event.
- Login → **project page** is where all the work happens (create/scope/run/watch/report on one page).
This extends sub-steps **2.5–2.9** (event model carries node state; `ws/hub` streams it; the frontend
RunLive page renders the Cytoscape map + live log). See DESIGN §6.1 (event envelope) — add
`node_state` to `task.*`/`run.status` `data`.

**How to resume:** read this file → check the last ✅ step → continue at the first ☐. Design inputs
are in `docs/` (`ENGINE_INTEGRATION.md` is authoritative for how to call the engine; `DESIGN.md` for
the architecture; `ROADMAP.md` for the phased plan). Never edit `../src/oscprecon`.

---

## Legend
`✅ done` · `🚧 in progress` · `☐ not started` · `⏭ next` · `⛔ blocked`

---

## Phase 0 — Discovery & Design (grounding)

- [x] **0.1** Locate + analyze classic Nabu (`/home/hacker/oscp-recon`), read handoffs & constraints (CLAUDE.md §2 exam-legality, offline, no-LLM-at-runtime). ✅
- [x] **0.2** Map the reusable engine APIs (multi-agent workflow) → **`docs/ENGINE_INTEGRATION.md`** (scan, data model, catalog, research, reporter, CLI, `shell.py` chokepoint + safety invariants). ✅
- [x] **0.3** Design the platform across 5 dimensions (orchestration · engine adapter · web platform · brain seam · deploy/security) + adversarial verification (workflow). ✅
- [x] **0.4** Synthesize **`docs/DESIGN.md`** + **`docs/ROADMAP.md`** + **`docs/SCAFFOLD_MANIFEST.md`** (verifier fixes folded in; package layout reconciled to one root `nabu_agent/`). ✅
- [x] **0.5** Manager-facing **interactive `docs/nabu-agent.html`** — built (tabs: Overview/Architecture/Agent Flow/Roadmap/Safety; light-dark; reuses the presentation.html design system). ✅ — — adapt the existing `../docs/presentation.html` design system (tabs, light/dark tokens) into a Nabu Agent overview + architecture + agent-graph + roadmap page. Publish as an Artifact for review.

## Phase 1 — Scaffold the "body" (this round's main deliverable)

- [x] **1.1** Backend project root: `backend/pyproject.toml` (path-dep on the engine, headless/no-Qt), `README.md`, `.gitignore`.
- [x] **1.2** Typed config/settings + **`.env.example`** (platform + Redis/Postgres + the **LLM brain-seam** keys).
- [x] **1.3** **LLM provider seam** — `llm/base.py` (Protocol + wire types), `llm/openai_compat.py` (default adapter), `llm/config.py`, `llm/factory.py`.
- [x] **1.4** **Engine adapter** (read-only seam) — `engine/{guard,workspace,tools,schemas,errors,settings}.py` wrapping real `oscprecon` calls; preserves the `shell.run` chokepoint, scope-lock, audit.
- [x] **1.5** **Orchestration** — `orchestration/{states,tasks(supervisor+fan-out),blackboard,limits,checkpoints,worker}.py` on Arq/Redis.
- [x] **1.6** **Agent layer (brain-facing)** — `agents/{runner,roles,context,safety,budget}.py` + role prompt templates.
- [x] **1.7** **Web platform** — `main.py`, `auth/`, `rbac.py`, `audit.py`, `db/models.py` + migrations, `routers/`, `ws/` (WebSocket live progress).
- [x] **1.8** **Frontend** — React + Vite + TS skeleton: login → projects → project → start run → live agent tree → report.
- [x] **1.9** **Deploy & quality** — `docker-compose.yml`, `deploy/` (Dockerfiles, nginx), CI, and a **policy-invariant test suite** (asserts the agent layer can never bypass `shell.run`/scope-lock/auto-exploit).

**Phase 1 exit criterion:** the tree is coherent and importable; `docker compose config` validates;
the FastAPI app boots; the provider seam + engine adapter have real (not empty) implementations with
a clean stub where the owner attaches the LLM endpoint.

## Phase 2 — MVP thin slice — DETAILED PROJECT PLAN

**Goal (ROADMAP exit):** from a clean deploy an operator logs in, creates a scoped project, starts a
recon run against ONE authorized IP, watches live progress over WebSocket, and reads a rendered
report — no manual DB/CLI steps. Single-target only (fan-out is Phase 3). Every step keeps the
policy-invariant gate green and `../src/oscprecon` untouched.

**How to build it (ordered sub-steps — do in order, test each, tick as you go):**

- [x] **2.1 Test harness** — `tests/conftest.py`: async in-memory SQLite (`aiosqlite`) engine +
  `Base.metadata.create_all` fixture; `fakeredis.aioredis` fixture; a FastAPI `TestClient`/`httpx`
  fixture with dependency overrides (`get_db`, redis, and the engine adapter mocked). Deps already in
  the test venv (`.venv-agent`): `pytest-asyncio`, `aiosqlite`, `fakeredis`.
- [x] **2.2 DB session wiring** — make `db/session.py` build the engine from `Settings.database_url`
  lazily (not at import) so tests can point it at sqlite; add `create_all()` helper for dev/test;
  keep `get_db` the injected dependency.
- [x] **2.3 Auth (local first)** — implement `auth/providers.LocalProvider` (argon2 verify),
  `auth/sessions` (redis-backed opaque session in the httpOnly cookie), `auth/deps`
  (`get_current_user`, `require_role`, `require_project_role`, `csrf_protect`), and
  `bootstrap.seed_admin`. Wire `routers/auth.py` login/logout/me. OIDC stays scaffolded.
- [x] **2.4 Projects + scope** — `routers/projects.py` create → `engine.gateway.create_project_profile`
  (`Profile.create`), list/get/patch, members, settings (spray/exploit gates, admin only);
  `routers/scope.py` allowlist CRUD with `models.validate_host_or_range` + human-gated promote. RBAC
  via `auth/deps`. Platform-audit each mutation (`nabu_agent.audit`).
- [x] **2.5 Runs API** — `routers/runs.py`: `POST /projects/{id}/runs` → `assert_in_scope` +
  RBAC + gating + `admission.acquire_run_slot` + enqueue `supervise_run`; `GET /runs/{id}` (+ tasks),
  `POST /runs/{id}/cancel`. Persist `runs`/`agent_tasks`/`run_events` (monotonic `seq`).
- [~] **2.6 (demo path done; REAL recon `_run_real` deferred)**  —— original: **2.6 Orchestration (single target, no fan-out)** — implement `bus.py` (redis enqueue /
  cancel-flag / publish-subscribe), `orchestration/admission.py`, the single-writer `blackboard.py`,
  and `orchestration/tasks.supervise_run` for ONE host: validating → alive_check (`check_alive`) →
  scanning (`run_scan`) → enriching (one `enum_service` per discovered service, still serial) →
  synthesizing (`generate_report`) → report_ready. Engine calls run in a worker thread; cancel flag →
  `threading.Event`; idempotency key; blocked/missing_tool recorded, never retried → `partial`.
- [x] **2.7 WebSocket** — `ws/hub.py`: cookie-auth handshake, replay `run_events` by `seq` then tail
  the redis `run:{id}` channel, ~20s heartbeat, ~250ms coalescing of `task.updated`/`log.line`.
- [~] **2.8 (gateway funcs exist; router bodies deferred)**  —— original: **2.8 Reports/findings** — `routers/reports.py` (`gateway.render_report`, artifacts) +
  `routers/findings.py` (`gateway.list_findings/list_services/build_graph`); apply
  `agents/report_grounding.validate_claims` and delimit AI-narrative.
- [x] **2.9 Frontend** — finish `api/client.ts` + `ws/client.ts`; build the pages: Login, Projects
  (list + create + scope), RunLive (task tree + streamed log via WS), Report. Route guards on auth.
- [x] **2.10 Integration tests** — happy path: login → create project (mock `Profile.create`) →
  start run (mocked engine tools) → receive `run_events` → fetch rendered report; error-contract
  mapping (out-of-scope → 403 `scope_violation`); WS replay-by-seq reconnect; grounding validator
  rejects an injected unbacked claim. Keep the invariant gate green.

**Phase 2 exit checklist (all must pass):**
- [ ] clean deploy → operator completes login → project+scope → run → live progress → report, no CLI.
- [ ] mid-run WS reconnect reconciles to the same task tree (replay-by-seq).
- [ ] out-of-scope target refused at the API (403) and never enqueued.
- [ ] secrets absent from `run_events`/WS payloads (cred_ref only); `creds.json` stays 0600.
- [ ] happy-path API + WS integration test green in CI; policy-invariant gate still green.

**Testing notes:** use `.venv-agent` (already built) — `PYTHONPATH=. .venv-agent/bin/python -m pytest`.
No docker needed for unit/integration (sqlite + fakeredis + mocked engine). Full `docker compose up`
is the manual acceptance check when Postgres/Redis are available.

## Phase 3 — Hardening (later)

- [ ] **3.1** Cancellation/timeouts wired to WS; range fan-out caps; per-project Redis lock; auth provider (OIDC) wired; observability/tracing; secret handling; test coverage.

## Phase 4 — GitHub update

- [x] **4.1** Stage **`nabu-agent/` only** (never `src/oscprecon`), commit with attribution.
- [x] **4.2** Pushed `nabu-agent-scaffold` → `origin`; **PR #1** open: https://github.com/7H35C4r3Cr0W/recon/pull/1 ✅

---

## Decisions log
- **2026-09-09** Product = *Nabu Agent*; folder `nabu-agent/`; classic Nabu untouched.
- **2026-09-09** Brain is owner-attached, OpenAI-compatible; body defaults to an OpenAI-compatible
  provider adapter, fully swappable via config.
- **2026-09-09** Reuse the engine **as an imported library** (path dep), never rebuild recon knowledge.
- **2026-09-09** Carry over classic Nabu's safety posture: single `shell.run` chokepoint,
  authorized-scope-only, **no blind auto-exploit** (recon automated; attack/spray stays human-gated),
  audit everything.
- **2026-09-09** Package layout reconciled to a single root — see `docs/DESIGN.md` (§Folder layout).

## Open questions for the owner
- Auth source of truth (OIDC/SSO provider details vs. local accounts) for the internal deployment.
- Where it will be hosted (single VM vs. k8s) and network-egress policy for tool execution.
- Confirmation that engagements are always against authorized scope (scope-allowlist per project).

---

## Phase 5 — Full agent orchestration + UX (feed, help guide, dark "hacker" theme)

**Owner asks (2026-09-09), to do in a LOGICAL order (not the order stated):** wire up ALL the agent
roles into a real fan-out; add a notifications/**feed** at the front of the app; add a **help guide**;
give the whole SPA an easy-to-read **dark "hacker" theme** + good UX; add the deferred **WS-path
integration test**. Track every step here and tick as done (multi-session safe).

### The agent roster (what "all the agents" means)
The run graph is a supervisor + LLM worker agents. Each LLM agent is an `AgentRunner` (role prompt +
allow-listed tools + SafetyGate + budget) and shows as its own node on the live BloodHound map.

| Agent | Kind | Tools (allow-list) | Does | Map node |
|---|---|---|---|---|
| **Supervisor** | orchestration (no LLM) | — | drives the RunState machine, scan, fan-out, join | `run-<id>` |
| **Planner** | LLM | list_discovered_services, suggest_next_steps, catalog_actions_for | reads discovered services, decides enum order + what to research | `agent-planner-<id>` |
| **Enum agent** (1 per service) | LLM | enum_service, list_discovered_services | drives Tier-1 recon for its service → findings | `agent-enum-<port>` |
| **Research agent** (per notable finding/service) | LLM | research_finding, catalog_actions_for, list_discovered_services | HackTricks/EDB/GTFOBins + candidate next steps (proposals only) | `agent-research-<port>` |
| **Reporter** | LLM | generate_report, suggest_next_steps, list_discovered_services | synthesizes the grounded report + prioritised next steps | `agent-report-<id>` |

Roles live in `nabu_agent/agents/roles.py` (planner / enum_writer / research / reporter) + shared
`SAFETY_PREAMBLE`. Attack (spray/exploit) is NEVER an agent — only a human-gated checkpoint.

### Ordered steps (logical order)
- [x] **5.1 WS-path integration test** — a real WebSocket client drives `/ws/runs/{id}` end-to-end
  (auth handshake, replay-by-seq, live tail, terminal close) using Starlette's WS test client on the
  in-process app + a demo run. Closes the last review-flagged test gap.
- [x] **5.2 Wire up ALL agents (multi-role fan-out)** — `_run_agent` becomes: scan → **planner** →
  fan out **enum agents** (per service, concurrent) → **research agents** (per notable service/finding)
  → **reporter**, each an `AgentRunner` streaming its own map node + log. Bounded by RunLimits; each
  role's node goes green→teal (or yellow/red). Falls back cleanly if no LLM configured. Tests with a
  scripted fake provider assert every role node appears.
- [x] **5.3 Notifications / feed (backend)** — a per-user activity **feed**: recent runs (start/finish),
  findings, checkpoints (approvals needed), across the user's projects. `GET /api/feed` (+ unread
  count); lightweight (derived from runs/agent_tasks/findings_index + a notifications table for
  approvals). WS or poll for live updates.
- [x] **5.4 UX shell + dark "hacker" theme** — a real SPA design system: dark theme tokens (near-black
  bg, green/teal accents, monospace headings), an app shell (top bar + left nav: Feed / Projects /
  Help), and restyled Login / Projects / Project / RunLive pages. Easy on the eyes, consistent.
- [x] **5.5 Feed page (frontend)** — a "feed" landing view at the front (notifications + recent
  activity), with an unread badge in the top bar; live via the project WS or polling.
- [x] **5.6 Help guide (frontend)** — an in-app, easy-to-read Help page: what Nabu Agent is, how to
  run recon, the run kinds (demo/scan/agent), the live map colours, attaching the LLM, SSO, safety.

### Progress log (append one line per completed step)
- 5.1 ✅ WS-path integration test (httpx-ws): auth-reject, live-tail→done, reconnect-to-finished terminates.
- 5.2 ✅ full agent roster wired (planner/enum/research/reporter), each a map node.
- 5.3 ✅ feed backend: GET /api/feed (per-user activity across projects + unread/attention count); test_feed isolates per user.
- 5.4 ✅ dark 'hacker' theme (theme.css) + app Shell (topbar + sidebar nav + live unread badge).
- 5.5 ✅ Feed page = the front '/' (live auto-refresh, click → run live view).
- 5.6 ✅ Help guide page (what it is, getting started, run kinds, map colours, LLM attach, SSO, safety).
- Frontend builds clean (tsc strict + vite + theme). 40 backend tests.
- FE tests ✅ Vitest + React Testing Library: 12 tests; CI runs `npm test`.
- Richer map edges ✅ labeled hand-off edges (planner→enum, enum→finding/research, agents→report).
- Log backpressure ✅ LogPump (bounded deque + coalesced batches + suppressed count).
- /24 load test ✅ tests/load/test_cidr_load.py (pytest -m load, excluded from unit CI): event pipeline ~504 ev/s / 1537 events durable+monotonic; wide fan-out 300 svc peak-concurrency ≤ cap. Adversarial workflow analysis → **docs/LOAD_TEST.md**. HONEST VERDICT: the event substrate + per-service fan-out are bounded/ready, but a real /24 CANNOT run yet — there is NO per-HOST fan-out (single-target only), CIDR collapses to one host-less Profile, and most RunLimits host guardrails (max_hosts/approval/max_enum_per_host) + admission/blackboard are unwired stubs. LOAD_TEST.md has the prioritized plan to close it (host tier → per-host Profile+identity → wire guardrails → event-commit batching → worker model → frontend Cytoscape debounce → paged WS replay).
- Project delete + on-disk workspace GC ✅ DELETE /api/projects/{id} (owner/admin; refuses while a run is active) removes all DB rows + safely rmtrees the project's workspace dir (traversal-guarded); UI 'Delete project' button. Tested. 51 backend + 12 FE tests.
- OIDC back-channel logout ✅ per-user session index + POST /api/auth/oidc/backchannel-logout (validates the IdP logout token: sig via JWKS, iss/aud/events/sub, no nonce) → revokes all the user's sessions; unconfigured→404, bad token→400. Tested (validation mocked). 48 backend + 12 FE tests.
- Retention/quotas ✅ orchestration/retention.py: event-TTL (prune terminal runs' events > N days) + per-project run cap (keep newest N + cascade delete children); Arq cron (hourly + startup) on the worker; admin endpoints GET /api/admin/storage + POST /api/admin/retention (admin-only). Unit + endpoint tests. 45 backend + 12 FE tests. **All Phase-5 items + all optional polish complete.**

---

## Phase 6 — Host tier (multi-host / CIDR fan-out) — closes the LOAD_TEST.md gap

**Goal:** a run whose target is a CIDR (or multi-host scope) sweeps for live hosts and fans out
per-HOST recon (each host its own Profile + host-scoped map nodes), bounded by the RunLimits host
guardrails. Closes the critical gap from docs/LOAD_TEST.md (recs 1-3).

- [x] **6.1 Host-scoped node identity** — enum/research/finding node ids include the host
  (`agent-enum-{host}-{port}`, `agent-research-{host}-{port}`, `finding-{host}-...`; svc already
  `svc-{host}-{port}-{proto}` when target=host). Update existing tests to the host-scoped ids.
- [x] **6.2 Per-host Profile** — `workspace_for(project_id, host_ip)` per live host → its own
  findings.json (fixes the host-less `findings._key` collision without touching the engine).
- [x] **6.3 `_recon_host()`** — extract the per-host scan→services→enum-fan-out→findings→report from
  `_run_real`, host-scoped, under a per-host service semaphore (`max_enum_per_host`).
- [x] **6.4 Multi-host driver** — `_run_real` single host (no `/`) → one `_recon_host`; CIDR →
  alive-sweep (`check_alive`) → live hosts → clamp `max_hosts` → fan out `_recon_host` concurrently
  under `max_concurrent_hosts`; global `max_total_tasks` product cap; aggregate → partial/done.
- [x] **6.5 Wire guardrails** — clamp `max_hosts`; per-host `max_enum_per_host`; `max_concurrent_hosts`
  (new); `max_total_tasks` as the hosts×services budget; emit a note when `approval_required_above_hosts`
  is exceeded (full human recon-approval gate = follow-up).
- [x] **6.6 Tests** — multi-host scan (mock engine: alive-sweep returns N hosts, each with services)
  asserts per-host host-scoped nodes, per-host profiles, caps enforced (clamp > max_hosts), no
  cross-host collision.

### Phase 6 progress log
- DONE (UX completion) — the frontend had orphaned/stub pages; closed the real gaps the owner flagged:
  * **Report & outputs page** (`frontend/src/pages/Report.tsx`, was a stub + unrouted) — now routed at
    `/projects/:projectId/report`: a severity-coloured findings table + the full report rendered from
    markdown (small safe renderer: headings/tables/lists/bold). Reachable from ProjectDetail.
  * **Run history on the project page** (`ProjectDetail.tsx`) — lists past runs (state pill + kind +
    target), each linking to its live agent map (`/projects/:pid/runs/:rid`) + a "Report & outputs"
    link. So the agent chain/map IS reachable from the project page (open any run → the Cytoscape map).
  * **Aggregated findings for CIDR** — `GET /projects/{id}/findings` had the same
    read-the-sweep-Profile gap the report had; added `gateway.list_combined_findings` (per-host
    aggregation, host-tagged, severity-sorted) and wired the router (CIDR → combined, single host
    unchanged). Backend test added.
  Tests: `Report.test.tsx` (2), `ProjectDetail.test.tsx` (2), `test_combined_report_api` +1 (findings
  aggregation). Gate: ruff clean, mypy 10, 70 backend + 2 load + 9 invariant + 18 frontend, build OK.
  STILL orphaned (documented, low priority): `Approvals.tsx` stub (the in-run RunLive banner + the
  Feed 'attention' state cover approvals) and `Health.tsx` (real readiness page, just not linked).
  NO attack execution exists (recon only; attacks are human-gated + deliberately unwired) — the live
  view shows live RECON, not an attack. The LLM `agent` kind needs the brain (`NABU_LLM_*`) attached.

- DONE (follow-up) — **distributed (two-pool) supervisor + admission control**. Under `NABU_USE_ARQ`
  the supervisor (`execute_run` via `supervise_run`) now, at the per-host fan-out step, ENQUEUES one
  `recon_host_job` per live host onto the Arq worker pool and AWAITS its result (gather = the fan-in
  barrier) instead of running all hosts in its own coroutine — so heavy per-host recon spreads across
  the pool (bounded by worker `max_jobs`) while the supervisor stays a light coordinator that still
  owns the single terminal DONE + heartbeat + gate. `services/runs._dispatch_host` picks in-process
  (use_arq off; unchanged) vs enqueue-and-await (on); `run_host_in_worker` is the host job's body
  (rebuilds publish/cancel/log-pump, beats heartbeat); `tasks.recon_host_job` + `worker.py` function.
  **Admission** (`orchestration/admission.py`): one active run per project (Redis SET-NX mutex on the
  Profile dir, TTL `RUN_SLOT_TTL_S`) + global ceiling (`DEFAULT_GLOBAL_RUN_CEILING`), acquired at the
  top of `execute_run` (project-less demo runs skip it), released in finally; a refused run ends
  `failed` with a clear error. New limit `host_job_timeout_s`. Blackboard single-writer-Profile deltas
  left UNIMPLEMENTED on purpose — per-host Profiles make cross-process findings.json races impossible,
  so the supervisor need not be the sole writer. Tests: `test_admission.py` (3 unit, fakeredis),
  `test_distributed_run.py` (2 — fake Arq pool runs enqueued tasks inline: asserts 1 supervise_run + 3
  recon_host_job enqueues, per-host nodes, single DONE; + admission refuses a 2nd run on a busy
  project). CAVEAT: the real multi-worker Arq path can't be integration-tested here (fakeredis, no
  worker) — the fake pool exercises the choreography; a live-cluster smoke test is still needed. Gate:
  ruff clean, mypy 10, 69 backend + 2 load + 9 invariant + 14 frontend, build OK.

- DONE (follow-up) — **hard host-count approval checkpoint**. A fan-out above
  `RunLimits.approval_required_above_hosts` (16) now PARKS the run: `services/runs._gate_host_fanout`
  (called by both drivers after `_resolve_hosts`) persists a `hosts` Checkpoint, sets state
  `awaiting_approval`, emits `approval.required` (run node -> stuck/yellow), and polls the checkpoint
  until approved (-> resume fan-out) / rejected (-> cancelled) / cancel / timeout (`_APPROVAL_TIMEOUT_S`
  default 30m -> failed). Heartbeat keeps beating while parked so the reaper leaves it alone. API:
  `GET /runs/{id}/checkpoints`, `POST .../{cp}/approve|reject` (`require_run_access`; only kind
  `hosts` is approvable here — spray/exploit stay proposal-only). Frontend: RunLive shows an
  Approve/Reject banner on `approval.required`. New CheckpointKind.HOSTS. Tests:
  `test_approval_gate.py` (4: approve->proceed, reject->cancelled, timeout->failed, small fan-out no
  gate), RunLive.test.tsx (2), + updated `test_multihost_run` (_drive auto-approves; setup.ts stubs
  Element.scrollTo). Gate: ruff clean, mypy 10, 64 backend + 2 load + 9 invariant + 14 frontend, build OK.

- DONE (follow-up) — **combined multi-host report** + a **workspace isolation fix** (the important
  one). `gateway.render_combined_report(project_id)` enumerates every per-host Profile under the
  project (skips the CIDR 'sweep' Profile whose target has '/'), and builds one markdown: cross-host
  summary table (Host | Services | Findings | Top severity), aggregate severity tally, "Suggested
  next steps" (notable findings across hosts, strongest first via finding_severity.rank), then each
  host's full `Reporter(prof).render()` with headings demoted to nest. `routers/reports.get_report`
  serves it whenever the scope is a CIDR (single host unchanged). **Root-cause fix:**
  `AgentWorkspace.create()` called `Profile.create(workspace_root, project_id, target)` -> wrote to
  `<workspace>/<project_id>`, IGNORING the target, while `directory`/`open()`/`exists()` looked in
  `<workspace>/<project_id>/<slug(target)>`. So every in-scope host collapsed into ONE Profile /
  findings.json — silently breaking the host tier's per-host isolation (the multihost tests missed
  it because they fully mock workspace_for). Fixed create() to build under the per-target subdir.
  Tests: `test_combined_report.py` (2, unit), `test_combined_report_api.py` (2, router gating),
  `test_workspace_isolation.py` (2, regression). Gate: ruff clean, mypy 10, 60 backend (incl. 9 invariant) + 2 load, frontend unchanged.

- (starting 6.1/6.5)
- DONE — host tier shipped for the `scan` kind. `services/runs.py`: added `_resolve_hosts`
  (single host -> [t]; CIDR -> `check_alive` sweep -> clamp `max_hosts` -> notice over
  `approval_required_above_hosts`) + `_recon_host` (per-host Profile via
  `workspace_for(project_id, host)`, host-scoped nodes `host-/svc-/agent-enum-/finding-`,
  per-host enum semaphore = `max_enum_per_host`, per-host `report.md`) + rewrote `_run_real`
  as the multi-host driver (fan out under `max_concurrent_hosts`, `max_total_tasks` product
  cap via `per_host_budget`, per-host error -> red host node, all-hosts-failed -> surface as
  driver failure so the `failed`+error-event reliability contract holds). Host-scoped the
  `_run_agent` ids too (still single target). New limit `max_concurrent_hosts`=4.
- Tests: `tests/integration/test_multihost_run.py` (2) — CIDR fans out per host with
  host-scoped subtrees + no collision; alive > `max_hosts` clamps to 32 with a capping log.
  Updated `test_real_run`/`test_fanout`/`test_agent_run` to the host-scoped ids; load test's
  wide-fanout cap now asserts `max_enum_per_host` (measured peak 4/4). Full local gate green:
  ruff clean, mypy 10 (down from 11; new code clean), 53 backend + 2 load + 9 invariant + 7
  unit + 12 frontend tests pass, frontend build OK.
- DONE (follow-up) — **agent-kind multi-host**. Extracted `_agent_host` (full LLM roster for ONE
  host into its own Profile: scan -> planner -> per-service enum -> per-service research ->
  reporter, all host-scoped incl. `agent-planner-{ip}`/`agent-report-{ip}`, per-host enum semaphore
  = `max_enum_per_host`, per-host report) and rewrote `_run_agent` as the multi-host driver reusing
  `_resolve_hosts` + `max_concurrent_hosts` + `max_total_tasks` product cap + the same per-host-crash
  / all-hosts-fail-surfaces-as-driver-failure handling as `_run_real`. LLM-config check stays at the
  driver. Test: `tests/integration/test_multihost_agent_run.py` (CIDR -> per-host roster, no
  collision). Updated single-host `test_agent_run` planner/reporter ids to host-scoped. Gate green:
  ruff, mypy 10, 54 backend + 2 load + 9 invariant, frontend unchanged.
- Doc: `docs/LOAD_TEST.md` updated — gap now largely closed for `scan`; guardrail table +
  verdict revised; remaining follow-ups (agent-kind multi-host, combined report, hard
  approval checkpoint, distributed supervisor) listed honestly.
- NOTE surfaced to owner: `nabu-agent/.github/workflows/nabu-agent-ci.yml` is in a location
  GitHub never scans (workflows must live at repo ROOT `.github/workflows/`), and the repo's
  root CI is deliberately **manual-only** (`workflow_dispatch`, auto-triggers removed to save
  Actions minutes) — gates run LOCALLY before push. So the nabu-agent CI never auto-ran. Left
  as-is (not silently converted to auto-trigger against that policy); flagged for a decision.
