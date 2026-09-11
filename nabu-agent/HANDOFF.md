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
DATE:        2026-09-11
BRANCH:      main @ f5ab774+ (PRs #1–#50 merged).
STATUS:      DEV SIDE DONE (per docs/DEFINITION_OF_DONE.md). Full recon (single + CIDR fan-out on the
             Arq worker pool), live BloodHound map, reports + triage, RBAC/audit/creds vault, admin
             LLM setup + test-fire, AND the human-gated attack EXECUTION gate (propose → double-gated
             approve → run via the one door; dry-run + four-eyes + rate-limit; credential injected only
             at execute, previews/logs redacted). Interactive demo:
             https://claude.ai/code/artifact/68d8ab3a-2351-4d06-8bb6-742190d69846
GATE:        ruff + mypy clean; 112 backend + 10 policy-invariant + 27 frontend tests; vite build OK;
             alembic upgrade head verified; src/oscprecon untouched.
REMAINING:   Tier 2 only (LLM-gated, blocked on legal): attach the model → `agent` runs; Phase B
             (agents PROPOSE into the built gate); run-level LLM budgets; live agent-run validation.
ATTACH BRAIN: set NABU_LLM_BASE_URL (+ API_KEY, MODEL) via Admin → LLM setup → test-fire. No code change.
OPS NOTE:    the hourly git-autosync crontab line is PAUSED during active dev (kept local; uncomment to
             restore) so WIP stops landing on main.
HOW TO TEST: cd nabu-agent && uv sync --group dev && uv run pytest -q -m "not load"   (+ -m invariant);
             frontend: cd frontend && npx vitest run && npx vite build
```

---

## System structure & processes (orientation)

*Read this to understand HOW the system is built and how work flows; the dated log further down is the
blow-by-blow history.*

**Two products, one repo.** `src/oscprecon` = the classic desktop recon engine (READ-ONLY, never
edited). `nabu-agent/` = this offshoot: the web/agent "body" that drives the engine as a library.

**Runtime processes (docker-compose):**
- `api` (FastAPI, async) — HTTP + WebSocket; drops Linux caps and **runs no tools** (reads engine
  state only). `postgres` — projects/runs/events/checkpoints/findings/audit. `redis` — event pub/sub +
  the Arq job queue + cancel flags + rate-limit keys. `worker` (Arq) — where runs actually execute
  (blocking engine calls in threads). `frontend` (nginx) — the built React SPA + TLS.
- Dev/tests run the worker path **in-process** (`NABU_USE_ARQ=false`, aiosqlite + fakeredis).

**The one chokepoint.** `engine/shell_gateway.py` is the ONLY module that calls `oscprecon.shell.run`.
`run_recon_tool` hard-wires `spray=exploit=False`; `execute_gated_action` is the SOLE place those flags
can be True, and it refuses anything but a human-approved checkpoint. A policy-invariant AST test
enforces this structurally.

**Run lifecycle** (`orchestration/states.py`): queued → validating → alive_check → scanning → fan_out →
enriching → researching → synthesizing → report_ready → (done|partial). The ONLY human branch is
awaiting_approval → executing_approved, entered by an attack/host-count gate. Terminal: done/partial/
failed/cancelled. Two-pool fan-out: the supervisor enqueues one `recon_host_job` per live host and
awaits them (`services/runs.py`), each host writing its own per-host engine Profile.

**The attack gate** (Phases A/C/D/E — the human-gated attack path):
`POST /runs/{id}/attack-proposals` (operator+) → `proposed` Checkpoint (stores service+action_id +
params, NOT a command) → `approve_checkpoint` enforces the double gate (platform switch + per-project
toggle + exploit_confirmed / credential + optional four-eyes + rate-limit) → enqueues
`execute_approved_action`, which re-derives the command from the catalog, resolves the credential
server-side (secret redacted in previews/events), and calls the one door. Design: `docs/SPRAY_EXPLOIT_GATE.md`.

**Module map:** `routers/` (HTTP), `services/runs.py` (the run driver + attack executor), `orchestration/`
(states, limits, checkpoints, reaper, retention, tasks, admission), `engine/` (the read-only adapter:
gateway, shell_gateway, tools, workspace, creds_ref), `agents/` (LLM roster: roles, safety, dispatch —
dormant until the model is attached), `auth/` + `rbac.py` (sessions, OIDC, per-project RBAC/IDOR),
`bus.py` (Redis/Arq), `events/schema.py` (the canonical WS event envelope). Frontend: `pages/` +
`components/RunGraph.tsx` (Cytoscape map) + `ws/` + `theme.css`.

**Working agreement (how every change ships):** one PR per feature off `main`; the gate (ruff + mypy +
backend/invariant/frontend tests + `vite build`) must be green before merge; NEVER touch `src/oscprecon`;
keep `docs/DEFINITION_OF_DONE.md` (the fixed finish line) + this file current. Key docs: DESIGN.md,
DEFINITION_OF_DONE.md, SPRAY_EXPLOIT_GATE.md, deploy/RUNBOOK.md (+ smoke.sh), docs/OPERATOR_GUIDE.md,
docs/nabu-agent.html (leadership overview).

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
- WAVE 1 (deploy readiness). Found + fixed a REAL deploy blocker: `alembic upgrade head` on a fresh DB
  failed with "duplicate column heartbeat_at" — 0001 uses Base.metadata.create_all (reflects the full
  current model, incl. heartbeat_at) so 0002's blind add_column double-added it. Made 0002 idempotent
  (guard the column via inspector); verified `upgrade head` now creates all 15 tables + `downgrade base`
  works on a fresh sqlite. `docker-compose config` validates (6 services, env resolves, no undefaulted
  refs). Dockerfiles (Kali headless api/worker + nginx frontend) + Makefile reviewed — solid. Added
  NABU_ADMIN_EMAIL/PASSWORD to .env.example; corrected the stale README "Phase 0 scaffold" Status to
  feature-complete; wrote `deploy/RUNBOOK.md` (prereqs → configure → up → verify → wire LLM/OIDC → team
  → operate → upgrades/backups/troubleshooting/security). NOTE for Wave 2 hardening: bootstrap defaults
  NABU_ADMIN_PASSWORD='changeme' — enforce non-default in production.

- DONE (full code review + fixes — 4-dimension review: roster / runs+orchestration / org+dead-code /
  security). Verdict: the load-bearing SAFETY invariants HOLD (single shell chokepoint; exploit/spray
  only in execute_gated_action; attacks never an agent — no attack role/tool, SafetyGate hard-blocks;
  membership RBAC/IDOR closed). Fixes applied:
  * **Batch A (correctness):** health/main engine()→dispose bug (readiness DB check was always false +
    pool never disposed); retention prune now deletes ALL FK children (findings_index/artifacts/
    llm_call were missed → prune always rolled back → run cap never applied) + only prunes terminal
    runs; heartbeat now beats through cancel unwind (was stopping on cancel → reaper double-DONE
    race); reaper releases the admission slot (global counter + project mutex leaked on worker crash);
    admission-refused path suppress-guarded + no _EMIT_LOCKS leak. mypy 10→0.
  * **Batch B (security):** `_resolve_hosts` now drops swept hosts outside the scoped CIDR (the
    per-host assert_in_scope was tautological — real containment backstop now).
  * **Batch C (dead code + honesty):** deleted `agents/budget.py` (superseded by RoleDef inline
    enforcement) and `orchestration/blackboard.py` (moot — per-host Profiles make the single-writer
    design unnecessary); deleted the orphaned `Approvals.tsx`; wired the (now-fixed) Health page into
    the router+nav; removed dead `SafetyGate.assert_scope`/`needs_approval` + corrected its docstring;
    fixed `db/models` comments (role no longer names "attack"; Checkpoint lists the real `hosts` kind);
    trimmed unused CSS. Regression tests added (retention FK children, reaper slot release, out-of-scope
    host dropped). Gate: ruff clean, mypy clean, 75 tests (backend+load+invariant) + 18 frontend, build OK.
- CORRECTED DOC DRIFT: earlier claims that audit.py / rbac.py / orchestration/checkpoints.py were
  "done/full" were STALE — they are PLANNED stubs, NOT wired: `audit.py` (platform audit trail) writes
  no rows; `rbac.py` capability matrix is unenforced (only binary project membership is — fine today,
  since the only member is the owner; MUST be wired before member-provisioning ships); `checkpoints.py`
  spray/exploit approve/reject gate is unused (the host-count gate uses the DB-model flow). Test counts
  in this doc's older sections ("28/28") are stale — real: ~75 backend/load/invariant + 18 frontend.
- REVIEW FOLLOW-UPS (documented, NOT done): run-level LLM token ceiling + per-agent wall-clock are
  defined but unenforced (inert until the brain is attached — wire in run_role when LLM lands); wire
  rbac.can into start/cancel/scope/approve before member-provisioning; implement audit.py; the
  _run_real/_run_agent + _recon_host/_agent_host duplication + shared test-mock fixture could be
  factored; client-side WS reconnect/replay-by-seq isn't implemented.

- DONE (design pass — demo-ready UI). Rewrote `frontend/src/theme.css` into a cohesive dark design
  system: soft teal/green accent glow (radial backdrops), display/mono type scale, cards with hover
  lift + accent, status pills with animated live dots, refined inputs/buttons/nav (active glow bar),
  custom scrollbars, selection. Login is now a centered hero (brand + tagline + glowing card).
  RunLive (the showpiece) uses polished classes — glowing legend dots, a pulsing "live" recording
  indicator, cleaner map/log panels + approval bar. RunGraph nodes/edges upgraded (bigger, text
  outline for contrast, teal glow on active / blue on done / red-error / gold-stuck, kind shapes,
  radial map backdrop). Feed/Projects/ProjectDetail/Report inherit the system. All text preserved →
  18 frontend tests + build still green.

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

---

## 2026-09-10 — spray/exploit execution gate DESIGN + visual Help + UI aesthetic direction

- **Design doc: `docs/SPRAY_EXPLOIT_GATE.md`** — the plan for how a spray/exploit actually *runs*,
  the most safety-critical path, written before any code. Grounds itself in what exists
  (`engine/shell_gateway.execute_gated_action` = the one door; the `Checkpoint` DB row; the host-count
  approve/reject flow it reuses; project `spray_enabled`/`exploit_enabled` toggles; `catalog_actions_for`
  proposals with the `executable` flag; `CHECKPOINT_DECIDE` perm). Specifies: the propose→approve→execute
  state machine; a NEW `orchestration/tasks.execute_approved_action` Arq job; a NEW
  `POST /runs/{id}/attack-proposals`; lifting the approve endpoint's non-`hosts` refusal behind a double
  gate. **Key safety decision:** the checkpoint stores `action_id`, NOT a command — the executor
  re-derives the shell line from the catalog at execute time, so a forged/edited command is impossible.
  Defence-in-depth stack: Gate 1 project toggle → Gate 2 human approval (+ exploit_confirmed / creds) →
  server-side command re-derivation → scope re-validation → the one door → `NABU_AUTONOMY` kill-switch.
  Phase A (human-driven: operator proposes from the catalog → approves → runs) is buildable NOW with no
  LLM; only agent-*initiated* proposals (Phase B) need the model. New invariant tests spelled out. No
  code shipped yet — this is the plan; it changes nothing until built and never touches `src/oscprecon`.

- **Visual Help page (`frontend/src/pages/Help.tsx`)** — rebuilt the in-app guide as visual-first for
  visual learners: four inline HTML/CSS diagrams (no external libs, theme-aware, honour
  prefers-reduced-motion) — (1) *how a run flows* the agent chain + the human-gated attack branch,
  (2) *anatomy of a run* the lifecycle rail, (3) *live map colours* glowing-orb legend, (4) *the safety
  gate* the two-locks diagram. All prose headings preserved. New diagram CSS appended to `theme.css`
  (`.diagram/.flow/.fnode/.life/.legend/.pulse`, danger=red / gate=gold styling). Help test extended
  (visual sections asserted). Gate: tsc clean, **24 frontend tests** (was 23) + `vite build` OK.

- **UI aesthetic direction (owner):** standing preference for a **hacker-artsy, aesthetically-pleasing**
  UI — apply to all new UI work (recorded in memory `ui-aesthetic-hacker-artsy`). The dark teal/green-on-
  near-black + JetBrains Mono theme is the base; go further with tasteful glow, monospace texture, and
  restrained motion on live state. The attack-gate UI section of the design doc already reflects this
  (amber→red danger palette, terminal-panel command preview, glowing live attack node).

- README doc list updated to link `docs/OPERATOR_GUIDE.md` + `docs/SPRAY_EXPLOIT_GATE.md`.

---

## 2026-09-10 — spray/exploit execution gate, Phase A (human-driven) SHIPPED

Built the human-driven attack path from `docs/SPRAY_EXPLOIT_GATE.md` — no LLM required. Recon stays
automated; an attack runs only when a human approves a specific action behind the double gate.

- **Propose** — `POST /runs/{id}/attack-proposals` (operator+ via `CHECKPOINT_DECIDE`; viewers 403).
  Validates target ∈ scope + that `action_id` resolves to an attacker-runnable, fully-filled catalog
  command (the same server-side derivation the executor uses → the response's command preview is
  truthful). Creates a `proposed` Checkpoint (kind spray|exploit; service stored in `requires`);
  emits CHECKPOINT_REQUESTED + APPROVAL_REQUIRED (attack map node) + audits `attack-proposed`. Never
  runs anything.
- **Approve (double gate)** — the approve endpoint now handles spray/exploit (previously refused): it
  requires the **platform switch** (`NABU_SPRAY_ENABLED`/`NABU_EXPLOIT_ENABLED`, default off) AND the
  **per-project toggle** AND, for exploit, `exploit_confirmed=true`, AND, for spray, a `credential_ref`.
  On success it stamps `approved_by`/`approved_at` and **enqueues** `execute_approved_action` (Arq in
  prod, in-process task in dev/tests). Reject marks rejected. `GET checkpoints` enriches spray/exploit
  rows with a live command preview + gate state.
- **Execute** — `services/runs.execute_approved_action(cp_id)` (registered as the Arq task in
  `worker.py`): re-verifies the approval, re-checks platform + project gates, opens the target's own
  profile, **RE-DERIVES the command from the catalog by action_id** (the checkpoint stores no command —
  a forged command can't reach the executor), then hands it to `shell_gateway.execute_gated_action` —
  the ONE place spray=/exploit=True is set, which itself re-verifies the approval + re-validates scope.
  Streams a dedicated `attack-{cp}` node (active→done/error) + log onto the run; marks the checkpoint
  executing→executed/failed; best-effort run-state EXECUTING_APPROVED→REPORT_READY (guarded by
  `_try_set_state`, so attacking a finished recon run is fine). App-audits `attack-executed`. Never
  raises — a gate/derive/door failure marks the checkpoint FAILED + a red node.
- **UI** — Report page gained a danger-styled "⚔ Attack actions" panel (`pages/AttackGate.tsx` +
  `theme.css` .atk-*): lists runnable catalog actions with a monospace command preview + Propose;
  shows gated proposals with the two gate lamps, an exploit-confirm checkbox / credential picker, and
  a red **Approve & run** (disabled until the gates + requirement are satisfied), then live-polls the
  status. Honours the hacker-artsy direction.
- **Enums/audit:** CheckpointStatus += EXECUTING/FAILED; audit slugs += ATTACK_PROPOSED/ATTACK_EXECUTED.
- **Tests:** `tests/integration/test_attack_gate.py` (6) — happy path (executed command == catalog
  command, door got a real approval), platform-off blocks approval, spray needs a credential, bad
  action_id not proposable, out-of-scope 403, viewer can't propose. `frontend/pages/AttackGate.test.tsx`
  (2). Also **declared the test deps** `fakeredis` + `aiosqlite` in the dev group (they were undeclared
  — a `uv sync` produced a venv that couldn't run the suite; now `uv sync --group dev` is enough).
- Gate: ruff + mypy clean (78 files); **107 backend** (was 101) + 10 invariant + **26 frontend** (was
  24); `vite build` OK; `src/oscprecon` untouched. Policy invariants still pass (the new job calls the
  door, never `shell.run`). Phases B–D remain; only Phase B (agent-*proposed* actions) needs the LLM.

---

## 2026-09-11 — Definition of Done written + attack gate Phase C SHIPPED

- **`docs/DEFINITION_OF_DONE.md`** — the fixed completion standard (owner asked for a defined finish
  line instead of ad-hoc phases). Tier 1 = Dev-Complete (drive to 100% now): baseline + Phase A done;
  REQUIRED remaining = (1) attack Phase C, (2) attack Phase D dry-run, (3) distributed smoke script.
  Tier 2 = LLM-gated (parked). Dev-side is "done" when items 1–3 are checked.
- **Attack gate Phase C (PR #47)** — attacks are now genuinely usable + safe:
  - Credential injection: a chosen vault credential fills `{user}/{username}/{password}/{hash}/{ntlm}/
    {domain}`; resolved server-side at execute time from creds.json, NEVER stored on the checkpoint.
    New shared helper `engine/creds_ref.py` (`credential_cid`/`resolve_credential`/`credential_values`);
    `routers/creds.py` `_cid` now delegates to it (no drift).
  - Operator params: the proposal carries a `params` map filling non-credential placeholders
    (`{wordlist}/{lhost}/{command}` …). An action is proposable only once EVERY placeholder resolves;
    otherwise 422 "needs: …". `_resolve_gated_command` gained `_gated_values` (target + discovered
    port + params + credential).
  - Secret redaction: previews (`_preview_command`, GET checkpoints) and the execute log line use an
    ALWAYS-ON mask (`credential_values(redact=True)` → `<password:redacted>`), deliberately NOT the
    engine's `creds.redact` (a no-op unless a report flag is set). Execution passes the real secret only
    to `execute_gated_action`. Verified: no run event contains the plaintext.
  - Attack cap: `RunLimits.max_gated_actions_per_run` (25); propose past it → 409.
  - Result recording: after a non-blocked run the target is appended to the credential's
    `tested_against` via `profile.replace_credential`; the attempt is appended to `run.summary["attacks"]`.
  - UI (`pages/AttackGate.tsx`): runnable actions now show a credential picker + a text input per
    remaining placeholder; Propose is disabled until all are filled; gated-proposal card unchanged
    (command already redacted by the API).
- **Tests:** `test_attack_gate.py` → 8 (credential injected at execute but redacted in preview + no
  event leaks it + tested_against recorded; operator params fill/needs-message; spray needs a credential
  then runs; per-run cap; + the Phase A gate refusals). `AttackGate.test.tsx` → 3 (cred picker + param
  input gate the Propose button).
- Gate: ruff + mypy clean (79 files); **109 backend** + 10 invariant + **27 frontend**; `vite build` OK;
  `src/oscprecon` untouched. NOTE: audit writes warn "no such table: audit_log" in the TEST env only
  (conftest create_all doesn't build that table; audit is best-effort so it's swallowed) — pre-existing,
  cosmetic, not introduced here. Next: item 2 (D1 dry-run), then item 3 (S1 smoke).

---

## 2026-09-11 (cont.) — Phase D dry-run + distributed smoke script → DEV SIDE DONE

- **Attack gate Phase D — dry-run (PR #48):** `ApproveBody.dry_run`; approving with `dry_run:true`
  runs the full resolve-and-show path (opens the profile, re-derives the command with creds/params,
  emits a redacted "would run: …" log + a done attack node, marks the checkpoint `dry-run`, records
  the attempt in `run.summary`) but **never calls `execute_gated_action`** — a safe rehearsal. New
  `CheckpointStatus.DRY_RUN`. UI: a **Dry run** button beside Approve (same gate enable). Test asserts
  the door is never called and the log shows the command (redacted).
- **Distributed smoke (PR #48):** `deploy/smoke.sh` — waits for `/api/health/ready`, logs in, creates
  a project + scope, starts a real `scan`, polls to a terminal `done`/`partial` (exercises the Redis +
  Arq worker fan-out). Env-configurable (BASE/TARGET/ADMIN_*/TIMEOUT/SMOKE_UP); `bash -n` clean;
  referenced from RUNBOOK §4. (Executed by a human in a real cluster — can't run a live cluster here.)
- **`docs/DEFINITION_OF_DONE.md`: all three required Tier-1 items now checked → THE DEV SIDE IS DONE.**
  Gate: ruff + mypy clean; **110 backend** + 10 invariant + **27 frontend**; `vite build` OK; policy
  invariants hold; `src/oscprecon` untouched. Remaining = Tier 2 (LLM-gated: attach the model, Phase B
  agent-proposed, run-level budgets, live agent-run validation) + the explicitly-optional polish.

---

## 2026-09-11 (cont.) — autosync cron PAUSED + attack-path hardening (optional, PR #49)

- **Autosync cron PAUSED:** the hourly `git add -A && commit "autosync github" && push github main`
  crontab line is commented out (crontab backed up locally outside the repo; the
  3-hourly rsync line left active). Restore by uncommenting that line. No more WIP landing on main.
- **Attack-path hardening (optional DoD item, PR #49)** — real safety controls for a tool that fires
  exploits, both default OFF (platform settings, no DB migration):
  - `NABU_REQUIRE_TWO_APPROVERS` — **four-eyes**: a real exploit approval records approver #1 and stays
    `proposed` until a SECOND, DISTINCT approver confirms; the same user is refused (409). Dry-run is
    exempt. The gate view carries `two_person` + `first_approver` so the UI shows "approved by 1 —
    a different second approver must confirm".
  - `NABU_ATTACK_MIN_INTERVAL_S` — **cooldown** (Redis, per project) between gated executions; a second
    approve inside the window → 429 + Retry-After. `bus.attack_cooldown_ttl`/`set_attack_cooldown`.
  - Tests: `test_attack_gate.py` → 11 (four-eyes: #1 doesn't execute, same user 409, distinct #2 runs;
    cooldown 429). Gate: ruff+mypy clean; 112 backend + 10 invariant + 27 frontend; vite build OK.
- These were the OPTIONAL items in the DoD; the required Tier-1 set was already done (#47/#48). Remaining
  = Tier 2 (LLM-gated) + the throughput micro-opts (still optional).

---

## 2026-09-11 (cont.) — live-map relayout debounced (PR #50)

- `components/RunGraph.tsx`: the breadthfirst layout used to re-run on EVERY event (a wide fan-out →
  dozens of relayouts/sec → jank). Element upserts stay immediate (nodes/colours appear at once); the
  expensive relayout is now **debounced 150ms** so a burst settles into one layout. Timer cleared on
  unmount. Gate: tsc clean, 27 frontend tests, vite build OK.
- The other throughput ideas (batching `_emit` DB commits, WS-replay paging) are **deliberately
  de-scoped** — they touch the seq-ordered event pipeline the WS live-tail dedup relies on, so the
  correctness risk isn't justified without a measured bottleneck. Recorded in DEFINITION_OF_DONE.md.
- With this, the buildable dev surface is genuinely exhausted: required Tier-1 done (#47/#48), both
  optional attack-hardening + the safe throughput opt done (#49/#50). Everything remaining is Tier 2
  (LLM-gated) — blocked until the model is attached.

---

## 2026-09-11 (cont.) — full code review + fixes (31 findings, 30 fixed)

Ran a 6-dimension adversarial code review (bugs, error-handling/logging, safety, async/lifecycle,
organization, tests). 31 findings confirmed; **30 fixed**, 1 documented-as-intended. Highlights:

**Safety (high):**
- **Scope-lock bypass** — operator `params` could override `{target}` and send an approved attack
  off-scope. `_gated_values` now drops host-alias params and re-pins every host placeholder to the
  profile's authorized target (regression test added).
- **Credential in audit.jsonl** — the engine's redactor ships OFF, so the gated door was persisting
  the plaintext secret. Added a nabu-owned `_redact` mask (scrubs `-p`/`-H`/`--password`… tokens)
  independent of the engine flag.
- **Double-execute** — `execute_approved_action` now atomically claims a checkpoint (approved→executing)
  so a raced approval can't run it twice.

**Error handling / logging (owner priority):** run_id now bound (`bind_run`) into contextvars at every
run entrypoint so all log lines carry it; request_id added to the 500/engine-error log lines;
`verify_password` no longer swallows backend errors silently; the SafetyGate autonomy-block, WS
spool drops, dispatch tool failures, gateway profile-skip, OIDC login failures, and the cancel-watch
Redis outage are all now logged (several were silent); cancel-watch bumped debug→warning. The
ATTACK_EXECUTED audit is now written BEFORE the terminal state (was racing test teardown → the
"no such table" noise is gone) and is asserted by a test.

**Leaks/lifecycle:** per-run LLM client now closed on all paths (`provider.aclose()`); `_EMIT_LOCKS`
is a WeakValueDictionary (no unbounded growth on a long-lived worker); the attack heartbeat is
cancelled (no ~10s slot hold); worker on_shutdown closes the bus Redis client + Arq pool.

**Organization:** deleted 4 dead modules (`orchestration/checkpoints.py`, `orchestration/runmap.py`,
`ws/hub.py`, `llm/retry.py`) + 4 unused helpers; de-duplicated `_scope_for` into `routers/_common.py`;
renamed a shadowed loop var in RunLive.tsx.

**Tests:** +4 (params scope-pin regression, ATTACK_EXECUTED audit assertion, project-toggle-off
refusal, the door's unconfirmed-exploit re-gate). Suite: 116 backend + 10 invariant + 27 frontend.

**Documented as intended (not a bug):** the executed command is re-derived from live profile state at
execute time (not bound to the approval-time preview). This is the deliberate safety property (the
checkpoint stores an action id, never a command); the scope-pin fix above closes the only way a
re-derivation could have gone off-target. A stricter "pin the exact approved command" is a possible
future hardening but is not required.

Gate: ruff + mypy clean (76 source files); `vite build` OK; `src/oscprecon` untouched. Demo refreshed
(attack gate) at https://claude.ai/code/artifact/68d8ab3a-2351-4d06-8bb6-742190d69846 ; leadership doc
`docs/nabu-agent.html` updated (Phase 5 + demo link).

---

## 2026-09-11 (cont.) — admin LLM setup is now a real FORM (attach from the UI, no restart)

The admin "Connect the LLM brain" page went from view-status + env-directions to a guided **form** that
saves the config to the DB and applies it at runtime — no editing env files, no container restart.
- `config_store.py` — Fernet encrypt/decrypt keyed off `NABU_SESSION_SECRET`; the api key is stored
  ENCRYPTED and never returned by the API.
- `db.models.AppSetting` (key/value; covered by the 0001 create_all baseline) holds the saved override.
- `services/llm_config.py` — `save` / `clear` / `status` / `effective_llm_settings(overrides?)`: env
  defaults + saved DB override merged on top (+ an ephemeral override for test-before-save).
- `routers/admin.py` — `GET /admin/llm/config` (status incl. source env|saved|none), `PUT` (save),
  `DELETE` (revert to env), `POST /admin/llm/test` (test-fire; accepts inline values to validate
  BEFORE saving). Admin-only; audited.
- The run driver (`run_host_in_worker`, `_run_multi`) + `/llm/health` now build the provider from
  `effective_llm_settings()`, so a UI-saved config drives agent runs live.
- `pages/LlmSetup.tsx` — a step-by-step guided form: Base URL / Model / API key (write-only) /
  Organization / Advanced (temp, tokens, context, timeout, TLS) + **Test connection** (latency +
  token metrics) + **Save & attach** + **Clear saved**. Keeps the env-var alternative in a details block.
- Tests: `test_llm_config.py` (save/test/effective roundtrip + key encrypted-at-rest + never returned +
  non-admin 403; test-before-save). 119 backend + 28 frontend; ruff + mypy clean; `cryptography` added
  to deps. **L1 mechanism is now fully built — attaching a real endpoint is still legal-gated, but the
  admin does it in the UI, not by editing env.**

---

## 2026-09-11 (cont.) — recon map overhauled to BloodHound-style (full-screen + phases + pulse)

The live run view now looks like the classic Nabu GUI's BloodHound graph (owner request), drawing on
`src/oscprecon/gui/graph_html` for the palette + force layout.
- `components/RunGraph.tsx`: force-directed **cose** layout (BloodHound feel; Hierarchy = breadthfirst),
  coloured discs by node KIND using the GUI's Catppuccin palette (target #1e3a8a, host #74c7ec,
  service #89b4fa, finding #f9e2af diamond, report #cba6f7 star, attack #f38ba8), thick live STATE
  rings, and a **pulsating-green "digging" halo** on active nodes (a ping-pong overlay animation;
  honours prefers-reduced-motion). New `layoutName` + `fitNonce` props.
- `pages/RunLive.tsx`: full-screen layout with a **phase stepper** (Queued → Scanning → Enumerating →
  Researching → Reporting → Done) driven by the run's live state — the current phase pulses green — a
  **controls toolbar** (Force/Hierarchy toggle, Fit, Hide log, Cancel run), and the log/approval banner.
- `theme.css`: `.phases`, `.map-controls`, `.map-body` (full-height grid).
- Demo (`68d8ab3a…`): the Live-map tab rebuilt to match — big BloodHound spider, phase stepper,
  pulsing-green nodes, layout toggle + Fit + Cancel, a node-type legend + a **run-config panel**, and
  the live log. Verified via headless-chromium screenshot.
- Gate: tsc clean; 28 frontend tests; `vite build` OK. Backend untouched.

---

## 2026-09-11 (cont.) — recon map: verified in the real app + BloodHound augmentation

- **Verified the real app renders** (not just the demo): built a throwaway Vite harness that mounts the
  real `RunLive`+`RunGraph` (real Cytoscape) with stubbed ws/api, drove it with real run events, and
  screenshot it over http (file:// blocks ES modules) — the phase stepper, force graph, active-green
  rings, error node, controls, and log all render. Harness was removed after.
- **Augmented toward SpecterOps BloodHound** (which uses Sigma.js + a force layout): added TYPE GLYPHS
  inside the node discs (target crosshair / host / service / agent icons, SVG background-images),
  widened the cose spread (nodeRepulsion/idealEdgeLength/componentSpacing + nodeDimensionsIncludeLabels
  so labels stop colliding), and BloodHound's signature **hover-to-highlight-neighbourhood** (dim the
  rest via a `.faded` class) + **click-to-select a node → a details drawer** (`onSelect` prop +
  `.node-drawer`). Demo mirrors it (glyphs + hover-dim). tsc clean; 28 frontend tests; vite build OK.
