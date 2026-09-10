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
- **Repo:** `git@github.com:7H35C4r3Cr0W/recon.git` · working branch **`nabu-agent-scaffold`**.

---

## Current position

```
DATE:        2026-09-09
BRANCH:      nabu-agent-scaffold
PHASE:       Phases 0, 1, 4 DONE — scaffold committed + pushed + PR open
DOING NOW:   (idle) — awaiting review
NEXT UP:     Phase 2 (MVP thin slice) in a later session — resume at step 2.1
PR:          https://github.com/7H35C4r3Cr0W/recon/pull/1  (commit b551866, 123 files)
BLOCKERS:    none
VERIFIED:    122 files; 71 backend .py compile clean; engine seam imports against REAL oscprecon
             with PySide6 NOT loaded (headless holds); 12/12 policy-invariant + unit tests PASS;
             docker-compose + seccomp + CI YAML valid.
NOT DONE:    manager HTML, GitHub push; then MVP wiring (Phase 2) + hardening (Phase 3) later.
```

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

- [ ] **2.1 Test harness** — `tests/conftest.py`: async in-memory SQLite (`aiosqlite`) engine +
  `Base.metadata.create_all` fixture; `fakeredis.aioredis` fixture; a FastAPI `TestClient`/`httpx`
  fixture with dependency overrides (`get_db`, redis, and the engine adapter mocked). Deps already in
  the test venv (`.venv-agent`): `pytest-asyncio`, `aiosqlite`, `fakeredis`.
- [ ] **2.2 DB session wiring** — make `db/session.py` build the engine from `Settings.database_url`
  lazily (not at import) so tests can point it at sqlite; add `create_all()` helper for dev/test;
  keep `get_db` the injected dependency.
- [ ] **2.3 Auth (local first)** — implement `auth/providers.LocalProvider` (argon2 verify),
  `auth/sessions` (redis-backed opaque session in the httpOnly cookie), `auth/deps`
  (`get_current_user`, `require_role`, `require_project_role`, `csrf_protect`), and
  `bootstrap.seed_admin`. Wire `routers/auth.py` login/logout/me. OIDC stays scaffolded.
- [ ] **2.4 Projects + scope** — `routers/projects.py` create → `engine.gateway.create_project_profile`
  (`Profile.create`), list/get/patch, members, settings (spray/exploit gates, admin only);
  `routers/scope.py` allowlist CRUD with `models.validate_host_or_range` + human-gated promote. RBAC
  via `auth/deps`. Platform-audit each mutation (`nabu_agent.audit`).
- [ ] **2.5 Runs API** — `routers/runs.py`: `POST /projects/{id}/runs` → `assert_in_scope` +
  RBAC + gating + `admission.acquire_run_slot` + enqueue `supervise_run`; `GET /runs/{id}` (+ tasks),
  `POST /runs/{id}/cancel`. Persist `runs`/`agent_tasks`/`run_events` (monotonic `seq`).
- [ ] **2.6 Orchestration (single target, no fan-out)** — implement `bus.py` (redis enqueue /
  cancel-flag / publish-subscribe), `orchestration/admission.py`, the single-writer `blackboard.py`,
  and `orchestration/tasks.supervise_run` for ONE host: validating → alive_check (`check_alive`) →
  scanning (`run_scan`) → enriching (one `enum_service` per discovered service, still serial) →
  synthesizing (`generate_report`) → report_ready. Engine calls run in a worker thread; cancel flag →
  `threading.Event`; idempotency key; blocked/missing_tool recorded, never retried → `partial`.
- [ ] **2.7 WebSocket** — `ws/hub.py`: cookie-auth handshake, replay `run_events` by `seq` then tail
  the redis `run:{id}` channel, ~20s heartbeat, ~250ms coalescing of `task.updated`/`log.line`.
- [ ] **2.8 Reports/findings** — `routers/reports.py` (`gateway.render_report`, artifacts) +
  `routers/findings.py` (`gateway.list_findings/list_services/build_graph`); apply
  `agents/report_grounding.validate_claims` and delimit AI-narrative.
- [ ] **2.9 Frontend** — finish `api/client.ts` + `ws/client.ts`; build the pages: Login, Projects
  (list + create + scope), RunLive (task tree + streamed log via WS), Report. Route guards on auth.
- [ ] **2.10 Integration tests** — happy path: login → create project (mock `Profile.create`) →
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
