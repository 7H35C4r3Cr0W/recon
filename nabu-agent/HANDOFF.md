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

## Phase 2 — MVP thin slice (next session)

- [ ] **2.1** End-to-end: log in → create project + authorized scope → start recon run → supervisor fans out per-service/research/writer agents → live WebSocket progress → clean report + next steps.

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
