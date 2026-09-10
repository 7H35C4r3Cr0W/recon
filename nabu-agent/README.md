# Nabu Agent

**An internally-hosted, agent-driven automation of the classic [Nabu](../README.md) (`oscprecon`)
recon tool.** An operator logs into a web platform, creates a scope-limited engagement project,
launches an autonomous recon run against an IP or IP/range, watches a live agent-task tree stream to
the browser, and reads a grounded report + next steps — while every attack action (spray/exploit)
stays behind an explicit human gate.

> This is a **separate product** that lives beside the classic desktop tool in the same repo. It
> **never modifies `src/oscprecon`** — the engine is a read-only dependency. See
> [`docs/DESIGN.md`](docs/DESIGN.md), [`docs/ROADMAP.md`](docs/ROADMAP.md),
> [`docs/ENGINE_INTEGRATION.md`](docs/ENGINE_INTEGRATION.md), and the live progress tracker
> [`HANDOFF.md`](HANDOFF.md).

## Brain / body / hands

| Layer | What | Who provides it |
|---|---|---|
| **Brain** | The LLM that plans, chooses tools, writes prose. | **The owner attaches it** — an internally-hosted, OpenAI-compatible endpoint (GPT-5.1 today). Point `NABU_LLM_BASE_URL` at it. Fully swappable via `NABU_LLM_PROVIDER`. |
| **Body** | This project — FastAPI edge, Arq orchestration, engine adapter, Postgres/Redis, React SPA. | Built here. |
| **Hands** | `oscprecon` — the recon engine + its allow-listed tools. | Read-only dependency; the sole executor of tools via `shell.run`. |

## The six non-negotiables (carried over from classic Nabu, enforced in code)

1. `src/oscprecon` is **read-only** (CI fails any PR that diffs it).
2. A **single `shell.run` chokepoint** — only `nabu_agent/engine/shell_gateway.py` calls it.
3. **Authorized-scope-only** — every target validated by the engine's validators *and* confirmed in
   the project's scope allowlist before any tool runs.
4. **No blind auto-exploit / double-gated spray** — recon is automated; spray/exploit need a
   per-project toggle **plus** a human-approved checkpoint. `exploit=True` lives in exactly one
   human-gated executor, unreachable from any agent path.
5. **Swappable OpenAI-compatible LLM seam** — endpoint/model from config, no vendor SDK.
6. **Recon automated, attack human-gated.**

## Architecture (one glance)

```
Browser SPA ── nginx ──> FastAPI api (REST + WebSocket, runs NO tools)
                              │  enqueue                    ▲ read-only engine facade
                              ▼                             │
                           Redis (queue + pub/sub) ──> Arq worker(s)
                                                          │  AgentRunner (LLM loop)
                                                          ▼
                              engine/shell_gateway.py  ── the ONE shell.run chokepoint
                                                          ▼
                              oscprecon (imported, read-only)  ──> /workspace (Profiles)
                           Postgres: users/projects/scope/runs/agent_tasks/checkpoints/...
```

Full detail in [`docs/DESIGN.md`](docs/DESIGN.md). Interactive overview:
[`docs/nabu-agent.html`](docs/nabu-agent.html).

## Quickstart (Phase 0 scaffold)

```bash
cd nabu-agent
cp .env.example .env                     # fill NABU_SESSION_SECRET + NABU_LLM_BASE_URL/API_KEY
mkdir -p secrets && echo "$(openssl rand -hex 16)" > secrets/postgres_password.txt
make up                                  # docker compose up --build (migrates + seeds admin)
# → SPA behind nginx on https://127.0.0.1:8443 ; GET /api/health/ready returns readiness
```

Local dev without Docker: `uv sync` then `make fe-dev` (Vite) + `uvicorn nabu_agent.main:app --reload`.

## Status

Phase 0 (runnable scaffold) — see [`HANDOFF.md`](HANDOFF.md) for the live step tracker. The engine
adapter, the single chokepoint, the LLM provider seam, the data model, and the policy-invariant
tests are in place; agent fan-out + the LLM loop are scaffolded and filled in Phases 1–3.
