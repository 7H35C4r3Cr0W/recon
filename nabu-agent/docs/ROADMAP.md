# Nabu Agent — ROADMAP.md

Five phases. Each phase has explicit **exit criteria** that must all pass before the next begins. Every phase keeps `src/oscprecon` untouched and the policy-invariant CI gate green.

---

## Phase 0 — Runnable scaffold (foundation)

**Goal:** clone → `docker compose up` reaches a healthy stack; one canonical package root; safety guardrails scaffolded and testable; nothing agent-shaped yet.

**Work**
- Bind the **one package root** decision (`nabu_agent/`); delete the `backend/app/` and `src/nabu_agent/` drafts by merging their files in.
- `pyproject.toml`: full runtime deps (fastapi, uvicorn[standard], pydantic, pydantic-settings, sqlalchemy[asyncio], asyncpg, alembic, redis, arq, authlib, argon2-cffi, pyjwt, itsdangerous, python-multipart, email-validator, httpx[http2], structlog, jinja2, tenacity, opentelemetry-*) + dev group (pytest, pytest-asyncio, pytest-cov, ruff, mypy) + `[tool.pytest.ini_options]` registering the `invariant` marker + ruff/mypy config. Engine as **non-editable** path dep (`{ path = "..", editable = false }`).
- Boot entrypoints: `main.py` (app factory + lifespan) and top-level `worker.py` (WorkerSettings, two pools). `health.py` (`/health`, `/health/ready`).
- `db/models.py` (full ORM) + Alembic init + initial migration; one-shot `migrate` compose service; `bootstrap.py` seeds first admin.
- `settings.py` unified config; complete `.env.example`; secrets (session_secret, llm_api_key, TLS cert/key) wired as docker secrets.
- Engine seam skeleton: `engine/shell_gateway.py` (the single chokepoint — `run_recon_tool` + `execute_gated_action` signatures), `engine/errors.py`, `engine/schemas.py`, `engine/workspace.py`, `engine/settings.py`, `engine/gateway.py` (read-only facade).
- `events/schema.py` canonical envelope; `bus.py`.
- Deploy: `docker-compose.yml` (five services + migrate, least-privilege, init/tini), `Dockerfile.api` (headless, no Qt), `Dockerfile.frontend`, `nginx.conf`, `seccomp/worker.json`.
- Frontend scaffold: Vite+TS+React, router, empty login + health page, typed API/WS client stubs.
- CI: `nabu-agent-ci.yml` — ruff, mypy (pointed at `nabu_agent/`), unit (`-m 'not invariant'`), **separate policy-invariant gate** (`-m invariant`), hygiene job (fail on `src/oscprecon` diff), frontend lint/build, docker build, alembic-diff, secret scan.
- Policy-invariant tests: single-chokepoint AST scan (asserts SRC root exists + non-empty), no subprocess/shell=True, `exploit=True` only in `execute_gated_action`, `run_recon_tool` has no exploit/spray param, headless (no PySide6).

**Exit criteria**
- [ ] `docker compose up` brings all five services healthy; `GET /api/health/ready` returns 200 (DB+Redis+engine-import+workspace).
- [ ] `alembic upgrade head` runs via the migrate service; all tables exist; first admin seeded.
- [ ] Frontend builds and serves; login page renders behind nginx; `/api` and `/ws` proxy correctly.
- [ ] CI green: lint, mypy on the real package, unit, **policy-invariant gate**, hygiene, docker build, secret scan.
- [ ] The invariant suite proves: exactly one `shell.run` caller module; `exploit=True` nowhere except `execute_gated_action`; no subprocess/shell=True; engine tree untouched.

---

## Phase 1 — Engine seam + chokepoint (real recon, no agents)

**Goal:** a run can execute real recon against one authorized IP through the single chokepoint, end to end, driven by the API (not yet by an LLM).

**Work**
- Implement `engine/tools.py`: `check_alive` (`alive.build_alive_command`/`parse_alive`), `run_scan` (`Orchestrator(profile, on_line=, scan_profile=, cancel=).run_nmap()`), `list_discovered_services`, `enum_service` (`SmbEnum/FtpEnum/SshEnum/DnsEnum/LdapEnum`, `mode='full'`, `ReconAuth.from_credential`), `research_finding`, `suggest_next_steps` (`patterns.engine.suggest_for`), `generate_report` (`Reporter(profile).render()`), `catalog_actions_for` (display-only: `exploit.build_context`/`rank_actions`/`suggested_action_ids`).
- Implement `shell_gateway.run_recon_tool` (per-step `timeout=`, PGID registry, `raise_for_result`, `audit`) and `assert_in_scope` (format validators + `scope_targets` membership: exact host / CIDR containment / promoted row).
- Implement `workspace.py` mapping (one Profile per host for CIDR; single Profile for single host); single-writer `blackboard.py`.
- Orchestration for a **single-target scan run**: `states.py`, minimal `tasks.supervise_run` (no fan-out yet), `worker.py` execution in worker threads, cancellation (Redis cancel flag → threading.Event, PGID confirm-dead), idempotency key.
- Runs router: `POST /projects/{id}/runs` (scope + RBAC + enqueue), `POST /runs/{rid}/cancel`, task-tree snapshot; `run_events` persistence.
- Admission control: one active run per project; global run cap.

**Exit criteria**
- [ ] A run against one authorized host performs a real nmap scan + at least one service enum through `run_recon_tool`; `findings_index`/`services_mirror` populate from the Profile.
- [ ] Out-of-scope target is refused at the API (403 ScopeViolation) and never enqueued; an in-scope host inside a CIDR is accepted.
- [ ] Cancel kills the process group (verified: no orphan nmap after cancel or worker SIGTERM); `job_timeout` also kills the tool.
- [ ] A retried job that already ran does **not** re-execute the tool or double-add findings.
- [ ] `blocked` (126) / `missing_tool` (127) recorded as data, surfaced, never retried; run can end `partial`.
- [ ] Two audit trails present: engine `audit.jsonl` entry for the tool run + Postgres `audit_log` "run-started".

---

## Phase 2 — MVP thin slice (login → project → run recon → live progress → report)

**Goal:** the demonstrable end-to-end product for one operator: sign in, create a scoped project, launch a recon run against one IP, watch it live, read the report.

**Work**
- Auth: local `LocalProvider` login + Redis session cookie; OIDC path scaffolded but local is sufficient for MVP; RBAC dependencies enforced.
- WS hub: cookie-auth handshake, replay `run_events` by seq then tail Redis, heartbeat, coalescing.
- Frontend pages: login, project list, create-project (+ scope entry), run launch, **live run view** (agent-task tree + streamed log lines + status), findings list, report view. Typed WS client bound to the canonical envelope.
- `engine/gateway.py` read-only endpoints wired: report render, findings/services/graph, activity (`audit.load_entries`).
- Report grounding validator applied to `generate_report` output; AI-narrative sections delimited (even though single-target recon is mostly ground-truth here).
- Error contract: global exception handler + code→status mapping live.

**Exit criteria**
- [ ] From a clean deploy: operator logs in, creates a project with one in-scope IP, starts a recon run, sees live progress over WebSocket (with heartbeat, no idle-timeout drop), and views a rendered report — no manual DB/CLI steps.
- [ ] A browser that reconnects mid-run reconciles to the same task tree (replay-by-seq verified).
- [ ] Report claims are backed by engine artifacts; the grounding validator flags/rejects an injected unbacked claim in a test.
- [ ] Secrets do not appear in `run_events`/WS payloads (cred_ref only); `creds.json` remains 0600 on the workspace volume.
- [ ] Happy-path API + WS integration test green in CI.

---

## Phase 3 — Agent fan-out (autonomous multi-agent recon)

**Goal:** the supervisor + fan-out agent graph with a real LLM brain drives multi-service, multi-host recon; spray/exploit remain human-gated proposals.

**Work**
- LLM seam: `openai_compat.py` (SSE + tool_call delta reassembly), `factory.build_provider`, `retry.py`, `tokens.py`, `GET /api/llm/health`.
- `AgentRunner` loop with `SafetyGate` (delegating scope to the chokepoint), `ToolRegistry`/`ToolDispatcher` (routing through `run_recon_tool`), `ContextAssembler` (notable-findings-only research, `budget_fit`), `BudgetStore` (atomic run-level `DECRBY` + per-agent ceilings), streaming to the bus.
- Non-blocking supervisor + re-trigger-on-last-finisher barrier; separate supervisor/agent-work pools; `max_total_tasks` cap; per-host re-validation on CIDR fan-out.
- Checkpoints: research/writer agents surface spray/exploit `Checkpoint` proposals; `awaiting_approval` state; `POST /checkpoints/{cid}/decision`; `execute_gated_action` executes an approved checkpoint (the sole `exploit=True`/`spray=True` site) with server-minted non-forgeable checkpoint id.
- Frontend: approvals screen, catalog/suggestions (display-only), per-agent usage/budget view.

**Exit criteria**
- [ ] A CIDR run fans out per live host and per discovered service; results join via the barrier without supervisor slot starvation (verified under concurrent runs).
- [ ] Two hosts with the same finding value are both reported (per-host Profile prevents `findings._key` collision).
- [ ] A spray/exploit proposal parks the run in `awaiting_approval`; execution occurs **only** after a human approves the checkpoint; an agent-supplied/unapproved token is refused (invariant test).
- [ ] Run-level token ceiling is enforced atomically under concurrency; an over-budget agent stops cleanly with `stopped_reason=budget`.
- [ ] Prompt-injected "run exploit" in tool output does not reach an exploit call (SafetyGate + no exposed param); LLM SSE/retry + safety-gate unit tests green.

---

## Phase 4 — Hardening (production readiness)

**Goal:** operability, resilience, and security posture for a long-lived internal deployment.

**Work**
- OIDC/SSO fully wired (JIT provisioning, back-channel logout considerations); API keys/JWT for machine clients.
- Observability: OpenTelemetry run/agent traces; structured logs keyed by run_id/agent_id; dashboards for queue depth, budget spend, orphan-PG count.
- Artifact/data lifecycle: on-disk artifact path convention; retention/rotation/GC (arq cron) for `run_events`, `agent_tasks.output_file`, audit archives; per-run/per-project quotas; workspace-volume sizing guidance.
- At-rest posture: encrypted workspace volume; access-controlled sensitive Postgres tables; backup redaction/retention policy; downloads `no-store` + audited.
- Resilience: WS coalescing/throttle tuning; worker thread-pool sizing vs `max_jobs`; per-scan-profile `job_timeout`/chunking for UDP `-p-`; seccomp profile materialized in CI; base-image digest pinning.
- Test depth: integration tests for OIDC, checkpoint flow, cancellation/orphan-reaper, retry idempotency; load test a `/24`; secret-scan and alembic-diff gates enforced.

**Exit criteria**
- [ ] OIDC login + local fallback both work; RBAC and both audit trails verified end-to-end.
- [ ] A wide (`/24`) run completes or degrades to `partial` without orphaned scans, without exhausting Redis/Postgres, and without WS overwhelm; traces/metrics visible.
- [ ] GC/retention jobs run on schedule; workspace and Postgres growth bounded; quotas enforced.
- [ ] Security review: least-privilege caps, egress isolation, secrets in the secret store (not plain env), no cleartext secrets on networked surfaces, seccomp active, engine tree read-only — all confirmed.
- [ ] Full CI matrix green including integration + load smoke; policy-invariant gate still mandatory and passing.
