# Nabu Agent — Initial Scaffold Manifest

Concrete file tree to create **now** under `nabu-agent/`. Fidelity: **full** = working code; **stub** = signatures + docstrings, `NotImplementedError` bodies; **config** = concrete config/data file. "Scaffold now" = create in the initial commit (Phase 0); "later" = deferred to the named phase.

## Root / project config — scaffold now
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `pyproject.toml` | config | now | Full runtime + dev deps; engine as **non-editable** path dep `{ path="..", editable=false }`; `[tool.pytest.ini_options]` registers `invariant` marker; ruff + mypy config (mypy targets `nabu_agent/`). |
| `alembic.ini` | config | now | Points at `nabu_agent/db/migrations`. |
| `docker-compose.yml` | full | now | 5 services + one-shot `migrate`; least-privilege (api cap_drop ALL; worker cap_drop ALL + cap_add NET_RAW, `no-new-privileges`, seccomp, `init: true`); internal backend net + isolated egress net; named volumes; docker secrets. |
| `docker-compose.override.yml` | config | now | Local dev: hot reload, exposed ports, FE dev proxy. |
| `.env.example` | config | now | Every key across all Settings, grouped, required-vs-default marked (NABU_*, NABU_LLM_*, OIDC_*, COOKIE/CSRF/SESSION, DEFAULT_SCAN_PROFILE, budgets). |
| `.gitignore` | config | now | Excludes `.env`, `secrets/`, TLS keys, build artifacts. |
| `Makefile` | config | now | `up migrate seed test lint fe-dev`. |
| `README.md` | config | now | Clone→run quickstart. |
| `CLAUDE.md` | config | now | Locked decisions + `src/oscprecon` read-only rule. |

## Backend package root `nabu_agent/` — scaffold now
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `nabu_agent/__init__.py` | stub | now | States engine is read-only, accessed only via `nabu_agent.engine`. |
| `nabu_agent/main.py` | full | now | App factory, middleware chain, `/api` + `/ws` mount, lifespan (DB+Redis pools, headless engine-import check, workspace-writable check). |
| `nabu_agent/worker.py` | full | now | `WorkerSettings` naming supervisor + agent-work pools; `job_timeout` backstop; `max_tries`. Compose runs `arq nabu_agent.worker.WorkerSettings`. |
| `nabu_agent/settings.py` | full | now | Root `Settings` (NABU_) composing `LLMSettings`. |
| `nabu_agent/rbac.py` | full | now | Role/ProjectRole/Perm + `PERMISSIONS` matrix + `can()`. |
| `nabu_agent/audit.py` | full | now | Platform `audit_log` writer. |
| `nabu_agent/bootstrap.py` | full | now | Seed first admin + default settings. |
| `nabu_agent/bus.py` | full | now | Redis: enqueue, cancel-flag, publish/subscribe. |

## DB layer — scaffold now
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `nabu_agent/db/models.py` | full | now | All platform + orchestration tables; enums aligned to `orchestration.states.RunState`. |
| `nabu_agent/db/session.py` | stub | now | Async engine + sessionmaker + `get_db`. |
| `nabu_agent/db/migrations/env.py` | config | now | Alembic env. |
| `nabu_agent/db/migrations/versions/0001_init.py` | config | now | Initial migration for the full schema (incl. partial-unique index on `runs(project_id)`). |

## Auth — scaffold now
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `nabu_agent/auth/providers.py` | full | now | AuthProvider protocol, OIDCProvider (Authlib), LocalProvider (argon2), JIT `provision_user`. |
| `nabu_agent/auth/sessions.py` | full | now | Redis session store, cookie create/read/destroy, WS handshake auth. |
| `nabu_agent/auth/deps.py` | full | now | `get_current_user`, `require_role`, `require_project_role`, `csrf_protect`. |

## Engine adapter seam (only importer of oscprecon) — scaffold now
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `nabu_agent/engine/__init__.py` | full | now | Public surface + `TOOLS` registry (ToolSpec executes/mutates). No exploit/spray tool. |
| `nabu_agent/engine/shell_gateway.py` | full | now | **THE single `shell.run` caller.** `run_recon_tool` (spray/exploit hard-False, no param, per-step `timeout=`, PGID registry) + `execute_gated_action` (sole `exploit=True`/`spray=True` site, Postgres-verifies approved checkpoint) + `assert_in_scope` (format + `scope_targets` membership) + `raise_for_result` + `audit`. |
| `nabu_agent/engine/tools.py` | stub | now (full in Phase 1) | Eight tools; docstrings map each to real engine calls: `Orchestrator.run_nmap`, `alive.build_alive_command`/`parse_alive`, `SmbEnum/FtpEnum/SshEnum/DnsEnum/LdapEnum`, `nse_vuln.plan_scans`/`to_findings`, `exploit.build_context`/`rank_actions`/`suggested_action_ids`, `references.match`/`hacktricks.page_for_module`, `patterns.engine.suggest_for`, `Reporter.render`. |
| `nabu_agent/engine/gateway.py` | full | now | Read-only api facade: `validate_scope`, `create_project_profile` (Profile.create), `load_profile` (read_only), `render_report`, `sync_findings` (+`finding_severity`), `build_graph` (`graph_data.build_elements`), `catalog_for_project`, `suggestions`, `activity` (`audit.load_entries`). |
| `nabu_agent/engine/workspace.py` | full | now | `AgentWorkspace`; **one Profile per host for CIDR/multi-host**, single Profile for single host. |
| `nabu_agent/engine/schemas.py` | full | now | TypedDicts + converters (`to_service_dto`, `to_shell_dto`); notes `DiscoveredService.port` vs `Port.number`. |
| `nabu_agent/engine/errors.py` | full | now | Typed codes. |
| `nabu_agent/engine/settings.py` | full | now | Adapter env config. |

## Orchestration — scaffold now (bodies filled Phase 1/3)
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `nabu_agent/orchestration/__init__.py` | config | now | Package marker. |
| `nabu_agent/orchestration/states.py` | full | now | `RunState`, `TERMINAL`, `can_transition`. |
| `nabu_agent/orchestration/limits.py` | full | now | `RunLimits.from_settings` (clamp to engine `max_concurrency`) + `max_total_tasks`. |
| `nabu_agent/orchestration/checkpoints.py` | full | now | Checkpoint model + enums + `approve()` double gate; sole carrier of `exploit_confirmed`. |
| `nabu_agent/orchestration/admission.py` | full | now | One-active-run-per-project (Redis `profile_dir` mutex) + global run cap. |
| `nabu_agent/orchestration/blackboard.py` | stub | now (full Phase 1) | Read/Write single-writer split + Service/Credential deltas; docstrings cite `merge_services`/`add_credential`/`findings.add_findings`. |
| `nabu_agent/orchestration/tasks.py` | stub | now (Phase 1 single-target; Phase 3 fan-out) | Non-blocking supervisor + re-trigger barrier; agent job signatures with engine-call docstrings; `execute_approved_action` delegates to `shell_gateway.execute_gated_action`. |

## Brain seam — scaffold now (mostly Phase 3)
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `nabu_agent/llm/base.py` | full | now | Provider Protocol + wire dataclasses. |
| `nabu_agent/llm/config.py` | config | now | `LLMSettings` (NABU_LLM_*). |
| `nabu_agent/llm/factory.py` | full | now | `build_provider` + registry + shared httpx client. |
| `nabu_agent/llm/openai_compat.py` | stub | now (full Phase 3) | chat/stream SSE + tool_call reassembly + count_tokens. |
| `nabu_agent/llm/retry.py` | full | now | Backoff + jitter + Retry-After + retriable classification. |
| `nabu_agent/llm/errors.py` | full | now | LLMError hierarchy. |
| `nabu_agent/llm/tokens.py` | full | now | tiktoken-or-heuristic + context fitting. |
| `nabu_agent/agents/runner.py` | stub | later (Phase 3) | AgentRunner loop; binds to chokepoint. |
| `nabu_agent/agents/roles.py` | full | now | RoleDef registry + SAFETY_PREAMBLE + `render_system_prompt`. |
| `nabu_agent/agents/prompts/{planner,enum_writer,research,reporter}.j2` | full | now | System-prompt templates. |
| `nabu_agent/agents/context.py` | stub | later (Phase 3) | ContextAssembler; notable-only research; budget_fit. |
| `nabu_agent/agents/safety.py` | full | now | SafetyGate; delegates scope to `shell_gateway.assert_in_scope`. |
| `nabu_agent/agents/budget.py` | full | now | BudgetPolicy + BudgetStore (atomic `DECRBY` run-level). |
| `nabu_agent/agents/report_grounding.py` | stub | later (Phase 2) | Validates claims against edb.json/creds.json/discovered_services. |
| `nabu_agent/agents/tools/registry.py` | stub | later (Phase 3) | ToolRegistry unifying `engine.TOOLS`. |
| `nabu_agent/agents/tools/dispatch.py` | stub | later (Phase 3) | Routes through `engine.shell_gateway.run_recon_tool`; never sets exploit. |

## Events + WebSocket — scaffold now
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `nabu_agent/events/schema.py` | full | now | **The one canonical `Event` envelope** + superset type enum + client-op set. |
| `nabu_agent/ws/hub.py` | full | now | Cookie auth, RBAC, replay-by-seq then Redis tail, ~250 ms coalescing, ~20 s heartbeat. |
| `nabu_agent/ws/routes.py` | full | now | `/ws/runs/{id}`, `/ws/projects/{id}`. |

## Routers — scaffold now (full vs stub as marked)
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `nabu_agent/routers/health.py` | full | now | `/health`, `/health/ready`. |
| `nabu_agent/routers/auth.py` | full | now | providers/login/oidc/logout/me/refresh. |
| `nabu_agent/routers/projects.py` | full | now | CRUD + members + settings; Profile.create via gateway. |
| `nabu_agent/routers/scope.py` | full | now | Allowlist CRUD + pivot promotion. |
| `nabu_agent/routers/runs.py` | full | now (gating deepens Phase 3) | Start/cancel/status/output + checkpoint decision. |
| `nabu_agent/routers/reports.py` | full | now | Render/artifacts/download/export. |
| `nabu_agent/routers/findings.py` | stub | now | Findings/services/graph. |
| `nabu_agent/routers/catalog.py` | stub | later (Phase 3) | Display-only suggestions + catalog. |
| `nabu_agent/routers/creds.py` | stub | later (Phase 2) | Gated + audited vault. |
| `nabu_agent/routers/users.py` | stub | later (Phase 4) | Admin users + API keys. |
| `nabu_agent/routers/audit.py` | stub | now | Platform audit_log + engine activity. |
| `nabu_agent/routers/settings.py` | stub | later (Phase 4) | Global settings. |
| `nabu_agent/schemas/` | stub | now | Pydantic request/response per router + error envelope. |
| `nabu_agent/obs/logging.py` | stub | now | structlog JSON + two-audit doctrine. |

## Frontend `frontend/` — scaffold now (pages fill Phase 2)
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `frontend/package.json` | config | now | React + Vite + TS. |
| `frontend/tsconfig.json` | config | now | |
| `frontend/vite.config.ts` | config | now | `/api` + `/ws` dev proxy. |
| `frontend/index.html` | config | now | |
| `frontend/src/main.tsx` | full | now | Bootstrap. |
| `frontend/src/router.tsx` | full | now | Route inventory: login, projects, project dashboard, scope, run/live, findings, catalog, report, approvals, admin/users, audit. |
| `frontend/src/api/client.ts` | stub | now (full Phase 2) | Typed REST client + error-envelope handling. |
| `frontend/src/ws/client.ts` | stub | now (full Phase 2) | WS client bound to `events/schema.py` envelope; replay/heartbeat aware. |
| `frontend/src/pages/*` | stub | now (Login+Health full; rest Phase 2) | One file per route. |

## Deploy — scaffold now
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `deploy/Dockerfile.api` | full | now | Kali headless, recon toolset, engine read-only, nmap re-cap, uid 10001, `WITH_ATTACK=0`; shared by api+worker. |
| `deploy/Dockerfile.frontend` | config | now | Two-stage Vite → nginx. |
| `deploy/nginx.conf` | config | now | Reverse proxy `/api` + `/ws` (upgrade, long read) + SPA fallback + security headers. |
| `deploy/seccomp/worker.json` | config | now | Denylist source; CI materializes effective profile. |

## Tests + CI — scaffold now
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `tests/conftest.py` | full | now | Engine-mock + async test-DB + Redis fixtures. |
| `tests/policy_invariants/test_single_chokepoint.py` | full | now | AST: only `shell_gateway` calls `shell.run`; no subprocess/shell=True; SRC root exists + non-empty. |
| `tests/policy_invariants/test_scope_and_bypass.py` | full | now | Scope-lock, spray double-gate, audit-on-exec. |
| `tests/policy_invariants/test_exploit_gate.py` | full | now | `exploit=True` only in `execute_gated_action`; unapproved/agent-supplied checkpoint refused; gate sourced from Postgres not engine config. |
| `tests/unit/` | stub | now | Placeholder + first unit tests. |
| `tests/integration/` | stub | later (Phase 2) | Happy-path API/WS. |
| `tests/llm/test_openai_compat_stream.py` | stub | later (Phase 3) | SSE reassembly, retry, no-replay-after-side-effect. |
| `tests/agents/test_safety_gate.py` | stub | later (Phase 3) | Exploit blocked, out-of-scope blocked, spray needs config+approval. |
| `.github/workflows/nabu-agent-ci.yml` | full | now | Jobs: gates (ruff/mypy/unit), **policy-invariants (separate required gate)**, hygiene (fail on `src/oscprecon` diff), frontend build, docker build, alembic-diff, secret-scan. |

## Docs — scaffold now
| Path | Fidelity | Now/Later | Notes |
|---|---|---|---|
| `docs/DESIGN.md` | config | now | This design document. |
| `docs/ROADMAP.md` | config | now | The phased build plan. |

**Runnable-but-thin guarantee (Phase 0):** with the "now/full" files above, `docker compose up` migrates the DB, seeds an admin, serves the SPA login behind nginx, and passes `GET /api/health/ready` — while the single-chokepoint, exploit-gate, and read-only-engine invariants are already enforced by the mandatory CI gate before any recon or agent logic lands.

---

Notes on the key conflicts I resolved (folded into the documents above, not left as open items): one canonical package root `nabu_agent/`; one `shell.run` chokepoint module hosting both the recon path and the sole human-gated `exploit=True` executor (which reconciles the AST invariant with a working approved-exploit path); one scope-authorization function doing format validation plus multi-row allowlist membership; gate source-of-truth is Postgres flags + approved checkpoint only (engine `exploit_enabled()` default-True is never consulted); one canonical WebSocket event envelope; one Profile-per-host for CIDR to defeat the host-less `findings._key` collision; non-blocking supervisor with a re-trigger barrier plus separate queues and admission control; per-step tool timeout + PGID reaper for cancellation; idempotency keys against retry double-execution; atomic run-level token reservation; report-grounding validator; and secret redaction at the new networked boundaries.
