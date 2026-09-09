# Nabu Agent — brief & hard rules (for any AI/engineer continuing this)

**Read [`HANDOFF.md`](HANDOFF.md) first** — it is the live "where are we" tracker.
**Authoritative design:** [`docs/DESIGN.md`](docs/DESIGN.md) · **plan:** [`docs/ROADMAP.md`](docs/ROADMAP.md)
· **engine API:** [`docs/ENGINE_INTEGRATION.md`](docs/ENGINE_INTEGRATION.md).

## What this is
Nabu Agent is the agent-driven web platform (the "body") wrapping the classic Nabu (`oscprecon`)
recon engine (the "hands"). The owner attaches the "brain" — an internally-hosted, OpenAI-compatible
LLM. It is an **offshoot product** in this repo's `nabu-agent/` folder.

## Hard rules (non-negotiable)
1. **Never modify `../src/oscprecon`** (or the engine's repo-root files). It is a read-only path
   dependency. A CI hygiene job fails any PR under `nabu-agent/` that also diffs `src/oscprecon/`.
2. **One `shell.run` chokepoint:** only `nabu_agent/engine/shell_gateway.py` may import/call
   `oscprecon.shell.run`. Everything else runs tools via `run_recon_tool`. No `subprocess`,
   `os.system`, or `shell=True` anywhere. (Enforced by `tests/policy_invariants/`.)
3. **Authorized-scope-only:** validate every target with the engine validators AND confirm it is in
   the project's scope allowlist (`assert_in_scope`) before any tool runs. Re-validate per host on a
   CIDR fan-out.
4. **No blind auto-exploit:** `exploit=True`/`spray=True` may be set **only** in
   `execute_gated_action`, sourced from a Postgres-verified, human-approved checkpoint. Agents can
   *propose* attack actions (Checkpoints) but never execute them. `run_recon_tool` has no
   exploit/spray parameter — by design.
5. **The brain is swappable:** all LLM access goes through `nabu_agent/llm` (`build_provider`);
   default adapter is OpenAI-compatible, configured by `NABU_LLM_*`. No vendor SDK, no hardcoded
   endpoint.
6. **Audit everything that runs or changes state** — engine `audit.jsonl` (what ran) + platform
   `audit_log` (who did what). Read-only actions audit nothing.

## Layout
`nabu_agent/` is the one canonical package (`uvicorn nabu_agent.main:app`,
`arq nabu_agent.worker.WorkerSettings`). Engine reached only via `nabu_agent/engine/`. See
`docs/DESIGN.md` §12 for the full tree.

## Gates
`make lint` (ruff) · `make typecheck` (mypy) · `make test` (unit) · `make invariants` (the required
policy-invariant gate). CI mirrors these + a hygiene job asserting `src/oscprecon` is untouched.
