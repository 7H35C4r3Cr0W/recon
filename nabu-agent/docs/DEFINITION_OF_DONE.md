# Definition of Done — Nabu Agent

The fixed standard for when this project is finished. This file is the source of truth: the checklist
below does not grow by invention — items are added only when they're a concrete, bounded piece of the
product, each with an acceptance test. Progress is tracked here; when the **Dev-Complete** set is all
checked, the dev side is done and only the LLM-attach items remain.

---

## The two tiers

**Tier 1 — DEV-COMPLETE** *(the finish line we drive to now; no live model needed)*
Everything the platform can do without the owner-attached LLM. When Tier 1 is fully checked + verified
(tests + ruff + mypy green, `vite build` OK, policy invariants hold, `src/oscprecon` untouched), the
**dev side is 100% done** and I say so — no reprompt needed.

**Tier 2 — LLM-GATED** *(parked; blocked until legal approves the internal model, ~days out)*
Items that fundamentally need the live model. Not part of "dev-done"; listed so nothing is lost.

---

## Tier 1 — Dev-Complete checklist

### Already shipped (PRs #18–#46) — the baseline
- [x] Recon: single-host + CIDR fan-out (per-host Profiles, alive-sweep, host-count approval gate)
- [x] Distributed two-pool Arq supervisor; admission control; reaper; retention
- [x] RBAC + membership (IDOR closed), audit trail, credentials vault, per-project settings
- [x] All API endpoints implemented (no 501 stubs); combined multi-host report; findings triage
- [x] Web UI: live BloodHound-style map, run history, report/export, admin LLM setup + test-fire
- [x] Deploy: Docker Compose + `deploy/RUNBOOK.md`; security hardening; manual CI; docs; visual Help
- [x] **Attack gate design** (`SPRAY_EXPLOIT_GATE.md`) + **Phase A** (propose → double-gated approve →
      execute via the one door; command re-derived from the catalog, never stored)

### Remaining — REQUIRED for dev-done
- [x] **1. Attack gate Phase C — attacks are actually usable + safe** ✅ (PR #47)
  - [x] C1 **Credential injection** — a chosen vault credential fills `{user}/{username}/{password}/
    {hash}/{ntlm}/{domain}` in the action; the secret is resolved server-side at execute time from
    the vault, never stored on the checkpoint.
  - [x] C2 **Operator params** — the proposal carries a `params` map that fills the remaining
    non-credential placeholders (`{wordlist}`, `{lhost}`, `{lport}`, `{command}`, …). An action is
    proposable only once *every* placeholder resolves; otherwise 422 lists exactly what's missing.
  - [x] C3 **Secret redaction** — the command preview (API + UI) shows secrets redacted; execution uses
    the real secret; no event/log ever carries the plaintext.
  - [x] C4 **Attack cap** — a per-run ceiling (`max_gated_actions_per_run`) refuses proposals past the cap
    with a clear error.
  - [x] C5 **Result recording** — after a spray/exploit runs, the target is appended to the used
    credential's `tested_against`, and the run summary records the attempt.
  - *Acceptance:* `test_attack_gate.py` grows: injection fills the command; the preview redacts the
    secret and no emitted event contains it; params fill the rest; over-cap is refused; `tested_against`
    is updated.
- [x] **2. Attack gate Phase D — safe-by-default operation** ✅ (PR #48)
  - [x] D1 **Dry-run** — an approve option that resolves + shows the exact command and records the
    checkpoint as `dry-run` **without ever calling the gated door** (no `shell.run`). UI toggle.
  - *Acceptance:* a dry-run approval never reaches `execute_gated_action`; asserted by test.
- [x] **3. Distributed-path smoke deliverable** ✅ (PR #48)
  - [x] S1 A compose-based smoke script (`deploy/smoke.sh`) + documented procedure that drives a real
    `scan` through Redis + the Arq worker and asserts a terminal `done`. (Executed by a human in a
    real cluster — I can't run a live cluster here — but the script + steps are committed and
    lint-clean.)
  - *Acceptance:* the script exists, is referenced from the RUNBOOK, and its non-cluster parts
    (arg parsing, health polling) are sound.

### Optional — explicitly NOT required for dev-done (won't block "done")
- [x] Attack rate-limiting (per-project cooldown) + four-eyes (second approver) for exploit ✅ (PR #49)
- [~] Throughput: **Cytoscape relayout is debounced** ✅ (PR #50). The other two — coalescing `_emit`
      DB commits and WS-replay paging — are **deliberately de-scoped**: they touch the seq-ordered
      event pipeline the live-tail dedup depends on, so they carry real correctness risk and there's
      no measured bottleneck to justify it. Revisit only if a load test shows one.

*(Optional items are done only on explicit request; they do not gate the "done" call.)*

---

## Tier 2 — LLM-Gated (parked — blocked on legal approval of the internal model)
- [ ] L1 Attach the internal OpenAI-compatible model (Admin → LLM setup → test-fire) → enable `agent` runs
- [ ] L2 Attack gate **Phase B** — agents *propose* into the same gate (they can only propose; humans approve)
- [ ] L3 Run-level LLM token / wall-clock budget enforcement in the agent role loop
- [ ] L4 End-to-end `agent`-kind run validation against the real endpoint

---

## Current position
- **2026-09-11:** ALL Tier-1 items (baseline + Phase A + C + D + smoke) are checked. **THE DEV SIDE IS
  DONE.** Verified: ruff + mypy clean, 110 backend + 10 invariant + 27 frontend tests, `vite build` OK,
  policy invariants hold, `src/oscprecon` untouched.
- The only work left is **Tier 2 (LLM-gated)** — blocked until legal approves the internal model — and
  the explicitly-optional polish. Nothing further ships on the dev side without a new request.
