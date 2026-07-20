# HANDOFF — continue the Nabu work from here

**Point Claude Code here when your context resets** ("read HANDOFF.md"). It says what this project
is, the exact state it's in, how I work on it, and what's worth doing next. `CLAUDE.md` is the full
brief and the source of truth for the hard rules (§2 exam-legality especially) — this file is the
short "pick up where we left off" companion. When they conflict, CLAUDE.md wins.

---

## What this is (one paragraph)
**Nabu** — a PySide6 desktop recon orchestrator for OSCP prep/exam (internal package `oscprecon`,
entry points `nabu` GUI / `nabu-cli` CLI). Recon-first and **exam-legal by default**; a separate,
owner-authorized **Exploitation tab** (§2b) runs human-confirmed manual attacks; **Spray mode** (§2a)
is opt-in/off-by-default. Wraps standard tools, links HackTricks/Exploit-DB, draws a BloodHound-style
graph, exports Obsidian markdown. Never auto-exploits, never calls an LLM at runtime.

## Current state (update this line as you go)
- **github/main HEAD: `24c0ac5`** (all pushed). `origin` = local Gitea (often offline) — push to the
  **`github`** remote (`git push github main`).
- Exploit catalog: **182 services / 3,433 actions**. Pattern library: **127 rules**.
- Full test suite green (**pytest EXIT=0**), all four gates clean.
- Author/maintainer: **Andre Boyle · its.lagus@proton.me · github.com/7H35C4r3Cr0W/recon**
  (single source of truth: `src/oscprecon/branding.py`).

## The four gates — run before EVERY commit, pause for approval only if the user asked
```bash
uv run ruff check
uv run ruff format --check
uv run mypy --strict src/
QT_QPA_PLATFORM=offscreen uv run pytest -q      # slow on this VM (~20 min); run targeted tests first
```
The pytest suite is slow here — run the **targeted** test files for what you touched first, then a
full-suite backstop in the background (write a done-marker, poll it) before reporting.

## How I work on this (the owner's expectations)
- **Autonomous + chunked.** Don't ask permission mid-task; do it, test, commit per logical chunk,
  report once. (See memory `work-fully-autonomously`, `autonomous-chunking`, `box-review-efficiency`.)
- **Docs in sync.** A code change also updates README / CLAUDE.md / the in-app guide (`src/oscprecon/
  guide/pages/*.md`) / docs where relevant. (memory `keep-docs-in-sync`)
- **Don't break functions.** Additive/guarded fixes; no tech-stack changes (§3 is locked); no big
  risky refactors unless asked.
- **Commit trailers** (already enforced by the harness): `Co-Authored-By: Andre Boyle
  <its.lagus@proton.me>` + the Claude line.

## The highest-value activity: adversarial review → fix → test
This session, background review agents + sweeps found **27 real bugs, all fixed + regression-tested**.
The pattern that works:
1. `Agent` (general-purpose, run_in_background) scoped to a **fresh, not-yet-reviewed slice**, told to
   **empirically confirm every finding with test data** and return `FILE:LINE — defect — trigger →
   wrong output — fix`.
2. For each real finding: reproduce with a throwaway `uv run python -c`, fix minimally, add a
   regression test asserting the fix, gate, commit.
- **Already reviewed (clean or fixed):** GUI churn (main_window/nav/task_bar/pivot/exploit_panel/
  owl/ligolo/cli), engine core (shell/exploit-base/parsers/manual_commands/orchestrator/wordlists),
  recon parsers (nmap/http/smb/ldap/snmp/ftp/dns/smtp + references matcher), persistence (profile/
  creds/findings/reporter/live_hacktricks/sections), recon GUI widgets, spray subsystem + graph_data
  + DB parsers, the views (graph_view/dashboard/findings/report/activity/notes/app_header), and
  reporter templates + workspace search/health + msfvenom builder.
- **Not yet swept (candidates for the next round):** `edb.py` / searchsploit lookup, `nmap_scan.py`
  builder edge cases, `references/live_hacktricks` under odd network, `workspace/bulk.py` +
  `index.py`, the graph_html JS bridge, `config.py` settings migration, the theme system.

## How to add a recon service module
Drop `src/oscprecon/modules/<svc>/` with `__init__.py` (subclass `Module`), `parsers.py`,
`manual_commands.yaml`. Add a fixture + parser test + ≥3 pattern entries (`patterns/<svc>.yaml`, each
with a `# source:`) + a `references/services.yaml` entry. Keep it §2-allowed (recon-only; brute/spray
is Tier-3, off by default). `manual_commands` for modules in `_NEW_MODULES` must use **allow-listed**
tools (a test enforces it) — non-allowlisted enum tools are copy-only shown commands only for the
older modules.

## How to add an Exploitation-tab service (§2b)
Drop `src/oscprecon/exploit/<svc>.py` that `register()`s a `ServiceExploits`; `base._load_builtin()`
imports it (module name must be a valid Python identifier — no hyphens). Each `ExploitAction` needs a
`source=`; `runs_on="attacker"` ONLY if the filled command is a single Popen-safe argv from Kali (no
pipes/redirects/chains/listeners/interactive-getters — the guard test enforces it), else `"victim"`
(copy-only). NEVER ship sqlmap/msfconsole/meterpreter/msfvenom as the first token of a service action
(a test enforces it). The catalog is **saturated** — prefer fixing bugs / recon patterns over padding.

## Where the durable memory lives
`~/.claude/projects/-home-hacker-oscp-recon/memory/` (indexed by `MEMORY.md`). Key ones:
`session-feature-batch-2026-07-19` (the full blow-by-blow of this session), `build-state`,
`session-handoff`, `dev-workflow`, `service-gating-discipline`, `owner-decisions`,
`obsidian-notes-location` (the vault path for `# source:` mining).

## If told "continue where you left off"
1. `git -C ~/oscp-recon log --oneline -8` and read this file's "Current state".
2. Pick the next chunk: another **adversarial review round** on a not-yet-swept slice (above), or a
   feature the user names. Confirm scope only if genuinely ambiguous.
3. Chunk → gates → targeted tests → commit → `git push github main` → brief report. Update the
   "Current state" HEAD line here when you land meaningful work.
