# oscp-recon — ROADMAP

Phase-by-phase build order. **`CLAUDE.md` is authoritative**; where this file disagrees with it, `CLAUDE.md` wins. A phase is "done" when the tool has been used on ≥ 3 boxes from `boxes/TRACKER.md` without major gaps for that phase's features (see `CLAUDE.md` §23).

Status legend: ✅ done · 🚧 in progress · ⬜ not started

---

## Phase 0 — Scaffold (engine + minimal GUI + nmap) — ✅ built & verified

Delivered:

- `pyproject.toml` + `uv` env; `mypy --strict`, `ruff check`, `ruff format` all configured and green.
- Engine: `shell.py` (sole exec chokepoint), `config.py` (XDG paths, `recent.json`), `models.py` (shared domain types + target validation), `profile.py` (folder tree + `profile.json` v1, atomic save), `orchestrator.py`, `reporter.py`.
- `modules/base.py` (the `Module` ABC) + `modules/nmap.py` (TCP top-1000 → full → versioned, UDP top-100; opt-in UDP full).
- `cli.py` — Typer `oscprecon-cli scan <ip> --profile <name>` (+ `--hostname`, `--udp-full`, `--workspace`).
- `__main__.py` → GUI launch; `gui/app.py`, `gui/main_window.py` (File menu, New-Scan-Profile dialog, target label, Run-nmap button in a `QThread` worker, streaming output panel, recent-profile auto-restore).
- `tests/`: nmap fixtures + parser tests, target-validation tests, shell-policy tests, nmap-command tests, pytest-qt GUI smoke test.

**Exit criterion:** File → New → type IP → Run → nmap runs (TCP + UDP) → close → reopen → state restored. ✅

**Hardening applied after adversarial review (pre-commit):** target-string validation (blocks NSE `*-brute` injection), allow/deny policy at the exec chokepoint, atomic `profile.json` writes, UTF-8-lossy tool decoding, real `timeout` watchdog + process kill, GUI menu lockout during scans, `closeEvent` waits for the worker, and corrupt-profile-safe startup.

---

## Phase 1 — Full GUI shell + wordlist subsystem + references — ✅ feature-complete

Delivered across 6 chunks: `wordlists.py` (+ password-list filtering), `references/` (services.yaml
matcher + Exploit-DB lookup), `creds.json` (0600) + references-visited, three-pane GUI
(`service_tree` / `tool_panel` / `reference_pane`), HackTricks `QWebEngineView` + live searchsploit
EDB list, and the `wordlist_picker` / notes pane / credentials dialog. Exit path verified live
(select service → HackTricks + EDB load, tool hints populate). Remaining before "done" per §23:
run it on ≥3 real boxes.

### Original plan

- Three-pane layout: `service_tree.py`, `tool_panel.py`, `reference_pane.py`.
- `wordlists.py` + `wordlist_picker.py` (favorites, recent; filters out `seclists/Passwords/`).
- `references/services.yaml` loader + matcher.
- HackTricks `QWebEngineView` + Exploit-DB `searchsploit` lookup (lookup-only) + per-port tool hints.
- Notes pane editing `<profile>/notes.md`; credentials dialog writing `creds.json` (chmod 600); references-visited persistence.

**Exit:** scan HTB easy → services in tree → click SMB → HackTricks + EDB load, tool hints populate.

---

## Phase 2 — Core service modules — ✅ built & verified
<!-- All 14 core modules + Redis/MongoDB/MSSQL/MySQL DB modules ship engine + parser tests +
     manual_commands.yaml + services.yaml tool-hints + GUI panels. See PROGRESS.md per-module logs. -->


Order: `http` (granular controls + non-standard ports) → `vhost` → `smb` (tiered) → `ftp` → `ssh` → `dns` → `ldap` → `smtp` → `nfs` → `snmp` → `tftp` → `netbios` → `ike` → `ntp`.

Each ships: fixture, parser test, ≥ 3 pattern entries, HackTricks + `tools:` in `services.yaml`, `manual_commands.yaml` (≥ 5 entries), auto-walk where the §12 table permits.

**Exit:** scan 3 TRACKER boxes (mix HTB + PG, ≥ 1 with a UDP service) with full coverage.

---

## Phase 3 — Pattern library + suggestion engine — ✅ built & verified
<!-- patterns/engine.py + per-service patterns/*.yaml (provenance + forbidden-content gates),
     "Recon next steps" GUI panel (pre-fill, no auto-run), report citations. -->


- `patterns/engine.py`; per-service YAML with `# source:` provenance requirement (build gate).
- "Recon next steps" sub-section in the Tool Panel (pre-fill on click, never auto-execute).
- Report includes suggestions with citations.

**Exit:** on a fresh box, suggestions read like a sensible recon plan.

---

## Phase 4 — Graph view (Bloodhound-style) — ✅ built & verified
<!-- graph_view.py (QWebEngineView + vendored Cytoscape.js in gui/graph_html/), graph_data.py,
     QWebChannel GraphBridge, graph.json persistence, Ctrl+G toggle. -->


- `graph_view.py` — `QWebEngineView` + vendored Cytoscape.js; `QWebChannel` bridge.
- Node/edge types, layouts, interactions per §16; `graph.json` persistence; `View → Graph` (Ctrl+G).
- **Presentation reinforcements (queued 2026-07-11, CLAUDE.md §16):** full drag-and-drop repositioning
  (positions persist across sessions), right-click → Add Note (→ `graph.json` + hover tooltip + report),
  consistent per-type colors + edge labels + minimap + zoom/pan, and **Export graph as PNG/SVG**.

**Exit:** graph shows the discovery story end-to-end; can mark/annotate nodes in place.

---

## Phase 5 — Quality of life + Obsidian output — ✅ built & verified
<!-- --resume/--force (skip existing output), bounded parallel execution + task status bar with
     working cancel, real scan cancellation (cancel Event -> shell.run kills the child group),
     report viewer tab, single-file Obsidian frontmatter + File -> Export to Obsidian Vault,
     dark/light theme. -->


- `--resume` (skip commands with existing output unless `--force`).
- **Bounded parallel execution + status bar with cancel buttons** (real interrupt/cancel for in-flight scans — see Deferred below).
- Reference search box; report viewer tab; single-file Obsidian frontmatter mode (default) + `File → Export to Obsidian Vault...`.
- Profile actions (right-click Recent): Open Folder / Mark Done / Duplicate / Delete; TRACKER.md sync on root; dark/light theme.
- **Queued additions (2026-07-11) — reconciled 2026-07-13:**
  - ✅ **Status footer** (CLAUDE.md §19) — built into `main_window.py` (`_update_status_footer`): app+version, active profile, workspace root, exam-legal reminder.
  - ✅ **Full GUI audit log** (CLAUDE.md §6a) — `audit.py` + `<profile>/audit.jsonl`; feeds the dashboard Activity timeline.
  - ✅ **Concurrent-copy lock** (CLAUDE.md §6b) — advisory `<profile>/.lock` + read-only prompt + stale-lock reclaim (delivered in the Workspace upgrade).
  - ✅ **Project file operations** (CLAUDE.md §19) — `workspace/portability.py`: File → Open by IP / Import Project / Export Project (.tar.gz, warns `creds.json` included) + CLI `export-project`/`import-project`. Import is path-traversal-safe (rejects `..`/absolute/backslash/symlink/special/multi-top/non-profile + decompression-bomb cap; stages then swaps). (`bulk.export_project` remains a distinct Obsidian *vault* export.)

**Exit:** pleasant to use under exam pressure; reports drop into Obsidian cleanly.

---

## Phase 6 — Exam-day polish — 🚧 partial (only the timed mock remains)
<!-- DONE: `oscprecon-cli doctor` (which-check for every wrapped tool + install hints). Self-contained
     report. Exam-mode scan profile (quick/default/full/exam). TODO: timed mock-exam dry run (needs a
     live target). -->


- ✅ `oscprecon-cli doctor` + Help → Doctor (checks each wrapped tool via `which`, prints install commands).
- ✅ **Exam-mode scan profile** (tight/fast; no `--script vuln`) — `quick`/`default`/`full`/`exam` govern
  the nmap battery. Exam = `--top-ports 1000 -T4` → `-p- --min-rate 1000 -T4` → UDP top-100. Selectable
  in Preferences (default), `Scan → Run recon with profile` (per-run), and `oscprecon-cli --scan-profile`.
- ✅ Self-contained report. ⛔ Timed mock exam (3 standalone + AD set) — blocked on an authorized target.

**Exit:** would trust it on the real exam.

---

## Workspace Dashboard & Project Organization — ✅ built & verified (cross-cutting)

Deterministic upgrade turning individually-opened profiles into an organized local workspace. Business
logic in `src/oscprecon/workspace/` (profiles stay authoritative; the index is never a second source of
truth); GUI in `src/oscprecon/gui/workspace/`. Delivered in chunks (`e6ffb7e`…`eebc8cc`) + a settings
dialog:

- **Index + organization metadata** — `scan_workspace` → typed `ProfileSummary` (counts + booleans,
  never secrets); backward-compatible `profile.json` `organization` block (status/tags/pinned/archived/
  display_name), normalized + atomic.
- **Dashboard** — searchable/filterable home view (`Ctrl+0`), off-thread cancellable scan, corrupt
  profiles surface as ⚠ rows; pin/tag/status/archive + bulk actions (no scan/cred/delete).
- **Global search** — never indexes/shows passwords/tokens/keys; credential hits carry username/domain
  only, previews plain-text + capped.
- **Health + repairs** — read-only checks; opt-in repairs back up before changing, never delete.
- **Locks + read-only** — advisory `<profile>/.lock` (§6b — resolves the deferred item below); live-lock
  never stolen, stale recovered, foreign-host conservative; read-only blocks every write, export still
  works.
- **Activity timeline, saved views, safe bulk actions** — all filter-/read-only, secret-redacted.
- **Preferences dialog** (§19) — `File → Preferences…` (`Ctrl+,`), 8 tabbed sections (Workspace /
  Appearance / Tool paths / Scan / Reports / Privacy / Performance / Advanced) over a typed
  `config.Settings` layer (validate + clamp + atomic, no secrets). Mandatory secret protections are
  shown **locked-on** and cannot be disabled.

Verified: four gates + offscreen GUI green (657 tests); wheel ships and imports `workspace/` +
`gui/workspace/` from a clean venv. **See [`PROJECT_MAP.md`](PROJECT_MAP.md) for the current
subsystem-by-subsystem status map and forward plan.**

---

## Deferred / TODO (cross-cutting)

Out-of-scope items surfaced during earlier phases, parked here per `CLAUDE.md` §27:

- ✅ **Pattern-library coverage** — DONE: `patterns/{ssh,ike,tftp,vhost}.yaml` added; **all 19 modules**
  now have provenance-cited, forbidden-gate-clean, policy-clean pattern entries (47 rules).
- ✅ **Report Exploit-DB-hit persistence** — DONE: `edb.py` → per-profile `edb.json` + an "Exploit-DB
  references" report section. Lookup-only (§14): EDB-ID/title/URL only, never the local PoC path.
- ✅ **AD/Kerberos enum workflow** — DONE: `modules/kerberos` (Tier-1 credential-free `nmap -sV -p88`
  KDC confirm; Tier-2 enum-only single-user AS-REP + GetADUsers/GetUserSPNs). Parser records
  principals/SPNs but **never the AS-REP/TGS hash**; no `-usersfile`, no `-request`, no cracking.
- **Finding-aware HackTricks integration** — *recommended next chunk (owner greenlit direction).*
  Vendor the CC-licensed HackTricks markdown offline and surface the relevant section per finding.
  **Gate: propose a CLAUDE.md §2/§27 edit first** (permit offline vendoring, still forbid live
  scraping) + attribution. Phase 1 = vendor + index. Deterministic/offline once permitted.
- **Timed mock exam (Phase 6).** A timed dry run against a standalone + AD set. Blocked on an authorized
  live target.
- **Distribution & resilience (future, not greenlit).** Public GitHub release: tool-update-resilient
  parsers, `doctor`→safe installer, single-click contained app, splash screen. See the build memory.

**The in-scope, deterministic recon/report backlog is now exhausted** — 20 modules, patterns 20/20,
exam profile, portability, EDB persistence, and AD/Kerberos all shipped.

*(The concurrent-copy profile lock, CLAUDE.md §6b, the status footer §19, and the audit log §6a are now
built — see the Workspace Dashboard section.)*

<!-- Resolved and removed from this list (proven by code + tests):
     real scan cancellation (cancel Event + closeEvent cancel-then-wait);
     findings persistence (src/oscprecon/findings.py + findings.json);
     DB-client primitive backstop in shell.policy_violation. -->

