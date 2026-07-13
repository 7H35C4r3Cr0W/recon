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
- **Queued additions (2026-07-11):**
  - **Status footer** (CLAUDE.md §19) — app name+version, active profile, workspace root, "recon-only — OSCP exam legal". May land earlier alongside module UI.
  - **Project file operations** (CLAUDE.md §19) — File → Open by IP / Import Project (.tar.gz) / Export Project (.tar.gz, warns `creds.json` included); each `~/oscprecon/<name>/` is a project file.
  - **Full GUI audit log** (CLAUDE.md §6a) — append-only `<profile>/audit.jsonl` of every user action; report "Audit trail" appendix; wire emit points as earlier phases' UI lands (backfill is cheap).
  - **Concurrent-copy lock** (CLAUDE.md §6b) — `<profile>/.lock` (flock) + "open read-only?" prompt + stale-lock (dead-PID) reclaim.

**Exit:** pleasant to use under exam pressure; reports drop into Obsidian cleanly.

---

## Phase 6 — Exam-day polish — 🚧 partial
<!-- DONE: `oscprecon-cli doctor` (which-check for every wrapped tool + install hints). Self-contained
     report. TODO: exam-profile preset (tight fast command set), timed mock-exam dry run. -->


- `oscprecon-cli doctor` + Help → Doctor (checks each wrapped tool via `which`, prints install commands).
- Exam profile preset (tight/fast; no `--script vuln`, no deep recursion).
- Self-contained report; mock exam (3 standalone + AD set, timed); fix roughness.

**Exit:** would trust it on the real exam.

---

## Deferred / TODO (cross-cutting)

Out-of-scope items surfaced during earlier phases, parked here per `CLAUDE.md` §27:

- **Concurrent-copy profile lock (`<profile>/.lock`, CLAUDE.md §6b).** Still queued: opening a profile
  for edit should flock a `.lock` (owning PID) so a second GUI instance prompts "open read-only?".
- **Exam-profile preset + timed mock exam (Phase 6).** A tight/fast command-set preset (no `--script
  vuln`, no deep recursion) and a timed dry run against a standalone + AD set.

<!-- Resolved and removed from this list (proven by code + tests):
     real scan cancellation (cancel Event + closeEvent cancel-then-wait);
     findings persistence (src/oscprecon/findings.py + findings.json);
     DB-client primitive backstop in shell.policy_violation. -->

