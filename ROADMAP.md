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

## Phase 2 — Core service modules — ⬜

Order: `http` (granular controls + non-standard ports) → `vhost` → `smb` (tiered) → `ftp` → `ssh` → `dns` → `ldap` → `smtp` → `nfs` → `snmp` → `tftp` → `netbios` → `ike` → `ntp`.

Each ships: fixture, parser test, ≥ 3 pattern entries, HackTricks + `tools:` in `services.yaml`, `manual_commands.yaml` (≥ 5 entries), auto-walk where the §12 table permits.

**Exit:** scan 3 TRACKER boxes (mix HTB + PG, ≥ 1 with a UDP service) with full coverage.

---

## Phase 3 — Pattern library + suggestion engine — ⬜

- `patterns/engine.py`; per-service YAML with `# source:` provenance requirement (build gate).
- "Recon next steps" sub-section in the Tool Panel (pre-fill on click, never auto-execute).
- Report includes suggestions with citations.

**Exit:** on a fresh box, suggestions read like a sensible recon plan.

---

## Phase 4 — Graph view (Bloodhound-style) — ⬜

- `graph_view.py` — `QWebEngineView` + vendored Cytoscape.js; `QWebChannel` bridge.
- Node/edge types, layouts, interactions per §16; `graph.json` persistence; `View → Graph` (Ctrl+G).
- **Presentation reinforcements (queued 2026-07-11, CLAUDE.md §16):** full drag-and-drop repositioning
  (positions persist across sessions), right-click → Add Note (→ `graph.json` + hover tooltip + report),
  consistent per-type colors + edge labels + minimap + zoom/pan, and **Export graph as PNG/SVG**.

**Exit:** graph shows the discovery story end-to-end; can mark/annotate nodes in place.

---

## Phase 5 — Quality of life + Obsidian output — ⬜

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

## Phase 6 — Exam-day polish — ⬜

- `oscprecon-cli doctor` + Help → Doctor (checks each wrapped tool via `which`, prints install commands).
- Exam profile preset (tight/fast; no `--script vuln`, no deep recursion).
- Self-contained report; mock exam (3 standalone + AD set, timed); fix roughness.

**Exit:** would trust it on the real exam.

---

## Deferred / TODO (cross-cutting)

Out-of-scope items surfaced during earlier phases, parked here per `CLAUDE.md` §27:

- **Real scan cancellation (Phase 5).** Phase 0's `closeEvent` currently *blocks* until the running nmap finishes (safe, but can freeze the UI on a long `-p-` sweep). Phase 5's "cancel buttons" deliverable should add cooperative interruption that kills the in-flight subprocess via the `shell.run` timeout/kill path and unwinds the worker cleanly.
- **Findings persistence (`findings.json`).** `Module.parse()` returns `Finding`s; Phase 0 only surfaces them via the report. A dedicated `findings.json` writer is due when the first non-nmap module lands (Phase 2).
- **DB-client primitive backstop on the custom-command path (Phase 6).** Surfaced by the MySQL module review. Every command the modules *surface* is read-only, but now that `mysql`/`psql`/`mongosh`/`redis-cli` are allow-listed, a user hand-typing into the command builder can slip an exploitation primitive past `shell.policy_violation` — e.g. `mysql -e "SELECT … INTO OUTFILE '/var/www/x.php'"`, `LOAD_FILE(…)`, `sys_exec`, or a `\!` client shell-escape. Mirrors the existing `ntpdate -q` / `ike-scan -P` backstops: add a per-client refusal in `policy_violation` for `into outfile`/`into dumpfile`/`load_file`/`sys_exec`/`sys_eval`/`\!`. Cross-cutting (the same path already allows `curl -T`/`smbclient put`), so treat as recon-only hardening, not a per-module fix.
