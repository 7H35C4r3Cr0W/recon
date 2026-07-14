# oscp-recon — PROJECT MAP

Project-control map of what the application **actually is** right now, confirmed from code and tests
— not from prose. `CLAUDE.md` remains authoritative for safety and architecture boundaries; this file
is the single "what is done / partial / next / blocked" view. Historical build detail stays in
`PROGRESS.md`; the phase plan stays in `ROADMAP.md`.

- **Product name:** **Nabu** (*Local Recon Workspace*) · internal package `oscprecon`, distribution
  `oscp-recon` (unchanged; see [`docs/OWNER_DECISIONS.md`](docs/OWNER_DECISIONS.md)).
- **Version:** 0.0.1 · **Entry points:** `nabu`, `nabu-cli` (preferred) + `oscp-recon`, `oscprecon`,
  `oscprecon-cli` (legacy aliases).
- **Verified:** `mypy --strict` clean (132 files) · `ruff check` + `ruff format --check` clean ·
  **970 tests** pass (incl. offscreen GUI) · `test_packaging` green (wheel ships resources, incl. the
  vendored HackTricks snapshot + the Nabu SVG identity; `packaging/` build infra excluded from the
  wheel), verified installed out-of-checkout (`nabu`/`nabu-cli` + legacy scripts + assets resolve).
  Live-fetch + credential-durability paths independently refute-reviewed; the Nabu UI pass was
  inline adversarial-reviewed (no secret-exposure / behaviour / policy defects). Spray preserves the
  discovered port.
- **Nabu UI/UX pass DONE** (12 commits): rename+entry points, original SVG identity, typed design
  tokens/styles/icons, conservative `finding_severity`, primary-nav shell + compact header,
  Findings/Activity views, dashboard + recon polish, reference tier badge + Tier-1 ranking, vault/
  spray/dialog uniformity, richer Findings filter, feedback banner, keyboard+a11y sweep, performance
  caching, `docs/screenshots/`. Remaining: interactive HTML module-flow mind-map for management (last).
- Visual companion: [`docs/project-map.mmd`](docs/project-map.mmd) (Mermaid mind map).
- Owner-approved policy decisions: [`docs/OWNER_DECISIONS.md`](docs/OWNER_DECISIONS.md) (live
  HackTricks fetch/cache is approved; project credentials are durable in `<project>/creds.json`).

## Status legend

```text
✅ Complete      confirmed by code AND tests
🚧 Partial       some of it exists; named gaps remain
⏭ Next           the recommended immediate chunk
🕒 Later          planned, not started, not blocked
⛔ Blocked        cannot proceed (needs an authorized live target / external state)
❌ Out of scope   deliberately excluded (CLAUDE.md §2/§27)
```

> **"Complete" rule:** nothing here is marked ✅ because a doc says so. Each ✅ is backed by named
> source files **and** named tests. Where docs over- or under-claimed, see *Documentation reconciliation*.

---

## 1. Product purpose — ✅

Recon-only, OSCP-exam-legal PySide6 desktop orchestrator for OSCP prep and exam day. Wraps standard
enumeration tools, surfaces findings in a tree + Bloodhound-style graph, links each service to
HackTricks / Exploit-DB, and emits Obsidian-friendly reports. **No** exploitation, credential
brute/spray, Metasploit/SQLMap, or LLM calls at runtime.

- **Files:** `CLAUDE.md` (brief/constraints), `README.md`, `ROADMAP.md`.
- **Risk:** scope creep past the recon-only line — governed by the exec policy (§10 below).

## 2. Core execution — ✅

- **Status:** ✅ Complete.
- **Files:** `shell.py` (sole exec chokepoint + `policy_violation`), `orchestrator.py`
  (phase runner + `--resume`/`--force`), `models.py` (domain types + target validation),
  `profile.py`, `config.py`, `cli.py` (Typer: `scan`, `doctor`), `__main__.py`.
- **Does:** every subprocess routes through `shell.run` → logs, times, writes raw output, enforces the
  allow/deny policy and DB-primitive backstop, kills the process group on timeout/cancel.
- **Complete:** two-stage nmap flow, **scan profiles** (quick/default/full/exam govern the nmap
  battery), resume semantics, target validation, atomic writes, cancellation.
- **Remaining:** none for the core.
- **Depends on:** nothing (foundation).
- **Risks:** the exec chokepoint is the single security-critical seam — any new module must pass
  through it and never call `subprocess` directly (CLAUDE.md §24).
- **Tests:** `test_shell_policy`, `test_shell_cancel`, `test_target_validation`, `test_config`,
  `test_orchestrator_resume`, `test_nmap_commands`, `test_cli_doctor`.

## 3. Recon modules — ✅ (core) · 🚧 (breadth)

- **Status:** ✅ for the 20 built modules; 🚧 as a set (extended §12 services not modularized).
- **Files:** `modules/base.py` (ABC) + `modules/nmap.py` + `modules/<svc>/{__init__.py,parsers.py,
  manual_commands.yaml}` for: **http, vhost, smb, ftp, ssh, dns, ldap, smtp, nfs, snmp, tftp, netbios,
  ike, ntp, kerberos** and read-only DB modules **redis, mongodb, mssql, mysql, postgresql**.
- **Does:** each module gives Tier-1 auto recon (credential-free), Tier-2 manual follow-ups, a parser →
  `findings.json`, and pattern "recon next steps". HTTP reproduces the §9 feroxbuster line via controls;
  SMB is tiered (null/guest, never list-driven); **kerberos** confirms the KDC (Tier-1 `nmap -sV`) and
  offers enum-only AD follow-ups (single-user AS-REP, GetADUsers/GetUserSPNs) — **no cracking, and the
  parser records principals/SPNs but never the AS-REP/TGS hash**.
- **Complete:** all 20 modules ship engine + parser tests + fixtures + `manual_commands.yaml` +
  `services.yaml` hints, and **all 20 now have `patterns/*.yaml`** (51 rules).
- **Remaining:** extended §12 services (rsync, finger, memcached, elasticsearch, couchdb, docker, etcd,
  zookeeper, vnc, webdav, ipmi, ipp, mdns, upnp) are **not** dedicated modules (❌ until a real box
  needs one).
- **Depends on:** core execution + references + patterns.
- **Risks:** a Tier-2 command drifting into list-driven brute (guard: policy + review).
- **Tests:** `test_<svc>_module` + `test_<svc>_parsers` for every module; fixtures under
  `tests/fixtures/<svc>/`.

## 4. GUI and navigation — ✅

- **Status:** ✅ Complete.
- **Files:** `gui/main_window.py`, `gui/app.py`, `gui/theme.py`, `gui/task_manager.py`,
  `gui/widgets/*` (service_tree, tool_panel, reference_pane, notes_pane, report_view, wordlist_picker,
  task_status_bar, graph_view, per-service panels: http/smb/ftp/ssh/dns/ldap/vhost, simple_recon_panel),
  `gui/workers/*` (base, scans, service_recon, simple), `gui/dialogs/*` (new_profile, credential,
  settings).
- **Does:** three-pane shell (tree · command builder + output + follow-ups · HackTricks/EDB), menus
  (File/Scan/Edit/View/Help), status footer (§19), Nmap scan-preset submenu, dark/light theme, graph
  toggle (Ctrl+G), report preview (Ctrl+R), dashboard (Ctrl+0), Preferences (Ctrl+,).
- **Complete:** all long-running work runs off the UI thread via `QThread` workers with a centralized
  task lifecycle and cancellation; workers capture their originating profile (stale-profile fix).
- **Remaining:** none blocking; project-file menu items (§13) still to add.
- **Depends on:** core execution, profile model, references.
- **Risks:** worker lifecycle / cancellation correctness under profile switching (well-tested).
- **Tests:** `tests/gui/*` — smoke, per-panel, task lifecycle/manager, workers, bounded-parallel,
  dialogs, theme, dashboard, settings_dialog, report_view, graph_view, recon_next_steps, scan_presets.

## 5. Workspace organization — ✅

- **Status:** ✅ Complete (the 12-chunk upgrade, `e6ffb7e`…`7237b4f`).
- **Files (logic):** `workspace/{index,models,search,health,locks,activity,bulk,views}.py`.
  **(GUI):** `gui/workspace/{dashboard,index_worker}.py`.
- **Does:** discovers profiles under the workspace root → typed `ProfileSummary` (counts + booleans,
  **never secrets**); dashboard home view (searchable/filterable, corrupt profiles surface as ⚠ rows);
  status/tags/pin/archive + safe bulk actions; global search; read-only health checks + opt-in repairs;
  advisory locks + read-only mode; activity timeline; saved views.
- **Complete:** profiles stay authoritative — the index is never a second source of truth.
- **Remaining:** none for this upgrade.
- **Depends on:** profile model (organization block), audit log (activity), locks (read-only).
- **Risks:** index staleness vs. profile edits (index is derived, re-scanned; low risk).
- **Tests:** `test_workspace_{index,search,health,locks,activity,bulk,views}`, `test_organization`,
  `tests/gui/test_dashboard`.

## 6. Profiles and persistence — ✅

- **Status:** ✅ Complete.
- **Files:** `profile.py`, `models.py`, `config.py`, plus per-profile JSON.
- **Does:** each `~/oscprecon/<name>/` folder is self-contained: `profile.json` (v1, `schema_version`,
  discovered services, command history, references-visited, `organization` block), per-service output
  folders, atomic saves, recent-profile restore.
- **Complete:** schema versioned + backward-compatible; corrupt-profile-safe load. **Project
  portability** — Open-by-IP, Import/Export `.tar.gz` (`workspace/portability.py`); import is
  path-traversal-safe (rejects `..`/absolute/backslash/symlink/special/multi-top/non-profile + a
  decompression-bomb cap), stages then swaps so a bad archive leaves nothing behind.
- **Remaining:** none.
- **Depends on:** core execution, workspace index.
- **Risks:** future schema migrations must stay backward-compatible.
- **Tests:** `test_config`, `test_settings`, `test_organization`, `test_workspace_index`,
  `test_workspace_portability`, `test_cli_project`, `tests/gui/test_project_ops`.

## 7. Findings and credentials — ✅

- **Status:** ✅ Complete.
- **Files:** `findings.py` (+ `findings.json`), `creds.py` (+ `creds.json`, mode 0600), `audit.py`.
- **Does:** parsers write structured findings; anonymous/null-session enum auto-writes a credential
  entry (`source: <module>-anon-enum`) consumed by later modules; **secrets are redacted everywhere**
  (reports, audit log, search, graph) and never logged.
- **Complete:** 0600 file mode, dedup, redaction, concurrency-safe writes.
- **Remaining:** none.
- **Depends on:** core execution, modules.
- **Risks:** any new surface that renders a credential must go through `redact()` (§10 guarantees).
- **Tests:** `test_findings`, `test_findings_concurrency`, `test_creds`, `test_audit`,
  `tests/gui/test_audit_wiring`, `test_wordlist_notes_creds`.

## 8. Graph functionality — ✅

- **Status:** ✅ Complete (Phase 4 + §16 presentation reinforcements).
- **Files:** `gui/widgets/graph_view.py`, `gui/graph_data.py`, `gui/graph_html/*` (vendored
  `cytoscape.min.js`, `cytoscape-svg.js`, `index.html`, `app.js`, `style.css`).
- **Does:** offline Cytoscape.js via `QWebEngineView` + `QWebChannel` bridge; node/edge types per §16;
  drag-to-reposition **persisted** to `graph.json`; right-click **Add Note** (→ tooltip + report);
  minimap; smooth zoom/pan; **Export PNG / SVG**.
- **Complete:** all §16 reinforcements verified present in code + JS.
- **Remaining:** none.
- **Depends on:** profile model (graph.json), findings/credentials.
- **Risks:** none material (fully local, no network).
- **Tests:** `test_graph_data`, `tests/gui/test_graph_view`.

## 9. Reports and exports — ✅ · 🚧 (project archive)

- **Status:** ✅ report + Obsidian; 🚧 project `.tar.gz` portability not built.
- **Files:** `reporter.py`, `templates/report.md.j2`, `vault_export.py`, `gui/widgets/report_view.py`,
  `workspace/bulk.py` (`generate_report`, `export_project`→vault export).
- **Does:** `report.md` with Obsidian YAML frontmatter + callouts + full command log; prior report
  archived to `report-archive/` before overwrite; rendered report tab; `File → Export to Obsidian
  Vault…` writes a linked note folder (also available as a bulk action).
- **Complete:** single-file Obsidian mode (default) + on-demand vault export. **Exploit-DB references**
  now persist per profile (`edb.py` → `edb.json`) and render as an "Exploit-DB references" report
  section — **lookup-only (§14): EDB-ID/title/URL only, never the local PoC path or content.**
- **Remaining:** none of the known report gaps. **Note:** the §19 `.tar.gz` project import/export lives
  in `workspace/portability.py` (§6); `bulk.export_project` remains a distinct *vault* export.
- **Depends on:** profile model, findings/credentials, references.
- **Risks:** report must stay self-contained (no external inlined content) for exam use.
- **Tests:** `test_reporter_findings`, `test_vault_export`, `tests/gui/test_report_view`,
  `tests/gui/test_export_vault_action`.

## 10. Safety and command policy — ✅

- **Status:** ✅ Complete (CLAUDE.md §2 enforced in code).
- **Files:** `shell.py` (`policy_violation`), `wordlists.py` (password-list filter),
  `references/__init__.py` (searchsploit flag stripping), `gui/dialogs/settings.py` (locked-on Privacy).
- **Does:** one exec chokepoint refuses non-allow-listed tools, brute/spray flags, and file-write /
  OS-exec DB primitives; wordlist indexer uses an **affirmative allowlist + denylist** so password
  lists never surface; searchsploit is display-only (leading-`-`/`-m/-x/-u` blocked); Preferences shows
  the mandatory protections **locked-on** (cannot be disabled).
- **Complete:** Tier 1/2/3 credential line honored; recon-only guarantees testable.
- **Remaining:** none; every new feature must respect this line.
- **Depends on:** nothing (foundation).
- **Risks:** the highest-value invariant in the project — regressions here are release-blockers.
- **Tests:** `test_shell_policy`, `test_target_validation`, `test_wordlists`, `test_references`,
  `test_settings::test_credential_wordlists_stay_filtered_when_a_settings_path_is_added` (new).

## 11. Testing and quality — ✅

- **Status:** ✅ Complete and enforced.
- **Files:** `tests/` (92 test modules), `tests/fixtures/`, `tests/gui/`, `pyproject.toml` gate config.
- **Does:** parser tests against committed fixtures; pytest-qt offscreen GUI smoke; four gates green.
- **Complete:** 657 tests pass; mypy strict clean; ruff clean; format clean.
- **Remaining:** none (grows with each feature).
- **Depends on:** everything.
- **Risks:** GUI tests must stay offscreen (`QT_QPA_PLATFORM=offscreen`) and never hit the network.
- **Tests:** the suite itself; `test_packaging` guards resource shipping.

## 12. Packaging and deployment — ✅

- **Status:** ✅ Complete.
- **Files:** `pyproject.toml` (hatchling), `.gitea/workflows/ci.yaml`, `tests/test_packaging.py`,
  `share/applications/oscp-recon.desktop`, `py.typed`.
- **Does:** wheel bundles all package resources (patterns, references YAML, templates, graph_html,
  manual_commands); three console scripts; Gitea CI runs the gates; `oscprecon-cli doctor` reports
  missing host tools.
- **Complete:** clean-venv install verified imports `workspace/` + `gui/workspace/` + resources.
- **Remaining:** none. (Push to the Gitea remote is on-network only — commits land locally on `main`.)
- **Depends on:** all packages + resources.
- **Risks:** a new non-`.py` resource not shipping — `test_packaging` is the guard.
- **Tests:** `test_packaging`, `test_cli_doctor`.

## 13. Planned features — 🕒 / ⏭

| Feature | Marker | Depends on | Note |
|---|---|---|---|
| Scan profiles incl. **exam mode** | ✅ **Done** | orchestrator, modules, settings | quick/default/full/exam govern the nmap battery; exam is speed-tuned + exam-legal (no `--script vuln`). Preferences default + `Scan → Run recon with profile` + CLI `--scan-profile` |
| Project file ops (`Open by IP`, `Import`/`Export .tar.gz`) | ✅ **Done** | profile model, workspace index | `workspace/portability.py` + File menu + CLI `export-project`/`import-project`; traversal-safe import, warns `creds.json` included |
| Pattern coverage for ssh/ike/tftp/vhost | ✅ **Done** | pattern engine | all 19 modules now have `patterns/*.yaml` (47 rules); commands policy-clean |
| Report EDB-hit persistence | ✅ **Done** | references, profile store | `edb.py`→`edb.json` + report section; lookup-only (no PoC path) |
| AD / Kerberos enum workflow | ✅ **Done** | smb/ldap modules | `modules/kerberos` (Tier-1 KDC confirm + enum-only Tier-2); parser stores no hashes |
| Finding-aware HackTricks (offline Phases 1–3) | ✅ **Done** | §2/§27 gate ✅ | 21 vendored pages + loader + offline render + finding-aware jump + `clean_markdown` + 12-module/30-entry verified section map |
| Owner-approved live HackTricks fetch/cache | ✅ **Done** | §14a policy ✅ | `references/live_hacktricks.py` — allow-listed HTTPS, bounded, sanitized, XDG cache; off-by-default; never transmits target/cred data. Security-reviewed: 0 confirmed defects |
| Cred store + password spraying | ✅ **Done** | §2a | opt-in/off-by-default; creds durable in `<project>/creds.json`, isolated, only explicit edit/delete removes; confirmed-spray recorded add-only |
| Preserve discovered port through spray | ✅ **Done** | spray dialog | `spray.discovered_port` maps by nmap service name → `build_spray_command` injects hydra `-s`/netexec `--port`; standard ports stay clean. Still policy-gated + secret-redacted |
| Timed mock-exam dry run | ⛔ | exam preset (✅) + live targets | The "timed" part needs authorized targets |
| Interactive + cross-machine AppImage acceptance | 🕒 | AppImage build (✅) | build + headless construction verified on Kali; on-screen/cross-machine open — see `packaging/ACCEPTANCE.md` |

## 14. Completed features (roll-up) — ✅

Phases 0–5 (scaffold, GUI shell + wordlists + references, all 14 core modules + 5 DB modules, pattern
library + suggestion engine, graph view, resume + Obsidian output, dark/light theme, status footer,
audit log §6a, concurrent-copy lock §6b) and the full Workspace Dashboard & Organization upgrade
(index, dashboard, search, health, locks, activity, saved views, bulk actions, Preferences dialog).

## 15. Partial features — 🚧

- **Phase 6 (exam-day polish):** `doctor` ✅, self-contained report ✅, **exam-mode scan profile ✅**;
  only the **timed** mock-exam dry run remains (⛔ needs an authorized target).
- _(No known coverage gaps remain in the recon/report core: pattern breadth is 19/19 and Exploit-DB
  references now persist into the report. Remaining work is forward-looking — see §13 and the phases.)_

## 16. Blocked work — ⛔

- **Live acceptance testing** — running the tool end-to-end on ≥3 authorized `boxes/TRACKER.md`
  targets, live parser validation, and performance-under-load. **Blocked:** no authorized live target /
  VPN in this environment. Every phase's §23 "exit criterion" (used on ≥3 real boxes) awaits this; to
  date verification = fixtures + unit/GUI tests, **not** live boxes.
- **Timed mock exam** — depends on the above.

## 17. Explicitly out-of-scope — ❌

Metasploit / msfvenom / meterpreter · SQLMap · hydra/medusa/patator/crowbar · password spraying /
list-driven auth · commercial scanners (Nessus/Burp Pro/…) · **any LLM/AI call at runtime** ·
automated exploit chains · Exploit-DB PoC download/execute/transform · HackTricks scraping/caching ·
tech-stack rewrites (CLAUDE.md §3/§27). Dedicated modules for §12 extended services are ❌ until a real
box needs one (no module merely because a port exists).

---

## Dependency map

Which subsystems rest on which — and which future work must **not** begin until its foundation is done.
Solid arrows = "builds on"; dashed = "future work waiting on a dependency".

```mermaid
flowchart TD
    shell["Shell policy · shell.run + policy_violation ✅"]
    workers["GUI workers + task lifecycle ✅"]
    modules["Recon modules ✅"]
    guiexec["GUI execution ✅"]
    profile["Profile model ✅"]
    fcn["Findings / credentials / notes ✅"]
    graph["Graph ✅"]
    reports["Reports / Obsidian ✅"]
    audit["Audit log ✅"]
    index["Workspace index ✅"]
    dash["Dashboard ✅"]
    search["Global search ✅"]
    views["Saved views ✅"]
    bulk["Safe bulk actions ✅"]
    locks["Profile locking ✅"]
    ro["Read-only mode ✅"]
    activity["Activity timeline ✅"]

    exam["Exam-mode scan profile ✅"]
    mock["Timed mock exam ⛔"]
    proj["Project file ops tar.gz ✅"]
    live["Live validation ⛔"]

    shell --> workers --> guiexec
    shell --> modules --> guiexec
    profile --> fcn --> graph
    fcn --> reports
    profile --> reports
    profile --> index --> dash
    index --> search
    index --> views
    index --> bulk
    profile --> locks --> ro
    audit --> activity
    fcn --> audit

    modules --> exam
    exam -.-> mock
    profile --> proj
    index --> proj
    exam -.-> live
    modules -.-> live
    mock -.-> live

    classDef done fill:#173a2a,stroke:#2f9e6b,color:#e8fff4;
    classDef later fill:#3d3410,stroke:#c9a227,color:#fff7e0;
    classDef blocked fill:#3d1616,stroke:#d05050,color:#ffe8e8;
    class shell,workers,modules,guiexec,profile,fcn,graph,reports,audit,index,dash,search,views,bulk,locks,ro,activity,exam,proj done;
    class mock,live blocked;
```

**Do-not-start-yet rules from the graph:**
- **Next chunk is pattern coverage** (ssh/ike/tftp/vhost YAMLs) — a leaf on the pattern engine (✅),
  no blocking deps.
- **Timed mock exam** waits on the (complete) exam-mode profile **and** an authorized live target.
- **Live validation** waits on everything and an authorized target — never claim it without one.

---

## Current-state summary

| Subsystem | Status | Test coverage | Main remaining risk | Recommended next action |
|---|---|---|---|---|
| Shell & command policy | ✅ | High (`test_shell_policy`, `test_shell_cancel`) | Any new module bypassing the chokepoint | Keep it the only exec path |
| Task lifecycle | ✅ | High (`test_task_lifecycle/manager`, `test_workers`) | Cancellation under profile switch | None — stable |
| Service modules | ✅ (20) | High (per-module + parser tests + 51 patterns) | Tier-2 drift toward brute | None — all 20 have patterns; kerberos enum-only |
| PostgreSQL | ✅ | High (`test_postgresql_*`) | DB-primitive backstop coverage | None — hardened |
| GUI architecture | ✅ | High (`tests/gui/*`) | Worker lifecycle regressions | None — refactor landed |
| Profiles | ✅ | High (`test_config/organization`) | Future schema migrations | Keep schema backward-compatible |
| Findings | ✅ | High (`test_findings*`) | New unredacted render surface | Route all through `redact()` |
| Credentials | ✅ | High (`test_creds`, `test_audit`) | Secret leakage | None — 0600 + redaction |
| Graph | ✅ | Medium (`test_graph_data/_view`) | None material | None |
| Reports | ✅ | High (`test_reporter_findings`, `test_edb`) | Report injection via tool output | None — EDB refs persist (lookup-only) |
| Obsidian export | ✅ | High (`test_vault_export`) | None | None |
| Project portability | ✅ | High (`test_workspace_portability`, `test_cli_project`, GUI) | Malicious archive on import | Done — traversal-safe + bomb cap |
| Packaging | ✅ | Medium (`test_packaging`) | Unshipped new resource | Keep `test_packaging` current |
| CI | ✅ | n/a (Gitea workflow) | Remote unreachable off-LAN | Push on-network via `autosave.sh` |
| Workspace dashboard | ✅ | High (`test_dashboard`, `test_workspace_index`) | Index staleness | None |
| Global search | ✅ | High (`test_workspace_search`) | Secret leakage in results | None — usernames/domains only |
| Profile locking | ✅ | High (`test_workspace_locks`) | PID reuse / foreign host | None — conservative already |
| Exam mode (scan profile) | ✅ | High (`test_nmap_commands`, `test_cli_scan`) | Timed mock still needs a live target | Done — only the timed dry-run is blocked |
| Live acceptance testing | ⛔ | None (needs targets) | Real parser gaps unseen | Run on 3 authorized boxes when available |

---

## Development phases (forward plan)

The originally-suggested Phases A–C (product organization, safe multi-profile use, workspace
intelligence) are **already delivered** by the Workspace Dashboard upgrade — the code shows a different
remaining order, so the forward plan is re-cast below (≤5 phases). One major chunk active at a time.

- **Phase 1 — Exam-day readiness** ✅ (preset) — exam-mode scan profile shipped (tight/fast, exam-legal;
  quick/default/full/exam). Only the *timed* mock-exam dry run remains, which is ⛔ (needs a live target).
- **Phase 2 — Project portability & recovery** ✅ — `File → Open by IP`, `Import Project` (.tar.gz),
  `Export Project` (.tar.gz, warns `creds.json` included) + CLI equivalents. Traversal-safe import.
- **Phase 3 — Recon depth** ✅ — pattern YAMLs (20/20 modules), report EDB-hit persistence, and the
  AD/Kerberos enum module (enumeration only) all shipped.
- **Phase 4 — Extended services (only as needed)** 🕒/❌ — dedicated modules for §12 services *actually
  encountered on a box* (rsync, finger, memcached, elasticsearch, couchdb, …). Never speculative.
- **Phase 5 — Live validation** ⛔ — 3 authorized lab targets, live parser validation, performance
  testing, timed mock exam, workflow corrections. Deps: everything + an authorized target.
- **Phase 6 — Distribution & resilience** 🕒 (future; **not greenlit** — user's stated end-goal for a
  public GitHub release). Owner-recorded ideas, to scope one chunk at a time when greenlit:
  1. **Tool-update-resilient parsers** — a wrapped tool changing output must never crash the app;
     parsers degrade gracefully and surface "couldn't parse X"; consider multi-version fixtures.
  2. **`doctor` → guided safe installer** — extend `oscprecon-cli doctor` to detect the Kali host and
     offer to install missing §2-allowed tools (explicit confirm, never silent, never forbidden tools).
  3. **Host-readiness check** on first run.
  4. **Single-click contained app** — evaluate PyInstaller/Briefcase/AppImage; launches the GUI on click.
  5. **Splash screen** with ASCII-art branding on load (`QSplashScreen`), Burp-style.
  6. **Public-release hygiene** — license, outside-user README, screenshots, clean fresh-Kali install.
- **Finding-aware HackTricks integration** 🕒 (future; **not greenlit**, and needs a **CLAUDE.md §27
  change first** — §27 currently forbids scraping/caching HackTricks). Idea: on a finding, surface the
  exact relevant HackTricks section (not just the page) inline / into notes, likely by vendoring the
  open-source HackTricks markdown repo offline (exam-legal, must attribute — CC BY-NC-SA). Reconcile
  §2/§27 with the owner before any work.

---

## Rules for starting new work

- Only **one** major implementation chunk may be active at a time; finish and verify it before starting
  another.
- Do **not** interrupt implementation to do a broad refactor or planning pass.
- A chunk must **identify its dependencies** and **define completion requirements** before coding.
- Do **not** mix architecture refactors with feature development, or live acceptance testing with major
  feature additions.
- Do **not** add a service module merely because a port or tool exists.
- Do **not** claim live validation without a real authorized target.
- Classify every new idea as **core / optional / later / blocked / out-of-scope** before implementation.
- Every completed chunk **updates `PROJECT_MAP.md`, `ROADMAP.md`, and `PROGRESS.md`** and **passes all
  quality gates** (`mypy --strict`, `pytest`, `ruff check`, `ruff format --check`, offscreen GUI tests,
  packaging check).
- Prefer a finished smaller chunk over several partially-implemented features.

---

## Immediate next chunk

Cred-spraying (now **port-aware**), HackTricks (**Phases 1–3 + owner-approved live fetch/cache §14a**,
both refute-review residuals hardened), parser multi-version resilience, durable project credentials,
the **`doctor` guided safe installer**, and the **single-click AppImage + branded splash** (real
acceptance build on Kali) are all done.

**The in-scope, deterministic backlog is exhausted — no deterministic next chunk remains.** What's
left needs external resources, so the next move is the owner's call:

- **⛔ Timed mock exam** — needs an authorized target.
- **🕒 Full interactive + cross-machine AppImage acceptance** — a real desktop / a second VM (build +
  headless construction are already verified; see `packaging/ACCEPTANCE.md`).

Anything beyond those is new feature scope (not on the current roadmap) and should be owner-greenlit
first.

**Parallel future tracks (need an owner decision / gate):**
- **Credential spraying (opt-in, off by default)** — ✅ **COMPLETE** end-to-end: CLAUDE.md §1/§2/§2a
  amendment (`ab9829f`); engine (`e4fcf7d`/`2923177`/`6ea11cc`) — gate, gated policy, `spray.py`
  builder, wordlist gating; **Credential Vault dialog** (`bd4fd1e`, add/edit/delete); **Spray dialog +
  gated runner** (`1531f59`, `Scan → Credential Spray…`). `spray=True` is passed in exactly one place,
  only when `config.spray_enabled`. UX polish (Burp-clean) is a later refinement. See
  [[cred-spray-scope-change]].
- **Finding-aware HackTricks integration** — **Phases 1–2 ✅**. Phase 1 (`37f0d68`): 21 pages vendored
  offline + `hacktricks.py` loader. Phase 2 (`7e5005e`/`f2fdef3`): reference pane renders the offline
  page (`QTextBrowser`, no WebEngine) beside the live link, **defaults offline-first**, jumps to the
  section matching a finding kind, and has a find-in-page box. 🕒 **Later:** Phase 3 polish (more
  kind→section mappings, cleaner mdBook rendering) + the owner FYSA §27 relax to also allow live fetch.
- **Phase 6 distribution** (installer / tool-update-resilient parsers / single-click app / splash).

**Blocked:** live validation + timed mock (authorized target required). Full detail in the build memory
([[hacktricks-integration]], [[cred-spray-scope-change]], [[distribution-goals]]).

---

## Documentation reconciliation

Corrected while building this map (code + tests are the source of truth; `CLAUDE.md` stays authoritative
for safety/architecture):

- **ROADMAP "Queued additions (2026-07-11)":** status footer (§19), full audit log (§6a), and
  concurrent-copy lock (§6b) are now **built** — only project file ops (`.tar.gz`) remain queued.
  Reconciled in `ROADMAP.md`.
- **Test count:** was cited as 656 / 554 in various places → now **657** (updated in ROADMAP + memory).
- **PROGRESS "Next up":** still framed Phase 2 as next — stale; replaced with a pointer to this map and
  the exam-mode-preset recommendation. Historical entries preserved.
- **`bulk.export_project` naming:** it performs an **Obsidian vault export**, *not* the §19 `.tar.gz`
  project backup — the tarball feature remains unbuilt (clarified here and in §9/§13).
- **"Built & verified":** across docs this meant *unit/fixture + offscreen-GUI verified*, **not**
  live-box verified. This map states that distinction explicitly (§16 / Live validation ⛔).
- **Graph Phase 4:** §16 "presentation reinforcements" (drag-persist, add-note, minimap, PNG/SVG) were
  queued in prose but are in fact **built** — confirmed in `graph_view.py` + `graph_html/app.js`.
- **Project file ops (§19):** now **built** in `workspace/portability.py` (Open-by-IP / Import / Export
  `.tar.gz`, traversal-safe) — the last item that was still "queued" in ROADMAP is done.
