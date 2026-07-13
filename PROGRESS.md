# oscp-recon — progress log

Running record of what's been built, in order, so any session can pick up mid-stream.
**Read "Next up" first, then the newest log entry.** Authoritative specs live in `CLAUDE.md`
(the brief) and `ROADMAP.md` (the phase plan); this file is "where are we right now".

## Next up

**See [`PROJECT_MAP.md`](PROJECT_MAP.md) for the authoritative status map** (subsystem-by-subsystem
✅/🚧/⏭/🕒/⛔/❌, dependency graph, forward phases). This "Next up" is the one-line pointer.

Phases 0–5, all **20 recon modules**, Phase 4 graph, the full Workspace Dashboard, exam profile,
project file ops §19, EDB persistence, AD/Kerberos, **HackTricks Phases 1–3 + owner-approved live
fetch/cache (§14a)**, **durable project credentials + opt-in spray**, the **doctor guided installer**,
the **single-click AppImage + splash**, and **parser multi-version resilience** are **DONE**. Phase 6
is partial: only the *timed* mock exam remains (blocked on a live target).

**The in-scope, deterministic backlog is now fully exhausted** — spray preserves the discovered port,
and both low-severity live-fetch residuals are hardened (markdown link-syntax escaped in extracted
live content, proven at render level; missing `Content-Type` explicitly rejected). **Everything that
remains is blocked on external resources:** the *timed* mock exam needs an authorized target, and full
interactive + cross-machine AppImage acceptance needs a real desktop / a second VM (see
`packaging/ACCEPTANCE.md`). No deterministic next chunk — the next move is the owner's call.

### Pre-live-testing polish (owner-requested)
A run of owner-requested improvements before live-box testing:
- **Finding-aware jump now applies to LIVE HackTricks content** (not just vendored); **audit coverage**
  for live-refresh / spray-confirmations / secret-copy (all secret-free).
- **Doctor** now checks the Spray-mode tools (hydra/medusa), labeled spray-only + excluded from
  auto-install (recon users aren't pushed them).
- **Fail-loud parsers**: `run_parser(raw=…)` surfaces "output present but 0 findings parsed — possible
  drift" (the silent-zero-findings case); nmap "ran but 0 services parsed" warning in the orchestrator.
- **FTP + SMB post-access file peek**: on anon/authed access, a bounded file **tree** (name · size ·
  ext) plus a safe **~60-char content peek** of small text files (`peek.py` shared helpers; SMB share
  contents are now parsed for the first time). Bounded triage (§12), never bulk exfil.
- **Graph → BloodHound feel**: a **search bar** (type ssh/445/admin → highlight + fit), **auto-highlight
  of notable/vulnerable findings** (anon access, writable, weak signing → red ring), and **double-click
  drill-down** (collapse/expand a service's findings).
- **`install.sh`**: hardened fresh-Kali bootstrap (allow-listed tools + uv + app; spray tools behind
  `--with-spray`; fail-safe; doctor readiness check).

### Credential-spray Burp-clean UX polish
Owner-expressed direction ("clean GUI, Burp's layout"). Applied to the credential surface:
- **Credential Vault → a proper table** (Username / Domain / Type / Secret / Source / Confirmed) with
  masked secrets. **Copy username** + **Copy secret** put values on the clipboard only — the plaintext
  is never rendered in the UI. **Edit** (prefill via the Add dialog) alongside Add / Delete. A
  **Confirmed** column surfaces which services a spray validated a credential against (from
  `tested_against`). Read-only disables mutation but keeps copy.
- **Add Credential dialog** gained edit-prefill (titled "Edit Credential").
- **Spray dialog** reorganized into clean group-box sections (Credentials · Services · Command preview).
- +3 tests (vault table masking, copy-to-clipboard-only, edit-replaces, confirmed column, read-only).

### Live HackTricks fetch/cache + durable creds + parser resilience + AppImage acceptance
A sequenced workstream (owner-approved live HackTricks + the two permanent product rules). In order:
- **Owner decisions + policy** — `docs/OWNER_DECISIONS.md` + CLAUDE.md §14a: live fetch/cache is
  approved but bounded (only the canonical mapped page, HTTPS + allow-listed host, NEVER transmit
  target/cred data; vendored offline stays the fallback). Exploit-DB stays lookup-only.
- **Live engine** (`references/live_hacktricks.py`) — allow-listed HTTPS fetch (size/timeout/
  content-type bounded, cross-host redirects refused), HTML→own-markdown sanitizer (no remote JS/HTML
  rendered), XDG cache with conditional requests + atomic writes + corrupt-degrade + refresh-failure
  retention + clear-cache-spares-project-data. Off-by-default `hacktricks_*` settings.
- **Live GUI** — reference pane states (offline vendored / live cached / live refreshed / live page /
  unavailable) + Refresh / Use-offline buttons; off-thread `LiveHacktricksWorker`; stale-result
  guard (request-id + url match) so A never overwrites B; References Preferences tab.
- **Routing + sections** — fixed a real bug (DBs/services on non-standard ports routed nowhere → added
  service-name fallbacks); `references/sections.py` local, code-fence-aware section extraction with the
  §14a priority; product-aware jump fallback.
- **Durable credentials** — audited (mutated only via guarded add/delete; originating-project scoped;
  never unlinked); hardened save (partial-temp cleanup preserves the prior store); `set_credentials`
  bulk write; confirmed-spray recording into `tested_against` (add-only, service-specific, no secret
  leak); safe spray temp-file cleanup (only users.txt/passwords.txt, after the last worker).
- **Parser resilience** — partial-extraction: fixed whatweb NDJSON drift (was 0 findings) + control-char
  leak into HttpFinding; multi-version fixtures asserting valid rows survive malformed/truncated ones.
- **AppImage acceptance** — real build on Kali; fixed two build-script defects (externally-managed pip,
  non-relocatable symlink copy → 961 KB empty bundle); 242 MiB self-contained artifact verified from
  outside the checkout (`packaging/ACCEPTANCE.md`). Interactive/cross-machine acceptance still open.

### AD/Kerberos enum module — DONE (enumeration only, no cracking §2)
New `modules/kerberos/` — the 20th service module, wired into the shared SimpleRecon panel.
- **Tier-1 (credential-free):** `nmap -sV -p 88` confirms the KDC (a DC) + reads its server time
  (Kerberos clock-skew reference). Parser → `service` / `server-time` findings + a "this is a DC"
  suggestion.
- **Tier-2 manual follow-ups** (`manual_commands.yaml`, shown/never-auto): single-user AS-REP check
  `GetNPUsers.py {domain}/USER -no-pass` (edit USER — **not a userlist**, so not a list brute); creds-
  gated `GetADUsers.py -all` (user listing), `GetUserSPNs.py` (SPN listing, **no `-request`**), and an
  LDAP SPN query. All impacket scripts are §2-allowed enum scripts.
- **Parsers** for GetNPUsers/GetUserSPNs/GetADUsers: extract the **principal / SPN / username** —
  **NEVER the AS-REP or TGS hash** (that's cracking material, out of scope). `patterns/kerberos.yaml`
  (4 entries) says "cracking is out of scope" explicitly.
- **Tests (+12 → 721):** parser tests (incl. an assertion the hash blob never reaches a finding),
  module tests (triggers, Tier-1 command, DC suggestion), manual-command policy-clean + enum-only
  (no `-usersfile`/`-request`/cracking tools), SimpleRecon worker parse, pattern firing. The
  parametrized `test_simple_panel_manual_followups_stay_legal` now covers kerberos too.

### HackTricks Phase 3 — cleaner mdBook render + expanded finding→section maps
Offline HackTricks pane polish. Two deterministic in-scope parts; the third (§27 live-fetch relax) is a
policy decision deliberately NOT bundled here — the scraping ban is a hard §2/§27 line (amend-first).
- **Cleaner rendering** — `hacktricks.clean_markdown()` normalizes the mdBook/HackTricks syntax that
  Qt's CommonMark renderer showed as literal noise: `> [!TIP]/[!WARNING]/[!CAUTION]` callouts → bold
  labels, `<details>/<summary>` → bold heading + preserved content, offline `<figure>/<img>` removed.
  Verified zero leftover tokens across all 21 pages. Applied at the render boundary (loader still
  returns raw). `reference_pane` also gets a light theme-neutral document stylesheet.
- **Expanded + fixed section map** — `_FINDING_SECTIONS` grew from 5 modules/8 entries to 12 modules/30
  entries, all keyed on **real** parser finding kinds and all keywords verified to exist in the cleaned
  page. Fixed two long-dead entries (`ldap:auth`→`bind`, `snmp:system`→real kinds) that never fired.
- Tests: `clean_markdown` unit + real-page token-strip; a **guard test** that every map keyword exists
  in its cleaned page (catches drift on a future vendor refresh); an integration test that the rendered
  offline text has no raw callouts/tags.

### Single-click contained app + branded splash (distribution items 4–5)
Public-release packaging + startup branding. §27 amended first to permit an offline splash + a
build-time contained-app bundle (still no runtime network/telemetry/auto-update).
- **Splash** — `src/oscprecon/gui/splash.py::make_splash()` paints an ASCII wordmark + version + the
  recon-only tagline onto a `QSplashScreen`. Wired into `gui/app.py::main()` **defensively**: a splash
  failure is caught and `splash=None`, so it can never block the main window. Shown → `processEvents`
  → build MainWindow → `finish()`; no artificial delay. Offscreen smoke tests + a lifecycle smoke.
- **AppImage** — `packaging/`: `build-appimage.sh` (maintainer script, run on Kali — bundles a
  relocatable `uv` standalone CPython + the wheel; Qt/QtWebEngine ride inside the PySide6 wheel; AppRun
  runs `-m oscprecon`; `appimagetool` packs `dist/oscp-recon-<ver>-x86_64.AppImage`), a validated
  `.desktop`, and a generated `oscp-recon.png` icon. Not shipped in the wheel (build infra).
- Can't produce/run the binary in this sandbox (no display/network for appimagetool) — the splash is
  fully tested; the AppImage recipe is verified by lint/format/asset checks and run on Kali by the user.
- Tests: splash render + version symbol; packaging assets present/well-formed (PNG magic, desktop keys,
  script shebang + `-m oscprecon`, no forbidden tools) + wheel excludes `packaging/`.

### `doctor` → guided safe installer (distribution item 2)
`oscprecon-cli doctor` gained a guided installer + a GUI Help→Doctor status view. Safety-first:
- **`src/oscprecon/doctor.py`** engine: `scan()` (per-tool present/missing + hint), `install_plan()`
  (deduped apt packages derived ONLY from allow-listed tools' curated hints via a strict
  `^apt install <pkg>` regex — non-apt pipx/git hints become MANUAL, never auto-run), `install()`
  (shows the exact `[sudo] apt-get install -y <pkgs>`, requires explicit confirm unless `--yes`,
  injectable runner, catches OSError when apt/sudo absent → tells the user the command). No shell, no
  user input in the command — packages can't smuggle metacharacters.
- **CLI**: `doctor --install [--yes]` (status output preserved; points to `--install` otherwise).
- **GUI**: Help → Doctor… read-only dialog (present ✓ + missing with hints); installation stays in the
  CLI (apt needs a terminal/sudo).
- Tests: engine (scan/plan dedup+manual-split/`_apt_package` injection-safety/confirm gating/runner/
  missing-apt OSError), CLI (--install runs one curated apt argv via a fake runner; cancel path), GUI
  dialog. Independent code-review run on the diff.

### Parser tool-update resilience — never crash on drifted tool output (`595d55a`)
The owner's top public-release worry. Two layers:
- **Containment net:** `src/oscprecon/parsing.py::run_parser(parse, *, label, on_line=None)` wraps a
  parser at the worker/GUI boundary; on ANY exception → log + emit `[parse-error] couldn't parse <tool>
  … the tool may have changed` + return `[]`, so the recon step still completes. Wired at every runtime
  parse site: `workers/simple.py` (`module.parse`), `workers/service_recon.py` (smb/ftp/ssh/dns/ldap via
  `functools.partial` — no loop-closure bug), `main_window` (http/vhost).
- **Per-parser:** `tests/test_parser_resilience.py` fuzzes every dispatcher (real tool keys) with 11
  malformed/drifted inputs (empty, garbage, truncated/wrong-typed JSON, 8k line, control bytes, "new
  format") asserting each returns a list, never raises. Found one raiser — http ffuf/gobuster/whatweb
  JSON `int()` on a non-numeric field — fixed with a type-safe `_to_int` (bad value → 0).
- Tests (+~60): the fuzz matrix; run_parser contains a raiser + passes success through; a
  SimpleReconWorker survives a `parse()` that raises. 813 pass. (Deepening: multi-tool-version fixtures.)

### HackTricks integration Phase 2 — offline render + finding-aware jump (`7e5005e`, `f2fdef3`)
Reference pane now surfaces the vendored HackTricks page:
- **2a (`7e5005e`):** an "Offline" tab renders the vendored markdown via `QTextBrowser.setMarkdown`
  (no WebEngine, works with no internet), default-selected when a page exists; a "Live page" tab holds
  the existing web view; the clickable `book.hacktricks.wiki` link stays above both (view-it-yourself).
- **2b (`f2fdef3`):** finding-aware jump — `main_window._on_service_selected` passes the service's
  findings; the pane scrolls the offline page to the section matching a finding kind (verified keyword
  map: smb auth→Server Enumeration / share→Shared Folders, ftp auth→Anonymous login, ssh
  algo-weak→Weak Cipher Algorithms, ldap auth→Anonymous Access, snmp→community/enumeration), showing a
  grey hint; a miss is a no-op. Plus a wrap-around "Find in HackTricks page…" box.
Tests (+7): offline render (smb→445/SMB, no `{{#include}}`), offline-first default + live link, live
fallback for unmapped services, finding-aware jump + hint, kind→section map, find box. NEXT: Phase 3
polish (more maps, cleaner mdBook render) — or pivot to distribution (parser tool-update resilience).

### HackTricks integration Phase 1 — vendored offline snapshot + loader (`37f0d68`)
§2/§27 gate cleared earlier (`bf42f1e`). Build-time vendoring, NO runtime scraping.
- `references/hacktricks/refresh.py` (maintainer-run, the only network toucher): fetches source
  markdown for our 21 service modules via an explicit `module → repo-path` map (repo filenames include
  port prefixes and differ from book-URL slugs, so it's curated + verified against the repo listing),
  strips mdBook `{{#include}}` banner directives, writes `pages/<module>.md` + `index.json` + `NOTICE.md`
  (CC BY-NC-SA attribution). 21 pages, ~436 KB.
- `oscprecon/hacktricks.py`: offline loader — `page_for_module(m)` → `HacktricksPage{title, markdown,
  live url}`; pure file reads.
- Tests (+4): offline index load, real content + book link, unknown→None, and an accuracy guard that
  every vendored page actually matches its service + has includes stripped. `test_packaging` asserts the
  snapshot ships in the wheel. NEXT: Phase 2 render + section extraction (show data beside the link).

### Credential spraying — opt-in, off by default (§2a) — COMPLETE end-to-end
GUI (chunks 4–5): **Credential Vault dialog** (`bd4fd1e`) — Edit → Credential Vault…, list with
redacted secrets + add/delete (Profile.add/delete_credential, read-only-guarded). **Spray dialog +
runner** (`1531f59`) — Scan → Credential Spray…, service checkboxes + live preview; Run gated on the
setting; `_on_credential_spray` re-checks `config.spray_enabled`, writes 0600 spray lists from the
vault, and launches each service via `CommandWorker(spray=True)` — the ONE place spray=True is passed.
Safety test: launches NOTHING when the setting is off, even if the dialog is stubbed to accept.

### Credential spraying — opt-in, off by default (§2a) — ENGINE DONE
Owner-approved scope change (verified OSCP-legal). CLAUDE.md amended (`ab9829f`): §1 recon-only →
recon-first, §2 hydra/spray gated, new §2a Spray-mode contract, Tier-3 Forbidden → Gated. Engine
across 3 chunks:
- **spray 1/N (`e4fcf7d`):** `config.spray_enabled` (default false) + accessor; `shell.policy_violation
  (argv, *, spray=False)` — default byte-identical, `spray=True` unlocks ONLY the credential-attempt
  category (SPRAY_TOOLS hydra/medusa, --passwords/--continue-on-success, wpscan -P/-U, netexec
  list-spray, nmap *-brute) and STILL blocks Metasploit/SQLMap/DB-primitive/ike-PSK/searchsploit-PoC/
  ntpdate; `shell.run(..., spray=False)`.
- **spray 2/N (`2923177`):** `spray.py` (SPRAY_SERVICES smb/winrm/ldap=netexec + ssh/ftp/rdp=hydra;
  build_spray_command single-target; write_spray_lists 0600; vault_material passwords-only);
  `creds.delete_credential`; `wordlists` password-list gating (surfaced only in Spray mode).
- **spray 3/N (`6ea11cc`):** Preferences Scan-tab "Enable Spray mode" toggle (off by default, §2a
  warning).
Safety: every spray command is BLOCKED by the default policy and clears ONLY with spray=True (tested
per service). NEXT: the spray GUI (panel + editable cred-vault UI, Burp-clean; worker gates on
config.spray_enabled). 732 tests green.

### Report Exploit-DB-hit persistence — DONE (lookup-only §14)
searchsploit runs live in the reference pane; now its hits persist and land in the report.
- **`src/oscprecon/edb.py`** — per-profile `edb.json` store: `add_edb(service, product, version, hits)`
  writes `{service, product, version, edb_id, title, url, discovered_at}`, deduped on
  (edb_id, product, version). **Lookup-only: the local PoC `path` is NEVER stored** — no run/copy path.
- **GUI**: `MainWindow._on_service_selected` captures the service context; `_on_edb_done` →
  `_persist_edb` writes the store for the current lookup (stale results dropped), **skipped in
  read-only mode**. searchsploit results come from the local exploitdb DB (curated titles), not target
  output, so no report-injection surface.
- **Reporter**: `_group_edb` + an "Exploit-DB references" `report.md` section (Obsidian callout stating
  lookup-only §14; grouped by service; clickable `[EDB-<id>](url)` links; no PoC path).
- **Tests (+9 → 709):** store round-trip/dedup/distinct-version/empty/corrupt; report renders the
  section + placeholder + omits the PoC path; GUI persists + read-only skips.

### Pattern coverage ssh/ike/tftp/vhost — DONE (Phase 3 breadth complete: 19/19 modules)
Added `patterns/{ssh,ike,tftp,vhost}.yaml`, closing the last pattern gap (was 15/19). Each entry
matches the module's REAL finding shape and interpolates context:
- **ssh** (kind banner/hostkey/algo-weak/auth): version→searchsploit lookup; publickey→hunt for
  id_rsa; password-auth note (single manual login only, never a list); weak-algo note.
- **ike** (kind service/transform/aggressive/note): enumerate transforms + aggressive-mode test
  (`ike-scan -M -A {target}`); aggressive-mode misconfig note; weak-transform note.
- **tftp** (kind file): `curl -s "tftp://{target}/{value}"` retrieval; well-known config filenames;
  grep-downloaded-files-for-secrets note.
- **vhost** (vhost/status/size/ip): `whatweb http://{vhost}/`; status-200→`feroxbuster` content
  discovery; response-size vs wildcard-baseline note.
All recon-only (pass the §15 forbidden-content gate), all commands allow-listed + policy-clean, all
provenance-cited (`# source: Obsidian: 0.01 Cheatsheets/All_In_One`). +1 engine test asserting they
fire on real shapes and every command clears `shell.policy_violation`. 47 rules total; 700 tests green.

### Project file operations §19 — DONE (deterministic; no live target)
Each `~/oscprecon/<name>/` is now a portable project file. New module
`src/oscprecon/workspace/portability.py`:
- **`find_profiles_by_ip`** — scan `<workspace>/*/profile.json`, return dirs whose `target.ip` matches
  (corrupt/partial profiles skipped). Backs `File → Open by IP…`.
- **`export_project_archive`** — pack `<profile>/` → `<name>.tar.gz`, dropping transient `.lock`/`*.tmp`.
  Includes `creds.json` verbatim; the caller warns (GUI + CLI both do).
- **`import_project_archive`** — **security-critical.** Validates EVERY member before extracting:
  rejects absolute paths, `..` traversal, backslash names, symlinks/hardlinks, device/fifo specials,
  members that escape the workspace, multiple top-level dirs, non-profile archives, and a
  decompression-bomb size cap (2 GiB). Extracts to a staging dir, confirms `profile.json`, then swaps
  into place — a hostile/non-profile archive leaves nothing behind. Refuses to clobber unless
  `overwrite=True` (raises `ProjectExistsError`).
- **GUI** (`main_window`): File menu Open by IP / Import Project / Export Project; import prompts to
  overwrite on collision and warns on malicious archives; export warns `creds.json` is included; all
  three gate off during a running scan. **CLI**: `export-project` / `import-project` (`--overwrite`).
- **Tests (+28 → 699):** 17 portability (round-trip, find-by-ip, collision/overwrite, and the full
  malicious-archive matrix incl. bomb), 4 CLI, 7 GUI. Adversarial review added the decompression-bomb
  cap. Gates green incl. packaging (new module ships).

### Phase 6 · exam-mode scan profile — DONE (deterministic; no live target)
Introduced scan profiles governing the nmap discovery battery, plumbed end-to-end:
- **`config.Settings.scan_profile`** (`quick`/`default`/`full`/`exam`, default `default`) — validated
  in `normalized()`, persisted in `prefs.json`, invalid → default. New non-secret pref key.
- **`NmapModule(scan_profile=...)`** — `_discovery_battery` branches by profile; unknown value falls
  back to `default` (defence-in-depth). `default` is byte-identical to the historical battery.
  - quick: `--top-ports 1000 -T4` only (no `-p-`, no UDP).
  - default: `--top-ports 1000` → `-p-` → UDP top-100 (+ udp-full on the flag).
  - full: default battery + always `-sU -p-`.
  - exam: `--top-ports 1000 -T4` → `-p- --min-rate 1000 -T4` → UDP top-100. Tight/fast, **no `--script
    vuln`** — every line clears the §2 exec policy.
- **Plumbing:** `Orchestrator(scan_profile=...)`, CLI `oscprecon-cli scan --scan-profile` (validated,
  exits 2 on unknown), GUI `NmapWorker(scan_profile=...)`, `MainWindow._start_recon` (Run Full Recon
  uses the configured default; `Scan → Run recon with profile` overrides per-run), Preferences → Scan
  tab default-profile combo.
- **Tests (+14 → 671):** per-profile batteries + `default`-unchanged regression + every-profile
  policy-clean + unknown→default; settings roundtrip/invalid/known-keys; CLI reject-unknown + threads-
  through; GUI combo populate/collect + `_start_recon` profile pass-through. Adversarial review found +
  fixed 2 items (KeyError-proof menu tooltips via `.get`; added the CLI validation test).
- Gates green: `mypy --strict`, `ruff check`, `ruff format --check`, 671 pytest (182 offscreen GUI),
  packaging. No new shipped resources.

### Workspace Dashboard & Project Organization upgrade — DONE (deterministic; no live target)
Turned the app from individually-opened profiles into an organized local workspace. New non-GUI
package `src/oscprecon/workspace/` (business logic; profiles stay authoritative, the index is never a
second source of truth) + `src/oscprecon/gui/workspace/` (dashboard). Commits `e6ffb7e`..`6bfef69`.
- **index + models** (`e6ffb7e`): scan_workspace/summarize_profile → lightweight ProfileSummary (counts
  + booleans, NEVER secrets) built without reading raw output; tolerant of missing/corrupt/partial
  profiles (warning rows), ignores unrelated folders, skips symlink escapes, survives permission
  failures. profile.json gains a normalized `organization` block (status/tags/pinned/archived/
  display_name) — backward-compatible, atomic; Profile setters + `mark_opened()`.
- **search** (`e19897e`): cross-profile search (names/targets/tags/services/ports/findings/notes/report/
  commands/cred USERNAMES+DOMAINS). Secret values never indexed/shown; previews single-line, control-
  stripped, capped, PLAIN-text. Filters: port/service/tags/status/finding-kind/profile/archived/limit.
- **locks + read-only** (`6336f90`): advisory `<profile>/.lock` (pid/host/version/ts, no personal data);
  live-lock never stolen, stale (same-host dead PID) recoverable, foreign-host conservative, PID-reuse
  safe. Profile `read_only` flag raises ReadOnlyError on every disk write; reads + export still work.
- **health** (`268471d`): read-only check_profile (corrupt/truncated JSON, malformed audit lines,
  stale temp, orphan output, orphan findings, world-readable creds, path escape) + safe repairs
  (creds→0600; stale temp MOVED to health-backup/, never deleted).
- **activity** (`0a47b4d`): human-readable timeline from audit.jsonl (malformed lines skipped+counted,
  secrets redacted). **saved views** (`ccd9457`): filter-only config, built-ins + user CRUD, corrupt-
  safe. **bulk** (`67a24f8`): tag/status/archive/restore/report/export/health across a selection —
  never stops on first failure, skips locked/corrupt, cancellable, audited (no scan/cred/delete).
- **dashboard + wiring** (`6bfef69`): WorkspaceDashboard (off-thread cancellable scan, table, filter,
  saved-view combo, show-archived, actions, empty-state, a11y) is the home view (`Ctrl+0` / startup);
  MainWindow acquires the lock on open, prompts read-only for a live foreign lock, and disables all
  writes (run/save/add-cred/notes/audit/reference-visits) + shows `[READ-ONLY]` when read-only.
- **packaging verification + docs** (`1e6d11e`): confirmed the wheel ships `workspace/` + `gui/workspace/`
  and both import + function from a clean venv outside the checkout.
- **adversarial-review fixes** (`eebc8cc`): refute-biased review across the upgrade surfaced 8 real
  defects, each reproduced + regression-tested + fixed with the smallest change — tag single-source-of-
  truth (organization.tags mirrored to profile.tags for the report/Obsidian frontmatter), profile.json
  symlink-escape guard, cancellable `scan_workspace`, atomic-rename `recover_stale`, dashboard skips
  live-locked profiles + emits `profile_mutated`, PlainText details/lock dialogs, main-window reloads an
  open profile's org block so a later save can't clobber a dashboard edit.
- **settings dialog** (Chunk 11): `config.Settings` typed layer (load/save/reset, validation +
  clamping, atomic, no secrets) on top of `prefs.json`; `DEFAULT_WORDLIST_PATHS` + validation bounds
  centralized in `config`. `SettingsDialog` (`File → Preferences…`, `Ctrl+,`) with 8 tabbed sections —
  Workspace (root, create-on-save), Appearance (theme + live font override), Tool paths (wordlist
  search paths, password lists always filtered), Scan (opt-in full-UDP sweep), Reports (fixed
  redaction/archiving guarantees, informational), Privacy (mandatory protections shown locked-on —
  cannot be disabled), Performance (max concurrent workers), Advanced (config path + reset). Wired live:
  theme/font/concurrency re-applied on save, `nmap_udp_full` drives `NmapWorker`, dashboard re-scans on
  workspace-root change, theme menu stays in sync.
- Verify: four gates + offscreen GUI green, 656 tests; wheel ships `workspace/` + `gui/workspace/` and
  they import + function from a clean venv outside the checkout. Import note: `workspace/bulk.py`
  imports profile/reporter/vault_export so it is NOT re-exported from `workspace/__init__` (cycle).

### GUI architecture cleanup — behavior-preserving extraction of main_window.py — DONE (3 chunks)
main_window.py 1633 → 945 lines with no behavior change (all signals, menu actions, auditing,
cancellation, reports, module workflows preserved); one latent stale-profile bug fixed along the way.

**Original responsibility map** (what main_window owned): 2 dialog classes; the CancellableThread base
+ 8 QThread worker classes (nmap/command/searchsploit + Smb/Ftp/Ssh/Dns/Ldap/Simple recon) + their
Result dataclasses; worker launch/registration/cancellation/completion/release; profile
create/open/save/close/recent; findings + credential persistence; notes flush; graph/report/vault
export; audit events; menu + status-footer + busy-gate refresh; module-specific completion handlers;
shutdown.

**Extractions:**
- **1/N `a136d05`** — workers → `src/oscprecon/gui/workers/` (base.py = CancellableThread; scans.py =
  Nmap/Command/Searchsploit; service_recon.py = Smb/Ftp/Ssh/Dns/Ldap + Result dataclasses; simple.py =
  SimpleReconWorker). Every signal, cancel path (`shell.run(cancel=)` + process-group kill), output
  filename, per-worker profile ownership, and port propagation preserved verbatim; re-exported from
  main_window via `__all__` so existing imports/tests keep working. tests/gui/test_workers.py.
- **2/N `4f6debd`** — dialogs → `src/oscprecon/gui/dialogs/` (new_profile.py, credential.py), re-exported.
  tests/gui/test_dialogs.py (accept/cancel/empty/validation/secret-masking).
- **3/N `fb10c7c`** — centralized task lifecycle (`_start` = one line/done/failed wiring path; `_release`
  idempotent) + **stale-profile protection**: every launcher captures the ORIGINATING profile and binds
  it into the completion handler, so a worker that finishes after the user switched profiles persists
  its creds/findings/service-mutations to the profile that started it (not the active one), and only
  echoes to the panel when its origin is still active. Previously used `self._profile` (a late result
  would have written another profile's data + shown A's results in B; the New/Open gating made it
  UI-unreachable, so this is defense-in-depth made robust). tests/gui/test_task_lifecycle.py.

**Deliberately kept in MainWindow** (no clean non-GUI boundary): profile create/open/save/export are
thin orchestration over the existing `Profile` model + `config` recent-list + dialogs + `_set_profile`
UI refresh — a "controller" would be pure indirection. closeEvent stays (cancel-then-wait, already
tested deterministically). Completion handlers stay per-module (their summaries/creds differ) but now
share `_record_creds` + the origin-guard for the genuinely-identical parts.

**Verify:** four gates green, offscreen GUI suite green, 554 tests, clean-wheel install imports
`gui.workers` + `gui.dialogs` from outside the checkout with re-exports intact.

### Repo-wide cleanup pass (adversarial review — 10 findings, all fixed) — DONE
Area-partitioned review (10 subsystem finders + refute-biased verify, all reproduced) → 10 confirmed
findings, each fixed with a regression test in small commits:
- **shell.py** (`11ae100`): timeout/cancel/finally killed only the direct PID; since the child is a
  `start_new_session` group leader, forked helpers (enum4linux-ng→smbclient, dnsenum→dig) orphaned and
  could hold the stdout pipe so timeout/cancel never landed → `_terminate()` kills the group. Plus the
  queued **DB-client primitive backstop**: `policy_violation` now refuses INTO OUTFILE/DUMPFILE,
  LOAD_FILE, sys_exec/eval, lo_import/export, pg_read_file/ls_dir, `\!` for mysql/psql/mongosh/redis-cli.
- **dns** (`8eece95`): `parse_dnsrecon` only matched legacy `[*]` rows; dnsrecon 1.6.x (current Kali)
  logs `<ts> INFO TYPE name data` → all records silently dropped. Accept both prefixes (+ INFO fixture).
- **config/patterns/vault/graph** (`f941c01`): atomic temp+rename for prefs/recent.json; `_FORBIDDEN`
  pattern gate gained --continue-on-success/patator/crowbar; vault re-export rmtree's its own subfolder
  first (stale-orphan snapshot); `load_graph` coerces wrong-typed user_edges/node_overrides.
- **wordlists + dead code** (`e3c730e`): `_category_for` matched needles as unbounded substrings so
  "api" mis-tagged capital/therapist/rapid → token-boundary match; removed dead `_auto_output` +
  WordlistPicker.indexed signal.
- **gui closeEvent** (`4cfbc7f`): waited on running QThreads without cancelling first → froze the UI for
  the tool's full remaining runtime on close. Cancel-then-wait.
- **repo hygiene**: `.gitignore` now covers mypy/ruff caches, build/dist, coverage, `*.log`, and the
  local `mirror.sh`; classified stray files (`autosave.sh` tracked/intentional; `mirror.sh`+`sc_audit.log`
  local artifacts; `prompts/` empty). Repeatable **packaging smoke test** proves the wheel ships all
  YAML/HTML/CSS/JS/template resources and the 3 console entry points load from a clean venv.
- 511 → tests green after the pass; four gates + offscreen GUI suite clean.

### Phase 2 · PostgreSQL module (postgresql) — DONE
Fifth and final DB service module (module name `postgresql`, matching the services.yaml stub).
Banner-only per §12, but distinct from the mysql/mssql twins in two ways below.
- **Tier-1 is credential-free `nmap -sV -p {port}` version detection ONLY**: there is no unauth
  PostgreSQL info NSE (the only pgsql script is `pgsql-brute`, forbidden + policy-blocked), so none is
  invented and no login is attempted. Test asserts the argv carries no `-U`/`-c`/`--script`/creds.
- **Non-standard port propagation** (the mysql/mssql modules silently hardcoded their default): the
  discovered port now flows through the shared simple-recon chain — panel `recon_requested(module,
  port)` → `tool_panel.simple_recon_requested(str,int)` → `SimpleReconWorker(profile, module, port)` →
  `steps_fn(target, port)` → `recon_steps(target, port)`. PostgreSQL honours it in the command, the
  output filename (`nmap-sv-{port}.txt`), and a `port` finding; mysql/mssql recon_steps now take the
  port too (default when 0). No silent 5432 fallback (regression-tested end-to-end + panel-emits-port).
- **parser** (`parsers.py`): structural `^<port>/tcp open [ssl/]postgresql\b` match → service / version
  (product prefix stripped) / TLS-wrapped / port findings. A bare "PostgreSQL" log/error line is never a
  finding; `[ \t]` anti-newline-bleed; CRLF + `[missing]`/`[blocked]` sentinel + malformed-safe; dedup.
- **shell-policy hardening**: the DB-client backstop gained a PostgreSQL keyword regex (`_PG_FORBIDDEN_RE`)
  blocking COPY…TO/FROM/PROGRAM, CREATE/DROP FUNCTION/EXTENSION/ROLE/DATABASE, ALTER ROLE, DO $$,
  pg_read_file/pg_write_file/pg_ls_dir, lo_import/export on the custom-command path — WITHOUT
  false-positiving read-only enum (SELECT … FROM pg_database/pg_roles). Applies to all DB clients.
- **Tier-2** `manual_commands.yaml` (6): single postgres superuser check (terminal-only — GUI disables
  stdin), postgres:postgres default-cred, and creds-gated version/databases/roles/current-user enum, all
  via the libpq connection URI (`postgresql://user:pass@host:port/db`) so creds work under argv exec
  (`PGPASSWORD=` would not). **pattern** `patterns/postgresql.yaml` (2, `# source:`): fires only on real
  identification (never a bare open 5432) and interpolates target+port. **GUI**: one `SIMPLE_SPECS` entry.
- 12 parser + 6 module + postgres shell-policy + pattern-engine + 3 GUI (worker, non-standard port,
  panel-emits-port) tests. 537 pass; wheel ships the new resources. **Adversarial 5-lens review**
  (11 agents): parser / port-propagation / tier-boundaries / manual-safety / patterns / GUI-lifecycle /
  packaging all came back **clean**; 6 confirmed findings, all in the new custom-command policy backstop
  (defense-in-depth), all fixed: tagged dollar-quote `DO $body$…$body$` bypass, `/**/` comment splitting
  `CREATE/**/FUNCTION`, `ALTER/DROP USER` role-aliases, `pg_read_binary_file`/`pg_ls_*dir`/`pg_stat_file`
  variants, `GRANT pg_read_server_files`, and a `SELECT copy FROM` false positive. Backstop now strips
  SQL comments before matching + uses keyword-family regexes. `6628bc8` + policy hardening follow-up.

### Phase 2 · MySQL module (mysql) — DONE
Fourth DB service module — banner-only per CLAUDE.md §12 (MySQL = "Banner only"; root default-cred is
user judgment, Tier-2), built as the direct twin of MSSQL. Shared `SimpleReconSpec`, name `mysql`
matching the existing services.yaml 3306 stub.
- **engine** (`modules/mysql/`): `MysqlModule` triggers 3306 + service `mysql`; ONE Tier-1 step
  `nmap -sV -p 3306 --script mysql-info` attempting NO credential — the pre-login handshake leaks
  version / protocol / auth-plugin (test asserts argv carries no mysqluser/mysqlpass/-u/empty-password
  + passes `shell.policy_violation`). suggest() nudges the single root-empty/root:root Tier-2 check.
- **parsers** (`parsers.py`): version (structured `Version:` field, else the -sV service line — handles
  MariaDB and the TLS-wrapped `ssl/mysql` banner), protocol, auth-plugin. The MSSQL review lessons were
  applied up front: `[ \t]` anti-newline-bleed leading char-classes + `\s*$` trailing anchors on every
  field regex (CRLF-safe), an -sV-only fallback, and the `[missing]`/`[blocked]` sentinel skip.
- **Tier-2** `manual_commands.yaml` (6): nmap `mysql-empty-password` (single root+anonymous, not a
  list), root:'' and root:root mysql-client logins, and creds-gated `mysql-variables`/`mysql-users`
  NSE + `SHOW DATABASES`. NetExec has no mysql protocol (verified against the nmap DB), so the client
  checks use the `mysql` client + nmap only; test enforces argv0 ∈ {nmap,mysql} and no
  `INTO OUTFILE`/`LOAD_FILE`/`sys_exec`/`\!`.
- **pattern** `patterns/mysql.yaml` (2 rules, `# source:` cheatsheet): version → Tier-2 default-cred
  (2 suggests); legacy 4.x/5.x/MariaDB → searchsploit (display-only). **GUI**: one `SIMPLE_SPECS` entry.
- 2 fixtures (nmap-info / -sV-only) + parser/module/GUI tests incl. MariaDB, `ssl/mysql`, CRLF, the
  bare-line no-bleed, and `suggest([])`. Extended `test_patterns_engine` to positively assert the
  mysql+mssql shipped patterns fire through the engine (closed a shared coverage gap the review found).
  Repointed the `test_widgets` hints-only example 3306→3389/rdp (the new module moved 3306 to a
  dedicated panel). **Adversarial 3-lens review** (10 agents): 6 confirmed / 1 refuted, **no medium+**
  (the proactive lessons paid off) — `ssl/mysql` miss, CRLF auth-plugin drop, dead `mariadb` name, and
  the MariaDB pattern hyphen all fixed; the custom-command DB-primitive backstop
  (`INTO OUTFILE`/`LOAD_FILE`) is cross-cutting → ROADMAP Phase-6 TODO. Exam-legality clean
  (`mysql-empty-password` root+anonymous confirmed Tier-2). Four gates green, 498 tests.

### Phase 2 · MSSQL module (mssql) — DONE
Third DB service module (after Redis/Mongo), but banner-only per CLAUDE.md §12 (MSSQL = "Banner
only" — default-cred is user judgment, not auto). No data auto-enum; the whole Tier-1 is an unauth
pre-login info leak. Shared `SimpleReconSpec` (no bespoke panel/worker), name `mssql` matching the
existing services.yaml 1433 + 1434-browser stubs.
- **engine** (`modules/mssql/`): `MssqlModule` triggers 1433 + `ms-sql-s`/`ms-sql`/`ms-sql-m`/`mssql`;
  ONE Tier-1 recon step — `nmap -sV -p 1433 --script ms-sql-info,ms-sql-ntlm-info` — attempting NO
  credential (test asserts the argv carries no `mssql.username`/`ms-sql-empty-password`/`sa:` + passes
  `shell.policy_violation`). suggest() nudges the single sa-empty/sa:sa Tier-2 check + AD-domain pivot.
- **parsers** (`parsers.py`): extracts version / instance / hostname / AD-domain / os-build from the
  NSE tables. Three review-driven hardenings: (1) `_VERSION_LINE` uses `[ \t]+` not `\s+` — `\s+` spans
  the newline, so a bare `ms-sql-s` -sV line with ms-sql-info blocked captured the following ntlm-info
  header as a bogus version; (2) multi-instance via `finditer` over instance blocks (every instance +
  version, not just the first); (3) domain prefers the DNS FQDN and drops the literal `WORKGROUP` so a
  standalone box is no longer mislabeled AD-joined. `[missing]`/`[blocked]` sentinel skip as usual.
- **Tier-2** `manual_commands.yaml` (6): single sa-empty (nmap NSE + netexec + impacket), sa:sa,
  ms-sql-dac instance/DAC-port leak, and a creds-gated `SELECT name FROM sys.databases`. No xp_cmdshell,
  no list-driven auth (test enforces argv0 ∈ {nmap,netexec,impacket-mssqlclient} + no `-x`/`xp_cmdshell`).
- **pattern** `patterns/mssql.yaml` (2 rules, `# source:` CPTS MSSQL notes): version → Tier-2 sa check;
  domain → LDAP/SMB/Kerberos pivot. **GUI**: one `SIMPLE_SPECS` entry (shared panel auto-wires).
- 3 fixtures (AD single-instance / multi-instance / -sV-only) + parser/module/GUI tests, incl. the
  bare-line regression, the WORKGROUP guard, and `suggest([]) == []`. **Adversarial 3-lens review**
  (11 agents, refute-biased verify): 6 confirmed / 0 refuted → version-newline-bleed (medium),
  multi-instance drop, WORKGROUP mislabel + coverage gaps all fixed; 2 findings dispositioned by-design
  (instance/pattern divergence is moot post-fix; `ms-sql-m`/1434 trigger with `-p 1433` recon is the
  §12-scoped probe). Exam-legality reviewer returned zero findings. Four gates green, 484 tests. `fc30475`.

### Phase 2 · MongoDB module (mongodb) — DONE
Second DB service module after Redis (the template). Read-only unauth Tier-1 auto-enum via the shared
SimpleReconSpec (no bespoke panel/worker), name `mongodb` matching the existing services.yaml stub.
- **engine** (`modules/mongodb/`): `MongoDbModule` triggers 27017/8/9 + `mongodb`/`mongod`; 3 recon
  steps — version / listDatabases / per-DB collections — all `print()`-wrapped `--eval` so output is
  **identical across mongosh and the legacy `mongo` shell** (which render objects very differently) and
  auth-required always surfaces via the asserting `getDBNames()` helper. All read-only (no
  insert/update/drop/eval); host is the only variable (validated `Target.ip`).
- **parsers** (`parsers.py`): dual-shell tolerant — ANSI/OSC + banner strip, `[missing]`/`[blocked]`
  sentinel skip, and access classification (unauth / auth-required / connection-error / **wire-version
  -mismatch**). The wire note encodes the HTB Mongod insight: modern mongosh refuses old MongoDB (3.6 =
  wire v6) → retry with the legacy `mongo` shell (why both clients are allow-listed). Collection/db
  names captured permissively (spaces/unicode/symbols) while rejecting error-stack lines.
- **Tier-2** `manual_commands.yaml` (6): serverStatus, collections-in-`<db>`, bounded `find().limit()`
  doc sample, connectionStatus, replica/shard status, and the legacy-`mongo` fallback.
- **pattern** `patterns/mongodb.yaml` (2 rules, `# source:` HTB Mongod): unauth → read collections/docs;
  wire-mismatch → legacy shell. **GUI**: one `SIMPLE_SPECS` entry (shared panel auto-wires).
- Fixtures + parser/module/GUI tests. **Adversarial 3-lens review** (7 agents, refute-biased verify):
  4 raised → 1 confirmed (name char-class silent-drop) + 2 downgraded parser polish, all fixed; the
  27018/27019-vs-hardcoded-27017 finding was refuted (triggers has no dispatch call-site; panel only
  opens for the 27017 node — same as Redis hardcoding 6379). Four gates green.

### Full vault coverage build (DONE — user authorized adding everything recon-useful)
User approved expanding the §2 allow-list for read-only enum tools and wiring everything. Tracked as
6 tasks, all committed + gate-green:
- **Allow-list**: `shell.py` ALLOWED_TOOLS 44 → **60** — impacket enum trio + mssqlclient, ssh-audit,
  snmp-check, snmpbulkwalk, windapsearch, ldapdomaindump, svn, iscsiadm, openssl, DB clients
  (redis-cli/mongosh/mongo/mysql/psql). Read-only/Tier-2 only; `--passwords`/spray guard still applies.
- **Wired into existing modules**: impacket samrdump/lookupsid (smb), windapsearch/ldapdomaindump
  (ldap), snmp-check/snmpbulkwalk (snmp), rpcdump/ssh-audit/SVN/iSCSI (services.yaml).
- **DB + data services**: MSSQL/MySQL/Postgres/Redis/Mongo clients + Elasticsearch/CouchDB/Memcached/
  Docker tool-hints. **Redis** built as a full Tier-1 auto-enum module (INFO/CONFIG/CLIENT LIST parser
  + findings + pattern + panel).
- **Scan → Nmap presets**: mined nmap variants (UDP -sU -sV -sC, --script vuln opt-in, connect-scan
  for pivot, AD-DC port profile, source-port-53, version-intensity…) pre-fill the command builder.
- **`oscprecon-cli doctor`**: wrapped-tool presence check with install hints.
- **Second mining pass** (mail/Kerberos/UDP/rpcbind/rsync + anything-else, 40 items): fixed the SNMP
  `onesixtyone` no-op + mDNS missing `-sU`; added POP3/IMAP(S) caps+NTLM, Kerberos, ident, Oracle TNS,
  MS-SQL Browser, SIP, SSDP, HTTPS ssl-enum-ciphers, SMB smb-enum NSE, WinRM wsman NTLM, rpcbind
  rpc-grind; LDAP AS-REP/kerberoast/delegation bitwise filters; SMB getdompwinfo.

**Coverage now: 99 tool-hints / 94 service rules, 26 pattern rules / 48 suggestions, 60 allow-listed
tools, 16 module packages.** The vault is essentially exhausted for recon syntax (2nd pass was mostly
fixes + protocol-gap fills). **Remaining follow-ups** (not blockers): all five DB modules
(Redis + Mongo full auto-enum; MSSQL + MySQL + PostgreSQL banner-only per §12) are done — remaining
is a Kerberos module home for the AS-REP/SPN
manuals; `openssl s_client` STARTTLS variants for 110/143. Skipped as too-borderline for §2:
ssl-heartbleed, rmi-vuln-classloader, IIS http-iis-short-name-brute (policy blocks *brute*), and the
new-binaries tnscmd10g/ident-user-enum/svmap/braa (nmap covers them).

### Vault mining pass (DONE for allowed-tool items; decisions pending)
Ran an 8-area adversarial mining workflow over `/home/hacker/Documents/notes-vault` (90 candidates,
deduped against services.yaml + patterns + manual_commands). Wired the §2-allowed subset in 3 commits:
services.yaml → **61 tool-hints** (was 43; new ports VNC/AJP/IPP/Java-RMI + Telnet/Finger/MSRPC/IPMI/
WinRM tools + FTP/LDAP/HTTPS/MSSQL/MySQL/RDP NSE); http.yaml patterns (file/backup ferox, nikto, PRTG,
Splunk, WP sitemap/xmlrpc) → **25 rules / 46 suggestions**; manuals (nikto — §9 named it, was unwired;
DNS DC-locator/Kerberos SRV; SMB rpcclient/netexec null; SNMP -Oa; NFS statfs NSE; vhost dnsenum; LDAP
get-network/admin-count). Every command passes shell.policy + provenance + forbidden gates.

**DEFERRED — need a §2 allow-list decision before wiring** (all read-only enum, but not on the §2 list):
`impacket-samrdump/lookupsid/rpcdump` (§2 already permits "impacket enum scripts" in spirit),
`ssh-audit`, `snmp-check`, `snmpbulkwalk`, `windapsearch`, `ldapdomaindump`, and interactive DB clients
`impacket-mssqlclient / redis-cli / mongo / mysql / psql` (need new modules for MSSQL/MySQL/Postgres/
Redis/Mongo + single-default-cred Tier-2), plus niche `svn` / `iscsiadm`. Any accepted binary also goes
in `oscprecon-cli doctor`. **Structural**: an nmap-variants "manual" set (UDP `-sU -sV -sC`, `--script
vuln` opt-in, `-Pn`, connect-scan-for-pivot, AD-port DC profile) has no home (nmap is a file, not a
package). **Second-pass thin areas**: mail (110/143/993/995), Kerberos(88), bare UDP (1900/5353).
Dropped: IIS `http-iis-short-name-brute` (policy correctly blocks any `--script *brute*`).

### Phase 5 · adversarial review + fixes (DONE)
Ran a 6-dimension multi-agent adversarial review over the whole session's Phase 5 diff (37 agents;
each finding double-verified by refute-biased skeptics — 5 of 15 candidates survived). All 5 fixed,
each with a regression test:
- **(high) orchestrator reuse** — `_completed` admitted any-ever exit-0, so a later truncating
  force-run resurrected a partial file and the versioned scan was skipped when a resume found a new
  port. Now key the LATEST entry per `output_file` and require exit-0 **+** matching `shell_line`.
- **(med) `--resume` wrong target** — the CLI `ip` arg was silently ignored (stored target scanned);
  now errors on mismatch.
- **(med) parallel UI churn** — every worker completion re-ran `_set_profile`, reloading the notes
  editor (cursor/undo reset) and rebuilding the tree (selection dropped). `NotesPane.set_profile` and
  `ServiceTree.populate` are now idempotent; `_post_run_refresh` is lightweight.
- **(med) vault frontmatter** — raw f-strings produced invalid YAML on ordinary nmap version strings
  (`(workgroup: X)`); now `yaml.safe_dump`.
- **(low) audit table** — `_audit_summary` now collapses CR/LF (a pasted multi-line value broke the
  markdown row). Plus a real in-flight-worker cancel test (the earlier hang bug's coverage gap).
Two headline severities were verifier-downgraded and one "injection" framing flagged a false-positive.

### Phase 5 · block 3: audit log (§6a) (DONE)
Append-only `<profile>/audit.jsonl` trail. **Engine** `audit.py`: `record()` writes {ts, actor,
action, profile, details} best-effort (a serialization/I/O failure is logged, never raised),
redacts secret-named detail fields to `<redacted len=N>`, rotates into `audit-archive/` past 5 MB;
`Auditor` binds dir+name for terse call sites; `load_entries` feeds the report. **GUI wiring**: an
`Auditor` bound per profile in `_set_profile`; emit points at `run`/`run-finished` (centralized in
`_launch`/`_release`, covering every task), profile created/opened/saved/exported/closed, dry-run,
add-to-report, and credential-added (field names + source only — never the secret value). **Report**:
a `## Audit trail` appendix (after Command log), most-recent-N capped, details escaped for markdown.
Caught + fixed a self-inflicted hang: an audit-wiring test started a bare `QThread` (default `run()`
= a forever `exec()` loop) so `_release`'s `worker.wait()` blocked — the concurrent-run pileup had
masked it. Full suite RC=0 (~429 tests).

### Phase 5 · block 2: bounded parallel execution + task status bar (DONE)
Shipped in 6 sub-chunks, each gate-green: **(A)** `gui/task_manager.py` — `TaskManager` caps
concurrent workers (default 4) with an exclusive slot for nmap discovery (it mutates the Profile
from its own thread). **(B)** `shell.run(cancel=Event)` — a monitor thread kills the child the moment
the event is set; `ShellResult.cancelled`. **(C1)** `findings.add_findings` now holds a lock (recon
workers write it from their threads — read-modify-write was clobber-prone). **(C2)** `CancellableThread`
base; NmapWorker/CommandWorker + 6 recon workers thread `self._cancel` into every `shell.run` and
check it between steps; `Orchestrator(cancel=…)`. **(C3)** MainWindow migrated off the single
`self._worker` slot to the TaskManager — nmap exclusive, service/command runs parallel; lifecycle on
the QThread `finished` signal (`_launch`/`_release`); the shared parse slots
(`_http_parse`/`_vhost_parse`/`_wildcard_out`/`_treat_http_ctx`) were replaced by per-worker
completion closures so parallel CommandWorkers can't collide; `TaskStatusBar` shows a chip + ✕ Cancel
per running task. ~17 new tests (TaskManager policy, shell cancel, findings concurrency, orchestrator
pre-cancel, status-bar/gating/exclusivity/release).

### Phase 5 · block 1: resume + Obsidian output (DONE)
- **`--resume` / `--force`** (`orchestrator.py` + `cli.py`): reuse only commands that finished cleanly
  in a prior run (exit 0 + output file still on disk, non-empty); blocked/missing/timeout and
  aborted-mid-run (no exit-0 record) re-run; `--force` re-runs all. CLI `--resume` LOADS the prior
  profile so `command_history` survives (`Profile.create` would overwrite it). 5 tests.
- **Report enrichment (§18)**: `report.md` now renders a **Per-service findings** section (§18 #5,
  grouped by module with Obsidian `#<module>` tags, handles both finding shapes) and a **HackTricks
  link** per discovered service (§18 #4, via `references.match`). 6 tests.
- **Obsidian Vault export (§17 Mode 2)**: new `vault_export.py` snapshots a profile into a folder of
  linked notes (index + target/services/findings/credentials/commands/notes), frontmatter + wikilinks,
  **creds redacted** (`creds.redact`). Headless `oscprecon-cli export-vault <dest> -p <profile>` +
  wired `File → Export to Obsidian Vault...` GUI action. 4 engine + 2 pytest-qt tests.

### Phase 3 — DONE (engine + gates + report + GUI + note-sourced patterns for 8 services).
The user's Obsidian vault is now a LOCAL copy at **`vault:`** (the
earlier vboxsf mount `/media/sf_notes-vault2` returned `Protocol error` on host-authored files —
they were OneDrive online-only placeholders; the local copy fixed it; see memory
`obsidian-notes-location`). Patterns were authored from `0.01 Cheatsheets` + `0.00 Methdology/.../1.
Enumeration` (esp. `Ports and tools.md`), recon-only, each `# source:`-cited. **§21 rule for adding
more: extract recon INSIGHTS only — cite `# source:`, NEVER commit the raw notes / prose / creds /
wordlists.** The tool runs commands via `shlex.split` (no shell) — one command per suggestion, no `;`.

**NOW: Phase 4 — Bloodhound-style graph view (§16, §23).** Deliverables: `gui/widgets/graph_view.py`
(QWebEngineView + vendored offline Cytoscape.js, NO runtime CDN), `QWebChannel` GraphBridge
(get_data / node_clicked / status_changed / add_user_edge / save_layout), `gui/graph_html/`
(index.html + app.js + cytoscape.min.js + style.css), node/edge types + colors per §16, `graph.json`
persistence (user edges, node positions, per-node status/notes), `View → Graph` (Ctrl+G) toggle, and
the §16 QUEUED reinforcements (drag-drop persistence, right-click Add Note→graph.json+tooltip+report,
minimap + edge labels, PNG/SVG export). Also queued/owed after Phase 4: project file ops (§19), audit
log (§6a), concurrent-copy lock (§6b), the rest of Phase 5 QoL, Phase 6 doctor/exam-preset.

Recurring review lessons: parsers must match REAL current tool output;
always release the worker slot in a finally/guard; make on-disk artifact filenames injective; thread
the service port through every command; **validate every user/server-supplied token that reaches a
command line (host via validate_host, domain via normalize_domain, base DN via sanitize_basedn) —
the manual-follow-up path must validate too, not just the recon button.**

## Queued additions (recorded 2026-07-11 — do NOT build early; pick up at the noted phase)

Five features queued into `CLAUDE.md` + `ROADMAP.md` for a fresh session to build at the right time.
Specs are authoritative in CLAUDE.md; this is the pointer list.

1. ~~**Status footer** (CLAUDE.md §19)~~ — **DONE** (Phase 2 QoL): QStatusBar strip with app+version,
   active profile, workspace root, and the muted "recon-only — OSCP exam legal" reminder.
2. **Project file operations** (CLAUDE.md §19) — File → Open by IP / Import Project / Export Project
   (.tar.gz; warns `creds.json` included). Each `~/oscprecon/<name>/` is a project file. → Phase 5.
3. **Full GUI audit log** (CLAUDE.md §6a) — append-only `<profile>/audit.jsonl` of every user action;
   report "Audit trail" appendix. Wire emit points as earlier UI lands (cheap backfill). → Phase 5.
4. **Concurrent-copy lock** (CLAUDE.md §6b) — `<profile>/.lock` (flock) + "open read-only?" prompt +
   stale-PID reclaim. → Phase 5.
5. **Graph presentation polish** (CLAUDE.md §16) — drag-drop repositioning, right-click Add Note,
   persistent layout, minimap + edge labels, PNG/SVG export. → Phase 4 (amends existing deliverable).

## How to resume

1. `cd ~/oscp-recon` (repo is local-only, no git remote yet). `uv` lives at `~/.local/bin/uv`; run `uv sync` if deps are missing.
2. Gates before every commit: `uv run mypy --strict src/`, `uv run pytest -q`, `uv run ruff check`, `uv run ruff format --check`. GUI tests need `QT_QPA_PLATFORM=offscreen`.
3. Commit each chunk once gates are green — no need to ask. Show any new *wrapped command* before writing it (CLAUDE.md §27); only recon tools on the §2 allowlist.
4. Update this file with each chunk and commit it alongside that chunk.

## Log (newest first)

### Phase 3 · step 3: web-app discovery patterns (23 rules / 39 suggestions)
- Mined the CPTS "Attacking Common Applications" discovery notes for HTTP app patterns that fire on
  the whatweb `note`: **Tomcat** (/docs version, manager/host-manager console), **Jenkins** (login-page
  version), **GitLab** (/explore public projects, /users/sign_up), **Drupal** (CHANGELOG.txt version),
  **ColdFusion** (/CFIDE/administrator). All discovery/recon-only — no default-cred brute / WAR upload.
- Added credentialed **GPP hunt** to smb.yaml (`netexec -M gpp_password -M gpp_autologin`, SYSVOL creds).
- Stopped at the honest edge of the vault: IIS tilde-enum (needs a non-wrapped short-name scanner /
  the policy-blocked `http-iis-short-name-brute` NSE) and the MSSQL path (no module emits a trigger)
  don't map to wrapped/allowlisted recon commands, so they're deliberately excluded.
- **Verified end-to-end**: a Tomcat box renders general content-discovery + the Tomcat manager check;
  an AD box renders the full null-session → credentialed-expansion → LDAP/AS-REP → GPP chain. Gates +
  exec policy clean (except the intentional sudo-mount copy-to-terminal line).

### Phase 3 · step 2: note-sourced pattern library (10 services, 18 rules) — Phase 3 COMPLETE
- Authored `patterns/*.yaml` from Andre's local Obsidian vault (`/home/hacker/Documents/notes-vault`),
  recon-only, each entry `# source:`-cited: **smb** (enum4linux -a / smb-enum-users / smbmap -H,-R /
  rpcclient null / smbclient share browse + **AD**: netexec smb null groups/computers/sessions,
  SYSVOL grab, credentialed expansion, kerberoast/asreproast REQUESTS), **http** (feroxbuster+gobuster
  raft content discovery / whatweb / nmap http-enum NSE / wpscan -e + wp-json users — brute excluded),
  **ftp** (anon → wget -r mirror), **nfs** (world-readable → ro mount), **dns** (dig NS/MX/TXT/AXFR),
  **ldap** (naming-context → anon ldapsearch dump + **AD** netexec ldap null enum + AS-REP; user →
  GetNPUsers), **snmp** (community → snmpwalk), **ntp** (ntpq -pn), **smtp** (VRFY → smtp-enum-users),
  **netbios** (domain → enum4linux-ng AD pivot). Classic `enum4linux` added to the exec allowlist.
  **Verified**: an AD box (smb-auth + ldap contexts/users + a cred) yields a coherent 12-step recon
  plan. Every pattern command passes the exec policy (except the intentional sudo-mount copy-to-terminal
  one). SSH/IKE/TFTP/vhost left to their modules (thin/covered notes).
- **Engine gap fixed first**: HTTP findings are `{port,path,note}` not `{kind,value,detail}`, so
  `detail_contains` now searches ALL finding fields and `_context` exposes ALL fields for
  interpolation ({path}/{port} for http). Backward-compatible.
- Both build-gates (`check_provenance` + `check_forbidden`) run over the shipped dir in the test suite;
  a firing test asserts the shipped patterns produce sourced suggestions. **Verified end-to-end**: a
  report with smb/http findings renders the "Suggested next steps" section with interpolated commands +
  `_source:` citations. SSH/SMTP/IKE/TFTP/NetBIOS left to their modules' `suggest()` (notes thin/covered).

### Phase 3 · step 1b: GUI "Recon next steps" panel (pre-fill, no auto-run)
- **tool_panel**: a "Recon next steps" QGroupBox (below the module stack) lists the pattern-library
  suggestions — each row shows the text, its `↳ source:` citation, and (if the entry has a command)
  the `$ command`. Double-clicking a command row **pre-fills** the command builder and switches to the
  generic page so the user reviews it and clicks Run — never auto-executed. Advisory-only rows (no
  command) do nothing on activation. Empty → a non-selectable "No pattern suggestions yet." placeholder.
- **main_window**: `_refresh_suggestions()` recomputes via `suggest_for(findings, target, domain,
  has_credential)` on profile open AND after every recon run (through `_finish_worker` → `_set_profile`).
- 3 GUI tests (set+prefill+advisory-noop, empty placeholder, main-window refresh via monkeypatched
  engine). 373 tests. **Phase 3 step 1 COMPLETE (engine + gates + report + GUI).** Step 2 next: author
  real `patterns/*.yaml` from the mounted Obsidian cheatsheets, `# source:`-cited, proposed in batches.

### Phase 3 · step 1a: pattern engine + provenance/forbidden gates + report wiring
- **`patterns/engine.py`**: `load_patterns()` parses each `patterns/<svc>.yaml` (list of `{match,
  suggest}` entries) and — since yaml.safe_load drops comments — re-splits the raw text per top-level
  entry to recover each entry's `# source:` provenance. `suggest_for(findings, target, domain,
  has_credential)` matches findings (keys: service/port/proto/detail_contains/field+value-regex/
  has_credential), interpolates `{target}/{domain}/{value}/{kind}` plus a `{<kind>}` alias (a `share`
  finding exposes `{share}`), dedups, and emits `Suggestion(text, command_template, source_pattern,
  source_box)`. A suggest item is a plain string (advisory) or `{text, command}` (pre-fillable).
- **Gates**: `check_provenance()` flags any entry missing `# source:` (the §15 build gate);
  `check_forbidden()` flags exploit/cracking content (cve-/metasploit/msfvenom/meterpreter/hydra/
  medusa/sqlmap/rockyou/--passwords) — content-discovery wordlists stay allowed. A test runs BOTH over
  the real (currently empty) `patterns/` dir so they stay green as entries land.
- **Report**: `reporter.py` feeds findings through `suggest_for`; the "Suggested next steps" section
  now renders each suggestion + its command + `source:` citation.
- 6 engine tests (load+source, provenance-fail, forbidden-fail, match+interpolate, dedup, shipped-gates)
  over `tests/fixtures/patterns{,_bad,_forbidden}/`. 370 tests. **Step 1b next:** GUI "Recon next
  steps" panel (pre-fill, no auto-run). **Step 2:** author real `patterns/*.yaml` from the mounted
  Obsidian cheatsheets with `# source:` provenance (memory `obsidian-notes-location`, §21 rules).

### Phase 4 · graph view — chunk 3d: minimap + node-type filter (Phase 4 COMPLETE)
- **Minimap**: a bottom-right overview built as a SECOND locked Cytoscape instance (positions mirrored
  from the main graph, non-interactive) + a live `#minimap-viewport` rectangle that tracks the main
  view's pan/zoom, and click-the-minimap-to-pan. Deliberately NOT the cytoscape-navigator extension —
  it hard-requires jQuery (verified 3 `jQuery(` calls), too heavy for optional polish; the custom
  overview reuses the already-vendored Cytoscape with no new deps.
- **Filter**: toolbar checkboxes (services / findings / creds) toggle a `.hidden` class
  (`display: none`) across BOTH the graph and the minimap; an edge is hidden when either endpoint is.
- **Verified in a real webengine render**: minimap has all 5 nodes, viewport rect is sized, and
  unchecking creds gives `display=none visible=false` (reverses on re-check). JS-only chunk. 364 tests.

### Phase 4 · graph view — chunk 3c: relates-to edge drawing (link mode)
- Toolbar **Link mode** toggle (§16 "drag edge between two nodes → relates-to user edge"): click a
  source node, then a target → `bridge.add_user_edge(src, dst, "")` persists it to graph.json AND the
  edge is added to the live cy immediately (dashed purple relates-to); link mode auto-exits. The tap is
  swallowed in link mode so the detail sidebar doesn't open.
- **Verified end-to-end in a real webengine render**: simulated the two taps → 1 relates-to edge on the
  canvas + `graph.json.user_edges == [{"from":"target","to":"service-80-tcp","label":""}]`. The
  `add_user_edge` persistence path is also unit-tested (chunk 2). 364 tests.
- **Phase 4 substantially complete.** Remaining optional §16 polish: minimap (cytoscape-navigator
  extension) + node-type filter sidebar.

### Phase 4 · graph view — chunk 3b: PNG / SVG export (§16)
- Toolbar **Export PNG** / **Export SVG** buttons. PNG uses Cytoscape's built-in `cy.png()` (scale 2,
  full graph); SVG uses the vendored **cytoscape-svg 0.4.0** extension (`cy.svg()`), registered via
  `cytoscape.use(window.cytoscapeSvg)`. app.js sends the image to `bridge.export_image(format, data)`.
- `GraphBridge.export_image` → `export_requested(format, data)` → `GraphView._on_export` opens a
  QFileDialog and writes via the testable `_write_image` (PNG: strip the `base64,` data-uri prefix +
  b64decode → bytes; SVG: write the string verbatim).
- Verified in a real webengine render that both `cy.png` and `cy.svg` are registered functions
  (`true|true`). 11 graph tests (added export-emit + write-image png/svg). 364 tests, gates green.

### Phase 4 · graph view — chunk 3a: node-detail sidebar + native status/note UI
- **`GraphDetail`** sidebar (left of the web view in a QSplitter): shows the tapped node's label +
  a `type · port · module · source · detail · status` line, four **Status** buttons
  (new/investigating/done/dead-end), a **Note** editor + Save, and (for service nodes) an
  **"Open service tooling →"** button. app.js now sends `evt.target.data()` with the tap so the
  sidebar has the full node; `GraphBridge.node_selected` became `(id, data)`.
- Status/note edits go through the bridge → graph.json and reload the graph so the border/badge
  updates live. The old "tap a service node yanks you to the three-pane" behavior became an explicit
  button: `GraphView.service_open_requested(port, proto)` → main_window switches + selects.
- 9 graph GUI tests (bridge id+data, detail show/emit, view persistence, service-open switch). Real
  headless render re-verified (4 nodes, no warnings). 362 tests. **Chunk 3b:** PNG/SVG export.
  **Chunk 3c:** drag-to-draw relates-to edges + minimap.

### Phase 4 · graph view — chunk 2: GraphView widget + Cytoscape HTML/JS + View→Graph
- **`gui/graph_html/`**: index.html (loads Qt's `qrc:///` qwebchannel.js + the vendored
  cytoscape.min.js), app.js (Cytoscape init with the §16 node/edge colors — target ellipse / TCP blue
  / UDP green / finding yellow / credential red, status borders, dashed relates-to; hierarchical +
  force-directed layouts; tap → `bridge.node_clicked`; dragfree → `bridge.save_positions`), style.css.
- **`gui/widgets/graph_view.py`**: `GraphBridge` (QWebChannel QObject) serves `get_data()` (the
  build_elements JSON) and persists edits to graph.json — `set_status` (validated), `add_note`,
  `save_positions`, `add_user_edge` — and emits `node_selected` on a tap. `GraphView` hosts the
  QWebEngineView + channel with the same graceful QtWebEngine fallback as the reference pane.
- **main_window**: central QStackedWidget (three-pane ↔ graph); View → Graph (Ctrl+G, checkable)
  toggles + reloads on show; a service-node tap switches back to the three-pane and selects that
  service so its detail shows. `set_profile` feeds the graph.
- **Verified with a real headless QtWebEngine render**: draws all nodes (probe: cytoscape loaded, 4
  nodes for target + 2 services + 1 finding), no console warnings after tightening the edge-label
  selector + dropping the custom wheel-sensitivity.
- 7 GUI tests (bridge get_data / click / persist / edge / bad-json, fallback construct, toggle,
  service-node switch-back). 360 tests. **Next chunk 3:** native status/note UI on `node_selected`,
  drag-to-draw relates-to edges, minimap, PNG/SVG export, node-detail sidebar.

### Phase 4 · graph view — chunk 1: data model + graph.json persistence
- **`gui/graph_data.py`** `build_elements(profile)` — pure-Python (no Qt) Cytoscape elements builder:
  target → services (`has-service`) → findings (`exposes-finding`, linked to the owning service via the
  references module→port map, else the target) → credentials (`references-credential`, secret REDACTED
  via `creds.redact` — never reaches the graph). Overlays `graph.json`: per-node status
  (new/investigating/done/dead-end, validated), note, saved position, and user-drawn `relates-to` edges
  (a dangling edge whose endpoint no longer exists is dropped so Cytoscape never errors).
- **`Profile.graph_path` / `load_graph` / `save_graph`** — atomic write mirroring profile.json; load
  returns the `{user_edges, node_overrides}` default when the file is absent or corrupt.
- Cytoscape.js 3.30.2 vendored offline to `gui/graph_html/cytoscape.min.js` (committed with chunk 2).
- 6 unit tests (structure, module→service finding links, redaction, overrides + user-edge filtering,
  invalid-status rejection, persistence round-trip). 353 tests. **Next chunk 2:** GraphView widget
  (QWebEngineView + QWebChannel bridge) + `graph_html/` (index.html/app.js/style.css) + View→Graph
  (Ctrl+G). **Chunk 3:** interactions (click→detail, right-click Add Note/status, drag-edge relates-to,
  drag-position persistence), minimap, PNG/SVG export.

### Phase 2 · QoL — status footer (§19)
- Always-visible `QStatusBar` strip: `oscp-recon v<version>` (importlib.metadata, falls back to
  0.0.1), the active profile (`profile: <name>` / `no profile loaded`), the workspace root, and a
  muted permanent `recon-only — OSCP exam legal per CLAUDE.md §2` reminder. `_update_status_footer`
  refreshes it on every profile load. Closes queued item #1. 347 tests, four gates green.

### Phase 2 · GUI — generic simple-recon panel for the 7 engine-only modules
- **SimpleReconPanel** (`gui/widgets/simple_recon_panel.py`) + **SimpleReconWorker** (`main_window.py`)
  + **registry** (`gui/simple_recon.py`): ONE panel type for the read-only single-shape modules
  (smtp/nfs/snmp/tftp/netbios/ike/ntp) instead of 7 bespoke widgets. Each `SimpleReconSpec` supplies the
  Tier-1 button label, intro, `manual_commands.yaml`, a module factory (for the uniform
  `Module.parse`/`suggest`), and a typed step-provider (snmp adds the public MIB walk; tftp fans out the
  COMMON_FILES GETs) — so the base Module never needs the concrete step methods.
- The worker runs the Tier-1 steps through the policy-enforced `shell.run`, builds `raw_outputs` keyed
  by tool, calls `module.parse()` → base Findings → `findings.json`, and produces a per-kind summary +
  `suggest()` next-steps. Empty parse writes nothing (mirrors the ssh worker).
- `tool_panel` adds one SimpleReconPanel per module to the stack, dispatches by `ref.module`, forwards
  `simple_recon_requested(name)` + Tier-2 manual follow-ups (validated at the shell chokepoint), and
  disables them during a scan. `main_window` wires the worker with the standard worker-slot /
  `_finish_worker` guard.
- 12 GUI tests (ntp + netbios worker parse→findings, empty case, panel dispatch + signal forwarding,
  manual-legality across all 7 specs). Updated the one widget test that assumed smtp used the generic
  hints page (smtp now has a panel; mysql covers the generic page). 346 tests, four gates green.

### Phase 2 · modules 13–14 (ike, ntp) — hardening
Adversarial reviews (verified against real ike-scan / ntpq / ntpdate output). Both modules were clean
on their OWN commands; the confirmed defects were parser gaps + a shared exec-chokepoint backstop gap
(the recurring "the sole §2 chokepoint must enforce the invariant, not just the module" theme).
- **ike correctness (LOW–MED): SA transform truncated on a nested-paren lifetime.** Real ike-scan
  encodes the lifetime as `LifeDuration(4)=0x00007080` — a nested paren — so `SA=\([^)]*\)` cut the
  transform off there. Allow one level of nesting (still stops before the aggressive-mode trailing
  payloads KeyExchange(..)/Nonce(..)/ID(..)/Hash(..)).
- **ike §12 (MED): exec chokepoint didn't block ike-scan PSK capture.** shell.py enforces every other
  §2 rule but let `ike-scan --pskcrack` / `-Pfile` through — the module never emits it, but the §19
  custom-command surface could. Added an ike-scan guard (prefix-matches the concatenated `-Pfile`).
- **ntp §2 (MED): exec chokepoint didn't enforce the `ntpdate -q` invariant.** Bare `ntpdate <target>`
  SETS the local clock; the module always uses -q but the chokepoint didn't back-stop it. Now blocks
  ntpdate without -q.
- **ntp correctness (LOW): `parse_ntpdate` dropped an IPv6 server.** The regex hard-coded a dotted
  quad; Target accepts IPv6. Broadened to a non-greedy server capture. Regression tests for all four
  (incl. shell-policy tests for both backstops).

### Phase 2 · module 8 (smtp) — hardening
Adversarial review (verified against the real `smtp-*.nse` sources, nmap 7.99). 2 confirmed parser
gaps; compliance/injection clean.
- **correctness (MED): verbs on the smtp-commands HELP line were dropped.** `smtp-commands.nse` returns
  TWO payloads — EHLO extensions AND the HELP response — on two lines (`| smtp-commands: ...` then
  `|_ This server supports the following commands: ... VRFY EXPN`). `_verbs` read only the first, so
  VRFY/EXPN (base SMTP verbs that often surface ONLY on HELP) were missed — the module's headline
  user-enum capability. Now reads both lines (deduped).
- **correctness (LOW): banner missed on ssl/smtp (465) + submission (587).** The module triggers on
  those ports but `_SMTP_VER` required the service token to start with `smtp`; nmap prints `ssl/smtp`
  and `submission`. Broadened the regex. Tests added for both.

### Phase 2 · module 14 (ntp) — engine — ALL 14 PHASE-2 MODULE ENGINES COMPLETE
- **NtpModule** (`modules/ntp/`, UDP 123): triggers on 123 / ntp. Tier-1 read-only: `ntpq -c readlist`
  + `ntpq -c sysinfo` + `ntpdate -q` (always `-q` — recon never adjusts the local clock).
- **parsers.py**: `parse_ntpq` pulls `version`/`system`/`processor` (host fingerprint) from the
  `key="value"` readlist form and stratum from either `stratum=3` (readlist) or `stratum:  3`
  (sysinfo); `parse_ntpdate` extracts stratum + server from the `server IP, stratum N` line. Dispatch:
  ntpq-readlist/ntpq-sysinfo → parse_ntpq, ntpdate → parse_ntpdate.
- `suggest()` uses the disclosed version/OS to fingerprint and points at ntp-monlist (Tier-2 nmap).
  Tier-2 `manual_commands.yaml` (5): readlist/sysinfo/peers, `ntpdate -q`, nmap ntp-info/ntp-monlist —
  ntpdate is only ever used with `-q` (enforced by both the module and a manual-legality test).
- shell.py: install hints for ntpq (ntpsec) + ntpdate (ntpsec-ntpdate). 9 tests.

### Phase 2 · module 13 (ike) — engine
- **IkeModule** (`modules/ike/`, UDP 500): triggers on 500 / isakmp. Tier-1 read-only: `ike-scan -M`
  (detect the IKE/ISAKMP VPN responder + its main-mode transform) + `ike-scan -M -A` (aggressive-mode
  check). No `-P` / PSK-hash capture — offline PSK cracking is out of scope for this recon tool.
- **parsers.py**: `parse_ike_scan` flags main-mode (`service`) and aggressive-mode (`aggressive`
  enabled — PSK-material disclosure) handshakes and extracts the SA transform (Enc/Hash/Group/Auth) for
  either; dispatch keys `ike-scan` + `ike-scan-aggressive` both map to it (distinct keys avoid the
  raw_outputs collision).
- `suggest()` notes aggressive mode (recon only — explicitly states offline PSK cracking is out of
  scope) or a bare VPN presence. Tier-2 `manual_commands.yaml` (5): detection, aggressive check,
  transform enumeration, named-group aggressive, nmap ike-version. No PSK capture/cracking anywhere.
- 8 tests (parsers + module incl. a "no -P" assertion + a manual no-PSK-crack check).

### Phase 2 · module 12 (netbios) — hardening
Adversarial 3-lens review (verified against real nmblookup/nbtscan output). 4 candidates, 1 CONFIRMED;
3 refuted.
- **parser-correctness (MED): order-dependent `<03>` classification.** The `<03>`-messenger-vs-hostname
  suppression was single-pass, so if the target returned a host's `<03>` row before its own `<00>` row
  (RFC 1002 node-status ordering is target-controlled), the box's OWN computer name was misreported as
  a logged-in user and `suggest()` advised user-enum against it. Made `parse_nmblookup` two-pass:
  collect all `<00>` host names first, then classify — order-independent. Regression test added.
- Refuted (verified non-issues): no cross-tool dedup between nmblookup+nbtscan (deliberate per-tool
  house convention, matches smtp/nfs; each finding is individually correct); MAC in two formats (each
  parser faithfully echoes its tool — cosmetic); the `__MSBROWSE__` guard is dead code (the `<01>`
  suffix path already excludes it) but emits nothing wrong; plus a pure test-coverage nit.

### Phase 2 · module 11 (tftp) — hardening
Adversarial 3-lens review (verified against the real `tftp-enum.nse` source). 4 candidates, 2 CONFIRMED
(one issue found by two lenses); 2 refuted.
- **parser-correctness (MED): `_SKIP_PREFIXES` dropped real files.** The guard skipped in-section lines
  starting with started/date/error/info — but tftp-enum's output is ONLY found filenames (those strings
  appear only in the script's `debug1()` calls, never in output), so the filter protected against
  nothing while silently deleting legitimate readable files named `info.txt` / `error.log` / `date`.
  Removed the guard (every in-section `|` line is a filename); added a regression test.
- Refuted (verified non-issues): adjacent-NSE-block leak (`fingerprint-strings` from `-sV` sorts before
  `tftp-enum`, so no `|` block ever follows it — the non-`|` trailing lines already end the section);
  0-byte-miss vs 0-byte-hit ambiguity (speculation about a not-yet-built worker; `ShellResult` already
  exposes `exit_code`).

### Phase 2 · module 12 (netbios) — engine
- **NetbiosModule** (`modules/netbios/`, UDP 137): triggers on 137 / netbios-ns. Tier-1 read-only:
  `nmblookup -A {target}` + `nbtscan {target}` (NetBIOS name table — host, domain/workgroup, service
  roles, MAC). Both already on the allowlist; services.yaml already had the 137 entry.
- **parsers.py**: `parse_nmblookup` reads each `NAME <XX> - [<GROUP>] <node> <ACTIVE>` row and maps the
  suffix code to meaning — `<00>` unique→hostname / group→domain, `<20>`→file-server(SMB),
  `<1c>`/`<1b>`→domain-controller (also emits the AD domain), `<03>`→logged-in user (skipped when it
  equals the host's own name), plus MAC; `__MSBROWSE__` is dropped. `parse_nbtscan` reads the one-line
  table (name + `<server>` flag + MAC). `parse_netbios_tool` dispatch.
- `suggest()` pivots: a DC/PDC → LDAP/kerberos/SMB AD flows; `<20>` → SMB module; `<03>` → user enum.
- Tier-2 `manual_commands.yaml` (5): nmblookup -A, nbtscan (+ -v), name resolve, nmap nbstat. Recon-only.
- 10 tests (parsers + module incl. the <03>==hostname suppression and header-not-a-finding checks).

### Phase 2 · module 10 (snmp) — hardening
Adversarial 3-lens review (7 agents; verified against real onesixtyone / snmpwalk output). 4
candidates, 4 CONFIRMED — but #1–#3 were the SAME root issue, found independently by all three lenses.
- **injection (MED ×3): unvalidated community reaches a command line.** `walk_step` spliced
  `{community}` unquoted into `snmpwalk -v2c -c {community} {ip}`, into `suggest()`'s hint, and into
  the `snmp/snmpwalk-{community}.txt` path. The shipped onesixtyone list itself holds valid
  space-bearing communities (`all private`), which onesixtyone echoes verbatim → `parse_onesixtyone`
  keeps the space → `shlex.split` turns `-c all private 10.x` into community `all` + agent `private`,
  redirecting the walk off-target (and `../evil` escaped the snmp/ dir). Fix: `shlex.quote` the
  community in the command + `suggest()` (preserves a valid space-bearing community as ONE argv token,
  unlike a reject-charset guard that would break `all private`), and a `re.sub` slug for the filename.
- **correctness (LOW): `_CRED_HINT` false positives.** `pass(word|wd)?[=:]` (unanchored) fired on
  `compass=` / `bypass:`. Added a `(?<![A-Za-z])` lookbehind (beats `\b`: still matches `_password=`
  and `--password=`). Regression tests for both fixes.

### Phase 2 · module 11 (tftp) — engine
- **TftpModule** (`modules/tftp/`, UDP 69): triggers on 69 / tftp. TFTP has NO listing protocol, so
  Tier-1 recon is `nmap -sU -sV --script tftp-enum` (enumerate readable files from nmap's well-known
  list) + a `curl -s tftp://{target}/<file>` GET per name in a small fixed `COMMON_FILES` list
  (network-device configs/backups). GET-only — no PUT/upload ever. curl already speaks tftp and is on
  the allowlist, so no shell.py change.
- **`tftp_get_url`** URL-encodes the filename (encoding `/` too) so a target-controlled tftp-enum name
  can't smuggle a curl flag or a second URL; `get_step` hashes the full name into the on-disk snapshot
  filename (injective, mirrors ftp). **parsers.py**: `parse_nmap_tftp` reads the filenames listed under
  the `tftp-enum:` block (real @output format: header then `|_ bootrom.ld` lines), ends the section at
  the next non-`|` line, dedups. `parse_tftp_tool` dispatch.
- Tier-2 `manual_commands.yaml` (6): nmap tftp-enum, curl GETs (running/startup-config, named file),
  and copy-to-terminal tftp/atftp GETs. Read-only only.
- 10 tests (parsers + module incl. a hostile-filename injection test + a no-upload manual check).
  Four gates green.

### Phase 2 · module 10 (snmp) — engine
- **SnmpModule** (`modules/snmp/`, UDP 161): triggers on 161 / snmp. Tier-1 read-only recon:
  `discovery_steps` = `onesixtyone -c <small community list> {target}` (§2 explicitly allows
  onesixtyone with a small list — used the 822-byte onesixtyone-formatted seclists file, NOT the
  22 KB one) + `nmap -sU -sV --script snmp-info,snmp-sysdescr,snmp-interfaces,snmp-processes,
  snmp-netstat` (no snmp-brute). `walk_step(community="public")` = `snmpwalk -v2c -c <community>`;
  `commands()` = discovery + a default public walk.
- **parsers.py**: `parse_onesixtyone` (`IP [community] sysDescr` → community + banner, deduped),
  `parse_nmap_snmp` (version-line + snmp-sysdescr banners, snmp-processes `Name:`, interface IP
  isolated from the trailing `Netmask:`, enterprise note), `parse_snmpwalk` (sysDescr banner, Windows
  LanMgr users + hrSWRunName processes matched via prefix-independent numeric OID tails so the `iso.`
  and `.1.` render forms both hit; a `pass(word)?[=:]` value raises a credential NOTE without copying
  the secret — §6). `parse_snmp_tool` dispatch.
- Tier-2 `manual_commands.yaml` (8): v2c/v1 walks, discovered-community re-walk, targeted OID pulls
  (users / processes / installed software / listening ports), nmap NSE. No brute — onesixtyone stays
  on the small default list; no user/password iteration anywhere.
- 13 tests (parsers + module incl. secret-not-leaked assertions + a manual recon-only check);
  onesixtyone + snmpwalk already on the exec allowlist. Four gates green.

### Phase 2 · module 9 (nfs) — hardening
Adversarial 3-lens review (7 agents: 3 review lenses → per-finding adversarial verify, checked against
the real `nfs-ls.nse` / `nselib/ls.lua` source). 1 of 4 candidates survived verification; 3 correctly
refuted.
- **correctness (HIGH): multi-export nfs-ls mis-attribution.** `parse_nmap_nfs` captured the volume
  only from the inline `nfs-ls:` header, but real nmap prints each export as its own `Volume /path`
  line — so on a multi-share box every file/access after the first was credited to the wrong (or
  empty) export, aiming the writable-share + sensitive-file findings at the wrong share in the
  report/graph. Fix: match a standalone `^Volume\s+(/\S+)` line inside the ls section and re-anchor
  `volume`. Rewrote the fixture to real nmap output (standalone 2nd `Volume` + 10-char type-char
  perms) and added a multi-volume attribution regression test.
- Refuted (verified non-issues): fixture's type-char-less perms "drop findings" (the `[dlbcps-]?`
  regex already handles the real 10-char form; only a speculative future regex-tightening breaks it);
  `is_secret_name` misses/over-fires (non-executing hint tuning; `.htpasswd`/`.git-credentials`
  already match via the `passwd`/`credential` substrings); mixed-ACL test gap (`_world_readable`
  already flags `10.0.0.0/24,*` as world-readable — hypothetical regression, not a live defect).

### Phase 2 · module 9 (nfs) — engine
- **NfsModule** (`modules/nfs/`): triggers on 2049 / nfs service names. Tier-1 read-only recon
  (`recon_steps`): `showmount -e {target}` (exports + client ACL) + `nmap -sV --script
  nfs-showmount,nfs-ls,nfs-statfs -p 2049 {target}` (exports, a BOUNDED directory listing over the
  NFS protocol with NO local mount, fs stats). Mounting stays Tier-2 (§12 "mount only on confirm").
  `anon_credential` (source `nfs-anon-enum`) for a world-readable export.
- **parsers.py**: `parse_showmount` (export path + client ACL; world-readable = a client token of
  `*`/`(everyone)`/`0.0.0.0/0`, exact-token not substring so `*.corp` and `/24` stay restricted;
  leading-`/` filter skips the header, RPC errors, and `[missing]`/`[blocked]` sentinels) and
  `parse_nmap_nfs` (banner, nfs-showmount exports, nfs-ls files [skips `.`/`..`, filename kept
  verbatim], access-line writable detection via `\bModify\b` so "NoModify" is not misread as
  writable). `is_secret_name` flags id_rsa/.ssh/shadow/etc. `parse_nfs_tool` dispatch.
- Tier-2 `manual_commands.yaml` (8): rpcinfo, showmount -e/-d/-a, nmap nfs-ls (no mount), and a
  read-only mount → ls -laR → umount workflow (copy-to-a-terminal; sudo/ls/mount aren't on the exec
  allowlist, so a stray in-GUI run of them safely `[blocked]`s). No creds, no lists.
- shell.py: correct install hints for showmount (nfs-common) + rpcinfo (rpcbind).
- 16 tests (parsers + module incl. world-readable ACL cases, writable-vs-NoModify, and a mount
  read-only invariant); `services.yaml` already had the 2049 entry. Four gates green.

### Phase 2 · modules 5–7 (ssh, dns, ldap) — feature + hardening
- **ssh** (§ next after ftp): `SshModule` Tier-1 = one nmap NSE scan (ssh2-enum-algos,ssh-auth-methods,
  ssh-hostkey); parser extracts banner, host keys, weak algos, offered auth methods. `ssh` added to
  shell ALLOWED_TOOLS. Hardening: interactive ssh password logins could hang the sole worker slot —
  fixed at the chokepoint (Popen now `stdin=DEVNULL` + `start_new_session=True`, so no wrapped tool
  can block on stdin//dev/tty), + ConnectTimeout on ssh entries + honest "copy to a terminal" wording.
- **dns** (protocol-only; subdomain brute stays in vhost): version.bind + nmap dns-nsid/dns-recursion,
  and zone transfer + `dnsrecon -t std` only when a validated domain is present. Hardening: the manual
  path interpolated the UNVALIDATED domain (could smuggle `-t brt`) → now normalize_domain-gated;
  parse_dig_version skips `[missing]`/`[blocked]`/`dig:` sentinels; added 53/udp + `service_name:
  domain` reference rules.
- **ldap**: two-phase worker — anonymous root DSE (ldapsearch + nmap ldap-rootdse) → discover naming
  context → bounded (`-z 200`) anonymous user search. `sanitize_basedn` guards the `-b "..."` surface
  against BOTH a user-typed and a hostile server-returned base DN; LDIF parser unfolds continuation
  lines and skips base64 values; anonymous bind auto-writes an `ldap-anon-enum` cred. LDAPS-aware URI
  (636/3269 → ldaps://). manual_commands.expand gained `{basedn}`.
- Each shipped with fixtures + parser/module/GUI tests; four gates green at every commit.

### Phase 2 · module 4 (ftp) hardening (this commit)
Adversarial 3-lens review (12 agents, verified against real nmap 7.99 / curl 8.x); 5 of 9 survived, all
fixed (4 non-issues correctly rejected):
- **correctness (MED): parser drift — nmap `[NSE: writeable]` marker** was folded into the file/dir name
  (`/incoming [NSE: writeable]`). Strip it and record a `note` (writable anon dir = notable recon).
- **correctness (MED): multi-space filenames** — `split()`/`join` collapsed `two  dirs` → `two dirs`, so
  the walk built a wrong URL and missed the subtree. Parse the 8 fixed ls -l fields positionally, take
  the name verbatim (keep internal + trailing spaces).
- **correctness (MED): Tier-2 manual port** — templates had no `{port}`, so every follow-up hit :21 on a
  non-standard FTP box. Fold `:port` into the host authority when port != 21.
- **gui-concurrency (MED): worker-slot wedge** — `_on_ftp_done` (and `_on_smb_done`) added creds before
  `_finish_worker` with no guard; a creds.json write error stranded `self._worker` and locked the UI.
  Guard the body so the slot is always released.
- **gui-concurrency (LOW): snapshot filename collisions** — `_dir_slug` is lossy (`/` and `/root` both →
  `root`), clobbering on-disk `ftp/dirs/*.txt`. Append a sha1[:8] of the full path (injective).
- Rejected (verified non-issues): silent depth-truncation (every entry is still recorded + summarized;
  "no silent truncation" was the reviewer's invented rule), per-LIST result not capped (a listing snapshot
  is explicitly allowed by §12; the WALK is bounded), <9-token/device lines dropped (not in the real input
  domain), `..`/`/` scope escape (curl removes dot-segments client-side; `--path-as-is` never passed).

### Phase 2 · module 4 (ftp) — GUI (73c9f70)
- **FtpPanel** (`gui/widgets/ftp_panel.py`): Tier-1 buttons ("Run full FTP recon (bounded walk)" → full,
  "Just list anonymous root" → anon) emitting `recon_requested(mode, port)` (FTP carries the port);
  Tier-2 manual follow-ups (target/port-expanded, FILE/SUBDIR left literal) with copy menu; findings
  summary. Shown as tool_panel stack page 3 when `ref.module == "ftp"`; disabled during a scan.
- **FtpReconWorker** (`main_window.py`): drives the bounded anonymous auto-walk on its thread — nmap
  banner/anon → curl root LIST → BFS recurse into subdirs, **capped at depth 3 / 25 dirs** (emits a
  "bounded" line when it truncates, never silently), LIST-only (never downloads). `seen` set stops
  symlink loops. Confirms anon from nmap OR a non-empty listing; writes findings.json + anon cred
  (`ftp-anon-enum`). Modes: full (recurse) / anon (root only).
- 6 GUI tests (buttons+port, manual legality, page switch, worker full-walk recursion + anon-no-recurse).

### Phase 2 · module 4 (ftp) — engine (24a3837)
- **FtpModule** (`modules/ftp/`): triggers on 21 / ftp service names. Step-builders return `FtpStep`s
  (parser key per step): `banner_steps` (`nmap -sV --script ftp-anon,ftp-syst,ftp-bounce`), `anon_steps`
  (`curl -s ftp://host/` root LIST), `list_step(path)` for the bounded walk. `ftp_dir_url` URL-encodes
  the target-controlled path (keeping '/') and always ends in '/' so curl LISTs (never downloads a file)
  and a hostile dir name (`-x`, spaces, `:`) can't inject a flag/second URL. anon_credential
  (source `ftp-anon-enum`).
- **parsers.py**: `parse_ftp_listing` handles both Unix `ls -l` (incl. multi-word names, symlinks) and
  MS-DOS/IIS listings → `FtpEntry`; `parse_nmap_ftp` (anon-allowed, -sV banner, ftp-bounce note, ftp-anon
  root snapshot, ignores the ftp-syst STAT block); `subdirs` drives the walk. `parse_ftp_tool` dispatch.
- Tier-2 `manual_commands.yaml` (7): targeted read/download (FILE), subdir listing (SUBDIR), passive
  listing, explicit mirror, single default-cred checks (ftp:ftp, admin:admin) — never lists/spray.
- 16 tests (parsers + module incl. untrusted-path injection); services.yaml already had the ftp entry.

### Phase 2 · module 3 (smb) hardening (4f662f2)
Adversarial 3-lens review (12 agents, each finding verified against the REAL installed netexec 1.4.0);
6 of 9 candidates survived verification, all fixed (3 non-issues correctly rejected):
- **§2/§11 (HIGH ×2): netexec spray-guard bypasses.** The old guard only checked the single token after
  -u/-p and only for is_file(). But netexec -u/-p are argparse `nargs='+'` and user×password spray is the
  DEFAULT, so three Tier-3 vectors slipped through: `-p a b c` (inline spray), `-p decoy rockyou.txt`
  (file in 2nd position), and `-p=rockyou.txt` / `-prockyou.txt` (= / concatenated syntax). Rewrote as
  `_netexec_violation`: normalizes =/concatenated forms, consumes the whole nargs run, blocks >1 literal
  OR any file value; single literals (`-p ''`, `-p sa`) still pass. Verified all 29 real module/manual
  commands pass and all bypass vectors are blocked.
- **correctness (HIGH): parse_netexec_users matched nothing on netexec 1.4.0.** 1.4.0 prints --users as a
  fixed-width table with NO `domain\user` prefix (header `-Username- -Last PW Set- -BadPW- -Description-`);
  the old regex required a backslash → zero users on a successful enum. Now takes the first column, with a
  backslash fallback for older CME output; regenerated the fixture to the real 1.4.0 format.
- **correctness (MED): READ,WRITE shares read as no-access.** netexec joins perms into one `READ,WRITE`
  token; the membership test never matched → a writable share looked inaccessible. Now comma-split.
- **correctness (LOW ×2): multi-word share names truncated** (split on 2+ spaces so `Team Share` survives;
  quote the UNC in the follow-up smbclient command); **duplicate readable shares** listed twice in
  full/shares mode (dict.fromkeys before the per-share loop).
- Rejected (verified non-issues): _on_smb_done cred-add wedge (findings.json write front-runs it on the
  same path, so failures surface via the guarded worker try/except), timeout=None hang (tools self-bound:
  netexec --smb-timeout 2s, enum4linux-ng 10s), Add-Credential-during-run (modal dialog; writes only
  creds.json on the UI thread, no profile.json race).

### Phase 2 · module 3 (smb) — GUI (660a9cd)
- **SmbPanel** (`gui/widgets/smb_panel.py`): Tier-1 recon buttons (full / null-only / guest-only /
  shares-only → `recon_requested`), Tier-2 manual follow-ups list loaded from `manual_commands.yaml`
  and target-expanded (double-click runs via the ad-hoc path; right-click → copy as `//`, `\\`, or
  bash-escaped UNC), and a live "Findings so far" summary. Tier-3 is never shown.
- **tool_panel**: SmbPanel is stack page 2, shown when `ref.module == "smb"`; `smb_recon_requested`
  forwarded; manual follow-ups reuse `run_requested` (validated at the shell chokepoint); disabled
  during a scan.
- **SmbReconWorker** (`main_window.py`): QThread that drives the conditional Tier-1 *sequence* on its
  own thread — banner → null/guest phases → detect auth (`netexec_auth_ok`) → if authed, followups
  (users/pass-pol/rid-brute/rpcclient) + per-readable-share `ls`. Writes findings.json; returns
  anon creds (source `smb-anon-enum`) for the UI thread to add. Modes: full/null/guest/shares
  (shares skips followups).
- UNC command transforms `to_backslash_command`/`to_escaped_command` added to the smb module.
- Tests: `tests/gui/test_smb_panel.py` (buttons, manual legality, worker full-drive + shares-mode via
  a monkeypatched shell.run) + UNC-transform unit tests; updated two widget tests that assumed 445
  used the generic hints page (it now opens the SMB panel). 146 pass; all four gates green.

### Phase 2 · module 3 (smb) — engine (b177316)
- **SmbModule** (`modules/smb/`): triggers on 139/445; step-builders (`banner/null_session/guest/
  followup/share_steps`) returning `SmbStep`s (each carrying a parser key) since Tier-1 is a
  conditional sequence, not one command. Tier-2 `manual_commands.yaml` = single default-cred attempts
  (administrator:'', admin:'', sa:sa, guest) + RID cycling + rpcclient/smbmap enum (no secretsdump,
  no lists). anon_credential(source smb-anon-enum).
- **parsers.py**: netexec shares/users/rid-brute/pass-pol, smbclient -L, rpcclient enumdomusers →
  `SmbFinding`; modelled on real tool output. `readable_shares`, `netexec_auth_ok`.
- **§11 spray guard** (shell.py): a `-u`/`-p` value that is a *file* (netexec's own list semantics) is
  blocked as Tier-3 brute; single literals pass. `nxc` added to the allowlist.

### Phase 2 · module 2 (vhost) hardening (4c04471)
Adversarial 3-lens review; fixed all 9 findings (the correctness lens ran the real installed tools):
- **§2 (high):** validate the vhost domain/dns_server like Target.ip (reject whitespace/leading-'-'/
  quotes) — blocks flag injection (a crafted domain adding ffuf `-x proxy` → off-target traffic).
- **tool-version bugs (high):** gobuster 3.8.2 uses `--domain`/`--resolver` (not `-d`/`-r`); gobuster
  vhost now hits the target IP (not the domain URL, so no /etc/hosts needed); dnsrecon 1.6.0 output is
  "INFO A host ip" (no `[+]`); added a dedicated gobuster-dns parser and a wfuzz parser (both had
  silently dropped every hit).
- **robustness:** broadened the parse guard (a ValueError could wedge the worker); defensive int
  coercion; clear a stale `-o` before a re-run; set_profile no longer clobbers a user-typed domain.

### Phase 2 · module 2 (vhost) — engine + GUI (6cb6899, 062cc18)
- engine: VhostModule (active/target-directed only; passive OSINT excluded per §2), build_command
  (ffuf Host-FUZZ, gobuster vhost/dns, dnsrecon, wfuzz), wildcard probe, 5 parsers -> findings.json
  (dedup key gained 'vhost'), 10 manual commands.
- GUI: vhost builder in a second web tab (domain/tool/scheme/wordlist/-fs + Detect-wildcard/threads/
  DNS server), discovered-vhosts list + "enumerate as new HTTP target"; run -> findings; wildcard
  probe auto-fills -fs.

### Phase 2 · module 1 (http) hardening (04313f5)
Adversarial 3-lens review of the HTTP module; fixed all 8 findings (+ regression tests):
- **§2:** shell.run now blocks wpscan `-P`/`-U` (short aliases of --passwords/--usernames), not just --passwords.
- **HIGH concurrency:** disable the service tree + HTTP builder during a scan so a UI edit can't race
  the worker's `profile.save()` (module_settings mutation → "dict changed size during iteration").
- **path containment:** reject an absolute/`..` Output value (was writable outside the profile dir).
- **worker-slot wedge:** parse-on-done wrapped so a findings-write error can't strand `self._worker`.
- parse_nikto no longer fabricates `/paths` from banner lines; findings dedup keys on size/redirect/note
  too (was dropping distinct wpscan users/version); default_url brackets IPv6; custom output no longer
  clobbered mid-session.

### Phase 2 · module 1 (http) — engine + GUI + QoL (7715f98, f64983b, 7547d29)
- engine: HttpModule, build_command (feroxbuster §9 line reproduced via controls), 11 extension presets
  + Wide net, status presets, 7 parsers -> findings.json, manual_commands.yaml (20), findings store.
- GUI: HTTP command-builder panel (all §9 controls + live preview + Run/Dry-run/Add-to-report +
  persistence), tool_panel QStackedWidget, http run -> findings parse, treat-as-HTTP right-click probe.
- qol: `oscp-recon` console script (`uv pip install -e .`), Kali `.desktop`, README.

### Phase 1 · adversarial review + hardening (1898c94)
Ran a 3-lens review of the Phase 1 additions; fixed all 15 findings (+9 regression tests → 63):
- **§2 password-list leak (high):** `wordlists.py` now uses an AFFIRMATIVE category allowlist
  (only web-content/dns/usernames/fuzzing/discovery surfaced) + expanded denylist — `fasttrack.txt`
  / `wifite.txt` no longer leak from `/usr/share/wordlists` (verified live: 0 leaks).
- **searchsploit flag injection (high):** strip leading `-` from query tokens + block
  `-m/-x/-u` at the exec chokepoint (a hostile banner can't turn lookup into PoC copy/update).
- **`_IndexWorker` SIGABRT (high):** `WordlistPicker.shutdown()` waits the worker before teardown.
- creds temp file created 0600 (not umask); `Profile.load` recreates service dirs; manual output
  files hash-suffixed; scan-time ref-visits buffered+drained; secret field masked; matcher
  tie-break; `load_rules` degrades on bad YAML; line-count off-by-one; skip huge-file counting.

### Phase 1 · chunk 6 — wordlist picker + notes + credentials (b7d97c3) — Phase 1 COMPLETE
- `wordlist_picker.py`: searchable/filterable list backed by `wordlists.py` (background indexing
  thread), category filter, favorites pinned top; emits `wordlist_chosen`.
- `notes_pane.py`: debounced-autosave editor for `<profile>/notes.md` (atomic write); flushes on
  profile switch / save / close; wired as a bottom Notes dock (View menu toggle).
- `AddCredentialDialog` (Edit menu) writes `creds.json` via `Profile.add_credential`;
  "Browse Wordlists…" (View menu) opens the picker.

### Phase 1 · chunk 5 — GUI references integration (58f08dd)
- `reference_pane.py`: real `QWebEngineView` loading the matched HackTricks page on service
  selection (graceful fallback to a link label when QtWebEngine can't init / is disabled);
  Exploit-DB list filled from `searchsploit --json` off the UI thread, click → loads the EDB
  page in the same view; emits `page_visited` → recorded via `Profile.add_reference_visited`.
- `SearchsploitWorker` (QThread) with stale-result guarding; workers kept alive until `finished`.

### Phase 1 · chunk 4 — three-pane GUI restructure (f0c9be7)
- MainWindow → `QSplitter(service_tree | tool_panel | reference_pane)`; selection wiring;
  `CommandWorker` runs ad-hoc tool-hint commands through the policy-enforced `shell.run`.

### Phase 1 · chunk 3 — creds.json + references-visited (76bae3d)
- `models.Credential`; `creds.py` (atomic 0600 write, `redact()`, dedup); `Profile` helpers
  `creds_path` / `credentials()` / `add_credential()` / `add_reference_visited()`.

### Phase 1 · chunk 2 — references subsystem (5a4dbd7)
- `references/` package: `services.yaml` + matcher (§14 precedence) + `searchsploit --json`
  Exploit-DB lookup (display-only). All tool-hint templates pass the exec policy.

### Phase 1 · chunk 1 — wordlists (155a7ac)
- `wordlists.py`: index wordlist paths, filter password lists (substring on any path part +
  metasploit + rockyou + symlink target), app-wide favorites.

### Phase 0 — scaffold (646fc29)
- Engine (`shell`/`models`/`config`/`profile`/`orchestrator`/`reporter`) + nmap module +
  Typer CLI + minimal PySide6 GUI + fixtures/tests. Hardened after adversarial review: target
  validation, exec allow/deny policy, atomic writes, real timeout watchdog, GUI safety.
