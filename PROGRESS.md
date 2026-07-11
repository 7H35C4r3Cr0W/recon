# oscp-recon — progress log

Running record of what's been built, in order, so any session can pick up mid-stream.
**Read "Next up" first, then the newest log entry.** Authoritative specs live in `CLAUDE.md`
(the brief) and `ROADMAP.md` (the phase plan); this file is "where are we right now".

## Next up

**Phase 2 module 3 — smb** (tiered auto-recon, §11): Tier-1 auto null-session/guest checks
(smbclient -L -N, netexec --shares, enum4linux-ng -A, rpcclient null, RID cycling, per-share
listing), Tier-2 shown-only single default-cred checks (administrator:'', admin:'', sa:sa),
NEVER Tier-3 list-driven brute. Auto-write null/guest success to creds.json (source smb-anon-enum).
Then ftp/ssh/dns/ldap/smtp/nfs/snmp/tftp/netbios/ike/ntp. **HTTP + vhost done + hardened.**

## How to resume

1. `cd ~/oscp-recon` (repo is local-only, no git remote yet). `uv` lives at `~/.local/bin/uv`; run `uv sync` if deps are missing.
2. Gates before every commit: `uv run mypy --strict src/`, `uv run pytest -q`, `uv run ruff check`, `uv run ruff format --check`. GUI tests need `QT_QPA_PLATFORM=offscreen`.
3. Commit each chunk once gates are green — no need to ask. Show any new *wrapped command* before writing it (CLAUDE.md §27); only recon tools on the §2 allowlist.
4. Update this file with each chunk and commit it alongside that chunk.

## Log (newest first)

### Phase 2 · module 2 (vhost) hardening (this commit)
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
