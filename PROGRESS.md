# oscp-recon — progress log

Running record of what's been built, in order, so any session can pick up mid-stream.
**Read "Next up" first, then the newest log entry.** Authoritative specs live in `CLAUDE.md`
(the brief) and `ROADMAP.md` (the phase plan); this file is "where are we right now".

## Next up

**Phase 2 module 5 — next service module** (§12 order): pick from **ssh/dns/ldap/smtp/nfs/snmp/tftp/
netbios/ike/ntp**. Same engine→GUI→adversarial-review→commit pattern. **HTTP + vhost + smb + ftp all
done, reviewed, hardened** (175 tests). Note the recurring review lessons: parsers must match REAL
current tool output (run the tool's help/script-help), always release the worker slot in a finally/
guard, make on-disk artifact filenames injective, thread the service port through every command.

## Queued additions (recorded 2026-07-11 — do NOT build early; pick up at the noted phase)

Five features queued into `CLAUDE.md` + `ROADMAP.md` for a fresh session to build at the right time.
Specs are authoritative in CLAUDE.md; this is the pointer list.

1. **Status footer** (CLAUDE.md §19) — always-visible bottom strip: app+version (from pyproject),
   active profile, workspace root, "recon-only — OSCP exam legal". → Phase 2 QoL or Phase 5.
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
