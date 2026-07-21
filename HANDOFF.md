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
- **github/main HEAD `41db300`: Cereal box review + cross-box attack-coverage + GUI-UX round 2** (pushed).
  `origin` = local Gitea (often offline) — push to the **`github`** remote (`git push github main`).
- Session (2026-07-20l) — **Cereal box + overnight "hammer large chunks": attack-coverage catch-up + GUI-UX round 2 + full-suite hang fix.**
  - **Full-suite hang FIXED (root cause found).** The deterministic ~16% freeze was NOT flaky/env — a
    modal `QMessageBox.information` I'd added to `_on_scan_preset` (no-project path) blocked forever
    headless. Fixed the specific test (spy the modal) **and** added a systemic conftest autouse guard
    `_neuter_blocking_dialogs` that auto-answers every QMessageBox/QFileDialog/QInputDialog/QDialog.exec
    so any stray modal is now a fast FAILURE, not a hang (a test needing a real return overrides it).
    Verified the suite sails past 16%. Commits `af27d72` + `0648a6e`.
  - **Attack-coverage audit → `7081eba`** — audited the Exploitation catalog vs Phoenix/Drive/Cereal/
    Snoopy chains (Workflow); confirmed most feared gaps were ALREADY covered (flask-unsign, git-dumper,
    ysoserial.NET, graphql-introspection, GodPotato/SweetPotato) and added the **7 genuinely-missing
    generic techniques**: `totp-code-from-secret` (oathtool — the missing last mile of a 2FA bypass),
    Django known-SECRET_KEY leak+forge (parallels the Flask coverage), `xss-ssrf-internal-read`,
    `crack-phpass` (hashcat -m 400), `genericpotato-shell` (completes the potato family),
    `nsupdate-tsig-key-authenticated-update`, and a `clamscan` GTFOBins entry. Regression-locked in
    `test_recent_box_attack_techniques_present`; §21-safe (generic classes, no CVE/box payloads).
  - **GUI-UX round 2 → `41db300`** — 16-agent find→verify review found 11 confirmed defects, all fixed:
    (HIGH) EDB-result click now switches to the Live tab (was loading behind the hidden tab); New Project
    over an existing name now BLOCKS instead of silently wiping profile.json; simple-recon Tier-2
    follow-ups now fill {user}/{password}/{domain} + dim requires:["creds"]. (MED) per-task Stop button
    feedback; gtfobins Copy flash; notes-pane autosave-failure surfaced; honest manual-followup labels.
    (LOW) simple-panel empty-state placeholder; msfvenom raw-format placeholder truth; report_view
    buttons gated on a loaded profile. +2 regression tests (EDB tab-switch, new-project no-wipe).
- Session (2026-07-20k) — **Breadcrumbs box review + the owner's recon-AND-attack catch-up.** The owner
  (rightly, angrily) called out that the last few box reviews skipped the ATTACK side. Fixed:
  - **Recon (Breadcrumbs) `<discovered-urls uploads flag>`** — the Discovered-URLs "Important" column
    flagged source/backup/VCS files but not an `/uploads/`-type directory (the webshell-drop target,
    Breadcrumbs' `/portal/uploads/`). New `is_upload_dir`/`interesting_path_reason` (curated high-signal
    names, no `/files`/`/images` noise) → upload dirs get their own ⚠ flag + tooltip + CSV label.
  - **ATTACK catch-up `0fd47b3`** — audited the Exploitation catalog vs Spider/Breadcrumbs/EarlyAccess/
    Spooktrol attack chains (via a Workflow) and added the **6 generic techniques** that were missing:
    4 Jinja2 SSTI WAF-bypass payloads (Spider), `jwt-alg-confusion` (Breadcrumbs — completes jwt_tool
    set), `upload-filename-traversal-write` (Spooktrol), `php-variable-function-rce` (EarlyAccess),
    generic SQLite loot triage + row-injection (Spooktrol), `arp` capability file-read + gtfobins
    (EarlyAccess). All pass the Popen-safe/no-restricted guards; §21-safe (generic classes, no CVE/box
    payloads). **Rule now in this file's "How I work": every box review checks BOTH recon AND attack.**
- Session (2026-07-20j) — **HTB Spider box review** (Hard Linux; web injection — SSTI/Flask-cookie
  forging/SQLi/WAF-bypass/XXE, all exploitation → out of §21 scope). Recon surface is thin: nmap →
  22/80 + an nginx 301 to `spider.htb` (**already** auto-set from both the nmap http-title redirect
  and whatweb RedirectLocation — verified, no gap). One clean gap → **`feat(patterns)` `17d163c`**: a
  **Python web framework** recon lead. whatweb fingerprints the Flask app as `Werkzeug[2.0.1]` but the
  tool had no nudge — `detect_api_server` deliberately excludes Werkzeug/gunicorn (they front HTML
  apps). New http pattern (matches `note` for `Werkzeug[…]` / `Django[…]|/…`, the plugin/version form
  so a "Django" page title doesn't false-fire) → check the Werkzeug `/console` debug endpoint +
  decode the Flask session cookie's structure (recon-only). 140 pattern rules.
- Session (2026-07-20i) — **HTB EarlyAccess box review + a full owner-mandated sweep**. EarlyAccess
  first: **`feat(nmap)` `98246be`** — mine the box hostname from the **ssl-cert CN/SAN** (nmap
  `ssl-cert` NSE); `_handle_redirect_vhosts`→`_handle_hostname_leads` unions the redirect + cert
  sources, regression-safe (redirect keeps its exact auto-set; the cert auto-sets ONLY when there's
  no redirect + no hostname; user hostname never overridden; SANs → vhost leads). Then the owner asked
  for a **complete sweep** run as parallel audit Workflows → fixed in orderly chunks:
  - **`fix(gui)` `af66a00`** — 15 GUI-UX defects (silent no-ops now give feedback: scan-preset load /
    http Fingerprint / vhost Run+wildcard+enumerate; `styles.flash_copied` "Copied ✓" on cred-vault /
    msfvenom / pivot copies; Save gated on a loaded project; theme radio matches multi-word names via
    `action.setData`; dashboard status → status bar; graph-export + log-clear failures surfaced;
    wordlist empty-state hint; shortcut labels corrected).
  - **`fix` `e35510e`** — 7 code-review bugs, reproduced + regression-tested: 3 report.md.j2 markdown
    injections (Summary-table `|`, ``` code-fence break-out, YAML-frontmatter newline → new `mdcell`/
    zero-width-break/`yamlstr`), a kubernetes parser crash on a non-list `versions`, `cli exploit`
    ignoring hash creds (now fills `{hash}` like the GUI), `workspace.bulk` clobbering a malformed-lock
    profile, and an `exploit/cmsms` attacker action with a `~`-path argv0 → victim (the popen-runnable
    guard now also rejects `~`/`$VAR`).
  - **`feat(cli)` `2fb511b`** — closed 11 CLI↔GUI parity gaps: new CLI `enum <svc>` (runs the 44
    SIMPLE_SPECS services' Tier-1 recon headlessly), `creds` add/list/rm, `list`, `findings`, `health`,
    `activity`, `delete-project`, `searchsploit`, `spray` + `config` (gated), and a GUI **Scan →
    Resume Recon** (parity with `scan --resume`).
  - **`feat(patterns)` `9a71c69`** — +16 vault-mined recon next-steps (ldap/kerberos/smb/smtp/http;
    AD-Path/CPTS-sourced, all recon-only + provenance-cited). 139 pattern rules now.

  **Deferred follow-ups from the mandate (not yet done):**
  - CLI `enum` covers the 44 SIMPLE_SPECS services; **http/smb/ftp/ssh/dns/ldap/vhost keep their
    settings-heavy panels GUI-primary** (wordlist pickers, tiered SMB, vhost fuzz config). Their nmap
    discovery already runs headless via `scan`. If full parity is wanted, extract those panels'
    Qt-free step builders into a shared module and add them to `enum`.
  - 4 vault "missing techniques" need an **allow-list decision or a parser/module change** first:
    `kerbrute userenum`, `certipy-ad find` (both need adding to `ALLOWED_TOOLS`); `smtp-enum-users`
    NSE (add to the smtp scan); `snmpwalk -Oa` (readable hex strings — changes the snmp parser +
    fixtures, so verify carefully).
- Session (2026-07-20h) — **HTB Spooktrol box review** (Hard Linux; uvicorn/FastAPI malware-C2,
  path-traversal file-write, SQLite task injection). Recon-only lessons (§21) — the Ghidra/implant/DB
  exploitation is out of scope. Three chunks, full suite EXIT=0:
  (1) **`feat(http)` `09b32f1`** — the box is a JSON API and the tool had ZERO API awareness (a JSON
  root looks like a broken site to file-oriented discovery). New `detect_api_server()` +
  `HttpModule.suggest()` API lead (curl /openapi.json, /docs, /redoc, /swagger.json, /api/v1 — the
  schema lists every route+param) + inline `[api]` follow-up. (2) **`feat(nmap)` `d04b7bc`** — nmap's
  `-sC` reveals `http-robots.txt` disallowed entries (Spooktrol: `/file_management/?file=implant` = the
  whole path to the box) + a uvicorn/JSON banner, both buried in the NSE blob. New
  `nmap.robots_disclosures()` + orchestrator `_handle_nse_leads` emit `[robots]`/`[api]` tips at scan
  time (mirrors `_handle_redirect_vhosts`). Complements the Phoenix curl-robots fetch. (3) **`fix`
  `f1b9578`** — a background adversarial review (3 slices) confirmed **4 real defects, all reproduced +
  fixed**: MEDIUM `detect_api_server` false-fired on **every WordPress site** (`application/json` ⊂
  `application/json+oembed`) + bare names in page bodies → now a **Server-header-context regex** +
  anchored JSON + inline check gated to whatweb; MEDIUM `robots_disclosures` over-captured a
  `/`-token from a following `http-title: Index of /files` → block now ends on any non-`/`-path line;
  LOW orchestrator `[api]` tip on a no-web box (`Computer name: DAPHNE`) → gated on an HTTP service
  being present; LOW ReDoS in `_ROBOTS_NSE_HEADER` (`\s*\d*\s*` O(n²), ~70s) → `[\s\d]*` linear.
- Session (2026-07-20g) — **HTB Phoenix box review** (Hard Linux; WordPress → asgaros SQLi → 2FA
  bypass → Download-from-Files upload → rsync wildcard root). Three chunks, full suite EXIT=0:
  (1) **`fix(http)` `c34d600`** — nmap's disallowed `/wp-admin/` in robots.txt is the canonical
  WordPress tell, but the tool never fetched robots.txt in the GUI recon flow and `detect_wordpress`
  only matched wordpress/wp-content/wp-login. New `parse_robots` (surfaces every Disallow/Allow/Sitemap
  path — hidden admin/backup dirs, useful on ANY box) + `"robots"` in `_PARSERS`; **Fingerprint** now
  curls robots.txt from the host root (tool="robots"); `detect_wordpress` broadened with
  wp-admin/wp-includes/wp-json (fires the `[wordpress] detected` follow-up + the `suggest()` wpscan
  step from robots alone); exploit-tab presence folds wp-content/wp-admin → WordPress ●. (2)
  **`feat(exploit/linux)` `4a9218d`** — generic `cron-wildcard-rsync` primitive (a file named
  `-e sh shell.sh` becomes rsync's remote-shell option), the victim/copy-only sibling of the existing
  tar `--checkpoint` variant; the rest of the chain (pspy, wildcard, WordPress attacks) was already
  covered at the right non-CVE altitude. (3) **`fix(http)` `601229c`** — a background adversarial
  review (4 slices) confirmed 3 real defects in the new robots code, all reproduced + fixed:
  **MEDIUM ReDoS** in `_ROBOTS_RULE` (lazy `\S.*?`+`\s*$` → O(n²) on a whitespace run; the target
  serves robots.txt, so it's untrusted — made greedy) + a secondary O(n²) list-dedup (now set-backed);
  **LOW** inline-`#`-comment swallowed into the path (now trimmed per RFC 9309); **LOW** scheme-less
  URL+path fetched robots from the wrong location (urlsplit now `//`-prefixed). Two other slices
  (rsync action, main_window parse flow) came back clean.
- Session (2026-07-20f) — **HTB Carpediem box review** (Hard Linux; nginx portal / SIP-VoIP / Backdrop
  CMS / container escape). Full suite EXIT=0. Chunks: (1) **`fix(http)`** — the domain `carpediem.htb`
  lives ONLY in the landing-page `<h1>` body (not email/title/redirect), so whatweb+nmap surfaced
  nothing. The **Fingerprint** button now also snapshots the index page (`curl -sk -o index.html`) and
  `parse_webpage`/`lab_hostnames_from_text` mine lab-TLD hostnames (`*.htb/.vl/.thm/.local/…`, CDN
  hosts ignored) into a `HttpFinding.page_host` finding + vhost-enum suggest step. Verified live: body
  → `carpediem.htb` → vhost enum → `portal.carpediem.htb`. (2) **`feat(exploit/docker)`** — added the
  cgroup-v1 `release_agent` container escape (victim/copy-only, the generic CAP_SYS_ADMIN breakout
  behind CVE-2022-0492); the rest of the chain was already covered (`api-mass-assignment`, file-upload,
  `backdrop.py`, `sip.py`, getcap, tcpdump, cron). (3) **`fix` robustness** — 3 bugs from an adversarial
  review of 4 not-yet-swept slices: corrupt-config-bricks-startup (HIGH; `config._read_json` now
  `except (OSError, ValueError)`), nmap `--reason` polluting `product` (MEDIUM; stripped in
  `parse_port_line`), `live_hacktricks.read_cache` raising on non-UTF-8 (LOW). A `bulk.py` lost-update
  is latent (feature unwired — `run_bulk` has no GUI caller) → deferred.
- Session (2026-07-20e) — **HTB Snoopy box review** (Hard Linux; DNS Bind9 / nginx LFI → leaked
  rndc-key DNS-hijack → Mattermost → git/clamscan sudo). Two chunks, both full-suite EXIT=0:
  (1) **`fix(http)` `00c7baa`** — whatweb captured `Email[info@snoopy.htb]` but only rendered it into
  the note; `suggest()` did nothing, so an IP-only scan gave no nudge toward the `snoopy.htb` domain
  that unlocks the box (vhost enum → `mm.snoopy.htb`, verified live). Now `email_domains_from_plugins`
  + `HttpFinding.email_domain` (persisted) mine the email's domain (public providers filtered) into a
  first-class recon finding + a "add to /etc/hosts, Set Hostname, enumerate vhosts" next-step. Fixture
  + 4 tests + recon-guide sync. Box #31 logged. Attack chain already covered (LFI `....//`, nsupdate
  DNS-injection, mattermost.py, git-sudo GTFOBins) at the correct non-CVE altitude. (2) **`fix(gui)`
  `4ca14fd`** — adversarial review of 5 not-yet-swept slices (graph_html JS bridge, edb.py,
  gtfobins_search, config migration, themes) → core clean, fixed 4 low-sev bugs: graph link-mode
  duplicate-edge (dedup + `cy.add` guard, was stranding link mode), empty-note orphan, Dark theme
  palette grey↔navy mismatch (derive from tokens), `osBadge` Darwin→Windows mislabel. 1 flagged item
  was a false positive (reference node IS created via `finding_severity.classify`). 2 tests added.
- Session (2026-07-20d) — **HTB Drive box review** (Django IDOR / vhost / filtered Gitea on 3000).
  vhost redirect to `drive.htb` surfaces via both whatweb and nmap. Fixed 1 gap: **filtered ports were
  dropped entirely** — the parser only matched `open`/`open|filtered`, so `3000/tcp filtered` (Gitea,
  the post-foothold pivot) vanished. `nmap.parse()` now emits an informational finding for explicitly-
  filtered ports (deduped; "revisit after a foothold/pivot") WITHOUT adding them to
  `discovered_services` (no phantom actionable node, unaffected presence). Verified on the real Drive
  output. Tested.
- Session (2026-07-20c) — **HTB BigBang box review** (WordPress + BuddyForms / vhost-redirect /
  Grafana). Verified the Race fixes hold live (vhost `blog.bigbang.htb` redirect + WP enum suggestion
  both fire) and fixed 2 more gaps, tested: (1) **nmap `http-generator` → fingerprint presence** — the
  CMS name nmap's NSE finds ("WordPress 6.5.4") lives in `nmap_scripts_output`, which the exploit-tab
  fingerprint fold ignored; now included, so WordPress is `●` right after the scan (before whatweb).
  (2) **`open|filtered` UDP no longer marks a service present** — the UDP top-100 returns non-responding
  ports as `open|filtered`, which falsely flagged SMB/SNMP/AD present; added `DiscoveredService.state`
  (parsed + persisted) and the exploit-tab presence now counts only `state=="open"`. Verified live on
  10.129.41.186: present = {ssh, wordpress}; no false smb/snmp/ad. Guide (exploitation) synced.
- Session (2026-07-20b) — **HTB Race box review** (Grav CMS / phpsysinfo / subdir-hosted app). Found +
  fixed 4 gaps, each tested: (1) **base-path redirect** — a root meta-refresh/301 to a subdirectory
  (`/` → `/racers/`) was dropped; now surfaced as an http finding + "point content discovery at this
  base path" next-step (`HttpFinding.base_path`, `base_path_from_redirect`). (2) **web-app fingerprint
  → Exploitation-tab presence** — a specific web app (Grav/WordPress/Drupal/…) was never marked `●`
  because the panel only read nmap service *names* ("http"); it now folds whatweb/nmap fingerprints
  from findings into presence (`exploit.web_app_keys_from_fingerprints`, curated + left-token-boundary
  matched; panel `_present_keys()`/`_fingerprint_texts()`). (3) **latent `_service_key_for_name` bug** —
  substring matching mapped `wordpress`→`rdp` and `ftp`⊂`tftp`; hardened to left-token-boundary regex
  (`_FRAG_PATTERNS`). (4) **401 Basic-auth** — a 401 endpoint (phpsysinfo, `admin:admin`) got no hint;
  now a Tier-2 single-shot default-cred next-step (never a spray). Verified end-to-end live on
  10.129.234.209: base_path `/racers/` + `grav` present both surface. Guide (recon/exploitation) synced.
- Prior session (2026-07-20): **+6 GUI themes** (Dracula/Nord/Gruvbox/Solarized/Tokyo Night/Monokai,
  all WCAG-AA-validated, now 12 total) · **nmap** 83 scan presets (was 29) + a searchable NSE picker +
  `--open`/`-O`/`-n`/`--reason`/`--min-rate` in the Scan dialog (new `nmap_nse.py`) · **doctor** now
  also checks reference data (SecLists/NSE/Exploit-DB), host readiness (VPN/disk/raw-socket), and
  `--versions`. THEN a **full adversarial code review** (8 background agents over the whole tool) found
  **18 confirmed bugs, all fixed + regression-tested** — highlights: closed 4 §2/§6 shell policy/
  redaction holes (wpscan `--passwords=`/`-P` bypass, impacket `-hashes` not redacted, nmap `--script
  all/*`, netexec relative-wordlist), graphql Run-button dead from literal braces, blocking listeners
  mis-marked attacker, exploit-panel braced-cred silent-Run + cred-lost-on-reentry, foreign-host lock
  PID-collision, read-only notes clobber, version-match boundary, HTML-sanitizer void-tag, +cli/parser.
  Commits `b1a2584`→`71e8efb`. (Also, non-repo: a `/etc/cron.d/nabu-maint` system-maintenance job on
  this Kali box — Timeshift snapshot → `apt full-upgrade` → junk cleanup, 3-day self-guarded; script at
  `/usr/local/sbin/nabu-maintenance.sh`.)
- Exploit catalog: **182 services / 3,434 actions**. Pattern library: **140 rules**.
  CLI (`nabu-cli`) and GUI (`nabu`) are now at **feature parity** for automatable work (see the
  parity note above for the intentional GUI-primary panels).
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
- **⚠ EVERY BOX REVIEW CHECKS BOTH RECON AND ATTACK — NON-NEGOTIABLE.** Do NOT wave off the attack
  side as "out of §21 scope". For each box: (1) fix the **recon** gaps AND (2) verify the
  **Exploitation-tab** catalog (§2b, `exploit/*.py`) carries the **generic** techniques for the box's
  attack chain — and **add any missing generic technique** (like Phoenix's `cron-wildcard-rsync`,
  Carpediem's docker `release_agent` escape). §21 forbids box-SPECIFIC exploit code / CVE payloads /
  hardcoded creds; it does NOT forbid adding generic technique classes (SSTI/XXE/JWT-forging/SQLi/
  unrestricted-upload/LFI-php-filter/cmd-injection/cookie-forging/wildcard-injection/capability-privesc).
  Report BOTH sides per box. (memory `box-review-covers-recon-and-attack` — the owner was ANGRY about
  this being skipped.)
- **Autonomous + chunked.** Don't ask permission mid-task; do it, test, commit per logical chunk,
  report once. (See memory `work-fully-autonomously`, `autonomous-chunking`, `box-review-efficiency`.)
- **Thorough — "I do not want to have to come back and revisit this."** On a broad ask, spawn parallel
  audit **Workflows** (code-review / CLI-GUI-parity / GUI-UX / Obsidian-mining), then implement each
  result as its own gated, committed chunk. Be exhaustive, not fast.
- **Full CLI↔GUI parity.** Nothing should be behind only one surface — if a capability exists in the
  GUI, wire it into the CLI (and vice-versa). Both drive the same engine.
- **Keep mining the Obsidian vault** (`vault:`, esp. `CBBH` / `CPTS` /
  `HTB AD Path`) for recon patterns + techniques (memory `obsidian-notes-location`). Recon-only,
  exam-legal, `# source:`-cited.
- **Docs in sync — especially THIS file.** A code change also updates README / CLAUDE.md / the in-app
  guide (`src/oscprecon/guide/pages/*.md`) / docs. Keep HANDOFF current so a fresh session knows
  exactly what's expected. (memory `keep-docs-in-sync`)
- **Reports: concise, to the point.** No long-winded write-ups; a TLDR per box/bug/change.
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
- **Swept 2026-07-20e (Snoopy):** `edb.py`/searchsploit lookup, `gtfobins_search`, `config.py`
  migration, the theme system, and the `graph_html` JS bridge — core clean, 4 low-sev GUI bugs fixed.
- **Swept 2026-07-20f (Carpediem):** `nmap_scan.py`+`nmap.py`, `live_hacktricks.py`, `workspace/bulk.py`
  +`index.py`, `config.py` — 3 bugs fixed (config-crash HIGH, nmap `--reason`, cache non-UTF-8); 1
  latent (`bulk.py` lost-update, feature unwired) deferred.
- **Swept 2026-07-20g (Phoenix):** the session's own new robots.txt code (`parse_robots` +
  `_on_fingerprint` robots fetch), reviewed by a 4-slice adversarial Workflow → 3 confirmed bugs
  fixed in-session (ReDoS MEDIUM + 2 LOW). The rsync-action + main_window http-parse slices: clean.
- **Swept 2026-07-20h (Spooktrol):** the session's own new API-detection + nmap-NSE-lead code
  (`detect_api_server`, `robots_disclosures`, `_handle_nse_leads`), 3-slice adversarial Workflow → 4
  confirmed bugs fixed in-session (2 detection false-positives, a no-web-box false tip, a ReDoS).
- **Not yet swept (candidates for the next round):** `workspace/bulk.py` GUI wiring + its lost-update
  fix (when wired), the reporter templates under odd findings, `simple_recon.py` worker edge cases.

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
