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
- **github/main HEAD `3d085d1`: HTB DarkCorp box review (LIVE-validated) — AD relay/loot + PG-superuser + SSSD** (pushed).
  `origin` = local Gitea (often offline) — push to the **`github`** remote (`git push github main`).
- Session (2026-07-21e) — **HTB DarkCorp box review, HIT LIVE** (Insane Win/AD). Owner (angrily, twice)
  established the standing rule now at the top of "How I work": **hit the live box AND run the
  walkthrough together; warn if the VPN is down.** Ran Nabu against 10.129.232.7 over VPN → 22/ssh +
  80/nginx; **live-validated** the recon: the box uses an HTML **meta-refresh** redirect (not HTTP 301)
  to drip.htb, and the whatweb parser's `meta-refresh-redirect` handling caught it correctly
  (`redirect_to=drip.htb`). Then an 8-dimension survey→verify audit → `feat` `3d085d1` (catalog
  3487→3497). Already-covered: the core NTLM-relay/PrinterBug/ESC8/shadow-cred/silvertkt/DCSync/bloodhound
  chain in ad.py. Added: services.yaml Roundcube row + roundcube IDOR http pattern; postgres.py
  `psql-lo-from-bytea-write` + `psql-archive-command-rce`; linux.py **"SSSD cache loot"**
  (`sssd-read-config`/`sssd-extract-cached-hash` → cached AD $6$ hash); ad.py `getTGT-enterprise-principal`
  (mixed-vendor "broken marriage" Kerberos) + `krbrelay-adcs` (Kerberos ESC8 relay) +
  `dnsadmins-serverlevelplugindll`; windows.py `credman-get-storedcredential` + `credman-scheduledtask-dump`
  + `dpapi-decrypt-blob-local`.
- Session (2026-07-21d) — **HTB RopeTwo box review** (Insane exploit-dev: V8 type-confusion → glibc heap
  tcache → Linux-kernel-module ROP). The bespoke V8/heap/kernel chains are **box-specific and OUT per §21**
  (the audit verifier rejected them). 6-dimension survey→verify **audit workflow** → `feat` `d64391c`.
  Already-covered: known-vuln lookup (searchsploit + git.py). Added the verified GENERIC gaps:
  - RECON: `services.yaml` GitLab `product_contains` row (labels a fingerprinted GitLab like the
    Tomcat/Jenkins rows — note bare port-rows still win on alt-HTTP ports by §14 precedence);
    `patterns/http.yaml` contact/feedback/comment-form path → blind-XSS + client-side-SSRF recon hint.
  - ATTACK: gitlab.py `gitlab-list-snippets-api` + `gitlab-repo-commits-api` (attacker curl, unauth
    secret-leak surfaces); web.py `xss-blind-oob-beacon` (OOB callback in a bot/admin browser, victim);
    linux.py "Kernel exploit" `kmod-enum` + `kmod-modinfo` (enumerate a CUSTOM loaded driver — distinct
    from the version-only kernel-info/les-run); linux.py "Binary exploitation" `binexp-patchelf-target-libc`
    (run a looted binary against the target's own libc). Catalog **3481→3487**.
- Session (2026-07-21c) — **HTB Intense box review** (Flask source-review → SQLite blind SQLi → hash
  length-extension → path traversal → SNMP rwcommunity RCE → custom-binary ROP). 7-dimension
  survey→verify **audit workflow** → `feat` `7bd9e9a`. Already-covered (grep-confirmed): **SNMP
  NET-SNMP-extend RCE** (`snmp.py` extend-rce-create/trigger), path-traversal/LFI, ssh -L pivot +
  authorized_keys plant. Added the verified gaps:
  - RECON: `modules/http/parsers.py` **`is_source_archive()`** — flags a leaked source/site-backup
    ARCHIVE at web root (src.zip/source.tar.gz/www.zip/backup.7z) as the top HTTP disclosure (archive
    ext + high-signal stem only; jquery.zip stays quiet). New "leaked source archive" ⚠ reason +
    tooltip + CSV flag + parser test.
  - ATTACK: web.py `hash-length-extension` (hashpump forge H(secret‖data), brute secret len),
    `sqli-sqlite-blind-oracle` (SQLite CASE WHEN…load_extension error-oracle + substr extraction),
    `sqli-filter-bypass` (keyword/WAF bypass cheatsheet) — all victim; linux.py new **"Binary
    exploitation"** category `binexp-checksec` + `binexp-pwntools-skeleton` (generic copy-only ROP
    scaffold, NOT the box-specific chain per §21).
  - Catalog **3476→3481**.
- Session (2026-07-21b) — **HTB Tentacle box review** (Squid proxy → OpenSMTPD RCE → MIT Kerberos
  lateral + privesc). Ran a 9-dimension survey→adversarial-verify **audit workflow** across BOTH
  recon and attack sides → `feat` `53f9817`. Already-covered (grep-confirmed, NOT re-added): OpenSMTPD
  6.6 RCE, Squid proxy pivot (`exploit/squid.py`), DNS PTR-sweep (`modules/dns/manual_commands.yaml`).
  Added the verified §21-safe gaps:
  - RECON: `services.yaml` port-3128 **Squid** entry (Squid HackTricks page + proxy-pivot/cache-mgr
    hints, beats the http-proxy fallback); `patterns/dns.yaml` **WPAD/PAC** discovery next-step.
  - ATTACK — the **MIT-Kerberos-on-Linux** chain (distinct from the AD/impacket Kerberos set): ad.py
    `kinit-tgt` (victim) + `krb5-conf-generate` (attacker); ssh.py `connect-gssapi-kerberos` (victim);
    linux.py new **"MIT Kerberos (keytab/.k5login)"** category — `krb-keytab-list` (klist -kte),
    `krb-keytab-kinit` (-kt), `krb-keytab-ktutil-dump`, `krb-keytab-kadmin-addprinc` (KDC takeover from
    a readable keytab), `krb-k5login-plant` (→ passwordless ksu/ssh), `krb-ksu-principal`.
  - Squid ref + WPAD suggestion verified to FIRE through the engines; catalog **3467→3476**.
- Session (2026-07-21) — **owner asked to re-check the ATTACK modules for EVERY box in the whole review
  series** (Phoenix/Spooktrol/EarlyAccess/Spider/Breadcrumbs/Cereal/Snoopy/Carpediem + earlier
  Base/Vaccine/Download/Active/Race/BigBang). Ran a **5-agent parallel audit**, each grep-verifying the
  3,455-action catalog. Most technique classes were ALREADY covered (grep-confirmed) — added the **12
  genuinely-missing GENERIC, §21-safe techniques** → `feat(exploit)` `7e05421`:
  - web.py: `uwsgi-ini-magic-exec-rce` (Flask/uWSGI @(exec://)), `sqli-header-second-order`,
    `dotnet-viewstate-machinekey-forge` (the generic leaked-machineKey ViewState forge — existing
    ViewState actions were all CVE/app-specific), `web-race-condition-parallel` (TOCTOU) — all victim.
  - windows.py `cred-hunt-stickynotes` (plum.sqlite, victim); ad.py `gpp-decrypt-cpassword` (offline
    GPP cpassword, attacker); adb.py `apk-decompile-apktool`+`apk-decompile-jadx` (attacker).
  - **NEW `exploit/qdpm.py`** per-CMS module (4 attacker curl actions: CHANGELOG version, databases.yml
    cred leak, authenticated attachment-upload webshell, trigger) + loader + fingerprint-presence entry.
  - Regression-locked in `test_recent_box_attack_techniques_present`; catalog **3455→3467 / 183 svcs**.
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
- Exploit catalog: **183 services / 3,187 actions** (verified from `base._REGISTRY`; top: ad 143 · web
  124 · linux 73 · windows 40 · shells 39). Pattern library: **52 YAML files**.
  CLI (`nabu-cli`) and GUI (`nabu`) are now at **feature parity** for automatable work (see the
  parity note above for the intentional GUI-primary panels).
- Full test suite green (**pytest EXIT=0**), all four gates clean.
- Author/maintainer: **Lagus · its.lagus@proton.me · github.com/7H35C4r3Cr0W/recon ·
  ☕ buymeacoffee.com/lagus** (single source of truth: `src/oscprecon/branding.py` — CLI banner +
  `--version`, GUI About dialog + status-footer watermark all read from it; pyproject `Funding` URL +
  README carry the coffee link too).

## The four gates — run before EVERY commit, pause for approval only if the user asked
```bash
uv run ruff check
uv run ruff format --check
uv run mypy --strict src/
QT_QPA_PLATFORM=offscreen uv run pytest -q      # slow on this VM (~20 min); run targeted tests first
```
The pytest suite is slow here — run the **targeted** test files for what you touched first, then a
full-suite backstop in the background (write a done-marker, poll it) before reporting.

## ⭐ WHAT THIS TOOL IS FOR (read this first — the owner had to correct me hard on it)
**Nabu is a recon/attack DECISION-AID + automated WORKFLOW for the pentester. It is NOT a CVE/exploit
database.** The value is helping the operator make good recon/enum/attack DECISIONS fast and run a
clean automated recon/enum workflow — NOT hoarding every CVE and PoC. **Do NOT dump box-specific CVE
exploits / novel one-off payloads into the attack modules — that's insanity and bloats the tool; each
CTF is different and those get hand-crafted per box anyway.** If you ever add a specific-CVE exploit
action, DELETE it. What the attack side SHOULD carry is GENERIC, reusable DECISION-AID technique
CLASSES (e.g. "you have PostgreSQL SQLi as superuser → here are the file-read / RCE paths"), not
"CVE-XXXX-YYYY PoC runner".

## ⚠⚠⚠⚠ EVERY LIVE BOX: FULL-GAMBIT SMOKE-TEST TO FIND TOOL BUGS + AUGMENT THE REUSABLE WORKFLOW
The point of running against a live box is to **find and fix BUGS in the recon/enum/attack GUI+CLI**
and confirm the tool actually AIDS the operator's decisions — not to harvest exploits. For every box:
- (a) Field-test the RELEVANT modules (recon+enum+attack — only services the box actually runs) against
  the live target; give a **PASS/FAIL per module**.
- (b) **Hunt tool bugs** and fix them — that's the payoff (the DarkCorp run found+fixed `{url}`
  double-slash, the `postgresql`/`postgres` exploit-key mismatch, and `enum` not covering http/ssh).
- (c) **Augment the REUSABLE recon/enum/decision-aid** — add generic improvements that help on FUTURE
  boxes (e.g. `enum` now runs the full recon modules; a generic PostgreSQL-SQLi decision-aid).
  **Do NOT add box-specific CVE payloads** — capture only the reusable class / recon-enum improvement /
  bug fix. (memory `live-box-always`, `tool-is-decision-aid-not-cve-db`.)
- **⚠⚠⚠ "TEST IT" = RECON **AND** ATTACK THE LIVE BOX, END-TO-END — NON-NEGOTIABLE (owner ANGRY, said 3×).**
  When the owner says test/hit a box, they mean actually WORK it on the real target through the WHOLE
  chain — recon AND the attack path (foothold → user → root): stand up a catcher on tun0, exploit,
  coerce/relay, dump, pivot, using Nabu's Exploitation tab + the underlying tools. That IS the goal of
  the tool. Recon-only / walkthrough-only is LAZY and makes the owner furious. HTB/CTF boxes the owner
  spins up are AUTHORIZED (owner = the human directing every action, §2b). If boxes are up, GO — go as
  far as the box allows. (memory `live-box-always`.)
- **⚠⚠ EVERY BOX = HIT THE LIVE BOX **AND** RUN THE WALKTHROUGH — NON-NEGOTIABLE (owner ANGRY, said twice).**
  A "box review" is NOT walkthrough-only. For EVERY box the owner gives with an IP: (1) **check the VPN
  tunnel** (`ip -brief addr show | grep tun`, route to `10.129.0.0/16`) and confirm the target is
  reachable, and **SAY the result**; (2) if up, **actually run Nabu against the live target**
  (`nabu-cli scan <ip> -p <profile>`, then validate recon features on real data — e.g. DarkCorp's
  meta-refresh→vhost; run `enum`, exploit templates, GUI) — dogfood the tool + find real bugs/UX; (3)
  read the walkthrough **in parallel** and build/fix the generic techniques. **If the OVPN/tunnel is
  DOWN or the box is unreachable, WARN THE OWNER IMMEDIATELY** ("tunnel's down, can't hit it live") —
  never silently fall back to walkthrough-only. (memory `live-box-always` — the owner keeps the VPN
  open specifically so the tool is validated live; skipping it twice made them furious.)
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
- **Commit trailers** (enforced by the harness): commits are authored by the git user (Lagus/Andre);
  the harness appends `Co-Authored-By: Claude ... <noreply@anthropic.com>` + a `Claude-Session:` line.

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
