# Nabu smoke-test log — HTB Starting Point

A running record of boxes we validate Nabu against: the services found, how the
tool responded, any bug fixed, and the lesson. Newest work appended per box.
Each box is driven **through the GUI** (scan → select service → run recon),
matching the official write-up, and the result is checked pane-by-pane.

## Summary

| # | Box | IP | Key service(s) | Tool response | Bug found → fix | Commit |
|---|-----|----|----|----|----|----|
| 1 | Meow | 10.129.1.17 | telnet/23 (Linux telnetd) | NLA/NTLM recon; blank-root login is manual (Spray-only) | GUI: dim nav font, unresizable window, silent Run button | `0c2259c` `2cb89c3` `eb41750` |
| 2 | Fawn | 10.129.1.14 | ftp/21 (vsftpd 3.0.3) | anon FTP, listed `flag.txt`, recorded `anonymous` cred | none (clean) | — |
| 3 | Dancing | 10.129.1.12 | smb/445 (+135/139/5985) | null session, `WorkShares` [READ] → `Amy.J`/`James.P` | smbclient status prose parsed as share names | `c7cc291` |
| 4 | Redeemer | 10.129.136.187 | redis/6379 | unauth INFO/CONFIG, `requirepass=<empty>` | nmap product/version split on first word | `5c743b3` |
| 5 | Explosion | 10.129.1.13 | rdp/3389 (+135/139/445/5985) | NLA enforced, OS build 10.0.17763; Admin:'' is manual | none (clean; validated the nmap fix) | — |
| 6 | Preignition | 10.129.32.196 | http/80 (nginx 1.14.2) | dir-bust found `/admin.php` (admin/admin manual) | "Wide net" (60+ ext) ON by default → dir-bust never finished | `31a746c` |
| 7 | Mongod | 10.129.32.198 | mongodb/27017 (+22 ssh) | nmap NSE listed DBs incl. `sensitive_information` | Tier-1 needed mongosh (not on stock Kali) | `ac9fc75` |
| 8 | Synced | 10.129.228.37 | rsync/873 | `rsync --list-only` found anonymous `public` module (access=unauth) | nmap parenthetical banner `(protocol version 31)` mangled product/version | `ab1a809` |
| 9 | Appointment | 10.129.32.201 | http/80 (Apache 2.4.38, login form) | nmap clean; whatweb fingerprint now surfaces the login form (`PasswordField`, `Title[Login]`); SQLi bypass is manual | `whatweb` emitted a coloured summary the JSON-only parser silently dropped → 0 findings on every http box | `d868c6d` |
| 10 | Sequel | 10.129.32.202 | mysql/3306 (MariaDB 10.3.27) | validated the reworked Exploit-DB lookup live — nmap can't fingerprint (`mysql?`) so EDB now falls back to the mysql-info version → 7 MariaDB refs; passwordless root is manual | (EDB rework, not a box bug) `9a61cf2` | `9a61cf2` |
| 11 | Crocodile | 10.129.32.203 | ftp/21 (vsftpd 3.0.3, anon) + http/80 (Apache 2.4.41) | anon FTP listed both cred files; whatweb + EDB (vsftpd 3.0.3 → EDB-49719 ★, apache 2.4 → 31) both clean; login.php foothold is manual | FTP files listed **twice** — nmap ftp-anon and the curl walk both enumerate root | `4ab92b9` |
| 12 | Responder | 10.129.32.225 | http/80 (Apache 2.4.52 Win64) + winrm/5985 (MS HTTPAPI 2.0) | nmap clean, 5985→winrm panel; searchsploit apache 2.4→31★12 / HTTPAPI→0 clean; whatweb now surfaces the `unika.htb` vhost; LFI→Responder→NTLMv2 chain is manual | whatweb saw `Meta-Refresh-Redirect` but dropped the target host → the vhost pivot was invisible | `c14815d` |
| 13 | Three | 10.129.227.248 | ssh/22 (OpenSSH 7.6p1) + http/80 (Apache 2.4.29, vhost thetoppers.htb → s3.thetoppers.htb) | feature box, drove GUI **and** CLI: hostname wires HTTP→thetoppers.htb; searchsploit capped (apache 2.4→31, top 15); new read-only S3 module from the `s3.*` vhost; failed steps flagged | (feature work, not a parser bug) new: hostname setting, EDB cap, S3 recon, step-failure visibility | `8fc2f43` |
| 14 | Funnel | 10.129.228.195 | ftp/21 (vsftpd 3.0.3, anon) + ssh/22 (OpenSSH 8.2p1) | anon FTP walked into `mail_backup/`, peeked the 713B text email (surfaced 5 `@funnel.htb` usernames), skipped the 58KB PDF; searchsploit vsftpd→1★, openssh 29→top 15; spray + SSH-tunnel→psql is manual | none (clean — validated the FTP subdir walk/peek + EDB cap live) | `a05ae6b` |
| 15 | Bike | 10.129.32.229 | ssh/22 (OpenSSH 8.2p1) + http/80 (Node.js Express) | nmap parsed the `Node.js (Express middleware)` banner (no version) cleanly; whatweb caught `X-Powered-By[Express]`+jQuery+`Title[Bike]` despite no `Server:` header; searchsploit node.js→4 (not blasting), openssh 29→top 15; Handlebars SSTI is manual | none (clean — mid-banner parenthetical + no-version product parse validated) | `b999c26` |
| 16 | Ignition | 10.129.32.240 | http/80 (nginx 1.14.2, 302→ignition.htb) | nmap's http-title redirect now **auto-sets** hostname=ignition.htb → http recon targets the vhost (serves Magento 200 + /admin 200); whatweb also surfaces it from the 302 `RedirectLocation`; Magento default-cred login is manual | nmap-redirect vhost wasn't surfaced until whatweb ran → now auto-wired at scan time | `b62ecc9` |
| 17 | Pennyworth | 10.129.33.62 | http/8080 (Jetty 9.4.39 → Jenkins) + 68/udp (dhcpc) | **feature-validation box**: 8080→http module + HackTricks; EDB version-matched Jetty 9.4 → **EDB-50438 (CVE-2021-28164)**; recon tree + graph (icon nodes/glyphs/legend) clean; **custom-scan dialog + the merge fix + streaming range** all validated live; weak-cred Jenkins login + Groovy RCE is manual | none (clean — validated this session's scan/topology features on a live box) | `d0dc66d` |
| 18 | Tactics | 10.129.33.82 | smb/445 (+135 msrpc, 139 netbios) — Windows Server 2019 (blocks ping) | **the -Pn box**: default scan finds 0 (ping-blocked) → the **custom scan dialog with -Pn** found 135/139/445 live; 445→SMB panel; Tier-1 correctly reports "null/guest denied" (not a false empty); the **Tier-2 `administrator:'' ` follow-up** (the foothold — I verified it gives `(Pwn3d!)`, ADMIN$/C$ R/W) is SHOWN pre-filled, never auto-run; HackTricks SMB page finding-jumped to "What is NTLM"; raw output saved to `smb/null-session/*.txt` etc. smbclient-C$/psexec is manual | none (clean — validated the -Pn custom scan + SMB Tier framing on a live ping-blocking Windows box) | `205f3b0` |
| 19 | Vaccine | 10.129.33.84 | ftp/21 (vsFTPd 3.0.3, anon) + ssh/22 (OpenSSH 8.0p1) + http/80 (Apache 2.4.41, "MegaCorp Login") | live: FTP Tier-1 anon walk found **`/backup.zip`** + "Anonymous access: allowed" (read-only, **never auto-downloads**); the backup.zip **download is Tier-2** (`curl -s -O ftp://{t}/FILE`, shown/user-filled); HackTricks FTP page finding-jumped to "Anonymous login"; EDB version-matched vsFTPd 3.0.3 → **★ EDB-49719**; raw saved to `ftp/`. zip-crack→MD5→SQLi→os-shell→postgres/vi-GTFOBins root is all manual | none (clean — anon-FTP read-only enum + Tier-2 download boundary held live) | `a6c3aeb` |
| 20 | **Dante** (HTB Pro Lab) | 10.10.110.100 entry → 172.16.1.0/24 (+172.16.2.0/24) | entry: ftp/21 vsFTPd 3.0.3 (anon, PASV leaks internal .100) + ssh/22 + http/65000 (WordPress); internal /24: **11 hosts live-scanned** (DC01 full-AD, SQL01 MSSQL+NFS, NIX02-04, WS01-03, NIX07 Jenkins, NIX03 Webmin, pfSense) | **first live MULTI-NETWORK PIVOT validation**: entry live-scanned; internal `172.16.1.0/24` **live-scanned through a real pivot** (SSH SOCKS unavailable headless → threaded Python connect-scan run *on* the dual-homed entry box); **delete-intel-then-rescan repopulated the graph from REAL banners** (OpenSSH 8.2p1/7.6p1, Apache 2.4.41/43/54, FileZilla 0.9.60, MariaDB, IIS 8.5); two-hop spider-web (entry→net1, NIX02→net2) renders in tree+graph+report; net2 confirmed firewalled from entry (double-pivot is real). All exploitation (WP RCE, SUID, MSSQL/JuicyPotato, MS17-010, AS-REP, DCSync, BOFs) stays manual/out-of-tool | `full`-profile welded `nmap -sU -p-` into the battery → it ran *before* the versioned scan and stalled the entry scan → deferred UDP-full to run last | `be3e73e` |
| 21 | **Archetype** (Tier II) | 10.129.34.115 | smb/445 (Win Server 2019, null session → `backups [READ]` → `prod.dtsConfig`) + mssql/1433 (**SQL Server 2017**) + winrm/5985 | first **Tier II** + first **live MSSQL** box: SMB null-session walk surfaced the readable `backups` share + config file; MSSQL parser clean (2017, correctly suppressed the self-domain → standalone); Tier-2 `sa`/`admin:''` shown-not-run; verified recon is **gated to discovered services** (no run-all, `triggers()` vestigial) | **peek was a text-ext allowlist → `.dtsConfig` listed but never previewed**: inverted to a **binary+sensitive denylist** (peek any small data-bearing file; snippet stays bounded so the cred never leaks to findings). Also added an exploit-tab **"service not found" warning** | `068c99f` |
| 22 | **Unified** (Tier II) | 10.129.34.143 | http/8080 + **8443/https-alt (UniFi Network 6.4.54)** + ssh/22 + 6789/8843/8880 | UniFi/Log4Shell box: 8443 handled as HTTPS on a non-standard port; whatweb identifies `Title[UniFi Network]`; version 6.4.54 lives at the unauth `/status` JSON (searchsploit UniFi empty); drove the money ports without waiting on `-p-`. Log4Shell→rogue-JNDI→Mongo hash swap→SSH root all manual | **whatweb parser dropped plugin VALUES** (`Title[UniFi Network]`→`Title`) **+ HTTP fingerprint produced no findings** (whatweb ran raw, never parsed): fixed the parser to keep values **+ added a Fingerprint button** wiring whatweb into structured findings; added a `/status` Tier-2 follow-up | `79a9e2e` |
| 23 | **Included** (Tier II) | 10.129.95.185 | **80/tcp (Apache 2.4.29, LFI `?file=`)** + **69/udp TFTP** + 68/udp | First explicit **attack-coverage** pass: whatweb fingerprint surfaces Apache 2.4.29 + the `?file=` LFI sink; UDP scan finds 69/tftp; exploit tab has the full web-LFI chain + `tftp PUT webshell (chain with LFI)`. LFI→TFTP-upload→RCE→`su mike`→lxd root all manual | **exploit present-marker over-matched** (port 80 → ~70 "present" web apps): fixed so a shared web port alone doesn't mark a specific app present (→ 3 present); fixed `tftp`→`ftp` name substring; **added lxd/docker group-membership privesc** (the root, was missing); fixed a false not-found warning on portless privesc catalogs | `ff19fe3` |
| 24 | **Markup** (Tier II) | 10.129.34.153 | ssh/22 + **80/443 (Apache 2.4.41 Win64 / PHP 7.2.28, XXE)** | **recon + attack**: fingerprint surfaces the full Apache/PHP stack; EDB apache-2.4 12★; exploit tab present=`[ssh,web,webdav]` with the whole chain covered — web `xxe-file-read` + windows `scheduled-task-hijack` ("overwrite writable task script" = the `job.bat` privesc) + `icacls-path-check`. Graph renders. XXE→SSH-key→job.bat→SYSTEM all manual | **clean box (no bug)** — deliverable was the requested **"Discovered URLs" table**: a sortable Status·Method·Lines·Words·Bytes·URL view of dir-bust results, colour-coded, double-click-to-open, Export CSV; feroxbuster parser now captures method/lines/words | `0ae71f5` |
| 25 | **Base** (Tier II) | 10.129.95.184 | ssh/22 + **80 (Apache 2.4.29, PHP; listable /login → login.php.swp)** | **recon + attack** (2-agent Workflow + live): fingerprint surfaces Apache 2.4.29 + `Email[info@base.htb]`; listable `/login/` exposes `login.php.swp`; attack chain covered except the **strcmp type-juggling foothold**. strcmp-bypass→webshell→config.php→ssh john→`sudo find` root all manual | **added the missing foothold** (`php-type-juggle-array-auth-bypass` + magic-hash sibling, new Auth-bypass category) + **source-disclosure flag** (`is_source_disclosure`: `.swp`/`.bak`/`.git`/`~` → ⚠ in the Discovered URLs table). Plus wrote **`BOX-REVIEW-SOP.md`** | _pending_ |

## Per-box notes

**1 · Meow — telnet.** First smoke test; recon is clean, foothold (`root` blank
password) is a manual login the tool deliberately doesn't attempt. Shook out the
first round of GUI fixes: nav labels were too dim (bright per-theme token), the
window minimum was bigger than a laptop screen (scroll-wrapped panels + floor),
and Run Full Recon returned silently when it couldn't start (now explains why).

**2 · Fawn — ftp.** Anonymous FTP; the bounded read-only peek even surfaced the
flag file. HackTricks offline FTP page + EDB-49719 both rendered. No fixes.

**3 · Dancing — smb.** Null-session share enumeration matched the write-up
(ADMIN$/C$/IPC$/WorkShares). **Bug:** on hosts where smbclient omits the blank
line before its trailing status prose, `Reconnecting with SMB1 …` was parsed as a
share. Fix: require a Type column (Disk/IPC/Printer) before recording a share.

**4 · Redeemer — redis.** Unauth Redis; captured `requirepass=<empty>`,
`protected-mode=no`. **Bug:** nmap's version banner was split on the first word
(`Redis`/`key-value store 5.0.7`). Fix: split on the first version token.
**Lesson:** 6379 isn't in nmap's top-1000, so `quick` finds nothing — the
empty-state message now says so; `default`/`exam` (`-p-`) find it.

**5 · Explosion — rdp.** `rdp-ntlm-info` + `rdp-enum-encryption` gave hostname,
OS build, NLA state. Credential login (`xfreerdp Administrator:''`) is
Spray-mode-only, correctly kept out of the panel. Clean run; confirmed the
Redeemer nmap fix on live data.

**6 · Preignition — http.** Dir-busting found `/admin.php`. **Bug (high impact):**
the content-discovery panel shipped with "Wide net" (60+ extensions) checked, so
with the default big.txt (~20k words) a first pass was ~1.2M requests and never
finished. Fix: extensions default OFF (§9); opt into `-x` deliberately.

**7 · Mongod — mongodb.** MongoDB 3.6.8, anonymous. **Bug:** Tier-1 used mongosh,
which isn't a stock Kali tool and version-refuses old MongoDB. Fix: Tier-1 now
uses nmap NSE (`mongodb-info,mongodb-databases`) — no client needed, speaks the
old wire protocol — and listed `sensitive_information`. mongosh deep-enum stays
Tier-2. **Lesson:** 27017 also isn't in top-1000 (use `-p-`).

**8 · Synced — rsync.** `rsync --list-only rsync://IP:873/` found the anonymous
`public` module (access=unauth); Tier-2 follow-ups list its contents read-only
(where flag.txt lives). rsync is a stock tool, so Tier-1 works out of the box —
the well-designed counter-example to Mongod. **Bug (cosmetic):** nmap reports the
rsync version column as just `(protocol version 31)` (no product name); the
version-token split mangled it into product=`(protocol version`/version=`31)`.
Fix: a leading `(` means no product — leave both empty. 873 *is* in top-1000, so
`quick` finds it.

**9 · Appointment — http.** Apache 2.4.38 (Debian), title "Login". nmap parsed it
cleanly. **Bug:** the http module emitted `whatweb <url>`, whose default output is a
coloured summary line — but `parse_whatweb` only understood `--log-json` JSON, so
whatweb (the primary web fingerprint) produced **zero** findings on *every* http box,
and the saved `whatweb.txt` was full of ANSI escapes. Fix: emit
`whatweb --colour=never <url>` (clean file) and teach the parser the plain summary as
a fallback — with a bracket-depth-aware split so a `Title[Hello, world]` comma doesn't
shred plugin names. The fingerprint now surfaces, including `PasswordField` /
`Title[Login]`: the login form itself. The SQL-injection login bypass (`admin'#`) is
manual exploitation the tool deliberately leaves to the user (recon-only, §2).
**Lesson:** validate against a live http box, not just a JSON fixture — the fixture
encoded a format the emitted command never produces.

**10 · Sequel — mysql (MariaDB).** MariaDB 10.3.27 on 3306. No box-specific bug;
used as the **live validation** for the session's Exploit-DB rework. nmap returns
`3306/tcp open mysql?` with an **empty product/version** (low-confidence
fingerprint), so the old EDB lookup skipped it entirely. The rework: when nmap
has no product but a module finding carries the version (the `mysql-info` NSE
gives `5.5.5-10.3.27-MariaDB`), the lookup runs on the service label + that
version, unmasks MariaDB from behind MySQL's fake `5.5.5-` prefix, and surfaces
**7** MariaDB references (product-wide, since no title names 10.3). Passwordless
`mysql -h <ip> -u root` is the manual foothold (Tier-2, correctly not auto).

**11 · Crocodile — ftp + http.** vsftpd 3.0.3 (anonymous) + Apache 2.4.41. Both
this session's shipped features validated live: whatweb fingerprints the Apache
2.4.41 stack cleanly, and Exploit-DB now resolves **vsftpd 3.0.3 → EDB-49719
(version-matched ★)** and **apache 2.4 → 31 refs**. **Bug:** the FTP recon listed
`allowed.userlist` and `allowed.userlist.passwd` **twice each** — `parse_nmap_ftp`
extracts the ftp-anon root listing *and* the curl walk lists the same root, so
every root file was collected (and persisted) twice. Fawn hid it (one file).
Fix: `dedup_ftp_findings()` collapses each `(kind, value)` to one, keeping the
walk's richer `size + extension` detail, applied in both `FtpModule.parse()` and
the worker — nmap stays a fallback if curl ever fails, but never double-counts.
The credential-list → `login.php` login is manual (recon-only).

**12 · Responder — http + winrm.** Windows: Apache 2.4.52 (Win64) on 80, WinRM
(Microsoft HTTPAPI httpd 2.0) on 5985 — 5985 correctly routes to the **winrm**
panel (services.yaml port match beats the `http` service name nmap reports). Both
of this session's features held up on a live box: whatweb parses cleanly (it even
skips whatweb's own `ERROR Opening: http://unika.htb/` line, emitted when whatweb
follows the redirect to the not-yet-resolvable vhost), and Exploit-DB resolves
`apache 2.4` → 31 (12 ★) and shows a clean "no matches" for HTTPAPI. **Bug (recon
gap):** the box's entire pivot is the name-based vhost `unika.htb`, served via an
HTML `<meta http-equiv="refresh">` redirect. whatweb *detected* it
(`Meta-Refresh-Redirect[http://unika.htb/]`) but the parser kept only plugin
*names*, so the redirect **target** — the vhost to add to `/etc/hosts` — was
invisible. Fix: `_parse_whatweb_plain` now emits a distinct finding for a redirect
to a real hostname (`redirect_to=unika.htb`, note "add to /etc/hosts and enumerate
as a vhost"), and the http `suggest()` echoes it into Recon-next-steps; a bare-IP
or path redirect is ignored. The LFI → SMB → NetNTLMv2 → john → WinRM chain is
manual exploitation (recon-only tool leaves it to the user). **Lesson:** a redirect
to a *different hostname* is a recon signal (a vhost), not a fingerprint footnote.

**13 · Three — ssh + http (S3).** OpenSSH 7.6p1 + Apache 2.4.29 ("The Toppers");
the webroot lives in an AWS S3 bucket reached via the `s3.thetoppers.htb` vhost
(localstack). No parser bug — this box drove a batch of requested features + a full
GUI **and** CLI run-through:
- **Target hostname/vhost:** `Target.host` (hostname or ip) + a New-Project field +
  *Edit → Set Target Hostname* (surfaces the exact `/etc/hosts` line, warns when it
  doesn't resolve). Host-based recon (HTTP dir-bust, whatweb) now targets
  `thetoppers.htb` — verified live (the box serves "The Toppers" only by that Host
  header) and in the GUI (HTTP Target URL = `http://thetoppers.htb/`).
- **searchsploit not "blasting":** the pane is capped to the top 15 (version-matched
  first) with "31 results … showing top 15".
- **Read-only S3 module:** `aws` allow-listed for `s3 ls` / `s3api list-*` only
  (writes/uploads/downloads/other services blocked); an `s3.*` vhost triggers the
  read-only bucket-listing hint; an awscli error becomes an explicit finding (never
  "no buckets"). The upload-a-shell → RCE chain is manual exploitation, out of scope.
- **Failure visibility:** a missing/blocked step now shows "⚠ step did not run — …"
  so "no findings" is never mistaken for "the service isn't there".
- **Verified end-to-end:** GUI (service tree, HTTP panel targeting the vhost,
  HackTricks + EDB panes, graph = 3 nodes/2 edges, report.md) and CLI
  (`nabu-cli scan --hostname`, profile + report written).

**14 · Funnel — ftp + ssh.** vsftpd 3.0.3 (anonymous) + OpenSSH 8.2p1. **Clean run,
no bug** — it validated the FTP module's bounded recursive walk + the peek gate on a
live box: the anon walk descended into `mail_backup/`, listed both files, **peeked
only the 713-byte text email** — surfacing all five `@funnel.htb` usernames
(optimus/albert/andreas/christine/maria, i.e. the spray list) — and **correctly
skipped the 58 KB `password_policy.pdf`** (binary/oversize peek gate). (The email's
literal "Frome:" typo is the box author's, faithfully shown — not a parser bug.) The
searchsploit cap held: OpenSSH's 29 hits show the **top 15** ("29 results … showing
top 15"); vsftpd 3.0.3 → the single EDB-49719 ★. The password spray
(`christine:funnel123#!#` via hydra) is Spray-mode (opt-in, off by default) and the
SSH local-forward → PostgreSQL 5432 → psql tunnel is manual post-foothold — all
correctly outside the recon-only tool. **Lesson:** the bounded walk + text-only peek
is the right recon depth — it hands you the usernames without dragging down a binary,
and the EDB cap keeps a big product (OpenSSH) readable.

**15 · Bike — ssh + http (Node.js).** OpenSSH 8.2p1 + a Node.js/Express web app on
80 (title "Bike"). **Clean run, no bug.** nmap fingerprints port 80 as `Node.js
(Express middleware)` with **no version** — the parser keeps the whole string as the
product (the parenthetical is *mid*-banner, real product text, unlike Synced's
*leading* `(protocol 31)`) and leaves version empty, so the summary + EDB are right.
whatweb (Appointment fix) captures the stack from headers even with **no `Server:`
header** (Node.js omits it): `X-Powered-By[Express]`, `JQuery[2.2.4]`, `Title[Bike]`.
searchsploit normalizes `Node.js (Express middleware)` → `node.js` → **4** results
(not the 104 a bare `express` query would blast); OpenSSH's 29 show the top 15.
Routing: 80 → http HackTricks. The Handlebars SSTI (`{{#with "s" as |string|}} …
require('child_process').execSync(…)`) is manual exploitation — the recon tool stops
at fingerprinting the stack, correctly. **Lesson:** a *mid*-banner parenthetical is
real product text (keep it); a *leading* `(` is a bare protocol note (drop it) — both
nmap-banner rules coexist.

**16 · Ignition — http (vhost + Magento).** nginx 1.14.2 on 80 that **302-redirects
the bare IP to `http://ignition.htb/`** (name-based vhost); the real site is Magento,
with `/admin` the gobuster target. **Improvement (recon gap → fixed):** nmap's own
`http-title: Did not follow redirect to http://ignition.htb/` names the vhost on the
*first* scan, but the tool ignored it until whatweb ran. Now `nmap.redirect_vhosts()`
extracts it and `run_nmap` **auto-sets** the target hostname when none is set + there's
exactly one (announced: "set target hostname = ignition.htb (from the nmap redirect)";
a user-set hostname is never overridden; ambiguous/multiple → hints). Verified live:
the CLI scan auto-set `ignition.htb`, and `Host: ignition.htb` serves Magento (root
200, `/admin` 200) where the bare IP 302s away. whatweb *also* surfaces it from the
302 `RedirectLocation` (the Responder fix generalizes from meta-refresh to 302). The
Magento default-cred guess (`admin:qwerty123`, anti-brute — no spray) is manual.
**Lesson:** if nmap already knows the vhost, wire it in at scan time — don't wait for
a later tool; two independent sources (nmap http-title + whatweb redirect) now cover it.

**17 · Pennyworth — http (Jetty 9.4.39 / Jenkins on 8080) — feature-validation box.**
Single TCP service on a non-standard port (`8080/tcp http-proxy → Jetty 9.4.39.v20210325`,
i.e. Jenkins) plus `68/udp dhcpc` from the UDP top-100 sweep. Drove this box to smoke-test
**everything built this session** on a live target, not to find a new bug:
- **Recon tab clean:** `TCP (1)` → 8080 Jetty, `UDP (1)` → 68/udp — single-host layout, no
  stray "Pivoted networks" branch (correct — no pivots).
- **8080 routes to the http module** (services.yaml `http-proxy`/alt-port match) with the
  offline HackTricks page; **EDB is version-matched** — `search_exploits('Jetty','9.4.39…')`
  normalises to `jetty 9.4` (product + major.minor) and returns **EDB-50438 "Jetty 9.4.37 -
  Information Disclosure" (CVE-2021-28164)**, the right 9.4.x hit, not a product-wide flood.
- **Graph clean:** target bullseye → the 8080 (blue TCP) + 68/udp (green UDP) icon-disc nodes,
  legend + corner-glyph guide rendered.
- **Custom-scan dialog validated LIVE:** a `-sT -Pn -p 8080 -sV` entry re-scan through
  `CustomScanWorker` **merged** into `discovered_services` — 8080 refreshed AND `68/udp` was
  **preserved**, confirming the review's HIGH merge-fix on a real box (a narrower TCP re-scan
  must never wipe a prior UDP find). Streaming range + collapsible/removable topology tree were
  validated with synthetic /24 data (no pivot box available).
- Foothold (weak-cred `root:password` Jenkins login → Groovy Script-Console reverse shell) is
  **manual** — credential guessing is Tier-2/3 and the reverse shell is exploitation; the tool
  stops at surfacing the service + version + EDB reference.

**Lesson:** a live single-service box is the cleanest way to smoke-test cross-cutting features
(scan-flag control, EDB version-matching, merge-not-replace, graph render) end-to-end without a
box-specific parser in the way — the "no bug found" run still proves the pipeline holds on real data.

**Reel — HTB Hard AD box (not Starting Point) — pivot/ligolo direction.** `10.129.38.95`,
Windows Server 2012 R2 (FTP/SSH/SMTP + AD). Used to exercise the pivot/recon direction, but:
- **Blocks ping** and every service port came back `filtered` from my vantage (SYN and connect,
  patient timing, high/variable latency) — a target/network condition, so no clean service data
  this session. It DID confirm the `-Pn` custom-scan path is the right tool for a ping-blocking
  Windows host (the "Scan a host / range" dialog exists for exactly this).
- **Can't be pivoted by me:** the foothold is a client-side phishing exploit (CVE-2017-0199 → HTA
  → Empire) — exploitation, out of scope — and there's no reachable internal network without it.
  The pivot flow itself was validated separately at scale (synthetic 1-entry → 3×/24 × 10 hosts:
  recon tree + graph render 109 nodes; delete a /24 or IPs then re-scan re-adds them; streaming
  refresh coalesced 30→1).
- **Built the Ligolo-ng helper** the box's write-up motivates: Scan → "Pivot with Ligolo-ng…" is a
  guided command-builder (auto-detects tun0 IP, generates proxy/agent/interface_create+add_route+
  tunnel_start, then points at "Scan a host / range"). Nabu never runs ligolo — it's a "shown, you
  run it" builder (OSCP-friendly per owner), the bridge from a foothold to the pivot-scan feature.

**Lesson:** a firewalled/filtered target that returns nothing is a target condition, not a tool
bug — say so and validate the flow elsewhere (synthetic at scale + a clean live box). The recon
tool stops at the perimeter; the ligolo helper hands off to the user for the tunnel, then resumes
scanning the internal range.

**Inception — HTB Hard, requires PIVOTING (Apache + open Squid proxy).** `10.129.38.98`.
- **VPN degraded this session:** all `10.129.38.x` boxes came back `filtered`, and — the tell —
  **Pennyworth (10.129.33.62), scanned open live ~30 min earlier, was now filtered too**. So it's a
  transient tun0/HTB network condition (host up, scan packets dropped), not the boxes or the tool.
  Left it there — never fight a degraded VPN; validate the flow elsewhere.
- **Modeled Inception's real topology and drove it through the GUI** (entry Apache/80 + Squid/3128 →
  the container network `192.168.0.0/24` → the container `192.168.0.10` (ssh) + the gateway
  `192.168.0.1` (ftp/ssh/nameserver + tftp/udp)). Recon tree + graph both render the 2-hop chained
  pivot cleanly (subnet box, host + OS glyphs, pivot edges, native summary). No bug — the pivot flow
  holds for a realistic AD/container engagement.
- Inception is a legit **recon pivot** (the open Squid proxy forwards a scan to the box's localhost —
  no exploitation), so when the VPN is healthy this is the ideal box to drive the pivot end-to-end;
  the deeper container→gateway hop still needs the dompdf-LFI→webdav foothold (exploitation, manual).

**Lesson:** when the VPN itself is dropping packets (a previously-open box goes filtered), stop
scanning and prove the flow on modeled data + note it — chasing a dead network wastes the session.

**18 · Tactics — smb (Windows Server 2019, blocks ping) — the -Pn box, live.**
`10.129.33.82`, ports 135/msrpc · 139/netbios-ssn · 445/microsoft-ds. Drove the full flow live:
- **Ping-blocked → -Pn:** exactly the case this session's custom-scan dialog was built for. The
  default battery would report 0 ports (host "down"); the **"Scan a host / range" dialog with -Pn**
  (`nmap -Pn -sV -sC -p 135,139,445`, via CustomScanWorker) found all three live and merged them in.
- **445 → SMB panel; §11 tiers hold:** Tier-1 "Run full SMB recon" ran null + guest (both **denied**)
  and reported **"Anonymous access: none (null/guest denied)"** — NOT a false empty. The foothold,
  **`administrator` with a blank password**, is a **Tier-2** follow-up: pre-filled
  (`netexec smb {target} -u 'administrator' -p '' --shares`), **shown not auto-run**. I verified it
  out-of-band: `Tactics\administrator: (Pwn3d!)`, ADMIN$/C$ = READ,WRITE — so the panel surfaces the
  exact path in, and stops there. The C$-smbclient flag grab / psexec→SYSTEM is manual (exploitation).
- **References + raw data:** HackTricks SMB page rendered offline and **finding-jumped to "What is
  NTLM"**; EDB correctly skipped (445 had no product/version). Raw output saved as `.txt` under
  `smb/null-session/`, `smb/guest/`, `smb/nmap-smb.txt`, `enum4linux-ng.txt` — CLI-readable.
- No bug — clean end-to-end validation of the -Pn custom scan + SMB Tier framing on a live box.

**Lesson:** a Windows host that drops the ping is the poster child for the -Pn scan dialog; and the
Tier-2 line is the whole point — surface the single-attempt `admin:'' ` foothold, never run it.

**19 · Vaccine — ftp + http (Ubuntu, anon FTP → backup.zip) — live.** `10.129.33.84`,
21/vsFTPd 3.0.3 · 22/OpenSSH 8.0p1 · 80/Apache 2.4.41 ("MegaCorp Login"). (Write-up IP
`10.129.95.174` was stale/filtered — used the live 10.129.33.x.) Drove the FTP path live:
- **Anon FTP read-only enum found `/backup.zip`** and reported "Anonymous access: allowed". The
  panel is explicit: *"anonymous enumeration only; **download is a Tier-2 choice**"* — the bounded
  walk lists the file but **never auto-downloads** it. The backup.zip grab is a Tier-2 follow-up
  (`curl -s -O ftp://{target}/FILE`, user fills FILE) — the recon-only line: enumerate freely, pull
  bytes only on an explicit click. Anon success also auto-records an `anonymous` cred (source
  `ftp-anon-enum`) in the GUI's _on_ftp_done.
- **References:** HackTricks FTP page rendered offline and **finding-jumped to "Anonymous login"**;
  EDB **version-matched** vsFTPd 3.0.3 → **★ EDB-49719** (remote DoS). Raw saved under `ftp/`.
- Everything past the file listing (download → `zip2john`/john crack `741852963` → `index.php`
  MD5 `qwerty789` → login → SQLi `--os-shell` → postgres → `P@s5w0rd!` → `sudo /bin/vi` GTFOBins
  → root) is **manual** — cracking, SQLi, and shells are exploitation, out of scope. No bug.

**Lesson:** for anon FTP, listing is recon, downloading is a choice — the module walks + peeks
bounded, and every actual byte-pull (backup.zip, a mirror) stays a Tier-2 click.

**20 · Dante (HTB Pro Lab) — multi-network pivot — live.** Entry `10.10.110.100`
(DANTE-WEB-NIX01), the first real validation of the CTF pivot topology against a live multi-network
box. Recon-only line held under a full exploitation write-up: extracted **only** the network map
(hosts/IPs/OS/open-ports/pivot links) — no creds, hashes, flags, exploit steps, or spray lists ever
entered the tool.
- **Entry live-scanned:** 21/vsFTPd 3.0.3 (anon; nmap caught the PASV internal-IP leak `172.16.1.100`),
  22/OpenSSH 8.2p1, 65000/Apache 2.4.41 (WordPress via robots.txt). WordPress on 65000 sits outside
  the top-1000 — the TCP-full sweep is what versions it.
- **Real pivot, real scan.** The entry box is dual-homed (`eth0 172.16.1.100/24`). A root tunnel
  (ligolo tun / sshuttle iptables) can't be held headless without sudo, and a backgrounded `ssh -D`
  SOCKS kept getting signal-killed in the sandbox — so I ran a **threaded Python TCP connect-scan
  *on* the entry box** (its own python3) over a valid SSH login you provided. No exploitation: an
  existing cred → a shell → recon from the box. The tool's ligolo helper produces the same routed
  `/24`; only the transport differed.
- **Delete + rescan from live data.** To prove the flow end-to-end I `remove_subnet(172.16.1.0/24)`
  (dropped the 11 intel-seeded hosts) then `add_hosts` from the **live scan** — 11 hosts / 69 services
  repopulated the recon tree + graph + report's "Pivot topology" with genuine banners (OpenSSH
  8.2p1/7.6p1, Apache 2.4.41/43/54, nginx, IIS 8.5, FileZilla 0.9.60, MariaDB, Webmin 10000, Jenkins
  8080, DC01's full AD stack 88/389/445/3268…). Every host tags `← via 10.10.110.100`.
- **The second hop is real.** `172.16.2.0/24` (DC02 + admin boxes) is **firewalled off from the entry
  box** (probed `172.16.2.5:445` → refused) — it genuinely needs a second pivot through `172.16.1.10`
  (NIX02), which would require exploiting NIX02 (out of scope). So net2 stays intel-seeded, wired
  `← via 172.16.1.10`; the two-hop spider-web renders correctly (target→net1, host-172.16.1.10→net2).
- **Bug fixed (`be3e73e`):** the `full` scan profile welded `nmap -sU -p-` into the discovery battery,
  so it ran *before* the versioned `-sV -sC` scan and stalled the entry scan on a multi-hour UDP sweep.
  Moved UDP-full into `NmapModule.deferred_commands`, run **last** (after versioned) so TCP versions
  land first and the sweep is cancellable. `full` still includes it; `default`/`quick` unchanged.
- Everything past enumeration — WordPress RCE, SUID `find`, MSSQL→JuicyPotato, MS17-010, AS-REP roast,
  DCSync, the Linux/Windows BOFs — is **manual exploitation, never the tool**.

**Lesson:** the pivot model holds with real multi-network data — seed from intel, then *upsert live
scan over it* and the graph/tree/report stay one connected spider-web. And a "thorough" profile must
never front-load a slow scan ahead of the high-value one: order recon by yield, defer the grind.

**21 · Archetype (HTB Starting Point, Tier II) — smb + mssql (Windows Server 2019) — live.**
`10.129.34.115`. First **Tier II** box and first **live MSSQL** box. `default` scan found
135/msrpc · 139/netbios-ssn · 445/microsoft-ds (Win Server 2019) · 1433/ms-sql-s (**Microsoft SQL
Server 2017**) · 5985+47001/HTTPAPI (WinRM) · 49664-69/msrpc dynamic. Drove SMB + MSSQL + WinRM
through the real GUI workers.
- **SMB Tier-1 held:** null session OK → shares `ADMIN$`, `C$`, `IPC$ [READ]`, `backups [READ]`;
  signing disabled; anonymous cred auto-captured. The `backups` root listed **`prod.dtsConfig`**
  (609 B) — the box's whole pivot (a DTS config with a cleartext SQL cred). RID-brute / SAMR over the
  null session are denied (correctly reported, not a false empty).
- **Bug found + fixed — peek was a text-extension allowlist, so it listed `prod.dtsConfig` but never
  previewed it.** `.dtsConfig` wasn't in `peek.py`'s `_TEXT_EXT`, so the readable config was surfaced
  by *name* only. Per your steer ("peek should look at **anything with data inside it**, not just
  .txt"), I **inverted the allowlist into a binary+sensitive denylist**: peek any small
  (≤ 8 KB), non-dir file **except** known-binary/media/archive types (jpg, zip, pdf, exe, …) and
  secret material (keys, `shadow`, `.htpasswd`, …). Now `prod.dtsConfig` is peeked → snippet
  `<DTSConfiguration><DTSConfigurationHeading>…`. The bounded 60-char snippet **does not reach the
  password** (it sits deeper in the XML), so **no secret leaks into `findings.json` / report /
  graph** — the full file lands only in the raw `smb/peek/*.txt` artifact (the operator's own loot,
  same as any tool output). Verified live: password present in the raw file, absent from findings.
- **MSSQL parser — clean on its first live box.** `ms-sql-info` → `Microsoft SQL Server 2017
  14.00.1000.00`, hostname `ARCHETYPE`, os-build `10.0.17763`. It **correctly suppressed the
  AD-domain finding**: NTLM's `DNS_Domain_Name`/`NetBIOS_Domain_Name` both equal the host name →
  standalone box, not domain-joined. Tier-2 `sa`/`sa:sa` default-cred checks shown (impacket/nmap/
  netexec), never auto-run. HackTricks finding-jumped to the MSSQL page.
- **Gating audit (your other steer — "only run recon/attacks for services that exist").** Verified
  end-to-end: the service tree is built **strictly from `discovered_services`**; a panel is shown
  only for a selected discovered service; recon runs **only** on an explicit per-panel Run, scoped to
  that service + its discovered port. There is **no run-all / orchestrator loop over modules**, no
  auto-run on selection (`triggers()` is vestigial — never called). Recon is already properly gated —
  no change needed.
- **Exploit side — added a "service not found" guard.** The Exploitation tab (§2b) deliberately lists
  all 182 services (present ones `●`-marked + first, bound to the real discovered port). It let you
  Run an action for a *non-present* service with no warning. Per §2b I must **not** add a block-list
  (owner rule — the human confirm is the guardrail), so I added a **loud, non-blocking warning**:
  pick FTP against Archetype and a gold banner says *"⚠ FTP was NOT found on this target by the
  scan…"*; pick MSSQL (present) and there's no warning + the command binds to `:1433`. Run stays
  enabled. New test locks it in.
- Everything past enumeration — `mssqlclient` auth with the peeked cred, `xp_cmdshell`, the nc
  reverse shell, winPEAS, the PS-history Administrator cred, `psexec` — is **manual exploitation,
  never the tool**.

**Lesson:** a file's *extension* is a bad proxy for "is this worth reading" — recon loot hides behind
odd extensions (`.dtsConfig`) and none at all. Peek anything small that isn't provably binary or
secret, keep the snippet bounded so no cred leaks into structured findings, and let the raw artifact
hold the full content. And "surface everything, gate on the human" (the exploit tab) still owes the
human a clear signal when they're about to act on a service the scan never saw.

**22 · Unified (HTB Starting Point, Tier II) — http (UniFi Network / Log4Shell) — live.**
`10.129.34.143`. A UniFi Network controller. `default` scan found 22/ssh, 6789/ibm-db2-admin,
**8080/http-proxy + 8443/https-alt** (the UniFi web, redirects `/`→`/manage`→login), and 8843/8880
(other UniFi ports, off the top-1000 — the `-p-` sweep caught them). nmap `-sV` fingerprints **no
product/version** on any of them (UniFi doesn't banner), so Exploit-DB is correctly skipped.
**Efficiency:** the money ports (8080/8443) are in the top-1000, so I drove HTTP recon on them
immediately instead of blocking on the ~10-min `-p-` sweep (which only added 8843/8880).
- **8443 handled as HTTPS on a non-standard port** — `_TLS_PORTS` includes 8443, so recon targets
  `https://{t}:8443/` with `-k` (self-signed). whatweb follows the redirects and reports
  `Title[UniFi Network]` on the login page — the app identity.
- **Bug found + fixed (two compounding, both generalizable):**
  1. **`parse_whatweb` threw away every plugin VALUE** — `Title[UniFi Network]` collapsed to a bare
     `Title`, `HTTPServer[Apache/2.4.38]` to `Apache`. The single most identifying signal was dropped
     on *every* http box. Fixed to keep the values (dropping only `Country`/`IP` noise), bounded +
     deduped. An existing test that asserted the old name-only note was updated to the value-preserving
     one.
  2. **The HTTP fingerprint produced NO structured findings** — unlike SMB/others, whatweb only ran
     via a generic tool-hint (raw output, no parse); the parse path (`_on_http_run`→`parse_tool`)
     existed but nothing triggered it with `tool="whatweb"`. Added a **Fingerprint** button to the
     HTTP panel that runs whatweb through that path (`--log-brief` writes where the parser reads),
     so the stack fingerprint now lands in `findings.json`/report/graph like every other module.
     Verified live end-to-end: click Fingerprint on 8443 → structured finding
     `whatweb: … Title[UniFi Network] …`.
- **Version 6.4.54 lives at the unauth `/status` JSON** (`{"meta":{"server_version":"6.4.54"}}`), not
  on the login page whatweb sees, and `searchsploit UniFi` is empty — so the version has no
  Exploit-DB downstream here. Added a **Tier-2 follow-up** `curl -sk {url}status` (shown, not
  auto-run) alongside the existing `/api/version` + `/health` probes, so the operator can pull the
  version with one double-click. Generalizable — many app controllers expose `/status`.
- Everything past enumeration — the Log4Shell `${jndi:ldap://…}` `remember`-header injection, the
  rogue-JNDI LDAP server + reverse shell, the MongoDB `x_shadow` hash swap, and the SSH root
  password — is **manual exploitation, never the tool**.

**Lesson:** a fingerprint you *run* but never *parse* is invisible recon — the HTTP module wrapped
whatweb but, uniquely among modules, never turned it into findings, and the parser silently discarded
the one value that mattered (the title). Fingerprint→findings should be a first-class one-click step,
and a parser must keep the *values*, not just prove a plugin fired. Also: probe the money ports the
moment discovery returns; don't let a full `-p-` sweep gate the high-value recon.

**23 · Included (HTB Starting Point, Tier II) — http LFI + tftp (69/udp) — live.** `10.129.95.185`.
First box driven with an explicit **attack-coverage** pass (exploit tab), not just recon. `default`
scan found **80/tcp Apache 2.4.29** and — the box's teaching, a *different transport layer* —
**69/udp TFTP** (plus 68/udp dhcpc), caught by the UDP top-100 sweep.
- **Recon validated the Unified whatweb fix on a fresh box:** the Fingerprint on 80 now surfaces
  `Apache[2.4.29]` + `HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)]` **and**
  `RedirectLocation[…/index.php?file=home.php]` — so the **LFI `?file=` sink is visible** in the
  fingerprint (before the value-preservation fix it was a bare `Apache`/`RedirectLocation`). nmap
  also versioned 80 as Apache 2.4.29. TFTP recon runs `tftp-enum` NSE + GETs well-known files.
- **Attack coverage (the point of this pass):** the exploit tab already had the full **web LFI
  chain** (`read /etc/passwd`, php://filter, data:// RCE, **log poisoning**, double-encoded
  traversal) and **`curl PUT webshell into TFTP root (chain with LFI)`** — exactly Included's
  foothold. **Gap: no `lxd`/`docker` group-membership privesc** (the box's *root*, and one of the
  most common HTB/OSCP privescs). Added a **Group membership** category to `linux.py` (lxd, docker,
  disk, + an `id;groups` check), victim-side/copy-only, sourced to HackTricks.
- **Bug found + fixed — the exploit tab's present-marker was near-useless on any web box.**
  `services_present` matched by port, so opening **port 80 marked ~70 web-app services present**
  (drupal, joomla, wordpress, magento, …) — a bare web server is "a web server", not "Drupal". Fixed
  so a **shared web port (80/443/8080/…) alone never marks a specific app present** — only the
  generic `web`/`webdav`, a name match, or a service-specific (non-web) port count. Included dropped
  from **~70 ● to 3** (`web`, `webdav`, `tftp`). Also fixed a **name-fragment substring misfire**
  (`tftp` matched the `ftp` fragment → `ftp` shown too) by matching the **longest fragment first**.
- **GUI/UX bug found + fixed on the pass (my own earlier warning):** the "service not found" warning
  fired for **`linux`/`windows` privesc** — but those are **portless post-ex catalogs**, never
  "found" by a scan, so the warning was a false positive. Suppressed it for portless services.
- Everything past enumeration — writing `shell.php` via TFTP, including it through the LFI for RCE,
  `su mike` with the `.htpasswd` password, and the `lxd` container→root — is **manual exploitation,
  never the tool**.

**Lesson:** "present on this box" must be a *strong* signal — a shared port shared by 70 services is
noise, not presence; match on name or a service-specific port, and let the generic `web` stand in for
"a web server is here." And when you add a UX affordance (the not-found warning), re-check it against
the *portless* corners of the model (privesc/post-ex catalogs), or it fires where it makes no sense.
Attack coverage is worth an explicit pass: the recon can be perfect while the box's actual root
(a group-membership privesc) is simply missing from the catalog.

**24 · Markup (HTB Starting Point, Tier II) — http XXE (Windows) — recon + attack — live.**
`10.129.34.153`. A Windows box: 22/ssh (OpenSSH-for-Windows), **80 + 443 (Apache 2.4.41 (Win64) /
OpenSSL / PHP 7.2.28)**, a web app with an **XXE** in the Order form → read files → daniel's SSH key →
a **writable scheduled-task `job.bat`** (BUILTIN\Users full control) → SYSTEM.
- **Recon:** the Fingerprint on 80/443 surfaces the full `Apache[2.4.41]` / `HTTPServer[… PHP/7.2.28]`
  stack; nmap versioned it too; Exploit-DB matched **apache 2.4 → 31 results, 12 version-matched
  (★), top 15**. The graph renders correctly (native tree: target → 22/80/443 with the finding
  nested under 80 → credentials).
- **Attack — clean coverage, no gap this box.** Exploit tab present = `[ssh, web, webdav]` (focused,
  post the Included fix). The whole chain is already in the catalog: web **`xxe-file-read`** (the
  core vuln), windows **`scheduled-task-hijack`** ("Overwrite a writable task script" →
  `echo …nc.exe… > "{path}"`, *exactly* the `job.bat` technique) + **`icacls-path-check`** (finds
  the BUILTIN\Users write perm) + `schtasks-enum`. Everything past enum (default-cred login, the XXE
  payloads, the SSH key, the `job.bat` reverse shell) is **manual exploitation**.
- **Feature you asked for — a clean "excel-sheet" of discovered URLs.** The raw feroxbuster/gobuster
  stream is great for watching but a pain to act on. New **"Discovered URLs"** tab beside "Content
  discovery": a sortable table — **Status · Method · Lines · Words · Bytes · URL** — colour-coded by
  status, **double-click a row to open it in the browser**, **Export CSV**. It reads the accumulated
  http findings (grows across runs) and leaves the raw pane untouched. The feroxbuster parser now
  captures `method`/`lines`/`words` (not just status/size) to fill the columns. Verified live on
  Markup: 10 URLs (`/index.php`, `/phpmyadmin`, `/server-status`, `/Images/background.jpg`, …) as
  clean clickable rows.

**Lesson:** a raw tool stream and a *queryable* view of its results are two different products — keep
the stream (operators read it live) but also parse it into a clean, sortable, clickable, exportable
table so the findings are something you can *act on*, not just scroll. And when a box is genuinely
clean (recon + attack both covered), that's a valid outcome — mark it down and move on rather than
inventing a fix.

**25 · Base (HTB Starting Point, Tier II) — http PHP (strcmp bypass → webshell → sudo find) — recon
+ attack — live.** `10.129.95.184`. Linux: 22/ssh + **80 (Apache 2.4.29 (Ubuntu), PHP)**. The chain:
a **listable `/login/`** dir exposes **`login.php.swp`** (Vim swap → source disclosure) → the source
shows a `strcmp()==0` login → **type-juggling array bypass** (`username[]=admin&password[]=x`) → PHP
upload webshell → RCE → `config.php` creds → SSH as john → **`sudo find` GTFOBins** → root. Verified
the code with a 2-agent **Workflow** (attack-coverage + recon-angles) alongside the live drive.
- **Recon:** the Fingerprint surfaces `Apache[2.4.29]` + **`Email[info@base.htb]`** (value-preservation
  fix again); the listable `/login/` autoindex directly exposes `config.php` + `login.php.swp` (both
  200). Content discovery fills the Discovered URLs table (94 URLs on Base).
- **Attack — one real gap, filled.** The webshell chain (`upload-php-webshell-file` →
  `upload-curl-multipart` → `webshell-trigger-rce`) and **`sudo-find`** (`sudo find . -exec /bin/sh \;
  -quit`) were already in the catalog. **Missing: the strcmp/type-juggling auth bypass — Base's
  foothold and a recurring PHP/OSCP pattern.** Added **`php-type-juggle-array-auth-bypass`**
  (`curl … --data "username[]=admin&password[]=x"`) + a **`php-magic-hash-type-juggle`** sibling
  (0e loose-`==`), both a new **Auth bypass** category in `web.py`, victim-side/copy-only, sourced to
  HackTricks.
- **Recon fix — flag leaked source.** Nothing marked a `.swp`/`.bak`/`.git` as notable — `login.php.swp`
  looked like any 200. Added **`is_source_disclosure()`** (swap/backup/VCS extensions + `~` + `.git`
  paths) and the **Discovered URLs table now flags those rows with a ⚠ + warning colour** and a
  count ("⚠ 1 source/backup file(s) flagged") so the leaked-source file jumps out. The plain URL still
  opens/copies.
- **New deliverable:** wrote **`boxes/BOX-REVIEW-SOP.md`** — the standing box-review procedure (the
  recon→attack→bugs→UI/graph→fix→mark-down→docs→gates→commit loop + every standing preference) so
  the owner doesn't have to repeat the instructions each box.
- Everything past enum — the type-juggling login bypass, the webshell upload, the `config.php` creds,
  the SSH-as-john, the `sudo find` root — is **manual exploitation**.

**Lesson:** the box's *foothold* technique can be missing even when the flashy steps (webshell, privesc)
are covered — walk the WHOLE chain, first link included. And "content discovery found 94 URLs" is only
useful if the *one* that matters (a leaked `.swp`) is made to stand out — flag source/backup/VCS
disclosures, don't drown them in font files.

## Trends & lessons (adapt going forward)

- **Real boxes catch what unit tests can't.** Every bug here (share prose,
  version split, wide-net default, mongosh dependency) passed the suite before —
  the tests encoded the wrong assumption. Fix the code *and* the test.
- **Tier-1 must work on a stock Kali.** Prefer nmap NSE / already-installed
  clients (redis-cli, netexec) for automatic recon; push tools the user must
  install (mongosh) to Tier-2 manual follow-ups.
- **Sane, fast defaults.** Automatic recon shouldn't fire hundreds of thousands of
  requests or hang. Bounded, first-pass-friendly defaults; heavy options opt-in.
- **Non-standard ports (6379, 27017, …) aren't in nmap's top-1000.** `quick`
  misses them — the empty-state message points to a fuller profile; "Run Full
  Recon" (default/exam) does `-p-`.
- **This Kali runs nmap privileged**, so UDP scans work without sudo here.
- **Parser hygiene:** anchor on structural columns (share Type, version token,
  NSE block scoping), not "first word" / greedy line matching.
- **The emitted command and its parser must speak the same format.** whatweb's
  default coloured summary ≠ its `--log-json` output; a JSON-only parser dropped
  every real run. Pin the command to a deterministic, parseable form (and force
  `--colour=never` for tools that colour even when piped).
- **A redirect to a different hostname is recon, not a footnote.** A meta-refresh
  or `Location` redirect to a *name* (unika.htb) is a vhost to enumerate — surface
  the target host (and hint /etc/hosts + vhost enum), don't just note "a redirect
  exists". Ignore redirects to a bare IP or a path.
- **Overlapping enumerators duplicate findings.** When two tools list the same
  thing (nmap ftp-anon + curl walk; nmap + NSE), dedup on a structural key and keep
  the richer detail — one file is one finding, whatever surfaced it.
- **Recon the name, not the IP.** Name-based vhosts (thetoppers.htb, unika.htb,
  ignition.htb) serve content the bare IP won't; set the target hostname and host-based
  tools follow. Two sources now surface the vhost automatically: nmap's http-title
  redirect (auto-set at scan time) and whatweb's redirect target (meta-refresh *and*
  302 Location). Cloud services (S3) hide behind subdomains with no port — surface them
  via the vhost path, read-only.
- **A failure must never look like an empty result.** A missing/blocked tool that
  yields "no findings" invites "the service isn't there" — say "⚠ step did not run"
  explicitly. Same for an unreachable endpoint (awscli "Could not connect" → an
  explicit error finding, not zero buckets).
