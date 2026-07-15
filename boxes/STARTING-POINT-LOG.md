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
| 16 | Ignition | 10.129.32.240 | http/80 (nginx 1.14.2, 302→ignition.htb) | nmap's http-title redirect now **auto-sets** hostname=ignition.htb → http recon targets the vhost (serves Magento 200 + /admin 200); whatweb also surfaces it from the 302 `RedirectLocation`; Magento default-cred login is manual | nmap-redirect vhost wasn't surfaced until whatweb ran → now auto-wired at scan time | _this commit_ |

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
