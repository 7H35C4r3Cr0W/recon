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
| 11 | Crocodile | 10.129.32.203 | ftp/21 (vsftpd 3.0.3, anon) + http/80 (Apache 2.4.41) | anon FTP listed both cred files; whatweb + EDB (vsftpd 3.0.3 → EDB-49719 ★, apache 2.4 → 31) both clean; login.php foothold is manual | FTP files listed **twice** — nmap ftp-anon and the curl walk both enumerate root | _this commit_ |

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
