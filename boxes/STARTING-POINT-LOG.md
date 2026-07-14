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
