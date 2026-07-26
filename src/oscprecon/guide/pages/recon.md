# The recon workflow

## The three panes

| Pane | What it shows |
| --- | --- |
| **Left — service tree** | Every discovered port/service. Non-standard HTTP/DB ports get their own node. |
| **Middle — tool panel** | The command builder for the selected service, a live shell preview, `Run` / `Dry-run`, the streamed output, and **Tier-2 manual follow-ups** (e.g. the HTTP panel surfaces WebDAV `OPTIONS`/`PROPFIND` + endpoint probes — double-click to run). The HTTP panel also has a one-click **Fingerprint** button (whatweb) that records the web stack — server, page title, framework versions — as structured findings, and a **Discovered URLs** tab: a clean, sortable table (Status · Method · Lines · Words · Bytes · URL) of everything feroxbuster/gobuster found on that port — **double-click a row to open it in the browser**, or **Export CSV**. It accumulates across runs alongside the raw output, and **flags source / backup / VCS disclosures** (`login.php.swp`, `*.bak`, `.git/…`) with a ⚠ so a leaked-source file stands out among the noise. A live **Filter** box narrows the table as you type (matches URL, status, or method — e.g. `.php`, `admin`, `403`), and a **Hide static assets** toggle drops the js/css/image/font rows so app endpoints stand out (on a real box that's ~40 asset rows out of the way); **Export CSV** writes exactly the filtered/cleaned view you're looking at. |
| **Right — reference pane** | The matched HackTricks page (vendored offline) and version-aware `searchsploit` Exploit-DB hits (lookup only). |

## Staged nmap discovery

Recon goes fast-to-thorough so you're never blocked waiting on a full scan:

1. **TCP top-1000** — quick first look.
2. **TCP full** (`-p-`) — every port.
3. **UDP top-100** — the common UDP services.
4. **Versioned** (`-sCV`) — service/version + default scripts on the ports that were found.

The **Run Recon** split-button chooses how heavy to go (Quick / Default / Full / Exam), and the
**Scan a host / range** dialog gives full nmap-flag control — scan type, `-Pn`, ports, timing, NSE,
`--open`, `-O`, `-n`, `--reason`, `--min-rate`, free-form flags — with a live preview. Its **NSE
picker** is a searchable dropdown (type to filter across every script the installed nmap ships,
brute-filtered per §2) with an **Add** button that appends the chosen script. The target can be a
single IP **or a whole `/24`**.

**Scan → More options…** opens the preset chooser — 80+ labelled nmap scans grouped by situation
(Fast / triage · Full TCP · Version & scripts · UDP · Firewall/IDS evasion · Active Directory ·
Service-focused NSE bundles · TLS/SSL · Verbose/debug · Host discovery · OS & vulnerability). Filter
by keyword, read what each is for, then **Load into builder** or **Run**.

## Per-service modules & the tier model

A module's panel appears **only for a service the scan actually found** — the tool never runs a
service's recon for a port that isn't open. You pick a discovered service and click its **Run**; each
run is scoped to that one service and its discovered port. Nothing fans out or auto-runs.

Each service has a module that runs the right enumeration, gated by a strict safety model:

- **Tier 1 — Auto.** Read-only checks with bounded output (null session, anonymous FTP, `showmount`,
  SNMP walk on default communities). Runs on one click. When a readable SMB share or anonymous FTP
  directory is walked, small non-binary files get a **bounded content peek** — a short, safe preview
  (secret material like keys/hash stores is never previewed) that flags config files worth reading.
- **Tier 2 — Shown, not auto.** A *single* attempt against a well-known account with an empty/default
  password (`administrator:''`, `sa:sa`). Pre-filled in **Manual follow-ups** — you click Run.
- **Tier 3 — Gated.** Iterating a list of credentials is **credential spraying** — off by default,
  behind opt-in Spray mode. See **Exploitation & spraying**.

## Vuln scripts (NSE) — per service, one click

A default `-sC -sV` sweep does **not** run nmap's vuln-category scripts. That is how a box gets lost
for an evening: everything looks clean because the check that would have found the way in was never
asked to run.

So every service panel carries a **⚠ Vuln scripts (NSE)** button, and **Scan → Vuln scripts on every
discovered service** queues them all (one run per service *family* — 139 and 445 are a single SMB
pass). Headless: `nabu-cli vuln <service> -p <profile>`, or `--all`.

Three modes:

- **all vuln checks** (default) — `--script vuln`, scoped with `-p` to the ports this box has open.
  nmap's own portrules decide what applies, so this is complete for *any* service without a
  hand-maintained script list.
- **targeted family** — the form you'd type yourself (`smb-vuln-*`, `http-vuln-*`, `ftp-vuln-*`).
  Faster and narrower.
- **safe checks only** — drops the DoS-category scripts. Several `smb-vuln-*` checks (ms06-025,
  ms07-029, ms08-067, cve2009-3103) *crash* a vulnerable service by design; use this on anything
  fragile, or on a box you can't revert.

Two things make the result trustworthy:

- **Every check states its verdict, including the negative ones** (`vulns.showall`). Without this,
  nmap prints nothing for a check that came back clean — so a silent run is indistinguishable from
  a check that never ran. You can see that MS08-067 *was* tested and came back NOT VULNERABLE.
- **A check that reached no verdict is reported as inconclusive**, never as "not vulnerable". A
  timeout or `NT_STATUS_ACCESS_DENIED` means *unknown* — it is recorded and shown as
  `⚠ could not check`, so re-running it against that one port stays on your list.

A `VULNERABLE` verdict is written into `findings.json` with its CVE/MS ids, at the **vulnerable**
severity — the strongest category, and the only one that is never inferred from a banner. It flows
into the Findings view, the graph, `report.md`, and the Exploitation tab's ★ suggestions.

## Several scans at once

Scans run in parallel. A full `-p-` sweep, a `--script vuln` scan on 445 and two feroxbuster runs
with different wordlists can all be in flight together; the task bar lists each with its own Stop.

Work is admitted in **lanes** so an exam box isn't hammered:

| Lane | Cap | What runs there |
|---|---|---|
| battery | 1 | The full **Run Recon** staged sweep — it owns the profile's staged output files |
| nmap | 3 | Ad-hoc scans: presets, *Scan a host / range*, per-service vuln scripts |
| tool | pool | Service recon, content discovery, vhost — everything else |

Output filenames follow the command and its settings, so two feroxbuster runs on the same port with
different extensions no longer resolve to the same file. A running scan also holds a **claim** on its
output file: launching a second run that would write the same file is refused by name rather than
letting the two interleave. While more than one scan is streaming, each output line is prefixed with
the run it came from.

## The CLI runs the same recon, not a lighter one

`nabu-cli enum <service>` and the service panel drive one shared engine, so the headless path does
the whole sequence — for SMB that is banner → null session → guest → follow-ups (users, password
policy, RID cycling) → a listing of every readable share → a bounded peek at small files — and
records the anonymous credential exactly as the panel does. It used to stop after the first phase.

`enum4linux-ng` runs in the null-session phase and **its output is parsed** now: workgroup/domain,
NetBIOS computer name, DNS domain, OS build, users and shares, whether the null session was
accepted, whether signing is required, and the supported SMB dialects. That last one matters —
`SMB 1.0: true` is flagged as *SMBv1 enabled — MS17-010 / EternalBlue precondition*, which tells you
exactly which vuln check to run next.

## The scan tells you what it is about to run

Every recon run opens with its **plan**: the whole ordered nmap battery, each command's exact syntax,
why it is there and roughly how long it takes. Then each command is echoed with `$` as it starts —
including the pre-flight host-discovery ping, which used to stream nmap output with nothing saying
what had been run.

To read the syntax *without* scanning: **Scan → Show scan plan (dry run)**, or
`nabu-cli scan <ip> -p <name> --dry-run` (which creates no project). The versioned scan's port list
is only known after discovery, so it shows as `nmap -sV -sC -p <discovered ports> <target>`.

## Anonymous first, then as whoever you found

Recon starts anonymous — null session, guest, anonymous FTP, anonymous LDAP bind. That is the right
first move, and it stays the default. But once a credential turns up (an http config, a share, a
PDF), the **Run as:** dropdown on the SMB, FTP and LDAP panels re-runs the *same* enumeration as that
user, and it returns far more: authenticated SMB adds domain groups, logged-on sessions, local-group
membership, an `smbmap` permission walk and a metadata-only `--spider-plus` file index.

The same picker is on the WinRM, MSSQL, RDP, MySQL and PostgreSQL panels. There it *adds* an
authenticated pass to the fingerprint rather than replacing it: WinRM/MSSQL/RDP report netexec's login
verdict — **`(Pwn3d!)` means administrative access**, which on WinRM is a shell — and MySQL/PostgreSQL
list the databases, accounts and roles the credential can actually see. A service with nothing to
offer authenticated shows no picker at all.

The dropdown lists every credential in the project vault, so a password found during http enum is
one click from the SMB recon that uses it — no retyping, no copy-paste. The flagship button relabels
(*Run full SMB recon as svc_account*) so an authenticated pass never looks like the anonymous one.
Headless: `nabu-cli enum smb -p box --as svc_account` (or `--as user@domain`); the secret is read
from the vault, never taken on the command line where it would land in shell history and in `ps`.

Each identity writes its own output folder (`smb/as-svc_account/`, `ldap/as-j.doe/`), so one user's
share list never overwrites another's, and a rejected credential is called out rather than quietly
producing an empty result.

This is *not* a credential attack — it is one credential you already hold, which is what you would
type by hand. Iterating a list is still Spray mode (off by default).

## Conservative findings, visible failures

An open port, a version string, or an Exploit-DB match is **never** called a vulnerability — only a
real weak posture (anonymous access, null session, SMB signing off) or a **tool-confirmed
`VULNERABLE` verdict** is flagged. And a missing/blocked tool is called out with **`⚠ step did not
run`**, so "no findings" is never confused with "the service isn't there".

## Your own findings

Parsers only see what a tool printed. The working SQLi, the credential in a PDF, the path that
actually gave you a foothold — record those yourself: **Edit → Add Finding** (`Ctrl+Shift+F`), or the
**＋ Add finding** button on the Findings view. You get a one-line description, a kind, a severity you
judge (info / reference / access / exposure / relay-risk), the **host and port** it was on (both
prefilled from what the scan discovered), a **PoC / repro** block, notes and a reference URL.

They live in the same `findings.json` as parsed findings — so they flow into the graph and
`report.md` (their own **My findings** section, PoC preserved in a fenced block, ready to paste into
an exam report) — but are marked `✎`, filterable via **My findings**, searchable by their PoC text,
and stay editable or deletable (double-click a row). Parsed tool output is never editable: it is the
record of what the tools actually saw. Headless: `nabu-cli add-finding -p box "…" --poc "…"`.

## Recon next steps

As findings land, the pattern library surfaces **Recon next steps** in the tool panel — sensible,
provenance-cited suggestions with a *Pre-fill command* button. They are hints; nothing auto-runs.
The HTTP module adds its own, e.g.: when the **site root redirects into a subdirectory** (a
meta-refresh or 301 from `/` to `/racers/`), it tells you the app lives there and to point content
discovery / whatweb / nikto at that base path — enumerating `/` alone would miss everything; when the
**Fingerprint** turns up an email address on the page (whatweb's `Email[…]` plugin, e.g.
`info@snoopy.htb`), it surfaces the email's **domain as a vhost/subdomain-enum lead** — add it to
`/etc/hosts`, *Set Target Hostname*, and fuzz `Host: FUZZ.<domain>`; a name-based vhost often serves
content the bare IP won't (public mailbox providers like `gmail.com` are filtered out as noise); the
**Fingerprint** also snapshots the index page and mines **lab hostnames printed in the body** (a
heading/footer/comment, e.g. `<h1>carpediem.htb</h1>`) — whatweb never reads page text, so a domain
that lives only in the HTML would otherwise be invisible; any `*.htb` / `*.vl` / `*.thm` / `*.local`
host becomes the same "add to `/etc/hosts`, *Set Target Hostname*, fuzz `Host: FUZZ.<host>`" lead;
**Fingerprint** also fetches **`robots.txt`** from the host root and surfaces every `Disallow` /
`Allow` / `Sitemap` entry as a finding — a free disclosure of the paths an admin wanted hidden (admin
panels, backup/upload dirs, a CMS's install layout). A WordPress `robots.txt` disallows `/wp-admin/`,
which is the **canonical WordPress fingerprint** even when whatweb never prints "WordPress" — so a
WordPress-detected box surfaces the *enumerate (never brute)* `wpscan --enumerate …` next-step (and
marks WordPress ● on the Exploitation tab) from the `robots.txt`/page-body `wp-content` signal alone;
and when an endpoint returns **401** it suggests a *single* well-known default (`curl -u admin:admin
…`) — a Tier-2 recon-adjacent check, never a password spray. When the fingerprint shows a **JSON API
server** — an ASGI stack (`uvicorn` / `hypercorn` / `daphne`), a `FastAPI`/`Starlette` banner, or an
`application/json` root — it nudges you to **enumerate the API surface, not dir-bust for files**: curl
the auto-generated docs/schema (`/openapi.json`, `/docs`, `/redoc`, `/swagger.json`) and versioned
roots (`/api`, `/api/v1`), which list every route and its expected parameters.

Some of these leads surface **the moment the nmap scan lands**, before you touch a service panel: the
default `-sC` scripts are mined for the box's **hostname/vhost** — from an http→name **redirect**
(`http-title`) *and* from the **TLS certificate's Subject CN / SAN** (`ssl-cert`, e.g.
`CN=earlyaccess.htb` on a 443-only box with no redirect). When none is set and there's a single clear
candidate it's **auto-wired as the target hostname** (announced, never silent, never overriding a
user's); extra SAN names become vhost leads. The scan is also mined for **`http-robots.txt` disallowed
entries** (each disallowed path — an admin panel, a backup, the thing they didn't want indexed —
becomes a `[robots]` lead) and for a **JSON API banner** (`uvicorn` / `application/json` → the same
`[api]` "enumerate the schema, not files" nudge).

## Tie discovered hosts to /etc/hosts (no hand-editing)

Recon constantly turns up names that only resolve once mapped to an IP — a subdomain from vhost
fuzzing (`research.bedside.htb`), a domain/DC name from AD enum (`dc01.corp.local`), an internal
vhost printed in a page body or a TLS cert SAN. Instead of hand-editing `/etc/hosts` every time, Nabu
collects them and adds them for you (it writes `/etc/hosts` directly when run as root, otherwise
copies the exact `sudo` command).

**GUI — Hosts Manager** (`Edit → Add Host to /etc/hosts…`): auto-lists every discovered
`(ip, hostname)` for the box — target, pivot-discovered hosts, and vhost/redirect findings — with the
already-mapped ones marked. Check the ones you want and press **Add checked → /etc/hosts**. There's a
manual-entry row for anything recon didn't capture. The **Exploitation tab** also has a **＋hosts**
button beside the Host dropdown that adds the selected hostname in one click.

**CLI:**

```
nabu-cli hosts 10.10.10.5 research.bedside.htb          # add one mapping
nabu-cli hosts 10.10.10.5 dc01.corp.local corp.local    # several names -> one IP
sudo nabu-cli hosts 10.10.10.5 research.bedside.htb      # write /etc/hosts directly (root)
nabu-cli hosts -p htb-active                             # add EVERYTHING discovered for the profile
```

The add is **idempotent** — re-running never duplicates a line, and a name already mapped to a
different IP is flagged so you don't silently create a resolution conflict.
