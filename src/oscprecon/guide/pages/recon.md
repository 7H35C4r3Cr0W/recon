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

## Conservative findings, visible failures

An open port, a version string, or an Exploit-DB match is **never** called a vulnerability — only
real weak postures (anonymous access, null session, SMB signing off) are flagged. And a
missing/blocked tool is called out with **`⚠ step did not run`**, so "no findings" is never confused
with "the service isn't there".

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
