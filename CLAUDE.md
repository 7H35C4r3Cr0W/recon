# oscp-recon — Claude Code project brief

**This file is auto-loaded by Claude Code as project context.** It is the single source of truth for what this project is, what it must NOT do, how it is built, and how you (Claude Code) should behave when working on it. Read it fully before proposing any change.

Companion files in this repo elaborate specific slices — `ROADMAP.md` for phase-by-phase build order, `prompts/*.md` for paste-able sequenced work chunks, `boxes/TRACKER.md` for the study list — but everything critical is in this file.

---

## 1. What this project is

A **PySide6 desktop GUI recon orchestrator** for OSCP exam prep and exam day, built in Python. It runs on Kali Linux. Two goals in parallel:

1. **Learn** — work each box on Lain Kusanagi's OSCP-like list manually to build muscle memory.
2. **Build** — turn each box's lessons into reusable, OSCP-exam-legal recon automation.

The tool is **recon-only**. It wraps standard OSCP-allowed enumeration tools, surfaces findings in a Bloodhound-style graph, links inline to HackTricks and Exploit-DB references, and produces Obsidian-friendly markdown reports. It does **not** exploit, brute-force auth, chain attacks, or call any LLM at runtime.

---

## 2. Hard constraints — OSCP exam compliance

The OSCP exam has strict tooling rules. This tool must be exam-legal by default so it can be used **during the exam**, not just prep. If a feature crosses into "automated exploitation," it's out. If it crosses into "credential brute force," it's out.

### Allowed (free to wrap)

- `nmap` — full NSE (`-sC`, `--script vuln`, `--script smb-*`, `--script http-*`, etc.)
- **Web content discovery:** `feroxbuster`, `gobuster`, `ffuf`, `dirsearch`, `dirb`
- **Web fingerprint:** `nikto`, `whatweb`, `curl`, `wget`
- **WordPress enum:** `wpscan --enumerate` — never `--passwords`
- **SMB / AD enum:** `enum4linux-ng`, `smbclient`, `smbmap`, `rpcclient`, `netexec` (a.k.a. `crackmapexec`) in enum modes only, no spraying
- **LDAP:** `ldapsearch`
- **SNMP:** `snmpwalk` (default communities), `onesixtyone` (small community list)
- **DNS:** `dnsrecon`, `dig`, `dnsenum`
- **Vhost / subdomain:** `ffuf -H "Host: FUZZ.{domain}"`, `gobuster vhost`, `gobuster dns`, `dnsrecon -t brt`, `wfuzz`
- **Impacket enum scripts:** `GetADUsers.py`, `GetNPUsers.py`, `GetUserSPNs.py` in enumeration context (no cracking on-host)
- **Lookups:** `searchsploit` (display only — never execute results)

### Forbidden (do NOT wrap, do NOT propose)

- **Metasploit / msfvenom / meterpreter** — exam allows one use total; not for recon. Out of this tool entirely.
- **SQLMap** — exam restrictions too tight. Not wrapped.
- **Brute-force auth tools** — `hydra`, `medusa`, `patator`, `crowbar`. Banned on exam.
- **Password spray combos** — `netexec --users <list> --passwords <list>`, `wpscan --passwords`, similar.
- **Commercial scanners** — Nessus, Burp Pro, Acunetix, Qualys.
- **AI / LLM calls at runtime** — banned during exam. The tool runs offline/local.
- **Automated exploit chains** — no scan → vuln-match → run-exploit → shell pipelines.
- **PoC download / execute / transform** from Exploit-DB — lookup and linkout only.
- **Anything that needs internet at runtime** — except direct probing of the target and live rendering of HackTricks / Exploit-DB pages in the reference pane. **Allowed exception:** a **build-time-vendored, offline snapshot** of the open-source HackTricks **markdown** (bundled in the wheel, read from disk, **attributed** per its licence — see § 27), used for finding-aware offline section rendering; it needs no runtime internet. **Still forbidden:** live scraping or runtime caching of the HackTricks / Exploit-DB **websites**.

### Tier framing for credential-adjacent recon

This is the line every service module must respect:

| Tier | What | Behavior |
|---|---|---|
| **Tier 1 — Auto** | Null session / anonymous access checks; single well-known account with empty password (`guest:''`) | Runs on one click, streams to output files |
| **Tier 2 — Shown, not auto** | Single-attempt default credentials against a well-known account (`administrator:''`, `admin:''`, `sa:sa`) | Pre-filled in Manual Follow-ups tab; user clicks Run |
| **Tier 3 — Forbidden** | Iterating a list of usernames or passwords; anything list-driven; `--continue-on-success` | Not wrapped. Not shown. Not proposed. |

**Definitional line:** A single attempt against a well-known account with an empty/default password is recon-adjacent. Iterating a list is brute force.

### Content discovery vs. credential brute force

`feroxbuster`/`gobuster`/`ffuf`/`dirsearch` against web paths is **content discovery** — allowed. Hitting a login form with a wordlist is **credential brute force** — banned. The wordlist picker in the GUI filters out `seclists/Passwords/` entirely.

---

## 3. Tech stack (pinned — do not propose alternatives)

Two layers: an **engine** (modules, parsers, patterns, reporter) and a **GUI** (PySide6 desktop app) that drives it. A **CLI** exists as a headless entry for scripting and tests.

| Layer | Package | Version | Purpose |
|---|---|---|---|
| Language | Python | 3.11+ | required |
| GUI | [PySide6](https://doc.qt.io/qtforpython-6/) | ≥ 6.6 | Qt for Python, LGPL |
| Web widget | QtWebEngine | ships with PySide6 | embeds HackTricks / Cytoscape.js |
| CLI | [Typer](https://typer.tiangolo.com/) | ≥ 0.12 | headless `oscprecon-cli` |
| Templates | [Jinja2](https://jinja.palletsprojects.com/) | ≥ 3.1 | markdown / HTML reports |
| Config | [PyYAML](https://pyyaml.org/) | ≥ 6.0 | pattern library, references, config |
| Tests | [pytest](https://docs.pytest.org/) | ≥ 8 | unit + parser tests |
| GUI tests | [pytest-qt](https://pytest-qt.readthedocs.io/) | ≥ 4 | widget smoke tests |
| Deps | [uv](https://docs.astral.sh/uv/) | latest | dep management |
| Types | [mypy](https://mypy.readthedocs.io/) | strict | type gate |
| Lint / format | [ruff](https://docs.astral.sh/ruff/) | latest | style gate |
| Graph JS | [Cytoscape.js](https://js.cytoscape.org/) | vendored offline | Bloodhound-style graph view |

**No alternatives** — do not propose Rust, Go, Electron, web UI, Tkinter, Kivy, or rewriting to another framework. Decision is locked.

Runtime dependencies on the host (Kali) — the tool doesn't install these, but `oscprecon-cli doctor` reports missing ones:

- `nmap`, `feroxbuster`, `gobuster`, `ffuf`, `dirsearch`, `nikto`, `whatweb`, `wpscan`
- `enum4linux-ng`, `smbclient`, `smbmap`, `netexec`, `rpcclient`
- `ldapsearch`, `snmpwalk`, `onesixtyone`, `dnsrecon`, `dig`
- `ike-scan`, `nmblookup`, `nbtscan`, `ntpq`, `ntpdate`
- `searchsploit`
- `seclists` package for wordlists

---

## 4. Target environment

- **Primary:** Kali Linux 2024.x or newer (Rolling)
- **Dev also OK:** Ubuntu 22.04+, macOS, Windows 11 with WSL2
- **Wordlists** default paths: `/usr/share/seclists/`, `/usr/share/wordlists/`, `~/wordlists/`
- **Workspace root** for scan profiles: `~/oscprecon/` (configurable in Preferences)
- **User config** (XDG): `~/.config/oscprecon/{recent.json, favorites.json, prefs.json}`

Install on a fresh Kali:

```bash
sudo apt update && sudo apt install -y \
  nmap feroxbuster gobuster ffuf dirsearch nikto whatweb wpscan \
  smbclient smbmap enum4linux-ng rpcclient impacket-scripts \
  netexec ldap-utils snmp onesixtyone dnsrecon dnsutils \
  ike-scan nbtscan ntpdate seclists exploitdb

# Python via uv
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone <repo>/oscp-recon.git ~/oscp-recon && cd ~/oscp-recon
uv sync
python -m oscprecon
```

---

## 5. Repository layout

```
oscp-recon/
├── CLAUDE.md                 ← this file (auto-loaded by Claude Code)
├── ROADMAP.md                ← phased build plan (superseded by this file where they differ)
├── pyproject.toml
├── src/oscprecon/
│   ├── __main__.py           ← `python -m oscprecon` launches the GUI
│   ├── cli.py                ← Typer headless entry (`oscprecon-cli`)
│   ├── orchestrator.py       ← runs phases against a target
│   ├── shell.py              ← subprocess helper — sole chokepoint for exec
│   ├── profile.py            ← Profile model (load/save profile.json, manage folders)
│   ├── wordlists.py          ← scans/indexes wordlist paths, filters passwords out
│   ├── modules/              ← service modules (one file each)
│   │   ├── base.py           ← Module ABC
│   │   ├── nmap.py
│   │   ├── http.py           ← handles non-standard ports too
│   │   ├── vhost.py          ← subdomain / virtual-host enumeration
│   │   ├── smb.py            ← tiered auto-recon
│   │   ├── ftp.py
│   │   ├── ssh.py
│   │   ├── dns.py            ← DNS protocol only (subdomain enum is vhost)
│   │   ├── ldap.py
│   │   ├── smtp.py
│   │   ├── nfs.py
│   │   ├── snmp.py           ← UDP
│   │   ├── tftp.py           ← UDP
│   │   ├── netbios.py        ← UDP
│   │   ├── ike.py            ← UDP
│   │   └── ntp.py            ← UDP
│   ├── patterns/             ← YAML pattern library — one file per service
│   │   ├── http.yaml
│   │   ├── smb.yaml
│   │   └── ...
│   ├── references/           ← service → HackTricks URL + tool hints
│   │   └── services.yaml
│   ├── reporter.py           ← markdown report writer (Obsidian-compatible)
│   ├── templates/            ← Jinja2 templates
│   ├── gui/
│   │   ├── app.py            ← QApplication bootstrap
│   │   ├── main_window.py
│   │   ├── widgets/
│   │   │   ├── service_tree.py     ← left pane
│   │   │   ├── tool_panel.py       ← middle pane (command builder + output + follow-ups)
│   │   │   ├── reference_pane.py   ← right pane (HackTricks + EDB + tool hints)
│   │   │   ├── graph_view.py       ← Cytoscape.js graph (Ctrl+G)
│   │   │   ├── wordlist_picker.py  ← reusable dropdown widget
│   │   │   ├── notes_pane.py       ← live-edits <profile>/notes.md
│   │   │   └── report_preview.py
│   │   └── graph_html/       ← vendored Cytoscape.js + local HTML/JS/CSS
│   └── config.py
├── boxes/
│   ├── README.md
│   ├── TRACKER.md            ← Lain Kusanagi's OSCP-like list (267 boxes), HackSmarter excluded
│   ├── boxes.csv
│   ├── boxes.json
│   ├── _template.md          ← per-box notes template
│   └── <platform>-<box>.md   ← user notes per box
├── walkthroughs/             ← gitignored except README.md + _sample-*.md
│   ├── README.md
│   ├── _sample-htb-linux.md
│   ├── _sample-htb-ad.md
│   └── _sample-vl-chain.md
├── prompts/                  ← sequenced paste-able prompts (mostly used with Windsurf; still valid here)
│   ├── README.md
│   └── 00–08-*.md
├── tests/
│   ├── fixtures/             ← committed sample tool outputs
│   └── gui/                  ← pytest-qt smoke tests
└── (runtime data lives at ~/oscprecon/, NOT in the repo)
```

---

## 6. Data model

### Profile folder — one per box

Default workspace: `~/oscprecon/`. Each profile is a folder:

```
~/oscprecon/htb-active/
├── profile.json              ← metadata + service list + command history
├── findings.json             ← structured findings from parsers
├── creds.json                ← collected credentials, chmod 600
├── graph.json                ← user-drawn edges, node positions, statuses
├── notes.md                  ← long-form user notes (editable in-GUI)
├── report.md                 ← auto-generated Obsidian-compatible master report
├── report-archive/           ← timestamped snapshots of prior report.md
├── audit.jsonl               ← append-only GUI action audit log — QUEUED (§ 6a, Phase 5)
├── audit-archive/            ← rotated audit logs, per-day after N MB — QUEUED (§ 6a, Phase 5)
├── .lock                     ← present while opened for edit; concurrent-copy guard — QUEUED (§ 6b, Phase 5)
├── nmap/
│   ├── tcp-top1000.txt
│   ├── tcp-full.txt
│   ├── tcp-versioned.txt
│   ├── udp-top100.txt
│   └── udp-full.txt          ← only if --udp-full
├── http/
│   ├── 80/  (feroxbuster / nikto / whatweb / index.html / robots.txt / sitemap.xml)
│   ├── 8080/  (per-port subtree)
│   └── 8443/
├── smb/
│   ├── nmap-smb-scripts.txt
│   ├── null-session/  (smbclient-L.txt / netexec-shares.txt / enum4linux-ng-A.txt)
│   ├── guest/
│   ├── shares/       ← per-share listings
│   ├── users.txt     ← union of enum methods
│   ├── domain.txt
│   ├── pass-pol.txt
│   ├── rid-brute.txt
│   └── rpcclient-enum.txt
├── vhost/
├── ftp/  ssh/  dns/  ldap/  smtp/  nfs/  snmp/  tftp/  netbios/  ike/  ntp/
├── references/
│   └── visited.json          ← HackTricks pages / EDB-IDs opened
└── manual/
    ├── commands.txt          ← history of manually-run commands
    └── credentials-hints.md  ← user-curated hints
```

### profile.json schema (v1, versioned)

```json
{
  "schema_version": 1,
  "profile_name": "htb-active",
  "target": {
    "ip": "10.10.10.100",
    "hostname": "active.htb",
    "platform": "htb",
    "box_name": "Active",
    "os_guess": "Windows"
  },
  "status": {
    "state": "wip",
    "started_at": "2026-05-19T22:55:00Z",
    "rooted_at": null,
    "last_active": "2026-05-19T23:30:00Z"
  },
  "discovered_services": [
    { "port": 445, "proto": "tcp", "service": "microsoft-ds", "product": "Windows Server 2008 R2", "version": "", "discovered_at": "..." }
  ],
  "command_history": [
    { "id": "cmd-001", "module": "nmap", "shell_line": "nmap -sCV -p- ...",
      "started_at": "...", "finished_at": "...", "exit_code": 0,
      "output_file": "nmap/tcp-versioned.txt", "phase": "initial-recon" }
  ],
  "references_visited": [
    { "service": "smb", "url": "https://book.hacktricks.wiki/...", "visited_at": "..." }
  ],
  "user_notes_path": "notes.md",
  "module_settings": {
    "http": { "last_wordlist": "...", "last_extensions": ["..."], "threads": 40 }
  },
  "tags": ["ad", "easy"]
}
```

### creds.json schema

```json
{
  "schema_version": 1,
  "entries": [
    {
      "username": "svc_account",
      "domain": "active.htb",
      "secret_type": "password",
      "secret": "<plain>",
      "source": "smb-share-readme.txt",
      "tested_against": ["smb:445", "winrm:5985"],
      "notes": "Found in plaintext on SYSVOL"
    }
  ]
}
```

- File mode `0600` on write.
- Never log secret values. Reports redact: `password=<redacted len=12>`.
- Successful anonymous/null-session enumerations auto-write an entry with `source: <module>-anon-enum`.

### graph.json schema

```json
{
  "user_edges": [
    { "from": "smb-share-IT", "to": "cred-svc_account", "label": "found here" }
  ],
  "node_overrides": {
    "service-445-tcp": { "position": [320, 180], "status": "investigating", "note": "weird share names" }
  }
}
```

### 6a. Audit log — `<profile>/audit.jsonl` — QUEUED (Phase 5)

**Not built yet — recorded here so it lands in Phase 5.** An append-only, one-JSON-object-per-line
record of every GUI action, for a complete exam audit trail. Writes are **best-effort — never block
the UI**. Rotated into `audit-archive/` per day once the live file passes N MB.

Entry shape:

```json
{ "ts": "2026-05-19T22:55:00Z", "actor": "user", "action": "run-command",
  "profile": "htb-active", "details": { "shell_line": "nmap ...", "module": "nmap" } }
```

- `actor`: `"user"` | `"system"`. `action`: kebab-case slug. `details`: action-specific object.
- Events to capture:
  - **Profile lifecycle** — created / opened / closed / saved / exported / imported
  - **Work triggers** — Run / Dry-run / Stop / Add-to-report button clicks
  - **Command runs** — finer-grained superset of `profile.json.command_history`
  - **Setting changes** — wordlist picked, extensions changed, threads/depth/timeout adjusted, tool switched, status codes changed
  - **Reference clicks** — HackTricks page visited, EDB-ID clicked
  - **Notes edits** — one debounced entry per save with a byte-diff summary (never per keystroke)
  - **Credentials added/edited** — **redact the secret value**; log field names + source only
  - **Graph interactions** (Phase 4) — node status change, edge added, layout saved
  - **Menu selections** — New / Open / Save / Preferences opened
- The report generator (§18) gains an **"Audit trail"** appendix that reads from this log.
- **Wiring guidance:** add the emit points as each earlier phase's UI lands (cheap backfill), but
  the audit-log subsystem itself is a Phase 5 deliverable.

### 6b. Concurrent copies & profile lock — `<profile>/.lock` — QUEUED (Phase 5)

**Not built yet.** The exam workflow may run several GUI instances at once (a second window on a
different profile, or the same profile open read-only for reference).

- Opening a profile **for edit** writes `<profile>/.lock` (flock/fcntl, records the owning PID).
- A second instance opening the same profile prompts: *"This profile is open in another window —
  open read-only?"* Read-only mode disables Run buttons and dims edits.
- The lock is released on graceful close, and reclaimed on startup via **stale-lock detection**
  (recorded PID no longer alive).

---

## 7. Module contract

Every service module subclasses `oscprecon.modules.base.Module`:

```python
class Module(ABC):
    name: str                                # e.g. "http"

    @abstractmethod
    def triggers(self, scan_results: ScanResults) -> bool: ...
        # should this module run given what nmap found?

    @abstractmethod
    def commands(self, target: Target, ports: list[Port]) -> list[Command]: ...
        # exact shell commands, in order

    @abstractmethod
    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]: ...
        # extract structured findings

    @abstractmethod
    def suggest(self, findings: list[Finding]) -> list[str]: ...
        # next-step hints — text only, never auto-executed
```

Every `Command` records:
- `shell_line: str` — the exact shell line (what will run)
- `why: str` — one sentence explaining why this command
- `expected_runtime_hint: str` — for the UI ("< 30s", "1-5 min", "slow")

All commands appear in the report log with full args. **No hidden magic.**

---

## 8. Nmap module

- **TCP top-1000** (fast initial): `nmap --top-ports 1000 -oN nmap/tcp-top1000.txt <target>`
- **TCP full**: `nmap -p- -oN nmap/tcp-full.txt <target>`
- **TCP versioned** (only on found ports): `nmap -sV -sC -p <found> -oN nmap/tcp-versioned.txt <target>`
- **UDP top-100** (default on): `nmap -sU --top-ports 100 -oN nmap/udp-top100.txt <target>`
- **UDP full** (opt-in only, flagged slow): `nmap -sU -p- -oN nmap/udp-full.txt <target>`

Parses stdout into `discovered_services` — each entry: `port`, `proto`, `service`, `product`, `version`, `nmap_scripts_output`.

NSE is allowed. `--script vuln`, `--script smb-*`, `--script http-*` are opt-in in the GUI (they're slow / noisy).

---

## 9. HTTP module — full granular controls

The command builder in the GUI must be able to reproduce this reference command by dropdowns / sliders alone:

```bash
feroxbuster -u http://10.129.95.192/ \
  -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -x php,phps,asp,aspx,jsp,cfm,js,css,html,htm,txt,log,bak,backup,old,swp,zip,tar,tar.gz,tgz,7z,rar,sql,sqlite,xml,json,conf,config,ini,inc \
  -d 4 -t 100 --timeout 25 --rate-limit 40 -k \
  -s 200,204,301,302,307,401,403,404,500 \
  -o ferox_10.129.95.192.txt
```

### Controls exposed

| Control | Widget | Default | Notes |
|---|---|---|---|
| Target URL | text | auto from service node | editable |
| Wordlist | `WordlistPicker` | last-used per profile | filters out `seclists/Passwords/` |
| Extensions | multi-select + custom | none | preset groups below |
| Threads | slider 1–200 | 40 | warn > 100 |
| Recursion depth | slider 0–10 | 2 | warn > 4 |
| Timeout (s) | numeric 1–120 | 10 | |
| Rate limit | optional numeric | off | |
| Skip TLS verify | checkbox | ON | lab boxes have self-signed certs |
| Status codes | multi-select preset | "All informative" | see below |
| Output file | text | `<profile>/http/<port>/feroxbuster-<wordlist>.txt` | editable |
| Tool | dropdown | `feroxbuster` | `gobuster dir` / `ffuf` / `dirsearch` translated |

### Extension preset groups

- **Web stack** — `php phps asp aspx jsp jspx cfm`
- **Static** — `html htm js css txt`
- **Backups** — `bak backup old swp orig tmp save ~`
- **Archives** — `zip tar tar.gz tgz 7z rar gz`
- **Logs / data** — `log sql sqlite xml json yaml yml`
- **Config** — `conf config ini inc env properties cfg`
- **Microsoft** — `asp aspx cfm config`
- **Wide net** — union of all above (matches the reference command)

### Status code presets

- **Found-only** — `200, 204, 301, 302, 307`
- **+ Auth-protected** — `200, 204, 301, 302, 307, 401, 403`
- **All informative** — `200, 204, 301, 302, 307, 401, 403, 404, 500` (recommended)
- **Custom** — free text

### Non-standard HTTP/HTTPS ports (per-port nodes)

Every HTTP-flagged port gets its own service tree node and its own subtree of enumeration output. Detection:

1. **From nmap** — any port with `service_name ∈ {http, https, http-alt, http-proxy, ssl/http, ssl/https, ssl/https-alt}` regardless of port number
2. **Proactive** — right-click any open port → "Treat as HTTP" → `curl -sI` probe → adds HTTP node if it responds
3. **Common alt ports surfaced** in the port-hint panel: 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9001, 9090, 9091, 5000, 5001, 4443, 3000, 7001, 7002, 10000

Per-port output folders:

```
<profile>/http/
├── 80/       (feroxbuster-*.txt, nikto.txt, whatweb.txt, index.html, robots.txt, sitemap.xml)
├── 8080/     (same layout, different port)
└── 8443/
```

### Other HTTP module actions

- **`nikto`**, **`whatweb`**, **`curl -sI`**, snapshots of `/`, `/robots.txt`, `/sitemap.xml`, `/.git/HEAD` check, `/backup/` check.
- **`wpscan --enumerate vp,vt,tt,cb,dbe,u,m`** when WordPress detected. **Never `--passwords`.**
- **Last-used HTTP settings** persist per profile in `profile.json.module_settings.http`.

---

## 10. Subdomain / vhost module

Separate from `dns` (which handles DNS-protocol queries). Uses HTTP-flavored tools to enumerate vhosts served by the target IP.

### Triggers

- Auto-runs a small-wordlist pass (`subdomains-top1million-5000.txt`) when: HTTP service found AND a domain name is known (nmap hostname / cert CN/SAN / user input).
- Deep enumeration on-click.

### Tools wrapped

Active (against target — always OK for OSCP):
- `ffuf -u http://target -H "Host: FUZZ.{domain}" -w <wordlist> -fs <wildcard-size>`
- `gobuster vhost`
- `gobuster dns` (if a target DNS server is known)
- `dnsrecon -d {domain} -t brt`
- `wfuzz`

Passive (need internet, rarely useful for lab boxes — flagged in GUI):
- `subfinder -d {domain}`
- `amass enum -passive -d {domain}`
- `assetfinder {domain}`

### Wildcard detection

Probe with a random string first. If the response size matches valid guesses, set `-fs <size>` filter automatically. GUI shows "Wildcard detected — filtering by size delta X".

### Discovered vhost → enumerate as HTTP

Each vhost becomes a graph node. Right-click → "Enumerate as new HTTP target" adds it as a new HTTP node with target `http://<vhost>/` and runs the HTTP module against it.

---

## 11. SMB module — tiered auto-recon

Highest-detail module. Follows the tier framing from § 2 strictly.

### Tier 1 (always auto — pure recon)

Runs on one click of "Run full SMB recon":

1. **Banner / OS / signing / protocols**
   - `nmap --script smb-os-discovery,smb-protocols,smb-security-mode,smb2-security-mode -p 139,445 {target}`
   - `netexec smb {target}` (banner)

2. **Null session** (`-u '' -p ''`)
   - `smbclient -L //{target}/ -N`
   - `netexec smb {target} -u '' -p '' --shares`
   - `enum4linux-ng -A {target}`

3. **Guest** (`-u 'guest' -p ''`)
   - `netexec smb {target} -u 'guest' -p '' --shares`
   - `smbclient -L //{target}/ -U 'guest%'`

4. **If null OR guest worked**, follow-ups:
   - Users: `netexec smb {target} -u <method> -p '' --users`
   - Password policy: `netexec smb {target} -u <method> -p '' --pass-pol`
   - Domain info: `netexec smb {target} -u <method> -p '' --domain`
   - RID cycling (recon, not brute): `netexec smb {target} -u <method> -p '' --rid-brute 10000`
   - RPC null session: `rpcclient -U '' -N {target}` → `enumdomusers`, `enumdomgroups`, `querydispinfo`, `lookupsids`

5. **For each readable share**
   - Root listing: `smbclient //{target}/<share> -U <user>%<pass> -c 'ls'`
   - Bounded recursive: `smbclient //{target}/<share> -U <user>%<pass> -c 'recurse on; ls'` — capped ~500 entries; deeper needs second click

### Tier 2 (shown only — never auto)

In `manual_commands.yaml`, pre-filled in the Manual Follow-ups tab:

```yaml
- description: "Try administrator with empty password"
  why: "Single attempt — not a brute force"
  command: "netexec smb {target} -u 'administrator' -p '' --shares"

- description: "Try admin with empty password"
  why: "Single attempt — common misconfiguration check"
  command: "netexec smb {target} -u 'admin' -p '' --shares"

- description: "Default-cred sanity check (sa/sa)"
  why: "Single attempt against well-known default"
  command: "netexec smb {target} -u 'sa' -p 'sa' --shares"
```

### Tier 3 (forbidden — not wrapped, not shown)

- Username+password lists (`-u users.txt -p passwords.txt`)
- `--continue-on-success` spraying
- Hashcat / john on captured hashes

### Credential auto-propagation

On Tier 1 success (null session or guest), auto-write entry to `creds.json` with `source: smb-anon-enum`. LDAP / RPC / WinRM modules then consume this without re-prompting.

### UNC syntax toggle

GUI default: forward-slash form `//target/share` (cleaner in bash, no escapes). Right-click on any generated SMB command → "Copy as backslash UNC" with sub-options:

```bash
# Linux / bash (default):
smbclient -L //10.129.11.142/ -N

# Windows cmd form:
smbclient -L \\10.129.11.142\

# Bash-escaped:
smbclient -L \\\\10.129.11.142\\
```

### GUI surface

Tool panel for SMB:

```
SMB recon — 10.129.11.142
─────────────────────────────────────
[ Run full SMB recon ]  ← runs Tier 1
[ Just check null session ]
[ Just check guest ]
[ Just enumerate shares ]

Manual follow-ups (Tier 2):
  ▸ Try administrator:''
  ▸ Try admin:''
  ▸ Try sa:sa

Findings so far:
  ✓ Null session works
  ✓ 4 shares (1 readable)
  ✓ 23 users via RID brute
  ! Guest disabled
```

---

## 12. Other service modules

Each follows the same shape (auto Tier 1, `manual_commands.yaml` for Tier 2). Full auto-crawl reference table:

| Service | Default port(s) | Auto on anon | Notes |
|---|---|---|---|
| **FTP** | 21 | Anon → `ls -laR` bounded → file list snapshot | Download = explicit click |
| **NFS** | 2049 | `showmount -e` → for each world-readable export, mount `ro` + `ls -laR` bounded → unmount | Mount only on confirm |
| **LDAP** | 389, 636, 3268, 3269 | Anonymous bind → root DSE → naming contexts → users/groups | Consumes propagated creds if any |
| **SNMP** | 161/udp | `onesixtyone` → if hit, `snmpwalk -v2c -c <community>` for system, users, services, processes | Auto if any hit |
| **rsync** | 873 | List modules → for each unauth module, list contents | |
| **TFTP** | 69/udp | GET on common filenames (running-config, startup-config, backup) | No listing protocol |
| **Finger** | 79 | Query common usernames | Shown |
| **NTP** | 123/udp | `ntpq -c readlist`, `ntpq -c sysinfo`, `ntpdate -q` | Auto |
| **NetBIOS-NS** | 137/udp | `nmblookup -A`, `nbtscan` | Auto |
| **Redis** | 6379 | Ping → if unauth, `INFO`, `CONFIG GET *`, `CLIENT LIST`, `KEYS *` bounded | Auto if unauth |
| **MongoDB** | 27017 | `listDatabases`, per-db collections | Auto if unauth |
| **Memcached** | 11211 | `stats`, `version`, `stats items`, `stats slabs` | Auto |
| **WebDAV** | 80/443/8080 | `OPTIONS` → `PROPFIND` → `cadaver` listing | Auto if WebDAV verbs allowed |
| **mDNS** | 5353/udp | `nmap --script dns-service-discovery` | Auto |
| **UPnP/SSDP** | 1900/udp | `nmap --script upnp-info` | Auto |
| **IPMI** | 623/udp | `nmap --script ipmi-version,ipmi-cipher-zero` | Auto |
| **IKE** | 500/udp | `ike-scan`, `ike-scan -M -A` (aggressive-mode check) | Auto |
| **IPP** | 631 | `nmap --script ipp-info`, `ipptool` get-printer-attributes | Auto if printer found |
| **MSSQL** | 1433 | Banner only. Default-cred (`sa:''`, `sa:sa`) → Tier 2 | User judgment |
| **MySQL** | 3306 | Banner only. Default-cred (`root:''`, `root:root`) → Tier 2 | User judgment |
| **PostgreSQL** | 5432 | Banner only. Default-cred → Tier 2 | User judgment |
| **Elasticsearch** | 9200 | `curl _cat/indices`, `_cluster/health` | Auto if 200 |
| **CouchDB** | 5984 | `_all_dbs`, `_membership` | Auto if 200 |
| **Docker API** | 2375 | `/info`, `/containers/json`, `/version` | Auto if 200 |
| **Etcd** | 2379, 2380 | `/v2/keys`, `/version` | Auto if 200 |
| **Zookeeper** | 2181 | `ruok`, `mntr`, `stat` via nc | Auto |
| **VNC** | 5900–5906 | `nmap --script vnc-info` — banner + auth types | Auto |

**Hard rule for "auto":** read-only enumeration with finite output bounded by listing protocols. Bulk download, auth-guessing, list-based auth = **Tier 2 or Tier 3**.

---

## 13. Wordlist subsystem

Cross-cutting. Used by HTTP, vhost, and any future module taking a wordlist.

- `src/oscprecon/wordlists.py` — scans configured paths at app start; indexes each with: full path, filename, category (inferred from path — `web-content`, `dns`, `usernames`, `fuzzing`, etc.), file size, line count.
- **Filters out `seclists/Passwords/` entirely** — password brute is out of scope. Any wordlist under a path containing `/Passwords/` is suppressed.
- **`WordlistPicker` widget** — searchable dropdown with category chips, favorites pinned top, per-module recent, size + line count per entry.
- **Persistence:** per-profile last-used in `profile.json`; app-wide favorites in `~/.config/oscprecon/favorites.json`.

### Common Kali wordlist locations

- **SecLists:** `/usr/share/seclists/` — `Discovery/Web-Content/`, `Discovery/DNS/`, `Fuzzing/`, `Usernames/` (Passwords/ filtered)
- **Standard:** `/usr/share/wordlists/` — `dirb/`, `dirbuster/`, `metasploit/` (skip), `nmap.lst`, `rockyou.txt` (filtered)
- **Custom:** `~/wordlists/` — user's own curation

Repos:
- SecLists: https://github.com/danielmiessler/SecLists
- Assetnote wordlists: https://wordlists.assetnote.io/

---

## 14. References integration (HackTricks + Exploit-DB)

Right pane of the GUI has two sub-areas:

### HackTricks WebEngineView

`QWebEngineView` loads the URL matched from `src/oscprecon/references/services.yaml` when a service is selected in the tree.

Base URL: https://book.hacktricks.wiki/en/network-services-pentesting/

### Exploit-DB

For services with `product` + `version` detected, run `searchsploit --json <product> <version>` and display results as clickable list. Click → loads `https://www.exploit-db.com/exploits/<EDB-ID>` in the same WebEngineView.

**Hard rule:** Exploit-DB integration is **lookup-only**. Never download, execute, or transform a PoC. No "click to exploit" anywhere.

### services.yaml schema

```yaml
- match: { port: 445, proto: "tcp" }              # match keys: port, proto (tcp|udp), product_contains, service_name, nmap_script
  label: "SMB"
  hacktricks: "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smb/index.html"
  module: "smb"                                    # engine module that owns this port
  tools:                                           # per-port hint panel entries
    - { name: "smbclient -L //{target}/ -N",           purpose: "list shares via null session" }
    - { name: "netexec smb {target} -u '' -p '' --shares", purpose: "shares + perms via null session" }
    - { name: "enum4linux-ng -A {target}",             purpose: "broad anonymous enumeration" }
```

Match order: `port + proto + product + version > port + proto + product > port + proto > port > product > service_name` — most specific wins.

Seed the YAML with:
- All common ports 21, 22, 25, 53, 69, 79, 80, 88, 110, 111, 123, 135, 137, 139, 143, 161, 389, 443, 445, 464, 500, 514, 593, 623, 636, 873, 1194, 1433, 1900, 2049, 3268, 3269, 3306, 3389, 5353, 5432, 5985, 5986, 6379, 27017
- All alt HTTP ports: 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9001, 9090, 9091, 5000, 5001, 4443, 3000, 7001, 7002, 10000
- Generic `service_name` matchers for HTTP variants: `http`, `https`, `http-alt`, `http-proxy`, `ssl/http`, `ssl/https`, `ssl/https-alt`
- Product-specific overrides: Apache, nginx, IIS, Tomcat, Jenkins, Joomla, Drupal, WordPress, OpenSSH, vsftpd, ProFTPD

### Per-port tool hints panel

When a service is selected, the tool panel shows the `tools:` list. Each row is clickable → pre-fills the command builder with placeholders (`{target}`, `{port}`, `{share}`, etc.) expanded from the active profile. User clicks Run.

---

## 15. Pattern library

Dynamic suggestions from findings. Separate from static tool hints.

### Files

`src/oscprecon/patterns/<service>.yaml` — one YAML per service module.

### Schema

```yaml
# patterns/smb.yaml
- match:
    service: smb
    detail_contains: "signing: disabled"
  suggest:
    - "SMB signing disabled — relay candidate. Confirm scope before attempting."
    - "Manual check: netexec smb {target} -u '' -p '' --shares"
# source: htb-active.md
```

Match keys: `service`, `port`, `proto`, `detail_contains`, `field`+`value` (regex), `has_credential: true`.

Suggestions interpolate `{target}`, `{port}`, `{share}`, `{user}`, `{domain}`, `{community}`, etc. from finding context.

### Provenance requirement

**Every pattern entry has a `# source:` comment.** Sourced from a real box (`# source: htb-active.md`) or walkthrough (`# source: walkthroughs/vl-heron.md`). Build fails if any entry lacks provenance.

### Engine behavior

- Re-runs after every command completes (findings may update).
- Emits `Suggestion(text, command_template, source_pattern, source_box?)`.
- GUI surface: "Recon next steps" sub-section in the Tool Panel. Each row has a "Pre-fill command" button. Never auto-executed.
- Suggestions appear in `report.md` "Suggested next steps" section with source_pattern cited.

### Forbidden pattern contents

- No "try CVE-XXXX-XXXX" hints
- No exploit-specific suggestions
- No credential lists / wordlists as suggestion contents
- No "run Metasploit module X"

---

## 16. Graph view (Bloodhound-style)

Alternate visual interface to the tree view. Toggle: `View → Graph` (Ctrl+G).

### Implementation

`QWebEngineView` loads a local HTML file that uses [Cytoscape.js](https://js.cytoscape.org/) (vendored offline, NO CDN loads at runtime). `QWebChannel` bridges Qt ↔ JS.

`src/oscprecon/gui/graph_html/`:
- `index.html`
- `app.js`
- `cytoscape.min.js` — vendored, offline
- `style.css`

### Node types

| Node | Source | Color |
|---|---|---|
| Target | scanned IP | dark blue, root |
| Service | discovered port | light blue TCP, green UDP |
| Finding | parser-extracted fact | yellow |
| Artifact | file / share / user / endpoint | orange |
| Credential | creds.json entry (redacted) | red |
| Note | user annotation | gray |

### Edge types

- `has-service` (target → service)
- `exposes-finding` (service → finding)
- `contains` (service → artifact)
- `references-credential` (finding → credential)
- `relates-to` (user-drawn between any two)
- `next-step` (finding → suggested action)

### Interactions

- **Click node** → right pane detail
- **Double-click service** → drill into artifacts as children
- **Right-click** → context menu: Mark Investigated / Add Note / Open Folder / Copy Command / Hide
- **Drag edge between two nodes** → creates `relates-to` user edge
- **Status badges** (`new` / `investigating` / `done` / `dead-end`) affect color saturation
- **Filter sidebar** — toggle node types, filter by status / tag / port / proto
- **Layout** — hierarchical (default) + force-directed toggle

### Persistence

`<profile>/graph.json` — user-drawn edges, node positions, per-node status/notes.

### Presentation & export — QUEUED reinforcements (Phase 4)

The Phase 4 graph must be presentation-quality, not merely functional. Explicit expectations to
build into the Phase 4 deliverable:

- **Full drag-and-drop** node repositioning; positions persist in `graph.json` **across sessions**.
- **Right-click any node → Add Note** — persists to `graph.json`, shows as a hover tooltip, and
  appears in `report.md`.
- **Consistent visual language** — fixed colors per node type (table above), edge labels, a minimap,
  smooth zoom/pan.
- **Export graph as PNG / SVG** — for reports and walkthroughs.

BloodHound reference (for design comparison only, not a dependency): https://github.com/BloodHoundAD/BloodHound

---

## 17. Obsidian-friendly output

Two modes:

### Mode 1 — Single-file (default)

`<profile>/report.md` is Obsidian-compatible:

- **YAML frontmatter**:
  ```yaml
  ---
  type: scan-report
  profile: htb-active
  target: 10.10.10.100
  platform: htb
  box: Active
  status: in-progress
  started: 2026-05-19T22:55:00Z
  last-active: 2026-05-19T23:30:00Z
  tags: [oscp, htb, ad, windows]
  ---
  ```
- Headings H1 = profile, H2 = phase, H3 = service — Obsidian outline works
- Sprinkled tags: `#smb #null-session`, etc.
- Wikilinks between sections: `[[#445/tcp - SMB]]`
- Callout blocks: `> [!warning] SMB signing disabled`

Drop into any Obsidian vault → works.

### Mode 2 — Vault export (on-demand)

`File → Export to Obsidian Vault...` → folder picker → writes:

```
<chosen-dir>/<profile-name>/
├── index.md
├── target/<ip>.md
├── services/<port>-<proto>-<service>.md
├── findings/<slug>.md
├── credentials/<user>.md         (values redacted)
├── commands/<timestamp>-<slug>.md
└── notes/<date>-progress.md
```

Each .md has frontmatter + wikilinks. Snapshot, not live-linked. Re-export to refresh. State this clearly in the export dialog.

Obsidian: https://obsidian.md/

---

## 18. Report structure

`report.md` sections in order:

1. **Frontmatter** (Obsidian YAML)
2. **Header** — profile name, target, status, timestamps
3. **Summary table** — open ports at a glance (TCP + UDP)
4. **Discovered services** — per service with HackTricks link + EDB hits
5. **Per-service findings** — one section per module that ran
6. **Suggested next steps** — from pattern library, with source_pattern citation
7. **User notes** — pulled from `notes.md`
8. **Command log** — every command run, with timing and exit code

Never hide what was run. Every command appears with full args.

Rewritten every scan event. Prior version archived to `<profile>/report-archive/report-<YYYYMMDD-HHMMSS>.md` before overwrite.

---

## 19. GUI shell — three-pane layout

```
┌─ oscp-recon ─────────────────────── target: 10.10.10.5 ────────────────────┐
│ Services tree           │ Tool panel / command builder   │ Reference pane │
│ ▾ Ports                 │  <selected tool's controls>    │ HackTricks     │
│   • 22  ssh OpenSSH 8.4 │  <shell preview>               │ ┌───────────┐  │
│   • 80  http nginx 1.18 │  [Run] [Dry-run] [→ report]    │ │ rendered  │  │
│   • 445 smb Win10       │                                │ │ page      │  │
│ ▾ HTTP                  │  Manual follow-ups (Tier 2):   │ └───────────┘  │
│    gobuster *           │  ▸ ...                         │ Exploit-DB     │
│    nikto                │                                │ • EDB-12345    │
│ ▾ SMB                   │  Recon next steps (patterns):  │ • EDB-23456    │
│    ...                  │  ▸ ...                         │ searchsploit ↻ │
└─────────────────────────┴────────────────────────────────┴────────────────┘
 ?: help  q: quit  /: filter  enter: run  Ctrl+G: toggle graph  m: notes
```

### Status footer — QUEUED (Phase 2 or Phase 5 QoL, wherever cleanest)

**Not built yet.** A small always-visible strip along the bottom of the main window:

- App name + version (read from `pyproject.toml`)
- Active profile name (or `no profile loaded`)
- Workspace root path
- Muted text: `recon-only — OSCP exam legal per CLAUDE.md § 2`

Cleanest to add alongside the first module UI work (Phase 2) or with the Phase 5 QoL pass —
implementer's call.

### File menu

| Item | Shortcut | Action |
|---|---|---|
| New Scan Profile... | Ctrl+N | Modal: name + IP + optional box dropdown from `boxes/TRACKER.md` |
| Open Scan Profile... | Ctrl+O | Folder picker at `~/oscprecon/` |
| Recent Profiles | — | Last 10 |
| Save | Ctrl+S | Writes `profile.json` |
| Save As... | Ctrl+Shift+S | Copies active profile |
| Close Profile | Ctrl+W | |
| Export Report... | — | Renders `report.md` to HTML |
| Export to Obsidian Vault... | — | See § 17 |
| Open by IP... | — | **QUEUED (Phase 5).** Search all `~/oscprecon/` profiles for one whose `profile.json.target.ip` matches; open it. Fast recovery when the name is forgotten |
| Import Project... | — | **QUEUED (Phase 5).** Extract a `<name>.tar.gz` (or folder) exported elsewhere into `~/oscprecon/<name>/` and open it |
| Export Project... | — | **QUEUED (Phase 5).** Pack the active profile folder into `<name>.tar.gz` for backup/transfer; **warn that `creds.json` is included** |
| Preferences... | — | Workspace root, wordlist paths, theme |
| Exit | Ctrl+Q | |

### Project file operations — QUEUED (Phase 5)

Each `~/oscprecon/<name>/` folder is a self-contained **project file**: opening it restores
everything — discovered services, notes, audit log (§ 6a), command history, references visited,
credentials, findings, and graph layout. The three File-menu actions above formalize that model:

- **Open by IP...** — fast recovery when the profile name is forgotten; matches `profile.json.target.ip`.
- **Import Project...** — accept a `<name>.tar.gz` (or folder) exported from another machine.
- **Export Project...** — pack the folder for backup/transfer. Redacts nothing (it is the user's own
  working copy) but **warns that `creds.json` is included**.

### Other menus

- **Edit** — Add Note / Add Credential / Add Manual Finding
- **Scan** — Run Quick Recon / Run Full Recon / Custom Command / Stop All
- **View** — Service Tree / Graph (Ctrl+G) / Notes / Report Preview / Theme
- **Help** — About / OSCP Constraints / Doctor

### Preferences

- Workspace root path (default `~/oscprecon/`)
- Wordlist paths (add/remove; default `/usr/share/seclists/`, `/usr/share/wordlists/`, `~/wordlists/`)
- Default scan profile: `quick` / `default` / `full` / `exam`
- Theme: light / dark
- Font size

---

## 20. Manual command lists

Every module ships a `manual_commands.yaml`:

```yaml
- description: "Enumerate users via RID brute force (null session)"
  why: "RID cycling sometimes returns users LDAP/SAMR enum misses"
  command: "netexec smb {target} -u '' -p '' --rid-brute 10000"

- description: "Dump SAM database via secretsdump (requires creds)"
  why: "Recon: confirms what we can read; not executing as exploitation"
  command: "impacket-secretsdump '{domain}/{user}:{password}@{target}'"
  requires: ["creds"]
```

- Commands tagged `requires: ["creds"]` are dimmed until `creds.json` has entries.
- Commands with `{placeholders}` are filled from the active profile.
- Shown in the Manual Follow-ups tab of the tool panel. Never auto-executed.

---

## 21. Walkthrough inputs

Drop walkthrough markdowns into `walkthroughs/<platform>-<box>.md` (e.g. `htb-active.md`, `vl-heron.md`). Content gitignored — third-party writeups stay local.

### Permitted uses

- Spot recon steps the tool missed → propose new commands for the relevant module
- Identify patterns worth codifying in the pattern library (with `# source:` comment citing the walkthrough)
- Improve parsers when a walkthrough shows tool output the parser missed something in — fix the parser and add a fixture
- Confirm existing pattern library entries across multiple boxes

### Forbidden uses

- **Do NOT add exploit code, payloads, reverse-shell snippets, or exploit modules.**
- **Do NOT hardcode credentials, password lists, wordlists, or hashes** from walkthroughs.
- **Do NOT reproduce walkthrough prose** in tool output, reports, comments, commits.
- **Do NOT add CVE-specific exploit logic.**
- **Do NOT put "try CVE-XXXX-XXXX" style suggestions into the pattern library.**
- **Do NOT commit walkthrough files.** They're gitignored.

### Workflow when a walkthrough lands

1. Read silently. **Do NOT echo it back to the user.**
2. Extract recon insights only.
3. Propose changes one at a time:
   - "Walkthrough for `<box>` shows the tool missed `<step>`. Want me to add `<command>` to `modules/<module>.py`?"
   - "Walkthrough confirms a pattern: when `<condition>`, suggest `<recon next step>`. Want me to add to `patterns/<service>.yaml`?"
4. Wait for approval before changing code.
5. Pattern entries derived from walkthroughs get `# source: walkthroughs/<file>.md`.

---

## 22. Box study list

**Lain Kusanagi's OSCP-like list** — the source of truth. Extracted tracker at [`boxes/TRACKER.md`](boxes/TRACKER.md). 267 boxes across:

- Hack The Box (79)
- Proving Grounds Practice (72)
- Proving Grounds Play (14)
- VulnLab (19)
- Virtual Hacking Labs (39)
- TryHackMe deprecated set (44)

**HackSmarter excluded** by project decision.

Source sheet: https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/htmlview

Refresh procedure in [`boxes/README.md`](boxes/README.md).

Suggested starting order for validating the tool: HTB Linux easies (Sea, Nibbles, Bashed) → HTB Windows easies (Jerry, Netmon) → PG Practice for volume → AD-flavored boxes.

---

## 23. Build phases

Six phases. Phase "done" = tool used on ≥ 3 boxes from `TRACKER.md` without major gaps for that phase's features.

### Phase 0 — Scaffold (engine + minimal GUI + nmap)

- `pyproject.toml`, `uv sync`, `mypy --strict`, `ruff` configured
- `shell.py`, `profile.py`, `orchestrator.py`, `reporter.py`
- `modules/base.py` (ABC), `modules/nmap.py` (TCP top-1000 → full → versioned, UDP top-100)
- `cli.py` — Typer entry `oscprecon-cli scan <ip> --profile <name>`
- `__main__.py` — GUI launch
- Basic PySide6 window: File menu, New Scan Profile dialog, target input, "Run nmap" button, output panel
- Profile auto-load on start via `recent.json`
- `tests/fixtures/nmap/` + parser test + pytest-qt smoke test

**Exit:** File → New → type IP → click Run → nmap runs (TCP + UDP) → close → reopen → state restored.

### Phase 1 — Full GUI shell + wordlist subsystem + references

- Three-pane layout: `service_tree.py`, `tool_panel.py`, `reference_pane.py`
- `wordlists.py` + `wordlist_picker.py` widget, favorites, recent
- `references/services.yaml` loader + matcher
- HackTricks WebEngineView + Exploit-DB searchsploit lookup + per-port tool hints
- Notes pane editing `<profile>/notes.md`
- Credentials dialog writing `creds.json` (chmod 600)
- References-visited persistence

**Exit:** scan HTB easy, services in tree, click SMB → HackTricks + EDB load, tool hints populate.

### Phase 2 — Core service modules

Order: `http` (with granular controls + non-standard ports), `vhost`, `smb` (tiered), `ftp`, `ssh`, `dns`, `ldap`, `smtp`, `nfs`, `snmp`, `tftp`, `netbios`, `ike`, `ntp`.

Each ships with: fixture, parser test, ≥ 3 pattern library entries, HackTricks + `tools:` in `services.yaml`, `manual_commands.yaml` with ≥ 5 entries, `auto_walk` where table permits.

**Exit:** scan 3 TRACKER boxes (mix HTB + PG, ≥ 1 with UDP service) with full coverage.

### Phase 3 — Pattern library + suggestion engine

- `patterns/engine.py`
- Per-service YAML files with `# source:` provenance requirement (build gate)
- "Recon next steps" sub-section in Tool Panel, pre-fill on click, no auto-execute
- Report includes suggestions with citations

**Exit:** on a fresh box, suggestions read like a sensible recon plan.

### Phase 4 — Graph view (Bloodhound-style)

- `graph_view.py` — QWebEngineView + vendored Cytoscape.js
- `QWebChannel` bridge — `GraphBridge` methods for get_data / node_clicked / status_changed / add_user_edge / save_layout
- Node/edge types, layouts, interactions per § 16
- `graph.json` persistence
- `View → Graph` (Ctrl+G) toggles view

**Exit:** graph shows discovery story end-to-end; can mark/annotate nodes in place.

### Phase 5 — Quality of life + Obsidian output

- `--resume` semantics (skip commands with existing output unless `--force`)
- Bounded parallel execution + status bar with cancel buttons
- Reference search box
- Report viewer tab (rendered `report.md`, "Open in editor")
- Single-file Obsidian frontmatter mode (default)
- `File → Export to Obsidian Vault...`
- Profile actions (right-click Recent): Open Folder / Mark Done / Duplicate / Delete
- TRACKER.md sync — rooting a profile updates the tracker row
- Dark / light theme

**Exit:** pleasant to use under exam pressure; reports drop into Obsidian cleanly.

### Phase 6 — Exam-day polish

- `oscprecon-cli doctor` + Help → Doctor menu — checks each wrapped tool via `which`, prints install commands for missing
- Exam profile preset: tight fast command set (no `--script vuln`, no deep recursion)
- Self-contained report — no inlined external content beyond user findings and commands
- Mock exam: 3 standalone + AD set, timed
- Fix roughness

**Exit:** would trust on the real exam.

---

## 24. Coding conventions

- **Type hints everywhere.** `mypy --strict` must pass.
- **All subprocess calls through `shell.run()`** — logs command, times, writes raw output to file. Never `subprocess.run` directly outside `shell.py`.
- **No silent failures.** Missing tool → log `[missing] gobuster — install with: apt install gobuster` and continue.
- **Errors at boundaries only** — don't wrap internal calls in try/except defensively.
- **No comments narrating what code does.** Only `# why:` for non-obvious decisions. No docstrings on obvious functions.
- **Long-running commands** run in `QThread` or `QProcess` — never block the UI thread.
- **Tests:** parsers tested against committed fixtures in `tests/fixtures/`. GUI widgets smoke-tested with `pytest-qt`.
- **Imports sorted, `ruff format` on save, `ruff check` clean.**
- **Never bypass hooks** (`--no-verify`, `--no-gpg-sign`) unless the user explicitly asks.

Gates before every commit:

```bash
uv run mypy --strict src/
uv run pytest -q
uv run ruff check
uv run ruff format --check
```

---

## 25. Influences (what we borrowed, what we didn't)

### Borrowed from AutoRecon (Tib3rius)

- Service-keyed module dispatch
- Per-service manual command lists (`manual_commands.yaml`)
- Default UDP top-100 alongside TCP
- Per-service output folders
- Pattern matchers per service
- Repo: https://github.com/Tib3rius/AutoRecon

### Borrowed from MassRecon (mikaelkall)

- User-level workspace root (`~/oscprecon/` mirrors `~/.massrecon/`)
- Per-host structured documentation
- Two-stage nmap workflow (quick discovery → versioned scan on found ports)
- Repo: https://github.com/mikaelkall/massrecon

### Deliberately NOT borrowed

- AutoRecon's fully-automated run-everything mode — we want user-controlled execution one phase at a time
- AutoRecon's `dirb` / `dirsearch` defaults — we default to `feroxbuster`
- MassRecon's CherryTree integration — we have our own GUI + Obsidian export
- MassRecon's `exploits/` and `loot/` folders — recon-only, no exploits stored
- nmapAutomator's auto-CME / auto-Metasploit chaining — out of scope
- rustscan as primary scanner — nmap with sensible defaults is exam-portable

### Reference (worth reading, not depending on)

- **BloodHound** — for graph view design inspiration: https://github.com/BloodHoundAD/BloodHound
- **HackTricks** — the canonical recon reference we link to: https://book.hacktricks.wiki/
- **PayloadsAllTheThings** — general pentesting notes: https://github.com/swisskyrepo/PayloadsAllTheThings

---

## 26. External references (all the URLs you'll need)

### Documentation

- **HackTricks book**: https://book.hacktricks.wiki/
- **HackTricks network services**: https://book.hacktricks.wiki/en/network-services-pentesting/
- **Exploit-DB search**: https://www.exploit-db.com/search
- **Exploit-DB PoC page pattern**: `https://www.exploit-db.com/exploits/<EDB-ID>`
- **NVD CVE lookup**: https://nvd.nist.gov/vuln/search

### Tools

- **nmap**: https://nmap.org/book/
- **feroxbuster**: https://github.com/epi052/feroxbuster
- **gobuster**: https://github.com/OJ/gobuster
- **ffuf**: https://github.com/ffuf/ffuf
- **dirsearch**: https://github.com/maurosoria/dirsearch
- **nikto**: https://github.com/sullo/nikto
- **whatweb**: https://github.com/urbanadventurer/WhatWeb
- **wpscan**: https://github.com/wpscanteam/wpscan
- **netexec** (crackmapexec successor): https://github.com/Pennyw0rth/NetExec
- **enum4linux-ng**: https://github.com/cddmp/enum4linux-ng
- **smbmap**: https://github.com/ShawnDEvans/smbmap
- **impacket**: https://github.com/fortra/impacket
- **searchsploit**: https://gitlab.com/exploit-database/exploitdb
- **ike-scan**: https://github.com/royhills/ike-scan

### Frameworks

- **PySide6**: https://doc.qt.io/qtforpython-6/
- **Qt for Python tutorials**: https://doc.qt.io/qtforpython-6/tutorials/index.html
- **Typer**: https://typer.tiangolo.com/
- **Jinja2**: https://jinja.palletsprojects.com/
- **PyYAML**: https://pyyaml.org/
- **pytest**: https://docs.pytest.org/
- **pytest-qt**: https://pytest-qt.readthedocs.io/
- **uv**: https://docs.astral.sh/uv/
- **mypy**: https://mypy.readthedocs.io/
- **ruff**: https://docs.astral.sh/ruff/
- **Cytoscape.js**: https://js.cytoscape.org/

### Wordlists

- **SecLists**: https://github.com/danielmiessler/SecLists
- **Assetnote**: https://wordlists.assetnote.io/

### OSCP resources

- **OffSec help / rules**: https://help.offsec.com/
- **Lain Kusanagi's list** (source sheet): https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/htmlview
- **Obsidian**: https://obsidian.md/

---

## 27. AI collaboration rules (Claude Code specifically)

### Read before proposing

- This file, in full. Don't skim §§ 2 (constraints), 11 (SMB tiers), 21 (walkthroughs).
- `ROADMAP.md` for phase context if working across phases.
- `prompts/*.md` if the user asks you to work on a specific prompt.

### Behavior

- **One change per PR-sized chunk.** New module, or pattern expansion, or report tweak — not all three.
- **Show me the command(s) you're going to add before writing the module.** If not on the Allowed list in § 2, stop and ask.
- **Before committing:** run all four gates from § 24. Pause for my approval.
- **Don't add narrating comments** or docstrings on obvious functions. Naming is documentation.
- **Don't create new markdown docs** unless I ask. Notes go into `boxes/<box>.md` (per-box) or `ROADMAP.md` (cross-cutting).
- **Wait for approval** before committing anything. Even after all four gates are green.

### Yes to propose

- New service modules from the Allowed list
- Better parsers extracting more findings
- Pattern library entries (with `# source:`)
- New entries in `references/services.yaml`
- A **build-time-vendored, offline HackTricks markdown snapshot** — from the open-source repo, **attributed** per its licence (CC BY-NC-SA; confirm at vendor time), **size-bounded** to the network-services-pentesting pages, refreshed by a maintainer-run script (never fetched at runtime) — for finding-aware offline section surfacing (see § 2, § 14)
- Report template improvements
- GUI widgets exposing existing engine functionality
- Bounded parallel execution
- `--dry-run` / "show command, don't run" preview improvements
- Fixture-based tests when parsers change

### No, don't propose

- Anything from the Forbidden list in § 2
- Wrapping Metasploit, SQLMap, hydra, or commercial tools
- LLM/AI calls at runtime — even "optional"
- Auto-exploitation gated behind flags
- Downloading, executing, transforming Exploit-DB PoCs
- **Live scraping or runtime caching of the HackTricks / Exploit-DB _websites_** — fetching or persisting rendered pages at runtime (a build-time-vendored offline markdown snapshot is allowed — see "Yes to propose" and § 2)
- Rewrites of the tech stack — decided in § 3
- Speculative abstractions for features not in the roadmap
- Splash screens, telemetry, update checks, login flows, cloud sync

### When Claude Code proposes something outside the current scope

Decline politely. Note it as a TODO in `ROADMAP.md` (cross-cutting) or `boxes/<box>.md` (box-specific). Return to the active work.

### When ambiguity exists

Ask, don't guess. But make the reasonable call on trivial things (naming, file placement) and mention what you assumed.

---

## 28. Quick-start checklist for Claude Code

New session? Do these first:

1. Read this file (`CLAUDE.md`) fully.
2. Read `ROADMAP.md`.
3. Skim `boxes/TRACKER.md` and `walkthroughs/_sample-*.md`.
4. Confirm: "Which phase are we on?" — check what's in `src/oscprecon/` vs. the phase deliverables in § 23.
5. Ask the user which phase / feature / module to work on. Don't guess.
6. Before writing code: list the specific commands you will wrap and confirm they're on the Allowed list in § 2.
7. Write code. Run the four gates (§ 24). Show diff. Wait for approval.

---

*End of brief. Keep this file authoritative; when it disagrees with older `README.md` or `ROADMAP.md` content, this file wins. Use the reference `nmapAutomator.sh` (kept alongside the original tooling notes) for inspiration too.*
