# Nabu — Local Recon Workspace

[![CI](https://github.com/7H35C4r3Cr0W/recon/actions/workflows/ci.yml/badge.svg)](https://github.com/7H35C4r3Cr0W/recon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A **recon-first, OSCP-exam-legal desktop workspace** that orchestrates the standard enumeration
tools you already use (nmap, feroxbuster/gobuster/ffuf, nikto/whatweb, smbclient/netexec, …),
structures what they find, links each service to HackTricks and Exploit-DB, draws a BloodHound-style
attack-surface graph, and produces Obsidian-friendly reports. It runs **offline** and makes **no LLM
calls at runtime**. Recon is **exam-legal by default**; a separate, **owner-authorized Exploitation
tab** lets you build and Run **human-confirmed** attacks by hand — **183 services / 3,187 actions**
(impacket, evil-winrm, netexec, public PoCs, port-80 web attacks) plus an **msfvenom payload
builder** — nothing auto-runs, you confirm every command, and SQLmap/Metasploit-modules are never
shipped as actions.

*Internal package `oscprecon`; installs as `oscp-recon`; entry points `nabu` (GUI) and `nabu-cli` (headless).*

![Nabu — the three-pane recon workspace](docs/screenshots/shell-dark.png)

> **See it in action:**
> **[▶ Interactive presentation](https://claude.ai/code/artifact/11e5bc74-ffa2-426b-b890-d11250e7e757)** — one page
> covering the finished tool, its agent/tool map, a recon→root decision tree, and where it goes next (also saved
> offline as [`docs/presentation.html`](docs/presentation.html)) ·
> [`docs/screenshots/`](docs/screenshots/) — the screenshot set ·
> [`docs/keyboard-shortcuts.md`](docs/keyboard-shortcuts.md) — shortcuts.

## Features at a glance

- **Staged nmap discovery** → a service tree (TCP top-1000 → full → UDP top-100 → versioned), with
  per-port nodes for non-standard HTTP/DB ports.
- **Per-service modules** with a tiered, safety-gated recon model — auto read-only checks, one-click
  default-credential checks, and opt-in (off-by-default) spraying. Includes **read-only S3 bucket
  enumeration** (`aws s3 ls` only — writes/uploads/downloads are blocked) surfaced when an `s3.*`
  vhost is discovered.
- **Target hostname / vhost** — set a name (e.g. `box.htb`) on New Project or via *Edit → Set Target
  Hostname*; host-based recon (HTTP dir-bust, whatweb, vhost) then targets the name, not the IP, and
  the app surfaces the exact `/etc/hosts` line (and warns when the name doesn't resolve yet).
- **Conservative findings + visible failures** — an open port / version / Exploit-DB match is *never*
  called a vulnerability; only real weak postures (anonymous access, null session, SMB signing off)
  are flagged. A missing/blocked tool is called out (`⚠ step did not run`) so "no findings" is never
  mistaken for "the service isn't there".
- **Reference pane** — vendored **offline** HackTricks + optional live copy, and a **version-aware
  `searchsploit`** Exploit-DB lookup (product + `major.minor`, product-wide fallback, version-matched
  hits ranked first, capped to the top 15 with a "showing top N of M" note — linkout only, never run).
- **Surgical recon, not all-or-nothing** — the **Run Recon** split-button chooses how heavy to go: a
  single click runs a fast **Quick** scan (top-1000 TCP), and its ▾ menu offers every profile
  (Quick / Default / Full / Exam), a custom scan, and **category-grouped nmap presets** (Fast /
  Full-TCP / Version / UDP / Firewall-IDS-evasion / AD-Windows / Service / Host-discovery / OS-Vuln,
  filterable, each with a "what it's for" note). Each service panel is likewise granular (e.g. SMB:
  full recon, or just null-session / guest / shares).
- **Stop any scan** — while recon runs, the **Run** button becomes a red **⏹ Stop**, and a status
  bar shows every in-flight scan with its own **⏹ Stop** (plus Stop-all) so a long scan is never
  something you're stuck watching. `Ctrl+.` stops everything.
- **Custom & range scanning** — a "Scan a host / range" dialog with full nmap-flag control (scan type
  `-sT`/`-sS`/`-sU`/`-sn`, `-Pn`, ports, timing, NSE, free-form extra flags) and a live preview + raw-edit
  escape hatch. Target can be a single IP **or a whole `/24`**.
- **Pivot tab** — a dedicated, guided **ligolo-ng** command-builder for reaching an internal network from
  a foothold. Fill in your tun0 IP / port / interface / routes and the copy-paste steps update live, with
  a **Linux ↔ Windows** switch that swaps the agent delivery (wget+chmod vs PowerShell `iwr`/certutil).
  Inline how-to + GitHub / releases / docs links + a version-currency note (ligolo-ng changes often). Nabu
  never runs ligolo — it's the "shown, you run it" model. From the same tab: *import a pivot scan* or
  *scan a host / range* through the tunnel.
- **Pivot topology** — scan an internal `/24` and hosts **stream** into the recon tree and the graph as
  they're found, grouped by subnet with the pivot source they were reached through. Right-click to remove
  a host or subnet, or re-scan a host deeper — the tree and graph stay in sync.
- **BloodHound-style graph** (`Ctrl+G`) — icon nodes with corner glyphs (danger / OS / status / note),
  a **progressive drill-down** pivot topology: it opens centred on one node (the entry) and expands on
  **double-click** (`entry → /24 → host → service`, all connected by lines), re-laying-out into a clean
  tree so nodes spread instead of stacking; double-click the entry to collapse it all back to one node.
  **Single-click** a node for its full detail (IP / OS / service+version / a /24's host count) and a
  note, without leaving the graph. Zoom with +/− or the wheel, drag to pan (hand cursor), drag a node
  to move it. Plus a native always-visible summary tree so scan data shows even where QtWebEngine can't
  render, a **credential vault** (shown in full, `0600`, click-away autosave), **audit trail**, and an
  **Obsidian-ready `report.md`** with a pivot-topology section.
- **Exploitation tab** (owner-authorized, human-driven) — clearly separated from Recon. It surfaces the
  services found on *this* box first and, across **183 services / 3,187 actions** mined from
  the vault (AD, web/port-80, SMB, databases, mail, app servers, CVE-technique targets, …), shows the
  exact attack command pre-filled from the profile + a chosen vault credential. **Nothing auto-runs**:
  you pick an action and press **Run ▸**, which confirms the target before executing **one** command
  (never a chain), then **Parse** extracts dumped hashes/creds into the vault. Attacker-side actions get
  a Run button; victim-side privesc/reverse-shells are copy-only. The **Active Directory** service is
  exhaustively covered (143 actions: PowerView/LOTL/BloodHound enum, Kerberos incl. Rubeus, ADCS ESC,
  coercion, delegation/ACL abuse, DCSync/gMSA/DPAPI, DCOM/winrs lateral, noPac/PrintNightmare/Zerologon,
  SCCM). Two copy-only helpers: a **🔍 GTFOBins** lookup (search a SUID/sudo binary → the break-out)
  and a **🎯 msfvenom payload builder** (platform → payload → format → the command **plus its listener**;
  exam-safe non-meterpreter default). Exam-legal by the OSCP+ guide (manual attack scripts allowed);
  SQLmap/Metasploit-modules are never shipped as actions.
- **Workspace dashboard** — searchable/filterable table of every project, with locking, health checks,
  and portable `<name>.tar.gz` import/export.
- **12 built-in themes** (Light · Dark · HTB · Leet · Amber · Synthwave · Dracula · Nord · Gruvbox · Solarized · Tokyo Night · Monokai), offline splash, and a **diagnostics log** (Help → View Diagnostics Log).

## Quickstart

**The easy way (Kali/Debian).** One script installs the wrapped recon tools, `uv`, Nabu itself, and
puts `nabu` / `nabu-cli` on your PATH. It's **non-interactive** (never stops to ask), safe to
re-run, and **won't break your Kali**: it installs only the tools you're *missing* (never
force-upgrades an installed one, so it can't trigger a rolling-release partial upgrade), resolves
package names to what actually exists on your release, and **dry-runs the plan first — aborting the
tool step if apt would remove or downgrade anything** (it tells you to `sudo apt full-upgrade`
instead). Nabu's own setup is a self-contained virtualenv that can't touch your system.

```bash
# 1. clone
git clone https://github.com/7H35C4r3Cr0W/recon.git ~/oscp-recon
cd ~/oscp-recon

# 2. install everything — guided and non-interactive; only the tools you're missing are added,
#    after a dry-run that refuses to remove/downgrade anything on your system
#    (./install.sh --help explains every step; --with-spray also installs hydra/medusa, §2a)
./install.sh

# 3. use it (a new terminal, if the installer said ~/.local/bin wasn't on PATH yet)
nabu-cli doctor         # check the host has the wrapped tools
nabu                    # launch the GUI
```

**Manual / other OS.** Install the wrapped tools yourself (see [Requirements](#requirements)), then
set up the app with `uv`. The console scripts live inside the project's `.venv`, so either run them
with `uv run`, or put them on your PATH with `packaging/install-desktop.sh`:

```bash
git clone https://github.com/7H35C4r3Cr0W/recon.git ~/oscp-recon && cd ~/oscp-recon
uv sync                       # create the venv and install Nabu + deps

uv run nabu-cli doctor        # check the wrapped tools
uv run nabu                   # launch the GUI  (uv run python -m oscprecon is equivalent)
```

> **Heads-up:** after `uv sync`, a *bare* `nabu` / `nabu-cli` will say `command not found` — the
> scripts are in `.venv/bin`, which isn't on your PATH. Use `uv run nabu …`, or run
> `packaging/install-desktop.sh` (or `./install.sh`) once to add the `~/.local/bin` symlinks.

On first launch Nabu creates its workspace at `~/oscprecon/` and opens to the Workspace dashboard.

## Requirements

- Python 3.11+ and [uv](https://docs.astral.sh/uv/).
- Kali Linux (or any host with the wrapped tools on `PATH`). Nabu never installs these — `nabu-cli
  doctor` reports which are missing. Install the common set on Kali:

  ```bash
  sudo apt update && sudo apt install -y \
    nmap feroxbuster gobuster ffuf dirsearch nikto whatweb wpscan \
    smbclient smbmap enum4linux-ng rpcclient impacket-scripts \
    netexec ldap-utils snmp onesixtyone dnsrecon dnsutils \
    ike-scan nbtscan ntpdate seclists exploitdb
  ```

  Or let Nabu offer to install the missing allow-listed tools for you (asks before each `apt`):
  `nabu-cli doctor --install`.

## Usage

### GUI

`nabu` launches the three-pane desktop app (service tree · command builder + output + follow-ups ·
HackTricks/Exploit-DB reference), plus the graph view (`Ctrl+G`) and the workspace dashboard
(`Ctrl+0`). Nothing runs itself — you click **Run** on every command, and each one is shown in full.

### CLI — a real example

The headless CLI (`nabu-cli`) is handy for scripting and quick scans. A scan streams nmap live and
writes everything into a self-contained project folder:

```console
$ nabu-cli scan 10.10.10.100 --profile htb-active
   {o,o}   Nabu — Local Recon Workspace
   |)__)   v0.0.1 · recon-first · OSCP exam-legal by default
   -"-"-   offline · human-confirmed exploitation · no AI at runtime

[profile] /home/kali/oscprecon/htb-active  (scan profile: default)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.4p1
80/tcp   open  http          nginx 1.18.0
445/tcp  open  microsoft-ds  Windows Server 2019
161/udp  open  snmp
# → results saved under ~/oscprecon/htb-active/nmap/*.txt and recorded in profile.json
```

Reopen the same folder in the GUI (or `--resume` on the CLI, or `Scan → Resume Recon` in the GUI) and
the whole state comes back. **The CLI is at feature parity with the GUI** for automatable work — the
same engine, nothing GUI-only:

- **Recon:** `nabu-cli scan` (staged nmap), `nabu-cli enum <service> -p <profile>` (run a service's
  Tier-1 enumeration headlessly — SMB null-session, SNMP walk, FTP/SMTP/… — the same steps the GUI
  panels run), `nabu-cli findings -p <profile>` (browse structured findings).
- **Project management:** `nabu-cli list` (workspace dashboard), `open`/`import-project`/`export-project`
  /`export-vault`/`delete-project`, `nabu-cli health -p <profile> [--repair]`, `nabu-cli activity`.
- **Credentials:** `nabu-cli creds add|list|rm -p <profile>` (the vault, chmod-600, secrets shown in full).
- **References / helpers:** `nabu-cli doctor [--install]`, `nabu-cli searchsploit <product> [version]`,
  `nabu-cli exploit [service]` (the Exploitation catalog, display-only), `nabu-cli payload` (msfvenom
  builder), `nabu-cli gtfobins [binary]`, `nabu-cli pivot` (ligolo-ng, `--os linux|windows`), `nabu-cli docs`.
- **Opt-in modes (§2a/§2b):** `nabu-cli config --spray/--exploit` toggles the gates; `nabu-cli spray
  <service> -p <profile>` runs an OSCP-legal spray from the vault (refused while Spray mode is off,
  the exam-legal default).

Run `nabu-cli --help` (or `nabu-cli <command> --help`) for the full surface.

**Scan profiles** — `quick` (top-1000 only), `default`, `full` (adds the slow full UDP sweep), or
`exam` (speed-tuned, tight, exam-legal — no vuln NSE). Pick one in Preferences, via `Scan → Run recon
with profile`, or `nabu-cli scan --scan-profile <name>`.

## What Nabu does

- **Discovery** — two-stage nmap (TCP top-1000 → full → UDP top-100, then a versioned `-sCV` pass on
  the open ports), parsed into a service tree. Non-standard HTTP/DB ports get their own per-port nodes
  and output folders.
- **Per-service modules** — HTTP (granular feroxbuster/gobuster/ffuf/dirsearch builder), vhost, SMB
  (tiered null/guest auto-recon), FTP, SSH, DNS, LDAP, SMTP, NFS, SNMP, TFTP, NetBIOS, IKE, NTP,
  **Kerberos/AD** (KDC confirm + enum-only AS-REP/SPN follow-ups, no cracking), read-only DB modules
  (Redis, MongoDB, MSSQL, MySQL, PostgreSQL, **Oracle**), Windows/remote-access services (**RDP**,
  **WinRM**, **VNC**, **MSRPC/WMI**), mail (**IMAP**, **POP3**), HTTP-API data stores
  (**Elasticsearch**, **CouchDB**, **Docker API**, **Kubernetes**, **Memcached**),
  **rsync**, **AJP/Tomcat**, **IPMI**, **SIP/VoIP**, **Finger**, **X11**, and the discovery/legacy
  services **Telnet**, **IPP/CUPS**, **iSCSI**, **Subversion (SVN)**, **Ident**, **mDNS**, **UPnP**,
  **Java RMI**, **OpenVPN**, **rpcbind/portmapper**, **etcd**, and **ZooKeeper**. Each ships Tier-1 auto recon, Tier-2 manual
  follow-ups, a parser, and pattern-library "recon next steps".
- **Findings & credentials** persist to `findings.json` / `creds.json` (mode `0600`); anonymous / null
  enum auto-records a credential entry that later modules consume.
- **Reports** — `report.md` (Obsidian-friendly frontmatter + callouts, prior versions archived) with a
  rendered report tab, an **Exploit-DB references** section (searchsploit EDB-IDs per service —
  lookup-only), and an **audit-trail appendix**. `File → Export to Obsidian Vault…` writes a linked
  note folder.
- **Resume** — `--resume` skips commands whose output already exists (`--force` re-runs).
- **Doctor** — `nabu-cli doctor` (Help → Doctor) checks every wrapped tool on `PATH`, the reference
  data they rely on (SecLists / nmap NSE / Exploit-DB), and exam-day host readiness (VPN tunnel up?
  workspace disk free? can nmap raw-socket scan?), with install hints. `--versions` also prints the
  installed version of each present tool.

### Reference pane (HackTricks + Exploit-DB)

For the selected service the reference pane offers three content tiers, most-reliable first:

1. **Vendored offline** — a build-time markdown snapshot (works with no internet), the reliable
   fallback; it jumps to the section matching your findings. CC BY-NC-SA — see
   [`src/oscprecon/references/hacktricks/NOTICE.md`](src/oscprecon/references/hacktricks/NOTICE.md).
2. **Live cached** — an owner-approved live fetch of the single canonical mapped page, cached under
   `~/.cache/oscprecon/` for later offline viewing. **OFF by default** (Preferences → References).
3. **Live page** — the canonical URL rendered live.

Live fetching is bounded: only the mapped page URL is requested (HTTPS, allow-listed host only), and
**your target IP, banners, findings, and credentials are never sent** — local context only chooses
which local sections to show. Exploit-DB stays `searchsploit` lookup + linkout only.

### Workspace dashboard

The home view (`Ctrl+0`, or shown on startup with no profile) is a searchable, filterable table of
every profile under the workspace root — built off the GUI thread, tolerant of corrupt/partial
profiles (they surface as ⚠ warning rows, never hidden). It shows target, status, tags, last activity,
and service/finding/**credential counts** (counts only — secret values never appear anywhere).

- **Organize** — per-profile status (new/active/needs-review/blocked/completed), tags, pin, and
  archive (archive hides by default and never deletes). Right-click for actions; bulk tag/status/
  archive/report/export/health across a selection.
- **Global search** — across names, targets, tags, services, ports, findings, notes, report headings,
  commands, and credential **usernames/domains**. Passwords/tokens/keys are never indexed or shown.
- **Saved views** — reusable filters (Pinned, Confirmed credentials, Missing a report, Failed scans,
  Windows, PostgreSQL, …) plus your own.
- **Health** — a read-only per-profile scan (corrupt/truncated JSON, stale temp files, orphaned
  output, world-readable creds, path escapes) with opt-in safe repairs that back up before changing.
- **Activity** — a human-readable timeline derived from the audit log (secrets shown in full).
- **Locking & read-only** — opening a profile takes an advisory `<profile>/.lock`; a profile already
  open elsewhere offers **read-only** (title shows `[READ-ONLY]`, every write is blocked, export still
  works). Stale locks (dead PID, same host) are recovered automatically; live/foreign ones are never
  stolen.
- **Portable projects** — each profile folder is self-contained. `File → Open by IP…` finds a profile
  by its target IP; `Import Project…` / `Export Project…` move a profile between machines as a
  path-traversal-safe `<name>.tar.gz` (export **warns that `creds.json` is included**). Headless
  equivalents: `nabu-cli export-project` / `import-project`.

### Preferences

`File → Preferences…` (`Ctrl+,`) opens a tabbed settings dialog, persisted atomically to
`~/.config/oscprecon/prefs.json`:

- **Workspace** — workspace root (created on save if missing).
- **Appearance** — a 12-theme picker (Light, Dark, HTB, Leet, Amber, Synthwave, Dracula, Nord, Gruvbox, Solarized, Tokyo Night, Monokai) and an optional application font-size override (applied live).
- **Tool paths** — wordlist search paths (password lists are always filtered out and never shown).
- **Scan** — default scan profile (quick/default/full/exam) + opt-in full UDP port sweep (default
  stays UDP top-100).
- **Reports** — the fixed report-archiving guarantees, shown for reference (secrets are shown in full
  by default; a `redact_secrets` toggle ships off for a hypothetical shared build).
- **Privacy** — the mandatory secret protections (§2), displayed locked-on; they cannot be disabled.
- **Performance** — cap on concurrent recon workers.
- **Advanced** — config-file location and *Reset all settings to defaults*.

Invalid values fall back to safe defaults; out-of-range numbers are clamped.

### Profile layout

Each box is a self-contained folder under the workspace root (default `~/oscprecon/`):

```
~/oscprecon/<name>/
├── profile.json          metadata · discovered services · command history
├── findings.json  creds.json (0600)  graph.json  notes.md  report.md
├── audit.jsonl           append-only GUI action log
└── nmap/ http/ smb/ …    per-service output folders
```

## Safety boundaries (OSCP exam-legal by default)

Recon-first and **exam-legal by default**, with **no LLM calls at runtime** — see
[`CLAUDE.md`](CLAUDE.md) §2. In the default recon mode every command runs through one chokepoint
(`shell.run` → `policy_violation`) that refuses non-allow-listed tools, brute/spray flags, and
file-write / OS-exec DB primitives; the wordlist picker hides `Passwords/` and credential attempts are
single-shot Tier-2 actions the user clicks. **SQLmap and Metasploit exploitation modules are never
shipped as one-click actions** (a test enforces this).

**Exploitation** happens only in the separate, **owner-authorized Exploitation tab** (§2b) — and only
because *you* pick an action and **confirm each Run**. The guardrail there is the human, not an
allow-list: `policy_violation(exploit=True)` runs the exact command you selected (impacket, evil-winrm,
netexec, public PoCs, msfvenom — all OSCP-legal manual attack scripts). Nothing auto-runs, nothing
chains, and the default recon mode is untouched. This is exactly what the OSCP+ Exam Guide permits
(manual attack scripts yes; autopwn / mass scanners / Metasploit-as-a-target no).

**Credential spraying** (hydra/medusa/netexec across SMB/WinRM/LDAP/SSH/FTP/RDP) is OSCP-legal against
your own authorized targets and is supported as an **explicit, opt-in, off-by-default** mode
(`Preferences → Scan → Enable Spray mode`; §2a). With it off, recon mode blocks all brute/spray. When
on, `Edit → Credential Vault…` manages the creds and `Scan → Credential Spray…` runs single-target
sprays from them.

## Troubleshooting

If the GUI or CLI misbehaves, Nabu writes a diagnostic log (crashes, errors, Qt warnings) to
`~/.local/state/oscprecon/logs/nabu.log`. Open it in-app via **Help → View Diagnostics Log…** (with
buttons to reveal the folder or clear it). On a CLI crash the log path is printed to stderr.

## Kali app menu / taskbar icon / Desktop launcher

One idempotent script installs everything — no root required (everything lands under `$HOME`):

```bash
packaging/install-desktop.sh        # reverse with packaging/uninstall-desktop.sh
```

It installs:

- a **Nabu** launcher (GUI) in the Network/Security app menu — pin it to the taskbar; the running
  window's `WM_CLASS` matches the launcher so it groups under the pinned icon;
- a **Nabu CLI** launcher that opens the headless CLI in a terminal;
- **Desktop icons** for both (marked trusted);
- hicolor icons at every size, so `Icon=nabu` resolves in any theme;
- `nabu` and `nabu-cli` symlinks in `~/.local/bin` (already on the Kali PATH), so both run from any
  terminal.

(A single `packaging/nabu.desktop` with `Exec=nabu` also exists for AppImage/global installs.)

## Development

```bash
uv run mypy --strict src/
uv run pytest -q                       # GUI tests use QT_QPA_PLATFORM=offscreen
uv run ruff check
uv run ruff format --check
```

## Docs & further reading

- [`CLAUDE.md`](CLAUDE.md) — the full project brief and hard constraints.
- [`ROADMAP.md`](ROADMAP.md) — the phase-by-phase build plan.
- [`PROJECT_MAP.md`](PROJECT_MAP.md) — subsystem-by-subsystem status map and forward plan.

## Author

**Nabu** is created and maintained by **Lagus**
· [its.lagus@proton.me](mailto:its.lagus@proton.me)
· [github.com/7H35C4r3Cr0W/recon](https://github.com/7H35C4r3Cr0W/recon)

☕ If Nabu saves you time, you can **[buy me a coffee](https://buymeacoffee.com/lagus)** — it keeps the project going.

## License

MIT — see [`pyproject.toml`](pyproject.toml). Bundled HackTricks content is CC BY-NC-SA; see the
[NOTICE](src/oscprecon/references/hacktricks/NOTICE.md).
