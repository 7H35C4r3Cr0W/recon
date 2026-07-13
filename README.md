# oscp-recon

A **recon-only**, OSCP-exam-legal desktop GUI that orchestrates standard enumeration tools
(nmap, feroxbuster/gobuster/ffuf, nikto/whatweb, smbclient/netexec, …), links each service to
HackTricks and Exploit-DB, and produces Obsidian-friendly reports. It does **not** exploit,
brute-force credentials, or call any LLM at runtime.

See [`CLAUDE.md`](CLAUDE.md) for the full project brief and hard constraints, [`ROADMAP.md`](ROADMAP.md)
for the phase plan, [`PROJECT_MAP.md`](PROJECT_MAP.md) for the subsystem-by-subsystem status map and
forward plan, and [`PROGRESS.md`](PROGRESS.md) for the detailed build log.

## Requirements

- Python 3.11+ and [uv](https://docs.astral.sh/uv/)
- Kali Linux (or any host with the wrapped tools on `PATH`). The tool never installs these; it
  reports missing ones. Install the common set on Kali:

  ```bash
  sudo apt update && sudo apt install -y \
    nmap feroxbuster gobuster ffuf dirsearch nikto whatweb wpscan \
    smbclient smbmap enum4linux-ng rpcclient impacket-scripts \
    netexec ldap-utils snmp onesixtyone dnsrecon dnsutils \
    ike-scan nbtscan ntpdate seclists exploitdb
  ```

## Install

```bash
git clone <repo>/oscp-recon.git ~/oscp-recon && cd ~/oscp-recon
uv sync                 # create the venv and install deps
uv pip install -e .     # install the console scripts (oscp-recon, oscprecon-cli)
```

After `uv pip install -e .` the GUI is launchable from any terminal:

```bash
oscp-recon              # launch the GUI
python -m oscprecon     # equivalent
oscprecon-cli scan 10.10.10.10 --profile htb-box   # headless nmap
```

## What it does

Three-pane desktop GUI (service tree · command builder + output + follow-ups · HackTricks/Exploit-DB
reference), plus a Bloodhound-style graph view (`Ctrl+G`).

- **Discovery** — two-stage nmap (TCP top-1000 → full → versioned on found ports; UDP top-100),
  parsed into a service tree. Non-standard HTTP/DB ports get their own per-port nodes and output.
  Pick a **scan profile** — `quick` (top-1000 only), `default`, `full` (adds the slow full UDP sweep),
  or `exam` (speed-tuned, tight, exam-legal — no vuln NSE) — via Preferences, `Scan → Run recon with
  profile`, or `oscprecon-cli scan --scan-profile`.
- **Per-service modules** — HTTP (granular feroxbuster/gobuster/ffuf/dirsearch builder), vhost, SMB
  (tiered null/guest auto-recon), FTP, SSH, DNS, LDAP, SMTP, NFS, SNMP, TFTP, NetBIOS, IKE, NTP, and
  read-only DB modules (Redis, MongoDB, MSSQL, MySQL, PostgreSQL). Each ships Tier-1 auto recon, Tier-2 manual
  follow-ups, a parser, and pattern-library "recon next steps".
- **Findings & credentials** persist to `findings.json` / `creds.json` (mode 600); anonymous/null
  enum auto-records a credential entry consumed by later modules.
- **Reports** — `report.md` (Obsidian-friendly frontmatter + callouts, prior versions archived) with a
  rendered report tab, including an **Exploit-DB references** section (searchsploit EDB-IDs surfaced per
  service — lookup-only, no PoC fetched or run). `File → Export to Obsidian Vault…` writes a linked note
  folder.
- **Resume** — `--resume` skips commands whose output already exists (`--force` re-runs).
- **Doctor** — `oscprecon-cli doctor` checks every wrapped tool on `PATH` and prints install hints.

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
- **Activity** — a human-readable timeline derived from the audit log (secrets redacted).
- **Locking & read-only** — opening a profile takes an advisory `<profile>/.lock`; a profile already
  open elsewhere offers **read-only** (title shows `[READ-ONLY]`, every write is blocked, export still
  works). Stale locks (dead PID, same host) are recovered automatically; live/foreign ones are never
  stolen.
- **Portable projects** — each profile folder is self-contained. `File → Open by IP…` finds a profile
  by its target IP; `Import Project…` / `Export Project…` move a profile between machines as a
  path-traversal-safe `<name>.tar.gz` (export **warns that `creds.json` is included**). Headless
  equivalents: `oscprecon-cli export-project` / `import-project`.

### Preferences

`File → Preferences…` (`Ctrl+,`) opens a tabbed settings dialog, persisted atomically to
`~/.config/oscprecon/prefs.json`:

- **Workspace** — workspace root (created on save if missing).
- **Appearance** — light/dark theme and an optional application font-size override (applied live).
- **Tool paths** — wordlist search paths (password lists are always filtered out and never shown).
- **Scan** — default scan profile (quick/default/full/exam) + opt-in full UDP port sweep (default
  stays UDP top-100).
- **Reports** — the fixed redaction/archiving guarantees, shown for reference.
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

Recon-only. **No** exploitation, credential brute force / spraying, Metasploit, SQLMap, or LLM calls
at runtime — see [`CLAUDE.md`](CLAUDE.md) §2. Every command runs through one chokepoint
(`shell.run` → `policy_violation`) that refuses non-allow-listed tools, brute/spray flags, and
file-write / OS-exec DB primitives. The wordlist picker hides `Passwords/`. Credential attempts are
single-shot Tier-2 actions the user clicks — never automated, never list-driven.

## Kali app menu / taskbar icon

```bash
cp share/applications/oscp-recon.desktop ~/.local/share/applications/
update-desktop-database ~/.local/share/applications/
```

`oscp-recon` then appears under the Network/Security app menu (placeholder terminal icon;
swap `Icon=` in the `.desktop` for your own).

## Development

```bash
uv run mypy --strict src/
uv run pytest -q                       # GUI tests: QT_QPA_PLATFORM=offscreen
uv run ruff check
uv run ruff format --check
```
