# oscp-recon

A **recon-only**, OSCP-exam-legal desktop GUI that orchestrates standard enumeration tools
(nmap, feroxbuster/gobuster/ffuf, nikto/whatweb, smbclient/netexec, …), links each service to
HackTricks and Exploit-DB, and produces Obsidian-friendly reports. It does **not** exploit,
brute-force credentials, or call any LLM at runtime.

See [`CLAUDE.md`](CLAUDE.md) for the full project brief and hard constraints, [`ROADMAP.md`](ROADMAP.md)
for the phase plan, and [`PROGRESS.md`](PROGRESS.md) for the current build state.

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
- **Per-service modules** — HTTP (granular feroxbuster/gobuster/ffuf/dirsearch builder), vhost, SMB
  (tiered null/guest auto-recon), FTP, SSH, DNS, LDAP, SMTP, NFS, SNMP, TFTP, NetBIOS, IKE, NTP, and
  read-only DB modules (Redis, MongoDB, MSSQL, MySQL). Each ships Tier-1 auto recon, Tier-2 manual
  follow-ups, a parser, and pattern-library "recon next steps".
- **Findings & credentials** persist to `findings.json` / `creds.json` (mode 600); anonymous/null
  enum auto-records a credential entry consumed by later modules.
- **Reports** — `report.md` (Obsidian-friendly frontmatter + callouts, prior versions archived) with a
  rendered report tab. `File → Export to Obsidian Vault…` writes a linked note folder.
- **Resume** — `--resume` skips commands whose output already exists (`--force` re-runs).
- **Doctor** — `oscprecon-cli doctor` checks every wrapped tool on `PATH` and prints install hints.

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
