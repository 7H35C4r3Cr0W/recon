# Getting started

## Install (Kali / Debian, Python 3.11+ and uv)

```bash
git clone https://github.com/7H35C4r3Cr0W/recon.git ~/oscp-recon && cd ~/oscp-recon
uv sync                 # create the venv and install deps
uv pip install -e .     # install the console scripts (nabu, nabu-cli)
```

Then check your host has the wrapped tools:

```bash
nabu-cli doctor         # prints an install hint for anything missing
```

`doctor` only reports — it never installs behind your back. `doctor --install` will offer to
`apt install` the missing **allow-listed** (recon) tools, asking first. It also lists — but never
auto-installs — the **Spray-mode** (§2a) and **Exploitation-tab** (§2b) tools (evil-winrm, certipy,
impacket-secretsdump, responder, hashcat, …) with their install hints, so you can confirm your
attack tools are present before exam day. Those span apt/pipx/gem, so you install the ones you use.

## Launch

```bash
nabu                    # the GUI  (python -m oscprecon is equivalent)
nabu-cli scan 10.10.10.5 --profile htb-active   # headless staged nmap
nabu-cli enum smb -p htb-active                 # run a service's Tier-1 recon headlessly
nabu-cli findings -p htb-active                 # browse what was found
nabu-cli list                                   # your workspace projects
nabu-cli creds list -p htb-active               # the vault (secrets shown in full)
nabu-cli docs           # this documentation, in the terminal
```

The **CLI is at feature parity with the GUI** for automatable work — `scan`, `enum`, `findings`,
`creds` (add/list/rm), `list`, `health`, `activity`, `delete-project`, `searchsploit`, `exploit`,
`payload`, `gtfobins`, `pivot`, `export-*`/`import-project`, and the gated `spray`/`config`. Run
`nabu-cli --help` for the full surface. (The settings-heavy web/SMB panels — wordlist-driven content
discovery, tiered SMB — stay richest in the GUI.)

## Your first scan (GUI)

1. **File → New Scan Profile** (`Ctrl+N`). Give it a name and the target IP. If you know the box's
   hostname (e.g. `active.htb`), set it here — host-based recon then targets the name, not the IP,
   and the app shows you the exact `/etc/hosts` line to add.
2. Click **Run Recon**. A single click runs a fast **Quick** scan; the **▾** menu offers heavier
   profiles (Default / Full / Exam), a custom scan, or individual nmap presets.
3. Discovered services stream into the tree on the left. Click one to load its command builder
   (middle) and its HackTricks page + Exploit-DB hits (right).

## Where your data lives

- **Workspace:** `~/oscprecon/` (each project is a self-contained folder — change the root in
  Preferences).
- **Config:** `~/.config/oscprecon/`
- **Cache:** `~/.cache/oscprecon/`
- **Diagnostics log:** `~/.local/state/oscprecon/logs/` (Help → View Diagnostics Log)

A project folder holds everything — `profile.json`, `findings.json`, `creds.json` (chmod `0600`),
`graph.json`, `notes.md`, and the generated `report.md` — so you can back it up or move it with
**File → Export Project** (a `.tar.gz`).
