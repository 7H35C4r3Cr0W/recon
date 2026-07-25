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

## Run in Docker (any host — Kali, Parrot, Ubuntu, macOS, Windows)

Prefer not to touch your host's packages? Run Nabu as a container — the whole Kali toolset is baked
**into the image**, so your host's `apt` is never involved and it runs the same everywhere Docker
does. **The host distro doesn't matter (Parrot works exactly like Kali)** because the tools live in
the container, not on your host.

```bash
docker/nabu-docker.sh build                    # build once (~4GB: all tools + Nabu)
docker/nabu-docker.sh doctor                   # headless: check the toolset
docker/nabu-docker.sh scan 10.10.10.5 -p box   # a scan — persists to ~/.nabu on your host
docker/nabu-docker.sh gui                       # the desktop GUI (forwards your X11 display)
docker/nabu-docker.sh shell                     # a shell inside the container
```

Scans/creds/notes persist on your host at `~/.nabu` (override with `NABU_DATA=…`). `--network host`
gives the container your VPN tun + raw-socket nmap on Linux. The GUI needs an X11 server (native on
Linux/Parrot; XQuartz on macOS; WSLg on Windows).

## Launch

```bash
nabu                    # the GUI  (python -m oscprecon is equivalent)

# --- recon ---
nabu-cli scan 10.10.10.5 -p htb-active                 # staged nmap (quick/default/full/exam)
nabu-cli scan 10.10.10.5 -p htb-active --scan-profile exam   # full sweep, rate-boosted
nabu-cli enum smb -p htb-active                        # a service's Tier-1 recon, headless
nabu-cli vuln smb -p htb-active                        # NSE vuln checks for a discovered service
nabu-cli vuln -p htb-active --all                      # ...every discovered service
nabu-cli findings -p htb-active                        # browse what was found
nabu-cli searchsploit vsftpd 2.3.4                     # offline Exploit-DB lookup

# --- tie discovered hosts to /etc/hosts (no more hand-editing) ---
nabu-cli hosts 10.10.10.5 research.bedside.htb         # add one discovered vhost (needs root)
nabu-cli hosts 10.10.10.5 dc01.corp.local corp.local  # several names -> one IP
nabu-cli hosts -p htb-active                           # add EVERYTHING discovered, in one go

# --- attack (display-only; copy a command to run it) ---
nabu-cli exploit smb -p htb-active                     # SMB attacks, pre-filled from the profile
nabu-cli exploit ad -p htb-active                      # the full Active Directory catalog
nabu-cli exploit web -p htb-active --port 8080         # web attacks aimed at port 8080
nabu-cli exploit mssql -p htb-active -t 10.10.10.7     # aim at a SPECIFIC host (one IP of a /24)

# --- workspace / vault ---
nabu-cli list                                          # your workspace projects
nabu-cli creds list -p htb-active                      # the vault (secrets shown in full)
nabu-cli docs                                          # this documentation, in the terminal
```

The **CLI is at feature parity with the GUI** for automatable work — `scan`, `enum`, `findings`,
`creds` (add/list/rm), `list`, `health`, `activity`, `delete-project`, `searchsploit`, `exploit`,
`payload`, `gtfobins`, `pivot`, `export-*`/`import-project`, and the gated `spray`/`config`. Run
`nabu-cli --help` for the full surface. (The settings-heavy web/SMB panels — wordlist-driven content
discovery, tiered SMB — stay richest in the GUI.)

**Every command self-documents.** `nabu-cli --help` shows the typical workflow; `nabu-cli scan --help`
lays out the scan batteries (`quick` / `default` / `full` / `exam`), every flag, and copy-paste
examples — so you never have to guess the syntax. The same holds for `enum`, `searchsploit`, `payload`,
`creds`, and the rest.

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
