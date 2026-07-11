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
