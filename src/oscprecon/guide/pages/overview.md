# Overview

**Nabu** is a *recon-first, OSCP-exam-legal* desktop workspace. It orchestrates the standard
enumeration tools you already use — `nmap`, `feroxbuster`/`gobuster`/`ffuf`, `nikto`/`whatweb`,
`smbclient`/`netexec`, and more — then **structures what they find**: a service tree, a
BloodHound-style attack-surface graph, inline HackTricks + Exploit-DB references, and an
Obsidian-friendly report.

It runs **offline** and makes **no LLM calls at runtime**.

## Two modes, one app

- **Recon (default).** Exam-legal by design — read-only enumeration only. This is what you use
  during the exam. Nothing here brute-forces credentials or auto-exploits.
- **Exploitation (separate tab, owner-authorized).** A human-driven attack console: it *builds* the
  exact command, *runs* it only when **you** press **Run** and confirm the target, and *parses* the
  output into loot. Nothing auto-runs, nothing chains. See **Exploitation & spraying**.
- **Pivot (separate tab).** A guided **ligolo-ng** command-builder for reaching an internal network
  from a foothold — a **Linux ↔ Windows** switch swaps the agent delivery, the steps update live, and
  inline how-to + GitHub/releases links keep it current. Nabu never runs ligolo; you copy and run each
  command. Once the route is up, *scan a host / range* through the tunnel from the same tab.

## The shape of a session

1. **New project** → enter an IP (and optionally a hostname like `box.htb`).
2. **Run Recon** → staged nmap discovers services; per-service modules enumerate them.
3. Work the **three panes**: services on the left, the command builder + output in the middle,
   HackTricks + Exploit-DB on the right.
4. Flip to the **graph** (`Ctrl+G`) to see the attack surface, annotate nodes, mark status.
5. Everything lands in an **Obsidian-ready `report.md`** and a masked **credential vault**.

## Names

Internal Python package `oscprecon`; installs as `oscp-recon`. Entry points: **`nabu`** (GUI) and
**`nabu-cli`** (headless). The `oscprecon` / `oscprecon-cli` aliases still work.

> The whole design brief lives in `CLAUDE.md`; this guide is the user-facing subset.
