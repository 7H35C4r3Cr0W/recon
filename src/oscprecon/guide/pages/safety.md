# Safety & OSCP compliance

Nabu is built to be usable **during** the OSCP exam, not just for prep. The default mode is
exam-legal, and the guardrails are deliberate.

## What the default (recon) mode allows

Standard OSCP-permitted enumeration, wrapped for convenience:

- `nmap` with full NSE (`-sC`, `--script vuln`, `smb-*`, `http-*`).
- Web content discovery — `feroxbuster`, `gobuster`, `ffuf`, `dirsearch`, `dirb`.
- Web fingerprint — `nikto`, `whatweb`, `curl`, `wget`.
- WordPress — `wpscan --enumerate` (never `--passwords`).
- SMB / AD enum — `enum4linux-ng`, `smbclient`, `smbmap`, `rpcclient`, `netexec` (enum modes only).
- `ldapsearch`, `snmpwalk`, `onesixtyone`, `dnsrecon`, `dig`, impacket **enum** scripts.
- `searchsploit` — **display only**, results are never executed.

## What is never wrapped as a default action

- **Credential brute / spraying** in the default mode (`hydra`, `medusa`, list-driven `netexec`,
  `wpscan --passwords`). These are supported **only** in opt-in Spray mode — see
  **Exploitation & spraying**.
- **Metasploit exploitation modules** and meterpreter-as-shell. (The **msfvenom** payload builder is
  a copy-only carve-out, explicitly allowed by the OSCP+ guide.)
- **SQLMap**, commercial scanners (Nessus, Burp Pro), and any **AI / LLM call at runtime**.
- **Automated exploit chains** — no scan → match → run-exploit pipeline anywhere.
- **Downloading / executing an Exploit-DB PoC** — lookup and link-out only.

## The credential tiers

| Tier | What | Behaviour |
| --- | --- | --- |
| **1 — Auto** | Null / anonymous checks; a well-known account with an empty password | Runs on one click |
| **2 — Shown** | A *single* attempt at a default cred (`administrator:''`, `sa:sa`) | Pre-filled; you click Run |
| **3 — Gated** | Iterating a *list* of credentials (spraying) | OFF by default; opt-in Spray mode only |

A single attempt against a well-known account is recon-adjacent. **Iterating a list is spraying** —
OSCP-legal against your authorized target, but gated behind Spray mode and never on by default.

The tiers are about **guessing**. Using a credential you *already hold* is none of them — that is
authenticated enumeration, the first thing you do after a foothold, and the **Run as** picker on the
service panels (or `nabu-cli enum <svc> --as <user>`) exists for it. The secret comes from the project
vault, one credential at a time; anonymous stays the default.

## Offline & private

No network at runtime except probing the target itself, rendering the reference pane, and the
owner-approved HackTricks fetch of the single mapped page (opt-in). Target data, credentials,
findings, and notes are **never** transmitted anywhere.

> The authoritative rules live in `CLAUDE.md` §2.
