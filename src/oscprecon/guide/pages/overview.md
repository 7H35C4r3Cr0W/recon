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
- **Pivot (separate tab).** A guided, **end-to-end ligolo-ng** command-builder for reaching an
  internal network from a foothold — the whole flow, spelled out for beginners: **download the
  binaries off GitHub → find your tun0 IP → start the proxy → serve + pull the agent onto the target
  → build the tunnel → scan through it**. A **Linux ↔ Windows** switch swaps the agent delivery and
  reorders the transfer menus; the steps fill your tun0 IP + routes live. A **reference section**
  lists *every* way to serve the agent (python/php/ruby/busybox/updog/SMB), pull it onto a Windows or
  Linux target (IWR / WebClient / certutil / curl / bitsadmin / SMB · wget / curl), tunnel reverse
  shells + files back through the pivot (`listener_add`), transfer filelessly in a stripped shell
  (base64), and the ligolo console command reference — plus SSH/chisel/sshuttle/socat/plink for when
  ligolo isn't an option. Nabu never runs ligolo; you copy each command. `nabu-cli pivot` prints the
  same thing headless.

## The shape of a session

1. **New project** → enter an IP (and optionally a hostname like `box.htb`).
2. **Run Recon** → staged nmap discovers services; per-service modules enumerate them.
3. Work the **three panes**: services on the left, the command builder + output in the middle,
   HackTricks + Exploit-DB on the right.
4. Flip to the **graph** (`Ctrl+G`) to see the attack surface, annotate nodes, mark status.
5. Everything lands in an **Obsidian-ready `report.md`** and a **credential vault** (loot is shown in
   full — this is your own tool against your own authorized targets, so nothing is redacted).

## Names

Internal Python package `oscprecon`; installs as `oscp-recon`. Entry points: **`nabu`** (GUI) and
**`nabu-cli`** (headless). The `oscprecon` / `oscprecon-cli` aliases still work.

> The whole design brief lives in `CLAUDE.md`; this guide is the user-facing subset.

## Credits

Nabu is built and maintained by **Lagus** — [github.com/7H35C4r3Cr0W/recon](https://github.com/7H35C4r3Cr0W/recon)
· [its.lagus@proton.me](mailto:its.lagus@proton.me). If it saves you time on a box or the exam, you can
[**buy me a coffee** ☕](https://buymeacoffee.com/lagus). Same credit shows in **Help → About** and
`nabu-cli --version`.
