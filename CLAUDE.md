# oscp-recon — Claude Code project brief

**This file is auto-loaded by Claude Code as project context.** It is the single source of truth for what this project is, what it must NOT do, how it is built, and how you (Claude Code) should behave when working on it. Read it fully before proposing any change.

> **▶ CONTINUING PRIOR WORK / CONTEXT WAS RESET?** Read [`HANDOFF.md`](HANDOFF.md) first — it has the current repo HEAD, the four gates, how the owner wants work done, the adversarial-review workflow, what's already been swept, and what to do next. This file (CLAUDE.md) is the full brief and the rules; HANDOFF.md is the short "pick up where we left off" companion.

Companion files in this repo elaborate specific slices — `ROADMAP.md` for phase-by-phase build order, `prompts/*.md` for paste-able sequenced work chunks, `boxes/TRACKER.md` for the study list — but everything critical is in this file.

---

## 1. What this project is

**The product is named "Nabu"** (*Local Recon Workspace*) — the user-facing brand. The **internal Python package stays `oscprecon`** and the distribution/wheel name stays `oscp-recon` (renaming either buys nothing and breaks installs/imports/data paths). Preferred entry points are `nabu` (GUI) and `nabu-cli` (headless); `oscp-recon` / `oscprecon` / `oscprecon-cli` remain as legacy aliases. Data paths are unchanged: workspace `~/oscprecon/`, config `~/.config/oscprecon/`, cache `~/.cache/oscprecon/`, diagnostics logs `~/.local/state/oscprecon/` (XDG state; see § 19a). See `docs/OWNER_DECISIONS.md`.

A **PySide6 desktop GUI recon orchestrator** for OSCP exam prep and exam day, built in Python. It runs on Kali Linux. Two goals in parallel:

1. **Learn** — work each box on Lain Kusanagi's OSCP-like list manually to build muscle memory.
2. **Build** — turn each box's lessons into reusable, OSCP-exam-legal recon automation.

The tool is **recon-first**. It wraps standard OSCP-allowed enumeration tools, surfaces findings in a Bloodhound-style graph, links inline to HackTricks and Exploit-DB references, and produces Obsidian-friendly markdown reports. It does **not** auto-exploit, chain attacks, or call any LLM at runtime — the engine never executes an exploit. **Credential spraying** — OSCP-legal against your own authorized targets — is supported as an **explicit, opt-in, off-by-default** capability (see § 2a); with Spray mode **off** (the default) the tool is strictly recon-only and blocks all brute/spray. A separate, owner-authorized **Exploitation tab** (see § 2b) lets the user run exploitation / post-ex **by hand** — it *builds* the command (pre-filled from the profile + a vault cred), *runs* it on an explicit, **human-confirmed** Run (`shell.run(exploit=True)` — one command, never a chain or auto-attack), and *parses* the output into loot. The guardrail is the human confirmation, not a tool block-list; the **default recon mode is unchanged and stays exam-legal**. Exploit execution is **ON by default** (`exploit_enabled`, owner 2026-07-16) — but nothing ever runs automatically; every Run is user-initiated and confirmed. The user can set the tab to shown-only in Preferences.

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
- **Vhost / subdomain:** `ffuf -H "Host: FUZZ.{domain}"`, `gobuster vhost`, `gobuster dns`, `dnsrecon -t brt`, `dnsenum --dnsserver {target}`, `wfuzz`
- **Impacket enum scripts:** `GetADUsers.py`, `GetNPUsers.py`, `GetUserSPNs.py` in enumeration context (no cracking on-host)
- **Lookups:** `searchsploit` (display only — never execute results)

### Forbidden (do NOT wrap, do NOT propose)

- **Metasploit framework (msfconsole exploitation modules) / meterpreter-as-shell** — the exam limits these to **one target total**; never for recon, never as an auto-run action, never chained. Not wrapped as an engine capability. **Exception (owner-authorized, § 2c):** the **msfvenom payload builder** — a *copy-only* reverse-shell command generator — is allowed, because the OSCP+ Exam Guide explicitly permits **msfvenom + multi/handler**. It never executes anything (no `shell.run`); it only assembles syntax the operator copies and runs. It defaults to exam-safe non-meterpreter `*_reverse_tcp` shells (no exam limit) and **flags** meterpreter payloads as counting toward the one-use limit. Metasploit *exploitation modules* stay forbidden as actions.
- **SQLMap** — exam restrictions too tight. Not wrapped.
- **Credential brute / spraying in the DEFAULT (recon-only) mode** — `hydra`, `medusa`, `patator`, `crowbar`, list-driven `netexec` spraying (`-u <list> -p <list>`, `--continue-on-success`), `wpscan --passwords`. These are **OSCP-legal against your own authorized targets** and are supported **only** in opt-in Spray mode (§ 2a); they are **never** run in the default mode, and never against the exam VPN / control panel or any out-of-scope host.
- **Commercial scanners** — Nessus, Burp Pro, Acunetix, Qualys.
- **AI / LLM calls at runtime** — banned during exam. The tool runs offline/local.
- **Automated exploit chains** — no scan → vuln-match → run-exploit → shell pipelines.
- **PoC download / execute / transform** from Exploit-DB — lookup and linkout only.
- **Anything that needs internet at runtime** — except direct probing of the target, live rendering of HackTricks / Exploit-DB pages in the reference pane, and the **owner-approved live HackTricks fetch/cache** described below (see § 14a). **Allowed exceptions:** (a) a **build-time-vendored, offline snapshot** of the open-source HackTricks **markdown** (bundled in the wheel, read from disk, **attributed** per its licence — see § 27), used for finding-aware offline section rendering; and (b) **owner-approved live HackTricks fetching** of the single canonical mapped page for the selected service, with local caching for later offline viewing (§ 14a). **The offline vendored snapshot remains the reliable fallback and is never less authoritative than the live cache.** **Still forbidden:** crawling the HackTricks site, scraping arbitrary URLs, and any scraping/download of Exploit-DB **PoC content** (Exploit-DB stays lookup + linkout only).

  **Live-fetch privacy rule (non-negotiable):** Only the canonical HackTricks page URL selected from the local `references/services.yaml` map may be fetched. Local target data (IP, hostname, banners, product, version, findings, notes, commands, credentials) is used **only** to choose and filter local display content and **must never** be transmitted as query parameters, request bodies, or headers.

### Tier framing for credential-adjacent recon

This is the line every service module must respect:

| Tier | What | Behavior |
|---|---|---|
| **Tier 1 — Auto** | Null session / anonymous access checks; single well-known account with empty password (`guest:''`) | Runs on one click, streams to output files |
| **Tier 2 — Shown, not auto** | Single-attempt default credentials against a well-known account (`administrator:''`, `admin:''`, `sa:sa`) | Pre-filled in Manual Follow-ups tab; user clicks Run |
| **Tier 3 — Gated (opt-in Spray mode)** | Iterating a list of usernames/passwords; list-driven spraying; `--continue-on-success` | **OFF by default.** Enabled only in opt-in Spray mode (§ 2a); target-scoped; user selects creds + confirms before it runs |

**Definitional line:** A single attempt against a well-known account with an empty/default password is recon-adjacent (Tier 2). Iterating a list is credential spraying (Tier 3) — OSCP-legal against authorized targets, but **gated behind opt-in Spray mode (§ 2a), off by default**.

### Content discovery vs. credential brute force

`feroxbuster`/`gobuster`/`ffuf`/`dirsearch` against web paths is **content discovery** — always allowed. Hitting a login form with a password wordlist is **credential brute force** — allowed **only** in opt-in Spray mode (§ 2a). The wordlist picker filters out `seclists/Passwords/` in the default mode, and surfaces password lists only when Spray mode is on.

### 2a. Credential spraying — opt-in, off by default

Password spraying / credential brute against **your own authorized targets** is OSCP-legal (OffSec bans automated *exploitation*, not credential attacks — verified vs. the OSCP Exam Guide/FAQ). It is therefore **supported**, but as an **explicit, opt-in capability that is OFF BY DEFAULT** so the tool stays exam-legal-by-default for anyone who runs it (this matters for the public release). Rules:

- **Off by default.** A `spray_enabled` setting (default `false`) gates everything below. With it off, `shell.run` blocks every brute/spray tool exactly as it does today, and the wordlist picker still filters `seclists/Passwords/`. Nothing about the default posture changes.
- **What Spray mode unlocks (only when on):** `hydra`, `medusa`, list-driven `netexec` spraying (`-u <list> -p <list>`, `--continue-on-success`), `wpscan --passwords`, and password wordlists in the picker — against SMB / FTP / SSH / WinRM / HTTP-login etc. on the **active profile's single target**.
- **Still forbidden even in Spray mode:** Metasploit / meterpreter, SQLMap, commercial scanners, LLM calls, automated exploit *chains*, and spraying anything other than the assigned target (never the exam VPN / control panel or an out-of-scope host — that is a hard, non-negotiable scope limit).
- **Cred vault:** sprays draw from the editable `creds.json` store (add / edit / delete in the GUI). The user selects which credentials / combinations to spray and **confirms before anything runs** — it never auto-sprays.
- **Tooling preference:** prefer `netexec` (already wrapped) for SMB/WinRM; `hydra`/`medusa` for FTP/SSH/etc. Cracked/winning secrets are shown **in full** (owner decision, § 6 — no redaction). UX: a clean, Burp-style surface.

### 2b. Exploitation tab — owner-authorized, human-driven attack console

Owner-authorized (Andre, 2026-07-15): the tool carries an **Exploitation** tab, clearly separated from Recon, for **manual** exploitation / post-exploitation. It **builds** the exact attack command (pre-filled from the profile + a chosen vault credential), **runs** it when the user presses **Run** (after a confirmation), and **parses** the output into loot. This is the AutoRecon/Tier-2 "you select it, you run it" model extended to attack tools — **never an autopwn chain**.

**The guardrail is the human, not a tool block-list.** The owner's rule (2026-07-16): *"running scripts for attacks is OK; I just want a human to attack, not blind auto-attacking."* The OSCP+ Exam Guide backs this — it forbids **automatic exploitation tools** (SQLmap, SQLninja, db_autopwn), **mass vulnerability scanners** (Nessus, OpenVAS, NeXpose, Canvas, Core Impact, SAINT), **commercial tools** (Metasploit Pro, Burp Pro), **Metasploit/Meterpreter** (one target only; msfvenom + multi/handler allowed), **spoofing**, and **AI chatbots** — but explicitly **allows** Nmap/NSE, Nikto, Burp Free, DirBuster, and **manual attack scripts** (impacket, evil-winrm, netexec, responder, certipy, hashcat/john, public PoCs). A per-command, user-selected, single-shot, human-confirmed attack is exam-legal.

Rules (non-negotiable):

- **No blind/auto attacks — every Run is human-selected + confirmed.** A Run only ever happens because the operator picked the action and clicked Run; it pops a confirmation naming the target before anything executes. **No auto-run, no chaining, no "scan → exploit" pipeline.** One command per Run. That confirmation IS the safety model.
- **Exploit mode runs the confirmed command as-is.** `shell.run(..., exploit=True)` → `policy_violation(exploit=True)` returns `None` — the operator's selected + confirmed command runs, including attack tools recon mode would never allow. There is **no tool block-list in exploit mode** (do not add one — the owner rejected it). Only the empty-command check remains.
- **The DEFAULT recon mode is unchanged and exam-legal.** With `exploit=False`/`spray=False`, `policy_violation` still enforces the `ALLOWED_TOOLS` allow-list exactly as before, so the base tool (and the recon custom-command box) stays recon-only. Exploit mode is reached ONLY from the Exploitation tab's confirmed Run.
- **We don't SHIP exam-restricted tools as actions.** No module offers SQLmap / Metasploit / a mass scanner as a one-click action (they're exam-restricted; a test enforces this). The operator is responsible if they hand-type one — the banner says so. **Never add sqlmap/Metasploit/scanner actions.**
- **Execution ON by default** (`exploit_enabled` default `true`, owner 2026-07-16) — the user wants the tab usable, and stays in control because **nothing runs automatically**: every Run is user-initiated and confirmed. A user who wants the tab shown-only can uncheck it in Preferences. This is a distribution posture, not a per-command gate — the per-run confirmation is the real gate.
- **Loot is the operator's own data — shown in full, not redacted.** Run streams into the output pane (or paste tool output), **Parse** extracts hashes/creds, **Add to vault** writes `creds.json`. The loot table shows the dumped secrets **in full** (the owner wants to see/use them — do NOT redact them). **As of 2026-07-22 this extends to the RECON side too: nothing is redacted anywhere** (command logs, audit, reports, graph, spray, SNMP findings, vault) — see § 6. The old "recon commands keep their existing redaction" note is superseded.
- **`runs_on` distinguishes attacker vs victim.** `"attacker"` = runs FROM Kali against the target → **Run** (a single Popen-safe argv). `"victim"` = a command you paste into an already-obtained shell ON the target (SUID checks, `sudo -l`, GTFOBins, winPEAS, reverse shells, mimikatz) → **copy-only**, never executed here. An action is only `attacker` if its filled command is a single Popen-safe argv beginning with a real program (no shell pipes/redirects/subshells, no payload fragment, not a victim-only tool).
- **Tied to discovered services/ports.** Each `ServiceExploits` declares the `ports` that signal its presence; the picker surfaces the surfaces open on *this* box first (`●`-marked, mirrors Recon's service focus) and binds `{port}`/`{url}` to the actual discovered port. **Presence must be a *strong* signal:** a shared web port (80/443/8080/…) alone marks only the generic `web`/`webdav` present — a *specific* web app (Drupal, WordPress, …) is `●` only via a service-name/fingerprint match or a service-specific (non-web) port, never merely because port 80 is open (else a bare web server marks ~70 apps present). Portless post-ex catalogs (`linux`/`windows` privesc, `shells`) are never "present" and never warn. Selecting an action for a *network* service the scan did **not** find shows a loud, non-blocking warning ("⚠ … was NOT found on this target by the scan") — it never disables Run (the human confirm stays the guardrail per this section), it just tells the operator they're acting on a service discovery didn't see.
- **Engine lives in `src/oscprecon/exploit/`** (`base.py` registry + `fill_template` + `runs_on`/`ports`, one module per service, `parsers.py`). Every action cites a `source=`. GUI is `gui/widgets/exploit_panel.py`; execution is `main_window._on_exploit_run` (confirm → `CommandWorker(exploit=True)` → stream → auto-parse). Headless: `nabu-cli exploit [service] [-p profile]` (display view, RUN vs COPY).
- **DECISION-AID, NOT a CVE database (owner rule, 2026-07-21).** The catalog exists to make recon/enum/attack *decisions* — per service it keeps fingerprint/version detection, `searchsploit` lookup, enumeration, default/weak-cred checks, config/loot reads, and **generic offensive technique CLASSES** (web SQLi/SSRF/LFI/SSTI/upload/deserialization *primitives*, the full AD attack catalog, potato family, GTFOBins, file transfers, privesc enumeration, Log4Shell/Text4Shell/Shellshock, DB→RCE via legit features). It does **not** hoard box-specific, novel, single-named-CVE **weaponized PoC delivery** (build-the-gadget / upload-the-webshell / run-the-CVE-exploit / CVE-pinned reverse-shell) — crafting the per-box exploit is the pentester's job. On 2026-07-21 a vault-gap audit removed **230 such named-CVE PoC-delivery actions across 81 service modules** (e.g. Ghostcat, Drupalgeddon2, Struts S2-04x/05x OGNL/XStream RCE, gitlab-22205/2825, grafana-43798 traversal, xwiki/solr/confluence/sharepoint/nexus RCE chains) while keeping every service's recon core (no module emptied). When a box hits a specific CVE, the tool fingerprints it + points at the CVE via `searchsploit`/the reference pane; the operator writes the exploit.
- **Built out (2026-07-16, deep-mined 2026-07-19, CVE-PoC-trimmed 2026-07-21):** **183 services / ~3,187 actions** (verified from `base._REGISTRY`; top modules: ad 143 · web 124 · linux 73 · windows 40 · shells 39) mined from the maintainer's vault + standard tooling — `ad`, `web`, `smb`, `mssql`, `mysql`, `ftp`, `ssh`, `snmp`, `redis`, `rdp`, `nfs`, `linux`/`windows` (privesc, victim-side), `shells`, and the full long tail of app servers, CMSes, mail/DB/monitoring daemons, and appliances (recon/fingerprint/enum/default-cred surface for each; the box-specific CVE *delivery* actions were removed per the decision-aid rule above). The **`ad` service is exhaustively mined from the HTB AD Path vault** — 133 actions across 14 categories: enumeration (PowerView · built-in/LOTL · BloodHound · LDAP filters), Kerberos (impacket **+** Rubeus, overpass/pass-the-key, targeted-roast, S4U alt-service, cross-forest), delegation & ACL abuse, ADCS (ESC1/3/4/8/9/10/11, shadow creds, PassTheCert, golden cert), coercion (PetitPotam/PrinterBug/Coercer/DFSCoerce), credential dumping (secretsdump/DCSync/NTDS/gMSA/DPAPI/Golden-gMSA), lateral movement (psexec/wmiexec/smbexec/atexec/evil-winrm/DCOM/winrs/PSSession), NTLM relay, AD CVEs (noPac/PrintNightmare/Zerologon), SCCM, and DC-level persistence (Skeleton Key/DCShadow/DSRM). The **`web` service is deep-mined from the CPTS/CBBH/OSWE web curriculum (86 actions)** — manual SQLi, SSRF/IDOR, File Inclusion (LFI filter bypasses · RFI · php/data/expect wrappers), command-injection filter bypasses (${IFS}/quote-insertion/base64-smuggle), XXE (php://filter/SSRF/blind-OOB/expect), deserialization (ysoserial · PHPGGC · Phar polyglot · Python pickle · ysoserial.net), GraphQL/API (introspection · alias-batching · mass-assignment · verb-tampering), SSTI across engines (Jinja2 · Twig · Freemarker · Smarty · ERB/Mako), file-upload filter bypasses (ext tricks · exiftool/GIF polyglots · Content-Type spoof · .htaccess), and an XSS set. `linux` carries a **Loot cracking** category (unshadow/keepass2john/ssh2john/zip2john/office2john + hashcat modes) and `shells` a full **File Transfers** set (http.server/smbserver/bitsadmin/WebClient/base64-fileless/dev-tcp/exfil) — both from the CPTS Password-Attacks / File-Transfers modules. The full **potato family** (JuicyPotato/RoguePotato/JuicyPotatoNG/SweetPotato/GodPotato/PrintSpoofer) carries step-by-step directions. A **copy-only GTFOBins lookup** (`references/gtfobins.yaml`, ~62 binaries) is reachable from the Exploitation tab + `nabu-cli gtfobins`. Later batches were driven by a vault **gap-analysis** workflow (agents survey the vault for uncovered services, then mine templates); the vault is substantially exhausted at 183. Add a new service by dropping `exploit/<svc>.py` that `register()`s — `base._load_builtin()` imports it (keys must be valid Python module names — no hyphens). Keep the port/service tie-back + `source=` provenance. `runs_on` (attacker Run vs victim copy-only) is decided by Popen-safety — the `reclassify.py` pipeline demotes interactive sessions (bare ssh/DB logins, `nc` connects), shell chains/pipes, listeners, and unfillable-brace payloads to victim.

### 2c. msfvenom payload builder — owner-authorized, copy-only reverse-shell helper

Owner-requested (Andre, 2026-07-16): a guided **msfvenom payload builder** so reverse-shell syntax is easy to get right. This is a **narrow, explicit carve-out** of the §2 Metasploit ban, justified because the **OSCP+ Exam Guide explicitly allows `msfvenom` + `multi/handler`** (what it restricts to one target is Metasploit's *exploitation modules* + meterpreter-as-shell). Non-negotiable rules:

- **Copy-only. It NEVER executes anything.** The builder assembles the exact `msfvenom` command + its matching listener as text; the operator copies and runs them. It does **not** call `shell.run` (no exploit-mode gate interaction, no execution path). This is the same "shown, you run it" model as the Ligolo helper.
- **Exam-safe by default.** Defaults to non-meterpreter `*_reverse_tcp` shells caught with a bare `nc -lvnp` listener — these have **no exam limit**. Staged / meterpreter payloads pair with a `multi/handler` listener and carry a visible **note** that meterpreter counts toward the one-Metasploit-use limit.
- **Never shipped as a service action.** It is a **separate engine** (`exploit/msfvenom.py`) + dialog (`gui/dialogs/msfvenom_builder.py`), NOT a `ServiceExploits`/`ExploitAction`. So the `test_modules_do_not_ship_exam_restricted_tools` guard (which forbids `msfvenom`/`msfconsole`/`meterpreter` as the first token of any *service action*) stays valid and green — no service module ever ships these.
- **Surfaces:** a "🎯 Payload builder…" button on the Exploitation tab opens the dialog (platform → payload → format dropdowns, LHOST auto from tun0, LPORT, encoder, bad chars, output file; live command + listener + Copy). Headless: `nabu-cli payload [id] [-l LHOST] [-P LPORT] [-f fmt] [-e enc] [-b badchars] [-o out]` (display-only). Bad chars are shell-quoted so `\x..` escapes survive a paste.

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
│   ├── exploit/              ← Exploitation tab engine (§ 2b) — command builder, one file per service
│   │   ├── base.py           ← ExploitAction/ServiceExploits registry + fill_template + runs_on/ports
│   │   ├── parsers.py        ← parse pasted tool output (secretsdump/kerberos) into loot
│   │   ├── ad.py  web.py  smb.py  mssql.py  mysql.py  ftp.py  ssh.py  snmp.py
│   │   └── redis.py  rdp.py  nfs.py  linux.py  windows.py  shells.py
│   ├── references/           ← service → HackTricks URL + tool hints
│   │   └── services.yaml
│   ├── reporter.py           ← markdown report writer (Obsidian-compatible)
│   ├── templates/            ← Jinja2 templates
│   ├── gui/
│   │   ├── app.py            ← QApplication bootstrap
│   │   ├── main_window.py
│   │   ├── controllers/      ← cohesive subsystems extracted from main_window (spray_controller.py, …)
│   │   ├── widgets/
│   │   │   ├── service_tree.py     ← left pane
│   │   │   ├── tool_panel.py       ← middle pane (command builder + output + follow-ups)
│   │   │   ├── reference_pane.py   ← right pane (HackTricks + EDB + tool hints)
│   │   │   ├── graph_view.py       ← Cytoscape.js graph (Ctrl+G)
│   │   │   ├── exploit_panel.py    ← Exploitation tab (§ 2b) — build/Run attacks + parse loot
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
├── audit.jsonl               ← append-only GUI action audit log — BUILT (§ 6a)
├── audit-archive/            ← rotated audit logs, per-day after N MB — BUILT (§ 6a)
├── .lock                     ← present while opened for edit; concurrent-copy guard — BUILT (§ 6b)
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
- **NO REDACTION (owner decision, 2026-07-22).** The tool NEVER hides secrets. Hashes, PSKs, and
  passwords are the assessment deliverable, and this is the operator's own tool against their own
  authorized targets — so command logs, the audit trail, reports, the graph, spray output, the SNMP
  findings, and the credential vault all show the **full** value. The masking helpers still exist but
  ship **off** (`config.Settings.redact_secrets` / `shell.REDACT_SECRETS`, both default `False`); flip
  the flag on only for a hypothetical shared/public build. Do **not** re-introduce redaction as a
  default. (Supersedes the earlier "reports redact `password=<redacted len=12>`" rule.)
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

### 6a. Audit log — `<profile>/audit.jsonl` — BUILT

**Built (`audit.py` + `<profile>/audit.jsonl`; feeds the dashboard Activity timeline).** An
append-only, one-JSON-object-per-line record of every GUI action, for a complete exam audit trail.
Writes are **best-effort — never block the UI**. Rotated into `audit-archive/` per day once the live
file passes N MB.

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

### 6b. Concurrent copies & profile lock — `<profile>/.lock` — BUILT

**Built (advisory `<profile>/.lock` + read-only prompt + stale-lock reclaim; delivered in the
Workspace upgrade).** The exam workflow may run several GUI instances at once (a second window on a
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
- **Discovered URLs table** (`gui/widgets/discovered_urls_panel.py`, a "Discovered URLs" tab beside "Content discovery"): a clean, sortable site map of the content-discovery findings for the current web port — one row per URL with **Status · Method · Lines · Words · Bytes · URL** columns, colour-coded status, **double-click a row to open it in the browser** (`QDesktopServices`), and **Export CSV** (the "excel-sheet" view). It reads the accumulated http findings (persisted in `findings.json`, so it grows across runs) and leaves the raw streamed output untouched. The feroxbuster parser captures `method`/`lines`/`words` (in addition to status/size) to feed it. **Source / backup / VCS disclosures** (`is_source_disclosure()` — `.swp`/`.swo`/`.bak`/`.old`/`~`/`.git`/`.svn`/`.sql`, e.g. HTB Base's `login.php.swp`) get a ⚠ + warning colour so a leaked-source file stands out. A live **Filter** box (`_passes`) narrows rows by substring across URL/status/method as you type, and a **Hide static assets** toggle (`_is_static_asset` — js/css/image/font/media extensions) drops asset noise so app endpoints surface (Base: 38→11); **Export CSV** writes exactly the filtered/cleaned view, with a trailing **Important** column that carries the ⚠ source/backup/VCS-disclosure flag (`"source/backup disclosure"`) so the interesting URLs are sortable/filterable in Excel, not lost on export.

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
- `dnsenum --dnsserver {target} --noreverse -f <wordlist> {domain}` (DNS subdomain brute + NS/MX/host records + AXFR per NS)
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
| **WebDAV** | 80/443/8080 | `nmap http-webdav-scan`, `curl -X OPTIONS`, `curl -X PROPFIND` — Tier-2 follow-ups surfaced in the HTTP panel (WebDAV is an HTTP property, no separate node); `cadaver` is copy-only | Shown in HTTP follow-ups |
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
| **Zookeeper** | 2181 | `nmap -sV` banner (auto, Popen-safe); `ruok`/`mntr`/`stat`/`conf`/`envi` 4lw via `nc` are Tier-2 shown/copy (nc off the allowlist) | Auto banner + shown 4lw |
| **VNC** | 5900–5906 | `nmap --script vnc-info` — banner + auth types | Auto |

**Hard rule for "auto":** read-only enumeration with finite output bounded by listing protocols. Bulk download, auth-guessing, list-based auth = **Tier 2 or Tier 3**.

---

## 13. Wordlist subsystem

Cross-cutting. Used by HTTP, vhost, and any future module taking a wordlist.

- `src/oscprecon/wordlists.py` — scans configured paths at app start; indexes each with: full path, filename, category (inferred from path — `web-content`, `dns`, `usernames`, `fuzzing`, etc.), file size, line count.
- **Filters out `seclists/Passwords/` by default** — password lists are suppressed unless opt-in Spray mode (§ 2a) is enabled. Any wordlist under a path containing `/Passwords/` is hidden in the default (recon-only) mode, and surfaced only when Spray mode is on.
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

### 14a. Live HackTricks fetch + cache (owner-approved)

Owner-approved (see `docs/OWNER_DECISIONS.md`). This narrows the former blanket ban: live fetching,
section extraction, and local caching of HackTricks reference pages **are allowed**, within tight
boundaries. Three content tiers coexist, most-reliable first:

1. **Vendored offline** — the build-time markdown snapshot (§ 2, § 27). Always available, no network,
   the **reliable fallback**; never overridden in authority by the live cache.
2. **Live cached** — a previously fetched-and-sanitized page held in the rebuildable XDG cache.
3. **Live page** — the canonical URL rendered live in the reference pane (already allowed).

**Allowed:**
- User-initiated live fetch of a **mapped** HackTricks page; optional auto-fetch when enabled in Preferences.
- Fetching **only** from approved canonical HackTricks hosts, over **HTTPS**.
- Extracting relevant headings/sections and **local caching** for later offline viewing; manual refresh; cache clearing.
- Falling back to the vendored offline snapshot on any failure.

**Forbidden:**
- Crawling the whole HackTricks site; scraping arbitrary/user-entered URLs; following links to unrelated domains.
- Executing JavaScript from fetched content; downloading executable content; rendering unsanitized remote HTML.
- Runtime LLM calls; telemetry; uploading project information.
- Sending target addresses, credentials, findings, notes, commands, or any project data to HackTricks.
- Scraping/downloading Exploit-DB **PoC** content (Exploit-DB stays `searchsploit` + linkout only).
- Using fetched reference content to **automatically execute** commands.

**Explicit rule:** *Only the canonical HackTricks page URL selected from the local reference map may be
fetched. Local target data is used only to choose and filter local display content and must never be
transmitted as query parameters, request bodies, or headers.*

**Implementation constraints:** the fetch/parse/cache logic lives in a non-GUI subsystem
(`references/live_hacktricks.py`), never in a Qt widget. Fetches run off the GUI thread, are
cancellable, rate-limited, size/timeout-bounded, content-type-validated, reject cross-host redirects,
and use a descriptive application User-Agent. A result for one service/project must never replace the
reference shown for another. Cache lives under `~/.cache/oscprecon/hacktricks/` — **never** inside
`creds.json`, findings, or other authoritative project data; clearing it never touches project data.

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

### Presentation & export — BUILT (Phase 4 reinforcements)

The Phase 4 graph is presentation-quality, not merely functional. All of the below are built:

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

### Status footer — BUILT

**Built (`main_window._update_status_footer`).** A small always-visible strip along the bottom of
the main window:

- App name + version (read from `pyproject.toml`)
- Active profile name (or `no profile loaded`)
- Workspace root path
- Muted text: `recon-only — OSCP exam legal per CLAUDE.md § 2`

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
| Open by IP... | — | **BUILT.** Search all `~/oscprecon/` profiles for one whose `profile.json.target.ip` matches; open it. Fast recovery when the name is forgotten |
| Import Project... | — | **BUILT.** Extract a `<name>.tar.gz` (or folder) exported elsewhere into `~/oscprecon/<name>/` and open it (path-traversal-safe) |
| Export Project... | — | **BUILT.** Pack the active profile folder into `<name>.tar.gz` for backup/transfer; **warns that `creds.json` is included** |
| Preferences... | — | Workspace root, wordlist paths, theme |
| Exit | Ctrl+Q | |

### Project file operations — BUILT (`workspace/portability.py`)

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
- **Help** — About / OSCP Constraints / Doctor / Documentation / Shortcuts / **View Diagnostics Log**

### 19a. Brand mark & diagnostics log — BUILT

- **Brand mark** — the header's top-right carries the Nabu wordmark with the **owl-furby mascot**
  (`gui/assets/furby.svg`, `AppHeader._brand`), the maintainer's mark; the CLI prints an owl-furby
  ASCII banner (`branding.cli_banner()`) to **stderr on a TTY only**, so it never pollutes piped
  output or tests. Purely cosmetic; on-brand palette (teal/gold), no external artwork.
- **Diagnostics log** — a robust, best-effort local crash/error log (`src/oscprecon/diagnostics.py`),
  distinct from the per-profile audit log (§ 6a). A rotating file at
  `~/.local/state/oscprecon/logs/nabu.log` (XDG state, `config.state_dir()`), a chained
  `sys.excepthook`, and a Qt message handler — installed at GUI (`gui/app.py`) and CLI (`cli.py`)
  startup. **Help → View Diagnostics Log** (`LogViewerDialog`) shows the tail with reveal-folder /
  clear; the CLI prints the log path to stderr on a crash. Setup is best-effort (never blocks the
  app). Offline, no telemetry; the log is diagnostic and **non-authoritative — never project data**.

### Preferences

- Workspace root path (default `~/oscprecon/`)
- Wordlist paths (add/remove; default `/usr/share/seclists/`, `/usr/share/wordlists/`, `~/wordlists/`)
- Default scan profile: `quick` / `default` / `full` / `exam`
- Theme: one of 12 — Light · Dark · HTB (default) · Leet · Amber · Synthwave · Dracula · Nord · Gruvbox · Solarized · Tokyo Night · Monokai (all WCAG-AA-validated)
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
- `cli.py` — Typer entry (`nabu-cli`), at **feature parity with the GUI** for automatable work:
  `scan` (+ `--resume`), `enum <service>` (headless Tier-1 service recon), `creds` (add/list/rm),
  `list`/`findings`/`health`/`activity`/`delete-project`, `searchsploit`, `exploit`, `payload`,
  `gtfobins`, `pivot`, `doctor`, `docs`, `export-*`/`import-project`, and the gated `spray` + `config`
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

- `oscprecon-cli doctor` + Help → Doctor menu — checks each wrapped tool via `which` (prints install commands for missing), the reference data they rely on (SecLists / nmap NSE / Exploit-DB), and exam-day host readiness (VPN tun up? workspace disk free? nmap raw-socket capable?); `--versions` prints each present tool's version
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
- **Owner-approved live HackTricks fetch/cache** (§ 14a) — user-initiated (or Preferences-enabled auto) fetch of the single canonical mapped page over HTTPS from an allow-listed host, local section extraction + rebuildable XDG cache, manual refresh / clear, offline fallback. **Never** transmit target/project data; never crawl; never scrape Exploit-DB PoCs
- Report template improvements
- GUI widgets exposing existing engine functionality
- Bounded parallel execution
- `--dry-run` / "show command, don't run" preview improvements
- Fixture-based tests when parsers change
- A **build-time contained-app bundle** for the public GitHub release — an **AppImage** (or equivalent) that bundles the existing PySide6 app so a user can download → `chmod +x` → double-click. Packaging only; **not** a tech-stack rewrite (§ 3 stands), no runtime network, no auto-update
- An **offline, no-network branded splash screen** shown during GUI startup (ASCII-art wordmark + version + the recon-only tagline). Owner-requested for the public release; must degrade gracefully (a splash failure never blocks the main window) and pull in **no** network/telemetry

### No, don't propose

- Anything from the Forbidden list in § 2
- Wrapping Metasploit, SQLMap, or commercial tools (hydra/medusa/spraying are allowed **only** in opt-in Spray mode — § 2a — off by default)
- LLM/AI calls at runtime — even "optional"
- Auto-exploitation gated behind flags
- Downloading, executing, transforming Exploit-DB PoCs
- **Crawling the HackTricks site, scraping arbitrary/user-entered URLs, or following links to unrelated domains** — the owner-approved live fetch (§ 14a) is limited to the single canonical mapped page per service; the vendored offline snapshot and the local cache remain the defaults. **Any scraping/download of Exploit-DB PoC content stays forbidden** (Exploit-DB = lookup + linkout only)
- Rewrites of the tech stack — decided in § 3
- Speculative abstractions for features not in the roadmap
- Telemetry, update checks, login flows, cloud sync (an **offline, no-network branded splash screen** for the public-release build is the one allowed exception — owner-requested; see "Yes to propose")

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
