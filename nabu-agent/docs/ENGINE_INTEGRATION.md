# Nabu Engine Integration Map

**For:** engineers building **Nabu Agent** (new agentic web platform, sibling folder `nabu-agent/`)
**Reuses:** the classic **Nabu / `oscprecon`** recon engine at `/home/hacker/oscp-recon/src/oscprecon/`
**Date:** 2026-09-09

## Ground rules (read first)

1. **Never rebuild recon knowledge.** The engine already encodes the service→NSE matrix, the 183-service / 3190-action decision-aid catalog, the HackTricks/EDB/GTFOBins/hashcat/pattern research surface, and the OSCP-legal tool allow-list. Nabu Agent orchestrates these; it does not re-derive them.
2. **Never modify `src/oscprecon`.** Treat it as a read-only, versioned dependency. All new code lives under `nabu-agent/`.
3. **The engine is Qt-free and headless by design.** A test asserts importing the engine never loads PySide6. Every subsystem below is pure Python + stdlib (+ Jinja2 for the reporter), so the agent body **imports it as a library** — with the single, deliberate exception of the reference `searchsploit` shell-out, which is already encapsulated inside `search_exploits`.
4. **All tool execution goes through one chokepoint** (`shell.run`, `src/oscprecon/shell.py`) — see §7. This is non-negotiable and the core safety invariant.

---

## 1. Launch a scan and read back discovered ports/services

### 1a. Top-level, Profile-driven (recommended default)

The whole nmap battery is driven by the **`Orchestrator`** (`src/oscprecon/orchestrator.py`), which is Qt-free:

```python
Orchestrator(profile: Profile, *, on_line: Callable[[str], None] | None = None,
             udp_full: bool = False, scan_profile: str = 'default',
             resume: bool = False, force: bool = False,
             cancel: threading.Event | None = None)

Orchestrator.run_nmap(self) -> None
```

**Flow:** construct with a live `Profile` (§2), then call `run_nmap()`. It runs the full battery in order — discovery sweeps → parse → versioned `-sV -sC` over found-open TCP ports → deferred UDP `-p-` (only for `scan_profile='full'` or `udp_full=True`). `scan_profile` ∈ `quick | default | exam | full`.

**Reading back results:** `run_nmap()` returns `None`. It merges into and persists the profile as a side effect. Read the results from:

```python
profile.discovered_services   # list[DiscoveredService]
```

`on_line` is a plain `str -> None` sink (use a logger/echo in headless use; the CLI passes `typer.echo`, the GUI passes `signal.emit`). `cancel` is a `threading.Event`. `run_nmap()` also writes `report.md` via the Reporter (§5).

### 1b. Profile-less / fine-grained (drive `NmapModule` yourself)

Use `NmapModule` (`src/oscprecon/modules/nmap.py`) when you want scan results without the Profile/report machinery:

```python
NmapModule(udp_full: bool = False, scan_profile: str = 'default')
NmapModule.commands(self, target: Target, ports: list[Port]) -> list[Command]
NmapModule.plan(self, target: Target) -> list[Command]                 # preview exact syntax
NmapModule.deferred_commands(self, target: Target) -> list[Command]    # slow UDP -p-, last
NmapModule.discovered_services(self, raw_outputs: dict[str, str]) -> list[DiscoveredService]
```

**Two-phase pattern (important):**

```python
m = NmapModule(scan_profile="default")
raw = {}
for cmd in m.commands(target, []):          # phase 1: ports==[] → discovery battery
    r = shell.run(cmd.shell_line, out_path(cmd.output_file))
    raw[cmd.output_file] = read_text(out_path(cmd.output_file))
services = m.discovered_services(raw)        # parse open ports + service ids
tcp_ports = [Port(number=s.port, proto=Proto.TCP) for s in services if s.proto == Proto.TCP]
for cmd in m.commands(target, tcp_ports):    # phase 2: non-empty → single "nmap -sV -sC -p ..." line
    ...
for cmd in m.deferred_commands(target):      # UDP -p-, only full/udp_full
    ...
```

- `commands([])` → discovery battery; `commands(open_ports)` → the single versioned command. **An empty port list collapses back to discovery**, so only call phase 2 when TCP ports exist.
- **`discovered_services(raw_outputs)` is THE parser** to reuse. `raw_outputs` maps `output_file -> contents`. It merges by `(port, proto)`: `-sV` product/version/name is authoritative, `-sC` fills `nmap_scripts_output`. Sorted by `(proto, port)`.

### 1c. Ad-hoc single scan / CIDR / liveness

`src/oscprecon/nmap_scan.py`:
- `build_nmap_command(spec: ScanSpec) -> str` — structured single-scan builder; validates target, rejects file-writing / shell-metachar fields. Pair with `shell.run` + `NmapModule.discovered_services`.
- `network_scan_command(cidr: str, scan_profile='default') -> str` — whole-/24 versioned sweep.
- `merge_services(existing, new) -> list[DiscoveredService]` — union-by-`(port,proto)`; a narrow re-scan **adds to, never replaces** prior discovery.

Pre-flight liveness (`src/oscprecon/alive.py`):
```python
build_alive_command(target: str) -> str        # nmap -sn host discovery, host or CIDR
parse_alive(text: str) -> AliveResult           # .hosts, .up, .count
```
Run `shell.run(build_alive_command(ip), out)` then `parse_alive(text)`.

### Key data shapes (`src/oscprecon/models.py`)

- **`DiscoveredService`** (mutable dataclass) — the canonical discovered-service shape: `port:int, proto:Proto, service:str, product:str, version:str, nmap_scripts_output:str, discovered_at:str, state:str='open'` (`'open'` or `'open|filtered'` for unconfirmed UDP).
- **`Port`** (frozen) — the versioned-phase **input**: `number:int, proto:Proto, service, product, version, state`. ⚠️ **`Port.number` vs `DiscoveredService.port` — do not confuse them.**
- **`Target`** (frozen) — `ip:str` (single host OR CIDR), `hostname`, `platform`, `box_name`, `os_guess`. Props `.is_range`, `.host`. `__post_init__` validates the ip; a CIDR range drops hostname.
- **`Command`** (frozen) — `module, shell_line, why, expected_runtime_hint, output_file, phase`. `shell_line` → `shell.run`; `output_file` is relative to `profile.directory`.
- **`Proto`** (StrEnum) — `TCP='tcp'`, `UDP='udp'`.

**Gotchas:** discovered services are **monotonic within a project** (merge, never replace — a port that later closes stays listed). UDP `-p-` is slow and deferred. A CIDR `Target.ip` gets network-wide discovery, not the single-host battery.

---

## 2. The Profile / findings / creds / graph data model — create / load / save

All in `src/oscprecon/profile.py`, `findings.py`, `creds.py`, `graph_data.py`, `models.py`. Pure Python, concurrency-safe (module `RLock` in profile; `threading.Lock` + cross-process `fcntl.flock` in findings).

### 2a. Profile lifecycle

```python
Profile.create(cls, workspace_root: Path, name: str, target: Target) -> Profile   # created + saved to disk
Profile.load(cls, directory: Path) -> Profile                                      # defensive; raises ValueError on corrupt/missing
Profile.save(self) -> None                                                         # atomic (temp + os.replace) under RLock; always writes SCHEMA_VERSION=2
```

Get `workspace_root` from `config.workspace_root()` (default `~/oscprecon`).

**`Profile`** dataclass fields: `directory:Path, profile_name:str, target:Target, status:dict, discovered_services:list[DiscoveredService], discovered_hosts:list[DiscoveredHost], command_history:list[dict], references_visited:list[dict], module_settings:dict, tags:list[str], organization:dict, schema_version:int=2, read_only:bool` (runtime-only). Path props: `profile_json_path, notes_path, creds_path, graph_path`.

### 2b. Mutators (most do NOT auto-save — call `profile.save()` after batches)

```python
set_services(services)          merge_services(services)           # union by (port,proto); neither auto-saves
add_command(record) -> str      # mints 'cmd-NNN' + appends command_history under one lock
add_hosts(hosts) -> int         remove_host(ip) -> bool            remove_subnet(subnet) -> int   # pivot topology (schema v2)
credentials() -> list[Credential]   add_credential(cred)   replace_credential(current, updated)
load_graph() -> dict            save_graph(data)                   # graph.json: {user_edges, node_overrides}
set_status / set_display_name / set_pinned / set_archived / add_tag / remove_tag / set_tags / organization_meta()
```

**Which mutators auto-save:** `rename`, `set_target`, `set_hostname`, `remove_host`, `remove_subnet`, and **the organization setters** save themselves. Everything else (`set_services`, `merge_services`, `add_command`, `add_hosts`, `add_credential`) `touch()`es `last_active` but **you must call `profile.save()`**.

### 2c. Findings — a SEPARATE store (`src/oscprecon/findings.py`)

`findings.json` is a **flat JSON list of dict rows** (NOT wrapped in an object). Key against `profile.directory`, not a Profile field:

```python
load_findings(profile_dir) -> list[dict]
add_findings(profile_dir, new: list[dict]) -> list[dict]          # dedups by _key(); in-proc Lock + fcntl.flock
from_parsed(service, fields, detail, discovered_at, port=0) -> dict   # build a tool-output row
add_manual_finding(profile_dir, finding) -> dict                  # manual:True + uuid id + added_at; never deduped
update_manual_finding / delete_manual_finding                     # ONLY manual rows are editable/deletable
```

Two distinct "Finding" notions: `models.Finding` (parser value object with `.fields`) **vs** the persisted `findings.json` dict row — **build persisted rows with `findings.from_parsed`**, never by serializing `models.Finding`.

**Severity** (`src/oscprecon/finding_severity.py`): `category_of(finding) -> str`, `classify(kind,value,detail)`, `rank(category) -> int` (strongest-first, `vulnerable=0`), `is_notable(category)`. Six categories weakest→strongest: `info, reference, access, exposure, relay-risk, vulnerable`. NOTABLE = `{access, exposure, relay-risk, vulnerable}`.

### 2d. Credentials (`src/oscprecon/creds.py`)

`creds.json` = `{schema_version:1, entries:[...]}`, written **0600**. Dedup/edit key `cred_key = (username, domain, secret, source)` — **ignores `tested_against`**, so recording a spray result needs `replace_credential`, not `add_credential`. `Credential`: `username, secret, secret_type='password', domain, source, tested_against:list, notes`. **Secrets are NOT redacted by default** (owner policy 2026-07-22).

### 2e. Graph (`src/oscprecon/graph_data.py`)

```python
build_elements(profile: Profile) -> {'nodes':[...], 'edges':[...]}   # Cytoscape.js elements, pure data
```
Merges target + services + `findings.json` + `creds.json` + `discovered_hosts` topology, overlaid with `graph.json` `node_overrides` + `user_edges`. Node ids: `target`, `service-<port>-<proto>`, `finding-<i>`, `cred-<i>`, `subnet-<cidr>`, `host-<ip>`, `hostservice-<ip>-<port>-<proto>`.

### 2f. Workspace listing (no profiles opened)

`src/oscprecon/workspace/index.py`:
```python
scan_workspace(root, *, include_archived=True, cancel=None) -> list[ProfileSummary]   # never raises, never reads secrets
summarize_profile(directory, *, workspace_root=None) -> ProfileSummary
```

**Gotchas:** `read_only` mode raises `ReadOnlyError` on every write (set when the `.lock` is held elsewhere; runtime-only, never persisted). `Target` is **frozen** — mutate via `dataclasses.replace`. Host strings feed `shlex`-split command lines — `validate_host` / `validate_host_or_range` reject leading `-` or whitespace (argv-injection guard; §7). `add_hosts` treats an empty services list as "no new data" and never adds the entry Target. Cross-process safety: `findings.json` is fcntl-protected; `profile.json` relies on the advisory `.lock` file, not the in-process lock — a separate agent **process** sharing a folder with a GUI must respect that.

---

## 3. Query the decision-aid catalog for a given service

Package `src/oscprecon/exploit/` — **pure Python, no Qt, executes nothing** (it only *builds* command text and *parses* pasted output). Import via `from oscprecon import exploit as ex`; the `__init__` re-exports the whole public API. **Do not reach into `base._REGISTRY`.**

```python
ex.service_keys() -> list[str]                                  # all 183 registered keys, picker order
ex.service_exploits(key) -> ServiceExploits | None              # one service's whole catalog
ex.services_present(services: list[tuple[int,str]]) -> list[str]   # THE "which catalogs apply" query (● dots)
ex.web_app_keys_from_fingerprints(texts) -> ...                 # fold whatweb/nmap product fps into presence
ex.services_for_ports(open_ports: set[int]) -> list[str]        # simpler port-only presence
ex.port_for_service(pairs, key) -> int                          # the real discovered port for a key
ex.action_ports(action, spec=None) -> (tuple[int,...], str)     # target ports + provenance
ex.fill_template(template, values: dict[str,str]) -> str        # pre-fill {placeholders}
ex.missing_placeholders(template, values) -> list[str]
```

**Answer "for service X with open port P and product V, what applies":** build `(port, name)` pairs → `ex.services_present(pairs)` (+ `web_app_keys_from_fingerprints(texts)`) → for each present key `ex.service_exploits(key)`; use `ex.port_for_service(pairs, key)` for the discovered port.

**Ranking / suggested set** (`src/oscprecon/exploit/relevance.py`) — evidence-based, shared with the GUI stars:

```python
ex.build_context(services, fingerprint_texts, findings, credentials, command_history) -> RankContext  # once per profile
ex.score_services(services, fingerprint_texts=None) -> dict[str,int]     # grades presence; {k:v>0} == services_present
ex.rank_actions(spec: ServiceExploits, ctx: RankContext) -> list[Scored] # best-first, stable
ex.suggested_action_ids(spec, ctx, limit=12) -> set[str]                 # the ★ set (score >= 55)
ex.category_order(spec, ctx) -> list[str]
```

**Headless CLI equivalent:** `nabu-cli exploit [SERVICE] [-p PROFILE] [--suggested]` drives the exact same engine.

### Data shapes (`exploit/base.py`, `exploit/relevance.py`)

- **`ExploitAction`** (frozen) — `id, title, template ({placeholder}), why, category, tool, requires:tuple, parses:str, source, ports:tuple[int,...], runs_on:str='attacker'`. Prop `executable` (== `runs_on=='attacker'`); `placeholders()`.
- **`ServiceExploits`** (frozen) — `key, label, note, ports:tuple, actions:tuple`. `categories()`, `by_category(c)`.
- **`RankContext`** (frozen) — `open_ports, service_names, fingerprint_text, finding_text, vuln_ids, has_password, has_hash, ran_tools, os_family, service_scores, service_ports`.
- **`Scored`** (frozen) — `action, score, reasons`; prop `suggested` (score ≥ 55).

**Gotchas:**
- **Presence-strength rule (§2b, load-bearing):** a shared/generic port alone (80/443/8080…, 21/25/110/143/631) marks only the generic catch-all (`web`/`webdav`/`ftp`/`smtp`/`pop3imap`/`cups`), **never a specific app** (Drupal/Exim) — those need a name/fingerprint match. `score_services` grades but never recomputes presence, so `●`, `⚠`, `★` can never contradict.
- **`action_ports` provenance:** relevance counts only `declared by this action` / `written into this command` / `default for <tool>` as real port evidence — the `<label> service ports` fallback is a display guess only.
- **The catalog is a decision-aid, NOT a CVE/PoC DB** (owner rule): recon/enum/default-cred/technique-CLASS actions only. 230 named-CVE weaponized-PoC actions were deliberately removed. **Never add sqlmap / Metasploit / mass-scanner actions** (a test enforces first-token bans). `msfvenom` lives in a separate `exploit/msfvenom.py`.
- **`runs_on='attacker'` vs `'victim'`** is Popen-safety-derived, not a capability claim — `victim` actions (evil-winrm, interactive logins, listeners) are **copy-only**.
- `_REGISTRY` is populated at import time; `rank_actions` runs per-service (up to 143 actions for `ad`), so **build `RankContext` once**, not per action.

---

## 4. Fetch research for a finding (HackTricks / EDB / GTFOBins / patterns)

The **research surface** — `src/oscprecon/references/`, `hacktricks.py`, `edb.py`, `patterns/engine.py`. Pure, importable; **every reference loader degrades to empty on missing/corrupt data rather than raising**, so no defensive wrapping needed. Only one call shells out (`searchsploit`, encapsulated).

### 4a. Service → reference resolver

```python
references.match(service: DiscoveredService, rules=None) -> ServiceRef | None   # most-specific rule from services.yaml
references.load_rules(path=None) -> list[MatchRule]
references.expand_hint(template, *, target, port='', proto='', domain='', share='') -> str
```
`ServiceRef` = `label, hacktricks (URL), module, tools:list[ToolHint]`. Never auto-runs.

### 4b. Exploit-DB / searchsploit

```python
references.search_exploits(product, version, output_file: Path, *, runner=None) -> EdbSearch
references.parse_searchsploit_json(text) -> list[ExploitHit]        # pure parser
edb.add_edb(profile_dir, *, service, product, version, hits) -> list[dict]   # persists CITATIONS only
edb.load_edb(profile_dir) -> list[dict]
```
`search_exploits` internally runs `searchsploit --json <query>` **through `oscprecon.shell.run`** (searchsploit must be installed + allow-listed) — tiered: `core short` (`scope='version'`) → `core` only (`scope='product'`). `runner=` is a pure test/offline injection seam. `EdbSearch` = `hits (top 15), query, scope, total`. `ExploitHit` = `edb_id, title, url, path, type, platform, date, cve, version_match`.

### 4c. HackTricks — offline (default) and owner-approved live

```python
hacktricks.page_for_module(module) -> HacktricksPage | None        # offline vendored, NO network, lru_cached
sections.relevant_sections(markdown, *, keywords, product='', version='', limit=4) -> list[Section]  # LOCAL selection only
references.live_hacktricks.get_page(url, *, enabled=True, force=False, max_age_days=..., opener=None) -> LiveResult
references.live_hacktricks.html_to_markdown(html) -> (markdown, headings)
```
`page_for_module` → `HacktricksPage.markdown`; `relevant_sections` picks pertinent chunks by finding-kind keywords → product → version → service-general → page start (fence-aware, deterministic, **nothing sent to a server**). Live fetch (`get_page`) is gated: URL must be in `mapped_urls()`, HTTPS, host in `{book.hacktricks.wiki}`; bounded 3 MB / 12 s; converted to our own sanitized markdown; **no project/target data ever transmitted**.

### 4d. GTFOBins / hashcat (offline, display/lookup-only)

```python
gtfobins.get(name) -> Binary | None     gtfobins.search(query) -> list[Binary]
hashcat.search(query) -> list[HashMode]  hashcat.build_command(mode, attack='0', hashfile=..., wordlist=..., mask=..., rules='', extra='') -> str
```
Nabu never runs hashcat or GTFOBins techniques — `build_command` just assembles a copy-paste string.

### 4e. Pattern-based "next steps"

```python
patterns.engine.suggest_for(findings: list[dict], *, target, domain='', has_credential=False, rules=None) -> list[Suggestion]
patterns.engine.check_provenance(directory=None) -> list[str]   # §15 build gate: every entry needs a `# source:`
patterns.engine.check_forbidden(directory=None) -> list[str]    # §15 build gate: bans exploit/cracking tokens
```
`Suggestion` = `text, command_template, source_pattern, source_box`.

**Gotchas (§14 lookup-only / privacy, enforced structurally):**
- `ExploitHit.path` (local PoC file) is **never persisted or opened**; `edb.json` stores citations only — there is no run/copy code path.
- searchsploit input is hard-sanitized (`_sanitize_query` strips all but `[A-Za-z0-9.- space]` and leading dashes) so a hostile banner like `product=-m 47080` can't become `searchsploit -m` (which copies a PoC).
- Live HackTricks: only URLs already in `services.yaml`; verbatim URL, no query/body/custom headers; cross-host redirects refused; caches + throttles (2 s/URL).
- `hashcat.build_command`'s default wordlist references `rockyou.txt` — fine there, but `rockyou` is a **§15-forbidden token inside pattern suggestions**. Treat the `check_forbidden` / `check_provenance` gates as invariants, don't re-derive suggestions that violate them.

---

## 5. Generate a report

`src/oscprecon/reporter.py` + `templates/report.md.j2`. Pure Python + Jinja2, no Qt.

```python
Reporter(profile: Profile)          # reporter.py:204
Reporter.render(self) -> str        # reporter.py:345 — clean report string, ZERO disk side effects
Reporter.write(self) -> Path        # reporter.py:348 — archives prior report.md then overwrites; returns report.md Path
```

**Recommended agent flow:**
```python
from oscprecon.profile import Profile
from oscprecon.reporter import Reporter
profile = Profile.load(profile_dir)                 # or reuse the open Profile
markdown = Reporter(profile).render()               # to show the user, no writes
# optionally:
report_path = Reporter(profile).write()             # persist with §18 archive-then-overwrite
```

`render()` reads the filesystem fresh each call — `findings.json`, `edb.json`, `audit.jsonl`, `notes.md`, `graph.json` (via `build_elements`, wrapped in try/except) — so the profile dir must hold current artifacts. Findings/EDB/audit are **not** Profile fields; they are re-loaded fresh (not cached).

**Report sections (in order):** frontmatter; header; Summary open-ports table; Discovered services (HackTricks link + NSE output); Exploit-DB references (lookup-only); My findings (manual, verbatim fenced PoC); Per-service findings (grouped by module); Pivot topology; Suggested next steps (with `source_pattern`/`source_box` citation, from `patterns.engine.suggest_for`); User notes; Graph annotations; Command log; Audit trail (last 200 of N).

**Standalone next-steps** (without a full report): call `patterns.engine.suggest_for(findings, target=ip, domain=..., has_credential=bool)` directly (§4e).

**Obsidian vault export is a SEPARATE feature** — `vault_export.export_vault(profile, dest_root) -> Path` (`vault_export.py:230`) — a point-in-time folder of linked-markdown notes that **rmtrees + recreates its slugged subfolder** and **contains credential values IN FULL**. Not the `report.md` clean-report path.

**Gotchas:** `autoescape=False` by design → heavy manual injection-hardening (CR/LF collapse; 3+-backtick runs broken with zero-width spaces to stop fence escape; manual PoC ``` → `'''`; command log run through `shell.redact_command`). Real credential values never appear in `report.md` (redacted); they **do** appear in the vault export. `render()` is side-effect-free; `write()` mutates disk.

---

## 6. Headless CLI commands (to shell out to)

Console script **`nabu-cli`** → `oscprecon.cli:main` (Typer). Only `--version/-V` is global; **each subcommand declares its own `--profile/-p`, `--workspace` (default `~/oscprecon`), and where relevant `--scan-profile`/`--port`.** Stdout stays clean for parsing; banner + `[error]`/warnings go to **stderr** (banner only on a TTY). Exit codes: **0** ok, **1** soft/no-match/need-root, **2** usage/validation/precondition. Line convention: `[tag]`-prefixed (`[profile]`, `[enum]`, `[vuln]`, `[finding]`, `[creds]`, `[error]`…).

| Command | Kind | Signature highlights |
|---|---|---|
| `scan` | **drives a scan** | `scan IP -p PROFILE [--hostname] [--scan-profile quick\|default\|full\|exam] [--udp-full] [--resume] [--force] [--dry-run] [--workspace]` — `Orchestrator.run_nmap`; `--dry-run` creates nothing; loads existing profile (history preserved); refuses IP mismatch (exit 2) |
| `enum` | **enumerates a service** | `enum [SERVICE] -p PROFILE [--port] [--as user\|user@domain\|guest] [--workspace]` — Tier-1, same as GUI panels; no-arg lists runnable services; `--as` re-runs authed **from the vault only**; writes findings.json + report.md |
| `vuln` | **drives a scan** | `vuln [SERVICE] -p PROFILE [--port] [--mode version\|enum\|vuln\|auth\|brute\|dangerous] [--show] [--all]` — NSE; `--show` dry preview; `brute` gated behind Spray mode |
| `exploit` | **queries catalog (display-only)** | `exploit [SERVICE] [-p PROFILE] [-t TARGET] [--port] [--suggested]` — no writes/audit; `--suggested` needs `-p` |
| `payload` | display-only | `payload [PAYLOAD] -l LHOST -P LPORT ...` — msfvenom command builder, runs nothing |
| `gtfobins` / `hashcat` / `pivot` / `searchsploit` / `docs` | display-only ref queries | `searchsploit PRODUCT [VERSION]` never downloads/runs PoC (§14) |
| `list` | query workspace | `list [--ip] [--archived/--no-archived] [--workspace]` — read-only |
| `findings` | report/query | `findings -p PROFILE [--service] [--workspace]` — severity-tagged, read-only |
| `add-finding` | **records** | `add-finding -p PROFILE VALUE [-k KIND] [-s SEVERITY] [--host] [--port] [-m MODULE] [-n NOTE] [--poc] [--reference] [--delete ID]` — writes findings.json, audits |
| `activity` | report | `activity -p PROFILE [-n LIMIT]` — audit timeline, read-only |
| `hosts` | **system edit** | `hosts [IP] [NAMES...] [-p PROFILE] [--file /etc/hosts]` — needs root; without it exits 1 and prints the sudo command |
| `doctor` / `health` | diagnostics | `doctor [--install] [-y] [--versions]`; `health -p PROFILE [--repair]` |
| `export-vault` / `export-project` / `import-project` / `delete-project` | export / workspace mgmt | export-* include **credential values in full**; `delete-project` is destructive |
| `creds list` / `creds add` / `creds rm` | vault | `creds add -p PROFILE -u USER -s SECRET [--type password\|hash] [-d DOMAIN] [--source]` |
| `config` | **settings gates** | `config [--spray/--no-spray] [--exploit/--no-exploit] [-p PROFILE]` — app-wide opt-in toggles |
| `spray` | **drives an attack** | `spray SERVICE{smb\|winrm\|ldap\|ssh\|ftp\|rdp} -p PROFILE [--port]` — gated behind opt-in Spray mode (OFF by default), exit 2 if disabled |

**CLI gotchas:** `doctor --install` and `delete-project` call `typer.confirm` — pass `-y/--yes` non-interactively or they block on stdin. `--as` reads secrets **only from the vault**, refused (exit 2) for ssh/dns. A GUI-locked profile makes write commands print a loud stderr warning (not refusal), except `delete-project` which refuses (exit 2). `creds add`/`spray` take secrets as CLI args → they land in shell history / `ps`. **For structured consumption, prefer reading the JSON artifacts directly** (`findings.json`, `audit.jsonl`, `profile.json`, `creds.json`) — the CLI prints human text, not JSON.

---

## 7. The `shell.py` exec chokepoint + audit + safety invariants (MUST preserve)

### 7a. The sole exec chokepoint (`src/oscprecon/shell.py`)

```python
run(shell_line: str, output_file: Path, *, cwd=None, timeout=None,
    cancel: threading.Event|None=None, on_line: Callable[[str],None]|None=None,
    spray: bool=False, exploit: bool=False) -> ShellResult
```

**Pipeline:** `shlex.split` (unbalanced quotes → exit 126, `blocked`, never raises) → `policy_violation(argv, spray, exploit)` non-None → writes `[blocked] <reason>` to `output_file`, returns exit **126** + `blocked`, **never executes** → `shutil.which` None → exit **127** + `missing_tool` → else `subprocess.Popen(argv, stdin=DEVNULL, stderr=STDOUT, start_new_session=True)`. **NO `shell=True`** — argv passed directly, so shell metacharacters are never interpreted. Timeout via `threading.Timer` that `killpg`s the whole group; cancel via poller thread. **`run()` never raises** — check `.blocked` / `.missing_tool` fields, do not `try/except`.

**`ShellResult`**: `shell_line, exit_code, output_file:Path, started_at, finished_at, duration_s, missing_tool:str|None, blocked:str|None, cancelled:bool`. Convention: **exit 126 + `blocked`** = policy/parse refusal (nothing ran); **exit 127 + `missing_tool`** = binary not on PATH; **`cancelled=True`** = killed on request.

### 7b. The policy gate

```python
policy_violation(argv, *, spray=False, exploit=False) -> str | None   # None = allowed
```
- **Empty argv** → `'empty command'`.
- **`exploit=True` → returns `None` IMMEDIATELY** (no allow-list, no flag checks). Per §2b, the human confirm in the Exploitation tab is the sole guardrail. **This is the ONLY path that runs tools outside `ALLOWED_TOOLS`.**
- **Recon/spray (`exploit=False`):** tool must be in `ALLOWED_TOOLS` (~70 exam-legal recon binaries; plus `SPRAY_TOOLS={hydra,medusa}` only when `spray=True`), matched by **both raw `argv[0]` AND basename** (stops path-prefix bypass). Non-spray: `_FORBIDDEN_FLAGS` (`--continue-on-success`, `--passwords`, incl. `=FILE`) refused. Per-tool deep checks key off basename: nmap `_nmap_selection_violation` judges what `--script` *selects* (refuses brute + `_THIRD_PARTY_LOOKUPS`); searchsploit `-m/-x/-u`; aws allow-list; netexec/nxc/crackmapexec `_netexec_violation` (>1 inline cred or list-file = spray); ike-scan `-P/--pskcrack`; ntpdate requires `-q`; DB clients `_db_primitive_violation` (`INTO OUTFILE`/`xp_cmdshell`/`load_file`/PG file funcs/redis `flushall`/mongo `.drop`).

### 7c. Audit trail (`src/oscprecon/audit.py`)

```python
record(profile_dir, profile_name, action, *, actor='user', details: dict|None=None) -> None   # best-effort, never raises
Auditor.record(...)
load_entries(...) -> list[dict]
```
Appends one JSON object per line to `<profile_dir>/audit.jsonl`: `{ts, actor:'user'|'system', action:kebab-slug, profile, details:{}}`. Rotates to `audit-archive/` at >5 MiB. The agent body **must record every executed / state-changing action with the SAME kebab slugs** the GUI/CLI use: `run-command`, `scan`, `enum`, `vuln`, `credential-added`/`-deleted`/`-spray`, `add-finding`/`finding-deleted`, `settings-changed`, `spray`, `set-hostname`, `add-hosts-entry`, `profile-created`/`-opened`/`-exported`/`-imported`/`-deleted`, `repair`, `vuln-scan`, `run`/`run-finished`. **Read-only actions write nothing.** `record` swallows all exceptions — never use it for control flow.

### 7d. Target validation & credential/spray syntax

```python
models.validate_host(value) -> str          models.validate_host_or_range(value) -> str
nmap_scan.validate_scan_target(target) -> str
nmap_scan._reject_unsafe_field(...)          # rejects [;&|`$><\n] + file-writing nmap flags in structured fields
peek.has_unsafe_peek_chars(...) / peek.is_peekable(...)   # attacker-controlled remote filenames before smbclient -c
```
Targets are interpolated then `shlex`-split, so they must never become a separate token: reject empty, leading `-`, ANY whitespace; accept only valid IP / strict DNS hostname / (for `_or_range`/scan) normalized CIDR. **Always validate before interpolation.**

**Credential syntax lives in ONE place** — `src/oscprecon/recon_auth.py` `ReconAuth` (frozen: `username, secret, secret_type, domain, kind∈{null,guest,cred}`; ctors `null()/guest()/from_credential(cred)`; builders `netexec_args()/smbclient_auth()/rpcclient_auth()/ldapsearch_args()/smbmap_args()/curl_userpass()/psql_uri()`). Modules never hand-build cred syntax. Single `-u user -p pass` is allowed; a list file is refused — that is the recon/spray line.

**Spray construction** (`src/oscprecon/spray.py`) is **pure construction, never executes**:
```python
spray.build_spray_command(service_key, target, users:Path, passwords:Path, port=None) -> str   # shlex.quotes paths, injects discovered port
spray.write_spray_lists(profile_dir, usernames, passwords) -> (Path, Path)                      # written 0600
```
Execution goes through `shell.run(..., spray=True)`, gated on `config.spray_enabled`.

### 7e. Safety invariants the agent body MUST preserve

1. **Every tool execution goes through `shell.run`.** Never subprocess a binary directly, never `shell=True`, never re-implement the allow-list.
2. **Authorized-scope-only.** Validate every target via `validate_host`/`validate_host_or_range`/`validate_scan_target` **before** interpolation, and confirm it is the **active profile's assigned target**. Spraying/exploiting anything else — the exam VPN, control panel, or any out-of-scope host — is a hard scope violation (§2a).
3. **No blind / auto attacks (§2b).** `exploit=True` **completely bypasses the policy gate** — it must be reachable **only** from an explicit, human-selected-and-confirmed action. An autonomous agent auto-setting `exploit=True` defeats every safety invariant. Reproduce the human-confirm step; never auto-set it.
4. **Spray is opt-in + confirmed.** Set `spray=True` only when `config.spray_enabled` **AND** the user selected + confirmed the creds for this run. Never against out-of-scope hosts.
5. **Build creds only via `ReconAuth.*`; build sprays only via `spray.build_spray_command`.** Never hand-assemble credential flags.
6. **Audit every executed / state-changing action** with the established kebab slugs so the timeline reads as one story. Read-only actions audit nothing.
7. **Check `ShellResult` fields, don't catch.** `blocked`/`missing_tool`/`cancelled` are the signal, not exceptions.
8. **Preserve the deep gates.** `shell.run` only allow-lists the first token; the nmap `--script`-selection gate and DB-client query gate are the deep checks — don't construct selectors/queries that route around them.
9. **Redaction ships OFF** (owner policy). `audit.jsonl`, logs, `report.md` command log, and spray output carry full cleartext secrets by design (spray files 0600). Know that output files and audit contain live creds; do not re-introduce redaction as a default, but treat these files as sensitive.

---

## 8. Reuse strategy: import-as-library vs shell-out-to-nabu-cli

| Subsystem | Recommendation | Why |
|---|---|---|
| **Scan launch + Tier-1 enum** (`Orchestrator`, `NmapModule`, `service_enum`, `alive`) | **Import as library** | Qt-free, gives you streaming (`on_line`), cancellation (`cancel` Event), and typed results in-process. The CLI is a thin wrapper over these. Replicate `cli.py _run_engine_enum`'s service→engine dispatch (there is **no factory** in `service_enum` — each front-end maps `smb→SmbEnum(prof,'full',...)`, `ftp→FtpEnum`, `ssh→SshEnum`, `dns→DnsEnum`, else `LdapEnum`; pass `mode='full'` to unlock deep conditional recon). |
| **Data model** (`Profile`, `findings`, `creds`, `graph_data`, `workspace.index`) | **Import as library** | This is shared mutable state — you need the in-process `RLock`/`fcntl` concurrency guarantees and the exact save/merge semantics. Shelling out would serialize every mutation through a subprocess and lose transactionality. |
| **Decision-aid catalog** (`exploit/`) | **Import as library** | Pure, read-only, executes nothing; `RankContext` should be built once and reused across many `rank_actions` calls — impossible efficiently across subprocess boundaries. `nabu-cli exploit --suggested` is a fine fallback for a quick one-off or a language boundary. |
| **Research surface** (`references`, `hacktricks`, `edb`, `patterns`) | **Import as library** | Pure importable functions; loaders degrade to empty rather than raise. The only shell-out (`searchsploit`) is already encapsulated inside `search_exploits` and routed through `shell.run`. |
| **Reporter** | **Import as library** | `Reporter(profile).render()` gives the markdown string with zero side effects — ideal for a web UI. Use `.write()` only when persisting. |
| **Exec chokepoint + audit + validation + spray/ReconAuth** (`shell`, `audit`, `models` validators, `recon_auth`, `spray`) | **Import as library — MANDATORY** | This *is* the safety enforcement layer. It must run in the same process as the agent body so there is exactly one chokepoint. Re-implementing or bypassing it is the single most dangerous mistake. |
| **CLI** (`nabu-cli`) | **Shell out only as a fallback** | Use for language boundaries (a non-Python worker), quick manual ops, or when you specifically want the CLI's exit-code/`[tag]` contract. For structured consumption, read the JSON artifacts (`findings.json`, `audit.jsonl`, `profile.json`, `creds.json`) directly rather than parsing human text. Never shell out to `nabu-cli` for the hot path — you'd lose streaming, cancellation, and in-process state. |

**Net recommendation:** Nabu Agent's Python body **imports the engine as a library** for everything, treating `src/oscprecon` as a read-only dependency. Reserve `nabu-cli` shell-outs for (a) non-Python components and (b) convenience one-offs. Wherever a scan or attack runs, it flows through the *imported* `shell.run`, never a subprocess of your own or the CLI.

---

## 9. Safety invariants to carry into the agent layer (checklist)

- [ ] **Single chokepoint:** every external tool runs through the imported `shell.run` — never `subprocess`/`os.system` directly, never `shell=True`, never a home-grown allow-list.
- [ ] **Scope lock:** target validated (`validate_host`/`validate_host_or_range`/`validate_scan_target`) **before** interpolation, and confirmed equal to the active profile's assigned target. No out-of-scope host, ever (exam VPN, control panel included).
- [ ] **No blind auto-exploit:** `exploit=True` is reachable **only** behind an explicit human select-and-confirm; the agent never auto-sets it. Autonomous ranking (`suggested_action_ids`) may *surface* actions but never *execute* them.
- [ ] **Spray gated twice:** `spray=True` only when `config.spray_enabled` **and** a per-run human confirmation with chosen creds; sprays built via `spray.build_spray_command`, wordlists via `write_spray_lists` (0600).
- [ ] **Credential syntax via `ReconAuth` only** — no hand-built `-u/-p`/hash flags; single inline cred only (list-file inline = spray path).
- [ ] **Check `ShellResult`**, don't `try/except`: handle `blocked` (126), `missing_tool` (127), `cancelled` as data.
- [ ] **Audit everything that runs or changes state** with the established kebab slugs (`run-command`, `scan`, `enum`, `vuln`, `credential-*`, `finding-*`, `spray`, `settings-changed`, …); read-only actions audit nothing; audit is best-effort — never gate logic on it.
- [ ] **Preserve deep gates:** don't craft nmap `--script` selectors or DB-client queries that route around `_nmap_selection_violation` / `_db_primitive_violation`; keep `peek` filename checks in front of any remote content read.
- [ ] **Respect lookup-only research (§14):** never persist or open `ExploitHit.path`; store EDB citations only via `edb.add_edb`; never transmit project/target data to live HackTricks (only `mapped_urls()` URLs, verbatim, no query/body).
- [ ] **Honor the catalog's scope (§2b):** it is a decision-aid, not a PoC DB — never add sqlmap/Metasploit/mass-scanner/named-CVE-delivery actions; `victim` (`runs_on`) actions are copy-only.
- [ ] **Respect pattern gates (§15):** suggestions must carry `# source:` provenance and must not contain exploit/cracking tokens (`cve-`, `msf*`, `meterpreter`, `hydra/medusa/patator/crowbar`, `sqlmap`, `rockyou`, spray flags).
- [ ] **Concurrency & read-only:** honor `ReadOnlyError` when a profile's `.lock` is held elsewhere; call `profile.save()` after non-auto-saving mutations; a separate agent *process* sharing a folder with a GUI is fcntl-protected only for `findings.json`.
- [ ] **Secrets ship un-redacted (owner policy):** treat `audit.jsonl`, `report.md` command log, `creds.json` (0600), and spray output as sensitive; vault/project exports contain full credentials.
- [ ] **Never modify `src/oscprecon`;** all new behavior lives in `nabu-agent/`.

---

*All file paths are under `/home/hacker/oscp-recon/`. Signatures and section references (§2a/§2b/§6/§14/§14a/§15/§17/§18) are drawn from the provided subsystem inventories and `CLAUDE.md`; verified against the live repo layout (183 exploit service modules, references/patterns/templates present). The `nabu-agent/` sibling folder does not yet exist and is to be created for the agent layer.*
