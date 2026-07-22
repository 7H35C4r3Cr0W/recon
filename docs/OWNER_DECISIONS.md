# Owner decisions

Authoritative record of owner-approved policy changes. `CLAUDE.md` remains the enforced brief; this
file records *why* the relevant sections read as they do. Concise by design — not a progress log.

## Permanent product rules

1. **HackTricks follows the selected service's real context** and may be fetched and cached live,
   within the approved privacy and host boundaries below.
2. **Credentials are durable project data** stored in `<project>/creds.json` and remain there until
   the user explicitly edits or deletes them.

## Live HackTricks (approved 2026-07-13)

- Live fetching / extraction / caching is **approved** (amends the former blanket §2/§27 scraping ban).
- The **vendored offline pages remain the reliable fallback** and are never treated as less
  authoritative than the live cache.
- Live fetch retrieves **only the one canonical mapped page** for the selected service context, then
  filters to relevant sections **locally**. No site crawl. No arbitrary URLs.
- **Target/service data is never transmitted** — port, proto, product, version, module, findings pick
  and filter *local* display content only; never sent as query params, body, or headers.
- **Exploit-DB stays lookup-only** — `searchsploit` + linkout; never scrape/download/execute PoC.

## Project credentials (durable)

- Each project directory is the authoritative data unit; project creds live in `<project>/creds.json`.
- Manually added and confirmed credentials persist until an **explicit** user edit/delete.
- A **successful** auth never removes a credential; a **failed** auth never removes one.
- Close / restart / project-switch / archive / restore / report / graph / export / import / cancel /
  missing-tool / parser-failure must **not** remove credentials.
- Spraying draws from the **active project's** credential store (user-selected).
- Hydra/Medusa/NetExec temp input files are **derived artifacts, not the credential store**; they may
  be cleaned safely, but cleanup must **never** touch `creds.json` or durable credentials.

## Product name — "Nabu"

- The user-facing product is **Nabu** (tagline *Local Recon Workspace*). Display everywhere:
  window title, splash, About, status footer, CLI help, Doctor, README, packaging.
- The **internal Python package stays `oscprecon`** and the **distribution/wheel name stays
  `oscp-recon`** — renaming either buys nothing and would break installs, imports, and
  `importlib.metadata` lookups. `branding.py` is the single source of the display name.
- **No data migration.** Workspace root (`~/oscprecon/`), XDG config (`~/.config/oscprecon/`) and
  cache (`~/.cache/oscprecon/`) are unchanged; existing projects keep working untouched.
- Entry points: `nabu` (GUI) and `nabu-cli` (headless) are preferred; `oscp-recon`, `oscprecon`,
  and `oscprecon-cli` remain as **legacy aliases for ≥1 release** so existing scripts don't break.
- **Visual identity is original and offline** — hand-authored SVGs in `src/oscprecon/gui/assets/`
  (cuneiform stylus + network-graph motif). No copyrighted/commercial artwork, no runtime asset
  fetch, no telemetry. Palette: deep ink/navy, gold/bronze accent, muted teal secondary.
- **The CLI must not emit ASCII-art banners** into piped/subcommand/machine-readable output; the
  splash wordmark is GUI-only.

## Risk framing — conservative by construction

- `finding_severity.classify()` is the **one** place that decides how a finding is visually framed.
- **Nothing is ever labelled a vulnerability from an open port, a product/version banner, or an
  Exploit-DB search hit alone.** Those are neutral facts / references.
- Only explicit weak-posture finding *kinds* escalate: anonymous/guest auth → access; null session /
  world-readable / writable / no_root_squash → exposure; SMB signing **disabled** (not merely
  present) / open-relay / weak-algo → relay-risk. A username or share *name* stays informational.
- Exploit-DB is a **reference badge**, never a confirmed vuln, and never the graph's danger ring.
- **NO REDACTION (owner, 2026-07-22).** The tool never hides secrets — hashes/PSKs/passwords are the
  assessment deliverable and this is the operator's own tool on their own authorized targets. Command
  logs, audit, reports, the graph credential nodes, spray output, SNMP findings, and the credential
  vault all show the **full** value. Masking helpers remain but ship **off** (`shell.REDACT_SECRETS` /
  `config.Settings.redact_secrets`, default `False`). Secrets stay **excluded from graph search** only
  to keep the search index clean, not to hide them.

## Process

- Finish one major implementation chunk before starting another.
- Do not auto-select and begin another feature after a completed chunk.
