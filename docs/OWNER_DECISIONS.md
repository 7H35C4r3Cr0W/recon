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

## Process

- Finish one major implementation chunk before starting another.
- Do not auto-select and begin another feature after a completed chunk.
