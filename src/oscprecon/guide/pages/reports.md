# Reports, vault & Obsidian

## `report.md` — the master report

Every project has an auto-generated **`report.md`** in its folder, rewritten after each scan event
(the prior version is archived to `report-archive/` first). It's **Obsidian-compatible** — YAML
frontmatter, heading outline, tags, callouts — so it drops straight into any vault.

Sections, in order:

1. Header + open-ports summary (TCP + UDP).
2. Discovered services, each with its HackTricks link and Exploit-DB hits.
3. Per-service findings.
4. **Suggested next steps** (from the pattern library, with sources cited).
5. **Pivot topology** (if you scanned internal `/24`s).
6. Your notes, and **Graph annotations** (notes you dropped on graph nodes).
7. The full command log — every command, with timing and exit code. Nothing is hidden.

Open it with **View → Report** (`Ctrl+R`) — the preview has **Regenerate** and **Open in
editor**. To hand it to someone else, use **File → Export to Obsidian Vault…** (a linked
folder of notes) or **File → Export Project…** (the whole project folder as a tar.gz).

## Export to an Obsidian vault

**File → Export to Obsidian Vault…** writes a linked folder of notes (index, per-service, findings,
credentials, commands) with frontmatter + wikilinks. It's a snapshot — re-export to refresh.

## The credential vault

Credentials you collect (or parse from loot) live in **`creds.json`** (chmod `0600`), editable in the
GUI: add / edit / delete. In the vault dialog secrets are shown **in full**, autosave on click-away.

- Successful anonymous / null-session enumerations auto-write an entry (`source: <module>-anon-enum`),
  so LDAP / RPC / WinRM modules reuse them without re-prompting.
- **Secrets are shown in full everywhere** — vault, reports, audit log, graph, and loot table (owner
  policy 2026-07-22: the loot is the deliverable and this is your own tool against your own authorized
  targets, so nothing is redacted). A `redact_secrets` setting exists but ships **off**; flip it on only
  for a hypothetical shared/public build. The graph keeps secrets out of its **search index** only.

## Project portability

Each `~/oscprecon/<name>/` folder is a self-contained project. **File → Export Project** packs it to
`<name>.tar.gz` (it **warns that `creds.json` is included**); **Import Project** unpacks one
(path-traversal-safe); **Open by IP…** finds a project by its target IP when you've forgotten the
name.
