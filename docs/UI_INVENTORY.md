# UI inventory — pre-Nabu baseline

Code-based inventory (the GUI runs only headless/offscreen here, so this is from reading the widgets,
not a live click-through). Drives the Nabu UI/UX pass. Concise by design.

> **Status — superseded (historical baseline).** This is the *before* snapshot that drove the Nabu
> UI/UX pass; every gap listed below was subsequently addressed (compact header, dashboard empty
> state + illustration, dedicated Findings view, graph legend, feedback banner, accessibility sweep,
> and the Nabu + owl-furby brand mark). Kept as a record of what the pass fixed. For the **current**
> UI see the [README](../README.md) and [`PROJECT_MAP.md`](../PROJECT_MAP.md). Shipped nav: Workspace · Recon · Graph · Findings ·
> Credentials · Notes · Report · Activity; the header carries the brand mark, and
> **Help → View Diagnostics Log** opens the crash/error log (§ 19a).

## Product identity
- **Name is inconsistent / unbranded.** Window title, status footer, and splash all say `oscp-recon`;
  the splash paints an "OSCP RECON" ASCII wordmark. No About dialog. No cohesive mark or palette.
- Colours are **scattered literals** across widgets (`#0b0f14`, `#7fd1b9`, `#c0392b`, `gray`, etc.) —
  no shared token layer. `gui/theme.py` handles light/dark palette + font but not a design system.

## Already good — preserve
- Three-pane recon shell, workspace dashboard, graph (Cytoscape + minimap + search + notable ring +
  drill-down), Credential Vault table (masked + copy + confirmed column), Spray dialog (grouped,
  gated), reference pane (offline/cached/live tiers + finding jump), Doctor dialog, Preferences (tabs),
  status footer, audit log. These WORK — the pass is presentation, not re-architecture.

## Gaps to address (by area)
- **Shell/header:** no compact header showing project · target · read-only · running-task count ·
  quick-return-to-workspace in one consistent strip; info is spread across the footer + window title.
- **Dashboard:** empty state is text-only (no illustration/clear primary actions); rows are dense text
  without a strong name/target/status hierarchy or compact badges.
- **Service tree:** port/proto/product alignment + finding/status badges rely on text; TCP/UDP not
  visually distinct beyond the graph.
- **Tool panel:** Tier-1 / Tier-2 / Spray actions not always visually ranked; primary vs. destructive
  vs. disabled states inconsistent.
- **Output:** monospace but lacks search-in-output / wrap toggle / copy-all / explicit exit-status chip.
- **Reference pane:** tiers exist but the source state + "why this section" + refresh time aren't
  always surfaced together; no prev/next match affordance beyond find-in-page.
- **Graph:** search + notable ring + drill-down landed, but no **legend**, and node semantics are still
  fairly flat (findings mostly one yellow; no conservative info/notable/warning tiering surfaced).
- **Findings:** no dedicated findings view (group/filter/search) — findings live only under services.
- **Dialogs:** button ordering / Enter-activates-primary / near-field validation / accessible names are
  not uniform; icon-only controls lack consistent tooltip+focus treatment.
- **Feedback:** loading / partial-success / blocked / missing-tool / parse-warning states are logged to
  output but not surfaced as consistent inline banners/chips.
- **Accessibility:** focus visibility, colour-independent status, and accessible names are patchy.
- **UI-state persistence:** window size/splitters/last-view/column-widths not persisted.

## Rename surfaces (Chunk 2 targets)
window title · status footer · splash wordmark · `setApplicationName` · CLI help title · README H1 ·
`packaging/*.desktop` `Name=` · AppImage output filename + desktop metadata · Doctor + version display ·
new About dialog · `nabu` / `nabu-cli` entry points (legacy `oscp-recon`/`oscprecon-cli` kept).
Internal package `oscprecon` and all data paths (`~/oscprecon`, `~/.config/oscprecon`,
`~/.cache/oscprecon`) stay unchanged for compatibility.
