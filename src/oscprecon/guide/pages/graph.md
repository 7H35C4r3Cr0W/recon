# The attack-surface graph

Press **`Ctrl+G`** (or **View → Graph**) for a BloodHound-style view of everything the scan found.

## Reading it

Nodes are icon discs with a colour per type and up to four **corner glyphs** (danger / OS / status /
note). The colour key is in the on-canvas **Legend**:

- **Target** — the entry host (dark blue, a radar disc).
- **Service** — light blue (TCP) / green (UDP).
- **Finding** — yellow. **Credential** — red (shown in full on the canvas; kept out of the search index only).
- **Exploit-DB reference** — lavender (something to *read*, never a confirmed vuln).

A red ring marks a *notable* finding (anonymous access, writable share, weak signing).

## Driving it

- **Single-click** a node → its full detail (IP / OS / service+version / a /24's host count) in the
  side panel, plus a **status** (`new` / `investigating` / `done` / `dead-end`) and a **note**.
- **Right-click** a node → every one of those actions in one menu: the four status marks (the current
  one ticked — pick it again to clear it), *Add / Edit note…*, *Select in service tree →* (jumps back
  to that port's tooling), *Copy label / IP / subnet / target:port*, and *Open project folder*. The
  same menu is on the summary-tree rows. On a read-only project (open in another window) the status
  and note entries are replaced by a read-only notice.
- **Double-click** the entry, a `/24`, or a host to **drill down** — it opens centred on one node and
  expands `entry → /24 → host → service`, re-laying-out into a clean tree. Double-click the entry
  again to fold it all back to one node.
- **Zoom** with `+`/`−` or the wheel; **drag the canvas** to pan (hand cursor); **drag a node** to
  move it (positions persist).
- **Link mode** draws a `relates-to` edge between any two nodes. **Search** highlights matches and
  dims the rest. **Export** the graph as PNG or SVG for your report.

Notes you add here appear in **`report.md`** under *Graph annotations*.

## Pivot topology (CTF / AD)

For an engagement that starts at one host and pivots inward (you tunnel with **ligolo-ng**), scan an
internal `/24` — hosts **stream** into both the tree and the graph as they're found, grouped by
subnet with the pivot source they were reached through. Right-click to remove a host/subnet or
re-scan a host deeper; the tree and graph stay in sync.

## Always-visible fallback

The graph also shows a native **summary tree** (target → services → findings → credentials) that
works even where the embedded web canvas can't render (headless / no-GPU VM) — status and notes work
there too, so you never lose your scan data.

The canvas recolours with the app theme; the semantic node colours above stay fixed so the legend
always reads.
