# Nabu screenshots

Generated from **synthetic demo data only** — target `10.10.10.100 / demo.local`, no real hosts,
no real credentials (the one demo secret is masked to its length, exactly as in the live UI).

Regenerate after UI changes:

```bash
QT_QPA_PLATFORM=offscreen uv run python docs/screenshots/generate.py
```

| File | What |
|---|---|
| `shell-light.png` / `shell-dark.png` | Full application shell: primary nav rail, compact header, three-pane recon, notes dock, status footer (both themes) |
| `dashboard-empty.png` | Workspace dashboard empty state (illustration + primary CTA) |
| `findings.png` | Findings view — search + category filter, conservative colour categories |
| `credential-vault.png` | Credential Vault — masked secrets, primary/destructive button ranking |
| `smb-tool-panel.png` | SMB tool panel — Tier-1 primary action ranked above Tier-2 follow-ups |
| `reference-offline.png` | Reference pane — offline HackTricks with the source tier badge + finding-aware jump |

The graph (Cytoscape) and live-HackTricks panes need Chromium/QtWebEngine and are not captured in
this headless offline render; the offline reference render stands in for the reference pane.
