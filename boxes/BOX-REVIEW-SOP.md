# Box-review SOP — how Nabu gets validated against a box

**This is the standing procedure for reviewing Nabu against an HTB / OSCP-style box.**
It captures every instruction the owner has given across box reviews so it doesn't have to be
repeated. Follow it top-to-bottom for each box, then append the result to
[`STARTING-POINT-LOG.md`](STARTING-POINT-LOG.md). Companion: [`../CLAUDE.md`](../CLAUDE.md) is the
authoritative product brief; this file is *process*, not product.

The one-line loop:

> **recon → attack → check bugs → check UI / UX / GUI / graph → fix errors → mark down the box
> → keep docs in sync → run the gates → commit + push → report once. Rinse, repeat.**

---

## 0. Ground rules (always)

- **Recon-only stays exam-legal by default.** Everything past enumeration — cracking, SQLi, reverse
  shells, credential *use*, privesc execution — is **manual exploitation** and out of the recon tool.
  The Exploitation tab *builds* + *human-confirms* attack commands; it never auto-runs a chain.
- **Walkthroughs (CLAUDE.md §21):** read silently, extract **recon/attack-surface insights only**.
  Never reproduce walkthrough prose, never hardcode creds/wordlists/hashes, never paste exploit code
  into recon patterns. A walkthrough tells you *what the box should surface*, not what to copy in.
- **Be efficient.** Don't block on the slow `nmap -p-` sweep — the money ports are almost always in
  the top-1000, so drive recon on them the moment quick-discovery returns and let `-p-` finish in the
  background as a safety net. Probe a service's ground truth directly (curl/whatweb) when deciding a
  fix, instead of spinning up heavy harnesses.
- **Only touch what exists.** Recon and attacks run **only for services the scan discovered** — never
  fan out to services that aren't there. (Recon is already gated: tree = discovered services,
  per-panel Run, no run-all. The exploit present-list must stay focused — a bare web port marks
  only generic `web`/`webdav`, not 70 specific apps.)
- **Independent + chunked.** Do the whole loop without asking between steps; report **once** at the
  end with what happened. Don't baby the owner with "shall I…?" mid-task.

---

## 1. Recon

1. **Scan.** `nabu-cli scan <ip> -p htb-<box> --scan-profile default` (TCP top-1000 → `-p-` →
   versioned → UDP top-100). If the host blocks ping, use the custom-scan dialog with `-Pn`.
2. **Drive the discovered services** through the real workers (headless is fine — it's the exact GUI
   code path): SMB via `SmbReconWorker`, banner-only services via `SimpleReconWorker`, HTTP via the
   **Fingerprint** button (whatweb → structured findings) + content discovery.
3. **Focus on the box's real attack surface** first (the 1-2 services that matter); smoke-check the
   rest just *render* correctly — don't do a full run on every discovered service.
4. **HTTP/HTTPS specifically:** run the Fingerprint (surfaces server/title/versions — keep the plugin
   *values*, e.g. `Title[UniFi Network]`, `Apache[2.4.41]`); run content discovery; confirm the
   **Discovered URLs** table fills cleanly (Status · Method · Lines · Words · Bytes · URL, clickable,
   Export CSV) — it's the owner's preferred way to read dir-bust results. Non-standard ports
   (8443/8080/65000…) must be treated as HTTP/HTTPS and versioned.
5. **Bounded read-only enrichment is good:** peek *any* small data-bearing file (not a text-extension
   allowlist), redact nothing into structured findings that would leak a secret, keep the raw
   artifact on disk.

## 2. Attack (do this for every box — not just recon)

1. Open the **Exploitation tab** mentally/▸ for the discovered services. Confirm the **present-list is
   focused** (`●` = services the scan actually found, bound to the real discovered port).
2. Walk the box's actual chain and confirm each step has a catalog action: web (LFI/XXE/upload
   webshell/SQLi-technique), the service exploits (smb/mssql/tftp/…), and the **privesc** (linux:
   sudo/GTFOBins, SUID, cron, capabilities, **group membership: lxd/docker**, writable path;
   windows: SeImpersonate/potato, **scheduled-task hijack**, service misconfig, AlwaysInstallElevated).
3. **If the box's actual root/foothold technique is missing from the catalog, add it** — victim-side
   / copy-only, exam-legal manual attack script, `source=` a real reference (HackTricks / the vault),
   never sqlmap/Metasploit/scanner as a service action.
4. Every attack action stays **human-selected + confirmed**; the "service not found on the target"
   warning must fire for a non-present *network* service but **never** for portless post-ex catalogs
   (linux/windows/shells).

## 3. Check bugs + UI / UX / GUI / graph

- **Parsers:** anchor on structure (not first-word / greedy); keep *values*, not just names; the
  emitted command and its parser must speak the same format.
- **GUI/UX:** every panel renders for the selected service; Tier framing holds (Tier-1 auto, Tier-2
  shown-not-run, Tier-3 gated); no false "empty" where a step failed ("⚠ step did not run").
- **Graph:** toggle it (Ctrl+G) — the native **ReconSummaryTree** must show target → services →
  findings (nested under their service) → credentials. (The WebEngine Cytoscape canvas renders on the
  real X display; it's blank in offscreen/headless — that's the documented fallback, not a bug.)
- **Verification tools:** offscreen widget grabs always work (`QT_QPA_PLATFORM=offscreen` +
  `widget.grab().save()`); the real display at `DISPLAY=:0.0` gives full-window shots but blanks
  sometimes (retry). `set_services()` is in-memory + persisted by the caller — a reload-from-disk
  harness must save first, or services "vanish" (harness artifact, not a bug).

## 4. Fix errors

One cohesive change at a time. Add/adjust a **fixture + test** for every parser/behaviour change
("fix the code *and* the test" — the tests encoded the wrong assumption if a live box broke them).

## 5. Mark down the box

Append to [`STARTING-POINT-LOG.md`](STARTING-POINT-LOG.md): a summary-table row **and** a per-box
note. Record: box #, name, IP, key services, **whether it was recon / attack / both**, the tool's
response, the **bug → fix** (or "clean — no bug", a valid outcome), a one-line **lesson**, and the
**commit hash**. A clean box is a real result — mark it and move on, don't invent a fix.

## 6. Keep docs in sync

Every code change updates, as relevant: `README.md`, `CLAUDE.md`, and the in-app guide
`src/oscprecon/guide/pages/*.md` (powers Help → Documentation + `nabu-cli docs`).

## 7. Gates (all four, before every commit)

```bash
uv run ruff check
uv run ruff format --check
uv run mypy --strict src/
QT_QPA_PLATFORM=offscreen uv run pytest -q     # slow on a loaded VM (10–20 min) — confirm exit 0 + [100%]
```

## 8. Commit + push + report

- Commit to `main` (repo convention), push `git push github main`. If the log row cites its own
  commit hash, a tiny follow-up `docs(log): record box #N commit hash` closes it.
- End-of-commit trailers per the harness (Co-Authored-By + Claude-Session).
- **Report once**, leading with the outcome (what happened / what was found), then the detail.

---

## Definition of done (per box)

- [ ] Recon driven live on every discovered service; HTTP fingerprint + Discovered URLs verified.
- [ ] Attack coverage checked in the Exploitation tab; the box's real chain is present (or added).
- [ ] Bugs + GUI/UX/graph checked; anything broken is fixed with a test.
- [ ] Docs synced.
- [ ] All four gates green.
- [ ] Box marked down in the log (recon/attack/both, bug→fix or clean, commit hash, lesson).
- [ ] Committed + pushed; reported once.
