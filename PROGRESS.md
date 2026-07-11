# oscp-recon — progress log

Running record of what's been built, in order, so any session can pick up mid-stream.
**Read "Next up" first, then the newest log entry.** Authoritative specs live in `CLAUDE.md`
(the brief) and `ROADMAP.md` (the phase plan); this file is "where are we right now".

## Next up

**Phase 2 COMPLETE — all 14 modules have engine + adversarial review + GUI panel** (http, vhost, smb,
ftp, ssh, dns, ldap, smtp, nfs, snmp, tftp, netbios, ike, ntp) + status footer QoL. All 14 done,
reviewed, hardened, GUI'd (347 tests).

### ⚠️ ORDER — we are JUMPING Phase 3 → Phase 4 (user decision 2026-07-11). DO NOT SKIP PHASE 3.
**Phase 3 (pattern library + suggestion engine) is DEFERRED, not done.** It is BLOCKED on `# source:`
provenance (§15): no walkthroughs/box notes are committed yet. The user is loading their Obsidian
notes / box writeups onto Kali **separately** to unblock it. **Do NOT build pattern entries or mark
Phase 3 complete until real `walkthroughs/*.md` or `boxes/*.md` sources are committed.** After Phase 4,
**return to Phase 3.** (Phase 3 deliverables still owed: `patterns/engine.py`, per-service
`patterns/<svc>.yaml` with the provenance build-gate, "Recon next steps" tool-panel section with
pre-fill-no-autorun, report "Suggested next steps" with citations.)

**NOW: Phase 4 — Bloodhound-style graph view (§16, §23).** Deliverables: `gui/widgets/graph_view.py`
(QWebEngineView + vendored offline Cytoscape.js, NO runtime CDN), `QWebChannel` GraphBridge
(get_data / node_clicked / status_changed / add_user_edge / save_layout), `gui/graph_html/`
(index.html + app.js + cytoscape.min.js + style.css), node/edge types + colors per §16, `graph.json`
persistence (user edges, node positions, per-node status/notes), `View → Graph` (Ctrl+G) toggle, and
the §16 QUEUED reinforcements (drag-drop persistence, right-click Add Note→graph.json+tooltip+report,
minimap + edge labels, PNG/SVG export). Also queued/owed after Phase 4: project file ops (§19), audit
log (§6a), concurrent-copy lock (§6b), the rest of Phase 5 QoL, Phase 6 doctor/exam-preset.

Recurring review lessons: parsers must match REAL current tool output;
always release the worker slot in a finally/guard; make on-disk artifact filenames injective; thread
the service port through every command; **validate every user/server-supplied token that reaches a
command line (host via validate_host, domain via normalize_domain, base DN via sanitize_basedn) —
the manual-follow-up path must validate too, not just the recon button.**

## Queued additions (recorded 2026-07-11 — do NOT build early; pick up at the noted phase)

Five features queued into `CLAUDE.md` + `ROADMAP.md` for a fresh session to build at the right time.
Specs are authoritative in CLAUDE.md; this is the pointer list.

1. ~~**Status footer** (CLAUDE.md §19)~~ — **DONE** (Phase 2 QoL): QStatusBar strip with app+version,
   active profile, workspace root, and the muted "recon-only — OSCP exam legal" reminder.
2. **Project file operations** (CLAUDE.md §19) — File → Open by IP / Import Project / Export Project
   (.tar.gz; warns `creds.json` included). Each `~/oscprecon/<name>/` is a project file. → Phase 5.
3. **Full GUI audit log** (CLAUDE.md §6a) — append-only `<profile>/audit.jsonl` of every user action;
   report "Audit trail" appendix. Wire emit points as earlier UI lands (cheap backfill). → Phase 5.
4. **Concurrent-copy lock** (CLAUDE.md §6b) — `<profile>/.lock` (flock) + "open read-only?" prompt +
   stale-PID reclaim. → Phase 5.
5. **Graph presentation polish** (CLAUDE.md §16) — drag-drop repositioning, right-click Add Note,
   persistent layout, minimap + edge labels, PNG/SVG export. → Phase 4 (amends existing deliverable).

## How to resume

1. `cd ~/oscp-recon` (repo is local-only, no git remote yet). `uv` lives at `~/.local/bin/uv`; run `uv sync` if deps are missing.
2. Gates before every commit: `uv run mypy --strict src/`, `uv run pytest -q`, `uv run ruff check`, `uv run ruff format --check`. GUI tests need `QT_QPA_PLATFORM=offscreen`.
3. Commit each chunk once gates are green — no need to ask. Show any new *wrapped command* before writing it (CLAUDE.md §27); only recon tools on the §2 allowlist.
4. Update this file with each chunk and commit it alongside that chunk.

## Log (newest first)

### Phase 4 · graph view — chunk 3b: PNG / SVG export (§16)
- Toolbar **Export PNG** / **Export SVG** buttons. PNG uses Cytoscape's built-in `cy.png()` (scale 2,
  full graph); SVG uses the vendored **cytoscape-svg 0.4.0** extension (`cy.svg()`), registered via
  `cytoscape.use(window.cytoscapeSvg)`. app.js sends the image to `bridge.export_image(format, data)`.
- `GraphBridge.export_image` → `export_requested(format, data)` → `GraphView._on_export` opens a
  QFileDialog and writes via the testable `_write_image` (PNG: strip the `base64,` data-uri prefix +
  b64decode → bytes; SVG: write the string verbatim).
- Verified in a real webengine render that both `cy.png` and `cy.svg` are registered functions
  (`true|true`). 11 graph tests (added export-emit + write-image png/svg). 364 tests, gates green.

### Phase 4 · graph view — chunk 3a: node-detail sidebar + native status/note UI
- **`GraphDetail`** sidebar (left of the web view in a QSplitter): shows the tapped node's label +
  a `type · port · module · source · detail · status` line, four **Status** buttons
  (new/investigating/done/dead-end), a **Note** editor + Save, and (for service nodes) an
  **"Open service tooling →"** button. app.js now sends `evt.target.data()` with the tap so the
  sidebar has the full node; `GraphBridge.node_selected` became `(id, data)`.
- Status/note edits go through the bridge → graph.json and reload the graph so the border/badge
  updates live. The old "tap a service node yanks you to the three-pane" behavior became an explicit
  button: `GraphView.service_open_requested(port, proto)` → main_window switches + selects.
- 9 graph GUI tests (bridge id+data, detail show/emit, view persistence, service-open switch). Real
  headless render re-verified (4 nodes, no warnings). 362 tests. **Chunk 3b:** PNG/SVG export.
  **Chunk 3c:** drag-to-draw relates-to edges + minimap.

### Phase 4 · graph view — chunk 2: GraphView widget + Cytoscape HTML/JS + View→Graph
- **`gui/graph_html/`**: index.html (loads Qt's `qrc:///` qwebchannel.js + the vendored
  cytoscape.min.js), app.js (Cytoscape init with the §16 node/edge colors — target ellipse / TCP blue
  / UDP green / finding yellow / credential red, status borders, dashed relates-to; hierarchical +
  force-directed layouts; tap → `bridge.node_clicked`; dragfree → `bridge.save_positions`), style.css.
- **`gui/widgets/graph_view.py`**: `GraphBridge` (QWebChannel QObject) serves `get_data()` (the
  build_elements JSON) and persists edits to graph.json — `set_status` (validated), `add_note`,
  `save_positions`, `add_user_edge` — and emits `node_selected` on a tap. `GraphView` hosts the
  QWebEngineView + channel with the same graceful QtWebEngine fallback as the reference pane.
- **main_window**: central QStackedWidget (three-pane ↔ graph); View → Graph (Ctrl+G, checkable)
  toggles + reloads on show; a service-node tap switches back to the three-pane and selects that
  service so its detail shows. `set_profile` feeds the graph.
- **Verified with a real headless QtWebEngine render**: draws all nodes (probe: cytoscape loaded, 4
  nodes for target + 2 services + 1 finding), no console warnings after tightening the edge-label
  selector + dropping the custom wheel-sensitivity.
- 7 GUI tests (bridge get_data / click / persist / edge / bad-json, fallback construct, toggle,
  service-node switch-back). 360 tests. **Next chunk 3:** native status/note UI on `node_selected`,
  drag-to-draw relates-to edges, minimap, PNG/SVG export, node-detail sidebar.

### Phase 4 · graph view — chunk 1: data model + graph.json persistence
- **`gui/graph_data.py`** `build_elements(profile)` — pure-Python (no Qt) Cytoscape elements builder:
  target → services (`has-service`) → findings (`exposes-finding`, linked to the owning service via the
  references module→port map, else the target) → credentials (`references-credential`, secret REDACTED
  via `creds.redact` — never reaches the graph). Overlays `graph.json`: per-node status
  (new/investigating/done/dead-end, validated), note, saved position, and user-drawn `relates-to` edges
  (a dangling edge whose endpoint no longer exists is dropped so Cytoscape never errors).
- **`Profile.graph_path` / `load_graph` / `save_graph`** — atomic write mirroring profile.json; load
  returns the `{user_edges, node_overrides}` default when the file is absent or corrupt.
- Cytoscape.js 3.30.2 vendored offline to `gui/graph_html/cytoscape.min.js` (committed with chunk 2).
- 6 unit tests (structure, module→service finding links, redaction, overrides + user-edge filtering,
  invalid-status rejection, persistence round-trip). 353 tests. **Next chunk 2:** GraphView widget
  (QWebEngineView + QWebChannel bridge) + `graph_html/` (index.html/app.js/style.css) + View→Graph
  (Ctrl+G). **Chunk 3:** interactions (click→detail, right-click Add Note/status, drag-edge relates-to,
  drag-position persistence), minimap, PNG/SVG export.

### Phase 2 · QoL — status footer (§19)
- Always-visible `QStatusBar` strip: `oscp-recon v<version>` (importlib.metadata, falls back to
  0.0.1), the active profile (`profile: <name>` / `no profile loaded`), the workspace root, and a
  muted permanent `recon-only — OSCP exam legal per CLAUDE.md §2` reminder. `_update_status_footer`
  refreshes it on every profile load. Closes queued item #1. 347 tests, four gates green.

### Phase 2 · GUI — generic simple-recon panel for the 7 engine-only modules
- **SimpleReconPanel** (`gui/widgets/simple_recon_panel.py`) + **SimpleReconWorker** (`main_window.py`)
  + **registry** (`gui/simple_recon.py`): ONE panel type for the read-only single-shape modules
  (smtp/nfs/snmp/tftp/netbios/ike/ntp) instead of 7 bespoke widgets. Each `SimpleReconSpec` supplies the
  Tier-1 button label, intro, `manual_commands.yaml`, a module factory (for the uniform
  `Module.parse`/`suggest`), and a typed step-provider (snmp adds the public MIB walk; tftp fans out the
  COMMON_FILES GETs) — so the base Module never needs the concrete step methods.
- The worker runs the Tier-1 steps through the policy-enforced `shell.run`, builds `raw_outputs` keyed
  by tool, calls `module.parse()` → base Findings → `findings.json`, and produces a per-kind summary +
  `suggest()` next-steps. Empty parse writes nothing (mirrors the ssh worker).
- `tool_panel` adds one SimpleReconPanel per module to the stack, dispatches by `ref.module`, forwards
  `simple_recon_requested(name)` + Tier-2 manual follow-ups (validated at the shell chokepoint), and
  disables them during a scan. `main_window` wires the worker with the standard worker-slot /
  `_finish_worker` guard.
- 12 GUI tests (ntp + netbios worker parse→findings, empty case, panel dispatch + signal forwarding,
  manual-legality across all 7 specs). Updated the one widget test that assumed smtp used the generic
  hints page (smtp now has a panel; mysql covers the generic page). 346 tests, four gates green.

### Phase 2 · modules 13–14 (ike, ntp) — hardening
Adversarial reviews (verified against real ike-scan / ntpq / ntpdate output). Both modules were clean
on their OWN commands; the confirmed defects were parser gaps + a shared exec-chokepoint backstop gap
(the recurring "the sole §2 chokepoint must enforce the invariant, not just the module" theme).
- **ike correctness (LOW–MED): SA transform truncated on a nested-paren lifetime.** Real ike-scan
  encodes the lifetime as `LifeDuration(4)=0x00007080` — a nested paren — so `SA=\([^)]*\)` cut the
  transform off there. Allow one level of nesting (still stops before the aggressive-mode trailing
  payloads KeyExchange(..)/Nonce(..)/ID(..)/Hash(..)).
- **ike §12 (MED): exec chokepoint didn't block ike-scan PSK capture.** shell.py enforces every other
  §2 rule but let `ike-scan --pskcrack` / `-Pfile` through — the module never emits it, but the §19
  custom-command surface could. Added an ike-scan guard (prefix-matches the concatenated `-Pfile`).
- **ntp §2 (MED): exec chokepoint didn't enforce the `ntpdate -q` invariant.** Bare `ntpdate <target>`
  SETS the local clock; the module always uses -q but the chokepoint didn't back-stop it. Now blocks
  ntpdate without -q.
- **ntp correctness (LOW): `parse_ntpdate` dropped an IPv6 server.** The regex hard-coded a dotted
  quad; Target accepts IPv6. Broadened to a non-greedy server capture. Regression tests for all four
  (incl. shell-policy tests for both backstops).

### Phase 2 · module 8 (smtp) — hardening
Adversarial review (verified against the real `smtp-*.nse` sources, nmap 7.99). 2 confirmed parser
gaps; compliance/injection clean.
- **correctness (MED): verbs on the smtp-commands HELP line were dropped.** `smtp-commands.nse` returns
  TWO payloads — EHLO extensions AND the HELP response — on two lines (`| smtp-commands: ...` then
  `|_ This server supports the following commands: ... VRFY EXPN`). `_verbs` read only the first, so
  VRFY/EXPN (base SMTP verbs that often surface ONLY on HELP) were missed — the module's headline
  user-enum capability. Now reads both lines (deduped).
- **correctness (LOW): banner missed on ssl/smtp (465) + submission (587).** The module triggers on
  those ports but `_SMTP_VER` required the service token to start with `smtp`; nmap prints `ssl/smtp`
  and `submission`. Broadened the regex. Tests added for both.

### Phase 2 · module 14 (ntp) — engine — ALL 14 PHASE-2 MODULE ENGINES COMPLETE
- **NtpModule** (`modules/ntp/`, UDP 123): triggers on 123 / ntp. Tier-1 read-only: `ntpq -c readlist`
  + `ntpq -c sysinfo` + `ntpdate -q` (always `-q` — recon never adjusts the local clock).
- **parsers.py**: `parse_ntpq` pulls `version`/`system`/`processor` (host fingerprint) from the
  `key="value"` readlist form and stratum from either `stratum=3` (readlist) or `stratum:  3`
  (sysinfo); `parse_ntpdate` extracts stratum + server from the `server IP, stratum N` line. Dispatch:
  ntpq-readlist/ntpq-sysinfo → parse_ntpq, ntpdate → parse_ntpdate.
- `suggest()` uses the disclosed version/OS to fingerprint and points at ntp-monlist (Tier-2 nmap).
  Tier-2 `manual_commands.yaml` (5): readlist/sysinfo/peers, `ntpdate -q`, nmap ntp-info/ntp-monlist —
  ntpdate is only ever used with `-q` (enforced by both the module and a manual-legality test).
- shell.py: install hints for ntpq (ntpsec) + ntpdate (ntpsec-ntpdate). 9 tests.

### Phase 2 · module 13 (ike) — engine
- **IkeModule** (`modules/ike/`, UDP 500): triggers on 500 / isakmp. Tier-1 read-only: `ike-scan -M`
  (detect the IKE/ISAKMP VPN responder + its main-mode transform) + `ike-scan -M -A` (aggressive-mode
  check). No `-P` / PSK-hash capture — offline PSK cracking is out of scope for this recon tool.
- **parsers.py**: `parse_ike_scan` flags main-mode (`service`) and aggressive-mode (`aggressive`
  enabled — PSK-material disclosure) handshakes and extracts the SA transform (Enc/Hash/Group/Auth) for
  either; dispatch keys `ike-scan` + `ike-scan-aggressive` both map to it (distinct keys avoid the
  raw_outputs collision).
- `suggest()` notes aggressive mode (recon only — explicitly states offline PSK cracking is out of
  scope) or a bare VPN presence. Tier-2 `manual_commands.yaml` (5): detection, aggressive check,
  transform enumeration, named-group aggressive, nmap ike-version. No PSK capture/cracking anywhere.
- 8 tests (parsers + module incl. a "no -P" assertion + a manual no-PSK-crack check).

### Phase 2 · module 12 (netbios) — hardening
Adversarial 3-lens review (verified against real nmblookup/nbtscan output). 4 candidates, 1 CONFIRMED;
3 refuted.
- **parser-correctness (MED): order-dependent `<03>` classification.** The `<03>`-messenger-vs-hostname
  suppression was single-pass, so if the target returned a host's `<03>` row before its own `<00>` row
  (RFC 1002 node-status ordering is target-controlled), the box's OWN computer name was misreported as
  a logged-in user and `suggest()` advised user-enum against it. Made `parse_nmblookup` two-pass:
  collect all `<00>` host names first, then classify — order-independent. Regression test added.
- Refuted (verified non-issues): no cross-tool dedup between nmblookup+nbtscan (deliberate per-tool
  house convention, matches smtp/nfs; each finding is individually correct); MAC in two formats (each
  parser faithfully echoes its tool — cosmetic); the `__MSBROWSE__` guard is dead code (the `<01>`
  suffix path already excludes it) but emits nothing wrong; plus a pure test-coverage nit.

### Phase 2 · module 11 (tftp) — hardening
Adversarial 3-lens review (verified against the real `tftp-enum.nse` source). 4 candidates, 2 CONFIRMED
(one issue found by two lenses); 2 refuted.
- **parser-correctness (MED): `_SKIP_PREFIXES` dropped real files.** The guard skipped in-section lines
  starting with started/date/error/info — but tftp-enum's output is ONLY found filenames (those strings
  appear only in the script's `debug1()` calls, never in output), so the filter protected against
  nothing while silently deleting legitimate readable files named `info.txt` / `error.log` / `date`.
  Removed the guard (every in-section `|` line is a filename); added a regression test.
- Refuted (verified non-issues): adjacent-NSE-block leak (`fingerprint-strings` from `-sV` sorts before
  `tftp-enum`, so no `|` block ever follows it — the non-`|` trailing lines already end the section);
  0-byte-miss vs 0-byte-hit ambiguity (speculation about a not-yet-built worker; `ShellResult` already
  exposes `exit_code`).

### Phase 2 · module 12 (netbios) — engine
- **NetbiosModule** (`modules/netbios/`, UDP 137): triggers on 137 / netbios-ns. Tier-1 read-only:
  `nmblookup -A {target}` + `nbtscan {target}` (NetBIOS name table — host, domain/workgroup, service
  roles, MAC). Both already on the allowlist; services.yaml already had the 137 entry.
- **parsers.py**: `parse_nmblookup` reads each `NAME <XX> - [<GROUP>] <node> <ACTIVE>` row and maps the
  suffix code to meaning — `<00>` unique→hostname / group→domain, `<20>`→file-server(SMB),
  `<1c>`/`<1b>`→domain-controller (also emits the AD domain), `<03>`→logged-in user (skipped when it
  equals the host's own name), plus MAC; `__MSBROWSE__` is dropped. `parse_nbtscan` reads the one-line
  table (name + `<server>` flag + MAC). `parse_netbios_tool` dispatch.
- `suggest()` pivots: a DC/PDC → LDAP/kerberos/SMB AD flows; `<20>` → SMB module; `<03>` → user enum.
- Tier-2 `manual_commands.yaml` (5): nmblookup -A, nbtscan (+ -v), name resolve, nmap nbstat. Recon-only.
- 10 tests (parsers + module incl. the <03>==hostname suppression and header-not-a-finding checks).

### Phase 2 · module 10 (snmp) — hardening
Adversarial 3-lens review (7 agents; verified against real onesixtyone / snmpwalk output). 4
candidates, 4 CONFIRMED — but #1–#3 were the SAME root issue, found independently by all three lenses.
- **injection (MED ×3): unvalidated community reaches a command line.** `walk_step` spliced
  `{community}` unquoted into `snmpwalk -v2c -c {community} {ip}`, into `suggest()`'s hint, and into
  the `snmp/snmpwalk-{community}.txt` path. The shipped onesixtyone list itself holds valid
  space-bearing communities (`all private`), which onesixtyone echoes verbatim → `parse_onesixtyone`
  keeps the space → `shlex.split` turns `-c all private 10.x` into community `all` + agent `private`,
  redirecting the walk off-target (and `../evil` escaped the snmp/ dir). Fix: `shlex.quote` the
  community in the command + `suggest()` (preserves a valid space-bearing community as ONE argv token,
  unlike a reject-charset guard that would break `all private`), and a `re.sub` slug for the filename.
- **correctness (LOW): `_CRED_HINT` false positives.** `pass(word|wd)?[=:]` (unanchored) fired on
  `compass=` / `bypass:`. Added a `(?<![A-Za-z])` lookbehind (beats `\b`: still matches `_password=`
  and `--password=`). Regression tests for both fixes.

### Phase 2 · module 11 (tftp) — engine
- **TftpModule** (`modules/tftp/`, UDP 69): triggers on 69 / tftp. TFTP has NO listing protocol, so
  Tier-1 recon is `nmap -sU -sV --script tftp-enum` (enumerate readable files from nmap's well-known
  list) + a `curl -s tftp://{target}/<file>` GET per name in a small fixed `COMMON_FILES` list
  (network-device configs/backups). GET-only — no PUT/upload ever. curl already speaks tftp and is on
  the allowlist, so no shell.py change.
- **`tftp_get_url`** URL-encodes the filename (encoding `/` too) so a target-controlled tftp-enum name
  can't smuggle a curl flag or a second URL; `get_step` hashes the full name into the on-disk snapshot
  filename (injective, mirrors ftp). **parsers.py**: `parse_nmap_tftp` reads the filenames listed under
  the `tftp-enum:` block (real @output format: header then `|_ bootrom.ld` lines), ends the section at
  the next non-`|` line, dedups. `parse_tftp_tool` dispatch.
- Tier-2 `manual_commands.yaml` (6): nmap tftp-enum, curl GETs (running/startup-config, named file),
  and copy-to-terminal tftp/atftp GETs. Read-only only.
- 10 tests (parsers + module incl. a hostile-filename injection test + a no-upload manual check).
  Four gates green.

### Phase 2 · module 10 (snmp) — engine
- **SnmpModule** (`modules/snmp/`, UDP 161): triggers on 161 / snmp. Tier-1 read-only recon:
  `discovery_steps` = `onesixtyone -c <small community list> {target}` (§2 explicitly allows
  onesixtyone with a small list — used the 822-byte onesixtyone-formatted seclists file, NOT the
  22 KB one) + `nmap -sU -sV --script snmp-info,snmp-sysdescr,snmp-interfaces,snmp-processes,
  snmp-netstat` (no snmp-brute). `walk_step(community="public")` = `snmpwalk -v2c -c <community>`;
  `commands()` = discovery + a default public walk.
- **parsers.py**: `parse_onesixtyone` (`IP [community] sysDescr` → community + banner, deduped),
  `parse_nmap_snmp` (version-line + snmp-sysdescr banners, snmp-processes `Name:`, interface IP
  isolated from the trailing `Netmask:`, enterprise note), `parse_snmpwalk` (sysDescr banner, Windows
  LanMgr users + hrSWRunName processes matched via prefix-independent numeric OID tails so the `iso.`
  and `.1.` render forms both hit; a `pass(word)?[=:]` value raises a credential NOTE without copying
  the secret — §6). `parse_snmp_tool` dispatch.
- Tier-2 `manual_commands.yaml` (8): v2c/v1 walks, discovered-community re-walk, targeted OID pulls
  (users / processes / installed software / listening ports), nmap NSE. No brute — onesixtyone stays
  on the small default list; no user/password iteration anywhere.
- 13 tests (parsers + module incl. secret-not-leaked assertions + a manual recon-only check);
  onesixtyone + snmpwalk already on the exec allowlist. Four gates green.

### Phase 2 · module 9 (nfs) — hardening
Adversarial 3-lens review (7 agents: 3 review lenses → per-finding adversarial verify, checked against
the real `nfs-ls.nse` / `nselib/ls.lua` source). 1 of 4 candidates survived verification; 3 correctly
refuted.
- **correctness (HIGH): multi-export nfs-ls mis-attribution.** `parse_nmap_nfs` captured the volume
  only from the inline `nfs-ls:` header, but real nmap prints each export as its own `Volume /path`
  line — so on a multi-share box every file/access after the first was credited to the wrong (or
  empty) export, aiming the writable-share + sensitive-file findings at the wrong share in the
  report/graph. Fix: match a standalone `^Volume\s+(/\S+)` line inside the ls section and re-anchor
  `volume`. Rewrote the fixture to real nmap output (standalone 2nd `Volume` + 10-char type-char
  perms) and added a multi-volume attribution regression test.
- Refuted (verified non-issues): fixture's type-char-less perms "drop findings" (the `[dlbcps-]?`
  regex already handles the real 10-char form; only a speculative future regex-tightening breaks it);
  `is_secret_name` misses/over-fires (non-executing hint tuning; `.htpasswd`/`.git-credentials`
  already match via the `passwd`/`credential` substrings); mixed-ACL test gap (`_world_readable`
  already flags `10.0.0.0/24,*` as world-readable — hypothetical regression, not a live defect).

### Phase 2 · module 9 (nfs) — engine
- **NfsModule** (`modules/nfs/`): triggers on 2049 / nfs service names. Tier-1 read-only recon
  (`recon_steps`): `showmount -e {target}` (exports + client ACL) + `nmap -sV --script
  nfs-showmount,nfs-ls,nfs-statfs -p 2049 {target}` (exports, a BOUNDED directory listing over the
  NFS protocol with NO local mount, fs stats). Mounting stays Tier-2 (§12 "mount only on confirm").
  `anon_credential` (source `nfs-anon-enum`) for a world-readable export.
- **parsers.py**: `parse_showmount` (export path + client ACL; world-readable = a client token of
  `*`/`(everyone)`/`0.0.0.0/0`, exact-token not substring so `*.corp` and `/24` stay restricted;
  leading-`/` filter skips the header, RPC errors, and `[missing]`/`[blocked]` sentinels) and
  `parse_nmap_nfs` (banner, nfs-showmount exports, nfs-ls files [skips `.`/`..`, filename kept
  verbatim], access-line writable detection via `\bModify\b` so "NoModify" is not misread as
  writable). `is_secret_name` flags id_rsa/.ssh/shadow/etc. `parse_nfs_tool` dispatch.
- Tier-2 `manual_commands.yaml` (8): rpcinfo, showmount -e/-d/-a, nmap nfs-ls (no mount), and a
  read-only mount → ls -laR → umount workflow (copy-to-a-terminal; sudo/ls/mount aren't on the exec
  allowlist, so a stray in-GUI run of them safely `[blocked]`s). No creds, no lists.
- shell.py: correct install hints for showmount (nfs-common) + rpcinfo (rpcbind).
- 16 tests (parsers + module incl. world-readable ACL cases, writable-vs-NoModify, and a mount
  read-only invariant); `services.yaml` already had the 2049 entry. Four gates green.

### Phase 2 · modules 5–7 (ssh, dns, ldap) — feature + hardening
- **ssh** (§ next after ftp): `SshModule` Tier-1 = one nmap NSE scan (ssh2-enum-algos,ssh-auth-methods,
  ssh-hostkey); parser extracts banner, host keys, weak algos, offered auth methods. `ssh` added to
  shell ALLOWED_TOOLS. Hardening: interactive ssh password logins could hang the sole worker slot —
  fixed at the chokepoint (Popen now `stdin=DEVNULL` + `start_new_session=True`, so no wrapped tool
  can block on stdin//dev/tty), + ConnectTimeout on ssh entries + honest "copy to a terminal" wording.
- **dns** (protocol-only; subdomain brute stays in vhost): version.bind + nmap dns-nsid/dns-recursion,
  and zone transfer + `dnsrecon -t std` only when a validated domain is present. Hardening: the manual
  path interpolated the UNVALIDATED domain (could smuggle `-t brt`) → now normalize_domain-gated;
  parse_dig_version skips `[missing]`/`[blocked]`/`dig:` sentinels; added 53/udp + `service_name:
  domain` reference rules.
- **ldap**: two-phase worker — anonymous root DSE (ldapsearch + nmap ldap-rootdse) → discover naming
  context → bounded (`-z 200`) anonymous user search. `sanitize_basedn` guards the `-b "..."` surface
  against BOTH a user-typed and a hostile server-returned base DN; LDIF parser unfolds continuation
  lines and skips base64 values; anonymous bind auto-writes an `ldap-anon-enum` cred. LDAPS-aware URI
  (636/3269 → ldaps://). manual_commands.expand gained `{basedn}`.
- Each shipped with fixtures + parser/module/GUI tests; four gates green at every commit.

### Phase 2 · module 4 (ftp) hardening (this commit)
Adversarial 3-lens review (12 agents, verified against real nmap 7.99 / curl 8.x); 5 of 9 survived, all
fixed (4 non-issues correctly rejected):
- **correctness (MED): parser drift — nmap `[NSE: writeable]` marker** was folded into the file/dir name
  (`/incoming [NSE: writeable]`). Strip it and record a `note` (writable anon dir = notable recon).
- **correctness (MED): multi-space filenames** — `split()`/`join` collapsed `two  dirs` → `two dirs`, so
  the walk built a wrong URL and missed the subtree. Parse the 8 fixed ls -l fields positionally, take
  the name verbatim (keep internal + trailing spaces).
- **correctness (MED): Tier-2 manual port** — templates had no `{port}`, so every follow-up hit :21 on a
  non-standard FTP box. Fold `:port` into the host authority when port != 21.
- **gui-concurrency (MED): worker-slot wedge** — `_on_ftp_done` (and `_on_smb_done`) added creds before
  `_finish_worker` with no guard; a creds.json write error stranded `self._worker` and locked the UI.
  Guard the body so the slot is always released.
- **gui-concurrency (LOW): snapshot filename collisions** — `_dir_slug` is lossy (`/` and `/root` both →
  `root`), clobbering on-disk `ftp/dirs/*.txt`. Append a sha1[:8] of the full path (injective).
- Rejected (verified non-issues): silent depth-truncation (every entry is still recorded + summarized;
  "no silent truncation" was the reviewer's invented rule), per-LIST result not capped (a listing snapshot
  is explicitly allowed by §12; the WALK is bounded), <9-token/device lines dropped (not in the real input
  domain), `..`/`/` scope escape (curl removes dot-segments client-side; `--path-as-is` never passed).

### Phase 2 · module 4 (ftp) — GUI (73c9f70)
- **FtpPanel** (`gui/widgets/ftp_panel.py`): Tier-1 buttons ("Run full FTP recon (bounded walk)" → full,
  "Just list anonymous root" → anon) emitting `recon_requested(mode, port)` (FTP carries the port);
  Tier-2 manual follow-ups (target/port-expanded, FILE/SUBDIR left literal) with copy menu; findings
  summary. Shown as tool_panel stack page 3 when `ref.module == "ftp"`; disabled during a scan.
- **FtpReconWorker** (`main_window.py`): drives the bounded anonymous auto-walk on its thread — nmap
  banner/anon → curl root LIST → BFS recurse into subdirs, **capped at depth 3 / 25 dirs** (emits a
  "bounded" line when it truncates, never silently), LIST-only (never downloads). `seen` set stops
  symlink loops. Confirms anon from nmap OR a non-empty listing; writes findings.json + anon cred
  (`ftp-anon-enum`). Modes: full (recurse) / anon (root only).
- 6 GUI tests (buttons+port, manual legality, page switch, worker full-walk recursion + anon-no-recurse).

### Phase 2 · module 4 (ftp) — engine (24a3837)
- **FtpModule** (`modules/ftp/`): triggers on 21 / ftp service names. Step-builders return `FtpStep`s
  (parser key per step): `banner_steps` (`nmap -sV --script ftp-anon,ftp-syst,ftp-bounce`), `anon_steps`
  (`curl -s ftp://host/` root LIST), `list_step(path)` for the bounded walk. `ftp_dir_url` URL-encodes
  the target-controlled path (keeping '/') and always ends in '/' so curl LISTs (never downloads a file)
  and a hostile dir name (`-x`, spaces, `:`) can't inject a flag/second URL. anon_credential
  (source `ftp-anon-enum`).
- **parsers.py**: `parse_ftp_listing` handles both Unix `ls -l` (incl. multi-word names, symlinks) and
  MS-DOS/IIS listings → `FtpEntry`; `parse_nmap_ftp` (anon-allowed, -sV banner, ftp-bounce note, ftp-anon
  root snapshot, ignores the ftp-syst STAT block); `subdirs` drives the walk. `parse_ftp_tool` dispatch.
- Tier-2 `manual_commands.yaml` (7): targeted read/download (FILE), subdir listing (SUBDIR), passive
  listing, explicit mirror, single default-cred checks (ftp:ftp, admin:admin) — never lists/spray.
- 16 tests (parsers + module incl. untrusted-path injection); services.yaml already had the ftp entry.

### Phase 2 · module 3 (smb) hardening (4f662f2)
Adversarial 3-lens review (12 agents, each finding verified against the REAL installed netexec 1.4.0);
6 of 9 candidates survived verification, all fixed (3 non-issues correctly rejected):
- **§2/§11 (HIGH ×2): netexec spray-guard bypasses.** The old guard only checked the single token after
  -u/-p and only for is_file(). But netexec -u/-p are argparse `nargs='+'` and user×password spray is the
  DEFAULT, so three Tier-3 vectors slipped through: `-p a b c` (inline spray), `-p decoy rockyou.txt`
  (file in 2nd position), and `-p=rockyou.txt` / `-prockyou.txt` (= / concatenated syntax). Rewrote as
  `_netexec_violation`: normalizes =/concatenated forms, consumes the whole nargs run, blocks >1 literal
  OR any file value; single literals (`-p ''`, `-p sa`) still pass. Verified all 29 real module/manual
  commands pass and all bypass vectors are blocked.
- **correctness (HIGH): parse_netexec_users matched nothing on netexec 1.4.0.** 1.4.0 prints --users as a
  fixed-width table with NO `domain\user` prefix (header `-Username- -Last PW Set- -BadPW- -Description-`);
  the old regex required a backslash → zero users on a successful enum. Now takes the first column, with a
  backslash fallback for older CME output; regenerated the fixture to the real 1.4.0 format.
- **correctness (MED): READ,WRITE shares read as no-access.** netexec joins perms into one `READ,WRITE`
  token; the membership test never matched → a writable share looked inaccessible. Now comma-split.
- **correctness (LOW ×2): multi-word share names truncated** (split on 2+ spaces so `Team Share` survives;
  quote the UNC in the follow-up smbclient command); **duplicate readable shares** listed twice in
  full/shares mode (dict.fromkeys before the per-share loop).
- Rejected (verified non-issues): _on_smb_done cred-add wedge (findings.json write front-runs it on the
  same path, so failures surface via the guarded worker try/except), timeout=None hang (tools self-bound:
  netexec --smb-timeout 2s, enum4linux-ng 10s), Add-Credential-during-run (modal dialog; writes only
  creds.json on the UI thread, no profile.json race).

### Phase 2 · module 3 (smb) — GUI (660a9cd)
- **SmbPanel** (`gui/widgets/smb_panel.py`): Tier-1 recon buttons (full / null-only / guest-only /
  shares-only → `recon_requested`), Tier-2 manual follow-ups list loaded from `manual_commands.yaml`
  and target-expanded (double-click runs via the ad-hoc path; right-click → copy as `//`, `\\`, or
  bash-escaped UNC), and a live "Findings so far" summary. Tier-3 is never shown.
- **tool_panel**: SmbPanel is stack page 2, shown when `ref.module == "smb"`; `smb_recon_requested`
  forwarded; manual follow-ups reuse `run_requested` (validated at the shell chokepoint); disabled
  during a scan.
- **SmbReconWorker** (`main_window.py`): QThread that drives the conditional Tier-1 *sequence* on its
  own thread — banner → null/guest phases → detect auth (`netexec_auth_ok`) → if authed, followups
  (users/pass-pol/rid-brute/rpcclient) + per-readable-share `ls`. Writes findings.json; returns
  anon creds (source `smb-anon-enum`) for the UI thread to add. Modes: full/null/guest/shares
  (shares skips followups).
- UNC command transforms `to_backslash_command`/`to_escaped_command` added to the smb module.
- Tests: `tests/gui/test_smb_panel.py` (buttons, manual legality, worker full-drive + shares-mode via
  a monkeypatched shell.run) + UNC-transform unit tests; updated two widget tests that assumed 445
  used the generic hints page (it now opens the SMB panel). 146 pass; all four gates green.

### Phase 2 · module 3 (smb) — engine (b177316)
- **SmbModule** (`modules/smb/`): triggers on 139/445; step-builders (`banner/null_session/guest/
  followup/share_steps`) returning `SmbStep`s (each carrying a parser key) since Tier-1 is a
  conditional sequence, not one command. Tier-2 `manual_commands.yaml` = single default-cred attempts
  (administrator:'', admin:'', sa:sa, guest) + RID cycling + rpcclient/smbmap enum (no secretsdump,
  no lists). anon_credential(source smb-anon-enum).
- **parsers.py**: netexec shares/users/rid-brute/pass-pol, smbclient -L, rpcclient enumdomusers →
  `SmbFinding`; modelled on real tool output. `readable_shares`, `netexec_auth_ok`.
- **§11 spray guard** (shell.py): a `-u`/`-p` value that is a *file* (netexec's own list semantics) is
  blocked as Tier-3 brute; single literals pass. `nxc` added to the allowlist.

### Phase 2 · module 2 (vhost) hardening (4c04471)
Adversarial 3-lens review; fixed all 9 findings (the correctness lens ran the real installed tools):
- **§2 (high):** validate the vhost domain/dns_server like Target.ip (reject whitespace/leading-'-'/
  quotes) — blocks flag injection (a crafted domain adding ffuf `-x proxy` → off-target traffic).
- **tool-version bugs (high):** gobuster 3.8.2 uses `--domain`/`--resolver` (not `-d`/`-r`); gobuster
  vhost now hits the target IP (not the domain URL, so no /etc/hosts needed); dnsrecon 1.6.0 output is
  "INFO A host ip" (no `[+]`); added a dedicated gobuster-dns parser and a wfuzz parser (both had
  silently dropped every hit).
- **robustness:** broadened the parse guard (a ValueError could wedge the worker); defensive int
  coercion; clear a stale `-o` before a re-run; set_profile no longer clobbers a user-typed domain.

### Phase 2 · module 2 (vhost) — engine + GUI (6cb6899, 062cc18)
- engine: VhostModule (active/target-directed only; passive OSINT excluded per §2), build_command
  (ffuf Host-FUZZ, gobuster vhost/dns, dnsrecon, wfuzz), wildcard probe, 5 parsers -> findings.json
  (dedup key gained 'vhost'), 10 manual commands.
- GUI: vhost builder in a second web tab (domain/tool/scheme/wordlist/-fs + Detect-wildcard/threads/
  DNS server), discovered-vhosts list + "enumerate as new HTTP target"; run -> findings; wildcard
  probe auto-fills -fs.

### Phase 2 · module 1 (http) hardening (04313f5)
Adversarial 3-lens review of the HTTP module; fixed all 8 findings (+ regression tests):
- **§2:** shell.run now blocks wpscan `-P`/`-U` (short aliases of --passwords/--usernames), not just --passwords.
- **HIGH concurrency:** disable the service tree + HTTP builder during a scan so a UI edit can't race
  the worker's `profile.save()` (module_settings mutation → "dict changed size during iteration").
- **path containment:** reject an absolute/`..` Output value (was writable outside the profile dir).
- **worker-slot wedge:** parse-on-done wrapped so a findings-write error can't strand `self._worker`.
- parse_nikto no longer fabricates `/paths` from banner lines; findings dedup keys on size/redirect/note
  too (was dropping distinct wpscan users/version); default_url brackets IPv6; custom output no longer
  clobbered mid-session.

### Phase 2 · module 1 (http) — engine + GUI + QoL (7715f98, f64983b, 7547d29)
- engine: HttpModule, build_command (feroxbuster §9 line reproduced via controls), 11 extension presets
  + Wide net, status presets, 7 parsers -> findings.json, manual_commands.yaml (20), findings store.
- GUI: HTTP command-builder panel (all §9 controls + live preview + Run/Dry-run/Add-to-report +
  persistence), tool_panel QStackedWidget, http run -> findings parse, treat-as-HTTP right-click probe.
- qol: `oscp-recon` console script (`uv pip install -e .`), Kali `.desktop`, README.

### Phase 1 · adversarial review + hardening (1898c94)
Ran a 3-lens review of the Phase 1 additions; fixed all 15 findings (+9 regression tests → 63):
- **§2 password-list leak (high):** `wordlists.py` now uses an AFFIRMATIVE category allowlist
  (only web-content/dns/usernames/fuzzing/discovery surfaced) + expanded denylist — `fasttrack.txt`
  / `wifite.txt` no longer leak from `/usr/share/wordlists` (verified live: 0 leaks).
- **searchsploit flag injection (high):** strip leading `-` from query tokens + block
  `-m/-x/-u` at the exec chokepoint (a hostile banner can't turn lookup into PoC copy/update).
- **`_IndexWorker` SIGABRT (high):** `WordlistPicker.shutdown()` waits the worker before teardown.
- creds temp file created 0600 (not umask); `Profile.load` recreates service dirs; manual output
  files hash-suffixed; scan-time ref-visits buffered+drained; secret field masked; matcher
  tie-break; `load_rules` degrades on bad YAML; line-count off-by-one; skip huge-file counting.

### Phase 1 · chunk 6 — wordlist picker + notes + credentials (b7d97c3) — Phase 1 COMPLETE
- `wordlist_picker.py`: searchable/filterable list backed by `wordlists.py` (background indexing
  thread), category filter, favorites pinned top; emits `wordlist_chosen`.
- `notes_pane.py`: debounced-autosave editor for `<profile>/notes.md` (atomic write); flushes on
  profile switch / save / close; wired as a bottom Notes dock (View menu toggle).
- `AddCredentialDialog` (Edit menu) writes `creds.json` via `Profile.add_credential`;
  "Browse Wordlists…" (View menu) opens the picker.

### Phase 1 · chunk 5 — GUI references integration (58f08dd)
- `reference_pane.py`: real `QWebEngineView` loading the matched HackTricks page on service
  selection (graceful fallback to a link label when QtWebEngine can't init / is disabled);
  Exploit-DB list filled from `searchsploit --json` off the UI thread, click → loads the EDB
  page in the same view; emits `page_visited` → recorded via `Profile.add_reference_visited`.
- `SearchsploitWorker` (QThread) with stale-result guarding; workers kept alive until `finished`.

### Phase 1 · chunk 4 — three-pane GUI restructure (f0c9be7)
- MainWindow → `QSplitter(service_tree | tool_panel | reference_pane)`; selection wiring;
  `CommandWorker` runs ad-hoc tool-hint commands through the policy-enforced `shell.run`.

### Phase 1 · chunk 3 — creds.json + references-visited (76bae3d)
- `models.Credential`; `creds.py` (atomic 0600 write, `redact()`, dedup); `Profile` helpers
  `creds_path` / `credentials()` / `add_credential()` / `add_reference_visited()`.

### Phase 1 · chunk 2 — references subsystem (5a4dbd7)
- `references/` package: `services.yaml` + matcher (§14 precedence) + `searchsploit --json`
  Exploit-DB lookup (display-only). All tool-hint templates pass the exec policy.

### Phase 1 · chunk 1 — wordlists (155a7ac)
- `wordlists.py`: index wordlist paths, filter password lists (substring on any path part +
  metasploit + rockyou + symlink target), app-wide favorites.

### Phase 0 — scaffold (646fc29)
- Engine (`shell`/`models`/`config`/`profile`/`orchestrator`/`reporter`) + nmap module +
  Typer CLI + minimal PySide6 GUI + fixtures/tests. Hardened after adversarial review: target
  validation, exec allow/deny policy, atomic writes, real timeout watchdog, GUI safety.
