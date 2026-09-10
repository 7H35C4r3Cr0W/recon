"""Agent tools — the typed functions the LLM/agents call.

Each function wraps REAL oscprecon calls (import-as-library) and returns JSON-serializable
data. They are synchronous/blocking (the engine is blocking); the API dimension runs them in
a threadpool and serializes writes per project with a Redis lock.

LLM-facing signature vs. Python signature
------------------------------------------
The LLM sees ``project`` (a project GUID). The service layer resolves it to a live engine
``Profile`` via workspace.workspace_for(project_id, scope_from_db).open() and passes that
Profile in as the first arg. Resolving from the DB (not from LLM input) is what keeps the
scope-lock trustworthy — see guard.assert_in_scope.

Safety posture carried over (per tool, noted inline):
  * scan/enum/check_alive/research execute tools ONLY through guard.run_tool -> shell.run.
  * catalog_actions_for is DISPLAY-ONLY: it builds/ranks/pre-fills command text and never runs
    anything. exploit=True / spray=True are unreachable from this module.
  * every executing / state-changing tool records an audit entry with the engine's kebab slugs.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from oscprecon import alive, edb, hacktricks, references, service_enum
from oscprecon import exploit as ex
from oscprecon import findings as findings_mod
from oscprecon.models import DiscoveredService, Proto
from oscprecon.orchestrator import Orchestrator
from oscprecon.patterns import engine as patterns_engine
from oscprecon.profile import Profile
from oscprecon.recon_auth import ReconAuth
from oscprecon.references import gtfobins, sections
from oscprecon.reporter import Reporter

from . import shell_gateway as gw
from .schemas import CatalogActionDTO, ServiceDTO, to_service_dto

OnLine = Callable[[str], None] | None


# ------------------------------------------------------------------ 1. check_alive

def check_alive(
    profile: Profile,
    target: str | None = None,
    *,
    on_line: OnLine = None,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    """Pre-flight liveness. LLM signature: check_alive(project, target?) -> {up, hosts, count}.

    Engine calls: alive.build_alive_command + gw.run_recon_tool(shell.run) + alive.parse_alive.
    Scope-lock: target defaults to the project scope; any explicit target is asserted in scope.
    Audit: 'run-command'.
    """
    tgt = gw.assert_in_scope(profile, target or profile.target.ip)
    out = profile.directory / "nmap" / "alive.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    shell_line = alive.build_alive_command(tgt)
    result = gw.raise_for_result(
        gw.run_recon_tool(profile, shell_line, out, on_line=on_line, cancel=cancel)
    )
    gw.audit(profile, "run-command", details={"shell_line": shell_line, "module": "alive"})
    parsed = alive.parse_alive(out.read_text(errors="replace"))
    return {"up": parsed.up, "count": parsed.count, "hosts": list(parsed.hosts),
            "shell": result}


# ------------------------------------------------------------------ 2. run_scan

def run_scan(
    profile: Profile,
    scan_profile: str = "default",
    *,
    resume: bool = False,
    force: bool = False,
    on_line: OnLine = None,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    """Launch the full nmap battery. LLM: run_scan(project, scan_profile) -> {services:[...]}.

    Engine call: Orchestrator(profile, on_line, scan_profile, resume, force, cancel).run_nmap().
    The Orchestrator drives every command through the imported shell.run, merges + saves the
    profile, and writes report.md — so the chokepoint and persistence are the engine's own.
    Scope-lock: the profile target is the scope; the Orchestrator only scans profile.target.
    Audit: 'scan' before, 'run-finished' after (mirrors the CLI's audit envelope).
    scan_profile ∈ quick|default|exam|full.
    """
    gw.assert_in_scope(profile, profile.target.ip)
    gw.audit(profile, "scan", details={"scan_profile": scan_profile,
                                          "target": profile.target.ip})
    orch = Orchestrator(
        profile,
        on_line=on_line,
        scan_profile=scan_profile,
        resume=resume,
        force=force,
        cancel=cancel,
    )
    orch.run_nmap()  # side effects: merge_services + save + report.md
    gw.audit(profile, "run-finished", details={"scan_profile": scan_profile})
    return {"services": [to_service_dto(s) for s in profile.discovered_services]}


# ------------------------------------------------------------------ 3. list_discovered_services

def list_discovered_services(profile: Profile) -> dict[str, list[ServiceDTO]]:
    """Read back discovered ports/services. LLM: list_discovered_services(project).

    Read-only: no exec, no audit. Reads profile.discovered_services (monotonic within a project).
    """
    return {"services": [to_service_dto(s) for s in profile.discovered_services]}


# ------------------------------------------------------------------ 4. enum_service

_ENUM_ALIASES = {"microsoft-ds": "smb", "netbios-ssn": "smb", "http": "http",
                 "postgresql": "postgres"}


def enum_service(
    profile: Profile,
    service: str,
    mode: str = "full",
    *,
    port: int = 0,
    as_user: str | None = None,
    on_line: OnLine = None,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    """Tier-1 service enumeration. LLM: enum_service(project, service, mode).

    Engine calls: service_enum.{Smb,Ftp,Ssh,Dns,Ldap}Enum(...).run() — the SAME dispatch as
    cli._run_engine_enum (there is no engine-side factory; the front-end owns the mapping).
    Each engine drives its steps through the imported shell.run internally. Discovered creds are
    persisted via profile.add_credential; findings are written to findings.json by the engine.
    Auth: --as re-runs authenticated FROM THE VAULT ONLY (ReconAuth.from_credential); never from
    LLM-supplied secrets. Audit: 'enum'. Returns summary + creds/findings deltas.
    """
    key = _ENUM_ALIASES.get(service, service)
    auth = _resolve_vault_auth(profile, as_user) if as_user else None

    before = len(findings_mod.load_findings(profile.directory))

    engine: service_enum.EnumEngine
    if key == "smb":
        engine = service_enum.SmbEnum(profile, mode, on_line, cancel, auth)
    elif key == "ftp":
        engine = service_enum.FtpEnum(profile, mode, port, on_line, cancel, auth)
    elif key == "ssh":
        engine = service_enum.SshEnum(profile, port, on_line, cancel)
    elif key == "dns":
        engine = service_enum.DnsEnum(profile, profile.target.hostname or "", port, on_line, cancel)
    else:
        engine = service_enum.LdapEnum(profile, "", port, on_line, cancel, auth)

    result = engine.run()

    creds_added = 0
    for cred in result.creds:
        profile.add_credential(cred)   # dedup by cred_key; does not auto-save creds beyond its write
        creds_added += 1

    Reporter(profile).write()          # refresh report.md (engine side-effect parity with CLI)
    after = len(findings_mod.load_findings(profile.directory))
    gw.audit(profile, "enum", details={"service": key, "mode": mode,
                                           "as": (auth.label if auth else None)})
    return {
        "service": key,
        "summary": list(result.summary),
        "credentials_added": creds_added,
        "findings_added": max(0, after - before),
    }


def _resolve_vault_auth(profile: Profile, as_user: str) -> ReconAuth | None:
    """Map a --as selector to a vault Credential -> ReconAuth. Vault is the ONLY secret source."""
    if as_user == "guest":
        return ReconAuth.guest()
    want_user, _, want_domain = as_user.partition("@")
    for cred in profile.credentials():
        if cred.username == want_user and (not want_domain or cred.domain == want_domain):
            return ReconAuth.from_credential(cred)
    return None


# ------------------------------------------------------------------ 5. catalog_actions_for  (DISPLAY-ONLY)

def catalog_actions_for(
    service: str,
    evidence: dict[str, Any],
    *,
    limit: int | None = None,
) -> dict[str, Any]:
    """Decision-aid catalog lookup + evidence ranking. DISPLAY-ONLY — executes NOTHING.

    LLM: catalog_actions_for(service, evidence) -> {label, note, actions:[CatalogActionDTO]}.

    ``evidence`` is a JSON blob the agent assembles from the profile (kept explicit so this tool
    is pure and stateless):
        {"services": [[port, name], ...],           # (port, nmap-service-name) pairs
         "fingerprints": ["Apache/2.4.49", ...],    # whatweb/nmap product texts
         "findings": [ {finding row}, ... ],
         "credentials": [ {"secret_type": "..."} ], # only shapes relevance reads
         "command_history": [ {...} ],
         "values": {"target": "...", "domain": "...", "port": "..."}}  # for fill_template

    Engine calls: ex.service_exploits / ex.build_context / ex.rank_actions /
    ex.suggested_action_ids / ex.fill_template / ex.action_ports.

    This is the seam's safety keystone: the catalog is a decision-aid, and even 'attacker'-
    runnable actions are surfaced with an ``executable`` flag but are NEVER auto-run. There is no
    exploit tool in this adapter; any attack stays behind the separate human-gated endpoint.
    """
    spec = ex.service_exploits(service)
    if spec is None:
        return {"service": service, "label": service, "note": "", "actions": []}

    pairs = [(int(p), str(n)) for p, n in evidence.get("services", [])]
    ctx = ex.build_context(
        pairs,
        list(evidence.get("fingerprints", [])),
        list(evidence.get("findings", [])),
        list(evidence.get("credentials", [])),
        list(evidence.get("command_history", [])),
    )
    suggested = ex.suggested_action_ids(spec, ctx, limit=limit or 12)
    values = {k: str(v) for k, v in evidence.get("values", {}).items()}

    actions: list[CatalogActionDTO] = []
    for scored in ex.rank_actions(spec, ctx):
        a = scored.action
        filled = ex.fill_template(a.template, values)
        ports, provenance = ex.action_ports(a, spec)
        actions.append(CatalogActionDTO(
            id=a.id,
            title=a.title,
            category=a.category,
            command=filled,
            unfilled=ex.missing_placeholders(a.template, values),
            tool=a.tool,
            ports=list(ports),
            port_provenance=provenance,
            runs_on=a.runs_on,
            executable=a.executable,      # display flag ONLY
            suggested=a.id in suggested,
            score=scored.score,
            why=a.why,
            source=a.source,
        ))
    return {"service": service, "label": spec.label, "note": spec.note, "actions": actions}


# ------------------------------------------------------------------ 6. research_finding

def research_finding(
    profile: Profile,
    finding: dict[str, Any],
    *,
    on_line: OnLine = None,
) -> dict[str, Any]:
    """Pull research for a finding: HackTricks / Exploit-DB / GTFOBins / hashcat / patterns.

    LLM: research_finding(project, finding) -> {reference, hacktricks_sections, edb, gtfobins,
    hashcat, next_steps}.

    Engine calls:
      - references.match(DiscoveredService) -> ServiceRef (HackTricks URL, module, tool hints)
      - hacktricks.page_for_module + sections.relevant_sections  (offline, LOCAL selection)
      - references.search_exploits(product, version, out) -> EdbSearch  (its ONLY shell-out,
        `searchsploit --json`, already routed through the imported shell.run; PoC path never
        opened) then edb.add_edb persists CITATIONS only
      - gtfobins.search / hashcat.search  (lookup-only, build command strings, never run)
      - patterns.engine.suggest_for  (recon next-steps with provenance)

    Reference loaders degrade to empty rather than raise, so no defensive wrapping is needed.
    Audit: 'run-command' for the searchsploit lookup (the one thing that executes).
    """
    svc = DiscoveredService(
        port=int(finding.get("port", 0)),
        proto=Proto(finding.get("proto", "tcp")),
        service=finding.get("service", finding.get("module", "")),
        product=finding.get("product", ""),
        version=finding.get("version", ""),
    )
    ref = references.match(svc)
    out: dict[str, Any] = {"reference": None, "hacktricks_sections": [], "edb": [],
                           "gtfobins": [], "hashcat": [], "next_steps": []}

    if ref is not None:
        out["reference"] = {"label": ref.label, "hacktricks": ref.hacktricks,
                            "module": ref.module,
                            "tools": [{"name": t.name, "purpose": t.purpose} for t in ref.tools]}
        page = hacktricks.page_for_module(ref.module)
        if page is not None:
            kinds = [str(finding.get("kind", "")), str(finding.get("value", ""))]
            secs = sections.relevant_sections(
                page.markdown, keywords=[k for k in kinds if k],
                product=svc.product, version=svc.version, limit=4)
            out["hacktricks_sections"] = [{"heading": s.heading, "body": s.body} for s in secs]

    if svc.product:
        edb_out = profile.directory / "edb" / f"{svc.service or 'svc'}.txt"
        edb_out.parent.mkdir(parents=True, exist_ok=True)
        search = references.search_exploits(svc.product, svc.version, edb_out)
        gw.audit(profile, "run-command",
                    details={"shell_line": f"searchsploit {svc.product} {svc.version}".strip(),
                             "module": "searchsploit"})
        edb.add_edb(profile.directory, service=svc.service, product=svc.product,
                    version=svc.version, hits=search.hits)   # citations only, never PoC path
        out["edb"] = [{"edb_id": h.edb_id, "title": h.title, "url": h.url, "cve": h.cve,
                       "version_match": h.version_match} for h in search.hits]

    binmatch = gtfobins.search(svc.service) if svc.service else []
    out["gtfobins"] = [{"name": b.name, "url": b.url, "functions": b.functions} for b in binmatch[:5]]

    return out


# ------------------------------------------------------------------ 7. suggest_next_steps

def suggest_next_steps(profile: Profile) -> dict[str, Any]:
    """Pattern-based next steps for the whole project. LLM: suggest_next_steps(project).

    Engine call: patterns.engine.suggest_for(findings, target, domain, has_credential).
    Read-only. Suggestions carry source_pattern + source_box provenance (the §15 gate ensures
    no exploit/cracking tokens leak in). No exec, no audit.
    """
    rows = findings_mod.load_findings(profile.directory)
    has_cred = bool(profile.credentials())
    suggestions = patterns_engine.suggest_for(
        rows,
        target=profile.target.ip,
        domain=profile.target.hostname or "",
        has_credential=has_cred,
    )
    return {"next_steps": [
        {"text": s.text, "command": s.command_template,
         "source_pattern": s.source_pattern, "source_box": s.source_box}
        for s in suggestions
    ]}


# ------------------------------------------------------------------ 8. generate_report

def generate_report(profile: Profile, *, persist: bool = False) -> dict[str, Any]:
    """Produce the clean report. LLM: generate_report(project) -> {markdown, path?}.

    Engine call: Reporter(profile).render() (zero side effects) — ideal for a web view.
    ``persist=True`` also calls .write() (archive-then-overwrite) and returns the report.md path.
    render() re-reads findings.json / edb.json / audit.jsonl / notes.md / graph.json fresh, and
    redacts credential values in the command log by design. Read-only unless persist.
    """
    reporter = Reporter(profile)
    markdown = reporter.render()
    result: dict[str, Any] = {"markdown": markdown}
    if persist:
        result["path"] = str(reporter.write())
    return result
