"""Arq task functions -- the fan-out worker model.

The supervisor is itself an Arq job (`supervise_run`); it enqueues per-service
jobs and joins on their results, advancing the RunState machine. Recon tool
execution goes through the engine adapter's recon-only chokepoint
(nabu_agent.engine.shell_gateway.run_recon_tool -> oscprecon.shell.run, spray/exploit
hard-wired False). Engine calls BLOCK (subprocess.Popen), so each task runs the
engine in a thread (loop.run_in_executor) and bridges the engine on_line
str-sink into a Redis pub/sub channel for the WebSocket layer.

CANCELLATION: each task derives a threading.Event set when the run's Redis
cancel flag flips; it is passed straight into shell_gateway.run_recon_tool(cancel=) /
Orchestrator(cancel=) / the enum engines (all accept `cancel`). ShellResultDTO
["cancelled"] is the signal, not an exception.

RETRIES (Arq): only transient infra errors retry (see worker.is_retryable).
ToolBlocked (policy refusal) and ToolMissing (not on PATH) are DATA -> recorded
on the agent_task row and surfaced in the report; never retried. Re-runs are
safe: nmap supports --resume/--force, merge_services is monotonic, findings
dedup by _key.
"""
from __future__ import annotations

from typing import Any


# --------------------------------------------------------------------------- supervisor
async def supervise_run(ctx: dict, run_id: str) -> None:
    """Drive one Run through the RunState machine (see orchestration.states).

    VALIDATING  : engine.shell_gateway.assert_in_scope(profile, scope) -- the scope is the
                  Postgres project row, never agent/LLM input. Bad -> FAILED.
    ALIVE_CHECK : enqueue recon_alive; cap up-hosts to RunLimits.max_hosts. If the
                  live count exceeds approval_required_above_hosts -> a Checkpoint
                  and AWAITING_APPROVAL before continuing (range-explosion guard).
    SCANNING    : enqueue one recon_scan per (capped) host; join.
    FAN_OUT     : open a READ-ONLY blackboard, snapshot discovered_services into the
                  Postgres service mirror, build the enum+vuln+research task graph.
    ENRICHING   : enqueue enum_service/vuln_service under a run-scoped asyncio
                  semaphore(RunLimits.max_concurrent_service_agents) and a per-host
                  cap; as each returns, apply its ServiceDelta/CredentialDelta as the
                  SOLE profile.json writer (WriteBlackboard).
    RESEARCHING : enqueue research_service (read-only) -- may overlap ENRICHING.
    SYNTHESIZING: enqueue synthesize_report -> REPORT_READY.
    Fan-in: join via awaited Arq job results; a failed/blocked/missing task marks
    its row and does NOT fail the run -> terminal PARTIAL if any agent failed,
    else DONE. Honor the Redis cancel flag between every stage -> CANCELLED.
    """
    raise NotImplementedError


# --------------------------------------------------------------------------- recon (automated)
async def recon_alive(ctx: dict, run_id: str, target: str) -> dict[str, Any]:
    """alive.build_alive_command(target) -> shell_gateway.run_recon_tool -> alive.parse_alive(text).
    Returns {"up": [...], "count": N}. Supervisor caps the list for a CIDR."""
    raise NotImplementedError


async def recon_scan(ctx: dict, run_id: str, host: str) -> dict[str, Any]:
    """Full nmap battery for one host.
    Single host: Orchestrator(profile, on_line=<redis sink>, scan_profile=...,
      cancel=<Event>).run_nmap(); read profile.discovered_services (Orchestrator
      is itself a writer -- so recon_scan for the ENTRY host runs inside the
      supervisor's single-writer context, not a parallel worker).
    Range members: NmapModule two-phase (commands([]) -> shell_gateway.run_recon_tool ->
      discovered_services(raw) -> commands(open_tcp_ports) -> deferred_commands)
      and return a ServiceDelta to the supervisor rather than writing profile.json."""
    raise NotImplementedError


async def enum_service(
    ctx: dict, run_id: str, host: str, port: int, proto: str, service: str
) -> dict[str, Any]:
    """One agent per discovered service. Maps service -> EnumEngine exactly as
    cli._run_engine_enum: smb->SmbEnum(prof,'full',...); ftp->FtpEnum(prof,'full',
    port,...); ssh->SshEnum(prof,port,...); dns->DnsEnum(prof,domain,port,...);
    else->LdapEnum(prof,'',port,...). Runs engine.run() (mode='full' unlocks deep
    conditional recon; the engine's own 300s per-step watchdog applies). Writes
    result findings straight to findings.json (fcntl-safe); returns result.creds
    as CredentialDelta[]. Audits 'enum'."""
    raise NotImplementedError


async def vuln_service(
    ctx: dict, run_id: str, host: str, services: list[tuple[int, str, str, str]]
) -> dict[str, Any]:
    """Vuln NSE per family: nse_vuln.plan_scans(services) -> per VulnTarget
    build_command -> shell_gateway.run_recon_tool -> parse_vuln_output(text, default_port=vt.port,
    proto=vt.proto) -> to_findings/summary_lines. Writes findings directly. The
    shell policy gate refuses brute NSE, so never build a brute selector. Audits 'vuln'."""
    raise NotImplementedError


# --------------------------------------------------------------------------- research (read-only)
async def research_service(
    ctx: dict, run_id: str, port: int, service: str, product: str, version: str
) -> dict[str, Any]:
    """references.match -> HackTricks (page_for_module + relevant_sections);
    references.search_exploits(product, version, out) -> edb.add_edb (citations
    only; ExploitHit.path never opened); exploit.build_context + rank_actions /
    suggested_action_ids for an evidence-ranked decision aid; patterns.engine.
    suggest_for for next steps. The LLMProvider summarizes. Produces PROPOSALS
    only -- never executes, never sets exploit=True. Any spray/exploit action is
    handed up as a Checkpoint proposal, not run."""
    raise NotImplementedError


# --------------------------------------------------------------------------- writer / synthesis
async def synthesize_report(ctx: dict, run_id: str) -> dict[str, Any]:
    """Reporter(profile).render() for the clean markdown; the LLMProvider adds a
    narrative + prioritized next-steps from ranked actions + patterns suggestions.
    Optionally Reporter(profile).write() to persist (archive-then-overwrite).
    Surfaced spray/exploit actions become Checkpoint proposals. -> REPORT_READY."""
    raise NotImplementedError


# --------------------------------------------------------------------------- HUMAN-GATED attack
async def execute_approved_action(ctx: dict, run_id: str, checkpoint_id: str) -> dict[str, Any]:
    """Runs ONE operator-APPROVED spray/exploit action. Does NOT go through
    shell_gateway.run_recon_tool (that path is recon-only). Uses the separate human-gated attack
    executor which calls oscprecon.shell.run directly with its confirmation flow:
      - checkpoints.approve() already enforced config.spray_enabled (spray) /
        per-action exploit_confirmed (exploit) + operator approval;
      - re-validate the checkpoint target == the project scope here, again;
      - spray built via spray.build_spray_command + write_spray_lists (0600),
        cred syntax via ReconAuth.* only, shell.run(..., spray=True);
      - exploit=True is set ONLY from checkpoint.exploit_confirmed -- never by an
        agent. Audits 'spray' / 'run-command'. -> back to REPORT_READY (re-synth)."""
    raise NotImplementedError
