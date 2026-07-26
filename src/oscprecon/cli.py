from __future__ import annotations

import contextlib
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer

from oscprecon import audit, branding, config, diagnostics, guide, shell, vault_export
from oscprecon import doctor as doctor_mod
from oscprecon.models import Target
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile
from oscprecon.reporter import Reporter
from oscprecon.workspace import portability

if TYPE_CHECKING:  # annotation-only names (imported at call time in the function bodies)
    from oscprecon.models import Command, Port
    from oscprecon.modules.base import Module

app = typer.Typer(
    help=(
        "Nabu — headless recon CLI (recon-only, OSCP exam-legal).\n\n"
        "Run `nabu-cli COMMAND --help` for a command's full syntax, flags, and examples "
        "(e.g. `nabu-cli scan --help`). A **profile** (`-p NAME`) is a folder under your workspace "
        "(`~/oscprecon`) that holds all output for one target.\n\n"
        "**Typical workflow:**\n\n"
        "```\n"
        "nabu-cli doctor                      # check the wrapped tools are installed\n"
        "nabu-cli scan 10.10.10.5 -p box      # staged nmap recon into profile 'box'\n"
        "nabu-cli enum smb -p box            # deeper per-service recon (smb/http/ftp/...)\n"
        "nabu-cli findings -p box             # show what has been discovered so far\n"
        "nabu-cli searchsploit vsftpd 2.3.4   # offline Exploit-DB lookup\n"
        "nabu                                 # or open the desktop GUI for the full workspace\n"
        "```\n\n"
        "**Docker** (any host — Kali/Parrot/Ubuntu/macOS/Windows):\n\n"
        "```\n"
        "docker/nabu-docker.sh doctor | scan 10.10.10.5 -p box | gui | shell\n"
        "```\n\n"
        f"By {branding.AUTHOR_NAME} · {branding.AUTHOR_GITHUB} · ☕ {branding.AUTHOR_COFFEE}"
    ),
    add_completion=False,
    rich_markup_mode="markdown",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{branding.APP_NAME} v{branding.app_version()} ({branding.DIST_NAME})")
        typer.echo(f"Created by {branding.AUTHOR_NAME} · {branding.AUTHOR_EMAIL}")
        typer.echo(branding.AUTHOR_GITHUB)
        typer.echo(f"Buy me a coffee — {branding.AUTHOR_COFFEE}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version + author and exit.", callback=_version_callback
    ),
) -> None:
    # why: a callback keeps `scan` an explicit subcommand — Typer otherwise collapses a
    # single-command app and drops the subcommand name (`oscprecon-cli scan <ip>` would break).
    diagnostics.install("cli")  # capture uncaught crashes to the log; best-effort, never blocks
    config.apply_redaction_policy()  # owner policy: never redact (unless the pref is flipped on)
    # cosmetic owl-furby banner — stderr + TTY only, so it never pollutes piped stdout or tests
    if sys.stderr.isatty():
        sys.stderr.write("\n" + branding.cli_banner() + "\n")


# why: §6a — the audit trail is ONE timeline per project, whether the work was done in a window or
# headlessly, so the CLI writes the SAME action slugs the GUI does ("run" / "run-finished" /
# "vuln-scan" / "credential-added" / …). Read-only commands (list/findings/activity/docs/exploit/…)
# never audit — a read is not project history.
# lane names mirror gui.task_manager's constants without importing Qt into the CLI.
_NMAP_LANE = "nmap"
_TOOL_LANE = "tool"
_BATTERY_LANE = "battery"


def _audit(profile_dir: Path, profile_name: str, action: str, **details: Any) -> None:
    # best-effort by contract: audit.record swallows + logs every I/O/serialization failure, so an
    # unwritable audit.jsonl can never fail the command that was actually asked for (§6a).
    audit.record(profile_dir, profile_name, action, actor="user", details=details)


def _audit_profile(prof: Profile, action: str, **details: Any) -> None:
    _audit(prof.directory, prof.profile_name, action, **details)


@contextlib.contextmanager
def _audited_run(prof: Profile, label: str, **details: Any) -> Iterator[dict[str, Any]]:
    """Pair a `run` with its `run-finished`, whatever happens in between.

    A `run` with no matching `run-finished` reads as a scan that never ended — which is exactly what
    a crashed or interrupted headless command used to leave in the trail.
    """
    _audit_profile(prof, "run", label=label, **details)
    outcome: dict[str, Any] = {}
    try:
        yield outcome
    except BaseException:
        _audit_profile(prof, "run-finished", label=label, outcome="aborted")
        raise
    else:
        _audit_profile(prof, "run-finished", label=label, **outcome)


@app.command()
def scan(
    ip: str = typer.Argument(..., help="Target IP or hostname (e.g. 10.10.10.5 or target.htb)."),
    profile: str = typer.Option(
        ...,
        "--profile",
        "-p",
        help="Profile = the ~/oscprecon folder holding this target's output.",
    ),
    hostname: str | None = typer.Option(
        None, help="Optional hostname for the target (feeds vhost/TLS-aware modules)."
    ),
    scan_profile: str | None = typer.Option(
        None,
        "--scan-profile",
        help="nmap battery: quick | default | full | exam (default: your configured preference).",
    ),
    udp_full: bool = typer.Option(
        False, "--udp-full", help="Also run the slow full UDP sweep (65535 ports; adds to top-100)."
    ),
    resume: bool = typer.Option(
        False,
        "--resume",
        help="Reuse output from commands that already completed (exit 0); skip re-running them.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Re-run every command even when prior output exists (overrides --resume).",
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Run staged nmap recon against a target and save findings to a profile.

    Discovers open ports, then runs a versioned `nmap -sV -sC` over exactly the ports it found,
    parsing everything into `<workspace>/<profile>/`. Safe to re-run; open the profile in the GUI
    (`nabu`) to keep enumerating each service.

    **Scan batteries** (`--scan-profile`), fastest to most thorough — all pure nmap, exam-legal:

    ```
    quick    Top-1000 TCP only (-T4). Fast triage; no full sweep, no UDP.
    default  Top-1000 + full 65535 TCP (-p- -T4) + UDP top-100, then -sV -sC on open ports.
    full     Same thorough sweep as default.
    exam     Full sweep rate-boosted (-p- --min-rate 1000 -T4) to finish fast under exam time.
    ```

    A profile (`-p/--profile`) is a named folder under the workspace. Re-running scan on an existing
    profile **reuses** it (history preserved); choose a new name to start a fresh scan.

    **Examples:**

    ```
    nabu-cli scan 10.10.10.5 -p box                        # default battery -> profile 'box'
    nabu-cli scan 10.10.10.5 -p box --scan-profile quick   # fast top-1000 triage only
    nabu-cli scan 10.10.10.5 -p box --scan-profile exam    # full sweep, rate-boosted
    nabu-cli scan target.htb -p box --hostname target.htb --udp-full   # + full UDP sweep
    nabu-cli scan 10.10.10.5 -p box --resume               # continue; skip finished commands
    ```
    """
    root = workspace if workspace is not None else config.workspace_root()
    profile_choice = (
        scan_profile if scan_profile is not None else config.load_settings().scan_profile
    )
    if profile_choice not in config.SCAN_PROFILES:
        typer.echo(
            f"[error] unknown --scan-profile '{profile_choice}'; "
            f"choose one of {', '.join(config.SCAN_PROFILES)}.",
            err=True,
        )
        raise typer.Exit(2)
    try:
        target = Target(ip=ip, hostname=hostname)
    except ValueError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    directory = Path(root) / profile
    # why: an EXISTING profile is always LOADED, never re-created — Profile.create overwrites
    # profile.json and erases command_history/tags/started_at (bug #2: re-running `scan` on a
    # profile without --resume silently wiped its history, the GUI's New-Project guard has no CLI
    # equivalent). --resume additionally controls whether finished commands re-run (Orchestrator).
    if (directory / "profile.json").exists():
        try:
            prof = Profile.load(directory)
        except (ValueError, OSError) as exc:
            typer.echo(f"[error] cannot read profile '{profile}': {exc}", err=True)
            raise typer.Exit(2) from exc
        # the loaded profile's stored target is authoritative (run_nmap scans it), so a differing
        # ip would be silently ignored — scanning the wrong host. Refuse the mismatch rather than
        # guess (Target() canonicalizes a host-bit CIDR, so 10.10.5.5/24 vs stored 10.10.5.0/24 is
        # not a mismatch); the user opens the right profile or picks a new name for a fresh scan.
        if prof.target.ip != target.ip:
            typer.echo(
                f"[error] target mismatch: profile '{profile}' targets {prof.target.ip}, but you "
                f"gave {ip}. Use the matching IP, or a new profile name to start a fresh scan.",
                err=True,
            )
            raise typer.Exit(2)
        # you usually learn the vhost AFTER the first scan, so `--hostname` on a re-run must be
        # applied, not dropped — TLS/vhost-aware recon keys off target.hostname. [review]
        if hostname and hostname != prof.target.hostname:
            try:
                prof.set_hostname(hostname)  # same path the GUI's Set Target Hostname uses
            except ValueError as exc:
                typer.echo(f"[error] invalid --hostname: {exc}", err=True)
                raise typer.Exit(2) from exc
            typer.echo(f"[profile] hostname set to {hostname}")
            _audit_profile(prof, "set-hostname", hostname=hostname)
        _audit_profile(prof, "profile-opened", target=prof.target.ip, resume=resume)
        if resume:
            typer.echo(f"[resume] {prof.directory} — {len(prof.command_history)} prior commands")
        else:
            typer.echo(
                f"[profile] reusing {prof.directory} — history preserved "
                f"(use a new name for a fresh profile)"
            )
    else:
        prof = Profile.create(root, profile, target)
        _audit_profile(prof, "profile-created", target=prof.target.ip)
    config.add_recent(prof.directory)
    typer.echo(f"[profile] {prof.directory}  (scan profile: {profile_choice})")
    label = f"scan:{prof.target.ip}"
    _audit_profile(
        prof,
        "run",
        label=label,
        lane=_BATTERY_LANE,
        module="nmap",
        scan_profile=profile_choice,
        udp_full=udp_full,
    )
    try:
        Orchestrator(
            prof,
            on_line=lambda line: typer.echo(line),
            udp_full=udp_full,
            scan_profile=profile_choice,
            resume=resume,
            force=force,
        ).run_nmap()
    finally:
        # mirrors the GUI, which audits run-finished from the worker's `finished` signal — i.e. also
        # when the run failed or was interrupted. A started scan always has a matching end.
        _audit_profile(prof, "run-finished", label=label, services=len(prof.discovered_services))


@app.command("export-vault")
def export_vault_cmd(
    dest: Path = typer.Argument(..., help="Destination folder (an Obsidian vault or any dir)."),
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Export a profile to an Obsidian vault as linked markdown.

    Includes credential values IN FULL (CLAUDE.md §6) — treat the export as sensitive.
    """
    prof = _load_profile(profile, workspace)
    out = vault_export.export_vault(prof, dest)
    _audit_profile(prof, "profile-exported", dest=str(out))
    typer.echo(
        f"[exported] {out} (snapshot — includes credential values IN FULL; treat it as sensitive)"
    )


@app.command("export-project")
def export_project_cmd(
    dest: Path = typer.Argument(..., help="Destination folder, or an explicit <name>.tar.gz path."),
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Pack a profile folder into <name>.tar.gz for backup/transfer (includes creds.json)."""
    root = workspace if workspace is not None else config.workspace_root()
    directory = Path(root) / profile
    if not (directory / "profile.json").exists():
        typer.echo(f"[error] no profile at {directory}", err=True)
        raise typer.Exit(2)
    try:
        out = portability.export_project_archive(directory, dest)
    except portability.ProjectArchiveError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    _audit(directory, profile, "project-exported", dest=str(out))
    typer.echo(f"[exported] {out}  (WARNING: includes creds.json — treat the archive as sensitive)")


@app.command("import-project")
def import_project_cmd(
    archive: Path = typer.Argument(..., help="Project archive (.tar.gz) to import."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Replace an existing profile of the same name."
    ),
) -> None:
    """Extract a project archive into the workspace (path-traversal-safe) and register it."""
    root = workspace if workspace is not None else config.workspace_root()
    try:
        dest = portability.import_project_archive(archive, Path(root), overwrite=overwrite)
    except portability.ProjectExistsError as exc:
        typer.echo(f"[error] {exc} — re-run with --overwrite to replace it.", err=True)
        raise typer.Exit(2) from exc
    except portability.ProjectArchiveError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    config.add_recent(dest)
    _audit(dest, dest.name, "project-imported", source=str(archive))
    typer.echo(f"[imported] {dest}")


@app.command()
def doctor(
    install: bool = typer.Option(
        False, "--install", help="Offer to apt-install the missing allow-listed tools (asks first)."
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the confirmation prompt (non-interactive install)."
    ),
    show_versions: bool = typer.Option(
        False, "--versions", help="Also print the installed version of each present tool (slower)."
    ),
) -> None:
    """Check each wrapped tool; print install hints, optionally apt-install the missing ones."""
    report = doctor_mod.scan()
    required = report.required
    # why: group-aware missing — don't report a tool as missing when a present alternative already
    # covers it. Otherwise impacket-scripts looks "missing" because its scripts install as
    # impacket-GetADUsers (no .py), not the .py variant we also allow-list.
    eff_missing = doctor_mod.effective_missing(report)
    req_missing = [tool for tool in eff_missing if not tool.optional]
    spray_missing = [tool for tool in eff_missing if tool.category == "spray"]
    exploit_missing = [tool for tool in eff_missing if tool.category == "exploit"]
    present_ct = sum(1 for tool in required if tool.present)
    typer.echo(f"[doctor] {present_ct}/{len(required)} required tools found on PATH")
    if req_missing:
        typer.echo(f"[doctor] {len(req_missing)} missing (install the ones you need):")
        for tool in req_missing:
            typer.echo(f"  {tool.name:24}  {tool.hint}")
        # why: alternatives cover the same capability — don't alarm the user about skipping them.
        typer.echo(
            "\nNote: alternatives are fine to skip — netexec covers nxc/crackmapexec, and "
            "GetX.py covers impacket-GetX.py (and vice-versa)."
        )
    else:
        typer.echo("[doctor] all wrapped tools present — exam-ready.")
    if spray_missing:
        typer.echo("\n[doctor] Spray-mode tools (only needed if you enable Spray mode, §2a):")
        for tool in spray_missing:
            typer.echo(f"  {tool.name:24}  {tool.hint}")
    if exploit_missing:
        typer.echo(
            "\n[doctor] Exploitation-tab tools (§2b — needed only when you run manual attacks):"
        )
        for tool in exploit_missing:
            typer.echo(f"  {tool.name:24}  {tool.hint}")

    typer.echo("\n[doctor] Reference data (wordlists / NSE / Exploit-DB):")
    for check in doctor_mod.scan_resources():
        mark = "  ok" if check.ok else "  !!"
        typer.echo(f"{mark}  {check.name:28}{'' if check.ok else '  ' + check.detail}")

    typer.echo("\n[doctor] Host readiness:")
    for check in doctor_mod.scan_system():
        mark = "  ok" if check.ok else "  !!"
        typer.echo(f"{mark}  {check.name:30}  {check.detail}")

    if show_versions:
        vers = doctor_mod.versions(report)
        typer.echo("\n[doctor] Installed versions (present tools):")
        for name in sorted(vers):
            typer.echo(f"  {name:22}  {vers[name]}")

    if not req_missing:
        return
    if not install:
        typer.echo("\nRe-run `doctor --install` to apt-install the required ones (asks first).")
        return
    plan = doctor_mod.install_plan(report)
    if plan.manual:
        typer.echo("\n[doctor] install these manually (not apt):")
        for name, hint in plan.manual:
            typer.echo(f"  {name:24}  {hint}")
    code = doctor_mod.install(
        plan,
        assume_yes=yes,
        confirm=lambda command: typer.confirm(f"[doctor] run `{command}`?"),
        echo=typer.echo,
    )
    raise typer.Exit(code)


@app.command("docs")
def docs_cmd(
    topic: str | None = typer.Argument(
        None, help="A topic id or title prefix (e.g. 'graph'). Omit to list all topics."
    ),
    plain: bool = typer.Option(
        False, "--plain", help="Print raw markdown instead of terminal-rendered."
    ),
) -> None:
    """Read the bundled user guide — the same content as the GUI's Help -> Documentation."""
    if topic is None:
        typer.echo("Nabu documentation — run `nabu-cli docs <topic>`:\n")
        for entry in guide.topics():
            typer.echo(f"  {entry.id:16}  {entry.summary}")
        return
    resolved = guide.resolve(topic)
    if resolved is None:
        typer.echo(
            f"[docs] no topic matches '{topic}'. Run `nabu-cli docs` to list them.", err=True
        )
        raise typer.Exit(1)
    markdown = guide.load(resolved.id)
    # pretty-render on a real terminal; fall back to raw markdown when piped or with --plain, so the
    # output stays clean for scripts and tests.
    if plain or not sys.stdout.isatty():
        typer.echo(markdown)
        return
    try:
        from rich.console import Console
        from rich.markdown import Markdown

        Console().print(Markdown(markdown))
    except Exception:  # boundary: rich should be present, but never fail `docs` over rendering
        typer.echo(markdown)


@app.command("exploit")
def exploit_cmd(
    service: str | None = typer.Argument(
        None,
        help="Service key (ad, web, smb, mssql, mysql, ftp, ssh, snmp, redis, rdp, nfs, "
        "linux, windows, shells). Omit to list all services.",
    ),
    profile: str | None = typer.Option(
        None, "--profile", "-p", help="Profile to pre-fill {target}/{domain}/{cred} from."
    ),
    target: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Aim at a SPECIFIC host — fills {target}/{ip}/{dc}, overriding the profile target "
        "(use it to attack one host of a /24 at a time).",
    ),
    port: str | None = typer.Option(
        None,
        "--port",
        help="Port the commands fill into {port}/{url} (default: the discovered port).",
    ),
    suggested: bool = typer.Option(
        False,
        "--suggested",
        help="Only the actions this box's evidence points at (needs --profile). Same ★ ranking "
        "as the GUI: open ports, confirmed vuln ids, findings, vault credentials.",
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Show exploitation command templates (§2b) — the ATTACK catalog. Display-only: copy to run.

    Recon feeds attack: scan/enum a box, then `exploit <service>` prints pre-filled attack commands
    bound to the profile's target, the discovered port, and your vault credentials. Aim at a
    specific host/port with `--target`/`--port` — handy on a /24 (one host at a time). Actions
    tagged `RUN` run from Kali; `COPY` are victim-side (paste into a shell you own).

    **Examples:**

    ```
    nabu-cli exploit                          # list every service in the attack catalog
    nabu-cli exploit smb -p box               # SMB attacks, pre-filled from profile 'box'
    nabu-cli exploit ad -p box                # the full Active Directory attack catalog
    nabu-cli exploit web -p box --port 8080   # web attacks aimed at port 8080
    nabu-cli exploit mssql -p box -t 10.10.10.7  # aim at a SPECIFIC host (one IP of a /24)
    nabu-cli exploit linux                    # victim-side privesc (copy-paste in your shell)
    nabu-cli exploit smb -p box --suggested   # only what this box's evidence points at
    ```
    """
    from oscprecon import exploit as exploit_mod
    from oscprecon import ligolo

    values: dict[str, str] = {}
    # mirror the GUI ExploitPanel fill: reverse-shell templates need {lhost}/{lport} filled even
    # without a profile (else a copied command still shows literal {lhost}). tun0 is best-effort.
    lhost = ligolo.detect_tun_ip("tun0") or ligolo.detect_tun_ip("tun1")
    if lhost:
        values["lhost"] = lhost
    values["lport"] = "4444"
    prof: Profile | None = None
    if profile is not None:
        prof = _load_profile(profile, workspace)
        values["target"] = prof.target.ip
        values["dc"] = prof.target.ip
        # no trailing slash: templates use {url}/path — a trailing slash double-slashed them
        # (http://host//CHANGELOG.md). {url}?query still resolves fine.
        values["url"] = f"http://{prof.target.host}"
        if prof.target.hostname and "." in prof.target.hostname:
            values["domain"] = prof.target.hostname.split(".", 1)[1]
        creds = prof.credentials()
        # mirror the GUI's ExploitPanel fill: a hash cred fills {hash} for pass-the-hash actions,
        # a password cred fills {password} — fill both when present so neither kind of template is
        # left with an unfilled brace. user/domain come from the password cred, else the hash cred.
        # ONE credential fills the command, like the GUI's Credential dropdown. Taking the
        # username from one entry and the hash from another produced a command that authenticated
        # as nobody: `-hashes <svc_b's hash>` under `svc_a`'s name. [review]
        pw = next((c for c in creds if c.secret_type == "password"), None)
        hc = next((c for c in creds if c.secret_type == "hash"), None)
        primary = pw or hc
        pw = primary if primary is not None and primary.secret_type == "password" else None
        hc = primary if primary is not None and primary.secret_type == "hash" else None
        if primary is not None:
            values["user"] = primary.username
            if primary.domain:
                values["domain"] = primary.domain
        if pw is not None:
            values["password"] = pw.secret
        if hc is not None:
            values["hash"] = hc.secret

    if service is None:
        typer.echo("Exploitation services (use `nabu-cli exploit <service>` for actions):\n")
        for key in exploit_mod.service_keys():
            spec = exploit_mod.service_exploits(key)
            if spec is None:
                continue
            ports = ", ".join(str(p) for p in spec.ports) or "—"
            typer.echo(f"  {key:9} {spec.label:22} {len(spec.actions):3} actions   ports: {ports}")
        raise typer.Exit(0)

    # accept the service-name variants nmap/`enum` use (postgresql->postgres, etc.) so
    # `exploit <name>` resolves the same key `enum <name>` and the tree use.
    _ALIASES = {
        "postgresql": "postgres",
        "ms-sql-s": "mssql",
        "microsoft-ds": "smb",
        "netbios-ssn": "smb",
        "domain": "dns",
        "http": "web",
        "https": "web",
        "http-proxy": "squid",
    }
    key = _ALIASES.get(service.lower(), service)
    spec = exploit_mod.service_exploits(key)
    if spec is None:
        typer.echo(f"[error] unknown service '{service}'", err=True)
        raise typer.Exit(2)
    rank_ctx: exploit_mod.RankContext | None = None  # no profile -> no evidence -> no ★
    if prof is not None:
        # bind {port} to the DISCOVERED port for this service (mirrors the GUI ExploitPanel), so
        # port-parameterised templates aren't left with a literal {port}; fall back to the catalog
        # default. And emit the GUI's "attacks belong to identified services" decision-aid warning.
        open_svcs = [(s.port, s.service) for s in prof.discovered_services if s.state == "open"]
        discovered_port = exploit_mod.port_for_service(open_svcs, key)
        if discovered_port is not None:
            values["port"] = str(discovered_port)
        elif spec.ports:
            values["port"] = str(spec.ports[0])
        from oscprecon import findings as _findings

        fp_texts: list[str] = []
        for s in prof.discovered_services:
            fp_texts.append(f"{s.product} {s.version}")
            if s.nmap_scripts_output:
                fp_texts.append(s.nmap_scripts_output)
        found_rows: list[dict[str, object]] = []
        try:
            for f in _findings.load_findings(prof.directory):
                found_rows.append(dict(f))
                note = str(f.get("note") or f.get("detail") or "")
                if note:
                    fp_texts.append(note)
        except OSError:
            pass
        scores = exploit_mod.score_services(open_svcs, fp_texts)
        present = {k for k, v in scores.items() if v > 0}
        # the same ranking the GUI stars, from the same engine — GUI and CLI must never disagree
        rank_ctx = exploit_mod.build_context(
            open_svcs, fp_texts, found_rows, list(prof.credentials()), prof.command_history
        )
        if spec.ports and key not in present:  # portless catalogs (linux/windows/shells) never warn
            typer.echo(
                f"⚠ {spec.label} was NOT found on this target by the scan — attacks belong to "
                f"identified services; only run this if you confirmed it's really there.\n"
            )

    # explicit host/port overrides so you can aim an attack at a SPECIFIC host/port (one IP of a
    # /24), with or without a profile. These win over the profile/discovered defaults. [user req]
    if target:
        values["target"] = target
        values["dc"] = target
    port_val = port or values.get("port", "")
    if port_val:
        values["port"] = port_val
    host_for_url = target or (prof.target.host if prof is not None else "")
    if host_for_url:
        # scheme from the SERVICE, mirroring the GUI (exploit_panel._service_url): an nmap
        # "ssl/http" / "https" name — or a TLS port — means https. Building http:// for an
        # HTTPS-only host made every copied command hit the wrong scheme and fail. [review]
        svc_name = ""
        if prof is not None and port_val.isdigit():
            svc_name = next(
                (
                    s.service.lower()
                    for s in prof.discovered_services
                    if s.port == int(port_val) and s.state == "open"
                ),
                "",
            )
        secure = "https" in svc_name or "ssl" in svc_name or port_val in ("443", "8443")
        scheme = "https" if secure else "http"
        # only a WEB service gets :port in {url} — mirrors exploit_panel._service_url(). Appending
        # an SMB/LDAP port to a URL produced http://host:445, which is not a thing. [review]
        web_family = (
            key in ("web", "webdav")
            or "http" in svc_name
            or "ssl" in svc_name
            or bool(set(spec.ports) & exploit_mod.WEB_PORTS)
        )
        if web_family and port_val and port_val not in ("80", "443"):
            values["url"] = f"{scheme}://{host_for_url}:{port_val}"
        else:
            values["url"] = f"{scheme}://{host_for_url}"

    typer.echo(f"# {spec.label} — {spec.note}\n")
    # which ports each attack goes to, marked ✓ when the scan found that port open on this box —
    # the same decision aid the GUI shows, so a 445 command is never quietly aimed elsewhere.
    open_ports: set[int] = (
        {s.port for s in prof.discovered_services if s.state == "open"}
        if prof is not None
        else set()
    )
    if suggested and rank_ctx is None:
        typer.echo(
            "[error] --suggested ranks against a project's evidence — add -p PROFILE, or drop "
            "--suggested for the full catalog.",
            err=True,
        )
        raise typer.Exit(2)
    starred = exploit_mod.suggested_action_ids(spec, rank_ctx) if rank_ctx is not None else set()
    if suggested and not starred:
        typer.echo(
            "No suggestions for this service — nothing in the project points at it yet. "
            "Run recon (and `nabu-cli vuln`) first, or drop --suggested for the full catalog.\n"
        )
        raise typer.Exit(0)
    ranked = (
        {s.action.id: s.score for s in exploit_mod.rank_actions(spec, rank_ctx)}
        if rank_ctx is not None
        else {}
    )
    categories = (
        exploit_mod.category_order(spec, rank_ctx) if rank_ctx is not None else spec.categories()
    )
    for category in categories:
        actions = sorted(spec.by_category(category), key=lambda a: -ranked.get(a.id, 0))
        if suggested:
            actions = [a for a in actions if a.id in starred]
            if not actions:
                continue
        typer.echo(f"── {category} ──")
        for action in actions:
            tag = "RUN " if action.executable else "COPY"  # attacker (run) vs victim (copy)
            star = "★ " if action.id in starred else ""
            act_ports, port_why = exploit_mod.action_ports(action, spec)
            if act_ports:
                ordered = sorted(act_ports, key=lambda p: (p not in open_ports, act_ports.index(p)))
                shown = ordered[:4]
                marks = ",".join(f"{p}{'✓' if p in open_ports else ''}" for p in shown)
                if len(ordered) > len(shown):
                    marks += f",+{len(ordered) - len(shown)}"
                port_note = f"  ports: {marks} ({port_why})"
            else:
                port_note = f"  ports: {port_why}" if port_why else ""
            typer.echo(f"[{tag}] {star}{action.title}  ({action.tool}){port_note}")
            typer.echo(f"    {exploit_mod.fill_template(action.template, values)}")
        typer.echo("")
    if open_ports:
        typer.echo(
            f"✓ = the scan found that port open on {prof.target.ip if prof else 'this box'}."
        )
    if starred and not suggested:
        typer.echo("★ = this box's evidence points at it (--suggested shows only these).")
    raise typer.Exit(0)


@app.command("payload")
def payload_cmd(
    payload: str | None = typer.Argument(
        None, help="Payload id (see `nabu-cli payload` with no args) or a raw msfvenom -p string."
    ),
    lhost: str = typer.Option("", "--lhost", "-l", help="Your VPN/tun0 IP (LHOST)."),
    lport: int = typer.Option(4444, "--lport", "-P", help="Listener port (LPORT)."),
    fmt: str = typer.Option("", "--format", "-f", help="Output format (default: payload's own)."),
    encoder: str = typer.Option("", "--encoder", "-e", help="Encoder, e.g. x86/shikata_ga_nai."),
    iterations: int = typer.Option(1, "--iterations", "-i", help="Encoder iterations."),
    badchars: str = typer.Option("", "--badchars", "-b", help=r"Bad chars, e.g. \x00\x0a."),
    out: str = typer.Option("", "--out", "-o", help="Output file (default: shell.<ext>)."),
) -> None:
    """Build an msfvenom reverse-shell payload + its listener (display-only — copy and run it).

    **Examples:**

    ```
    nabu-cli payload                                        # list the payload ids
    nabu-cli payload lin-x64-stageless -l 10.10.14.5 -P 443     # Linux shell, your tun0 IP + port
    nabu-cli payload win-x64-stageless -l 10.10.14.5 -f exe -o shell.exe   # Windows .exe
    ```
    """
    from oscprecon.exploit import msfvenom

    if payload is None:
        typer.echo("msfvenom payload builder — pick an id:\n")
        for plat in msfvenom.PLATFORMS:
            typer.echo(f"── {plat.label} ──")
            for p in plat.payloads:
                flag = "  [meterpreter=one-use]" if p.meterpreter else ""
                typer.echo(f"  {p.id:19} {p.payload}{flag}")
            typer.echo("")
        typer.echo("e.g.  nabu-cli payload win-x64-stageless -l 10.10.14.7 -P 443")
        raise typer.Exit(0)

    result = msfvenom.build_command(
        msfvenom.MsfvenomSpec(
            payload=payload,
            fmt=fmt,
            lhost=lhost,
            lport=lport,
            encoder=encoder,
            iterations=iterations,
            badchars=badchars,
            outfile=out,
        )
    )
    typer.echo("# generate the payload (on Kali):")
    typer.echo(result.command)
    typer.echo("\n# catch the shell (start this first):")
    typer.echo(result.listener)
    for note in result.notes:
        typer.echo(f"\n⚠ {note}")
    raise typer.Exit(0)


@app.command("gtfobins")
def gtfobins_cmd(
    binary: str | None = typer.Argument(
        None,
        help="Binary or technique to search (e.g. find, tar, sudo, suid, capabilities). "
        "Omit to list every binary.",
    ),
) -> None:
    """Offline GTFOBins lookup — SUID/sudo/capability abuse for a Unix binary (display-only).

    **Examples:**

    ```
    nabu-cli gtfobins tar               # break-outs for tar (suid / sudo / capabilities)
    nabu-cli gtfobins find              # the classic sudo/suid escape
    nabu-cli gtfobins vim               # shell escapes from a restricted editor
    ```
    """
    from oscprecon.references import gtfobins as gtfo

    results = gtfo.search(binary or "")
    if not results:
        typer.echo(f"[no match] '{binary}' — try a binary or function (sudo/suid/…)", err=True)
        raise typer.Exit(1)
    if binary is None:
        typer.echo("GTFOBins (use `nabu-cli gtfobins <binary>` for the techniques):\n")
        for b in results:
            typer.echo(f"  {b.name:14} {', '.join(b.functions)}")
        raise typer.Exit(0)
    for b in results:
        typer.echo(f"# {b.name}  —  {b.url}")
        for tech in b.techniques:
            typer.echo(f"  [{tech.func}] {tech.code}")
        typer.echo("")
    raise typer.Exit(0)


@app.command("hashcat")
def hashcat_cmd(
    query: str | None = typer.Argument(
        None, help="Search hash type by name/mode/category (e.g. apr1, ntlm, 1800, kerberos)."
    ),
    attack: str = typer.Option("0", "--attack", "-a", help="Attack mode: 0 dict, 1 combo, 3 mask."),
    hashfile: str = typer.Option("hash.txt", "--hashfile", help="Hash file for the built command."),
    wordlist: str = typer.Option(
        "/usr/share/wordlists/rockyou.txt", "--wordlist", "-w", help="Wordlist (attack 0/1/6/7)."
    ),
    mask: str = typer.Option("?a?a?a?a?a?a", "--mask", help="Mask (attack 3/6/7)."),
) -> None:
    """Hashcat mode helper — find the -m for a hash and build the crack command (display-only).

    **Examples:**

    ```
    nabu-cli hashcat ntlm               # search modes matching 'ntlm'
    nabu-cli hashcat 1000               # look up mode 1000 + build the crack command
    nabu-cli hashcat krb5tgs -a 3       # a mask/brute attack (attack mode 3)
    ```
    """
    from oscprecon.references import hashcat as hc

    results = hc.search(query or "")
    if not results:
        typer.echo(f"[no match] '{query}' — try apr1 / ntlm / kerberos / a -m number", err=True)
        raise typer.Exit(1)
    if query is None:
        typer.echo("Hashcat modes (use `nabu-cli hashcat <search>` to narrow + build a command):\n")
        cat = ""
        for m in results:
            if m.category != cat:
                cat = m.category
                typer.echo(f"── {cat} ──")
            typer.echo(f"  -m {m.mode:<6} {m.name}")
        typer.echo("\nAttack modes: " + " · ".join(f"-a {a} {n}" for a, n, _ in hc.ATTACK_MODES))
        raise typer.Exit(0)
    typer.echo(f"# matches for '{query}':\n")
    for m in results:
        cmd = hc.build_command(
            m.mode, attack=attack, hashfile=hashfile, wordlist=wordlist, mask=mask
        )
        typer.echo(f"  -m {m.mode:<6} {m.name}  [{m.category}]")
        typer.echo(f"      {cmd}")
    typer.echo("")
    raise typer.Exit(0)


@app.command("pivot")
def pivot_cmd(
    lhost: str = typer.Option(
        "", "--lhost", "-l", help="Your VPN/tun0 IP (the agent dials back here). Auto from tun0."
    ),
    routes: str = typer.Option("", "--routes", "-r", help="Internal /24(s), comma-separated."),
    agent_os: str = typer.Option("linux", "--os", help="Pivot host OS: linux | windows."),
    port: int = typer.Option(11601, "--port", "-P", help="Proxy listen port."),
    iface: str = typer.Option("ligolo", "--iface", help="Tun interface name."),
) -> None:
    """Show the ligolo-ng pivot workflow as copy-paste steps (display-only; same as the Pivot tab).

    **Examples:**

    ```
    nabu-cli pivot -l 10.10.14.5                    # Linux pivot, your tun0 IP
    nabu-cli pivot --os windows -r 172.16.5.0/24    # Windows agent + an internal /24 to route
    nabu-cli pivot -r 172.16.5.0/24,172.16.6.0/24   # multiple internal ranges
    ```
    """
    from oscprecon import ligolo

    # normalize up front: build_ligolo_steps() falls back to the Linux workflow for any unknown
    # value, so the header must match — else `--os bogus` prints "bogus pivot" over Linux steps.
    agent_os = agent_os.strip().lower()
    if agent_os not in ("linux", "windows"):
        agent_os = "linux"
    ip = lhost.strip() or ligolo.detect_tun_ip("tun0") or ligolo.detect_tun_ip("tun1")
    route_list = [r.strip() for r in routes.replace(";", ",").split(",") if r.strip()]
    typer.echo(f"# ligolo-ng — reach an internal network ({agent_os} pivot)")
    typer.echo(f"# GitHub: {ligolo.LIGOLO_GITHUB}  ·  Releases: {ligolo.LIGOLO_RELEASES}")
    typer.echo(
        f"# syntax checked vs {ligolo.LIGOLO_REF_VERSION} ({ligolo.LIGOLO_REF_VERIFIED}) — "
        "check releases if stale\n"
    )
    for step in ligolo.build_ligolo_steps(
        ip, port=port, iface=iface, routes=route_list, agent_os=agent_os
    ):
        typer.echo(f"── {step.n}. {step.title}  (on {step.where}) ──")
        for line in step.commands:
            typer.echo(f"  {line}")
        if step.note:
            typer.echo(f"  # {step.note}")
        typer.echo("")
    typer.echo("# ═══ Ligolo reference — serve · transfer · tunnel · console ═══\n")
    for section in ligolo.ligolo_reference_sections(ip, port=port, agent_os=agent_os):
        typer.echo(f"── {section.title} ──")
        typer.echo(f"  # {section.subtitle}")
        for item in section.items:
            typer.echo(f"  • {item.label}")
            for line in item.command.split("\n"):
                typer.echo(f"      {line}")
        typer.echo("")
    typer.echo("# ── Other pivot methods (when ligolo isn't an option) ──")
    for method in ligolo.PIVOT_METHODS:
        typer.echo(f"── {method.name}  —  {method.when} ──")
        for line in method.commands:
            typer.echo(f"  {line}")
        typer.echo("")
    raise typer.Exit(0)


def _profile_dir(profile: str, workspace: Path | None) -> Path:
    root = workspace if workspace is not None else config.workspace_root()
    directory = Path(root) / profile
    if not (directory / "profile.json").exists():
        typer.echo(f"[error] no profile '{profile}' in {root}", err=True)
        raise typer.Exit(2)
    return directory


def _load_profile(profile: str, workspace: Path | None, *, writes: bool = True) -> Profile:
    # a corrupt / foreign profile.json makes Profile.load raise ValueError; catch it and exit with
    # the clean `[error] … / exit 2` convention instead of dumping a traceback (bug #17).
    directory = _profile_dir(profile, workspace)
    try:
        loaded = Profile.load(directory)
    except (ValueError, OSError) as exc:
        typer.echo(f"[error] cannot read profile '{profile}': {exc}", err=True)
        raise typer.Exit(2) from exc
    if writes:
        _warn_if_locked(directory, profile)
    return loaded


def _warn_if_locked(directory: Path, profile: str) -> None:
    # §6b: a GUI window holding the edit lock has this project's state in memory and will write it
    # back. A CLI run against the same folder interleaves with that — the two disagree, and the
    # window's next save wins. The GUI refuses this; the CLI said nothing at all. Warn loudly
    # rather than refuse: a headless scan on a locked project is a legitimate thing to insist on.
    from oscprecon.workspace import locks

    info, _malformed = locks.read_lock(directory)
    if info is None or locks.is_stale(info) or locks.is_ours(info):
        return
    typer.echo(
        f"⚠ '{profile}' is open for editing in another Nabu window (pid {info.pid}). That window "
        "holds this project in memory and will overwrite what this command writes — close it "
        "first, or expect to lose one side's changes.",
        err=True,
    )


# the richer recon modules (their own commands()/parse(), not simple-spec steps). enum runs the
# LIGHT Tier-1 battery each emits (banner/whatweb/curl/nmap-scripts) headlessly — the same engine
# the GUI panels drive. default ports pick the module's port when the profile hasn't discovered one.
_FULL_ENUM_MODULES: dict[str, int] = {
    "ssh": 22,
    "ftp": 21,
    "http": 80,
    "smb": 445,
    "ldap": 389,
    "dns": 53,
    "smtp": 25,
    "vhost": 80,
}


def _tier1_enum_steps(
    service: str, module: Module, target: Target, port: int, ports: list[Port]
) -> list[tuple[Command, str]]:
    # Mirror the GUI's bespoke recon workers: use each module's native step methods, which tag every
    # step with the correct parser key (`.tool`). The output-file STEM must NOT be used as the key —
    # stems don't match the _PARSERS dispatch keys (smb `users.txt` vs the "netexec-users" parser,
    # ldap `rootdse.txt` vs "ldapsearch-rootdse", ftp `curl-root.txt` vs "curl-list", …), so a
    # stem-keyed raw dict silently parses to zero findings. http/vhost are commands()-driven and
    # their parse() keys on "<tool>:<port>" / "<tool>:<domain>", so those keys are built explicitly.
    from oscprecon.modules.dns import DnsModule
    from oscprecon.modules.ftp import FtpModule
    from oscprecon.modules.ldap import LdapModule
    from oscprecon.modules.smb import SmbModule
    from oscprecon.modules.smtp import SmtpModule
    from oscprecon.modules.ssh import SshModule

    domain = target.hostname or ""
    if isinstance(module, SshModule):
        return [(s.command, s.tool) for s in module.recon_steps(target, port)]
    if isinstance(module, SmtpModule):
        return [(s.command, s.tool) for s in module.recon_steps(target, port)]
    if isinstance(module, DnsModule):
        return [(s.command, s.tool) for s in module.recon_steps(target, domain or None, port)]
    if isinstance(module, FtpModule):
        ftp_steps = [*module.banner_steps(target, port), *module.anon_steps(target, port)]
        return [(s.command, s.tool) for s in ftp_steps]
    if isinstance(module, LdapModule):
        return [(s.command, s.tool) for s in module.rootdse_steps(target, port)]
    if isinstance(module, SmbModule):
        smb_steps = [
            *module.banner_steps(target),
            *module.null_session_steps(target),
            *module.guest_steps(target),
        ]
        return [(s.command, s.tool) for s in smb_steps]
    if service == "vhost":  # parse() does label.partition(":") -> (tool, domain)
        return [(c, f"{Path(c.output_file).stem}:{domain}") for c in module.commands(target, ports)]
    # http (and any commands()-driven fallback): parse() keys on "<tool>:<port>" where port is the
    # per-port output subdir; the whatweb/robots battery uses clean stems so stem:port is correct.
    out: list[tuple[Command, str]] = []
    for c in module.commands(target, ports):
        of = Path(c.output_file)
        key = f"{of.stem}:{of.parent.name}" if of.parent.name.isdigit() else of.stem
        out.append((c, key))
    return out


# services whose Tier-1 recon is a conditional SEQUENCE, not a flat list of commands — they run the
# shared engine in `service_enum`, which is also what the GUI panels drive.
_ENGINE_SERVICES = frozenset({"smb", "ftp", "ssh", "dns", "ldap"})


def _run_engine_enum(service: str, prof: Profile, port: int) -> None:
    from oscprecon import findings as findings_mod
    from oscprecon import service_enum

    target = prof.target
    engine: service_enum.EnumEngine
    if service == "smb":
        engine = service_enum.SmbEnum(prof, "full", typer.echo)
    elif service == "ftp":
        engine = service_enum.FtpEnum(prof, "full", port, typer.echo)
    elif service == "ssh":
        engine = service_enum.SshEnum(prof, port, typer.echo)
    elif service == "dns":
        engine = service_enum.DnsEnum(prof, target.hostname or "", port, typer.echo)
    else:
        engine = service_enum.LdapEnum(prof, "", port, typer.echo)
    result = engine.run()
    for line in result.summary:
        typer.echo(f"  {line}")
    for cred in result.creds:
        prof.add_credential(cred)
        typer.echo(f"[cred] {cred.username} (source: {cred.source})")
    Reporter(prof).write()
    recorded = len(findings_mod.load_findings(prof.directory))
    typer.echo(f"\n[enum] {service}: {recorded} finding(s) recorded in this project")


def _run_full_module_enum(service: str, profile: str, workspace: Path | None, port: int) -> None:
    # run a full recon Module (native Tier-1 steps -> shell.run -> parse -> record findings),
    # mirroring the GUI's bespoke workers so http/ssh/ftp/dns/ldap/smb/smtp/vhost are enum-runnable.
    import importlib
    import inspect
    from datetime import UTC, datetime

    from oscprecon import findings as findings_mod
    from oscprecon.models import Port, Proto
    from oscprecon.modules.base import Module
    from oscprecon.parsing import run_parser

    mod = importlib.import_module(f"oscprecon.modules.{service}")
    cls = next(
        (
            obj
            for _, obj in inspect.getmembers(mod, inspect.isclass)
            if issubclass(obj, Module)
            and obj is not Module
            and obj.__module__.startswith(mod.__name__)
        ),
        None,
    )
    if cls is None:
        typer.echo(f"[error] no recon module class for '{service}'", err=True)
        raise typer.Exit(2)
    module = cls()
    prof = _load_profile(profile, workspace)
    # ports for this module: the discovered ports whose service name matches, else the CLI override
    # or the module's default port — so it still runs a Tier-1 pass even before a versioned scan.
    default_port = port or _FULL_ENUM_MODULES[service]
    # match discovered services through the SAME name-alias table the simple-spec path uses, so
    # nmap's name (dns->"domain", smb->"microsoft-ds") is recognised — an exact string compare made
    # `enum dns` (etc.) miss the real port and fall back to the default.
    from oscprecon.exploit import services_present

    ports = [
        Port(number=s.port, proto=s.proto, service=s.service, product=s.product, version=s.version)
        for s in prof.discovered_services
        if s.proto == Proto.TCP
        and (
            s.service == service
            or (service == "http" and "http" in s.service)
            or service in services_present([(s.port, s.service)])
        )
    ]
    if not ports:
        ports = [Port(number=default_port, proto=Proto.TCP, service=service)]
    elif port:
        # an explicit --port is an instruction, not a hint: aim at THAT port. Without this, a box
        # with 80 discovered ignored `enum http --port 8080` entirely and re-enumerated 80 — the
        # multi-port modules (http/vhost) build their commands from this list. [review]
        chosen = next((p for p in ports if p.number == port), None)
        ports = [chosen or Port(number=port, proto=Proto.TCP, service=service)]
    # the scalar port the single-port step modules (ssh/ftp/ldap/smtp/dns/smb) actually probe: an
    # explicit --port wins (bug #15: it was silently ignored once the service was discovered), else
    # the DISCOVERED port when the scan found the service on a non-standard port, else the default.
    probe_port = port or ports[0].number
    if service == "http":
        # an unresolved profile hostname makes every http probe fail with "no address" — warn and
        # let the module fall back to the IP so recon still works (add /etc/hosts for a real vhost).
        from oscprecon.modules.http import effective_web_host

        _, unresolved = effective_web_host(prof.target)
        if unresolved:
            typer.echo(
                f"⚠ hostname '{prof.target.hostname}' does not resolve — probing the IP "
                f"{prof.target.ip} instead. For a name-based vhost, add "
                f"'{prof.target.ip} {prof.target.hostname}' to /etc/hosts and re-run."
            )
    if service in _ENGINE_SERVICES:
        # smb/ftp/ssh/dns/ldap run the SHARED engine — the same conditional sequence the GUI panel
        # drives (SMB null -> guest -> follow-ups -> share walk -> peek; FTP's bounded BFS + peek).
        # The CLI used to run only each module's FIRST phase and stop, so `enum smb` and the SMB
        # panel's "Run full SMB recon" did visibly different amounts of work. [parity]
        engine_label = f"{service}:{probe_port}"
        _audit_profile(
            prof, "run", label=engine_label, lane=_TOOL_LANE, module=service, port=probe_port
        )
        try:
            _run_engine_enum(service, prof, probe_port)
        finally:
            _audit_profile(prof, "run-finished", label=engine_label)
        return
    raw: dict[str, str] = {}
    issues: list[str] = []
    steps = _tier1_enum_steps(service, module, prof.target, probe_port, ports)
    if not steps:
        # §24 no silent failures: vhost fuzzing needs a domain, and with none the module builds no
        # commands at all. Reporting "0 finding(s)" read as "nothing is there" when in fact nothing
        # ran — say which input is missing, and exit non-zero. [review]
        hint = (
            "vhost enumeration needs a domain — set one with "
            f"`nabu-cli scan {prof.target.ip} -p {profile} --hostname box.htb` "
            "(or Edit → Set Target Hostname in the GUI), then re-run."
            if service == "vhost"
            else f"the {service} module produced no commands for this target."
        )
        typer.echo(f"[enum] {service}: nothing to run — {hint}", err=True)
        raise typer.Exit(2)
    label = f"{service}:{probe_port}"
    with _audited_run(prof, label, lane=_TOOL_LANE, module=service, port=probe_port) as run_details:
        for command, key in steps:
            out = prof.directory / command.output_file
            result = shell.run(command.shell_line, out, cwd=prof.directory, on_line=typer.echo)
            if result.missing_tool is not None:
                issues.append(f"{result.missing_tool} not installed")
            elif result.blocked is not None:
                issues.append("a step was blocked by the recon-only policy")
            try:
                text = out.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if key:  # unparsed steps (e.g. smb nmap-smb, http headers) run but carry no parser key
                # ACCUMULATE, don't overwrite: several steps legitimately share one parser key
                # (smb's null-session AND guest steps are both netexec-shares/smbclient-shares), so
                # raw[key]=text let the guest run (often LOGON_FAILURE) clobber the null findings.
                raw[key] = raw[key] + "\n" + text if key in raw else text
        # WordPress follow-up (CLAUDE.md §9): when a web port's fingerprint shows WordPress, run
        # wpscan enumeration (never brute) for that port and fold its JSON into the same parse pass,
        # so users / plugins / themes / version land in findings.json, not just a text suggestion.
        if service == "http":
            from oscprecon.modules.http import detect_wordpress, is_tls, wordpress_command

            for web_port in ports:
                port_texts = [v for k, v in raw.items() if k.endswith(f":{web_port.number}")]
                if not detect_wordpress(*port_texts):
                    continue
                wp_cmd = wordpress_command(
                    prof.target, web_port.number, is_tls(web_port.service, web_port.number)
                )
                typer.echo(
                    f"\n[wordpress] detected on port {web_port.number} — running "
                    f"wpscan enumeration (plugins/themes/users; never brute)…"
                )
                wp_out = prof.directory / wp_cmd.output_file
                wp_result = shell.run(
                    wp_cmd.shell_line, wp_out, cwd=prof.directory, on_line=typer.echo
                )
                if wp_result.missing_tool is not None:
                    issues.append(f"{wp_result.missing_tool} not installed")
                elif wp_result.blocked is not None:
                    issues.append("a step was blocked by the recon-only policy")
                try:
                    wp_text = wp_out.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    wp_text = ""
                raw[f"wpscan:{web_port.number}"] = wp_text
        found = run_parser(lambda: module.parse(raw), label=service, raw="\n".join(raw.values()))
        if found:
            now = datetime.now(UTC).isoformat()
            findings_mod.add_findings(
                prof.directory,
                [
                    findings_mod.from_parsed(f.service, f.fields, f.detail, now, port=probe_port)
                    for f in found
                ],
            )
        if issues:
            typer.echo(
                f"\n⚠ {len(dict.fromkeys(issues))} step(s) did not run — "
                f"{'; '.join(dict.fromkeys(issues))}. Findings may be INCOMPLETE."
            )
        run_details["findings"] = len(found)
    typer.echo(f"\n[enum] {service}: {len(found)} finding(s)")
    for f in found:
        typer.echo(
            f"  • {f.fields.get('kind', '?')}: {f.fields.get('value', '')}  {f.detail}".rstrip()
        )
    for tip in module.suggest(found):
        typer.echo(f"  → {tip}")
    Reporter(prof).write()


@app.command("enum")
def enum_cmd(
    service: str | None = typer.Argument(
        None, help="Service to enumerate (see the no-arg list). Omit to list runnable services."
    ),
    profile: str | None = typer.Option(
        None, "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    port: int = typer.Option(0, "--port", help="Override the discovered port (0 = the default)."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Run a service's Tier-1 recon headlessly (the same enumeration the GUI service panels run).

    Uses the profile's target and the discovered port for that service (override with `--port`).

    **Examples:**

    ```
    nabu-cli enum                       # list the services you can enumerate
    nabu-cli enum smb -p box            # SMB null-session / guest / shares recon
    nabu-cli enum http -p box           # HTTP fingerprint + content-discovery leads
    nabu-cli enum ldap -p box --port 3268   # override the discovered port
    ```
    """
    from datetime import UTC, datetime

    from oscprecon import findings as findings_mod
    from oscprecon.gui.simple_recon import SIMPLE_SPECS  # Qt-free: importing it never loads PySide6
    from oscprecon.parsing import run_parser

    if service is None:
        # the no-arg listing is documented as the first example — it must work WITHOUT a profile
        typer.echo("Runnable services (`nabu-cli enum <service> -p <profile>`):\n")
        typer.echo("  " + ", ".join(sorted(set(SIMPLE_SPECS) | set(_FULL_ENUM_MODULES))))
        raise typer.Exit(0)
    if profile is None:
        typer.echo(f"[error] enum needs a project: nabu-cli enum {service} -p <profile>", err=True)
        raise typer.Exit(2)
    spec = SIMPLE_SPECS.get(service)
    if spec is None:
        # not a simple-spec service — try the richer full recon modules (http/ssh/ftp/dns/ldap/…)
        if service in _FULL_ENUM_MODULES:
            _run_full_module_enum(service, profile, workspace, port)
            raise typer.Exit(0)
        runnable = ", ".join(sorted(set(SIMPLE_SPECS) | set(_FULL_ENUM_MODULES)))
        typer.echo(
            f"[error] '{service}' is not a runnable enum service. Choose one of: {runnable}",
            err=True,
        )
        raise typer.Exit(2)
    prof = _load_profile(profile, workspace)
    # use the DISCOVERED port when the scan found this service on a non-standard port (mirrors the
    # GUI, which passes service.port). Was a bug: the raw --port default (0) made steps_fn fall back
    # to the module default and miss a service on an odd port. Same fix as _run_full_module_enum.
    from oscprecon.exploit import services_present
    from oscprecon.models import Proto as _Proto

    probe_port = port
    if probe_port == 0:
        # match through the service-name alias table (bug #16): the enum key is mssql/rdp/winrm
        # but nmap names the port "ms-sql-s"/"ms-wbt-server"/"wsman" — an exact compare missed those
        # and fell back to the default port, so a scan that found the service was ignored.
        probe_port = next(
            (
                s.port
                for s in prof.discovered_services
                if s.proto == _Proto.TCP
                and s.state == "open"
                and (s.service == service or service in services_present([(s.port, s.service)]))
            ),
            0,
        )
    raw: dict[str, str] = {}
    issues: list[str] = []
    # probe_port stays 0 when the scan never found this service (the tool then uses its own
    # default), and "mssql:0" would read as a port — label it by service alone in that case.
    label = f"{spec.module}:{probe_port}" if probe_port else spec.module
    with _audited_run(
        prof, label, lane=_TOOL_LANE, module=spec.module, port=probe_port
    ) as run_details:
        for command, tool in spec.steps_fn(prof.target, probe_port):
            out = prof.directory / command.output_file
            result = shell.run(command.shell_line, out, cwd=prof.directory, on_line=typer.echo)
            if result.missing_tool is not None:
                issues.append(f"{result.missing_tool} not installed")
            elif result.blocked is not None:
                issues.append("a step was blocked by the recon-only policy")
            if tool:
                try:
                    raw[tool] = out.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    raw[tool] = ""
        module = spec.factory()
        found = run_parser(
            lambda: module.parse(raw), label=spec.module, raw="\n".join(raw.values())
        )
        if found:
            now = datetime.now(UTC).isoformat()
            findings_mod.add_findings(
                prof.directory,
                [
                    findings_mod.from_parsed(f.service, f.fields, f.detail, now, port=probe_port)
                    for f in found
                ],
            )
        if issues:
            typer.echo(
                f"\n⚠ {len(dict.fromkeys(issues))} step(s) did not run — "
                f"{'; '.join(dict.fromkeys(issues))}. Findings may be INCOMPLETE."
            )
        run_details["findings"] = len(found)
    typer.echo(f"\n[enum] {spec.module}: {len(found)} finding(s)")
    for f in found:
        kind = f.fields.get("kind", "?")
        typer.echo(f"  • {kind}: {f.fields.get('value', '')}  {f.detail}".rstrip())
    for tip in module.suggest(found):
        typer.echo(f"  → {tip}")
    Reporter(prof).write()


@app.command("vuln")
def vuln_cmd(
    service: str | None = typer.Argument(
        None, help="Service to check (omit to list what this box's discovered services map to)."
    ),
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    port: int = typer.Option(
        0, "--port", help="Check only this port (0 = every port of the chosen service family)."
    ),
    mode: str = typer.Option(
        "vuln",
        "--mode",
        help="version | enum | vuln | auth | brute | dangerous — how far to escalate.",
    ),
    show: bool = typer.Option(
        False, "--show", help="Print the scripts each profile would run, and exit (a dry preview)."
    ),
    scan_all: bool = typer.Option(
        False, "--all", help="Check EVERY discovered service on this box, one after another."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Run the NSE vulnerability checks for a discovered service (GUI: the Vuln scripts button).

    A default `-sC -sV` sweep does NOT run vuln-category scripts, so a box whose only way in is an
    `smb-vuln-*` verdict looks clean. This runs them per service, prints every check's verdict —
    including the ones that came back CLEAN, so "nothing found" is backed by evidence — and records
    anything VULNERABLE (or inconclusive) into findings.json.

    **Examples:**

    ```
    nabu-cli vuln -p box                    # what each discovered service maps to
    nabu-cli vuln smb -p box                # the SMB checks on the discovered SMB port(s)
    nabu-cli vuln -p box --all              # every discovered service, in turn
    nabu-cli vuln http -p box --mode safe   # skip the DoS-category checks
    ```
    """
    from dataclasses import replace
    from datetime import UTC, datetime

    from oscprecon import findings as findings_mod
    from oscprecon import nse_profiles, nse_vuln
    from oscprecon.models import Proto
    from oscprecon.parsing import run_parser

    if mode not in nse_profiles.MODES:
        typer.echo(f"[error] --mode must be one of: {', '.join(nse_profiles.MODES)}", err=True)
        raise typer.Exit(2)
    gate = nse_profiles.gate_for(mode)
    if gate == "spray" and not config.load_settings().spray_enabled:
        typer.echo(
            "[error] the brute profile iterates credentials — that is opt-in Spray mode (§2a), "
            "off by default. Enable it with `nabu-cli config --spray`.",
            err=True,
        )
        raise typer.Exit(2)
    if port and scan_all:
        typer.echo(
            "[error] --port checks ONE port; --all checks every service. Use one or the other.",
            err=True,
        )
        raise typer.Exit(2)
    prof = _load_profile(profile, workspace)
    open_services = [s for s in prof.discovered_services if s.state == "open"]
    if not open_services:
        typer.echo("[vuln] no discovered services — run `nabu-cli scan` first.")
        raise typer.Exit(0)

    # one scan per service FAMILY — 139 and 445 are both SMB and share a single nmap pass
    plan = nse_vuln.plan_scans([(s.port, s.proto, s.service, s.product) for s in open_services])

    if service is None and port:
        # --port alone is a complete instruction: check that port. Don't fall through to the list.
        matched = [t for t in plan if port in t.ports]
        if not matched:
            typer.echo(f"[error] port {port} is not open on this box.", err=True)
            raise typer.Exit(2)
        service = matched[0].profile.key
    if service is None and not scan_all:
        typer.echo("Discovered services and the vuln checks they map to:\n")
        for target in plan:
            port_list = ",".join(str(p) for p in target.ports)
            typer.echo(f"  {port_list:>12}/{target.proto.value}  → {target.profile.label}")
            _label, prefixes, _ports = nse_profiles.for_service(target.service_name, target.port)
            mode_spec = nse_profiles.MODE_SPECS[mode]
            scripts = nse_profiles.preview(prefixes, mode)
            typer.echo(f"         {mode_spec.label}: {len(scripts)} script(s)")
            if show and scripts:
                for name in scripts:
                    typer.echo(f"           {name}")
        typer.echo("\nRun one:  nabu-cli vuln <service> -p " + profile)
        typer.echo("Run all:  nabu-cli vuln -p " + profile + " --all")
        raise typer.Exit(0)

    if scan_all:
        targets = plan
    else:
        wanted = service or ""
        targets = [t for t in plan if t.matches(wanted) or (port and port in t.ports)]
        if port:
            # --port means "only this one", not just "the group containing it" — otherwise the flag
            # silently widened the scan to the whole family and the help line was a lie.
            targets = [
                replace(t, ports=(port,), port=port) for t in targets if port in t.ports
            ] or [t for t in plan if port in t.ports]
        if not targets:
            names = ", ".join(sorted({t.profile.key for t in plan}))
            typer.echo(
                f"[error] '{service}' is not an open service on this box. Found: {names}", err=True
            )
            raise typer.Exit(2)

    if show:
        for target in targets:
            _label, prefixes, _declared = nse_profiles.for_service(target.service_name, target.port)
            scripts = nse_profiles.preview(prefixes, mode)
            typer.echo(f"\n[{mode}] {target.label} — {len(scripts)} script(s):")
            for name in scripts:
                typer.echo(f"  {name}")
            preview_cmd = nse_profiles.build_command(
                prof.target.ip, target.ports, prefixes, mode, proto=target.proto
            )
            typer.echo(f"$ {preview_cmd}")
        raise typer.Exit(0)
    total_hits = 0
    for target in targets:
        spec = target.profile
        ports = list(target.ports)
        proto = target.proto
        svc_port = target.port
        _label, prefixes, _declared = nse_profiles.for_service(target.service_name, target.port)
        command = nse_profiles.build_command(
            prof.target.ip, tuple(ports), prefixes, mode, proto=proto
        )
        out = prof.directory / "nmap" / nse_vuln.output_name(spec, ports, mode)
        out.parent.mkdir(parents=True, exist_ok=True)
        typer.echo(f"\n[vuln] {target.label}")
        if nse_profiles.gate_for(mode) == "dangerous" or (
            spec.dos_note and mode == nse_profiles.MODE_VULN
        ):
            typer.echo(f"[warning] {spec.dos_note}")
        typer.echo(f"$ {command}")
        # the GUI emits the same trio per service (run → vuln-scan → run-finished); keep it
        # identical so a mixed GUI/CLI session reads as one timeline.
        vuln_label = f"vuln:{spec.key}:{svc_port}"
        _audit_profile(prof, "run", label=vuln_label, lane=_NMAP_LANE, module=spec.key)
        _audit_profile(
            prof,
            "vuln-scan",
            service=spec.key,
            port=svc_port,
            mode=mode,
            proto=proto.value,
            host=prof.target.ip,
            command=command,
        )
        try:
            result = shell.run(command, out, cwd=prof.directory, on_line=typer.echo)
        finally:
            _audit_profile(prof, "run-finished", label=vuln_label)
        if result.missing_tool is not None:
            typer.echo(f"⚠ {result.missing_tool} is not installed — nothing was checked.")
            continue
        if result.blocked is not None:
            typer.echo(f"⚠ blocked by the recon-only policy: {result.blocked}")
            continue
        try:
            text = out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""

        # bind this iteration's values explicitly — a bare closure over the loop variables would
        # parse whatever the LAST iteration left behind.
        def _parse(
            t: str = text, sp: int = svc_port, pr: Proto = proto
        ) -> list[nse_vuln.VulnResult]:
            return nse_vuln.parse_vuln_output(t, default_port=sp, proto=pr)

        results = run_parser(_parse, label=f"nse-vuln {spec.key}", raw=text)
        for line in nse_vuln.summary_lines(results):
            typer.echo(f"  {line}")
        found = nse_vuln.to_findings(results, spec.key)
        total_hits += sum(1 for r in results if r.vulnerable)
        if found:
            now = datetime.now(UTC).isoformat()
            findings_mod.add_findings(
                prof.directory,
                [
                    findings_mod.from_parsed(f.service, f.fields, f.detail, now, port=f.port or 0)
                    for f in found
                ],
            )
    Reporter(prof).write()
    typer.echo(f"\n[vuln] {total_hits} confirmed vulnerability finding(s) recorded.")


@app.command("list")
def list_cmd(
    ip: str | None = typer.Option(None, "--ip", help="Only profiles whose target IP matches."),
    archived: bool = typer.Option(
        True, "--archived/--no-archived", help="Include archived profiles."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """List workspace projects (name · IP · status · service/finding/cred counts).

    **Example:**

    ```
    nabu-cli list                       # all your projects at a glance
    ```
    """
    from oscprecon.workspace import index, portability

    root = workspace if workspace is not None else config.workspace_root()
    if ip is not None:
        matches = portability.find_profiles_by_ip(Path(root), ip)
        if not matches:
            typer.echo(f"[list] no profile targets {ip} in {root}")
            raise typer.Exit(0)
        for directory in matches:
            typer.echo(f"  {directory.name}  ({directory})")
        raise typer.Exit(0)
    summaries = index.scan_workspace(Path(root), include_archived=archived)
    if not summaries:
        typer.echo(f"[list] no projects in {root}")
        raise typer.Exit(0)
    typer.echo(f"{'NAME':22} {'TARGET':18} {'STATUS':10}  SVC/FIND/CRED")
    for s in summaries:
        flag = " (archived)" if s.archived else ""
        counts = f"{s.service_count}/{s.finding_count}/{s.credential_count}"
        typer.echo(f"{s.name[:22]:22} {s.target[:18]:18} {s.status[:10]:10}  {counts}{flag}")


@app.command("findings")
def findings_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    service: str | None = typer.Option(None, "--service", help="Only findings from this module."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Print the structured findings a profile has collected (the Findings view, headless).

    **Example:**

    ```
    nabu-cli findings -p box            # everything discovered so far for profile 'box'
    ```
    """
    from oscprecon import finding_severity
    from oscprecon import findings as findings_mod
    from oscprecon.modules.http.parsers import interesting_path_reason

    rows = findings_mod.load_findings(_profile_dir(profile, workspace))
    if service is not None:
        rows = [r for r in rows if str(r.get("module", "")) == service]
    if not rows:
        typer.echo("[findings] none recorded yet.")
        raise typer.Exit(0)
    for r in rows:
        mod = str(r.get("module", "?"))
        head = str(r.get("kind") or r.get("path") or "").strip()
        val = str(r.get("value") or r.get("status") or "").strip()
        detail = str(r.get("detail") or r.get("note") or "").replace("\n", " ").strip()
        # parity with the GUI FindingsView / DiscoveredUrlsPanel: show the severity category + a
        # notable mark, and flag a source/backup/VCS disclosure or upload dir (was CLI-silent).
        category = finding_severity.category_of(r)
        mark = "‼" if finding_severity.is_notable(category) else " "
        reason = interesting_path_reason(str(r.get("path", ""))) if r.get("path") else ""
        warn = f"   ⚠ {reason}" if reason else ""
        # your own findings are marked ✎ and carry their id, so you can edit/delete them headlessly
        if r.get("manual"):
            where = ":".join(str(r.get(k, "")) for k in ("host", "port") if str(r.get(k, "")))
            bits = f" ({where})" if where else ""
            typer.echo(f"{mark} ✎[{category}][{mod}] {head} {val}{bits}  {detail}".rstrip())
            if r.get("poc"):
                for line in str(r["poc"]).splitlines():
                    typer.echo(f"      | {line}")
            typer.echo(f"      id: {r.get('id', '')}")
            continue
        typer.echo(f"{mark} [{category}][{mod}] {head} {val}  {detail}{warn}".rstrip())


@app.command("add-finding")
def add_finding_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    value: str = typer.Argument("", help="What you found, in one line (not needed with --delete)."),
    kind: str = typer.Option("note", "--kind", "-k", help="vuln | credential | foothold | note …"),
    severity: str = typer.Option(
        "info",
        "--severity",
        "-s",
        help="info | reference | access | exposure | relay-risk | vulnerable (how you judge it).",
    ),
    host: str | None = typer.Option(None, "--host", help="Host / source IP it was found on."),
    port: int | None = typer.Option(None, "--port", help="Port it was found on."),
    module: str = typer.Option("manual", "--module", "-m", help="Service it belongs under."),
    detail: str = typer.Option("", "--note", "-n", help="Notes / context."),
    poc: str = typer.Option("", "--poc", help="How to reproduce it (use $'…\\n…' for lines)."),
    reference: str = typer.Option("", "--reference", help="A URL to read later."),
    delete: str | None = typer.Option(
        None, "--delete", help="Delete one of YOUR findings by id (see `findings`) instead."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Record a finding YOU made — the thing no parser can see (GUI: Edit → Add Finding).

    It lands in the same `findings.json` as parsed findings, so it shows up in the Findings view,
    the graph and `report.md` (with its PoC in a fenced block) — marked as yours, and editable or
    deletable later.

    **Examples:**

    ```
    nabu-cli add-finding -p box "SQLi in /search.php?q=" -k vuln -s exposure --port 80 \\
        --poc "curl 'http://10.10.10.5/search.php?q=1%27+OR+1=1--'"
    nabu-cli add-finding -p box "creds in backup.zip" -k credential --host 10.10.10.5
    nabu-cli findings -p box                       # list them (yours are marked ✎ with an id)
    nabu-cli add-finding -p box --delete 9f2c1a4b7d3e       # remove one of yours
    ```
    """
    from oscprecon import finding_severity
    from oscprecon import findings as findings_mod

    directory = _profile_dir(profile, workspace)
    if delete:
        if findings_mod.delete_manual_finding(directory, delete):
            _audit(directory, profile, "finding-deleted", finding_id=delete)
            typer.echo(f"[finding] deleted {delete}")
            raise typer.Exit(0)
        typer.echo(f"[error] no finding of yours with id '{delete}'", err=True)
        raise typer.Exit(2)
    if not value.strip():
        typer.echo(
            "[error] describe the finding in one line, e.g. "
            '`nabu-cli add-finding -p box "SQLi in /search.php"` (or use --delete ID).',
            err=True,
        )
        raise typer.Exit(2)
    if severity not in finding_severity.ALL_CATEGORIES:
        typer.echo(
            f"[error] unknown --severity '{severity}'; choose one of "
            f"{', '.join(finding_severity.ALL_CATEGORIES)}.",
            err=True,
        )
        raise typer.Exit(2)
    entry: dict[str, Any] = {
        "module": module,
        "kind": kind,
        "value": value,
        "detail": detail,
        "severity": severity,
        "poc": poc,
        "reference": reference,
    }
    if host:
        entry["host"] = host
    if port is not None:
        entry["port"] = port
    saved = findings_mod.add_manual_finding(directory, entry)
    _audit(
        directory,
        profile,
        "finding-added",
        finding_id=str(saved["id"]),
        module=module,
        kind=kind,
        severity=severity,
        host=host or "",
        port=port if port is not None else "",
    )
    typer.echo(f"[finding] added {saved['id']} — {value}")


@app.command("health")
def health_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    repair: bool = typer.Option(
        False, "--repair", help="Fix the repairable issues (creds perms, stale temp)."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Check a profile's health (creds perms, stale temp, lock/schema) — optionally repair it."""
    from oscprecon.workspace import health as health_mod

    root = workspace if workspace is not None else config.workspace_root()
    directory = _profile_dir(profile, workspace)
    issues = health_mod.check_profile(directory, workspace_root=Path(root))
    if not issues:
        typer.echo("[health] no issues — profile is clean.")
        raise typer.Exit(0)
    for issue in issues:
        mark = {"error": "!!", "warning": " !", "info": "  "}.get(issue.severity, "  ")
        typer.echo(f"{mark} [{issue.severity}] {issue.code}: {issue.message}")
    if repair:
        fixed = health_mod.repair_creds_permissions(directory)
        removed = health_mod.repair_remove_stale_temp(directory)
        # the same slug workspace.bulk records for a GUI repair — only --repair writes; a plain
        # health check reads and stays out of the trail.
        _audit(directory, profile, "repair", creds_perms=fixed, removed=len(removed))
        typer.echo(
            f"[health] repaired: creds perms {'set' if fixed else 'ok'}; "
            f"removed {len(removed)} stale temp file(s)."
        )


@app.command("activity")
def activity_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    limit: int = typer.Option(50, "--limit", "-n", help="Most-recent N events."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Print the profile's audit-trail timeline (audit.jsonl) — the Activity view, headless."""
    from oscprecon.workspace import activity as activity_mod

    directory = _profile_dir(profile, workspace)
    events, malformed = activity_mod.load_activity(directory, limit=limit)
    total = activity_mod.count_activity(directory)
    if not events:
        typer.echo("[activity] no recorded activity.")
        raise typer.Exit(0)
    for event in events:
        typer.echo(f"  {event.timestamp}  {event.event_type:16} {event.description}")
    if total > len(events):
        typer.echo(f"  … {total - len(events)} older event(s) not shown (raise --limit).")
    if malformed:
        typer.echo(f"  ⚠ {malformed} unreadable audit line(s) skipped.")


@app.command("delete-project")
def delete_project_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Permanently delete a project folder (lock-safe). Destructive — asks first unless --yes."""
    from oscprecon.workspace import locks, portability

    root = workspace if workspace is not None else config.workspace_root()
    directory = _profile_dir(profile, workspace)
    # "lock-safe" has to mean it: a project open for edit in a running Nabu window must not be
    # deleted out from under it (§6b). The GUI already refuses this; the CLI silently did not.
    info, _malformed = locks.read_lock(directory)
    if info is not None and not locks.is_stale(info) and not locks.is_ours(info):
        typer.echo(
            f"[error] '{profile}' is open in another Nabu window (pid {info.pid}) — close it "
            "first, or the running window would keep writing into a deleted folder.",
            err=True,
        )
        raise typer.Exit(2)
    if not yes and not typer.confirm(f"Permanently delete {directory}? This cannot be undone."):
        typer.echo("[delete] cancelled.")
        raise typer.Exit(0)
    # recorded BEFORE the folder goes: it vanishes with a successful delete, but survives (and
    # explains the half-deleted state) when portability.delete_project refuses or fails.
    _audit(directory, profile, "project-deleted", dest=str(directory))
    try:
        portability.delete_project(directory, Path(root))
    except portability.ProjectArchiveError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"[deleted] {directory}")


@app.command("searchsploit")
def searchsploit_cmd(
    product: str = typer.Argument(..., help="Product name, e.g. 'vsftpd' or 'apache'."),
    version: str = typer.Argument("", help="Optional version, e.g. '2.4.49'."),
) -> None:
    """Version-aware Exploit-DB lookup (display-only — never downloads or runs a PoC, §14).

    **Examples:**

    ```
    nabu-cli searchsploit vsftpd 2.3.4      # product + version (version hits are starred)
    nabu-cli searchsploit "apache 2.4.49"   # quote a product that has spaces
    nabu-cli searchsploit tomcat            # product-wide when no version is given
    ```
    """
    import tempfile

    from oscprecon import references

    with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
        result = references.search_exploits(product, version, Path(tmp.name))
    if not result.hits:
        typer.echo(f"[searchsploit] no hits for '{product} {version}'.".rstrip())
        raise typer.Exit(0)
    scope = {"version": "version-specific", "product": "product-wide (version had no title match)"}
    typer.echo(
        f"# {result.query}  —  {scope.get(result.scope, result.scope)}  ({result.total} total)\n"
    )
    for hit in result.hits:
        star = "★ " if hit.version_match else "  "
        badge = f"[{hit.type or '?'}/{hit.platform or '?'}]"
        typer.echo(f"{star}EDB-{hit.edb_id:7} {badge:20} {hit.title}")
        typer.echo(f"     {hit.url}")


@app.command("hosts")
def hosts_cmd(
    ip: str | None = typer.Argument(
        None, help="IP to map. Omit and pass --profile to add ALL discovered hosts at once."
    ),
    names: list[str] | None = typer.Argument(
        None, help="Hostnames/vhosts to map to IP, e.g. research.bedside.htb admin.bedside.htb"
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help="Add EVERY hostname discovered in this profile (subdomains, vhosts, AD/DC names) to "
        "/etc/hosts in one go — no more hand-editing.",
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
    hosts_file: Path = typer.Option(
        Path("/etc/hosts"), "--file", help="hosts file to edit (default /etc/hosts)."
    ),
) -> None:
    """Add discovered vhosts/hostnames to /etc/hosts so they resolve (idempotent).

    Two ways: give an IP + hostname(s) explicitly, or `-p PROFILE` to auto-add EVERYTHING recon
    discovered (target hostname, vhosts, AD/DC names, pivot hosts). Needs root to write /etc/hosts —
    if it can't, it prints the exact sudo command instead.

    **Examples:**

    ```
    nabu-cli hosts 10.10.10.5 research.bedside.htb          # add one mapping
    nabu-cli hosts 10.10.10.5 dc01.corp.local corp.local    # several names -> one IP
    sudo nabu-cli hosts 10.10.10.5 research.bedside.htb      # write /etc/hosts directly (root)
    nabu-cli hosts -p box                                    # add ALL discovered hosts for 'box'
    ```
    """
    from oscprecon import hosts as hosts_mod

    # bulk mode: collect every discovered (ip, hostname) from the profile and add them all.
    if profile is not None and not ip:
        prof = _load_profile(profile, workspace)
        cands = hosts_mod.collect_profile_hosts(prof)
        if not cands:
            typer.echo("[hosts] no discovered hostnames yet — scan/enum the box first.")
            raise typer.Exit(0)
        typer.echo(f"[hosts] {len(cands)} discovered host(s) for '{profile}':")
        for c in cands:
            typer.echo(f"    {c.ip}\t{c.hostname}   ({c.source})")
        entries = [(c.ip, c.hostname) for c in cands]
        try:
            results = hosts_mod.add_many(entries, hosts_file)
        except OSError:
            cmd = hosts_mod.sudo_append_many(entries)
            typer.echo(
                f"\n[hosts] can't write {hosts_file} (need root). Add them all with:\n  {cmd}",
                err=True,
            )
            raise typer.Exit(1) from None
        added = sum(1 for r in results if r.changed)
        _audit_profile(
            prof,
            "add-hosts-entry",
            names=" ".join(f"{c.ip}={c.hostname}" for c in cands),
            added=added,
            file=str(hosts_file),
        )
        typer.echo(f"[hosts] {added} new mapping(s) written to {hosts_file} ({len(cands)} total).")
        return

    if not ip or not names:
        typer.echo(
            "[error] give an IP and hostname(s), or `-p PROFILE` to add discovered hosts.", err=True
        )
        raise typer.Exit(2)

    # resolve the audit target BEFORE touching /etc/hosts, for the same reason as `config`: a bad
    # -p must fail before the system file is edited, not after. [review]
    _hosts_audit_dir = _profile_dir(profile, workspace) if profile is not None else None
    try:
        result = hosts_mod.add_entry(ip, names, hosts_file)
    except ValueError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    except OSError:
        cmd = hosts_mod.sudo_append_command(ip, names)
        typer.echo(
            f"[hosts] can't write {hosts_file} (need root). Run this instead:\n  {cmd}", err=True
        )
        raise typer.Exit(1) from None
    if profile is not None and _hosts_audit_dir is not None:
        # only a project carries an audit trail — a bare `hosts IP NAME` edits /etc/hosts with no
        # project context, so there is nothing to record it against.
        _audit(
            _hosts_audit_dir,
            profile,
            "add-hosts-entry",
            ip=ip,
            names=" ".join(names),
            file=str(hosts_file),
        )
    typer.echo(f"[hosts] {result.message}")


creds_app = typer.Typer(help="Manage the profile credential vault (creds.json, chmod 600).")
app.add_typer(creds_app, name="creds")


@creds_app.command("list")
def creds_list_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """List stored credentials — shown in FULL, exactly like the GUI vault (CLAUDE.md §6).

    Your own loot against your own authorized targets is the deliverable, so nothing is masked. Set
    `redact_secrets` in Preferences if you ever need the masked form.
    """
    from oscprecon.creds import redact

    prof = _load_profile(profile, workspace)
    entries = prof.credentials()
    if not entries:
        typer.echo("[creds] none stored.")
        raise typer.Exit(0)
    for c in entries:
        who = f"{c.domain}\\{c.username}" if c.domain else c.username
        # redact() honours the redact_secrets preference and is a no-op by default — so this stays
        # the SAME text the GUI vault shows, instead of the CLI unilaterally hiding it.
        typer.echo(f"  {who:32} {redact(c.secret):32} {c.secret_type:9} {c.source}")


@creds_app.command("add")
def creds_add_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    username: str = typer.Option(..., "--user", "-u", help="Username."),
    secret: str = typer.Option(..., "--secret", "-s", help="Password or hash."),
    secret_type: str = typer.Option("password", "--type", help="password | hash."),
    domain: str = typer.Option("", "--domain", "-d", help="Domain (optional)."),
    source: str = typer.Option("cli", "--source", help="Where it came from."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Record a credential in the vault (creds.json is written chmod 600)."""
    from oscprecon.models import Credential

    prof = _load_profile(profile, workspace)
    prof.add_credential(
        Credential(
            username=username, secret=secret, secret_type=secret_type, domain=domain, source=source
        )
    )
    # §6a — the GUI logs a credential's field names + source. The secret VALUE is deliberately not
    # a detail: audit.record would carry it in full under the owner's no-redaction posture.
    _audit_profile(
        prof,
        "credential-added",
        username=username,
        domain=domain,
        secret_type=secret_type,
        source=source,
    )
    typer.echo(f"[creds] stored {domain + chr(92) if domain else ''}{username} ({secret_type}).")


@creds_app.command("rm")
def creds_rm_cmd(
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    username: str = typer.Option(..., "--user", "-u", help="Username to remove."),
    domain: str = typer.Option("", "--domain", "-d", help="Domain (to disambiguate)."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Delete a credential from the vault by username (+ optional domain)."""
    prof = _load_profile(profile, workspace)
    matches = [
        c
        for c in prof.credentials()
        if c.username == username and (not domain or c.domain == domain)
    ]
    if not matches:
        typer.echo(f"[creds] no credential for '{username}'.", err=True)
        raise typer.Exit(1)
    for c in matches:
        prof.delete_credential(c)
    _audit_profile(prof, "credential-deleted", username=username, domain=domain, count=len(matches))
    typer.echo(f"[creds] removed {len(matches)} credential(s) for '{username}'.")


@app.command("config")
def config_cmd(
    spray: bool | None = typer.Option(
        None, "--spray/--no-spray", help="Enable/disable Spray mode (§2a)."
    ),
    exploit: bool | None = typer.Option(
        None, "--exploit/--no-exploit", help="Enable/disable exploit execution (§2b)."
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help="Record the toggle in this project's audit trail (§6a). The setting itself is "
        "app-wide either way.",
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Show or toggle the opt-in mode gates (Spray mode / Exploit execution). No arg = show."""
    from dataclasses import replace

    settings = config.load_settings()
    if spray is None and exploit is None:
        typer.echo(f"spray_enabled   = {settings.spray_enabled}")
        typer.echo(f"exploit_enabled = {settings.exploit_enabled}")
        raise typer.Exit(0)
    updated = replace(
        settings,
        spray_enabled=settings.spray_enabled if spray is None else spray,
        exploit_enabled=settings.exploit_enabled if exploit is None else exploit,
    )
    # resolve the audit target BEFORE changing anything: _profile_dir exits 2 on an unknown name,
    # and doing it after the save flipped the gate while telling the operator the command failed.
    # §2a's premise is that Spray mode is an opt-in you know the state of. [review]
    audit_dir = _profile_dir(profile, workspace) if profile is not None else None
    config.save_settings(updated)
    if profile is not None and audit_dir is not None:
        # the gates are app-wide, so there is no project to own the change unless you name one —
        # exam-day matters which box you flipped Spray mode for, hence the opt-in -p.
        _audit(
            audit_dir,
            profile,
            "settings-changed",
            spray_enabled=updated.spray_enabled,
            exploit_enabled=updated.exploit_enabled,
        )
    typer.echo(
        f"[config] spray_enabled={updated.spray_enabled} exploit_enabled={updated.exploit_enabled}"
    )


@app.command("spray")
def spray_cmd(
    service: str = typer.Argument(..., help="Service key: smb | winrm | ldap | ssh | ftp | rdp."),
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    port: int = typer.Option(0, "--port", help="Override the discovered port (0 = tool default)."),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Password-spray a service using the vault creds (opt-in Spray mode, §2a — OFF by default)."""
    from oscprecon import spray as spray_mod

    if not config.spray_enabled():
        typer.echo(
            "[error] Spray mode is OFF (exam-legal default). Enable it with "
            "`nabu-cli config --spray`, then re-run. Only spray your own authorized target.",
            err=True,
        )
        raise typer.Exit(2)
    prof = _load_profile(profile, workspace)
    users, passwords = spray_mod.vault_material(prof.credentials())
    if not users or not passwords:
        typer.echo(
            "[error] the vault has no usernames/passwords to spray — add some with `creds add`.",
            err=True,
        )
        raise typer.Exit(2)
    try:
        user_file, pass_file = spray_mod.write_spray_lists(prof.directory, users, passwords)
        command = spray_mod.build_spray_command(
            service, prof.target.ip, user_file, pass_file, port or None
        )
        typer.echo(f"[spray] {command}")
        # same slug + details the GUI spray controller writes — service + target, never the material
        _audit_profile(prof, "credential-spray", service=service, target=prof.target.ip)
        redactor = spray_mod.make_redactor(passwords)
        out = prof.directory / f"spray/{service}.txt"
        spray_mod.secure_output_file(
            out
        )  # 0600 — the spray log holds the winning cred in cleartext
        spray_label = f"spray:{service}"
        _audit_profile(prof, "run", label=spray_label, lane=_TOOL_LANE, module="spray")
        try:
            shell.run(
                command,
                out,
                cwd=prof.directory,
                spray=True,
                on_line=lambda line: typer.echo(redactor(line)),
            )
        finally:
            _audit_profile(prof, "run-finished", label=spray_label)
    except ValueError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    finally:
        spray_mod.clean_spray_artifacts(prof.directory)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
