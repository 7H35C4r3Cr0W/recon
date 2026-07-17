from __future__ import annotations

import sys
from pathlib import Path

import typer

from oscprecon import branding, config, diagnostics, guide, vault_export
from oscprecon import doctor as doctor_mod
from oscprecon.models import Target
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile
from oscprecon.workspace import portability

app = typer.Typer(
    help="Nabu — headless recon CLI (recon-only, OSCP exam-legal).",
    add_completion=False,
)


@app.callback()
def _root() -> None:
    # why: a callback keeps `scan` an explicit subcommand — Typer otherwise collapses a
    # single-command app and drops the subcommand name (`oscprecon-cli scan <ip>` would break).
    diagnostics.install("cli")  # capture uncaught crashes to the log; best-effort, never blocks
    # cosmetic owl-furby banner — stderr + TTY only, so it never pollutes piped stdout or tests
    if sys.stderr.isatty():
        sys.stderr.write("\n" + branding.cli_banner() + "\n")


@app.command()
def scan(
    ip: str = typer.Argument(..., help="Target IP or hostname."),
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    hostname: str | None = typer.Option(None, help="Optional hostname for the target."),
    scan_profile: str | None = typer.Option(
        None,
        "--scan-profile",
        help="nmap battery: quick | default | full | exam (default: the configured preference).",
    ),
    udp_full: bool = typer.Option(False, "--udp-full", help="Also run the slow full UDP sweep."),
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
    # why: --resume must LOAD the prior profile so its command_history survives — Profile.create
    # would overwrite profile.json and erase every record of what already finished.
    if resume and (directory / "profile.json").exists():
        prof = Profile.load(directory)
        # why: on resume the loaded profile's stored target is authoritative (run_nmap scans it),
        # so a differing CLI ip would be silently ignored — scanning the wrong host. Refuse the
        # mismatch rather than guess; the user opens the right profile or creates a new one.
        if prof.target.ip != ip:
            typer.echo(
                f"[error] --resume target mismatch: profile '{profile}' targets {prof.target.ip}, "
                f"but you gave {ip}. Use the matching IP, or drop --resume to start a new scan.",
                err=True,
            )
            raise typer.Exit(2)
        typer.echo(f"[resume] {prof.directory} — {len(prof.command_history)} prior commands")
    else:
        prof = Profile.create(root, profile, target)
    config.add_recent(prof.directory)
    typer.echo(f"[profile] {prof.directory}  (scan profile: {profile_choice})")
    Orchestrator(
        prof,
        on_line=lambda line: typer.echo(line),
        udp_full=udp_full,
        scan_profile=profile_choice,
        resume=resume,
        force=force,
    ).run_nmap()


@app.command("export-vault")
def export_vault_cmd(
    dest: Path = typer.Argument(..., help="Destination folder (an Obsidian vault or any dir)."),
    profile: str = typer.Option(
        ..., "--profile", "-p", help="Profile name (folder under workspace)."
    ),
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    root = workspace if workspace is not None else config.workspace_root()
    directory = Path(root) / profile
    if not (directory / "profile.json").exists():
        typer.echo(f"[error] no profile at {directory}", err=True)
        raise typer.Exit(2)
    out = vault_export.export_vault(Profile.load(directory), dest)
    typer.echo(f"[exported] {out} (snapshot — creds.json values redacted)")


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
    typer.echo(f"[imported] {dest}")


@app.command()
def doctor(
    install: bool = typer.Option(
        False, "--install", help="Offer to apt-install the missing allow-listed tools (asks first)."
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the confirmation prompt (non-interactive install)."
    ),
) -> None:
    """Check each wrapped tool; print install hints, optionally apt-install the missing ones."""
    report = doctor_mod.scan()
    required = report.required
    req_missing = [tool for tool in required if not tool.present]
    opt_missing = [tool for tool in report.optional if not tool.present]
    typer.echo(
        f"[doctor] {len(required) - len(req_missing)}/{len(required)} wrapped tools found on PATH"
    )
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
    if opt_missing:
        typer.echo("\n[doctor] Spray-mode tools (only needed if you enable Spray mode, §2a):")
        for tool in opt_missing:
            typer.echo(f"  {tool.name:24}  {tool.hint}")
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
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    """Show exploitation command templates (§2b). CLI is display-only — copy a command to run it."""
    from oscprecon import exploit as exploit_mod

    values: dict[str, str] = {}
    if profile is not None:
        root = workspace if workspace is not None else config.workspace_root()
        directory = Path(root) / profile
        if not (directory / "profile.json").exists():
            typer.echo(f"[error] no profile '{profile}' in {root}", err=True)
            raise typer.Exit(2)
        prof = Profile.load(directory)
        values["target"] = prof.target.ip
        values["dc"] = prof.target.ip
        values["url"] = f"http://{prof.target.host}/"
        if prof.target.hostname and "." in prof.target.hostname:
            values["domain"] = prof.target.hostname.split(".", 1)[1]
        creds = prof.credentials()
        pw = next((c for c in creds if c.secret_type == "password"), None)
        if pw is not None:
            values["user"] = pw.username
            values["password"] = pw.secret
            if pw.domain:
                values["domain"] = pw.domain

    if service is None:
        typer.echo("Exploitation services (use `nabu-cli exploit <service>` for actions):\n")
        for key in exploit_mod.service_keys():
            spec = exploit_mod.service_exploits(key)
            if spec is None:
                continue
            ports = ", ".join(str(p) for p in spec.ports) or "—"
            typer.echo(f"  {key:9} {spec.label:22} {len(spec.actions):3} actions   ports: {ports}")
        raise typer.Exit(0)

    spec = exploit_mod.service_exploits(service)
    if spec is None:
        typer.echo(f"[error] unknown service '{service}'", err=True)
        raise typer.Exit(2)
    typer.echo(f"# {spec.label} — {spec.note}\n")
    for category in spec.categories():
        typer.echo(f"── {category} ──")
        for action in spec.by_category(category):
            tag = "RUN " if action.executable else "COPY"  # attacker (run) vs victim (copy)
            typer.echo(f"[{tag}] {action.title}  ({action.tool})")
            typer.echo(f"    {exploit_mod.fill_template(action.template, values)}")
        typer.echo("")
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
    """Build an msfvenom reverse-shell payload + its listener (display-only — copy and run it)."""
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
