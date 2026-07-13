from __future__ import annotations

from pathlib import Path

import typer

from oscprecon import config, doctor as doctor_mod, vault_export
from oscprecon.models import Target
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile
from oscprecon.workspace import portability

app = typer.Typer(
    help="oscprecon headless CLI — recon-only, OSCP exam-legal.",
    add_completion=False,
)


@app.callback()
def _root() -> None:
    # why: a callback keeps `scan` an explicit subcommand — Typer otherwise collapses a
    # single-command app and drops the subcommand name (`oscprecon-cli scan <ip>` would break).
    pass


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
    """Check each wrapped tool; print install hints, and with --install offer to apt-install them."""
    report = doctor_mod.scan()
    total = len(report.tools)
    missing = report.missing
    typer.echo(f"[doctor] {total - len(missing)}/{total} wrapped tools found on PATH")
    if not missing:
        typer.echo("[doctor] all wrapped tools present — exam-ready.")
        return
    typer.echo(f"[doctor] {len(missing)} missing (install the ones you need):")
    for tool in missing:
        typer.echo(f"  {tool.name:24}  {tool.hint}")
    # why: alternatives cover the same capability — don't alarm the user about skipping them.
    typer.echo(
        "\nNote: alternatives are fine to skip — netexec covers nxc/crackmapexec, and "
        "GetX.py covers impacket-GetX.py (and vice-versa)."
    )
    if not install:
        typer.echo("\nRe-run `doctor --install` to apt-install them (asks before running anything).")
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
