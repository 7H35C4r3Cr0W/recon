from __future__ import annotations

from pathlib import Path

import typer

from oscprecon import config, vault_export
from oscprecon.models import Target
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile

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
        typer.echo(f"[resume] {prof.directory} — {len(prof.command_history)} prior commands")
    else:
        prof = Profile.create(root, profile, target)
    config.add_recent(prof.directory)
    typer.echo(f"[profile] {prof.directory}")
    Orchestrator(
        prof,
        on_line=lambda line: typer.echo(line),
        udp_full=udp_full,
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
