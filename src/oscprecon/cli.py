from __future__ import annotations

from pathlib import Path

import typer

from oscprecon import config
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
    workspace: Path | None = typer.Option(None, help="Workspace root (default: ~/oscprecon)."),
) -> None:
    root = workspace if workspace is not None else config.workspace_root()
    try:
        target = Target(ip=ip, hostname=hostname)
    except ValueError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(2) from exc
    prof = Profile.create(root, profile, target)
    config.add_recent(prof.directory)
    typer.echo(f"[profile] {prof.directory}")
    Orchestrator(prof, on_line=lambda line: typer.echo(line), udp_full=udp_full).run_nmap()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
