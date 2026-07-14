from __future__ import annotations

from typer.testing import CliRunner

from oscprecon import branding
from oscprecon.cli import app

runner = CliRunner()


def test_cli_banner_content() -> None:
    banner = branding.cli_banner()
    assert "Nabu" in banner
    assert "{o,o}" in banner  # the owl-furby face
    assert branding.app_version() in banner


def test_banner_never_leaks_into_output() -> None:
    # the banner is stderr + TTY-only; under CliRunner (not a TTY) it must never appear, so piped
    # output and tests stay clean.
    result = runner.invoke(app, ["doctor"])
    assert "{o,o}" not in result.output
    assert "recon-only by default · OSCP exam-legal" not in result.output


def test_cli_still_runs_with_the_callback() -> None:
    # sanity: the _root() callback (which installs diagnostics + the banner guard) doesn't break a
    # normal subcommand invocation.
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code in (0, 1)  # 0 all present, 1 not applicable; never a crash
    assert "[doctor]" in result.output
