import pytest
from typer.testing import CliRunner

from oscprecon import cli
from oscprecon.cli import app
from oscprecon.shell import ALLOWED_TOOLS


def test_doctor_all_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "exam-ready" in result.output
    assert f"{len(ALLOWED_TOOLS)}/{len(ALLOWED_TOOLS)}" in result.output


def test_doctor_reports_missing_with_hints(monkeypatch: pytest.MonkeyPatch) -> None:
    # only nmap is installed; everything else is missing
    monkeypatch.setattr(
        cli.shutil, "which", lambda tool: "/usr/bin/nmap" if tool == "nmap" else None
    )
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "missing" in result.output
    # a newly-allowed binary shows up as missing with its install hint
    assert "impacket-mssqlclient" in result.output
    assert "ssh-audit" in result.output
    assert "redis-cli" in result.output
    # nmap (present) is not listed in the missing block
    missing_block = result.output.split("missing (install the ones you need):", 1)[1]
    assert "nmap " not in missing_block
