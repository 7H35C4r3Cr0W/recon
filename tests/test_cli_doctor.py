import pytest
from typer.testing import CliRunner

from oscprecon import doctor
from oscprecon.cli import app
from oscprecon.shell import ALLOWED_TOOLS


def test_doctor_all_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "exam-ready" in result.output
    assert f"{len(ALLOWED_TOOLS)}/{len(ALLOWED_TOOLS)}" in result.output


def test_doctor_reports_missing_with_hints(monkeypatch: pytest.MonkeyPatch) -> None:
    # only nmap is installed; everything else is missing
    monkeypatch.setattr(
        doctor.shutil, "which", lambda tool: "/usr/bin/nmap" if tool == "nmap" else None
    )
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "missing" in result.output
    assert "impacket-mssqlclient" in result.output
    assert "ssh-audit" in result.output
    assert "redis-cli" in result.output
    missing_block = result.output.split("missing (install the ones you need):", 1)[1]
    assert "nmap " not in missing_block
    assert "--install" in result.output  # points the user at the installer


def test_doctor_install_runs_curated_apt_command(monkeypatch: pytest.MonkeyPatch) -> None:
    # everything missing; --install --yes installs each curated package via its OWN apt-get call
    # (a single batched command would abort entirely if one package were unavailable).
    monkeypatch.setattr(doctor.shutil, "which", lambda tool: None)
    captured: list[list[str]] = []
    monkeypatch.setattr(doctor, "_default_runner", lambda argv: captured.append(argv) or 0)
    result = CliRunner().invoke(app, ["doctor", "--install", "--yes"])
    assert result.exit_code == 0
    assert captured  # ran at least one package
    assert all(argv[-3:-1] == ["install", "-y"] for argv in captured)  # one package per call
    installed = {argv[-1] for argv in captured}
    assert "nmap" in installed and "smbclient" in installed  # curated packages present
    assert "crackmapexec" not in installed  # deprecated alternative is not installed
    # a pipx/git tool is shown as manual, never in an apt argv
    assert "windapsearch-py" not in installed
    assert "install these manually" in result.output


def test_doctor_install_cancelled_without_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda tool: None)
    ran: list[list[str]] = []
    monkeypatch.setattr(doctor, "_default_runner", lambda argv: ran.append(argv) or 0)
    # answer "n" to the confirmation prompt → nothing runs, non-zero exit
    result = CliRunner().invoke(app, ["doctor", "--install"], input="n\n")
    assert ran == []  # runner never called
    assert result.exit_code == 1
    assert "cancelled" in result.output
