from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon import shell
from oscprecon.gui.widgets.ftp_panel import _COMMAND_ROLE, FtpPanel
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef
from oscprecon.service_enum import FtpEnum

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "ftp"


def _ftp_ref() -> ServiceRef:
    return ServiceRef(label="FTP", hacktricks="https://x", module="ftp", tools=[])


def test_recon_buttons_emit_mode_and_port(qtbot: QtBot) -> None:
    panel = FtpPanel()
    qtbot.addWidget(panel)
    panel.configure(DiscoveredService(2121, Proto.TCP, "ftp"))  # non-default port
    captured: list[tuple[str, int]] = []
    panel.recon_requested.connect(lambda mode, port: captured.append((mode, port)))
    panel._full.click()
    panel._anon.click()
    assert captured == [("full", 2121), ("anon", 2121)]


def test_manual_followups_expand_and_stay_legal(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = FtpPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    assert panel._manual.count() > 0
    commands = [panel._manual.item(i).data(_COMMAND_ROLE) for i in range(panel._manual.count())]
    joined = " ".join(commands)
    assert "10.10.10.5" in joined
    assert "--passwords" not in joined
    assert "rockyou" not in joined
    for tool in ("hydra", "medusa", "ncrack"):
        assert tool not in joined


def test_manual_followups_honor_non_default_port(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = FtpPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.configure(DiscoveredService(2121, Proto.TCP, "ftp"))
    commands = [panel._manual.item(i).data(_COMMAND_ROLE) for i in range(panel._manual.count())]
    joined = " ".join(commands)
    assert "10.10.10.5:2121" in joined  # the port reaches every follow-up
    assert "ftp:ftp@10.10.10.5:2121" in joined
    assert "ftp://10.10.10.5/" not in joined  # no bare :21 URL slipped through


def test_tool_panel_switches_to_ftp_page(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_target("10.10.10.5")
    panel.set_profile(prof)
    panel.show_service(DiscoveredService(21, Proto.TCP, "ftp"), _ftp_ref())
    assert panel._stack.currentWidget() is panel._ftp
    panel.set_ftp_summary(["Anonymous access: allowed"])
    assert panel._ftp._summary.count() == 1


def test_tool_panel_forwards_ftp_signals(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.show_service(DiscoveredService(21, Proto.TCP, "ftp"), _ftp_ref())
    modes: list[tuple[str, int]] = []
    manual: list[str] = []
    panel.ftp_recon_requested.connect(lambda mode, port: modes.append((mode, port)))
    panel.run_requested.connect(manual.append)
    panel._ftp._full.click()
    panel._ftp._on_manual_activated(panel._ftp._manual.item(0))
    assert modes == [("full", 21)]
    assert manual and "10.10.10.5" in manual[0]


def _fake_run_factory() -> object:
    nmap = (_FIXTURES / "nmap-ftp.txt").read_text(encoding="utf-8")
    root = (_FIXTURES / "curl-list-unix.txt").read_text(encoding="utf-8")

    def fake_run(
        shell_line: str,
        output_file: Path,
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        cancel: object | None = None,
        on_line: object | None = None,
    ) -> object:
        if shell_line.startswith("nmap"):
            text = nmap
        elif "/backups/" in shell_line:
            text = "-rw-r--r--    1 0        0             200 Jun 20  2023 db.sql\n"
        elif shell_line.endswith("10.10.10.5/"):  # anonymous root listing
            text = root
        else:
            text = ""  # New Folder / anything deeper is empty
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    return fake_run


def test_ftp_worker_full_walk_recurses(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    monkeypatch.setattr(shell, "run", _fake_run_factory())

    engine = FtpEnum(prof, "full", 21)
    result = engine.run()

    assert result.creds and result.creds[0].username == "anonymous"
    assert result.creds[0].source == "ftp-anon-enum"
    assert any("Banner: vsftpd 3.0.3" in line for line in result.summary)
    assert any("/backups" in line for line in result.summary)
    # recursion: /backups was listed and its file surfaced
    stored = findings_mod.load_findings(prof.directory)
    values = {f.get("value") for f in stored}
    assert "/backups/db.sql" in values
    assert any("allowed" in line for line in result.summary)


def test_ftp_worker_anon_mode_does_not_recurse(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    monkeypatch.setattr(shell, "run", _fake_run_factory())

    engine = FtpEnum(prof, "anon", 21)
    engine.run()

    values = {f.get("value") for f in findings_mod.load_findings(prof.directory)}
    assert "/backups" in values  # root listing captured
    assert "/backups/db.sql" not in values  # but no recursion in anon mode
