from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon import shell
from oscprecon.gui import main_window as mw
from oscprecon.gui.widgets.smb_panel import _COMMAND_ROLE, SmbPanel
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "smb"


def _smb_ref() -> ServiceRef:
    return ServiceRef(label="SMB", hacktricks="https://x", module="smb", tools=[])


def test_recon_buttons_emit_modes(qtbot: QtBot) -> None:
    panel = SmbPanel()
    qtbot.addWidget(panel)
    captured: list[str] = []
    panel.recon_requested.connect(captured.append)
    panel._full.click()
    panel._null.click()
    panel._guest.click()
    panel._shares.click()
    assert captured == ["full", "null", "guest", "shares"]


def test_manual_followups_expand_and_stay_legal(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5", hostname="active.htb"))
    panel = SmbPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    assert panel._manual.count() > 0
    commands = [panel._manual.item(i).data(_COMMAND_ROLE) for i in range(panel._manual.count())]
    joined = " ".join(commands)
    assert "10.10.10.5" in joined  # target expanded
    # §11: only Tier-2 single-cred/enum follow-ups — never Tier-3 spray or credential dumping
    assert "--passwords" not in joined
    assert "-P " not in joined
    assert "rockyou" not in joined
    assert "secretsdump" not in joined


def test_manual_double_click_emits_command(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = SmbPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    captured: list[str] = []
    panel.manual_requested.connect(captured.append)
    item = panel._manual.item(0)
    panel._on_manual_activated(item)
    assert captured and captured[0] == item.data(_COMMAND_ROLE)


def test_summary_populates(qtbot: QtBot) -> None:
    panel = SmbPanel()
    qtbot.addWidget(panel)
    panel.set_summary(["SMB signing: disabled", "Shares (2):", "  Replication [READ]"])
    assert panel._summary.count() == 3
    panel.set_summary(["fresh"])
    assert panel._summary.count() == 1  # cleared between updates


def test_running_disables_recon_buttons(qtbot: QtBot) -> None:
    panel = SmbPanel()
    qtbot.addWidget(panel)
    panel.set_running(True)
    assert not panel._full.isEnabled()
    panel.set_running(False)
    assert panel._full.isEnabled()


def test_tool_panel_switches_to_smb_page(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_target("10.10.10.5")
    panel.set_profile(prof)
    panel.show_service(DiscoveredService(445, Proto.TCP, "microsoft-ds"), _smb_ref())
    assert panel._stack.currentWidget() is panel._smb
    panel.set_smb_summary(["Shares (1):"])
    assert panel._smb._summary.count() == 1


def test_tool_panel_forwards_smb_signals(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    modes: list[str] = []
    manual: list[str] = []
    panel.smb_recon_requested.connect(modes.append)
    panel.run_requested.connect(manual.append)  # Tier-2 follow-ups reuse the ad-hoc path
    panel._smb._full.click()
    panel._smb._on_manual_activated(panel._smb._manual.item(0))
    assert modes == ["full"]
    assert manual and "10.10.10.5" in manual[0]


def _fake_run_factory() -> object:
    shares = (_FIXTURES / "netexec-shares.txt").read_text(encoding="utf-8")
    users = (_FIXTURES / "netexec-users.txt").read_text(encoding="utf-8")

    def fake_run(
        shell_line: str,
        output_file: Path,
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        on_line: object | None = None,
    ) -> object:
        if "--shares" in shell_line and "-u '' " in shell_line:
            text = shares  # null session authenticates
        elif "--shares" in shell_line and "guest" in shell_line:
            text = "SMB 10.10.10.5 445 DC01 [-] active.htb\\guest: STATUS_ACCESS_DENIED"
        elif "--users" in shell_line:
            text = users
        else:
            text = ""
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    return fake_run


def test_smb_recon_worker_full_drive(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5", hostname="active.htb"))
    monkeypatch.setattr(shell, "run", _fake_run_factory())

    worker = mw.SmbReconWorker(prof, "full")
    result = worker._drive()

    assert any("null session OK" in line for line in result.summary)
    assert result.creds and result.creds[0].username == "anonymous"
    assert result.creds[0].source == "smb-anon-enum"
    # readable share surfaced in the summary
    assert any("Replication" in line for line in result.summary)
    # users only appear because the null session authenticated and followups ran
    assert any("svc_tgs" in line for line in result.summary)
    # findings persisted to the graph store
    stored = findings_mod.load_findings(prof.directory)
    assert any(f.get("kind") == "share" for f in stored)
    assert any(f.get("kind") == "user" for f in stored)


def test_smb_recon_worker_shares_mode_skips_followups(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    monkeypatch.setattr(shell, "run", _fake_run_factory())

    worker = mw.SmbReconWorker(prof, "shares")
    result = worker._drive()

    # shares enumerated, but no user enumeration (followups are skipped in shares mode)
    assert any("Replication" in line for line in result.summary)
    assert not any("svc_tgs" in line for line in result.summary)
