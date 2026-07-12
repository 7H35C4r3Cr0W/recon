from collections.abc import Callable
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon import shell
from oscprecon.gui import main_window as mw
from oscprecon.gui.simple_recon import SIMPLE_SPECS
from oscprecon.gui.widgets.simple_recon_panel import _COMMAND_ROLE, SimpleReconPanel
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef

_FIX = Path(__file__).parent.parent / "fixtures"


def _ref(module: str) -> ServiceRef:
    return ServiceRef(label=module.upper(), hacktricks="https://x", module=module, tools=[])


def _fake_run(fixture_map: dict[str, str]) -> Callable[..., object]:
    def run(
        shell_line: str,
        output_file: Path,
        *,
        cwd: Path | None = None,
        timeout: object | None = None,
        cancel: object | None = None,
        on_line: object | None = None,
    ) -> object:
        text = ""
        for key, rel in fixture_map.items():
            if key in shell_line:
                text = (_FIX / rel).read_text(encoding="utf-8")
                break
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    return run


def test_ntp_worker_parses_and_writes_findings(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    monkeypatch.setattr(
        shell,
        "run",
        _fake_run({"ntpq -c readlist": "ntp/ntpq-readlist.txt", "ntpdate -q": "ntp/ntpdate.txt"}),
    )
    result = mw.SimpleReconWorker(prof, "ntp")._drive()
    assert result.module == "ntp"
    assert any(line.startswith("info (") for line in result.summary)
    assert any(line.startswith("→") for line in result.summary)  # a suggestion surfaced
    stored = findings_mod.load_findings(prof.directory)
    kinds = {f.get("kind") for f in stored}
    assert {"info", "stratum"} <= kinds


def test_netbios_worker_parses_and_writes_findings(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    monkeypatch.setattr(
        shell,
        "run",
        _fake_run({"nmblookup": "netbios/nmblookup-A.txt", "nbtscan": "netbios/nbtscan.txt"}),
    )
    result = mw.SimpleReconWorker(prof, "netbios")._drive()
    kinds = {f.get("kind") for f in findings_mod.load_findings(prof.directory)}
    assert {"hostname", "domain", "role"} <= kinds
    assert any("domain controller" in line.lower() for line in result.summary)


def test_mongodb_worker_parses_and_writes_findings(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.14"))
    monkeypatch.setattr(
        shell,
        "run",
        _fake_run(
            {
                "print(db.version())": "mongodb/version.txt",
                "print('DB '+n)": "mongodb/databases.txt",
                "print(n+'.'+c)": "mongodb/collections.txt",
            }
        ),
    )
    result = mw.SimpleReconWorker(prof, "mongodb")._drive()
    assert result.module == "mongodb"
    assert any(line.startswith("→") for line in result.summary)  # unauth suggestion surfaced
    kinds = {f.get("kind") for f in findings_mod.load_findings(prof.directory)}
    assert {"access", "version", "database", "collection"} <= kinds


def test_worker_empty_output_writes_nothing(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    monkeypatch.setattr(shell, "run", _fake_run({}))  # every command yields empty output
    result = mw.SimpleReconWorker(prof, "ike")._drive()
    assert result.summary == ["No IKE findings."]
    assert findings_mod.load_findings(prof.directory) == []


def test_tool_panel_switches_to_simple_panel(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_target("10.10.10.5")
    panel.set_profile(prof)
    panel.show_service(DiscoveredService(123, Proto.UDP, "ntp"), _ref("ntp"))
    assert panel._stack.currentWidget() is panel._simple["ntp"]
    panel.set_simple_summary("ntp", ["stratum (1): 3"])
    assert panel._simple["ntp"]._summary.count() == 1


def test_tool_panel_forwards_simple_signals(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.show_service(DiscoveredService(137, Proto.UDP, "netbios-ns"), _ref("netbios"))
    modules: list[str] = []
    manual: list[str] = []
    panel.simple_recon_requested.connect(modules.append)
    panel.run_requested.connect(manual.append)
    nb = panel._simple["netbios"]
    nb._recon.click()
    nb._on_manual_activated(nb._manual.item(0))
    assert modules == ["netbios"]
    assert manual and "10.10.10.5" in manual[0]


@pytest.mark.parametrize("module", list(SIMPLE_SPECS))
def test_simple_panel_manual_followups_stay_legal(
    qtbot: QtBot, tmp_path: Path, module: str
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    panel = SimpleReconPanel(SIMPLE_SPECS[module])
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    assert panel._manual.count() > 0
    commands = [panel._manual.item(i).data(_COMMAND_ROLE) for i in range(panel._manual.count())]
    joined = " ".join(commands)
    assert "10.10.10.5" in joined
    for banned in ("--passwords", "--pskcrack", "hydra", "medusa", "rockyou"):
        assert banned not in joined
