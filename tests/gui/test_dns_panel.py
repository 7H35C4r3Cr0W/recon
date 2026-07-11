from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon import shell
from oscprecon.gui import main_window as mw
from oscprecon.gui.widgets.dns_panel import _COMMAND_ROLE, DnsPanel
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "dns"


def _dns_ref() -> ServiceRef:
    return ServiceRef(label="DNS", hacktricks="https://x", module="dns", tools=[])


def _profile(tmp_path: Path) -> Profile:
    return Profile.create(tmp_path, "b", Target(ip="10.10.10.5", hostname="example.htb"))


def test_recon_button_emits_domain_and_port(qtbot: QtBot, tmp_path: Path) -> None:
    panel = DnsPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))  # seeds domain from hostname
    panel.configure(DiscoveredService(53, Proto.TCP, "domain"))
    captured: list[tuple[str, int]] = []
    panel.recon_requested.connect(lambda domain, port: captured.append((domain, port)))
    panel._recon.click()
    assert captured == [("example.htb", 53)]


def test_invalid_domain_blocks_recon(qtbot: QtBot, tmp_path: Path) -> None:
    panel = DnsPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel._domain.setText("-x evil")
    recon: list[tuple[str, int]] = []
    failures: list[str] = []
    panel.recon_requested.connect(lambda d, p: recon.append((d, p)))
    panel.validation_failed.connect(failures.append)
    panel._recon.click()
    assert recon == []  # never emitted a recon for a hostile domain
    assert failures and "invalid domain" in failures[0]


def test_empty_domain_still_runs_baseline(qtbot: QtBot, tmp_path: Path) -> None:
    panel = DnsPanel()
    qtbot.addWidget(panel)
    panel.set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.5")))  # no hostname
    captured: list[tuple[str, int]] = []
    panel.recon_requested.connect(lambda d, p: captured.append((d, p)))
    panel._recon.click()
    assert captured == [("", 53)]  # version + recursion run even without a zone


def test_manual_followups_expand_and_stay_legal(qtbot: QtBot, tmp_path: Path) -> None:
    panel = DnsPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    assert panel._manual.count() > 0
    commands = [panel._manual.item(i).data(_COMMAND_ROLE) for i in range(panel._manual.count())]
    joined = " ".join(commands)
    assert "10.10.10.5" in joined
    assert "example.htb" in joined  # the domain reaches every follow-up
    assert "--passwords" not in joined
    assert "rockyou" not in joined
    for tool in ("hydra", "medusa", "dns-brute", "-t brt"):
        assert tool not in joined  # subdomain brute stays in the vhost module


def test_tool_panel_switches_to_dns_page(qtbot: QtBot, tmp_path: Path) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_target("10.10.10.5")
    panel.set_profile(_profile(tmp_path))
    panel.show_service(DiscoveredService(53, Proto.TCP, "domain"), _dns_ref())
    assert panel._stack.currentWidget() is panel._dns
    panel.set_dns_summary(["Zone transfer: allowed"])
    assert panel._dns._summary.count() == 1


def test_tool_panel_forwards_dns_signals(qtbot: QtBot, tmp_path: Path) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel.show_service(DiscoveredService(53, Proto.TCP, "domain"), _dns_ref())
    recon: list[tuple[str, int]] = []
    manual: list[str] = []
    panel.dns_recon_requested.connect(lambda d, p: recon.append((d, p)))
    panel.run_requested.connect(manual.append)
    panel._dns._recon.click()
    panel._dns._on_manual_activated(panel._dns._manual.item(0))
    assert recon == [("example.htb", 53)]
    assert manual and "10.10.10.5" in manual[0]


def _fake_run_factory() -> object:
    def fake_run(
        shell_line: str,
        output_file: Path,
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        on_line: object | None = None,
    ) -> object:
        if shell_line.startswith("nmap"):
            text = (_FIXTURES / "nmap-dns.txt").read_text(encoding="utf-8")
        elif shell_line.startswith("dnsrecon"):
            text = (_FIXTURES / "dnsrecon-std.txt").read_text(encoding="utf-8")
        elif "AXFR" in shell_line:
            text = (_FIXTURES / "dig-axfr.txt").read_text(encoding="utf-8")
        elif "version.bind" in shell_line:
            text = (_FIXTURES / "dig-version.txt").read_text(encoding="utf-8")
        else:
            text = ""
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    return fake_run


def test_dns_worker_parses_and_writes_findings(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = _profile(tmp_path)
    monkeypatch.setattr(shell, "run", _fake_run_factory())

    worker = mw.DnsReconWorker(prof, "example.htb", 53)
    result = worker._drive()

    assert any("Version: 9.11.3" in line for line in result.summary)
    assert any("Zone transfer: allowed" in line for line in result.summary)
    assert any("Recursion: enabled" in line for line in result.summary)

    stored = findings_mod.load_findings(prof.directory)
    values = {f.get("value") for f in stored}
    assert "admin.example.htb. A 10.10.10.10" in values  # from dig AXFR
    kinds = {f.get("kind") for f in stored}
    assert {"version", "record", "zone-transfer", "recursion"} <= kinds
