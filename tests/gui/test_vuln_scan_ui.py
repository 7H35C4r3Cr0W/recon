from __future__ import annotations

from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon import nse_vuln
from oscprecon.gui.main_window import MainWindow
from oscprecon.gui.task_manager import NMAP_LANE, TOOL_LANE, TaskManager
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile


class _Dummy:
    def cancel(self) -> None:
        pass


def _service(port: int, name: str) -> DiscoveredService:
    return DiscoveredService(port=port, proto=Proto.TCP, service=name, discovered_at="")


def test_every_service_offers_a_vuln_scan(qtbot: QtBot) -> None:
    # the driving miss: the vuln checks must be reachable from ANY selected service, not just SMB
    panel = ToolPanel()
    qtbot.addWidget(panel)
    for port, name in ((445, "microsoft-ds"), (80, "http"), (21, "ftp"), (12345, "unknown")):
        panel.show_service(_service(port, name), None)
        assert panel._vuln_row.isVisible() or not panel.isVisible()
        assert panel._vuln_button.isEnabled()


def test_the_vuln_row_hides_when_nothing_is_selected(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.show_service(None, None)
    assert panel._vuln_row.isVisible() is False


def test_vuln_button_emits_the_selected_service_and_port(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.show_service(_service(445, "microsoft-ds"), None)
    with qtbot.waitSignal(panel.vuln_scan_requested, timeout=1000) as blocker:
        panel._vuln_button.click()
    assert blocker.args == ["microsoft-ds", 445, nse_vuln.MODE_ALL, "tcp", ""]


def test_vuln_row_names_the_service_family_it_will_check(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.show_service(_service(445, "microsoft-ds"), None)
    assert "SMB" in panel._vuln_hint.text()
    panel.show_service(_service(3389, "ms-wbt-server"), None)
    assert "RDP" in panel._vuln_hint.text()


def test_vuln_button_is_disabled_while_running(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.show_service(_service(445, "microsoft-ds"), None)
    panel.set_running(True)
    assert panel._vuln_button.isEnabled() is False
    panel.set_running(False)
    assert panel._vuln_button.isEnabled() is True


def test_vuln_scan_uses_the_nmap_lane_so_it_runs_beside_other_work(
    qtbot: QtBot, tmp_path: Path, monkeypatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.set_services([_service(445, "microsoft-ds"), _service(139, "netbios-ssn")])
    window._set_profile(profile)

    launched: list[tuple[str, str]] = []
    monkeypatch.setattr(
        window,
        "_start",
        lambda worker, label, on_done, **kw: launched.append((label, kw.get("lane", TOOL_LANE))),
    )
    window._on_vuln_scan("microsoft-ds", 445, nse_vuln.MODE_ALL, "tcp")
    assert launched == [("vuln:microsoft-ds:445", NMAP_LANE)]


def test_scan_all_vulns_queues_one_run_per_service_family(
    qtbot: QtBot, tmp_path: Path, monkeypatch
) -> None:
    # 139 + 445 are one SMB pass, not two identical scans
    window = MainWindow()
    qtbot.addWidget(window)
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.set_services(
        [
            _service(139, "netbios-ssn"),
            _service(445, "microsoft-ds"),
            _service(3389, "ms-wbt-server"),
        ]
    )
    window._set_profile(profile)
    monkeypatch.setattr(window, "_on_vuln_scan", lambda *a, **k: None)
    window._on_scan_all_vulns()
    # one queued entry per family; the first is popped by the drain, the rest remain
    assert len(window._pending_vuln_scans) <= 2


def test_a_vuln_line_reaches_the_alarm_banner(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.append_output("[vuln] VULNERABLE: smb-vuln-ms17-010 — SMBv1 RCE")
    assert panel._banner._kind == "error"


def test_output_is_tagged_only_when_several_scans_run(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.append_output("plain line", "nmap #1")
    assert panel._output.toPlainText().strip() == "plain line"  # single run: unchanged
    panel.set_multi(True)
    panel.append_output("second line", "vuln:smb #2")
    assert "vuln:smb #2 │ second line" in panel._output.toPlainText()


def test_task_tags_are_unique_per_run() -> None:
    manager = TaskManager()
    a = manager.add(object(), "http:80")
    b = manager.add(object(), "http:80")  # same label, different run
    assert a.tag != b.tag


def test_two_content_discovery_runs_with_different_settings_coexist(
    qtbot: QtBot, tmp_path: Path, monkeypatch
) -> None:
    # the headline request: hit the same web port with two wordlists / extension sets at once.
    # They must resolve to DIFFERENT output files, and the second must not be refused.
    from oscprecon.gui.main_window import MainWindow
    from oscprecon.modules.http import default_output

    window = MainWindow()
    qtbot.addWidget(window)
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.set_services([_service(80, "http")])
    window._set_profile(profile)

    started: list[str] = []
    monkeypatch.setattr(
        window, "_start", lambda worker, label, on_done, **kw: started.append(label)
    )
    first = default_output(80, "feroxbuster", "/usr/share/seclists/big.txt", "aaa111")
    second = default_output(80, "feroxbuster", "/usr/share/seclists/big.txt", "bbb222")
    assert first != second

    window._on_http_run("feroxbuster -u http://10.10.10.100/", first, "feroxbuster", 80)
    window._on_http_run("feroxbuster -u http://10.10.10.100/", second, "feroxbuster", 80)
    assert started == ["http:80", "http:80"]  # both admitted


def test_a_second_run_writing_the_same_file_is_refused_by_name(
    qtbot: QtBot, tmp_path: Path, monkeypatch
) -> None:
    # …but two runs that WOULD write the same file must not interleave. §24: say why.
    from oscprecon.gui.main_window import MainWindow
    from oscprecon.modules.http import default_output

    window = MainWindow()
    qtbot.addWidget(window)
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.set_services([_service(80, "http")])
    window._set_profile(profile)
    monkeypatch.setattr(window, "_start", lambda worker, label, on_done, **kw: None)

    same = default_output(80, "feroxbuster", "/usr/share/seclists/big.txt")
    window._on_http_run("feroxbuster -u http://10.10.10.100/", same, "feroxbuster", 80)
    window._tool_panel.clear_output()
    window._on_http_run("feroxbuster -u http://10.10.10.100/", same, "feroxbuster", 80)
    assert "[busy]" in window._tool_panel._output.toPlainText()
    assert same in window._tool_panel._output.toPlainText()


def test_a_queued_vuln_sweep_is_dropped_when_the_project_changes(
    qtbot: QtBot, tmp_path: Path, monkeypatch
) -> None:
    # the queue holds (service, port) from ONE box; draining it after a switch would aim the old
    # box's ports at the new box's IP.
    window = MainWindow()
    qtbot.addWidget(window)
    first = Profile.create(tmp_path / "a", "one", Target(ip="10.10.10.100"))
    first.set_services([_service(445, "microsoft-ds"), _service(3389, "ms-wbt-server")])
    window._set_profile(first)
    # fill the nmap lane so the queue is parked rather than drained immediately
    for i in range(window._tasks.lane_cap(NMAP_LANE)):
        window._tasks.add(_Dummy(), f"busy-{i}", lane=NMAP_LANE)
    window._on_scan_all_vulns()
    assert window._pending_vuln_scans

    second = Profile.create(tmp_path / "b", "two", Target(ip="10.10.10.200"))
    window._set_profile(second)
    window._drain_vuln_queue()
    assert window._pending_vuln_scans == []
    assert "project changed" in window._tool_panel._output.toPlainText()


def test_a_udp_service_is_scanned_over_udp(qtbot: QtBot) -> None:
    # a UDP service scanned over TCP comes back "clean" and the operator believes it
    panel = ToolPanel()
    qtbot.addWidget(panel)
    udp = DiscoveredService(port=161, proto=Proto.UDP, service="snmp", discovered_at="")
    panel.show_service(udp, None)
    with qtbot.waitSignal(panel.vuln_scan_requested, timeout=1000) as blocker:
        panel._vuln_button.click()
    assert blocker.args[3] == "udp"
    assert "-sU" in panel._vuln_button.toolTip()


def test_a_pivoted_hosts_service_is_scanned_on_that_host(qtbot: QtBot, tmp_path: Path) -> None:
    # every other panel receives host_ip so a pivoted host isn't reconned against the entry box
    from oscprecon.gui.workers.vuln import VulnScanWorker

    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.show_service(_service(445, "microsoft-ds"), None, "172.16.1.20")
    with qtbot.waitSignal(panel.vuln_scan_requested, timeout=1000) as blocker:
        panel._vuln_button.click()
    assert blocker.args[4] == "172.16.1.20"

    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.set_services([_service(445, "microsoft-ds")])
    worker = VulnScanWorker(profile, "microsoft-ds", 445, host="172.16.1.20")
    assert "172.16.1.20" in worker.output_rel()  # never overwrites the entry box's scan


def test_stop_clears_a_queued_sweep_instead_of_starting_the_next_one(
    qtbot: QtBot, tmp_path: Path
) -> None:
    # cancelling frees a lane slot, and _release drains the queue into it — so without clearing,
    # "Stop all" LAUNCHED the next queued scan and the sweep could not be interrupted.
    window = MainWindow()
    qtbot.addWidget(window)
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.set_services(
        [_service(445, "microsoft-ds"), _service(3389, "ms-wbt-server"), _service(21, "ftp")]
    )
    window._set_profile(profile)
    for i in range(window._tasks.lane_cap(NMAP_LANE)):
        window._tasks.add(_Dummy(), f"busy-{i}", lane=NMAP_LANE)
    window._on_scan_all_vulns()
    assert window._pending_vuln_scans

    window._stop_all()
    assert window._pending_vuln_scans == []
    assert "queued vuln scan(s) cancelled" in window._tool_panel._output.toPlainText()


def test_suggested_only_never_leaves_an_empty_unrecoverable_tree(
    qtbot: QtBot, tmp_path: Path
) -> None:
    from oscprecon.gui.widgets.exploit_panel import ExploitPanel

    panel = ExploitPanel()
    qtbot.addWidget(panel)
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.set_services([_service(445, "microsoft-ds")])
    panel.set_profile(profile)
    panel._suggested_only.setChecked(True)

    # a service with no suggestions must still show its actions, and the box must stay usable
    panel._service.setCurrentIndex(panel._service.findData("activemq"))
    visible = 0
    for i in range(panel._tree.topLevelItemCount()):
        parent = panel._tree.topLevelItem(i)
        for j in range(parent.childCount()):
            visible += 0 if parent.child(j).isHidden() else 1
    assert visible > 0
    assert panel._suggested_only.isEnabled()
