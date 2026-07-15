import io
import tarfile
from pathlib import Path

import pytest
from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox
from pytestqt.qtbot import QtBot

from oscprecon import config
from oscprecon.gui.main_window import MainWindow
from oscprecon.models import Target
from oscprecon.profile import Profile
from oscprecon.workspace import portability


def test_open_by_ip_opens_matching_profile(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    Profile.create(config.workspace_root(), "target-a", Target(ip="10.10.10.55"))
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("10.10.10.55", True))
    window._on_open_by_ip()
    assert window._profile is not None and window._profile.target.ip == "10.10.10.55"


def test_open_by_ip_no_match_leaves_profile(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("172.16.0.9", True))
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: QMessageBox.StandardButton.Ok)
    window._on_open_by_ip()
    assert window._profile is None  # nothing matched, nothing opened


def test_import_project_opens_imported(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    src = Profile.create(tmp_path / "src", "imported-box", Target(ip="10.9.9.9"))
    archive = portability.export_project_archive(src.directory, tmp_path)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(archive), ""))
    window._on_import_project()
    assert window._profile is not None and window._profile.profile_name == "imported-box"
    assert (config.workspace_root() / "imported-box" / "profile.json").is_file()


def test_import_collision_prompts_and_overwrites(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    dup = Profile.create(config.workspace_root(), "dup", Target(ip="10.2.2.2"))
    archive = portability.export_project_archive(dup.directory, tmp_path)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(archive), ""))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    window._on_import_project()  # dup exists → prompt → overwrite
    assert window._profile is not None and window._profile.profile_name == "dup"


def test_import_malicious_archive_warns_and_opens_nothing(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        info = tarfile.TarInfo("proj/../../pwned")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    window = MainWindow()
    qtbot.addWidget(window)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(bad), ""))
    warned: list[str] = []
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *a, **k: warned.append(a[-1]) or QMessageBox.StandardButton.Ok,
    )
    window._on_import_project()
    assert window._profile is None  # nothing opened
    assert warned and "traversal" in warned[0]
    assert not (tmp_path / "pwned").exists()


def test_export_project_writes_archive(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "exportme", Target(ip="10.1.1.1"))
    window._set_profile(prof)
    out = tmp_path / "exportme.tar.gz"
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), ""))
    window._on_export_project()
    assert out.is_file()
    with tarfile.open(out) as tar:
        assert any(name.endswith("profile.json") for name in tar.getnames())


def test_export_project_cancelled_confirm_writes_nothing(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(config.workspace_root(), "x", Target(ip="10.1.1.2")))
    out = tmp_path / "x.tar.gz"
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Cancel)
    saved: list[str] = []
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", lambda *a, **k: saved.append("x") or ("", "")
    )
    window._on_export_project()
    assert (
        not out.exists() and not saved
    )  # declining the creds warning aborts before the file picker


# ---- project delete (dashboard right-click → confirm → host window removes the folder) --------


def test_delete_non_active_project_removes_folder(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "gone", Target(ip="10.3.3.3"))
    assert prof.directory.is_dir()
    window._on_delete_requested([str(prof.directory)])
    assert not prof.directory.exists()
    window.close()  # closeEvent cancels + waits the dashboard/index/EDB threads


def test_delete_active_project_closes_then_removes(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "active-gone", Target(ip="10.3.3.4"))
    window._set_profile(prof)  # becomes the active, edit-locked profile
    window._on_delete_requested([str(prof.directory)])
    assert not prof.directory.exists()
    assert window._profile is None  # the open project was closed before removal
    window.close()  # closeEvent cancels + waits the dashboard/index/EDB threads


def test_delete_refuses_project_locked_by_another_live_instance(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    # defect regression: a project open read-only here while ANOTHER live instance holds the edit
    # lock must never be deleted out from under that other instance — even though it is "active".
    from oscprecon.workspace import locks

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "held-elsewhere", Target(ip="10.3.3.5"))
    prof.read_only = True
    window._profile = prof  # simulate: opened read-only because the lock is held by window A

    foreign = locks.LockInfo(
        pid=999_999, hostname="other-host", app_version="1", started_at="2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(locks, "read_lock", lambda directory: (foreign, False))
    monkeypatch.setattr(locks, "is_stale", lambda info: False)  # the other instance is alive

    window._on_delete_requested([str(prof.directory)])
    assert prof.directory.is_dir()  # refused — the other instance's project is untouched
    window.close()  # closeEvent cancels + waits the dashboard/index/EDB threads


# ---- pivot topology (Edit → Add Pivoted Network) ---------------------------------------------


def test_add_pivot_network_dialog_parses_and_returns_hosts(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oscprecon.gui.dialogs.pivot_network import AddPivotNetworkDialog

    dialog = AddPivotNetworkDialog(["10.10.10.5", "10.10.5.23"])
    qtbot.addWidget(dialog)
    dialog._pivot_source.setCurrentText("10.10.10.5")
    dialog._text.setPlainText(
        "Nmap scan report for 10.10.5.40\n445/tcp open microsoft-ds Windows Server 2019\n"
    )
    dialog._on_accept()
    hosts = dialog.hosts()
    assert [h.ip for h in hosts] == ["10.10.5.40"]
    assert hosts[0].pivot_source == "10.10.10.5"  # picked source is stamped on the hosts


def test_add_pivot_network_wires_into_profile_and_graph(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    from PySide6.QtWidgets import QDialog

    from oscprecon.gui.dialogs.pivot_network import AddPivotNetworkDialog
    from oscprecon.models import DiscoveredHost

    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(config.workspace_root(), "ctf", Target(ip="10.10.10.5")))

    def fake_exec(self: AddPivotNetworkDialog) -> int:
        self._hosts = [DiscoveredHost(ip="10.10.5.23", pivot_source="10.10.10.5")]
        return int(QDialog.DialogCode.Accepted)

    monkeypatch.setattr(AddPivotNetworkDialog, "exec", fake_exec)
    window._on_add_pivot_network()
    assert window._profile is not None
    assert [h.ip for h in window._profile.discovered_hosts] == ["10.10.5.23"]
    # persisted to disk too
    reloaded = Profile.load(window._profile.directory)
    assert [h.ip for h in reloaded.discovered_hosts] == ["10.10.5.23"]
    window.close()


# ---- custom scan (Scan → Scan a host / range) ------------------------------------------------


def test_scan_host_found_adds_host_and_shows_in_recon_tree(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oscprecon.models import DiscoveredHost, DiscoveredService, Proto

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "ctf", Target(ip="10.129.33.39"))
    window._set_profile(prof)
    host = DiscoveredHost(
        ip="10.10.5.23",
        pivot_source="10.129.33.39",
        services=[DiscoveredService(445, Proto.TCP, "smb")],
    )
    window._on_scan_host_found(host, prof)  # streamed host from a range scan
    assert [h.ip for h in window._profile.discovered_hosts] == ["10.10.5.23"]
    # it shows in the recon-tab tree under a Pivoted networks branch
    labels = []

    def walk(item: object) -> None:
        labels.append(item.text(0))  # type: ignore[attr-defined]
        for i in range(item.childCount()):  # type: ignore[attr-defined]
            walk(item.child(i))  # type: ignore[attr-defined]

    tree = window._service_tree
    for i in range(tree.topLevelItemCount()):
        walk(tree.topLevelItem(i))
    assert any("Pivoted networks" in x for x in labels)
    assert any("10.10.5.23" in x for x in labels)
    window.close()


def test_custom_scan_done_entry_parses_services(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "entry", Target(ip="10.129.33.39"))
    window._set_profile(prof)
    out = prof.directory / "nmap" / "tcp-versioned.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "Nmap scan report for 10.129.33.39\n80/tcp open http nginx 1.14.2\n", encoding="utf-8"
    )
    window._on_custom_scan_done(0, prof, is_entry=True, output_file=out)
    ports = [s.port for s in window._profile.discovered_services]
    assert 80 in ports  # the entry scan's services were parsed into discovered_services
    window.close()


def test_custom_entry_rescan_merges_and_preserves_prior_ports(qtbot: QtBot) -> None:
    from oscprecon.models import DiscoveredService, Proto

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "entry", Target(ip="10.129.33.39"))
    # a prior full recon found a UDP port + a high TCP port (only via -p-)
    prof.set_services(
        [DiscoveredService(161, Proto.UDP, "snmp"), DiscoveredService(54321, Proto.TCP, "unknown")]
    )
    window._set_profile(prof)
    out = prof.directory / "nmap" / "tcp-versioned.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "Nmap scan report for 10.129.33.39\n80/tcp open http nginx 1.14.2\n", encoding="utf-8"
    )
    window._on_custom_scan_done(0, prof, is_entry=True, output_file=out)  # a narrower re-scan
    ports = {(s.port, s.proto.value) for s in window._profile.discovered_services}
    assert (80, "tcp") in ports  # new port added
    assert (161, "udp") in ports  # prior UDP port NOT wiped
    assert (54321, "tcp") in ports  # prior high TCP port NOT wiped
    window.close()


def test_scan_host_found_skips_the_entry_host(qtbot: QtBot) -> None:
    from oscprecon.models import DiscoveredHost, DiscoveredService, Proto

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "ctf", Target(ip="10.10.5.23"))
    window._set_profile(prof)
    # a /24 range scan streams the entry host itself — it must not become a pivoted host
    window._on_scan_host_found(
        DiscoveredHost(ip="10.10.5.23", services=[DiscoveredService(445, Proto.TCP, "smb")]), prof
    )
    assert window._profile.discovered_hosts == []
    window.close()


def test_custom_scan_no_profile_is_safe(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    from PySide6.QtWidgets import QMessageBox

    window = MainWindow()
    qtbot.addWidget(window)
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: QMessageBox.StandardButton.Ok)
    window._on_custom_scan()  # no project loaded -> info dialog, no crash
    assert window._profile is None
    window.close()


# ---- remove host / subnet from the topology (recon-tree right-click) --------------------------


def test_remove_host_flows_to_tree_and_graph(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    from PySide6.QtWidgets import QMessageBox

    from oscprecon.gui.graph_data import build_elements
    from oscprecon.models import DiscoveredHost

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "ctf", Target(ip="10.129.33.39"))
    prof.add_hosts(
        [
            DiscoveredHost(ip="10.10.5.10", pivot_source="10.129.33.39"),
            DiscoveredHost(ip="10.10.5.23", pivot_source="10.129.33.39"),
        ]
    )
    window._set_profile(prof)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    window._on_remove_host("10.10.5.23")
    assert [h.ip for h in window._profile.discovered_hosts] == ["10.10.5.10"]
    # flows to the map: the removed host is no longer a graph node, but the kept one is
    ids = {n["data"]["id"] for n in build_elements(window._profile)["nodes"]}
    assert "host-10.10.5.10" in ids
    assert "host-10.10.5.23" not in ids
    window.close()


def test_remove_subnet_flows_to_tree_and_graph(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    from PySide6.QtWidgets import QMessageBox

    from oscprecon.gui.graph_data import build_elements
    from oscprecon.models import DiscoveredHost

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "ctf", Target(ip="10.129.33.39"))
    prof.add_hosts(
        [
            DiscoveredHost(ip="10.10.5.10", pivot_source="10.129.33.39"),
            DiscoveredHost(ip="10.10.5.23", pivot_source="10.129.33.39"),
            DiscoveredHost(ip="172.16.8.10", pivot_source="10.10.5.10"),
        ]
    )
    window._set_profile(prof)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    window._on_remove_subnet("10.10.5.0/24")
    assert [h.ip for h in window._profile.discovered_hosts] == ["172.16.8.10"]
    ids = {n["data"]["id"] for n in build_elements(window._profile)["nodes"]}
    assert "subnet-10.10.5.0/24" not in ids and "host-10.10.5.10" not in ids
    assert "subnet-172.16.8.0/24" in ids  # the untouched subnet remains
    window.close()


def test_remove_host_cancelled_keeps_it(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    from PySide6.QtWidgets import QMessageBox

    from oscprecon.models import DiscoveredHost

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "ctf", Target(ip="10.0.0.1"))
    prof.add_hosts([DiscoveredHost(ip="10.10.5.10", pivot_source="10.0.0.1")])
    window._set_profile(prof)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Cancel)
    window._on_remove_host("10.10.5.10")
    assert [h.ip for h in window._profile.discovered_hosts] == ["10.10.5.10"]  # cancel keeps it
    window.close()
