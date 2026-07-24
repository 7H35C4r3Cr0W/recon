from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import hosts as hosts_mod
from oscprecon.gui.dialogs import hosts_manager as hm
from oscprecon.models import DiscoveredHost, Target
from oscprecon.profile import Profile


def test_hosts_manager_collects_and_bulk_adds(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the Hosts Manager auto-collects discovered (ip, hostname) and adds the checked ones in one go.
    prof = Profile.create(tmp_path, "box", Target(ip="10.10.10.5", hostname="dc01.corp.local"))
    prof.discovered_hosts = [DiscoveredHost(ip="10.10.10.7", hostname="web01.corp.local")]

    hf = tmp_path / "hosts"
    hf.write_text("127.0.0.1\tlocalhost\n")
    # redirect the module's /etc/hosts reads/writes to a temp file (capture reals before patching).
    real_current = hosts_mod.current_mappings
    real_add_many = hosts_mod.add_many
    monkeypatch.setattr(hm.hosts, "current_mappings", lambda: real_current(hf))
    monkeypatch.setattr(hm.hosts, "add_many", lambda entries: real_add_many(entries, hf))

    dlg = hm.HostsManagerDialog(prof)
    qtbot.addWidget(dlg)
    assert dlg._table.rowCount() >= 2  # target + discovered host collected

    dlg._on_add_checked()
    text = hf.read_text()
    assert "dc01.corp.local" in text
    assert "web01.corp.local" in text
