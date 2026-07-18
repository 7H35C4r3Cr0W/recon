import csv
from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon.gui.widgets.discovered_urls_panel import DiscoveredUrlsPanel
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def _profile(tmp_path: Path) -> Profile:
    prof = Profile.create(tmp_path, "m", Target(ip="10.129.34.153"))
    findings_mod.add_findings(
        prof.directory,
        [
            # dir-buster results on port 80 — these become table rows
            {
                "module": "http",
                "port": 80,
                "path": "/index.php",
                "status": 200,
                "size": 12100,
                "method": "GET",
                "lines": 377,
                "words": 738,
                "discovered_at": "t",
            },
            {
                "module": "http",
                "port": 80,
                "path": "/server-status",
                "status": 403,
                "size": 1205,
                "method": "GET",
                "lines": 45,
                "words": 113,
                "discovered_at": "t",
            },
            # a whatweb fingerprint note on the same port — must NOT show as a discovered URL
            {
                "module": "http",
                "port": 80,
                "path": "/",
                "status": 200,
                "note": "whatweb: Apache[2.4.41]",
                "discovered_at": "t",
            },
            # a finding on a DIFFERENT port — must not appear when configured for 80
            {"module": "http", "port": 443, "path": "/secret", "status": 200, "discovered_at": "t"},
        ],
    )
    return prof


def test_table_shows_only_this_port_dirbust_urls(qtbot: QtBot, tmp_path: Path) -> None:
    panel = DiscoveredUrlsPanel("dark")
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel.configure(DiscoveredService(80, Proto.TCP, "http"))

    # /index.php + /server-status; NOT the whatweb note, NOT the :443 finding
    assert panel._table.rowCount() == 2
    urls = {panel._row_url(r) for r in range(panel._table.rowCount())}
    assert urls == {"http://10.129.34.153/index.php", "http://10.129.34.153/server-status"}

    # columns carry the real data (row order is status-sorted: 200 before 403)
    row0 = [panel._table.item(0, c).text() for c in range(6)]
    assert row0 == ["200", "GET", "377", "738", "12100", "http://10.129.34.153/index.php"]


def test_https_port_builds_https_urls(qtbot: QtBot, tmp_path: Path) -> None:
    panel = DiscoveredUrlsPanel("dark")
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel.configure(DiscoveredService(443, Proto.TCP, "https"))
    assert panel._table.rowCount() == 1
    assert (
        panel._row_url(0) == "https://10.129.34.153/secret"
    )  # https, no :443 for the default port


def test_export_csv_writes_the_rows(qtbot: QtBot, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    panel = DiscoveredUrlsPanel("dark")
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path))
    panel.configure(DiscoveredService(80, Proto.TCP, "http"))

    out = tmp_path / "urls.csv"
    monkeypatch.setattr(
        "oscprecon.gui.widgets.discovered_urls_panel.QFileDialog.getSaveFileName",
        lambda *a, **k: (str(out), "CSV (*.csv)"),
    )
    panel._export_csv()
    rows = list(csv.reader(out.open()))
    assert rows[0] == ["Status", "Method", "Lines", "Words", "Bytes", "URL"]
    assert ["200", "GET", "377", "738", "12100", "http://10.129.34.153/index.php"] in rows


def test_source_disclosure_row_is_flagged(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.129.95.184"))
    findings_mod.add_findings(
        prof.directory,
        [
            {
                "module": "http",
                "port": 80,
                "path": "/login/login.php.swp",
                "status": 200,
                "size": 3210,
                "method": "GET",
                "discovered_at": "t",
            },
            {
                "module": "http",
                "port": 80,
                "path": "/index.php",
                "status": 200,
                "discovered_at": "t",
            },
        ],
    )
    panel = DiscoveredUrlsPanel("dark")
    qtbot.addWidget(panel)
    panel.set_profile(prof)
    panel.configure(DiscoveredService(80, Proto.TCP, "http"))

    # the .swp row is marked source-disclosure (7th tuple element); index.php is not
    rows = {r[5]: r[6] for r in panel._collect_rows()}
    assert rows["http://10.129.95.184/login/login.php.swp"] is True
    assert rows["http://10.129.95.184/index.php"] is False

    # displayed with a ⚠ prefix, but the plain URL still opens/copies
    swp_row = next(
        r for r in range(panel._table.rowCount()) if panel._row_url(r).endswith("login.php.swp")
    )
    assert panel._table.item(swp_row, 5).text().startswith("⚠")
    assert panel._row_url(swp_row) == "http://10.129.95.184/login/login.php.swp"
    assert "source/backup" in panel._count.text()
