from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon.gui.dialogs.manual_finding import ManualFindingDialog
from oscprecon.gui.widgets.findings_view import FindingsView
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile

# Operator-entered findings (user request): add / edit / delete your own findings, with host, port,
# PoC and notes, alongside everything the parsers found.


def _profile(tmp_path: Path) -> Profile:
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.5", hostname="box.htb"))
    profile.set_services([DiscoveredService(80, Proto.TCP, "http")])
    return profile


def test_manual_finding_shows_in_the_table_with_host_port_and_marker(
    qtbot: QtBot, tmp_path: Path
) -> None:
    profile = _profile(tmp_path)
    findings_mod.add_manual_finding(
        profile.directory,
        {
            "kind": "vuln",
            "value": "SQLi in /search.php",
            "severity": "exposure",
            "host": "10.10.10.5",
            "port": 80,
            "poc": "curl 'http://10.10.10.5/search.php?q=1'",
        },
    )
    view = FindingsView("dark")
    qtbot.addWidget(view)
    view.set_profile(profile)
    assert view._table.rowCount() == 1
    row_text = [view._table.item(0, c).text() for c in range(view._table.columnCount())]
    assert "exposure" in row_text[0] and "✎" in row_text[0]  # your own finding is marked
    assert row_text[3] == "10.10.10.5"  # host column
    assert row_text[4] == "80"  # port column
    assert "SQLi" in row_text[5]


def test_selecting_a_manual_finding_shows_its_poc_and_enables_edit_delete(
    qtbot: QtBot, tmp_path: Path
) -> None:
    profile = _profile(tmp_path)
    findings_mod.add_manual_finding(
        profile.directory, {"kind": "vuln", "value": "x", "poc": "curl http://t/x"}
    )
    view = FindingsView("dark")
    qtbot.addWidget(view)
    view.set_profile(profile)
    view._table.selectRow(0)
    assert not view._detail_view.isHidden()
    assert "curl http://t/x" in view._detail_view.toPlainText()
    assert view._edit_btn.isEnabled() and view._delete_btn.isEnabled()


def test_parsed_findings_are_not_editable(qtbot: QtBot, tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    findings_mod.add_findings(
        profile.directory, [{"module": "http", "kind": "product", "value": "nginx 1.18"}]
    )
    view = FindingsView("dark")
    qtbot.addWidget(view)
    view.set_profile(profile)
    view._table.selectRow(0)
    assert not view._edit_btn.isEnabled()
    assert not view._delete_btn.isEnabled()


def test_my_findings_filter_and_search_covers_the_poc(qtbot: QtBot, tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    findings_mod.add_findings(
        profile.directory, [{"module": "http", "kind": "port", "value": "80"}]
    )
    findings_mod.add_manual_finding(
        profile.directory, {"kind": "vuln", "value": "mine", "poc": "sqlmap-free manual payload"}
    )
    view = FindingsView("dark")
    qtbot.addWidget(view)
    view.set_profile(profile)
    assert view._table.rowCount() == 2
    view._category.setCurrentText("My findings")
    assert view._table.rowCount() == 1
    view._category.setCurrentText("All categories")
    view._filter.setText("manual payload")  # PoC text is searchable
    assert view._table.rowCount() == 1


def test_read_only_profile_cannot_add_findings(qtbot: QtBot, tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    profile.read_only = True
    view = FindingsView("dark")
    qtbot.addWidget(view)
    view.set_profile(profile)
    assert not view._add_btn.isEnabled()


def test_dialog_round_trips_every_field(qtbot: QtBot, tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    dialog = ManualFindingDialog(None, profile)
    qtbot.addWidget(dialog)
    dialog._title.setText("creds in backup.zip")
    dialog._kind.setCurrentText("credential")
    dialog._severity.setCurrentIndex(dialog._severity.findData("access"))
    dialog._host.setCurrentText("10.10.10.9")
    dialog._port.setCurrentText("80 — http")  # annotated entry -> bare number in the data
    dialog._poc.setPlainText("unzip backup.zip")
    dialog._detail.setPlainText("found in /backup")
    data = dialog.finding()
    assert data["value"] == "creds in backup.zip"
    assert data["kind"] == "credential"
    assert data["severity"] == "access"
    assert data["host"] == "10.10.10.9"
    assert data["port"] == 80
    assert data["poc"] == "unzip backup.zip"

    saved = findings_mod.add_manual_finding(profile.directory, data)
    edit = ManualFindingDialog(None, profile, saved)
    qtbot.addWidget(edit)
    assert edit._title.text() == "creds in backup.zip"
    assert edit._selected_port() == "80"
    assert edit.finding()["id"] == saved["id"]  # an edit keeps the identity


def test_dialog_requires_a_description(qtbot: QtBot, tmp_path: Path) -> None:
    dialog = ManualFindingDialog(None, _profile(tmp_path))
    qtbot.addWidget(dialog)
    dialog._on_accept()  # empty title
    assert not dialog._error.isHidden()
    assert dialog.result() != int(ManualFindingDialog.DialogCode.Accepted)


def test_editing_can_clear_the_port(qtbot: QtBot, tmp_path: Path) -> None:
    # review finding: the dialog omitted an empty port, and update_manual_finding MERGES — so the
    # old port silently came back and "this isn't port-specific after all" was impossible to say.
    profile = _profile(tmp_path)
    saved = findings_mod.add_manual_finding(
        profile.directory, {"kind": "vuln", "value": "x", "port": 445}
    )
    dialog = ManualFindingDialog(None, profile, saved)
    qtbot.addWidget(dialog)
    dialog._port.setCurrentText("")
    findings_mod.update_manual_finding(profile.directory, str(saved["id"]), dialog.finding())
    assert findings_mod.load_findings(profile.directory)[0]["port"] == ""

    view = FindingsView("dark")
    qtbot.addWidget(view)
    view.set_profile(profile)
    port_cell = view._table.item(0, 4)
    assert port_cell is not None and port_cell.text() == ""  # renders as blank, not "445"
