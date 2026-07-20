from pytestqt.qtbot import QtBot

from oscprecon.gui.dialogs.nmap_scan import NmapScanDialog


def test_preview_updates_from_controls(qtbot: QtBot) -> None:
    dlg = NmapScanDialog("10.10.5.0/24", ["10.129.33.39", "10.10.5.23"], "10.129.33.39")
    qtbot.addWidget(dlg)
    dlg._no_ping.setChecked(True)
    dlg._scripts_default.setChecked(True)
    dlg._ports.setText("-p-")
    assert dlg._preview.text() == "nmap -sT -Pn -T4 -p- -sV -sC 10.10.5.0/24"
    # switching to ping-sweep drops ports/version
    dlg._scan_type.setCurrentIndex(3)
    assert dlg._preview.text() == "nmap -sn -T4 10.10.5.0/24"


def test_raw_mode_lets_user_own_the_command(qtbot: QtBot) -> None:
    dlg = NmapScanDialog("10.10.5.23", ["10.129.33.39"], "10.129.33.39")
    qtbot.addWidget(dlg)
    dlg._raw.setChecked(True)
    assert dlg._preview.isReadOnly() is False
    assert dlg._scan_type.isEnabled() is False  # structured controls greyed out
    dlg._preview.setText("nmap -sT -Pn --scanflags SYNACK 10.10.5.23")
    dlg._on_accept()
    assert dlg.command() == "nmap -sT -Pn --scanflags SYNACK 10.10.5.23"
    assert dlg.target() == "10.10.5.23"


def test_accept_rejects_bad_target(qtbot: QtBot) -> None:
    dlg = NmapScanDialog("-oG/tmp/x", ["10.0.0.1"], "10.0.0.1")
    qtbot.addWidget(dlg)
    dlg._on_accept()  # must not accept a flag-like target
    assert dlg.result() != int(dlg.DialogCode.Accepted)
    assert dlg._error.text()


def test_accept_requires_nmap_command(qtbot: QtBot) -> None:
    dlg = NmapScanDialog("10.0.0.5", ["10.0.0.1"], "10.0.0.1")
    qtbot.addWidget(dlg)
    dlg._raw.setChecked(True)
    dlg._preview.setText("rm -rf /")  # not an nmap command
    dlg._on_accept()
    assert dlg.result() != int(dlg.DialogCode.Accepted)
    assert "must start with 'nmap'" in dlg._error.text()


def test_pivot_source_defaults_to_entry(qtbot: QtBot) -> None:
    dlg = NmapScanDialog("10.10.5.23", ["10.129.33.39", "10.10.5.23"], "10.129.33.39")
    qtbot.addWidget(dlg)
    assert dlg.pivot_source() == "10.129.33.39"


def test_nse_picker_appends_and_dedupes(qtbot: QtBot) -> None:
    dlg = NmapScanDialog("10.0.0.5", ["10.0.0.5"], "10.0.0.5")
    qtbot.addWidget(dlg)
    dlg._nse_pick.setCurrentText("smb-os-discovery")
    dlg._nse_add.click()
    dlg._nse_pick.setCurrentText("http-title")
    dlg._nse_add.click()
    assert dlg._scripts.text() == "smb-os-discovery,http-title"
    assert "--script smb-os-discovery,http-title" in dlg._preview.text()
    dlg._nse_pick.setCurrentText("http-title")  # already present -> no duplicate
    dlg._nse_add.click()
    assert dlg._scripts.text() == "smb-os-discovery,http-title"


def test_open_and_os_detect_checkboxes(qtbot: QtBot) -> None:
    dlg = NmapScanDialog("10.0.0.5", ["10.0.0.5"], "10.0.0.5")
    qtbot.addWidget(dlg)
    dlg._only_open.setChecked(True)
    dlg._os_detect.setChecked(True)
    assert dlg._preview.text() == "nmap -sT -T4 --top-ports 1000 -sV -O --open 10.0.0.5"
