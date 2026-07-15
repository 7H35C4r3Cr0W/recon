from pytestqt.qtbot import QtBot

from oscprecon.gui.dialogs.ligolo import LigoloHelperDialog


def test_ligolo_dialog_builds_and_regenerates(qtbot: QtBot) -> None:
    dlg = LigoloHelperDialog(["10.10.5.0/24"])
    qtbot.addWidget(dlg)
    assert dlg._routes.text() == "10.10.5.0/24"  # seeded from known subnets
    assert dlg._steps_layout.count() > 0  # step cards rendered
    # changing a value rebuilds the steps (live preview) without crashing
    before = dlg._steps_layout.count()
    dlg._ip.setText("10.10.14.99")
    dlg._routes.setText("172.16.8.0/24, 192.168.99.0/24")
    assert dlg._steps_layout.count() >= before
