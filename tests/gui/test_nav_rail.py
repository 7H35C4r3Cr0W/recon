from pytestqt.qtbot import QtBot

from oscprecon.gui.widgets.nav_rail import NavRail


def test_nav_collapse_toggles_width_and_persists(qtbot: QtBot) -> None:
    rail = NavRail("dark")
    qtbot.addWidget(rail)
    expanded = rail.width()
    rail._toggle_collapsed()
    collapsed = rail.width()
    assert collapsed < expanded  # icon-only rail is narrower
    rail._toggle_collapsed()
    assert rail.width() == expanded  # toggles back

    # a fresh rail reads the persisted state
    rail._toggle_collapsed()  # persist collapsed=1
    try:
        assert NavRail("dark")._collapsed is True
    finally:
        rail._toggle_collapsed()  # restore persisted state to expanded


def test_nav_labels_are_full_text_when_expanded(qtbot: QtBot) -> None:
    rail = NavRail("dark")
    qtbot.addWidget(rail)
    # the label the user reported truncated ("Exp...ation") must be present in full
    assert rail._buttons["exploit"].text().strip() == "Exploitation"
