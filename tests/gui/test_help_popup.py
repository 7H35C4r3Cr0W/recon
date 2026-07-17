from PySide6.QtCore import Qt
from pytestqt.qtbot import QtBot

from oscprecon import guide
from oscprecon.gui.dialogs.help_viewer import HelpPopup


def test_help_popup_lists_every_topic_and_loads_the_first(qtbot: QtBot) -> None:
    popup = HelpPopup("htb")
    qtbot.addWidget(popup)
    assert popup._toc.count() == len(guide.topics())
    assert popup._toc.currentRow() == 0
    assert popup._view.toPlainText().strip()  # the first page rendered into the viewer


def test_help_popup_selecting_a_topic_renders_its_page(qtbot: QtBot) -> None:
    popup = HelpPopup("htb")
    qtbot.addWidget(popup)
    row = [t.id for t in guide.topics()].index("shortcuts")
    popup._toc.setCurrentRow(row)
    assert "F1" in popup._view.toPlainText()  # the shortcuts page content is now shown


def test_help_popup_is_a_clickaway_popup(qtbot: QtBot) -> None:
    # frameless Qt.Popup => Qt dismisses it on a click outside its geometry (and on Esc)
    popup = HelpPopup("light")
    qtbot.addWidget(popup)
    assert popup.windowFlags() & Qt.WindowType.Popup
