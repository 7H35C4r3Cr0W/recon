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


def test_help_window_is_movable_resizable_and_minimizable(qtbot: QtBot) -> None:
    # user request: the docs are a REAL window — the WM gives move/resize/minimize/maximize, so it
    # must NOT be a fixed-size frameless popup (the old behaviour) any more.
    popup = HelpPopup("light")
    qtbot.addWidget(popup)
    flags = popup.windowFlags()
    # the window-type bits (masked — Popup's value shares the Window bit) must say "normal window"
    assert (flags & Qt.WindowType.WindowType_Mask) == Qt.WindowType.Window
    assert not (flags & Qt.WindowType.FramelessWindowHint)
    assert flags & Qt.WindowType.WindowMinMaxButtonsHint  # minimize + maximize buttons
    # resizable: a real range between the minimum and the maximum, not a pinned size
    assert popup.minimumWidth() < popup.maximumWidth()
    assert popup.minimumHeight() < popup.maximumHeight()
    # a modest size that fits any (virtual) screen, so this asserts resizability, not a screen size
    popup.resize(640, 480)
    assert popup.size().width() == 640 and popup.size().height() == 480


def test_help_window_remembers_its_geometry(qtbot: QtBot, tmp_path: object) -> None:
    from oscprecon import config

    popup = HelpPopup("light")
    qtbot.addWidget(popup)
    popup.resize(640, 480)
    popup.store_geometry()
    assert config.window_geometry("help")  # persisted for the next session
    reopened = HelpPopup("light")
    qtbot.addWidget(reopened)
    assert reopened._restore_geometry()
    assert reopened.size() == popup.size()  # reopens the size the operator left it
