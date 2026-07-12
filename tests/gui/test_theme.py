from pathlib import Path

from PySide6.QtGui import QPalette
from pytestqt.qtbot import QtBot

from oscprecon import config
from oscprecon.gui import theme
from oscprecon.gui.main_window import MainWindow


def test_apply_dark_then_light_changes_window_color(qtbot: QtBot) -> None:
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    assert app is not None

    theme.apply_theme("dark")
    dark = app.palette().color(QPalette.ColorRole.Window)
    theme.apply_theme("light")
    light = app.palette().color(QPalette.ColorRole.Window)
    assert dark != light  # the two themes produce distinct window backgrounds
    assert dark.lightness() < light.lightness()  # dark is darker


def test_normalize_falls_back_to_default() -> None:
    assert theme.normalize("dark") == "dark"
    assert theme.normalize("nonsense") == theme.DEFAULT_THEME


def test_set_theme_persists_pref(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_theme("dark")
    assert config.load_prefs().get("theme") == "dark"
    window._set_theme("light")  # restore so we don't leave the app dark for other tests
    assert config.load_prefs().get("theme") == "light"


def test_theme_group_has_both_options(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    labels = {a.text().lower() for a in window._theme_group.actions()}
    assert labels == {"light", "dark"}
