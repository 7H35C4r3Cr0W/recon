from pathlib import Path

import pytest
from PySide6.QtGui import QColor, QPalette
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
    assert theme.normalize("htb") == "htb"
    assert theme.normalize("nonsense") == theme.DEFAULT_THEME


def test_htb_theme_is_dark_with_parrot_highlight(qtbot: QtBot) -> None:
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    assert app is not None
    theme.apply_theme("htb")
    window = app.palette().color(QPalette.ColorRole.Window)
    highlight = app.palette().color(QPalette.ColorRole.Highlight)
    theme.apply_theme("light")  # restore for other tests
    assert window.lightness() < 60  # a deep dark ground
    assert (highlight.red(), highlight.green(), highlight.blue()) == (21, 228, 241)  # #15e4f1


def test_htb_primary_buttons_use_the_theme_accent() -> None:
    from oscprecon.gui.theme import styles, tokens

    theme.apply_theme("htb")
    qss = styles.primary_button(tokens.active_palette())
    theme.apply_theme("light")  # restore
    assert "#15e4f1" in qss  # the Parrot cyan-green accent drives the primary button in HTB mode


def test_theme_label_is_friendly() -> None:
    assert theme.label("htb") == "HTB"
    assert theme.label("dark") == "Dark"


def test_set_theme_persists_pref(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_theme("dark")
    assert config.load_prefs().get("theme") == "dark"
    window._set_theme("light")  # restore so we don't leave the app dark for other tests
    assert config.load_prefs().get("theme") == "light"


def test_theme_group_has_all_options(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    labels = {a.text().lower() for a in window._theme_group.actions()}
    assert labels == {"light", "dark", "htb", "leet", "amber", "synthwave"}


@pytest.mark.parametrize("name", ["leet", "amber", "synthwave"])
def test_extra_themes_apply_via_fusion_palette(qtbot: QtBot, name: str) -> None:
    # the three brand-kit themes have no hand-written QPalette — they ride the generic
    # _fusion_palette() branch, so assert apply_theme wires Window/Highlight from their tokens.
    from PySide6.QtWidgets import QApplication

    from oscprecon.gui.theme import tokens

    app = QApplication.instance()
    assert app is not None
    theme.apply_theme(name)
    window = app.palette().color(QPalette.ColorRole.Window)
    highlight = app.palette().color(QPalette.ColorRole.Highlight)
    theme.apply_theme("light")  # restore for other tests
    pal = tokens.palette(name)
    assert window == QColor(pal.bg)
    assert highlight == QColor(pal.accent)
    assert name in theme.THEMES and name in config.THEMES
