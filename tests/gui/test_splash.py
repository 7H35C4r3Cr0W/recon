from PySide6.QtWidgets import QSplashScreen
from pytestqt.qtbot import QtBot

from oscprecon import __version__
from oscprecon.gui.splash import make_splash


def test_make_splash_renders_a_pixmap(qtbot: QtBot) -> None:
    splash = make_splash()
    qtbot.addWidget(splash)
    assert isinstance(splash, QSplashScreen)
    pixmap = splash.pixmap()
    assert not pixmap.isNull()
    assert pixmap.width() > 0 and pixmap.height() > 0


def test_version_string_is_available_for_the_splash() -> None:
    # the splash paints v{__version__}; guard that the symbol it reads stays importable
    assert __version__
