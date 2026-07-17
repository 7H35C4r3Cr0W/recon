import pytest
from pytestqt.qtbot import QtBot

from oscprecon import __version__
from oscprecon.gui.splash import NabuSplash, _kf, make_splash


def test_make_splash_returns_nabu_splash(qtbot: QtBot) -> None:
    splash = make_splash()
    qtbot.addWidget(splash)
    assert isinstance(splash, NabuSplash)
    assert splash.width() > 640 and splash.height() > 400  # card + shadow margin


def test_kf_interpolates_and_clamps() -> None:
    pts = [(0.0, 0.0), (0.5, 10.0), (1.0, 0.0)]
    assert _kf(0.0, pts) == 0.0
    assert _kf(0.5, pts) == 10.0
    assert _kf(1.0, pts) == 0.0
    mid = _kf(0.25, pts)  # eased, so strictly between the endpoints
    assert 0.0 < mid < 10.0


@pytest.mark.parametrize("ms", [0, 1200, 2600, 3300, 4999])
def test_splash_paints_across_the_loop(qtbot: QtBot, ms: int) -> None:
    # every beat of the ~5 s loop must paint without error (beams, mascot evasion, loading UI).
    splash = make_splash()
    qtbot.addWidget(splash)
    splash._test_ms = ms
    pix = splash.grab()
    assert not pix.isNull()


def test_splash_is_still_and_closes_cleanly(qtbot: QtBot) -> None:
    splash = make_splash()
    qtbot.addWidget(splash)
    splash.show()
    assert splash._live is False  # offscreen => no repeating timer (would hang idle-waiters)
    assert not splash._timer.isActive()
    splash._graceful_close()  # the finish() close path must stop the timer and hide the widget
    assert not splash._timer.isActive()
    assert not splash.isVisible()


def test_version_string_is_available_for_the_splash() -> None:
    # the splash paints v{__version__}; guard that the symbol it reads stays importable
    assert __version__
