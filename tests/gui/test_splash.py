import pytest
from PySide6.QtGui import QColor
from pytestqt.qtbot import QtBot

from oscprecon import __version__
from oscprecon.gui.splash import NabuSplash, _kf, make_splash
from oscprecon.gui.theme import tokens


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
    splash._graceful_close()  # the close primitive must stop the timer and hide the widget
    assert not splash._timer.isActive()
    assert not splash.isVisible()


def test_finish_closes_the_splash_after_min_show(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    # drive the real finish() path (not just _graceful_close): it schedules _graceful_close after
    # _MIN_SHOW_MS. Shrink that so the test is fast, then assert the splash truly closes.
    import oscprecon.gui.splash as splash_mod

    monkeypatch.setattr(splash_mod, "_MIN_SHOW_MS", 20)
    splash = make_splash()
    qtbot.addWidget(splash)
    splash.show()
    assert splash.isVisible()
    splash.finish(splash)  # the window arg is unused by design; the splash closes on the timer
    qtbot.waitUntil(lambda: not splash.isVisible(), timeout=2000)
    assert not splash._timer.isActive()


def test_version_string_is_available_for_the_splash() -> None:
    # the splash paints v{__version__}; guard that the symbol it reads stays importable
    assert __version__


def test_splash_always_uses_the_htb_look_regardless_of_theme(qtbot: QtBot) -> None:
    # the boot splash is ONE fixed loading screen — always the HTB / Parrot palette, whatever theme
    # the app is set to (owner decision). Guard that NO palette-derived colour leaks from the active
    # theme into the splash — check every colour the splash captures, not just a couple.
    htb = tokens.palette("htb")
    expected = {
        "_bg": htb.bg,
        "_surface": htb.surface,
        "_accent": htb.accent,
        "_secondary": htb.secondary,
        "_text": htb.text,
        "_muted": htb.text_muted,
        "_gold": htb.nav_label,
    }
    prev = tokens._active_theme
    try:
        for active in ("light", "amber", "dark", "synthwave"):
            tokens.set_active_theme(active)
            splash = make_splash()
            qtbot.addWidget(splash)
            for attr, hexval in expected.items():
                assert getattr(splash, attr).name() == QColor(hexval).name(), f"{active}:{attr}"
    finally:
        tokens.set_active_theme(prev)
