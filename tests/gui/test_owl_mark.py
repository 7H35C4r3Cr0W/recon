from pytestqt.qtbot import QtBot

from oscprecon.gui.widgets.owl_mark import OwlMark, _base_svg


def test_base_svg_strips_pupils_and_highlights() -> None:
    # OwlMark paints the pupils (#08252b) + highlights (#ffffff) live, so the still base must have
    # them removed while the rest of the mascot (gradients, sclera, body) survives.
    base = _base_svg().decode("utf-8")
    assert "#08252b" not in base  # pupils gone
    assert "#ffffff" not in base  # highlight circles gone
    assert "nbSclera" in base and "nbBody" in base  # the mascot itself is intact
    assert base.count("<circle") < _asset_circle_count()  # some circles were removed


def _asset_circle_count() -> int:
    from oscprecon.gui.assets import FURBY, asset_path

    return asset_path(FURBY).read_text(encoding="utf-8").count("<circle")


def test_owl_mark_constructs_and_paints(qtbot: QtBot) -> None:
    widget = OwlMark(34)
    qtbot.addWidget(widget)
    assert widget.size().width() == 34
    pix = widget.grab()  # forces paintEvent — base SVG + live pupils/highlights, no crash
    assert not pix.isNull()


def test_owl_mark_is_still_under_offscreen(qtbot: QtBot) -> None:
    # under the offscreen test platform the mark must NOT start repeating timers (they would keep
    # the event loop from going idle and hang idle-waiters). It renders as a still mark instead.
    widget = OwlMark(34)
    qtbot.addWidget(widget)
    widget.show()
    assert widget._live is False
    assert not widget._follow.isActive()
    assert not widget._next_blink.isActive()
