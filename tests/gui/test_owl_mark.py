from PySide6.QtCore import QEvent, QPointF, Qt
from PySide6.QtGui import QMouseEvent
from pytestqt.qtbot import QtBot

from oscprecon.gui.widgets.owl_mark import _REACTIONS, OwlMark, _base_svg


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


def test_owl_reactions_transform_and_render(qtbot: QtBot) -> None:
    # easter egg: each reaction drives a transform/tint and renders without error
    owl = OwlMark(60)
    qtbot.addWidget(owl)
    assert len(_REACTIONS) == 10

    owl._reaction = "spin"
    owl._on_react(0.25)
    assert abs(owl._angle - 90.0) < 1e-6  # quarter of a full spin

    owl._reaction = "cry"
    owl._on_react(0.5)
    assert owl._tear > 0.0 and owl._tint.alpha() > 0  # tear + blue mood wash

    for name, _dur in _REACTIONS:
        owl._reaction = name
        for t in (0.0, 0.5, 1.0):
            owl._on_react(t)
            owl.grab()

    owl._reset_reaction()
    assert owl._reaction == "" and owl._angle == 0.0 and owl._tint.alpha() == 0


def test_owl_left_click_plays_a_reaction(qtbot: QtBot) -> None:
    owl = OwlMark(60)
    qtbot.addWidget(owl)
    played: list[str | None] = []
    orig = owl.play_reaction

    def spy(name: str | None = None) -> None:
        played.append(name)
        orig(name)

    owl.play_reaction = spy  # type: ignore[method-assign]
    ev = QMouseEvent(
        QEvent.Type.MouseButtonPress,
        QPointF(5, 5),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    owl.mousePressEvent(ev)
    assert played  # a left click triggered a reaction
