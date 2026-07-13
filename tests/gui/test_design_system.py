import pytest
from pytestqt.qtbot import QtBot

from oscprecon.gui.theme import icons, styles, tokens


def test_both_palettes_define_every_token() -> None:
    fields = tokens.Palette.__dataclass_fields__
    for pal in (tokens.DARK, tokens.LIGHT):
        for name in fields:
            value = getattr(pal, name)
            assert isinstance(value, str) and value.startswith("#"), name
            assert len(value) == 7  # #rrggbb


def test_palette_selector() -> None:
    assert tokens.palette("dark") is tokens.DARK
    assert tokens.palette("light") is tokens.LIGHT
    assert tokens.palette("nonsense") is tokens.LIGHT  # default


def test_style_builders_embed_token_colors() -> None:
    pal = tokens.DARK
    assert pal.accent in styles.primary_button(pal)
    assert pal.border in styles.secondary_button(pal)
    assert pal.focus in styles.focus_ring(pal)
    assert styles.status_color("error", pal) == pal.error
    assert pal.warning in styles.badge("warning", pal)


def test_shift_helpers_stay_in_range() -> None:
    assert styles._lighten("#c9a227").startswith("#")
    assert styles._darken("#000000") == "#000000"  # clamps, never underflows
    assert styles._lighten("#ffffff") == "#ffffff"  # clamps, never overflows


def test_icon_set_renders(qtbot: QtBot) -> None:
    for name in icons.available_icons():
        icon = icons.get_icon(name, tokens.DARK.accent)
        assert not icon.isNull(), name


def test_icon_button_enforces_accessibility(qtbot: QtBot) -> None:
    button = icons.icon_button("search", "Find in graph", color=tokens.DARK.text)
    qtbot.addWidget(button)
    assert button.toolTip() == "Find in graph"
    assert button.accessibleName() == "Find in graph"
    assert button.focusPolicy() == button.focusPolicy().StrongFocus
    with pytest.raises(ValueError):
        icons.icon_button("search", "   ", color=tokens.DARK.text)
