from oscprecon.gui.theme import tokens


def _lin(channel: int) -> float:
    c = channel / 255
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def _luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def _contrast(a: str, b: str) -> float:
    la, lb = _luminance(a), _luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


# (foreground, background, min ratio): 4.5 for normal text, 3.0 for large text / UI accents (AA)
_PAIRS = (
    ("text", "bg", 4.5),
    ("text", "surface", 4.5),
    ("text_muted", "bg", 4.5),
    ("text_muted", "surface", 4.5),
    ("nav_label", "bg", 3.0),
    ("accent", "bg", 3.0),
    ("accent_text", "accent", 4.5),
)


def test_every_theme_meets_wcag_aa_contrast() -> None:
    for name in tokens._PALETTES:
        pal = tokens.palette(name)
        for fg, bg, threshold in _PAIRS:
            ratio = _contrast(getattr(pal, fg), getattr(pal, bg))
            assert ratio >= threshold, f"{name}: {fg}/{bg} = {ratio:.2f} < {threshold} (WCAG AA)"
