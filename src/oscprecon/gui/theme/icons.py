from __future__ import annotations

from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QToolButton

from oscprecon.gui.theme import tokens

# A small, consistent set of stroke glyphs (24x24, 2px stroke) rendered in a themeable colour. Kept
# minimal on purpose — one legible visual language for icon-only controls. `{c}` is the stroke
# colour, substituted at build time; no external files, so icons render offline.
_GLYPHS: dict[str, str] = {
    "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="M20 20 L15.5 15.5"/>',
    "run": '<path d="M8 5 L19 12 L8 19 Z" fill="{c}" stroke="none"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="2" fill="{c}" stroke="none"/>',
    "refresh": '<path d="M20 12 a8 8 0 1 1 -2.3 -5.6"/><path d="M20 4 V8 H16"/>',
    "folder": '<path d="M3 6 h6 l2 2 h10 v10 h-18 Z"/>',
    "add": '<path d="M12 5 V19 M5 12 H19"/>',
    "graph": '<circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="16" r="2.5"/>'
    '<circle cx="13" cy="6" r="2.5"/><path d="M7.8 16.6 L11.2 8 M14.6 7.5 L17 13.8"/>',
}


def _svg(name: str, color: str) -> str:
    body = _GLYPHS[name].replace("{c}", color)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        f'fill="none" stroke="{color}" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
    )


def get_icon(name: str, color: str, size: int = tokens.ICON_MD) -> QIcon:
    renderer = QSvgRenderer(QByteArray(_svg(name, color).encode()))
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return QIcon(pixmap)


def icon_button(
    name: str,
    tooltip: str,
    *,
    color: str,
    size: int = tokens.ICON_MD,
) -> QToolButton:
    # why: every icon-only control MUST carry a tooltip + accessible name + keyboard focus (§ a11y).
    # Enforce it here so no icon button can ship without them.
    if not tooltip.strip():
        raise ValueError("icon_button requires a non-empty tooltip / accessible name")
    button = QToolButton()
    button.setIcon(get_icon(name, color, size))
    button.setIconSize(QSize(size, size))
    button.setToolTip(tooltip)
    button.setAccessibleName(tooltip)
    button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    button.setAutoRaise(True)
    return button


def available_icons() -> tuple[str, ...]:
    return tuple(_GLYPHS)
