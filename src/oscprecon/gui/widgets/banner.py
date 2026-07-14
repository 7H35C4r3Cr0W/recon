from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QToolButton, QWidget

from oscprecon.gui.theme import tokens
from oscprecon.gui.theme.tokens import Palette

# A compact, dismissible inline banner for the latest actionable feedback (blocked command, missing
# tool, parse warning, error, success). The output pane still logs the full stream; this just makes
# the most recent significant state impossible to miss. Colour-coded but always carries text, so the
# meaning never depends on colour alone.

_KIND_FIELD = {
    "info": "info",
    "success": "success",
    "warning": "warning",
    "error": "error",
    "loading": "accent",
}
_KIND_MARK = {
    "info": "ℹ",
    "success": "✓",
    "warning": "⚠",
    "error": "✕",
    "loading": "…",
}


class Banner(QWidget):
    def __init__(self, theme_name: str = "dark", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("banner")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._theme = theme_name

        self._mark = QLabel("")
        self._msg = QLabel("")
        self._msg.setWordWrap(True)
        self._msg.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._dismiss = QToolButton()
        self._dismiss.setText("✕")
        self._dismiss.setAutoRaise(True)
        self._dismiss.setToolTip("Dismiss")
        self._dismiss.setAccessibleName("Dismiss message")
        self._dismiss.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._dismiss.clicked.connect(self.clear)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(
            tokens.SPACE_MD, tokens.SPACE_SM, tokens.SPACE_SM, tokens.SPACE_SM
        )
        layout.setSpacing(tokens.SPACE_SM)
        layout.addWidget(self._mark)
        layout.addWidget(self._msg, stretch=1)
        layout.addWidget(self._dismiss)
        self.setVisible(False)

    def show_message(self, kind: str, text: str) -> None:
        pal: Palette = tokens.palette(self._theme)
        color = str(getattr(pal, _KIND_FIELD.get(kind, "info")))
        self._mark.setText(_KIND_MARK.get(kind, "ℹ"))
        self._mark.setStyleSheet(f"color:{color}; font-weight:600;")
        self._msg.setText(text)
        self._msg.setStyleSheet(f"color:{color};")
        self.setStyleSheet(
            f"#banner {{ border-left:4px solid {color};"
            f" border:1px solid {pal.border}; border-left:4px solid {color};"
            f" border-radius:{tokens.RADIUS_SM}px; background:{pal.surface}; }}"
        )
        self.setVisible(True)

    def clear(self) -> None:
        self._msg.setText("")
        self.setVisible(False)

    def restyle(self, theme_name: str) -> None:
        self._theme = theme_name
