from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import QButtonGroup, QToolButton, QVBoxLayout, QWidget

from oscprecon import config
from oscprecon.gui.theme import icons, tokens
from oscprecon.gui.theme.tokens import Palette

# Primary navigation rail — the app's backbone. Page items switch the central view; action items
# (notes, credentials) trigger a surface without owning a persistent page. The rail never decides
# what a destination does; it only announces `navigate(key)` and the MainWindow routes it.

# (key, label, icon, is_action, shortcut-hint)
_ITEMS: tuple[tuple[str, str, str, bool, str], ...] = (
    ("workspace", "Workspace", "home", False, "Ctrl+0"),
    ("recon", "Recon", "target", False, ""),
    ("exploit", "Exploitation", "bolt", False, ""),
    ("pivot", "Pivot", "pivot", False, ""),
    ("graph", "Graph", "graph", False, "Ctrl+G"),
    ("findings", "Findings", "flag", False, ""),
    ("credentials", "Credentials", "key", True, ""),
    ("notes", "Notes", "note", True, ""),
    ("report", "Report", "chart", False, "Ctrl+R"),
    ("activity", "Activity", "pulse", False, ""),
)

PAGE_KEYS = tuple(key for key, _, _, is_action, _ in _ITEMS if not is_action)
ACTION_KEYS = tuple(key for key, _, _, is_action, _ in _ITEMS if is_action)

# wide enough that the longest label ("Exploitation") never elides; collapsed shows icons only.
_WIDTH_EXPANDED = 184
_WIDTH_COLLAPSED = 54
_PREF_COLLAPSED = "nav_collapsed"


class NavRail(QWidget):
    navigate = Signal(str)

    def __init__(self, theme_name: str = "dark", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("navRail")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)  # so QSS bg actually paints
        self._collapsed = config.load_prefs().get(_PREF_COLLAPSED) == "1"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            tokens.SPACE_SM, tokens.SPACE_MD, tokens.SPACE_SM, tokens.SPACE_MD
        )
        layout.setSpacing(tokens.SPACE_XS)

        # collapse/expand toggle — a chevron at the top; tooltips keep labels reachable collapsed
        self._toggle = QToolButton()
        self._toggle.setObjectName("navToggle")
        self._toggle.setAutoRaise(True)
        self._toggle.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._toggle.clicked.connect(self._toggle_collapsed)
        layout.addWidget(self._toggle)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._buttons: dict[str, QToolButton] = {}
        for key, label, _icon, is_action, hint in _ITEMS:
            button = QToolButton()
            button.setText("  " + label)
            button.setIconSize(QSize(tokens.ICON_MD, tokens.ICON_MD))  # icon set by restyle() below
            button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            button.setCheckable(not is_action)  # action items don't hold a persistent state
            button.setAutoRaise(True)
            button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            tip = f"{label} ({hint})" if hint else label
            button.setToolTip(tip)
            button.setAccessibleName(label)
            button.clicked.connect(lambda _checked=False, k=key: self.navigate.emit(k))
            if not is_action:
                self._group.addButton(button)
            self._buttons[key] = button
            layout.addWidget(button)
        layout.addStretch(1)
        self.restyle(theme_name)
        self._apply_collapsed()

    def _apply_collapsed(self) -> None:
        # icon-only + narrow when collapsed; icon+label + wide when expanded. Tooltips stay on so a
        # collapsed rail is still navigable.
        style = (
            Qt.ToolButtonStyle.ToolButtonIconOnly
            if self._collapsed
            else Qt.ToolButtonStyle.ToolButtonTextBesideIcon
        )
        for button in self._buttons.values():
            button.setToolButtonStyle(style)
        self.setFixedWidth(_WIDTH_COLLAPSED if self._collapsed else _WIDTH_EXPANDED)
        self._toggle.setText("»" if self._collapsed else "«")
        self._toggle.setToolTip("Expand sidebar" if self._collapsed else "Collapse sidebar")
        self._toggle.setAccessibleName(self._toggle.toolTip())

    def _toggle_collapsed(self) -> None:
        self._collapsed = not self._collapsed
        self._apply_collapsed()
        # persist (load-merge-save keeps unrelated prefs intact, like save_settings does)
        prefs = config.load_prefs()
        prefs[_PREF_COLLAPSED] = "1" if self._collapsed else "0"
        config.save_prefs(prefs)

    def restyle(self, theme_name: str) -> None:
        pal: Palette = tokens.palette(theme_name)
        self.setStyleSheet(
            f"#navRail {{ background:{pal.surface}; border-right:1px solid {pal.border}; }}"
            "QToolButton {"
            f" color:{pal.nav_label}; background:transparent; border:none; text-align:left;"
            f" padding:{tokens.SPACE_SM}px {tokens.SPACE_MD}px; border-radius:{tokens.RADIUS_SM}px;"
            f" min-height:{tokens.CONTROL_HEIGHT}px; }}"
            f" QToolButton:hover {{ color:{pal.text}; background:{pal.surface_alt}; }}"
            f" QToolButton:checked {{ color:{pal.accent}; background:{pal.selection};"
            f" font-weight:600; }}"
            f" QToolButton:focus {{ border:2px solid {pal.focus}; }}"
            f" QToolButton:disabled {{ color:{pal.border}; }}"
            f" #navToggle {{ color:{pal.nav_label}; font-size:16px; font-weight:700;"
            f" text-align:center; }}"
            f" #navToggle:hover {{ color:{pal.accent}; background:{pal.surface_alt}; }}"
        )
        for key, _, icon, _, _ in _ITEMS:
            self._buttons[key].setIcon(icons.get_icon(icon, pal.nav_label, tokens.ICON_MD))

    def set_current(self, key: str) -> None:
        # reflect the active page WITHOUT re-emitting navigate (used to sync after a view change, or
        # to bounce the highlight back after an action item is clicked)
        button = self._buttons.get(key)
        if button is None or not button.isCheckable():
            return
        was = self._group.blockSignals(True)
        button.setChecked(True)
        self._group.blockSignals(was)

    def set_enabled_keys(self, enabled: bool) -> None:
        # everything except Workspace needs a loaded profile
        for key, button in self._buttons.items():
            button.setEnabled(enabled or key == "workspace")
