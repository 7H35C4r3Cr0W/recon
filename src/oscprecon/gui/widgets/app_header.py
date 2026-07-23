from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QToolButton, QVBoxLayout, QWidget

from oscprecon.gui.theme import icons, tokens
from oscprecon.gui.theme.tokens import Palette
from oscprecon.gui.widgets.owl_mark import OwlMark

# Compact application header: one consistent strip that always answers "which project, which target,
# can I edit, is anything running, how do I get back to the workspace". Purely presentational — the
# MainWindow feeds it state; it never reaches into a profile.


class AppHeader(QWidget):
    home_requested = Signal()

    def __init__(self, theme_name: str = "dark", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("appHeader")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)  # so QSS bg actually paints

        layout = QHBoxLayout(self)
        layout.setContentsMargins(
            tokens.SPACE_MD, tokens.SPACE_SM, tokens.SPACE_MD, tokens.SPACE_SM
        )
        layout.setSpacing(tokens.SPACE_MD)

        self._home = QToolButton()
        self._home.setObjectName("hdrHome")
        self._home.setText(" Workspace")
        self._home.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._home.setToolTip("Back to the workspace dashboard (Ctrl+0)")
        self._home.setAccessibleName("Back to workspace")
        self._home.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._home.clicked.connect(self.home_requested)

        self._project = QLabel("No project loaded")
        self._project.setObjectName("hdrProject")
        self._target = QLabel("")
        self._target.setObjectName("hdrTarget")
        self._read_only = QLabel("READ-ONLY")
        self._read_only.setObjectName("hdrReadOnly")
        self._read_only.setVisible(False)
        self._tasks = QLabel("")
        self._tasks.setObjectName("hdrTasks")

        # brand mark (top-right): the Nabu wordmark with the owl-furby mascot below it — the
        # maintainer's mark. Purely decorative; carries a tooltip, excluded from tab focus.
        self._brand = QWidget()
        self._brand.setObjectName("hdrBrand")
        self._brand.setToolTip("Nabu — Local Recon Workspace")
        brand_col = QVBoxLayout(self._brand)
        brand_col.setContentsMargins(0, 0, 0, 0)
        brand_col.setSpacing(0)
        self._brand_name = QLabel("Nabu")
        self._brand_name.setObjectName("hdrBrandName")
        self._brand_name.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        # the mascot lives on a WIDE stage that fills the header gap, so its click easter egg can
        # run across that space (kamehameha, moonwalk, jailbreak…). It rests at the stage's right,
        # just left of the wordmark; the wordmark stays in the brand column.
        self._furby = OwlMark(34)
        brand_col.addWidget(self._brand_name, alignment=Qt.AlignmentFlag.AlignHCenter)

        layout.addWidget(self._home)
        layout.addWidget(self._project)
        layout.addWidget(self._target)
        layout.addWidget(self._read_only)
        layout.addWidget(
            self._furby, 1
        )  # expanding: takes the gap between the target and the brand
        layout.addWidget(self._tasks)
        layout.addWidget(self._brand)
        self.restyle(theme_name)

    def restyle(self, theme_name: str) -> None:
        pal: Palette = tokens.palette(theme_name)
        self.setStyleSheet(
            f"#appHeader {{ background:{pal.surface}; border-bottom:1px solid {pal.border}; }}"
            f"#appHeader QLabel {{ color:{pal.text}; }}"
            f"#hdrProject {{ font-weight:600; }}"
            f"#hdrTarget {{ color:{pal.text_muted}; }}"
            f"#hdrReadOnly {{ color:{pal.warning}; border:1px solid {pal.warning};"
            f" border-radius:{tokens.RADIUS_SM}px; padding:0 {tokens.SPACE_SM}px; }}"
            f"#hdrTasks {{ color:{pal.accent}; }}"
            f"#hdrBrandName {{ color:{pal.accent}; font-weight:700;"
            f" font-size:{tokens.FONT_SIZE_SM}px; letter-spacing:1px; }}"
            "#hdrHome {"
            f" color:{pal.text}; background:transparent; border:1px solid {pal.border};"
            f" border-radius:{tokens.RADIUS_SM}px; padding:3px {tokens.SPACE_MD}px; }}"
            f" #hdrHome:hover {{ border-color:{pal.accent}; color:{pal.accent}; }}"
            f" #hdrHome:focus {{ border:2px solid {pal.focus}; }}"
        )
        self._home.setIcon(icons.get_icon("home", pal.text, tokens.ICON_SM))

    def set_profile(self, name: str, ip: str, hostname: str, *, read_only: bool) -> None:
        self._project.setText(name)
        target = ip + (f" · {hostname}" if hostname else "")
        self._target.setText(target)
        self._read_only.setVisible(read_only)

    def clear_profile(self) -> None:
        self._project.setText("No project loaded")
        self._target.setText("")
        self._read_only.setVisible(False)

    def set_task_count(self, count: int) -> None:
        self._tasks.setText(f"● {count} running" if count > 0 else "")
