from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QKeyEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from oscprecon import guide
from oscprecon.branding import APP_NAME
from oscprecon.gui.assets import ICON, asset_path
from oscprecon.gui.theme import tokens
from oscprecon.gui.theme.tokens import palette


class HelpPopup(QFrame):
    """On-brand documentation popup with a TOC + markdown viewer.

    A frameless Qt.Popup, so it dismisses the moment the user clicks outside it (or presses Esc) —
    no OK button to hunt for. Reads the bundled guide (single source shared with `nabu-cli docs`),
    renders each page with the native QTextBrowser markdown engine (no QtWebEngine). Recolours from
    the active theme at construction; it is transient, so it is rebuilt on each open.
    """

    def __init__(self, theme_name: str = "htb", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        pal = palette(theme_name)
        accent = pal.accent
        self.setWindowFlags(Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.setFixedSize(900, 620)
        self.setObjectName("helpPopup")
        self.setStyleSheet(
            f"#helpPopup {{ background: {pal.bg}; border: 1px solid {accent};"
            f" border-radius: {tokens.RADIUS_LG}px; }}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_header(pal))

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._build_toc(pal))
        split.addWidget(self._build_view(pal))
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        root.addWidget(split, stretch=1)

        self._toc.setCurrentRow(0)  # load the first page

    def _build_header(self, pal: tokens.Palette) -> QWidget:
        header = QWidget()
        header.setObjectName("helpHeader")
        header.setStyleSheet(
            f"#helpHeader {{ background: {pal.surface};"
            f" border-top-left-radius: {tokens.RADIUS_LG}px;"
            f" border-top-right-radius: {tokens.RADIUS_LG}px;"
            f" border-bottom: 1px solid {pal.surface_alt}; }}"
        )
        row = QHBoxLayout(header)
        row.setContentsMargins(tokens.SPACE_LG, tokens.SPACE_MD, tokens.SPACE_MD, tokens.SPACE_MD)
        row.setSpacing(tokens.SPACE_SM)
        icon = QLabel()
        icon.setPixmap(QIcon(str(asset_path(ICON))).pixmap(22, 22))
        row.addWidget(icon)
        brand = QLabel(APP_NAME)
        brand.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {pal.text};")
        title = QLabel("Documentation")
        title.setStyleSheet(f"font-size: 15px; font-weight: 600; color: {pal.accent};")
        row.addWidget(brand)
        row.addWidget(title)
        row.addStretch(1)
        hint = QLabel("Esc or click away to close")
        hint.setStyleSheet(f"color: {pal.text_muted}; font-size: 11px;")
        row.addWidget(hint)
        close = QPushButton("✕")
        close.setFixedSize(26, 26)
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.setStyleSheet(
            f"QPushButton {{ border: none; color: {pal.text_muted}; font-size: 15px; }}"
            f" QPushButton:hover {{ color: {pal.accent}; }}"
        )
        close.clicked.connect(self.close)
        row.addWidget(close)
        return header

    def _build_toc(self, pal: tokens.Palette) -> QWidget:
        self._toc = QListWidget()
        self._toc.setObjectName("helpToc")
        self._toc.setFixedWidth(230)
        self._toc.setStyleSheet(
            f"#helpToc {{ background: {pal.surface}; border: none; padding: {tokens.SPACE_SM}px;"
            f" font-size: 13px; }}"
            f" #helpToc::item {{ padding: 7px 8px; border-radius: {tokens.RADIUS_SM}px;"
            f" color: {pal.text}; }}"
            f" #helpToc::item:selected {{ background: {pal.accent}; color: {pal.accent_text}; }}"
            f" #helpToc::item:hover {{ background: {pal.surface_alt}; }}"
        )
        for topic in guide.topics():
            item = QListWidgetItem(topic.title)
            item.setData(Qt.ItemDataRole.UserRole, topic.id)
            item.setToolTip(topic.summary)
            self._toc.addItem(item)
        self._toc.currentItemChanged.connect(self._on_select)
        return self._toc

    def _build_view(self, pal: tokens.Palette) -> QWidget:
        self._view = QTextBrowser()
        self._view.setOpenExternalLinks(False)  # offline — never launch a browser
        self._view.setStyleSheet(
            f"QTextBrowser {{ background: {pal.bg}; color: {pal.text}; border: none;"
            f" padding: {tokens.SPACE_LG}px; font-size: 14px; }}"
        )
        doc = self._view.document()
        if doc is not None:
            doc.setDefaultStyleSheet(
                f"h1 {{ color: {pal.accent}; }} h2 {{ color: {pal.accent}; }}"
                f" h3 {{ color: {pal.text}; }} a {{ color: {pal.accent}; }}"
                f" code {{ background: {pal.surface}; color: {pal.nav_label};"
                f" font-family: monospace; }} th {{ color: {pal.accent}; text-align: left; }}"
            )
        return self._view

    def _on_select(self, current: QListWidgetItem | None, _prev: object) -> None:
        if current is None:
            return
        topic_id = str(current.data(Qt.ItemDataRole.UserRole))
        try:
            self._view.setMarkdown(guide.load(topic_id))
        except KeyError:
            self._view.setMarkdown("# Not found")
        bar = self._view.verticalScrollBar()
        if bar is not None:
            bar.setValue(0)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.close()
            return
        super().keyPressEvent(event)

    def open_centered(self, over: QWidget | None) -> None:
        # centre over the parent window before showing (a Popup must be positioned pre-show)
        if over is not None:
            center = over.window().frameGeometry().center()
            self.move(center.x() - self.width() // 2, center.y() - self.height() // 2)
        self.show()
        self.setFocus()
