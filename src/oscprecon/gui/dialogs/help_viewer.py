from __future__ import annotations

import contextlib
import math

from PySide6.QtCore import QByteArray, QPointF, QRectF, Qt
from PySide6.QtGui import (
    QCloseEvent,
    QColor,
    QIcon,
    QKeyEvent,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPaintEvent,
    QPen,
    QRadialGradient,
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from oscprecon import config, guide
from oscprecon.branding import APP_NAME
from oscprecon.gui.assets import FURBY, ICON, asset_path
from oscprecon.gui.theme import tokens
from oscprecon.gui.theme.tokens import palette


def _rgba(hex_str: str, a: float) -> str:
    c = QColor(hex_str)
    return f"rgba({c.red()},{c.green()},{c.blue()},{a})"


class HelpPopup(QFrame):
    """On-brand documentation window with a TOC + markdown viewer.

    A REAL top-level window (not a popup): the window manager gives it move, resize, maximize and
    minimize, it appears in the taskbar, and it stays open beside the app while you work — the
    operator decides how big the docs are and where they sit. Its size/position persist between
    sessions. Reads the bundled guide (single source shared with `nabu-cli docs`), rendering each
    page with the native QTextBrowser markdown engine (no QtWebEngine).
    """

    def __init__(self, theme_name: str = "htb", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        pal = palette(theme_name)
        self._pal = pal
        self._furby = QSvgRenderer(QByteArray(asset_path(FURBY).read_bytes()))
        accent = pal.accent
        # a normal window with the full system title bar: drag it anywhere, resize from any edge,
        # maximize, minimize, snap it beside the main window. (It used to be a frameless Qt.Popup
        # pinned to a fixed 900×620 — hence "why can't I move or resize the docs?")
        self.setWindowFlags(
            Qt.WindowType.Window
            | Qt.WindowType.WindowMinMaxButtonsHint
            | Qt.WindowType.WindowCloseButtonHint
        )
        self.setWindowTitle(f"{APP_NAME} — Documentation")
        self.setWindowIcon(QIcon(str(asset_path(ICON))))
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.setMinimumSize(420, 320)  # a floor that keeps the TOC + a readable column
        self.resize(900, 620)
        self.setObjectName("helpPopup")
        self.setStyleSheet(
            f"#helpPopup {{ background: {pal.bg}; border: 1px solid {accent};"
            f" border-radius: {tokens.RADIUS_LG}px; }}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_header(pal))

        self._split = QSplitter(Qt.Orientation.Horizontal)
        self._split.addWidget(self._build_toc(pal))
        self._split.addWidget(self._build_view(pal))
        self._split.setStretchFactor(0, 0)
        self._split.setStretchFactor(1, 1)
        root.addWidget(self._split, stretch=1)

        self._toc.setCurrentRow(0)  # load the first page
        self._restore_geometry()

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
        hint = QLabel("Esc to close · drag or resize this window as you like")
        hint.setStyleSheet(f"color: {pal.text_muted}; font-size: 11px;")
        row.addWidget(hint)
        return header

    def _build_toc(self, pal: tokens.Palette) -> QWidget:
        self._toc = QListWidget()
        self._toc.setObjectName("helpToc")
        # a floor and a ceiling instead of a fixed width, so the splitter can be dragged to give
        # the page more room on a small window (or the TOC more on a wide one)
        self._toc.setMinimumWidth(150)
        self._toc.setMaximumWidth(360)
        self._toc.resize(230, self._toc.height())
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
        # semi-transparent so the DBZ furby skin painted behind the popup glows through the docs
        self._view.setStyleSheet(
            f"QTextBrowser {{ background: {_rgba(pal.bg, 0.70)}; color: {pal.text}; border: none;"
            f" padding: {tokens.SPACE_LG}px; font-size: 14px; }}"
        )
        vp = self._view.viewport()
        if vp is not None:
            vp.setAutoFillBackground(False)
            vp.setStyleSheet("background: transparent;")
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

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)  # frame bg + border from the stylesheet
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        clip = QPainterPath()
        clip.addRoundedRect(QRectF(self.rect()), float(tokens.RADIUS_LG), float(tokens.RADIUS_LG))
        p.setClipPath(clip)
        self._paint_skin(p)
        p.end()

    def _paint_skin(self, p: QPainter) -> None:
        # a low-opacity DBZ skin behind the docs: the furby powering up (super-saiyan aura) and
        # cupping a kamehameha ball, on a cool energy backdrop. Faint, so the text stays readable.
        w, h = float(self.width()), float(self.height())
        ac = QColor(self._pal.accent)
        gold = QColor("#ffcf4a")
        eg = QRadialGradient(w * 0.80, h * 0.74, w * 0.6)
        eg.setColorAt(0.0, QColor(ac.red(), ac.green(), ac.blue(), 42))
        eg.setColorAt(0.5, QColor(120, 80, 180, 24))
        eg.setColorAt(1.0, QColor(0, 0, 0, 0))
        # start the skin where the TOC ends — the splitter is draggable now, so this can't be a
        # hard-coded 230px or the glow bleeds under the contents list.
        toc_w = float(max(0, self._toc.width()))
        p.fillRect(QRectF(toc_w, 44.0, max(0.0, w - toc_w), h - 44.0), eg)
        p.setPen(QPen(QColor(255, 255, 255, 13), 2))
        for i in range(12):
            x = 300.0 + i * 60.0
            p.drawLine(QPointF(x, h), QPointF(x + 130.0, h - 240.0))
        cx, cy, sz = w * 0.72, h * 0.60, h * 0.68
        p.setPen(Qt.PenStyle.NoPen)
        p.setOpacity(0.26)
        aura = QRadialGradient(cx, cy - sz * 0.04, sz * 0.9)
        aura.setColorAt(0.0, QColor(gold.red(), gold.green(), gold.blue(), 210))
        aura.setColorAt(0.5, QColor(255, 130, 30, 90))
        aura.setColorAt(1.0, QColor(255, 120, 20, 0))
        p.setBrush(aura)
        p.drawEllipse(QPointF(cx, cy - sz * 0.04), sz * 0.82, sz * 0.98)
        flame = QPainterPath()
        n = 12
        for i in range(n + 1):
            ang = math.pi + (i / n) * math.pi
            rad = sz * (0.55 + 0.28 * (0.5 + 0.5 * math.sin(i * 1.7)))
            px = cx + math.cos(ang) * rad * 0.62
            py = (cy - sz * 0.04) + math.sin(ang) * rad
            (flame.moveTo if i == 0 else flame.lineTo)(px, py)
        flame.lineTo(cx + sz * 0.3, cy + sz * 0.5)
        flame.lineTo(cx - sz * 0.3, cy + sz * 0.5)
        flame.closeSubpath()
        fg = QLinearGradient(cx, cy - sz, cx, cy + sz * 0.5)
        fg.setColorAt(0.0, QColor(255, 246, 200, 150))
        fg.setColorAt(0.5, QColor(gold.red(), gold.green(), gold.blue(), 110))
        fg.setColorAt(1.0, QColor(255, 122, 31, 10))
        p.setBrush(fg)
        p.drawPath(flame)
        p.setOpacity(0.55)
        p.save()
        p.translate(cx, cy)
        p.rotate(-8)
        p.scale(1.05, 1.05)
        p.translate(-sz / 2, -sz / 2)
        self._furby.render(p, QRectF(0.0, 0.0, sz, sz))
        p.restore()
        bx, by, r = cx - sz * 0.42, cy + sz * 0.14, sz * 0.17
        p.setOpacity(0.30)
        ball = QRadialGradient(bx, by, r * 1.9)
        ball.setColorAt(0.0, QColor(255, 255, 255, 230))
        ball.setColorAt(0.45, QColor(92, 208, 255, 150))
        ball.setColorAt(1.0, QColor(31, 143, 255, 0))
        p.setBrush(ball)
        p.drawEllipse(QPointF(bx, by), r * 1.9, r * 1.9)
        p.setOpacity(1.0)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.close()
            return
        super().keyPressEvent(event)

    _GEOMETRY_KEY = "help"

    def _restore_geometry(self) -> bool:
        # come back the size and place the operator left it. Best-effort: a stale/corrupt blob (or
        # a screen that no longer exists) must never stop the docs from opening.
        blob = config.window_geometry(self._GEOMETRY_KEY)
        if not blob:
            return False
        try:
            return bool(self.restoreGeometry(QByteArray.fromHex(QByteArray(blob.encode("ascii")))))
        except (ValueError, UnicodeEncodeError):
            return False

    def store_geometry(self) -> None:
        if self.isMinimized() or self.isFullScreen():
            return  # never persist a minimized/fullscreen frame — it reopens unusable
        with contextlib.suppress(OSError):
            config.save_window_geometry(
                self._GEOMETRY_KEY, self.saveGeometry().toHex().toStdString()
            )

    def closeEvent(self, event: QCloseEvent) -> None:
        self.store_geometry()
        super().closeEvent(event)

    def open_centered(self, over: QWidget | None) -> None:
        # first open: centre over the main window. After that the remembered geometry wins, so the
        # docs reopen exactly where the operator parked them.
        if not self._restore_geometry() and over is not None:
            center = over.window().frameGeometry().center()
            self.move(center.x() - self.width() // 2, center.y() - self.height() // 2)
        self.show()
        self.raise_()
        self.activateWindow()
