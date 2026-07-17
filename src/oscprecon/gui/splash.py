from __future__ import annotations

import math

from PySide6.QtCore import QByteArray, QElapsedTimer, QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import (
    QColor,
    QFont,
    QGuiApplication,
    QLinearGradient,
    QPainter,
    QPaintEvent,
    QPen,
    QRadialGradient,
    QShowEvent,
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QWidget

from oscprecon import __version__
from oscprecon.branding import APP_NAME
from oscprecon.gui.assets import FURBY, asset_path
from oscprecon.gui.theme import tokens

# Nabu — "Laser-Dodge" loading splash. The owl-furby ducks, leans and hops through a grid of red
# security lasers (Mission-Impossible style) while the app boots, with a cyan recon scan sweeping
# across and a rotating status line below. Native Qt (a single elapsed clock drives every beat) —
# no QtWebEngine (fragile in the Kali VM), offline, and it degrades gracefully: a splash failure
# never blocks startup (§27). Recolours from the active palette; laser red stays fixed.

# ---- geometry (card-local px) --------------------------------------------------------------------
_CARD_W = 640
_TOPBAR_H = 40
_CHAMBER_H = 262
_FOOTER_H = 128
_CARD_H = _TOPBAR_H + _CHAMBER_H + _FOOTER_H
_MARGIN = 26  # transparent gutter around the card for the drop shadow
_LOOP_MS = 5000  # the evasion loop, matching the design
_MIN_SHOW_MS = 1900  # keep the splash up at least this long so the animation is actually seen

# fixed non-theme colours (the danger red is rationed to the tripwires)
_LASER = QColor("#ff3b5c")
_LASER_SOFT = QColor(255, 59, 92, 130)
_GREEN = QColor("#3ddc84")
_PINK = QColor("#ff5c7a")
_AMBER = QColor("#f5c518")

_STATUS = (
    "probing intrusion detection…",
    "mapping local attack surface…",
    "arming recon modules…",
    "loading HackTricks (offline)…",
    "weaving past the tripwires…",
    "establishing secure tunnel…",
    "indexing service fingerprints…",
)


def _ease(x: float) -> float:
    # smoothstep — a cheap ease-in-out that mimics the CSS timing function
    x = max(0.0, min(1.0, x))
    return x * x * (3.0 - 2.0 * x)


def _kf(t: float, pts: list[tuple[float, float]]) -> float:
    # piecewise keyframe interpolation over t∈[0,1); flat where consecutive points repeat a value
    for i in range(len(pts) - 1):
        p0, v0 = pts[i]
        p1, v1 = pts[i + 1]
        if p0 <= t <= p1:
            if p1 <= p0:
                return v1
            return v0 + (v1 - v0) * _ease((t - p0) / (p1 - p0))
    return pts[-1][1]


# mascot evasion beats (translate / rotate / scale), keyed to the loop fraction
_EV_TX = [
    (0.0, 0.0),
    (0.10, -22.0),
    (0.24, -8.0),
    (0.38, 6.0),
    (0.52, 24.0),
    (0.66, 6.0),
    (0.78, -4.0),
    (0.90, -14.0),
    (1.0, 0.0),
]
_EV_TY = [
    (0.0, 0.0),
    (0.10, 2.0),
    (0.24, 26.0),
    (0.38, -4.0),
    (0.52, 4.0),
    (0.66, -30.0),
    (0.78, 9.0),
    (0.90, -2.0),
    (1.0, 0.0),
]
_EV_ROT = [
    (0.0, 0.0),
    (0.10, -7.0),
    (0.24, -2.0),
    (0.38, 3.0),
    (0.52, 9.0),
    (0.66, 2.0),
    (0.78, -3.0),
    (0.90, -5.0),
    (1.0, 0.0),
]
_EV_SX = [
    (0.0, 1.0),
    (0.10, 1.0),
    (0.24, 1.07),
    (0.38, 1.0),
    (0.66, 1.0),
    (0.78, 1.05),
    (0.90, 1.0),
    (1.0, 1.0),
]
_EV_SY = [
    (0.0, 1.0),
    (0.10, 0.99),
    (0.24, 0.82),
    (0.38, 1.02),
    (0.52, 0.98),
    (0.66, 1.07),
    (0.78, 0.90),
    (0.90, 1.0),
    (1.0, 1.0),
]
_DROP_TY = [(0.0, -14.0), (0.08, -14.0), (0.22, 74.0), (0.29, 74.0), (0.46, -14.0), (1.0, -14.0)]
_RISE_TY = [(0.0, 44.0), (0.50, 44.0), (0.63, -6.0), (0.73, -6.0), (0.88, 44.0), (1.0, 44.0)]
_RISE_OP = [(0.0, 0.55), (0.50, 0.55), (0.63, 1.0), (0.73, 1.0), (0.88, 0.55), (1.0, 0.55)]
_SWEEP_ROT = [(0.0, -19.0), (0.28, -19.0), (0.50, 13.0), (0.72, -19.0), (1.0, -19.0)]
_SHADOW_SX = [(0.0, 1.0), (0.24, 1.18), (0.52, 1.05), (0.66, 0.68), (1.0, 1.0)]
_SHADOW_TX = [(0.0, 0.0), (0.24, 0.0), (0.52, 14.0), (0.66, 0.0), (1.0, 0.0)]
_SHADOW_OP = [(0.0, 0.5), (0.24, 0.6), (0.52, 0.5), (0.66, 0.28), (1.0, 0.5)]
_FLASH_OP = [
    (0.0, 0.0),
    (0.19, 0.0),
    (0.24, 0.55),
    (0.30, 0.0),
    (0.61, 0.0),
    (0.66, 0.5),
    (0.72, 0.0),
    (1.0, 0.0),
]


class NabuSplash(QWidget):
    """Frameless, centred, animated boot splash. show()/finish(window) mirror QSplashScreen."""

    def __init__(self) -> None:
        super().__init__(None, Qt.WindowType.SplashScreen | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        # why: purely decorative chrome — it lingers on top for ~2s after the window is shown, so it
        # must never intercept clicks meant for the window beneath, nor steal focus on show.
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
        self.setFixedSize(_CARD_W + 2 * _MARGIN, _CARD_H + 2 * _MARGIN)
        self._center_on_screen()

        pal = tokens.active_palette()  # recolour from the active theme; laser red stays fixed
        self._bg = QColor(pal.bg)
        self._is_light = self._bg.lightnessF() > 0.5  # keep the chamber a dark room on light themes
        self._surface = QColor(pal.surface)
        self._accent = QColor(pal.accent)
        self._secondary = QColor(pal.secondary)
        self._text = QColor(pal.text)
        self._muted = QColor(pal.text_muted)
        self._gold = QColor(pal.nav_label)

        self._svg = QSvgRenderer(QByteArray(asset_path(FURBY).read_bytes()))
        self._clock = QElapsedTimer()
        self._clock.start()
        self._test_ms: int | None = None  # tests pin the frame time; None => live clock

        self._timer = QTimer(self)
        self._timer.setInterval(33)  # ~30 fps
        self._timer.timeout.connect(self.update)
        # Don't animate under the offscreen test platform — a repeating timer there keeps the event
        # loop from ever going idle (which hangs idle-waiters); it renders as a still frame instead.
        self._live = QGuiApplication.platformName() != "offscreen"

    def _center_on_screen(self) -> None:
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            geo = screen.availableGeometry()
            self.move(geo.center().x() - self.width() // 2, geo.center().y() - self.height() // 2)

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        if self._live and not self._timer.isActive():
            self._clock.restart()
            self._timer.start()

    def finish(self, window: QWidget) -> None:
        # The animation is frozen during boot (the event loop is blocked building MainWindow), so
        # re-anchor the clock here and play a fresh _MIN_SHOW_MS of animation once the loop is live,
        # then close — that guarantees the evasion loop is actually seen rather than flashing by.
        self._clock.restart()  # re-anchor so the loop plays from the top during the event loop
        QTimer.singleShot(_MIN_SHOW_MS, self._graceful_close)

    def _graceful_close(self) -> None:
        self._timer.stop()
        self.close()

    # ---- painting --------------------------------------------------------------------------------
    def _elapsed(self) -> int:
        return self._test_ms if self._test_ms is not None else self._clock.elapsed()

    def paintEvent(self, event: QPaintEvent) -> None:
        ms = self._elapsed()
        t = (ms % _LOOP_MS) / _LOOP_MS  # loop fraction 0..1
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        x0, y0 = float(_MARGIN), float(_MARGIN)
        card = QRectF(x0, y0, _CARD_W, _CARD_H)
        self._paint_shadow(p, card)
        p.save()
        p.setClipPath(_rounded_path(card, 26))
        self._paint_card_bg(p, card)
        self._paint_topbar(p, x0, y0)
        chamber_top = y0 + _TOPBAR_H
        self._paint_chamber(p, x0, chamber_top, t, ms)
        p.restore()  # drop the clip so the footer border draws crisp
        self._paint_footer(p, x0, chamber_top + _CHAMBER_H, ms)
        # card outline
        p.setPen(QPen(QColor(self._accent.red(), self._accent.green(), self._accent.blue(), 72), 1))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(_rounded_path(card, 26))
        p.end()

    def _paint_shadow(self, p: QPainter, card: QRectF) -> None:
        p.setPen(Qt.PenStyle.NoPen)
        for i in range(6):
            spread = (i + 1) * 3.0
            p.setBrush(QColor(0, 0, 0, 16))
            p.drawPath(
                _rounded_path(card.adjusted(-spread, -spread + 6, spread, spread + 10), 26 + spread)
            )

    def _paint_card_bg(self, p: QPainter, card: QRectF) -> None:
        grad = QRadialGradient(
            card.center().x(), card.top() + card.height() * 0.06, card.width() * 1.1
        )
        grad.setColorAt(0.0, _lift(self._surface, 6))
        grad.setColorAt(0.62, self._bg)
        grad.setColorAt(1.0, _dim(self._bg, 10))
        p.fillRect(card, grad)

    def _paint_topbar(self, p: QPainter, x0: float, y0: float) -> None:
        bar = QRectF(x0, y0, _CARD_W, _TOPBAR_H)
        p.fillRect(bar, QColor(0, 0, 0, 70))
        p.setPen(QPen(QColor(self._muted.red(), self._muted.green(), self._muted.blue(), 90), 1))
        p.drawLine(QPointF(x0, y0 + _TOPBAR_H), QPointF(x0 + _CARD_W, y0 + _TOPBAR_H))
        cy = y0 + _TOPBAR_H / 2
        p.setPen(Qt.PenStyle.NoPen)
        for i, col in enumerate((_PINK, _AMBER, _GREEN)):
            p.setBrush(col)
            p.drawEllipse(QPointF(x0 + 18 + i * 15, cy), 4.5, 4.5)
        p.setFont(_font(mono=True, size=10))
        p.setPen(self._muted)
        p.drawText(
            QRectF(x0 + 70, y0, 260, _TOPBAR_H), int(Qt.AlignmentFlag.AlignVCenter), "nabu@recon:~/"
        )
        p.setPen(self._accent)
        p.drawText(
            QRectF(x0, y0, _CARD_W - 18, _TOPBAR_H),
            int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight),
            "secure boot",
        )

    def _paint_chamber(self, p: QPainter, x0: float, top: float, t: float, ms: int) -> None:
        chamber = QRectF(x0, top, _CARD_W, _CHAMBER_H)
        if self._is_light:
            # why: over a light card the translucent fill muddies to flat grey and kills the
            # laser-room drama — paint an opaque dark "chamber floor" so the scope stays crisp.
            floor = QLinearGradient(x0, top, x0, top + _CHAMBER_H)
            floor.setColorAt(0.0, QColor(9, 16, 21))
            floor.setColorAt(1.0, QColor(4, 8, 11))
            p.fillRect(chamber, floor)
        else:
            p.fillRect(chamber, QColor(6, 11, 14, 120))
        cx = x0 + _CARD_W / 2
        ring_cy = top + 118

        # radar rings; the innermost pulses on its own 4 s cycle
        for r in (180.0, 125.0):
            p.setPen(
                QPen(QColor(self._accent.red(), self._accent.green(), self._accent.blue(), 22), 1)
            )
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(QPointF(cx, ring_cy), r, r)
        pulse = (ms % 4000) / 4000.0
        pr = 75.0 * (0.6 + 0.9 * pulse)
        pa = int(120 * (1.0 - pulse))
        p.setPen(QPen(QColor(self._accent.red(), self._accent.green(), self._accent.blue(), pa), 1))
        p.drawEllipse(QPointF(cx, ring_cy), pr, pr)

        # faint static tripwires
        p.save()
        p.setClipRect(chamber)
        for ty, ang in ((150.0, -22.0), (96.0, 16.0)):
            p.save()
            p.translate(cx, top + ty)
            p.rotate(ang)
            self._beam_line(p, -320, 320, _LASER_SOFT, width=1.4, glow=False)
            p.restore()

        # cyan recon scan — sweeps left→right on a 3.2 s cycle
        scan_x = x0 + 16 + (ms % 3200) / 3200.0 * 560
        grad = QLinearGradient(scan_x, top + 10, scan_x, top + _CHAMBER_H - 10)
        c = self._accent
        grad.setColorAt(0.0, QColor(c.red(), c.green(), c.blue(), 0))
        grad.setColorAt(0.5, QColor(c.red(), c.green(), c.blue(), 150))
        grad.setColorAt(1.0, QColor(c.red(), c.green(), c.blue(), 0))
        p.setPen(QPen(grad, 2))
        p.drawLine(QPointF(scan_x, top + 10), QPointF(scan_x, top + _CHAMBER_H - 10))

        # sweeper (pivoting red beam)
        p.save()
        p.translate(x0 + 0.09 * _CARD_W, top + 132)
        p.rotate(_kf(t, _SWEEP_ROT))
        self._beam_line(p, 0, 0.82 * _CARD_W, _LASER, width=2.0, glow=True, fade=True)
        self._node(p, 0.0, 0.0, 5.5)
        p.restore()

        # mascot — dodging (drawn under the drop/rise beams so a beam can pass "in front")
        self._paint_mascot(p, cx, top, t)

        # drop beam (guillotine)
        drop_y = top + 30 + _kf(t, _DROP_TY)
        p.save()
        p.translate(cx, drop_y)
        self._beam_line(p, -0.44 * _CARD_W, 0.44 * _CARD_W, _LASER, width=2.5, glow=True)
        self._node(p, -0.44 * _CARD_W, 0.0, 4.5)
        self._node(p, 0.44 * _CARD_W, 0.0, 4.5)
        p.restore()

        # rising beam
        rise_y = top + 214 + _kf(t, _RISE_TY)
        rise_op = _kf(t, _RISE_OP)
        p.save()
        p.setOpacity(rise_op)
        p.translate(cx, rise_y)
        self._beam_line(p, -0.44 * _CARD_W, 0.44 * _CARD_W, _LASER, width=2.5, glow=True)
        self._node(p, -0.44 * _CARD_W, 0.0, 4.5)
        self._node(p, 0.44 * _CARD_W, 0.0, 4.5)
        p.restore()
        p.setOpacity(1.0)

        # red proximity flash at the two near-misses
        flash = _kf(t, _FLASH_OP)
        if flash > 0.01:
            fg = QRadialGradient(cx, top + _CHAMBER_H * 0.62, _CARD_W * 0.42)
            fg.setColorAt(0.0, QColor(255, 59, 92, int(90 * flash)))
            fg.setColorAt(0.58, QColor(255, 59, 92, 0))
            p.fillRect(chamber, fg)
        p.restore()  # clip

        # vignette
        vg = QLinearGradient(0, top, 0, top + _CHAMBER_H)
        vg.setColorAt(0.0, QColor(6, 11, 14, 90))
        vg.setColorAt(0.35, QColor(6, 11, 14, 0))
        vg.setColorAt(1.0, QColor(6, 11, 14, 150))
        p.fillRect(chamber, vg)

    def _paint_mascot(self, p: QPainter, cx: float, top: float, t: float) -> None:
        anchor_y = top + _CHAMBER_H - 16  # bottom-centre pivot of the mascot box
        # ground shadow
        p.save()
        p.setOpacity(_kf(t, _SHADOW_OP))
        p.translate(cx + _kf(t, _SHADOW_TX), anchor_y - 2)
        p.scale(_kf(t, _SHADOW_SX), 1.0)
        sg = QRadialGradient(0, 0, 60)
        sg.setColorAt(0.0, QColor(0, 0, 0, 170))
        sg.setColorAt(0.72, QColor(0, 0, 0, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(sg)
        p.drawEllipse(QPointF(0, 0), 59, 10)
        p.restore()
        # the owl, running the evasion beats about its feet
        p.save()
        p.translate(cx + _kf(t, _EV_TX), anchor_y + _kf(t, _EV_TY))
        p.rotate(_kf(t, _EV_ROT))
        p.scale(_kf(t, _EV_SX), _kf(t, _EV_SY))
        self._svg.render(p, QRectF(-75, -150, 150, 150))
        p.restore()

    def _paint_footer(self, p: QPainter, x0: float, top: float, ms: int) -> None:
        foot = QRectF(x0, top, _CARD_W, _FOOTER_H)
        p.fillRect(foot, QColor(0, 0, 0, 60))
        p.setPen(QPen(QColor(self._muted.red(), self._muted.green(), self._muted.blue(), 90), 1))
        p.drawLine(QPointF(x0, top), QPointF(x0 + _CARD_W, top))
        pad = 22.0
        # brand row
        p.setFont(_font(bold=True, size=16))
        p.setPen(self._text)
        p.drawText(QPointF(x0 + pad, top + 30), APP_NAME)
        p.setFont(_font(mono=True, size=9))
        p.setPen(self._gold)
        p.drawText(QPointF(x0 + pad + 74, top + 30), "L O C A L   R E C O N   W O R K S P A C E")
        p.setPen(self._muted)
        p.drawText(
            QRectF(x0, top + 14, _CARD_W - pad, 22),
            int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            f"v{__version__}",
        )
        # LOADING row
        ly = top + 62
        p.setFont(_font(bold=True, size=13))
        p.setPen(self._accent)
        p.drawText(QPointF(x0 + pad, ly), "L O A D I N G")
        if (ms % 1100) < 550:  # blinking block cursor
            p.fillRect(QRectF(x0 + pad + 118, ly - 12, 9, 15), self._accent)
        dot_a = int(90 + 165 * (0.5 + 0.5 * math.sin(ms / 1400.0 * 2 * math.pi)))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(
            QColor(self._accent.red(), self._accent.green(), self._accent.blue(), min(255, dot_a))
        )
        p.drawEllipse(QPointF(x0 + _CARD_W - pad - 40, ly - 5), 4.0, 4.0)
        p.setFont(_font(mono=True, size=10))
        p.setPen(self._muted)
        p.drawText(QPointF(x0 + _CARD_W - pad - 26, ly - 1), "live")
        # rotating status line
        msg = _STATUS[(ms // 1650) % len(_STATUS)]
        sy = top + 88
        p.setFont(_font(mono=True, size=11))
        p.setPen(_GREEN)
        p.drawText(QPointF(x0 + pad, sy), ">")
        p.setPen(self._muted)
        p.drawText(QPointF(x0 + pad + 16, sy), msg)
        # indeterminate scan bar
        bar = QRectF(x0 + pad, top + 102, _CARD_W - 2 * pad, 5)
        p.setPen(QPen(QColor(self._muted.red(), self._muted.green(), self._muted.blue(), 60), 1))
        p.setBrush(QColor(0, 0, 0, 120))
        p.drawRoundedRect(bar, 3, 3)
        seg_w = bar.width() * 0.38
        travel = bar.width() + seg_w
        sx = bar.left() - seg_w + _ease((ms % 1600) / 1600.0) * travel
        seg = QRectF(sx, bar.top(), seg_w, bar.height()).intersected(bar)
        if seg.width() > 0:
            sg = QLinearGradient(seg.left(), 0, seg.right(), 0)
            sg.setColorAt(
                0.0, QColor(self._accent.red(), self._accent.green(), self._accent.blue(), 0)
            )
            sg.setColorAt(0.6, self._accent)
            sg.setColorAt(1.0, self._secondary)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(sg)
            p.drawRoundedRect(seg, 3, 3)

    # ---- paint helpers ---------------------------------------------------------------------------
    def _beam_line(
        self,
        p: QPainter,
        x1: float,
        x2: float,
        col: QColor,
        *,
        width: float,
        glow: bool,
        fade: bool = False,
    ) -> None:
        grad = QLinearGradient(x1, 0, x2, 0)
        edge = QColor(col.red(), col.green(), col.blue(), 0)
        if fade:
            grad.setColorAt(0.0, col)
            grad.setColorAt(1.0, edge)
        else:
            grad.setColorAt(0.0, edge)
            grad.setColorAt(0.12, col)
            grad.setColorAt(0.88, col)
            grad.setColorAt(1.0, edge)
        if glow:
            p.setPen(QPen(QColor(col.red(), col.green(), col.blue(), 60), width + 5))
            p.drawLine(QPointF(x1, 0), QPointF(x2, 0))
        p.setPen(QPen(grad, width))
        p.drawLine(QPointF(x1, 0), QPointF(x2, 0))

    def _node(self, p: QPainter, x: float, y: float, r: float) -> None:
        pen = p.pen()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(255, 59, 92, 70))
        p.drawEllipse(QPointF(x, y), r + 4, r + 4)
        p.setBrush(_LASER)
        p.drawEllipse(QPointF(x, y), r, r)
        p.setPen(pen)


def _rounded_path(rect: QRectF, radius: float):  # type: ignore[no-untyped-def]
    from PySide6.QtGui import QPainterPath

    path = QPainterPath()
    path.addRoundedRect(rect, radius, radius)
    return path


def _font(*, bold: bool = False, mono: bool = False, size: int = 11) -> QFont:
    f = QFont()
    f.setFamilies(_MONO_FAMILIES if mono else _SANS_FAMILIES)
    f.setPixelSize(size + 4)
    if bold:
        f.setWeight(QFont.Weight.Bold)
    return f


_SANS_FAMILIES = ["Space Grotesk", "Segoe UI", "Noto Sans", "DejaVu Sans", "Arial"]
_MONO_FAMILIES = ["JetBrains Mono", "DejaVu Sans Mono", "Menlo", "Consolas", "monospace"]


def _lift(c: QColor, d: int) -> QColor:
    return QColor(min(255, c.red() + d), min(255, c.green() + d), min(255, c.blue() + d))


def _dim(c: QColor, d: int) -> QColor:
    return QColor(max(0, c.red() - d), max(0, c.green() - d), max(0, c.blue() - d))


def make_splash() -> NabuSplash:
    return NabuSplash()
