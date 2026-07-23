from __future__ import annotations

import math

from PySide6.QtCore import QByteArray, QElapsedTimer, QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import (
    QColor,
    QFont,
    QGuiApplication,
    QLinearGradient,
    QPainter,
    QPainterPath,
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

# Nabu — "Kamehameha" loading splash (Dragon-Ball-Z style). The owl-furby fighter gets blasted back
# into a mountain, powers up in a gold Super-Saiyan aura, charges a cyan energy ball, then fires a
# kamehameha beam that slams the opponent into the far mountain (screen flash + shockwave). Native
# Qt (one elapsed clock drives every beat) — no QtWebEngine (fragile in the Kali VM), offline, and
# degrades gracefully: a splash failure never blocks startup (§27). Always the fixed HTB / Parrot
# look for the card chrome (owner decision 2026-07-17), independent of the app's active theme.

# ---- geometry (card-local px) --------------------------------------------------------------------
_CARD_W = 640
_TOPBAR_H = 40
_CHAMBER_H = 262
_FOOTER_H = 128
_CARD_H = _TOPBAR_H + _CHAMBER_H + _FOOTER_H
_MARGIN = 26  # transparent gutter around the card for the drop shadow
_LOOP_MS = 1900  # the full fight beat — fast so the whole saga plays inside the show window
_MIN_SHOW_MS = 2050  # keep the splash up ≥ one full loop so the entire fight is seen

# fixed non-theme colours — the Toonami-era broadcast palette (environment quiet, energy loud)
_VOID = QColor("#060a12")  # deep-space ground
_VOID2 = QColor("#0c1826")  # upper sky
_STEEL = QColor("#24384f")  # blue-biased neutral rock (chosen, not default grey)
_CYAN = QColor("#46d5ff")  # Toonami cyan — HUD, rim light, ki
_AMBER = QColor("#ff8a3f")  # Toonami warm accent
_GOLD = QColor("#ffcf4a")  # super-saiyan aura
_KI = _CYAN  # kamehameha
_KI_DEEP = QColor("#1f7fff")
_KI_CORE = QColor("#ffffff")
_AURA = _GOLD
_AURA2 = QColor("#ff7a1f")
_OPP = QColor("#2b2246")  # indigo villain — reads by rim light + glowing eyes, not bright fill
_OPP_DK = QColor("#150d24")
_GREEN = QColor("#3ddc84")
_PINK = QColor("#ff5c7a")

_STATUS = (
    "charging ki…",
    "powering up — aura rising…",
    "arming recon modules…",
    "loading HackTricks (offline)…",
    "focusing the kamehameha…",
    "establishing secure tunnel…",
    "indexing service fingerprints…",
)


def _ease(x: float) -> float:
    # smoothstep — a cheap ease-in-out
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


# ---- fight beats, keyed to the loop fraction -----------------------------------------------------
# 0.00–0.14 knockback into the mountain · 0.14–0.44 power up · 0.44–0.64 charge ·
# 0.64–0.86 KAMEHAMEHA blast (opponent slammed into the far mountain) · 0.86–1.0 settle
_OWL_TX = [
    (0.0, 0.0),
    (0.05, -46.0),
    (0.14, -36.0),
    (0.30, -24.0),
    (0.44, -18.0),
    (0.63, -16.0),
    (0.68, -2.0),
    (0.74, -12.0),
    (0.86, -16.0),
    (1.0, 0.0),
]
_OWL_TY = [
    (0.0, 0.0),
    (0.10, -6.0),
    (0.14, 0.0),
    (0.30, -11.0),
    (0.44, -7.0),
    (0.63, -4.0),
    (1.0, 0.0),
]
_OWL_SX = [
    (0.0, 1.0),
    (0.10, 1.14),
    (0.14, 1.0),
    (0.44, 1.10),
    (0.63, 1.05),
    (0.68, 1.16),
    (0.82, 1.0),
    (1.0, 1.0),
]
_OWL_SY = [
    (0.0, 1.0),
    (0.10, 0.84),
    (0.14, 1.0),
    (0.44, 1.13),
    (0.63, 1.08),
    (0.68, 1.16),
    (0.82, 1.0),
    (1.0, 1.0),
]
_AURA_K = [
    (0.0, 0.0),
    (0.14, 0.12),
    (0.30, 0.9),
    (0.44, 1.0),
    (0.63, 0.95),
    (0.80, 0.6),
    (0.95, 0.15),
    (1.0, 0.0),
]
_BALL = [(0.0, 0.0), (0.44, 3.0), (0.55, 22.0), (0.62, 34.0), (0.66, 46.0), (0.70, 0.0), (1.0, 0.0)]
_BEAM = [(0.0, 0.0), (0.65, 0.0), (0.685, 1.0), (0.83, 1.0), (0.90, 0.25), (1.0, 0.0)]
_BEAMLEN = [(0.0, 0.0), (0.66, 0.06), (0.71, 1.0), (1.0, 1.0)]
_OPP_TX = [(0.0, 0.0), (0.70, 0.0), (0.74, 26.0), (0.86, 92.0), (0.98, 92.0), (1.0, 0.0)]
_OPP_TY = [(0.0, 0.0), (0.70, 0.0), (0.74, -10.0), (0.86, 6.0), (1.0, 0.0)]
_SHOCK = [(0.0, 0.0), (0.72, 0.0), (0.75, 16.0), (0.90, 210.0), (1.0, 0.0)]
_FLASH = [
    (0.0, 0.0),
    (0.02, 0.55),
    (0.10, 0.0),
    (0.65, 0.0),
    (0.685, 0.75),
    (0.73, 0.14),
    (0.745, 0.9),
    (0.80, 0.14),
    (0.90, 0.0),
    (1.0, 0.0),
]
_GOLD_K = [
    (0.0, 0.0),
    (0.14, 0.0),
    (0.30, 0.22),
    (0.44, 0.26),
    (0.63, 0.12),
    (0.80, 0.0),
    (1.0, 0.0),
]
_IMPACT = [(0.0, 0.0), (0.02, 1.0), (0.12, 0.0), (1.0, 0.0)]  # left-mountain hit dust


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

        # why: the boot splash is ONE fixed loading screen — always the HTB / Parrot look for the
        # card chrome (owner decision, 2026-07-17), independent of the app's active theme.
        pal = tokens.palette("htb")
        self._bg = QColor(pal.bg)
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
        # re-anchor the clock here and play a fresh _MIN_SHOW_MS once the loop is live, then close —
        # that guarantees the fight is actually seen rather than flashing by.
        self._clock.restart()
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

    # ---- the fight (Toonami-era broadcast) -------------------------------------------------------
    def _paint_chamber(self, p: QPainter, x0: float, top: float, t: float, ms: int) -> None:
        chamber = QRectF(x0, top, _CARD_W, _CHAMBER_H)
        ground_y = top + 210.0
        owl_x = x0 + 200.0 + _kf(t, _OWL_TX)
        opp_x = x0 + 494.0 + _kf(t, _OPP_TX)
        opp_y = ground_y + _kf(t, _OPP_TY)
        aura = _kf(t, _AURA_K)
        ball_r = _kf(t, _BALL)
        beam = _kf(t, _BEAM)
        ball_x, ball_y = owl_x + 42.0, ground_y - 52.0

        p.save()
        p.setClipRect(chamber)
        self._scene_bg(p, x0, top, ground_y, ms)
        self._grid_ground(p, x0, top, ground_y)
        self._mountain(p, x0 - 26, ground_y, 150.0, 126.0)
        self._mountain(p, x0 + 424, ground_y, 244.0, 150.0)

        gold = _kf(t, _GOLD_K)
        if gold > 0.01:
            gg = QRadialGradient(owl_x, ground_y - 46, 250)
            gg.setColorAt(0.0, QColor(_GOLD.red(), _GOLD.green(), _GOLD.blue(), int(90 * gold)))
            gg.setColorAt(1.0, QColor(_GOLD.red(), _GOLD.green(), _GOLD.blue(), 0))
            p.fillRect(chamber, gg)

        self._opponent(p, opp_x, opp_y, beam)

        if beam > 0.01:
            reach = _kf(t, _BEAMLEN)
            bx1 = ball_x + 4
            bx2 = bx1 + (opp_x - 12 - bx1) * reach
            self._beam(p, bx1, bx2, ball_y, beam, ms)

        shock = _kf(t, _SHOCK)
        if shock > 2:
            self._shock(p, opp_x + 8, opp_y - 48, shock)
            self._lens_flare(
                p, opp_x, opp_y - 48, 26 * min(1.0, shock / 60), _CYAN, min(1.0, shock / 44)
            )

        self._fighter(p, owl_x, ground_y, t, aura, ms)
        if ball_r > 1:
            self._energy_ball(p, ball_x, ball_y, ball_r, ms)

        flash = _kf(t, _FLASH)
        if flash > 0.01:
            p.fillRect(chamber, QColor(210, 240, 255, int(150 * flash)))
        p.restore()  # clip

        self._broadcast_overlay(p, x0, top, chamber, ms)

    def _scene_bg(self, p: QPainter, x0: float, top: float, ground_y: float, ms: int) -> None:
        sky = QLinearGradient(0, top, 0, ground_y)
        sky.setColorAt(0.0, _VOID2)
        sky.setColorAt(0.7, QColor(9, 15, 24))
        sky.setColorAt(1.0, QColor(14, 22, 32))
        p.fillRect(QRectF(x0, top, _CARD_W, ground_y - top), sky)
        # nebula washes
        for cxr, cyr, rr, col in (
            (x0 + 150, top + 60, 210, QColor(70, 120, 200)),
            (x0 + 470, top + 120, 230, QColor(120, 70, 160)),
        ):
            ng = QRadialGradient(cxr, cyr, rr)
            ng.setColorAt(0.0, QColor(col.red(), col.green(), col.blue(), 34))
            ng.setColorAt(1.0, QColor(col.red(), col.green(), col.blue(), 0))
            p.fillRect(QRectF(x0, top, _CARD_W, ground_y - top), ng)
        # a planet, upper-right, dark with an amber crescent rim
        px, py, pr = x0 + 556, top + 44, 62.0
        pg = QRadialGradient(px - pr * 0.4, py - pr * 0.4, pr * 1.6)
        pg.setColorAt(0.0, QColor(40, 52, 70))
        pg.setColorAt(1.0, QColor(10, 14, 22))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(pg)
        p.drawEllipse(QPointF(px, py), pr, pr)
        p.setPen(QPen(QColor(_AMBER.red(), _AMBER.green(), _AMBER.blue(), 150), 2.4))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawArc(QRectF(px - pr, py - pr, pr * 2, pr * 2), -70 * 16, 130 * 16)
        # starfield (deterministic + twinkle)
        p.setPen(Qt.PenStyle.NoPen)
        span = int(ground_y - top - 16)
        for i in range(48):
            sx = x0 + (i * 71 + 13) % _CARD_W
            sy = top + 6 + (i * 137 + 29) % span
            tw = 0.5 + 0.5 * math.sin(ms / 720.0 + i * 1.7)
            a = int((30 + 150 * tw) * (0.4 if i % 4 else 1.0))
            p.setBrush(QColor(210, 235, 255, a))
            p.drawEllipse(QPointF(sx, sy), 0.8 + 0.6 * tw, 0.8 + 0.6 * tw)
        # horizon haze
        hz = QLinearGradient(0, ground_y - 40, 0, ground_y + 8)
        hz.setColorAt(0.0, QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), 0))
        hz.setColorAt(1.0, QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), 45))
        p.fillRect(QRectF(x0, ground_y - 40, _CARD_W, 48), hz)

    def _grid_ground(self, p: QPainter, x0: float, top: float, ground_y: float) -> None:
        bottom = top + _CHAMBER_H
        cx = x0 + _CARD_W / 2
        gnd = QLinearGradient(0, ground_y, 0, bottom)
        gnd.setColorAt(0.0, QColor(12, 16, 24))
        gnd.setColorAt(1.0, _VOID)
        p.fillRect(QRectF(x0, ground_y, _CARD_W, bottom - ground_y), gnd)
        # perspective grid (Tron/Toonami floor)
        for k in range(1, 8):
            fy = ground_y + (bottom - ground_y) * (k / 8.0) ** 1.7
            a = int(70 * (1 - k / 8.0))
            p.setPen(QPen(QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), a), 1))
            p.drawLine(QPointF(x0, fy), QPointF(x0 + _CARD_W, fy))
        for vx in range(-6, 7):
            fx = cx + vx * 46
            p.setPen(QPen(QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), 40), 1))
            p.drawLine(QPointF(cx + vx * 8, ground_y), QPointF(fx, bottom))

    def _mountain(
        self, p: QPainter, base_x: float, base_y: float, peak_dx: float, h: float
    ) -> None:
        path = QPainterPath()
        path.moveTo(base_x - 80, base_y)
        path.lineTo(base_x + peak_dx * 0.34, base_y - h * 0.60)
        path.lineTo(base_x + peak_dx * 0.5, base_y - h * 0.82)
        path.lineTo(base_x + peak_dx * 0.62, base_y - h)
        path.lineTo(base_x + peak_dx * 0.76, base_y - h * 0.68)
        path.lineTo(base_x + peak_dx * 0.9, base_y - h * 0.86)
        path.lineTo(base_x + peak_dx + 130, base_y)
        path.closeSubpath()
        g = QLinearGradient(0, base_y - h, 0, base_y)
        g.setColorAt(0.0, _STEEL)
        g.setColorAt(1.0, QColor(9, 15, 21))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(g)
        p.drawPath(path)
        # cool rim light on the ridge
        p.setPen(QPen(QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), 70), 1.4))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(path)

    def _opponent(self, p: QPainter, cx: float, feet_y: float, hit: float) -> None:
        # a cel-shaded caped warrior, backlit by the incoming ki (cyan rim), with glowing eyes
        p.save()
        p.translate(cx, feet_y)
        lit = min(1.0, hit)
        base = _lerp(_OPP, QColor(255, 244, 235), lit * 0.85)
        dk = _lerp(_OPP_DK, QColor(200, 170, 195), lit * 0.6)
        p.setPen(Qt.PenStyle.NoPen)
        # billowing cape (behind)
        cape = QPainterPath()
        cape.moveTo(4, -116)
        cape.cubicTo(48, -94, 46, -34, 32, -2)
        cape.lineTo(8, -2)
        cape.cubicTo(0, -54, -2, -92, 4, -116)
        cape.closeSubpath()
        cg = QLinearGradient(0, -116, 0, 0)
        cg.setColorAt(0.0, dk)
        cg.setColorAt(1.0, _OPP_DK)
        p.setBrush(cg)
        p.drawPath(cape)
        # body silhouette (broad shoulders -> V-taper -> planted stance)
        body = QPainterPath()
        body.moveTo(-25, -102)
        body.cubicTo(-32, -94, -17, -90, -14, -62)
        body.lineTo(-16, -2)
        body.lineTo(-7, -2)
        body.lineTo(-4, -56)
        body.lineTo(4, -56)
        body.lineTo(7, -2)
        body.lineTo(16, -2)
        body.lineTo(14, -62)
        body.cubicTo(17, -90, 32, -94, 25, -102)
        body.cubicTo(15, -110, -15, -110, -25, -102)
        body.closeSubpath()
        bg = QLinearGradient(0, -110, 0, 0)
        bg.setColorAt(0.0, _lerp(base, QColor(255, 255, 255), 0.14))
        bg.setColorAt(0.5, base)
        bg.setColorAt(1.0, dk)
        p.setBrush(bg)
        p.drawPath(body)
        # fists up (fighting guard) + head + antennae
        p.setBrush(base)
        p.drawEllipse(QPointF(-13, -70), 6.5, 6.5)
        p.drawEllipse(QPointF(13, -70), 6.5, 6.5)
        p.setBrush(bg)
        p.drawEllipse(QPointF(0, -117), 11.5, 12.5)
        p.setPen(QPen(base, 3.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(QPointF(-4, -126), QPointF(-9, -140))
        p.drawLine(QPointF(4, -126), QPointF(9, -140))
        p.setPen(Qt.PenStyle.NoPen)
        # cyan rim light on the contour facing the blast (grows as it's hit)
        rimw = 1.6 + 2.8 * hit
        p.setPen(QPen(QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), int(110 + 130 * hit)), rimw))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.save()
        p.translate(-1.6, 0)
        p.drawPath(body)
        p.restore()
        p.setPen(Qt.PenStyle.NoPen)
        # glowing eyes (amber -> white when blasted)
        eye = _lerp(_AMBER, QColor(255, 255, 255), lit)
        eg = QRadialGradient(0, -118, 11)
        eg.setColorAt(0.0, QColor(eye.red(), eye.green(), eye.blue(), 200))
        eg.setColorAt(1.0, QColor(eye.red(), eye.green(), eye.blue(), 0))
        p.setBrush(eg)
        p.drawEllipse(QPointF(0, -118), 11, 7)
        p.setBrush(eye)
        p.drawEllipse(QPointF(-4, -118), 2.2, 1.7)
        p.drawEllipse(QPointF(4, -118), 2.2, 1.7)
        p.restore()

    def _fighter(
        self, p: QPainter, owl_x: float, ground_y: float, t: float, aura: float, ms: int
    ) -> None:
        sx, sy = _kf(t, _OWL_SX), _kf(t, _OWL_SY)
        oy = ground_y + _kf(t, _OWL_TY)
        p.setPen(Qt.PenStyle.NoPen)
        # floor glow / reflection
        rg = QRadialGradient(owl_x, ground_y + 2, 60)
        rg.setColorAt(0.0, QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), int(50 + 90 * aura)))
        rg.setColorAt(1.0, QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), 0))
        p.setBrush(rg)
        p.drawEllipse(QPointF(owl_x, ground_y + 1), 50 * sx, 11)
        # gold super-saiyan aura behind the fighter
        if aura > 0.02:
            cx, cy = owl_x, oy - 44
            glow = QRadialGradient(cx, cy, 82)
            glow.setColorAt(0.0, QColor(255, 244, 190, int(150 * aura)))
            glow.setColorAt(0.5, QColor(_AURA.red(), _AURA.green(), _AURA.blue(), int(90 * aura)))
            glow.setColorAt(1.0, QColor(_AURA2.red(), _AURA2.green(), _AURA2.blue(), 0))
            p.setBrush(glow)
            p.drawEllipse(QPointF(cx, cy), 74, 96)
            flame = QPainterPath()
            n = 11
            for i in range(n + 1):
                ang = math.pi + (i / n) * math.pi
                wob = 1.0 + 0.5 * math.sin(ms / 85.0 + i * 1.7) * aura
                rad = (40 + 34 * wob) * (0.7 + 0.3 * aura)
                px = cx + math.cos(ang) * rad * 0.64
                py = cy + math.sin(ang) * rad
                (flame.moveTo if i == 0 else flame.lineTo)(px, py)
            flame.lineTo(cx + 30, oy)
            flame.lineTo(cx - 30, oy)
            flame.closeSubpath()
            fg = QLinearGradient(cx, cy - 92, cx, oy)
            fg.setColorAt(0.0, QColor(255, 246, 200, int(160 * aura)))
            fg.setColorAt(0.45, QColor(_AURA.red(), _AURA.green(), _AURA.blue(), int(120 * aura)))
            fg.setColorAt(1.0, QColor(_AURA2.red(), _AURA2.green(), _AURA2.blue(), int(30 * aura)))
            p.setBrush(fg)
            p.drawPath(flame)
            # lightning arcs
            p.setPen(QPen(QColor(210, 240, 255, int(200 * aura)), 1.3))
            for j in range(3):
                a0 = ms / 70.0 + j * 2.1
                lx, ly = cx + math.cos(a0) * 30, cy + math.sin(a0) * 40
                seg = QPainterPath()
                seg.moveTo(lx, ly)
                for s in range(3):
                    lx += math.cos(a0) * 14 + math.sin(ms / 40.0 + s) * 6
                    ly += math.sin(a0) * 14
                    seg.lineTo(lx, ly)
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawPath(seg)
            p.setPen(Qt.PenStyle.NoPen)
            for i in range(7):
                ph = (ms / 600.0 + i * 0.37) % 1.0
                dx = owl_x + (i - 3) * 15
                dy = ground_y - ph * 92 * aura
                p.setBrush(QColor(130, 118, 100, int(180 * (1 - ph) * aura)))
                p.drawEllipse(QPointF(dx, dy), 2.2, 2.2)
        # cool rim halo so the owl reads against the dark scene
        halo = QRadialGradient(owl_x, oy - 44, 58)
        halo.setColorAt(0.0, QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), int(60 + 90 * aura)))
        halo.setColorAt(1.0, QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), 0))
        p.setBrush(halo)
        p.drawEllipse(QPointF(owl_x, oy - 44), 46, 58)
        # the owl fighter
        p.save()
        p.translate(owl_x, oy)
        p.scale(sx, sy)
        self._svg.render(p, QRectF(-45, -92, 90, 90))
        p.restore()

    def _energy_ball(self, p: QPainter, cx: float, cy: float, r: float, ms: int) -> None:
        halo = QRadialGradient(cx, cy, r * 2.0)
        halo.setColorAt(0.0, QColor(_KI.red(), _KI.green(), _KI.blue(), 160))
        halo.setColorAt(0.5, QColor(_KI_DEEP.red(), _KI_DEEP.green(), _KI_DEEP.blue(), 60))
        halo.setColorAt(1.0, QColor(_KI_DEEP.red(), _KI_DEEP.green(), _KI_DEEP.blue(), 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(halo)
        p.drawEllipse(QPointF(cx, cy), r * 2.0, r * 2.0)
        core = QRadialGradient(cx - r * 0.22, cy - r * 0.22, r)
        core.setColorAt(0.0, _KI_CORE)
        core.setColorAt(0.55, QColor(_KI.red(), _KI.green(), _KI.blue(), 240))
        core.setColorAt(1.0, QColor(_KI_DEEP.red(), _KI_DEEP.green(), _KI_DEEP.blue(), 130))
        p.setBrush(core)
        p.drawEllipse(QPointF(cx, cy), r, r)
        self._lens_flare(p, cx, cy, r * 1.4, _KI_CORE, 1.0)
        p.setPen(QPen(QColor(_KI_CORE.red(), _KI_CORE.green(), _KI_CORE.blue(), 210), 1.3))
        for i in range(5):
            a = ms / 55.0 + i * 1.257
            p.drawLine(
                QPointF(cx + math.cos(a) * r * 1.05, cy + math.sin(a) * r * 1.05),
                QPointF(cx + math.cos(a + 0.5) * r * 1.7, cy + math.sin(a + 0.5) * r * 1.7),
            )

    def _beam(self, p: QPainter, x1: float, x2: float, y: float, k: float, ms: int) -> None:
        if x2 <= x1:
            return
        h = (16 + 9 * math.sin(ms / 65.0)) * k
        p.setPen(Qt.PenStyle.NoPen)
        og = QLinearGradient(0, y - h * 2.4, 0, y + h * 2.4)
        og.setColorAt(0.0, QColor(_KI.red(), _KI.green(), _KI.blue(), 0))
        og.setColorAt(0.5, QColor(_KI.red(), _KI.green(), _KI.blue(), int(130 * k)))
        og.setColorAt(1.0, QColor(_KI.red(), _KI.green(), _KI.blue(), 0))
        p.setBrush(og)
        p.drawRoundedRect(QRectF(x1, y - h * 2.4, x2 - x1, h * 4.8), h, h)
        p.setBrush(QColor(_KI.red(), _KI.green(), _KI.blue(), int(235 * k)))
        p.drawRoundedRect(QRectF(x1, y - h, x2 - x1, h * 2), h, h)
        p.setBrush(QColor(255, 255, 255, int(245 * k)))
        p.drawRoundedRect(QRectF(x1, y - h * 0.4, x2 - x1, h * 0.8), h * 0.4, h * 0.4)
        self._lens_flare(p, x1, y, h * 2.2, _KI_CORE, k)  # muzzle
        for i in range(10):
            ph = (ms / 190.0 + i * 0.29) % 1.0
            px = x1 + (x2 - x1) * ph
            py = y + math.sin(ms / 75.0 + i) * h * 0.7
            p.setBrush(QColor(255, 255, 255, int(200 * k * (1 - ph))))
            p.drawEllipse(QPointF(px, py), 1.6, 1.6)

    def _lens_flare(
        self, p: QPainter, cx: float, cy: float, r: float, col: QColor, k: float
    ) -> None:
        if r <= 0 or k <= 0:
            return
        p.setPen(Qt.PenStyle.NoPen)
        g = QRadialGradient(cx, cy, r)
        g.setColorAt(0.0, QColor(col.red(), col.green(), col.blue(), int(230 * k)))
        g.setColorAt(0.4, QColor(col.red(), col.green(), col.blue(), int(80 * k)))
        g.setColorAt(1.0, QColor(col.red(), col.green(), col.blue(), 0))
        p.setBrush(g)
        p.drawEllipse(QPointF(cx, cy), r, r)
        p.setPen(QPen(QColor(col.red(), col.green(), col.blue(), int(200 * k)), max(1.0, r * 0.06)))
        p.drawLine(QPointF(cx - r * 1.6, cy), QPointF(cx + r * 1.6, cy))
        p.drawLine(QPointF(cx, cy - r * 1.15), QPointF(cx, cy + r * 1.15))
        p.setPen(Qt.PenStyle.NoPen)

    def _shock(self, p: QPainter, cx: float, cy: float, r: float) -> None:
        p.setBrush(Qt.BrushStyle.NoBrush)
        for kk in range(2):
            rr = r * (1.0 - 0.28 * kk)
            a = int(150 * (1 - r / 210.0) * (1 - 0.3 * kk))
            p.setPen(QPen(QColor(_KI.red(), _KI.green(), _KI.blue(), max(0, a)), 2.4 - kk))
            p.drawEllipse(QPointF(cx, cy), rr, rr * 0.78)

    def _broadcast_overlay(
        self, p: QPainter, x0: float, top: float, chamber: QRectF, ms: int
    ) -> None:
        # scanlines
        p.setPen(QPen(QColor(0, 0, 0, 26), 1))
        yy = top + 1
        while yy < top + _CHAMBER_H:
            p.drawLine(QPointF(x0, yy), QPointF(x0 + _CARD_W, yy))
            yy += 3
        # vignette
        vg = QLinearGradient(0, top, 0, top + _CHAMBER_H)
        vg.setColorAt(0.0, QColor(4, 8, 12, 130))
        vg.setColorAt(0.4, QColor(4, 8, 12, 0))
        vg.setColorAt(1.0, QColor(4, 8, 12, 150))
        p.fillRect(chamber, vg)
        # cinematic letterbox
        p.fillRect(QRectF(x0, top, _CARD_W, 8), QColor(0, 0, 0, 235))
        p.fillRect(QRectF(x0, top + _CHAMBER_H - 8, _CARD_W, 8), QColor(0, 0, 0, 235))
        # HUD corner brackets
        cyhud = QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), 150)
        p.setPen(QPen(cyhud, 1.4))
        p.setBrush(Qt.BrushStyle.NoBrush)
        b, ln = 14.0, 16.0
        for hx, hy, dx, dy in (
            (x0 + b, top + b + 4, 1, 1),
            (x0 + _CARD_W - b, top + b + 4, -1, 1),
            (x0 + b, top + _CHAMBER_H - b - 4, 1, -1),
            (x0 + _CARD_W - b, top + _CHAMBER_H - b - 4, -1, -1),
        ):
            p.drawLine(QPointF(hx, hy), QPointF(hx + dx * ln, hy))
            p.drawLine(QPointF(hx, hy), QPointF(hx, hy + dy * ln))
        # transmission readout
        p.setFont(_font(mono=True, size=8))
        p.setPen(QColor(_CYAN.red(), _CYAN.green(), _CYAN.blue(), 170))
        p.drawText(QPointF(x0 + 36, top + 24), "// TRANSMISSION  ·  NABU-TV")
        p.setPen(QColor(_AMBER.red(), _AMBER.green(), _AMBER.blue(), 190))
        p.drawText(
            QRectF(x0, top + 14, _CARD_W - 36, 14),
            int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            "SECTOR 07  ▸  LIVE",
        )
        if (ms % 1000) < 600:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(255, 70, 70, 220))
            p.drawEllipse(QPointF(x0 + _CARD_W - 96, top + 19), 3.0, 3.0)

    def _paint_footer(self, p: QPainter, x0: float, top: float, ms: int) -> None:
        foot = QRectF(x0, top, _CARD_W, _FOOTER_H)
        p.fillRect(foot, QColor(0, 0, 0, 60))
        p.setPen(QPen(QColor(self._muted.red(), self._muted.green(), self._muted.blue(), 90), 1))
        p.drawLine(QPointF(x0, top), QPointF(x0 + _CARD_W, top))
        pad = 22.0
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
        msg = _STATUS[(ms // 1650) % len(_STATUS)]
        sy = top + 88
        p.setFont(_font(mono=True, size=11))
        p.setPen(_GREEN)
        p.drawText(QPointF(x0 + pad, sy), ">")
        p.setPen(self._muted)
        p.drawText(QPointF(x0 + pad + 16, sy), msg)
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


def _rounded_path(rect: QRectF, radius: float) -> QPainterPath:
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


def _lerp(a: QColor, b: QColor, t: float) -> QColor:
    t = max(0.0, min(1.0, t))
    return QColor(
        int(a.red() + (b.red() - a.red()) * t),
        int(a.green() + (b.green() - a.green()) * t),
        int(a.blue() + (b.blue() - a.blue()) * t),
    )


def make_splash() -> NabuSplash:
    return NabuSplash()
