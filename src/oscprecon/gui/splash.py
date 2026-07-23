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
_LOOP_MS = 5200  # the full fight beat
_MIN_SHOW_MS = 2000  # keep the splash up at least this long so the fight is actually seen

# fixed non-theme colours — the DBZ palette
_KI = QColor("#5cd0ff")  # kamehameha cyan-blue
_KI_DEEP = QColor("#1f8fff")
_KI_CORE = QColor("#ffffff")
_AURA = QColor("#ffd23f")  # super-saiyan gold
_AURA2 = QColor("#ff8a1f")  # orange aura edge
_OPP = QColor("#7a4fb0")  # opponent (Piccolo-ish) purple
_OPP_DK = QColor("#39235a")
_GREEN = QColor("#3ddc84")
_PINK = QColor("#ff5c7a")
_AMBER = QColor("#f5c518")

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
_GOLD = [(0.0, 0.0), (0.14, 0.0), (0.30, 0.22), (0.44, 0.26), (0.63, 0.12), (0.80, 0.0), (1.0, 0.0)]
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

    # ---- the fight -------------------------------------------------------------------------------
    def _paint_chamber(self, p: QPainter, x0: float, top: float, t: float, ms: int) -> None:
        chamber = QRectF(x0, top, _CARD_W, _CHAMBER_H)
        ground_y = top + 206.0
        owl_x = x0 + 196.0 + _kf(t, _OWL_TX)
        opp_x = x0 + 496.0 + _kf(t, _OPP_TX)
        opp_y = ground_y + _kf(t, _OPP_TY)
        aura = _kf(t, _AURA_K)
        ball_r = _kf(t, _BALL)
        beam = _kf(t, _BEAM)
        ball_x, ball_y = owl_x + 40.0, ground_y - 52.0

        p.save()
        p.setClipRect(chamber)

        # --- battlefield sky + ground ---
        sky = QLinearGradient(0, top, 0, ground_y)
        sky.setColorAt(0.0, QColor(8, 14, 22))
        sky.setColorAt(0.6, QColor(14, 22, 34))
        sky.setColorAt(1.0, QColor(20, 30, 44))
        p.fillRect(QRectF(x0, top, _CARD_W, ground_y - top), sky)
        gnd = QLinearGradient(0, ground_y, 0, top + _CHAMBER_H)
        gnd.setColorAt(0.0, QColor(26, 22, 20))
        gnd.setColorAt(1.0, QColor(10, 9, 9))
        p.fillRect(QRectF(x0, ground_y, _CARD_W, top + _CHAMBER_H - ground_y), gnd)

        # power-up gold wash on the whole scene
        gold = _kf(t, _GOLD)
        if gold > 0.01:
            gg = QRadialGradient(owl_x, ground_y - 40, 260)
            gg.setColorAt(0.0, QColor(_AURA.red(), _AURA.green(), _AURA.blue(), int(120 * gold)))
            gg.setColorAt(1.0, QColor(_AURA.red(), _AURA.green(), _AURA.blue(), 0))
            p.fillRect(chamber, gg)

        # mountains (left = where the fighter got slammed, right = where the opponent gets blasted)
        self._mountain(p, x0 + 8, ground_y, 150.0, 132.0, QColor(15, 27, 34), QColor(10, 19, 24))
        self._mountain(p, x0 + 402, ground_y, 236.0, 150.0, QColor(13, 24, 30), QColor(8, 16, 20))
        p.setPen(QPen(QColor(0, 0, 0, 90), 1))
        p.drawLine(QPointF(x0, ground_y), QPointF(x0 + _CARD_W, ground_y))

        # ambient rising ki sparks
        for i in range(16):
            ph = (ms / 900.0 + i * 0.61) % 1.0
            sx = x0 + 40 + (i * 89 % (_CARD_W - 80))
            sy = ground_y - ph * 150
            a = int(120 * (1 - ph))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(_KI.red(), _KI.green(), _KI.blue(), a))
            p.drawEllipse(QPointF(sx, sy), 1.4, 1.4 + 2 * (1 - ph))

        # left-mountain impact dust (the knockback)
        imp = _kf(t, _IMPACT)
        if imp > 0.01:
            self._burst(p, owl_x - 6, ground_y - 34, 70 * imp, QColor(210, 200, 170), imp)

        # --- opponent (Piccolo-ish) on the right ---
        self._opponent(p, opp_x, opp_y, beam)

        # --- kamehameha beam: fighter -> opponent ---
        if beam > 0.01:
            reach = _kf(t, _BEAMLEN)
            bx1 = ball_x + 6
            bx2 = bx1 + (opp_x - 18 - bx1) * reach
            self._beam(p, bx1, bx2, ball_y, beam, ms)

        # --- shockwave where the opponent slams the far mountain ---
        shock = _kf(t, _SHOCK)
        if shock > 2:
            for k in range(2):
                rr = shock * (1.0 - 0.28 * k)
                a = int(150 * (1 - shock / 210.0) * (1 - 0.3 * k))
                p.setPen(QPen(QColor(_KI.red(), _KI.green(), _KI.blue(), max(0, a)), 2.4 - k))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(QPointF(opp_x + 10, opp_y - 40), rr, rr * 0.8)

        # --- the fighter: aura + owl + charging ball ---
        self._fighter(p, owl_x, ground_y, t, aura, ms)
        if ball_r > 1:
            self._energy_ball(p, ball_x, ball_y, ball_r, ms)

        # --- full-screen flash (impacts + the blast) ---
        flash = _kf(t, _FLASH)
        if flash > 0.01:
            p.fillRect(chamber, QColor(255, 255, 255, int(150 * flash)))

        p.restore()  # clip

        # vignette
        vg = QLinearGradient(0, top, 0, top + _CHAMBER_H)
        vg.setColorAt(0.0, QColor(4, 8, 12, 120))
        vg.setColorAt(0.4, QColor(4, 8, 12, 0))
        vg.setColorAt(1.0, QColor(4, 8, 12, 150))
        p.fillRect(chamber, vg)

    def _mountain(
        self,
        p: QPainter,
        base_x: float,
        base_y: float,
        peak_dx: float,
        h: float,
        c1: QColor,
        c2: QColor,
    ) -> None:
        path = QPainterPath()
        path.moveTo(base_x - 80, base_y)
        path.lineTo(base_x + peak_dx * 0.35, base_y - h * 0.62)
        path.lineTo(base_x + peak_dx * 0.5, base_y - h * 0.82)
        path.lineTo(base_x + peak_dx * 0.62, base_y - h)
        path.lineTo(base_x + peak_dx * 0.78, base_y - h * 0.7)
        path.lineTo(base_x + peak_dx * 0.92, base_y - h * 0.88)
        path.lineTo(base_x + peak_dx + 120, base_y)
        path.closeSubpath()
        g = QLinearGradient(0, base_y - h, 0, base_y)
        g.setColorAt(0.0, c1)
        g.setColorAt(1.0, c2)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(g)
        p.drawPath(path)

    def _fighter(
        self, p: QPainter, owl_x: float, ground_y: float, t: float, aura: float, ms: int
    ) -> None:
        sx, sy = _kf(t, _OWL_SX), _kf(t, _OWL_SY)
        oy = ground_y + _kf(t, _OWL_TY)
        # ground shadow
        p.setPen(Qt.PenStyle.NoPen)
        sg = QRadialGradient(owl_x, ground_y - 2, 52)
        sg.setColorAt(0.0, QColor(0, 0, 0, 150))
        sg.setColorAt(0.72, QColor(0, 0, 0, 0))
        p.setBrush(sg)
        p.drawEllipse(QPointF(owl_x, ground_y - 2), 46 * sx, 9)
        # gold super-saiyan aura (flame spikes + radial glow) behind the fighter
        if aura > 0.02:
            cx, cy = owl_x, oy - 42
            glow = QRadialGradient(cx, cy, 78)
            glow.setColorAt(0.0, QColor(_AURA.red(), _AURA.green(), _AURA.blue(), int(150 * aura)))
            glow.setColorAt(
                0.5, QColor(_AURA2.red(), _AURA2.green(), _AURA2.blue(), int(70 * aura))
            )
            glow.setColorAt(1.0, QColor(_AURA2.red(), _AURA2.green(), _AURA2.blue(), 0))
            p.setBrush(glow)
            p.drawEllipse(QPointF(cx, cy), 74, 92)
            flame = QPainterPath()
            n = 11
            for i in range(n + 1):
                ang = math.pi + (i / n) * math.pi  # top half sweep
                wob = 1.0 + 0.5 * math.sin(ms / 90.0 + i * 1.7) * aura
                rad = (40 + 34 * wob) * (0.7 + 0.3 * aura)
                px = cx + math.cos(ang) * rad * 0.66
                py = cy + math.sin(ang) * rad
                (flame.moveTo if i == 0 else flame.lineTo)(px, py)
            flame.lineTo(cx + 30, oy)
            flame.lineTo(cx - 30, oy)
            flame.closeSubpath()
            fg = QLinearGradient(cx, cy - 90, cx, oy)
            fg.setColorAt(0.0, QColor(255, 240, 180, int(150 * aura)))
            fg.setColorAt(0.45, QColor(_AURA.red(), _AURA.green(), _AURA.blue(), int(120 * aura)))
            fg.setColorAt(1.0, QColor(_AURA2.red(), _AURA2.green(), _AURA2.blue(), int(30 * aura)))
            p.setBrush(fg)
            p.drawPath(flame)
            # rising debris while powering up
            for i in range(7):
                ph = (ms / 620.0 + i * 0.37) % 1.0
                dx = owl_x + (i - 3) * 15
                dy = ground_y - ph * 90 * aura
                p.setBrush(QColor(120, 110, 95, int(180 * (1 - ph) * aura)))
                p.drawEllipse(QPointF(dx, dy), 2.2, 2.2)
        # the owl fighter
        p.save()
        p.translate(owl_x, oy)
        p.scale(sx, sy)
        self._svg.render(p, QRectF(-46, -94, 92, 92))
        p.restore()

    def _energy_ball(self, p: QPainter, cx: float, cy: float, r: float, ms: int) -> None:
        halo = QRadialGradient(cx, cy, r * 1.9)
        halo.setColorAt(0.0, QColor(_KI.red(), _KI.green(), _KI.blue(), 150))
        halo.setColorAt(0.5, QColor(_KI_DEEP.red(), _KI_DEEP.green(), _KI_DEEP.blue(), 60))
        halo.setColorAt(1.0, QColor(_KI_DEEP.red(), _KI_DEEP.green(), _KI_DEEP.blue(), 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(halo)
        p.drawEllipse(QPointF(cx, cy), r * 1.9, r * 1.9)
        core = QRadialGradient(cx - r * 0.2, cy - r * 0.2, r)
        core.setColorAt(0.0, _KI_CORE)
        core.setColorAt(0.55, QColor(_KI.red(), _KI.green(), _KI.blue(), 235))
        core.setColorAt(1.0, QColor(_KI_DEEP.red(), _KI_DEEP.green(), _KI_DEEP.blue(), 120))
        p.setBrush(core)
        p.drawEllipse(QPointF(cx, cy), r, r)
        # electric crackle
        p.setPen(QPen(QColor(_KI_CORE.red(), _KI_CORE.green(), _KI_CORE.blue(), 200), 1.4))
        for i in range(5):
            a = ms / 60.0 + i * 1.257
            r1, r2 = r * 1.05, r * 1.7
            p.drawLine(
                QPointF(cx + math.cos(a) * r1, cy + math.sin(a) * r1),
                QPointF(cx + math.cos(a + 0.5) * r2, cy + math.sin(a + 0.5) * r2),
            )

    def _beam(self, p: QPainter, x1: float, x2: float, y: float, k: float, ms: int) -> None:
        if x2 <= x1:
            return
        h = (16 + 10 * math.sin(ms / 70.0)) * k
        # outer glow
        og = QLinearGradient(0, y - h * 2, 0, y + h * 2)
        og.setColorAt(0.0, QColor(_KI.red(), _KI.green(), _KI.blue(), 0))
        og.setColorAt(0.5, QColor(_KI.red(), _KI.green(), _KI.blue(), int(120 * k)))
        og.setColorAt(1.0, QColor(_KI.red(), _KI.green(), _KI.blue(), 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(og)
        p.drawRoundedRect(QRectF(x1, y - h * 2, x2 - x1, h * 4), h, h)
        # cyan body
        p.setBrush(QColor(_KI.red(), _KI.green(), _KI.blue(), int(230 * k)))
        p.drawRoundedRect(QRectF(x1, y - h, x2 - x1, h * 2), h, h)
        # white core
        p.setBrush(QColor(255, 255, 255, int(240 * k)))
        p.drawRoundedRect(QRectF(x1, y - h * 0.42, x2 - x1, h * 0.84), h * 0.4, h * 0.4)
        # muzzle burst at the fighter's hands
        mb = QRadialGradient(x1, y, h * 2.4)
        mb.setColorAt(0.0, QColor(255, 255, 255, int(230 * k)))
        mb.setColorAt(0.5, QColor(_KI.red(), _KI.green(), _KI.blue(), int(150 * k)))
        mb.setColorAt(1.0, QColor(_KI.red(), _KI.green(), _KI.blue(), 0))
        p.setBrush(mb)
        p.drawEllipse(QPointF(x1, y), h * 2.4, h * 2.4)
        # streaking particles along the beam
        for i in range(9):
            ph = (ms / 200.0 + i * 0.31) % 1.0
            px = x1 + (x2 - x1) * ph
            py = y + math.sin(ms / 80.0 + i) * h * 0.7
            p.setBrush(QColor(255, 255, 255, int(200 * k * (1 - ph))))
            p.drawEllipse(QPointF(px, py), 1.6, 1.6)

    def _opponent(self, p: QPainter, cx: float, feet_y: float, hit: float) -> None:
        # a lean Piccolo-ish silhouette: cape, body, head + two antennae; braces on the blast
        p.save()
        p.translate(cx, feet_y)
        col = _OPP if hit < 0.2 else _lerp(_OPP, QColor(255, 210, 180), min(1.0, hit))
        cape = QPainterPath()
        cape.moveTo(-4, -96)
        cape.cubicTo(-34, -70, -30, -18, -20, 0)
        cape.lineTo(22, 0)
        cape.cubicTo(30, -20, 32, -66, 4, -96)
        cape.closeSubpath()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(_OPP_DK)
        p.drawPath(cape)
        body = QPainterPath()
        body.moveTo(-11, -2)
        body.lineTo(-13, -70)
        body.cubicTo(-13, -84, 13, -84, 13, -70)
        body.lineTo(11, -2)
        body.closeSubpath()
        p.setBrush(col)
        p.drawPath(body)
        p.drawEllipse(QPointF(0, -92), 12, 13)  # head
        p.setPen(QPen(col, 3.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(QPointF(-4, -101), QPointF(-8, -114))  # antennae
        p.drawLine(QPointF(4, -101), QPointF(8, -114))
        p.restore()

    def _burst(self, p: QPainter, cx: float, cy: float, r: float, col: QColor, a: float) -> None:
        p.setPen(Qt.PenStyle.NoPen)
        g = QRadialGradient(cx, cy, max(1.0, r))
        g.setColorAt(0.0, QColor(col.red(), col.green(), col.blue(), int(200 * a)))
        g.setColorAt(1.0, QColor(col.red(), col.green(), col.blue(), 0))
        p.setBrush(g)
        p.drawEllipse(QPointF(cx, cy), r, r)
        for i in range(8):
            ang = i * math.pi / 4
            dr = r * (0.7 + 0.3 * (i % 3))
            p.setBrush(QColor(col.red(), col.green(), col.blue(), int(180 * a)))
            p.drawEllipse(QPointF(cx + math.cos(ang) * dr, cy + math.sin(ang) * dr), 2.4, 2.4)

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
