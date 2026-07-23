from __future__ import annotations

import math
import random
import re

from PySide6.QtCore import QByteArray, QPoint, QPointF, QRectF, Qt, QTimer, QVariantAnimation
from PySide6.QtGui import (
    QColor,
    QCursor,
    QGuiApplication,
    QHideEvent,
    QLinearGradient,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPaintEvent,
    QPen,
    QRadialGradient,
    QShowEvent,
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QSizePolicy, QWidget

from oscprecon.gui.assets import FURBY, asset_path

# Nabu — the owl mascot as a LIVE brand mark: its pupils follow the cursor and it blinks. It lives
# on a WIDE stage (the header gap), resting at the right; clicking it plays a 2s "show-off" where
# it can run across that space — kamehameha a Piccolo, moonwalk, bust out of jail, spin like Taz.
# The vendored SVG (assets/furby.svg) is rendered as the still base MINUS its pupils/highlights;
# OwlMark paints those live. Offline, cheap; renders as a still mark under the offscreen platform.

# eye geometry in the mascot's 0..100 viewBox (must track assets/furby.svg)
_EYES = ((38.0, 47.0), (62.0, 47.0))  # sclera centres
_PUPILS = ((39.5, 48.0), (60.5, 48.0))  # pupil rest positions ("looking forward")
_SCLERA_R = 9.5
_PUPIL_R = 4.6
_MAX_OFF = 3.4  # how far a pupil travels toward the cursor (kept inside the sclera)
_LID = QColor("#45959c")  # face-teal eyelid used for the blink
_PUPIL = QColor("#08252b")
_HL = QColor("#ffffff")
_HL2 = QColor(255, 255, 255, 205)

# fixed effect colours
_KI = QColor("#5ccaff")  # kamehameha cyan
_KI_DEEP = QColor("#1f7fff")
_AURA = QColor("#ffcf4a")  # super-saiyan gold
_AURA2 = QColor("#ff7a1f")
_AMBER = QColor("#ff8a3f")
_OPP = QColor("#2b2246")  # Piccolo indigo
_OPP_DK = QColor("#160e26")

# easter egg: clicking the mascot plays one of these reactions. Purely cosmetic — no state, no
# network, ends on its own. Durations in ms; the show-off moves are 2s so they're actually seen.
_REACTIONS: tuple[tuple[str, int], ...] = (
    ("spin", 700),
    ("backflip", 800),
    ("bounce", 700),
    ("mad", 650),
    ("wobble", 700),
    ("smile", 700),
    ("dance", 1600),
    ("dizzy", 1200),
    ("cry", 1200),
    ("nod", 700),
    ("powerup", 2000),  # gold super-saiyan aura flare
    ("kamehameha", 2000),  # run left, turn, fire a beam that blasts a Piccolo
    ("flex", 2000),  # shoulder-press show-off
    ("taz", 2000),  # spin like the Tasmanian devil (dust tornado), drifting
    ("breakdance", 2000),  # spin + floor slides
    ("pullups", 2000),  # rhythmic pull-ups
    ("jump", 2000),  # double leap
    ("vibrate", 2000),  # excited jitter
    ("faint", 2000),  # topple over
    ("boing", 2000),  # springy stretch/squash
    ("sneeze", 2000),  # rear back + achoo
    ("love", 2000),  # pink float-up
    ("moonwalk", 2000),  # slide left, glide back right, facing forward
    ("jailbreak", 2000),  # rattle the bars, bust out, run
    ("runaround", 2000),  # dash left and back
)


def _base_svg() -> bytes:
    # the mascot minus its pupils (#08252b) + highlights (#ffffff) — OwlMark paints those live.
    text = asset_path(FURBY).read_text(encoding="utf-8")
    text = re.sub(r'<circle[^>]*fill="#08252b"[^>]*>(?:</circle>)?', "", text)
    text = re.sub(r'<circle[^>]*fill="#ffffff"[^>]*>(?:</circle>)?', "", text)
    return text.encode("utf-8")


def _lerp(a: QColor, b: QColor, t: float) -> QColor:
    t = max(0.0, min(1.0, t))
    return QColor(
        int(a.red() + (b.red() - a.red()) * t),
        int(a.green() + (b.green() - a.green()) * t),
        int(a.blue() + (b.blue() - a.blue()) * t),
    )


class OwlMark(QWidget):
    """The Nabu mascot as a living mark on a wide stage: cursor-tracking pupils, blink, and a
    click easter egg where it runs across the header gap doing 2s show-off moves."""

    def __init__(self, size: int = 34, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._sprite = size  # the drawn mascot size; the widget is wider (it fills the header gap)
        self.setFixedHeight(size + 8)
        self.setMinimumWidth(size + 6)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setToolTip("Nabu — click me")
        self.setAccessibleName("Nabu mascot")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._renderer = QSvgRenderer(QByteArray(_base_svg()))
        self._gaze = QPointF(0.0, 0.0)
        self._blink = 0.0

        # easter-egg reaction state
        self._reaction = ""
        self._angle = 0.0
        self._scale = 1.0
        self._dx = 0.0
        self._dy = 0.0
        self._tear = 0.0
        self._tint = QColor(0, 0, 0, 0)
        self._fx = ""  # overlay/prop to paint, driven by _t
        self._t = 0.0
        self._run = 0.0  # horizontal position fraction: 0 = home (right), -1 = far left
        self._flip = 1.0  # facing: +1 = right, -1 = left
        self._react_anim = QVariantAnimation(self)
        self._react_anim.setStartValue(0.0)
        self._react_anim.setEndValue(1.0)
        self._react_anim.valueChanged.connect(self._on_react)
        self._react_anim.finished.connect(self._reset_reaction)

        self._blink_anim = QVariantAnimation(self)
        self._blink_anim.setDuration(190)
        self._blink_anim.setKeyValueAt(0.0, 0.0)
        self._blink_anim.setKeyValueAt(0.45, 1.0)
        self._blink_anim.setKeyValueAt(1.0, 0.0)
        self._blink_anim.valueChanged.connect(self._on_blink)

        self._follow = QTimer(self)
        self._follow.setInterval(45)
        self._follow.timeout.connect(self._track)
        self._next_blink = QTimer(self)
        self._next_blink.setSingleShot(True)
        self._next_blink.timeout.connect(self._do_blink)
        # Animate only on a real display and while shown. A repeating timer under the offscreen test
        # platform keeps the event loop from ever going idle (hangs idle-waiters) — there it's a
        # still mark. Timers start/stop in showEvent/hideEvent.
        self._live = QGuiApplication.platformName() != "offscreen"

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        if self._live:
            if not self._follow.isActive():
                self._follow.start()
            if not self._next_blink.isActive():
                self._schedule_blink()

    def hideEvent(self, event: QHideEvent) -> None:
        super().hideEvent(event)
        self._follow.stop()
        self._next_blink.stop()
        self._blink_anim.stop()

    def _schedule_blink(self) -> None:
        self._next_blink.start(int(random.uniform(3.2, 7.5) * 1000))

    def _do_blink(self) -> None:
        if self.isVisible():
            self._blink_anim.stop()
            self._blink_anim.start()
        self._schedule_blink()

    def _on_blink(self, value: object) -> None:
        self._blink = float(value) if isinstance(value, int | float) else 0.0
        self.update()

    # ---- geometry: the mascot rests at the right, runs left across the stage ----------------
    def _mascot_xy(self) -> tuple[float, float, float]:
        w, h = float(self.width()), float(self.height())
        half = self._sprite / 2.0
        home_x = w - half - 3.0
        run = max(0.0, w - self._sprite - 10.0)  # horizontal travel available
        mx = min(max(home_x + self._run * run + self._dx, half), w - half)
        return mx, h / 2.0 + self._dy, half

    def _track(self) -> None:
        if not self.isVisible():
            return
        half = self._sprite / 2.0
        home = self.mapToGlobal(QPoint(int(self.width() - half - 3), self.height() // 2))
        pos = QCursor.pos()
        gx = max(-1.0, min(1.0, (pos.x() - home.x()) / 260.0))
        gy = max(-1.0, min(1.0, (pos.y() - home.y()) / 220.0))
        if abs(gx - self._gaze.x()) > 0.02 or abs(gy - self._gaze.y()) > 0.02:
            self._gaze = QPointF(gx, gy)
            self.update()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.play_reaction()
            event.accept()
            return
        super().mousePressEvent(event)

    def play_reaction(self, name: str | None = None) -> None:
        choices = [r for r in _REACTIONS if name is None or r[0] == name]
        if not choices:
            return
        reaction, duration = random.choice(choices)
        self._reaction = reaction
        self._react_anim.stop()
        self._react_anim.setDuration(duration)
        if self._live:
            self._react_anim.start()
        else:  # offscreen (tests): no event loop to drive frames — settle at rest
            self._reset_reaction()

    def _on_react(self, value: object) -> None:
        t = float(value) if isinstance(value, int | float) else 0.0
        r = self._reaction
        self._angle = self._dx = self._dy = self._tear = self._run = 0.0
        self._scale = 1.0
        self._flip = 1.0
        self._tint = QColor(0, 0, 0, 0)
        self._fx = ""
        self._t = t
        pi = math.pi
        if r == "spin":
            self._angle = 360.0 * t
        elif r == "backflip":
            self._angle = -360.0 * t
            self._dy = -16.0 * math.sin(pi * t)
        elif r == "bounce":
            self._dy = -18.0 * abs(math.sin(2 * pi * t)) * (1.0 - 0.3 * t)
        elif r == "mad":
            self._dx = 4.0 * math.sin(24 * pi * t) * (1.0 - t)
            self._tint = QColor(255, 60, 40, int(150 * math.sin(pi * t)))
        elif r == "wobble":
            self._angle = 16.0 * math.sin(6 * pi * t) * (1.0 - t)
        elif r == "smile":
            self._scale = 1.0 + 0.22 * math.sin(pi * t)
            self._tint = QColor(255, 200, 60, int(120 * math.sin(pi * t)))
        elif r == "dance":
            self._run = -0.2 * abs(math.sin(2 * pi * t))
            self._dy = -7.0 * abs(math.sin(4 * pi * t))
            self._angle = 9.0 * math.sin(6 * pi * t)
            self._flip = 1.0 if math.sin(2 * pi * t) < 0 else -1.0
        elif r == "dizzy":
            self._angle = 720.0 * t * t
            self._scale = 1.0 - 0.08 * math.sin(pi * t)
        elif r == "cry":
            self._dy = 3.0 * math.sin(pi * t)
            self._tint = QColor(60, 140, 255, int(120 * math.sin(pi * t)))
            self._tear = t
        elif r == "nod":
            self._dy = 6.0 * math.sin(6 * pi * t) * (1.0 - 0.5 * t)
        elif r == "powerup":
            inten = math.sin(pi * t)
            self._scale = 1.0 + 0.16 * inten
            self._dy = -3.0 * inten
            self._fx = "powerup"
        elif r == "kamehameha":
            self._fx = "kamehameha"
            if t < 0.30:  # dash left
                self._run = -0.9 * (t / 0.30)
                self._flip = -1.0
                self._dy = -1.6 * abs(math.sin(11 * pi * t))
            elif t < 0.42:  # skid + turn to face the enemy on the right
                self._run = -0.9
                self._flip = -1.0 + 2.0 * ((t - 0.30) / 0.12)
            elif t < 0.90:  # plant, charge, fire
                self._run = -0.9
                self._flip = 1.0
            else:  # dash back home
                self._run = -0.9 * (1.0 - (t - 0.90) / 0.10)
                self._flip = -1.0
        elif r == "flex":
            reps = abs(math.sin(2.5 * pi * t))
            self._dy = -10.0 * reps
            self._scale = 1.0 + 0.11 * reps
            self._tint = QColor(255, 190, 60, int(90 * reps))
        elif r == "taz":
            self._angle = 1440.0 * t
            self._run = -0.35 * abs(math.sin(2 * pi * t))
            self._scale = 0.9 + 0.14 * abs(math.sin(6 * pi * t))
            self._fx = "taz"
        elif r == "breakdance":
            self._angle = 720.0 * t
            self._run = -0.45 * math.sin(2 * pi * t)
            self._dy = 5.0 * math.sin(4 * pi * t)
            self._scale = 0.95 + 0.1 * abs(math.sin(3 * pi * t))
        elif r == "pullups":
            reps = abs(math.sin(2.5 * pi * t))
            self._dy = -13.0 * reps
            self._scale = 1.0 - 0.04 * reps
        elif r == "jump":
            hh = abs(math.sin(2 * pi * t))
            self._dy = -16.0 * hh
            self._scale = 1.0 + 0.07 * hh
        elif r == "vibrate":
            d = 1.0 - t
            self._dx = 2.4 * math.sin(46 * pi * t) * d
            self._dy = 2.0 * math.cos(42 * pi * t) * d
        elif r == "faint":
            e = min(t * 1.4, 1.0)
            self._angle = 90.0 * e
            self._dy = 12.0 * e
            self._tint = QColor(120, 160, 255, int(100 * math.sin(pi * t)))
        elif r == "boing":
            b = math.sin(3 * pi * t) * (1.0 - t)
            self._scale = 1.0 + 0.24 * b
            self._dy = -12.0 * b
        elif r == "sneeze":
            if t < 0.65:
                u = t / 0.65
                self._dy = -5.0 * u
                self._angle = -7.0 * u
            else:
                k = (t - 0.65) / 0.35
                self._dy = -5.0 + 12.0 * k
                self._angle = -7.0 + 16.0 * k
                self._scale = 1.0 + 0.08 * (1.0 - k)
        elif r == "love":
            self._scale = 1.0 + 0.15 * math.sin(pi * t)
            self._dy = -12.0 * t
            self._tint = QColor(255, 110, 150, int(130 * math.sin(pi * t)))
        elif r == "moonwalk":
            self._run = -0.85 * math.sin(pi * t)  # slide left, glide back
            self._flip = 1.0  # faces forward/right while sliding left — the illusion
            self._dy = -1.4 * abs(math.sin(8 * pi * t))
            self._angle = -5.0 * math.sin(pi * t)
        elif r == "jailbreak":
            self._fx = "jail"
            if t < 0.34:  # rattle the bars
                self._dx = 2.4 * math.sin(30 * pi * t)
            elif t < 0.48:  # burst
                self._scale = 1.0 + 0.14 * ((t - 0.34) / 0.14)
            else:  # bust out and run
                p = (t - 0.48) / 0.52
                self._run = -0.95 * math.sin(pi * p)
                self._flip = -1.0 if p < 0.55 else 1.0
                self._dy = -1.6 * abs(math.sin(12 * pi * t))
        elif r == "runaround":
            self._run = -0.9 * math.sin(pi * t)
            self._flip = -1.0 if t < 0.5 else 1.0
            self._dy = -1.6 * abs(math.sin(12 * pi * t))
        self.update()

    def _reset_reaction(self) -> None:
        self._reaction = ""
        self._angle = self._dx = self._dy = self._tear = self._run = 0.0
        self._scale = 1.0
        self._flip = 1.0
        self._tint = QColor(0, 0, 0, 0)
        self._fx = ""
        self._t = 0.0
        self.update()

    # ---- painting --------------------------------------------------------------------------------
    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w, h = float(self.width()), float(self.height())
        mx, my, half = self._mascot_xy()
        s = self._sprite / 100.0

        self._paint_prop_back(painter, mx, my, w)

        # mascot + eyes under one transform about (mx, my)
        painter.save()
        painter.translate(mx, my)
        painter.rotate(self._angle)
        painter.scale(self._flip * self._scale, self._scale)
        painter.translate(-half, -half)
        self._renderer.render(painter, QRectF(0.0, 0.0, float(self._sprite), float(self._sprite)))
        painter.setPen(Qt.PenStyle.NoPen)
        for (ex, ey), (px, py) in zip(_EYES, _PUPILS, strict=True):
            cx = (px + self._gaze.x() * _MAX_OFF) * s
            cy = (py + self._gaze.y() * _MAX_OFF) * s
            painter.setBrush(_PUPIL)
            painter.drawEllipse(QPointF(cx, cy), _PUPIL_R * s, _PUPIL_R * s)
            painter.setBrush(_HL)
            painter.drawEllipse(QPointF(cx - 2.5 * s, cy - 3.0 * s), 2.0 * s, 2.0 * s)
            painter.setBrush(_HL2)
            painter.drawEllipse(QPointF(cx + 2.0 * s, cy + 2.0 * s), 0.9 * s, 0.9 * s)
            if self._blink > 0.001:
                clip = QPainterPath()
                clip.addEllipse(QPointF(ex * s, ey * s), _SCLERA_R * s, _SCLERA_R * s)
                painter.save()
                painter.setClipPath(clip)
                lid_h = self._blink * _SCLERA_R * 2 * s
                painter.fillRect(
                    QRectF((ex - _SCLERA_R) * s, (ey - _SCLERA_R) * s, _SCLERA_R * 2 * s, lid_h),
                    _LID,
                )
                painter.restore()
        painter.restore()  # end mascot transform

        # mood wash — a soft glow around the mascot, not a full-stage fill
        if self._tint.alpha() > 0:
            tg = QRadialGradient(mx, my, self._sprite)
            tg.setColorAt(0.0, self._tint)
            fade = QColor(self._tint)
            fade.setAlpha(0)
            tg.setColorAt(1.0, fade)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(tg)
            painter.drawEllipse(QPointF(mx, my), self._sprite, self._sprite)
        if self._tear > 0.0:
            tx = mx + (38.0 - 50.0) * s
            ty = my + (47.0 + 6.0 - 50.0) * s + self._tear * h * 0.45
            painter.setBrush(QColor(90, 170, 255, 220))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(QPointF(tx, ty), 2.2 * s, 3.0 * s)

        self._paint_energy(painter, mx, my, w)
        self._paint_prop_front(painter, mx, my)
        painter.end()

    def _paint_prop_back(self, p: QPainter, mx: float, my: float, w: float) -> None:
        # the Piccolo enemy stands at the right (the mascot's home spot), behind the action
        if self._fx == "kamehameha" and self._t > 0.16:
            hit = 1.0 if 0.62 <= self._t <= 0.9 else 0.0
            self._draw_piccolo(p, w - self._sprite * 0.7, my, self._sprite * 0.95, hit)

    def _paint_prop_front(self, p: QPainter, mx: float, my: float) -> None:
        # jail bars stand IN FRONT of the mascot until he bursts out
        if self._fx == "jail" and self._t < 0.5:
            self._draw_jail(p, mx, my, float(self._sprite), self._t)

    def _paint_energy(self, p: QPainter, mx: float, my: float, w: float) -> None:
        if not self._fx:
            return
        t = self._t
        sp = float(self._sprite)
        p.setPen(Qt.PenStyle.NoPen)
        if self._fx == "powerup":
            inten = math.sin(math.pi * t)
            aura = QRadialGradient(mx, my, sp * 0.95)
            aura.setColorAt(0.0, QColor(255, 244, 190, int(150 * inten)))
            aura.setColorAt(0.4, QColor(_AURA.red(), _AURA.green(), _AURA.blue(), int(120 * inten)))
            aura.setColorAt(1.0, QColor(_AURA2.red(), _AURA2.green(), _AURA2.blue(), 0))
            p.setBrush(aura)
            p.drawEllipse(QPointF(mx, my), sp * 0.95, sp)
            p.setBrush(QColor(255, 226, 130, int(210 * inten)))
            for i in range(6):
                ph = (t * 3 + i * 0.5) % 1.0
                fx = mx + (i - 2.5) * sp * 0.16
                fy = my + sp * 0.34 - ph * sp * 0.85
                p.drawEllipse(QPointF(fx, fy), sp * 0.04 * (1 - ph), sp * 0.07 * (1 - ph))
        elif self._fx == "taz":
            p.setPen(QPen(QColor(190, 160, 120, 150), max(1.0, sp * 0.05)))
            p.setBrush(Qt.BrushStyle.NoBrush)
            for i in range(3):
                rr = sp * (0.42 + 0.16 * i)
                a0 = int((t * 1440 + i * 130) % 360)
                p.drawArc(QRectF(mx - rr, my - rr, rr * 2, rr * 2), a0 * 16, 210 * 16)
            p.setPen(Qt.PenStyle.NoPen)
        elif self._fx == "kamehameha":
            bx, by = mx + sp * 0.46, my
            if 0.42 <= t < 0.62:  # charge the ball
                r = ((t - 0.42) / 0.20) * sp * 0.34
                halo = QRadialGradient(bx, by, r * 2.0)
                halo.setColorAt(0.0, QColor(150, 225, 255, 200))
                halo.setColorAt(0.5, QColor(_KI_DEEP.red(), _KI_DEEP.green(), _KI_DEEP.blue(), 70))
                halo.setColorAt(1.0, QColor(_KI_DEEP.red(), _KI_DEEP.green(), _KI_DEEP.blue(), 0))
                p.setBrush(halo)
                p.drawEllipse(QPointF(bx, by), r * 2.0, r * 2.0)
                core = QRadialGradient(bx - r * 0.2, by - r * 0.2, max(1.0, r))
                core.setColorAt(0.0, QColor(255, 255, 255))
                core.setColorAt(0.6, QColor(_KI.red(), _KI.green(), _KI.blue(), 235))
                core.setColorAt(1.0, QColor(_KI_DEEP.red(), _KI_DEEP.green(), _KI_DEEP.blue(), 140))
                p.setBrush(core)
                p.drawEllipse(QPointF(bx, by), r, r)
                p.setPen(QPen(QColor(255, 255, 255, 210), max(1.0, sp * 0.02)))
                p.drawLine(QPointF(bx - r * 2.4, by), QPointF(bx + r * 2.4, by))
                p.drawLine(QPointF(bx, by - r * 2.4), QPointF(bx, by + r * 2.4))
                p.setPen(Qt.PenStyle.NoPen)
            elif 0.62 <= t <= 0.92:  # FIRE — beam to the Piccolo on the right
                k = min(1.0, (t - 0.62) / 0.10)
                hgt = sp * 0.2 * (1.2 - 0.35 * k)
                x2 = w - self._sprite * 0.7
                if x2 > bx:
                    og = QLinearGradient(0.0, by - hgt * 2.4, 0.0, by + hgt * 2.4)
                    og.setColorAt(0.0, QColor(_KI.red(), _KI.green(), _KI.blue(), 0))
                    og.setColorAt(0.5, QColor(_KI.red(), _KI.green(), _KI.blue(), int(150 * k)))
                    og.setColorAt(1.0, QColor(_KI.red(), _KI.green(), _KI.blue(), 0))
                    p.setBrush(og)
                    p.drawRoundedRect(QRectF(bx, by - hgt * 2.4, x2 - bx, hgt * 4.8), hgt, hgt)
                    p.setBrush(QColor(_KI.red(), _KI.green(), _KI.blue(), int(235 * k)))
                    p.drawRoundedRect(QRectF(bx, by - hgt, x2 - bx, hgt * 2), hgt, hgt)
                    p.setBrush(QColor(255, 255, 255, int(245 * k)))
                    p.drawRoundedRect(
                        QRectF(bx, by - hgt * 0.42, x2 - bx, hgt * 0.84), hgt * 0.4, hgt * 0.4
                    )
                    mb = QRadialGradient(x2, by, hgt * 3.0)
                    mb.setColorAt(0.0, QColor(255, 255, 255, int(230 * k)))
                    mb.setColorAt(0.5, QColor(_KI.red(), _KI.green(), _KI.blue(), int(140 * k)))
                    mb.setColorAt(1.0, QColor(_KI.red(), _KI.green(), _KI.blue(), 0))
                    p.setBrush(mb)
                    p.drawEllipse(QPointF(x2, by), hgt * 3.0, hgt * 3.0)

    def _draw_piccolo(self, p: QPainter, px: float, py: float, sz: float, hit: float) -> None:
        p.save()
        p.translate(px, py)
        u = sz / 40.0
        lit = min(1.0, hit)
        base = _lerp(_OPP, QColor(255, 244, 235), lit * 0.8)
        p.setPen(Qt.PenStyle.NoPen)
        cape = QPainterPath()
        cape.moveTo(2 * u, -15 * u)
        cape.cubicTo(15 * u, -6 * u, 12 * u, 8 * u, 8 * u, 15 * u)
        cape.lineTo(-4 * u, 15 * u)
        cape.cubicTo(-6 * u, 2 * u, -6 * u, -8 * u, 2 * u, -15 * u)
        cape.closeSubpath()
        p.setBrush(_OPP_DK)
        p.drawPath(cape)
        p.setBrush(base)
        p.drawRoundedRect(QRectF(-6.5 * u, -9 * u, 13 * u, 24 * u), 4 * u, 4 * u)
        p.drawEllipse(QPointF(0.0, -15 * u), 6 * u, 6.5 * u)
        p.setPen(QPen(base, 1.8 * u, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(QPointF(-2.5 * u, -20 * u), QPointF(-4.5 * u, -26 * u))
        p.drawLine(QPointF(2.5 * u, -20 * u), QPointF(4.5 * u, -26 * u))
        p.setPen(Qt.PenStyle.NoPen)
        if hit > 0:  # cyan rim on the struck side
            p.setPen(QPen(QColor(_KI.red(), _KI.green(), _KI.blue(), int(220 * hit)), 1.8 * u))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(QRectF(-7.5 * u, -9 * u, 13 * u, 24 * u), 4 * u, 4 * u)
            p.setPen(Qt.PenStyle.NoPen)
        eye = _lerp(_AMBER, QColor(255, 255, 255), lit)
        p.setBrush(eye)
        p.drawEllipse(QPointF(-2.4 * u, -15 * u), 1.4 * u, 1.1 * u)
        p.drawEllipse(QPointF(2.4 * u, -15 * u), 1.4 * u, 1.1 * u)
        p.restore()

    def _draw_jail(self, p: QPainter, mx: float, my: float, sz: float, t: float) -> None:
        brk = max(0.0, (t - 0.34) / 0.14)  # 0..1 as the bars break
        x0, x1 = mx - sz * 0.6, mx + sz * 0.6
        top, bot = my - sz * 0.64, my + sz * 0.64
        n = 4
        bars = [
            (x0 + (x1 - x0) * i / (n - 1), brk * (x0 + (x1 - x0) * i / (n - 1) - mx) * 1.4)
            for i in range(n)
        ]
        for col, wmul in (
            (QColor(30, 36, 46), 1.0),
            (QColor(176, 190, 208), 0.5),
        ):  # shadow + steel
            p.setPen(
                QPen(
                    col, max(2.2, sz * 0.085) * wmul, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap
                )
            )
            if brk < 0.72:
                p.drawLine(QPointF(x0, top), QPointF(x1, top))
                p.drawLine(QPointF(x0, bot), QPointF(x1, bot))
            for bx, bend in bars:
                if brk < 1.0:
                    p.drawLine(QPointF(bx, top - brk * 4), QPointF(bx + bend, bot + brk * 4))
