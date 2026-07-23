from __future__ import annotations

import math
import random
import re

from PySide6.QtCore import QByteArray, QPointF, QRectF, Qt, QTimer, QVariantAnimation
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
from PySide6.QtWidgets import QWidget

from oscprecon.gui.assets import FURBY, asset_path

# Nabu — the owl mascot as a LIVE brand mark: its pupils follow the cursor and it blinks. The
# vendored mascot SVG (assets/furby.svg) is rendered as the still base MINUS its pupils/highlights;
# OwlMark paints those on top so the gaze + blink are dynamic. Offline, cheap, and unobtrusive —
# a slow occasional blink and a gentle gaze, nothing that distracts under exam pressure.

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

# easter egg: clicking the mascot plays one of these little reactions (motion + a mood tint). Purely
# cosmetic personality — no state, no network, ends on its own. Durations in ms.
_REACTIONS: tuple[tuple[str, int], ...] = (
    ("spin", 700),
    ("backflip", 800),
    ("bounce", 700),
    ("mad", 650),
    ("wobble", 700),
    ("smile", 700),
    ("dance", 1100),
    ("dizzy", 1200),
    ("cry", 1200),
    ("nod", 700),
    # anime moves — 2s each so they're actually seen
    ("powerup", 2000),  # gold super-saiyan aura flare
    ("kamehameha", 2000),  # charge a cyan energy ball, then fire a beam
    ("flex", 2000),  # shoulder-press show-off
    ("taz", 2000),  # spin like the Tasmanian devil (dust tornado)
    ("breakdance", 2000),  # spin + floor slides
    ("pullups", 2000),  # rhythmic pull-ups
    ("jump", 2000),  # double leap
    ("vibrate", 2000),  # excited jitter
    ("faint", 2000),  # topple over
    ("boing", 2000),  # springy stretch/squash
    ("sneeze", 2000),  # rear back + achoo
    ("love", 2000),  # pink float-up
)


def _base_svg() -> bytes:
    # the mascot minus its pupils (#08252b) + highlights (#ffffff) — OwlMark paints those live.
    text = asset_path(FURBY).read_text(encoding="utf-8")
    text = re.sub(r'<circle[^>]*fill="#08252b"[^>]*>(?:</circle>)?', "", text)
    text = re.sub(r'<circle[^>]*fill="#ffffff"[^>]*>(?:</circle>)?', "", text)
    return text.encode("utf-8")


class OwlMark(QWidget):
    """The Nabu mascot as a living mark: cursor-tracking pupils + an occasional blink."""

    def __init__(self, size: int = 34, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setToolTip("Nabu — Local Recon Workspace")
        self.setAccessibleName("Nabu mascot")
        self.setCursor(Qt.CursorShape.PointingHandCursor)  # subtle hint that it's clickable
        self._renderer = QSvgRenderer(QByteArray(_base_svg()))
        self._gaze = QPointF(0.0, 0.0)
        self._blink = 0.0  # 0 = open, 1 = shut

        # easter-egg reaction state (applied as a transform + tint in paintEvent)
        self._reaction = ""
        self._angle = 0.0
        self._scale = 1.0
        self._dx = 0.0
        self._dy = 0.0
        self._tear = 0.0
        self._tint = QColor(0, 0, 0, 0)
        self._fx = ""  # DBZ overlay to paint ("powerup" / "kamehameha"), driven by _t
        self._t = 0.0
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

        # poll the cursor so the gaze follows it anywhere in the window (not just on hover)
        self._follow = QTimer(self)
        self._follow.setInterval(45)
        self._follow.timeout.connect(self._track)
        self._next_blink = QTimer(self)
        self._next_blink.setSingleShot(True)
        self._next_blink.timeout.connect(self._do_blink)
        # Animate only on a real display and while shown. A repeating timer under the offscreen test
        # platform keeps the event loop from ever going idle (which hangs idle-waiters) — there the
        # owl renders as a still mark. Timers start/stop in showEvent/hideEvent.
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

    def _track(self) -> None:
        if not self.isVisible():
            return
        centre = self.mapToGlobal(self.rect().center())
        pos = QCursor.pos()
        radius = 260.0
        gx = max(-1.0, min(1.0, (pos.x() - centre.x()) / radius))
        gy = max(-1.0, min(1.0, (pos.y() - centre.y()) / radius))
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
        # pick (or force) a reaction and animate it once. Idempotent: a click mid-reaction restarts.
        choices = [r for r in _REACTIONS if name is None or r[0] == name]
        if not choices:
            return
        reaction, duration = random.choice(choices)
        self._reaction = reaction
        self._react_anim.stop()
        self._react_anim.setDuration(duration)
        if self._live:
            self._react_anim.start()
        else:  # offscreen (tests): no event loop to drive frames — just settle at rest
            self._reset_reaction()

    def _on_react(self, value: object) -> None:
        t = float(value) if isinstance(value, int | float) else 0.0
        r = self._reaction
        self._angle = self._dx = self._dy = self._tear = 0.0
        self._scale = 1.0
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
            self._tint = QColor(255, 60, 40, int(75 * math.sin(pi * t)))
        elif r == "wobble":
            self._angle = 16.0 * math.sin(6 * pi * t) * (1.0 - t)
        elif r == "smile":
            self._scale = 1.0 + 0.22 * math.sin(pi * t)
            self._tint = QColor(255, 200, 60, int(55 * math.sin(pi * t)))
        elif r == "dance":
            self._dx = 7.0 * math.sin(6 * pi * t)
            self._dy = -7.0 * abs(math.sin(4 * pi * t))
            self._angle = 9.0 * math.sin(6 * pi * t)
        elif r == "dizzy":
            self._angle = 720.0 * t * t
            self._scale = 1.0 - 0.08 * math.sin(pi * t)
        elif r == "cry":
            self._dy = 3.0 * math.sin(pi * t)
            self._tint = QColor(60, 140, 255, int(55 * math.sin(pi * t)))
            self._tear = t
        elif r == "nod":
            self._dy = 6.0 * math.sin(6 * pi * t) * (1.0 - 0.5 * t)
        elif r == "powerup":
            inten = math.sin(pi * t)
            self._scale = 1.0 + 0.16 * inten
            self._dy = -3.0 * inten
            self._tint = QColor(255, 205, 70, int(70 * inten))
            self._fx = "powerup"
        elif r == "kamehameha":
            # lean back to charge, then thrust forward to fire
            self._dx = -4.0 * (t * 2) if t < 0.5 else 4.0 * ((t - 0.5) * 2)
            self._fx = "kamehameha"
        elif r == "flex":  # shoulder press — bulge up on each rep
            reps = abs(math.sin(2.5 * pi * t))
            self._dy = -10.0 * reps
            self._scale = 1.0 + 0.11 * reps
            self._tint = QColor(255, 190, 60, int(45 * reps))
        elif r == "taz":  # Tasmanian-devil tornado spin
            self._angle = 1440.0 * t
            self._dx = 8.0 * math.sin(3 * pi * t) * (1.0 - t)
            self._scale = 0.9 + 0.14 * abs(math.sin(6 * pi * t))
            self._fx = "taz"
        elif r == "breakdance":
            self._angle = 720.0 * t
            self._dx = 11.0 * math.cos(2 * pi * t)
            self._dy = 5.0 * math.sin(4 * pi * t)
            self._scale = 0.95 + 0.1 * abs(math.sin(3 * pi * t))
        elif r == "pullups":
            reps = abs(math.sin(2.5 * pi * t))
            self._dy = -13.0 * reps
            self._scale = 1.0 - 0.04 * reps
        elif r == "jump":
            h = abs(math.sin(2 * pi * t))
            self._dy = -16.0 * h
            self._scale = 1.0 + 0.07 * h
        elif r == "vibrate":
            d = 1.0 - t
            self._dx = 2.4 * math.sin(46 * pi * t) * d
            self._dy = 2.0 * math.cos(42 * pi * t) * d
        elif r == "faint":
            e = min(t * 1.4, 1.0)
            self._angle = 90.0 * e
            self._dy = 12.0 * e
            self._tint = QColor(120, 160, 255, int(55 * math.sin(pi * t)))
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
            self._tint = QColor(255, 110, 150, int(70 * math.sin(pi * t)))
        self.update()

    def _reset_reaction(self) -> None:
        self._reaction = ""
        self._angle = self._dx = self._dy = self._tear = 0.0
        self._scale = 1.0
        self._tint = QColor(0, 0, 0, 0)
        self._fx = ""
        self._t = 0.0
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        # easter-egg transform: spin / flip / bounce / scale about the mascot's centre
        c = self.width() / 2.0
        painter.save()
        painter.translate(c + self._dx, c + self._dy)
        painter.rotate(self._angle)
        painter.scale(self._scale, self._scale)
        painter.translate(-c, -c)
        self._renderer.render(painter, QRectF(0, 0, float(self.width()), float(self.height())))
        s = self.width() / 100.0
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
        painter.restore()  # end the easter-egg transform — mood overlays draw in widget coords

        if self._tint.alpha() > 0:  # a mood wash (mad=red · smile=gold · cry=blue)
            painter.fillRect(self.rect(), self._tint)
        if self._tear > 0.0:  # a falling tear for the "cry" reaction
            ex, ey = _EYES[0]
            tx = ex * s
            ty = (ey + 8.0) * s + self._tear * self.height() * 0.55
            painter.setBrush(QColor(90, 170, 255, 220))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(QPointF(tx, ty), 2.2 * s, 3.0 * s)

        # DBZ energy overlays (widget coords, over the owl)
        if self._fx and self._t > 0.0:
            w = float(self.width())
            tt = self._t
            painter.setPen(Qt.PenStyle.NoPen)
            if self._fx == "powerup":
                inten = math.sin(math.pi * tt)
                aura = QRadialGradient(c, c, w * 0.78)
                aura.setColorAt(0.0, QColor(255, 244, 190, int(150 * inten)))
                aura.setColorAt(0.35, QColor(255, 196, 60, int(120 * inten)))
                aura.setColorAt(0.7, QColor(255, 130, 30, int(70 * inten)))
                aura.setColorAt(1.0, QColor(255, 120, 20, 0))
                painter.setBrush(aura)
                painter.drawEllipse(QPointF(c, c), w * 0.78, w * 0.86)
                painter.setBrush(QColor(255, 226, 130, int(210 * inten)))
                for i in range(6):
                    ph = (tt * 3 + i * 0.5) % 1.0
                    fx = c + (i - 2.5) * w * 0.14
                    fy = c + w * 0.28 - ph * w * 0.7
                    painter.drawEllipse(QPointF(fx, fy), w * 0.032 * (1 - ph), w * 0.06 * (1 - ph))
            elif self._fx == "kamehameha":
                bx, by = c + w * 0.30, c + w * 0.05
                if tt < 0.5:  # charge the ball
                    r = (tt / 0.5) * w * 0.2
                    halo = QRadialGradient(bx, by, r * 2.0)
                    halo.setColorAt(0.0, QColor(150, 225, 255, 200))
                    halo.setColorAt(0.5, QColor(60, 150, 255, 70))
                    halo.setColorAt(1.0, QColor(60, 150, 255, 0))
                    painter.setBrush(halo)
                    painter.drawEllipse(QPointF(bx, by), r * 2.0, r * 2.0)
                    core = QRadialGradient(bx - r * 0.2, by - r * 0.2, r)
                    core.setColorAt(0.0, QColor(255, 255, 255))
                    core.setColorAt(0.6, QColor(140, 220, 255, 235))
                    core.setColorAt(1.0, QColor(60, 150, 255, 140))
                    painter.setBrush(core)
                    painter.drawEllipse(QPointF(bx, by), r, r)
                    painter.setPen(QPen(QColor(255, 255, 255, 220), max(1.0, w * 0.012)))
                    painter.drawLine(QPointF(bx - r * 2.4, by), QPointF(bx + r * 2.4, by))
                    painter.drawLine(QPointF(bx, by - r * 2.4), QPointF(bx, by + r * 2.4))
                    painter.setPen(Qt.PenStyle.NoPen)
                else:  # fire the beam
                    k = min(1.0, (tt - 0.5) / 0.3)
                    h = w * 0.13 * (1.25 - 0.45 * k)
                    x2 = w + 4.0
                    og = QLinearGradient(0.0, by - h * 2.4, 0.0, by + h * 2.4)
                    og.setColorAt(0.0, QColor(92, 208, 255, 0))
                    og.setColorAt(0.5, QColor(92, 208, 255, 150))
                    og.setColorAt(1.0, QColor(92, 208, 255, 0))
                    painter.setBrush(og)
                    painter.drawRoundedRect(QRectF(bx, by - h * 2.4, x2 - bx, h * 4.8), h, h)
                    painter.setBrush(QColor(92, 208, 255, 235))
                    painter.drawRoundedRect(QRectF(bx, by - h, x2 - bx, h * 2), h, h)
                    painter.setBrush(QColor(255, 255, 255, 245))
                    painter.drawRoundedRect(
                        QRectF(bx, by - h * 0.42, x2 - bx, h * 0.84), h * 0.4, h * 0.4
                    )
                    mb = QRadialGradient(bx, by, h * 2.6)
                    mb.setColorAt(0.0, QColor(255, 255, 255, 235))
                    mb.setColorAt(0.5, QColor(140, 220, 255, 140))
                    mb.setColorAt(1.0, QColor(92, 208, 255, 0))
                    painter.setBrush(mb)
                    painter.drawEllipse(QPointF(bx, by), h * 2.6, h * 2.6)
                    if k < 0.35:
                        painter.fillRect(
                            self.rect(), QColor(255, 255, 255, int(130 * (1 - k / 0.35)))
                        )
            elif self._fx == "taz":  # dust-tornado swirl arcs
                painter.setPen(QPen(QColor(190, 160, 120, 150), max(1.0, w * 0.03)))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                for i in range(3):
                    rr = w * (0.30 + 0.12 * i)
                    a0 = int((tt * 1440 + i * 130) % 360)
                    painter.drawArc(QRectF(c - rr, c - rr, rr * 2, rr * 2), a0 * 16, 210 * 16)
                painter.setPen(Qt.PenStyle.NoPen)
        painter.end()
