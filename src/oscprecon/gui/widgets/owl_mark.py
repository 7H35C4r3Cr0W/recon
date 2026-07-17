from __future__ import annotations

import random
import re

from PySide6.QtCore import QByteArray, QPointF, QRectF, Qt, QTimer, QVariantAnimation
from PySide6.QtGui import (
    QColor,
    QCursor,
    QGuiApplication,
    QHideEvent,
    QPainter,
    QPainterPath,
    QPaintEvent,
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
        self._renderer = QSvgRenderer(QByteArray(_base_svg()))
        self._gaze = QPointF(0.0, 0.0)
        self._blink = 0.0  # 0 = open, 1 = shut

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

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
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
        painter.end()
