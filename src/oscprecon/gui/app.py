from __future__ import annotations

import os
import sys

from PySide6.QtCore import QCoreApplication, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from oscprecon import diagnostics
from oscprecon.branding import APP_NAME
from oscprecon.gui.assets import ICON, asset_path
from oscprecon.gui.main_window import MainWindow
from oscprecon.gui.splash import NabuSplash, make_splash


def _has_display() -> bool:
    # why: on a headless box / over SSH / a distro missing Qt's xcb libs, QApplication() aborts at
    # the C++ level ("could not load the Qt platform plugin xcb") with a coredump Python can't catch.
    # Detect the no-display case first so we can exit with an actionable message instead. This is the
    # "GUI works for some, not others" split: the CLI never needs a display; the GUI always does.
    platform = os.environ.get("QT_QPA_PLATFORM", "")
    if platform:  # an explicit platform (offscreen/minimal/vnc/wayland/…) — trust it, let Qt decide
        return True
    if sys.platform in ("win32", "darwin"):  # native window server is always present
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def main() -> int:
    if not _has_display():
        sys.stderr.write(
            f"{APP_NAME}: no graphical display found (DISPLAY / WAYLAND_DISPLAY are unset).\n"
            "The GUI needs a desktop; on a headless box use the CLI instead:\n\n"
            "  nabu-cli --help          # everything the GUI does, headless\n"
            "  nabu-cli doctor          # check the wrapped tools\n"
            "  nabu-cli scan IP -p NAME # run a scan\n\n"
            "To use the GUI anyway:\n"
            "  • over SSH:   ssh -X user@host   then run: nabu\n"
            "  • in Docker:  docker/nabu-docker.sh gui   (forwards your X11 socket)\n"
        )
        return 3
    # why: capture crashes + Qt warnings to a log file early, before anything can fail (Help → View
    # Diagnostics Log surfaces it). Best-effort — never blocks startup.
    diagnostics.install("gui")
    diagnostics.install_qt_message_handler()
    from oscprecon import config

    config.apply_redaction_policy()  # owner policy: never redact (unless the pref is flipped on)
    # why: QtWebEngine needs shared GL contexts set before the QApplication, and lab boxes / VMs
    # often have no GPU, no sandbox, and a tiny /dev/shm. --no-sandbox + --disable-gpu let the
    # embedded browser initialise; --disable-gpu-compositing avoids a blank canvas under software
    # rendering; --disable-dev-shm-usage stops the Chromium render process from crashing (which
    # shows as a blank graph) when /dev/shm is small — the common Kali-in-a-VM failure.
    os.environ.setdefault(
        "QTWEBENGINE_CHROMIUM_FLAGS",
        "--no-sandbox --disable-gpu --disable-gpu-compositing --disable-dev-shm-usage",
    )
    QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    # why: match the installed `nabu.desktop` so the X11 WM_CLASS lines up — the taskbar/panel then
    # groups the running window under its pinned launcher instead of a generic "python" entry.
    app.setDesktopFileName("nabu")
    app.setWindowIcon(QIcon(str(asset_path(ICON))))

    splash: NabuSplash | None = None
    try:
        splash = make_splash()
        splash.show()
        app.processEvents()  # paint it before the slower MainWindow (QtWebEngine) build
    except Exception:  # why: the splash is optional chrome — never let it block startup (§27)
        splash = None

    window = MainWindow()
    window.show()
    if splash is not None:
        splash.finish(window)
    return app.exec()
