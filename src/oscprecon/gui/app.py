from __future__ import annotations

import os
import sys

from PySide6.QtCore import QCoreApplication, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QSplashScreen

from oscprecon.branding import APP_NAME
from oscprecon.gui.assets import ICON, asset_path
from oscprecon.gui.main_window import MainWindow
from oscprecon.gui.splash import make_splash


def main() -> int:
    # why: QtWebEngine needs shared GL contexts set before the QApplication, and lab boxes often
    # have no GPU/sandbox — disable both so the embedded HackTricks browser initialises.
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--no-sandbox --disable-gpu")
    QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setWindowIcon(QIcon(str(asset_path(ICON))))

    splash: QSplashScreen | None = None
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
