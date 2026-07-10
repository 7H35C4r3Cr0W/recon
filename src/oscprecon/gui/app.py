from __future__ import annotations

import os
import sys

from PySide6.QtCore import QCoreApplication, Qt
from PySide6.QtWidgets import QApplication

from oscprecon.gui.main_window import MainWindow


def main() -> int:
    # why: QtWebEngine needs shared GL contexts set before the QApplication, and lab boxes often
    # have no GPU/sandbox — disable both so the embedded HackTricks browser initialises.
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--no-sandbox --disable-gpu")
    QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
    app = QApplication(sys.argv)
    app.setApplicationName("oscp-recon")
    window = MainWindow()
    window.show()
    return app.exec()
