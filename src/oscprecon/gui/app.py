from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from oscprecon.gui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("oscp-recon")
    window = MainWindow()
    window.show()
    return app.exec()
