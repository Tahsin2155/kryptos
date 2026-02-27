"""
Kryptos Local Desktop Edition — Entry Point
============================================

Launch the PySide6 GUI application.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on sys.path so ``import algo`` works
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QApplication

from main_window import KryptosMainWindow
from styles import STYLESHEET


def main() -> None:
    """Application entry point."""
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("Kryptos")
    app.setOrganizationName("Kryptos")
    app.setApplicationVersion("1.0.0")

    # Global font
    font = QFont("Segoe UI", 10)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(font)

    # Apply dark theme stylesheet
    app.setStyleSheet(STYLESHEET)

    window = KryptosMainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
