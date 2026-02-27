"""
Kryptos Main Window
====================

Tabbed main window with:
  - Text Encryption / Decryption
  - File Encryption / Decryption
  - Key Management
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from file_tab import FileTab
from key_manager import KeyManager
from key_tab import KeyTab
from text_tab import TextTab


class KryptosMainWindow(QMainWindow):
    """Main application window."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Kryptos — Encryption & Decryption")
        self.setMinimumSize(580, 420)
        self.resize(1050, 720)

        # Shared key manager
        self.key_manager = KeyManager()

        self._setup_ui()
        self._setup_menubar()
        self._setup_statusbar()

    # ----- UI setup -----

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 8, 10, 4)
        layout.setSpacing(6)

        # Header
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        title = QLabel("KRYPTOS")
        title.setStyleSheet(
            "font-size: 22px; font-weight: 800; letter-spacing: 4px;"
            "color: #eaeaea; padding: 0;"
        )
        header_layout.addWidget(title)

        subtitle = QLabel("Local Desktop Edition")
        subtitle.setStyleSheet(
            "font-size: 12px; color: #a0a0b8; padding-top: 8px;"
        )
        header_layout.addWidget(subtitle)
        header_layout.addStretch()

        version_label = QLabel("v1.0.0")
        version_label.setStyleSheet(
            "font-size: 11px; color: #6c6c80; padding-top: 8px;"
        )
        header_layout.addWidget(version_label)

        layout.addLayout(header_layout)

        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # Create tabs
        self.text_tab = TextTab(self.key_manager)
        self.file_tab = FileTab(self.key_manager)
        self.key_tab = KeyTab(self.key_manager)

        self.tabs.addTab(self.text_tab, "  Text  ")
        self.tabs.addTab(self.file_tab, "  File  ")
        self.tabs.addTab(self.key_tab, "  Keys  ")

        layout.addWidget(self.tabs)

    def _setup_menubar(self) -> None:
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        text_action = QAction("&Text Tab", self)
        text_action.setShortcut("Ctrl+1")
        text_action.triggered.connect(lambda: self.tabs.setCurrentIndex(0))
        view_menu.addAction(text_action)

        file_action = QAction("&File Tab", self)
        file_action.setShortcut("Ctrl+2")
        file_action.triggered.connect(lambda: self.tabs.setCurrentIndex(1))
        view_menu.addAction(file_action)

        keys_action = QAction("&Keys Tab", self)
        keys_action.setShortcut("Ctrl+3")
        keys_action.triggered.connect(lambda: self.tabs.setCurrentIndex(2))
        view_menu.addAction(keys_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")
        about_action = QAction("&About Kryptos", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_statusbar(self) -> None:
        status = QStatusBar()
        status.showMessage("Ready")
        self.setStatusBar(status)

    def _show_about(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        QMessageBox.about(
            self,
            "About Kryptos",
            "<h2>Kryptos</h2>"
            "<p>Local Desktop Edition v1.0.0</p>"
            "<p>AES-256-GCM authenticated encryption with "
            "PBKDF2 key derivation and RSA-4096 hybrid encryption.</p>"
            "<p>Cross-platform • Offline • Interoperable with Web Edition</p>",
        )
