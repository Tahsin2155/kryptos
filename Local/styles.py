"""
Kryptos Dark Theme Stylesheet
===============================

Modern dark theme for the PySide6 desktop application.
"""

# Color palette
_BG_DARK = "#1a1a2e"
_BG_MEDIUM = "#16213e"
_BG_LIGHT = "#0f3460"
_BG_CARD = "#1e2a4a"
_BG_INPUT = "#0d1b3e"
_ACCENT = "#e94560"
_ACCENT_HOVER = "#ff6b81"
_ACCENT_PRESSED = "#c0392b"
_TEXT_PRIMARY = "#eaeaea"
_TEXT_SECONDARY = "#a0a0b8"
_TEXT_MUTED = "#6c6c80"
_BORDER = "#2a2a4a"
_BORDER_FOCUS = "#e94560"
_SUCCESS = "#2ecc71"
_WARNING = "#f39c12"
_ERROR = "#e74c3c"
_SCROLLBAR = "#2a2a4a"
_SCROLLBAR_HANDLE = "#4a4a6a"

STYLESHEET = f"""
/* ===== Global ===== */
QWidget {{
    background-color: {_BG_DARK};
    color: {_TEXT_PRIMARY};
    font-family: "Segoe UI", "SF Pro Display", "Helvetica Neue", sans-serif;
}}

/* ===== Main Window ===== */
QMainWindow {{
    background-color: {_BG_DARK};
}}

/* ===== Tab Widget ===== */
QTabWidget::pane {{
    border: 1px solid {_BORDER};
    border-radius: 8px;
    background-color: {_BG_MEDIUM};
    margin-top: -1px;
}}

QTabBar::tab {{
    background-color: {_BG_DARK};
    color: {_TEXT_SECONDARY};
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    border: 1px solid transparent;
    border-bottom: 2px solid transparent;
    font-weight: 500;
    font-size: 13px;
    min-width: 60px;
}}

QTabBar::tab:selected {{
    background-color: {_BG_MEDIUM};
    color: {_TEXT_PRIMARY};
    border: 1px solid {_BORDER};
    border-bottom: 2px solid {_ACCENT};
}}

QTabBar::tab:hover:!selected {{
    background-color: {_BG_CARD};
    color: {_TEXT_PRIMARY};
}}

/* ===== Group Box ===== */
QGroupBox {{
    background-color: {_BG_CARD};
    border: 1px solid {_BORDER};
    border-radius: 8px;
    margin-top: 14px;
    padding: 20px 12px 10px 12px;
    font-weight: 600;
    font-size: 13px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 4px 12px;
    color: {_ACCENT};
    font-size: 13px;
}}

/* ===== Labels ===== */
QLabel {{
    background-color: transparent;
    color: {_TEXT_PRIMARY};
    font-size: 13px;
}}

QLabel[class="heading"] {{
    font-size: 18px;
    font-weight: 700;
    color: {_TEXT_PRIMARY};
}}

QLabel[class="subheading"] {{
    font-size: 12px;
    color: {_TEXT_SECONDARY};
}}

QLabel[class="status-success"] {{
    color: {_SUCCESS};
    font-weight: 600;
}}

QLabel[class="status-error"] {{
    color: {_ERROR};
    font-weight: 600;
}}

QLabel[class="status-warning"] {{
    color: {_WARNING};
    font-weight: 600;
}}

/* ===== Push Buttons ===== */
QPushButton {{
    background-color: {_ACCENT};
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 8px 20px;
    font-weight: 600;
    font-size: 13px;
    min-height: 20px;
}}

QPushButton:hover {{
    background-color: {_ACCENT_HOVER};
}}

QPushButton:pressed {{
    background-color: {_ACCENT_PRESSED};
}}

QPushButton:disabled {{
    background-color: {_BG_LIGHT};
    color: {_TEXT_MUTED};
}}

QPushButton[class="secondary"] {{
    background-color: {_BG_LIGHT};
    color: {_TEXT_PRIMARY};
    border: 1px solid {_BORDER};
}}

QPushButton[class="secondary"]:hover {{
    background-color: {_BG_CARD};
    border-color: {_ACCENT};
}}

QPushButton[class="danger"] {{
    background-color: {_ERROR};
}}

QPushButton[class="danger"]:hover {{
    background-color: #c0392b;
}}

QPushButton[class="success"] {{
    background-color: {_SUCCESS};
    color: #1a1a2e;
}}

QPushButton[class="success"]:hover {{
    background-color: #27ae60;
}}

/* ===== Line Edit ===== */
QLineEdit {{
    background-color: {_BG_INPUT};
    color: {_TEXT_PRIMARY};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 13px;
    selection-background-color: {_ACCENT};
}}

QLineEdit:focus {{
    border-color: {_BORDER_FOCUS};
}}

QLineEdit:disabled {{
    background-color: {_BG_DARK};
    color: {_TEXT_MUTED};
}}

/* ===== Text Edit / Plain Text Edit ===== */
QTextEdit, QPlainTextEdit {{
    background-color: {_BG_INPUT};
    color: {_TEXT_PRIMARY};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 8px;
    font-family: "Cascadia Code", "Fira Code", "Consolas", monospace;
    font-size: 13px;
    selection-background-color: {_ACCENT};
}}

QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {_BORDER_FOCUS};
}}

/* ===== Combo Box ===== */
QComboBox {{
    background-color: {_BG_INPUT};
    color: {_TEXT_PRIMARY};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 13px;
    min-height: 20px;
}}

QComboBox:hover {{
    border-color: {_ACCENT};
}}

QComboBox::drop-down {{
    border: none;
    width: 30px;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {_TEXT_SECONDARY};
    margin-right: 8px;
}}

QComboBox QAbstractItemView {{
    background-color: {_BG_CARD};
    color: {_TEXT_PRIMARY};
    border: 1px solid {_BORDER};
    selection-background-color: {_BG_LIGHT};
    outline: none;
}}

/* ===== Radio Button ===== */
QRadioButton {{
    background-color: transparent;
    color: {_TEXT_PRIMARY};
    spacing: 8px;
    font-size: 13px;
}}

QRadioButton::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 9px;
    border: 2px solid {_BORDER};
    background-color: {_BG_INPUT};
}}

QRadioButton::indicator:checked {{
    border-color: {_ACCENT};
    background-color: {_ACCENT};
}}

QRadioButton::indicator:hover {{
    border-color: {_ACCENT_HOVER};
}}

/* ===== Check Box ===== */
QCheckBox {{
    background-color: transparent;
    color: {_TEXT_PRIMARY};
    spacing: 8px;
    font-size: 13px;
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 2px solid {_BORDER};
    background-color: {_BG_INPUT};
}}

QCheckBox::indicator:checked {{
    border-color: {_ACCENT};
    background-color: {_ACCENT};
}}

/* ===== Progress Bar ===== */
QProgressBar {{
    background-color: {_BG_INPUT};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    text-align: center;
    color: {_TEXT_PRIMARY};
    font-size: 12px;
    min-height: 22px;
}}

QProgressBar::chunk {{
    background-color: {_ACCENT};
    border-radius: 5px;
}}

/* ===== Scroll Bar ===== */
QScrollBar:vertical {{
    background-color: {_SCROLLBAR};
    width: 10px;
    border-radius: 5px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background-color: {_SCROLLBAR_HANDLE};
    min-height: 30px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {_ACCENT};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background-color: {_SCROLLBAR};
    height: 10px;
    border-radius: 5px;
}}

QScrollBar::handle:horizontal {{
    background-color: {_SCROLLBAR_HANDLE};
    min-width: 30px;
    border-radius: 5px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {_ACCENT};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* ===== Table / List Widget ===== */
QTableWidget, QListWidget {{
    background-color: {_BG_INPUT};
    color: {_TEXT_PRIMARY};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    gridline-color: {_BORDER};
    font-size: 13px;
}}

QTableWidget::item, QListWidget::item {{
    padding: 6px 8px;
}}

QTableWidget::item:selected, QListWidget::item:selected {{
    background-color: {_BG_LIGHT};
    color: {_TEXT_PRIMARY};
}}

QHeaderView::section {{
    background-color: {_BG_CARD};
    color: {_TEXT_SECONDARY};
    padding: 8px;
    border: none;
    border-bottom: 1px solid {_BORDER};
    font-weight: 600;
    font-size: 12px;
}}

/* ===== Splitter ===== */
QSplitter::handle {{
    background-color: {_BORDER};
    width: 5px;
    margin: 4px 2px;
    border-radius: 2px;
}}

QSplitter::handle:hover {{
    background-color: {_ACCENT};
}}

/* ===== Tool Tip ===== */
QToolTip {{
    background-color: {_BG_CARD};
    color: {_TEXT_PRIMARY};
    border: 1px solid {_BORDER};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}}

/* ===== Status Bar ===== */
QStatusBar {{
    background-color: {_BG_MEDIUM};
    color: {_TEXT_SECONDARY};
    border-top: 1px solid {_BORDER};
    font-size: 12px;
    padding: 4px 8px;
    min-height: 22px;
}}

/* ===== Menu Bar ===== */
QMenuBar {{
    background-color: {_BG_DARK};
    color: {_TEXT_PRIMARY};
    border-bottom: 1px solid {_BORDER};
}}

QMenuBar::item:selected {{
    background-color: {_BG_LIGHT};
}}

QMenu {{
    background-color: {_BG_CARD};
    color: {_TEXT_PRIMARY};
    border: 1px solid {_BORDER};
    border-radius: 4px;
    padding: 4px;
}}

QMenu::item {{
    padding: 6px 24px;
}}

QMenu::item:selected {{
    background-color: {_BG_LIGHT};
}}

QMenu::separator {{
    height: 1px;
    background-color: {_BORDER};
    margin: 4px 8px;
}}

/* ===== Frame ===== */
QFrame[class="separator"] {{
    background-color: {_BORDER};
    max-height: 1px;
}}

QFrame[class="card"] {{
    background-color: {_BG_CARD};
    border: 1px solid {_BORDER};
    border-radius: 8px;
}}

/* ===== Scroll Area ===== */
QScrollArea {{
    background-color: transparent;
    border: none;
}}

QScrollArea > QWidget > QWidget {{
    background-color: transparent;
}}
"""
