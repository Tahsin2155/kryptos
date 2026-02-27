"""
Kryptos Text Tab
=================

Text encryption and decryption with support for:
  - Raw key mode (system-generated or stored key)
  - Passphrase mode (PBKDF2)
  - Base64 output for easy copy/paste
"""

from __future__ import annotations

import base64
import re
import math

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

import algo
from key_manager import KeyManager
from workers import TextDecryptWorker, TextEncryptWorker


def _passphrase_strength(passphrase: str) -> tuple[int, str, str]:
    """Return (score 0-100, label, color) for passphrase strength."""
    if not passphrase:
        return 0, "", "#6c6c80"
    length = len(passphrase)
    # Entropy estimation
    pool = 0
    if re.search(r"[a-z]", passphrase):
        pool += 26
    if re.search(r"[A-Z]", passphrase):
        pool += 26
    if re.search(r"[0-9]", passphrase):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", passphrase):
        pool += 32
    pool = max(pool, 1)
    entropy = length * math.log2(pool)
    # Map entropy to score
    score = min(int(entropy * 100 / 128), 100)
    if score < 25:
        return score, "Weak", "#e74c3c"
    if score < 50:
        return score, "Fair", "#f39c12"
    if score < 75:
        return score, "Good", "#3498db"
    return score, "Strong", "#2ecc71"


class TextTab(QWidget):
    """Text encryption / decryption tab."""

    def __init__(self, key_manager: KeyManager, parent=None):
        super().__init__(parent)
        self._km = key_manager
        self._worker = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # ----- Key Mode Selection -----
        key_group = QGroupBox("Key Mode")
        key_layout = QVBoxLayout(key_group)

        mode_row = QHBoxLayout()
        self._mode_group = QButtonGroup(self)

        self._radio_stored = QRadioButton("Stored Key")
        self._radio_passphrase = QRadioButton("Passphrase")
        self._radio_stored.setChecked(True)

        self._mode_group.addButton(self._radio_stored, 0)
        self._mode_group.addButton(self._radio_passphrase, 1)

        mode_row.addWidget(self._radio_stored)
        mode_row.addWidget(self._radio_passphrase)
        mode_row.addStretch()
        key_layout.addLayout(mode_row)

        # Stored key selector
        self._key_row = QHBoxLayout()
        self._key_label = QLabel("Select Key:")
        self._key_combo = QComboBox()
        self._key_combo.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self._refresh_key_combo()
        self._key_row.addWidget(self._key_label)
        self._key_row.addWidget(self._key_combo, 1)
        key_layout.addLayout(self._key_row)

        # Passphrase input
        self._pass_row = QHBoxLayout()
        self._pass_label = QLabel("Passphrase:")
        self._passphrase_input = QLineEdit()
        self._passphrase_input.setPlaceholderText("Enter your passphrase...")
        self._passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._show_pass_btn = QPushButton("Show")
        self._show_pass_btn.setProperty("class", "secondary")
        self._show_pass_btn.setFixedWidth(60)
        self._show_pass_btn.clicked.connect(self._toggle_passphrase_visibility)
        self._pass_row.addWidget(self._pass_label)
        self._pass_row.addWidget(self._passphrase_input, 1)
        self._pass_row.addWidget(self._show_pass_btn)
        key_layout.addLayout(self._pass_row)

        # Passphrase strength meter
        strength_row = QHBoxLayout()
        self._strength_bar = QProgressBar()
        self._strength_bar.setFixedHeight(6)
        self._strength_bar.setTextVisible(False)
        self._strength_bar.setRange(0, 100)
        self._strength_bar.setValue(0)
        self._strength_bar.setStyleSheet(
            "QProgressBar { background-color: #0d1b3e; border: none; border-radius: 3px; }"
            "QProgressBar::chunk { background-color: #6c6c80; border-radius: 3px; }"
        )
        self._strength_label = QLabel("")
        self._strength_label.setStyleSheet("font-size: 11px; color: #6c6c80;")
        self._strength_label.setFixedWidth(60)
        strength_row.addWidget(self._strength_bar, 1)
        strength_row.addWidget(self._strength_label)
        key_layout.addLayout(strength_row)

        self._passphrase_input.textChanged.connect(self._on_passphrase_changed)
        # Enter key triggers encrypt
        self._passphrase_input.returnPressed.connect(self._on_encrypt)

        layout.addWidget(key_group)

        # Toggle visibility of key mode fields
        self._mode_group.idToggled.connect(self._on_mode_changed)
        self._on_mode_changed(0, True)

        # ----- Input / Output -----
        self._splitter = QSplitter(Qt.Orientation.Horizontal)

        # Input panel
        input_panel = QWidget()
        input_layout = QVBoxLayout(input_panel)
        input_layout.setContentsMargins(0, 0, 4, 0)

        input_header = QHBoxLayout()
        input_label = QLabel("Input")
        input_label.setStyleSheet("font-weight: 600; font-size: 14px;")
        input_header.addWidget(input_label)
        input_header.addStretch()

        self._paste_btn = QPushButton("Paste")
        self._paste_btn.setProperty("class", "secondary")
        self._paste_btn.setFixedWidth(60)
        self._paste_btn.clicked.connect(self._paste_input)
        input_header.addWidget(self._paste_btn)

        self._clear_input_btn = QPushButton("Clear")
        self._clear_input_btn.setProperty("class", "secondary")
        self._clear_input_btn.setFixedWidth(60)
        self._clear_input_btn.clicked.connect(lambda: self._input_text.clear())
        input_header.addWidget(self._clear_input_btn)
        input_layout.addLayout(input_header)

        self._input_text = QPlainTextEdit()
        self._input_text.setPlaceholderText(
            "Enter plaintext to encrypt,\nor paste Base64 ciphertext to decrypt..."
        )
        input_layout.addWidget(self._input_text)

        # Input stats
        self._input_stats = QLabel("0 chars | 0 bytes")
        self._input_stats.setStyleSheet("font-size: 11px; color: #a0a0b8; padding: 2px 0;")
        input_layout.addWidget(self._input_stats)
        self._input_text.textChanged.connect(self._update_input_stats)

        # Output panel
        output_panel = QWidget()
        output_layout = QVBoxLayout(output_panel)
        output_layout.setContentsMargins(4, 0, 0, 0)

        output_header = QHBoxLayout()
        output_label = QLabel("Output")
        output_label.setStyleSheet("font-weight: 600; font-size: 14px;")
        output_header.addWidget(output_label)
        output_header.addStretch()

        self._copy_btn = QPushButton("Copy")
        self._copy_btn.setProperty("class", "secondary")
        self._copy_btn.setFixedWidth(60)
        self._copy_btn.clicked.connect(self._copy_output)
        output_header.addWidget(self._copy_btn)
        output_layout.addLayout(output_header)

        self._output_text = QPlainTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setPlaceholderText("Result will appear here...")
        output_layout.addWidget(self._output_text)

        # Output stats
        self._output_stats = QLabel("")
        self._output_stats.setStyleSheet("font-size: 11px; color: #a0a0b8; padding: 2px 0;")
        output_layout.addWidget(self._output_stats)

        self._splitter.addWidget(input_panel)
        self._splitter.addWidget(output_panel)
        self._splitter.setSizes([500, 500])
        layout.addWidget(self._splitter, 1)

        # ----- Action Buttons -----
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self._encrypt_btn = QPushButton("  Encrypt  ")
        self._encrypt_btn.setFixedHeight(40)
        self._encrypt_btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self._encrypt_btn.clicked.connect(self._on_encrypt)

        self._decrypt_btn = QPushButton("  Decrypt  ")
        self._decrypt_btn.setFixedHeight(40)
        self._decrypt_btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self._decrypt_btn.setProperty("class", "secondary")
        self._decrypt_btn.clicked.connect(self._on_decrypt)

        self._swap_btn = QPushButton("Output → Input")
        self._swap_btn.setProperty("class", "secondary")
        self._swap_btn.setFixedHeight(40)
        self._swap_btn.clicked.connect(self._swap_output_to_input)

        btn_row.addWidget(self._encrypt_btn)
        btn_row.addWidget(self._decrypt_btn)
        btn_row.addWidget(self._swap_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Status
        self._status_label = QLabel("")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setMinimumHeight(24)
        self._status_label.setStyleSheet("padding: 4px 0;")
        layout.addWidget(self._status_label)

    # ----- Key mode toggling -----

    def _on_mode_changed(self, id_: int, checked: bool) -> None:
        if not checked:
            return
        is_stored = id_ == 0
        self._key_label.setVisible(is_stored)
        self._key_combo.setVisible(is_stored)
        self._pass_label.setVisible(not is_stored)
        self._passphrase_input.setVisible(not is_stored)
        self._show_pass_btn.setVisible(not is_stored)
        self._strength_bar.setVisible(not is_stored)
        self._strength_label.setVisible(not is_stored)

    def _on_passphrase_changed(self, text: str) -> None:
        score, label, color = _passphrase_strength(text)
        self._strength_bar.setValue(score)
        self._strength_bar.setStyleSheet(
            f"QProgressBar {{ background-color: #0d1b3e; border: none; border-radius: 3px; }}"
            f"QProgressBar::chunk {{ background-color: {color}; border-radius: 3px; }}"
        )
        self._strength_label.setText(label)
        self._strength_label.setStyleSheet(f"font-size: 11px; color: {color};")

    def _toggle_passphrase_visibility(self) -> None:
        if self._passphrase_input.echoMode() == QLineEdit.EchoMode.Password:
            self._passphrase_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._show_pass_btn.setText("Hide")
        else:
            self._passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._show_pass_btn.setText("Show")

    def _refresh_key_combo(self) -> None:
        self._key_combo.clear()
        keys = self._km.list_keys()
        if not keys:
            self._key_combo.addItem("(No keys — go to Keys tab to create one)", "")
        for entry in keys:
            label = f"{entry.name}  [{entry.mode}]"
            self._key_combo.addItem(label, entry.key_id)

    def refresh_keys(self) -> None:
        """Public method: refresh combo box when keys change."""
        self._refresh_key_combo()

    # ----- Get key / passphrase -----

    def _get_key_or_passphrase(self):
        """Return (key_bytes, None) or (None, passphrase_str)."""
        if self._radio_passphrase.isChecked():
            pp = self._passphrase_input.text().strip()
            if not pp:
                raise ValueError("Please enter a passphrase.")
            return None, pp
        else:
            key_id = self._key_combo.currentData()
            if not key_id:
                raise ValueError(
                    "No key selected. Go to the Keys tab to generate or import one."
                )
            entry = self._km.get_key(key_id)
            if not entry:
                raise ValueError("Selected key not found.")
            return entry.get_key_bytes(), None

    # ----- Encrypt -----

    def _cleanup_worker(self) -> None:
        """Ensure previous worker is finished and cleaned up."""
        if self._worker is not None:
            if self._worker.isRunning():
                self._worker.wait(2000)
            self._worker.deleteLater()
            self._worker = None

    def _on_encrypt(self) -> None:
        text = self._input_text.toPlainText()
        if not text:
            self._set_status("Please enter text to encrypt.", "error")
            return

        try:
            key, passphrase = self._get_key_or_passphrase()
        except ValueError as e:
            self._set_status(str(e), "error")
            return

        self._cleanup_worker()
        self._set_busy(True)
        self._set_status("Encrypting...", "warning")

        plaintext = text.encode("utf-8")
        self._worker = TextEncryptWorker(
            plaintext, key=key, passphrase=passphrase, parent=self
        )
        self._worker.finished.connect(self._on_encrypt_done)
        self._worker.error.connect(self._on_worker_error)
        self._worker.start()

    def _on_encrypt_done(self, encrypted: bytes) -> None:
        # Output as Base64 for easy copy/paste
        b64 = base64.b64encode(encrypted).decode("ascii")
        self._output_text.setPlainText(b64)
        self._output_stats.setText(f"{len(b64)} chars | {len(encrypted)} bytes encrypted")
        self._set_status("Encryption successful!", "success")
        self._set_busy(False)

    # ----- Decrypt -----

    def _on_decrypt(self) -> None:
        text = self._input_text.toPlainText().strip()
        if not text:
            self._set_status("Please paste Base64 ciphertext to decrypt.", "error")
            return

        try:
            ciphertext = base64.b64decode(text)
        except Exception:
            self._set_status("Invalid Base64 input. Paste encrypted output.", "error")
            return

        try:
            key, passphrase = self._get_key_or_passphrase()
        except ValueError as e:
            self._set_status(str(e), "error")
            return

        self._cleanup_worker()
        self._set_busy(True)
        self._set_status("Decrypting...", "warning")

        self._worker = TextDecryptWorker(
            ciphertext, key=key, passphrase=passphrase, parent=self
        )
        self._worker.finished.connect(self._on_decrypt_done)
        self._worker.error.connect(self._on_worker_error)
        self._worker.start()

    def _on_decrypt_done(self, plaintext: bytes) -> None:
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            text = plaintext.hex()
        self._output_text.setPlainText(text)
        self._output_stats.setText(f"{len(text)} chars | {len(plaintext)} bytes decrypted")
        self._set_status("Decryption successful!", "success")
        self._set_busy(False)

    # ----- Common -----

    def _on_worker_error(self, msg: str) -> None:
        self._set_status(f"Error: {msg}", "error")
        self._set_busy(False)

    def _set_busy(self, busy: bool) -> None:
        self._encrypt_btn.setDisabled(busy)
        self._decrypt_btn.setDisabled(busy)

    def _set_status(self, msg: str, level: str = "") -> None:
        self._status_label.setText(msg)
        if level == "success":
            self._status_label.setStyleSheet("color: #2ecc71; font-weight: 600;")
        elif level == "error":
            self._status_label.setStyleSheet("color: #e74c3c; font-weight: 600;")
        elif level == "warning":
            self._status_label.setStyleSheet("color: #f39c12; font-weight: 600;")
        else:
            self._status_label.setStyleSheet("color: #a0a0b8;")

    def _copy_output(self) -> None:
        text = self._output_text.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self._set_status("Copied to clipboard!", "success")
        else:
            self._set_status("Nothing to copy.", "warning")

    def _paste_input(self) -> None:
        clip = QApplication.clipboard().text()
        if clip:
            self._input_text.setPlainText(clip)
            self._set_status("Pasted from clipboard.", "")
        else:
            self._set_status("Clipboard is empty.", "warning")

    def _swap_output_to_input(self) -> None:
        output = self._output_text.toPlainText()
        if output:
            self._input_text.setPlainText(output)
            self._output_text.clear()
            self._output_stats.setText("")
            self._set_status("Output moved to input.", "")

    def _update_input_stats(self) -> None:
        text = self._input_text.toPlainText()
        chars = len(text)
        byte_len = len(text.encode("utf-8"))
        self._input_stats.setText(f"{chars:,} chars | {byte_len:,} bytes")

    def resizeEvent(self, event) -> None:
        """Switch splitter orientation based on available width."""
        super().resizeEvent(event)
        w = event.size().width()
        if w < 650 and self._splitter.orientation() != Qt.Orientation.Vertical:
            self._splitter.setOrientation(Qt.Orientation.Vertical)
        elif w >= 650 and self._splitter.orientation() != Qt.Orientation.Horizontal:
            self._splitter.setOrientation(Qt.Orientation.Horizontal)

    def showEvent(self, event) -> None:
        """Refresh keys whenever tab becomes visible."""
        super().showEvent(event)
        self._refresh_key_combo()
