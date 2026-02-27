"""
Kryptos File Tab
=================

File encryption and decryption with:
  - Drag-and-drop file selection
  - File browser dialogs
  - Progress bar for large files
  - Save options (new file or replace)
  - Stored key or passphrase modes
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from key_manager import KeyManager
from workers import FileDecryptWorker, FileEncryptWorker


def _human_size(size: int) -> str:
    """Format byte count as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}" if size != int(size) else f"{int(size)} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


class FileDropArea(QLabel):
    """Drop area that accepts file drops."""

    _STYLE_IDLE = (
        "QLabel {"
        "  border: 2px dashed #4a4a6a;"
        "  border-radius: 12px;"
        "  background-color: #0d1b3e;"
        "  color: #a0a0b8;"
        "  font-size: 14px;"
        "  padding: 20px;"
        "}"
    )
    _STYLE_DRAG = (
        "QLabel {"
        "  border: 2px dashed #e94560;"
        "  border-radius: 12px;"
        "  background-color: #0d1b3e;"
        "  color: #e94560;"
        "  font-size: 14px;"
        "  padding: 20px;"
        "}"
    )
    _STYLE_LOADED = (
        "QLabel {"
        "  border: 2px solid #2ecc71;"
        "  border-radius: 12px;"
        "  background-color: #0d1b3e;"
        "  color: #2ecc71;"
        "  font-size: 14px;"
        "  padding: 20px;"
        "}"
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumHeight(80)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.setStyleSheet(self._STYLE_IDLE)
        self.setText("Drag & drop a file here\nor click Browse to select")
        self._file_path: str | None = None
        self._callback = None

    def set_callback(self, callback) -> None:
        self._callback = callback

    def set_loaded(self, filename: str) -> None:
        """Show loaded state with filename."""
        self.setText(filename)
        self.setStyleSheet(self._STYLE_LOADED)
        self._file_path = filename

    def reset(self) -> None:
        """Reset to idle."""
        self.setText("Drag & drop a file here\nor click Browse to select")
        self.setStyleSheet(self._STYLE_IDLE)
        self._file_path = None

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet(self._STYLE_DRAG)

    def dragLeaveEvent(self, event) -> None:
        if self._file_path:
            self.setStyleSheet(self._STYLE_LOADED)
        else:
            self.setStyleSheet(self._STYLE_IDLE)

    def dropEvent(self, event) -> None:
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self._file_path = path
                self.setText(Path(path).name)
                self.setStyleSheet(self._STYLE_LOADED)
                if self._callback:
                    self._callback(path)
            else:
                self.setStyleSheet(self._STYLE_IDLE)


class FileTab(QWidget):
    """File encryption / decryption tab."""

    def __init__(self, key_manager: KeyManager, parent=None):
        super().__init__(parent)
        self._km = key_manager
        self._worker = None
        self._input_path: str | None = None
        self._last_output_path: str | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        # Scroll wrapper so the tab is usable at small window sizes
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        layout.setSpacing(12)
        scroll.setWidget(scroll_content)
        outer.addWidget(scroll)

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
        self._key_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
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

        layout.addWidget(key_group)
        self._mode_group.idToggled.connect(self._on_mode_changed)
        self._on_mode_changed(0, True)

        # ----- File Selection -----
        file_group = QGroupBox("File")
        file_layout = QVBoxLayout(file_group)

        # Drop area
        self._drop_area = FileDropArea()
        self._drop_area.set_callback(self._on_file_selected)
        file_layout.addWidget(self._drop_area)

        # Browse row
        browse_row = QHBoxLayout()
        self._file_path_label = QLabel("No file selected")
        self._file_path_label.setStyleSheet("color: #a0a0b8; font-size: 12px;")
        self._file_path_label.setWordWrap(True)
        self._file_path_label.setMinimumHeight(20)
        self._file_path_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        browse_row.addWidget(self._file_path_label, 1)

        self._browse_btn = QPushButton("Browse...")
        self._browse_btn.setProperty("class", "secondary")
        self._browse_btn.clicked.connect(self._browse_file)
        browse_row.addWidget(self._browse_btn)
        file_layout.addLayout(browse_row)

        # File info
        self._file_info_label = QLabel("")
        self._file_info_label.setStyleSheet("color: #a0a0b8; font-size: 12px; padding: 2px 0;")
        file_layout.addWidget(self._file_info_label)

        layout.addWidget(file_group)

        # ----- Output Options -----
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout(output_group)

        out_row = QHBoxLayout()
        self._replace_check = QCheckBox("Replace original file")
        self._replace_check.setChecked(False)
        self._replace_check.toggled.connect(self._on_replace_toggled)
        out_row.addWidget(self._replace_check)
        out_row.addStretch()
        output_layout.addLayout(out_row)

        suffix_row = QHBoxLayout()
        suffix_label = QLabel("Encrypted suffix:")
        suffix_label.setStyleSheet("color: #a0a0b8;")
        self._suffix_input = QLineEdit(".enc")
        self._suffix_input.setFixedWidth(100)
        suffix_row.addWidget(suffix_label)
        suffix_row.addWidget(self._suffix_input)
        suffix_row.addSpacing(20)

        dec_suffix_label = QLabel("Decrypted suffix:")
        dec_suffix_label.setStyleSheet("color: #a0a0b8;")
        self._dec_suffix_input = QLineEdit(".dec")
        self._dec_suffix_input.setFixedWidth(100)
        suffix_row.addWidget(dec_suffix_label)
        suffix_row.addWidget(self._dec_suffix_input)
        suffix_row.addStretch()
        output_layout.addLayout(suffix_row)

        layout.addWidget(output_group)

        # ----- Progress -----
        prog_row = QHBoxLayout()
        self._progress_bar = QProgressBar()
        self._progress_bar.setVisible(False)
        self._progress_bar.setTextVisible(True)
        self._progress_bar.setFormat("%p%")
        prog_row.addWidget(self._progress_bar, 1)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setProperty("class", "danger")
        self._cancel_btn.setFixedWidth(80)
        self._cancel_btn.setVisible(False)
        self._cancel_btn.clicked.connect(self._on_cancel)
        prog_row.addWidget(self._cancel_btn)
        layout.addLayout(prog_row)

        # Speed / elapsed info
        self._speed_label = QLabel("")
        self._speed_label.setStyleSheet("font-size: 12px; color: #a0a0b8; padding: 2px 0;")
        self._speed_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._speed_label)

        # ----- Action Buttons -----
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self._encrypt_btn = QPushButton("  Encrypt File  ")
        self._encrypt_btn.setFixedHeight(40)
        self._encrypt_btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self._encrypt_btn.clicked.connect(self._on_encrypt)

        self._decrypt_btn = QPushButton("  Decrypt File  ")
        self._decrypt_btn.setFixedHeight(40)
        self._decrypt_btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self._decrypt_btn.setProperty("class", "secondary")
        self._decrypt_btn.clicked.connect(self._on_decrypt)

        self._open_folder_btn = QPushButton("  Open Folder  ")
        self._open_folder_btn.setFixedHeight(40)
        self._open_folder_btn.setProperty("class", "success")
        self._open_folder_btn.setVisible(False)
        self._open_folder_btn.clicked.connect(self._open_output_folder)

        btn_row.addWidget(self._encrypt_btn)
        btn_row.addWidget(self._decrypt_btn)
        btn_row.addWidget(self._open_folder_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Status
        self._status_label = QLabel("")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setMinimumHeight(24)
        self._status_label.setStyleSheet("padding: 4px 0; font-size: 13px;")
        layout.addWidget(self._status_label)

        layout.addStretch()

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

    def _toggle_passphrase_visibility(self) -> None:
        if self._passphrase_input.echoMode() == QLineEdit.EchoMode.Password:
            self._passphrase_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._show_pass_btn.setText("Hide")
        else:
            self._passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._show_pass_btn.setText("Show")

    def _on_replace_toggled(self, checked: bool) -> None:
        self._suffix_input.setEnabled(not checked)
        self._dec_suffix_input.setEnabled(not checked)

    def _refresh_key_combo(self) -> None:
        self._key_combo.clear()
        keys = self._km.list_keys()
        if not keys:
            self._key_combo.addItem("(No keys — go to Keys tab to create one)", "")
        for entry in keys:
            label = f"{entry.name}  [{entry.mode}]"
            self._key_combo.addItem(label, entry.key_id)

    # ----- File selection -----

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*)"
        )
        if path:
            self._on_file_selected(path)

    def _on_file_selected(self, path: str) -> None:
        self._input_path = path
        p = Path(path)
        self._file_path_label.setText(str(p))
        self._drop_area.set_loaded(p.name)
        self._open_folder_btn.setVisible(False)
        # Show file info
        try:
            size = p.stat().st_size
            self._file_info_label.setText(
                f"Size: {_human_size(size)}  |  Type: {p.suffix or 'unknown'}"
            )
        except OSError:
            self._file_info_label.setText("")

    # ----- Get key / passphrase -----

    def _get_key_or_passphrase(self):
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

    # ----- Output path -----

    def _get_output_path(self, mode: str) -> str:
        """Compute the output path for encrypt/decrypt."""
        p = Path(self._input_path)
        if self._replace_check.isChecked():
            # Use a temp file then rename
            return str(p.with_suffix(p.suffix + ".tmp"))
        if mode == "encrypt":
            suffix = self._suffix_input.text().strip() or ".enc"
            default = str(p) + suffix
        else:
            suffix = self._dec_suffix_input.text().strip() or ".dec"
            if p.suffix == ".enc":
                default = str(p.with_suffix("")) + suffix
            else:
                default = str(p) + suffix
        return default

    # ----- Cleanup & Cancel -----

    def _cleanup_worker(self) -> None:
        """Ensure previous worker is finished and cleaned up."""
        if self._worker is not None:
            if self._worker.isRunning():
                self._worker.cancel()
                self._worker.wait(3000)
            self._worker.deleteLater()
            self._worker = None

    def _on_cancel(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._cancel_btn.setEnabled(False)
            self._cancel_btn.setText("...")

    # ----- Encrypt -----

    def _on_encrypt(self) -> None:
        if not self._input_path:
            self._set_status("Please select a file first.", "error")
            return

        try:
            key, passphrase = self._get_key_or_passphrase()
        except ValueError as e:
            self._set_status(str(e), "error")
            return

        output_path = self._get_output_path("encrypt")

        # Confirm if output already exists
        if Path(output_path).exists():
            reply = QMessageBox.question(
                self,
                "File Exists",
                f"Output file already exists:\n{output_path}\n\nOverwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self._cleanup_worker()
        self._set_busy(True, show_cancel=True)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._speed_label.setText("")
        self._open_folder_btn.setVisible(False)
        self._set_status("Encrypting...", "warning")

        self._worker = FileEncryptWorker(
            self._input_path, output_path, key=key, passphrase=passphrase, parent=self
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(lambda p, t: self._on_file_done(p, t, "encrypt"))
        self._worker.error.connect(self._on_worker_error)
        self._worker.start()

    # ----- Decrypt -----

    def _on_decrypt(self) -> None:
        if not self._input_path:
            self._set_status("Please select an encrypted file.", "error")
            return

        try:
            key, passphrase = self._get_key_or_passphrase()
        except ValueError as e:
            self._set_status(str(e), "error")
            return

        output_path = self._get_output_path("decrypt")

        if Path(output_path).exists():
            reply = QMessageBox.question(
                self,
                "File Exists",
                f"Output file already exists:\n{output_path}\n\nOverwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self._cleanup_worker()
        self._set_busy(True, show_cancel=True)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._speed_label.setText("")
        self._open_folder_btn.setVisible(False)
        self._set_status("Decrypting...", "warning")

        self._worker = FileDecryptWorker(
            self._input_path, output_path, key=key, passphrase=passphrase, parent=self
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(lambda p, t: self._on_file_done(p, t, "decrypt"))
        self._worker.error.connect(self._on_worker_error)
        self._worker.start()

    # ----- Progress / Results -----

    def _on_progress(self, done: int, total: int, elapsed: float) -> None:
        self._progress_bar.setMaximum(total)
        self._progress_bar.setValue(done)
        pct = (done / total * 100) if total > 0 else 0
        self._progress_bar.setFormat(
            f"{pct:.0f}% — {_human_size(done)} / {_human_size(total)}"
        )
        # Speed calculation
        if elapsed > 0:
            speed = done / elapsed
            self._speed_label.setText(
                f"{_human_size(int(speed))}/s  |  Elapsed: {elapsed:.1f}s"
            )

    def _on_file_done(self, output_path: str, elapsed: float, mode: str) -> None:
        # Handle replace-original mode
        if self._replace_check.isChecked():
            try:
                original = Path(self._input_path)
                tmp = Path(output_path)
                original.unlink()
                tmp.rename(original)
                output_path = str(original)
            except OSError as e:
                self._set_status(f"Failed to replace original: {e}", "error")
                self._set_busy(False)
                return

        self._last_output_path = output_path
        action = "Encrypted" if mode == "encrypt" else "Decrypted"
        self._set_status(f"{action} successfully!", "success")
        self._progress_bar.setValue(self._progress_bar.maximum())

        # Show summary
        try:
            out_size = Path(output_path).stat().st_size
            self._speed_label.setText(
                f"Done in {elapsed:.1f}s  |  Output: {_human_size(out_size)}  |  {Path(output_path).name}"
            )
        except OSError:
            self._speed_label.setText(f"Done in {elapsed:.1f}s")

        self._open_folder_btn.setVisible(True)
        self._set_busy(False)

    def _on_worker_error(self, msg: str) -> None:
        self._set_status(f"Error: {msg}", "error")
        self._progress_bar.setVisible(False)
        self._speed_label.setText("")
        self._set_busy(False)

    def _set_busy(self, busy: bool, show_cancel: bool = False) -> None:
        self._encrypt_btn.setDisabled(busy)
        self._decrypt_btn.setDisabled(busy)
        self._browse_btn.setDisabled(busy)
        self._cancel_btn.setVisible(show_cancel and busy)
        self._cancel_btn.setEnabled(True)
        self._cancel_btn.setText("Cancel")
        if not busy:
            self._cancel_btn.setVisible(False)

    def _open_output_folder(self) -> None:
        """Open the folder containing the last output file."""
        if not self._last_output_path:
            return
        folder = str(Path(self._last_output_path).parent)
        try:
            if sys.platform == "win32":
                os.startfile(folder)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])
        except OSError:
            self._set_status(f"Could not open: {folder}", "error")

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

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._refresh_key_combo()
