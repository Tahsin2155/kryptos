"""
Kryptos Background Workers
===========================

QThread-based workers for long-running encryption/decryption operations.
Emits signals for progress tracking, elapsed time, and result/error reporting.

Features:
  - Cancellation support for file operations
  - Throttled progress signals to avoid UI flooding
  - Elapsed time tracking
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QThread, Signal

import algo


# ---------------------------------------------------------------------------
# Text Workers
# ---------------------------------------------------------------------------


class TextEncryptWorker(QThread):
    """Encrypt text in a background thread."""

    finished = Signal(bytes)   # encrypted blob
    error = Signal(str)        # error message

    def __init__(
        self,
        plaintext: bytes,
        key: Optional[bytes] = None,
        passphrase: Optional[str] = None,
        parent=None,
    ):
        super().__init__(parent)
        self._plaintext = plaintext
        self._key = key
        self._passphrase = passphrase

    def run(self) -> None:
        try:
            if self._passphrase:
                result = algo.encrypt_with_passphrase(
                    self._plaintext, self._passphrase
                )
            elif self._key:
                result = algo.encrypt(self._plaintext, self._key)
            else:
                raise algo.InvalidKeyError("No key or passphrase provided.")
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))


class TextDecryptWorker(QThread):
    """Decrypt text in a background thread."""

    finished = Signal(bytes)   # decrypted plaintext
    error = Signal(str)

    def __init__(
        self,
        ciphertext: bytes,
        key: Optional[bytes] = None,
        passphrase: Optional[str] = None,
        parent=None,
    ):
        super().__init__(parent)
        self._ciphertext = ciphertext
        self._key = key
        self._passphrase = passphrase

    def run(self) -> None:
        try:
            if self._passphrase:
                result = algo.decrypt_with_passphrase(
                    self._ciphertext, self._passphrase
                )
            elif self._key:
                result = algo.decrypt(self._ciphertext, self._key)
            else:
                raise algo.InvalidKeyError("No key or passphrase provided.")
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))


# ---------------------------------------------------------------------------
# File Workers — with cancellation, throttled progress & elapsed time
# ---------------------------------------------------------------------------

# Minimum interval between progress signal emissions (seconds)
_PROGRESS_THROTTLE = 0.05  # 50 ms -> max ~20 updates/sec


class FileEncryptWorker(QThread):
    """Encrypt a file in a background thread with progress reporting."""

    progress = Signal(int, int, float)  # (bytes_processed, total_bytes, elapsed_sec)
    finished = Signal(str, float)       # (output_path, elapsed_sec)
    error = Signal(str)

    def __init__(
        self,
        input_path: str,
        output_path: str,
        key: Optional[bytes] = None,
        passphrase: Optional[str] = None,
        parent=None,
    ):
        super().__init__(parent)
        self._input_path = input_path
        self._output_path = output_path
        self._key = key
        self._passphrase = passphrase
        self._cancelled = False

    def cancel(self) -> None:
        """Request cancellation (checked between chunks)."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    def run(self) -> None:
        t0 = time.perf_counter()
        last_emit = 0.0

        try:

            def _progress(done: int, total: int) -> None:
                nonlocal last_emit
                if self._cancelled:
                    raise _CancelledError()
                now = time.perf_counter()
                if now - last_emit >= _PROGRESS_THROTTLE:
                    self.progress.emit(done, total, now - t0)
                    last_emit = now

            if self._passphrase:
                algo.encrypt_file_with_passphrase(
                    self._input_path,
                    self._output_path,
                    self._passphrase,
                    progress_callback=_progress,
                )
            elif self._key:
                algo.encrypt_file(
                    self._input_path,
                    self._output_path,
                    self._key,
                    progress_callback=_progress,
                )
            else:
                raise algo.InvalidKeyError("No key or passphrase provided.")

            elapsed = time.perf_counter() - t0
            self.finished.emit(self._output_path, elapsed)

        except _CancelledError:
            self._cleanup_output()
            self.error.emit("Operation cancelled.")
        except Exception as exc:
            self._cleanup_output()
            self.error.emit(str(exc))

    def _cleanup_output(self) -> None:
        try:
            out = Path(self._output_path)
            if out.exists():
                out.unlink()
        except OSError:
            pass


class FileDecryptWorker(QThread):
    """Decrypt a file in a background thread with progress reporting."""

    progress = Signal(int, int, float)  # (bytes_processed, total_bytes, elapsed_sec)
    finished = Signal(str, float)       # (output_path, elapsed_sec)
    error = Signal(str)

    def __init__(
        self,
        input_path: str,
        output_path: str,
        key: Optional[bytes] = None,
        passphrase: Optional[str] = None,
        parent=None,
    ):
        super().__init__(parent)
        self._input_path = input_path
        self._output_path = output_path
        self._key = key
        self._passphrase = passphrase
        self._cancelled = False

    def cancel(self) -> None:
        """Request cancellation (checked between chunks)."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    def run(self) -> None:
        t0 = time.perf_counter()
        last_emit = 0.0

        try:

            def _progress(done: int, total: int) -> None:
                nonlocal last_emit
                if self._cancelled:
                    raise _CancelledError()
                now = time.perf_counter()
                if now - last_emit >= _PROGRESS_THROTTLE:
                    self.progress.emit(done, total, now - t0)
                    last_emit = now

            if self._passphrase:
                algo.decrypt_file_with_passphrase(
                    self._input_path,
                    self._output_path,
                    self._passphrase,
                    progress_callback=_progress,
                )
            elif self._key:
                algo.decrypt_file(
                    self._input_path,
                    self._output_path,
                    self._key,
                    progress_callback=_progress,
                )
            else:
                raise algo.InvalidKeyError("No key or passphrase provided.")

            elapsed = time.perf_counter() - t0
            self.finished.emit(self._output_path, elapsed)

        except _CancelledError:
            self._cleanup_output()
            self.error.emit("Operation cancelled.")
        except Exception as exc:
            self._cleanup_output()
            self.error.emit(str(exc))

    def _cleanup_output(self) -> None:
        try:
            out = Path(self._output_path)
            if out.exists():
                out.unlink()
        except OSError:
            pass


class _CancelledError(Exception):
    """Internal: raised inside progress callback to abort processing."""
