"""
Kryptos Web — Utility Helpers
==============================

Shared helpers for passphrase strength, file size formatting,
and output filename generation.
"""

from __future__ import annotations

import math
import re


# ---------------------------------------------------------------------------
# Passphrase strength (mirrors Local/text_tab.py logic)
# ---------------------------------------------------------------------------

def passphrase_strength(passphrase: str) -> tuple[int, str, str]:
    """
    Evaluate passphrase strength based on character-pool entropy.

    Returns
    -------
    (score, label, color) : tuple[int, str, str]
        score  — 0-100 normalised against 128-bit target entropy
        label  — "Weak" / "Fair" / "Good" / "Strong" / ""
        color  — hex colour string for the UI indicator
    """
    if not passphrase:
        return 0, "", "#6c6c80"

    length = len(passphrase)

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
    score = min(int(entropy * 100 / 128), 100)

    if score < 25:
        return score, "Weak", "#e74c3c"
    if score < 50:
        return score, "Fair", "#f39c12"
    if score < 75:
        return score, "Good", "#3498db"
    return score, "Strong", "#2ecc71"


# ---------------------------------------------------------------------------
# Human-readable file size
# ---------------------------------------------------------------------------

def human_file_size(size_bytes: int) -> str:
    """Convert byte count to a human-readable string (e.g. '1.5 MB')."""
    if size_bytes < 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024.0:
            if unit == "B":
                return f"{size_bytes} {unit}"
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0  # type: ignore[assignment]
    return f"{size_bytes:.1f} PB"


# ---------------------------------------------------------------------------
# Output filename helper
# ---------------------------------------------------------------------------

def safe_output_filename(original: str, encrypting: bool) -> str:
    """
    Derive an output filename for download.

    * Encrypting  → append ``.enc``
    * Decrypting  → strip ``.enc`` suffix if present, else prepend ``decrypted_``
    """
    if encrypting:
        return original + ".enc"
    if original.endswith(".enc"):
        return original[:-4]
    return "decrypted_" + original
