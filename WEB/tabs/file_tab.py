"""
Kryptos Web — File Tab
=======================

Encrypt / decrypt files using:
  • Stored AES key (raw key mode, chunked streaming)
  • Passphrase (PBKDF2 mode, chunked streaming)
  • RSA keypair (hybrid mode, chunked streaming)

Uses temporary files and ``algo.encrypt_file*`` / ``algo.decrypt_file*``
for memory-efficient streaming of large files.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import streamlit as st

# -- project-root import ---------------------------------------------------
_root = str(Path(__file__).resolve().parent.parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

import algo  # noqa: E402

from key_store import (  # noqa: E402
    get_aes_key_bytes,
    list_aes_keys,
    list_rsa_keys,
    get_rsa_key,
)
from utils import human_file_size, passphrase_strength, safe_output_filename  # noqa: E402


# ---------------------------------------------------------------------------
# Public render function
# ---------------------------------------------------------------------------

def render() -> None:
    """Render the File encryption / decryption tab."""

    # ---- Operation selector ----
    operation = st.radio(
        "Operation",
        ["Encrypt", "Decrypt"],
        horizontal=True,
        key="file_operation",
    )

    # ---- File uploader ----
    uploaded = st.file_uploader(
        "Choose a file" if operation == "Encrypt" else "Choose an encrypted file",
        key="file_uploader",
    )

    if uploaded:
        st.caption(
            f"**{uploaded.name}**  —  {human_file_size(uploaded.size)}"
        )

    # ---- Key mode selector ----
    key_mode = st.radio(
        "Key Mode",
        ["Stored Key", "Passphrase", "RSA Key"],
        horizontal=True,
        key="file_key_mode",
    )

    selected_key_id: str | None = None
    passphrase: str = ""
    selected_rsa_id: str | None = None

    if key_mode == "Stored Key":
        aes_keys = list_aes_keys()
        if not aes_keys:
            st.info("No keys stored yet. Generate or import one in the **Keys** tab.")
        else:
            options = {k.key_id: f"{k.name}  ({k.mode})" for k in aes_keys}
            selected_key_id = st.selectbox(
                "Select Key",
                options.keys(),
                format_func=lambda kid: options[kid],
                key="file_aes_key",
            )

    elif key_mode == "Passphrase":
        passphrase = st.text_input(
            "Passphrase",
            type="password",
            placeholder="Enter your passphrase…",
            key="file_passphrase",
        )
        if passphrase:
            score, label, color = passphrase_strength(passphrase)
            cols = st.columns([4, 1])
            with cols[0]:
                st.progress(score / 100)
            with cols[1]:
                st.markdown(
                    f"<span style='color:{color}; font-weight:600;'>{label}</span>",
                    unsafe_allow_html=True,
                )

    elif key_mode == "RSA Key":
        rsa_keys = list_rsa_keys()
        if not rsa_keys:
            st.info("No RSA keys stored yet. Generate or import one in the **Keys** tab.")
        else:
            options = {k.key_id: f"{k.name}  ({k.key_size}-bit)" for k in rsa_keys}
            selected_rsa_id = st.selectbox(
                "Select RSA Key",
                options.keys(),
                format_func=lambda kid: options[kid],
                key="file_rsa_key",
            )
            if operation == "Decrypt":
                rsa_entry = get_rsa_key(selected_rsa_id) if selected_rsa_id else None
                if rsa_entry and not rsa_entry.private_pem:
                    st.warning("This key has no private key — decryption is not possible.")

    # ---- Action button ----
    st.markdown("---")
    btn_label = "🔒 Encrypt File" if operation == "Encrypt" else "🔓 Decrypt File"

    if st.button(btn_label, type="primary", use_container_width=True, key="file_action"):
        if not uploaded:
            st.error("Please upload a file first.")
            return

        try:
            result_bytes, out_name = _process_file(
                uploaded, operation, key_mode, selected_key_id, passphrase, selected_rsa_id,
            )
            st.success(
                f"{'Encryption' if operation == 'Encrypt' else 'Decryption'} "
                f"successful!  ({human_file_size(len(result_bytes))})"
            )
            st.download_button(
                f"📥 Download {out_name}",
                data=result_bytes,
                file_name=out_name,
                mime="application/octet-stream",
                key="file_download",
            )

        except algo.DecryptionError as e:
            st.error(f"Decryption failed: {e}")
        except algo.InvalidKeyError as e:
            st.error(f"Invalid key: {e}")
        except algo.FormatError as e:
            st.error(f"Format error: {e}")
        except algo.KryptosError as e:
            st.error(f"Error: {e}")
        except Exception as e:
            st.error(f"Unexpected error: {e}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _process_file(
    uploaded,
    operation: str,
    key_mode: str,
    key_id: str | None,
    passphrase: str,
    rsa_id: str | None,
) -> tuple[bytes, str]:
    """
    Process the uploaded file through the algo engine.

    Returns (result_bytes, suggested_output_filename).
    """
    encrypting = operation == "Encrypt"
    out_name = safe_output_filename(uploaded.name, encrypting)

    # Write uploaded bytes to a temp file
    suffix_in = Path(uploaded.name).suffix or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix_in) as tmp_in:
        tmp_in.write(uploaded.getvalue())
        tmp_in_path = tmp_in.name

    suffix_out = ".enc" if encrypting else ".dec"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix_out) as tmp_out:
        tmp_out_path = tmp_out.name

    progress_bar = st.progress(0, text="Processing…")

    def progress_cb(done: int, total: int) -> None:
        if total > 0:
            pct = min(done / total, 1.0)
            progress_bar.progress(pct, text=f"Processing… {human_file_size(done)} / {human_file_size(total)}")

    try:
        if key_mode == "Stored Key":
            if not key_id:
                raise algo.InvalidKeyError("No key selected.")
            key = get_aes_key_bytes(key_id)
            if encrypting:
                algo.encrypt_file(tmp_in_path, tmp_out_path, key, progress_callback=progress_cb)
            else:
                algo.decrypt_file(tmp_in_path, tmp_out_path, key, progress_callback=progress_cb)

        elif key_mode == "Passphrase":
            if not passphrase:
                raise algo.InvalidKeyError("Passphrase must be a non-empty string.")
            if encrypting:
                algo.encrypt_file_with_passphrase(tmp_in_path, tmp_out_path, passphrase, progress_callback=progress_cb)
            else:
                algo.decrypt_file_with_passphrase(tmp_in_path, tmp_out_path, passphrase, progress_callback=progress_cb)

        elif key_mode == "RSA Key":
            if not rsa_id:
                raise algo.InvalidKeyError("No RSA key selected.")
            entry = get_rsa_key(rsa_id)
            if not entry:
                raise algo.InvalidKeyError("RSA key not found.")
            if encrypting:
                pub = algo.import_public_key(entry.public_pem.encode("utf-8"))
                algo.encrypt_file_with_rsa(tmp_in_path, tmp_out_path, pub, progress_callback=progress_cb)
            else:
                if not entry.private_pem:
                    raise algo.InvalidKeyError("No private key available for decryption.")
                priv = algo.import_private_key(entry.private_pem.encode("utf-8"))
                algo.decrypt_file_with_rsa(tmp_in_path, tmp_out_path, priv, progress_callback=progress_cb)
        else:
            raise algo.KryptosError(f"Unknown key mode: {key_mode}")

        progress_bar.progress(1.0, text="Done!")

        with open(tmp_out_path, "rb") as f:
            result = f.read()

        return result, out_name

    finally:
        # Clean up temp files
        for p in (tmp_in_path, tmp_out_path):
            try:
                os.unlink(p)
            except OSError:
                pass
