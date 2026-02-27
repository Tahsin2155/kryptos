"""
Kryptos Web — Text Tab
=======================

Encrypt / decrypt text using:
  • Stored AES key (raw key mode)
  • Passphrase (PBKDF2 mode)
  • RSA keypair (hybrid mode)

Output is Base64-encoded for easy copy/paste sharing.
"""

from __future__ import annotations

import base64
import sys
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
from utils import passphrase_strength  # noqa: E402


# ---------------------------------------------------------------------------
# Public render function
# ---------------------------------------------------------------------------

def render() -> None:
    """Render the Text encryption / decryption tab."""

    # ---- Operation selector ----
    operation = st.radio(
        "Operation",
        ["Encrypt", "Decrypt"],
        horizontal=True,
        key="text_operation",
    )

    # ---- Key mode selector ----
    key_mode = st.radio(
        "Key Mode",
        ["Stored Key", "Passphrase", "RSA Key"],
        horizontal=True,
        key="text_key_mode",
    )

    # ---- Key mode specific inputs ----
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
                key="text_aes_key",
            )

    elif key_mode == "Passphrase":
        passphrase = st.text_input(
            "Passphrase",
            type="password",
            placeholder="Enter your passphrase…",
            key="text_passphrase",
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
                key="text_rsa_key",
            )
            if operation == "Decrypt":
                rsa_entry = get_rsa_key(selected_rsa_id) if selected_rsa_id else None
                if rsa_entry and not rsa_entry.private_pem:
                    st.warning("This key has no private key — decryption is not possible.")

    # ---- Input area ----
    st.markdown("---")

    if operation == "Encrypt":
        input_text = st.text_area(
            "Plaintext",
            height=200,
            placeholder="Enter text to encrypt…",
            key="text_input_encrypt",
        )
    else:
        input_text = st.text_area(
            "Ciphertext (Base64)",
            height=200,
            placeholder="Paste Base64-encoded ciphertext…",
            key="text_input_decrypt",
        )

    # Input stats
    if input_text:
        n_chars = len(input_text)
        n_bytes = len(input_text.encode("utf-8"))
        st.caption(f"{n_chars:,} chars  |  {n_bytes:,} bytes")

    # ---- Action button ----
    btn_label = "🔒 Encrypt" if operation == "Encrypt" else "🔓 Decrypt"
    if st.button(btn_label, type="primary", use_container_width=True, key="text_action"):
        if not input_text:
            st.error("Please enter some text first.")
            return

        try:
            if operation == "Encrypt":
                result_bytes = _do_encrypt(input_text, key_mode, selected_key_id, passphrase, selected_rsa_id)
                result_b64 = base64.b64encode(result_bytes).decode("ascii")

                st.success("Encryption successful!")
                st.text_area(
                    "Encrypted Output (Base64)",
                    value=result_b64,
                    height=200,
                    key="text_output_display",
                )
                st.download_button(
                    "📥 Download as .enc file",
                    data=result_bytes,
                    file_name="encrypted.enc",
                    mime="application/octet-stream",
                    key="text_download_enc",
                )
            else:
                plaintext = _do_decrypt(input_text, key_mode, selected_key_id, passphrase, selected_rsa_id)

                st.success("Decryption successful!")
                try:
                    decoded = plaintext.decode("utf-8")
                    st.text_area(
                        "Decrypted Output",
                        value=decoded,
                        height=200,
                        key="text_output_display",
                    )
                except UnicodeDecodeError:
                    st.warning("Decrypted data is not valid UTF-8 text. Showing as Base64.")
                    st.text_area(
                        "Decrypted Output (Base64)",
                        value=base64.b64encode(plaintext).decode("ascii"),
                        height=200,
                        key="text_output_display",
                    )
                st.download_button(
                    "📥 Download decrypted data",
                    data=plaintext,
                    file_name="decrypted.txt",
                    mime="application/octet-stream",
                    key="text_download_dec",
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

def _do_encrypt(
    plaintext_str: str,
    key_mode: str,
    key_id: str | None,
    passphrase: str,
    rsa_id: str | None,
) -> bytes:
    """Encrypt plaintext string and return raw ciphertext bytes."""
    pt = plaintext_str.encode("utf-8")

    if key_mode == "Stored Key":
        if not key_id:
            raise algo.InvalidKeyError("No key selected.")
        key = get_aes_key_bytes(key_id)
        return algo.encrypt(pt, key)

    elif key_mode == "Passphrase":
        if not passphrase:
            raise algo.InvalidKeyError("Passphrase must be a non-empty string.")
        return algo.encrypt_with_passphrase(pt, passphrase)

    elif key_mode == "RSA Key":
        if not rsa_id:
            raise algo.InvalidKeyError("No RSA key selected.")
        entry = get_rsa_key(rsa_id)
        if not entry:
            raise algo.InvalidKeyError("RSA key not found.")
        pub = algo.import_public_key(entry.public_pem.encode("utf-8"))
        return algo.encrypt_with_rsa(pt, pub)

    raise algo.KryptosError(f"Unknown key mode: {key_mode}")


def _do_decrypt(
    ciphertext_b64: str,
    key_mode: str,
    key_id: str | None,
    passphrase: str,
    rsa_id: str | None,
) -> bytes:
    """Decrypt Base64-encoded ciphertext and return plaintext bytes."""
    try:
        data = base64.b64decode(ciphertext_b64.strip())
    except Exception:
        raise algo.FormatError("Input is not valid Base64.")

    if key_mode == "Stored Key":
        if not key_id:
            raise algo.InvalidKeyError("No key selected.")
        key = get_aes_key_bytes(key_id)
        return algo.decrypt(data, key)

    elif key_mode == "Passphrase":
        if not passphrase:
            raise algo.InvalidKeyError("Passphrase must be a non-empty string.")
        return algo.decrypt_with_passphrase(data, passphrase)

    elif key_mode == "RSA Key":
        if not rsa_id:
            raise algo.InvalidKeyError("No RSA key selected.")
        entry = get_rsa_key(rsa_id)
        if not entry:
            raise algo.InvalidKeyError("RSA key not found.")
        if not entry.private_pem:
            raise algo.InvalidKeyError("No private key available for decryption.")
        priv = algo.import_private_key(entry.private_pem.encode("utf-8"))
        return algo.decrypt_with_rsa(data, priv)

    raise algo.KryptosError(f"Unknown key mode: {key_mode}")
