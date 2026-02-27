"""
Kryptos Web — Keys Tab
=======================

Manage AES-256 symmetric keys and RSA keypairs:
  • Generate random system keys
  • Import custom keys (Base64 / Hex)
  • Generate RSA keypairs (2048 / 4096-bit)
  • Import RSA public/private PEM keys
  • View, copy, export, rename, delete keys
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import streamlit as st

# -- project-root import ---------------------------------------------------
_root = str(Path(__file__).resolve().parent.parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

import algo  # noqa: E402

from key_store import (  # noqa: E402
    delete_aes_key,
    delete_rsa_key,
    generate_rsa_keypair,
    generate_system_key,
    import_custom_key,
    import_rsa_keypair,
    import_rsa_public_key,
    list_aes_keys,
    list_rsa_keys,
    get_rsa_key,
    rename_aes_key,
    rename_rsa_key,
)


# ---------------------------------------------------------------------------
# Public render function
# ---------------------------------------------------------------------------

def render() -> None:
    """Render the Keys management tab."""

    aes_col, rsa_col = st.columns(2)

    # =====================================================================
    # LEFT COLUMN — AES Symmetric Keys
    # =====================================================================
    with aes_col:
        st.subheader("🔑 AES-256 Keys")

        # ---- Generate key ----
        with st.expander("Generate New Key", expanded=False):
            gen_name = st.text_input("Key Name", placeholder="e.g. My Encryption Key", key="aes_gen_name")
            if st.button("Generate", key="aes_gen_btn", use_container_width=True):
                if not gen_name.strip():
                    st.error("Please enter a name for the key.")
                else:
                    entry = generate_system_key(gen_name)
                    st.success(f"Key **{entry.name}** generated!")
                    st.rerun()

        # ---- Import key ----
        with st.expander("Import Existing Key", expanded=False):
            imp_name = st.text_input("Key Name", placeholder="e.g. Shared Key", key="aes_imp_name")
            imp_fmt = st.radio("Format", ["Base64", "Hex"], horizontal=True, key="aes_imp_fmt")
            imp_val = st.text_input(
                "Key Value",
                placeholder="Paste your Base64 or Hex key…",
                key="aes_imp_val",
            )
            if st.button("Import", key="aes_imp_btn", use_container_width=True):
                if not imp_val.strip():
                    st.error("Please enter a key value.")
                else:
                    try:
                        entry = import_custom_key(
                            imp_name or "Imported Key",
                            imp_val,
                            fmt=imp_fmt.lower(),
                        )
                        st.success(f"Key **{entry.name}** imported!")
                        st.rerun()
                    except algo.InvalidKeyError as e:
                        st.error(f"Invalid key: {e}")

        # ---- Key list ----
        st.markdown("---")
        aes_keys = list_aes_keys()
        if not aes_keys:
            st.info("No AES keys yet. Generate or import one above.")
        else:
            st.caption(f"{len(aes_keys)} key(s) stored in this session")
            for entry in aes_keys:
                _render_aes_key_card(entry)

    # =====================================================================
    # RIGHT COLUMN — RSA Keypairs
    # =====================================================================
    with rsa_col:
        st.subheader("🔐 RSA Keypairs")

        # ---- Generate RSA keypair ----
        with st.expander("Generate New RSA Keypair", expanded=False):
            rsa_name = st.text_input("Keypair Name", placeholder="e.g. My RSA Key", key="rsa_gen_name")
            rsa_size = st.selectbox("Key Size", [2048, 4096], index=1, key="rsa_gen_size")
            if st.button("Generate RSA Keypair", key="rsa_gen_btn", use_container_width=True):
                if not rsa_name.strip():
                    st.error("Please enter a name for the keypair.")
                else:
                    with st.spinner(f"Generating {rsa_size}-bit RSA keypair… This may take a moment."):
                        entry = generate_rsa_keypair(rsa_name, key_size=rsa_size)
                    st.success(f"RSA keypair **{entry.name}** ({entry.key_size}-bit) generated!")
                    st.rerun()

        # ---- Import RSA keys ----
        with st.expander("Import RSA Key(s)", expanded=False):
            rsa_imp_name = st.text_input("Key Name", placeholder="e.g. Partner's Public Key", key="rsa_imp_name")
            rsa_imp_mode = st.radio(
                "Import Type",
                ["Public Key Only", "Full Keypair (Public + Private)"],
                key="rsa_imp_mode",
            )

            pub_pem_text = st.text_area(
                "Public Key (PEM)",
                height=120,
                placeholder="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
                key="rsa_imp_pub",
            )

            priv_pem_text = ""
            priv_passphrase = ""
            if rsa_imp_mode == "Full Keypair (Public + Private)":
                priv_pem_text = st.text_area(
                    "Private Key (PEM)",
                    height=120,
                    placeholder="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
                    key="rsa_imp_priv",
                )
                priv_passphrase = st.text_input(
                    "Private Key Passphrase (if encrypted)",
                    type="password",
                    key="rsa_imp_pass",
                )

            if st.button("Import RSA Key", key="rsa_imp_btn", use_container_width=True):
                if not pub_pem_text.strip():
                    st.error("Please paste the public key PEM.")
                else:
                    try:
                        if rsa_imp_mode == "Public Key Only":
                            entry = import_rsa_public_key(rsa_imp_name or "Imported RSA Key", pub_pem_text)
                        else:
                            if not priv_pem_text.strip():
                                st.error("Please paste the private key PEM.")
                                return
                            entry = import_rsa_keypair(
                                rsa_imp_name or "Imported RSA Keypair",
                                pub_pem_text,
                                priv_pem_text,
                                passphrase=priv_passphrase or None,
                            )
                        st.success(f"RSA key **{entry.name}** imported!")
                        st.rerun()
                    except (algo.InvalidKeyError, Exception) as e:
                        st.error(f"Import failed: {e}")

        # ---- RSA key list ----
        st.markdown("---")
        rsa_keys = list_rsa_keys()
        if not rsa_keys:
            st.info("No RSA keys yet. Generate or import one above.")
        else:
            st.caption(f"{len(rsa_keys)} keypair(s) stored in this session")
            for entry in rsa_keys:
                _render_rsa_key_card(entry)


# ---------------------------------------------------------------------------
# Card renderers
# ---------------------------------------------------------------------------

def _render_aes_key_card(entry) -> None:
    """Render a single AES key card with actions."""
    with st.container(border=True):
        cols = st.columns([3, 1, 1])
        with cols[0]:
            st.markdown(f"**{entry.name}**")
            st.caption(f"{entry.mode} key  •  {_format_time(entry.created)}")
        with cols[1]:
            # Copy Base64
            st.code(entry.key_b64, language=None)
        with cols[2]:
            hex_val = algo.key_to_hex(algo.key_from_base64(entry.key_b64))
            st.code(hex_val, language=None)

        # Actions row
        action_cols = st.columns(4)
        with action_cols[0]:
            st.download_button(
                "📥 Export .key",
                data=f"# Kryptos AES-256 Key\n# Name: {entry.name}\n# Created: {entry.created}\n{entry.key_b64}\n",
                file_name=f"{entry.name.replace(' ', '_')}.key",
                mime="text/plain",
                key=f"aes_export_{entry.key_id}",
                use_container_width=True,
            )
        with action_cols[1]:
            new_name = st.text_input(
                "Rename",
                value=entry.name,
                key=f"aes_rename_input_{entry.key_id}",
                label_visibility="collapsed",
            )
            if new_name != entry.name:
                rename_aes_key(entry.key_id, new_name)
                st.rerun()
        with action_cols[2]:
            pass  # spacer
        with action_cols[3]:
            if st.button("🗑️ Delete", key=f"aes_del_{entry.key_id}", use_container_width=True):
                delete_aes_key(entry.key_id)
                st.rerun()


def _render_rsa_key_card(entry) -> None:
    """Render a single RSA key card with actions."""
    with st.container(border=True):
        cols = st.columns([3, 2])
        with cols[0]:
            st.markdown(f"**{entry.name}**")
            has_private = "Public + Private" if entry.private_pem else "Public Only"
            st.caption(f"{entry.key_size}-bit RSA  •  {has_private}  •  {_format_time(entry.created)}")
        with cols[1]:
            pass  # placeholder for alignment

        # Actions row
        action_cols = st.columns(4)
        with action_cols[0]:
            st.download_button(
                "📥 Public PEM",
                data=entry.public_pem,
                file_name=f"{entry.name.replace(' ', '_')}_public.pem",
                mime="application/x-pem-file",
                key=f"rsa_pub_dl_{entry.key_id}",
                use_container_width=True,
            )
        with action_cols[1]:
            if entry.private_pem:
                # Optional: encrypt private key for export
                export_pass = st.text_input(
                    "Export password",
                    type="password",
                    key=f"rsa_exp_pass_{entry.key_id}",
                    placeholder="Optional",
                    label_visibility="collapsed",
                )
                priv_obj = algo.import_private_key(entry.private_pem.encode("utf-8"))
                exported = algo.export_private_key(priv_obj, passphrase=export_pass or None)
                st.download_button(
                    "📥 Private PEM",
                    data=exported,
                    file_name=f"{entry.name.replace(' ', '_')}_private.pem",
                    mime="application/x-pem-file",
                    key=f"rsa_priv_dl_{entry.key_id}",
                    use_container_width=True,
                )
            else:
                st.caption("No private key")
        with action_cols[2]:
            new_name = st.text_input(
                "Rename",
                value=entry.name,
                key=f"rsa_rename_input_{entry.key_id}",
                label_visibility="collapsed",
            )
            if new_name != entry.name:
                rename_rsa_key(entry.key_id, new_name)
                st.rerun()
        with action_cols[3]:
            if st.button("🗑️ Delete", key=f"rsa_del_{entry.key_id}", use_container_width=True):
                delete_rsa_key(entry.key_id)
                st.rerun()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_time(iso_str: str) -> str:
    """Format an ISO timestamp for display."""
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso_str
