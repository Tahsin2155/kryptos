"""
Kryptos Web — Session-State Key Store
=======================================

Manage AES-256 symmetric keys and RSA keypairs entirely in
``st.session_state`` — nothing is persisted to disk or sent to the server
beyond the active session.
"""

from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import streamlit as st

# -- make project root importable so we can ``import algo`` ----------------
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import algo  # noqa: E402


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class KeyEntry:
    """A single AES-256 symmetric key stored in the session."""
    key_id: str
    name: str
    key_b64: str
    mode: str  # "system" | "custom"
    created: str
    description: str = ""


@dataclass
class RSAKeyEntry:
    """An RSA keypair stored in the session."""
    key_id: str
    name: str
    public_pem: str   # PEM text
    private_pem: str  # PEM text (unencrypted in memory)
    key_size: int
    created: str
    description: str = ""


# ---------------------------------------------------------------------------
# Session-state initialisation
# ---------------------------------------------------------------------------

_AES_KEY = "kryptos_aes_keys"
_RSA_KEY = "kryptos_rsa_keys"


def _init_state() -> None:
    """Ensure session-state dicts exist."""
    if _AES_KEY not in st.session_state:
        st.session_state[_AES_KEY] = {}
    if _RSA_KEY not in st.session_state:
        st.session_state[_RSA_KEY] = {}


# ---------------------------------------------------------------------------
# AES key operations
# ---------------------------------------------------------------------------

def generate_system_key(name: str, description: str = "") -> KeyEntry:
    """Generate a random AES-256 key and store it in the session."""
    _init_state()
    raw = algo.generate_key()
    entry = KeyEntry(
        key_id=uuid.uuid4().hex[:12],
        name=name.strip() or "Untitled Key",
        key_b64=algo.key_to_base64(raw),
        mode="system",
        created=datetime.now(timezone.utc).isoformat(),
        description=description,
    )
    st.session_state[_AES_KEY][entry.key_id] = entry
    return entry


def import_custom_key(
    name: str,
    value: str,
    fmt: str = "base64",
    description: str = "",
) -> KeyEntry:
    """
    Import a user-supplied key.

    Parameters
    ----------
    value : str
        The key in Base64 or Hex encoding.
    fmt : str
        ``"base64"`` or ``"hex"``.
    """
    _init_state()
    if fmt == "hex":
        raw = algo.key_from_hex(value.strip())
    else:
        raw = algo.key_from_base64(value.strip())

    entry = KeyEntry(
        key_id=uuid.uuid4().hex[:12],
        name=name.strip() or "Imported Key",
        key_b64=algo.key_to_base64(raw),
        mode="custom",
        created=datetime.now(timezone.utc).isoformat(),
        description=description,
    )
    st.session_state[_AES_KEY][entry.key_id] = entry
    return entry


def list_aes_keys() -> list[KeyEntry]:
    """Return all AES keys in the session (newest first)."""
    _init_state()
    keys = list(st.session_state[_AES_KEY].values())
    keys.sort(key=lambda k: k.created, reverse=True)
    return keys


def get_aes_key(key_id: str) -> Optional[KeyEntry]:
    """Look up a single AES key by ID."""
    _init_state()
    return st.session_state[_AES_KEY].get(key_id)


def get_aes_key_bytes(key_id: str) -> bytes:
    """Return the raw 32-byte key for the given ID."""
    entry = get_aes_key(key_id)
    if entry is None:
        raise algo.InvalidKeyError(f"Key '{key_id}' not found in session.")
    return algo.key_from_base64(entry.key_b64)


def delete_aes_key(key_id: str) -> bool:
    """Remove a key from the session. Returns True if it existed."""
    _init_state()
    return st.session_state[_AES_KEY].pop(key_id, None) is not None


def rename_aes_key(key_id: str, new_name: str) -> bool:
    """Rename a key. Returns True on success."""
    _init_state()
    entry = st.session_state[_AES_KEY].get(key_id)
    if entry is None:
        return False
    entry.name = new_name.strip() or entry.name
    return True


# ---------------------------------------------------------------------------
# RSA keypair operations
# ---------------------------------------------------------------------------

def generate_rsa_keypair(name: str, key_size: int = 4096, description: str = "") -> RSAKeyEntry:
    """Generate an RSA keypair and store it in the session."""
    _init_state()
    priv, pub = algo.generate_rsa_keypair(key_size=key_size)
    entry = RSAKeyEntry(
        key_id=uuid.uuid4().hex[:12],
        name=name.strip() or "Untitled RSA Key",
        public_pem=algo.export_public_key(pub).decode("utf-8"),
        private_pem=algo.export_private_key(priv).decode("utf-8"),
        key_size=key_size,
        created=datetime.now(timezone.utc).isoformat(),
        description=description,
    )
    st.session_state[_RSA_KEY][entry.key_id] = entry
    return entry


def import_rsa_public_key(name: str, pem_text: str, description: str = "") -> RSAKeyEntry:
    """Import an RSA public key (no private key)."""
    _init_state()
    pub = algo.import_public_key(pem_text.encode("utf-8"))
    key_size = pub.key_size
    entry = RSAKeyEntry(
        key_id=uuid.uuid4().hex[:12],
        name=name.strip() or "Imported RSA Public Key",
        public_pem=pem_text.strip(),
        private_pem="",
        key_size=key_size,
        created=datetime.now(timezone.utc).isoformat(),
        description=description,
    )
    st.session_state[_RSA_KEY][entry.key_id] = entry
    return entry


def import_rsa_keypair(
    name: str,
    public_pem: str,
    private_pem: str,
    passphrase: Optional[str] = None,
    description: str = "",
) -> RSAKeyEntry:
    """Import both RSA public and private keys."""
    _init_state()
    pub = algo.import_public_key(public_pem.encode("utf-8"))
    priv = algo.import_private_key(private_pem.encode("utf-8"), passphrase=passphrase)
    # Re-export private key unencrypted for session storage
    priv_clean = algo.export_private_key(priv).decode("utf-8")
    entry = RSAKeyEntry(
        key_id=uuid.uuid4().hex[:12],
        name=name.strip() or "Imported RSA Keypair",
        public_pem=public_pem.strip(),
        private_pem=priv_clean,
        key_size=pub.key_size,
        created=datetime.now(timezone.utc).isoformat(),
        description=description,
    )
    st.session_state[_RSA_KEY][entry.key_id] = entry
    return entry


def list_rsa_keys() -> list[RSAKeyEntry]:
    """Return all RSA keys in the session (newest first)."""
    _init_state()
    keys = list(st.session_state[_RSA_KEY].values())
    keys.sort(key=lambda k: k.created, reverse=True)
    return keys


def get_rsa_key(key_id: str) -> Optional[RSAKeyEntry]:
    _init_state()
    return st.session_state[_RSA_KEY].get(key_id)


def delete_rsa_key(key_id: str) -> bool:
    _init_state()
    return st.session_state[_RSA_KEY].pop(key_id, None) is not None


def rename_rsa_key(key_id: str, new_name: str) -> bool:
    _init_state()
    entry = st.session_state[_RSA_KEY].get(key_id)
    if entry is None:
        return False
    entry.name = new_name.strip() or entry.name
    return True
