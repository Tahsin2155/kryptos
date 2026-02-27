"""
Kryptos Key Manager
===================

Handles three key modes:
  1. System-generated keys — random AES-256 keys
  2. User-custom keys — passphrase-based (PBKDF2)
  3. Machine keys — derived from machine-specific identifiers and stored locally

Machine keys are stored in an OS-appropriate config directory
and protected with platform-level file permissions.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import algo


# ---------------------------------------------------------------------------
# Config directory
# ---------------------------------------------------------------------------

def _config_dir() -> Path:
    """Return the OS-appropriate config directory for Kryptos."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    config = base / "Kryptos"
    config.mkdir(parents=True, exist_ok=True)
    return config


# ---------------------------------------------------------------------------
# Machine fingerprint
# ---------------------------------------------------------------------------

def _machine_fingerprint() -> str:
    """Generate a stable machine-specific fingerprint."""
    parts = [
        platform.node(),
        platform.machine(),
        platform.processor(),
    ]
    # Add MAC address for extra uniqueness
    try:
        mac = uuid.getnode()
        parts.append(str(mac))
    except Exception:
        pass
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# KeyManager
# ---------------------------------------------------------------------------

class KeyEntry:
    """Represents a stored key entry."""

    def __init__(
        self,
        key_id: str,
        name: str,
        key_b64: str,
        mode: str,
        created: str,
        description: str = "",
    ):
        self.key_id = key_id
        self.name = name
        self.key_b64 = key_b64
        self.mode = mode  # "system", "custom", "machine"
        self.created = created
        self.description = description

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "name": self.name,
            "key_b64": self.key_b64,
            "mode": self.mode,
            "created": self.created,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KeyEntry":
        return cls(
            key_id=d["key_id"],
            name=d["name"],
            key_b64=d["key_b64"],
            mode=d["mode"],
            created=d["created"],
            description=d.get("description", ""),
        )

    def get_key_bytes(self) -> bytes:
        """Decode the stored key to raw bytes."""
        return algo.key_from_base64(self.key_b64)


class KeyManager:
    """Manage stored encryption keys."""

    def __init__(self):
        self._config_dir = _config_dir()
        self._keys_file = self._config_dir / "keys.json"
        self._keys: Dict[str, KeyEntry] = {}
        self._load()

    # ----- persistence -----

    def _load(self) -> None:
        """Load keys from disk."""
        if self._keys_file.exists():
            try:
                data = json.loads(self._keys_file.read_text("utf-8"))
                for d in data.get("keys", []):
                    entry = KeyEntry.from_dict(d)
                    self._keys[entry.key_id] = entry
            except Exception:
                # Corrupt file — start fresh
                self._keys = {}

    def _save(self) -> None:
        """Persist keys to disk."""
        data = {"keys": [e.to_dict() for e in self._keys.values()]}
        self._keys_file.write_text(json.dumps(data, indent=2), "utf-8")
        # Restrict permissions on the key file (owner-only)
        try:
            if platform.system() != "Windows":
                os.chmod(self._keys_file, 0o600)
        except OSError:
            pass

    # ----- operations -----

    def generate_system_key(self, name: str, description: str = "") -> KeyEntry:
        """Generate a random system key and store it."""
        raw_key = algo.generate_key()
        key_b64 = algo.key_to_base64(raw_key)
        key_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        entry = KeyEntry(key_id, name, key_b64, "system", now, description)
        self._keys[key_id] = entry
        self._save()
        return entry

    def import_custom_key(
        self, name: str, key_b64: str, description: str = ""
    ) -> KeyEntry:
        """Import a user-supplied key (Base64 encoded)."""
        # Validate it
        algo.key_from_base64(key_b64)
        key_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        entry = KeyEntry(key_id, name, key_b64, "custom", now, description)
        self._keys[key_id] = entry
        self._save()
        return entry

    def import_hex_key(
        self, name: str, key_hex: str, description: str = ""
    ) -> KeyEntry:
        """Import a user-supplied key (hex encoded)."""
        raw = algo.key_from_hex(key_hex)
        key_b64 = algo.key_to_base64(raw)
        key_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        entry = KeyEntry(key_id, name, key_b64, "custom", now, description)
        self._keys[key_id] = entry
        self._save()
        return entry

    def get_or_create_machine_key(self) -> KeyEntry:
        """
        Get (or create) the machine-specific key.

        The key is derived from a stable machine fingerprint combined with
        a random salt that is persisted once.
        """
        # Check if a machine key already exists
        for entry in self._keys.values():
            if entry.mode == "machine":
                return entry

        # Derive a new machine key
        fingerprint = _machine_fingerprint()
        salt = os.urandom(algo.SALT_SIZE)
        derived_key, _ = algo.derive_key(fingerprint, salt=salt)
        key_b64 = algo.key_to_base64(derived_key)
        key_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        entry = KeyEntry(
            key_id,
            "Machine Key",
            key_b64,
            "machine",
            now,
            f"Machine-specific key for {platform.node()}",
        )
        self._keys[key_id] = entry
        self._save()
        return entry

    def list_keys(self) -> List[KeyEntry]:
        """Return all stored keys."""
        return list(self._keys.values())

    def get_key(self, key_id: str) -> Optional[KeyEntry]:
        """Get a key by ID."""
        return self._keys.get(key_id)

    def delete_key(self, key_id: str) -> bool:
        """Delete a key by ID. Returns True if deleted."""
        if key_id in self._keys:
            del self._keys[key_id]
            self._save()
            return True
        return False

    def rename_key(self, key_id: str, new_name: str) -> bool:
        """Rename a key. Returns True if successful."""
        if key_id in self._keys:
            self._keys[key_id].name = new_name
            self._save()
            return True
        return False
