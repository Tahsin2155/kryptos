"""
Kryptos Encryption/Decryption Engine
=====================================

AES-256-GCM authenticated encryption with:
- PBKDF2-HMAC-SHA256 key derivation from passphrases
- RSA-4096 OAEP key wrapping (hybrid encryption)
- Chunked streaming file encryption with per-chunk authentication
- Cross-platform binary format (interoperable with Web Crypto API)

Uses the ``cryptography`` library exclusively.

Format specification (v1)
-------------------------
::

    [HEADER: 16 bytes]
      0-7   Magic   b"KRYPTOS\\x00"
      8     Version  0x01
      9     AlgID    0x01 (AES-256-GCM)
     10     KDF flag 0x00=raw | 0x01=PBKDF2 | 0x02=RSA-wrapped
     11-15  Reserved (zeroed)

    [VARIABLE SECTION — depends on KDF flag]
      flag 0x00  → (nothing)
      flag 0x01  → Salt: 16 bytes | PBKDF2 iterations: 4 bytes (big-endian)
      flag 0x02  → RSA-wrapped key length: 2 bytes (big-endian) | RSA-wrapped key blob

    [CRYPTO PAYLOAD]
      Nonce/IV : 12 bytes
      Ciphertext: variable
      GCM Tag  : 16 bytes (appended by cryptography lib)

    For streamed files the payload section repeats per chunk:
      Chunk nonce : 12 bytes   (base_nonce XOR chunk_index)
      Chunk length: 4 bytes    (big-endian, 0 = final sentinel)
      Chunk ciphertext + tag : variable (GCM fuses tag into ciphertext)
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from pathlib import Path
from typing import Callable, Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAGIC: bytes = b"KRYPTOS\x00"
FORMAT_VERSION: int = 1
ALG_AES256GCM: int = 1

KDF_NONE: int = 0
KDF_PBKDF2: int = 1
KDF_RSA: int = 2

HEADER_SIZE: int = 16  # fixed header length
NONCE_SIZE: int = 12   # AES-GCM recommended nonce
TAG_SIZE: int = 16     # GCM authentication tag
KEY_SIZE: int = 32     # AES-256 = 32 bytes
SALT_SIZE: int = 16    # PBKDF2 salt
PBKDF2_ITERATIONS: int = 600_000  # OWASP 2023 recommendation for SHA-256
DEFAULT_CHUNK: int = 64 * 1024     # 64 KiB streaming chunk

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class KryptosError(Exception):
    """Base exception for all Kryptos errors."""


class DecryptionError(KryptosError):
    """Wrong key, corrupted ciphertext, or authentication failure."""


class InvalidKeyError(KryptosError):
    """Key is malformed or has wrong length."""


class FormatError(KryptosError):
    """Encrypted data has an invalid or unsupported format."""


class IntegrityError(DecryptionError):
    """Authentication tag verification failed."""


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------


def _build_header(kdf_flag: int) -> bytes:
    """Build a 16-byte Kryptos file header."""
    header = bytearray(HEADER_SIZE)
    header[0:8] = MAGIC
    header[8] = FORMAT_VERSION
    header[9] = ALG_AES256GCM
    header[10] = kdf_flag
    # bytes 11-15 reserved (already zeroed)
    return bytes(header)


def _parse_header(data: bytes) -> int:
    """
    Validate and parse a 16-byte header.

    Returns the KDF flag.

    Raises
    ------
    FormatError
        If the header is invalid or unsupported.
    """
    if len(data) < HEADER_SIZE:
        raise FormatError("Data too short to contain a valid Kryptos header.")
    if data[0:8] != MAGIC:
        raise FormatError("Invalid magic bytes — not a Kryptos encrypted payload.")
    version = data[8]
    if version != FORMAT_VERSION:
        raise FormatError(f"Unsupported format version {version} (expected {FORMAT_VERSION}).")
    alg = data[9]
    if alg != ALG_AES256GCM:
        raise FormatError(f"Unsupported algorithm ID {alg}.")
    kdf_flag = data[10]
    if kdf_flag not in (KDF_NONE, KDF_PBKDF2, KDF_RSA):
        raise FormatError(f"Unknown KDF flag {kdf_flag}.")
    return kdf_flag


# ---------------------------------------------------------------------------
# Nonce derivation for streaming chunks
# ---------------------------------------------------------------------------


def _derive_chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    """XOR a 12-byte base nonce with a chunk index to produce a unique nonce."""
    n = int.from_bytes(base_nonce, "big") ^ index
    return n.to_bytes(NONCE_SIZE, "big")


# ---------------------------------------------------------------------------
# KryptosEngine
# ---------------------------------------------------------------------------


class KryptosEngine:
    """
    High-level encryption / decryption engine.

    All public methods are **static** — the class serves as a logical
    namespace and can be subclassed for future algorithm variants.
    """

    # ------------------------------------------------------------------
    # Key generation & conversion
    # ------------------------------------------------------------------

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure random 256-bit key."""
        return os.urandom(KEY_SIZE)

    @staticmethod
    def key_to_base64(key: bytes) -> str:
        """Encode a key as URL-safe Base64."""
        _validate_key(key)
        return base64.urlsafe_b64encode(key).decode("ascii")

    @staticmethod
    def key_from_base64(b64: str) -> bytes:
        """Decode a key from URL-safe Base64."""
        try:
            key = base64.urlsafe_b64decode(b64)
        except Exception as exc:
            raise InvalidKeyError("Invalid Base64 key encoding.") from exc
        _validate_key(key)
        return key

    @staticmethod
    def key_to_hex(key: bytes) -> str:
        """Encode a key as lowercase hex."""
        _validate_key(key)
        return key.hex()

    @staticmethod
    def key_from_hex(h: str) -> bytes:
        """Decode a key from hex."""
        try:
            key = bytes.fromhex(h)
        except Exception as exc:
            raise InvalidKeyError("Invalid hex key encoding.") from exc
        _validate_key(key)
        return key

    # ------------------------------------------------------------------
    # Key derivation (PBKDF2)
    # ------------------------------------------------------------------

    @staticmethod
    def derive_key(
        passphrase: str,
        salt: Optional[bytes] = None,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> Tuple[bytes, bytes]:
        """
        Derive a 256-bit key from a passphrase using PBKDF2-HMAC-SHA256.

        Parameters
        ----------
        passphrase : str
            User-supplied passphrase.
        salt : bytes, optional
            16-byte salt.  Generated randomly if not provided.
        iterations : int
            PBKDF2 iteration count (default 600 000).

        Returns
        -------
        (key, salt) : tuple[bytes, bytes]
        """
        _validate_passphrase(passphrase)
        if salt is None:
            salt = os.urandom(SALT_SIZE)
        if len(salt) != SALT_SIZE:
            raise InvalidKeyError(f"Salt must be {SALT_SIZE} bytes, got {len(salt)}.")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(passphrase.encode("utf-8"))
        return key, salt

    # ------------------------------------------------------------------
    # In-memory AES-256-GCM encrypt / decrypt (raw key)
    # ------------------------------------------------------------------

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        """
        Encrypt *plaintext* with a raw 256-bit *key*.

        Returns a self-contained blob:
        ``header(16) || nonce(12) || ciphertext+tag``
        """
        _validate_key(key)
        header = _build_header(KDF_NONE)
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, header)  # header as AAD
        return header + nonce + ct

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt`.

        Raises
        ------
        DecryptionError
            If the key is wrong or the data is corrupted.
        FormatError
            If the blob header is invalid.
        """
        _validate_key(key)
        kdf_flag = _parse_header(data)
        if kdf_flag != KDF_NONE:
            raise FormatError(
                "This payload was not encrypted with a raw key "
                f"(KDF flag={kdf_flag})."
            )
        header = data[:HEADER_SIZE]
        nonce = data[HEADER_SIZE : HEADER_SIZE + NONCE_SIZE]
        ct = data[HEADER_SIZE + NONCE_SIZE :]
        if len(nonce) != NONCE_SIZE or len(ct) < TAG_SIZE:
            raise FormatError("Payload too short — missing nonce or ciphertext.")
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ct, header)
        except InvalidTag:
            raise DecryptionError(
                "Authentication failed: wrong key or corrupted data."
            )

    # ------------------------------------------------------------------
    # In-memory encrypt / decrypt with passphrase
    # ------------------------------------------------------------------

    @staticmethod
    def encrypt_with_passphrase(
        plaintext: bytes,
        passphrase: str,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> bytes:
        """
        Encrypt using a passphrase (PBKDF2 key derivation).

        Output layout:
        ``header(16) || salt(16) || iterations(4 BE) || nonce(12) || ct+tag``
        """
        _validate_passphrase(passphrase)
        key, salt = KryptosEngine.derive_key(passphrase, iterations=iterations)
        header = _build_header(KDF_PBKDF2)
        nonce = os.urandom(NONCE_SIZE)
        # AAD covers header + salt + iterations so none can be tampered
        aad = header + salt + struct.pack(">I", iterations)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        return header + salt + struct.pack(">I", iterations) + nonce + ct

    @staticmethod
    def decrypt_with_passphrase(data: bytes, passphrase: str) -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt_with_passphrase`.
        """
        _validate_passphrase(passphrase)
        kdf_flag = _parse_header(data)
        if kdf_flag != KDF_PBKDF2:
            raise FormatError("Payload was not encrypted with a passphrase.")
        offset = HEADER_SIZE
        salt = data[offset : offset + SALT_SIZE]
        offset += SALT_SIZE
        if len(salt) != SALT_SIZE:
            raise FormatError("Payload too short — missing PBKDF2 salt.")
        iterations = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        nonce = data[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE
        ct = data[offset:]
        if len(nonce) != NONCE_SIZE or len(ct) < TAG_SIZE:
            raise FormatError("Payload too short — missing nonce or ciphertext.")

        key, _ = KryptosEngine.derive_key(passphrase, salt=salt, iterations=iterations)
        aad = data[:HEADER_SIZE] + salt + struct.pack(">I", iterations)
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ct, aad)
        except InvalidTag:
            raise DecryptionError(
                "Authentication failed: wrong passphrase or corrupted data."
            )

    # ------------------------------------------------------------------
    # Chunked streaming file encryption / decryption (raw key)
    # ------------------------------------------------------------------

    @staticmethod
    def encrypt_file(
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        key: bytes,
        *,
        chunk_size: int = DEFAULT_CHUNK,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """
        Encrypt a file using chunked AES-256-GCM.

        Each chunk is encrypted independently with a nonce derived from
        ``base_nonce XOR chunk_index``.  A zero-length final sentinel chunk
        prevents truncation attacks.

        Per-chunk on-disk layout::

            chunk_nonce(12) || chunk_len(4 BE) || chunk_ct+tag(variable)

        Parameters
        ----------
        input_path, output_path : path-like
        key : bytes (32)
        chunk_size : int
            Plaintext bytes per chunk (default 64 KiB).
        progress_callback : callable(bytes_processed, total_bytes)
        """
        _validate_key(key)
        input_path = Path(input_path)
        output_path = Path(output_path)
        total = input_path.stat().st_size
        header = _build_header(KDF_NONE)
        base_nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)

        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            # Write header + base nonce (used to derive per-chunk nonces)
            fout.write(header)
            fout.write(base_nonce)

            chunk_index = 0
            bytes_processed = 0

            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break

                cnonce = _derive_chunk_nonce(base_nonce, chunk_index)
                # AAD = header + chunk_index to bind ordering
                aad = header + struct.pack(">Q", chunk_index)
                ct = aesgcm.encrypt(cnonce, chunk, aad)
                fout.write(cnonce)
                fout.write(struct.pack(">I", len(chunk)))
                fout.write(ct)

                chunk_index += 1
                bytes_processed += len(chunk)
                if progress_callback:
                    progress_callback(bytes_processed, total)

            # Final sentinel (zero-length chunk) — prevents truncation
            cnonce = _derive_chunk_nonce(base_nonce, chunk_index)
            aad = header + struct.pack(">Q", chunk_index)
            ct = aesgcm.encrypt(cnonce, b"", aad)
            fout.write(cnonce)
            fout.write(struct.pack(">I", 0))
            fout.write(ct)

    @staticmethod
    def decrypt_file(
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        key: bytes,
        *,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """
        Decrypt a file produced by :meth:`encrypt_file`.
        """
        _validate_key(key)
        input_path = Path(input_path)
        output_path = Path(output_path)
        total = input_path.stat().st_size
        aesgcm = AESGCM(key)

        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            header = fin.read(HEADER_SIZE)
            kdf_flag = _parse_header(header)
            if kdf_flag != KDF_NONE:
                raise FormatError("Streamed file was not encrypted with a raw key.")
            base_nonce = fin.read(NONCE_SIZE)
            if len(base_nonce) != NONCE_SIZE:
                raise FormatError("Payload too short — missing base nonce.")

            chunk_index = 0
            bytes_processed = HEADER_SIZE + NONCE_SIZE

            while True:
                cnonce = fin.read(NONCE_SIZE)
                if len(cnonce) == 0:
                    raise FormatError("Missing sentinel — file may be truncated.")
                if len(cnonce) != NONCE_SIZE:
                    raise FormatError("Truncated chunk nonce.")

                raw_len = fin.read(4)
                if len(raw_len) != 4:
                    raise FormatError("Truncated chunk length.")
                chunk_pt_len = struct.unpack(">I", raw_len)[0]

                # ciphertext length = plaintext length + TAG_SIZE
                ct_len = chunk_pt_len + TAG_SIZE
                ct = fin.read(ct_len)
                if len(ct) != ct_len:
                    raise FormatError("Truncated chunk ciphertext.")

                expected_nonce = _derive_chunk_nonce(base_nonce, chunk_index)
                if cnonce != expected_nonce:
                    raise IntegrityError("Chunk nonce mismatch — possible reordering attack.")

                aad = header + struct.pack(">Q", chunk_index)
                try:
                    pt = aesgcm.decrypt(cnonce, ct, aad)
                except InvalidTag:
                    raise DecryptionError(
                        f"Authentication failed on chunk {chunk_index}: "
                        "wrong key or corrupted data."
                    )

                if chunk_pt_len == 0:
                    # Sentinel chunk — end of stream
                    break

                fout.write(pt)
                chunk_index += 1
                bytes_processed += NONCE_SIZE + 4 + ct_len
                if progress_callback:
                    progress_callback(bytes_processed, total)

    # ------------------------------------------------------------------
    # Streamed file encrypt / decrypt with passphrase
    # ------------------------------------------------------------------

    @staticmethod
    def encrypt_file_with_passphrase(
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        passphrase: str,
        *,
        chunk_size: int = DEFAULT_CHUNK,
        iterations: int = PBKDF2_ITERATIONS,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """
        Encrypt a file using a passphrase (PBKDF2 → AES-256-GCM streaming).

        Layout: ``header(16) || salt(16) || iterations(4) || <chunked payload>``
        """
        _validate_passphrase(passphrase)
        key, salt = KryptosEngine.derive_key(passphrase, iterations=iterations)

        input_path = Path(input_path)
        output_path = Path(output_path)
        total = input_path.stat().st_size
        header = _build_header(KDF_PBKDF2)
        base_nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)

        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            fout.write(header)
            fout.write(salt)
            fout.write(struct.pack(">I", iterations))
            fout.write(base_nonce)

            chunk_index = 0
            bytes_processed = 0

            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                cnonce = _derive_chunk_nonce(base_nonce, chunk_index)
                aad = header + salt + struct.pack(">I", iterations) + struct.pack(">Q", chunk_index)
                ct = aesgcm.encrypt(cnonce, chunk, aad)
                fout.write(cnonce)
                fout.write(struct.pack(">I", len(chunk)))
                fout.write(ct)
                chunk_index += 1
                bytes_processed += len(chunk)
                if progress_callback:
                    progress_callback(bytes_processed, total)

            # Sentinel
            cnonce = _derive_chunk_nonce(base_nonce, chunk_index)
            aad = header + salt + struct.pack(">I", iterations) + struct.pack(">Q", chunk_index)
            ct = aesgcm.encrypt(cnonce, b"", aad)
            fout.write(cnonce)
            fout.write(struct.pack(">I", 0))
            fout.write(ct)

    @staticmethod
    def decrypt_file_with_passphrase(
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        passphrase: str,
        *,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """
        Decrypt a file produced by :meth:`encrypt_file_with_passphrase`.
        """
        _validate_passphrase(passphrase)
        input_path = Path(input_path)
        output_path = Path(output_path)
        total = input_path.stat().st_size
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            header = fin.read(HEADER_SIZE)
            kdf_flag = _parse_header(header)
            if kdf_flag != KDF_PBKDF2:
                raise FormatError("Streamed file was not encrypted with a passphrase.")
            salt = fin.read(SALT_SIZE)
            if len(salt) != SALT_SIZE:
                raise FormatError("Missing PBKDF2 salt.")
            raw_iter = fin.read(4)
            if len(raw_iter) != 4:
                raise FormatError("Missing iteration count.")
            iterations = struct.unpack(">I", raw_iter)[0]
            base_nonce = fin.read(NONCE_SIZE)
            if len(base_nonce) != NONCE_SIZE:
                raise FormatError("Missing base nonce.")

            key, _ = KryptosEngine.derive_key(passphrase, salt=salt, iterations=iterations)
            aesgcm = AESGCM(key)
            chunk_index = 0
            bytes_processed = HEADER_SIZE + SALT_SIZE + 4 + NONCE_SIZE

            while True:
                cnonce = fin.read(NONCE_SIZE)
                if len(cnonce) == 0:
                    raise FormatError("Missing sentinel — file may be truncated.")
                if len(cnonce) != NONCE_SIZE:
                    raise FormatError("Truncated chunk nonce.")
                raw_len = fin.read(4)
                if len(raw_len) != 4:
                    raise FormatError("Truncated chunk length.")
                chunk_pt_len = struct.unpack(">I", raw_len)[0]
                ct_len = chunk_pt_len + TAG_SIZE
                ct = fin.read(ct_len)
                if len(ct) != ct_len:
                    raise FormatError("Truncated chunk ciphertext.")

                expected_nonce = _derive_chunk_nonce(base_nonce, chunk_index)
                if cnonce != expected_nonce:
                    raise IntegrityError("Chunk nonce mismatch.")

                aad = header + salt + struct.pack(">I", iterations) + struct.pack(">Q", chunk_index)
                try:
                    pt = aesgcm.decrypt(cnonce, ct, aad)
                except InvalidTag:
                    raise DecryptionError(
                        f"Authentication failed on chunk {chunk_index}: "
                        "wrong passphrase or corrupted data."
                    )
                if chunk_pt_len == 0:
                    break
                fout.write(pt)
                chunk_index += 1
                bytes_processed += NONCE_SIZE + 4 + ct_len
                if progress_callback:
                    progress_callback(bytes_processed, total)

    # ------------------------------------------------------------------
    # RSA key generation & serialization
    # ------------------------------------------------------------------

    @staticmethod
    def generate_rsa_keypair(
        key_size: int = 4096,
    ) -> Tuple[RSAPrivateKey, RSAPublicKey]:
        """Generate an RSA keypair (default 4096-bit)."""
        if key_size < 2048:
            raise InvalidKeyError("RSA key size must be at least 2048 bits.")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        return private_key, private_key.public_key()

    @staticmethod
    def export_public_key(pub_key: RSAPublicKey) -> bytes:
        """Serialize an RSA public key to PEM."""
        return pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def import_public_key(pem: bytes) -> RSAPublicKey:
        """Load an RSA public key from PEM."""
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, RSAPublicKey):
            raise InvalidKeyError("PEM does not contain an RSA public key.")
        return key

    @staticmethod
    def export_private_key(
        priv_key: RSAPrivateKey,
        passphrase: Optional[str] = None,
    ) -> bytes:
        """
        Serialize an RSA private key to PEM.

        If *passphrase* is given the key is encrypted with AES-256-CBC
        (via the ``cryptography`` library's built-in PEM encryption).
        """
        enc: serialization.KeySerializationEncryption
        if passphrase:
            enc = serialization.BestAvailableEncryption(
                passphrase.encode("utf-8")
            )
        else:
            enc = serialization.NoEncryption()
        return priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )

    @staticmethod
    def import_private_key(
        pem: bytes,
        passphrase: Optional[str] = None,
    ) -> RSAPrivateKey:
        """Load an RSA private key from PEM (optionally encrypted)."""
        pwd = passphrase.encode("utf-8") if passphrase else None
        key = serialization.load_pem_private_key(pem, password=pwd)
        if not isinstance(key, RSAPrivateKey):
            raise InvalidKeyError("PEM does not contain an RSA private key.")
        return key

    # ------------------------------------------------------------------
    # Hybrid RSA + AES-256-GCM encrypt / decrypt
    # ------------------------------------------------------------------

    @staticmethod
    def encrypt_with_rsa(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
        """
        Hybrid encryption: wrap a random AES key with RSA-OAEP, then
        encrypt *plaintext* with AES-256-GCM.

        Layout:
        ``header(16) || wrapped_key_len(2 BE) || wrapped_key || nonce(12) || ct+tag``
        """
        aes_key = KryptosEngine.generate_key()
        wrapped_key = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        header = _build_header(KDF_RSA)
        wk_len = struct.pack(">H", len(wrapped_key))
        nonce = os.urandom(NONCE_SIZE)
        # AAD covers header + wrapped key metadata
        aad = header + wk_len + wrapped_key
        aesgcm = AESGCM(aes_key)
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        return header + wk_len + wrapped_key + nonce + ct

    @staticmethod
    def decrypt_with_rsa(data: bytes, private_key: RSAPrivateKey) -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt_with_rsa`.
        """
        kdf_flag = _parse_header(data)
        if kdf_flag != KDF_RSA:
            raise FormatError("Payload was not encrypted with RSA key wrapping.")
        offset = HEADER_SIZE
        wk_len = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        wrapped_key = data[offset : offset + wk_len]
        offset += wk_len
        if len(wrapped_key) != wk_len:
            raise FormatError("Truncated RSA-wrapped key.")
        nonce = data[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE
        ct = data[offset:]
        if len(nonce) != NONCE_SIZE or len(ct) < TAG_SIZE:
            raise FormatError("Payload too short — missing nonce or ciphertext.")

        header = data[:HEADER_SIZE]
        aad = header + struct.pack(">H", wk_len) + wrapped_key

        try:
            aes_key = private_key.decrypt(
                wrapped_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception:
            raise DecryptionError("RSA decryption failed: wrong private key.")

        _validate_key(aes_key)
        aesgcm = AESGCM(aes_key)
        try:
            return aesgcm.decrypt(nonce, ct, aad)
        except InvalidTag:
            raise DecryptionError(
                "Authentication failed: wrong key or corrupted data."
            )

    # ------------------------------------------------------------------
    # Streamed file encrypt / decrypt with RSA
    # ------------------------------------------------------------------

    @staticmethod
    def encrypt_file_with_rsa(
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        public_key: RSAPublicKey,
        *,
        chunk_size: int = DEFAULT_CHUNK,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """
        Stream-encrypt a file with hybrid RSA + AES-256-GCM.

        Layout: ``header(16) || wk_len(2) || wrapped_key || base_nonce(12) || chunks…``
        """
        aes_key = KryptosEngine.generate_key()
        wrapped_key = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        header = _build_header(KDF_RSA)
        wk_len_bytes = struct.pack(">H", len(wrapped_key))
        base_nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(aes_key)

        input_path = Path(input_path)
        output_path = Path(output_path)
        total = input_path.stat().st_size

        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            fout.write(header)
            fout.write(wk_len_bytes)
            fout.write(wrapped_key)
            fout.write(base_nonce)

            preamble = header + wk_len_bytes + wrapped_key
            chunk_index = 0
            bytes_processed = 0

            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                cnonce = _derive_chunk_nonce(base_nonce, chunk_index)
                aad = preamble + struct.pack(">Q", chunk_index)
                ct = aesgcm.encrypt(cnonce, chunk, aad)
                fout.write(cnonce)
                fout.write(struct.pack(">I", len(chunk)))
                fout.write(ct)
                chunk_index += 1
                bytes_processed += len(chunk)
                if progress_callback:
                    progress_callback(bytes_processed, total)

            # Sentinel
            cnonce = _derive_chunk_nonce(base_nonce, chunk_index)
            aad = preamble + struct.pack(">Q", chunk_index)
            ct = aesgcm.encrypt(cnonce, b"", aad)
            fout.write(cnonce)
            fout.write(struct.pack(">I", 0))
            fout.write(ct)

    @staticmethod
    def decrypt_file_with_rsa(
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        private_key: RSAPrivateKey,
        *,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """
        Decrypt a file produced by :meth:`encrypt_file_with_rsa`.
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        total = input_path.stat().st_size

        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            header = fin.read(HEADER_SIZE)
            kdf_flag = _parse_header(header)
            if kdf_flag != KDF_RSA:
                raise FormatError("File was not encrypted with RSA.")
            raw_wk_len = fin.read(2)
            if len(raw_wk_len) != 2:
                raise FormatError("Truncated wrapped-key length.")
            wk_len = struct.unpack(">H", raw_wk_len)[0]
            wrapped_key = fin.read(wk_len)
            if len(wrapped_key) != wk_len:
                raise FormatError("Truncated RSA-wrapped key.")

            try:
                aes_key = private_key.decrypt(
                    wrapped_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            except Exception:
                raise DecryptionError("RSA decryption failed: wrong private key.")

            _validate_key(aes_key)
            aesgcm = AESGCM(aes_key)

            base_nonce = fin.read(NONCE_SIZE)
            if len(base_nonce) != NONCE_SIZE:
                raise FormatError("Missing base nonce.")

            preamble = header + raw_wk_len + wrapped_key
            chunk_index = 0
            bytes_processed = HEADER_SIZE + 2 + wk_len + NONCE_SIZE

            while True:
                cnonce = fin.read(NONCE_SIZE)
                if len(cnonce) == 0:
                    raise FormatError("Missing sentinel — file may be truncated.")
                if len(cnonce) != NONCE_SIZE:
                    raise FormatError("Truncated chunk nonce.")
                raw_len = fin.read(4)
                if len(raw_len) != 4:
                    raise FormatError("Truncated chunk length.")
                chunk_pt_len = struct.unpack(">I", raw_len)[0]
                ct_len = chunk_pt_len + TAG_SIZE
                ct = fin.read(ct_len)
                if len(ct) != ct_len:
                    raise FormatError("Truncated chunk ciphertext.")

                expected_nonce = _derive_chunk_nonce(base_nonce, chunk_index)
                if cnonce != expected_nonce:
                    raise IntegrityError("Chunk nonce mismatch.")

                aad = preamble + struct.pack(">Q", chunk_index)
                try:
                    pt = aesgcm.decrypt(cnonce, ct, aad)
                except InvalidTag:
                    raise DecryptionError(
                        f"Chunk {chunk_index} auth failed: wrong key or corrupt."
                    )
                if chunk_pt_len == 0:
                    break
                fout.write(pt)
                chunk_index += 1
                bytes_processed += NONCE_SIZE + 4 + ct_len
                if progress_callback:
                    progress_callback(bytes_processed, total)


# ---------------------------------------------------------------------------
# Validation helpers (module-private)
# ---------------------------------------------------------------------------


def _validate_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise InvalidKeyError("Key must be bytes.")
    if len(key) != KEY_SIZE:
        raise InvalidKeyError(
            f"Key must be exactly {KEY_SIZE} bytes (got {len(key)})."
        )


def _validate_passphrase(passphrase: str) -> None:
    if not isinstance(passphrase, str) or len(passphrase) == 0:
        raise InvalidKeyError("Passphrase must be a non-empty string.")


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

_engine = KryptosEngine

generate_key = _engine.generate_key
key_to_base64 = _engine.key_to_base64
key_from_base64 = _engine.key_from_base64
key_to_hex = _engine.key_to_hex
key_from_hex = _engine.key_from_hex
derive_key = _engine.derive_key

encrypt = _engine.encrypt
decrypt = _engine.decrypt
encrypt_with_passphrase = _engine.encrypt_with_passphrase
decrypt_with_passphrase = _engine.decrypt_with_passphrase

encrypt_file = _engine.encrypt_file
decrypt_file = _engine.decrypt_file
encrypt_file_with_passphrase = _engine.encrypt_file_with_passphrase
decrypt_file_with_passphrase = _engine.decrypt_file_with_passphrase

generate_rsa_keypair = _engine.generate_rsa_keypair
export_public_key = _engine.export_public_key
import_public_key = _engine.import_public_key
export_private_key = _engine.export_private_key
import_private_key = _engine.import_private_key
encrypt_with_rsa = _engine.encrypt_with_rsa
decrypt_with_rsa = _engine.decrypt_with_rsa
encrypt_file_with_rsa = _engine.encrypt_file_with_rsa
decrypt_file_with_rsa = _engine.decrypt_file_with_rsa


# ---------------------------------------------------------------------------
# Self-test / verification (run with: python algo.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile
    import sys

    passed = 0
    failed = 0

    def _test(name: str, fn):
        global passed, failed
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            failed += 1

    print("=" * 60)
    print("Kryptos Algorithm Self-Test")
    print("=" * 60)

    # --- 1. Key generation & conversion ---
    print("\n-- Key generation & conversion --")

    def test_keygen():
        k = generate_key()
        assert len(k) == 32, f"Expected 32 bytes, got {len(k)}"
        k2 = generate_key()
        assert k != k2, "Two generated keys must differ"

    _test("generate_key produces unique 32-byte keys", test_keygen)

    def test_key_b64_roundtrip():
        k = generate_key()
        assert key_from_base64(key_to_base64(k)) == k

    _test("Base64 key round-trip", test_key_b64_roundtrip)

    def test_key_hex_roundtrip():
        k = generate_key()
        assert key_from_hex(key_to_hex(k)) == k

    _test("Hex key round-trip", test_key_hex_roundtrip)

    # --- 2. In-memory raw-key encrypt/decrypt ---
    print("\n-- In-memory AES-256-GCM (raw key) --")

    def test_encrypt_decrypt():
        k = generate_key()
        pt = b"Hello Kryptos!"
        ct = encrypt(pt, k)
        assert decrypt(ct, k) == pt

    _test("Encrypt → Decrypt round-trip", test_encrypt_decrypt)

    def test_non_determinism():
        k = generate_key()
        pt = b"same plaintext"
        c1 = encrypt(pt, k)
        c2 = encrypt(pt, k)
        assert c1 != c2, "Ciphertexts must differ (non-deterministic)"

    _test("Non-determinism (same pt → different ct)", test_non_determinism)

    def test_wrong_key():
        k1 = generate_key()
        k2 = generate_key()
        ct = encrypt(b"secret", k1)
        try:
            decrypt(ct, k2)
            assert False, "Should have raised"
        except DecryptionError:
            pass

    _test("Wrong key raises DecryptionError", test_wrong_key)

    def test_tamper():
        k = generate_key()
        ct = bytearray(encrypt(b"data", k))
        ct[-1] ^= 0xFF  # flip last byte (in tag)
        try:
            decrypt(bytes(ct), k)
            assert False, "Should have raised"
        except DecryptionError:
            pass

    _test("Tampered ciphertext raises DecryptionError", test_tamper)

    def test_empty_plaintext():
        k = generate_key()
        ct = encrypt(b"", k)
        assert decrypt(ct, k) == b""

    _test("Empty plaintext encrypt/decrypt", test_empty_plaintext)

    def test_large_plaintext():
        k = generate_key()
        pt = os.urandom(1_000_000)  # 1 MB
        ct = encrypt(pt, k)
        assert decrypt(ct, k) == pt

    _test("1 MB plaintext encrypt/decrypt", test_large_plaintext)

    # --- 3. Passphrase encrypt/decrypt ---
    print("\n-- Passphrase (PBKDF2) --")

    def test_passphrase_roundtrip():
        pt = b"Hello Kryptos with passphrase!"
        pw = "correct horse battery staple"
        ct = encrypt_with_passphrase(pt, pw)
        assert decrypt_with_passphrase(ct, pw) == pt

    _test("Passphrase encrypt → decrypt round-trip", test_passphrase_roundtrip)

    def test_wrong_passphrase():
        ct = encrypt_with_passphrase(b"secret", "right")
        try:
            decrypt_with_passphrase(ct, "wrong")
            assert False
        except DecryptionError:
            pass

    _test("Wrong passphrase raises DecryptionError", test_wrong_passphrase)

    # --- 4. Streaming file encryption ---
    print("\n-- Streaming file encryption (raw key) --")

    def test_file_roundtrip():
        k = generate_key()
        pt = os.urandom(256_000)  # ~250 KB, multiple chunks
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(pt)
            src = f.name
        enc = src + ".enc"
        dec = src + ".dec"
        try:
            progress_calls = []
            encrypt_file(src, enc, k, chunk_size=8192,
                         progress_callback=lambda done, tot: progress_calls.append((done, tot)))
            assert len(progress_calls) > 1, "Progress callback should fire multiple times"

            decrypt_file(enc, dec, k)

            with open(dec, "rb") as f:
                result = f.read()
            assert hashlib.sha256(result).digest() == hashlib.sha256(pt).digest()
        finally:
            for p in (src, enc, dec):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    _test("File encrypt → decrypt (multi-chunk, SHA-256 match)", test_file_roundtrip)

    def test_file_passphrase():
        pt = os.urandom(100_000)
        pw = "streaming passphrase test"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(pt)
            src = f.name
        enc = src + ".enc"
        dec = src + ".dec"
        try:
            encrypt_file_with_passphrase(src, enc, pw, chunk_size=16384)
            decrypt_file_with_passphrase(enc, dec, pw)
            with open(dec, "rb") as f:
                result = f.read()
            assert result == pt
        finally:
            for p in (src, enc, dec):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    _test("File encrypt/decrypt with passphrase", test_file_passphrase)

    # --- 5. RSA hybrid encryption ---
    print("\n-- RSA hybrid encryption --")

    def test_rsa_roundtrip():
        priv, pub = generate_rsa_keypair(key_size=2048)  # 2048 for speed in tests
        pt = b"RSA hybrid test payload"
        ct = encrypt_with_rsa(pt, pub)
        assert decrypt_with_rsa(ct, priv) == pt

    _test("RSA encrypt → decrypt round-trip", test_rsa_roundtrip)

    def test_rsa_wrong_key():
        priv1, pub1 = generate_rsa_keypair(key_size=2048)
        priv2, _ = generate_rsa_keypair(key_size=2048)
        ct = encrypt_with_rsa(b"secret", pub1)
        try:
            decrypt_with_rsa(ct, priv2)
            assert False
        except DecryptionError:
            pass

    _test("RSA wrong private key raises DecryptionError", test_rsa_wrong_key)

    def test_rsa_key_serialization():
        priv, pub = generate_rsa_keypair(key_size=2048)
        pub_pem = export_public_key(pub)
        priv_pem = export_private_key(priv, passphrase="test123")
        pub2 = import_public_key(pub_pem)
        priv2 = import_private_key(priv_pem, passphrase="test123")
        pt = b"serialize test"
        ct = encrypt_with_rsa(pt, pub2)
        assert decrypt_with_rsa(ct, priv2) == pt

    _test("RSA key PEM export/import round-trip", test_rsa_key_serialization)

    # --- 6. RSA file streaming ---
    print("\n-- RSA file streaming --")

    def test_rsa_file_roundtrip():
        priv, pub = generate_rsa_keypair(key_size=2048)
        pt = os.urandom(100_000)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(pt)
            src = f.name
        enc = src + ".enc"
        dec = src + ".dec"
        try:
            encrypt_file_with_rsa(src, enc, pub, chunk_size=16384)
            decrypt_file_with_rsa(enc, dec, priv)
            with open(dec, "rb") as f:
                result = f.read()
            assert result == pt
        finally:
            for p in (src, enc, dec):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    _test("RSA file encrypt → decrypt (streaming)", test_rsa_file_roundtrip)

    # --- 7. Format / header validation ---
    print("\n-- Format validation --")

    def test_bad_magic():
        try:
            decrypt(b"BADDATA!" + b"\x00" * 50, generate_key())
            assert False
        except FormatError:
            pass

    _test("Bad magic bytes raise FormatError", test_bad_magic)

    def test_invalid_key_length():
        try:
            encrypt(b"x", b"short")
            assert False
        except InvalidKeyError:
            pass

    _test("Short key raises InvalidKeyError", test_invalid_key_length)

    def test_empty_passphrase():
        try:
            encrypt_with_passphrase(b"x", "")
            assert False
        except InvalidKeyError:
            pass

    _test("Empty passphrase raises InvalidKeyError", test_empty_passphrase)

    # --- Summary ---
    print("\n" + "=" * 60)
    total = passed + failed
    print(f"Results: {passed}/{total} passed, {failed} failed")
    if failed:
        print("SOME TESTS FAILED!")
        sys.exit(1)
    else:
        print("ALL TESTS PASSED!")
    print("=" * 60)
