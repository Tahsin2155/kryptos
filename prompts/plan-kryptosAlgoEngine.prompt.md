# Plan: Kryptos AES-256-GCM + RSA Encryption Engine

**TL;DR:** Implement a class-based `KryptosEngine` in algo.py using Python's `cryptography` library. The engine provides AES-256-GCM authenticated encryption with chunked streaming for large files, PBKDF2 key derivation from passphrases, RSA-OAEP key wrapping, and a cross-platform binary file format with magic header. Every operation is non-deterministic (random IV/nonce), authenticated (GCM tag), and interoperable with the Web Crypto API.

## Steps

### 1. Define the binary file format as constants in algo.py
- Magic bytes: `b"KRYPTOS\x00"` (8 bytes)
- Format version: `uint8` = `1` (1 byte)
- Algorithm ID: `uint8` — `1` = AES-256-GCM (1 byte)
- KDF flag: `uint8` — `0` = raw key, `1` = PBKDF2, `2` = RSA-wrapped key (1 byte)
- Reserved: 5 bytes (future extensibility, zeroed)
- **Fixed header: 16 bytes total**
- Followed by: Salt (16 bytes, if PBKDF2) or RSA-wrapped key blob (if RSA) or nothing (if raw key)
- Then: IV/Nonce (12 bytes) → Ciphertext (variable) → GCM Auth Tag (16 bytes)
- The header is bound as **AAD (Additional Authenticated Data)** so it cannot be tampered with

### 2. Implement `KryptosEngine` class with these core methods
- `generate_key() → bytes` — Generate a 256-bit key via `os.urandom(32)`
- `key_to_base64(key) → str` / `key_from_base64(b64) → bytes` — Key export/import
- `key_to_hex(key) → str` / `key_from_hex(h) → bytes` — Key export/import (hex)
- `derive_key(passphrase: str, salt: bytes = None) → tuple[bytes, bytes]` — PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt, returns `(key, salt)`

### 3. Implement AES-256-GCM encryption (core)
- `encrypt(plaintext: bytes, key: bytes) → bytes` — In-memory encrypt: generates 12-byte random nonce, encrypts with AES-256-GCM, returns full formatted output (header + nonce + ciphertext + tag)
- `decrypt(data: bytes, key: bytes) → bytes` — In-memory decrypt: parses header, validates magic/version, extracts nonce and tag, decrypts and authenticates
- `encrypt_with_passphrase(plaintext: bytes, passphrase: str) → bytes` — Derives key via PBKDF2, encrypts, includes salt in output
- `decrypt_with_passphrase(data: bytes, passphrase: str) → bytes` — Extracts salt from output, derives key, decrypts

### 4. Implement chunked streaming encryption for large files
- `encrypt_file(input_path: str, output_path: str, key: bytes, chunk_size: int = 64*1024, progress_callback: Callable = None)` — Reads input in chunks, writes encrypted output with header; uses AES-GCM (since GCM doesn't natively support streaming, implement a chunked approach: each chunk gets its own nonce derived from a base nonce + chunk counter, each chunk is independently authenticated, and a final sentinel chunk marks end-of-stream to prevent truncation attacks)
- `decrypt_file(input_path: str, output_path: str, key: bytes, chunk_size: int = 64*1024, progress_callback: Callable = None)` — Reverses the streaming process
- `encrypt_file_with_passphrase(...)` / `decrypt_file_with_passphrase(...)` — Passphrase variants
- Progress callback signature: `callback(bytes_processed: int, total_bytes: int)`

### 5. Implement RSA key wrapping
- `generate_rsa_keypair(key_size: int = 4096) → tuple[RSAPrivateKey, RSAPublicKey]` — Generate RSA keypair
- `export_public_key(pub_key) → bytes` (PEM) / `import_public_key(pem) → RSAPublicKey`
- `export_private_key(priv_key, passphrase: str = None) → bytes` (PEM, optionally encrypted) / `import_private_key(pem, passphrase: str = None) → RSAPrivateKey`
- `encrypt_with_rsa(plaintext: bytes, public_key: RSAPublicKey) → bytes` — Generates random AES key, wraps it with RSA-OAEP (SHA-256 + MGF1-SHA-256), encrypts plaintext with AES-GCM, outputs: header (KDF flag=2) + RSA-wrapped key blob (512 bytes for 4096-bit RSA) + nonce + ciphertext + tag
- `decrypt_with_rsa(data: bytes, private_key: RSAPrivateKey) → bytes` — Unwraps AES key from RSA blob, decrypts ciphertext

### 6. Implement robust error handling with custom exceptions
- `KryptosError` (base) → `DecryptionError` (wrong key / corrupt data), `InvalidKeyError` (bad key format/length), `FormatError` (malformed file header), `IntegrityError` (authentication tag mismatch)
- All exceptions carry user-safe messages, never expose internal crypto state
- Wrap `cryptography.exceptions.InvalidTag` into `DecryptionError("Authentication failed: wrong key or corrupted data")`

### 7. Add validation helpers
- `_validate_key(key)` — Assert 32 bytes exactly
- `_validate_header(data)` — Check magic bytes, supported version, valid algorithm ID
- `_validate_passphrase(passphrase)` — Non-empty string check

### 8. Add module-level convenience functions (thin wrappers around the class)
- `encrypt(data, key)`, `decrypt(data, key)`, `generate_key()`, etc. — For quick usage without instantiating the class

## Verification
Write inline test vectors at the bottom of `algo.py` (guarded by `if __name__ == "__main__"`) that:
- Generate a key, encrypt "Hello Kryptos", decrypt, assert match
- Encrypt with passphrase, decrypt with passphrase, assert match
- Encrypt with wrong key → assert `DecryptionError` raised
- Tamper with ciphertext → assert `DecryptionError` raised
- RSA: generate keypair, encrypt with public key, decrypt with private key, assert match
- File streaming: create a temp file, encrypt/decrypt it, compare SHA-256 hashes
- Verify non-determinism: encrypt same plaintext twice, assert ciphertexts differ

## Decisions

- **AES-GCM only** (no CBC+HMAC): GCM is the most secure authenticated mode, simpler implementation, and natively compatible with Web Crypto API
- **Class-based `KryptosEngine`**: Best extensibility for future modes, clean separation of concerns, easy to integrate into both Qt GUI and web backend
- **Chunked streaming with per-chunk authentication**: Since GCM has a ~64GB limit per nonce and doesn't support native streaming, each chunk is encrypted independently with a derived nonce (base_nonce XOR chunk_index), preventing truncation and reordering attacks
- **4096-bit RSA**: Maximum practical security for key wrapping
- **PBKDF2 at 600,000 iterations**: Matches OWASP 2023 recommendation for SHA-256
- **`cryptography` library**: Explicitly recommended in Local PRD, best Web Crypto API compatibility
- **Header as AAD**: Prevents format metadata tampering without detection
