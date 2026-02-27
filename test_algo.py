import algo

# Test 1: Basic encryption
print("=== Test 1: Basic Encryption ===")
key = algo.generate_key()
ct = algo.encrypt(b"Hello Kryptos!", key)
pt = algo.decrypt(ct, key)
print(f"✓ Round-trip successful: {pt.decode()}\n")

# Test 2: Passphrase
print("=== Test 2: Passphrase Encryption ===")
ct = algo.encrypt_with_passphrase(b"Secret data", "my password")
pt = algo.decrypt_with_passphrase(ct, "my password")
print(f"✓ Passphrase decryption: {pt.decode()}\n")

# Test 3: File encryption
print("=== Test 3: File Encryption ===")
with open("demo.txt", "wb") as f:
    f.write(b"This is a demo file with confidential content!")

algo.encrypt_file("demo.txt", "demo.enc", key)
algo.decrypt_file("demo.enc", "demo_dec.txt", key)

with open("demo_dec.txt", "rb") as f:
    print(f"✓ File decrypted: {f.read().decode()}")