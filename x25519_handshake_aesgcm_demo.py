from cryptography.hazmat.primitives.asymmetric import x25519                      # For X25519 key exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF                          # For deriving symmetric key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305          # For high-speed authenticated encryption
import os
# --- 1. Key generation (Simulate Alice/Bob) ---
# Generate Alice's X25519 private and public keys
alice_private_key = x25519.X25519PrivateKey.generate()                            # Alice generates a random private key
alice_public_key = alice_private_key.public_key()                                 # Alice derives her public key
# Generate Bob's X25519 private and public keys
bob_private_key = x25519.X25519PrivateKey.generate()                              # Bob generates his private key
bob_public_key = bob_private_key.public_key()                                     # Bob derives his public key
# Public key bytes (for transmission/serialization)
alice_public_bytes = alice_public_key.public_bytes(encoding=None, format=None)    # 32 bytes, for sending over wire
bob_public_bytes = bob_public_key.public_bytes(encoding=None, format=None)

# --- 2. Handshake (Key Agreement) ---
# Alice calculates shared secret using her private key and Bob's public key
alice_shared_secret = alice_private_key.exchange(bob_public_key)                  # 32 bytes
# Bob calculates shared secret using his private key and Alice's public key
bob_shared_secret = bob_private_key.exchange(alice_public_key)                    # 32 bytes
# The shared secret must be identical on both sides
if alice_shared_secret != bob_shared_secret:
    raise RuntimeError("Shared secrets do not match (key agreement failed)!")
# --- 3. Symmetric key derivation via HKDF ---
# Both parties independently derive the same 32-byte symmetric key (ChaCha20Poly1305 requires 32 bytes)
hkdf_info = b'X25519+ChaCha20Poly1305 demo 2024'
hkdf_salt = None                                                                  # No salt for demo; in production, consider using a random salt!
hkdf_alice = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=hkdf_salt,
    info=hkdf_info
)
symmetric_key_alice = hkdf_alice.derive(alice_shared_secret)
hkdf_bob = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=hkdf_salt,
    info=hkdf_info
)
symmetric_key_bob = hkdf_bob.derive(bob_shared_secret)
# Ensure both symmetric keys are identical
assert symmetric_key_alice == symmetric_key_bob, "Symmetric keys do not match after HKDF!"
# --- 4. Encrypt a message using ChaCha20-Poly1305 (Alice -> Bob) ---
plaintext = b"Hello Bob, this is Alice."                                          # Message to encrypt
associated_data = b"protocol-v2 AD"                                               # Optional associated data (authenticated, not encrypted)
# ChaCha20Poly1305 uses a 12-byte nonce, which must be unique per-key!
nonce = os.urandom(12)
# Alice encrypts the message
chacha_aead_alice = ChaCha20Poly1305(symmetric_key_alice)
ciphertext = chacha_aead_alice.encrypt(nonce, plaintext, associated_data)
# ciphertext contains both encrypted message and the Poly1305 auth tag (appended)
# --- 5. Bob receives ciphertext, decrypts and verifies authenticity ---
chacha_aead_bob = ChaCha20Poly1305(symmetric_key_bob)
try:
    decrypted = chacha_aead_bob.decrypt(nonce, ciphertext, associated_data)       # Raises exception if tag invalid
    print("Decrypted:", decrypted.decode())
except Exception as e:
    print("Failed to decrypt or authenticate message:", e)
# --- 6. Replay attack demonstration (wrong nonce/tag or associated_data) ---
# (1) Tamper with associated data (auth will fail)
try:
    wrong_ad = b"wrong protocol-v2 AD"
    chacha_aead_bob.decrypt(nonce, ciphertext, wrong_ad)
except Exception as e:
    print("Tampered AD authentication failed as expected:", e)

# (2) Tamper with ciphertext (auth will fail)
try:
    bad_ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])    # Flip one byte
    chacha_aead_bob.decrypt(nonce, bad_ciphertext, associated_data)
except Exception as e:
    print("Tampered ciphertext authentication failed as expected:", e)
# (3) Attempt reuse of nonce (REPLAY) for a different message: this doesn't throw, but is insecure and should be forbidden in protocol!
plaintext2 = b"This is a different message."
ciphertext2 = chacha_aead_alice.encrypt(nonce, plaintext2, associated_data)        # Reusing nonce (BAD practice)
try:
    decrypted2 = chacha_aead_bob.decrypt(nonce, ciphertext2, associated_data)
    print("Decrypted (reused nonce, should not do in protocol!):", decrypted2.decode())
except Exception as e:
    print("Decryption failed (as expected):", e)
# --- 7. Proper unique nonce handling ---
# Always use a new, random nonce for each message per key!
nonce3 = os.urandom(12)
ciphertext3 = chacha_aead_alice.encrypt(nonce3, b"Secure greetings, Bob", associated_data)
decrypted3 = chacha_aead_bob.decrypt(nonce3, ciphertext3, associated_data)
print("Decrypted (correct AD and nonce):", decrypted3.decode())
