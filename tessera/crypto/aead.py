from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def encrypt_aead(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"tessera-v2") -> bytes:
    """Authenticated encryption with ChaCha20-Poly1305 (16-byte Poly1305 tag appended)."""
    chacha = ChaCha20Poly1305(key)
    return chacha.encrypt(nonce, plaintext, aad)

def decrypt_aead(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"tessera-v2") -> bytes:
    """Decrypt and verify ciphertext with ChaCha20-Poly1305. Raises InvalidTag on mismatch."""
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, aad)
