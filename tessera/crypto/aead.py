"""Authenticated Encryption with Associated Data (AEAD) using ChaCha20-Poly1305.
Includes random-nonce encapsulation, fixed-block uniform padding, and session-parameter AAD binding.
"""
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

NONCE_LEN = 12
TAG_LEN = 16
LEN_PREFIX_LEN = 2
TOTAL_CIPHERTEXT_LEN = 1416  # K=24 * P=59
MAX_SECRET_LEN = TOTAL_CIPHERTEXT_LEN - NONCE_LEN - TAG_LEN - LEN_PREFIX_LEN  # 1386 Bytes


def make_v3_aad(
    salt: bytes,
    n: int = 32,
    k: int = 24,
    shard_len: int = 64,
    ct_len: int = TOTAL_CIPHERTEXT_LEN,
    width: int = 512,
    height: int = 512,
) -> bytes:
    """Bind protocol parameters and salt to AEAD ciphertext to prevent splicing attacks."""
    return b"tessera/v3" + struct.pack("!BBBBHH16s", n, k, shard_len, ct_len % 256, width, height, salt)


def encrypt_v3(key: bytes, secret: bytes, aad: bytes) -> bytes:
    """Encrypt secret into fixed 1,416-byte ciphertext using ChaCha20-Poly1305.
    
    Format: nonce(12B) || ciphertext(1388B) || Poly1305_tag(16B) = 1416B.
    Plaintext is padded with cryptographic random bytes to completely conceal length.
    """
    if len(secret) > MAX_SECRET_LEN:
        raise ValueError(f"Secret message length ({len(secret)} B) exceeds capacity ({MAX_SECRET_LEN} B)")

    nonce = os.urandom(NONCE_LEN)
    pad_len = MAX_SECRET_LEN - len(secret)
    random_pad = os.urandom(pad_len)
    padded_pt = struct.pack("!H", len(secret)) + secret + random_pad

    chacha = ChaCha20Poly1305(key)
    ct_and_tag = chacha.encrypt(nonce, padded_pt, aad)
    return nonce + ct_and_tag


def decrypt_v3(key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt and verify ciphertext.
    
    Raises InvalidTag if authentication tag fails or tampering is detected.
    Fails closed: never emits plaintext on tag mismatch.
    """
    if len(ciphertext) != TOTAL_CIPHERTEXT_LEN:
        raise ValueError(f"Ciphertext length must be exactly {TOTAL_CIPHERTEXT_LEN} B (got {len(ciphertext)} B)")

    nonce = ciphertext[:NONCE_LEN]
    ct_and_tag = ciphertext[NONCE_LEN:]

    chacha = ChaCha20Poly1305(key)
    # Will raise InvalidTag if tag does not verify
    padded_pt = chacha.decrypt(nonce, ct_and_tag, aad)

    sec_len = struct.unpack("!H", padded_pt[:LEN_PREFIX_LEN])[0]
    if sec_len > MAX_SECRET_LEN:
        raise ValueError("Decrypted length prefix exceeds valid capacity")

    return padded_pt[LEN_PREFIX_LEN:LEN_PREFIX_LEN + sec_len]


# Backwards compatibility wrappers for v2 modules
def encrypt_aead(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"tessera-v2") -> bytes:
    """Legacy v2 ChaCha20-Poly1305 encrypt."""
    chacha = ChaCha20Poly1305(key)
    return chacha.encrypt(nonce, plaintext, aad)


def decrypt_aead(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"tessera-v2") -> bytes:
    """Legacy v2 ChaCha20-Poly1305 decrypt."""
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, aad)
