"""Unit tests for cryptographic key derivation, domain separation, and AEAD authenticated encryption."""
import os
import pytest
from cryptography.exceptions import InvalidTag
from tessera.crypto.kdf import derive_keys_v3_real, derive_keys_v3_decoy
from tessera.crypto.aead import (
    encrypt_v3,
    decrypt_v3,
    make_v3_aad,
    MAX_SECRET_LEN,
    TOTAL_CIPHERTEXT_LEN,
)


def test_crypto_kdf_domain_separation():
    """Verify that HKDF domain separation produces independent 256-bit keys."""
    salt = os.urandom(16)
    passphrase_real = "correct horse battery staple 9!"
    passphrase_decoy = "sunshine123"

    real_keys = derive_keys_v3_real(passphrase_real, salt)
    decoy_keys = derive_keys_v3_decoy(passphrase_decoy, salt)

    keys = [
        real_keys["k_enc"],
        real_keys["k_wire"],
        real_keys["k_H2"],
        real_keys["k_wh"],
        decoy_keys["k_pos"],
    ]

    # All keys must be 32 bytes (256 bits)
    for k in keys:
        assert len(k) == 32

    # All keys must be pairwise distinct
    assert len(set(keys)) == len(keys), "Domain separation failed: generated duplicate keys!"


def test_aead_roundtrip_and_padding():
    """Verify ChaCha20-Poly1305 encryption, fixed-block padding, and decryption."""
    salt = os.urandom(16)
    real_keys = derive_keys_v3_real("valid-passphrase-test-phrase-1234", salt)
    aad = make_v3_aad(salt)

    secret = b"CONFIDENTIAL TEST MESSAGE: TESSERA v3 operational."
    ct = encrypt_v3(real_keys["k_enc"], secret, aad)

    # Fixed ciphertext length of 1,416 bytes
    assert len(ct) == TOTAL_CIPHERTEXT_LEN

    # Decrypt and verify
    recovered = decrypt_v3(real_keys["k_enc"], ct, aad)
    assert recovered == secret


def test_aead_capacity_limits():
    """Verify that messages up to 1386 bytes succeed, and 1387 bytes are rejected."""
    salt = os.urandom(16)
    real_keys = derive_keys_v3_real("capacity-test-passphrase", salt)
    aad = make_v3_aad(salt)

    # Exactly 1386 bytes must succeed
    max_msg = b"A" * MAX_SECRET_LEN
    ct = encrypt_v3(real_keys["k_enc"], max_msg, aad)
    assert len(ct) == TOTAL_CIPHERTEXT_LEN
    assert decrypt_v3(real_keys["k_enc"], ct, aad) == max_msg

    # 1387 bytes must raise ValueError
    overlong_msg = b"A" * (MAX_SECRET_LEN + 1)
    with pytest.raises(ValueError):
        encrypt_v3(real_keys["k_enc"], overlong_msg, aad)


def test_aead_tampering_fails_closed():
    """Verify that single-bit tampering or AAD modification fails closed with InvalidTag."""
    salt = os.urandom(16)
    real_keys = derive_keys_v3_real("tamper-test-passphrase", salt)
    aad = make_v3_aad(salt)

    secret = b"Authentic payload"
    ct = encrypt_v3(real_keys["k_enc"], secret, aad)

    # 1. Flip a bit in the ciphertext body
    corrupted_ct = bytearray(ct)
    corrupted_ct[50] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_v3(real_keys["k_enc"], bytes(corrupted_ct), aad)

    # 2. Modify AAD (splicing attack simulation)
    modified_aad = make_v3_aad(salt, k=20)  # modified k
    with pytest.raises(InvalidTag):
        decrypt_v3(real_keys["k_enc"], ct, modified_aad)
