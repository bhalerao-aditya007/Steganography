import os
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def master(passphrase: str, salt: bytes, light: bool = False) -> bytes:
    """Derive master key from passphrase and salt using Argon2id.
    
    Args:
        passphrase: User passphrase
        salt: 16-byte random salt
        light: If True, uses lighter cost (t=1, m=8MB) for decoy layer (dictionary crackable).
               If False, uses reference cost (t=2, m=19MB) for real layer.
    """
    if light:
        return hash_secret_raw(
            passphrase.encode("utf-8"),
            salt,
            time_cost=1,
            memory_cost=8192,
            parallelism=1,
            hash_len=32,
            type=Type.ID,
        )
    return hash_secret_raw(
        passphrase.encode("utf-8"),
        salt,
        time_cost=2,
        memory_cost=19456,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )

def hkdf(m: bytes, label: bytes, n: int = 32) -> bytes:
    """HKDF-SHA256 key expansion with context label."""
    return HKDF(hashes.SHA256(), n, None, label).derive(m)
