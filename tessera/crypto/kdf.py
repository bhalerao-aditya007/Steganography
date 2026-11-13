"""Cryptographic Key Derivation Function (KDF) using Argon2id and HKDF-SHA256.
Enforces strict domain separation across all operational cryptographic keys.
"""
import os
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def master_real_v3(passphrase: str, salt: bytes) -> bytes:
    """RFC 9106 recommended Argon2id derivation for the real layer secret:
    m = 64 MiB (65536 KiB), t = 3 iterations, p = 1 lane, 64-byte master key.
    """
    return hash_secret_raw(
        passphrase.encode("utf-8"),
        salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=64,
        type=Type.ID,
    )


def master_decoy_v3(passphrase: str, salt: bytes) -> bytes:
    """Intentionally lightweight Argon2id derivation for the decoy layer:
    m = 8 MiB (8192 KiB), t = 1 iteration, p = 1 lane, 32-byte master key.
    Deliberately permits fast offline dictionary cracking for plausible deniability.
    """
    return hash_secret_raw(
        passphrase.encode("utf-8"),
        salt,
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )


def hkdf_derive(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 domain expansion with explicit context label."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(master_key)


def derive_keys_v3_real(passphrase: str, salt: bytes) -> dict[str, bytes]:
    """Derive all real-layer cryptographic keys with domain separation."""
    m_real = master_real_v3(passphrase, salt)
    return {
        "master": m_real,
        "k_enc": hkdf_derive(m_real, b"tessera/v3/enc", 32),
        "k_wire": hkdf_derive(m_real, b"tessera/v3/wire", 32),
        "k_H2": hkdf_derive(m_real, b"tessera/v3/H2", 32),
        "k_wh": hkdf_derive(m_real, b"tessera/v3/wh", 32),
    }


def derive_keys_v3_decoy(passphrase: str, salt: bytes) -> dict[str, bytes]:
    """Derive decoy-layer keys with domain separation."""
    m_decoy = master_decoy_v3(passphrase, salt)
    return {
        "master": m_decoy,
        "k_pos": hkdf_derive(m_decoy, b"tessera/v3/pos", 32),
    }


# Backwards compatibility helpers for v2 modules
def master(passphrase: str, salt: bytes, light: bool = False) -> bytes:
    """Derive master key for legacy tests and v2 modules."""
    if light:
        return master_decoy_v3(passphrase, salt)
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
    """Legacy HKDF wrapper."""
    return hkdf_derive(m, label, n)
