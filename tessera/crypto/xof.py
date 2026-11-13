import hashlib
import numpy as np

def xof(key: bytes, *parts, n: int) -> bytes:
    """SHAKE-256 eXtendable Output Function / PRF keyed with `key` and domain parts."""
    h = hashlib.shake_256(key)
    for p in parts:
        h.update(b"|" + (p if isinstance(p, bytes) else str(p).encode("utf-8")))
    return h.digest(n)

def xof_bits(key: bytes, *parts, n: int) -> np.ndarray:
    """Generate `n` pseudorandom bits as a uint8 numpy array using SHAKE-256."""
    byte_count = (n + 7) // 8
    buf = xof(key, *parts, n=byte_count)
    arr = np.frombuffer(buf, dtype=np.uint8)
    return np.unpackbits(arr)[:n]
