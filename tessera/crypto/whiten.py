import numpy as np
from .xof import xof

def whiten_bytes(kw: bytes, t: int, data: bytes) -> bytes:
    """XOR data with a per-tile PRF keystream to ensure uniform distribution of shard bits.
    
    Whitening is mandatory to ensure structured RS parity bytes and CRCs do not create
    statistical bias in the sign channel.
    """
    keystream = xof(kw, "white", t, n=len(data))
    d_arr = np.frombuffer(data, dtype=np.uint8)
    k_arr = np.frombuffer(keystream, dtype=np.uint8)
    return bytes(d_arr ^ k_arr)

def unwhiten_bytes(kw: bytes, t: int, whitened_data: bytes) -> bytes:
    """Invert whitening (XOR with identical per-tile keystream)."""
    return whiten_bytes(kw, t, whitened_data)
