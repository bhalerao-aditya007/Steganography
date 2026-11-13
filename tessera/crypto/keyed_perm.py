import numpy as np
from .xof import xof

def tile_positions(kd: bytes, t: int, npix: int, n_d: int) -> np.ndarray:
    """Generate deterministic pseudorandom selection of pixel positions within tile `t`.
    
    Args:
        kd: Decoy position key (k_pos)
        t: Tile index
        npix: Total pixels in tile
        n_d: Number of embedding positions to select
        
    Returns:
        1D numpy array of `n_d` unique pixel indices in [0, npix).
    """
    keys = np.frombuffer(xof(kd, "perm", t, n=4 * npix), dtype=np.uint32)
    return np.argsort(keys, kind="stable")[:n_d]
