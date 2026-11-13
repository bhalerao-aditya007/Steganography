"""Single-layer Keyed LSB-Matching (LSBM) Embedder (Baseline B1)."""
import numpy as np
from ..crypto.keyed_perm import tile_positions

def embed_lsbm(
    cover: np.ndarray,
    kd: bytes,
    bits: np.ndarray,
    rng: np.random.Generator,
) -> tuple[np.ndarray, int]:
    """Embed bit sequence into cover using standard keyed LSB matching.
    
    If LSB(x) != bit, randomly modifies x by +1 or -1 (forced at boundaries 0 and 255).
    """
    x = cover.astype(np.int16).ravel()
    npix = x.size
    n_bits = len(bits)
    P = tile_positions(kd, 0, npix, n_bits)
    
    chg = (x[P] & 1) != bits
    idx = np.where(chg)[0]
    
    sg = rng.choice([-1, 1], size=len(idx))
    for k, i in enumerate(idx):
        val = x[P[i]]
        if val == 0:
            sg[k] = 1
        elif val == 255:
            sg[k] = -1
            
    y = x.copy()
    y[P[idx]] += sg
    return y.reshape(cover.shape).astype(np.uint8), int(chg.sum())

def extract_lsbm(
    stego: np.ndarray,
    kd: bytes,
    n_bits: int,
) -> np.ndarray:
    """Extract LSB bits from keyed positions."""
    y = stego.ravel()
    P = tile_positions(kd, 0, y.size, n_bits)
    return (y[P] & 1).astype(np.uint8)
