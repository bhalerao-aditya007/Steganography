"""Naive Multi-Secret Steganography Embedder (Baseline B4 - Ogiela & Koptyra style).

Embeds decoy layer in LSB (bit 0) and second layer directly in 2nd LSB (bit 1).
Demonstrates the failure of prior art: altering bit 1 independently forces ±2 modifications
or alters unchanged pixels, completely destroying evidence conservation.
"""
import numpy as np
from ..crypto.xof import xof_bits
from ..crypto.keyed_perm import tile_positions
from .profile import Profile

def embed_naive_second_lsb(
    cover_tile: np.ndarray,
    t: int,
    prof: Profile,
    kd: bytes,
    kh: bytes,
    hdr_ct_bits: np.ndarray,
    shard_bytes: bytes,
    rng: np.random.Generator,
) -> tuple[np.ndarray, int]:
    """Embeds decoy in bit 0, and second secret in bit 1 directly."""
    x = cover_tile.astype(np.int16).ravel()
    npix = x.size
    n_d = prof.n_d(t)
    P = tile_positions(kd, t, npix, n_d)

    # 1. Embed decoy in bit 0
    pad = xof_bits(kd, "pad", t, 0, n=n_d - 64)
    b1 = np.concatenate([hdr_ct_bits, pad]).astype(np.uint8)
    
    y = x.copy()
    chg1 = (y[P] & 1) != b1
    idx1 = np.where(chg1)[0]
    for i in idx1:
        if y[P[i]] == 0:
            y[P[i]] += 1
        elif y[P[i]] == 255:
            y[P[i]] -= 1
        else:
            y[P[i]] += rng.choice([-1, 1])

    # 2. Embed second secret in bit 1 (2nd LSB)
    # Shard bits
    m2 = np.unpackbits(np.frombuffer(shard_bytes, dtype=np.uint8))[:prof.r_bits]
    # Pick subset of positions for second secret
    P2 = P[:prof.r_bits]
    current_b2 = (y[P2] >> 1) & 1
    chg2 = current_b2 != m2
    idx2 = np.where(chg2)[0]

    # Flipping bit 1 without altering bit 0 requires ±2 changes!
    for i in idx2:
        val = y[P2[i]]
        if val <= 1:
            y[P2[i]] += 2
        elif val >= 254:
            y[P2[i]] -= 2
        else:
            # Flip bit 1
            if (val >> 1) & 1 == 0:
                y[P2[i]] = val + 2 if val + 2 <= 255 else val - 2
            else:
                y[P2[i]] = val - 2 if val - 2 >= 0 else val + 2

    diff = y - x
    n_changes = int((diff != 0).sum())
    stego_tile = y.reshape(cover_tile.shape).astype(np.uint8)
    return stego_tile, n_changes
