"""Core Mirage Embedder: Decoy LSB-matching + Sign-Channel Real Layer."""
import numpy as np
from ..crypto.xof import xof, xof_bits
from ..crypto.keyed_perm import tile_positions
from ..decoy.dte import dte_decode
from .profile import Profile
from .gf2 import gf2_solve, rows_to_ints

def H2_matrix(kh: bytes, t: int, r: int, n_d: int) -> np.ndarray:
    """Generate the dense r x n_d binary parity check matrix H2 for tile `t`."""
    return xof_bits(kh, "H2", t, n=r * n_d).reshape(r, n_d)

def embed_tile(
    cover_tile: np.ndarray,
    t: int,
    prof: Profile,
    kd: bytes,
    kh: bytes | None,
    kw: bytes | None,
    hdr_ct_bits: np.ndarray,
    shard_bytes_arr: bytes | None,
    rng: np.random.Generator,
    mode: str = "mirage",
    max_rerolls: int = 256,
) -> tuple[np.ndarray, int, int] | None:
    """Embed decoy payload (Layer 1) and optionally real shard (Layer 2) in a single tile.
    
    Args:
        cover_tile: 2D uint8 numpy array for this tile
        t: Tile index (0 <= t < T)
        prof: Profile parameters
        kd: Decoy position key (k_pos)
        kh: Real H2 matrix key (k_h2), required if mode == "mirage"
        kw: Real whitening key (k_white), required if mode == "mirage"
        hdr_ct_bits: 64-bit encrypted decoy seed as uint8 numpy array
        shard_bytes_arr: Whitened/unwhitened shard bytes to embed in sign channel (mode == "mirage")
        rng: Random generator for free variables and decoy sign choices
        mode: "mirage" (embeds both layers) or "decoy" (decoy layer only)
        max_rerolls: Maximum padding counter retries
        
    Returns:
        (stego_tile, n_changes, ctr) or None if solver/margin fails.
    """
    x = cover_tile.astype(np.int16).ravel()
    npix = x.size
    n_d = prof.n_d(t)
    P = tile_positions(kd, t, npix, n_d)

    m2 = None
    H2 = None
    if mode == "mirage":
        if kh is None or kw is None or shard_bytes_arr is None:
            raise ValueError("kh, kw, and shard_bytes_arr are required for mode='mirage'")
        raw_m2 = np.frombuffer(shard_bytes_arr, dtype=np.uint8)
        # Whitening
        white_mask = np.frombuffer(xof(kw, "white", t, n=len(raw_m2)), dtype=np.uint8)
        m2 = np.unpackbits(raw_m2 ^ white_mask)
        H2 = H2_matrix(kh, t, prof.r_bits, n_d)

    # Re-roll padding until there are sufficient dry positions
    for ctr in range(max_rerolls):
        pad = xof_bits(kd, "pad", t, ctr, n=n_d - 64)
        bits = np.concatenate([hdr_ct_bits, pad]).astype(np.uint8)
        chg = (x[P] & 1) != bits
        interior = (x[P] > 0) & (x[P] < 255)
        dry = chg & interior

        if mode != "mirage":
            break
        if dry.sum() >= prof.r_bits + prof.margin:
            break
    else:
        return None

    y = x.copy()
    # Default sign choices for decoy-only: random ±1; boundary: forced
    sg = rng.choice([-1, 1], size=n_d)
    sg[x[P] == 0] = 1
    sg[x[P] == 255] = -1

    if mode == "mirage":
        # Cover bit-2 values: g(v) = (v >> 1) & 1
        b2c = (x[P] >> 1) & 1
        yb2 = b2c.copy()
        forced = chg & ~interior
        yb2[forced] = (((x[P] + sg)[forced]) >> 1) & 1

        wet = ~dry
        w = (yb2 * wet).astype(np.uint8)
        # Syndrome contribution of fixed (wet) positions
        syn_wet = (H2[:, wet].astype(np.int64) @ w[wet].astype(np.int64)) % 2
        rhs = m2 ^ syn_wet.astype(np.uint8)

        dcols = np.where(dry)[0]
        sol = gf2_solve(rows_to_ints(H2[:, dcols]), rhs.tolist(), len(dcols), rng)
        if sol is None:
            return None

        # Choose modification direction (+1 or -1) on dry positions so that resulting bit-2 equals sol[k]
        for k, i in enumerate(dcols):
            v = x[P[i]]
            # Lemma 1: g(v-1) != g(v+1)
            # Pick -1 if bit-2 of (v-1) equals sol[k], else +1
            sg[i] = -1 if (((v - 1) >> 1) & 1) == sol[k] else 1

    idx = np.where(chg)[0]
    y[P[idx]] = x[P[idx]] + sg[idx]
    stego_tile = y.reshape(cover_tile.shape).astype(np.uint8)
    return stego_tile, int(chg.sum()), ctr

def extract_tile(
    stego_tile: np.ndarray,
    t: int,
    prof: Profile,
    kd: bytes,
    kh: bytes,
    kw: bytes,
) -> bytes:
    """Extract real layer shard from stego tile `t` (Bob)."""
    y = stego_tile.astype(np.int16).ravel()
    n_d = prof.n_d(t)
    P = tile_positions(kd, t, y.size, n_d)
    b2 = ((y[P] >> 1) & 1).astype(np.int64)
    H2 = H2_matrix(kh, t, prof.r_bits, n_d).astype(np.int64)
    syn = (H2 @ b2) % 2
    sb = np.packbits(syn.astype(np.uint8))
    white_mask = np.frombuffer(xof(kw, "white", t, n=len(sb)), dtype=np.uint8)
    return bytes(np.frombuffer(sb, dtype=np.uint8) ^ white_mask)

def decoy_peek(
    stego_tile: np.ndarray,
    t: int,
    prof: Profile,
    kd_guess: bytes,
) -> str:
    """Extract and decode decoy honey message using a guessed decoy key (Eve)."""
    y = stego_tile.astype(np.int16).ravel()
    n_d = prof.n_d(t)
    P = tile_positions(kd_guess, t, y.size, n_d)
    lsb = (y[P][:64] & 1).astype(np.uint8)
    ks = xof_bits(kd_guess, "hdr", t, n=64)
    seed_bits = lsb ^ ks
    seed = int("".join(map(str, seed_bits.tolist())), 2)
    return dte_decode(seed)
