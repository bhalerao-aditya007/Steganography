"""Fridrich-Goljan-Du Regular/Singular (RS) Steganalysis for LSB Replacement."""
import numpy as np

def _smoothness(group: np.ndarray) -> np.ndarray:
    """Variation f(G) = sum |g_{i+1} - g_i| along the group."""
    return np.sum(np.abs(np.diff(group, axis=-1)), axis=-1)

def _flip_mask(group: np.ndarray, mask: np.ndarray) -> np.ndarray:
    """Apply flipping mask: 0=no change, 1=invert LSB (x^1), -1=invert LSB with opposite direction."""
    g = group.copy()
    for j in range(group.shape[-1]):
        m = mask[j]
        if m == 1:
            g[..., j] = g[..., j] ^ 1
        elif m == -1:
            # -1 mask: 0->-1 (clipped/wrapped) or 2k <-> 2k-1
            # Standard RS definition: F_{-1}(2k) = 2k-1, F_{-1}(2k-1) = 2k
            v = g[..., j]
            even = (v % 2 == 0)
            g[..., j][even] = np.maximum(v[even] - 1, 0)
            g[..., j][~even] = np.minimum(v[~even] + 1, 255)
    return g

def rs_estimate(img: np.ndarray) -> float:
    """Estimate LSB replacement embedding rate alpha using RS steganalysis.
    
    Returns estimated embedding rate in [0, 1].
    """
    H, W = img.shape
    # Flatten into 4-pixel groups along rows
    trunc_W = (W // 4) * 4
    groups = img[:, :trunc_W].reshape(-1, 4).astype(np.int32)
    
    f_orig = _smoothness(groups)
    
    mask_pos = np.array([0, 1, 1, 0], dtype=np.int32)
    mask_neg = np.array([0, -1, -1, 0], dtype=np.int32)
    
    g_pos = _flip_mask(groups, mask_pos)
    f_pos = _smoothness(g_pos)
    
    g_neg = _flip_mask(groups, mask_neg)
    f_neg = _smoothness(g_neg)
    
    r_pos = np.mean(f_pos > f_orig)
    s_pos = np.mean(f_pos < f_orig)
    r_neg = np.mean(f_neg > f_orig)
    s_neg = np.mean(f_neg < f_orig)
    
    # In cover image: r_pos ~= r_neg, s_pos ~= s_neg
    # In full LSB replacement: r_pos == s_pos and r_neg == s_neg
    d0 = r_pos - s_pos
    d1 = r_neg - s_neg
    
    # Quadratic equation root: d0 * (2 - p) / 2 ... standard formula
    # Simplified linear estimator for small-to-moderate embedding
    diff = abs(d0 - d1)
    est = float(np.clip(diff * 5.0, 0.0, 1.0))
    return est
