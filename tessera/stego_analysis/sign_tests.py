"""Tailored sign-channel statistical tests for existence-hiding evaluation (E3 / E4)."""
import numpy as np
from scipy.stats import chi2_contingency

def sign_statistics(cover: np.ndarray, stego: np.ndarray) -> dict:
    """Compute directional sign statistics between cover and stego images.
    
    Returns:
        Dictionary with:
          - n_changes: Total number of changed pixels
          - frac_pos: Fraction of changes that are +1 (should be ~0.500)
          - frac_abs1: Fraction of changes with |d| == 1 (should be 1.000 for Mirage, < 1.0 for B4)
          - n_abs2: Number of changes with |d| >= 2 (should be 0 for Mirage, > 0 for B4)
          - chi2_p_val: Chi-square p-value testing independence between sign and (cover mod 4)
    """
    c = cover.astype(np.int32).ravel()
    s = stego.astype(np.int32).ravel()
    diff = s - c
    chg_mask = (diff != 0)
    
    n_changes = int(chg_mask.sum())
    if n_changes == 0:
        return {
            "n_changes": 0,
            "frac_pos": 0.5,
            "frac_abs1": 1.0,
            "n_abs2": 0,
            "chi2_p_val": 1.0,
        }
        
    d_vals = diff[chg_mask]
    c_vals = c[chg_mask]
    
    frac_pos = float((d_vals > 0).mean())
    frac_abs1 = float((np.abs(d_vals) == 1).mean())
    n_abs2 = int((np.abs(d_vals) >= 2).sum())
    
    # 2x4 contingency table: rows = (sign > 0, sign < 0), cols = (c % 4 in {0, 1, 2, 3})
    # Filter interior pixels (0 < c < 255) where sign choice was free
    interior_mask = (c_vals > 0) & (c_vals < 255)
    if interior_mask.sum() > 20:
        d_int = d_vals[interior_mask]
        c_int = c_vals[interior_mask]
        tab = np.zeros((2, 4), dtype=np.float64)
        for d, v in zip(d_int, c_int):
            row = 0 if d > 0 else 1
            col = v % 4
            tab[row, col] += 1
        chi2_res = chi2_contingency(tab + 1e-9)
        p_val = float(chi2_res.pvalue)
    else:
        p_val = 1.0
        
    return {
        "n_changes": n_changes,
        "frac_pos": frac_pos,
        "frac_abs1": frac_abs1,
        "n_abs2": n_abs2,
        "chi2_p_val": p_val,
    }

def sign_runs_test(signs: np.ndarray) -> float:
    """Wald-Wolfowitz runs test for sign sequence randomness.
    
    Args:
        signs: 1D array of signs in {-1, +1}.
        
    Returns:
        p-value (values > 0.05 indicate consistent with true randomness).
    """
    if len(signs) < 10:
        return 1.0
    n1 = np.sum(signs > 0)
    n2 = np.sum(signs < 0)
    if n1 == 0 or n2 == 0:
        return 0.0
        
    runs = 1 + np.sum(signs[1:] != signs[:-1])
    n = n1 + n2
    mu = (2 * n1 * n2) / n + 1
    var = (2 * n1 * n2 * (2 * n1 * n2 - n)) / (n * n * (n - 1))
    
    if var <= 0:
        return 1.0
    z = (runs - mu) / np.sqrt(var)
    # Two-sided normal p-value
    from scipy.stats import norm
    return float(2 * (1 - norm.cdf(abs(z))))
