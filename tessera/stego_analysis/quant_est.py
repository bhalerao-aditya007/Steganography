"""Quantitative change-rate and payload estimation for forensic analysis (E2 / E4)."""
import numpy as np

def estimate_change_rate(cover: np.ndarray, stego: np.ndarray) -> float:
    """Ground truth change rate beta = (# modified pixels) / N."""
    return float(np.mean(cover != stego))

def sample_pair_analysis_estimate(img: np.ndarray) -> float:
    """Dumitrescu-Wu-Wang Sample Pair Analysis (SPA) style change-rate estimator.
    
    Returns estimated relative payload alpha in [0, 1].
    """
    flat = img.ravel().astype(np.int32)
    # Consecutive horizontal pairs
    u = flat[:-1]
    v = flat[1:]
    
    # Trace pairs where (u, v) differ by 1 vs equal
    # Simplified finite-difference heuristic
    d = np.abs(u - v)
    p_zero = np.mean(d == 0)
    p_one = np.mean(d == 1)
    
    if p_one == 0:
        return 0.0
    est = max(0.0, min(1.0, float((p_one - p_zero) / (p_one + p_zero + 1e-6))))
    return est
