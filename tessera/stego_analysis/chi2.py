"""Westfeld-Pfitzmann Chi-Square steganalysis test on Pairs of Values (PoVs)."""
import numpy as np
from scipy.stats import chi2

def chi2_attack(img: np.ndarray, num_steps: int = 10) -> tuple[float, list[float], list[float]]:
    """Compute Westfeld-Pfitzmann Chi-Square test on image prefixes.
    
    Sequential LSB replacement equalizes adjacent pairs of values (2k, 2k+1).
    Returns:
        (final_p_val, fractions, p_values_curve)
    """
    flat = img.ravel()
    n_pixels = flat.size
    fractions = np.linspace(0.1, 1.0, num_steps)
    p_values = []
    
    for frac in fractions:
        sample_size = int(frac * n_pixels)
        sample = flat[:sample_size]
        
        # Compute histogram of 256 bins
        hist = np.bincount(sample, minlength=256)[:256]
        
        # Pairs of Values: (2k, 2k+1) for k = 0..127
        h_even = hist[0::2]
        h_odd = hist[1::2]
        h_avg = (h_even + h_odd) / 2.0
        
        mask = h_avg > 5  # Filter out very sparse pairs for statistical validity
        if mask.sum() < 2:
            p_values.append(0.5)
            continue
            
        chi_sq_stat = np.sum(((h_even[mask] - h_avg[mask]) ** 2) / h_avg[mask])
        dof = mask.sum() - 1
        
        # p-value: probability of observing this or larger deviation under cover hypothesis
        # When sequential LSB replacement is present, h_even ~= h_odd -> chi_sq_stat is near 0 -> p-value near 1.0
        # In steganography convention: P(embedded) = 1.0 - p_val
        p_val = float(1.0 - chi2.cdf(chi_sq_stat, dof))
        p_values.append(p_val)
        
    return p_values[-1], list(fractions), p_values
