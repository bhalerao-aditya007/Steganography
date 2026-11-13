"""Statistical tests: Wilson confidence intervals, TOST equivalence test, and capacity price accounting."""
import math
from scipy.stats import norm

def wilson_score_interval(successes: int, trials: int, confidence: float = 0.95) -> tuple[float, float, float]:
    """Calculate Wilson score confidence interval for a binomial proportion.
    
    Returns:
        (center, lower_bound, upper_bound)
    """
    if trials == 0:
        return 0.0, 0.0, 0.0
    p = successes / trials
    z = norm.ppf(1.0 - (1.0 - confidence) / 2.0)
    z2 = z * z
    denom = 1.0 + z2 / trials
    center = (p + z2 / (2.0 * trials)) / denom
    margin = (z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * trials)) / trials)) / denom
    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)
    return p, lower, upper

def tost_equivalence_test(auc: float, se_auc: float, target: float = 0.50, delta: float = 0.02, alpha: float = 0.05) -> dict:
    """Two One-Sided Tests (TOST) for statistical equivalence of AUC to target 0.50.
    
    Tests H01: AUC <= target - delta, vs H11: AUC > target - delta
    and   H02: AUC >= target + delta, vs H12: AUC < target + delta
    
    If both null hypotheses are rejected (p < alpha), we conclude AUC is within [target - delta, target + delta].
    """
    if se_auc <= 0:
        se_auc = 0.005  # lower floor
    z1 = (auc - (target - delta)) / se_auc
    z2 = ((target + delta) - auc) / se_auc
    
    p1 = 1.0 - norm.cdf(z1)
    p2 = 1.0 - norm.cdf(z2)
    p_tost = max(p1, p2)
    equivalent = bool(p_tost < alpha)
    
    return {
        "auc": auc,
        "target": target,
        "delta": delta,
        "p_tost": float(p_tost),
        "is_equivalent": equivalent,
        "conclusion": "Indistinguishable from random guessing (AUC ~ 0.50)" if equivalent else "Significant difference detected"
    }

def capacity_price_factor(decoy_coder: str = "lsbm") -> dict:
    """Compute capacity price of deniability (Section 5.8).
    
    At equal number of changes c:
      Single-layer SOTA carries e * c useful bits
      Mirage carries rho_r * c useful bits (decoy bits are bait)
      Capacity price factor = e / rho_r
    """
    rho_r = 0.6
    if decoy_coder == "lsbm":
        e = 2.0  # bits per change for LSB matching
    else:
        e = 5.0  # bits per change for STC at low rate
    factor = e / rho_r
    return {
        "decoy_coder": decoy_coder,
        "bits_per_change_single_layer": e,
        "real_bits_per_change_mirage": rho_r,
        "price_factor": factor,
        "explanation": f"Mirage trades {factor:.1f}x capacity for detection-conditional plausible deniability with zero extra evidence."
    }
