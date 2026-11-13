"""Difference maps and change-set equivalence analysis."""
import numpy as np

def compute_diff_map(img1: np.ndarray, img2: np.ndarray, amplify: int = 255) -> np.ndarray:
    """Compute visual difference map between two images, amplified for visibility.
    
    Unchanged pixels -> 0 (black).
    Modified pixels -> amplify (white/bright).
    """
    diff = np.abs(img1.astype(np.int32) - img2.astype(np.int32))
    diff_amplified = np.clip(diff * amplify, 0, 255).astype(np.uint8)
    return diff_amplified

def three_way_change_comparison(
    cover: np.ndarray,
    decoy_only: np.ndarray,
    mirage: np.ndarray,
) -> dict:
    """Verify the foundational hypothesis: Evidence Conservation.
    
    Decoy-only and Mirage must have IDENTICAL change sets, change counts,
    and solely +/-1 modifications.
    
    Returns:
        Dictionary with:
          - decoy_changes: Total pixels changed in decoy-only
          - mirage_changes: Total pixels changed in mirage
          - identical_change_set: True if (cover != decoy_only) == (cover != mirage) everywhere
          - discrepancy_count: Number of pixels where changed masks differ (must be 0)
          - mirage_max_abs_diff: Max |mirage - cover| (must be 1)
          - decoy_max_abs_diff: Max |decoy - cover| (must be 1)
          - diff_between_stegos: Count of pixels where mirage != decoy_only (the sign flips)
    """
    diff_d = (cover != decoy_only)
    diff_m = (cover != mirage)
    
    discrepancy = int(np.sum(diff_d != diff_m))
    identical_set = (discrepancy == 0)
    
    abs_diff_m = np.abs(mirage.astype(np.int32) - cover.astype(np.int32))
    abs_diff_d = np.abs(decoy_only.astype(np.int32) - cover.astype(np.int32))
    
    return {
        "decoy_changes": int(np.sum(diff_d)),
        "mirage_changes": int(np.sum(diff_m)),
        "identical_change_set": identical_set,
        "discrepancy_count": discrepancy,
        "mirage_max_abs_diff": int(np.max(abs_diff_m)) if np.max(abs_diff_m) > 0 else 0,
        "decoy_max_abs_diff": int(np.max(abs_diff_d)) if np.max(abs_diff_d) > 0 else 0,
        "diff_between_stegos": int(np.sum(mirage != decoy_only)),
    }
