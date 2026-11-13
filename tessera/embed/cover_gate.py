"""Cover image suitability gate for steganographic embedding.
Filters out saturated, overly smooth, or artificial images where +/-1 LSB matching
would be conspicuous or create wet-pixel shortages.
"""
import math
import numpy as np


def check_cover(
    img: np.ndarray,
    max_boundary_fraction: float = 0.05,
    max_flat_block_fraction: float = 0.35,
    min_residual_entropy: float = 1.5,
) -> tuple[bool, str, dict]:
    """Inspect cover image and determine if it meets suitability thresholds for Mirage stego.
    
    Returns:
        (is_suitable, reason_or_warning, metrics_dict)
    """
    if img.ndim != 2:
        return False, f"Expected 2D grayscale image, got {img.shape}", {}
    h, w = img.shape
    if (h, w) != (512, 512):
        return False, f"Expected 512x512 image, got {h}x{w}", {}

    x = img.astype(np.float64)
    total_pix = x.size

    # 1. Boundary / wet pixels (0 or 255)
    boundary_count = int(np.sum((img == 0) | (img == 255)))
    boundary_frac = boundary_count / total_pix

    # 2. Flat blocks analysis (8x8 blocks)
    block_h, block_w = 8, 8
    n_blocks_y, n_blocks_x = h // block_h, w // block_w
    flat_blocks = 0
    total_blocks = n_blocks_y * n_blocks_x

    for by in range(n_blocks_y):
        for bx in range(n_blocks_x):
            blk = x[by * block_h:(by + 1) * block_h, bx * block_w:(bx + 1) * block_w]
            if np.var(blk) < 2.0:
                flat_blocks += 1

    flat_frac = flat_blocks / total_blocks

    # 3. Residual entropy of horizontal differences
    diffs = np.clip(x[:, 1:] - x[:, :-1], -5, 5).astype(np.int32) + 5
    counts = np.bincount(diffs.ravel(), minlength=11)
    probs = counts / counts.sum()
    probs = probs[probs > 0]
    entropy = -float(np.sum(probs * np.log2(probs)))

    metrics = {
        "boundary_fraction": boundary_frac,
        "flat_block_fraction": flat_frac,
        "residual_entropy": entropy,
    }

    if boundary_frac > max_boundary_fraction:
        return False, f"Cover rejected: boundary pixels ({boundary_frac:.1%}) exceed threshold ({max_boundary_fraction:.1%})", metrics

    if flat_frac > max_flat_block_fraction:
        return False, f"Cover rejected: flat 8x8 blocks ({flat_frac:.1%}) exceed threshold ({max_flat_block_fraction:.1%})", metrics

    if entropy < min_residual_entropy:
        return False, f"Cover rejected: residual entropy ({entropy:.2f}) is below threshold ({min_residual_entropy:.2f})", metrics

    return True, "Cover passed steganographic suitability gate.", metrics
