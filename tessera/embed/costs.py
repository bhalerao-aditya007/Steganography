"""Distortion cost calculation for content-adaptive steganography (HILL / S-UNIWARD-lite)."""
import numpy as np
from scipy.signal import convolve2d

def compute_hill_costs(cover: np.ndarray) -> np.ndarray:
    """Compute symmetric pixel modification costs rho using a HILL-style directional high-pass filter.
    
    Smooth regions get high modification cost (low embedding probability).
    Textured and edge regions get lower modification cost (higher embedding capacity).
    """
    img = cover.astype(np.float64)
    # High-pass filter kernel (3x3 Laplacian / edge detector)
    h_kernel = np.array([
        [-1,  2, -1],
        [ 2, -4,  2],
        [-1,  2, -1]
    ], dtype=np.float64) / 4.0
    
    residual = np.abs(convolve2d(img, h_kernel, mode="same", boundary="symm"))
    
    # 3x3 low-pass smoothing of residual energy
    smooth_kernel = np.ones((3, 3), dtype=np.float64) / 9.0
    energy = convolve2d(residual, smooth_kernel, mode="same", boundary="symm")
    
    # Inverse energy: low energy (smooth) -> high cost
    eps = 1e-4
    costs = 1.0 / (eps + energy)
    
    # Boundary pixels (0 or 255) cannot be freely modified both ways
    costs[cover == 0] = 1e7
    costs[cover == 255] = 1e7
    
    return costs
