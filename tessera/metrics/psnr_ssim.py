"""Image quality and distortion metrics (PSNR, SSIM, MSE, changed bpp)."""
import numpy as np
from skimage.metrics import structural_similarity as ssim_fn

def compute_quality_metrics(cover: np.ndarray, stego: np.ndarray) -> dict:
    """Compute PSNR, SSIM, MSE, and fraction of modified pixels.
    
    Args:
        cover: 2D uint8 cover image
        stego: 2D uint8 stego image
        
    Returns:
        Dictionary with:
          - mse: Mean Squared Error
          - psnr_db: Peak Signal-to-Noise Ratio in dB (inf if identical)
          - ssim: Structural Similarity Index (1.0 if identical)
          - changed_pixels: Absolute count of modified pixels
          - changed_fraction: Fraction of modified pixels (beta)
    """
    c = cover.astype(np.float64)
    s = stego.astype(np.float64)
    
    mse = float(np.mean((c - s) ** 2))
    if mse == 0:
        psnr_db = float("inf")
    else:
        psnr_db = float(10.0 * np.log10((255.0 ** 2) / mse))
        
    ssim_val = float(ssim_fn(cover, stego, data_range=255))
    changed_pixels = int(np.sum(cover != stego))
    changed_fraction = float(np.mean(cover != stego))
    
    return {
        "mse": mse,
        "psnr_db": psnr_db,
        "ssim": ssim_val,
        "changed_pixels": changed_pixels,
        "changed_fraction": changed_fraction,
    }
