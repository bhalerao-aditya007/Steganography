"""Subtractive Pixel Adjacency Matrix (SPAM) Feature Extractor (Pevny-Bas-Fridrich).

Extracts second-order Markov transition probabilities on clipped first-order differences
along horizontal and vertical directions (T = 3 -> 7^3 = 343 dimensions per direction,
or 343-D pooled / 686-D concatenated).
"""
import numpy as np

def extract_spam_features(img: np.ndarray, T: int = 3) -> np.ndarray:
    """Extract SPAM second-order Markov transition features.
    
    Args:
        img: 2D uint8 grayscale image.
        T: Clipping threshold (default 3, giving 2*T + 1 = 7 difference states).
        
    Returns:
        1D feature vector of length 343.
    """
    X = img.astype(np.int32)
    # Horizontal difference: D_h(i, j) = X(i, j) - X(i, j+1)
    Dh = np.clip(X[:, :-1] - X[:, 1:], -T, T)
    # Vertical difference: D_v(i, j) = X(i, j) - X(i+1, j)
    Dv = np.clip(X[:-1, :] - X[1:, :], -T, T)
    
    # Map range [-T, T] to [0, 2T]
    Dh_idx = Dh + T
    Dv_idx = Dv + T
    k = 2 * T + 1  # 7
    k2 = k * k
    
    features = np.zeros(k ** 3, dtype=np.float64)
    
    # Horizontal triplets (u, v, w) -> index u * 49 + v * 7 + w
    if Dh.shape[1] >= 3:
        u = Dh_idx[:, :-2].ravel()
        v = Dh_idx[:, 1:-1].ravel()
        w = Dh_idx[:, 2:].ravel()
        triplets_h = u * k2 + v * k + w
        bincount_h = np.bincount(triplets_h, minlength=k**3)
        features += bincount_h
        
    # Vertical triplets
    if Dv.shape[0] >= 3:
        u = Dv_idx[:-2, :].ravel()
        v = Dv_idx[1:-1, :].ravel()
        w = Dv_idx[2:, :].ravel()
        triplets_v = u * k2 + v * k + w
        bincount_v = np.bincount(triplets_v, minlength=k**3)
        features += bincount_v
        
    total = np.sum(features)
    if total > 0:
        features /= total
        
    return features
