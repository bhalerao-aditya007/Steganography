"""Eve E6: Needle-in-a-haystack pooled batch steganalysis ranking."""
import numpy as np
from ..stego_analysis.detector import SteganalysisDetector

def evaluate_needle_in_haystack(
    decoy_only_images: list[np.ndarray],
    mirage_images: list[np.ndarray],
    trained_detector: SteganalysisDetector,
) -> dict:
    """Simulates Eve ranking a batch of N images where K carry Mirage and (N-K) carry Decoy-only.
    
    If existence-hiding holds, the detector cannot rank Mirage images higher than Decoy-only images,
    so top-K precision is close to baseline chance K / N.
    """
    scores_mirage = [trained_detector.predict_proba(img) for img in mirage_images]
    scores_decoy = [trained_detector.predict_proba(img) for img in decoy_only_images]
    
    K = len(mirage_images)
    N = K + len(decoy_only_images)
    baseline_chance = K / float(N) if N > 0 else 0.0
    
    # Combined scores with ground-truth label (1 for Mirage, 0 for Decoy)
    items = [(s, 1) for s in scores_mirage] + [(s, 0) for s in scores_decoy]
    items.sort(key=lambda x: x[0], reverse=True)
    
    top_k = items[:K]
    hits = sum(label for _, label in top_k)
    top_k_precision = hits / float(K) if K > 0 else 0.0
    
    return {
        "N_total": N,
        "K_mirage": K,
        "baseline_chance": baseline_chance,
        "top_k_hits": hits,
        "top_k_precision": top_k_precision,
        "verdict": "Eve achieves no advantage over random guessing (precision ~ baseline chance)" if abs(top_k_precision - baseline_chance) < 0.15 else "Eve successfully filters stego images"
    }
