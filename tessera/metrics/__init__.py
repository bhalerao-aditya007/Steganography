"""Metrics and evaluation subsystem for TESSERA v2 Mirage."""
from .psnr_ssim import compute_quality_metrics
from .diffmap import compute_diff_map, three_way_change_comparison
from .stats import wilson_score_interval, tost_equivalence_test, capacity_price_factor

__all__ = [
    "compute_quality_metrics",
    "compute_diff_map",
    "three_way_change_comparison",
    "wilson_score_interval",
    "tost_equivalence_test",
    "capacity_price_factor",
]
