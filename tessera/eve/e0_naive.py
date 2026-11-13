"""Eve E0: Naive scanner (Chi-Square, RS steganalysis, sequential unkeyed LSB)."""
import numpy as np
from ..stego_analysis.chi2 import chi2_attack
from ..stego_analysis.rs_attack import rs_estimate

class EveE0Scanner:
    """Simulates an automated scanner running classic LSB detectors."""
    def scan(self, img: np.ndarray) -> dict:
        p_val, fractions, curve = chi2_attack(img)
        rs_rate = rs_estimate(img)
        
        # Unkeyed sequential LSB extraction (first 128 bytes)
        flat_lsb = (img.ravel()[:1024] & 1).astype(np.uint8)
        extracted_bytes = bytes(np.packbits(flat_lsb))
        
        # A low chi-square p-value or high RS estimate triggers alarm
        # In sequential LSB replacement (B0), chi2 and RS will flag heavily
        detected_chi2 = (p_val < 0.05)
        detected_rs = (rs_rate > 0.05)
        
        return {
            "chi2_p_val": p_val,
            "chi2_curve": curve,
            "chi2_fractions": fractions,
            "rs_estimated_rate": rs_rate,
            "detected_by_chi2": detected_chi2,
            "detected_by_rs": detected_rs,
            "sample_extracted_bytes_hex": extracted_bytes[:32].hex(),
        }
