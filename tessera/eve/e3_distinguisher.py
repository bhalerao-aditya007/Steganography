"""Eve E3: Kerckhoffs-strong Distinguisher & Existence-Hiding Gap Evaluator."""
import numpy as np
from ..stego_analysis.detector import SteganalysisDetector
from ..stego_analysis.sign_tests import sign_statistics, sign_runs_test
from ..metrics.stats import tost_equivalence_test

class EveE3Distinguisher:
    """Kerckhoffs-strong classifier evaluating existence-hiding between Decoy-only and Mirage."""
    def __init__(self):
        self.detector_decoy_vs_mirage = SteganalysisDetector()
        self.detector_cover_vs_decoy = SteganalysisDetector()
        self.detector_decoy_vs_naive = SteganalysisDetector()

    def train_and_evaluate(
        self,
        covers: list[np.ndarray],
        decoys: list[np.ndarray],
        mirages: list[np.ndarray],
        naives: list[np.ndarray],
    ) -> dict:
        """Train and evaluate 3 classifiers:
        1. Cover vs Decoy-only (Verifies bait is detectable)
        2. Decoy-only vs Mirage (Main hypothesis: AUC ~ 0.50, indistinguishable)
        3. Decoy-only vs Naive 2nd LSB (Baseline B4: AUC >> 0.50, detectable)
        """
        # Split train / test
        n = len(covers)
        split = max(1, int(n * 0.7))
        
        # 1. Cover vs Decoy
        res_cover_decoy = self.detector_cover_vs_decoy.train(covers[:split], decoys[:split])
        eval_cover_decoy = self.detector_cover_vs_decoy.evaluate(covers[split:], decoys[split:]) if split < n else res_cover_decoy

        # 2. Decoy vs Mirage (The Headline Test)
        res_decoy_mirage = self.detector_decoy_vs_mirage.train(decoys[:split], mirages[:split])
        eval_decoy_mirage = self.detector_decoy_vs_mirage.evaluate(decoys[split:], mirages[split:]) if split < n else res_decoy_mirage

        # 3. Decoy vs Naive (B4 Baseline)
        res_decoy_naive = self.detector_decoy_vs_naive.train(decoys[:split], naives[:split])
        eval_decoy_naive = self.detector_decoy_vs_naive.evaluate(decoys[split:], naives[split:]) if split < n else res_decoy_naive

        # TOST statistical equivalence test on Decoy vs Mirage AUC
        tost = tost_equivalence_test(eval_decoy_mirage["auc"], se_auc=0.03, target=0.50, delta=0.04)

        return {
            "cover_vs_decoy": eval_cover_decoy,
            "decoy_vs_mirage": eval_decoy_mirage,
            "decoy_vs_naive": eval_decoy_naive,
            "tost_equivalence": tost,
        }

    def evaluate_sign_channel(self, cover: np.ndarray, stego: np.ndarray) -> dict:
        """Run targeted sign-channel statistical tests on an individual stego image."""
        stats = sign_statistics(cover, stego)
        diff = (stego.astype(int) - cover.astype(int)).ravel()
        chg = diff[diff != 0]
        signs = np.sign(chg)
        runs_p_val = sign_runs_test(signs) if len(signs) > 0 else 1.0
        
        stats["runs_test_p_val"] = runs_p_val
        stats["is_sign_random"] = (stats["chi2_p_val"] > 0.05 and runs_p_val > 0.05)
        return stats
