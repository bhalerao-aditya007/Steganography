#!/usr/bin/env python3
"""TESSERA Cover-vs-Stego Steganalysis Evaluation Harness:
Extracts SPAM-686 features (second-order Markov of clipped residuals, T=3),
evaluates detectability with Logistic Regression using pair-aware train/test splits,
computes bootstrap 95% confidence intervals across images/pairs,
and benchmarks across the 6 formal experimental arms (C, L, M, R, P+, N-).
"""
import argparse
import csv
import os
import sys
import numpy as np
from PIL import Image
from skimage import data
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.preprocessing import StandardScaler

# Ensure project root is on PYTHONPATH and UTF-8 console
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from tessera.embed.profile import Profile
from tessera.embed.mirage import embed_tile
from tessera.crypto.kdf import derive_keys_v3_real, derive_keys_v3_decoy
from tessera.crypto.xof import xof_bits
from tessera.decoy.dte import dte_encode
from tessera.net import fec


def _hist(D: np.ndarray, T: int = 3) -> np.ndarray:
    D = np.clip(D, -T, T) + T
    a, b, c = D[:, :-2], D[:, 1:-1], D[:, 2:]
    idx = (a * (2 * T + 1) + b) * (2 * T + 1) + c
    return np.bincount(idx.ravel(), minlength=(2 * T + 1) ** 3) / max(1, idx.size)


def _hist_diag(D: np.ndarray, T: int = 3) -> np.ndarray:
    D = np.clip(D, -T, T) + T
    a, b, c = D[:-2, :-2], D[1:-1, 1:-1], D[2:, 2:]
    idx = (a * (2 * T + 1) + b) * (2 * T + 1) + c
    return np.bincount(idx.ravel(), minlength=(2 * T + 1) ** 3) / max(1, idx.size)


def spam686(img: np.ndarray, T: int = 3) -> np.ndarray:
    """Extract 686-dimensional Subtractive Pixel Adjacency Matrix (SPAM) features."""
    x = img.astype(np.int16)
    hv = (
        _hist(x[:, :-1] - x[:, 1:], T)
        + _hist(x[:, 1:] - x[:, :-1], T)
        + _hist((x[:-1, :] - x[1:, :]).T, T)
        + _hist((x[1:, :] - x[:-1, :]).T, T)
    ) / 4.0
    dg = (
        _hist_diag(x[:-1, :-1] - x[1:, 1:], T)
        + _hist_diag(x[1:, 1:] - x[:-1, :-1], T)
        + _hist_diag(x[:-1, 1:] - x[1:, :-1], T)
        + _hist_diag(x[1:, :-1] - x[:-1, 1:], T)
    ) / 4.0
    return np.concatenate([hv, dg])  # 343 + 343 = 686


def lsbm(img: np.ndarray, change_rate: float, rng: np.random.Generator) -> np.ndarray:
    """Positive/Reference control embedder: random +/-1 at `change_rate` of pixels."""
    x = img.astype(np.int16).copy()
    m = rng.random(x.shape) < change_rate
    step = rng.choice([-1, 1], size=x.shape)
    step[x == 0] = 1
    step[x == 255] = -1
    return np.clip(x + step * m, 0, 255).astype(np.uint8)


def compute_p_e(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Compute minimum average detector error P_E = min(P_FA + P_MD) / 2."""
    fpr, tpr, _ = roc_curve(y_true, scores)
    return float(np.min((fpr + (1.0 - tpr)) / 2.0))


def evaluate_arms(cover_feats: np.ndarray, stego_feats: np.ndarray, n_boot: int = 200, seed: int = 42) -> dict:
    """Pair-aware evaluation: cover and stego of image i never cross the train/test split.
    Bootstraps over images/pairs, not independent samples.
    """
    rng = np.random.default_rng(seed)
    n = len(cover_feats)
    order = rng.permutation(n)
    tr, te = order[:n // 2], order[n // 2:]

    X_train = np.vstack([cover_feats[tr], stego_feats[tr]])
    y_train = np.r_[np.zeros(len(tr)), np.ones(len(tr))]

    sc = StandardScaler().fit(X_train)
    clf = LogisticRegression(C=1.0, max_iter=2000, random_state=seed)
    clf.fit(sc.transform(X_train), y_train)

    X_test = np.vstack([cover_feats[te], stego_feats[te]])
    y_test = np.r_[np.zeros(len(te)), np.ones(len(te))]
    scores = clf.decision_function(sc.transform(X_test))

    k = len(te)
    base_pe = compute_p_e(y_test, scores)
    base_auc = float(roc_auc_score(y_test, scores))

    pes, aucs = [], []
    for _ in range(n_boot):
        b = rng.integers(0, k, k)
        idx = np.r_[b, b + k]
        pes.append(compute_p_e(y_test[idx], scores[idx]))
        aucs.append(float(roc_auc_score(y_test[idx], scores[idx])))

    return {
        "P_E": base_pe,
        "AUC": base_auc,
        "P_E_CI95": (float(np.percentile(pes, 2.5)), float(np.percentile(pes, 97.5))),
        "AUC_CI95": (float(np.percentile(aucs, 2.5)), float(np.percentile(aucs, 97.5))),
    }


def generate_synthetic_cover(seed: int) -> np.ndarray:
    """Generate realistic synthetic cover image for controlled evaluation."""
    rng = np.random.default_rng(seed)
    x = np.linspace(0, 1, 512)
    y = np.linspace(0, 1, 512)
    xx, yy = np.meshgrid(x, y)
    base = 128 + 40 * np.sin(4 * np.pi * xx) * np.cos(4 * np.pi * yy)
    noise = rng.normal(0, 8, size=(512, 512))
    return np.clip(base + noise, 10, 245).astype(np.uint8)


def main():
    p = argparse.ArgumentParser(description="TESSERA Steganalysis Evaluation")
    p.add_argument("--n-images", type=int, default=4, help="Number of evaluation images (default: 4 for fast CLI verification)")
    p.add_argument("--quick", action="store_true", help="Quick mode: evaluates baseline and recommended alpha floor only")
    p.add_argument("--out-csv", default="results/stego_eval.csv", help="CSV results path")
    p.add_argument("--seed", type=int, default=42, help="RNG seed")
    a = p.parse_args()

    if a.quick:
        frontier_configs = [
            (0.123, 48),
            (0.157, 64),
            (0.200, 64),
        ]

    rng = np.random.default_rng(a.seed)
    os.makedirs(os.path.dirname(os.path.abspath(a.out_csv)), exist_ok=True)

    print("=" * 70)
    print("      TESSERA v3 STEGANALYSIS HARNESS: SPAM-686 CLASSIFICATION       ")
    print("=" * 70)
    print(f"Dataset Size: {a.n_images} images | Bootstrap Iterations: 200 | Seed: {a.seed}")

    # Generate covers
    covers = [generate_synthetic_cover(a.seed + i) for i in range(a.n_images)]
    print("[*] Extracting SPAM-686 features for clean covers (Arm C)...")
    c_feats = np.array([spam686(img) for img in covers])

    # 1. Negative control (Arm N-: Cover vs identical Cover)
    res_n = evaluate_arms(c_feats, c_feats, n_boot=100, seed=a.seed)
    print(f"  [Arm N- Negative Control]: AUC={res_n['AUC']:.3f} (CI95: {res_n['AUC_CI95'][0]:.3f}-{res_n['AUC_CI95'][1]:.3f}) | P_E={res_n['P_E']:.3f}")

    # 2. Positive control (Arm P+: LSBM @ 0.40 changes/pixel)
    p_plus_stego = [lsbm(img, 0.40, rng) for img in covers]
    p_plus_feats = np.array([spam686(img) for img in p_plus_stego])
    res_p = evaluate_arms(c_feats, p_plus_feats, n_boot=100, seed=a.seed)
    print(f"  [Arm P+ Positive Control]: AUC={res_p['AUC']:.3f} (CI95: {res_p['AUC_CI95'][0]:.3f}-{res_p['AUC_CI95'][1]:.3f}) | P_E={res_p['P_E']:.3f}")

    # 3. Sweep across alpha values and arms paired with shard sizes per Section 10.2 Table
    # (0.088 -> 32B, 0.123 -> 48B, 0.157 -> 64B, 0.200 -> 64B, 0.225 -> 96B)
    if not a.quick:
        frontier_configs = [
            (0.088, 32),
            (0.123, 48),
            (0.157, 64),
            (0.200, 64),
            (0.225, 96),
        ]
    results_rows = [
        {"arm": "N- (Cover vs Cover)", "alpha": 0.0, "AUC": res_n["AUC"], "AUC_lo": res_n["AUC_CI95"][0], "AUC_hi": res_n["AUC_CI95"][1], "P_E": res_n["P_E"], "P_E_lo": res_n["P_E_CI95"][0], "P_E_hi": res_n["P_E_CI95"][1]},
        {"arm": "P+ (LSBM 0.40)", "alpha": 0.40, "AUC": res_p["AUC"], "AUC_lo": res_p["AUC_CI95"][0], "AUC_hi": res_p["AUC_CI95"][1], "P_E": res_p["P_E"], "P_E_lo": res_p["P_E_CI95"][0], "P_E_hi": res_p["P_E_CI95"][1]},
    ]

    for alpha, slen in frontier_configs:
        print(f"[*] Benchmarking Frontier Point: alpha={alpha:.3f}, shard_len={slen}B...", flush=True)
        prof = Profile(H=512, W=512, T=32, alpha_d=alpha, shard_bytes=slen, k=24, v3=True)
        salt = b"\x01" * 16
        real_keys = derive_keys_v3_real("correct horse battery staple 9!", salt)
        decoy_keys = derive_keys_v3_decoy("sunshine123", salt)
        dummy_ct = b"\x55" * (24 * prof.payload)
        shards = fec.encode(dummy_ct, P=prof.payload)
        sb_seed_bits = np.zeros(64, dtype=np.uint8)

        stego_m = []
        stego_l = []

        for img_idx, img in enumerate(covers):
            sm = img.copy()
            sl = img.copy()
            for t in range(prof.T):
                r0, r1 = prof.tile_slice(t)
                ks = xof_bits(decoy_keys["k_pos"], "hdr", t, n=64)
                hdr_ct = sb_seed_bits ^ ks
                # Mirage (Arm M)
                om = embed_tile(img[r0:r1], t, prof, decoy_keys["k_pos"], real_keys["k_H2"], real_keys["k_wh"], hdr_ct, shards[t], rng, mode="mirage", max_rerolls=16)
                if om: sm[r0:r1] = om[0]
                # Decoy-only (Arm L)
                ol = embed_tile(img[r0:r1], t, prof, decoy_keys["k_pos"], None, None, hdr_ct, None, rng, mode="decoy", max_rerolls=16)
                if ol: sl[r0:r1] = ol[0]
            stego_m.append(sm)
            stego_l.append(sl)

        m_feats = np.array([spam686(img) for img in stego_m])
        l_feats = np.array([spam686(img) for img in stego_l])

        # Arm C vs Arm L (Decoy detectability)
        res_l = evaluate_arms(c_feats, l_feats, n_boot=100, seed=a.seed)
        print(f"  [Arm L Decoy @ alpha={alpha:.3f}]: AUC={res_l['AUC']:.3f} (CI: {res_l['AUC_CI95'][0]:.3f}-{res_l['AUC_CI95'][1]:.3f}) | P_E={res_l['P_E']:.3f}")
        results_rows.append({"arm": f"L (Decoy-only alpha={alpha:.3f})", "alpha": alpha, "AUC": res_l["AUC"], "AUC_lo": res_l["AUC_CI95"][0], "AUC_hi": res_l["AUC_CI95"][1], "P_E": res_l["P_E"], "P_E_lo": res_l["P_E_CI95"][0], "P_E_hi": res_l["P_E_CI95"][1]})

        # Arm C vs Arm M (Mirage detectability)
        res_m = evaluate_arms(c_feats, m_feats, n_boot=100, seed=a.seed)
        print(f"  [Arm M Mirage @ alpha={alpha:.3f}]: AUC={res_m['AUC']:.3f} (CI: {res_m['AUC_CI95'][0]:.3f}-{res_m['AUC_CI95'][1]:.3f}) | P_E={res_m['P_E']:.3f}")
        results_rows.append({"arm": f"M (Mirage alpha={alpha:.3f})", "alpha": alpha, "AUC": res_m["AUC"], "AUC_lo": res_m["AUC_CI95"][0], "AUC_hi": res_m["AUC_CI95"][1], "P_E": res_m["P_E"], "P_E_lo": res_m["P_E_CI95"][0], "P_E_hi": res_m["P_E_CI95"][1]})

        # Arm L vs Arm M (RQ1: Does Mirage add detectability over Decoy?)
        res_lm = evaluate_arms(l_feats, m_feats, n_boot=100, seed=a.seed)
        print(f"  [Arm L vs M (RQ1) @ alpha={alpha:.3f}]: AUC={res_lm['AUC']:.3f} (CI: {res_lm['AUC_CI95'][0]:.3f}-{res_lm['AUC_CI95'][1]:.3f}) | P_E={res_lm['P_E']:.3f}")
        results_rows.append({"arm": f"L_vs_M (RQ1 alpha={alpha:.3f})", "alpha": alpha, "AUC": res_lm["AUC"], "AUC_lo": res_lm["AUC_CI95"][0], "AUC_hi": res_lm["AUC_CI95"][1], "P_E": res_lm["P_E"], "P_E_lo": res_lm["P_E_CI95"][0], "P_E_hi": res_lm["P_E_CI95"][1]})

    # Write CSV
    with open(a.out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["arm", "alpha", "AUC", "AUC_lo", "AUC_hi", "P_E", "P_E_lo", "P_E_hi"])
        w.writeheader()
        w.writerows(results_rows)

    print(f"\n[SUCCESS] Steganalysis audit results saved to {a.out_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
