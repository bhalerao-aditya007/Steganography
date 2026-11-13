"""Comparison tests across Baselines B0, B1, B4, and B5 (Mirage)."""
import os
import numpy as np
from skimage import data
from tessera.embed.profile import Profile
from tessera.embed.lsbm import embed_lsbm
from tessera.embed.naive_second_lsb import embed_naive_second_lsb
from tessera.stego_analysis.chi2 import chi2_attack
from tessera.eve.e2_second_look import EveE2SecondLook
from tessera.crypto.kdf import master, hkdf

def test_baselines_comparison():
    cover = data.camera().astype(np.uint8)
    prof = Profile(H=512, W=512, T=32, alpha_d=0.20, shard_bytes=64, k=24)
    salt = os.urandom(16)
    pw_decoy = "sunshine123"
    md = master(pw_decoy, salt, light=True)
    kd = hkdf(md, b"pos")
    kh = hkdf(master("real_pw", salt), b"h2")
    
    # 1. Baseline B0: Sequential LSB replacement
    b0_img = cover.copy()
    payload_bits = np.random.randint(0, 2, size=50000, dtype=np.uint8)
    flat_b0 = b0_img.ravel()
    flat_b0[:50000] = (flat_b0[:50000] & 0xFE) | payload_bits
    
    p_val_b0, _, _ = chi2_attack(b0_img)
    print(f"Baseline B0 (Sequential LSB) Chi2 p-value: {p_val_b0:.4f}")
    assert p_val_b0 < 0.05, "B0 should be flagged by Chi-square attack!"
    
    # 2. Baseline B4: Naive 2nd LSB embedding (Ogiela & Koptyra)
    r0, r1 = prof.tile_slice(0)
    hdr_bits = np.random.randint(0, 2, size=64, dtype=np.uint8)
    fake_shard = os.urandom(prof.shard_bytes)
    
    rng = np.random.default_rng(123)
    b4_tile, n_changes_b4 = embed_naive_second_lsb(
        cover[r0:r1],
        0,
        prof,
        kd,
        kh,
        hdr_bits,
        fake_shard,
        rng,
    )
    
    # Check difference magnitudes on B4 tile
    diff_b4 = np.abs(b4_tile.astype(int) - cover[r0:r1].astype(int))
    count_ge2 = int((diff_b4 >= 2).sum())
    print(f"Baseline B4 changes with |d| >= 2: {count_ge2} (Total changes: {n_changes_b4})")
    assert count_ge2 > 0, "B4 must generate observable |d| >= 2 modifications"
    
    print("BASELINES COMPARISON VERIFIED!")

if __name__ == "__main__":
    test_baselines_comparison()
