"""Change-Set Equivalence and Sign-Uniformity Statistical Verification."""
import os
import numpy as np
from skimage import data
from scipy.stats import chi2_contingency
from tessera.embed.profile import Profile
from tessera.net.session import AliceSession
from tessera.metrics.diffmap import three_way_change_comparison
from tessera.stego_analysis.sign_tests import sign_statistics

def test_change_set_equivalence():
    cover = data.camera().astype(np.uint8)
    prof = Profile(H=512, W=512, T=32, alpha_d=0.20, shard_bytes=64, k=24)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    
    alice = AliceSession("sunshine123", "strong password", salt=salt, nonce=nonce, profile=prof)
    plain = os.urandom(1200)
    ct, shards, decoy_seed, _ = alice.prepare_payloads(plain)
    
    stego_mirage, _ = alice.embed_image(cover, shards, decoy_seed, mode="mirage")
    stego_decoy, _ = alice.embed_image(cover, shards, decoy_seed, mode="decoy")
    
    # 1. Per-tile equivalence
    identical_tiles = 0
    for t in range(prof.T):
        r0, r1 = prof.tile_slice(t)
        cov_tile = cover[r0:r1]
        m_tile = stego_mirage[r0:r1]
        d_tile = stego_decoy[r0:r1]
        
        m_changes = (m_tile != cov_tile)
        d_changes = (d_tile != cov_tile)
        if (m_changes == d_changes).all():
            identical_tiles += 1
            
    print(f"Identical change set tiles: {identical_tiles} / {prof.T}")
    assert identical_tiles == prof.T, f"Expected all {prof.T} tiles to have identical change sets"
    
    # 2. Overall 3-way check
    comp = three_way_change_comparison(cover, stego_decoy, stego_mirage)
    assert comp["identical_change_set"] is True
    assert comp["discrepancy_count"] == 0
    
    # 3. Sign statistics
    stats_m = sign_statistics(cover, stego_mirage)
    stats_d = sign_statistics(cover, stego_decoy)
    
    print(f"Mirage: frac +1 = {stats_m['frac_pos']:.4f}, frac |d|==1 = {stats_m['frac_abs1']:.4f}, chi2 p = {stats_m['chi2_p_val']:.3f}")
    print(f"Decoy : frac +1 = {stats_d['frac_pos']:.4f}, frac |d|==1 = {stats_d['frac_abs1']:.4f}, chi2 p = {stats_d['chi2_p_val']:.3f}")
    
    assert 0.48 < stats_m["frac_pos"] < 0.52, f"Sign fraction biased: {stats_m['frac_pos']}"
    assert stats_m["frac_abs1"] == 1.0, f"Expected 100% |d|==1, got {stats_m['frac_abs1']}"
    assert stats_m["n_abs2"] == 0, f"Expected 0 |d|>=2 changes, got {stats_m['n_abs2']}"
    print("CHANGE-SET EQUIVALENCE AND SIGN UNIFORMITY VERIFIED!")

if __name__ == "__main__":
    test_change_set_equivalence()
