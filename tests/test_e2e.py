"""End-to-End Test Suite for TESSERA v2 Mirage (Ported and Expanded from Specification Appendix A)."""
import os
import time
import numpy as np
from skimage import data
from tessera.embed.profile import Profile
from tessera.net.session import AliceSession, BobSession
from tessera.embed.mirage import decoy_peek
from tessera.crypto.kdf import master, hkdf
from tessera.metrics.psnr_ssim import compute_quality_metrics
from tessera.metrics.diffmap import three_way_change_comparison

def test_mirage_end_to_end():
    rng = np.random.default_rng(42)
    cover = data.camera().astype(np.uint8)
    prof = Profile(H=512, W=512, T=32, alpha_d=0.20, shard_bytes=64, k=24)
    
    salt = os.urandom(16)
    nonce = os.urandom(12)
    pw_decoy = "sunshine123"
    pw_real = "correct horse battery staple 9!"
    
    # 1. Initialize Alice
    alice = AliceSession(pw_decoy, pw_real, salt=salt, nonce=nonce, profile=prof)
    
    # 2. Real secret (1280 bytes)
    plain = (b"Rendezvous brief: coordinates 21.1458N 79.0882E, window 02:10-02:40. " * 18)[:1280]
    ct, shards, decoy_seed, decoy_msg = alice.prepare_payloads(plain, decoy_msg_indices=[0, 1, 4, 11, 2])
    
    print(f"Plaintext length: {len(plain)}B, Ciphertext length: {len(ct)}B, Total capacity: {prof.total_capacity}B")
    print(f"Decoy Honey Message: '{decoy_msg}'")
    
    # 3. Embed both Mirage (Real + Decoy) and Decoy-only
    stego_mirage, stats_m = alice.embed_image(cover, shards, decoy_seed, mode="mirage")
    stego_decoy, stats_d = alice.embed_image(cover, shards, decoy_seed, mode="decoy")
    
    # Quality metrics
    qm = compute_quality_metrics(cover, stego_mirage)
    print(f"Mirage PSNR: {qm['psnr_db']:.2f} dB, Changed fraction: {qm['changed_fraction']:.4f}")
    assert qm["psnr_db"] > 55.0, f"Expected PSNR > 55 dB, got {qm['psnr_db']}"
    assert 0.09 < qm["changed_fraction"] < 0.12, f"Expected changed fraction ~ 0.10, got {qm['changed_fraction']}"
    
    # 4. Evidence Conservation Verification
    comp = three_way_change_comparison(cover, stego_decoy, stego_mirage)
    print("Evidence Conservation Check:")
    print(f"  Identical Change Set: {comp['identical_change_set']}")
    print(f"  Discrepancy Count: {comp['discrepancy_count']}")
    print(f"  Mirage Max |d|: {comp['mirage_max_abs_diff']}")
    assert comp["identical_change_set"] is True, "Mirage and Decoy-only change sets MUST be identical!"
    assert comp["mirage_max_abs_diff"] == 1, "Mirage must ONLY use +/-1 modifications!"
    
    # 5. Eve Honey Decoy Inspection (Right vs Wrong Passphrases)
    r0, r1 = prof.tile_slice(0)
    tile0 = stego_mirage[r0:r1]
    
    peek_right = decoy_peek(tile0, 0, prof, alice.kd)
    print(f"Eve (Right Key 'sunshine123') : {peek_right}")
    assert peek_right == decoy_msg, f"Expected {decoy_msg}, got {peek_right}"
    
    for wrong_pw in ["password", "letmein", "qwerty1", "admin123"]:
        kd_wrong = hkdf(master(wrong_pw, salt, light=True), b"pos")
        peek_wrong = decoy_peek(tile0, 0, prof, kd_wrong)
        print(f"Eve (Wrong Key '{wrong_pw:<11}') : {peek_wrong}")
        assert peek_wrong != decoy_msg, "Wrong key must not match intended decoy"
        assert len(peek_wrong) > 10, "Wrong key must yield well-formed honey message"
        
    # 6. Bob Recovery under varying packet/tile loss rates (0, 4, 8, 9 tiles dropped)
    bob = BobSession(pw_decoy, pw_real, salt=salt, nonce=nonce, profile=prof)
    
    for loss_tiles in (0, 4, 8, 9):
        drop_indices = set(rng.choice(prof.T, loss_tiles, replace=False).tolist())
        received_tiles = {}
        for t in range(prof.T):
            if t not in drop_indices:
                r0, r1 = prof.tile_slice(t)
                received_tiles[t] = stego_mirage[r0:r1]
                
        res = bob.process_tiles(received_tiles)
        if loss_tiles <= 8:
            assert res["success"] is True, f"Failed recovery with {loss_tiles} lost tiles"
            assert res["recovered_secret"] == plain, "Recovered secret does not match original plain!"
            print(f"Loss test (drop {loss_tiles} tiles): SUCCESS (reconstructed {len(res['recovered_secret'])}B from {res['valid_shards']} shards)")
        else:
            assert res["success"] is False, "Expected NACK trigger when 9 tiles are lost"
            print(f"Loss test (drop {loss_tiles} tiles): NACK triggered as expected ({res['valid_shards']}/{prof.k} shards)")
            
    # 7. Bob with wrong real key
    bob_wrong = BobSession(pw_decoy, "wrong real password!", salt=salt, nonce=nonce, profile=prof)
    all_tiles = {t: stego_mirage[prof.tile_slice(t)[0]:prof.tile_slice(t)[1]] for t in range(prof.T)}
    res_wrong = bob_wrong.process_tiles(all_tiles)
    assert res_wrong["success"] is False, "Bob with wrong real password must fail authentication"
    print("Wrong real key test: Correctly failed authentication with 0 valid shards / AEAD error")
    print("ALL END-TO-END VERIFICATION CHECKS PASSED!")

if __name__ == "__main__":
    test_mirage_end_to_end()
