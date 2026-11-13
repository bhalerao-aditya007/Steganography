"""Eve E2: Second-look Eve (Coercion / Decoy passphrase revealed)."""
import numpy as np
from ..crypto.kdf import master, hkdf
from ..crypto.keyed_perm import tile_positions
from ..embed.profile import Profile

class EveE2SecondLook:
    """Evaluates the stego image when Eve has obtained the correct decoy passphrase."""
    def inspect(
        self,
        cover: np.ndarray,
        stego: np.ndarray,
        salt: bytes,
        pw_decoy: str,
        prof: Profile,
    ) -> dict:
        md = master(pw_decoy, salt, light=True)
        kd = hkdf(md, b"pos")
        
        c_flat = cover.astype(np.int32).ravel()
        s_flat = stego.astype(np.int32).ravel()
        diff = s_flat - c_flat
        chg_mask = (diff != 0)
        
        total_changes = int(chg_mask.sum())
        abs_diff = np.abs(diff)
        
        # Count modifications with magnitude >= 2
        count_abs_ge2 = int((abs_diff >= 2).sum())
        
        # Check if changes occur OUTSIDE the decoy positions P_t
        all_decoy_indices = []
        for t in range(prof.T):
            r0, r1 = prof.tile_slice(t)
            n_d = prof.n_d(t)
            tile_pixels = (r1 - r0) * prof.W
            P = tile_positions(kd, t, tile_pixels, n_d)
            # Offset into full image
            all_decoy_indices.extend((r0 * prof.W + P).tolist())
            
        decoy_mask = np.zeros(cover.size, dtype=bool)
        decoy_mask[all_decoy_indices] = True
        
        changes_outside_decoy = int((chg_mask & (~decoy_mask)).sum())
        expected_decoy_changes = int(len(all_decoy_indices) / 2)
        
        # Verdict: Does any forensic evidence contradict the cover story "I only embedded the decoy"?
        suspicious = (count_abs_ge2 > 0) or (changes_outside_decoy > 0)
        
        return {
            "total_changes": total_changes,
            "expected_decoy_changes": expected_decoy_changes,
            "changes_outside_decoy": changes_outside_decoy,
            "count_abs_ge2": count_abs_ge2,
            "suspicious_evidence_found": suspicious,
            "verdict": "CONTRADICTION DETECTED: Extra changes or +/-2 artifacts reveal second layer!" if suspicious else "CONSISTENT: All observable evidence fully explained by decoy layer alone."
        }
