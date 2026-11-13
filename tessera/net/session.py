"""End-to-End Session Orchestrator for Alice (Sender) and Bob (Receiver)."""
import os
import time
import numpy as np
from ..crypto.kdf import master, hkdf
from ..crypto.aead import encrypt_aead, decrypt_aead
from ..crypto.xof import xof_bits
from ..decoy.dte import dte_encode, dte_decode, sample_random_message
from ..embed.profile import Profile
from ..embed.mirage import embed_tile, extract_tile, decoy_peek
from ..ecc.shards import make_shards, recover_shards
from .rudp import RUDPTransmitter
from .impair import NetworkImpairer

class AliceSession:
    """Sender orchestrator: encrypts, shards, embeds, and packages stego image."""
    def __init__(
        self,
        pw_decoy: str,
        pw_real: str,
        salt: bytes | None = None,
        nonce: bytes | None = None,
        profile: Profile | None = None,
    ):
        self.salt = salt or os.urandom(16)
        self.nonce = nonce or os.urandom(12)
        self.profile = profile or Profile()
        
        # Key derivation
        self.md = master(pw_decoy, self.salt, light=True)
        self.mr = master(pw_real, self.salt, light=False)
        
        self.kd = hkdf(self.md, b"pos")
        self.kenc = hkdf(self.mr, b"enc")
        self.kh = hkdf(self.mr, b"h2")
        self.kw = hkdf(self.mr, b"white")
        self.kmac = hkdf(self.mr, b"mac")

    def prepare_payloads(
        self,
        real_secret: bytes,
        decoy_msg_indices: list[int] | None = None,
    ) -> tuple[bytes, list[bytes], int, str]:
        """Encrypt real secret and encode decoy honey message."""
        # 1. AEAD Encryption of real secret
        ct = encrypt_aead(self.kenc, self.nonce, real_secret, aad=b"tessera-v2")
        # 2. RS erasure sharding
        shards = make_shards(ct, self.profile)
        
        # 3. Honey decoy message
        if decoy_msg_indices is None:
            decoy_msg_indices = [0, 1, 4, 11, 2]  # Default demo meeting note
        decoy_seed = dte_encode(decoy_msg_indices)
        decoy_msg = dte_decode(decoy_seed)
        
        return ct, shards, decoy_seed, decoy_msg

    def embed_image(
        self,
        cover: np.ndarray,
        shards: list[bytes],
        decoy_seed: int,
        mode: str = "mirage",
    ) -> tuple[np.ndarray, dict]:
        """Embed into all tiles of the cover image.
        
        mode: 'mirage' (both layers) or 'decoy' (decoy layer only)
        """
        stego = cover.copy()
        prof = self.profile
        t0 = time.time()
        
        tile_stats = []
        sb_seed_bits = np.array([int(b) for b in format(decoy_seed, "064b")], dtype=np.uint8)

        for t in range(prof.T):
            r0, r1 = prof.tile_slice(t)
            ks = xof_bits(self.kd, "hdr", t, n=64)
            hdr_ct_bits = sb_seed_bits ^ ks
            
            shard_data = shards[t] if mode == "mirage" else None
            rng = np.random.default_rng(100 + t)
            
            out = embed_tile(
                cover[r0:r1],
                t,
                prof,
                self.kd,
                self.kh if mode == "mirage" else None,
                self.kw if mode == "mirage" else None,
                hdr_ct_bits,
                shard_data,
                rng,
                mode=mode,
            )
            if out is None:
                raise RuntimeError(f"Embedding failed at tile {t} (insufficient dry positions)")
            stego[r0:r1], n_chg, ctr = out
            tile_stats.append({"tile": t, "changes": n_chg, "rerolls": ctr})

        elapsed = time.time() - t0
        return stego, {
            "elapsed_seconds": elapsed,
            "tile_stats": tile_stats,
            "mean_changes_per_tile": float(np.mean([s["changes"] for s in tile_stats])),
            "total_rerolls": sum(s["rerolls"] for s in tile_stats),
        }

class BobSession:
    """Receiver orchestrator: extracts shards from received tiles, reconstructs secret."""
    def __init__(
        self,
        pw_decoy: str,
        pw_real: str,
        salt: bytes,
        nonce: bytes,
        profile: Profile | None = None,
    ):
        self.salt = salt
        self.nonce = nonce
        self.profile = profile or Profile()
        
        # Key derivation
        self.md = master(pw_decoy, self.salt, light=True)
        self.mr = master(pw_real, self.salt, light=False)
        
        self.kd = hkdf(self.md, b"pos")
        self.kenc = hkdf(self.mr, b"enc")
        self.kh = hkdf(self.mr, b"h2")
        self.kw = hkdf(self.mr, b"white")

    def process_tiles(
        self,
        received_tiles_by_idx: dict[int, np.ndarray],
    ) -> dict:
        """Extract shards from received tiles and attempt RS + AEAD reconstruction."""
        prof = self.profile
        extracted_shards = {}
        
        for t_idx, tile_img in received_tiles_by_idx.items():
            shard_bytes = extract_tile(tile_img, t_idx, prof, self.kd, self.kh, self.kw)
            extracted_shards[t_idx] = shard_bytes

        # Attempt RS recovery
        recovered_ct, valid_count = recover_shards(extracted_shards, prof)
        
        if recovered_ct is None:
            return {
                "success": False,
                "valid_shards": valid_count,
                "needed_shards": prof.k,
                "recovered_secret": None,
                "reason": f"Only {valid_count}/{prof.k} valid shards received. Triggering NACK retransmission.",
            }

        # Attempt AEAD decryption
        try:
            pt = decrypt_aead(self.kenc, self.nonce, recovered_ct, aad=b"tessera-v2")
            return {
                "success": True,
                "valid_shards": valid_count,
                "needed_shards": prof.k,
                "recovered_secret": pt,
                "reason": f"Success! Recovered secret from {valid_count} shards before complete reception.",
            }
        except Exception as e:
            return {
                "success": False,
                "valid_shards": valid_count,
                "needed_shards": prof.k,
                "recovered_secret": None,
                "reason": f"AEAD authentication failure (wrong key or tampering): {e}",
            }
