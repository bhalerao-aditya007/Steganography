#!/usr/bin/env python3
"""TESSERA Alice Sender CLI:
Loads cover image, derives keys with domain separation, encrypts with ChaCha20-Poly1305,
encodes with column-wise RS(32,24), embeds via Mirage sign-channel, and transmits over UDP.
"""
import argparse
import getpass
import hashlib
import json
import os
import platform
import struct
import sys
import time
import numpy as np
from PIL import Image

# Ensure project root is on PYTHONPATH and UTF-8 console
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from tessera.embed.profile import Profile
from tessera.embed.cover_gate import check_cover
from tessera.crypto.kdf import derive_keys_v3_real, derive_keys_v3_decoy
from tessera.crypto.aead import encrypt_v3, make_v3_aad, MAX_SECRET_LEN, TOTAL_CIPHERTEXT_LEN
from tessera.crypto.xof import xof_bits
from tessera.decoy.dte import dte_encode, dte_decode
from tessera.embed.mirage import embed_tile
from tessera.net import fec
from tessera.net.transport import Sender


def get_git_commit() -> str:
    try:
        import subprocess
        res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True)
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown"


def main():
    p = argparse.ArgumentParser(description="TESSERA v3 Alice Sender")
    p.add_argument("--dst", default="127.0.0.1:9998", help="Destination (Router or Bob host:port)")
    p.add_argument("--cover", default="covers/textured_01.png", help="Cover image path (512x512 grayscale)")
    p.add_argument("--mode", choices=["fec", "hybrid"], default="hybrid", help="Transport mode")
    p.add_argument("--secret", default=None, help="Secret message string to embed")
    p.add_argument("--secret-file", default=None, help="File containing secret message")
    p.add_argument("--capacity-check", action="store_true", help="Print message capacity and exit")
    p.add_argument("--pps", type=int, default=500, help="Sender pacing rate (packets/sec)")
    p.add_argument("--rto", type=float, default=0.2, help="Base retransmission timeout in seconds")
    p.add_argument("--max-rounds", type=int, default=8, help="Max ARQ repair rounds (hybrid mode)")
    p.add_argument("--mtu-safe", action="store_true", help="Fragment 8KB tiles into <=1200B frames")
    p.add_argument("--decoy-pass-env", default="TESSERA_DECOY", help="Env var name for decoy passphrase")
    p.add_argument("--real-pass-env", default="TESSERA_REAL", help="Env var name for real passphrase")
    p.add_argument("--save-stego", default=None, help="Path to save full stego image (PNG)")
    p.add_argument("--manifest", default=None, help="Path to save run_manifest.json")
    p.add_argument("--seed", type=int, default=None, help="RNG seed for deterministic test reproducibility")

    a = p.parse_args()

    if a.capacity_check:
        print(f"TESSERA v3 Framing Capacity:")
        print(f"  • Reed-Solomon Code : RS(32, 24) over GF(256)")
        print(f"  • Shard body length : {fec.DEFAULT_P} bytes per shard")
        print(f"  • Total ciphertext  : {TOTAL_CIPHERTEXT_LEN} bytes (24 * 59)")
        print(f"  • Nonce + Poly tag  : 12 B + 16 B = 28 bytes")
        print(f"  • Length prefix     : 2 bytes")
        print(f"  • Maximum Secret    : {MAX_SECRET_LEN} bytes (strictly enforced)")
        return 0

    # 1. Obtain secret message
    if a.secret:
        secret_bytes = a.secret.encode("utf-8")
    elif a.secret_file and os.path.exists(a.secret_file):
        with open(a.secret_file, "rb") as sf:
            secret_bytes = sf.read()
    else:
        secret_bytes = b"EXECUTIVE BRIEF: Project TESSERA v3 operational. Dual-layer evidence conservation verified."

    if len(secret_bytes) > MAX_SECRET_LEN:
        print(f"[FATAL] Message length ({len(secret_bytes)} B) exceeds capacity limit ({MAX_SECRET_LEN} B).", file=sys.stderr)
        return 1

    # 2. Obtain passphrases (Never from argv!)
    pw_decoy = os.environ.get(a.decoy_pass_env)
    if not pw_decoy:
        pw_decoy = getpass.getpass("Enter Decoy Passphrase: ")
    pw_real = os.environ.get(a.real_pass_env)
    if not pw_real:
        pw_real = getpass.getpass("Enter Real Secret Passphrase: ")

    # 3. Load cover image & run Gate
    if not os.path.exists(a.cover):
        print(f"[FATAL] Cover image '{a.cover}' not found.", file=sys.stderr)
        return 1

    cover_img = Image.open(a.cover).convert("L")
    if cover_img.size != (512, 512):
        cover_img = cover_img.resize((512, 512))
    cover = np.array(cover_img, dtype=np.uint8)

    gate_ok, gate_msg, gate_metrics = check_cover(cover)
    print(f"[GATE] {gate_msg} (boundary={gate_metrics.get('boundary_fraction',0):.2%}, flat={gate_metrics.get('flat_block_fraction',0):.2%})")
    if not gate_ok:
        print(f"[WARN] Cover image marginally suitable, proceeding with caution...")

    # 4. Key schedules & AAD binding
    salt = os.urandom(16)
    t_kdf0 = time.perf_counter()
    real_keys = derive_keys_v3_real(pw_real, salt)
    decoy_keys = derive_keys_v3_decoy(pw_decoy, salt)
    kdf_elapsed = time.perf_counter() - t_kdf0

    prof = Profile(H=512, W=512, T=32, alpha_d=0.157, shard_bytes=64, k=24, v3=True)
    aad = make_v3_aad(salt, n=prof.n, k=prof.k, shard_len=prof.shard_bytes, ct_len=TOTAL_CIPHERTEXT_LEN)

    # 5. AEAD Encryption & Column-wise RS Sharding
    ct = encrypt_v3(real_keys["k_enc"], secret_bytes, aad)
    shards = fec.encode(ct, P=prof.payload)

    # 6. Honey decoy generation
    decoy_seed = dte_encode([0, 1, 4, 11, 2])
    decoy_msg = dte_decode(decoy_seed)
    sb_seed_bits = np.array([int(b) for b in format(decoy_seed, "064b")], dtype=np.uint8)

    # 7. Mirage Sign-Channel Embedding
    print(f"[EMBED] Embedding {len(secret_bytes)}B secret into 32 tiles (mode={a.mode}, pps={a.pps})...")
    stego = cover.copy()
    tiles_data = []
    t_embed0 = time.perf_counter()

    for t in range(prof.T):
        r0, r1 = prof.tile_slice(t)
        ks = xof_bits(decoy_keys["k_pos"], "hdr", t, n=64)
        hdr_ct_bits = sb_seed_bits ^ ks
        rng = np.random.default_rng(a.seed + t if a.seed is not None else 100 + t)

        out = embed_tile(
            cover[r0:r1],
            t,
            prof,
            decoy_keys["k_pos"],
            real_keys["k_H2"],
            real_keys["k_wh"],
            hdr_ct_bits,
            shards[t],
            rng,
            mode="mirage",
        )
        if out is None:
            print(f"[FATAL] Embedding failed at tile {t} due to dry position shortfall.", file=sys.stderr)
            return 1
        stego[r0:r1], _, _ = out
        tiles_data.append(stego[r0:r1].tobytes())

    embed_elapsed = time.perf_counter() - t_embed0
    print(f"[EMBED] Completed 32 tiles in {embed_elapsed:.3f}s (Argon2id KDF: {kdf_elapsed:.3f}s)")

    if a.save_stego:
        Image.fromarray(stego).save(a.save_stego)
        print(f"[SAVED] Stego PNG written to {a.save_stego}")

    # 8. Manifest output (NO secrets/keys in manifest!)
    if a.manifest:
        cover_hash = hashlib.sha256(cover.tobytes()).hexdigest()
        manifest_data = {
            "timestamp": time.time(),
            "git_commit": get_git_commit(),
            "python_version": platform.python_version(),
            "cover_sha256": cover_hash,
            "secret_len": len(secret_bytes),
            "salt_hex": salt.hex(),
            "transport_mode": a.mode,
            "pps": a.pps,
            "mtu_safe": a.mtu_safe,
            "profile": prof.to_dict(),
        }
        with open(a.manifest, "w", encoding="utf-8") as mf:
            json.dump(manifest_data, mf, indent=2)
        print(f"[MANIFEST] Run manifest written to {a.manifest}")

    # 9. Network Transmission via Sender
    host, port_str = a.dst.split(":")
    dst_addr = (host, int(port_str))
    sender = Sender(
        dst_addr,
        tiles_data,
        wire_key=real_keys["k_wire"],
        salt=salt,
        n=prof.n,
        k=prof.k,
        shard_len=prof.shard_bytes,
        ct_len=TOTAL_CIPHERTEXT_LEN,
        mode=a.mode,
        pps=a.pps,
        rto=a.rto,
        max_rounds=a.max_rounds,
        size=(512, 512),
        mtu_safe=a.mtu_safe,
        log=print,
    )

    print(f"[NET  ] Transmitting to {a.dst} via UDP (session={sender.sess:08x})...")
    status = sender.run()
    print(f"[NET  ] Transmission outcome: {status} (Total data packets sent: {sender.sent_data})")

    return 0 if "done" in status or status == "sent" else 4


if __name__ == "__main__":
    sys.exit(main())
