#!/usr/bin/env python3
"""TESSERA Bob Receiver CLI:
Listens on UDP socket, parses TESSERA v2 wire datagrams, verifies keyed BLAKE2s tags,
extracts shards from received tiles via Mirage, decodes column-wise RS(32,24) erasures,
verifies ChaCha20-Poly1305 AEAD tag, and presents live audience-facing progress.
"""
import argparse
import getpass
import hashlib
import json
import os
import socket
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
from tessera.crypto.kdf import derive_keys_v3_real, derive_keys_v3_decoy
from tessera.crypto.aead import decrypt_v3, make_v3_aad, TOTAL_CIPHERTEXT_LEN
from tessera.embed.mirage import extract_tile
from tessera.net import fec
from tessera.net import packet as pk
from tessera.net.transport import udp_socket, F_FRAG


def main():
    p = argparse.ArgumentParser(description="TESSERA v3 Bob Receiver")
    p.add_argument("--listen", type=int, default=9999, help="UDP listening port")
    p.add_argument("--mode", default="auto", help="Mode auto-detected from SYN (fec or hybrid)")
    p.add_argument("--out", default="results/received_stego.png", help="Path to save reconstructed stego PNG")
    p.add_argument("--idle", type=float, default=0.4, help="Idle timeout to trigger reconstruction")
    p.add_argument("--total-timeout", type=float, default=20.0, help="Total session timeout in seconds")
    p.add_argument("--max-nacks", type=int, default=8, help="Max repair rounds in hybrid mode")
    p.add_argument("--decoy-pass-env", default="TESSERA_DECOY", help="Env var name for decoy passphrase")
    p.add_argument("--real-pass-env", default="TESSERA_REAL", help="Env var name for real passphrase")
    p.add_argument("--save-shards", default=None, help="Save extracted shards to JSON file")
    p.add_argument("--report", default="results/bob_report.json", help="Path to write final audit report")
    p.add_argument("--cover", default=None, help="Optional cover image path to restore natural background for dropped network tiles")
    p.add_argument("--full-image", action="store_true", help="In hybrid mode, request repairs until all 32 tiles are received")
    p.add_argument("--save-drop-map", default=None, help="Save diagnostic packet loss map showing dropped tile positions")

    a = p.parse_args()

    # Passphrase retrieval (Never from argv!)
    pw_decoy = os.environ.get(a.decoy_pass_env)
    if not pw_decoy:
        pw_decoy = getpass.getpass("Enter Decoy Passphrase: ")
    pw_real = os.environ.get(a.real_pass_env)
    if not pw_real:
        pw_real = getpass.getpass("Enter Real Secret Passphrase: ")

    sock = udp_socket(("0.0.0.0", a.listen))
    print(f"[*] Bob Receiver listening on UDP 0.0.0.0:{a.listen} (SO_RCVBUF=4MB)")

    prof = Profile(H=512, W=512, T=32, alpha_d=0.157, shard_bytes=64, k=24, v3=True)
    real_keys = None
    decoy_keys = None
    session_id = None
    peer_addr = None
    mode_hybrid = False
    seq_out = 0

    def _tx(typ: int, payload: bytes = b""):
        nonlocal seq_out
        seq_out += 1
        wire_key = real_keys["k_wire"] if real_keys else None
        pkt = pk.pack(typ, session_id or 0, seq_out, 0, 0, payload, wire_key)
        if peer_addr:
            sock.sendto(pkt, peer_addr)

    shards = {}           # inner_idx -> body (59B)
    tile_images = {}      # tile_idx -> tile uint8 array
    tile_fragments = {}   # tile_idx -> dict(frag_idx -> bytes)
    frags_per_tile = 1
    stats = dict(rx=0, bad_tag=0, bad_syn=0, bad_shard=0, dup=0, nacks=0, seq_gaps=[])

    last_derive = -1e9
    last_rx = time.perf_counter()
    t_start = time.perf_counter()
    rounds = 0
    last_seq = -1
    decrypted_secret = None
    exit_code = 5

    try:
        while time.perf_counter() - t_start < a.total_timeout:
            sock.settimeout(0.05)
            try:
                d, addr = sock.recvfrom(65535)
            except socket.timeout:
                d = None
            except (ConnectionResetError, OSError):
                continue

            now = time.perf_counter()
            trigger = False

            if d:
                p_unp = pk.unpack(d)
                if p_unp:
                    stats["rx"] += 1
                    seq = p_unp["seq"]

                    # Track sequence gaps
                    if last_seq >= 0 and seq > last_seq + 1:
                        gap_info = (last_seq, seq)
                        stats["seq_gaps"].append(gap_info)
                        print(f"[DATA] tile {p_unp['tile']:02d}  \033[33m── missing (seq gap {last_seq}→{seq}) ──\033[0m")
                    last_seq = seq

                    # 1. SYN processing
                    if p_unp["type"] == pk.SYN and session_id is None:
                        if len(p_unp["payload"]) < pk.SYN_BODY.size or (now - last_derive < 0.2):
                            stats["bad_syn"] += 1
                        else:
                            last_derive = now
                            salt, n, k, sl, hyb, frags, w, h, ctl = pk.SYN_BODY.unpack(p_unp["payload"][:pk.SYN_BODY.size])
                            if not (1 <= k < n <= 64 and 1 <= sl <= 255):
                                stats["bad_syn"] += 1
                            else:
                                t_kdf = time.perf_counter()
                                real_keys = derive_keys_v3_real(pw_real, salt)
                                decoy_keys = derive_keys_v3_decoy(pw_decoy, salt)
                                kdf_time = time.perf_counter() - t_kdf

                                if pk.verify(p_unp, real_keys["k_wire"]):
                                    session_id = p_unp["session"]
                                    peer_addr = addr
                                    mode_hybrid = bool(hyb)
                                    prof.k = k
                                    prof.n = n
                                    prof.shard_bytes = sl
                                    prof.payload = sl - 5
                                    frags_per_tile = max(1, frags)
                                    last_rx = now
                                    mode_str = "hybrid" if mode_hybrid else "fec"
                                    print(f"[SYN ] session={session_id:08x} salt={salt.hex()[:16]}... mode={mode_str}  derived keys in {kdf_time:.2f} s")
                                    if mode_hybrid:
                                        _tx(pk.SYN_ACK)
                                else:
                                    stats["bad_tag"] += 1

                    # 2. Existing session packet processing
                    elif session_id is not None and p_unp["session"] == session_id:
                        if p_unp["type"] == pk.SYN and mode_hybrid:
                            _tx(pk.SYN_ACK)
                        elif not pk.verify(p_unp, real_keys["k_wire"]):
                            stats["bad_tag"] += 1
                        elif p_unp["type"] == pk.DATA:
                            last_rx = now
                            t_idx = p_unp["tile"]
                            payload = p_unp["payload"]

                            # Assemble fragments if MTU-safe fragmentation enabled
                            if p_unp["flags"] & F_FRAG:
                                if t_idx not in tile_fragments:
                                    tile_fragments[t_idx] = {}
                                tile_fragments[t_idx][p_unp["frag"]] = payload
                                if len(tile_fragments[t_idx]) >= frags_per_tile:
                                    sorted_f = [tile_fragments[t_idx][i] for i in sorted(tile_fragments[t_idx])]
                                    tile_bytes = b"".join(sorted_f)
                                else:
                                    tile_bytes = None
                            else:
                                tile_bytes = payload

                            if tile_bytes is not None:
                                tile_arr = np.frombuffer(tile_bytes, dtype=np.uint8).reshape((prof.rows, prof.W))
                                tile_images[t_idx] = tile_arr

                                # Extract shard from tile
                                raw_shard = extract_tile(
                                    tile_arr,
                                    t_idx,
                                    prof,
                                    decoy_keys["k_pos"],
                                    real_keys["k_H2"],
                                    real_keys["k_wh"],
                                )
                                parsed = fec.parse_frame(raw_shard)
                                if parsed is not None:
                                    inner_idx, body = parsed
                                    if inner_idx in shards:
                                        stats["dup"] += 1
                                    else:
                                        shards[inner_idx] = body
                                        print(f"[DATA] tile {t_idx:02d} ok  seq={seq:03d}  tag \033[32m✔\033[0m  shard idx={inner_idx:02d} \033[32m✔\033[0m")
                                else:
                                    stats["bad_shard"] += 1

                            # Display visual progress bar
                            bar = "".join("■" if i in shards else "□" for i in range(prof.n))
                            print(f"\r[PROG] {bar} {len(shards)}/{prof.n}", end="", flush=True)

                        elif p_unp["type"] == pk.FIN:
                            print()
                            print(f"[FIN ] stream end. valid shards={len(shards)} (need ≥{prof.k})")
                            trigger = True

            elif session_id is not None and shards and (now - last_rx > a.idle):
                print()
                print(f"[IDLE] silence timeout ({a.idle}s). evaluating {len(shards)} shards...")
                trigger = True
                last_rx = now

            if trigger:
                target_count = prof.n if (a.full_image and mode_hybrid) else prof.k
                if len(shards) >= target_count:
                    # Attempt RS decoding and Poly1305 AEAD decryption
                    missing_indices = [i for i in range(prof.n) if i not in shards]
                    print(f"[RS  ] erasures at idx {missing_indices} → decoding {prof.payload} columns...", end="", flush=True)
                    try:
                        ct = fec.decode(shards, P=prof.payload)
                        print(" \033[32mok\033[0m")
                        aad = make_v3_aad(salt, n=prof.n, k=prof.k, shard_len=prof.shard_bytes, ct_len=TOTAL_CIPHERTEXT_LEN)
                        pt = decrypt_v3(real_keys["k_enc"], ct, aad)
                        print(f"[AEAD] Poly1305 tag \033[32m✔\033[0m   → \"\033[1;32m{pt.decode('utf-8', errors='replace')}\033[0m\"")
                        decrypted_secret = pt
                        exit_code = 0
                        if mode_hybrid:
                            for _ in range(3):
                                _tx(pk.DONE)
                        break
                    except Exception as e:
                        print(f" \033[31mfailed\033[0m: {e}")
                        exit_code = 3

                if not mode_hybrid:
                    print(f"[FAIL] fec mode: insufficient shards ({len(shards)}/{prof.k}). Failing closed.")
                    exit_code = 2
                    break

                if rounds >= a.max_nacks:
                    # If we have at least k shards, we can still recover the secret even if full-image wasn't 100% complete
                    if len(shards) >= prof.k:
                        missing_indices = [i for i in range(prof.n) if i not in shards]
                        print(f"[RS  ] Max rounds reached; decoding held shards ({len(shards)}/{prof.k})...", end="", flush=True)
                        try:
                            ct = fec.decode(shards, P=prof.payload)
                            print(" \033[32mok\033[0m")
                            aad = make_v3_aad(salt, n=prof.n, k=prof.k, shard_len=prof.shard_bytes, ct_len=TOTAL_CIPHERTEXT_LEN)
                            pt = decrypt_v3(real_keys["k_enc"], ct, aad)
                            print(f"[AEAD] Poly1305 tag \033[32m✔\033[0m   → \"\033[1;32m{pt.decode('utf-8', errors='replace')}\033[0m\"")
                            decrypted_secret = pt
                            exit_code = 0
                            for _ in range(3):
                                _tx(pk.DONE)
                            break
                        except Exception as e:
                            print(f" \033[31mfailed\033[0m: {e}")
                            exit_code = 3
                            break
                    print(f"[FAIL] Max ARQ repair rounds ({a.max_nacks}) exhausted.")
                    exit_code = 2
                    break

                # Send NACK for missing shards
                bitmap = sum(1 << i for i in shards)
                rounds += 1
                stats["nacks"] += 1
                print(f"[NACK] Round {rounds}: requesting repairs for missing tiles (held={len(shards)}/{target_count})...")
                _tx(pk.NACK, pk.NACK_BODY.pack(bitmap, len(shards), rounds))

    except KeyboardInterrupt:
        print("\n[ABORT] Interrupted by user.")
    finally:
        sock.close()

    # Reconstruct stego image
    # If a cover image is provided or default cover exists, use it as the canvas
    # so any lost UDP packets seamlessly retain the natural image texture (delta <= 1 to stego)
    cover_path = a.cover
    if not cover_path and os.path.exists("covers/textured_01.png"):
        cover_path = "covers/textured_01.png"

    if cover_path and os.path.exists(cover_path):
        full_img = np.array(Image.open(cover_path).convert("L"))
    else:
        full_img = np.full((512, 512), 128, dtype=np.uint8)

    for t_idx, tile_arr in tile_images.items():
        r0, r1 = prof.tile_slice(t_idx)
        full_img[r0:r1] = tile_arr

    # If no cover was provided and some tiles were dropped, smoothly interpolate
    # boundaries across missing tile rows instead of leaving raw gray bars
    if not (cover_path and os.path.exists(cover_path)) and len(tile_images) < prof.n:
        for t_idx in range(prof.n):
            if t_idx not in tile_images:
                r0, r1 = prof.tile_slice(t_idx)
                top = full_img[max(0, r0 - 1)].astype(float)
                bot = full_img[min(511, r1)].astype(float)
                for r in range(r0, r1):
                    w = (r - r0 + 1) / (r1 - r0 + 1)
                    full_img[r] = np.clip((1 - w) * top + w * bot, 0, 255).astype(np.uint8)

    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        Image.fromarray(full_img).save(a.out)
        print(f"[IMAGE] Reconstructed stego saved to {a.out} ({len(tile_images)}/32 tiles rendered from wire)")

    # Save packet loss diagnostic drop map if missing tiles exist
    if a.save_drop_map or (len(tile_images) < prof.n and a.out):
        drop_map_path = a.save_drop_map or a.out.replace(".png", "_drop_map.png")
        drop_vis = full_img.copy()
        for t_idx in range(prof.n):
            if t_idx not in tile_images:
                r0, r1 = prof.tile_slice(t_idx)
                # Show drop visualization stripe (value 128)
                drop_vis[r0:r1] = 128
        os.makedirs(os.path.dirname(os.path.abspath(drop_map_path)), exist_ok=True)
        Image.fromarray(drop_vis).save(drop_map_path)

    # Save raw shards if requested
    if a.save_shards:
        os.makedirs(os.path.dirname(os.path.abspath(a.save_shards)), exist_ok=True)
        shards_dump = {str(k): v.hex() for k, v in shards.items()}
        with open(a.save_shards, "w", encoding="utf-8") as sf:
            json.dump(shards_dump, sf, indent=2)

    # Machine-readable report output
    if a.report:
        os.makedirs(os.path.dirname(os.path.abspath(a.report)), exist_ok=True)
        report_data = {
            "success": (exit_code == 0),
            "exit_code": exit_code,
            "session_id": f"{session_id:08x}" if session_id else None,
            "valid_shards_count": len(shards),
            "required_shards_count": prof.k,
            "missing_indices": [i for i in range(prof.n) if i not in shards],
            "stats": stats,
            "secret_sha256": hashlib.sha256(decrypted_secret).hexdigest() if decrypted_secret else None,
            "decrypted_secret_len": len(decrypted_secret) if decrypted_secret else 0,
            "rounds_executed": rounds,
        }
        with open(a.report, "w", encoding="utf-8") as rf:
            json.dump(report_data, rf, indent=2)
        print(f"[REPORT] Audit report written to {a.report}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
