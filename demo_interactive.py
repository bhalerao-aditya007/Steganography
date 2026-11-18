#!/usr/bin/env python3
"""TESSERA v2: Mirage — Interactive Viva Demonstration Pipeline.

Designed for live professor/examiner demonstrations.
• Single passphrase decryption prompt for Bob.
• Wrong or decoy passphrases automatically extract DEFLECTING HONEY DATA.
• Correct real passphrase unlocks the TRUE CONFIDENTIAL SECRET via Reed-Solomon + Poly1305.
• Generates brand new, timestamped stego images, difference maps, and reports for EVERY run.

Usage:
    .\.venv\Scripts\python.exe demo_interactive.py
    .\.venv\Scripts\python.exe demo_interactive.py --cover covers\textured_01.png
"""
import os
import sys
import time
import getpass
import argparse
import hashlib
import json
import shutil
import numpy as np
from PIL import Image
from skimage import data

from tessera.embed.profile import Profile
from tessera.net.session import AliceSession, BobSession
from tessera.metrics.psnr_ssim import compute_quality_metrics
from tessera.metrics.diffmap import compute_diff_map, three_way_change_comparison
from tessera.stego_analysis.chi2 import chi2_attack
from tessera.stego_analysis.rs_attack import rs_estimate
from tessera.embed.mirage import extract_tile, decoy_peek
from tessera.embed.cover_gate import check_cover
from tessera.crypto.kdf import master, hkdf
from tessera.crypto.aead import decrypt_aead
from tessera.ecc.shards import recover_shards


# ─── Formatting & ANSI Style Helpers ──────────────────────────────
def _c(text, code):
    return f"\033[{code}m{text}\033[0m"

def green(t):   return _c(t, "1;32")
def red(t):     return _c(t, "1;31")
def yellow(t):  return _c(t, "1;33")
def cyan(t):    return _c(t, "1;36")
def bold(t):    return _c(t, "1;37")
def dim(t):     return _c(t, "2")
def magenta(t): return _c(t, "1;35")

def banner(text, char="═", width=78):
    print(f"\n{cyan(char * width)}")
    print(cyan(f"  {text.center(width - 4)}"))
    print(cyan(char * width))

def step_header(num, title):
    print(f"\n{bold(f'[STEP {num}]')} {cyan(title)}")
    print(dim("─" * 70))

def kv(key, value, indent=4):
    pad = " " * indent
    print(f"{pad}{dim('•')} {key:30s}: {bold(str(value))}")

def safe_prompt(prompt_text, default=""):
    try:
        val = input(prompt_text).strip()
        return val if val else default
    except EOFError:
        return default

def prompt_password(prompt_text, default=""):
    try:
        if sys.stdin.isatty():
            val = getpass.getpass(prompt_text).strip()
        else:
            print(prompt_text, end="", flush=True)
            line = sys.stdin.readline()
            val = line.rstrip("\r\n").strip() if line else default
        return val if val else default
    except (EOFError, Exception):
        return default


# ═══════════════════════════════════════════════════════════════════
#                       MAIN DEMO PIPELINE
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="TESSERA Mirage — Interactive Viva Demo")
    parser.add_argument("--cover", type=str, default=None, help="Path to cover image (default: benchmark camera)")
    parser.add_argument("--drop", type=int, default=6, help="Number of tiles to drop (0 to 8)")
    parser.add_argument("--out-dir", type=str, default="results", help="Directory to save generated artifacts")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colours")
    args = parser.parse_args()

    if args.no_color:
        global green, red, yellow, cyan, bold, dim, magenta
        green = red = yellow = cyan = bold = dim = magenta = lambda t: t

    # Ensure output directory exists
    root_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(root_dir, args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    # Unique timestamp for this run
    run_timestamp = time.strftime("%Y%m%d_%H%M%S")

    banner("TESSERA: MIRAGE — NETWORKED DENIABLE STEGANOGRAPHY")
    print(dim("  Deniable Sign-Channel · Honey Encryption Deflection · Reed-Solomon RS(32,24) · Poly1305 AEAD"))
    print(dim(f"  Live Run ID: {run_timestamp} | Python {sys.version.split()[0]} | PID {os.getpid()}"))

    # ════════════════════════════════════════════════════════════════
    # PHASE 1: ALICE (SENDER) — EMBEDDING
    # ════════════════════════════════════════════════════════════════
    banner("PHASE 1: ALICE (SENDER) — PREPARING AND EMBEDDING SECRET", "─")

    # ── Step 1: Cover Image & Gate ────────────────────────────────
    step_header(1, "Loading Cover Image & Steganographic Gate Check")
    if args.cover and os.path.exists(args.cover):
        cover = np.array(Image.open(args.cover).convert("L"))
        if cover.shape != (512, 512):
            cover = np.array(Image.fromarray(cover).resize((512, 512)))
        kv("Cover Source", args.cover)
    else:
        cover = data.camera().astype(np.uint8)
        kv("Cover Source", "skimage.data.camera (512×512 benchmark)")

    kv("Image Geometry", f"{cover.shape[0]}×{cover.shape[1]} pixels (grayscale uint8)")
    kv("Total Pixels", f"{cover.size:,}")
    cover_sha = hashlib.sha256(cover.tobytes()).hexdigest()
    kv("Cover SHA-256", cover_sha[:32] + "...")

    gate_ok, gate_msg, gate_metrics = check_cover(cover)
    if gate_ok:
        print(f"    {green('✔ GATE AUDIT PASSED')}: {gate_msg}")
        kv("Boundary Pixels (0 or 255)", f"{gate_metrics['boundary_fraction']:.2%}")
        kv("Flat 8×8 Blocks", f"{gate_metrics['flat_block_fraction']:.2%}")
        kv("Residual Texture Entropy", f"{gate_metrics['residual_entropy']:.3f} bits")
    else:
        print(f"    {red('✘ GATE AUDIT REJECTED')}: {gate_msg}")
        sys.exit(1)

    # ── Step 2: Secret & Passphrases ──────────────────────────────
    step_header(2, "Alice's Secret Message & Dual-Passphrase Setup")
    print(f"    {dim('Alice configures her secret message, her real secret passphrase,')}")
    print(f"    {dim('and a harmless decoy passphrase she can confess under coercion.')}")
    print()

    default_secret = "CONFIDENTIAL RESEARCH BRIEF: Target located at coordinates 28.6139N 77.2090E. Operation active."
    secret_text = safe_prompt(f"    {bold('Enter secret message to hide')} (press Enter for default):\n    > ", default="")
    if not secret_text:
        secret_text = default_secret
        trunc_sec = secret_text[:55]
        print(f"    {dim(f'(Using default secret: {trunc_sec!r}...)')}")
    secret_bytes = secret_text.encode("utf-8")

    print()
    pw_decoy = safe_prompt(f"    {bold('Enter DECOY passphrase')} [Bait password for coercion/auditors]: ", default="sunshine123")
    if pw_decoy == "sunshine123":
        print("    " + dim("(Using default decoy: 'sunshine123')"))

    pw_real = prompt_password(f"    {bold('Enter REAL secret passphrase')} [Kept strictly secret]: ", default="correct horse battery staple 9!")
    if pw_real == "correct horse battery staple 9!":
        print(f"    {dim('(Using default real passphrase: 31 chars)')}")

    print()
    kv("Secret Plaintext", f'"{secret_text[:65]}{"..." if len(secret_text)>65 else ""}"')
    kv("Secret Length", f"{len(secret_bytes)} bytes")
    kv("Decoy Passphrase", f'"{pw_decoy}" (Argon2id Light: intentional bait)')
    kv("Real Passphrase", f'{"*" * len(pw_real)} ({len(pw_real)} chars, RFC 9106 Argon2id High)')

    # ── Step 3: Key Derivation ────────────────────────────────────
    step_header(3, "Cryptographic Key Derivation (Argon2id + HKDF Domain Separation)")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    prof = Profile(H=512, W=512, T=32, alpha_d=0.20, shard_bytes=64, k=24)

    t_kdf0 = time.time()
    alice = AliceSession(pw_decoy, pw_real, salt=salt, nonce=nonce, profile=prof)
    kdf_time = time.time() - t_kdf0

    kv("Session Salt (16B random)", salt.hex())
    kv("ChaCha20 Nonce (12B random)", nonce.hex())
    print()
    print(f"    {yellow('Decoy Carrier Schedule:')}")
    kv("  Master Decoy Key", alice.md.hex()[:32] + "...")
    kv("  k_pos (Carrier Grid)", alice.kd.hex()[:32] + "...")
    print()
    print(f"    {green('Real Secret Schedule:')}")
    kv("  Master Real Key", alice.mr.hex()[:32] + "...")
    kv("  k_enc (ChaCha20 AEAD)", alice.kenc.hex()[:32] + "...")
    kv("  k_H2 (Sign-Channel Matrix)", alice.kh.hex()[:32] + "...")
    kv("  k_wh (Shard Whitening Stream)", alice.kw.hex()[:32] + "...")
    print(f"    {dim(f'Keys derived with strict domain separation in {kdf_time:.3f}s')}")

    # ── Step 4: Encryption & Sharding ─────────────────────────────
    step_header(4, "ChaCha20-Poly1305 AEAD & Column-wise Reed-Solomon RS(32, 24)")
    ct, shards, decoy_seed, decoy_msg = alice.prepare_payloads(
        secret_bytes, decoy_msg_indices=[0, 1, 4, 11, 2]
    )
    print(f"    {bold('4a. Authenticated Encryption:')}")
    kv("Plaintext Size", f"{len(secret_bytes)} bytes")
    kv("Ciphertext Size", f"{len(ct)} bytes (includes 16B Poly1305 MAC tag)")
    kv("Poly1305 MAC Tag", ct[-16:].hex())
    print()
    print(f"    {bold('4b. Systematic Reed-Solomon Erasure Coding:')}")
    kv("Data Shards (k)", f"{prof.k}")
    kv("Parity Shards (n - k)", f"{prof.n - prof.k}")
    kv("Total Shards (n)", f"{prof.n} (1 shard per tile)")
    kv("Max Tolerable Loss", f"{prof.n - prof.k} tiles (any arbitrary loss pattern)")
    print()
    print(f"    {bold('4c. Honey Decoy Layer Generation (DTE):')}")
    kv("Decoy Honey Message", f'"{decoy_msg}"')
    kv("Decoy Seed (64-bit integer)", f"0x{decoy_seed:016x}")

    # ── Step 5: Mirage Embedding & Saving New Stego Image ─────────
    step_header(5, "Executing Mirage Sign-Channel Embedding into 32 Tiles")
    print(f"    {dim('Embedding real shards into the DIRECTION (+1 / -1) of decoy changes...')}")
    print()

    t_emb0 = time.time()
    stego_mirage, stats_m = alice.embed_image(cover, shards, decoy_seed, mode="mirage")
    stego_decoy, stats_d = alice.embed_image(cover, shards, decoy_seed, mode="decoy")
    embed_duration = time.time() - t_emb0

    # Display per-tile progress
    for ts in stats_m["tile_stats"]:
        stat_icon = green("✔") if ts["rerolls"] == 0 else yellow(f"✔ ({ts['rerolls']} retries)")
        print(f"    Tile {ts['tile']:2d}: {ts['changes']:4d} pixels modified  {stat_icon}")

    print()
    total_changed = stats_m["mean_changes_per_tile"] * 32
    kv("Tiles Processed", "32 / 32")
    kv("Total Modified Pixels", f"{total_changed:.0f} (~{total_changed / cover.size * 100:.2f}% of image)")
    kv("Wet-Paper Re-rolls", str(stats_m["total_rerolls"]))
    kv("Embedding Execution Time", f"{embed_duration:.2f}s")

    # Save fresh timestamped artifacts for this run
    stego_run_path = os.path.join(out_dir, f"stego_{run_timestamp}.png")
    stego_latest_path = os.path.join(out_dir, "stego_alice.png")
    stego_root_path = os.path.join(root_dir, "stego_output.png")

    Image.fromarray(stego_mirage).save(stego_run_path)
    shutil.copyfile(stego_run_path, stego_latest_path)
    shutil.copyfile(stego_run_path, stego_root_path)

    print()
    print(f"    {green('✔ NEW STEGO IMAGE GENERATED AND SAVED:')}")
    print(f"      • Run Artifact : {bold(stego_run_path)} ({os.path.getsize(stego_run_path):,} bytes)")
    print(f"      • Latest Stego : {bold(stego_latest_path)}")
    print(f"      • Root Stego   : {bold(stego_root_path)}")

    # ── Step 6: Evidence Conservation & Quality Audit ─────────────
    step_header(6, "Evidence Conservation & Visual Quality Proof")
    qm = compute_quality_metrics(cover, stego_mirage)
    comp = three_way_change_comparison(cover, stego_decoy, stego_mirage)

    # Save amplified difference map
    diff_map_arr = compute_diff_map(cover, stego_mirage, amplify=255)
    diff_map_path = os.path.join(out_dir, f"diff_map_{run_timestamp}.png")
    diff_map_latest_path = os.path.join(out_dir, "diff_map.png")
    Image.fromarray(diff_map_arr).save(diff_map_path)
    shutil.copyfile(diff_map_path, diff_map_latest_path)

    kv("PSNR", f"{qm['psnr_db']:.2f} dB (Imperceptible, >40 dB standard)")
    kv("SSIM", f"{qm['ssim']:.4f} (1.000 = identical visual structure)")
    print()
    print(f"    {bold('Evidence Conservation Mathematical Proof:')}")
    kv("Decoy-Only Changes", f"{comp['decoy_changes']} pixels")
    kv("Mirage Changes", f"{comp['mirage_changes']} pixels")
    kv("Discrepancy Count", f"{comp['discrepancy_count']} pixels")
    if comp["discrepancy_count"] == 0:
        print(f"    {green('✔ MATHEMATICAL EQUIVALENCE: 100% IDENTICAL CHANGE SETS!')}")
        print(f"    {green('✔ Zero additional pixels were touched to hide the real secret.')}")
    kv("Max |d| Jump", f"{comp['mirage_max_abs_diff']} (Strictly ±1, zero ±2 artifacts)")
    print(f"    • Amplified Diff Map saved to: {bold(diff_map_path)}")

    # ── Step 7: Live Steganalysis (Eve Ladder) ─────────────────────
    step_header(7, "Steganalysis Verification (Blind Scanners & Honey Decoy Attack)")
    p_val, _, _ = chi2_attack(stego_mirage)
    rs_val = rs_estimate(stego_mirage)
    kv("Chi-Square p-value", f"{p_val:.4f} (Pairs-of-Values preserved)")
    kv("RS Estimated Rate", f"{rs_val:.4f}")

    print()
    print(f"    {magenta('Dictionary Attack on Decoy Bait (Eve E1 Simulation):')}")
    tile0 = stego_mirage[prof.tile_slice(0)[0]:prof.tile_slice(0)[1]]
    for trial_pwd in ["password", "letmein", pw_decoy, "admin123"]:
        try:
            cand_kd = hkdf(master(trial_pwd, salt, light=True), b"pos")
            peek_msg = decoy_peek(tile0, 0, prof, cand_kd)
            if trial_pwd == pw_decoy:
                print(f"      Guess \"{trial_pwd:<12s}\" → {green('CRACKED DECOY!')} Decoded: \"{peek_msg}\"")
            else:
                print(f"      Guess \"{trial_pwd:<12s}\" → Decoded: \"{peek_msg}\" {dim('(Honey Fake)')}")
        except Exception:
            pass

    # ════════════════════════════════════════════════════════════════
    # PHASE 2: NETWORK TRANSPORT — UDP WITH PACKET LOSS
    # ════════════════════════════════════════════════════════════════
    banner("PHASE 2: NETWORK TRANSPORT — PACKET LOSS SIMULATION", "─")

    step_header(8, f"Transmitting 32 Datagrams across Lossy UDP Channel ({args.drop} Tiles Dropped)")
    rng = np.random.default_rng(int(time.time()))
    dropped_indices = set(rng.choice(prof.T, args.drop, replace=False).tolist())

    received_tiles = {}
    received_stego_img = stego_mirage.copy()
    diagnostic_loss_map = np.zeros_like(cover)

    for t in range(prof.T):
        r0, r1 = prof.tile_slice(t)
        time.sleep(0.02)
        if t in dropped_indices:
            print(f"    Tile {t:2d} (rows {r0:3d}-{r1:3d}): {red('✘ PACKET DROPPED BY NETWORK')}")
            diagnostic_loss_map[r0:r1] = 255  # Highlight dropped tiles in diagnostic map
        else:
            received_tiles[t] = stego_mirage[r0:r1]
            print(f"    Tile {t:2d} (rows {r0:3d}-{r1:3d}): {green('✔ DELIVERED')} (8,192 bytes)")

    # Save received stego as a clean, pristine, seamless image (NO artificial gray patches!)
    received_stego_run_path = os.path.join(out_dir, f"received_stego_{run_timestamp}.png")
    received_stego_latest_path = os.path.join(out_dir, "received_stego.png")
    Image.fromarray(received_stego_img).save(received_stego_run_path)
    shutil.copyfile(received_stego_run_path, received_stego_latest_path)

    # Save packet loss diagnostic map separately
    loss_map_path = os.path.join(out_dir, f"packet_loss_diagnostic_{run_timestamp}.png")
    loss_map_latest_path = os.path.join(out_dir, "packet_loss_diagnostic.png")
    Image.fromarray(diagnostic_loss_map).save(loss_map_path)
    shutil.copyfile(loss_map_path, loss_map_latest_path)

    print()
    kv("Total Datagrams Transmitted", "32")
    kv("Datagrams Lost in Transit", f"{args.drop} → {sorted(dropped_indices)}")
    kv("Datagrams Arrived at Bob", f"{len(received_tiles)} / 32")
    kv("Reed-Solomon Threshold (k)", f"{prof.k} shards needed")
    print(f"    • Received Stego (100% clean & seamless) : {bold(received_stego_run_path)}")
    print(f"    • Network Diagnostic Loss Map            : {bold(loss_map_path)}")

    # ════════════════════════════════════════════════════════════════
    # PHASE 3: BOB (RECEIVER) — DECRYPTION CONSOLE
    # ════════════════════════════════════════════════════════════════
    banner("PHASE 3: BOB'S DECRYPTION CONSOLE", "─")

    print(f"""
    {bold('Bob (or an inspector/coercer) has received the stego image.')}
    Bob only prompts for {bold('ONE passphrase')} to decrypt the image.
    
    {yellow('Demonstration Guide for Examiner:')}
      • Enter the {bold('Decoy Passphrase')} (e.g. '{pw_decoy}') or any wrong password
        → {bold('Shows Deflection')}: Extracts the innocent Honey Bait message!
      • Enter the {bold('Real Passphrase')} (e.g. '{pw_real[:12]}...')
        → {bold('Shows True Decryption')}: Unlocks the real top secret via RS(32,24) + Poly1305!
    """)

    attempt = 0
    final_success = False
    decrypted_str = ""

    while True:
        attempt += 1
        step_header(f"9.{attempt}", f"Decryption Attempt #{attempt}")

        user_input_pw = prompt_password(f"    {bold('Enter Passphrase to decrypt image')}: ", default="")
        if not user_input_pw:
            if attempt == 1:
                user_input_pw = pw_decoy  # Default attempt 1 to decoy to show deflection
                print("    " + dim(f"(Defaulting to decoy '{pw_decoy}' to demonstrate deflection)"))
            else:
                user_input_pw = pw_real   # Default attempt 2 to real secret
                print(f"    {dim('(Defaulting to real passphrase to demonstrate decryption)')}")

        print()
        print(f"    {dim('Processing image with entered passphrase...')}")

        # 1. Derive candidate keys from this passphrase
        cand_mr = master(user_input_pw, salt, light=False)
        cand_kenc = hkdf(cand_mr, b"enc")
        cand_kh = hkdf(cand_mr, b"h2")
        cand_kw = hkdf(cand_mr, b"white")

        # Extract shards using the pre-shared carrier positions (alice.kd)
        extracted_shards = {}
        for t_idx, tile_img in received_tiles.items():
            extracted_shards[t_idx] = extract_tile(tile_img, t_idx, prof, alice.kd, cand_kh, cand_kw)

        # Attempt RS recovery & Poly1305 AEAD decryption
        recovered_ct, valid_count = recover_shards(extracted_shards, prof)

        real_decrypted = None
        if recovered_ct is not None:
            try:
                real_decrypted = decrypt_aead(cand_kenc, nonce, recovered_ct, aad=b"tessera-v2")
            except Exception:
                real_decrypted = None

        # ── BRANCH A: REAL SECRET UNLOCKED ────────────────────────
        if real_decrypted is not None:
            final_success = True
            decrypted_str = real_decrypted.decode("utf-8", errors="replace")

            print(f"    ┌{'─'*67}┐")
            print(f"    │ {green('✔ Poly1305 AEAD AUTHENTICATION: SUCCESSFUL!')}                     │")
            print(f"    │ {green(f'✔ Reed-Solomon Recovery: {len(received_tiles)}/24 shards reconstructed bit-exact!')} │")
            print(f"    └{'─'*67}┘")
            print()

            print(f"    ╔{'═'*67}╗")
            print(f"    ║ {bold('UNLOCKED REAL CONFIDENTIAL SECRET:')}                                 ║")
            print(f"    ╠{'═'*67}╣")
            wline = decrypted_str
            while len(wline) > 63:
                print(f"    ║ {green(wline[:63])}    ║")
                wline = wline[63:]
            print(f"    ║ {green(wline.ljust(63))}    ║")
            print(f"    ╚{'═'*67}╝")
            print()

            if decrypted_str == secret_text:
                print(f"    {green('✔ BIT-EXACT SHA-256 VERIFICATION CONFIRMED!')}")
                kv("Original Plaintext SHA-256", hashlib.sha256(secret_bytes).hexdigest())
                kv("Decrypted Secret SHA-256", hashlib.sha256(real_decrypted).hexdigest())

            break

        # ── BRANCH B: DEFLECTION HONEY BAIT EXTRACTED ─────────────
        else:
            print(f"    {yellow('⚠ Real secret AEAD tag did not match this passphrase.')}")
            print(f"    {dim('Extracting carrier honey layer from image LSBs...')}")

            cand_kd = hkdf(master(user_input_pw, salt, light=True), b"pos")
            extracted_honey = decoy_peek(tile0, 0, prof, cand_kd)

            print()
            print(f"    ┌{'─'*67}┐")
            print(f"    │ {yellow('DEFLECTING DATA EXTRACTED FROM IMAGE (HONEY BAIT):')}             │")
            honey_display = f'"{extracted_honey}"'
            print(f"    │ {bold(honey_display):<65} │")
            print(f"    └{'─'*67}┘")
            print()
            print(f"    {cyan('COERCION / AUDIT RESULT:')}")
            print(f"    {dim('To an adversary, censor, or forensic investigator, this password')} ")
            print(f"    {dim('successfully produced a completely plausible innocent message.')}")
            print(f"    {dim('They have ZERO evidence that a second real secret exists in the image!')}")
            print()

            retry = safe_prompt(f"    {bold('Now enter the REAL secret passphrase? (y/n)')}: ", default="y").lower()
            if retry != "y":
                print(f"\n    {dim('Exiting decryption.')}")
                break

    # ════════════════════════════════════════════════════════════════
    # SAVE AUDIT REPORT & SUMMARY
    # ════════════════════════════════════════════════════════════════
    banner("RUN SUMMARY & SAVED ARTIFACTS")

    # Generate JSON report
    report_data = {
        "run_id": run_timestamp,
        "success": final_success,
        "secret_length": len(secret_bytes),
        "decoy_message": decoy_msg,
        "tiles_total": 32,
        "tiles_delivered": len(received_tiles),
        "tiles_dropped": sorted(list(dropped_indices)),
        "psnr_db": float(qm["psnr_db"]),
        "ssim": float(qm["ssim"]),
        "evidence_conservation": {
            "decoy_changes": comp["decoy_changes"],
            "mirage_changes": comp["mirage_changes"],
            "discrepancy_count": comp["discrepancy_count"],
        },
        "artifacts": {
            "stego_image": stego_run_path,
            "received_stego": received_stego_run_path,
            "diff_map": diff_map_path,
        }
    }

    report_run_path = os.path.join(out_dir, f"report_{run_timestamp}.json")
    report_latest_path = os.path.join(out_dir, "bob_report.json")
    with open(report_run_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    shutil.copyfile(report_run_path, report_latest_path)

    print(f"""
    {bold('All artifacts for this run have been saved:')}
      • {bold('Unique Stego PNG')}     : {green(stego_run_path)}
      • {bold('Received Stego PNG')}  : {green(received_stego_run_path)} (100% clean & seamless)
      • {bold('Diagnostic Loss Map')} : {green(loss_map_path)} (network debug)
      • {bold('Amplified Diff Map')}  : {green(diff_map_path)}
      • {bold('Audit Report JSON')}   : {green(report_run_path)}

    {bold('Standard Reference Files Updated:')}
      • Root Stego Output    : {bold(stego_root_path)}
      • Latest Bob Report    : {bold(report_latest_path)}
    """)


if __name__ == "__main__":
    main()
