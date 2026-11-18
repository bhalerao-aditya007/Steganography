#!/usr/bin/env python3
"""One-click runner for the TESSERA v3 Live Terminal Demo:
Starts Bob Receiver, UDP Impairment Router (with 15% packet loss), and Alice Sender.
Demonstrates live RS(32,24) erasure recovery and ChaCha20-Poly1305 AEAD verification.
"""
import argparse
import os
import subprocess
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser(description="TESSERA v3 Live Demo Runner")
    parser.add_argument("--out-dir", default="results", help="Directory to save demo artifacts (default: results)")
    parser.add_argument("--loss", type=float, default=0.15, help="Router loss rate (default: 0.15)")
    parser.add_argument("--mode", default="hybrid", choices=["fec", "hybrid"], help="Transport mode (default: hybrid)")
    parser.add_argument("--secret", default="PROFESSOR EVALUATION: This confidential research secret survived real network packet loss via Reed-Solomon (32,24) and verified bit-exact via Poly1305!", help="Secret phrase")
    args = parser.parse_args()

    root_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(root_dir, ".venv", "Scripts", "python.exe")
    if not os.path.exists(venv_python):
        venv_python = sys.executable

    out_dir = os.path.join(root_dir, args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    env = os.environ.copy()
    env["PYTHONPATH"] = root_dir
    env["PYTHONUTF8"] = "1"
    env["TESSERA_DECOY"] = "sunshine123"
    env["TESSERA_REAL"] = "correct horse battery staple 9!"

    print("=" * 75, flush=True)
    print("      TESSERA v3: LIVE UDP RESEARCH DEMONSTRATION & RECOVERY RUNNER    ", flush=True)
    print("=" * 75, flush=True)

    pcap_path = os.path.join(out_dir, "capture.pcap")
    router_log_path = os.path.join(out_dir, "router_log.csv")
    received_stego_path = os.path.join(out_dir, "received_stego.png")
    stego_alice_path = os.path.join(out_dir, "stego_alice.png")
    bob_report_path = os.path.join(out_dir, "bob_report.json")
    manifest_path = os.path.join(out_dir, "run_manifest.json")

    # 1. Start Bob Receiver
    print("[1/3] Launching Bob Receiver on UDP :9999...", flush=True)
    bob_cmd = [
        venv_python,
        os.path.join(root_dir, "cli", "bob_receiver.py"),
        "--listen", "9999",
        "--mode", "auto",
        "--out", received_stego_path,
        "--report", bob_report_path,
        "--cover", os.path.join(root_dir, "covers", "textured_01.png"),
        "--full-image",
    ]
    bob_proc = subprocess.Popen(bob_cmd, env=env)
    time.sleep(0.3)

    # 2. Start Impairment Router
    print(f"[2/3] Launching UDP Impairment Router (:9998 -> :9999, loss={args.loss:.0%})...", flush=True)
    router_cmd = [
        venv_python,
        os.path.join(root_dir, "tools", "router_impair.py"),
        "--listen", "9998",
        "--to", "127.0.0.1:9999",
        "--loss", str(args.loss),
        "--seed", "7",
        "--log", router_log_path,
        "--pcap", pcap_path,
        "--idle", "1.5",
        "--duration", "15.0",
    ]
    router_proc = subprocess.Popen(router_cmd, env=env)
    time.sleep(0.3)

    # 3. Start Alice Sender
    print(f"[3/3] Launching Alice Sender (:9998, mode={args.mode})...", flush=True)
    alice_cmd = [
        venv_python,
        os.path.join(root_dir, "cli", "alice_sender.py"),
        "--dst", "127.0.0.1:9998",
        "--cover", os.path.join(root_dir, "covers", "textured_01.png"),
        "--mode", args.mode,
        "--secret", args.secret,
        "--save-stego", stego_alice_path,
        "--manifest", manifest_path,
    ]
    alice_proc = subprocess.Popen(alice_cmd, env=env)

    # Wait for processes
    alice_proc.wait()
    bob_proc.wait(timeout=10.0)

    try:
        router_proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        try:
            router_proc.terminate()
            router_proc.wait(timeout=1.0)
        except Exception:
            pass

    print("\n" + "=" * 75, flush=True)
    print("                      DEMONSTRATION RUN COMPLETE                       ", flush=True)
    print("=" * 75, flush=True)
    print(f"Artifacts Saved in {args.out_dir}:")
    print(f"  • Stego PNG (Alice)     : {stego_alice_path}")
    print(f"  • Received Stego (Bob)  : {received_stego_path}")
    print(f"  • Router Ground Truth   : {router_log_path}")
    print(f"  • Bob Evaluation Report : {bob_report_path}")
    print(f"  • Wire Traffic PCAP     : {pcap_path}")
    print(f"  • Run Manifest          : {manifest_path}")
    print("=" * 75, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
