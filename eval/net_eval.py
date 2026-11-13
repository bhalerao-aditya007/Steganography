#!/usr/bin/env python3
"""TESSERA Network Transport Evaluation Harness:
Sweeps i.i.d. and burst impairments, measures completion rates for fec vs hybrid modes,
computes empirical Wilson 95% confidence intervals, and compares with analytical MDS curves.
"""
import argparse
import csv
import math
import os
import random
import sys
import time
from math import comb

# Ensure project root is on PYTHONPATH and UTF-8 console
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from tessera.net import packet as pk
from tessera.net import fec


def wilson_interval(successes: int, n: int, confidence: float = 0.95) -> tuple[float, float, float]:
    """Compute Wilson score interval for binomial proportion."""
    if n == 0:
        return 0.0, 0.0, 0.0
    z = 1.95996  # 95% confidence
    p_hat = successes / n
    denom = 1.0 + z * z / n
    center = (p_hat + z * z / (2.0 * n)) / denom
    margin = (z * math.sqrt((p_hat * (1.0 - p_hat) / n) + (z * z / (4.0 * n * n)))) / denom
    return p_hat, max(0.0, center - margin), min(1.0, center + margin)


def p_fail_analytic(n: int = 32, k: int = 24, p_loss: float = 0.1) -> float:
    """Theoretical probability of RS(n, k) decoder failure under i.i.d. tile loss."""
    return sum(comb(n, x) * (p_loss ** x) * ((1.0 - p_loss) ** (n - x)) for x in range(n - k + 1, n + 1))


def run_transport_trial(mode: str, p_loss: float, rng: random.Random) -> dict:
    """Run one loss recovery simulation trial with RS(32, 24) systematic coding."""
    n, k, P = 32, 24, 59
    secret_bytes = b"SECRET-NETWORK-BENCHMARK-PAYLOAD"
    ct = secret_bytes.ljust(k * P, b"\x00")
    shards = fec.encode(ct, P=P)

    t_start = time.perf_counter()
    received_shards = {}
    sent_count = 0

    # 1. First flight (32 tiles sent)
    for t_idx in range(n):
        sent_count += 1
        if rng.random() >= p_loss:
            idx, body = fec.parse_frame(shards[t_idx])
            received_shards[idx] = body

    nack_rounds = 0
    max_rounds = 8

    # 2. Closed-loop Hybrid ARQ repair rounds
    if mode == "hybrid":
        while len(received_shards) < k and nack_rounds < max_rounds:
            nack_rounds += 1
            missing = [i for i in range(n) if i not in received_shards]
            need = max(0, k - len(received_shards))
            margin = max(2, math.ceil(0.3 * need))
            send_count = min(len(missing), need + margin)
            send_repairs = missing[:send_count]

            for t_idx in send_repairs:
                sent_count += 1
                if rng.random() >= p_loss:
                    idx, body = fec.parse_frame(shards[t_idx])
                    received_shards[idx] = body

    success = False
    if len(received_shards) >= k:
        try:
            rec_ct = fec.decode(received_shards, P=P)
            if rec_ct == ct:
                success = True
        except Exception:
            success = False

    elapsed = time.perf_counter() - t_start
    return {
        "success": success,
        "valid_shards": len(received_shards),
        "sent_packets": sent_count,
        "nack_rounds": nack_rounds,
        "elapsed": elapsed,
    }


def main():
    p = argparse.ArgumentParser(description="TESSERA Network Transport Evaluation")
    p.add_argument("--trials-per-point", type=int, default=100, help="Number of trials per loss rate")
    p.add_argument("--out-csv", default="results/net_eval.csv", help="CSV output path")
    p.add_argument("--seed", type=int, default=123, help="RNG seed")
    a = p.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(a.out_csv)), exist_ok=True)
    loss_rates = [0.0, 0.02, 0.05, 0.08, 0.10, 0.12, 0.15, 0.20, 0.25, 0.30]

    print("=" * 70)
    print("      TESSERA v3 NETWORK BENCHMARK: LOSS SWEEPS & RECOVERY METRICS      ")
    print("=" * 70)
    print(f"Trials per point: {a.trials_per_point} | Code: RS(32, 24) | P_fail analytic overlay", flush=True)

    results = []
    rng = random.Random(a.seed)

    for mode in ["fec", "hybrid"]:
        print(f"\n[*] Evaluating Transport Mode: '{mode}'...", flush=True)
        for p_loss in loss_rates:
            succ = 0
            sent_total = 0
            nacks_total = 0
            times = []

            for _ in range(a.trials_per_point):
                res = run_transport_trial(mode, p_loss, rng)
                if res["success"]:
                    succ += 1
                sent_total += res["sent_packets"]
                nacks_total += res["nack_rounds"]
                times.append(res["elapsed"])

            rate, ci_lo, ci_hi = wilson_interval(succ, a.trials_per_point)
            p_fail_th = p_fail_analytic(32, 24, p_loss)
            p_succ_th = 1.0 - p_fail_th
            avg_sent = sent_total / a.trials_per_point
            avg_time = sum(times) / max(1, len(times))

            print(
                f"  loss={p_loss:4.1%} | Success: {rate:6.1%} [95% CI: {ci_lo:5.1%}-{ci_hi:5.1%}] | "
                f"Analytic: {p_succ_th:6.1%} | Packets: {avg_sent:4.1f} | Latency: {avg_time*1000:5.2f}ms",
                flush=True
            )

            results.append({
                "mode": mode,
                "p_loss": p_loss,
                "success_rate": rate,
                "ci_lo": ci_lo,
                "ci_hi": ci_hi,
                "analytic_success": p_succ_th,
                "avg_sent_packets": avg_sent,
                "repair_overhead": avg_sent / 32.0,
                "avg_time_ms": avg_time * 1000.0,
            })

    # Save to CSV
    with open(a.out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "mode", "p_loss", "success_rate", "ci_lo", "ci_hi",
            "analytic_success", "avg_sent_packets", "repair_overhead", "avg_time_ms"
        ])
        w.writeheader()
        w.writerows(results)

    print(f"\n[SUCCESS] Network evaluation results saved to {a.out_csv}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
