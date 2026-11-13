"""Run all TESSERA verification tests, v3 network scenarios, and benchmarks with clean cross-platform execution."""
import os
import sys
import subprocess

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def run_cmd(name, cmd, env):
    print(f"\n>> Running: {name} ...", flush=True)
    res = subprocess.run(cmd, env=env)
    if res.returncode != 0:
        print(f"[FAIL] {name} exited with code {res.returncode}", flush=True)
        return False
    print(f"[PASS] {name} completed successfully.", flush=True)
    return True


def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.copy()
    env["PYTHONPATH"] = root_dir
    env["PYTHONUTF8"] = "1"

    print("=" * 70, flush=True)
    print("      TESSERA v3: COMPREHENSIVE VERIFICATION & BENCHMARK SUITE       ", flush=True)
    print("=" * 70, flush=True)

    pytest_exe = os.path.join(root_dir, ".venv", "Scripts", "pytest.exe")
    if not os.path.exists(pytest_exe):
        pytest_cmd = [sys.executable, "-m", "pytest"]
    else:
        pytest_cmd = [pytest_exe]

    test_steps = [
        # 1. Core v3 Unit Tests
        ("v3 Sign-Channel Lemma Verification", pytest_cmd + ["-v", "tests/test_lemma.py"]),
        ("v3 Wire Protocol v2 Pack/Unpack & Tags", pytest_cmd + ["-v", "tests/test_packet.py"]),
        ("v3 Column-Wise RS(32,24) & Errors/Erasures", pytest_cmd + ["-v", "tests/test_fec.py"]),
        ("v3 Crypto RFC 9106 & HKDF Domain Separation", pytest_cmd + ["-v", "tests/test_crypto.py"]),
        ("v3 Cover Image Gate Suitability Checks", pytest_cmd + ["-v", "tests/test_cover_gate.py"]),
        ("v3 Receiver Fuzzing & Total Function Robustness", pytest_cmd + ["-v", "tests/test_receiver_fuzz.py"]),

        # 2. Section 7.4 Six Impairment Network Scenarios
        ("v3 Network Scenarios (1-6) over UDP Impairment Router", pytest_cmd + ["-v", "tests/test_scenarios.py"]),

        # 3. Full System E2E v3 Test
        ("v3 Full System E2E Test (Alice -> Router -> Bob)", pytest_cmd + ["-v", "tests/test_e2e_v3.py"]),

        # 4. Legacy v2 Verification Suites
        ("v2 End-to-End Pipeline & Loss Recovery", [sys.executable, os.path.join(root_dir, "tests", "test_e2e.py")]),
        ("v2 Change-Set Equivalence & Sign Uniformity", [sys.executable, os.path.join(root_dir, "tests", "test_equivalence.py")]),
        ("v2 Honey Decoy DTE Plausibility", [sys.executable, os.path.join(root_dir, "tests", "test_honey.py")]),
        ("v2 Baselines Comparison (B0, B1, B4)", [sys.executable, os.path.join(root_dir, "tests", "test_baselines.py")]),

        # 5. Publication Figures
        ("v3 Publication Figure Generation", [sys.executable, os.path.join(root_dir, "eval", "plots.py")]),
    ]

    all_ok = True
    for name, cmd in test_steps:
        ok = run_cmd(name, cmd, env)
        if not ok:
            all_ok = False

    print("\n" + "=" * 70, flush=True)
    if all_ok:
        print("[SUCCESS] ALL TESSERA v3 TEST SUITES AND SCENARIOS PASSED PERFECTLY!", flush=True)
    else:
        print("[ERROR] SOME TESTS OR SCENARIOS ENCOUNTERED FAILURES.", flush=True)
    print("=" * 70, flush=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
