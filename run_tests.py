"""Run all TESSERA verification tests and benchmarks with clean cross-platform execution."""
import os
import sys
import subprocess

def run_test(name, script_path, env):
    print(f"\n>> Running: {name} ({script_path})...")
    cmd = [sys.executable, script_path]
    res = subprocess.run(cmd, env=env)
    if res.returncode != 0:
        print(f"[FAIL] {name} exited with code {res.returncode}")
        return False
    print(f"[PASS] {name} completed successfully.")
    return True

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.copy()
    env["PYTHONPATH"] = root_dir
    
    print("=" * 65)
    print("TESSERA v2: MIRAGE -- COMPLETE VERIFICATION TEST SUITE")
    print("=" * 65)
    
    tests = [
        ("End-to-End Pipeline & Loss Recovery", os.path.join(root_dir, "tests", "test_e2e.py")),
        ("Change-Set Equivalence & Sign Uniformity", os.path.join(root_dir, "tests", "test_equivalence.py")),
        ("Honey Decoy DTE Plausibility", os.path.join(root_dir, "tests", "test_honey.py")),
        ("Baselines Comparison (B0, B1, B4)", os.path.join(root_dir, "tests", "test_baselines.py")),
        ("Research Experimental Benchmarks (E0-E8)", os.path.join(root_dir, "tessera", "experiments", "benchmark.py")),
        ("Publication Figure Generation", os.path.join(root_dir, "tessera", "experiments", "make_figures.py")),
    ]
    
    all_ok = True
    for name, path in tests:
        ok = run_test(name, path, env)
        if not ok:
            all_ok = False
            
    print("\n" + "=" * 65)
    if all_ok:
        print("[SUCCESS] ALL TEST SUITES AND BENCHMARKS PASSED PERFECTLY!")
    else:
        print("[ERROR] SOME TESTS ENCOUNTERED FAILURES.")
    print("=" * 65)
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
