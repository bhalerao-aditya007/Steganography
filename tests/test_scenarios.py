"""Integration test suite for the six formal impairment scenarios from Section 7.4 of the Upgrade Guide:
  Scenario 1: 8 forced drops, fec mode -> Recovered, bit-exact
  Scenario 2: 9 forced drops, fec mode -> Failed closed, no plaintext
  Scenario 3: 10 forced drops, hybrid mode -> Recovered, bit-exact via NACK
  Scenario 4: 30% forward loss + 20% reverse loss, hybrid mode -> Recovered, bit-exact
  Scenario 5: Gilbert-Elliott bursts, hybrid mode -> Recovered, bit-exact
  Scenario 6: Jitter + 10% dup + 10% corrupt, hybrid mode -> Recovered, bit-exact
"""
import os
import random
import subprocess
import sys
import threading
import time
import pytest

from tessera.crypto.kdf import derive_keys_v3_real, derive_keys_v3_decoy
from tessera.crypto.aead import encrypt_v3, decrypt_v3, make_v3_aad, TOTAL_CIPHERTEXT_LEN
from tessera.net import fec
from tessera.net import packet as pk
from tessera.net.transport import Sender, Receiver


def run_scenario(
    scenario_name: str,
    mode: str,
    router_args: list[str],
    secret_text: bytes = b"CONFIDENTIAL SCENARIO VERIFICATION SECRET",
    rto: float = 0.2,
) -> tuple[bool, bytes | None, dict]:
    """Execute end-to-end Alice -> Router -> Bob scenario test."""
    port_alice = 12000 + random.randint(100, 5000)
    port_bob = port_alice + 1

    salt = os.urandom(16)
    pw_real = "correct horse battery staple 9!"
    real_keys = derive_keys_v3_real(pw_real, salt)
    aad = make_v3_aad(salt)

    # Prepare payload & shards
    ct = encrypt_v3(real_keys["k_enc"], secret_text, aad)
    shards = fec.encode(ct, P=fec.DEFAULT_P)
    tiles = [s + b"\x00" * (8192 - len(s)) for s in shards]

    # Spawn router subprocess
    router_script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools", "router_impair.py"))
    cmd = [
        sys.executable,
        router_script,
        "--listen", str(port_alice),
        "--to", f"127.0.0.1:{port_bob}",
        "--duration", "5.0",
    ] + router_args
    router_proc = subprocess.Popen(cmd)
    time.sleep(0.2)

    # Bob Receiver setup
    def derive_key(s):
        return derive_keys_v3_real(pw_real, s)["k_wire"]

    def extract(tile_data, tile_idx):
        return fec.parse_frame(tile_data[:64])

    def decode(sh):
        raw_ct = fec.decode(sh, P=fec.DEFAULT_P)
        return decrypt_v3(real_keys["k_enc"], raw_ct, aad)

    receiver = Receiver(
        port_bob,
        derive_key,
        extract,
        decode,
        idle=0.25,
        total_timeout=4.0,
        max_nacks=5,
    )

    bob_result = []

    def bob_thread():
        res = receiver.run()
        bob_result.append(res)

    t_bob = threading.Thread(target=bob_thread, daemon=True)
    t_bob.start()
    time.sleep(0.05)

    # Alice Sender setup
    sender = Sender(
        ("127.0.0.1", port_alice),
        tiles,
        wire_key=real_keys["k_wire"],
        salt=salt,
        mode=mode,
        pps=800,
        rto=rto,
        max_rounds=5,
    )
    sender.run()

    t_bob.join(timeout=4.5)
    try:
        router_proc.terminate()
        router_proc.wait(timeout=1.0)
    except Exception:
        pass

    assert len(bob_result) == 1, f"Bob did not complete in {scenario_name}"
    return bob_result[0]


def test_scenario_1_eight_forced_drops():
    """Scenario 1: 8 forced drops in fec mode -> Recovered, bit-exact."""
    # Drop tiles at arrival indices 5, 8, 12, 15, 19, 23, 27, 30
    drop_indices = "5,8,12,15,19,23,27,30"
    success, pt, stats = run_scenario("Scenario 1", "fec", ["--drop-nth", drop_indices])
    assert success is True
    assert pt == b"CONFIDENTIAL SCENARIO VERIFICATION SECRET"
    print("\n[PASS] Scenario 1 (8 forced drops, fec mode): Recovered bit-exact!")


def test_scenario_2_nine_forced_drops():
    """Scenario 2: 9 forced drops in fec mode -> Fails closed, no plaintext."""
    # Drop 9 arrival indices
    drop_indices = "4,7,10,13,16,19,22,25,28"
    success, pt, stats = run_scenario("Scenario 2", "fec", ["--drop-nth", drop_indices])
    assert success is False
    assert pt is None, "Security violation: plaintext emitted on decoding failure!"
    print("\n[PASS] Scenario 2 (9 forced drops, fec mode): Failed closed cleanly without plaintext!")


def test_scenario_3_ten_forced_drops_hybrid():
    """Scenario 3: 10 forced drops in hybrid mode -> Recovered, bit-exact via NACK."""
    # Forward path drops first flight tiles
    drop_indices = "4,6,8,10,12,14,16,18,20,22"
    success, pt, stats = run_scenario("Scenario 3", "hybrid", ["--drop-nth", drop_indices])
    assert success is True
    assert pt == b"CONFIDENTIAL SCENARIO VERIFICATION SECRET"
    assert stats["nacks"] >= 1, "Expected at least 1 NACK round in hybrid repair!"
    print("\n[PASS] Scenario 3 (10 forced drops, hybrid mode): Recovered bit-exact after NACK repair!")


def test_scenario_4_lossy_forward_and_reverse():
    """Scenario 4: 30% forward loss + 20% reverse loss in hybrid mode -> Recovered, bit-exact."""
    success, pt, stats = run_scenario("Scenario 4", "hybrid", ["--loss", "0.30", "--rev-loss", "0.20", "--seed", "42"])
    assert success is True
    assert pt == b"CONFIDENTIAL SCENARIO VERIFICATION SECRET"
    print("\n[PASS] Scenario 4 (30% fwd + 20% rev loss, hybrid mode): Recovered bit-exact!")


def test_scenario_5_gilbert_elliott_burst():
    """Scenario 5: Gilbert-Elliott burst loss in hybrid mode -> Recovered, bit-exact."""
    success, pt, stats = run_scenario("Scenario 5", "hybrid", ["--ge-gb", "0.1", "--ge-bg", "0.3", "--ge-loss", "0.9", "--seed", "7"])
    assert success is True
    assert pt == b"CONFIDENTIAL SCENARIO VERIFICATION SECRET"
    print("\n[PASS] Scenario 5 (Gilbert-Elliott bursts, hybrid mode): Recovered bit-exact!")


def test_scenario_6_hostile_network():
    """Scenario 6: Jitter + 10% dup + 10% corrupt in hybrid mode -> Recovered, bit-exact."""
    success, pt, stats = run_scenario("Scenario 6", "hybrid", ["--jitter", "0.01", "--dup", "0.10", "--corrupt", "0.10", "--seed", "19"])
    assert success is True
    assert pt == b"CONFIDENTIAL SCENARIO VERIFICATION SECRET"
    print("\n[PASS] Scenario 6 (Jitter + dup + corrupt, hybrid mode): Recovered bit-exact!")
