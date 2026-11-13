"""Honey Decoy DTE Unit Tests."""
import os
from tessera.decoy.dte import dte_decode, dte_encode, FIELDS, SEEDBITS
from tessera.decoy.messages import is_plausible_decoy

def test_honey_dte_plausibility():
    # 1. Test standard indices
    indices = [0, 1, 4, 11, 2]
    seed = dte_encode(indices)
    msg = dte_decode(seed)
    assert is_plausible_decoy(msg)
    
    # 2. Test 100 arbitrary pseudorandom 64-bit seeds
    for _ in range(100):
        rand_seed = int.from_bytes(os.urandom(8), "big")
        decoded = dte_decode(rand_seed)
        assert is_plausible_decoy(decoded), f"Decoded message '{decoded}' failed plausibility check!"
        
    print("HONEY DTE PLAUSIBILITY CHECKS PASSED FOR 100 ARBITRARY SEEDS!")

if __name__ == "__main__":
    test_honey_dte_plausibility()
