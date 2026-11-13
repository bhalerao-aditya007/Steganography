"""Unit tests for column-wise RS(32, 24) erasure coding, framing, and errors-and-erasures decoding."""
import os
import pytest
from reedsolo import ReedSolomonError
from tessera.net import fec


def test_fec_shard_framing():
    """Test shard framing and CRC32 erasure detection."""
    body = os.urandom(59)
    fr = fec.frame(7, body)
    assert len(fr) == 1 + 59 + 4  # 64 bytes
    assert fr[0] == 7

    parsed = fec.parse_frame(fr)
    assert parsed is not None
    idx, parsed_body = parsed
    assert idx == 7
    assert parsed_body == body

    # Corrupted frame should return None (detected as erasure)
    corrupt = bytearray(fr)
    corrupt[10] ^= 0x01
    assert fec.parse_frame(bytes(corrupt)) is None


def test_fec_encode_decode_exact():
    """Test perfect recovery when all 32 shards arrive."""
    P = 59
    ciphertext = os.urandom(fec.K * P)  # 24 * 59 = 1416 bytes
    shards = fec.encode(ciphertext, P=P)
    assert len(shards) == 32

    received = {}
    for fr in shards:
        parsed = fec.parse_frame(fr)
        assert parsed is not None
        received[parsed[0]] = parsed[1]

    recovered = fec.decode(received, P=P)
    assert recovered == ciphertext


def test_fec_erasures_recovery():
    """Test recovery under 0, 4, and 8 erasures (MDS property)."""
    P = 59
    ciphertext = os.urandom(fec.K * P)
    shards = fec.encode(ciphertext, P=P)

    parsed_shards = {}
    for fr in shards:
        idx, body = fec.parse_frame(fr)
        parsed_shards[idx] = body

    # 1. 4 erasures (28 shards remaining)
    rec_4 = {k: v for k, v in parsed_shards.items() if k not in {2, 7, 15, 29}}
    assert len(rec_4) == 28
    assert fec.decode(rec_4, P=P) == ciphertext

    # 2. 8 erasures (exactly 24 shards remaining)
    rec_8 = {k: v for k, v in parsed_shards.items() if k not in {0, 3, 8, 11, 17, 21, 26, 31}}
    assert len(rec_8) == 24
    assert fec.decode(rec_8, P=P) == ciphertext

    # 3. 9 erasures (23 shards remaining) must raise ValueError
    rec_9 = {k: v for k, v in parsed_shards.items() if k not in {0, 1, 2, 3, 4, 5, 6, 7, 8}}
    assert len(rec_9) == 23
    with pytest.raises(ValueError):
        fec.decode(rec_9, P=P)


def test_fec_errors_and_erasures():
    """Verify 2*e + f <= 8 boundary tested in Section 8.4 of the Upgrade Guide."""
    P = 59
    ciphertext = os.urandom(fec.K * P)
    shards = fec.encode(ciphertext, P=P)

    parsed_shards = {}
    for fr in shards:
        idx, body = fec.parse_frame(fr)
        parsed_shards[idx] = body

    # Case 1: f=4 erasures, e=2 undetected errors -> 2*2 + 4 = 8 <= 8 (MUST SUCCEED)
    # Simulate erasures: remove indices 0, 1, 2, 3
    rec_e2_f4 = {k: bytearray(v) for k, v in parsed_shards.items() if k not in {0, 1, 2, 3}}
    # Corrupt 2 shards (without modifying frame CRC - simulating CRC collision or undetected error)
    rec_e2_f4[10][5] ^= 0xAA
    rec_e2_f4[20][12] ^= 0x55
    rec_e2_f4 = {k: bytes(v) for k, v in rec_e2_f4.items()}
    assert fec.decode(rec_e2_f4, P=P) == ciphertext

    # Case 2: f=0 erasures, e=4 errors -> 2*4 + 0 = 8 <= 8 (MUST SUCCEED)
    rec_e4_f0 = {k: bytearray(v) for k, v in parsed_shards.items()}
    rec_e4_f0[5][0] ^= 0x01
    rec_e4_f0[12][1] ^= 0x02
    rec_e4_f0[18][2] ^= 0x04
    rec_e4_f0[25][3] ^= 0x08
    rec_e4_f0 = {k: bytes(v) for k, v in rec_e4_f0.items()}
    assert fec.decode(rec_e4_f0, P=P) == ciphertext

    # Case 3: f=5 erasures, e=2 errors in the SAME column (column 5) -> 2*2 + 5 = 9 > 8 (MUST FAIL)
    rec_e2_f5 = {k: bytearray(v) for k, v in parsed_shards.items() if k not in {0, 1, 2, 3, 4}}
    rec_e2_f5[10][5] ^= 0xAA
    rec_e2_f5[20][5] ^= 0x55
    rec_e2_f5 = {k: bytes(v) for k, v in rec_e2_f5.items()}
    with pytest.raises(ReedSolomonError):
        fec.decode(rec_e2_f5, P=P)
