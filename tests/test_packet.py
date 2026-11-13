"""Unit tests for Wire Protocol v2 framing, pack/unpack, keyed tags, and error resilience."""
import pytest
from tessera.net import packet as pk


def test_packet_pack_unpack_unkeyed():
    """Test unkeyed packet (CRC32 tag) pack and unpack."""
    payload = b"Hello, TESSERA network test payload!"
    raw = pk.pack(pk.DATA, session=0x12345678, seq=42, tile=5, frag=0, payload=payload, key=None)
    assert len(raw) == pk.HLEN + len(payload)
    assert raw[:2] == b"ST"

    p = pk.unpack(raw, key=None)
    assert p is not None
    assert p["type"] == pk.DATA
    assert p["session"] == 0x12345678
    assert p["seq"] == 42
    assert p["tile"] == 5
    assert p["frag"] == 0
    assert p["payload"] == payload
    assert p["ok"] is True


def test_packet_pack_unpack_keyed():
    """Test keyed packet (BLAKE2s-32 tag) pack, verify, and wrong key rejection."""
    key = b"supersecretwirekey12345678901234"
    payload = b"Authenticated datagram payload"
    raw = pk.pack(pk.DATA, session=0xAABBCCDD, seq=100, tile=12, frag=1, payload=payload, key=key)

    # 1. Unpack with correct key
    p_ok = pk.unpack(raw, key=key)
    assert p_ok is not None
    assert p_ok["ok"] is True
    assert p_ok["flags"] & pk.F_KEYED
    assert pk.verify(p_ok, key) is True

    # 2. Unpack with wrong key
    wrong_key = b"wrongwirekey12345678901234567890"
    p_wrong = pk.unpack(raw, key=wrong_key)
    assert p_wrong is not None
    assert p_wrong["ok"] is False
    assert pk.verify(p_wrong, wrong_key) is False

    # 3. Unpack without key initially (ok=None)
    p_nokey = pk.unpack(raw, key=None)
    assert p_nokey is not None
    assert p_nokey["ok"] is None
    # Now verify once key becomes available
    assert pk.verify(p_nokey, key) is True


def test_packet_malformed():
    """Verify total-function behavior on malformed or truncated datagrams."""
    # Too short
    assert pk.unpack(b"") is None
    assert pk.unpack(b"ST\x00") is None
    assert pk.unpack(b"ST" + b"\x00" * 17) is None

    # Wrong magic
    bogus = b"XX" + b"\x00" * 18
    assert pk.unpack(bogus) is None

    # Corrupted payload causes tag failure
    key = b"wirekey32byteslongforblake2skey!"
    raw = pk.pack(pk.DATA, 1, 1, 0, 0, b"original", key=key)
    corrupted = bytearray(raw)
    corrupted[-1] ^= 0x01
    p = pk.unpack(bytes(corrupted), key=key)
    assert p is not None
    assert p["ok"] is False
