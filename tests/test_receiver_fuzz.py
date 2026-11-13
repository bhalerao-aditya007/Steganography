"""Fuzz test for TESSERA Receiver:
Floods the receiver with thousands of hostile, malformed, truncated, and corrupt datagrams.
Verifies that the receiver acts as a total function and never crashes or raises unhandled exceptions.
"""
import os
import random
import socket
import struct
import threading
import time
import pytest
from tessera.net import packet as pk
from tessera.net.transport import Receiver


def hostile_datagram(i: int, rng: random.Random) -> bytes:
    m = i % 6
    if m == 0:
        # Completely random bytes
        return os.urandom(rng.randrange(0, 300))
    elif m == 1:
        # Valid magic ST + random garbage
        return b"ST" + os.urandom(rng.randrange(0, 50))
    elif m == 2:
        # Truncated SYN
        return pk.pack(pk.SYN, rng.getrandbits(32), i, 0, 0, os.urandom(rng.randrange(0, 26)), b"k" * 32)
    elif m == 3:
        # Absurd parameter SYN (e.g. k > n, zero shard length)
        body = struct.pack("!16sBBBBBHHH", os.urandom(16), 0, 5, 0, 0, 1, 512, 512, 100)
        return pk.pack(pk.SYN, 1, i, 0, 0, body, b"k" * 32)
    elif m == 4:
        # DATA datagram for non-existent session
        return pk.pack(pk.DATA, rng.getrandbits(32), i, rng.randrange(65535), 0, os.urandom(500), b"k" * 32)
    else:
        # Truncated header
        return b"ST\x20\x01\x11"


def test_receiver_fuzz_robustness():
    """Run receiver on a thread and blast 1,000 hostile datagrams; assert clean return without crashing."""
    port = 11456
    rng = random.Random(42)

    def dummy_derive(salt):
        return b"\x42" * 32

    def dummy_extract(payload, tile):
        return None

    def dummy_decode(shards):
        return b""

    rcv = Receiver(
        port,
        dummy_derive,
        dummy_extract,
        dummy_decode,
        idle=0.1,
        total_timeout=1.5,
        max_nacks=2,
    )

    result_holder = []

    def run_rcv():
        res = rcv.run()
        result_holder.append(res)

    t = threading.Thread(target=run_rcv, daemon=True)
    t.start()
    time.sleep(0.05)

    sender_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for i in range(1000):
            pkt = hostile_datagram(i, rng)
            try:
                sender_sock.sendto(pkt, ("127.0.0.1", port))
            except OSError:
                pass
    finally:
        sender_sock.close()

    t.join(timeout=3.0)
    assert not t.is_alive(), "Receiver hung on hostile fuzz input!"
    assert len(result_holder) == 1
    success, pt, stats = result_holder[0]
    assert success is False
    assert pt is None
    assert stats["rx"] > 0
    print(f"\n[PASS] Receiver successfully absorbed hostile datagrams: {stats}")
