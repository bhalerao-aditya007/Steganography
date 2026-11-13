"""TESSERA reference transport: Sender and Receiver for fec and hybrid modes.
Engine hooks (derive_key, extract, decode) are injected to decouple transport from steganography.
"""
import math
import os
import random
import socket
import struct
import time
from . import packet as pk
from .packet import SYN, DATA, NACK, FIN, SYN_ACK, DONE, F_FRAG


def precise_sleep(dt: float):
    """Windows time.sleep() granularity is ~15.6 ms: coarse sleep + spin."""
    end = time.perf_counter() + dt
    while (rem := end - time.perf_counter()) > 0:
        if rem > 0.003:
            time.sleep(rem - 0.002)


def udp_socket(bind=None, rcvbuf: int = 4 << 20) -> socket.socket:
    """Create UDP socket with 4MB receive buffer for high-burst stability."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    except OSError:
        pass
    if bind:
        s.bind(bind)
    return s


class Sender:
    """Sender state machine supporting open-loop FEC and closed-loop Hybrid ARQ."""
    def __init__(
        self,
        dst: tuple[str, int],
        tiles: list[bytes],
        wire_key: bytes | None,
        salt: bytes,
        *,
        n: int = 32,
        k: int = 24,
        shard_len: int = 64,
        ct_len: int = 0,
        mode: str = "hybrid",
        pps: int = 500,
        rto: float = 0.2,
        max_rounds: int = 8,
        size: tuple[int, int] = (512, 512),
        mtu_safe: bool = False,
        log=print,
    ):
        self.dst = dst
        self.tiles = tiles
        self.key = wire_key
        self.salt = salt
        self.n = n
        self.k = k
        self.sl = shard_len
        self.ct_len = ct_len
        self.mode = mode
        self.gap = 1.0 / max(1, pps)
        self.rto0 = rto
        self.max_rounds = max_rounds
        self.size = size
        self.mtu_safe = mtu_safe
        self.log = log
        self.sess = random.getrandbits(32)
        self.seq = 0
        self.sock = udp_socket(("127.0.0.1", 0))
        self.sent_data = 0

    def _tx(self, typ: int, tile: int = 0, frag: int = 0, payload: bytes = b""):
        self.seq += 1
        pkt = pk.pack(typ, self.sess, self.seq, tile, frag, payload, self.key)
        self.sock.sendto(pkt, self.dst)

    def _rx(self, timeout: float) -> dict | None:
        self.sock.settimeout(timeout)
        try:
            d, _ = self.sock.recvfrom(65535)
        except (socket.timeout, ConnectionResetError, OSError):
            return None
        p = pk.unpack(d, self.key)
        return p if (p and p.get("ok") and p.get("session") == self.sess) else None

    def _send_tile(self, t: int):
        data = self.tiles[t]
        if self.mtu_safe and len(data) > 1200:
            frag_size = 1172  # 7 fragments for 8192 B
            frags = [data[i:i + frag_size] for i in range(0, len(data), frag_size)]
            for f_idx, frag_bytes in enumerate(frags):
                self._tx(DATA, tile=t, frag=f_idx, payload=frag_bytes)
                self.sent_data += 1
        else:
            self._tx(DATA, tile=t, frag=0, payload=data)
            self.sent_data += 1

    def run(self) -> str:
        frags_per_tile = math.ceil(len(self.tiles[0]) / 1172) if (self.mtu_safe and len(self.tiles) > 0) else 1
        body = pk.SYN_BODY.pack(
            self.salt,
            self.n,
            self.k,
            self.sl,
            1 if self.mode == "hybrid" else 0,
            frags_per_tile,
            self.size[0],
            self.size[1],
            self.ct_len,
        )

        if self.mode == "hybrid":
            # SYN / SYN-ACK handshake with exponential backoff (RFC 6298 style)
            rto = self.rto0
            handshake_ok = False
            for attempt in range(6):
                self._tx(SYN, payload=body)
                t_end = time.perf_counter() + rto
                while (rem := t_end - time.perf_counter()) > 0:
                    p = self._rx(rem)
                    if p and p["type"] == SYN_ACK:
                        handshake_ok = True
                        break
                if handshake_ok:
                    break
                rto *= 2
            if not handshake_ok:
                return "handshake_failed"
        else:
            # Open-loop FEC: triple-send SYN for resilience
            for _ in range(3):
                self._tx(SYN, payload=body)
                precise_sleep(0.01)

        # First flight: paced DATA transmission
        nxt = time.perf_counter()
        for t in range(self.n):
            precise_sleep(max(0.0, nxt - time.perf_counter()))
            self._send_tile(t)
            nxt += self.gap

        # Signal end of first flight
        for _ in range(2):
            self._tx(FIN)
            precise_sleep(0.01)

        if self.mode != "hybrid":
            return "sent"

        # Hybrid ARQ repair loop
        deadline_rounds = 0
        while deadline_rounds < self.max_rounds:
            p = self._rx(self.rto0 * 4)
            if p is None:
                # Silence timeout: re-poke with FIN to elicit Bob's state
                self._tx(FIN)
                deadline_rounds += 1
                continue
            if p["type"] == DONE:
                return f"done_after_{self.sent_data}_data_pkts"
            if p["type"] == NACK:
                bitmap, valid, _rnd = pk.NACK_BODY.unpack(p["payload"][:pk.NACK_BODY.size])
                missing = [t for t in range(self.n) if not ((bitmap >> t) & 1)]
                need = max(0, self.k - valid)
                # Resend missing tiles with 30% margin + 2 vs repeat packet drops
                margin = max(2, math.ceil(0.3 * need))
                send_tiles = missing[: min(len(missing), need + margin)]
                
                nxt = time.perf_counter()
                for t in send_tiles:
                    precise_sleep(max(0.0, nxt - time.perf_counter()))
                    self._send_tile(t)
                    nxt += self.gap
                    
                self._tx(FIN)
                deadline_rounds += 1

        return "gave_up"


class Receiver:
    """Receiver state machine with total-function robustness on arbitrary network bytes."""
    def __init__(
        self,
        port: int,
        derive_key,
        extract,
        decode,
        *,
        idle: float = 0.4,
        total_timeout: float = 20.0,
        max_nacks: int = 8,
        log=print,
    ):
        self.sock = udp_socket(("127.0.0.1", port))
        self.derive_key = derive_key
        self.extract = extract
        self.decode = decode
        self.idle = idle
        self.total = total_timeout
        self.max_nacks = max_nacks
        self.log = log
        self.stats = dict(
            rx=0,
            bad_tag=0,
            bad_syn=0,
            bad_shard=0,
            dup=0,
            nacks=0,
            seq_gaps=0,
        )

    def _tx(self, typ: int, payload: bytes = b""):
        self.seq += 1
        pkt = pk.pack(typ, self.sess, self.seq, 0, 0, payload, self.key)
        self.sock.sendto(pkt, self.peer)

    def run(self) -> tuple[bool, bytes | None, dict]:
        self.sess = None
        self.key = None
        self.peer = None
        self.seq = 0
        shards = {}
        tile_fragments = {}  # for MTU fragmentation reassembly: tile -> dict(frag_idx -> bytes)
        last_derive = -1e9
        last_rx = time.perf_counter()
        t0 = time.perf_counter()
        mode_hybrid = False
        rounds = 0
        last_seen_seq = -1

        while time.perf_counter() - t0 < self.total:
            self.sock.settimeout(0.05)
            try:
                d, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                d = None
            except (ConnectionResetError, OSError):
                continue

            now = time.perf_counter()
            trigger = False

            if d:
                p = pk.unpack(d)
                if p:
                    self.stats["rx"] += 1
                    
                    # Track sequence gaps for loss observation
                    if last_seen_seq >= 0 and p["seq"] > last_seen_seq + 1:
                        self.stats["seq_gaps"] += p["seq"] - (last_seen_seq + 1)
                    last_seen_seq = p["seq"]

                    # 1. New session SYN handling
                    if p["type"] == SYN and self.sess is None:
                        if len(p["payload"]) < pk.SYN_BODY.size or (now - last_derive < 0.2):
                            # Malformed SYN or Argon2 rate limit trigger (DoS guard)
                            self.stats["bad_syn"] += 1
                        else:
                            last_derive = now
                            salt, n, k, sl, hyb, frags, w, h, ctl = pk.SYN_BODY.unpack(p["payload"][:pk.SYN_BODY.size])
                            if not (1 <= k < n <= 64 and 1 <= sl <= 255):
                                self.stats["bad_syn"] += 1
                            else:
                                key = self.derive_key(salt)
                                if pk.verify(p, key):
                                    self.sess = p["session"]
                                    self.key = key
                                    self.peer = addr
                                    mode_hybrid = bool(hyb)
                                    self.sl = sl
                                    self.k = k
                                    self.n = n
                                    self.frags_per_tile = frags
                                    last_rx = now
                                    if mode_hybrid:
                                        self._tx(SYN_ACK)
                                else:
                                    self.stats["bad_tag"] += 1

                    # 2. Existing session packet handling
                    elif self.sess is not None and p["session"] == self.sess:
                        if p["type"] == SYN and mode_hybrid:
                            # Lost SYN-ACK retry: resend SYN-ACK without re-deriving keys
                            self._tx(SYN_ACK)
                        elif not pk.verify(p, self.key):
                            self.stats["bad_tag"] += 1
                        elif p["type"] == DATA:
                            last_rx = now
                            tile_idx = p["tile"]
                            payload = p["payload"]
                            
                            # Handle reassembly if fragmented
                            if p["flags"] & F_FRAG:
                                if tile_idx not in tile_fragments:
                                    tile_fragments[tile_idx] = {}
                                tile_fragments[tile_idx][p["frag"]] = payload
                                if len(tile_fragments[tile_idx]) >= self.frags_per_tile:
                                    # All fragments present
                                    sorted_frags = [tile_fragments[tile_idx][f] for f in sorted(tile_fragments[tile_idx])]
                                    full_tile = b"".join(sorted_frags)
                                    r = self.extract(full_tile, tile_idx)
                                else:
                                    r = None
                            else:
                                r = self.extract(payload, tile_idx)

                            if r is not None:
                                shard_idx, shard_body = r
                                if shard_idx in shards:
                                    self.stats["dup"] += 1
                                else:
                                    shards[shard_idx] = shard_body
                            elif not (p["flags"] & F_FRAG):
                                self.stats["bad_shard"] += 1

                        elif p["type"] == FIN:
                            trigger = True

            elif self.sess is not None and shards and (now - last_rx > self.idle):
                # Silence timeout triggers reconstruction attempt
                trigger = True
                last_rx = now

            if trigger and len(shards) >= getattr(self, "k", 24):
                try:
                    pt = self.decode(shards)
                    if pt is not None:
                        if mode_hybrid:
                            for _ in range(3):
                                self._tx(DONE)
                        return True, pt, self.stats
                except Exception as e:
                    self.log(f"decode attempt failed ({e.__class__.__name__}): {e}; {len(shards)} shards held")

            if trigger:
                if not mode_hybrid:
                    return False, None, self.stats
                if rounds >= self.max_nacks:
                    return False, None, self.stats
                bitmap = sum(1 << i for i in shards)
                rounds += 1
                self.stats["nacks"] += 1
                self._tx(NACK, pk.NACK_BODY.pack(bitmap, len(shards), rounds))

        return False, None, self.stats
