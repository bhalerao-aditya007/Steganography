#!/usr/bin/env python3
"""UDP impairment router: Alice -> [left:LPORT] ROUTER [right:ephemeral] -> Bob.
Replies flow back from Bob to Alice.

Supported impairments:
  - i.i.d. Bernoulli packet loss (--loss)
  - Gilbert-Elliott 2-state Markov burst loss (--ge-gb, --ge-bg, --ge-loss)
  - Deterministic drop by arrival index (--drop-nth)
  - Delay + uniform jitter resulting in packet reordering (--delay, --jitter)
  - Packet duplication (--dup)
  - Single-bit payload corruption (--corrupt)
  - Serialization delay + tail-drop queue bandwidth cap (--bw-kbps, --queue-bytes)
  - Reverse path loss for control messages (--rev-loss)

Logs ground-truth fate of every single datagram to CSV.
"""
import argparse
import csv
import heapq
import os
import random
import selectors
import socket
import struct
import sys
import time


class GilbertElliott:
    """Gilbert-Elliott 2-state Markov burst-loss model."""
    def __init__(self, p_gb: float, p_bg: float, loss_good: float, loss_bad: float, rng: random.Random):
        self.p_gb = p_gb
        self.p_bg = p_bg
        self.lg = loss_good
        self.lb = loss_bad
        self.rng = rng
        self.bad = False

    def drop(self) -> bool:
        if self.bad:
            if self.rng.random() < self.p_bg:
                self.bad = False
        elif self.rng.random() < self.p_gb:
            self.bad = True
        return self.rng.random() < (self.lb if self.bad else self.lg)


class Path:
    """One direction's impairment pipeline."""
    def __init__(self, a: argparse.Namespace, rng: random.Random, name: str):
        self.a = a
        self.rng = rng
        self.name = name
        self.n = 0
        self.drop_nth = set(a.drop_nth) if name == "fwd" else set()
        self.loss = a.loss if name == "fwd" else a.rev_loss
        self.ge = (
            GilbertElliott(a.ge_gb, a.ge_bg, 0.0, a.ge_loss, rng)
            if (a.ge_gb > 0 and name == "fwd")
            else None
        )
        self.link_free = 0.0

    def process(self, data: bytes, now: float) -> list[tuple[float | None, bytes, str]]:
        """Process packet through pipeline -> list of (deliver_time, bytes, action)."""
        self.n += 1
        a = self.a

        if self.n in self.drop_nth:
            return [(None, data, "drop_nth")]
        if self.ge and self.ge.drop():
            return [(None, data, "drop_burst")]
        if self.loss and self.rng.random() < self.loss:
            return [(None, data, "drop_iid")]

        if a.bw_kbps > 0:
            # Serialization + tail-drop queue
            backlog = max(0.0, self.link_free - now) * a.bw_kbps * 1000 / 8
            if backlog + len(data) > a.queue_bytes:
                return [(None, data, "drop_queue")]
            start = max(now, self.link_free)
            self.link_free = start + len(data) * 8 / (a.bw_kbps * 1000)
            t0 = self.link_free
        else:
            t0 = now

        act = "fwd"
        if a.corrupt and self.rng.random() < a.corrupt and len(data) > 20:
            b = bytearray(data)
            i = self.rng.randrange(20, len(b))
            b[i] ^= 1 << self.rng.randrange(8)
            data = bytes(b)
            act = "corrupt"

        delay = a.delay + (self.rng.uniform(0, a.jitter) if a.jitter > 0 else 0)
        out = [(t0 + delay, data, act)]

        if a.dup and self.rng.random() < a.dup:
            dup_delay = a.delay + (self.rng.uniform(0, a.jitter) if a.jitter > 0 else 0)
            out.append((t0 + dup_delay, data, "dup"))

        return out


def main():
    p = argparse.ArgumentParser(description="TESSERA Impairment Router")
    p.add_argument("--listen", type=int, default=9998, help="Left socket port (Alice -> Router)")
    p.add_argument("--to", default="127.0.0.1:9999", help="Destination (Router -> Bob host:port)")
    p.add_argument("--loss", type=float, default=0.0, help="Forward path i.i.d. loss probability (0.0 to 1.0)")
    p.add_argument("--rev-loss", type=float, default=0.0, help="Reverse path loss probability")
    p.add_argument(
        "--drop-nth",
        type=lambda s: [int(x) for x in s.split(",") if x.strip()],
        default=[],
        help="Comma-separated 1-based arrival indices to drop on forward path (e.g. 4,9,15)",
    )
    p.add_argument("--ge-gb", type=float, default=0.0, help="Gilbert-Elliott P(good -> bad)")
    p.add_argument("--ge-bg", type=float, default=0.3, help="Gilbert-Elliott P(bad -> good)")
    p.add_argument("--ge-loss", type=float, default=0.9, help="Gilbert-Elliott loss prob in bad state")
    p.add_argument("--delay", type=float, default=0.0, help="Fixed base delay in seconds")
    p.add_argument("--jitter", type=float, default=0.0, help="Uniform delay jitter in seconds")
    p.add_argument("--dup", type=float, default=0.0, help="Packet duplication probability")
    p.add_argument("--corrupt", type=float, default=0.0, help="Single-bit payload corruption probability")
    p.add_argument("--bw-kbps", type=float, default=0.0, help="Bandwidth limit in kbps (0 = unlimited)")
    p.add_argument("--queue-bytes", type=int, default=64000, help="Tail-drop queue capacity in bytes")
    p.add_argument("--seed", type=int, default=1, help="RNG seed for deterministic impairment patterns")
    p.add_argument("--log", default="router_log.csv", help="CSV log output path")
    p.add_argument("--pcap", default="", help="Optional PCAP capture output path")
    p.add_argument("--duration", type=float, default=0.0, help="Auto-exit after duration seconds (0 = run until Ctrl+C)")
    p.add_argument("--idle", type=float, default=0.0, help="Auto-exit after N seconds of silence once traffic has been seen (0 = disabled)")

    a = p.parse_args()
    rng = random.Random(a.seed)
    host, port_str = a.to.split(":")
    bob = (host, int(port_str))

    left = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    left.bind(("0.0.0.0", a.listen))
    right = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    right.bind(("0.0.0.0", 0))

    for s in (left, right):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        except OSError:
            pass
        s.setblocking(False)

    sel = selectors.DefaultSelector()
    sel.register(left, selectors.EVENT_READ, "L")
    sel.register(right, selectors.EVENT_READ, "R")

    fwd = Path(a, rng, "fwd")
    rev = Path(a, rng, "rev")
    heap = []
    tie = 0
    alice = None
    t_start = time.perf_counter()
    t_last_act = time.perf_counter()

    f = open(a.log, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["t", "dir", "n", "type", "seq", "tile", "bytes", "action"])

    pcap_writer = None
    if a.pcap:
        try:
            from scapy.all import IP, UDP, Raw, PcapWriter
            pcap_dir = os.path.dirname(os.path.abspath(a.pcap))
            if pcap_dir:
                os.makedirs(pcap_dir, exist_ok=True)
            pcap_writer = PcapWriter(a.pcap, append=False, sync=True)
        except ImportError:
            pass

    def log_event(d: str, path: Path, data: bytes, act: str, now: float):
        typ = seq = tile = ""
        if len(data) >= 20 and data[:2] == b"ST":
            typ = data[3]
            seq = struct.unpack("!I", data[8:12])[0]
            tile = struct.unpack("!H", data[12:14])[0]
        w.writerow([f"{now - t_start:.6f}", d, path.n, typ, seq, tile, len(data), act])
        f.flush()

    try:
        while True:
            now = time.perf_counter()
            if a.duration > 0 and (now - t_start) > a.duration:
                break
            if a.idle > 0 and fwd.n > 0 and (now - t_last_act) > a.idle:
                break

            while heap and heap[0][0] <= now:
                _, _, sock, dst, data = heapq.heappop(heap)
                t_last_act = now
                try:
                    sock.sendto(data, dst)
                    if pcap_writer is not None:
                        src_port = right.getsockname()[1] if sock is right else a.listen
                        pcap_writer.write(IP(src="127.0.0.1", dst=dst[0]) / UDP(sport=src_port, dport=dst[1]) / Raw(load=data))
                except OSError:
                    pass

            timeout = max(0.0, heap[0][0] - now) if heap else 0.05
            for key, _ in sel.select(timeout):
                try:
                    data, src = key.fileobj.recvfrom(65535)
                except (ConnectionResetError, OSError):
                    # On Windows, ICMP port unreachable surfaces as ConnectionResetError
                    continue

                now = time.perf_counter()
                t_last_act = now
                if key.data == "L":
                    alice = src
                    path = fwd
                    sock = right
                    dst = bob
                    d = "A>B"
                    if pcap_writer is not None:
                        pcap_writer.write(IP(src=src[0], dst="127.0.0.1") / UDP(sport=src[1], dport=a.listen) / Raw(load=data))
                else:
                    if alice is None:
                        continue
                    path = rev
                    sock = left
                    dst = alice
                    d = "B>A"
                    if pcap_writer is not None:
                        pcap_writer.write(IP(src=src[0], dst="127.0.0.1") / UDP(sport=src[1], dport=right.getsockname()[1]) / Raw(load=data))

                for t_deliv, pkt, act in path.process(data, now):
                    log_event(d, path, pkt, act, now)
                    if t_deliv is not None:
                        tie += 1
                        heapq.heappush(heap, (t_deliv, tie, sock, dst, pkt))
    except KeyboardInterrupt:
        pass
    finally:
        f.close()
        left.close()
        right.close()
        if pcap_writer is not None:
            pcap_writer.close()


if __name__ == "__main__":
    main()
