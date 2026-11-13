#!/usr/bin/env python3
"""Offline loss and sequence analysis report from a Wireshark/Npcap capture of Alice -> Router -> Bob.
Leg 1 = datagrams arriving at the router port (default 9998).
Leg 2 = datagrams arriving at Bob's port (default 9999).
Loss per leg is inferred from sequence numbers; router-induced loss = Leg1 seqs that never appear on Leg2.
"""
import argparse
import struct
import sys
from collections import defaultdict
from scapy.all import rdpcap, UDP, Raw


def parse_header(raw: bytes):
    if len(raw) < 20 or raw[:2] != b"ST":
        return None
    typ = raw[3]
    sess, seq = struct.unpack("!II", raw[4:12])
    tile = struct.unpack("!H", raw[12:14])[0]
    return typ, sess, seq, tile


def main():
    ap = argparse.ArgumentParser(description="TESSERA PCAP Analysis Tool")
    ap.add_argument("pcap", help="Path to .pcap or .pcapng file")
    ap.add_argument("--in-port", type=int, default=9998, help="Router ingress port (default 9998)")
    ap.add_argument("--out-port", type=int, default=9999, help="Bob ingress port (default 9999)")
    a = ap.parse_args()

    leg = {a.in_port: {}, a.out_port: {}}
    packets = rdpcap(a.pcap)
    for pkt in packets:
        if UDP in pkt and Raw in pkt and pkt[UDP].dport in leg:
            r = parse_header(bytes(pkt[Raw].load))
            if r and r[0] in (1, 2, 4, 5, 6, 7):
                leg[pkt[UDP].dport][r[2]] = (r[0], r[3], float(pkt.time), len(pkt[Raw].load))

    sent, seen = leg[a.in_port], leg[a.out_port]
    lost = sorted(set(sent) - set(seen))
    data_sent = {s for s, v in sent.items() if v[0] == 2}
    data_lost = [s for s in lost if sent[s][0] == 2]

    print("=" * 65)
    print("           TESSERA PCAP OFFLINE TRANSPORT AUDIT REPORT           ")
    print("=" * 65)
    print(f"Leg 1 (Alice -> Router): {len(sent)} datagrams  ({len(data_sent)} DATA)")
    print(f"Leg 2 (Router -> Bob)  : {len(seen)} datagrams")
    print(f"Lost in Router         : {len(lost)} total, {len(data_lost)} DATA -> tiles {sorted(sent[s][1] for s in data_lost)}")
    data_loss_rate = len(data_lost) / max(1, len(data_sent))
    print(f"DATA Packet Loss Rate  : {data_loss_rate:.1%}")

    seqs = sorted(seen.keys())
    gaps = [(x, y) for x, y in zip(seqs, seqs[1:]) if y - x > 1]
    print(f"Sequence Gaps on Leg 2 : {gaps}")
    sizes = {v[3] for v in sent.values() if v[0] == 2}
    print(f"DATA Payload Sizes     : {sizes}  (constant sizes = traffic fingerprint)")
    print("=" * 65)


if __name__ == "__main__":
    main()
