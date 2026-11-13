"""TESSERA wire protocol v2: 20-byte header + payload.
Tag = CRC32 (plain) or keyed BLAKE2s-32 (secure).
"""
import hashlib
import hmac
import struct
import zlib

MAGIC = 0x5354  # "ST"
VER = 2

SYN, DATA, ACK, NACK, FIN, SYN_ACK, DONE = 1, 2, 3, 4, 5, 6, 7
F_KEYED, F_STEALTH, F_FRAG = 1, 2, 4

TYPE_NAMES = {
    SYN: "SYN",
    DATA: "DATA",
    ACK: "ACK",
    NACK: "NACK",
    FIN: "FIN",
    SYN_ACK: "SYN-ACK",
    DONE: "DONE",
}

# Legacy type aliases for v1 compatibility
TYPE_SYN = SYN
TYPE_DATA = DATA
TYPE_ACK = ACK
TYPE_NACK = NACK
TYPE_FIN = FIN

# Header: magic(2B) | ver<<4 | flags(1B) | type(1B) | session(4B) | seq(4B) | tile(2B) | frag(2B) | tag(4B) = 20 B
HDR = struct.Struct("!HBBIIHHI")
HLEN = HDR.size  # 20
HDR_STRUCT = HDR  # Legacy alias

# SYN body: salt(16B) | n(1B) | k(1B) | shard_len(1B) | mode(1B) | frags_per_tile(1B) | width(2B) | height(2B) | ct_len(2B) = 27 B
SYN_BODY = struct.Struct("!16sBBBBBHHH")

# NACK body: valid_tile_bitmap(4B) | valid_count(1B) | round(1B) = 6 B
NACK_BODY = struct.Struct("!IBB")


def _tag(key, head16: bytes, payload: bytes) -> int:
    """Compute 32-bit tag: CRC32 if key is None, else BLAKE2s-32 with key."""
    if key is None:
        return zlib.crc32(head16 + payload) & 0xFFFFFFFF
    return int.from_bytes(hashlib.blake2s(head16 + payload, key=key, digest_size=4).digest(), "big")


def pack(typ: int, session: int, seq: int, tile: int = 0, frag: int = 0, payload: bytes = b"", key: bytes | None = None) -> bytes:
    """Pack datagram with 20-byte v2 header and 4-byte CRC32 or BLAKE2s tag."""
    flags = F_KEYED if key else 0
    head16 = HDR.pack(MAGIC, (VER << 4) | flags, typ, session, seq, tile, frag, 0)[:16]
    tag_val = _tag(key, head16, payload)
    return head16 + tag_val.to_bytes(4, "big") + payload


def unpack(buf: bytes, key: bytes | None = None) -> dict | None:
    """Unpack v2 datagram into dict or None.
    
    ok=None indicates 'keyed packet, key not supplied yet' (e.g. used for initial SYN inspection).
    ok=True/False indicates tag verification result when key is supplied or packet is unkeyed.
    """
    if len(buf) < HLEN:
        return None
    magic, vf, typ, sess, seq, tile, frag, tag = HDR.unpack(buf[:HLEN])
    if magic != MAGIC or (vf >> 4) != VER:
        return None
    flags = vf & 15
    payload = buf[HLEN:]
    if (flags & F_KEYED) and key is None:
        ok = None
    else:
        actual_key = key if (flags & F_KEYED) else None
        expected_tag = _tag(actual_key, buf[:16], payload).to_bytes(4, "big")
        ok = hmac.compare_digest(expected_tag, buf[16:20])
    return dict(
        type=typ,
        flags=flags,
        session=sess,
        seq=seq,
        tile=tile,
        frag=frag,
        payload=payload,
        ok=ok,
        raw=buf,
    )


def verify(pkt: dict, key: bytes | None) -> bool:
    """Verify keyed or unkeyed tag on unpacked packet dict using constant-time comparison."""
    if "raw" not in pkt or len(pkt["raw"]) < HLEN:
        return False
    actual_key = key if (pkt.get("flags", 0) & F_KEYED) else None
    expected_tag = _tag(actual_key, pkt["raw"][:16], pkt["payload"]).to_bytes(4, "big")
    return hmac.compare_digest(expected_tag, pkt["raw"][16:20])


# Backward compatibility wrapper for v1 Packet class
class Packet:
    def __init__(
        self,
        pkt_type: int,
        session_id: int,
        seq: int,
        tile_idx: int = 0,
        frag_idx: int = 0,
        payload: bytes = b"",
    ):
        self.pkt_type = pkt_type
        self.session_id = session_id
        self.seq = seq
        self.tile_idx = tile_idx
        self.frag_idx = frag_idx
        self.payload = payload

    def serialize(self, key: bytes | None = None) -> bytes:
        return pack(self.pkt_type, self.session_id, self.seq, self.tile_idx, self.frag_idx, self.payload, key=key)

    @classmethod
    def parse(cls, data: bytes, key: bytes | None = None) -> "Packet | None":
        p = unpack(data, key=key)
        if p is None or p["ok"] is False:
            return None
        return cls(p["type"], p["session"], p["seq"], p["tile"], p["frag"], p["payload"])
