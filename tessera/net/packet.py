"""Wire packet format and serialization for TESSERA transport protocol."""
import struct
import zlib

MAGIC = 0x5354  # "ST"
VERSION = 1

# Packet types
TYPE_SYN = 1
TYPE_DATA = 2
TYPE_ACK = 3
TYPE_NACK = 4
TYPE_FIN = 5

TYPE_NAMES = {
    TYPE_SYN: "SYN",
    TYPE_DATA: "DATA",
    TYPE_ACK: "ACK",
    TYPE_NACK: "NACK",
    TYPE_FIN: "FIN",
}

# Header: magic(2B) | ver(1B) | type(1B) | session(4B) | seq(4B) | tile_idx(2B) | frag_idx(2B) | crc32(4B) = 20 Bytes
HDR_STRUCT = struct.Struct("!HBBIIHHI")

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

    def serialize(self) -> bytes:
        """Serialize packet into binary with CRC32 over header and payload."""
        # Calculate CRC with crc32 field initially 0
        hdr_no_crc = struct.pack(
            "!HBBIIHH",
            MAGIC,
            VERSION,
            self.pkt_type,
            self.session_id,
            self.seq,
            self.tile_idx,
            self.frag_idx,
        )
        crc = zlib.crc32(hdr_no_crc + self.payload)
        return HDR_STRUCT.pack(
            MAGIC,
            VERSION,
            self.pkt_type,
            self.session_id,
            self.seq,
            self.tile_idx,
            self.frag_idx,
            crc,
        ) + self.payload

    @classmethod
    def parse(cls, data: bytes) -> "Packet | None":
        """Parse binary data into Packet, verifying magic and CRC32."""
        if len(data) < HDR_STRUCT.size:
            return None
        magic, ver, p_type, sess, seq, tile_idx, frag_idx, expected_crc = HDR_STRUCT.unpack(data[:HDR_STRUCT.size])
        if magic != MAGIC or ver != VERSION:
            return None
            
        payload = data[HDR_STRUCT.size:]
        hdr_no_crc = struct.pack("!HBBIIHH", magic, ver, p_type, sess, seq, tile_idx, frag_idx)
        computed_crc = zlib.crc32(hdr_no_crc + payload)
        if computed_crc != expected_crc:
            return None  # Corrupted packet
            
        return cls(p_type, sess, seq, tile_idx, frag_idx, payload)
