"""Column-wise systematic RS(32,24) over GF(256).
Shard frame = idx(1) | body(P) | crc32(idx||body)(4).
Total shard size = P + 5 bytes (e.g. 59 + 5 = 64 bytes).
"""
import struct
import zlib
from reedsolo import RSCodec, ReedSolomonError

N, K, NSYM = 32, 24, 8
DEFAULT_P = 59

_rs = RSCodec(NSYM)


def frame(idx: int, body: bytes) -> bytes:
    """Frame shard with 1-byte index and 4-byte CRC32 erasure-detection tag."""
    chunk = bytes([idx]) + body
    crc = zlib.crc32(chunk) & 0xFFFFFFFF
    return chunk + crc.to_bytes(4, "big")


def parse_frame(fr: bytes) -> tuple[int, bytes] | None:
    """Parse shard frame -> (idx, body) or None if CRC fails.
    
    CRC here is an erasure detector: corrupt frames are detected and turned
    into known-position erasures, allowing RS to correct up to 8 lost symbols.
    """
    if len(fr) < 6:
        return None
    data_part = fr[:-4]
    expected_crc = int.from_bytes(fr[-4:], "big")
    if (zlib.crc32(data_part) & 0xFFFFFFFF) != expected_crc:
        return None
    return fr[0], fr[1:-4]


def encode(ciphertext: bytes, P: int = DEFAULT_P) -> list[bytes]:
    """Encode ciphertext of length K*P into N systematic shards using column-wise RS(32,24)."""
    if len(ciphertext) != K * P:
        raise ValueError(f"Ciphertext length {len(ciphertext)} does not match required K*P ({K}*{P}={K*P})")
    
    data = [ciphertext[i * P:(i + 1) * P] for i in range(K)]
    # Each column across the K data shards is encoded into 32 symbols (24 data + 8 parity)
    cols = [_rs.encode(bytes(d[c] for d in data)) for c in range(P)]
    shards = [bytes(cols[c][i] for c in range(P)) for i in range(N)]
    return [frame(i, shards[i]) for i in range(N)]


def decode(received: dict[int, bytes], P: int = DEFAULT_P) -> bytes:
    """Reconstruct ciphertext from received shards {idx: body}.
    
    Handles both known erasures (missing indices) and residual errors
    according to the MDS property: 2*e + f <= NSYM (8).
    Raises ValueError if fewer than K shards are received.
    Raises ReedSolomonError if errata exceed 2*e + f <= 8.
    """
    if len(received) < K:
        raise ValueError(f"Fewer than K shards received (got {len(received)}, need {K})")
    
    miss = [i for i in range(N) if i not in received]
    out = [bytearray(P) for _ in range(K)]
    
    for c in range(P):
        cw = bytearray(N)
        for i, b in received.items():
            if len(b) > c:
                cw[i] = b[c]
        # Decode column with erasure positions
        dec = _rs.decode(bytes(cw), erase_pos=miss)[0]
        for i in range(K):
            out[i][c] = dec[i]
            
    return b"".join(bytes(x) for x in out)
