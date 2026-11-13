"""Tile-aligned column-wise Reed-Solomon erasure coding and shard framing."""
import struct
import zlib
from reedsolo import RSCodec
from ..embed.profile import Profile

def make_shards(ct: bytes, prof: Profile) -> list[bytes]:
    """Encode ciphertext into `n` shards using column-wise Reed-Solomon(n, k).
    
    Each byte column across the `k` data shards is extended with `n - k` parity symbols.
    Each shard is framed with:
      header (5B): idx (1B) | k (1B) | n (1B) | ct_len (2B)
      payload (s B)
      crc32 (4B): CRC-32 over header + payload
      
    Total shard size = 5 + s + 4 = shard_bytes.
    """
    s = prof.payload
    k = prof.k
    n = prof.n
    
    if len(ct) > k * s:
        raise ValueError(f"Ciphertext length ({len(ct)} bytes) exceeds profile capacity ({k * s} bytes)")

    # Pad ciphertext to exactly k * s bytes
    buf = ct.ljust(k * s, b"\x00")
    data_rows = [buf[i * s : (i + 1) * s] for i in range(k)]
    
    rs = RSCodec(n - k)
    par_rows = [bytearray(s) for _ in range(n - k)]
    
    # Column-wise RS encoding
    for b in range(s):
        col_bytes = bytes(data_rows[i][b] for i in range(k))
        cw = rs.encode(col_bytes)
        for j in range(n - k):
            par_rows[j][b] = cw[k + j]
            
    payloads = data_rows + [bytes(p) for p in par_rows]
    shards = []
    ct_len = len(ct)
    
    for i, payload in enumerate(payloads):
        header = struct.pack("!BBBH", i, k, n, ct_len)
        chunk = header + payload
        crc = struct.pack("!I", zlib.crc32(chunk))
        shards.append(chunk + crc)
        
    return shards

def recover_shards(
    shards_by_idx: dict[int, bytes | None],
    prof: Profile
) -> tuple[bytes | None, int]:
    """Recover original ciphertext from received shards using RS erasure decoding.
    
    Corrupted shards (failing CRC32) or missing shards are treated as known-position erasures.
    
    Returns:
        (recovered_ct, valid_shard_count):
        If valid_shard_count < k, recovered_ct is None.
    """
    valid = {}
    for idx, raw_shard in shards_by_idx.items():
        if raw_shard is None or len(raw_shard) != prof.shard_bytes:
            continue
        # Verify CRC32
        data_part = raw_shard[:-4]
        expected_crc = struct.unpack("!I", raw_shard[-4:])[0]
        if zlib.crc32(data_part) != expected_crc:
            continue
        valid[raw_shard[0]] = raw_shard

    valid_count = len(valid)
    if valid_count < prof.k:
        return None, valid_count

    # Extract metadata from any valid shard
    any_shard = next(iter(valid.values()))
    _, k, n, ct_len = struct.unpack("!BBBH", any_shard[:5])
    
    s = prof.payload
    rs = RSCodec(n - k)
    erased_positions = [i for i in range(n) if i not in valid]

    # Column-wise RS erasure decoding
    cols = [bytearray(s) for _ in range(k)]
    for b in range(s):
        cw = bytearray(n)
        for i in range(n):
            if i in valid:
                cw[i] = valid[i][5 + b]
        decoded = rs.decode(bytes(cw), erase_pos=erased_positions)[0]
        for i in range(k):
            cols[i][b] = decoded[i]

    recovered = b"".join(bytes(c) for c in cols)[:ct_len]
    return recovered, valid_count
