"""TCP framing and stream transport (Baseline B0)."""
import struct

def frame_tcp_tile(tile_idx: int, tile_data: bytes) -> bytes:
    """Frame tile for TCP transmission: length(4B) | tile_idx(2B) | data."""
    length = 2 + len(tile_data)
    return struct.pack("!IH", length, tile_idx) + tile_data

def unframe_tcp_stream(stream_bytes: bytes) -> list[tuple[int, bytes]]:
    """Parse framed tiles from raw byte stream."""
    tiles = []
    offset = 0
    while offset + 6 <= len(stream_bytes):
        length, tile_idx = struct.unpack("!IH", stream_bytes[offset:offset+6])
        data_len = length - 2
        tile_payload = stream_bytes[offset+6 : offset+6+data_len]
        tiles.append((tile_idx, tile_payload))
        offset += 6 + data_len
    return tiles
