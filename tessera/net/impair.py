"""Network impairment simulator: loss, delay, reordering, and corruption."""
import random
import time

class NetworkImpairer:
    """Simulates real-world network impairments in-memory or on loopback sockets."""
    def __init__(
        self,
        loss_rate: float = 0.0,
        delay_ms: float = 0.0,
        reorder_rate: float = 0.0,
        bit_flip_rate: float = 0.0,
        rng_seed: int | None = None,
    ):
        self.loss_rate = loss_rate
        self.delay_ms = delay_ms
        self.reorder_rate = reorder_rate
        self.bit_flip_rate = bit_flip_rate
        self.rng = random.Random(rng_seed)
        self._delay_queue = []

    def process_packet(self, data: bytes) -> bytes | None:
        """Process an outgoing or incoming packet through the impairment pipeline.
        
        Returns:
            Packet bytes (possibly corrupted or delayed), or None if dropped (loss).
        """
        # 1. Packet Loss
        if self.loss_rate > 0 and self.rng.random() < self.loss_rate:
            return None  # Dropped
            
        # 2. Bit Flip Corruption
        if self.bit_flip_rate > 0 and self.rng.random() < self.bit_flip_rate and len(data) > 0:
            byte_arr = bytearray(data)
            flip_pos = self.rng.randint(0, len(byte_arr) - 1)
            byte_arr[flip_pos] ^= (1 << self.rng.randint(0, 7))
            data = bytes(byte_arr)

        # 3. Delay
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)

        return data
