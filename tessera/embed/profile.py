"""Embedding profile configuration for TESSERA v2 and v3."""

class Profile:
    """Steganographic and erasure coding profile parameters."""
    def __init__(
        self,
        H: int = 512,
        W: int = 512,
        T: int = 32,
        alpha_d: float = 0.20,
        shard_bytes: int = 64,
        k: int = 24,
        rho_r: float = 0.6,
        margin: int = 24,
        decoy: str = "lsbm",
        v3: bool = False,
    ):
        self.H = H
        self.W = W
        self.T = T
        self.alpha_d = alpha_d
        self.shard_bytes = shard_bytes
        self.k = k
        self.rho_r = rho_r
        self.margin = margin
        self.decoy = decoy
        self.v3 = v3
        
        self.rows = H // T
        self.n = T
        self.r_bits = shard_bytes * 8
        
        if v3:
            # v3 framing: idx(1B) | body(59B) | CRC32(4B) = 64B
            # k, n, ct_len are carried in SYN header instead of each shard
            self.payload = shard_bytes - 1 - 4  # 59 bytes per shard body
            self.total_capacity = self.k * self.payload  # 24 * 59 = 1416 bytes
            self.max_secret_length = self.total_capacity - 12 - 16 - 2  # 1386 bytes
        else:
            # v2 framing: idx(1B) | k(1B) | n(1B) | L(2B) = 5B header; Footer: CRC32(4B)
            self.payload = shard_bytes - 5 - 4  # 55 bytes per shard body
            self.total_capacity = self.k * self.payload  # 24 * 55 = 1320 bytes
            self.max_secret_length = 1280

    def tile_slice(self, t: int) -> tuple[int, int]:
        """Compute pixel row range [r0, r1) for horizontal stripe tile `t`."""
        r0 = t * self.rows
        r1 = self.H if t == self.T - 1 else r0 + self.rows
        return r0, r1

    def n_d(self, t: int) -> int:
        """Number of decoy positions in tile `t`."""
        r0, r1 = self.tile_slice(t)
        return int(self.alpha_d * (r1 - r0) * self.W)

    def to_dict(self) -> dict:
        return {
            "H": self.H,
            "W": self.W,
            "T": self.T,
            "alpha_d": self.alpha_d,
            "shard_bytes": self.shard_bytes,
            "k": self.k,
            "n": self.n,
            "r_bits": self.r_bits,
            "payload": self.payload,
            "total_capacity": self.total_capacity,
            "margin": self.margin,
            "decoy": self.decoy,
            "v3": self.v3,
        }
