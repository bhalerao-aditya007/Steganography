"""Joint Security-Reliability Planner for TESSERA v2 Mirage."""
import math
from scipy.stats import binom
from ..embed.profile import Profile

def compute_p_fail(n: int, r: int, p_tile: float) -> float:
    """Compute exact failure probability P(lost tiles > r) for RS(n, n-r)."""
    if r >= n:
        return 0.0
    # Probability of seeing at least r + 1 failures
    return float(1.0 - binom.cdf(r, n, p_tile))

def find_min_parity(n: int, p_tile: float, epsilon: float) -> int:
    """Find minimum parity shards r such that P_fail(r) <= epsilon."""
    for r in range(0, n):
        if compute_p_fail(n, r, p_tile) <= epsilon:
            return r
    return n - 1

class PlanResult:
    def __init__(
        self,
        feasible: bool,
        L: int,
        T: int,
        k: int,
        r: int,
        shard_bytes: int,
        alpha_d: float,
        p_tile: float,
        epsilon: float,
        p_fail: float,
        real_capacity: int,
        profile: Profile,
        reason: str = "",
    ):
        self.feasible = feasible
        self.L = L
        self.T = T
        self.k = k
        self.r = r
        self.shard_bytes = shard_bytes
        self.alpha_d = alpha_d
        self.p_tile = p_tile
        self.epsilon = epsilon
        self.p_fail = p_fail
        self.real_capacity = real_capacity
        self.profile = profile
        self.reason = reason

def plan(
    L: int,
    cover_shape: tuple[int, int] = (512, 512),
    p_tile: float = 0.05,
    epsilon: float = 1e-3,
    T_target: int = 32,
    shard_bytes: int = 64,
    rho_r: float = 0.6,
    max_alpha_d: float = 0.35,
) -> PlanResult:
    """Jointly plan erasure coding, tiling, and detectability parameters.
    
    Args:
        L: Secret plaintext length in bytes.
        cover_shape: (H, W) of the cover image.
        p_tile: Estimated tile erasure probability.
        epsilon: Maximum allowable loss failure probability.
        T_target: Desired tile count (default 32).
        shard_bytes: Size of each shard in bytes (default 64).
        rho_r: Real capacity ratio per change (default 0.6).
        max_alpha_d: Maximum allowable decoy embedding rate.
        
    Returns:
        PlanResult with detailed feasibility analysis.
    """
    H, W = cover_shape
    N = H * W
    s = shard_bytes - 9  # payload per shard (55 bytes)
    ct_len = L + 16      # Poly1305 16-byte tag
    
    k = math.ceil(ct_len / s)
    r = find_min_parity(T_target, p_tile, epsilon)
    n = T_target
    
    if k + r > n:
        # Cannot fit in T_target tiles with required parity
        return PlanResult(
            feasible=False,
            L=L,
            T=n,
            k=k,
            r=r,
            shard_bytes=shard_bytes,
            alpha_d=0.0,
            p_tile=p_tile,
            epsilon=epsilon,
            p_fail=1.0,
            real_capacity=k * s,
            profile=Profile(),
            reason=f"Payload {L}B needs k={k} shards + r={r} parity = {k+r} > T={n} tiles. Use smaller secret or larger cover."
        )

    # Use k shards, set parity r = n - k
    effective_r = n - k
    p_fail = compute_p_fail(n, effective_r, p_tile)
    
    # Decoy requirement: r_bits = 8 * shard_bytes
    r_bits = 8 * shard_bytes
    c_req = r_bits / rho_r  # required changes per tile
    n_d = int(c_req * 2.0)  # LSB matching changes ~ 50%
    
    pixels_per_tile = N / n
    alpha_d = n_d / pixels_per_tile
    
    if alpha_d > max_alpha_d:
        return PlanResult(
            feasible=False,
            L=L,
            T=n,
            k=k,
            r=effective_r,
            shard_bytes=shard_bytes,
            alpha_d=alpha_d,
            p_tile=p_tile,
            epsilon=epsilon,
            p_fail=p_fail,
            real_capacity=k * s,
            profile=Profile(),
            reason=f"Required decoy rate alpha_d={alpha_d:.3f} exceeds max detectability budget {max_alpha_d:.3f}."
        )

    prof = Profile(
        H=H,
        W=W,
        T=n,
        alpha_d=round(alpha_d, 3),
        shard_bytes=shard_bytes,
        k=k,
        rho_r=rho_r,
    )

    return PlanResult(
        feasible=True,
        L=L,
        T=n,
        k=k,
        r=effective_r,
        shard_bytes=shard_bytes,
        alpha_d=round(alpha_d, 3),
        p_tile=p_tile,
        epsilon=epsilon,
        p_fail=p_fail,
        real_capacity=k * s,
        profile=prof,
        reason="Optimal parameters satisfying reliability and security budgets."
    )
