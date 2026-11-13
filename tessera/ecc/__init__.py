"""Error-correction and planning subsystem for TESSERA v2 Mirage."""
from .shards import make_shards, recover_shards
from .planner import plan, PlanResult, compute_p_fail, find_min_parity

__all__ = [
    "make_shards",
    "recover_shards",
    "plan",
    "PlanResult",
    "compute_p_fail",
    "find_min_parity",
]
