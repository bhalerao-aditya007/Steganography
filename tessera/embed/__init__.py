"""Embedding primitives and implementations for TESSERA v2 Mirage."""
from .profile import Profile
from .gf2 import gf2_solve, rows_to_ints
from .mirage import embed_tile, extract_tile, decoy_peek, H2_matrix
from .lsbm import embed_lsbm, extract_lsbm
from .naive_second_lsb import embed_naive_second_lsb
from .costs import compute_hill_costs

__all__ = [
    "Profile",
    "gf2_solve",
    "rows_to_ints",
    "embed_tile",
    "extract_tile",
    "decoy_peek",
    "H2_matrix",
    "embed_lsbm",
    "extract_lsbm",
    "embed_naive_second_lsb",
    "compute_hill_costs",
]
