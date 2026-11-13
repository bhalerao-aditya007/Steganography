"""Fast linear system solver over GF(2) with Python bitsets.

Crucial for Mirage security:
When the system H_dry * d = rhs is underdetermined (more dry positions than syndrome bits r),
ALL free variables are sampled uniformly at random from {0, 1}.
This guarantees that the resulting bit-2 values (and therefore the modification signs)
are statistically independent and uniform, matching standard LSB matching.
"""
import numpy as np

def rows_to_ints(matrix: np.ndarray) -> list[int]:
    """Convert each row of a binary numpy matrix into a Python integer bitset."""
    out = []
    for row in matrix:
        if row.size == 0:
            out.append(0)
        else:
            # Bit 0 is row[0], bit 1 is row[1], etc.
            out.append(int("".join(map(str, row[::-1].tolist())), 2))
    return out

def gf2_solve(
    rows: list[int],
    rhs: list[int],
    ncols: int,
    rng: np.random.Generator
) -> np.ndarray | None:
    """Solve linear system H * x = rhs over GF(2).
    
    Args:
        rows: List of `r` integers, each representing a row of H of width `ncols`.
        rhs: List of `r` binary integers in {0, 1}.
        ncols: Number of columns (variables).
        rng: NumPy random generator to assign random bits to free variables.
        
    Returns:
        1D uint8 numpy array of size `ncols` solving H * x = rhs, or None if rank deficient.
    """
    r = len(rows)
    if r == 0:
        return np.zeros(ncols, dtype=np.uint8)
    
    # Augmented matrix: row_i | (rhs_i << ncols)
    R = [rows[i] | (int(rhs[i]) << ncols) for i in range(r)]
    used = 0
    piv = []
    
    # Forward elimination with full pivoting
    for c in range(ncols):
        p = next((i for i in range(used, r) if (R[i] >> c) & 1), None)
        if p is None:
            continue
        R[used], R[p] = R[p], R[used]
        pivot_row = R[used]
        for i in range(r):
            if i != used and ((R[i] >> c) & 1):
                R[i] ^= pivot_row
        piv.append(c)
        used += 1
        if used == r:
            break
            
    if used < r:
        # Rank deficient: fewer independent equations than rows
        return None
        
    # Free variables: sample uniformly from {0, 1}
    x = rng.integers(0, 2, ncols, dtype=np.uint8)
    for c in piv:
        x[c] = 0
        
    # Back-solve for pivot variables
    for k, c in enumerate(piv):
        row = R[k]
        mask = row & ((1 << ncols) - 1) & ~(1 << c)
        xi = 0
        m = mask
        while m:
            lb = m & -m
            col_idx = lb.bit_length() - 1
            xi ^= int(x[col_idx])
            m ^= lb
        x[c] = ((row >> ncols) & 1) ^ xi
        
    return x
