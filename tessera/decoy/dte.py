"""Distribution-Transforming Encoder (DTE) for Juels-Ristenpart Honey Encryption.

Maps structured categorical messages to and from a 64-bit seed space.
Crucial property: EVERY 64-bit seed (including those from wrong keys) decodes to a
syntactically valid and plausible decoy message.
"""
import os
import random

FIELDS = [
    ("act", [("MEET", 5), ("MOVE", 2), ("HOLD", 3), ("ABORT", 1)]),
    ("place", [
        ("old library", 4), ("north gate", 3), ("canteen", 5),
        ("bus stand", 3), ("lab block", 2), ("main gate", 4),
        ("sports ground", 2), ("station", 3)
    ]),
    ("day", [
        ("Mon", 3), ("Tue", 3), ("Wed", 3), ("Thu", 3),
        ("Fri", 4), ("Sat", 2), ("Sun", 1)
    ]),
    ("time", [
        (f"{h:02d}:{m:02d}", w)
        for h, w in zip(range(8, 22), [1, 2, 3, 3, 2, 2, 3, 3, 3, 3, 3, 2, 2, 1])
        for m in (0, 30)
    ]),
    ("code", [
        (w, 1) for w in [
            "falcon", "maple", "cobalt", "juniper",
            "orchid", "granite", "lantern", "saffron"
        ]
    ]),
]

SEEDBITS = 64

def dte_decode(seed: int) -> str:
    """Decode a 64-bit integer seed to a natural meeting note message."""
    lo, hi, out = 0, 1 << SEEDBITS, []
    for name, opts in FIELDS:
        W = sum(w for _, w in opts)
        width = hi - lo
        pos = ((seed - lo) * W) // width
        cum = 0
        for lbl, w in opts:
            if pos < cum + w:
                break
            cum += w
        out.append(lbl)
        lo, hi = lo + width * cum // W, lo + width * (cum + w) // W
    return f"{out[0]} @ {out[1]}, {out[2]} {out[3]}, code {out[4]}"

def dte_encode(msg_idx: list[int], rng_bytes: bytes | None = None) -> int:
    """Encode field indices into a uniformly chosen 64-bit seed within the message interval."""
    lo, hi = 0, 1 << SEEDBITS
    for (name, opts), idx in zip(FIELDS, msg_idx):
        W = sum(w for _, w in opts)
        width = hi - lo
        cum = sum(w for _, w in opts[:idx])
        w = opts[idx][1]
        lo, hi = lo + width * cum // W, lo + width * (cum + w) // W
    if rng_bytes is None:
        rng_bytes = os.urandom(8)
    r = int.from_bytes(rng_bytes, "big")
    return lo + (r % (hi - lo))

def sample_random_message() -> tuple[list[int], str, int]:
    """Sample a random message according to the field prior distribution."""
    indices = []
    for name, opts in FIELDS:
        weights = [w for _, w in opts]
        chosen = random.choices(range(len(opts)), weights=weights)[0]
        indices.append(chosen)
    seed = dte_encode(indices)
    msg = dte_decode(seed)
    return indices, msg, seed
