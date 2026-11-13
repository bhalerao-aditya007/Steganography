"""Decoy message templates and validation for plausibility checking."""
from .dte import FIELDS, dte_decode, dte_encode, sample_random_message

def is_plausible_decoy(msg: str) -> bool:
    """Validate whether an extracted decoy message conforms to the expected template."""
    try:
        # Expected format: "ACTION @ PLACE, DAY TIME, code WORD"
        parts = msg.split(" @ ")
        if len(parts) != 2:
            return False
        action = parts[0]
        rest = parts[1].split(", ")
        if len(rest) != 3:
            return False
        place = rest[0]
        day_time = rest[1].split(" ")
        if len(day_time) != 2:
            return False
        day, time_val = day_time
        code_part = rest[2]
        if not code_part.startswith("code "):
            return False
        code_word = code_part[5:]

        valid_acts = [lbl for lbl, _ in FIELDS[0][1]]
        valid_places = [lbl for lbl, _ in FIELDS[1][1]]
        valid_days = [lbl for lbl, _ in FIELDS[2][1]]
        valid_times = [lbl for lbl, _ in FIELDS[3][1]]
        valid_codes = [lbl for lbl, _ in FIELDS[4][1]]

        return (
            action in valid_acts and
            place in valid_places and
            day in valid_days and
            time_val in valid_times and
            code_word in valid_codes
        )
    except Exception:
        return False
