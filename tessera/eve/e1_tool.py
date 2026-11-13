"""Eve E1: Forensic tool (StegSeek/StegExpose style dictionary attack)."""
import time
from ..crypto.kdf import master, hkdf
from ..embed.profile import Profile
from ..embed.mirage import decoy_peek
from ..decoy.messages import is_plausible_decoy

DEFAULT_WORDLIST = [
    "password", "123456", "admin", "welcome", "qwerty", "sunshine",
    "dragon", "baseball", "football", "letmein", "monkey", "shadow",
    "master", "superman", "starwars", "sunshine123", "charlie", "jordan",
    "freedom", "computer", "password123", "secret", "trustno1", "hunter2"
]

class EveE1ForensicTool:
    """Attempts dictionary attack against the decoy passphrase.
    
    CRUCIAL HONEY ENCRYPTION PROPERTY:
    Even when Eve guesses an incorrect passphrase (e.g. 'password'),
    the DTE maps the resulting pseudorandom seed to a perfectly coherent,
    plausible meeting note! Eve receives NO verification oracle.
    """
    def __init__(self, wordlist: list[str] | None = None):
        self.wordlist = wordlist or DEFAULT_WORDLIST

    def attack(
        self,
        stego_tile: "np.ndarray",
        salt: bytes,
        prof: Profile,
        t: int = 0,
        target_password: str = "sunshine123"
    ) -> dict:
        t0 = time.time()
        candidates = []
        found_target = False
        target_decoded_msg = None
        
        for word in self.wordlist:
            md_guess = master(word, salt, light=True)
            kd_guess = hkdf(md_guess, b"pos")
            decoded_msg = decoy_peek(stego_tile, t, prof, kd_guess)
            plausible = is_plausible_decoy(decoded_msg)
            
            is_match = (word == target_password)
            if is_match:
                found_target = True
                target_decoded_msg = decoded_msg
                
            candidates.append({
                "passphrase": word,
                "decoded_msg": decoded_msg,
                "plausible": plausible,
                "is_intended_decoy": is_match,
            })
            
        elapsed = time.time() - t0
        return {
            "elapsed_seconds": elapsed,
            "words_tested": len(self.wordlist),
            "found_intended": found_target,
            "intended_message": target_decoded_msg,
            "candidates": candidates,
            "honey_property_verified": all(c["plausible"] for c in candidates),
        }

    def inspect_single_guess(
        self,
        stego_tile: "np.ndarray",
        salt: bytes,
        prof: Profile,
        guess: str,
        t: int = 0
    ) -> dict:
        """Inspect what any arbitrary user-supplied guess yields."""
        md_guess = master(guess, salt, light=True)
        kd_guess = hkdf(md_guess, b"pos")
        decoded_msg = decoy_peek(stego_tile, t, prof, kd_guess)
        return {
            "guess": guess,
            "decoded_msg": decoded_msg,
            "plausible": is_plausible_decoy(decoded_msg),
        }
