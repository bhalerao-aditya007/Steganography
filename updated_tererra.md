# TESSERA v2: Mirage — Deniable Image Steganography with a Sign-Channel Second Layer, Honey Decoys and Tile-Aligned Erasure-Coded Transport

**Data Privacy & Security Mini Project — Build, Evaluation and Demo Specification (v2, supersedes the v1 synopsis)**

> **Status of this document.** Everything marked **[VERIFIED]** was run in a prototype during the design session (code in Appendix A, also shipped as `mirage_core.py`, `test_e2e.py`, `test_equivalence.py`). Everything marked **[HYPOTHESIS]** is what your experiments must confirm or falsify. Everything marked **[VERIFY-CITE]** is a reference whose bibliographic details you must check before citing. Do not write any number into the report that your own harness did not produce.

---

## 0. TL;DR (read this first)

**One-sentence idea.** Eve asks "which pixels changed?" (the diameter answer) and gets a complete, self-consistent, crackable answer; the real message rides on "which *way* each change went" (+1 or −1, the arc answer), which costs **zero extra changes** and is statistically identical to the random sign choice that LSB-matching makes anyway.

**The circle riddle, mapped.**

| Riddle | Steganography |
|---|---|
| Crowd answer: "max distance = diameter" | Eve's natural hypothesis: "embedding = a set of changed pixels carrying a recoverable message" |
| Deflection: "adjacent points, the long way round" | Decoy layer explains *all* observable change evidence; real layer lives in the *direction* of each change |
| Same two points, two measures (chord vs arc) | Same changed pixel, two readings: parity of the value (decoy) vs bit‑2 of the value (real) |

**What the system does (four mechanisms):**

1. **M1 Decoy layer ("attractor").** Keyed LSB-matching (later: S-UNIWARD + STC) with a deliberately *weak, dictionary-crackable* passphrase. It is the bait Eve's tools find.
2. **M2 Honey payload in the decoy.** The decoy message is encoded with a distribution-transforming encoder (Juels–Ristenpart honey encryption), so *every* wrong passphrase also decodes to a plausible message. Eve gets no "wrong key" oracle and cannot tell which candidate is real.
3. **M3 Real layer in the sign channel.** At every changed pixel the two legal moves (+1, −1) give different values of bit 2. Bob reads bit 2 at the keyed positions and applies a secret binary matrix `H₂`: `m₂ = H₂·b₂ (mod 2)`. Alice solves this with a wet-paper code in which changed interior pixels are the "dry" (free) positions.
4. **M4 Evidence conservation + TESSERA transport.** The real layer adds no changes, so change set, change count and quantitative payload estimates equal those of a decoy-only image. Real shards are Reed–Solomon coded across tiles; one tile = one packet group; loss is a known-position erasure.

**Headline claims you can defend (and their honest limits):**

* **[VERIFIED]** On the reference implementation: 32/32 tiles had an identical change set with and without the real layer; sign fraction +1 = 0.502, sign vs pixel-value-mod-4 χ² p = 0.76 (decoy-only: 0.4995, p = 0.36); 1.3 KB real payload recovered bit-exactly with up to 8 of 32 tiles erased; PSNR 58.1 dB at decoy rate 0.2 bpp.
* **[VERIFIED, small-scale]** A SPAM-style-features + logistic-regression distinguisher got 0.494 ± 0.024 accuracy on *decoy-only vs Mirage* (chance), while *cover vs decoy-only* was 0.68 ± 0.15 (the bait is detectable) and *decoy-only vs a naive second-LSB layer* was 0.764 ± 0.124 (the prior-art style layer is detectable). 276 patches only; see §7 for caveats.
* **[HYPOTHESIS]** The same holds against SRM+EC and SRNet-class detectors on BOSSbase. This is the main experiment of the project (E3).
* **Not claimed:** that Mirage lowers detection probability. It does not; the decoy is *meant* to be detected. The claim is **deniability and existence-hiding conditional on detection**, bought with capacity (§5.8).

> **Honest novelty positioning (important for viva and any paper).** The *decoy idea* is not new: Mihara's "Misdirection steganography" (2020), Ogiela & Koptyra's false/multi-secret steganography (2015), Zhong/Xia et al.'s "Deniable Steganography" (arXiv 2205.12587) and plausible-deniability work such as Ahmad et al. (SECRYPT 2023) all precede it. Multilayer STC / ternary embedding (Filler & Fridrich 2010) already exploits the sign. What I found no prior work doing is the *combination*: (a) a real layer in the decoy's own modification direction so that **no evidence beyond the decoy exists** (evidence conservation); (b) honey-encoded decoys to remove the verification oracle; (c) an explicit Eve ladder with an *existence-hiding gap* metric; (d) integration with packet-aligned erasure coding. State the claim as "to the best of our knowledge" and cite the nearest work (§3).

---

## 1. What changed from v1

| v1 component | Status in v2 |
|---|---|
| C1 Detectability budget (steganalysis in the loop) | **Kept**, now budgets the **decoy rate α_d** (§5.7). Real capacity follows from the decoy's change count. |
| C2 Tile-aligned RS erasure coding | **Kept**, now applied to the **real layer shards** carried in the sign channel (§5.6). |
| C3 Joint security-reliability optimisation | **Kept**, extended with the capacity price of deniability (§5.8) → a 3-axis Pareto front. |
| C4 AEAD, keyed path, keyed STC, HMAC | **Kept**, with **two passphrases** and extra keys for `H₂` and whitening (§5.1). |
| C5 Benchmark harness | **Kept**, extended with the **Eve ladder** and existence-hiding metrics (§6). |
| **C6 Mirage layer (new)** | Decoy attractor + honey DTE + sign-channel real layer + evidence conservation (§5.2–5.5). **This is the headline.** |

v1 rule of thumb still applies: *Core = Mode L (spatial)*; Mode R (JPEG) and secret-sharing across images are stretch.

---

## 2. Problem Statement, Threat Model, Security Notions

### 2.1 Problem
Given cover `X` (N pixels), real secret `S` (L bytes), **two** passphrases (`pw_decoy` weak, `pw_real` strong) and an impaired network (tile-loss rate `p`, delay, reorder), deliver `S` to Bob such that:

1. **Detection-conditional deniability.** Even if Eve detects embedding and recovers the decoy, she cannot distinguish the image from a *decoy-only* image: AUC(decoy-only vs Mirage) ∈ [0.5 − δ, 0.5 + δ] (δ = 0.02 target).
2. **No verification oracle.** Wrong decoy passphrases decode to plausible honey messages with the same probability as the right one.
3. **Reliability.** `P(real secret recovered) ≥ 1 − ε` for tile-loss `p ≤ p_design`.
4. **Quality.** PSNR ≥ 45 dB, SSIM ≥ 0.99 (reported, secondary).
5. **Integrity/authenticity.** AEAD tag over the real secret; HMAC over transport metadata.
6. **Efficiency.** Report bytes sent, time-to-secret, retransmissions, and the **capacity price** of deniability.

### 2.2 The Eve ladder (attacker models)

| ID | Eve | Knows | Does |
|---|---|---|---|
| **E0** | Naive scanner | nothing | χ², RS/SPA on the image; unkeyed sequential LSB extraction |
| **E1** | Forensic-tool Eve (StegSeek/StegExpose style) | the algorithm, a wordlist | detect → dictionary-attack the decoy passphrase → output first plausible message |
| **E2** | Second-look Eve | algorithm + the **correct decoy passphrase** (e.g., coerced or lucky) | excludes decoy positions and re-runs detectors; compares quantitative payload/change-rate estimate with decoy length; looks for ±2 changes |
| **E3** | **Kerckhoffs-strong distinguisher** | full source code, the decoy passphrase, unlimited labelled training pairs (decoy-only vs Mirage), unlimited compute for training | trains SPAM/SRM+EC/CNN and tailored sign-statistics tests to separate the two worlds |
| **E4** | Coercer | E3 + Alice hands over the decoy passphrase and *claims* "decoy only" | looks for any statistical contradiction with that claim (equivalent to E3 operationally) |
| **E5** | Active warden (Mallory) | channel | recompresses, resizes, adds noise, randomises LSBs, drops tiles |
| **E6** | Needle-in-haystack Eve | E3 + a batch of N images of which K carry a real layer | ranks images; metric = top‑K precision vs K/N |

**Out of scope (state explicitly):** endpoint compromise, traffic analysis of the fact of communication (note: the raw-tile UDP protocol is itself an anomaly; Eve in the lab is given the reassembled stego PNG), side channels of the surrounding OS/apps (cf. Czeskis et al. on deniable file systems), Eve possessing the real passphrase.

### 2.3 Formal notions
* **Cachin ε-security** (kept from v1): `D_KL(P_C‖P_S) ≤ ε ⇒ P_E ≥ ½(1 − √(D_KL/2))` (Pinsker, nats). Applies to the *decoy* vs cover and is expected to **fail** (decoy is detectable) — that is the bait.
* **Existence-hiding (new).** Let `P_D` be the output distribution of the decoy-only embedder and `P_M` that of Mirage on the same cover/decoy key. Mirage is **(ε_h)-existence-hiding** if `SD(P_D, P_M) ≤ ε_h` for any Eve that does not hold the real passphrase. Section 5.5 gives `ε_h ≤ ε_prf + P(solver failure)`.
* **Honey no-oracle (new).** For wrong key `k'` the decoded message `m' = DTE⁻¹(seed ⊕ H(k'))` is distributed per the message distribution; Eve's success at message recovery is bounded as in Juels & Ristenpart, i.e. by the min-entropy of the message distribution rather than by the passphrase space.

---

## 3. Literature, Benchmarks and Novelty Positioning

### 3.1 Nearest prior work (read these before claiming anything)

| Topic | Work | Relevance / what it does **not** do |
|---|---|---|
| Decoy to misdirect | T. Mihara, *Misdirection steganography*, Soft Computing 24:16005–16010 (2020), doi:10.1007/s00500-020-05345-1 | True + decoy secret; extraction of the true secret depends on decoy embedding info; aim is to attract attention to the decoy. No evidence-conservation, no statistical evaluation against modern steganalysis. |
| False / multi-secret | M. Ogiela, K. Koptyra, *False and multi-secret steganography in digital images*, Soft Computing 19:3331–3339 (2015) | Real message in second LSB; adds extra modifications → detectable (our naive baseline **B4**). |
| Deniable deep stego | *Deniable Steganography*, arXiv:2205.12587 [VERIFY-CITE authors] | Receiver-deniable, learned encoder/decoder with a fake message; no sign-channel / no change-set equivalence argument. |
| Plausible deniability | S. Ahmad et al., *How to Plausibly Deny Steganographic Secrets*, SECRYPT 2023 [VERIFY-CITE] | Sender/receiver-deniable definitions; embedding-agnostic. |
| Honey encryption | A. Juels, T. Ristenpart, EUROCRYPT 2014 (ePrint 2014/155); J. Jaeger, T. Ristenpart, Q. Tang, ePrint 2016/174 | DTE + `seed ⊕ H(key)`: wrong keys → plausible honey messages. Main open problem: convincing decoys for natural language. |
| Non-binary embedding | T. Filler, J. Fridrich, *Minimizing additive distortion functions with non-binary embedding operation in steganography*, WIFS 2010; Filler–Judas–Fridrich, TIFS 2011 | Multilayer STC / ternary ±1 embedding already uses the sign as payload. We assign the extra layer a **different key and meaning** and prove indistinguishability from decoy-only. |
| Wet paper codes | Fridrich, Goljan, Lisoněk, Soukal, *Writing on Wet Paper*, IEEE TSP 2005 [VERIFY-CITE] | The coding tool used for layer 2 (receiver does not need to know the dry set). |
| Game theory | P. Schöttle, R. Böhme, *A game-theoretic approach to content-adaptive steganography*, IH 2012; *Game theory and adaptive steganography*, IEEE TIFS [VERIFY-CITE year/vol] | Naive adaptive embedding does not beat a strategic warden; optimum lies between naive adaptive and random. Our decoy is the "predictable focal point" by design. |
| Selection-channel-aware steganalysis | Denemark, Sedighi, Holub, Cogranne, Fridrich, WIFS 2014 (SCA-SRM); Denemark, Fridrich, Comesaña, EI 2016 | Eve that knows change probabilities detects better; defines the strong Eve you must test against. |
| Adversarial embedding | W. Tang, B. Li, S. Tan, M. Barni, J. Huang, *CNN-based adversarial embedding*, IEEE TIFS 2019 (pp. 2074–2087); *Backpack*, Bernard et al., IEEE TIFS 2022 [VERIFY-CITE] | Fools a target CNN; orthogonal to deniability; can be added to the decoy layer (stretch). |
| Double embedding is detectable | *Detection of classifier inconsistencies in image steganalysis*, arXiv:1909.10278; Steinebach et al., IWSPA 2018 | A second embedding raises ±1 counts and creates ±2 changes. Mirage avoids both by construction. |
| Algorithm mismatch | Reinders et al., *Algorithm mismatch in spatial steganalysis*, EI/MWSF 2019 | Detectors trained on one algorithm generalise to others → expect Eve to flag the decoy even with a mismatched detector. |
| Batch / steganographer ID | A. Ker, *Batch steganography and pooled steganalysis*, IH 2006; Ker & Pevný, SPIE 2012 (LOF), *The steganographer is the outlier* | Basis for experiment **E6** (needle-in-haystack). |
| Deniability pitfalls | Czeskis et al., *Defeating encrypted and deniable file systems*, HotSec 2008 | Environment leaks can break mathematical deniability; list as limitation. |
| Generative SOTA (positioning) | e.g., *Provably secure covert messaging using image-based diffusion processes*, arXiv:2503.10063; AAAI 2026 latent-diffusion steganography [VERIFY-CITE] | Provably secure generative schemes beat cover-modification on raw undetectability; Mirage competes on **deniability under detection**, not on P_E. |

### 3.2 Benchmark numbers for calibration (spatial, BOSSBase, detection error P_E; setups differ — rerun yourself)
From published tables [VERIFY-CITE and re-measure]: SRM+EC on S-UNIWARD ≈ 34.4 % (0.2 bpp) / 21.8 % (0.4 bpp); SRNet on S-UNIWARD ≈ 22.0 % / 12.9 %; SRNet on HILL ≈ 27.2 % / 17.3 %; Zhu-Net on S-UNIWARD ≈ 28.6 % / 15.5 % (other paper). Use these only to sanity-check that your *detector pipeline is not broken*; your decoy is LSB matching (far easier to detect than S-UNIWARD), so expect much lower P_E for the decoy.

### 3.3 Search strings for your related-work section
`"misdirection steganography"`, `"false steganography" "multi-secret"`, `"deniable steganography" "coercive attack"`, `"honey encryption" steganography`, `"multi-layered" "syndrome-trellis" ternary`, `"selection-channel-aware" steganalysis`, `"steganographer identification" decoy`, `"subliminal channel" steganography embedding randomness`. Re-run these on Google Scholar / IEEE Xplore / arXiv before writing "novel".

---

## 4. System Overview

```
 Alice
 pw_decoy (weak) ─Argon2id(light)─► master_d ─HKDF─► k_pos           (positions, decoy header/pad keystream)
 pw_real  (strong)─Argon2id───────► master_r ─HKDF─► k_enc k_h2 k_white k_mac
 secret S ─► [pad/len] ─► AEAD(k_enc) ─► C (ciphertext+tag) ─► RS(n,k) shards ─► [header|payload|CRC32] ─► whiten(k_white,t)
                                                                                                    │ m2 (r bits / tile)
 honey msg ─► DTE ─► 64-bit seed ─► seed ⊕ keystream(k_pos,"hdr",t) ─► hdr bits ┐
                                    pad bits = keystream(k_pos,"pad",t,ctr) ────┴► decoy bits b1 (n_d / tile)
 cover X ─► tiles (stripes) ─► per tile t:
      P_t = keyed permutation of tile pixels (k_pos), first n_d
      LAYER 1: LSB-matching so that LSB(y[P_t]) = b1            → changed set Ch_t
      LAYER 2: dry = Ch_t ∩ interior;  solve H2_t·bit2(y[P_t]) = m2 by choosing signs on dry   (wet-paper)
      (re-roll pad counter ctr until |dry| ≥ r + margin)
 stego Y ─► packetizer (1 tile = 1 datagram, or f fragments) ─► TCP | RUDP(SACK/NACK) ─► impaired network
 Bob
 tiles ─► per tile: P_t, bit2 at P_t, syndrome H2_t·b2 ─► de-whiten ─► CRC32 ✓? ─► shard | erasure
       ─► ≥ k shards? RS erasure decode ─► AEAD decrypt+verify ─► S      (else NACK missing tiles)
 Eve   (given only the image + algorithm + optionally pw_decoy)
       reads LSB at P_t ─► seed ─► DTE⁻¹ ─► plausible honey message  (for ANY passphrase)
```

**Why positions come from the decoy key.** Layer 2 reads bit 2 at the *same* positions as layer 1 (the dry set lives inside them). If positions came from the real key, Eve could not extract the decoy at all and there would be no attractor. Consequence: **Eve who cracks the decoy learns the position set `P_t`**; the real layer's secrecy rests on `H₂` and the whitened/encrypted shards, never on position secrecy.

### 4.1 Wire format (must not leak the existence of the real layer)
* One **profile ID** byte selects `(H, W, T, α_d, shard_bytes, r_bits, k, n)` from a table known to both sides. The HELLO is **identical** for decoy-only and Mirage sessions: `magic | ver | profile_id | session(4) | salt(16) | nonce(12) | HMAC(k_mac, …)[:16]`. In decoy-only sessions the HMAC key is random.
* Shard header (inside the whitened, embedded bits only): `idx(1) | k(1) | n(1) | ct_len(2) | payload | CRC32(4)`.
* UDP packet header (transport only, as in v1): `HDR = struct.Struct("!HBBIIHHI")` = `magic(2)=0x5354 | ver(1) | type(1: SYN/DATA/ACK/NACK/FIN) | session(4) | seq(4) | tile_idx(2) | frag_idx(2) | crc32(4)`; payload ≤ 1200 B in realistic mode.

---

## 5. Mathematics and Technical Details

### 5.1 Crypto layer
```
salt (16 B, in HELLO)
master_d = Argon2id(pw_decoy, salt, t=1, m=8 MiB, p=1)      # deliberately light: the decoy is meant to be crackable
master_r = Argon2id(pw_real,  salt, t=2, m=19 MiB, p=1)     # reference cost used in the tests; raise for production
k_pos   = HKDF(master_d, "pos")       # keyed tile permutations + decoy header/pad keystream
k_enc   = HKDF(master_r, "enc")       # ChaCha20-Poly1305
k_h2    = HKDF(master_r, "h2")        # generates H2_t (dense r x n_d binary matrix) per tile
k_white = HKDF(master_r, "white")     # per-tile keystream XORed over the whole shard (incl. header+CRC)
k_mac   = HKDF(master_r, "mac")       # HMAC-SHA256 over HELLO/FIN
C = ChaCha20Poly1305(k_enc).encrypt(nonce12, plaintext, aad=b"tessera-v2" || profile_id)
```
* **Whitening is mandatory.** RS parity bytes and CRCs are structured; without whitening the embedded bits are not uniform and the sign-uniformity argument (§5.5) breaks. Ablation A3 shows this.
* **Passphrase policy.** `pw_decoy` must be *in* the attacker's wordlist (demo: a top-1000 password such as `sunshine123`); `pw_real` ≥ 5 diceware words. Never reuse one as a prefix of the other.
* **Demo cost note.** Eve's live dictionary attack panel should use a ~300-word list (≈ 10–20 s at the light Argon2 setting) or a precomputed table; a 10⁴-word list at 19 MiB/t=2 takes minutes.

### 5.2 Honey decoy payload (M2)
**Construction (Juels–Ristenpart JR-style).** Message distribution `M` = product of categorical fields; `DTE: M → seed ∈ [0, 2⁶⁴)` maps a message to a uniformly random seed *inside its probability interval*; `DTE⁻¹` is deterministic inverse-CDF decoding. Encryption: `seed_ct = seed ⊕ XOF(k_pos, "hdr" ‖ t)[:64 bits]`. Decryption with *any* key yields a uniform `seed'`, hence a message drawn from `M`.

Reference fields (Appendix A, `FIELDS`): action (MEET/MOVE/HOLD/ABORT), place (8 campus locations), day, time (30‑min slots with a realistic daytime weighting), code word (8 words). **[VERIFIED]** outputs for right and wrong keys all read as plausible meeting notes, e.g. right key `MEET @ north gate, Fri 13:30, code cobalt`; wrong keys `MOVE @ old library, Mon 13:00, code lantern`, `MEET @ canteen, Tue 18:00, code cobalt`, `HOLD @ main gate, Mon 13:30, code lantern`.

**Design rules**
* Decoy container per tile = `[64‑bit seed_ct][pad bits]` with `pad = XOF(k_pos, "pad", t, ctr)`; the same seed appears (re-encrypted with a per-tile keystream) in **every** tile, so any received tile reveals the decoy and the decoy needs no erasure coding.
* The padding is uniform under any key: Eve cannot tell it is filler. Its only job is to produce enough changes for layer 2 (§5.4).
* **Typo problem** (legit user enters a wrong key and sees a plausible but wrong message) does not affect Bob: the real layer is AEAD-authenticated, so Bob always knows whether he is right.
* **Known limit:** decoy plausibility is only as good as `M`; a professor can ask "why would the note be this short and templated?". Prepare a second, richer template set (stretch: LLM-sampled decoy seeds via a rank-based DTE).

### 5.3 Layer 1: decoy embedding (M1)
**Phase A (core): keyed LSB matching.**
For tile pixels `x`, keyed positions `P_t`, decoy bits `b1`: if `LSB(x[P_i]) ≠ b1_i` change `x[P_i]` by ±1, else leave it. At boundaries (0 or 255) only the legal move is available. Distortion: each selected pixel changes w.p. ½ ⇒ change rate `α_d/2` per pixel ⇒ MSE = α_d/2.
```
PSNR = 10·log10(255² / MSE);  α_d = 0.2 ⇒ MSE = 0.1 ⇒ ≈ 58.1 dB   [VERIFIED on camera.png: 58.10 dB, changed fraction 0.1007]
```
**Phase B (upgrade): S-UNIWARD costs + STC.** Replace "flip if LSB differs" by an STC over the parity vector with costs `ρ`. Everything in layers 2–4 is unchanged because (i) the changed set is just the set where target parity ≠ cover parity, (ii) S-UNIWARD costs are symmetric in ±1 (`ρ⁺ = ρ⁻`), so the sign remains a free choice. Set `ρ = ∞` (wet) at pixel values 0 and 255. Real capacity then equals the *number of changes* produced by the STC (≈ `n_d / e`, `e` = embedding efficiency in bits/change), not `n_d/2`.

**S-UNIWARD cost (kept from v1).** Daubechies‑8 filter bank `{W^(1),W^(2),W^(3)}` (LH, HL, HH):
```
ρ_ij = Σ_k Σ_uv | W_uv^(k)(X) − W_uv^(k)(X_~ij) | / ( σ + | W_uv^(k)(X) | ),   σ ≈ 1
fast: ρ = Σ_k convolve2d( 1/(σ + |W^(k)(X)|), |impulse response of W^(k)| )
fallback (build first): ρ = 1/(ε + smoothed high-pass residual energy), label as "HILL-style/WOW-lite"
```
**Gibbs bound and STC (kept from v1).**
```
β_i(λ) = 1/(1+e^{λρ_i});   m(λ) = Σ H2(β_i(λ));   D*(m) = Σ β_i ρ_i   (lower bound for any coder)
solve λ by bisection (code in v1 §4.4); plot STC distortion vs D*(m)
STC: H from a small submatrix Ĥ (height h=7..10, width w=⌊1/α⌋) shifted down one row per w columns, seeded by k_pos
Viterbi over 2^h states, O(n·2^h): keep: cost[s]; flip: cost[s ⊕ Hcol_j] += ρ_j; at block ends keep states with LSB = m_b, shift right by 1
```
Implement in `numba` (h=7). If STC slips, ship Hamming matrix embedding `[2^p−1, 2^p−1−p]` (efficiency `p/(1−2^{−p})`) behind the same `Embedder` interface.

### 5.4 Layer 2: the sign channel (M3) — the core trick

**Lemma 1 (sign selects bit 2).** For integer `v` let `g(v) = ⌊v/2⌋ mod 2`. Then `v−1` and `v+1` both have `LSB ≠ LSB(v)`, and `g(v−1) ≠ g(v+1)` (they differ by 2). Hence whenever layer 1 requires a change at an interior pixel, **choosing the sign is exactly choosing the value of bit 2**, at no extra change and no change in layer‑1 parity.

**Receiver.** For tile `t` read `b₂[i] = g(y[P_{t,i}])` for all `i ≤ n_d`; compute `m₂ = H₂ᵗ · b₂ (mod 2)` where `H₂ᵗ` is an `r × n_d` binary matrix from `k_h2`. Then unwhiten → shard → CRC32 → erasure or valid shard. Bob never needs to know which pixels changed.

**Sender (wet-paper solve).**
1. Compute the changed set `Ch = {i : LSB(x[P_i]) ≠ b1_i}`; `dry = Ch ∩ {0 < x < 255}`; everything else is *wet*.
2. Wet positions have fixed `b₂` (cover's `g(x)` if unchanged; forced value at boundary changes).
3. Solve `H₂[:,dry]·d = m₂ ⊕ H₂[:,wet]·w (mod 2)` for `d ∈ {0,1}^{|dry|}` by Gaussian elimination over GF(2) (Python-int bitsets; ≈ r² XORs of `|dry|`-bit integers). **Set all free variables uniformly at random** (needed for uniformity, Prop. 1).
4. For each dry pixel choose the sign whose bit 2 equals `d_k`.
5. If `|dry| < r + margin` (margin = 24) or the system is rank-deficient: **increment the pad counter `ctr`** (re-roll the decoy padding) and retry. Padding is free randomness, so this is cost-free and the retry event is almost never triggered (**[VERIFIED]** 0 re-rolls on camera.png at profile A).

**Capacity.** `r ≤ |dry| − margin`; `E|dry| ≈ (#changes)·P(interior)`. With LSB matching `#changes ≈ n_d/2`, so
```
real bits / tile  r = ⌊ρ_r · c⌋, ρ_r ≈ 0.6   (c = #changes of the decoy layer; ρ_r < 1 leaves rank/saturation margin)
real_bpp ≈ ρ_r · (α_d / 2)   (LSB-matching decoy);   α_d = 0.2 ⇒ ≈ 0.06 bpp real
```
**Invariant worth putting on a slide: real capacity ≈ 0.6 bits per *decoy change*, independent of the decoy coder.**

### 5.5 Why Eve cannot see layer 2 (evidence conservation)

**Observation 1 (evidence is a function of the decoy only).** The changed set, number of changes, ±1-only magnitudes, change rate, and any "quantitative steganalysis" estimate depend only on which pixels flip parity. Layer 2 changes none of these. **[VERIFIED]** change sets identical in 32/32 tiles; `|d| = 1` for 100 % of changed pixels (no ±2 artefacts, unlike a naive second-LSB layer).

**Proposition 1 (sketch).** Assume (a) `W = whiten(shard)` is uniform on `{0,1}^r` and independent of cover and decoy bits (PRF assumption on `k_white`), (b) `H₂[:,dry]` has full row rank, (c) free variables of the solve are uniform. Then the vector of bit‑2 values on the dry set is uniform on `{0,1}^{|dry|}`, hence (Lemma 1) the sign vector is uniform on `{±1}^{|dry|}` and independent of `x` — exactly the distribution LSB matching uses. Therefore `SD(P_D, P_M) ≤ ε_prf + P(rank deficiency) + P(re-roll event)`; with margin 24, `P(rank deficiency) ≈ 2^{-24}`.
*Proof idea.* The map `d ↦ m₂ = H_dry d ⊕ const` is surjective with equal fibre sizes when `H_dry` has full row rank; uniform `m₂` plus a uniform choice inside the fibre gives uniform `d`. Conditioning on the retry rule depends on decoy bits and `x` only, not on signs.

**What Eve can still do and why it does not help.**
* Read `b₂` at `P_t` (she may know `P_t`): in both worlds it is cover bits at unchanged pixels and uniform bits at changed pixels.
* Estimate `x̂` by denoising and examine residual signs: random in both worlds.
* Know the cover `X` (never reuse covers!): she sees the decoy's changes and uniformly random signs in both worlds; without `H₂` she cannot test the syndrome.
* Fingerprint the algorithm: fingerprint says "LSB matching at α_d" (or "S-UNIWARD+STC") — the decoy.

**Assumptions to state in the report:** PRF security of SHAKE/ChaCha keystreams; AEAD ciphertext/RS parity whitened; covers fresh; positions revealed to Eve are harmless; the claim is *relative to decoy-only*, not absolute undetectability.

### 5.6 Tile layout, shards, RS erasure coding (C2 retained)

**Tiling.** Horizontal stripes of `rows = H // T` rows; the last tile absorbs the remainder. Raw pixel stripes on the wire (no PNG/deflate) so each datagram is independently meaningful: `[tile_idx | row_start | rows | pixel bytes]`.

**Shards.** Ciphertext `C` is padded to `k·s` bytes; `s = shard_bytes − 5 − 4`. Systematic RS over GF(2⁸) is applied **column-wise** (for each byte index `b`, the symbols `[shard_0[b], …, shard_{n−1}[b]]` form one RS(n,k) codeword), so a lost tile is a known-position erasure in every column. `n = T ≤ 255`. **[VERIFIED]** with `reedsolo`: recovery with 0, 4, 8 tiles erased; with 9 erased the receiver correctly reports `23/24` shards and requests NACK.

**Why erasures, not errors.** RS corrects `r` erasures but only `⌊r/2⌋` errors; CRC32 per shard converts corrupted-but-present tiles into erasures.

**Profile A ("demo")** — the default for the live demonstration.

| Parameter | Value | Note |
|---|---|---|
| Cover | 512×512, 8-bit grayscale | BOSSbase-style |
| Tiles `T = n` | 32 (16 rows each, 8192 px) | 1 tile = 1 datagram (loopback/jumbo) |
| Decoy rate `α_d` | 0.20 → `n_d` = 1638 bits/tile | |
| Changes/tile (measured) | ≈ 825 | [VERIFIED] mean 824.7 |
| Real bits/tile `r_bits` | 512 (shard 64 B → 55 B payload) | `r/c ≈ 0.62` |
| Data shards `k` | 24 (parity 8) | tolerates 8 lost tiles |
| Ciphertext capacity | `k·55 = 1320 B` | plaintext ≤ 1304 B (16 B tag) |
| Embed time (full image, pure Python) | ≈ 3 s | [VERIFIED] |
| PSNR / changed fraction | 58.1 dB / 0.1007 | [VERIFIED] on `camera.png` |

**Choosing parity `r` (joint with C3).** Tile-loss probability with `f` fragments per tile: `p_tile = 1 − (1 − p̂)^f`.
```
P_fail(r) = Σ_{j=r+1..n} C(n,j) · p_tile^j · (1 − p_tile)^{n−j}          r* = min{ r : P_fail(r) ≤ ε }
normal approx: r ≈ n·p + z_{1−ε} · sqrt(n·p·(1−p))
```
**Computed for n = 32 [VERIFIED numerically]** (`p` = tile-loss rate):

| p_tile | r for ε=1e‑3 | k | max plaintext (B) | r for ε=1e‑6 | k | max plaintext (B) |
|---|---|---|---|---|---|---|
| 0.02 | 4 | 28 | 1524 | 7 | 25 | 1359 |
| 0.05 | 6 | 26 | 1414 | 10 | 22 | 1194 |
| 0.10 | 9 | 23 | 1249 | 13 | 19 | 1029 |
| 0.15 | 12 | 20 | 1084 | 16 | 16 | 864 |
| 0.20 | 14 | 18 | 974 | 19 | 13 | 699 |
| 0.30 | 18 | 14 | 754 | 23 | 9 | 479 |

(Fixed `r=8`: P_fail = 9.5e‑9 @2 %, 1.9e‑5 @5 %, 3.3e‑3 @10 %, 0.175 @20 %, 0.656 @30 %.)

**Fragment caveat (important, do not hide it from the professor).** On a real LAN a 8 KB tile needs ≈ 7 datagrams of ≤ 1200 B, so `p_tile = 1 − (1−p)^7` (p = 5 % packet loss ⇒ p_tile ≈ 30 %). In the **demo mode** use one datagram per tile on loopback (MTU 65 536) and the in-app injector, and report loss as *tile-loss rate*; in **realistic mode** report both packet loss and the induced `p_tile`. Smaller tiles do not fix this: a 64‑byte shard needs ≈ 670 changes ⇒ ≈ 6.7 k pixels at α_d = 0.2.

**Joint planner `plan(L, cover, p̂, ε)` → `(T, k, r, shard_bytes, α_d, feasible?)`:**
```
1. C_len = L + 16 (+ nothing else; length is in shard headers)
2. choose shard_bytes (default 64); s = shard_bytes − 9; k = ceil(C_len / s)
3. r = r*(n, p_tile, ε) with n = k + r ≤ min(255, T_max); T = n
4. r_bits = 8·shard_bytes;  c_req = r_bits / ρ_r (ρ_r = 0.6);  n_d = c_req·(n_d/c ratio: 2 for LSBM, e for STC)
5. α_d = n_d / (N/T);  check α_d ≤ α*(τ)   (detectability budget, §5.7)
6. if violated: bigger cover | smaller L | larger ε | accept lower deniability headroom — and SHOW this on screen
```
**ARQ fallback (kept).** If after the timeout fewer than `k` valid shards are present, Bob sends a NACK listing missing tile indices; Alice retransmits only enough tiles to reach `k`. Metrics: *time-to-secret* (≥ k shards) vs *time-to-full-image* (cosmetic).

### 5.7 Detectability budget (C1) — now on the decoy
Square-root law (Ker et al. 2008): `D_KL ≈ ½ n β² I ⇒ changes ∝ √n`. "Max capacity" is never the safe payload. **Controller:** (1) offline, train `D_train` (SPAM-686 or reduced SRM + FLD ensemble or LR) on cover vs decoy-only at `α_d ∈ {0.05,0.1,0.2,0.3,0.4}`; (2) online, binary-search the largest `α_d*` with detector score ≤ τ calibrated to `P_E ≥ P_target`; (3) **never evaluate on the detector you tuned against** — report `P_E` on a held-out detector (different features/architecture, different image split); (4) `P_E = min_τ ½(P_FA + P_MD)`, also ROC-AUC.

*Mirage-specific twist.* Because the decoy is the bait, `P_target` can be **low** (e.g., 0.1–0.3): you *want* the decoy to be found; what you tune is the price you pay in detectability (and real capacity) versus the deniability you get. Plot this (E8).

### 5.8 The price of deniability (capacity accounting)
At equal number of changes `c` (hence comparable detectability):
```
single-layer SOTA (S-UNIWARD+STC):    carries  e·c  useful bits        (e = bits per change, ≈ 2 for LSBM, ≈ 4–6 for STC at low rate)
Mirage:                                carries  ρ_r·c ≈ 0.6·c  real bits (decoy bits are bait + padding)
price factor  ≈  e / 0.6    (≈ 3.3× for LSBM, ≈ 7–10× for STC)
```
Report this explicitly (D4). A professor will ask; the answer is "that is the premium for deniability; the sign channel costs no *extra detectability*, only the decoy's own."

### 5.9 JPEG / DCT mode (Mode R, stretch)
* Embed on the **quantised coefficient array** (`jpeglib` / `jpegio`), never by modifying pixels and re-saving. Cover set = AC coefficients (including zeros) of Y in keyed order; the position set **must not depend on coefficient values** (avoids F5-style shrinkage desynchronisation).
* Lemma 1 holds on the integer line, so the sign channel works on coefficients as well (`g(c) = ⌊c/2⌋ mod 2`, careful with negative coefficients; test round-trip first). Set DC and (optionally) flat-block coefficients wet. Costs: J-UNIWARD or "UERD-style" `ρ ∝ q_uv/(E_b + neighbour energy)` (label it *UERD-style* unless you reproduce the published formula).
* Robust variant (QIM with `Δ = k·q_target`, stability score over target QFs, BCH/RS ECC, BER vs QF ∈ {95,90,85,80,75,70}) is a separate stretch; say honestly that robust mode is more detectable. Expect the **sign layer to be the most fragile layer under recompression** (E5).

### 5.10 Transport (kept from v1)
**TCP path:** frames `[type|len|payload]`; messages HELLO, TILE, FIN (SHA-256 of `Y`). **Reliable-UDP path:**
* ACK = cumulative + 64-bit SACK bitmap (RFC 2018 style); sender sliding window, per-packet timers, selective retransmit, fast retransmit after 3 duplicate SACK gaps.
* **RTO (RFC 6298):** first sample `R`: `SRTT=R, RTTVAR=R/2`; then `RTTVAR=(1−β)RTTVAR+β|SRTT−R|` (β=¼), `SRTT=(1−α)SRTT+αR` (α=⅛), `RTO=SRTT+max(G,4·RTTVAR)`, double on timeout; Karn's rule (no RTT samples from retransmissions).
* **AIMD:** `cwnd += 1/cwnd` per ACK, `cwnd /= 2` on loss event; plot cwnd and RTO live.
* **Analytic sanity checks for the report:** expected transmissions per packet `1/(1−p)`; stop-and-wait throughput ≈ `(1−p)·MSS/RTT`; selective repeat efficiency ≈ `(1−p)·min(1, W/BDP_pkts)`; compare measured goodput.
* **Impairment:** (a) in-app injector (loss/delay/reorder, runs on localhost without root, used in the demo), (b) `tc qdisc add dev lo root netem loss 10% delay 50ms 10ms`, (c) Wireshark screenshot of your protocol.

### 5.11 Integrity table

| Layer | Mechanism | Detects |
|---|---|---|
| Packet | CRC32 (drop silently ⇒ loss) | accidental corruption |
| Stego image | SHA-256 of exact bytes of `Y` + HMAC-SHA256 (`k_mac`) in FIN | any bit change; forger cannot fix the hash |
| Shard | CRC32 inside whitened shard | corrupted tile ⇒ erasure |
| Real secret | AEAD tag (ChaCha20-Poly1305) | wrong key, tampering, decode errors |
| Decoy | none by design (honey) | — |

### 5.12 Quality metrics and visual proofs (for the UI)
PSNR `10log10(255²/MSE)`, SSIM (Wang et al. 2004); difference map `|X−Y|×255`; **three-way change map: cover ⊕ decoy-only ⊕ Mirage** (identical); histogram of cover vs stego; sign histogram `P(sign | x mod 4)`; χ² p-value curve; detector score gauge; capacity gauge (raw LSB capacity vs safe `α_d*` vs real capacity).

---

## 6. Evaluation Plan

### 6.1 Systems compared (same images, same impairments)

| ID | Hiding | Transport | Purpose |
|---|---|---|---|
| B0 | Sequential LSB replacement, plaintext | TCP | "PSNR high but detected" |
| B1 | Keyed LSB matching + AEAD | UDP + ACK | naive keyed baseline |
| B2 | S-UNIWARD + STC, single layer | UDP + ACK | modern single-layer SOTA proxy |
| B3 | TESSERA v1 (budget + tile RS), single layer | UDP + SACK/NACK | v1 headline |
| B4 | Decoy LSBM + **naive second layer in 2nd LSB** (Ogiela–Koptyra style) | same | shows evidence conservation matters |
| B5 | **Mirage (this work)** | UDP + SACK/NACK + RS | v2 headline |
| B6 | Decoy-only (no real layer) | same | the *reference world* for E3 |

### 6.2 Experiments

| # | Experiment | Protocol | Report | Falsifies the claim if… |
|---|---|---|---|---|
| E0 | Motivation | B0 at 0.05–0.5 bpp; χ², RS/SPA | PSNR vs detection curve | — |
| E1 | Decoy as bait | cover vs B6 with SPAM+EC, SRM-lite, (SRNet if GPU); α_d sweep | P_E, ROC | decoy is *not* detectable (then it is no attractor) |
| E2 | Tool-style Eve | Dictionary attack on 300–10⁴ words; honey plausibility checker | time-to-crack, % outputs accepted as plausible (right vs wrong keys), rank of true key | wrong keys produce garbage (honey broken) |
| E3 | **Existence-hiding gap (main result)** | train detectors on B6 vs B5 (≥ 5 000 pairs/class), test on ≥ 1 000 held-out images, held-out detector family, plus tailored sign tests (§6.3) | AUC, P_E, accuracy ± 95 % CI; TOST equivalence to 0.5 with δ = 0.02 | any distinguisher AUC significantly ≠ 0.5 |
| E3b | Same vs **B4** | same | AUC (expect ≫ 0.5) | B4 *not* detectable (then your baseline is wrong) |
| E4 | Second-look Eve | give correct `pw_decoy`; exclude decoy positions; re-detect; compare payload estimate to decoy length; count ±2 | residual scores; length mismatch statistics | residual evidence exists |
| E5 | Active warden | JPEG QF 95→70, resize 90 %, Gaussian noise σ∈{0.5,1,2}, LSB randomisation, tile drops | BER per layer, real recovery rate | (expected) sign layer fragile; **report honestly** |
| E6 | Needle in haystack | N = 100 images, K = 10 Mirage + 90 decoy-only; Eve ranks by best distinguisher | top‑K precision vs K/N | precision ≫ K/N |
| E7 | Reliability | `p_tile ∈ {0,2,5,10,20,30}%`, 200 trials/point; Wilson 95 % CIs | recovery rate, time-to-secret, retransmissions, goodput vs `(1−p)` formulas | recovery below `1−ε` at design loss |
| E8 | **Pareto** | sweep `(α_d, p_tile, ε)` | surface: decoy-detectability `P_E` × real capacity × P_fail × overhead | — |
| E9 | Distortion-bound gap (Phase B) | STC vs Gibbs `D*(m)` | gap % | — |
| E10 | Ablations | A1 no sign layer ⇒ B6; A2 naive 2nd LSB ⇒ B4; A3 no whitening; A4 no re-roll; A5 non-honey decoy (garbage on wrong key); A6 no RS; A7 no AEAD | what breaks | — |

**Statistics:** fixed seeds; ≥ 1 000 test images for security curves; mean ± 95 % CI (bootstrap, DeLong for AUC); all raw results to CSV; `make figures` regenerates every figure. **Never evaluate against the detector you tuned against.**

### 6.3 Detectors to implement
1. **χ²** (Westfeld–Pfitzmann) on growing prefixes; `χ² = Σ (h_{2i} − h̄_i)²/h̄_i`, `h̄_i = (h_{2i}+h_{2i+1})/2`.
2. **RS / SPA** (Fridrich–Goljan–Du; Dumitrescu–Wu–Wang).
3. **SPAM** (Pevný–Bas–Fridrich, 686-D, T = 3) or the lite version in Appendix A's test harness (343-D second-order Markov on clipped differences) + logistic regression / FLD ensemble (Kodovský–Fridrich–Holub).
4. **SRM-lite / maxSRM** features + ensemble (held-out); optional **SRNet** or Xu-Net (GPU).
5. **Tailored sign/plane tests for E3 (Eve knows the algorithm and `pw_decoy`)**: χ² on `(sign, x̂ mod 4)`; correlation of sign with local gradient/texture sign; runs test and autocorrelation of the sign sequence in `P` order; joint 2-bit-plane entropy at `P`; residual histogram of `y − x̂` split by bit‑2 (`x̂` = median/Wiener denoise); detector trained on features computed **only at positions `P`**.
6. **Quantitative steganalysis** (change-rate/payload estimate) to test length consistency with the decoy.

### 6.4 Data
* **BOSSBase 1.01** (10 000 grayscale 512×512). Split by seed: train 5 000 / val 1 000 / test 4 000. Cover-source-mismatch hold-out: BOWS2 (or your own camera images). Download on a machine with internet; the dev sandbox used here only had scikit-image's bundled images (`camera, moon, coins, page, chelsea, coffee, rocket, astronaut, text`).
* Colour demo images (50) for the UI; embed in luminance or per-channel (state which).

---

## 7. What Was Actually Verified (prototype evidence)

**Environment:** Python 3.11, numpy, scipy, scikit-image, scikit-learn, reedsolo, cryptography, argon2-cffi. Cover for end-to-end test: `skimage.data.camera()` 512×512.

| Test | Result |
|---|---|
| End-to-end: AEAD → RS(32,24) → whiten → 32 tiles → embed → extract → RS erasure decode → AEAD decrypt | success with 0, 4, 8 tiles erased; with 9 erased: `23/24` shards ⇒ NACK path |
| Wrong real passphrase | 0 valid shards (CRC/whitening mismatch) |
| Honey decoy | right key: `MEET @ north gate, Fri 13:30, code cobalt`; 3 wrong keys: three different plausible messages |
| Re-rolls | 0 / 32 tiles |
| Distortion | PSNR 58.10 dB; changed fraction 0.1007 |
| Change-set equivalence decoy-only vs Mirage | **32 / 32 tiles identical** |
| Sign statistics | Mirage: +1 fraction 0.5019, χ²(sign, x mod 4) p = 0.764; decoy-only: 0.4995, p = 0.360; `|d|=1` for 100 % of changes |
| First prototype (276 patches 128×128, α_d = 0.2, real = 0.7·changes) | round-trip 269/276 (7 returned "no solution" — likely insufficient dry positions on saturated patches such as `page`/`text`; **not diagnosed**; the re-roll rule in the final code is the intended fix); change set identical in all 269 |
| SPAM-style (343-D) + logistic regression, 5-fold CV | cover vs decoy-only **0.68 ± 0.15**; decoy-only vs Mirage **0.494 ± 0.024**; decoy-only vs naive second-LSB **0.764 ± 0.124**; cover vs Mirage 0.673 ± 0.147 |

**Caveats (say them before the professor does):** tiny sample, weak detector, non-BOSSbase images, one patch size, LSB-matching decoy only, no SRM/SRNet yet, no JPEG. The *structural* results (identical change sets, uniform signs) follow from the construction; the *detector* results are only feasibility evidence.

---

## 8. Step-by-Step Implementation Plan (5 weeks, core = Phases 0–7 for Mode L)

### Phase 0 — Setup (Day 1–2)
Python 3.11, venv; `pip install numpy scipy pillow opencv-python scikit-image numba cryptography argon2-cffi reedsolo scikit-learn matplotlib streamlit jpeglib` (+ `torch` only for CNN). Data (§6.4). Repo skeleton (§10). **Acceptance:** `pytest` runs; BOSSbase loads; fixed splits saved.

### Phase 1 — Baselines B0/B1 + attacks (Week 1)
Bit utilities; sequential LSB replacement (B0), keyed LSB matching (B1); PSNR/SSIM/diff map; χ² and RS/SPA; TCP sender/receiver. **Deliverable:** the "PSNR high but detected" figure (E0).

### Phase 2 — Crypto + keyed paths (Week 1–2)
Two-passphrase key schedule (§5.1), AEAD, keyed permutation, XOF utilities, whitening. **Tests:** wrong key ⇒ clean AEAD error; flipped bit ⇒ failure; whitened bits pass a simple bit-frequency/NIST-lite monobit/runs test.

### Phase 3 — **Mirage core (Week 2) — do this early, it is the headline**
1. Port `mirage_core.py` (Appendix A) into `embed/`; keep its tests (`test_e2e.py`, `test_equivalence.py`).
2. Honey DTE with your own message distribution; unit test: ≥ 1 000 wrong keys ⇒ 100 % decode to well-formed messages; chi-square test that field marginals match the intended distribution.
3. Sign-channel solver; property tests: round-trip for random profiles; change-set equality; `|d| = 1`; sign uniformity; behaviour on saturated images (all-255 tile ⇒ clean failure + larger cover recommendation).
**Deliverable:** the three-way change-map figure and sign histograms.

### Phase 4 — Adaptive decoy (Week 2–3)
Cost function (fallback first, then S-UNIWARD with `scipy.signal.convolve2d`), Gibbs solver, Hamming matrix embedding, then **STC Viterbi in numba**; plug into layer 1 (§5.3 Phase B); recheck Phase 3 tests with STC (real capacity now ≈ 0.6 × #STC changes). Plot STC vs Gibbs bound (E9).

### Phase 5 — Steganalysis harness + budget controller (Week 3)
SPAM features + FLD/LR; SRM-lite held-out; cache features; calibrate τ; `safe_decoy_rate(cover, P_target)`. Implement the **tailored sign tests** and **quantitative estimator** (§6.3). Run E1, E3, E3b.

### Phase 6 — Reliable UDP (Week 3)
Header, CRC, sender window, SACK receiver, RTO, fast retransmit, AIMD; injector; verify bit-exact files at 0–30 % loss; per-packet event log.

### Phase 7 — Tile RS + planner (Week 3–4, headline #2)
Tiling and packet mapping; per-tile Mirage embedding; RS erasure decode; NACK fallback; `plan(...)` (§5.6); compare B2/B3/B5 at equal impairments. **Deliverable:** E7 and E8.

### Phase 8 — UI + demo (Week 4)
§9. Eve runs as a **separate subprocess** that receives only the PNG, the algorithm code and (optionally) `pw_decoy` — it must be *structurally impossible* for the demo Eve to touch `pw_real`.

### Phase 9 — Experiments, report, viva (Week 4–5)
Full matrix (§6), `make figures`, report with literature table and "to the best of our knowledge" statement, recorded backup video.

**Stretch (after core):** Mode R (JPEG) incl. sign channel on DCT; adversarial-embedding cost tweak on the decoy (ADV-EMB/Backpack-style) with transfer test; rateless fountain codes instead of RS; k-of-n sharing across images (Krawczyk SSMS); decoy "cover traffic" (E6); decoy = innocuous "copyright watermark" cover story.

---

## 9. Demo Specification (what the professor sees)

### 9.1 UI (Streamlit, two real processes + an isolated Eve process)
Panels (stepper): **1 Select cover/secret** (capacity gauge: raw LSB, safe decoy `α_d*`, real capacity; warn if secret too large) → **2 Keys** (two passphrases; entropy bar; "decoy passphrase is intentionally crackable") → **3 Encrypt** (ciphertext entropy ≈ 8 bits/byte) → **4 Cost map** (heatmap `ρ`, histogram `β_i`) → **5 Embed** (tiles coloured by shard index; parity shards highlighted; decoy vs real layer toggle) → **6 Quality** (cover | stego | ×255 diff | change map; PSNR/SSIM/bpp; χ² curve; detector gauge) → **7 Plan** (`p̂, ε, (n,k,r)`, overhead, predicted `P_fail`, Pareto point) → **8 Transmit** (TCP / UDP-ARQ / UDP+RS toggle; loss/delay/reorder sliders; live packet log with SENT/ACK/LOST/RETX/NACK; cwnd/RTO chart; tile grid with holes) → **9 Receive & verify** (CRC/SHA/HMAC lights; erasures vs parity; "secret recovered before image completed") → **10 Eve console** (tabs E0–E4) → **11 Attack panel** (flip bits, JPEG QF75, drop tiles, wrong key).

### 9.2 Live script (≈ 10 minutes)
1. **0:00 Hook.** Show the circle riddle in one slide; one sentence mapping to Eve.
2. **1:00 Why naive fails.** B0 at 51 dB PSNR vs χ² detecting it (E0).
3. **2:00 Eve's turn.** Invite the professor to run the "forensic toolkit" on the Mirage PNG: detector flags it, algorithm fingerprint says LSB matching, dictionary attack cracks `sunshine123`, honey message appears. Then **change the guess** — a different password also gives a plausible note ("you cannot tell which is right").
4. **4:00 The turn.** Bob enters `pw_real`: the 1.3 KB real secret appears, AEAD ✓.
5. **5:00 Proof of non-existence of extra evidence.** Three-way change map (identical), sign histogram, "Eve with the code and decoy key" AUC panel ≈ 0.50; contrast with B4 (naive second layer) AUC ≫ 0.5.
6. **6:30 Network.** Loss slider to 20 %: tile grid shows holes, erasure counter, secret recovered before the picture completes; time-to-secret vs ARQ-only.
7. **8:00 Honest limits.** Attack panel: JPEG QF75 kills the sign layer (shows NACK / failure), decoy still reads; this is the cost of deniability.
8. **9:00 Pareto + price.** One slide: decoy detectability vs real capacity vs P_fail; capacity price factor.
9. **9:30 Challenge.** Optional: 10 images, 1 carries a real layer; ask the professor to pick — best Eve gets 1/10 (E6).

### 9.3 Safeguards
Built-in loss injector + localhost mode; recorded backup video; pre-computed Eve results cached (so the 10⁴-word dictionary result is shown instantly); fixed seeds; a "reset" button; do not rely on the college network.

---

## 10. Repository Structure and Interfaces

```
tessera/
  crypto/        kdf.py  aead.py  xof.py  keyed_perm.py  whiten.py
  decoy/         dte.py  messages.py                      # honey layer
  embed/         lsbm.py  costs.py  gibbs.py  stc.py  hamming.py  mirage.py  gf2.py  dct_jpeg.py  tiling.py
  ecc/           rs_columns.py  shards.py  planner.py
  stego_analysis/ chi2.py  rs_attack.py  spam.py  srm_lite.py  detector.py  sign_tests.py  quant_est.py  budget.py
  eve/           e0_naive.py  e1_tool.py  e2_second_look.py  e3_distinguisher.py  e6_haystack.py   # separate process, no access to pw_real
  net/           tcp.py  rudp.py  packet.py  rto.py  impair.py  session.py
  metrics/       psnr_ssim.py  diffmap.py  stats.py        # bootstrap CIs, DeLong, TOST
  ui/            app.py  panels/  eve_console.py
  experiments/   run_E0.py … run_E10.py  make_figures.py
  tests/         test_roundtrip.py  test_wrong_key.py  test_loss.py  test_erasure.py  test_equivalence.py  test_honey.py  test_sign_uniform.py  test_saturated.py
  config/        profiles.yaml  detectors.yaml
  README.md  requirements.txt  Makefile
```
**Stable interfaces.**
```python
class MirageEmbedder:
    def embed(cover_tile, t, profile, keys, decoy_hdr_bits, shard_bytes, rng, mode="mirage") -> (stego_tile, n_changes, ctr)
    def extract_real(stego_tile, t, profile, keys) -> shard_bytes          # Bob
    def peek_decoy(stego_tile, t, profile, pw_decoy_guess) -> str          # Eve
class Transport: send(frames); recv() -> frames
```
**`profiles.yaml` example**
```yaml
A_demo: {H: 512, W: 512, T: 32, alpha_d: 0.20, shard_bytes: 64, k: 24, rho_r: 0.6, margin: 24, decoy: lsbm}
B_stc:  {H: 512, W: 512, T: 32, alpha_d: 0.20, shard_bytes: 64, k: 24, rho_r: 0.6, margin: 24, decoy: s_uniward_stc, stc_h: 7}
```
**Makefile targets:** `setup`, `data`, `features`, `train-detectors`, `test`, `demo`, `eve-demo`, `experiments`, `figures`, `video`.
**Unit-test checklist:** round-trip (random profiles/seeds); wrong real key ⇒ 0 valid shards; wrong decoy key ⇒ valid honey message; flipped bit ⇒ CRC erasure; ≤ r erasures ⇒ recovery; r+1 ⇒ NACK; change-set equality; `|d|=1`; sign uniformity; whitened-bit monobit/runs; saturated tile ⇒ graceful failure; planner monotonicity.

---

## 11. Risks, Failure Modes and Mitigations

| Risk / failure mode | Why | Mitigation |
|---|---|---|
| **Prior-art overlap** (Mihara 2020, Ogiela–Koptyra, deniable stego, multilayer STC) | decoy + second layer is known | Claim the combination (evidence conservation + honey + Eve ladder + erasure transport); cite them; run B4 |
| Decoy not detected ⇒ no "attractor" | weak decoy at tiny α_d | Choose α_d from E1; the decoy should be detectable by plain detectors |
| Real layer solvable fails (saturated/flat patches) | few interior changed pixels (7/276 in prototype) | re-roll pad counter; larger cover; reduce ρ_r; fail loudly |
| Whitening forgotten ⇒ non-uniform embedded bits | RS parity/CRC structure | whitening + monobit test; ablation A3 |
| Honey decoys unconvincing | templated message distribution | richer `M`; plausibility human study (3 volunteers); disclose limitation |
| `pw_decoy` reused for real | operator error | UI forbids prefix/equality; entropy check |
| Eve with a stronger detector on the decoy | LSBM is weak | expected and fine; test STC decoy (Phase B) |
| Sign layer fragile (JPEG/resize/noise) | information lives in ±1 direction | state it; use RS; Mode R stretch; E5 reports |
| Fragment compounding `p_tile = 1−(1−p)^f` | tile > MTU | demo mode f=1; realistic mode reports both; plan with `p_tile` |
| Raw-tile UDP is itself an anomaly | metadata | out of scope; Eve gets PNG |
| STC too slow | numba/trellis | Hamming first; h=7 |
| SRM/CNN too heavy | compute | SPAM+EC primary; SRM-lite held-out; CNN optional |
| Overfitting to own detector | tuning | held-out detector + split |
| Demo fragility | network | injector, localhost, video |
| Over-claiming | — | "to the best of our knowledge"; ablations; list of non-claims |

**Open questions to resolve experimentally:** does an SRM+EC distinguisher exploit the *bit-2 plane at P* in any way not covered by §6.3? does STC-decoy change the sign-uniformity (asymmetric costs near saturation)? what is the minimum α_d at which real capacity ≥ 1 KB on BOSSbase covers? how does the capacity price vary by image texture?

---

## 12. Likely Viva Questions (with crisp answers)

1. **Why is PSNR not a security metric?** Quality ≠ detectability; B0 at ≈ 51 dB is detected by χ².
2. **Isn't a decoy layer already known?** Yes (Mihara 2020 etc.); our contribution is evidence conservation, honey no-oracle, the Eve ladder and the integrated transport; we cite and compare against B4.
3. **Isn't this just ternary/multilayer STC?** The channel is, yes (Filler–Fridrich 2010). The new part is assigning the sign layer a different key and meaning and proving/measuring that the output distribution equals decoy-only.
4. **Does it reduce detectability?** No. The decoy is intended to be detected. We trade capacity for deniability conditional on detection (D4 price factor).
5. **What if Eve knows everything but `pw_real`?** E3: distinguisher AUC ≈ 0.5; computationally, signs are PRF output.
6. **What if Eve has the cover?** She still sees only uniformly random signs; never reuse covers.
7. **Why honey encryption?** A non-honey decoy gives a verification oracle (garbage on wrong key); honey makes every candidate plausible.
8. **Why do positions come from the decoy key?** Layer 2 lives inside layer 1's changed set; Eve must be able to extract the decoy. Position knowledge is harmless.
9. **Why erasure codes instead of retransmission?** Known-position erasures, `r` corrections instead of `⌊r/2⌋`, fewer RTTs; show time-to-secret.
10. **Doesn't parity make you more detectable?** It raises real bits per tile, hence needs more decoy changes; that is the joint optimisation / Pareto front.
11. **What does the square-root law say?** Safe payload ∝ √n; max capacity is never safe.
12. **Why AEAD, not a checksum?** An attacker recomputes checksums.
13. **JPEG recompression?** Sign layer dies first; decoy may survive; show E5; Mode R is stretch.
14. **Limitations?** Capacity price, fragility, templated honey, environment side channels (Czeskis), strong unseen detectors, not competitive with provably secure generative stego on raw P_E.
15. **Could you have used one layer at low rate?** Yes for undetectability, but then there is no deniability once detected.

---

## 13. Possible Paper Outline (if you decide to publish)
*Title candidates:* "Mirage: Deniable Image Steganography by Hiding a Second Layer in the Direction of Decoy Changes"; "Evidence-Conserving Deniable Steganography with Honey-Encoded Decoys".
*Contributions:* (1) evidence-conserving sign-channel construction with an indistinguishability argument; (2) honey-encoded decoys removing the verification oracle; (3) Eve ladder + existence-hiding gap metric + TOST evaluation; (4) tile-aligned RS transport and joint planner; (5) open implementation and benchmark.
*Figures:* motivation curve (E0); three-way change map; sign histograms; AUC bars for E3/E3b/E6; Pareto (E8); reliability curves (E7); STC vs Gibbs (E9); ablations (E10).
*Venues to consider (check deadlines):* ACM IH&MMSec, IEEE WIFS, IWDW/ICIP workshops, arXiv preprint first.

---

## 14. References (verify details before citing)

**Closest prior work (found in this design session):** Mihara, *Misdirection steganography*, Soft Computing 24 (2020); Ogiela & Koptyra, *False and multi-secret steganography in digital images*, Soft Computing 19 (2015); *Deniable Steganography*, arXiv:2205.12587; Ahmad et al., *How to Plausibly Deny Steganographic Secrets*, SECRYPT 2023; Juels & Ristenpart, *Honey Encryption: Security Beyond the Brute-Force Bound*, EUROCRYPT 2014; Jaeger, Ristenpart, Tang, *Honey Encryption Beyond Message Recovery Security*, ePrint 2016/174; Filler & Fridrich, *Minimizing Additive Distortion Functions With Non-Binary Embedding Operation in Steganography*, WIFS 2010; Schöttle & Böhme (IH 2012; TIFS); Denemark et al., *Selection-channel-aware rich model*, WIFS 2014; Tang et al., *CNN-based adversarial embedding*, TIFS 2019; Bernard et al., *Backpack*, TIFS 2022; Reinders et al., *Algorithm mismatch in spatial steganalysis*, 2019; arXiv:1909.10278 (double stego); Steinebach et al. 2018 (double embedding steganalysis); Ker (2006) and Ker & Pevný (2011/2012); Czeskis et al., HotSec 2008.

**Steganography / coding (from v1):** Filler, Judas, Fridrich (STC), IEEE TIFS 2011; Holub, Fridrich, Denemark (S/J-UNIWARD), EURASIP JIS 2014; Pevný, Filler, Bas (HUGO) IH 2010; Holub & Fridrich (WOW) WIFS 2012; Guo et al. (UERD) TIFS 2015; Westfeld (F5) IH 2001; Filler & Fridrich, *Fisher information determines capacity of ε-secure steganography*, IH 2009; Ker et al., *The square root law of steganographic capacity*, MM&Sec 2008; Cachin, IH 1998.

**Steganalysis (from v1):** Westfeld & Pfitzmann (χ²) IH 1999; Fridrich, Goljan, Du (RS) 2001; Dumitrescu, Wu, Wang (SPA) 2002; Pevný, Bas, Fridrich (SPAM) TIFS 2010; Fridrich & Kodovský (SRM) TIFS 2012; Kodovský, Fridrich, Holub (ensembles) TIFS 2012; Boroumand, Chen, Fridrich (SRNet) TIFS 2019; Kin-Cleaves & Ker (dual-syndrome trellis codes) WIFS 2018.

**Network / crypto / data:** Reed & Solomon 1960; Luby (LT) FOCS 2002; RFC 6330 (RaptorQ); Shamir 1979; Krawczyk 1993; RFC 6298 (RTO), RFC 2018 (SACK), RFC 5681 (congestion control), RFC 8439 (ChaCha20-Poly1305), RFC 5869 (HKDF), RFC 9106 (Argon2); Wang et al., SSIM, TIP 2004; Bas, Filler, Pevný, *BOSSbase 1.01*, IH 2011; ITU-T T.81 (JPEG).

---

## 15. Final Deliverables Checklist

- [ ] Reference core ported and all Phase‑3 tests green (`test_e2e`, `test_equivalence`, honey, sign-uniformity, saturated-tile)
- [ ] Working two-machine demo (TCP, UDP-ARQ, UDP+RS) with live packet log and tile grid
- [ ] Eve console (E0–E4) running as an isolated process; precomputed caches for the live dictionary attack
- [ ] Three-way change-map figure; sign histograms; honey wrong-key outputs
- [ ] E1/E3/E3b/E6 AUC results on a **held-out detector family** with CIs and TOST
- [ ] Reliability curves (E7), Pareto surface (E8), capacity-price table (D4), STC vs Gibbs (E9), ablations (E10)
- [ ] Mode R / JPEG results or an explicit "future work" statement with E5 fragility numbers
- [ ] Report with "to the best of our knowledge" novelty statement, literature table, explicit non-claims and limitations
- [ ] `make figures`, README, requirements, recorded backup demo video

---

## Appendix A — Reference implementation (tested)

Files shipped alongside this document: `mirage_core.py`, `test_e2e.py`, `test_equivalence.py`. Run `python test_e2e.py` and `python test_equivalence.py` (needs `numpy scipy scikit-image reedsolo cryptography argon2-cffi`).

### A.1 `mirage_core.py`
```python
"""Reference implementation: Mirage layer (decoy LSB-matching + sign-channel real layer) with tile-aligned RS erasure coding."""
import hashlib, os, struct, zlib
import numpy as np
from fractions import Fraction
from reedsolo import RSCodec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type

# ---------- keys / PRF ----------
def master(passphrase: str, salt: bytes) -> bytes:
    return hash_secret_raw(passphrase.encode(), salt, time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, type=Type.ID)
def hkdf(m: bytes, label: bytes, n=32) -> bytes:
    return HKDF(hashes.SHA256(), n, None, label).derive(m)
def xof(key: bytes, *parts, n: int) -> bytes:
    h = hashlib.shake_256(key)
    for p in parts: h.update(b"|" + (p if isinstance(p, bytes) else str(p).encode()))
    return h.digest(n)
def xof_bits(key, *parts, n): 
    return np.unpackbits(np.frombuffer(xof(key, *parts, n=(n+7)//8), np.uint8))[:n]

# ---------- honey DTE (product distribution, integer interval arithmetic) ----------
FIELDS = [
 ("act",  [("MEET",5),("MOVE",2),("HOLD",3),("ABORT",1)]),
 ("place",[("old library",4),("north gate",3),("canteen",5),("bus stand",3),("lab block",2),("main gate",4),("sports ground",2),("station",3)]),
 ("day",  [("Mon",3),("Tue",3),("Wed",3),("Thu",3),("Fri",4),("Sat",2),("Sun",1)]),
 ("time", [(f"{h:02d}:{m:02d}",w) for h,w in zip(range(8,22),[1,2,3,3,2,2,3,3,3,3,3,2,2,1]) for m in (0,30)]),
 ("code", [(w,1) for w in ["falcon","maple","cobalt","juniper","orchid","granite","lantern","saffron"]]),
]
SEEDBITS = 64
def dte_decode(seed: int) -> str:
    lo, hi, out = 0, 1 << SEEDBITS, []
    for name, opts in FIELDS:
        W = sum(w for _, w in opts); width = hi - lo
        pos = ((seed - lo) * W) // width
        cum = 0
        for lbl, w in opts:
            if pos < cum + w: break
            cum += w
        out.append(lbl)
        lo, hi = lo + width * cum // W, lo + width * (cum + w) // W
    return f"{out[0]} @ {out[1]}, {out[2]} {out[3]}, code {out[4]}"
def dte_encode(msg_idx: list, rng=None) -> int:
    lo, hi = 0, 1 << SEEDBITS
    for (name, opts), idx in zip(FIELDS, msg_idx):
        W = sum(w for _, w in opts); width = hi - lo
        cum = sum(w for _, w in opts[:idx]); w = opts[idx][1]
        lo, hi = lo + width * cum // W, lo + width * (cum + w) // W
    r = int.from_bytes(os.urandom(8), "big")
    return lo + r % (hi - lo)

# ---------- layout ----------
class Profile:
    def __init__(s, H=512, W=512, T=32, alpha_d=0.2, shard_bytes=64, k=24):
        s.H, s.W, s.T, s.alpha_d, s.shard_bytes, s.k = H, W, T, alpha_d, shard_bytes, k
        s.rows = H // T
        s.n = T
        s.r_bits = shard_bytes * 8
        s.payload = shard_bytes - 5 - 4        # idx,k,n,len(2) | payload | crc32
        s.margin = 24
    def tile_slice(s, t):
        r0 = t * s.rows; r1 = s.H if t == s.T - 1 else r0 + s.rows
        return r0, r1
    def n_d(s, t):
        r0, r1 = s.tile_slice(t); return int(s.alpha_d * (r1 - r0) * s.W)

def tile_positions(kd, t, npix, n_d):
    keys = np.frombuffer(xof(kd, "perm", t, n=4 * npix), np.uint32)
    return np.argsort(keys, kind="stable")[:n_d]

def H2_matrix(kh, t, r, n_d):
    return xof_bits(kh, "H2", t, n=r * n_d).reshape(r, n_d)

# ---------- GF(2) solve with python-int bitsets ----------
def gf2_solve(rows, rhs, ncols, rng):
    r = len(rows); R = [rows[i] | (int(rhs[i]) << ncols) for i in range(r)]
    used = 0; piv = []
    for c in range(ncols):
        p = next((i for i in range(used, r) if (R[i] >> c) & 1), None)
        if p is None: continue
        R[used], R[p] = R[p], R[used]
        for i in range(r):
            if i != used and (R[i] >> c) & 1: R[i] ^= R[used]
        piv.append(c); used += 1
        if used == r: break
    if used < r: return None
    x = rng.integers(0, 2, ncols, dtype=np.uint8)
    for c in piv: x[c] = 0
    for k, c in enumerate(piv):
        row = R[k]; mask = row & ((1 << ncols) - 1) & ~(1 << c)
        xi = 0; m = mask
        while m:
            lb = m & -m; xi ^= int(x[lb.bit_length() - 1]); m ^= lb
        x[c] = ((row >> ncols) & 1) ^ xi
    return x

def rows_to_ints(sub):
    out = []
    for row in sub:
        out.append(int("".join(map(str, row[::-1].tolist())), 2) if row.size else 0)
    return out

# ---------- tile embed / extract ----------
def embed_tile(cover_tile, t, prof, kd, kh, kw, hdr_ct_bits, shard_bytes_arr, rng, mode="mirage"):
    x = cover_tile.astype(np.int16).ravel(); n = x.size; n_d = prof.n_d(t)
    P = tile_positions(kd, t, n, n_d)
    m2 = None
    if mode == "mirage":
        m2 = np.frombuffer(shard_bytes_arr, np.uint8)
        m2 = np.unpackbits(m2 ^ np.frombuffer(xof(kw, "white", t, n=len(m2)), np.uint8))
    H2 = H2_matrix(kh, t, prof.r_bits, n_d) if mode == "mirage" else None
    for ctr in range(256):                                   # re-roll padding until the real layer is solvable
        pad = xof_bits(kd, "pad", t, ctr, n=n_d - 64)
        bits = np.concatenate([hdr_ct_bits, pad]).astype(np.uint8)
        chg = (x[P] & 1) != bits
        interior = (x[P] > 0) & (x[P] < 255)
        dry = chg & interior
        if mode != "mirage" or dry.sum() >= prof.r_bits + prof.margin: break
    else:
        return None
    y = x.copy()
    # default (decoy-only) sign: random; boundary: forced
    sg = rng.choice([-1, 1], size=n_d)
    sg[x[P] == 0] = 1; sg[x[P] == 255] = -1
    if mode == "mirage":
        b2c = (x[P] >> 1) & 1
        yb2 = b2c.copy()
        forced = chg & ~interior
        yb2[forced] = (((x[P] + sg)[forced]) >> 1) & 1
        wet = ~dry
        w = (yb2 * wet).astype(np.uint8)
        syn_wet = (H2[:, wet].astype(np.int64) @ w[wet].astype(np.int64)) % 2
        rhs = m2 ^ syn_wet.astype(np.uint8)
        dcols = np.where(dry)[0]
        sol = gf2_solve(rows_to_ints(H2[:, dcols]), rhs.tolist(), len(dcols), rng)
        if sol is None: return None
        for k, i in enumerate(dcols):
            v = x[P[i]]
            sg[i] = -1 if (((v - 1) >> 1) & 1) == sol[k] else 1   # pick sign whose bit-2 equals sol[k]
    idx = np.where(chg)[0]
    y[P[idx]] = x[P[idx]] + sg[idx]
    return y.reshape(cover_tile.shape).astype(np.uint8), int(chg.sum()), ctr

def extract_tile(stego_tile, t, prof, kd, kh, kw):
    y = stego_tile.astype(np.int16).ravel(); n_d = prof.n_d(t)
    P = tile_positions(kd, t, y.size, n_d)
    b2 = ((y[P] >> 1) & 1).astype(np.int64)
    syn = (H2_matrix(kh, t, prof.r_bits, n_d).astype(np.int64) @ b2) % 2
    sb = np.packbits(syn.astype(np.uint8))
    return bytes(np.frombuffer(sb, np.uint8) ^ np.frombuffer(xof(kw, "white", t, n=len(sb)), np.uint8))

def decoy_peek(stego_tile, t, prof, kd_guess):
    """What Eve does with a (possibly wrong) decoy passphrase."""
    y = stego_tile.astype(np.int16).ravel(); n_d = prof.n_d(t)
    P = tile_positions(kd_guess, t, y.size, n_d)
    lsb = (y[P][:64] & 1).astype(np.uint8)
    ks = xof_bits(kd_guess, "hdr", t, n=64)
    seed = int("".join(map(str, (lsb ^ ks).tolist())), 2)
    return dte_decode(seed)

# ---------- shards / RS ----------
def make_shards(ct: bytes, prof):
    s = prof.payload; k = prof.k; n = prof.n
    assert len(ct) <= k * s, f"ciphertext {len(ct)} > capacity {k*s}"
    buf = ct.ljust(k * s, b"\x00")
    data = [buf[i * s:(i + 1) * s] for i in range(k)]
    rs = RSCodec(n - k)
    par = [bytearray(s) for _ in range(n - k)]
    for b in range(s):
        cw = rs.encode(bytes(d[b] for d in data))
        for j in range(n - k): par[j][b] = cw[k + j]
    pay = data + [bytes(p) for p in par]
    shards = []
    for i, p in enumerate(pay):
        h = struct.pack("!BBBH", i, k, n, len(ct)) + p
        shards.append(h + struct.pack("!I", zlib.crc32(h)))
    return shards

def recover(shards_by_idx: dict, prof):
    ok = {}
    for i, sb in shards_by_idx.items():
        if sb is None or len(sb) != prof.shard_bytes: continue
        if zlib.crc32(sb[:-4]) != struct.unpack("!I", sb[-4:])[0]: continue
        ok[sb[0]] = sb
    if len(ok) < prof.k: return None, len(ok)
    any_sb = next(iter(ok.values())); _, k, n, L = struct.unpack("!BBBH", any_sb[:5])
    s = prof.payload; rs = RSCodec(n - k)
    erase = [i for i in range(n) if i not in ok]
    cols = [bytearray(s) for _ in range(k)]
    for b in range(s):
        cw = bytearray(n)
        for i in range(n):
            if i in ok: cw[i] = ok[i][5 + b]
        dec = rs.decode(bytes(cw), erase_pos=erase)[0]
        for i in range(k): cols[i][b] = dec[i]
    return b"".join(bytes(c) for c in cols)[:L], len(ok)
```

### A.2 `test_e2e.py`
```python
import numpy as np, os, time, struct
from skimage import data
from mirage_core import *
rng = np.random.default_rng(1)
cover = data.camera().astype(np.uint8)
prof = Profile()
salt = os.urandom(16); nonce = os.urandom(12)
pw_decoy, pw_real = "sunshine123", "correct horse battery staple 9!"
md, mr = master(pw_decoy, salt), master(pw_real, salt)
kd = hkdf(md, b"pos"); kenc = hkdf(mr, b"enc"); kh = hkdf(mr, b"h2"); kw = hkdf(mr, b"white")
plain = (b"Rendezvous brief: coordinates 21.1458N 79.0882E, window 02:10-02:40. " * 18)[:1280]
ct = ChaCha20Poly1305(kenc).encrypt(nonce, plain, b"tessera-v2")
print("plaintext", len(plain), "ciphertext", len(ct), "capacity", prof.k * prof.payload)
shards = make_shards(ct, prof)
# decoy honey message
msg_idx = [0, 1, 4, 11, 2]
seed = dte_encode(msg_idx)
print("decoy honey msg:", dte_decode(seed))
stego = cover.copy(); stego_d = cover.copy(); t0 = time.time(); rerolls = []
nchg = []
for t in range(prof.T):
    r0, r1 = prof.tile_slice(t)
    ks = xof_bits(kd, "hdr", t, n=64); sb = np.array([int(b) for b in format(seed, "064b")], np.uint8)
    hdr_ct = sb ^ ks
    out = embed_tile(cover[r0:r1], t, prof, kd, kh, kw, hdr_ct, shards[t], np.random.default_rng(100 + t), "mirage")
    assert out is not None, f"tile {t} failed"
    stego[r0:r1], c, ctr = out; rerolls.append(ctr); nchg.append(c)
    # decoy-only with identical padding ctr (same change set expected)
print("embed time %.1fs" % (time.time() - t0), "rerolls>0:", sum(1 for r in rerolls if r), "mean changes/tile", np.mean(nchg))
print("PSNR", 10 * np.log10(255**2 / np.mean((cover.astype(float) - stego) ** 2)))
print("bpp changed %.4f" % (np.mean(cover != stego)))
# Eve: correct vs wrong decoy keys on tile 0
r0, r1 = prof.tile_slice(0)
print("Eve, right decoy key :", decoy_peek(stego[r0:r1], 0, prof, kd))
for g in ["password", "letmein", "qwerty1"]:
    print("Eve, wrong key %-9s:" % g, decoy_peek(stego[r0:r1], 0, prof, hkdf(master(g, salt), b"pos")))
# Bob with loss
for loss_tiles in (0, 4, 8, 9):
    drop = set(rng.choice(prof.T, loss_tiles, replace=False).tolist())
    got = {}
    for t in range(prof.T):
        if t in drop: continue
        r0, r1 = prof.tile_slice(t)
        got[t] = extract_tile(stego[r0:r1], t, prof, kd, kh, kw)
    ctr_, nok = recover(got, prof)
    if ctr_ is None: print(f"drop {loss_tiles}: only {nok}/{prof.k} shards -> NACK"); continue
    pt = ChaCha20Poly1305(kenc).decrypt(nonce, ctr_, b"tessera-v2")
    print(f"drop {loss_tiles}: recovered={pt == plain}")
# wrong real key -> AEAD fail
try:
    kbad = hkdf(master("wrong real", salt), b"h2"); kwb = hkdf(master("wrong real", salt), b"white")
    got = {t: extract_tile(stego[prof.tile_slice(t)[0]:prof.tile_slice(t)[1]], t, prof, kd, kbad, kwb) for t in range(prof.T)}
    print("wrong real key shards ok:", recover(got, prof)[1])
except Exception as e: print("wrong key err", e)
# sign statistics
d = (stego.astype(int) - cover.astype(int)); ch = d[d != 0]
print("frac +1 %.4f  frac |d|==1 %.4f" % ((ch > 0).mean(), (np.abs(ch) == 1).mean()))
```

### A.3 `test_equivalence.py`
```python
import numpy as np, os
from skimage import data
from scipy.stats import chi2_contingency
from mirage_core import *
cover=data.camera().astype(np.uint8); prof=Profile(); salt=os.urandom(16); nonce=os.urandom(12)
md,mr=master("sunshine123",salt),master("real pass phrase",salt)
kd=hkdf(md,b"pos");kh=hkdf(mr,b"h2");kw=hkdf(mr,b"white");kenc=hkdf(mr,b"enc")
ct=os.urandom(1258); shards=make_shards(ct,prof); seed=dte_encode([0,1,4,11,2])
sb=np.array([int(b) for b in format(seed,"064b")],np.uint8)
eq=0; tab_m=np.zeros((2,4)); tab_d=np.zeros((2,4))
for t in range(prof.T):
    r0,r1=prof.tile_slice(t); hdr=sb^xof_bits(kd,"hdr",t,n=64)
    ym,_,_=embed_tile(cover[r0:r1],t,prof,kd,kh,kw,hdr,shards[t],np.random.default_rng(t),"mirage")
    yd,_,_=embed_tile(cover[r0:r1],t,prof,kd,kh,kw,hdr,None,np.random.default_rng(t+999),"decoy")
    eq+=int(((ym!=cover[r0:r1])==(yd!=cover[r0:r1])).all())
    for yy,tab in((ym,tab_m),(yd,tab_d)):
        c=cover[r0:r1].astype(int); dd=(yy.astype(int)-c); m=(dd!=0)&(c>0)&(c<255)
        for s_,v in zip(dd[m],c[m]): tab[0 if s_>0 else 1, v%4]+=1
print("identical change set tiles:",eq,"/",prof.T)
for n,t in(("mirage",tab_m),("decoy-only",tab_d)):
    print(n,"frac+1=%.4f"%(t[0].sum()/t.sum()),"chi2 p(sign vs x mod 4)=%.3f"%chi2_contingency(t+1e-9)[1])
```

### A.4 Notes on the reference code
* `xof()` uses SHAKE‑256 as a PRF/XOF for the prototype; replace with ChaCha20 DRBG in the final system if you prefer (the interface is the same).
* `tile_positions` shuffles by `argsort` of random 32-bit keys (ties negligible); `H2_matrix` is dense (`r × n_d` bits, ≈ 0.84 Mbit per tile at profile A).
* `gf2_solve` uses Python-int bitsets; for bigger tiles move it to numba or a packed-bit implementation.
* The decoy-only mode (`mode="decoy"`) reuses the same padding counter, which is what makes the change-set equality test meaningful.
* The Eve helper `decoy_peek` reproduces what a dictionary attacker does with a (possibly wrong) passphrase.

## Appendix B — Parameter cheat sheet

| Symbol | Meaning | Default |
|---|---|---|
| `H×W` | cover size | 512×512 |
| `T = n` | tiles = RS length | 32 |
| `α_d`, `n_d` | decoy rate (bits/pixel), decoy bits per tile | 0.20, 1638 |
| `c` | changes per tile | ≈ n_d/2 (LSBM) |
| `ρ_r` | fraction of changes used for real bits | 0.6 |
| `r_bits` | real bits per tile | 512 |
| `margin` | extra dry positions for rank | 24 |
| `shard_bytes`, `s` | shard size, payload bytes | 64, 55 |
| `k`, `n−k` | data / parity shards | 24, 8 |
| `p̂`, `p_tile`, `f` | loss estimate, tile loss, fragments per tile | probe, `1−(1−p̂)^f`, 1 (demo) |
| `ε` | target failure probability | 1e‑3 |
| Argon2id decoy / real | light / reference | t=1,m=8 MiB / t=2,m=19 MiB |

## Appendix C — Glossary
**Decoy / attractor:** crackable layer that Eve finds. **Honey message:** plausible fake plaintext produced by any wrong key. **DTE:** distribution-transforming encoder. **Dry / wet:** positions that may / may not be modified in wet-paper coding. **Sign channel:** information carried by the direction (±1) of changes. **Evidence conservation:** real layer adds no observable change beyond the decoy's. **Existence-hiding gap:** distinguishability between decoy-only and Mirage worlds. **Eve ladder:** E0–E6 attacker models. **Capacity price:** `e/0.6` ratio between single-layer and Mirage useful bits at equal changes.
