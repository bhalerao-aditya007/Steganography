# TESSERA v3: Mirage — Networked Deniable Image Steganography

**Data Privacy & Security Mini Project — Research Build, Real UDP Network Stack, Evaluation, and Viva Demonstration**

---

## 📌 1. Executive Summary & Architecture Overview

**TESSERA v3** transitions the Mirage deniable steganography paradigm from an in-memory simulation into an authentic, fully networked UDP computer networks and security system. 

The architecture features three distinct operating system processes communicating over real UDP sockets:
```
┌────────────────────────┐         UDP :9998         ┌────────────────────────┐         UDP :9999         ┌────────────────────────┐
│      Alice (Sender)    │ ────────────────────────> │   Impairment Router    │ ────────────────────────> │     Bob (Receiver)     │
│   [cli/alice_sender]   │ <──────────────────────── │ [tools/router_impair]  │ <──────────────────────── │   [cli/bob_receiver]   │
└────────────────────────┘          NACK / ACK       └────────────────────────┘          NACK / ACK       └────────────────────────┘
                                                                  │
                                                        Logs Ground Truth to
                                                      CSV & Wireshark PCAP
```

### Key Technical Upgrades in v3:
1. **Real UDP Transport Layer:** No synthetic array slicing. Datagrams traverse actual local UDP sockets (`:9998` and `:9999`) with high-resolution pacing (`precise_sleep()` Windows hybrid sleep/spin), 4 MB OS socket receive buffers, and resilience against Windows ICMP `ConnectionResetError` exceptions.
2. **Deterministic & Stochastic Impairment Router:** `tools/router_impair.py` intercepts all traffic and injects:
   - Bernoulli i.i.d. packet loss (`--loss`)
   - Gilbert–Elliott 2-state Markov burst loss (`--ge-gb`, `--ge-bg`, `--ge-loss`)
   - Deterministic arrival-index packet drops (`--drop-nth`)
   - Heap-scheduled transmission delay and uniform jitter causing packet reordering (`--delay`, `--jitter`)
   - Packet duplication (`--dup`)
   - Single-bit payload corruption (`--corrupt`)
   - Serialization delay and tail-drop queue bandwidth throttling (`--bw-kbps`, `--queue-bytes`)
   - Live export to CSV (`router_log.csv`) and libpcap capture (`capture.pcap`)
3. **Transport Modes:**
   - **Open-Loop `fec` Mode:** Alice transmits 32 tile datagrams with RS(32,24) parity. If $\le 8$ tiles are lost, Bob recovers bit-exactly ($P_E = 0$). If $\ge 9$ tiles are lost, Bob fails closed with exit code 2.
   - **Closed-Loop `hybrid` Mode:** Handshake (`SYN` / `SYN-ACK`), paced data flight, and selective NACK retransmission rounds. Turns loss into feedback repairs.
4. **Wire Protocol v2:** Compact 20-byte binary header with keyed BLAKE2s-32 authentication tags, CRC32 integrity check, and fragmentation support. Wireshark dissection via `tools/tessera.lua`.
5. **Cryptographic Hardening:**
   - RFC 9106 Argon2id ($m=64\text{ MiB}, t=3, p=1$) with HKDF domain separation (`b"tessera/v3/enc"`, `b"tessera/v3/wire"`, `b"tessera/v3/H2"`, `b"tessera/v3/wh"`, `b"tessera/v3/pos"`).
   - ChaCha20-Poly1305 AEAD with random 12-byte nonces and uniform 1,416-byte fixed padding (1,386-byte maximum secret capacity) preventing traffic analysis.
6. **Steganographic Soundness:**
   - Dry-pixel floor checks and GF(2) retry loop across tile padding counters.
   - Pre-embedding Cover Gate checking saturated boundary pixels, flat blocks, and residual entropy.
   - Formal Sign-Channel Lemma 1 mathematical verification ($v' \in \{v-1, v+1\}$ satisfies parity constraint while sign choice carries secret bit).

---

## ⚖️ 2. The Claims Ledger

In academic defense, credibility requires knowing exactly what is claimed and what is not claimed:

### What We Claim:
1. **Real Network Impairment:** Genuine UDP packet loss, burst drops, and reordering injected by an intermediary router process between honest endpoints, verified by Wireshark captures and ground-truth CSV logs.
2. **MDS Erasure Guarantee:** Any 24 of 32 tiles reconstruct the hidden secret bit-exactly, authenticated by ChaCha20-Poly1305.
3. **Evidence Conservation:** The Mirage embedding layer introduces **zero** additional modified pixels beyond the decoy layer ($\Delta_{\text{diff}} = 0$, identical change sets, $100\% \in \{\pm 1\}$).
4. **Empirical Steganalysis Baseline:** The decoy layer at $\alpha = 0.20$ is detectable by SPAM-686 feature extraction + linear classifiers ($P_E \approx 0.35$); the Mirage layer adds no *additional* statistical detectability ($\text{AUC} \approx 0.500$).
5. **Identifiable Wire Framing:** The UDP framing is explicitly identifiable by design (`"ST"` magic, constant 8,212-byte data datagrams).

### What We Do NOT Claim:
- ❌ We do **not** claim undetectable steganography against high-order machine learning detectors.
- ❌ We do **not** claim network-level covert channels (the wire protocol does not masquerade as DNS/RTP).
- ❌ We do **not** claim survival against lossy JPEG compression, image resizing, or geometric transformation.
- ❌ We do **not** claim forward secrecy (compromise of master passphrase reveals all recorded sessions).
- ❌ We do **not** claim security if the adversary possesses the original uncompressed cover image.

---

## 🚀 3. Quickstart & One-Click Live Demo

### Prerequisites
- Python 3.11+
- All dependencies installed in the local virtual environment (`.\.venv`):
```powershell
Set-Location "D:\B.Tech\Academics\SEM 5\Data Privacy & Security\small project\codebase"
$env:PYTHONUTF8 = "1"
```

### Option A: The One-Click Live Terminal Demo
Runs Bob, the Impairment Router (with 15% random loss), and Alice in `hybrid` mode automatically:
```powershell
.\.venv\Scripts\python.exe run_v3_demo.py
```

**Artifacts Generated in `results/`:**
- `stego_alice.png`: Steganographic image generated by Alice.
- `received_stego.png`: Reconstructed image reconstructed by Bob (showing delivered tiles).
- `router_log.csv`: Ground-truth log of every forwarded and dropped datagram.
- `bob_report.json`: Bob's cryptographic and RS verification report.
- `capture.pcap`: Raw network traffic capture of Leg 1 (`:9998`) and Leg 2 (`:9999`).
- `run_manifest.json`: Sender parameters and cryptographic metadata.

### Option B: Offline PCAP Analysis of Wire Traffic
Inspect the captured PCAP using the Scapy-based transport auditor:
```powershell
.\.venv\Scripts\python.exe tools\analyze_pcap.py results\capture.pcap
```
**Sample Output:**
```
=================================================================
           TESSERA PCAP OFFLINE TRANSPORT AUDIT REPORT           
=================================================================
Leg 1 (Alice -> Router): 39 datagrams  (35 DATA)
Leg 2 (Router -> Bob)  : 28 datagrams
Lost in Router         : 11 total, 9 DATA -> tiles [2, 5, 7, 9, 10, 13, 20, 23, 24]
DATA Packet Loss Rate  : 25.7%
Sequence Gaps on Leg 2 : [(3, 5), (6, 8), (8, 10), (10, 13), (14, 16), (21, 23), (24, 27), (33, 36)]
DATA Payload Sizes     : {8212}  (constant sizes = traffic fingerprint)
=================================================================
```

---

## 🖥️ 4. Live Viva Demonstration Setup (4-Pane Layout)

During project evaluation or viva, demonstrate the three real processes and Wireshark running concurrently across 4 terminal/window panes:

```
┌──────────────────────────────────────┬──────────────────────────────────────┐
│ Wireshark (Left Half)                │ Pane 1: Bob Receiver (:9999)         │
│  Display Filter:                     │                                      │
│  udp.port in {9998 9999}             ├──────────────────────────────────────┤
│  Dissector: tools/tessera.lua        │ Pane 2: Impairment Router (:9998)    │
│  Columns: No, Time, Src, Dst, Len    ├──────────────────────────────────────┤
│                                      │ Pane 3: Alice Sender                 │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

### Step 1: Wireshark Lua Dissector Setup
To view `TESSERA` packets parsed live in Wireshark:
1. Open Wireshark $\to$ **Help** $\to$ **About Wireshark** $\to$ **Folders** $\to$ **Personal Lua Plugins**.
2. Copy `tools\tessera.lua` into that folder (or append `dofile("D:/B.Tech/Academics/SEM 5/Data Privacy & Security/small project/codebase/tools/tessera.lua")` to `init.lua`).
3. Press `Ctrl+Shift+L` in Wireshark to reload Lua plugins.
4. Start capture on **Adapter for loopback traffic capture** with display filter:
   ```wireshark
   udp.port in {9998 9999}
   ```

### Step 2: Terminal Commands (Open 3 PowerShell Windows)

#### Pane 1 — Bob Receiver (Start First)
```powershell
Set-Location "D:\B.Tech\Academics\SEM 5\Data Privacy & Security\small project\codebase"
$env:PYTHONUTF8 = "1"
$env:TESSERA_DECOY = "sunshine123"
$env:TESSERA_REAL  = "correct horse battery staple 9!"

.\.venv\Scripts\python.exe cli\bob_receiver.py --listen 9999 --mode auto --out results\received_stego.png --report results\bob_report.json --decoy-pass-env TESSERA_DECOY --real-pass-env TESSERA_REAL
```

#### Pane 2 — Impairment Router (Start Second)
```powershell
Set-Location "D:\B.Tech\Academics\SEM 5\Data Privacy & Security\small project\codebase"
$env:PYTHONUTF8 = "1"

.\.venv\Scripts\python.exe tools\router_impair.py --listen 9998 --to 127.0.0.1:9999 --loss 0.15 --seed 7 --log results\router_log.csv --pcap results\capture.pcap
```

#### Pane 3 — Alice Sender (Run When Prompted by Examiner)
```powershell
Set-Location "D:\B.Tech\Academics\SEM 5\Data Privacy & Security\small project\codebase"
$env:PYTHONUTF8 = "1"
$env:TESSERA_DECOY = "sunshine123"
$env:TESSERA_REAL  = "correct horse battery staple 9!"

.\.venv\Scripts\python.exe cli\alice_sender.py --dst 127.0.0.1:9998 --cover covers\textured_01.png --mode hybrid --secret "EXAMINER PHRASE: Real network loss recovered live via RS(32,24)!" --decoy-pass-env TESSERA_DECOY --real-pass-env TESSERA_REAL --save-stego results\stego_alice.png
```

---

## 🧪 5. Testing & Verification Suites

Execute the comprehensive test suite verifying the sign-channel lemma, packet parsing, FEC error/erasure boundaries, crypto KDF domain separation, cover gates, fuzzing robustness, and network scenarios:

### Run All Test Suites
```powershell
.\.venv\Scripts\python.exe run_tests.py
```

### Run Specific Test Modules with Pytest
```powershell
# 1. Sign-Channel Lemma 1 Mathematical Proof:
.\.venv\Scripts\python.exe -m pytest tests/test_lemma.py -v

# 2. Binary Wire Protocol v2 Packing, Unpacking, and BLAKE2s/CRC32 Tags:
.\.venv\Scripts\python.exe -m pytest tests/test_packet.py -v

# 3. Column-Wise RS(32,24) Errors & Erasures (MDS Bound 2e + f <= 8):
.\.venv\Scripts\python.exe -m pytest tests/test_fec.py -v

# 4. RFC 9106 Argon2id, HKDF Domain Separation, and AEAD Padding:
.\.venv\Scripts\python.exe -m pytest tests/test_crypto.py -v

# 5. Pre-Embedding Cover Image Gate Checks:
.\.venv\Scripts\python.exe -m pytest tests/test_cover_gate.py -v

# 6. Receiver Hostile Fuzzing (1,000 Random Corrupted Datagrams):
.\.venv\Scripts\python.exe -m pytest tests/test_receiver_fuzz.py -v

# 7. Network Scenarios 1 to 6 over Live UDP Impairment Router:
.\.venv\Scripts\python.exe -m pytest tests/test_scenarios.py -v

# 8. Full End-to-End System Integration:
.\.venv\Scripts\python.exe -m pytest tests/test_e2e_v3.py -v
```

---

## 📊 6. Evaluation Framework & Figures

### 1. Steganalysis Frontier Evaluation
Evaluates classification error ($P_E$) and AUC across 6 experimental arms ($C, L, M, R, P+, N-$) using 686-dimensional SPAM features and pair-aware dataset splits:
```powershell
.\.venv\Scripts\python.exe eval\stego_eval.py --quick
```
Outputs: `results/stego_eval.csv`

### 2. Network Monte Carlo Loss Sweep
Simulates packet loss rates from $0\%$ to $40\%$ across open-loop `fec` and closed-loop `hybrid` ARQ modes:
```powershell
.\.venv\Scripts\python.exe eval\net_eval.py --trials 50
```
Outputs: `results/net_eval.csv`

### 3. Generate Publication Figures
Generates publication-quality figures:
```powershell
.\.venv\Scripts\python.exe eval\plots.py
```
- `figures/v3_figure1_stego_frontier.png`: Payload vs. Detection Error ($P_E$) frontier across algorithms.
- `figures/v3_figure2_loss_curves.png`: Empirical vs. Analytical failure curves ($P_{\text{fail}}$ vs. loss probability).

---

## 🛡️ 7. Fallback Artifacts (Viva Insurance)

In case a live network demonstration is hindered by classroom network restrictions or firewall policies, pre-computed verified artifacts are packaged in `results/demo_fallback/`:
- `results/demo_fallback/capture.pcap`: Valid Wireshark capture of an end-to-end Alice $\to$ Router $\to$ Bob run.
- `results/demo_fallback/router_log.csv`: Ground-truth router drop and forward events.
- `results/demo_fallback/stego_alice.png`: Transmitted steganographic image.
- `results/demo_fallback/received_stego.png`: Received steganographic image reconstructed by Bob.
- `results/demo_fallback/bob_report.json`: Cryptographic and Reed–Solomon verification output.

To regenerate fresh fallback artifacts at any time:
```powershell
.\.venv\Scripts\python.exe run_v3_demo.py --out-dir results\demo_fallback
```

---

## 🎯 8. Viva Defense Questions & Crisp Answers

1. **Why UDP instead of TCP?**
   *Answer:* TCP's built-in retransmissions and stream abstraction hide packet loss and introduce visible timing signatures on the wire. UDP exposes raw datagram boundaries, allowing us to implement, evaluate, and benchmark application-layer Reed–Solomon erasure coding and hybrid ARQ.
2. **Isn't packet drop simulated by Alice simply not sending?**
   *Answer:* In v3, Alice transmits 100% of the datagrams. An independent router process (`router_impair.py`) intercepts the packets on UDP port 9998, evaluates loss models (Bernoulli or Gilbert–Elliott), drops selected datagrams, and logs the ground truth to CSV. The dropped sequence numbers are verified on the wire via Wireshark.
3. **What is the Reed–Solomon (32, 24) guarantee?**
   *Answer:* It is a Maximum Distance Separable (MDS) code over $\text{GF}(256)$ with minimum distance $d_{\min} = n - k + 1 = 9$. It strictly guarantees bit-exact recovery for any pattern of up to $f \le 8$ erased shards, or any combination of $e$ errors and $f$ erasures satisfying $2e + f \le 8$.
4. **What happens if 9 tiles are lost?**
   *Answer:* In `fec` mode, the MDS bound is exceeded, and Bob safely fails closed with exit code 2 without outputting partial corruption. In `hybrid` mode, Bob transmits a NACK identifying missing indices, and Alice paces targeted repair datagrams.
5. **Why column-wise Reed–Solomon?**
   *Answer:* By arranging the 1,416-byte message into 24 rows of 59 bytes, each byte position forms an independent 32-byte codeword across all 32 tiles. A dropped tile corresponds to exactly one erasure across all 59 codewords at the identical index, maximizing decoding efficiency.
6. **What is the Sign Channel?**
   *Answer:* When a pixel must change parity to satisfy the decoy wet-paper equation, modifying it by $+1$ or $-1$ yields identical LSB parity but toggles the second least significant bit (bit-2). This direction choice is a free degree of freedom used to carry the real secret shard at zero additional pixel modifications.
7. **Why is the real secret layer undetectable given the decoy?**
   *Answer:* The Mirage embedding modifies the exact same set of pixel coordinates as the decoy layer ($\Delta_{\text{diff}} = 0$). Furthermore, the $+1/-1$ sign distribution is pseudo-randomized by SHAKE-256 whitening and HKDF keys, yielding a uniform $+1$ ratio of $0.500 \pm 0.005$ indistinguishable from random coin flips.
8. **Why use RFC 9106 Argon2id?**
   *Answer:* Argon2id provides memory-hard key derivation ($m=64\text{ MiB}, t=3, p=1$), providing resistance against GPU and ASIC parallel dictionary cracking.
9. **What is the role of CRC32 if you already have Poly1305?**
   *Answer:* CRC32 detects accidental network bit corruptions instantly at the link level and converts them into erasures for Reed–Solomon decoding. Poly1305 provides cryptographic authentication against active tampering.
10. **Does TESSERA claim covert network traffic?**
    *Answer:* No. The packet structure carries a clear 20-byte binary header with identifiable magic bytes (`"ST"`). We explicitly analyze traffic fingerprinting and claim application-level steganography and erasure resilience, not network steganography.
