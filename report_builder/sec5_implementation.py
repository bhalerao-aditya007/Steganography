"""Section 5: Chapter 7 (Implementation & Key Technical Modules).
"""
import os
import docx
from docx.shared import Pt
from report_builder.styles import (
    COLOR_PRIMARY, COLOR_SECONDARY, COLOR_MUTED, COLOR_BLACK,
    add_p, add_bullet, add_h1, add_h2, add_h3, add_callout,
    add_figure, format_table
)

def build_chapter_7(doc):
    add_h1(doc, "7. Implementation & Key Technical Modules")
    
    add_h2(doc, "7.1 Real UDP Network Transport Engine (tessera/net/transport.py)")
    add_p(doc, 
        "The core network engine is implemented within tessera/net/transport.py, providing an object-oriented Sender and Receiver abstraction over native Python socket.socket(socket.AF_INET, socket.SOCK_DGRAM) primitives. Key engineering features include:"
    )
    add_bullet(doc, 
        "The Sender class implements an unchoked transmission loop pacing datagrams with precise_sleep(0.001) intervals. In closed-loop hybrid mode, it maintains a retransmission queue, tracks round-trip time estimates via Exponential Weighted Moving Average (EWMA), and re-emits unacknowledged tiles in response to NACK bitmasks.",
        bold_prefix="Sender State Machine: "
    )
    add_bullet(doc, 
        "The Receiver class allocates a 4 MB kernel receive buffer and executes a non-blocking select() polling loop with a configurable idle timeout. Received datagrams are authenticated against k_wire and validated via CRC32. Valid tiles are placed into an internal 32-element assembly buffer. When the number of received tiles reaches the MDS threshold (k = 24), the receiver triggers the Reed-Solomon reconstruction engine.",
        bold_prefix="Receiver State Machine: "
    )
    
    add_h2(doc, "7.2 Deterministic & Stochastic Impairment Router (tools/router_impair.py)")
    add_p(doc, 
        "To rigorously evaluate TESSERA under authentic, hostile network conditions without requiring expensive hardware network emulators, we engineered tools/router_impair.py. The router operates as an intermediary proxy listening on port 9998 and forwarding to port 9999. It provides an extensive CLI interface supporting both stochastic and deterministic impairments:"
    )
    add_bullet(doc, 
        "Injects independent identically distributed packet loss with probability p in [0.0, 1.0]. Evaluated across p = 0.10, 0.15, 0.20, 0.25, and 0.30.",
        bold_prefix="Bernoulli Loss (--loss <float>): "
    )
    add_bullet(doc, 
        "Implements a classic 2-state Markov chain switching between 'Good' (low loss) and 'Bad' (high loss) states, parameterized by transition probabilities p_GB and p_BG, faithfully modeling bursty wireless packet drops.",
        bold_prefix="Gilbert–Elliott Burst Loss (--ge-gb, --ge-bg, --ge-loss): "
    )
    add_bullet(doc, 
        "Forces deterministic packet drops at specific arrival indices (e.g., --drop-nth 4,8,12,16,20,24,28,32), enabling exact replication of edge test cases during faculty viva demonstrations.",
        bold_prefix="Deterministic Index Drops (--drop-nth <csv>): "
    )
    add_bullet(doc, 
        "Utilizes a Python heapq priority queue to schedule delayed packet forwardings, introducing Gaussian or uniform jitter that causes natural packet reordering.",
        bold_prefix="Delay & Jitter Simulation (--delay <ms>, --jitter <ms>): "
    )
    add_bullet(doc, 
        "Flips a single pseudorandom bit in the datagram payload to verify that receiver-side CRC32 and BLAKE2s-32 checks correctly identify and reject corrupted packets.",
        bold_prefix="Single-Bit Payload Corruption (--corrupt <float>): "
    )
    add_bullet(doc, 
        "Appends every processed datagram event to router_log.csv with precise timestamps, direction, sequence number, tile index, byte size, and forwarding action (fwd, drop_loss, drop_nth, reorder, corrupt), and writes raw libpcap captures to capture.pcap.",
        bold_prefix="Live Audit Logging (CSV & PCAP): "
    )
    
    add_h2(doc, "7.3 Mirage Dual-Layer Steganography Engine (tessera/embed/mirage.py)")
    add_p(doc, 
        "The Mirage embedding core resides in tessera/embed/mirage.py, implementing the formal Sign-Channel Lemma 1 algorithms. Given an 8-bit grayscale cover tile c and the corresponding decoy bits d and secret bits s, the embedding function executes in three vectorized numpy phases:"
    )
    add_bullet(doc, 
        "Computes the boolean mask of non-saturated pixels: mask = (c > 0) & (c < 255). Saturated pixels are exempted from modifications.",
        bold_prefix="Phase 1 (Boundary Masking): "
    )
    add_bullet(doc, 
        "Computes the wet-pixel mask where cover parity disagrees with the decoy bit: wet = mask & ((c % 2) != d). All dry pixels remain unmodified.",
        bold_prefix="Phase 2 (Parity Matching): "
    )
    add_bullet(doc, 
        "For each wet pixel, maps secret bit s_i to delta_i: delta_i = +1 if s_i == 1 else -1. Sets c' = c + delta. Computes the discrepancy count: discrepancy = sum(c'_mirage != c'_decoy), verifying that the set of modified pixels is identical to an honest LSB-matching encoder.",
        bold_prefix="Phase 3 (Sign Steer): "
    )
    
    # Embed figure 1: Three-way change map
    fig1_path = os.path.join(os.getcwd(), "figures", "figure1_three_way_change_map.png")
    add_figure(doc, fig1_path, "Figure 7.1: Spatial distribution of pixel modifications across Cover, Decoy, and Mirage layers. The change sets are identical, proving zero additional modified pixels (Delta_diff = 0).")
    
    add_h2(doc, "7.4 Pre-Embedding Cover Image Gatekeeper (tessera/embed/cover_gate.py)")
    add_p(doc, 
        "A critical vulnerability in real-world steganography is attempting to embed payloads into unsuited cover images (e.g., flat synthetic images, solid background graphics, or heavily clipped scans). TESSERA v3 incorporates an automated Pre-Embedding Cover Gatekeeper that inspects candidate covers against three forensic criteria before permitting embedding:"
    )
    add_bullet(doc, 
        "Measures the percentage of pixels exhibiting values <= 5 or >= 250. If saturated pixels exceed 5.0% of the image, the image is rejected to prevent visual clipping artifacts.",
        bold_prefix="1. Saturated Boundary Check: "
    )
    add_bullet(doc, 
        "Partitions the cover image into 8x8 blocks and computes spatial variance sigma^2. If more than 30% of blocks exhibit near-zero variance (sigma^2 < 4.0), the image is rejected because flat regions lack textural masking.",
        bold_prefix="2. Flat Block Texture Check: "
    )
    add_bullet(doc, 
        "Computes the empirical Shannon entropy of the first-order pixel residual. If residual entropy H(R) < 1.8 bits/pixel, the cover is rejected due to excessive statistical predictability.",
        bold_prefix="3. Residual Entropy Floor: "
    )
    
    add_h2(doc, "7.5 Plausible Honey Decoy Generation & DTE (tessera/decoy/dte.py)")
    add_p(doc, 
        "To satisfy the coercive adversary's demands, tessera/decoy/dte.py implements a Juels–Ristenpart Distribution-Transforming Encoder. Rather than emitting random ASCII noise, the decoy generator contains a structured probabilistic grammar modeling plausible sensitive communications: tactical rendezvous orders, executive financial approvals, and administrative credentials. When an adversary brute-forces the deliberately weak decoy password, the resulting plaintext is syntactically coherent and contextually convincing (e.g., 'MEET @ north gate, Fri 13:30, code cobalt'), terminating the adversary's search."
    )
    
    add_h2(doc, "7.6 Reed-Solomon Erasure Codec & Sharding Engine (tessera/net/fec.py)")
    add_p(doc, 
        "The erasure coding engine operates across tessera/net/fec.py and tessera/ecc/shards.py. The authenticated ciphertext (1,432 bytes) is segmented into 24 data shards of 60 bytes each. The RS encoder evaluates a 32-row Cauchy generator matrix in GF(2^8) to synthesize 8 parity shards. At the receiver, missing shards are identified by datagram arrival tracking. If >= 24 shards arrive, the system inverts the 24x24 sub-matrix via Gaussian elimination in GF(2^8) to reconstruct the original ciphertext vector in under 4.2 milliseconds on standard commodity hardware."
    )
    
    add_h2(doc, "7.7 Wireshark Lua Dissector & Scapy PCAP Transport Auditor")
    add_p(doc, 
        "To provide transparent network protocol analysis during academic evaluations, we authored tools/tessera.lua, a native Wireshark Lua protocol dissector. When loaded into Wireshark, the dissector automatically binds to UDP ports 9998 and 9999, identifying Wire Protocol v2 framing ('ST' magic), decoding sequence numbers, tile indices, and flags, verifying the BLAKE2s-32 authentication tag, and displaying whether the datagram is an original flight, retransmission, or NACK bitmap. For offline programmatic audit, tools/analyze_pcap.py uses Scapy to ingest PCAP traces and generate packet-by-packet transport audit summaries."
    )
    
    add_h2(doc, "7.8 Interactive Streamlit Security Lab & Multi-Persona Viva Console")
    add_p(doc, 
        "For visual demonstration and live evaluation, TESSERA v3 provides two interactive graphical interfaces: tessera/ui/app.py (a Streamlit-based interactive steganography laboratory) and tessera/ui/eve_console.py (a multi-persona adversarial console). The consoles allow users to upload arbitrary cover images, inspect pixel-level difference maps, observe real-time simulated brute-force password attacks, and visualize the complete decoupling between decoy honey plaintexts and covert Mirage plaintexts."
    )
    
    add_h2(doc, "7.9 Production Command-Line Interface Suite (cli/alice_sender.py & bob_receiver.py)")
    add_p(doc, 
        "The primary operational interface consists of two production CLI applications engineered with argparse, colorama, and rich console logging: cli/alice_sender.py and cli/bob_receiver.py. The CLIs accept configurable parameters for secret payload text, cover image paths, decoy passphrases, secret passphrases, transport modes (fec vs hybrid), target UDP ports, and inter-packet pacing. Exit codes strictly conform to POSIX conventions: 0 for successful secret recovery, 1 for configuration error, and 2 for closed failure under catastrophic network loss."
    )
