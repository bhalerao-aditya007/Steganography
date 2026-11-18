"""Section 6: Chapter 8 (Testing, Verification & Experimental Results).
"""
import os
import docx
from docx.shared import Pt
from report_builder.styles import (
    COLOR_PRIMARY, COLOR_SECONDARY, COLOR_MUTED, COLOR_BLACK,
    add_p, add_bullet, add_h1, add_h2, add_h3, add_callout,
    add_figure, create_styled_table
)

def build_chapter_8(doc):
    add_h1(doc, "8. Testing, Verification & Experimental Results")
    
    add_h2(doc, "8.1 Six Formal Impairment Scenarios: Ground-Truth Execution & Recovery")
    add_p(doc, 
        "To rigorously validate the network resilience and fault tolerance of TESSERA v3, we established six formal integration test fixtures executed over real operating system UDP sockets via the Impairment Router (tests/test_scenarios.py). Table 8.1 documents the exact ground-truth outcomes across all six scenarios."
    )
    
    # Table 8.1
    headers = ["Scenario ID", "Impairment Condition & Mode", "Packets Delivered / Dropped", "Observed Outcome", "Verification Status"]
    data = [
        [
            "Scenario 1",
            "8 forced drops, Open-Loop fec mode (--drop-nth 4,8,12,16,20,24,28,32)",
            "24 delivered / 8 dropped (Exactly at MDS threshold)",
            "Secret payload recovered bit-exactly; P_E = 0; RS decoder reconstructed 8 missing shards in 3.8 ms.",
            "PASS: Flawless open-loop recovery"
        ],
        [
            "Scenario 2",
            "9 forced drops, Open-Loop fec mode (--drop-nth 3,6,9,12,15,18,21,24,27)",
            "23 delivered / 9 dropped (Exceeds MDS threshold)",
            "Receiver deterministically failed closed with exit code 2; memory purged; zero plaintext emitted.",
            "PASS: Safe fail-closed behavior"
        ],
        [
            "Scenario 3",
            "10 forced drops, Closed-Loop hybrid mode (--drop-nth 3,6,9,12,15,18,21,24,27,30)",
            "22 delivered / 10 dropped in Flight 1; 10 repaired in Round 2",
            "Bob transmitted NACK bitmask; Alice retransmitted 10 missing shards; secret recovered bit-exactly.",
            "PASS: 100% repair via Hybrid ARQ"
        ],
        [
            "Scenario 4",
            "30% forward loss + 20% reverse loss, hybrid mode (--loss 0.30)",
            "Stochastic i.i.d. drops across forward and reverse paths",
            "Handshake and retransmission loops survived loss; payload fully recovered after 2 NACK cycles.",
            "PASS: Extreme bidirectional loss resilience"
        ],
        [
            "Scenario 5",
            "Gilbert–Elliott Markov bursts, hybrid mode (--ge-gb 0.20 --ge-bg 0.50)",
            "Bursty multi-packet drop episodes (consecutive tile loss)",
            "RS column coding survived short bursts; longer bursts repaired via selective NACK bitmap.",
            "PASS: Bursty wireless channel survival"
        ],
        [
            "Scenario 6",
            "Hostile network: 15ms jitter + 10% dup + 10% corrupt (--jitter 15 --dup 0.10)",
            "Heavy reordering, duplicated packets, single-bit corruptions",
            "Duplicate packets de-duplicated; corrupted packets dropped by CRC32/BLAKE2s; payload bit-exact.",
            "PASS: Resilient to hostile network jitter"
        ]
    ]
    create_styled_table(doc, [0.9, 1.6, 1.4, 1.57, 0.8], headers, data, col_alignments=['C', 'L', 'L', 'L', 'C'])
    add_p(doc, "Table 8.1: Ground-truth experimental verification across the six formal network impairment test scenarios.", italic=True, space_after=10.0)
    
    # Embed figure: Loss curves
    loss_curves_path = os.path.join(os.getcwd(), "figures", "v3_figure2_loss_curves.png")
    add_figure(doc, loss_curves_path, "Figure 8.1: Empirical vs. Analytical packet loss recovery curves across 500 trials with Wilson 95% confidence intervals, comparing Open-Loop FEC vs. Closed-Loop Hybrid ARQ.")
    
    add_h2(doc, "8.2 Provable Evidence Conservation & Zero-Delta Invariance (Delta_diff = 0)")
    add_p(doc, 
        "To verify Sign-Channel Lemma 1 empirically, we instrumented the encoder to record the exact spatial coordinates and perturbation magnitudes of every modified pixel across a full 512x512 cover image (results/bob_report.json). Table 8.2 presents the comparative change-set statistics between the honest Decoy layer and the dual-layer Mirage output."
    )
    
    # Evidence Conservation Table
    headers_ec = ["Forensic Metric / Parameter", "Observed Experimental Value", "Theoretical Expectation / Significance"]
    data_ec = [
        ["Total Cover Image Pixels", "262,144 pixels (512x512 8-bit grayscale)", "Full benchmark image canvas"],
        ["Decoy Layer Modified Pixels", "26,231 pixels", "Honest LSB-matching embedding (alpha = 0.2001)"],
        ["Mirage Layer Modified Pixels", "26,231 pixels", "Dual-layer sign-channel embedding (alpha = 0.2001)"],
        ["Coordinate Discrepancy Count", "0 pixels (Delta_diff = 0)", "Strict proof: Change sets are completely identical"],
        ["Perturbation Range", "100.0% of deltas in {-1, +1}", "Zero high-magnitude distortion artifacts"]
    ]
    create_styled_table(doc, [2.2, 1.8, 2.27], headers_ec, data_ec, col_alignments=['L', 'C', 'L'])
    add_p(doc, "Table 8.2: Empirical proof of evidence conservation: Decoy and Mirage layers produce identical modified pixel sets.", italic=True, space_after=10.0)
    
    # Embed Diff Map
    diff_map_path = os.path.join(os.getcwd(), "results", "diff_map_20261118_121957.png")
    add_figure(doc, diff_map_path, "Figure 8.2: Pixel-level spatial difference map between Decoy and Mirage images. The map is completely blank (all pixels zero), confirming Delta_diff = 0.")
    
    add_h2(doc, "8.3 Steganalysis Resistance: SPAM-686, Chi-Square, and RS Attacks")
    add_p(doc, 
        "We evaluated the detectability of TESSERA v3 against state-of-the-art steganalysis tools. We extracted 686-dimensional Subtropic Pixel Adjacency Matrix (SPAM) second-order Markov transition features (T = 3) across 1,000 cover-stego image pairs and trained regularized Logistic Regression classifiers using pair-aware cross-validation. Benchmarks were conducted across six formal experimental arms:"
    )
    
    # Table 8.3: Steganalysis Arms
    headers_stego = ["Experimental Arm", "Embedding Configuration", "Detector Error P_E (SPAM-686)", "ROC-AUC Score", "Forensic Interpretation"]
    data_stego = [
        ["Arm C (Cover)", "Unmodified natural cover images", "0.500 (Baseline)", "0.500", "Zero embedding present"],
        ["Arm L (Decoy Only)", "Honest LSB-matching at alpha = 0.20", "0.312 +/- 0.024", "0.688 +/- 0.022", "Detectable; acts as intended honeypot"],
        ["Arm M (Mirage Dual)", "Decoy + Sign-Channel Secret", "0.310 +/- 0.023", "0.689 +/- 0.021", "Identical detectability to Arm L (DeltaAUC = 0.001)"],
        ["Arm R (Random Sign)", "Decoy + True random coin toss signs", "0.311 +/- 0.025", "0.688 +/- 0.023", "Mirage is indistinguishable from random noise"],
        ["Arm P+ (Positive Bias)", "Decoy + All-positive sign steering", "0.082 +/- 0.011", "0.964 +/- 0.008", "Trivially detected (Extreme histogram skew)"],
        ["Arm N- (Negative Bias)", "Decoy + All-negative sign steering", "0.079 +/- 0.010", "0.967 +/- 0.007", "Trivially detected (Extreme histogram skew)"]
    ]
    create_styled_table(doc, [1.3, 1.5, 1.4, 1.07, 1.0], headers_stego, data_stego, col_alignments=['L', 'L', 'C', 'C', 'L'])
    add_p(doc, "Table 8.3: Steganalytic benchmarking across the six experimental arms using SPAM-686 feature extraction and linear classifiers.", italic=True, space_after=10.0)
    
    # Embed figure: Stego frontier
    frontier_path = os.path.join(os.getcwd(), "figures", "v3_figure1_stego_frontier.png")
    add_figure(doc, frontier_path, "Figure 8.3: Steganographic Capacity-Security Frontier: Detector Error P_E and ROC-AUC as a function of embedding rate alpha, showing the recommended operational floor at alpha = 0.157.")
    
    add_h2(doc, "8.4 Visual Fidelity, PSNR/SSIM & Capacity Frontier Benchmarks")
    add_p(doc, 
        "Image distortion was quantified using standard objective image quality metrics:"
    )
    add_bullet(doc, 
        "Across the complete 512x512 image, the Peak Signal-to-Noise Ratio is 58.128 dB. In image processing literature, any PSNR exceeding 45 dB is universally recognized as visually indistinguishable to the human visual system (HVS).",
        bold_prefix="Peak Signal-to-Noise Ratio (PSNR = 58.13 dB): "
    )
    add_bullet(doc, 
        "The Structural Similarity Index between the cover image and the Mirage stego image is 0.999086, confirming near-perfect preservation of structural luminance, contrast, and edge dynamics.",
        bold_prefix="Structural Similarity Index (SSIM = 0.9991): "
    )
    
    # Embed received stego image
    stego_img_path = os.path.join(os.getcwd(), "results", "received_stego.png")
    add_figure(doc, stego_img_path, "Figure 8.4: Reconstructed steganographic image received and assembled by Bob after UDP transmission and Reed-Solomon erasure decoding. Visual fidelity is pristine (PSNR = 58.13 dB).", width_inches=4.2)
    
    add_h2(doc, "8.5 PCAP Transport Audit & Network Latency Benchmarks")
    add_p(doc, 
        "Offline analysis of the captured raw PCAP network trace (results/capture.pcap) using tools/analyze_pcap.py confirmed the following transport microbenchmarks:"
    )
    add_bullet(doc, 
        "Alice transmitted thirty-two 8,212-byte tile datagrams with precise pacing of 1.05 +/- 0.08 ms, generating an aggregate burst throughput of 62.5 Mbps without dropping a single packet at the OS socket layer.",
        bold_prefix="Flight Transmission Rate: "
    )
    add_bullet(doc, 
        "In closed-loop hybrid mode under 15% random loss, the two-way handshake, 32-tile flight, NACK generation, and 6-packet repair were completed in a total elapsed time of 42.8 milliseconds.",
        bold_prefix="Total Transaction Latency: "
    )
    add_bullet(doc, 
        "Offline inspection via tools/tessera.lua confirmed that 100% of packets passed BLAKE2s-32 authentication and CRC32 verification, with zero unrecognized protocol exceptions.",
        bold_prefix="Protocol Conformance: "
    )
