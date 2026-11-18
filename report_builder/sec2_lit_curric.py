"""Section 2: Chapter 3 (Literature Review & Competitive Matrix) and Chapter 4 (Four-Module Curriculum Mapping).
"""
import docx
from docx.shared import Pt
from report_builder.styles import (
    COLOR_PRIMARY, COLOR_SECONDARY, COLOR_MUTED, COLOR_BLACK,
    add_p, add_bullet, add_h1, add_h2, add_callout, create_styled_table
)

def build_chapter_3(doc):
    add_h1(doc, "3. Literature Review & Existing Solutions")
    
    add_h2(doc, "3.1 State-of-the-Art Review")
    add_p(doc, 
        "To rigorously establish the contributions of TESSERA v3 within contemporary cybersecurity and data privacy research, existing privacy-preserving and steganographic systems are analyzed across five distinct operational paradigms:"
    )
    
    add_bullet(doc, 
        "Introduced in early multimedia security literature (Kurak & McHugh, 1992; Westfeld & Pfitzmann, 1999), LSB replacement overwrites the least significant bit of raster pixels with payload bits. While computationally trivial, it enforces an asymmetric transformation: an even pixel value 2k becomes {2k, 2k+1}, but can never become 2k-1. This fundamental asymmetry destroys the natural continuity of adjacent histogram bins, creating 'Pairs of Values' (PoV). Eve can expose this asymmetry using the Chi-Square goodness-of-fit attack (Westfeld, 2001) or Sample Pair Analysis (Dumitrescu et al., 2003) with near-certainty at embedding rates as low as 5% of capacity. It provides zero deniability and zero channel error tolerance.",
        bold_prefix="1. Naive LSB Replacement & Pairs of Values (PoV): "
    )
    
    add_bullet(doc, 
        "Proposed by Sharp (2001) and generalized by Mielikainen (2006), LSB matching avoids PoV histogram asymmetry by randomly incrementing or decrementing the pixel value by 1 whenever its parity does not match the secret bit: c' in {c-1, c+1}. This ensures that both even and odd values undergo symmetric transitions, neutralizing first-order histogram steganalysis (such as Chi-Square). However, conventional LSB matching treats the sign choice as an uninformative pseudo-random coin toss. Under coercive inspection, discovery of the steganographic key completely compromises the payload, offering no deniable decoy mechanisms.",
        bold_prefix="2. LSB Matching (+/- 1 Embedding) & First-Order Invariance: "
    )
    
    add_bullet(doc, 
        "Pioneered by Filler, Judas, and Fridrich (2011), STC formulates steganography as an optimal coding problem over linear block codes on a trellis, minimizing an additive distortion function. Modern algorithms like S-UNIWARD (Holub et al., 2014) and WOW (Holub & Fridrich, 2012) compute distortion costs based on wavelet filter bank residuals, concentrating changes within complex image textures where human eyes and statistical detectors are least sensitive. While achieving state-of-the-art empirical security against rich model classifiers (e.g., SRM, maxSRM), STC architectures do not incorporate plausible deniability, provide no multi-layer honey payloads, and assume an error-free underlying transport channel.",
        bold_prefix="3. Content-Adaptive Steganography & Syndrome-Trellis Codes (STC): "
    )
    
    add_bullet(doc, 
        "Introduced by Juels and Ristenpart (2014), Honey Encryption ensures that decryption of ciphertext using an incorrect passphrase produces a plausible, syntactically valid decoy plaintext rather than a garbled error. This is achieved via a Distribution-Transforming Encoder (DTE) that maps seed spaces to message spaces conforming to target natural language probability distributions (such as fake credit card numbers or military operation orders). While highly effective for password vaults, honey encryption operates exclusively in symbolic text domains and has never previously been integrated with physical image steganography or network packet transport.",
        bold_prefix="4. Honey Encryption & Distribution-Transforming Encoders (DTE): "
    )
    
    add_bullet(doc, 
        "Network covert channels (Zander et al., 2007; Wendzel et al., 2015) embed secret data directly into the unused or malleable fields of protocol headers (such as IP Identification, TCP Initial Sequence Numbers, or packet inter-arrival times). However, modern Deep Packet Inspection (DPI) middleboxes and carrier-grade NATs routinely scrub, normalize, or randomize these fields during transit. Furthermore, network covert channels exhibit tiny throughput (often < 10 bytes/sec) and leave clear traces in protocol statistical distributions.",
        bold_prefix="5. Network Covert Channels & Protocol Manipulation: "
    )
    
    add_h2(doc, "3.2 Comparative Analysis & Competitive Feature Matrix")
    add_p(doc, 
        "Table 3.1 establishes a rigorous comparative matrix benchmarking TESSERA v3 against existing academic and commercial privacy paradigms across eight critical technical dimensions."
    )
    
    # Table 3.1
    headers = [
        "Operational Dimension",
        "Naive LSB Tools (OpenStego/Steghide)",
        "Adaptive Stego (S-UNIWARD / STC)",
        "Honey Encryption (Juels-Ristenpart)",
        "TESSERA v3: Mirage (Our Platform)"
    ]
    data = [
        [
            "Coercion & Rubber-Hose Resistance",
            "None (Key surrender yields plaintext)",
            "None (Single-key model; payload compromised)",
            "High (Decryption yields plausible decoy text)",
            "High (Dual-layer: crackable decoy + covert Mirage)"
        ],
        [
            "Deniable Multi-Payload Support",
            "No (Single embedded stream only)",
            "No (Single embedded stream only)",
            "Yes (Purely in symbolic text domain)",
            "Yes (Decoy layer + Orthogonal sign-channel layer)"
        ],
        [
            "Evidence Conservation (Delta_diff)",
            "N/A (No secondary payload concept)",
            "N/A (Single payload distortion minimization)",
            "N/A (No spatial image embedding)",
            "Provable Delta_diff = 0 (Zero extra modified pixels)"
        ],
        [
            "Steganalysis Resistance",
            "Trivially Broken (Chi-Square, SPA, RS)",
            "High (Resistant to spatial rich models)",
            "N/A (Pure cryptographic layer)",
            "Decoy acts as attractor; Mirage adds 0 detectability"
        ],
        [
            "Transport-Channel Resilience",
            "Zero (Single lost byte destroys image decompressor)",
            "Zero (Requires ideal error-free file transfer)",
            "N/A (Transport agnostic text wrapper)",
            "MDS Reed-Solomon RS(32,24) + Closed-Loop Hybrid ARQ"
        ],
        [
            "Real Socket Network Stack",
            "No (File-based batch processing only)",
            "No (In-memory algorithmic simulation)",
            "No (Cryptographic primitive only)",
            "Yes (Real UDP sockets :9998/:9999 + Wireshark dissector)"
        ]
    ]
    create_styled_table(doc, [1.47, 1.2, 1.2, 1.2, 1.2], headers, data, col_alignments=['L', 'L', 'L', 'L', 'L'])
    add_p(doc, "Table 3.1: Comprehensive comparative capability matrix benchmarking TESSERA v3 against state-of-the-art privacy paradigms.", italic=True, space_after=10.0)

def build_chapter_4(doc):
    add_h1(doc, "4. Four-Module Curriculum Mapping (Data Privacy & Security)")
    
    add_p(doc, 
        "The Data Privacy & Security (SEM 5) curriculum at IIIT Nagpur is structured across four foundational pedagogical pillars spanning cryptographic engineering, statistical information hiding, network transport security, and empirical fault tolerance. Table 4.1 maps each academic module directly to its concrete software architecture, algorithmic design, and verifiable evidence within the TESSERA v3 codebase."
    )
    
    # Table 4.1
    headers = [
        "Module",
        "Curriculum Topic",
        "Implementation in TESSERA v3",
        "Codebase Artifact & Concrete Evidence"
    ]
    data = [
        [
            "Module 1",
            "Applied Cryptography & Key Management",
            "RFC 9106 Argon2id memory-hard KDF (m=64 MiB, t=3, p=1); HKDF-Expand-SHA256 5-way domain separation (enc, wire, H2, wh, pos); ChaCha20-Poly1305 AEAD authenticated encryption; uniform 1,416-byte fixed padding defeating traffic analysis.",
            "tessera/crypto/kdf.py (Lines 42–115)\ntessera/crypto/aead.py (Lines 28–84)\ntests/test_crypto.py (RFC 9106 test vectors)"
        ],
        [
            "Module 2",
            "Information Hiding & Steganalysis",
            "Mirage dual-layer sign-channel embedding (Sign-Channel Lemma 1); pre-embedding cover image gatekeeper checking saturated boundaries and flat blocks; SPAM-686 feature extractor; Chi-Square (χ²) and RS steganalysis attacks; honey DTE decoy generator.",
            "tessera/embed/mirage.py (Lines 14–92)\ntessera/embed/cover_gate.py (Lines 18–65)\ntessera/stego_analysis/spam.py\ntessera/decoy/dte.py"
        ],
        [
            "Module 3",
            "Network Security & Unreliable Protocols",
            "Real UDP socket transport engine on local OS ports (:9998, :9999); Wire Protocol v2 20-byte binary header with BLAKE2s-32 and CRC32; high-resolution hybrid spin-wait pacing; 4 MB OS socket receive buffers; Wireshark Lua dissector (tessera.lua).",
            "tessera/net/transport.py (Lines 35–210)\ntessera/net/packet.py (Lines 12–78)\ntools/router_impair.py (Lines 50–280)\ntools/tessera.lua"
        ],
        [
            "Module 4",
            "Fault Tolerance & Security Evaluation",
            "Column-wise Reed-Solomon RS(32,24) MDS erasure coding in GF(2^8); closed-loop Hybrid ARQ with NACK bitmap feedback; 6 formal impairment scenarios (burst drops, reordering, corruption); offline Scapy PCAP auditor; empirical Wilson 95% confidence intervals.",
            "tessera/net/fec.py (Lines 20–140)\ntessera/ecc/shards.py\ntests/test_scenarios.py (Scenarios 1–6)\ntools/analyze_pcap.py"
        ]
    ]
    create_styled_table(doc, [0.8, 1.4, 2.47, 1.6], headers, data, col_alignments=['C', 'L', 'L', 'L'])
    add_p(doc, "Table 4.1: Four-module academic curriculum mapping and concrete implementation evidence across the TESSERA v3 codebase.", italic=True, space_after=12.0)
