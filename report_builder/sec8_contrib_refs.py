"""Section 8: Chapter 11 (Individual Contributions & Academic Declarations) and Chapter 12 (References).
"""
import docx
from docx.shared import Pt, Inches
from report_builder.styles import (
    COLOR_PRIMARY, COLOR_SECONDARY, COLOR_MUTED, COLOR_BLACK,
    add_p, add_bullet, add_h1, add_h2, add_callout, create_styled_table
)

def build_chapter_11(doc):
    add_h1(doc, "11. Individual Contributions & Academic Declarations")
    
    add_h2(doc, "11.1 Atharv Deshmukh (BT24CSD004)")
    add_bullet(doc, 
        "Formulated the core theoretical architecture of the Mirage dual-layer deniability engine and authored the formal mathematical proof of Sign-Channel Lemma 1, establishing provable zero-delta evidence conservation (Delta_diff = 0).",
        bold_prefix="Steganographic Architecture & Lemma 1 Proof: "
    )
    add_bullet(doc, 
        "Engineered the comprehensive steganalysis evaluation suite in tessera/stego_analysis/, implementing 686-dimensional Subtropic Pixel Adjacency Matrix (SPAM) second-order Markov feature extraction, Chi-Square (χ²) histogram tests, and Sample Pair Analysis (SPA).",
        bold_prefix="Statistical Steganalysis & SPAM-686 Engine: "
    )
    add_bullet(doc, 
        "Implemented the automated pre-embedding cover image suitability checks (tessera/embed/cover_gate.py) evaluating boundary saturation percentages, 8x8 block texture variances, and residual Shannon entropy floors.",
        bold_prefix="Pre-Embedding Cover Gatekeeper: "
    )
    add_bullet(doc, 
        "Built the interactive Streamlit security laboratory (tessera/ui/app.py) and adversarial inspection console (tessera/ui/eve_console.py) providing real-time difference map rendering and brute-force cracking simulations.",
        bold_prefix="Interactive Security Lab & Visualizer: "
    )
    add_bullet(doc, 
        "Authored the publication figure generation pipeline (eval/plots.py) and co-authored Chapters 1, 2, 5, and 8 of this report.",
        bold_prefix="Evaluation Plots & Report Documentation: "
    )
    
    add_h2(doc, "11.2 Aditya Bhalerao (BT24CSD018)")
    add_bullet(doc, 
        "Architected and implemented the core socket transport layer (tessera/net/transport.py and tessera/net/rudp.py) using real BSD/POSIX UDP sockets (:9998 and :9999), incorporating high-resolution precise_sleep() hybrid spin-wait pacing and 4 MB SO_RCVBUF OS kernel allocations.",
        bold_prefix="Real UDP Network Transport Engine: "
    )
    add_bullet(doc, 
        "Designed and implemented the standalone network impairment emulator (tools/router_impair.py), supporting stochastic Bernoulli loss, Gilbert-Elliott 2-state Markov burst drops, heap-scheduled delay, jitter, packet duplication, and single-bit corruption.",
        bold_prefix="Deterministic & Stochastic Impairment Router: "
    )
    add_bullet(doc, 
        "Authored the native Wireshark Lua protocol dissector (tools/tessera.lua) for real-time packet inspection and engineered the offline Scapy transport auditor (tools/analyze_pcap.py) for programmatic PCAP verification.",
        bold_prefix="Wireshark Lua Dissector & PCAP Auditor: "
    )
    add_bullet(doc, 
        "Engineered the closed-loop Hybrid ARQ state machine, implementing asynchronous NACK bitmap generation, selective retransmission queues, and RFC 6298 EWMA round-trip timing.",
        bold_prefix="Closed-Loop Hybrid ARQ State Machine: "
    )
    add_bullet(doc, 
        "Resolved critical Windows OS network anomalies (suppressing WSAECONNRESET socket resets via SIO_UDP_CONNRESET ioctl) and co-authored Chapters 6, 7, and 10 of this report.",
        bold_prefix="Windows Kernel Socket Hardening & Report: "
    )
    
    add_h2(doc, "11.3 Aryan Karmore (BT24CSD009)")
    add_bullet(doc, 
        "Architected the memory-hard key derivation pipeline (tessera/crypto/kdf.py) adhering strictly to RFC 9106 Argon2id (m=64 MiB, t=3, p=1) and implemented 5-way cryptographic domain separation via HKDF-Expand-SHA256.",
        bold_prefix="Cryptographic Hardening & Argon2id Framework: "
    )
    add_bullet(doc, 
        "Integrated the RFC 8439 ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) suite (tessera/crypto/aead.py) with uniform 1,416-byte fixed padding to permanently eliminate ciphertext length leakage.",
        bold_prefix="Authenticated Encryption & Uniform Padding: "
    )
    add_bullet(doc, 
        "Implemented the Juels–Ristenpart Distribution-Transforming Encoder (tessera/decoy/dte.py), generating syntactically convincing, probabilistic decoy communications upon disclosure of weak passwords.",
        bold_prefix="Plausible Honey Decoy Generation (DTE): "
    )
    add_bullet(doc, 
        "Authored and executed the complete end-to-end integration test suite (tests/test_scenarios.py, tests/test_e2e_v3.py, and tests/test_receiver_fuzz.py), validating 100% bit-exact recovery across all six formal impairment scenarios.",
        bold_prefix="Comprehensive Verification Suite & Test Scenarios: "
    )
    add_bullet(doc, 
        "Engineered the production command-line interface suite (cli/alice_sender.py and cli/bob_receiver.py) and co-authored Chapters 3, 4, 9, and 11 of this report.",
        bold_prefix="Production CLI Applications & Documentation: "
    )
    
    add_h2(doc, "11.4 Academic Integrity Declaration")
    add_p(doc, 
        "We hereby declare that this academic project report entitled 'TESSERA v3: Mirage — Networked Deniable Image Steganography with Real UDP Socket Stack, Hybrid ARQ, Reed-Solomon Erasure Coding, and Provable Zero-Delta Invariance' is an authentic record of our own engineering work carried out during Semester 5 of the B.Tech program in Computer Science & Engineering (Data Science) at the Indian Institute of Information Technology, Nagpur."
    )
    add_p(doc, 
        "We confirm that all software modules, socket architectures, mathematical derivations, network impairment tools, and empirical benchmarks described herein represent real, working code executed within the project repository, and that all external academic literature and cryptographic standards have been faithfully cited."
    )
    
    # Table 11.1: Signatures
    headers_sig = [
        "Atharv Deshmukh (BT24CSD004)",
        "Aditya Bhalerao (BT24CSD018)",
        "Aryan Karmore (BT24CSD009)"
    ]
    data_sig = [
        [
            "Candidate Signature:\n\n___________________________",
            "Candidate Signature:\n\n___________________________",
            "Candidate Signature:\n\n___________________________"
        ],
        [
            "Date: 18 November 2026",
            "Date: 18 November 2026",
            "Date: 18 November 2026"
        ],
        [
            "Role: Steganography Core & Math",
            "Role: Socket Transport & Router",
            "Role: Cryptography & Verification"
        ]
    ]
    create_styled_table(doc, [2.09, 2.09, 2.09], headers_sig, data_sig, col_alignments=['C', 'C', 'C'])
    add_p(doc, "Table 11.1: Academic integrity declaration and candidate signatures.", italic=True, space_after=14.0)

def build_chapter_12(doc):
    add_h1(doc, "12. References")
    
    refs = [
        "[1] C. Cachin, 'An information-theoretic model for steganography,' Information and Computation, vol. 192, no. 1, pp. 41–56, 2004.",
        "[2] J. Fridrich, M. Goljan, and R. Du, 'Detecting LSB steganography in color, and gray-scale images,' IEEE MultiMedia, vol. 8, no. 4, pp. 22–28, 2001.",
        "[3] A. Westfeld, 'F5—a steganographic algorithm: High capacity with improved security,' in International Workshop on Information Hiding. Springer, 2001, pp. 289–302.",
        "[4] T. Sharp, 'An implementation of key-based digital signal steganography,' in International Workshop on Information Hiding. Springer, 2001, pp. 13–26.",
        "[5] J. Mielikainen, 'LSB matching: A simple alternative to LSB replacement,' IEEE Signal Processing Letters, vol. 13, no. 5, pp. 285–287, 2006.",
        "[6] T. Filler, J. Judas, and J. Fridrich, 'Minimizing additive distortion in steganography using syndrome-trellis codes,' IEEE Transactions on Information Forensics and Security, vol. 6, no. 3, pp. 920–935, 2011.",
        "[7] V. Holub, J. Fridrich, and T. Denemark, 'Universal distortion function for steganography in an arbitrary domain,' EURASIP Journal on Information Security, vol. 2014, no. 1, pp. 1–13, 2014.",
        "[8] T. Pevný, P. Bas, and J. Fridrich, 'Steganalysis by subtractive pixel adjacency matrix,' IEEE Transactions on Information Forensics and Security, vol. 5, no. 2, pp. 215–224, 2010.",
        "[9] A. Juels and T. Ristenpart, 'Honey encryption: Security beyond the brute-force bound,' in Advances in Cryptology – EUROCRYPT 2014. Springer, 2014, pp. 293–310.",
        "[10] A. Biryukov, D. Dinu, and D. Khovratovich, 'Argon2: New generation of memory-hard functions for password hashing and other applications,' RFC 9106, Internet Engineering Task Force, Feb. 2021.",
        "[11] Y. Nir and A. Langley, 'ChaCha20 and Poly1305 for IETF Protocols,' RFC 8439, Internet Engineering Task Force, June 2018.",
        "[12] H. Krawczyk and P. Eronen, 'HMAC-based Extract-and-Expand Key Derivation Function (HKDF),' RFC 5869, Internet Engineering Task Force, May 2010.",
        "[13] I. S. Reed and G. Solomon, 'Polynomial codes over certain finite fields,' Journal of the Society for Industrial and Applied Mathematics, vol. 8, no. 2, pp. 300–304, 1960.",
        "[14] E. N. Gilbert, 'Capacity of a burst-noise channel,' Bell System Technical Journal, vol. 39, no. 5, pp. 1253–1265, 1960.",
        "[15] E. O. Elliott, 'Estimates of error rates for codes on burst-noise channels,' Bell System Technical Journal, vol. 42, no. 5, pp. 1977–1997, 1963.",
        "[16] V. Paxson, M. Allman, J. Chu, and M. Sargent, 'Computing TCP's Retransmission Timer,' RFC 6298, Internet Engineering Task Force, June 2011.",
        "[17] S. Zander, G. Armitage, and P. Branch, 'A survey of covert channels and countermeasures in computer network protocols,' IEEE Communications Surveys & Tutorials, vol. 9, no. 3, pp. 44–57, 2007.",
        "[18] S. Wendzel, S. Zander, B. Bhuyan, et al., 'Lost and found in network traffic: A survey of network covert channels and countermeasures,' Security and Communication Networks, vol. 8, no. 18, pp. 4390–4412, 2015."
    ]
    
    for ref in refs:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(1)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.line_spacing = 1.15
        p.paragraph_format.left_indent = Inches(0.25)
        run = p.add_run(ref)
        run.font.name = 'Times New Roman'
        run.font.size = Pt(9.5)
        run.font.color.rgb = COLOR_SECONDARY
