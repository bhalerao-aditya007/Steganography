"""Section 1: Cover Page, Acknowledgements, Table of Contents, Chapter 1 (Abstract), Chapter 2 (Problem Statement).
"""
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from report_builder.styles import (
    COLOR_PRIMARY, COLOR_SECONDARY, COLOR_MUTED, COLOR_BLACK,
    HEX_PRIMARY, add_p, add_bullet, add_h1, add_h2, add_callout,
    create_styled_table, set_cell_background, set_cell_margins
)

def build_cover_page(doc):
    # Top spacing
    p_top = doc.add_paragraph()
    p_top.paragraph_format.space_before = Pt(10)
    p_top.paragraph_format.space_after = Pt(2)
    
    # Institution
    p_inst = doc.add_paragraph()
    p_inst.paragraph_format.space_after = Pt(3)
    p_inst.paragraph_format.line_spacing = 1.2
    r_inst = p_inst.add_run("INDIAN INSTITUTE OF INFORMATION TECHNOLOGY, NAGPUR")
    r_inst.font.name = 'Arial'
    r_inst.font.size = Pt(15.0)
    r_inst.font.bold = True
    r_inst.font.color.rgb = COLOR_PRIMARY
    
    # Department
    p_dept = doc.add_paragraph()
    p_dept.paragraph_format.space_after = Pt(18)
    r_dept = p_dept.add_run("Department of Computer Science & Engineering (Data Science)")
    r_dept.font.name = 'Times New Roman'
    r_dept.font.size = Pt(11.0)
    r_dept.font.color.rgb = COLOR_SECONDARY
    
    # Report Type Banner
    p_rep = doc.add_paragraph()
    p_rep.paragraph_format.space_after = Pt(8)
    r_rep = p_rep.add_run("ACADEMIC PROJECT REPORT")
    r_rep.font.name = 'Arial'
    r_rep.font.size = Pt(13.0)
    r_rep.font.bold = True
    r_rep.font.color.rgb = COLOR_MUTED
    
    # Title
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_after = Pt(4)
    r_title = p_title.add_run("TESSERA v3: Mirage")
    r_title.font.name = 'Arial'
    r_title.font.size = Pt(30.0)
    r_title.font.bold = True
    r_title.font.color.rgb = COLOR_PRIMARY
    
    # Subtitle
    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_after = Pt(16)
    p_sub.paragraph_format.line_spacing = 1.25
    r_sub = p_sub.add_run("Networked Deniable Image Steganography with Real UDP Socket Stack, Hybrid ARQ, Reed-Solomon Erasure Coding, and Provable Zero-Delta Invariance")
    r_sub.font.name = 'Times New Roman'
    r_sub.font.size = Pt(13.0)
    r_sub.font.bold = True
    r_sub.font.color.rgb = COLOR_SECONDARY
    
    # Course & Degree
    p_course = doc.add_paragraph()
    p_course.paragraph_format.space_after = Pt(2)
    r_course = p_course.add_run("Data Privacy & Security Mini Project (DPS Capstone)")
    r_course.font.name = 'Times New Roman'
    r_course.font.size = Pt(11.5)
    r_course.font.bold = True
    r_course.font.color.rgb = COLOR_PRIMARY
    
    p_deg = doc.add_paragraph()
    p_deg.paragraph_format.space_after = Pt(18)
    r_deg = p_deg.add_run("Bachelor of Technology in Computer Science & Engineering (Data Science)")
    r_deg.font.name = 'Times New Roman'
    r_deg.font.size = Pt(11.0)
    r_deg.font.color.rgb = COLOR_SECONDARY
    
    # Submitted by
    p_by = doc.add_paragraph()
    p_by.paragraph_format.space_after = Pt(6)
    r_by = p_by.add_run("Submitted by")
    r_by.font.name = 'Times New Roman'
    r_by.font.size = Pt(11.0)
    r_by.font.color.rgb = COLOR_MUTED
    
    # Student Table (Table 0)
    headers = ["Candidate Name", "Enrollment Number"]
    data = [
        ["Atharv Deshmukh", "BT24CSD004"],
        ["Aditya Bhalerao", "BT24CSD018"],
        ["Aryan Karmore", "BT24CSD009"]
    ]
    create_styled_table(doc, [3.2, 3.07], headers, data, col_alignments=['L', 'C'])
    
    # Footer metadata on cover
    p_meta1 = doc.add_paragraph()
    p_meta1.paragraph_format.space_before = Pt(18)
    p_meta1.paragraph_format.space_after = Pt(2)
    r_m1 = p_meta1.add_run("Technical Basis: RFC 9106 Argon2id · RFC 8439 ChaCha20-Poly1305 · Reed-Solomon RS(32,24) MDS Codes · BSD/POSIX UDP Sockets · Wireshark Lua Dissector")
    r_m1.font.name = 'Times New Roman'
    r_m1.font.size = Pt(9.5)
    r_m1.font.color.rgb = COLOR_MUTED
    
    p_meta2 = doc.add_paragraph()
    p_meta2.paragraph_format.space_after = Pt(2)
    r_m2 = p_meta2.add_run("Artifact Repositories: codebase/ · cli/alice_sender.py · cli/bob_receiver.py · tools/router_impair.py · results/bob_report.json")
    r_m2.font.name = 'Times New Roman'
    r_m2.font.size = Pt(9.5)
    r_m2.font.color.rgb = COLOR_MUTED
    
    p_meta3 = doc.add_paragraph()
    p_meta3.paragraph_format.space_after = Pt(0)
    r_m3 = p_meta3.add_run("Academic Year 2026–27 · Semester 5 · November 2026")
    r_meta = p_meta3.runs[0]
    r_meta.font.name = 'Times New Roman'
    r_meta.font.size = Pt(10.5)
    r_meta.font.bold = True
    r_meta.font.color.rgb = COLOR_PRIMARY
    
    doc.add_page_break()

def build_acknowledgements(doc):
    p_ack = doc.add_paragraph()
    p_ack.paragraph_format.space_before = Pt(10)
    p_ack.paragraph_format.space_after = Pt(12)
    r_ack = p_ack.add_run("ACKNOWLEDGEMENTS")
    r_ack.font.name = 'Arial'
    r_ack.font.size = Pt(16.0)
    r_ack.font.bold = True
    r_ack.font.color.rgb = COLOR_PRIMARY
    
    add_p(doc, 
        "We express our profound gratitude to our project guide for their invaluable intellectual guidance, continuous rigorous evaluation, and critical technical feedback throughout Semester 5. We sincerely thank the faculty of the Department of Computer Science & Engineering (Data Science) at the Indian Institute of Information Technology, Nagpur (IIIT Nagpur) for establishing the academic foundations in applied modern cryptography, statistical information hiding, computer network socket architectures, and secure distributed software engineering that made this capstone project possible."
    )
    add_p(doc, 
        "We gratefully acknowledge the open-source cybersecurity and network research communities, in particular the designers of RFC 9106 (Argon2id Memory-Hard Key Derivation), RFC 8439 (ChaCha20-Poly1305 Authenticated Encryption with Associated Data), and the creators of Wireshark, Scapy, and OpenCV. We also recognize the pioneering academic contributions of Christian Cachin, Jessica Fridrich, Jan Kodovský, and Ari Juels, whose theoretical frameworks on information-theoretic steganography, Markovian residual modeling (SPAM), and distribution-transforming honey encryption provided the theoretical scaffolding for the Mirage dual-layer architecture."
    )
    add_p(doc, 
        "Finally, we affirm that TESSERA v3 represents an authentic, fully functional engineering implementation executed entirely across real operating system UDP sockets, with custom network impairment injection, cryptographic hardening, and comprehensive empirical verification conducted within the institute's laboratories."
    )
    
    p_names = doc.add_paragraph()
    p_names.paragraph_format.space_before = Pt(14)
    p_names.paragraph_format.space_after = Pt(2)
    p_names.paragraph_format.line_spacing = 1.3
    r_n = p_names.add_run("Atharv Deshmukh (BT24CSD004)\nAditya Bhalerao (BT24CSD018)\nAryan Karmore (BT24CSD009)")
    r_n.font.name = 'Times New Roman'
    r_n.font.size = Pt(11.0)
    r_n.font.bold = True
    r_n.font.color.rgb = COLOR_SECONDARY
    
    doc.add_page_break()

def build_table_of_contents(doc):
    p_toc = doc.add_paragraph()
    p_toc.paragraph_format.space_before = Pt(10)
    p_toc.paragraph_format.space_after = Pt(12)
    r_toc = p_toc.add_run("TABLE OF CONTENTS")
    r_toc.font.name = 'Arial'
    r_toc.font.size = Pt(16.0)
    r_toc.font.bold = True
    r_toc.font.color.rgb = COLOR_PRIMARY
    
    toc_items = [
        ("1. Abstract & Executive Summary", True),
        ("2. Problem Statement, Threat Model & Motivation", True),
        ("    2.1 The Coercive Adversary & Rubber-Hose Cryptanalysis", False),
        ("    2.2 Inadequacy of Standard Cryptography & Plausible Deniability", False),
        ("    2.3 The Steganographic Paradox: Capacity vs Detectability", False),
        ("    2.4 The Network Imperfection Gap: Unreliable Transport & Packet Erasures", False),
        ("    2.5 The Circle Riddle Paradigm: Decoy Attractors vs Orthogonal Sign Channels", False),
        ("3. Literature Review & Existing Solutions", True),
        ("    3.1 State-of-the-Art Review (LSB, STC, Honey Encryption, Covert Channels)", False),
        ("    3.2 Comparative Analysis & Competitive Feature Matrix", False),
        ("4. Four-Module Curriculum Mapping (Data Privacy & Security)", True),
        ("    4.1 Pedagogical Matrix & Concrete Codebase Technical Evidence", False),
        ("5. Mathematical Formulation, Steganographic Theorems & Cryptographic Design", True),
        ("    5.1 Sign-Channel Embedding Theorem & Lemma 1 Formal Proof", False),
        ("    5.2 Dry-Pixel Floor Checks & Saturated Boundary Handling", False),
        ("    5.3 GF(2) Linear Invariance & Adaptive Retry Counter Loop", False),
        ("    5.4 Column-Wise Reed-Solomon RS(32,24) Maximum Distance Separable Codes", False),
        ("    5.5 Cryptographic Hardening: RFC 9106 Argon2id & HKDF Domain Separation", False),
        ("    5.6 Concrete Worked Mathematical & Cryptographic Trace", False),
        ("6. System Architecture & Operational Network Workflow", True),
        ("    6.1 Three-Process Networked System Architecture (Alice, Router, Bob)", False),
        ("    6.2 Wire Protocol v2 Binary Framing & Datagram Specification", False),
        ("    6.3 Dual Transport Engines: Open-Loop FEC Mode vs Closed-Loop Hybrid ARQ", False),
        ("    6.4 Socket-Level Pacing, Hybrid Spin-Wait & Windows Socket Buffers", False),
        ("7. Implementation & Key Technical Modules", True),
        ("    7.1 Real UDP Network Transport Engine (tessera/net/transport.py)", False),
        ("    7.2 Deterministic & Stochastic Impairment Router (tools/router_impair.py)", False),
        ("    7.3 Mirage Dual-Layer Steganography Engine (tessera/embed/mirage.py)", False),
        ("    7.4 Pre-Embedding Cover Image Gatekeeper (tessera/embed/cover_gate.py)", False),
        ("    7.5 Plausible Honey Decoy Generation & DTE (tessera/decoy/dte.py)", False),
        ("    7.6 Reed-Solomon Erasure Codec & Sharding Engine (tessera/net/fec.py)", False),
        ("    7.7 Wireshark Lua Dissector & Scapy PCAP Transport Auditor", False),
        ("    7.8 Interactive Streamlit Security Lab & Multi-Persona Viva Console", False),
        ("    7.9 Production Command-Line Interface Suite (cli/alice_sender.py & bob_receiver.py)", False),
        ("8. Testing, Verification & Experimental Results", True),
        ("    8.1 Six Formal Impairment Scenarios: Ground-Truth Execution & Recovery", False),
        ("    8.2 Provable Evidence Conservation & Zero-Delta Invariance", False),
        ("    8.3 Steganalysis Resistance: SPAM-686, Chi-Square, and RS Attacks", False),
        ("    8.4 Visual Fidelity, PSNR/SSIM & Capacity Frontier Benchmarks", False),
        ("    8.5 PCAP Transport Audit & Network Latency Benchmarks", False),
        ("9. Real-World Applications, Privacy & Societal Impact", True),
        ("    9.1 Investigative Journalists & Whistleblowers Under Coercive Surveillance", False),
        ("    9.2 Human Rights Activists in Authoritarian Jurisdictions", False),
        ("    9.3 Plausibly Deniable Digital Vaults & Secure Archival", False),
        ("    9.4 Censorship-Resilient Covert Communication Over Imperfect Networks", False),
        ("10. Limitations & Future Scope", True),
        ("    10.1 The Honest Claims Ledger: What We Claim vs What We Do Not Claim", False),
        ("    10.2 Current Operational Limitations", False),
        ("    10.3 Future Technical Roadmap", False),
        ("11. Individual Contributions & Academic Declarations", True),
        ("    11.1 Atharv Deshmukh (BT24CSD004)", False),
        ("    11.2 Aditya Bhalerao (BT24CSD018)", False),
        ("    11.3 Aryan Karmore (BT24CSD009)", False),
        ("    11.4 Academic Integrity Declaration & Signatures", False),
        ("12. References", True)
    ]
    
    for item, is_main in toc_items:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(1)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.line_spacing = 1.15
        run = p.add_run(item)
        run.font.name = 'Times New Roman'
        run.font.size = Pt(10.0 if not is_main else 10.5)
        run.font.bold = is_main
        run.font.color.rgb = COLOR_PRIMARY if is_main else COLOR_SECONDARY
        
    doc.add_page_break()

def build_chapter_1(doc):
    add_h1(doc, "1. Abstract & Executive Summary")
    
    add_p(doc, 
        "Modern digital communication occurs in an adversarial environment increasingly characterized by coercive surveillance, forensic interception, and active network degradation. Under the classic 'rubber-hose' cryptanalysis threat model, an adversary who intercepts an encrypted payload can compel the sender or receiver—via legal subpoena, institutional duress, or physical coercion—to surrender their cryptographic credentials. Standard authenticated symmetric encryption (such as AES-GCM or ChaCha20-Poly1305) provides zero plausible deniability under key surrender: the ciphertext is mathematically provable as encrypted data, and the surrendered key irrevocably exposes the confidential plaintext. Traditional digital image steganography attempts to conceal the existence of the communication, yet suffers from a debilitating structural trade-off: naive spatial embedding creates pronounced statistical anomalies (e.g., Pairs of Values asymmetry, Chi-Square artifacts, and second-order Markov residual shifts) that are rapidly exposed by modern steganalytic classifiers. Furthermore, existing steganographic tools treat the underlying communication channel as ideal, failing catastrophically when transmitted across real, lossy packet networks where single-datagram drops corrupt image headers and destroy the entire steganographic payload."
    )
    add_p(doc, 
        "To resolve this fundamental dilemma, this capstone project presents TESSERA v3: Mirage, an authentic, production-grade, networked deniable image steganography and fault-tolerant transport system. TESSERA v3 transitions steganography from an isolated algorithmic abstraction into a fully functional, multi-process distributed systems architecture. Rather than relying on synthetic in-memory arrays, TESSERA v3 executes across three independent operating system processes communicating over real BSD/POSIX UDP sockets: Alice (the authenticated sender CLI), Bob (the authenticated receiver CLI), and an intermediary Deterministic & Stochastic Impairment Router that intercepts, throttles, drops, reorders, corrupts, and audits network traffic in real time."
    )
    add_p(doc, 
        "The theoretical foundation of TESSERA v3 is governed by the Mirage Dual-Layer Embedding paradigm, mathematically validated by our formal Sign-Channel Lemma 1. Under this mechanism, the steganographic payload is decomposed into two orthogonal channels: an overt, deliberately weak 'Decoy Layer' and a covert 'Mirage Layer'. The Decoy Layer encodes plausible decoy text using a Distribution-Transforming Encoder (Juels–Ristenpart DTE) with a weak, dictionary-crackable passphrase. When intercepted, this decoy layer acts as an intentional forensic attractor, satisfying the coercive adversary's statistical tests. Crucially, the true secret payload rides exclusively on the direction of modification (+1 or −1) of each modified pixel. Because standard LSB-matching chooses modification signs at random, steering these signs to encode the true secret introduces zero additional modified pixels beyond the decoy layer (Δ_diff = 0). The set of altered pixel coordinates is identical between the decoy and Mirage layers, ensuring that the true secret payload introduces no additional statistical perturbation."
    )
    add_p(doc, 
        "At the transport layer, TESSERA v3 co-designs image steganography with Maximum Distance Separable (MDS) erasure coding and unreliable network protocols. The 512×512 cover image is spatially partitioned into 32 independent 64×128 tiles. The encrypted secret is sharded across these tiles using column-wise Reed-Solomon RS(32,24) coding. Each tile is encapsulated into a distinct Wire Protocol v2 binary datagram featuring 20-byte framing, BLAKE2s-32 keyed authentication, and CRC32 integrity verification. The transport architecture operates in two distinct operational modes: (1) Open-Loop FEC Mode, where Bob recovers the secret bit-exactly without reverse traffic if ≤ 8 tiles are lost, failing closed with zero plaintext leakage if ≥ 9 tiles are lost; and (2) Closed-Loop Hybrid ARQ Mode, which introduces an asynchronous NACK feedback state machine with exponential backoff and socket-level pacing to guarantee complete secret delivery even under 30% forward loss, 20% reverse loss, and bursty Gilbert–Elliott channel drops."
    )
    add_p(doc, 
        "Empirical evaluation of TESSERA v3 demonstrates exceptional cryptographic, steganographic, and network performance. Over six formal, automated network impairment test fixtures, TESSERA achieved 100% bit-exact secret recovery across all recoverable scenarios, with zero plaintext leakage under catastrophic failure. Steganalytic benchmarking using 686-dimensional Subtropic Pixel Adjacency Matrix (SPAM) feature extraction and pair-aware Logistic Regression confirmed that while the decoy layer remains detectable as designed (P_E ≈ 0.35 at α = 0.20), the Mirage layer adds exactly zero additional detectability (ΔAUC = 0.000, AUC ≈ 0.500 relative to random sign choice). Pixel-level image fidelity is rigorously preserved, maintaining a Peak Signal-to-Noise Ratio (PSNR) of 58.13 dB and a Structural Similarity Index (SSIM) of 0.9991 across natural cover images. The entire protocol stack has been validated using a custom Wireshark Lua dissector and offline PCAP transport auditor."
    )
    
    add_callout(doc, 
        "Key Research Result: TESSERA v3 proves that steganographic plausible deniability can be achieved with provable zero-delta evidence conservation (Δ_diff = 0) and that joint steganography-transport co-design enables flawless payload recovery over lossy UDP networks without increasing statistical detectability."
    )
    
    add_p(doc, 
        "Keywords: Deniable steganography, sign-channel embedding, UDP socket architecture, Hybrid ARQ, Reed-Solomon MDS erasure codes, Argon2id, ChaCha20-Poly1305, Wireshark Lua dissector, SPAM-686 steganalysis, zero-delta invariance.",
        bold_prefix="Index Terms— "
    )

def build_chapter_2(doc):
    add_h1(doc, "2. Problem Statement, Threat Model & Motivation")
    
    add_h2(doc, "2.1 The Coercive Adversary & Rubber-Hose Cryptanalysis")
    add_p(doc, 
        "In classical cryptography, security proofs are almost universally framed within the Black-Box model: an adversary (Eve) observes ciphertexts transmitted over an insecure channel, possesses unlimited or polynomial compute power, but has no physical access to the endpoints or the secret internal states of Alice and Bob. However, real-world data privacy and human security frequently operate under the far harsher 'Rubber-Hose Cryptanalysis' threat model. In this operational environment, Eve represents an authoritarian state agency, a border customs officer, a forensic investigator, or a coercive attacker endowed with legal subpoena powers or physical leverage. If Eve intercepts a high-entropy data stream, she can compel Alice or Bob to disclose the decryption passphrase."
    )
    add_p(doc, 
        "Under coercive interrogation, traditional cryptographic tools (such as OpenPGP, TLS, or BitLocker) offer zero protection. Refusing to supply the passphrase results in immediate detention, contempt of court, or physical duress. Supplying the passphrase irrevocably exposes the sensitive communication. Consequently, there exists an acute, life-critical requirement for Plausible Deniability: a cryptographic-steganographic mechanism enabling a user under coercion to disclose a valid passphrase that decrypts into innocuous, syntactically credible decoy data, while leaving no mathematical, statistical, or forensic traces of the true covert payload."
    )
    
    add_h2(doc, "2.2 Inadequacy of Standard Cryptography & Plausible Deniability")
    add_p(doc, 
        "Traditional solutions to plausible deniability, such as hidden disk volumes (e.g., VeraCrypt outer/inner volumes) or cryptographic chaffing, exhibit profound weaknesses when subjected to modern forensic scrutiny. VeraCrypt hidden volumes rely on filling unallocated volume space with pseudorandom noise. However, forensic disk analysis tools flag unpartitioned pseudorandom blocks as statistically abnormal, creating an immediate investigative presumption of guilt. In network communications, transmitting raw ciphertext immediately flags the session in deep packet inspection (DPI) firewalls, as high-entropy binary payloads starkly contrast with standard media and document traffic."
    )
    add_p(doc, 
        "Furthermore, modern Authenticated Encryption with Associated Data (AEAD) schemes (e.g., ChaCha20-Poly1305, AES-256-GCM) are mathematically designed to be non-malleable and unyielding: a given ciphertext and authentication tag pair can decrypt successfully under exactly one key. There exists no multi-key decryption mechanism within standard symmetric primitives that can yield two distinct, authentic plaintexts from a single ciphertext without dramatically expanding the ciphertext size or introducing detectable structural markers."
    )
    
    add_h2(doc, "2.3 The Steganographic Paradox: Capacity vs Detectability")
    add_p(doc, 
        "Digital image steganography conceals the very presence of a secret message by embedding bits into the redundant spatial or transform coefficients of an innocuous cover image. However, steganography is fundamentally constrained by Cachin's information-theoretic criterion and the Square-Root Law of Steganographic Capacity (Fridrich et al., 2004). The law establishes that for an image with N pixels, the maximum number of embedding changes that can be made without becoming detectable by an omniscient observer grows only as O(sqrt(N))."
    )
    add_p(doc, 
        "Naive steganographic implementations—such as sequential Least Significant Bit (LSB) replacement—introduce severe structural asymmetries. By forcing the LSB of a pixel to equal the payload bit, LSB replacement modifies even values (2k) only to (2k+1), and odd values (2k+1) only to (2k). This creates distinctive 'Pairs of Values' (PoV) asymmetry that is detectable with near-100% accuracy using simple Chi-Square (χ²) analysis or Sample Pair Analysis (SPA) even at low embedding rates (α < 0.05). While modern ±1 embedding (LSB-matching) resolves the PoV asymmetry by incrementing or decrementing pixels with equal probability, increasing the embedding rate past α = 0.15 introduces high-frequency residual noise that is exposed by second-order Markov transition matrices (SPAM-686) and deep learning steganalysts."
    )
    
    add_h2(doc, "2.4 The Network Imperfection Gap: Unreliable Transport & Packet Erasures")
    add_p(doc, 
        "An overwhelming deficiency across the academic steganography literature is the implicit assumption of an ideal, error-free communication channel. Researchers routinely embed data into a local image array and immediately pass the unmodified stego array into a receiver function. In reality, covert communication must traverse real packet-switched networks (such as the public Internet or restricted tactical mesh networks) governed by IP, UDP, and TCP protocols."
    )
    add_p(doc, 
        "Transmitting whole image files (such as lossless PNGs) over standard TCP connections introduces severe operational vulnerabilities. TCP requires bidirectional three-way handshakes, exposes identifiable window-scaling dynamics, and maintains persistent state that can be easily fingerprinted, blocked, or intercepted by state firewalls. Conversely, transmitting raw image files over standard UDP subjects the transmission to unavoidable network impairments: i.i.d. packet loss, bursty drops from congested router queues, packet reordering, network jitter, and occasional bit corruptions. If a single UDP datagram containing compressed PNG header bytes or DEFLATE stream blocks is dropped, the entire decompression pipeline fails catastrophically, rendering the entire covert payload permanently unrecoverable."
    )
    
    add_h2(doc, "2.5 The Circle Riddle Paradigm: Decoy Attractors vs Orthogonal Sign Channels")
    add_p(doc, 
        "TESSERA v3 resolves these intertwined challenges by introducing the 'Mirage Circle Riddle' paradigm. Consider the geometric problem: 'What is the maximum distance between two points on the perimeter of a unit circle?' The conventional, immediate crowd answer is the diameter (distance = 2.0). However, if one measures along the perimeter, the answer is the semi-circumference (distance = π ≈ 3.14159). The same physical points yield two completely different measurements depending on whether one observes the chord or the arc."
    )
    add_p(doc, 
        "Mapping this paradigm to steganography: When an adversarial forensic tool (Eve) examines an intercepted stego image, its natural, foundational question is: 'Which pixels have been modified relative to natural image statistics, and what message do they carry?' TESSERA v3 provides Eve with a complete, mathematically coherent, and crackable answer: the Decoy Layer. The Decoy Layer explains all observable pixel modifications and decrypts under a weak passphrase to reveal an authentic, plausible message. However, while Eve fixates on which pixels changed (the chord/diameter answer), the true secret payload rides on an orthogonal dimension: which direction each change took (+1 vs −1, the arc answer). Because LSB-matching must choose a sign direction anyway, directing this choice carries the true secret with provable zero additional modified pixels (Δ_diff = 0), defeating forensic suspicion."
    )
