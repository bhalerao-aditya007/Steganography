"""Section 7: Chapter 9 (Real-World Applications & Societal Impact) and Chapter 10 (Limitations & Future Scope).
"""
import docx
from docx.shared import Pt
from report_builder.styles import (
    COLOR_PRIMARY, COLOR_SECONDARY, COLOR_MUTED, COLOR_BLACK,
    add_p, add_bullet, add_h1, add_h2, add_callout, create_styled_table
)

def build_chapter_9(doc):
    add_h1(doc, "9. Real-World Applications, Privacy & Societal Impact")
    
    add_p(doc, 
        "TESSERA v3 addresses real-world, high-stakes human security problems where cryptographic failure or coerced disclosure carries severe physical, legal, or political consequences. The system provides immediate, actionable utility across four primary societal domains:"
    )
    
    add_bullet(doc, 
        "Journalists operating in conflict zones or investigating corporate malfeasance frequently face physical detention at border crossings, where security forces demand device passwords under threat of imprisonment. By employing TESSERA v3, a journalist can surrender the weak decoy passphrase, revealing an innocuous draft article or administrative memo. The forensic investigator verifies the decoy payload, satisfies their investigative mandate, and concludes the examination, while the true investigative leaks and source identities remain securely protected within the Mirage sign channel.",
        bold_prefix="1. Investigative Journalists & Whistleblowers Under Duress: "
    )
    add_bullet(doc, 
        "In authoritarian regimes where privacy technologies and encryption are criminalized, human rights advocates face continuous state interception. Transmitting raw encrypted files over the Internet flags dissidents for immediate arrest. TESSERA v3 enables advocates to transmit sensitive casualty registries, legal documentation, and field reports disguised within routine cultural photographs, news media, or social imagery, providing vital operational security across hostile networks.",
        bold_prefix="2. Human Rights Defenders in Authoritarian States: "
    )
    add_bullet(doc, 
        "Traditional full-disk encryption (such as BitLocker or standard VeraCrypt) provides no protection against judicial search warrants that compel password surrender under penalty of contempt. TESSERA v3 provides the foundational mathematical engine for plausibly deniable image archives: photo libraries where select images carry hidden digital vaults that cannot be proven to exist without the master Argon2id key.",
        bold_prefix="3. Plausibly Deniable Digital Vaults & Secure Archival: "
    )
    add_bullet(doc, 
        "Dissident networks operating in environments with degraded, heavily monitored Internet infrastructure (such as satellite uplinks, ad-hoc radio meshes, or state-throttled broadband) suffer from severe packet drops. TESSERA v3's tile-aligned RS(32,24) erasure coding and Hybrid ARQ ensure that confidential dispatches arrive intact without requiring complete file retransmissions that draw unwanted traffic analysis.",
        bold_prefix="4. Censorship-Resilient Mesh Communication: "
    )

def build_chapter_10(doc):
    add_h1(doc, "10. Limitations & Future Scope")
    
    add_h2(doc, "10.1 The Honest Claims Ledger: What We Claim vs What We Do Not Claim")
    add_p(doc, 
        "In academic engineering, scientific integrity demands establishing exactly what a security system achieves and where its theoretical boundaries lie. Table 10.1 presents the formal TESSERA v3 Claims Ledger."
    )
    
    # Table 10.1
    headers = ["Technical Dimension", "Formal Scientific Claim (What We Claim)", "Boundary & Negative Claim (What We Do NOT Claim)"]
    data = [
        [
            "Network Transport",
            "Genuine UDP packet loss, burst drops, and reordering across real OS sockets; verified by Wireshark captures and CSV ground-truth logs.",
            "We do NOT claim covert network framing; the wire protocol is explicitly identifiable by design ('ST' magic, 8,212B datagrams)."
        ],
        [
            "Erasure Coding",
            "MDS guarantee: Any 24 of 32 tiles reconstruct the hidden secret bit-exactly (P_E = 0), authenticated by ChaCha20-Poly1305.",
            "We do NOT claim recovery if >= 9 tiles are lost in open-loop mode; in that regime, the system safely fails closed with zero plaintext output."
        ],
        [
            "Evidence Conservation",
            "The Mirage layer introduces ZERO additional modified pixels beyond the decoy layer (Delta_diff = 0, identical change sets, 100% in {+/-1}).",
            "We do NOT claim that the decoy layer itself is undetectable; at alpha = 0.20, the decoy is intentionally detectable to act as honeypot."
        ],
        [
            "Steganalysis Security",
            "The Mirage layer introduces no additional statistical detectability beyond honest LSB matching (DeltaAUC = 0.000 vs random signs).",
            "We do NOT claim security if Eve possesses the original uncompressed cover image; steganography assumes the cover is secret."
        ],
        [
            "Channel Survivability",
            "Robust against packet drops, delay, jitter, and bit corruption across packet-switched UDP networks.",
            "We do NOT claim survival against lossy JPEG recompression, image resizing, or geometric spatial transforms."
        ]
    ]
    create_styled_table(doc, [1.4, 2.4, 2.47], headers, data, col_alignments=['L', 'L', 'L'])
    add_p(doc, "Table 10.1: The TESSERA v3 Honest Claims Ledger: Defending scientific integrity through precise operational boundaries.", italic=True, space_after=10.0)
    
    add_h2(doc, "10.2 Current Operational Limitations")
    add_bullet(doc, 
        "TESSERA v3 operates exclusively in the uncompressed spatial pixel domain (PNG, BMP, TIFF). Transmitting the stego image through lossy transformation channels (such as social media JPEG compression or WhatsApp image re-encoding) quantizes DCT coefficients, irreversibly destroying both the LSB parity and the sign channel.",
        bold_prefix="1. Lossy JPEG Recompression Vulnerability: "
    )
    add_bullet(doc, 
        "The tile-aligned transport architecture relies on spatial alignment: tile (r, c) must map to shard index i. Any geometric transformation (such as cropping, rotation, or non-integer scaling) desynchronizes the tile boundaries, preventing packet reconstruction.",
        bold_prefix="2. Geometric Synchronization Sensitivity: "
    )
    add_bullet(doc, 
        "TESSERA v3 derives all keys from a single master passphrase via Argon2id. Consequently, the current protocol does not achieve Forward Secrecy; compromise of the master passphrase exposes all recorded historical sessions.",
        bold_prefix="3. Absence of Forward Secrecy: "
    )
    
    add_h2(doc, "10.3 Future Technical Roadmap")
    add_bullet(doc, 
        "Integrating the Mirage sign-channel principle directly into transform-domain JPEG Discrete Cosine Transform (DCT) coefficients using J-UNIWARD distortion costs, enabling survival across lossy web image proxies.",
        bold_prefix="1. JPEG Transform-Domain Extension (J-UNIWARD): "
    )
    add_bullet(doc, 
        "Extending the wire protocol to incorporate Ephemeral Diffie-Hellman key exchange (X25519) within the SYN/SYN-ACK handshake, establishing session-level forward secrecy.",
        bold_prefix="2. Ephemeral Key Exchange & Forward Secrecy: "
    )
    add_bullet(doc, 
        "Engineering multi-path routing across independent UDP proxy nodes (Tor-style onion routing over UDP) to prevent flow-correlation attacks by global network adversaries.",
        bold_prefix="3. Multi-Path Dispersal & Dynamic Path Hopping: "
    )
