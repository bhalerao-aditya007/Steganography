"""Section 4: Chapter 6 (System Architecture & Operational Network Workflow).
"""
import os
import docx
from docx.shared import Pt
from report_builder.styles import (
    COLOR_PRIMARY, COLOR_SECONDARY, COLOR_MUTED, COLOR_BLACK,
    add_p, add_bullet, add_h1, add_h2, add_h3, add_callout,
    add_equation_box, add_figure, create_styled_table
)

def build_chapter_6(doc):
    add_h1(doc, "6. System Architecture & Operational Network Workflow")
    
    add_h2(doc, "6.1 Three-Process Networked System Architecture")
    add_p(doc, 
        "TESSERA v3 transitions the steganographic communication problem from an isolated academic algorithm into an authentic distributed computer networks system. The operational runtime is engineered as three distinct, concurrent operating system processes executing in user space and communicating over real BSD/POSIX UDP network sockets:"
    )
    
    add_bullet(doc, 
        "Executes cli/alice_sender.py. Responsible for ingesting the raw cover image, executing the pre-embedding cover gate suitability checks, computing the DTE honey decoy payload, executing the Mirage sign-channel embedding, generating RS(32,24) shards, framing tiles into Wire Protocol v2 datagrams, and transmitting datagrams with precise inter-packet pacing to local UDP port 9998.",
        bold_prefix="1. Alice (Authenticated Sender Process): "
    )
    add_bullet(doc, 
        "Executes tools/router_impair.py. Functions as an in-line network proxy listening on UDP port 9998 and forwarding to UDP port 9999. Ingests command-line impairment flags to inject stochastic Bernoulli packet loss, Gilbert-Elliott Markov burst drops, heap-scheduled delay, jitter, packet duplication, single-bit payload corruption, and tail-drop bandwidth throttling, while exporting ground-truth CSV logs (router_log.csv) and raw PCAP captures (capture.pcap).",
        bold_prefix="2. Impairment Router (Adversarial Channel Emulator): "
    )
    add_bullet(doc, 
        "Executes cli/bob_receiver.py. Listens on UDP port 9999 with an expanded 4 MB OS receive buffer. Demultiplexes Wire Protocol v2 headers, verifies BLAKE2s-32 authentication tags, checks CRC32 checksums, aggregates delivered tiles into an in-memory assembly matrix, executes the Reed-Solomon RS(32,24) erasure decoder, issues selective NACK bitmaps during closed-loop Hybrid ARQ rounds, and decrypts the authenticated secret payload via ChaCha20-Poly1305.",
        bold_prefix="3. Bob (Authenticated Receiver Process): "
    )
    
    add_p(doc, 
        "Figure 6.1 illustrates the architectural data flow and bidirectional network paths interconnecting Alice, the Impairment Router, and Bob:"
    )
    
    # ASCII Architecture diagram in a callout / code block
    arch_ascii = (
        "+----------------------+         UDP :9998        +----------------------+         UDP :9999        +----------------------+\n"
        "|    Alice (Sender)    | -----------------------> |  Impairment Router   | -----------------------> |    Bob (Receiver)    |\n"
        "|  [cli/alice_sender]  |                          | [tools/router_impair]|                          |  [cli/bob_receiver]  |\n"
        "|  - Cover Image Gate  |                          |  - Bernoulli Loss    |                          |  - 4 MB Socket Buffer|\n"
        "|  - Mirage Stego Core |                          |  - Gilbert-Elliott   |                          |  - CRC32 & BLAKE2s   |\n"
        "|  - RS(32,24) Sharding|                          |  - Delay & Jitter    |                          |  - RS(32,24) Decoder |\n"
        "|  - Wire Framing v2   |                          |  - Bit Corruption    |                          |  - ChaCha20-Poly1305 |\n"
        "|  - Socket Pacer      | <----------------------- |  - CSV / PCAP Logger | <----------------------- |  - NACK Generator    |\n"
        "+----------------------+        NACK / ACK        +----------------------+        NACK / ACK        +----------------------+"
    )
    add_equation_box(doc, arch_ascii, "Fig. 6.1: Three-Process Networked System Architecture")
    
    add_h2(doc, "6.2 Wire Protocol v2 Binary Framing & Datagram Specification")
    add_p(doc, 
        "To ensure robust parsing, low protocol overhead, and cryptographic resistance against packet injection attacks, TESSERA v3 introduces Wire Protocol v2. Every network datagram begins with a compact, 20-byte binary header followed by the variable payload. Table 6.1 specifies the exact binary memory layout of the Wire Protocol v2 header."
    )
    
    # Table 6.1
    headers = ["Byte Offset", "Field Identifier", "Data Type & Width", "Functional & Cryptographic Role"]
    data = [
        ["0 – 1 (2B)", "magic", "uint16_t (2 Bytes)", "Protocol identifier: 0x53 0x54 (ASCII 'ST' for Stego Transport)"],
        ["2 (1B)", "version", "uint8_t (1 Byte)", "Protocol version: 0x02 for Wire Protocol v2"],
        ["3 (1B)", "msg_type", "uint8_t (1 Byte)", "Datagram type: 1=SYN, 2=DATA, 3=NACK, 4=FIN, 5=ACK"],
        ["4 (1B)", "flags", "uint8_t (1 Byte)", "Control flags: Bit 0=LAST_TILE, Bit 1=KEYED_TAG, Bit 2=RETRANS"],
        ["5 (1B)", "reserved", "uint8_t (1 Byte)", "Reserved for future protocol extensions (Zero-padded)"],
        ["6 – 7 (2B)", "session_id", "uint16_t (2 Bytes)", "Ephemeral session identifier generated during Alice-Bob handshake"],
        ["8 – 9 (2B)", "seq_num", "uint16_t (2 Bytes)", "Monotonically increasing sequence number for reordering and audit"],
        ["10 – 11 (2B)", "tile_idx", "uint16_t (2 Bytes)", "Spatial tile and RS shard index (0 to 31)"],
        ["12 – 13 (2B)", "payload_len", "uint16_t (2 Bytes)", "Payload byte length: 8,192 bytes for full tile; 4B for NACK bitmap"],
        ["14 – 17 (4B)", "auth_tag", "uint32_t (4 Bytes)", "Keyed BLAKE2s-32 truncated authentication tag computed with k_wire"],
        ["18 – 19 (2B)", "checksum", "uint16_t (2 Bytes)", "CRC16/CRC32 integrity checksum over header and payload fields"]
    ]
    create_styled_table(doc, [1.0, 1.3, 1.4, 2.57], headers, data, col_alignments=['C', 'L', 'L', 'L'])
    add_p(doc, "Table 6.1: Binary specification and field definitions for the TESSERA Wire Protocol v2 20-byte transport header.", italic=True, space_after=10.0)
    
    add_p(doc, 
        "Total Datagram Geometry: For a full image tile payload of 8,192 bytes (64x128 pixels at 1 byte/pixel), the total UDP payload size is exactly 20 + 8,192 = 8,212 bytes. Transmitted over loopback (MTU = 65,535 bytes) or reassembled via IP fragmentation, the datagram length is held completely constant across all tiles, ensuring that payload length reveals zero information to a passive network observer."
    )
    
    add_h2(doc, "6.3 Dual Transport Engines: Open-Loop FEC vs Closed-Loop Hybrid ARQ")
    add_p(doc, 
        "TESSERA v3 provides two distinct, configurable transport engines tailored to different operational and threat environments:"
    )
    
    add_h3(doc, "Mode 1: Open-Loop FEC Mode (Strict Radio-Silence Transport)")
    add_p(doc, 
        "In tactical or high-threat surveillance environments, any reverse transmission from Bob to Alice (such as TCP ACKs or retransmission requests) can be intercepted by direction-finding equipment or state firewalls, exposing Bob's physical location. Under Open-Loop FEC mode, Alice transmits exactly 32 tile datagrams (24 data tiles + 8 parity tiles) with zero reverse feedback. Bob operates in listen-only mode. If Bob receives >= 24 tiles (loss <= 25%), the Reed-Solomon decoder reconstructs the secret payload bit-exactly with zero round-trip overhead. If Bob receives < 24 tiles, Bob deterministically fails closed with exit code 2, purging all partial shards from memory and emitting zero plaintext."
    )
    
    add_h3(doc, "Mode 2: Closed-Loop Hybrid ARQ Mode (Adaptive Loss Recovery)")
    add_p(doc, 
        "In standard lossy networks where reverse transmission is permitted, TESSERA v3 executes an adaptive Hybrid ARQ state machine. The transaction initiates with a two-way handshake (SYN from Alice, SYN-ACK from Bob) to synchronize session keys and negotiate MTU. Alice transmits the 32 tiles using paced socket flight. Upon completing flight transmission, Bob inspects the tile arrival bitmap. If any shards are missing, Bob transmits a NACK datagram containing a 32-bit bitmask indicating missing shard indices. Alice retransmits only the missing shards. Retransmission timeouts are dynamically calculated based on RFC 6298:"
    )
    add_equation_box(doc, "RTO = SRTT + 4 \\times RTTVAR,        \\text{with exponential backoff } RTO \\leftarrow 2 \\times RTO", "Eq. 6.1")
    add_p(doc, 
        "Hybrid ARQ guarantees 100% secret recovery even under extreme network distress (e.g., 30% forward loss, 20% reverse loss, and multi-packet Gilbert-Elliott burst drops) while maintaining minimal transmission overhead."
    )
    
    add_h2(doc, "6.4 Socket-Level Pacing, Hybrid Spin-Wait & Windows Socket Buffers")
    add_p(doc, 
        "Deploying high-speed UDP transport across modern operating systems introduces severe timing and socket buffer constraints that can cause artificial packet drops unrelated to network congestion:"
    )
    add_bullet(doc, 
        "On standard Windows OS platforms, the default system timer resolution is 15.625 ms (64 Hz). Calling standard time.sleep(0.001) routinely causes the thread to sleep for 15 ms, destroying transport throughput. To achieve sub-millisecond inter-packet spacing (e.g., 1.0 ms pacing between 8,212-byte datagrams), TESSERA v3 implements a precise_sleep() hybrid sleep/spin algorithm. The algorithm sleeps via OS primitives for the coarse duration (up to target - 1.5 ms) and actively spins on time.perf_counter() for the final microsecond interval, achieving sub-50 microsecond pacing jitter.",
        bold_prefix="1. High-Resolution Socket Pacing (precise_sleep): "
    )
    add_bullet(doc, 
        "Default OS UDP receive buffers are typically 64 KB. When Alice transmits a burst of thirty-two 8,212-byte datagrams (total flight = 262 KB), the OS network kernel buffer overflows instantly, dropping packets before the Python application can read them. Bob explicitly expands the socket receive buffer using SO_RCVBUF to 4,194,304 bytes (4 MB), completely eliminating kernel-level packet drops.",
        bold_prefix="2. 4 MB OS Socket Receive Buffers (SO_RCVBUF): "
    )
    add_bullet(doc, 
        "On Windows platforms, receiving an ICMP 'Port Unreachable' message from a previous closed connection raises an unhandled WSAECONNRESET (Windows error 10054) on subsequent UDP socket operations. TESSERA v3 explicitly handles and suppresses WSAECONNRESET using SIO_UDP_CONNRESET ioctl configuration, ensuring continuous socket availability during live viva demonstrations.",
        bold_prefix="3. Windows ICMP Reset Resilience (WSAECONNRESET): "
    )
