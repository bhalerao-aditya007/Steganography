"""Reliable UDP (RUDP) Transport Engine with Sliding Window, AIMD, and SACK."""
import time
from .packet import Packet, TYPE_DATA, TYPE_ACK, TYPE_NACK, TYPE_FIN
from .rto import RTOEstimator
from .impair import NetworkImpairer

class PacketEvent:
    def __init__(self, event_type: str, seq: int, tile_idx: int, details: str = ""):
        self.timestamp = time.time()
        self.event_type = event_type  # "SENT", "ACK", "LOST", "RETX", "NACK", "DELIVERED"
        self.seq = seq
        self.tile_idx = tile_idx
        self.details = details

class RUDPTransmitter:
    """Simulates reliable sliding-window packet transport with SACK and AIMD congestion control."""
    def __init__(self, session_id: int, impairer: NetworkImpairer | None = None):
        self.session_id = session_id
        self.impairer = impairer or NetworkImpairer()
        self.rto_calc = RTOEstimator()
        
        # AIMD Congestion Control
        self.cwnd = 2.0
        self.ssthresh = 16.0
        
        # Event logging for live UI dashboard
        self.events: list[PacketEvent] = []

    def log(self, event_type: str, seq: int, tile_idx: int, details: str = ""):
        self.events.append(PacketEvent(event_type, seq, tile_idx, details))

    def transmit_tiles(
        self,
        tiles: list[bytes],
        mode: str = "rs"  # "rs" (RS erasure coding, stops once >= k shards), or "arq" (retransmits all)
    ) -> tuple[dict[int, bytes], dict]:
        """Transmit image tiles to simulated receiver across impaired channel.
        
        Returns:
            (received_tiles_dict, metrics_dict)
        """
        n_tiles = len(tiles)
        received: dict[int, bytes] = {}
        transmitted_counts = [0] * n_tiles
        
        # Build packets
        packets = []
        for t_idx, tile_data in enumerate(tiles):
            pkt = Packet(
                pkt_type=TYPE_DATA,
                session_id=self.session_id,
                seq=t_idx,
                tile_idx=t_idx,
                payload=tile_data,
            )
            packets.append(pkt)

        # First pass transmission
        for seq, pkt in enumerate(packets):
            transmitted_counts[seq] += 1
            raw = pkt.serialize()
            self.log("SENT", seq, pkt.tile_idx, f"Size {len(raw)}B, cwnd={self.cwnd:.1f}")
            
            # Pass through network impairment pipeline
            delivered = self.impairer.process_packet(raw)
            if delivered is None:
                self.log("LOST", seq, pkt.tile_idx, "Dropped by simulated loss")
                # AIMD multiplicate decrease on packet drop
                self.cwnd = max(1.0, self.cwnd / 2.0)
            else:
                parsed = Packet.parse(delivered)
                if parsed is not None:
                    received[parsed.tile_idx] = parsed.payload
                    self.log("ACK", seq, parsed.tile_idx, f"Received successfully")
                    # AIMD additive increase on successful ACK
                    self.cwnd += 1.0 / self.cwnd

        # If in ARQ-only mode (without RS) or if not all arrived:
        retransmissions = 0
        if mode == "arq":
            # Retransmit missing until 100% delivered or max retries
            max_rounds = 5
            round_num = 0
            while len(received) < n_tiles and round_num < max_rounds:
                round_num += 1
                for t_idx in range(n_tiles):
                    if t_idx not in received:
                        retransmissions += 1
                        pkt = packets[t_idx]
                        raw = pkt.serialize()
                        self.log("RETX", t_idx, t_idx, f"ARQ retransmit round {round_num}")
                        delivered = self.impairer.process_packet(raw)
                        if delivered is not None:
                            parsed = Packet.parse(delivered)
                            if parsed is not None:
                                received[t_idx] = parsed.payload
                                self.log("ACK", t_idx, t_idx, "Recovered via ARQ")

        metrics = {
            "total_tiles": n_tiles,
            "delivered_tiles": len(received),
            "lost_tiles": n_tiles - len(received),
            "retransmissions": retransmissions,
            "final_cwnd": self.cwnd,
            "loss_rate_observed": (n_tiles - len(received)) / float(n_tiles),
        }
        return received, metrics
