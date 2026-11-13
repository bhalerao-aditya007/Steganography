"""RFC 6298 Retransmission Timer (RTO) estimation."""

class RTOEstimator:
    """Computes dynamic Retransmission Timeout (RTO) per RFC 6298."""
    def __init__(self, rto_initial: float = 1.0, rto_min: float = 0.2, rto_max: float = 60.0, clock_granularity: float = 0.05):
        self.rto_initial = rto_initial
        self.rto_min = rto_min
        self.rto_max = rto_max
        self.g = clock_granularity
        
        self.srtt: float | None = None
        self.rttvar: float | None = None
        self.rto: float = rto_initial

    def update_rtt(self, r_sample: float) -> float:
        """Update RTO with a new RTT sample (Karn's rule: only from un-retransmitted packets)."""
        alpha = 1.0 / 8.0  # 0.125
        beta = 1.0 / 4.0   # 0.250
        
        if self.srtt is None:
            # First RTT measurement
            self.srtt = r_sample
            self.rttvar = r_sample / 2.0
        else:
            self.rttvar = (1.0 - beta) * self.rttvar + beta * abs(self.srtt - r_sample)
            self.srtt = (1.0 - alpha) * self.srtt + alpha * r_sample
            
        self.rto = self.srtt + max(self.g, 4.0 * self.rttvar)
        self.rto = max(self.rto_min, min(self.rto_max, self.rto))
        return self.rto

    def backoff_on_timeout(self) -> float:
        """Exponential backoff when a retransmission timer expires."""
        self.rto = min(self.rto_max, self.rto * 2.0)
        return self.rto
