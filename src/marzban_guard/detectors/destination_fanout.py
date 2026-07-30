from __future__ import annotations

from marzban_guard.config import SecurityConfig
from marzban_guard.detectors.base import BaseDetector, DetectorResult
from marzban_guard.schemas.events import ConnectionEvent
from marzban_guard.services.rate_limiter import ConnectionStats


class DestinationFanoutDetector(BaseDetector):
    """Flags a user contacting an unusually large number of distinct
    destination IPs and/or ports in the detection window — the general
    "hitting hundreds of different targets quickly" signal (proxy/relay
    abuse, scraping botnets, credential-stuffing farms). Deliberately
    separate from PortScanDetector, which only fires on the *concentrated*
    variant (few hosts, many ports); this one fires on breadth regardless
    of concentration, and the two commonly co-occur without double-scoring
    the same narrow condition."""

    name = "destination_fanout"

    def evaluate(self, event: ConnectionEvent, stats: ConnectionStats, cfg: SecurityConfig) -> DetectorResult:
        scan_cfg = cfg.scan_detection
        if not scan_cfg.enabled:
            return DetectorResult.clean(self.name)

        too_many_ips = stats.distinct_destination_ips >= scan_cfg.ip_threshold
        too_many_ports = stats.distinct_destination_ports >= scan_cfg.port_threshold

        if not (too_many_ips or too_many_ports):
            return DetectorResult.clean(self.name)

        score = 0.0
        reasons = []
        if too_many_ips:
            score += cfg.scoring.weights.too_many_destination_ips
            reasons.append(f"{stats.distinct_destination_ips} distinct destination IPs")
        if too_many_ports:
            score += cfg.scoring.weights.too_many_destination_ports
            reasons.append(f"{stats.distinct_destination_ports} distinct destination ports")
        if stats.destination_ip_cap_hit or stats.destination_port_cap_hit:
            reasons.append("tracking cap reached — actual fanout may be higher")

        return DetectorResult(
            detector=self.name,
            triggered=True,
            score=score,
            reason="; ".join(reasons),
            details={
                "distinct_destination_ips": stats.distinct_destination_ips,
                "distinct_destination_ports": stats.distinct_destination_ports,
                "destination_ip_cap_hit": stats.destination_ip_cap_hit,
                "destination_port_cap_hit": stats.destination_port_cap_hit,
                "window_seconds": scan_cfg.window_seconds,
            },
        )
