from __future__ import annotations

from marzban_guard.config import SecurityConfig
from marzban_guard.detectors.base import BaseDetector, DetectorResult
from marzban_guard.schemas.events import ConnectionEvent
from marzban_guard.services.rate_limiter import ConnectionStats


class PortScanDetector(BaseDetector):
    """Flags concentrated port probing: many distinct destination ports
    reached while touching only a handful of destination IPs. That
    concentration is what separates an actual port scan from, say, a
    torrent client that also touches hundreds of distinct ports but
    spread across hundreds of distinct peer IPs (that pattern is instead
    DestinationDetector's too_many_destination_ips signal)."""

    name = "port_scan"

    def evaluate(self, event: ConnectionEvent, stats: ConnectionStats, cfg: SecurityConfig) -> DetectorResult:
        scan_cfg = cfg.scan_detection
        if not scan_cfg.enabled:
            return DetectorResult.clean(self.name)

        is_scan = (
            stats.distinct_destination_ports >= scan_cfg.port_threshold
            and stats.distinct_destination_ips <= scan_cfg.port_scan_max_distinct_ips
        )
        if not is_scan:
            return DetectorResult.clean(self.name)

        return DetectorResult(
            detector=self.name,
            triggered=True,
            score=cfg.scoring.weights.port_scan,
            reason=(
                f"{stats.distinct_destination_ports} distinct ports on only "
                f"{stats.distinct_destination_ips} host(s) within {scan_cfg.window_seconds}s"
            ),
            details={
                "distinct_destination_ports": stats.distinct_destination_ports,
                "distinct_destination_ips": stats.distinct_destination_ips,
                "window_seconds": scan_cfg.window_seconds,
            },
        )
