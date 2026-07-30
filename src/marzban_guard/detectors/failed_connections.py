from __future__ import annotations

from marzban_guard.config import SecurityConfig
from marzban_guard.detectors.base import BaseDetector, DetectorResult
from marzban_guard.schemas.events import ConnectionEvent
from marzban_guard.services.rate_limiter import ConnectionStats


class FailedConnectionDetector(BaseDetector):
    """Flags a burst of rejected/failed connection attempts — automated
    probing, credential stuffing against upstream services, or a broken
    client hammering a dead target. Only produces signal if the node's
    Xray log level is turned up enough to emit "rejected" lines (plain
    "info" level only logs successes) — see docs/DATA_SOURCES.md."""

    name = "failed_connections"

    def evaluate(self, event: ConnectionEvent, stats: ConnectionStats, cfg: SecurityConfig) -> DetectorResult:
        threshold = cfg.failed_connection_threshold_per_minute
        if stats.rejected_last_minute < threshold:
            return DetectorResult.clean(self.name)

        return DetectorResult(
            detector=self.name,
            triggered=True,
            score=cfg.scoring.weights.failed_connection_burst,
            reason=f"{stats.rejected_last_minute:.0f} rejected connections in the last minute (> {threshold})",
            details={"rejected_last_minute": stats.rejected_last_minute, "threshold": threshold},
        )
