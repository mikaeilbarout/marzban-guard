from __future__ import annotations

from marzban_guard.config import SecurityConfig
from marzban_guard.detectors.base import BaseDetector, DetectorResult
from marzban_guard.schemas.events import ConnectionEvent
from marzban_guard.services.rate_limiter import ConnectionStats


class ConnectionRateDetector(BaseDetector):
    """Flags a user exceeding their configured new-connection-rate or
    concurrency ceiling — the baseline "automated bot / bulk scraping"
    signal. Limits are per-user (security.per_user_overrides), so a
    legitimate power user can be given more headroom without loosening the
    limit for everyone."""

    name = "connection_rate"

    def evaluate(self, event: ConnectionEvent, stats: ConnectionStats, cfg: SecurityConfig) -> DetectorResult:
        limits = cfg.limits_for(event.username)
        weight = cfg.scoring.weights.high_connection_rate

        over_minute = stats.new_connections_last_minute > limits.connection_limit_per_minute
        over_hour = stats.new_connections_last_hour > limits.connection_limit_per_hour
        over_concurrent = stats.concurrent_estimate > limits.concurrent_limit

        if not (over_minute or over_hour or over_concurrent):
            return DetectorResult.clean(self.name)

        reasons = []
        if over_minute:
            reasons.append(f"{stats.new_connections_last_minute:.0f}/min > limit {limits.connection_limit_per_minute}")
        if over_hour:
            reasons.append(f"{stats.new_connections_last_hour:.0f}/hr > limit {limits.connection_limit_per_hour}")
        if over_concurrent:
            reasons.append(
                f"~{stats.concurrent_estimate:.0f} concurrent > limit {limits.concurrent_limit}"
            )

        return DetectorResult(
            detector=self.name,
            triggered=True,
            score=weight,
            reason="; ".join(reasons),
            details={
                "new_connections_last_minute": stats.new_connections_last_minute,
                "new_connections_last_hour": stats.new_connections_last_hour,
                "concurrent_estimate": stats.concurrent_estimate,
                "limits": limits.model_dump(),
            },
        )
