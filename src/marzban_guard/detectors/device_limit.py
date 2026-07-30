from __future__ import annotations

from marzban_guard.config import SecurityConfig
from marzban_guard.detectors.base import BaseDetector, DetectorResult
from marzban_guard.schemas.events import ConnectionEvent
from marzban_guard.services.rate_limiter import ConnectionStats


class DeviceLimitDetector(BaseDetector):
    """Flags an account being used from more distinct client IPs than its
    device limit allows (default 2, per-user overridable via
    security.per_user_overrides.<username>.max_devices — e.g. a
    family/business plan).

    "Device" here means "distinct client IP seen recently" — there's no
    real device fingerprint available from Xray's access log or Marzban's
    API, so this under-counts several real devices sharing one IP (NAT)
    and can over-count one device whose IP rotates mid-session. See
    docs/DATA_SOURCES.md and DeviceLimitConfig's docstring before treating
    this as an exact device count.

    Weighted at scoring.weights.device_limit_exceeded, which defaults to
    exactly thresholds.level_3 — one trigger alone is enough to
    temporarily suspend the account (forcing a cool-down) without waiting
    on other signals, since "too many devices" is a clear-cut policy
    violation rather than a fuzzy abuse heuristic."""

    name = "device_limit"

    def evaluate(self, event: ConnectionEvent, stats: ConnectionStats, cfg: SecurityConfig) -> DetectorResult:
        device_cfg = cfg.device_limit
        if not device_cfg.enabled:
            return DetectorResult.clean(self.name)

        limit = cfg.limits_for(event.username).max_devices
        if stats.distinct_client_devices <= limit:
            return DetectorResult.clean(self.name)

        return DetectorResult(
            detector=self.name,
            triggered=True,
            score=cfg.scoring.weights.device_limit_exceeded,
            reason=(
                f"{stats.distinct_client_devices} distinct client IPs in the last "
                f"{device_cfg.window_minutes} min (limit {limit})"
            ),
            details={
                "distinct_client_devices": stats.distinct_client_devices,
                "max_devices": limit,
                "window_minutes": device_cfg.window_minutes,
            },
        )
