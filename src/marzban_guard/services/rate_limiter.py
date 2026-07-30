"""
Per-user connection-rate tracking, backed by Redis. This is the hot path —
one call per ingested connection event — so everything here is O(1) Redis
ops (pipelined where more than one call is needed), no sorted sets storing
a growing history of timestamps, and every key carries a TTL so Redis
memory is self-bounding even under sustained abuse.

Two building blocks:
  - SlidingWindowCounter — rate over a rolling window (new connections/min,
    /hour, and the short-window "concurrent" proxy), using the standard
    two-fixed-bucket weighted-average approximation.
  - DestinationFanoutTracker — distinct destination IPs/ports contacted in
    a tumbling window, capped so one user can't grow a Redis set without
    bound (see ScanDetectionConfig.max_tracked_destinations). Also reused
    for distinct CLIENT IPs (device-limit enforcement, see
    DeviceLimitConfig) — same mechanism, different key/window.

See docs/DATA_SOURCES.md for why "concurrent connections", "session
duration", and "distinct devices" are all estimates rather than exact
counts — Xray's access log has no connection-close event to correlate
against, and no real device fingerprint exists to count against either.

Note on the tumbling window: DestinationFanoutTracker resets completely
at each window boundary rather than sliding continuously. For scan
detection that's fine (scans are short bursts well inside one window).
For device-limit tracking it means a device that happens not to open any
new connection in the first moments of a fresh window is briefly absent
from the count until its next connection — in practice a non-issue, since
normal VPN traffic opens new connections continuously, but worth knowing
if you see a device limit not fire exactly the instant a window rolls over.

A third piece, unrelated to rate tracking: get/set_device_limit_override()
store a persistent (no TTL — it's a standing policy, not a rate metric)
per-user device-count override in Redis, settable via
PUT /api/v1/admin/users/{username}/device-limit. This is how an external
shop can push "this customer's plan allows N devices" without
marzban-guard needing to know anything about plans — see
docs/ARCHITECTURE.md#shop-integration-keeping-the-storefront-in-sync.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from redis.asyncio import Redis

from marzban_guard.config import SecurityConfig
from marzban_guard.schemas.events import ConnectionEvent, Outcome

_KEY_PREFIX = "mg"


@dataclass(frozen=True)
class ConnectionStats:
    username: str
    new_connections_last_minute: float
    new_connections_last_hour: float
    concurrent_estimate: float
    rejected_last_minute: float
    distinct_destination_ips: int
    distinct_destination_ports: int
    destination_ip_cap_hit: bool
    destination_port_cap_hit: bool
    distinct_smtp_destination_ips: int
    distinct_client_devices: int
    # None = no override for this user, fall back to the global default /
    # YAML per_user_overrides (see config.SecurityConfig.limits_for). Set
    # via set_device_limit_override() — e.g. by the shop site pushing a
    # plan's device allowance whenever it provisions an order (PUT
    # /api/v1/admin/users/{username}/device-limit).
    device_limit_override: int | None


_DEVICE_LIMIT_OVERRIDE_KEY = f"{_KEY_PREFIX}:devlimit_override"


async def get_device_limit_override(redis: Redis, username: str) -> int | None:
    raw = await redis.get(f"{_DEVICE_LIMIT_OVERRIDE_KEY}:{username}")
    return int(raw) if raw is not None else None


async def set_device_limit_override(redis: Redis, username: str, max_devices: int | None) -> None:
    """None clears the override, reverting that user to the global
    default / YAML per_user_overrides."""
    key = f"{_DEVICE_LIMIT_OVERRIDE_KEY}:{username}"
    if max_devices is None:
        await redis.delete(key)
    else:
        await redis.set(key, max_devices)


class SlidingWindowCounter:
    """O(1)-per-op sliding window rate counter backed by two fixed buckets
    (current + previous):

        estimate = previous_bucket * (1 - elapsed_fraction) + current_bucket

    This trades a little accuracy right at bucket boundaries for O(1)
    Redis ops per connection — no per-event keys, no unbounded sorted set.
    """

    def __init__(self, redis: Redis, key: str, window_seconds: int):
        self._redis = redis
        self._key = key
        self._window = window_seconds

    def _bucket_index(self, now: float) -> int:
        return int(now // self._window)

    def _bucket_key(self, index: int) -> str:
        return f"{self._key}:{index}"

    async def increment(self, now: float, amount: int = 1) -> None:
        index = self._bucket_index(now)
        key = self._bucket_key(index)
        pipe = self._redis.pipeline(transaction=False)
        pipe.incrby(key, amount)
        # 2x window so the previous bucket is still readable from anywhere
        # inside the current one.
        pipe.expire(key, self._window * 2)
        await pipe.execute()

    async def estimate(self, now: float) -> float:
        index = self._bucket_index(now)
        elapsed_fraction = (now % self._window) / self._window
        pipe = self._redis.pipeline(transaction=False)
        pipe.get(self._bucket_key(index))
        pipe.get(self._bucket_key(index - 1))
        current_raw, previous_raw = await pipe.execute()
        current = int(current_raw or 0)
        previous = int(previous_raw or 0)
        return previous * (1 - elapsed_fraction) + current


class DestinationFanoutTracker:
    """Tracks distinct destination IPs/ports a user has hit within a
    tumbling window, hard-capped so a single abusive user can't grow the
    backing Redis set without bound. Hitting the cap is itself a strong
    abuse signal (see detectors/destination_fanout.py), so the returned
    count saturates at the cap rather than the tracker silently going
    inert once full.
    """

    def __init__(self, redis: Redis, key: str, window_seconds: int, max_members: int):
        self._redis = redis
        self._key = key
        self._window = window_seconds
        self._max_members = max_members

    def _window_key(self, now: float) -> str:
        bucket = int(now // self._window)
        return f"{self._key}:{bucket}"

    async def add_and_count(self, value: str, now: float) -> tuple[int, bool]:
        key = self._window_key(now)
        current_size = await self._redis.scard(key)
        cap_hit = current_size >= self._max_members
        if not cap_hit:
            pipe = self._redis.pipeline(transaction=False)
            pipe.sadd(key, value)
            pipe.expire(key, self._window * 2)
            await pipe.execute()
            current_size = await self._redis.scard(key)
        return current_size, cap_hit

    async def count(self, now: float) -> int:
        """Read-only peek — no SADD, no TTL refresh."""
        return await self._redis.scard(self._window_key(now))


class RateLimiter:
    """Facade used by the ingestion worker: one `record_connection()` call
    per event, returning the fresh rolling stats detectors need. Building a
    fresh set of tracker objects per call is intentional — they're stateless
    wrappers around a Redis key, not connections themselves, so there's
    nothing to pool."""

    def __init__(self, redis: Redis, security_cfg: SecurityConfig):
        self._redis = redis
        self._cfg = security_cfg

    async def record_connection(self, event: ConnectionEvent) -> ConnectionStats:
        now = event.occurred_at.timestamp() or time.time()
        user = event.username
        scan_cfg = self._cfg.scan_detection

        minute_counter = SlidingWindowCounter(self._redis, f"{_KEY_PREFIX}:cnt:min:{user}", 60)
        hour_counter = SlidingWindowCounter(self._redis, f"{_KEY_PREFIX}:cnt:hour:{user}", 3600)
        concurrent_counter = SlidingWindowCounter(
            self._redis,
            f"{_KEY_PREFIX}:concurrent:{user}",
            self._cfg.concurrency_estimate.window_seconds,
        )
        rejected_counter = SlidingWindowCounter(self._redis, f"{_KEY_PREFIX}:rejected:min:{user}", 60)
        ip_tracker = DestinationFanoutTracker(
            self._redis, f"{_KEY_PREFIX}:destip:{user}", scan_cfg.window_seconds, scan_cfg.max_tracked_destinations
        )
        port_tracker = DestinationFanoutTracker(
            self._redis, f"{_KEY_PREFIX}:destport:{user}", scan_cfg.window_seconds, scan_cfg.max_tracked_destinations
        )
        smtp_tracker = DestinationFanoutTracker(
            self._redis, f"{_KEY_PREFIX}:smtpdest:{user}", scan_cfg.window_seconds, scan_cfg.max_tracked_destinations
        )
        device_cfg = self._cfg.device_limit
        device_tracker = DestinationFanoutTracker(
            self._redis,
            f"{_KEY_PREFIX}:devices:{user}",
            device_cfg.window_minutes * 60,
            # A device count needs its own cap distinct from destination
            # fanout — reusing max_tracked_destinations here would be
            # needlessly huge for something that should never legitimately
            # exceed a handful.
            max(device_cfg.max_devices * 10, 50),
        )

        if event.outcome == Outcome.rejected:
            await rejected_counter.increment(now)
        else:
            await minute_counter.increment(now)
            await hour_counter.increment(now)
            await concurrent_counter.increment(now)

        ip_count, ip_cap_hit = await ip_tracker.add_and_count(event.destination_ip, now)
        port_count, port_cap_hit = await port_tracker.add_and_count(str(event.destination_port), now)

        device_count = 0
        if device_cfg.enabled:
            device_count, _ = await device_tracker.add_and_count(event.client_ip, now)

        spam_cfg = self._cfg.spam_detection
        if spam_cfg.enabled and event.outcome != Outcome.rejected and event.destination_port in spam_cfg.ports:
            await smtp_tracker.add_and_count(event.destination_ip, now)
        smtp_ip_count = await smtp_tracker.count(now)

        device_limit_override = await get_device_limit_override(self._redis, user)

        return ConnectionStats(
            username=user,
            new_connections_last_minute=await minute_counter.estimate(now),
            new_connections_last_hour=await hour_counter.estimate(now),
            concurrent_estimate=await concurrent_counter.estimate(now),
            rejected_last_minute=await rejected_counter.estimate(now),
            distinct_destination_ips=ip_count,
            distinct_destination_ports=port_count,
            destination_ip_cap_hit=ip_cap_hit,
            destination_port_cap_hit=port_cap_hit,
            distinct_smtp_destination_ips=smtp_ip_count,
            distinct_client_devices=device_count,
            device_limit_override=device_limit_override,
        )
