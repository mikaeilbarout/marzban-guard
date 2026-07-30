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
    bound (see ScanDetectionConfig.max_tracked_destinations).

See docs/DATA_SOURCES.md for why "concurrent connections" and "session
duration" are estimates rather than exact counts — Xray's access log has
no connection-close event to correlate against.
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

        if event.outcome == Outcome.rejected:
            await rejected_counter.increment(now)
        else:
            await minute_counter.increment(now)
            await hour_counter.increment(now)
            await concurrent_counter.increment(now)

        ip_count, ip_cap_hit = await ip_tracker.add_and_count(event.destination_ip, now)
        port_count, port_cap_hit = await port_tracker.add_and_count(str(event.destination_port), now)

        spam_cfg = self._cfg.spam_detection
        if spam_cfg.enabled and event.outcome != Outcome.rejected and event.destination_port in spam_cfg.ports:
            await smtp_tracker.add_and_count(event.destination_ip, now)
        smtp_ip_count = await smtp_tracker.count(now)

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
        )
