from __future__ import annotations

import pytest

from marzban_guard.services.rate_limiter import DestinationFanoutTracker, RateLimiter, SlidingWindowCounter
from tests.conftest import make_event

pytestmark = pytest.mark.asyncio


async def test_sliding_window_counter_counts_within_bucket(redis):
    counter = SlidingWindowCounter(redis, "test:sw", window_seconds=60)
    now = 1_700_000_000.0  # aligned to a bucket start-ish
    await counter.increment(now)
    await counter.increment(now + 1)
    await counter.increment(now + 2)
    estimate = await counter.estimate(now + 3)
    assert estimate == pytest.approx(3, abs=0.01)


async def test_sliding_window_counter_decays_into_next_bucket(redis):
    counter = SlidingWindowCounter(redis, "test:sw2", window_seconds=60)
    bucket_start = 1_700_000_000.0 - (1_700_000_000.0 % 60)
    await counter.increment(bucket_start + 1, amount=60)
    # Halfway into the NEXT bucket: previous bucket contributes ~50%.
    halfway_next = bucket_start + 60 + 30
    estimate = await counter.estimate(halfway_next)
    assert 25 <= estimate <= 35


async def test_destination_fanout_tracker_counts_distinct_values(redis):
    tracker = DestinationFanoutTracker(redis, "test:fanout", window_seconds=60, max_members=100)
    now = 1_700_000_000.0
    for ip in ["1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3"]:
        count, cap_hit = await tracker.add_and_count(ip, now)
    assert count == 3
    assert cap_hit is False


async def test_destination_fanout_tracker_saturates_at_cap(redis):
    tracker = DestinationFanoutTracker(redis, "test:fanout-cap", window_seconds=60, max_members=3)
    now = 1_700_000_000.0
    results = []
    for i in range(10):
        results.append(await tracker.add_and_count(f"10.0.0.{i}", now))
    # Cap hit means the set never grows past max_members, and the tracker
    # tells the caller it hit the cap instead of silently under-reporting.
    assert all(count <= 3 for count, _ in results)
    assert results[-1] == (3, True)


async def test_rate_limiter_record_connection_returns_fresh_stats(redis, security_config):
    limiter = RateLimiter(redis, security_config)
    event = make_event(username="bob")
    stats = await limiter.record_connection(event)
    assert stats.username == "bob"
    assert stats.new_connections_last_minute >= 1
    assert stats.distinct_destination_ips == 1
    assert stats.distinct_destination_ports == 1


async def test_rate_limiter_tracks_rejected_separately_from_accepted(redis, security_config):
    limiter = RateLimiter(redis, security_config)
    await limiter.record_connection(make_event(username="carol", outcome="rejected"))
    stats = await limiter.record_connection(make_event(username="carol", outcome="rejected"))
    assert stats.rejected_last_minute >= 2
    assert stats.new_connections_last_minute == 0
