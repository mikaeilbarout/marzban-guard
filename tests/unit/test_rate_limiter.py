from __future__ import annotations

import pytest

from marzban_guard.services.rate_limiter import (
    DestinationFanoutTracker,
    LiveSetTracker,
    RateLimiter,
    SlidingWindowCounter,
    get_device_limit_override,
    set_device_limit_override,
)
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


async def test_device_limit_override_defaults_to_none(redis):
    assert await get_device_limit_override(redis, "nobody-set-this") is None


async def test_device_limit_override_set_and_get(redis):
    await set_device_limit_override(redis, "planholder", 5)
    assert await get_device_limit_override(redis, "planholder") == 5


async def test_device_limit_override_clear_with_none(redis):
    await set_device_limit_override(redis, "planholder", 5)
    await set_device_limit_override(redis, "planholder", None)
    assert await get_device_limit_override(redis, "planholder") is None


async def test_rate_limiter_surfaces_device_limit_override_in_stats(redis, security_config):
    await set_device_limit_override(redis, "premium", 7)
    limiter = RateLimiter(redis, security_config)
    stats = await limiter.record_connection(make_event(username="premium"))
    assert stats.device_limit_override == 7


async def test_rate_limiter_counts_distinct_client_devices(redis, security_config):
    limiter = RateLimiter(redis, security_config)
    for client_ip in ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3"]:
        stats = await limiter.record_connection(make_event(username="dana", client_ip=client_ip))
    assert stats.distinct_client_devices == 3


async def test_live_set_tracker_counts_distinct_values(redis):
    tracker = LiveSetTracker(redis, "test:live", window_seconds=300, max_members=100)
    now = 1_700_000_000.0
    for ip in ["1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3"]:
        count, cap_hit = await tracker.add_and_count(ip, now)
    assert count == 3
    assert cap_hit is False


async def test_live_set_tracker_saturates_at_cap(redis):
    tracker = LiveSetTracker(redis, "test:live-cap", window_seconds=300, max_members=3)
    now = 1_700_000_000.0
    results = []
    for i in range(10):
        results.append(await tracker.add_and_count(f"10.0.0.{i}", now))
    assert all(count <= 3 for count, _ in results)
    assert results[-1] == (3, True)


async def test_live_set_tracker_prunes_members_older_than_window(redis):
    """The behavior this tracker exists for: a member seen once, then
    nothing further from it, drops out of the count once the window has
    elapsed — continuously, not just at a fixed bucket boundary the way
    DestinationFanoutTracker works. This is what makes a short
    window_minutes actually mean "currently active" for device-limit
    tracking instead of "was active sometime in this bucket"."""
    tracker = LiveSetTracker(redis, "test:live-prune", window_seconds=300, max_members=100)
    t0 = 1_700_000_000.0

    count, _ = await tracker.add_and_count("1.1.1.1", t0)
    assert count == 1

    # A second device shows up 250s later — both still within 300s of now.
    count, _ = await tracker.add_and_count("2.2.2.2", t0 + 250)
    assert count == 2

    # 400s after t0: 1.1.1.1's last (and only) activity is now 400s old —
    # past the 300s window, so it must have aged out. 2.2.2.2's last
    # activity is only 150s old — still well within its own window.
    count, _ = await tracker.add_and_count("3.3.3.3", t0 + 400)
    assert count == 2  # 2.2.2.2 (still active) + 3.3.3.3 (just added)


async def test_live_set_tracker_reconnect_refreshes_instead_of_double_counting(redis):
    """A device that keeps reconnecting stays counted once, and each
    reconnect pushes its expiry further out — it never ages out as long
    as it keeps being seen."""
    tracker = LiveSetTracker(redis, "test:live-refresh", window_seconds=300, max_members=100)
    t0 = 1_700_000_000.0

    await tracker.add_and_count("1.1.1.1", t0)
    # Reconnects just inside the window, repeatedly — should refresh, not
    # add a second member.
    count, _ = await tracker.add_and_count("1.1.1.1", t0 + 200)
    assert count == 1
    count, _ = await tracker.add_and_count("1.1.1.1", t0 + 400)
    assert count == 1

    # Confirmed still alive well past the *original* window from t0,
    # because its most recent activity (t0 + 400) refreshed it.
    assert await tracker.count(t0 + 650) == 1
