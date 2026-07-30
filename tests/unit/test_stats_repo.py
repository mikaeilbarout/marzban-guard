"""
Regression coverage for stats_repo.py's "latest sample per user" queries.

These went unnoticed for a while: the original implementation used
`select(...).distinct(TrafficSampleRow.username)`, which compiles to
Postgres's `DISTINCT ON` (correct — one row per user) but silently
degrades to a plain, non-deduplicating `SELECT DISTINCT` on any other
dialect, including the SQLite this test suite runs against. That means a
user with multiple samples in the window showed up multiple times instead
of once. See stats_repo.py's docstring for the portable fix.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from marzban_guard.db.models import TrafficSampleRow
from marzban_guard.repositories import stats_repo

pytestmark = pytest.mark.asyncio


async def _add_sample(db_session, **overrides):
    defaults = dict(
        id=f"sample-{overrides.get('username', 'x')}-{overrides.get('sampled_at', datetime.utcnow())}",
        username="alice",
        node_id="node-1",
        total_bytes=0,
        online=False,
        sampled_at=datetime.utcnow(),
    )
    defaults.update(overrides)
    db_session.add(TrafficSampleRow(**defaults))


async def test_top_bandwidth_returns_one_row_per_user_using_latest_sample(db_session):
    now = datetime.utcnow()
    await _add_sample(db_session, username="alice", total_bytes=100, sampled_at=now - timedelta(minutes=10))
    await _add_sample(db_session, username="alice", total_bytes=500, sampled_at=now)
    await _add_sample(db_session, username="bob", total_bytes=50, sampled_at=now)
    await db_session.commit()

    result = await stats_repo.top_bandwidth(db_session, now - timedelta(hours=1))

    usernames = [r.username for r in result]
    assert usernames.count("alice") == 1
    assert usernames.count("bob") == 1
    alice = next(r for r in result if r.username == "alice")
    assert alice.total_bytes == 500  # the latest sample, not the older 100


async def test_active_users_only_includes_users_whose_latest_sample_is_online(db_session):
    now = datetime.utcnow()
    # alice's LATEST sample is offline, even though an earlier one was online.
    await _add_sample(db_session, username="alice", online=True, sampled_at=now - timedelta(minutes=10))
    await _add_sample(db_session, username="alice", online=False, sampled_at=now)
    await _add_sample(db_session, username="bob", online=True, sampled_at=now)
    await db_session.commit()

    result = await stats_repo.active_users(db_session, now - timedelta(hours=1))

    usernames = [r.username for r in result]
    assert "bob" in usernames
    assert "alice" not in usernames
