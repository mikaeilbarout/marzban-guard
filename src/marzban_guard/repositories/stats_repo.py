"""Read-side queries backing the admin dashboard. Traffic and
online-status figures come from TrafficSampleRow (workers/traffic_poller.py
snapshots of Marzban's own counters) — NOT from the connection event
stream, which carries no byte counts. Connection-count figures come from
ConnectionRollup, the per-minute aggregates the event consumer writes."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from marzban_guard.db.models import ConnectionRollup, TrafficSampleRow


async def _latest_traffic_sample_per_user(session: AsyncSession, since: datetime) -> list[TrafficSampleRow]:
    stmt = (
        select(TrafficSampleRow)
        .distinct(TrafficSampleRow.username)
        .where(TrafficSampleRow.sampled_at >= since)
        .order_by(TrafficSampleRow.username, TrafficSampleRow.sampled_at.desc())
    )
    return list((await session.execute(stmt)).scalars().all())


async def active_users(session: AsyncSession, since: datetime, limit: int = 200) -> list[TrafficSampleRow]:
    samples = await _latest_traffic_sample_per_user(session, since)
    online = [s for s in samples if s.online]
    online.sort(key=lambda s: s.sampled_at, reverse=True)
    return online[:limit]


async def top_bandwidth(session: AsyncSession, since: datetime, limit: int = 20) -> list[TrafficSampleRow]:
    samples = await _latest_traffic_sample_per_user(session, since)
    samples.sort(key=lambda s: s.total_bytes, reverse=True)
    return samples[:limit]


async def top_connection_creators(
    session: AsyncSession, since: datetime, limit: int = 20
) -> list[tuple[str, int, datetime]]:
    total_connections = ConnectionRollup.new_connections_tcp + ConnectionRollup.new_connections_udp
    stmt = (
        select(
            ConnectionRollup.username,
            func.sum(total_connections).label("total"),
            func.max(ConnectionRollup.window_start).label("last_window"),
        )
        .where(ConnectionRollup.window_start >= since)
        .group_by(ConnectionRollup.username)
        .order_by(func.sum(total_connections).desc())
        .limit(limit)
    )
    return [(row.username, int(row.total), row.last_window) for row in (await session.execute(stmt)).all()]


async def connection_history(
    session: AsyncSession, username: str, since: datetime, limit: int = 500
) -> list[ConnectionRollup]:
    stmt = (
        select(ConnectionRollup)
        .where(ConnectionRollup.username == username, ConnectionRollup.window_start >= since)
        .order_by(ConnectionRollup.window_start.desc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())
