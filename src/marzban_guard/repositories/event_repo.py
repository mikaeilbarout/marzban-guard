from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from marzban_guard.db.models import AbuseEvent


async def add(
    session: AsyncSession, username: str, detector: str, score_delta: float, details: dict
) -> AbuseEvent:
    event = AbuseEvent(username=username, detector=detector, score_delta=score_delta, details=details)
    session.add(event)
    await session.flush()
    return event


async def recent_for_user(session: AsyncSession, username: str, since: datetime, limit: int = 100) -> list[AbuseEvent]:
    stmt = (
        select(AbuseEvent)
        .where(AbuseEvent.username == username, AbuseEvent.created_at >= since)
        .order_by(AbuseEvent.created_at.desc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())


async def count_since(session: AsyncSession, username: str, since: datetime) -> int:
    stmt = select(func.count(AbuseEvent.id)).where(
        AbuseEvent.username == username, AbuseEvent.created_at >= since
    )
    return (await session.execute(stmt)).scalar_one()


async def most_suspicious(session: AsyncSession, since: datetime, limit: int = 20) -> list[tuple[str, int, float]]:
    """(username, event_count, total_score) for the admin dashboard's
    "most suspicious users" view."""
    stmt = (
        select(AbuseEvent.username, func.count(AbuseEvent.id), func.sum(AbuseEvent.score_delta))
        .where(AbuseEvent.created_at >= since)
        .group_by(AbuseEvent.username)
        .order_by(func.sum(AbuseEvent.score_delta).desc())
        .limit(limit)
    )
    return [(row[0], row[1], float(row[2] or 0)) for row in (await session.execute(stmt)).all()]
