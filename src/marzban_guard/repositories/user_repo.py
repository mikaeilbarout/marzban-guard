"""
Repository pattern: every method here takes an AsyncSession and does
exactly one job against guard_users — no commits (the caller's unit of
work decides transaction boundaries), no business logic (that's
services/scoring.py and services/mitigation.py).
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from marzban_guard.db.models import GuardUser, UserStatus


async def get(session: AsyncSession, username: str) -> GuardUser | None:
    return await session.get(GuardUser, username)


async def get_or_create(session: AsyncSession, username: str) -> GuardUser:
    user = await get(session, username)
    if user:
        return user
    user = GuardUser(username=username)
    session.add(user)
    await session.flush()
    return user


async def touch_last_seen(session: AsyncSession, user: GuardUser, node_id: str, seen_at: datetime) -> None:
    user.last_seen_at = seen_at
    user.last_node_id = node_id


async def set_status(
    session: AsyncSession,
    user: GuardUser,
    status: UserStatus,
    reason: str,
    expires_at: datetime | None = None,
) -> None:
    user.status = status
    user.status_reason = reason
    user.status_expires_at = expires_at


async def top_by_risk_score(session: AsyncSession, limit: int = 20) -> list[GuardUser]:
    stmt = select(GuardUser).order_by(GuardUser.risk_score.desc()).limit(limit)
    return list((await session.execute(stmt)).scalars().all())


async def by_status(session: AsyncSession, status: UserStatus, limit: int = 100) -> list[GuardUser]:
    stmt = select(GuardUser).where(GuardUser.status == status).order_by(GuardUser.updated_at.desc()).limit(limit)
    return list((await session.execute(stmt)).scalars().all())


async def expired_suspensions(session: AsyncSession, now: datetime) -> list[GuardUser]:
    """Users whose temporary (level-3) suspension has run out — consumed by
    the worker's expiry sweep to auto-reinstate them."""
    stmt = select(GuardUser).where(
        GuardUser.status == UserStatus.suspended,
        GuardUser.status_expires_at.is_not(None),
        GuardUser.status_expires_at <= now,
    )
    return list((await session.execute(stmt)).scalars().all())
