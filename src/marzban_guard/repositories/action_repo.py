from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from marzban_guard.db.models import BlacklistEntry, MitigationAction


async def add(
    session: AsyncSession,
    username: str,
    level: int,
    action: str,
    reason: str,
    actor: str = "system",
    expires_at: datetime | None = None,
) -> MitigationAction:
    row = MitigationAction(
        username=username, level=level, action=action, reason=reason, actor=actor, expires_at=expires_at
    )
    session.add(row)
    await session.flush()
    return row


async def last_action(session: AsyncSession, username: str, action: str) -> MitigationAction | None:
    stmt = (
        select(MitigationAction)
        .where(MitigationAction.username == username, MitigationAction.action == action)
        .order_by(MitigationAction.created_at.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalars().first()


async def recent_for_user(session: AsyncSession, username: str, limit: int = 50) -> list[MitigationAction]:
    stmt = (
        select(MitigationAction)
        .where(MitigationAction.username == username)
        .order_by(MitigationAction.created_at.desc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())


async def add_blacklist_entry(session: AsyncSession, username: str, reason: str) -> BlacklistEntry:
    entry = BlacklistEntry(username=username, reason=reason)
    session.add(entry)
    await session.flush()
    return entry


async def blacklist_entries(session: AsyncSession, reviewed: bool | None = None) -> list[BlacklistEntry]:
    stmt = select(BlacklistEntry).order_by(BlacklistEntry.created_at.desc())
    if reviewed is not None:
        stmt = stmt.where(BlacklistEntry.reviewed == reviewed)
    return list((await session.execute(stmt)).scalars().all())
