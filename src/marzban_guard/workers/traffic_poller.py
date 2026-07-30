"""
The only source of traffic-volume and true online/offline status in this
system — Xray's access log carries neither (see docs/DATA_SOURCES.md).
Walks Marzban's paginated /api/users endpoint once per poll cycle and
writes one batched insert of TrafficSampleRow rows (session.add_all + one
commit), not one write per user.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from marzban_guard.db.models import TrafficSampleRow
from marzban_guard.logging import get_logger
from marzban_guard.services.marzban_client import MarzbanClient

logger = get_logger("traffic_poller")

_PAGE_SIZE = 200


def _is_online(user: dict) -> bool:
    """Marzban reports `online_at` (last time the user had active traffic)
    rather than a live boolean — treated as "online" if seen within the
    last 2 poll cycles' worth of time, so a slow poll interval doesn't
    make everyone look offline between polls."""
    online_at = user.get("online_at")
    if not online_at:
        return False
    try:
        seen = datetime.fromisoformat(online_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    return datetime.now(seen.tzinfo) - seen < timedelta(minutes=5)


class TrafficPoller:
    def __init__(
        self,
        marzban: MarzbanClient,
        sessionmaker: async_sessionmaker[AsyncSession],
        node_id: str,
        interval_seconds: int = 60,
    ):
        self._marzban = marzban
        self._sessionmaker = sessionmaker
        self._node_id = node_id
        self._interval = interval_seconds

    async def run_forever(self) -> None:
        while True:
            try:
                await self._poll_once()
            except Exception:
                logger.exception("event_type=traffic_poll_failed")
            await asyncio.sleep(self._interval)

    async def _poll_once(self) -> None:
        now = datetime.utcnow()
        rows: list[TrafficSampleRow] = []
        offset = 0

        while True:
            page = await self._marzban.list_users(offset=offset, limit=_PAGE_SIZE)
            users = page.get("users", [])
            if not users:
                break
            for u in users:
                username = u.get("username")
                if not username:
                    continue
                rows.append(
                    TrafficSampleRow(
                        username=username,
                        node_id=self._node_id,
                        total_bytes=int(u.get("used_traffic") or 0),
                        online=_is_online(u),
                        sampled_at=now,
                    )
                )
            offset += _PAGE_SIZE
            if len(users) < _PAGE_SIZE:
                break

        if not rows:
            return

        async with self._sessionmaker() as session:
            session.add_all(rows)
            await session.commit()

        logger.info("event_type=traffic_poll_completed", users=len(rows), node_id=self._node_id)
