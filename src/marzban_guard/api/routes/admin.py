"""
Admin dashboard API — everything a frontend (or `curl`/Grafana JSON
datasource) needs to see current risk state and act on it. Every mutating
endpoint records a MitigationAction row via MitigationService so manual
overrides are just as traceable as automatic ones.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from marzban_guard.api.deps import get_mitigation_service_dep, get_redis_dep
from marzban_guard.config import get_config
from marzban_guard.db.base import get_db_session
from marzban_guard.db.models import AbuseEvent, BlacklistEntry, GuardUser, MitigationAction, UserStatus
from marzban_guard.repositories import action_repo, event_repo, stats_repo, user_repo
from marzban_guard.schemas.admin import (
    AbuseEventOut,
    BandwidthUser,
    BlacklistEntryOut,
    BlacklistReviewRequest,
    ConnectionCreator,
    DeviceLimitIn,
    MitigationActionOut,
    OverrideRequest,
    StatsOut,
    SuspiciousUser,
    UserDetail,
    UserSummary,
)
from marzban_guard.security import require_admin_api_key
from marzban_guard.services.mitigation import MitigationService
from marzban_guard.services.rate_limiter import get_device_limit_override, set_device_limit_override
from marzban_guard.services.scoring import effective_score

router = APIRouter(prefix="/api/v1/admin", tags=["admin"], dependencies=[Depends(require_admin_api_key)])


def _user_summary(user: GuardUser, now: datetime) -> UserSummary:
    half_life = get_config().security.scoring.decay_half_life_seconds
    return UserSummary(
        username=user.username,
        risk_score=round(effective_score(user, now, half_life), 2),
        status=user.status.value,
        status_reason=user.status_reason,
        status_expires_at=user.status_expires_at,
        last_seen_at=user.last_seen_at,
        last_node_id=user.last_node_id,
    )


@router.get("/stats", response_model=StatsOut)
async def stats(session: AsyncSession = Depends(get_db_session)) -> StatsOut:
    since = datetime.utcnow() - timedelta(hours=24)

    async def count_status(status: UserStatus) -> int:
        stmt = select(func.count(GuardUser.username)).where(GuardUser.status == status)
        return (await session.execute(stmt)).scalar_one()

    events_24h = (
        await session.execute(select(func.count(AbuseEvent.id)).where(AbuseEvent.created_at >= since))
    ).scalar_one()
    actions_24h = (
        await session.execute(select(func.count(MitigationAction.id)).where(MitigationAction.created_at >= since))
    ).scalar_one()
    pending_review = (
        await session.execute(select(func.count(BlacklistEntry.id)).where(BlacklistEntry.reviewed.is_(False)))
    ).scalar_one()

    return StatsOut(
        active_users=await count_status(UserStatus.active),
        suspended_users=await count_status(UserStatus.suspended),
        disabled_users=await count_status(UserStatus.disabled),
        blacklisted_users=await count_status(UserStatus.blacklisted),
        abuse_events_last_24h=events_24h,
        mitigation_actions_last_24h=actions_24h,
        pending_blacklist_reviews=pending_review,
    )


@router.get("/users/top-risk", response_model=list[UserSummary])
async def top_risk(limit: int = 20, session: AsyncSession = Depends(get_db_session)) -> list[UserSummary]:
    now = datetime.utcnow()
    users = await user_repo.top_by_risk_score(session, limit)
    return [_user_summary(u, now) for u in users]


@router.get("/users/blocked", response_model=list[UserSummary])
async def blocked_users(session: AsyncSession = Depends(get_db_session)) -> list[UserSummary]:
    now = datetime.utcnow()
    users = []
    for status in (UserStatus.suspended, UserStatus.disabled, UserStatus.blacklisted):
        users.extend(await user_repo.by_status(session, status))
    return [_user_summary(u, now) for u in users]


@router.get("/users/most-suspicious", response_model=list[SuspiciousUser])
async def most_suspicious(
    hours: int = 24, limit: int = 20, session: AsyncSession = Depends(get_db_session)
) -> list[SuspiciousUser]:
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = await event_repo.most_suspicious(session, since, limit)
    return [SuspiciousUser(username=u, abuse_event_count=c, total_score=s) for u, c, s in rows]


@router.get("/users/top-bandwidth", response_model=list[BandwidthUser])
async def top_bandwidth(
    hours: int = 24, limit: int = 20, session: AsyncSession = Depends(get_db_session)
) -> list[BandwidthUser]:
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = await stats_repo.top_bandwidth(session, since, limit)
    return [BandwidthUser(username=r.username, total_bytes=r.total_bytes, sampled_at=r.sampled_at) for r in rows]


@router.get("/users/top-connections", response_model=list[ConnectionCreator])
async def top_connections(
    hours: int = 1, limit: int = 20, session: AsyncSession = Depends(get_db_session)
) -> list[ConnectionCreator]:
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = await stats_repo.top_connection_creators(session, since, limit)
    return [ConnectionCreator(username=u, new_connections=c, window_start=w) for u, c, w in rows]


@router.get("/users/active", response_model=list[UserSummary])
async def active_users(minutes: int = 15, session: AsyncSession = Depends(get_db_session)) -> list[UserSummary]:
    since = datetime.utcnow() - timedelta(minutes=minutes)
    samples = await stats_repo.active_users(session, since)
    now = datetime.utcnow()
    out = []
    for sample in samples:
        user = await user_repo.get(session, sample.username)
        if user:
            out.append(_user_summary(user, now))
    return out


@router.get("/users/{username}", response_model=UserDetail)
async def user_detail(username: str, session: AsyncSession = Depends(get_db_session)) -> UserDetail:
    user = await user_repo.get(session, username)
    if not user:
        raise HTTPException(404, "Unknown user (no events recorded for this username yet)")
    now = datetime.utcnow()
    since = now - timedelta(days=7)
    events = await event_repo.recent_for_user(session, username, since)
    actions = await action_repo.recent_for_user(session, username)
    summary = _user_summary(user, now)
    return UserDetail(
        **summary.model_dump(),
        recent_events=[
            AbuseEventOut(detector=e.detector, score_delta=e.score_delta, details=e.details, created_at=e.created_at)
            for e in events
        ],
        recent_actions=[
            MitigationActionOut(
                level=a.level, action=a.action, reason=a.reason, actor=a.actor,
                expires_at=a.expires_at, reverted_at=a.reverted_at, created_at=a.created_at,
            )
            for a in actions
        ],
    )


@router.get("/users/{username}/connections", response_model=list[dict])
async def user_connection_history(
    username: str, hours: int = 24, session: AsyncSession = Depends(get_db_session)
) -> list[dict]:
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = await stats_repo.connection_history(session, username, since)
    return [
        {
            "window_start": r.window_start,
            "new_connections_tcp": r.new_connections_tcp,
            "new_connections_udp": r.new_connections_udp,
            "distinct_destination_ips": r.distinct_destination_ips,
            "distinct_destination_ports": r.distinct_destination_ports,
            "top_destination_country": r.top_destination_country,
        }
        for r in rows
    ]


@router.post("/users/{username}/override", response_model=UserSummary)
async def override_user_status(
    username: str,
    payload: OverrideRequest,
    session: AsyncSession = Depends(get_db_session),
    mitigation: MitigationService = Depends(get_mitigation_service_dep),
) -> UserSummary:
    user = await user_repo.get_or_create(session, username)
    try:
        new_status = UserStatus(payload.status)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid status {payload.status!r}") from exc

    await mitigation.manual_override(session, user, new_status, payload.reason, payload.actor)
    await session.commit()
    return _user_summary(user, datetime.utcnow())


@router.put("/users/{username}/device-limit")
async def set_user_device_limit(
    username: str, payload: DeviceLimitIn, redis: Redis = Depends(get_redis_dep)
) -> dict:
    """Lets an external shop push "this customer's plan allows N devices"
    without marzban-guard needing to know anything about plans — stored
    directly in Redis (no DB row needed for a value this cheap and this
    hot-path-read), consulted by DeviceLimitDetector ahead of the static
    YAML per_user_overrides/global default. payload.max_devices=null
    clears the override."""
    await set_device_limit_override(redis, username, payload.max_devices)
    return {"ok": True, "username": username, "max_devices": payload.max_devices}


@router.get("/users/{username}/device-limit")
async def get_user_device_limit(username: str, redis: Redis = Depends(get_redis_dep)) -> dict:
    override = await get_device_limit_override(redis, username)
    return {"username": username, "max_devices": override}


@router.get("/blacklist", response_model=list[BlacklistEntryOut])
async def list_blacklist(
    reviewed: bool | None = None, session: AsyncSession = Depends(get_db_session)
) -> list[BlacklistEntryOut]:
    entries = await action_repo.blacklist_entries(session, reviewed)
    return [
        BlacklistEntryOut(
            id=e.id, username=e.username, reason=e.reason, created_at=e.created_at,
            reviewed=e.reviewed, reviewed_by=e.reviewed_by, reviewed_at=e.reviewed_at,
        )
        for e in entries
    ]


@router.post("/blacklist/{entry_id}/review")
async def review_blacklist_entry(
    entry_id: str,
    payload: BlacklistReviewRequest,
    session: AsyncSession = Depends(get_db_session),
    mitigation: MitigationService = Depends(get_mitigation_service_dep),
) -> dict:
    entry = await session.get(BlacklistEntry, entry_id)
    if not entry:
        raise HTTPException(404, "Blacklist entry not found")

    entry.reviewed = True
    entry.reviewed_by = payload.reviewed_by
    entry.reviewed_at = datetime.utcnow()

    if payload.reinstate:
        user = await user_repo.get_or_create(session, entry.username)
        await mitigation.manual_override(
            session, user, UserStatus.active, f"blacklist entry {entry_id} cleared on review", payload.reviewed_by
        )

    await session.commit()
    return {"ok": True}
