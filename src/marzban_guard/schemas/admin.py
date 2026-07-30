from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class UserSummary(BaseModel):
    username: str
    risk_score: float
    status: str
    status_reason: str | None
    status_expires_at: datetime | None
    last_seen_at: datetime | None
    last_node_id: str | None


class AbuseEventOut(BaseModel):
    detector: str
    score_delta: float
    details: dict
    created_at: datetime


class MitigationActionOut(BaseModel):
    level: int
    action: str
    reason: str
    actor: str
    expires_at: datetime | None
    reverted_at: datetime | None
    created_at: datetime


class UserDetail(UserSummary):
    recent_events: list[AbuseEventOut]
    recent_actions: list[MitigationActionOut]


class SuspiciousUser(BaseModel):
    username: str
    abuse_event_count: int
    total_score: float


class BandwidthUser(BaseModel):
    username: str
    total_bytes: int
    sampled_at: datetime


class ConnectionCreator(BaseModel):
    username: str
    new_connections: int
    window_start: datetime


class BlacklistEntryOut(BaseModel):
    id: str
    username: str
    reason: str
    created_at: datetime
    reviewed: bool
    reviewed_by: str | None
    reviewed_at: datetime | None


class OverrideRequest(BaseModel):
    status: str  # "active" | "suspended" | "disabled" | "blacklisted"
    reason: str
    actor: str


class BlacklistReviewRequest(BaseModel):
    reviewed_by: str
    reinstate: bool = False


class StatsOut(BaseModel):
    active_users: int
    suspended_users: int
    disabled_users: int
    blacklisted_users: int
    abuse_events_last_24h: int
    mitigation_actions_last_24h: int
    pending_blacklist_reviews: int
