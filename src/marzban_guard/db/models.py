from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from marzban_guard.db.base import Base

# JSONB in production (Postgres); plain JSON everywhere else (e.g. SQLite
# in tests) — SQLAlchemy's standard "use a better type on Postgres" pattern.
_JSONType = JSON().with_variant(JSONB(), "postgresql")


def gen_uuid() -> str:
    return uuid.uuid4().hex


class UserStatus(str, enum.Enum):
    active = "active"
    suspended = "suspended"       # temporary — status_expires_at set
    disabled = "disabled"         # level 4 — requires manual re-enable
    blacklisted = "blacklisted"   # level 5 — permanent until manual review


class GuardUser(Base):
    """One row per Marzban username marzban-guard has ever seen an event
    for. This is NOT a copy of the customer/account record (that lives in
    the shop's own DB) — just enough state to track risk and enforce
    mitigation for this one system."""

    __tablename__ = "guard_users"

    username: Mapped[str] = mapped_column(String, primary_key=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status"), default=UserStatus.active, nullable=False
    )
    status_reason: Mapped[str | None] = mapped_column(String, nullable=True)
    status_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_node_id: Mapped[str | None] = mapped_column(String, nullable=True)
    # When this user last had ANY detector trigger — distinct from
    # updated_at (which also changes on every risk_score decay-only
    # touch). Used to tell "still mid-burst" apart from "doing it again
    # later" — see ScoringConfig.repeat_offense_min_gap_seconds.
    last_abuse_event_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    abuse_events: Mapped[list[AbuseEvent]] = relationship(back_populates="user")
    actions: Mapped[list[MitigationAction]] = relationship(back_populates="user")


class AbuseEvent(Base):
    """One row per detector trigger (not per raw connection — see
    docs/ARCHITECTURE.md#storage). This is the audit trail behind every
    risk_score change."""

    __tablename__ = "abuse_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    username: Mapped[str] = mapped_column(ForeignKey("guard_users.username"), nullable=False, index=True)
    detector: Mapped[str] = mapped_column(String, nullable=False)
    score_delta: Mapped[float] = mapped_column(Float, nullable=False)
    details: Mapped[dict] = mapped_column(_JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    user: Mapped[GuardUser] = relationship(back_populates="abuse_events")


class MitigationAction(Base):
    """One row per mitigation action actually taken (or reverted) — the
    audit trail behind every status change, whether triggered
    automatically by the scoring engine or manually by an admin."""

    __tablename__ = "mitigation_actions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    username: Mapped[str] = mapped_column(ForeignKey("guard_users.username"), nullable=False, index=True)
    level: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)  # log|notify_admin|suspend|disable|blacklist
    reason: Mapped[str] = mapped_column(String, nullable=False)
    actor: Mapped[str] = mapped_column(String, default="system", nullable=False)  # "system" or admin username
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reverted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    user: Mapped[GuardUser] = relationship(back_populates="actions")


class BlacklistEntry(Base):
    """Level-5 mitigation lands here. A blacklisted user's Marzban account
    stays disabled until an admin explicitly reviews and clears the entry
    (see api/routes/admin.py) — never auto-expires, unlike a level-3
    suspension."""

    __tablename__ = "blacklist_entries"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    username: Mapped[str] = mapped_column(String, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ConnectionRollup(Base):
    """Per-user, per-minute aggregated connection stats — NOT one row per
    raw connection. Raw connections only ever live transiently in Redis
    (see services/rate_limiter.py); the worker rolls the window up into
    one row here per user per minute for history/dashboard/Prometheus, so
    storage stays O(users x minutes) instead of O(connections)."""

    __tablename__ = "connection_rollups"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    username: Mapped[str] = mapped_column(String, nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    new_connections_tcp: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    new_connections_udp: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    distinct_destination_ips: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    distinct_destination_ports: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    top_destination_country: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class TrafficSampleRow(Base):
    """One row per traffic_poller.py sample (see
    workers/traffic_poller.py) — periodic snapshots of Marzban's own
    per-user counters, since the access log carries no byte counts.

    Only a single cumulative `total_bytes` figure is stored, NOT a
    separate uplink/downlink split — Marzban's admin API
    (GET /api/user/{username}, GET /api/users) exposes one running
    `used_traffic` counter per user, not directional totals. Don't invent
    a split the underlying API doesn't actually provide."""

    __tablename__ = "traffic_samples"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    username: Mapped[str] = mapped_column(String, nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String, nullable=False)
    total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    online: Mapped[bool] = mapped_column(Boolean, nullable=False)
    sampled_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
