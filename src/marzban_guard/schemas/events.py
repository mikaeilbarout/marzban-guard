"""
Wire schemas for data flowing IN to marzban-guard.

ConnectionEvent is the one honest, cheap signal we can get straight out of
Xray's access log (log.access, loglevel "info"): one line per accepted
connection, giving us who (Marzban's "email" tag = username), from where,
to where, and over which protocol. See docs/DATA_SOURCES.md for exactly
what this does and doesn't cover — notably, Xray's access log has no
"connection closed" event, so true concurrent-connection counts and
per-connection duration are estimates (see services/rate_limiter.py), and
byte counters come from a separate poll of Marzban's traffic API
(TrafficSample below), not from the access log.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Protocol(str, Enum):
    tcp = "tcp"
    udp = "udp"


class Outcome(str, Enum):
    accepted = "accepted"
    # Only populated if the node's Xray log level is turned up to at least
    # "warning" — plain "info" (the default, and all that's needed for the
    # rest of this system) only logs accepted connections. See
    # docs/DATA_SOURCES.md before enabling failed_connection_burst scoring.
    rejected = "rejected"


class ConnectionEvent(BaseModel):
    username: str
    node_id: str
    client_ip: str
    destination_ip: str
    destination_port: int = Field(ge=1, le=65535)
    protocol: Protocol
    outcome: Outcome = Outcome.accepted
    occurred_at: datetime

    @field_validator("username")
    @classmethod
    def username_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("username must not be empty")
        return v


class ConnectionEventBatch(BaseModel):
    """What the node-side collector POSTs to /api/v1/ingest/events. Batched
    (rather than one HTTP call per connection) to keep ingestion overhead
    low under high connection churn — see docs/ARCHITECTURE.md#ingestion."""
    node_id: str
    events: list[ConnectionEvent] = Field(default_factory=list, max_length=10_000)


class TrafficSample(BaseModel):
    """Periodic snapshot from polling Marzban's own per-user traffic
    counter (workers/traffic_poller.py) — this is where total traffic and
    "currently online" actually come from, since the access log carries
    no byte counts. Marzban's admin API exposes one cumulative
    `used_traffic` figure per user, not an uplink/downlink split, so
    that's all that's modeled here."""
    username: str
    node_id: str
    total_bytes: int = Field(ge=0)
    online: bool
    sampled_at: datetime


class IngestAck(BaseModel):
    status: Literal["accepted"] = "accepted"
    accepted: int
    rejected: int = 0
