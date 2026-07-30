"""
Domain-level Prometheus metrics, shared by the API and the workers (the
same process-wide registry prometheus_fastapi_instrumentator's
Instrumentator() exposes at /metrics — see api/main.py). HTTP-level
metrics (request count/latency) come from Instrumentator automatically;
these are the abuse-specific ones a Grafana dashboard actually wants.
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

connection_events_processed_total = Counter(
    "mg_connection_events_processed_total",
    "Connection events consumed from the ingestion stream.",
    ["node_id"],
)

detector_triggers_total = Counter(
    "mg_detector_triggers_total",
    "Times a detector's evaluate() returned triggered=True.",
    ["detector"],
)

mitigation_actions_total = Counter(
    "mg_mitigation_actions_total",
    "Mitigation actions taken.",
    ["action", "level"],
)

event_consumer_batch_duration_seconds = Histogram(
    "mg_event_consumer_batch_duration_seconds",
    "Time to process one batch pulled from the Redis stream.",
)

stream_pending_entries = Gauge(
    "mg_stream_pending_entries",
    "Entries in the consumer group's pending-entries list (unacked work).",
)

users_by_status = Gauge(
    "mg_users_by_status",
    "Current guard_users count per status.",
    ["status"],
)
