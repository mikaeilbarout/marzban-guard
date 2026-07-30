"""
End-to-end (within the test process): POST a batch to /api/v1/ingest/events,
manually run one EventConsumer batch (rather than run_forever(), which
never returns), then assert the expected DB side effects — an abuse event
persisted, a risk score set, and a mitigation action recorded once a
user's synthetic traffic crosses a threshold.

Uses fakeredis + SQLite (see tests/conftest.py) instead of real
Postgres/Redis — a deliberate trade-off for fast, dependency-free tests;
docker-compose.yml is what actually runs against Postgres/Redis.
"""
from __future__ import annotations

import json
from datetime import datetime
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from marzban_guard.api.deps import get_redis_dep
from marzban_guard.config import get_config
from marzban_guard.db.base import get_db_session
from marzban_guard.db.models import GuardUser, MitigationAction, UserStatus
from marzban_guard.services.mitigation import MitigationService
from marzban_guard.services.notifier import Notifier
from marzban_guard.workers.event_consumer import EventConsumer

pytestmark = pytest.mark.asyncio


async def test_ingest_then_consume_flags_port_scan(db_session, redis, sessionmaker_returning):
    from marzban_guard.api.main import create_app

    app = create_app()
    app.dependency_overrides[get_redis_dep] = lambda: redis
    app.dependency_overrides[get_db_session] = lambda: db_session

    cfg = get_config()
    scan_cfg = cfg.security.scan_detection
    now = datetime.utcnow().isoformat()

    # Many distinct ports, concentrated on ONE destination IP — the
    # concentrated-port-scan signature (see PortScanDetector). Exactly
    # port_threshold events, all sharing one timestamp, so the threshold
    # is crossed on (and only on) the very last event in the batch — one
    # clean trigger, not several compounding ones from the same burst.
    events = [
        {
            "username": "attacker",
            "node_id": "node-1",
            "client_ip": "10.0.0.9",
            "destination_ip": "203.0.113.1",
            "destination_port": 1000 + i,
            "protocol": "tcp",
            "outcome": "accepted",
            "occurred_at": now,
        }
        for i in range(scan_cfg.port_threshold)
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/ingest/events",
            json={"node_id": "node-1", "events": events},
            headers={"Authorization": f"Bearer {cfg.ingest.api_key}"},
        )
    assert resp.status_code == 200
    assert resp.json()["accepted"] == len(events)

    # Now drive the consumer side manually — patch the Marzban client so no
    # real HTTP call happens, and use a no-op notifier.
    marzban = AsyncMock()
    mitigation = MitigationService(marzban, Notifier(cfg.notifications), cfg.security.mitigation)

    consumer = EventConsumer(
        redis, sessionmaker_returning, mitigation, cfg, consumer_id="test-consumer", block_ms=None
    )
    await consumer.ensure_group()
    await consumer._process_once()

    user = await db_session.get(GuardUser, "attacker")
    assert user is not None
    # Both PortScanDetector (concentrated ports on one host) AND
    # DestinationFanoutDetector (raw port breadth, regardless of
    # concentration) fire on this same event — that's by design, see
    # DestinationFanoutDetector's docstring — so the combined score clears
    # the level-3 threshold with default weights/thresholds.
    weights = cfg.security.scoring.weights
    expected_min_score = weights.port_scan + weights.too_many_destination_ports
    assert user.risk_score >= expected_min_score

    actions = (
        await db_session.execute(select(MitigationAction).where(MitigationAction.username == "attacker"))
    ).scalars().all()
    assert len(actions) >= 1
    assert user.status == UserStatus.suspended
    marzban.set_user_status.assert_awaited_once_with("attacker", active=False)


async def test_stale_pending_entries_are_reclaimed_and_processed(db_session, redis, sessionmaker_returning):
    """Regression test: a message read via XREADGROUP's ">" but never
    XACKed (the crash-mid-batch scenario) must NOT be lost forever — Redis
    Streams never redeliver it on their own, so EventConsumer has to
    reclaim it explicitly via XAUTOCLAIM. See event_consumer.py's
    _claim_stale_pending."""
    import json

    from marzban_guard.config import get_config

    cfg = get_config()

    event_payload = {
        "username": "ghost",
        "node_id": "node-1",
        "client_ip": "10.0.0.1",
        "destination_ip": "8.8.8.8",
        "destination_port": 443,
        "protocol": "tcp",
        "outcome": "accepted",
        "occurred_at": datetime.utcnow().isoformat(),
    }
    await redis.xadd(cfg.redis.stream_name, {"data": json.dumps(event_payload)})

    marzban = AsyncMock()
    mitigation = MitigationService(marzban, Notifier(cfg.notifications), cfg.security.mitigation)

    # Simulate a consumer that reads the message and then crashes before
    # acking — a raw xreadgroup call, bypassing EventConsumer entirely.
    dead_consumer = EventConsumer(
        redis, sessionmaker_returning, mitigation, cfg, consumer_id="dead-consumer", block_ms=None
    )
    await dead_consumer.ensure_group()
    read = await redis.xreadgroup(cfg.redis.consumer_group, "dead-consumer", {cfg.redis.stream_name: ">"}, count=10)
    assert read  # confirm it was actually delivered to the "dead" consumer

    pending = await redis.xpending(cfg.redis.stream_name, cfg.redis.consumer_group)
    assert pending["pending"] == 1

    # A fresh consumer (a replacement worker) must recover it — with the
    # idle threshold set to 0 so the test doesn't need to sleep 60s.
    survivor = EventConsumer(redis, sessionmaker_returning, mitigation, cfg, consumer_id="survivor", block_ms=None)
    survivor._claim_min_idle_ms = 0
    await survivor._process_once()

    # This one clean connection triggers no detector, so (by design — see
    # ScoringEngine's docstring) no guard_users/abuse_events row is
    # written. The one thing that IS always written per accepted
    # connection is its connection_rollups bucket — that's the proof the
    # reclaimed message actually got processed, not just acked and dropped.
    from marzban_guard.db.models import ConnectionRollup

    rollup = (
        await db_session.execute(select(ConnectionRollup).where(ConnectionRollup.username == "ghost"))
    ).scalars().first()
    assert rollup is not None
    assert rollup.new_connections_tcp == 1

    pending_after = await redis.xpending(cfg.redis.stream_name, cfg.redis.consumer_group)
    assert pending_after["pending"] == 0


async def test_mitigation_failure_for_one_user_does_not_sink_the_whole_batch(
    db_session, redis, sessionmaker_returning
):
    """Regression test: MitigationService.apply() calling the Marzban API
    (network blip, 5xx) must not kill the whole batch's commit — an
    unrelated user's scoring/rollup writes staged earlier in the same
    batch must still land, and the failing user's own score/abuse_event
    (already staged by ScoringEngine BEFORE mitigation.apply runs) must
    also survive so mitigation can retry on their next connection."""
    from marzban_guard.db.models import ConnectionRollup

    cfg = get_config()
    scan_cfg = cfg.security.scan_detection
    now = datetime.utcnow()

    # attacker: crosses the port-scan threshold -> triggers a level-3
    # escalation -> MitigationService calls marzban.set_user_status,
    # which is configured below to raise.
    for i in range(scan_cfg.port_threshold):
        event = {
            "username": "attacker",
            "node_id": "node-1",
            "client_ip": "10.0.0.9",
            "destination_ip": "203.0.113.1",
            "destination_port": 1000 + i,
            "protocol": "tcp",
            "outcome": "accepted",
            "occurred_at": now.isoformat(),
        }
        await redis.xadd(cfg.redis.stream_name, {"data": json.dumps(event)})

    # innocent: one ordinary clean connection, unrelated to the attacker,
    # in the SAME batch.
    innocent_event = {
        "username": "innocent",
        "node_id": "node-1",
        "client_ip": "10.0.0.50",
        "destination_ip": "8.8.8.8",
        "destination_port": 443,
        "protocol": "tcp",
        "outcome": "accepted",
        "occurred_at": now.isoformat(),
    }
    await redis.xadd(cfg.redis.stream_name, {"data": json.dumps(innocent_event)})

    marzban = AsyncMock()
    marzban.set_user_status.side_effect = ConnectionError("simulated Marzban outage")
    mitigation = MitigationService(marzban, Notifier(cfg.notifications), cfg.security.mitigation)

    consumer = EventConsumer(redis, sessionmaker_returning, mitigation, cfg, consumer_id="c1", block_ms=None)
    await consumer.ensure_group()
    await consumer._process_once()  # must NOT raise despite the simulated Marzban outage

    # The attacker's score was staged by ScoringEngine BEFORE the failed
    # mitigation attempt — it must survive the batch commit so mitigation
    # gets another chance on their next connection.
    attacker = await db_session.get(GuardUser, "attacker")
    assert attacker is not None
    assert attacker.risk_score > 0
    assert attacker.status == UserStatus.active  # escalation never completed

    # No mitigation action was recorded for the failed attempt — apply()
    # raised before it could write one.
    actions = (
        await db_session.execute(select(MitigationAction).where(MitigationAction.username == "attacker"))
    ).scalars().all()
    assert actions == []

    # The unrelated user's rollup — staged earlier in the same batch —
    # still committed.
    innocent_rollup = (
        await db_session.execute(select(ConnectionRollup).where(ConnectionRollup.username == "innocent"))
    ).scalars().first()
    assert innocent_rollup is not None

    # And the message was still acked — no point endlessly retrying a
    # deterministic Marzban outage for this one message; the score is
    # preserved and will re-trigger mitigation on the next connection.
    pending = await redis.xpending(cfg.redis.stream_name, cfg.redis.consumer_group)
    assert pending["pending"] == 0
