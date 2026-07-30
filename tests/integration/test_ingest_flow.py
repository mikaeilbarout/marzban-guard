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


async def test_ingest_then_consume_flags_port_scan(db_session, redis):
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

    class _CtxSessionmaker:
        def __call__(self):
            class _Ctx:
                async def __aenter__(self_inner):
                    return db_session

                async def __aexit__(self_inner, *exc):
                    return False

            return _Ctx()

    consumer = EventConsumer(redis, _CtxSessionmaker(), mitigation, cfg, consumer_id="test-consumer", block_ms=None)
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
