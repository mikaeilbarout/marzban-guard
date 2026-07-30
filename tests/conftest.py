"""
Test fixtures. Tests run against SQLite (aiosqlite) instead of Postgres and
fakeredis instead of a real Redis — both are drop-in enough for this
codebase's needs (no Postgres-only SQL, and the rate limiter only uses
basic string/set/pipeline commands fakeredis supports faithfully). This
keeps unit/integration tests runnable with no external services, while
docker-compose.yml is what's actually used against real Postgres/Redis in
staging/production.
"""
from __future__ import annotations

import os
from datetime import datetime

import pytest
import pytest_asyncio
from fakeredis import aioredis as fakeredis_aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

os.environ.setdefault("MARZBAN_GUARD_CONFIG", "config/config.example.yaml")
os.environ.setdefault("POSTGRES_PASSWORD", "test")
os.environ.setdefault("MARZBAN_ADMIN_USERNAME", "test")
os.environ.setdefault("MARZBAN_ADMIN_PASSWORD", "test")
os.environ.setdefault("INGEST_API_KEY", "test-ingest-key")
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")

from marzban_guard.config import get_config  # noqa: E402
from marzban_guard.db.base import Base  # noqa: E402


@pytest.fixture
def security_config():
    return get_config().security


@pytest_asyncio.fixture
async def redis():
    client = fakeredis_aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        yield session
    await engine.dispose()


def make_event(**overrides):
    from marzban_guard.schemas.events import ConnectionEvent

    defaults = dict(
        username="alice",
        node_id="node-1",
        client_ip="10.0.0.5",
        destination_ip="1.2.3.4",
        destination_port=443,
        protocol="tcp",
        outcome="accepted",
        occurred_at=datetime.utcnow(),
    )
    defaults.update(overrides)
    return ConnectionEvent.model_validate(defaults)
