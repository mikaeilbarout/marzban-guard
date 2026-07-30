"""
The device-limit endpoints are how an external shop (e.g. Freemiga) pushes
"this customer's plan allows N devices" into marzban-guard — this is the
one API surface an outside system is expected to call directly (as
opposed to shop_integration, which is marzban-guard calling OUT). See
docs/ARCHITECTURE.md#shop-integration-keeping-the-storefront-in-sync.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from marzban_guard.api.deps import get_redis_dep
from marzban_guard.config import get_config

pytestmark = pytest.mark.asyncio


async def test_device_limit_set_get_and_clear_round_trip(redis):
    from marzban_guard.api.main import create_app

    app = create_app()
    app.dependency_overrides[get_redis_dep] = lambda: redis
    cfg = get_config()
    headers = {"Authorization": f"Bearer {cfg.admin_api.api_key}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # No override set yet.
        resp = await client.get("/api/v1/admin/users/alice/device-limit", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == {"username": "alice", "max_devices": None}

        # Shop pushes a plan's device allowance.
        resp = await client.put(
            "/api/v1/admin/users/alice/device-limit", headers=headers, json={"max_devices": 5}
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True, "username": "alice", "max_devices": 5}

        resp = await client.get("/api/v1/admin/users/alice/device-limit", headers=headers)
        assert resp.json() == {"username": "alice", "max_devices": 5}

        # Clearing it (e.g. customer downgraded/cancelled) reverts to the
        # global default.
        resp = await client.put(
            "/api/v1/admin/users/alice/device-limit", headers=headers, json={"max_devices": None}
        )
        assert resp.status_code == 200
        resp = await client.get("/api/v1/admin/users/alice/device-limit", headers=headers)
        assert resp.json() == {"username": "alice", "max_devices": None}


async def test_device_limit_requires_admin_api_key(redis):
    from marzban_guard.api.main import create_app

    app = create_app()
    app.dependency_overrides[get_redis_dep] = lambda: redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.put("/api/v1/admin/users/alice/device-limit", json={"max_devices": 3})
        assert resp.status_code == 401
