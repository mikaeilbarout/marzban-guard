"""ShopNotifier tests using httpx.MockTransport — no real network calls,
but a real httpx.AsyncClient request/response cycle so the URL, headers,
and body actually sent are verified, not just that some function was
called."""
from __future__ import annotations

import httpx
import pytest

from marzban_guard.config import ShopIntegrationConfig
from marzban_guard.services.shop_notifier import ShopNotifier

pytestmark = pytest.mark.asyncio


async def test_notify_status_does_nothing_when_base_url_unset():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    notifier = ShopNotifier(ShopIntegrationConfig(base_url="", webhook_secret="s"))
    await notifier.notify_status("alice", banned=True, reason="test")
    assert calls == []


async def test_notify_status_posts_expected_request(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = request.content
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)

    original_client = httpx.AsyncClient

    def patched_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched_client)

    notifier = ShopNotifier(ShopIntegrationConfig(base_url="https://shop.example.com", webhook_secret="topsecret"))
    await notifier.notify_status("alice", banned=True, reason="port scan")

    assert captured["url"] == "https://shop.example.com/api/integrations/marzban-guard/status"
    assert captured["auth"] == "Bearer topsecret"
    import json

    body = json.loads(captured["body"])
    assert body == {"username": "alice", "banned": True, "reason": "port scan"}


async def test_notify_status_swallows_errors(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(handler)
    original_client = httpx.AsyncClient

    def patched_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched_client)

    notifier = ShopNotifier(ShopIntegrationConfig(base_url="https://shop.example.com", webhook_secret="s"))
    # Must not raise — a shop-callback failure can never affect mitigation.
    await notifier.notify_status("alice", banned=True, reason="x")
