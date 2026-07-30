from __future__ import annotations

from functools import lru_cache

from redis.asyncio import Redis

from marzban_guard.config import get_config
from marzban_guard.redis_client import get_redis
from marzban_guard.services.marzban_client import MarzbanClient
from marzban_guard.services.mitigation import MitigationService
from marzban_guard.services.notifier import Notifier
from marzban_guard.services.shop_notifier import ShopNotifier


async def get_redis_dep() -> Redis:
    return get_redis()


@lru_cache(maxsize=1)
def get_marzban_client() -> MarzbanClient:
    return MarzbanClient(get_config().marzban)


@lru_cache(maxsize=1)
def get_notifier() -> Notifier:
    return Notifier(get_config().notifications)


@lru_cache(maxsize=1)
def get_shop_notifier() -> ShopNotifier:
    return ShopNotifier(get_config().shop_integration)


@lru_cache(maxsize=1)
def get_mitigation_service() -> MitigationService:
    return MitigationService(
        get_marzban_client(), get_notifier(), get_config().security.mitigation, get_shop_notifier()
    )


async def get_mitigation_service_dep() -> MitigationService:
    return get_mitigation_service()
