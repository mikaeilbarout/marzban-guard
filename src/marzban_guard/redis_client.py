"""Single shared async Redis connection pool for the whole process (API,
worker, or tests) — created lazily so importing this module never opens a
connection by itself."""
from __future__ import annotations

from functools import lru_cache

from redis.asyncio import Redis

from marzban_guard.config import get_config


@lru_cache(maxsize=1)
def get_redis() -> Redis:
    cfg = get_config().redis
    return Redis.from_url(cfg.url, decode_responses=True)
