"""Kubernetes/Docker-style health probes.

- /healthz  (liveness)  — process is up and can serve HTTP. Never checks
  dependencies: a slow/unreachable Postgres shouldn't get this pod killed
  and restarted, since restarting won't fix a downstream outage.
- /readyz   (readiness) — actually pings Postgres and Redis; used to pull
  this instance out of a load balancer's rotation while a dependency is
  down, without killing the process.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Response, status
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from marzban_guard.api.deps import get_redis_dep
from marzban_guard.db.base import get_db_session
from marzban_guard.logging import get_logger

logger = get_logger("health")

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(
    response: Response,
    session: AsyncSession = Depends(get_db_session),
    redis: Redis = Depends(get_redis_dep),
) -> dict:
    checks = {"database": False, "redis": False}

    try:
        await session.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        logger.exception("readyz_database_check_failed")

    try:
        await redis.ping()
        checks["redis"] = True
    except Exception:
        logger.exception("readyz_redis_check_failed")

    ready = all(checks.values())
    response.status_code = status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ok" if ready else "not_ready", "checks": checks}
