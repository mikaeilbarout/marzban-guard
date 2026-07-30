from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator

from marzban_guard.api.routes import admin, health, ingest
from marzban_guard.config import get_config
from marzban_guard.db.base import get_engine
from marzban_guard.logging import configure_logging, get_logger

logger = get_logger("api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(get_config().service.log_level)
    logger.info("event_type=startup", environment=get_config().service.environment)
    yield
    await get_engine().dispose()
    logger.info("event_type=shutdown")


def create_app() -> FastAPI:
    app = FastAPI(title="marzban-guard", version="0.1.0", lifespan=lifespan)

    app.include_router(health.router)
    app.include_router(ingest.router)
    app.include_router(admin.router)

    # /metrics — Prometheus scrape target. Instrumentator adds request
    # count/latency histograms automatically; workers/event_consumer.py
    # additionally publishes domain metrics (see metrics.py) onto the same
    # process-wide registry.
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

    return app


app = create_app()
