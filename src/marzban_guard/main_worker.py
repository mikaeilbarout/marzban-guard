"""
Worker process entrypoint (run via `python -m marzban_guard.main_worker`,
see docker/Dockerfile.worker). Runs three things concurrently in one
process:

  - N EventConsumer instances sharing one Redis consumer group (N =
    worker.consumer_concurrency) — the detect/score/mitigate pipeline.
  - The level-3 suspension expiry sweep.
  - The traffic/online-status poller against Marzban's admin API.

Scale further by running more copies of this process/container (each
consumer_id is unique per process, so they safely share the same Redis
consumer group across containers too).
"""
from __future__ import annotations

import asyncio
import uuid

from prometheus_client import start_http_server

from marzban_guard.config import get_config
from marzban_guard.db.base import get_sessionmaker
from marzban_guard.logging import configure_logging, get_logger
from marzban_guard.redis_client import get_redis
from marzban_guard.services.marzban_client import MarzbanClient
from marzban_guard.services.mitigation import MitigationService
from marzban_guard.services.notifier import Notifier
from marzban_guard.workers.event_consumer import EventConsumer, expiry_sweep_forever
from marzban_guard.workers.traffic_poller import TrafficPoller

logger = get_logger("main_worker")


async def main() -> None:
    cfg = get_config()
    configure_logging(cfg.service.log_level)

    redis = get_redis()
    sessionmaker = get_sessionmaker()
    marzban = MarzbanClient(cfg.marzban)
    notifier = Notifier(cfg.notifications)
    mitigation = MitigationService(marzban, notifier, cfg.security.mitigation)

    if cfg.worker.metrics_port:
        start_http_server(cfg.worker.metrics_port)
        logger.info("event_type=metrics_server_started", port=cfg.worker.metrics_port)

    process_id = uuid.uuid4().hex[:8]
    consumers = [
        EventConsumer(redis, sessionmaker, mitigation, cfg, consumer_id=f"{process_id}-{i}")
        for i in range(cfg.worker.consumer_concurrency)
    ]
    traffic_poller = TrafficPoller(
        marzban, sessionmaker, cfg.worker.marzban_node_id, cfg.worker.traffic_poll_interval_seconds
    )

    logger.info("event_type=worker_starting", process_id=process_id, consumers=len(consumers))

    await asyncio.gather(
        *(c.run_forever() for c in consumers),
        expiry_sweep_forever(mitigation, sessionmaker, cfg.worker.expiry_sweep_interval_seconds),
        traffic_poller.run_forever(),
    )


if __name__ == "__main__":
    asyncio.run(main())
