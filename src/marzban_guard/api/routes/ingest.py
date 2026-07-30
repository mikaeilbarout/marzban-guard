"""
Where the node-side collector(s) POST batches of connection events. Kept
deliberately cheap: validate the batch, XADD every event onto the Redis
Stream, return — no detector/scoring/DB work happens in the request path,
so ingestion throughput isn't gated by Postgres write latency. See
workers/event_consumer.py for the consumer side.

The stream is trimmed to an approximate max length on every write
(maxlen=..., approximate=True) — if consumers ever fall behind, the stream
self-bounds instead of growing Redis memory without limit (the same
log-flooding/memory-exhaustion concern called out in the spec).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from redis.asyncio import Redis

from marzban_guard.api.deps import get_redis_dep
from marzban_guard.config import get_config
from marzban_guard.logging import get_logger
from marzban_guard.schemas.events import ConnectionEventBatch, IngestAck
from marzban_guard.security import require_ingest_api_key

logger = get_logger("ingest")

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"], dependencies=[Depends(require_ingest_api_key)])

_STREAM_MAXLEN = 200_000


@router.post("/events", response_model=IngestAck)
async def ingest_events(batch: ConnectionEventBatch, redis: Redis = Depends(get_redis_dep)) -> IngestAck:
    if not batch.events:
        return IngestAck(accepted=0)

    stream_name = get_config().redis.stream_name
    pipe = redis.pipeline(transaction=False)
    for event in batch.events:
        pipe.xadd(
            stream_name,
            {"data": event.model_dump_json()},
            maxlen=_STREAM_MAXLEN,
            approximate=True,
        )
    results = await pipe.execute()

    accepted = sum(1 for r in results if r)
    rejected = len(batch.events) - accepted
    if rejected:
        logger.warning("event_type=ingest_partial_failure", node_id=batch.node_id, rejected=rejected)

    return IngestAck(accepted=accepted, rejected=rejected)
