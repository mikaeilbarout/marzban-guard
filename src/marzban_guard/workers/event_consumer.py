"""
The consumer side of the ingestion pipeline: reads batches off the Redis
Stream via a consumer group (so multiple worker processes can share the
load and a crashed worker's in-flight batch gets re-delivered, not lost),
runs the full detect -> score -> mitigate pipeline per event, and does
exactly one batched Postgres write per read cycle — one upsert-by-append
per (user, node, minute) into connection_rollups, not one row per raw
connection. See docs/ARCHITECTURE.md#ingestion for the end-to-end picture.

Redelivery is NOT automatic in Redis Streams: a message read via
XREADGROUP's ">" that never gets XACKed (worker crash, unhandled
exception mid-batch) sits in the consumer group's pending-entries list
forever — no amount of further ">" reads brings it back. _process_once()
recovers this via XAUTOCLAIM (_claim_stale_pending) every cycle. One known
residual risk this doesn't solve: if a specific message deterministically
crashes _handle_event every time it's retried (a "poison message"), the
whole batch containing it will fail, stay unacked, and keep getting
reclaimed and retried indefinitely, blocking that batch's progress. A
proper fix (per-message retry count + dead-lettering) is a reasonable
follow-up but isn't implemented here — for now this trades "silently lost
forever" for "loudly stuck and retried forever", which at least shows up
in mg_stream_pending_entries and the worker's exception logs.
"""
from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from datetime import datetime

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from marzban_guard.config import AppConfig
from marzban_guard.db.models import ConnectionRollup
from marzban_guard.detectors.registry import get_detectors, run_all
from marzban_guard.logging import get_logger
from marzban_guard.metrics import (
    connection_events_processed_total,
    detector_triggers_total,
    event_consumer_batch_duration_seconds,
    mitigation_actions_total,
    stream_pending_entries,
)
from marzban_guard.repositories import user_repo
from marzban_guard.schemas.events import ConnectionEvent
from marzban_guard.services.geoip import GeoIPLookup, get_geoip_lookup
from marzban_guard.services.mitigation import MitigationService
from marzban_guard.services.rate_limiter import RateLimiter
from marzban_guard.services.scoring import ScoringEngine

logger = get_logger("event_consumer")

_BATCH_SIZE = 200
_BLOCK_MS = 5000


class EventConsumer:
    def __init__(
        self,
        redis: Redis,
        sessionmaker: async_sessionmaker[AsyncSession],
        mitigation: MitigationService,
        config: AppConfig,
        consumer_id: str,
        geoip: GeoIPLookup | None = None,
        block_ms: int | None = _BLOCK_MS,
    ):
        self._redis = redis
        self._sessionmaker = sessionmaker
        self._mitigation = mitigation
        self._stream = config.redis.stream_name
        self._group = config.redis.consumer_group
        self._consumer_id = consumer_id
        self._security_cfg = config.security
        self._rate_limiter = RateLimiter(redis, config.security)
        self._detectors = get_detectors()
        self._scoring = ScoringEngine(config.security)
        self._geoip = geoip or get_geoip_lookup()
        # None = no BLOCK clause at all (immediate return either way) —
        # used by tests against fakeredis, whose BLOCK support for streams
        # is unreliable. Real deployments keep the default so an idle
        # consumer long-polls instead of busy-looping.
        self._block_ms = block_ms
        self._claim_min_idle_ms = config.worker.claim_min_idle_seconds * 1000

    async def ensure_group(self) -> None:
        try:
            await self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def run_forever(self) -> None:
        await self.ensure_group()
        logger.info("event_type=consumer_started", consumer=self._consumer_id, stream=self._stream, group=self._group)
        while True:
            try:
                await self._process_once()
            except Exception:
                logger.exception("event_type=consumer_iteration_failed")
                await asyncio.sleep(2)

    async def _claim_stale_pending(self) -> list[tuple[str, dict]]:
        """Reclaims entries that were read (by this consumer or a sibling
        that then crashed / threw before acking) and have sat unacked for
        at least claim_min_idle_seconds. XREADGROUP's ">" NEVER redelivers
        these on its own — without this, a mid-batch crash means those
        events are silently never processed again, contradicting this
        class's whole reason for using a consumer group in the first
        place. Safe to call from multiple consumers concurrently: Redis
        only lets one of them win the claim for any given entry."""
        try:
            _cursor, claimed, _deleted = await self._redis.xautoclaim(
                self._stream,
                self._group,
                self._consumer_id,
                min_idle_time=self._claim_min_idle_ms,
                start_id="0-0",
                count=_BATCH_SIZE,
            )
            return claimed
        except Exception:
            logger.exception("event_type=xautoclaim_failed")
            return []

    async def _process_once(self) -> None:
        entries: list[tuple[str, dict]] = await self._claim_stale_pending()

        remaining = _BATCH_SIZE - len(entries)
        if remaining > 0:
            # Don't block if we already have reclaimed work waiting —
            # only wait for new messages when there's truly nothing to do.
            block = None if entries else self._block_ms
            response = await self._redis.xreadgroup(
                self._group, self._consumer_id, {self._stream: ">"}, count=remaining, block=block
            )
            for _stream_name, messages in response or []:
                entries.extend(messages)

        if not entries:
            return

        with event_consumer_batch_duration_seconds.time():
            rollups: dict[tuple[str, str, datetime], dict] = defaultdict(
                lambda: {"tcp": 0, "udp": 0, "ips": set(), "ports": set(), "countries": Counter()}
            )
            ack_ids: list[str] = []

            async with self._sessionmaker() as session:
                for message_id, fields in entries:
                    ack_ids.append(message_id)
                    raw = fields.get("data")
                    if not raw:
                        continue
                    try:
                        event = ConnectionEvent.model_validate_json(raw)
                    except Exception:
                        logger.warning("event_type=invalid_event_payload", message_id=message_id)
                        continue
                    await self._handle_event(session, event, rollups)

                await self._flush_rollups(session, rollups)
                await session.commit()

        if ack_ids:
            await self._redis.xack(self._stream, self._group, *ack_ids)

        pending = await self._redis.xpending(self._stream, self._group)
        if pending:
            stream_pending_entries.set(pending.get("pending", 0))

    async def _handle_event(self, session: AsyncSession, event: ConnectionEvent, rollups: dict) -> None:
        connection_events_processed_total.labels(node_id=event.node_id).inc()

        stats = await self._rate_limiter.record_connection(event)
        triggered = run_all(event, stats, self._security_cfg, self._detectors)
        for result in triggered:
            detector_triggers_total.labels(detector=result.detector).inc()

        outcome = await self._scoring.process_event(session, event, triggered)
        if outcome:
            try:
                await self._mitigation.apply(session, outcome)
                mitigation_actions_total.labels(action="scored", level=str(outcome.level)).inc()
            except Exception:
                # A transient Marzban API failure here (network blip, 5xx)
                # must not sink the WHOLE batch's commit — that would
                # discard the risk-score update and abuse_events row this
                # scoring pass already staged for THIS user, plus every
                # other unrelated user's scoring/rollup writes already
                # staged earlier in the same batch. Safe to isolate:
                # MitigationService always calls the Marzban API before
                # writing anything to the session, so a failure here never
                # leaves a half-written mitigation action behind. The
                # score itself is unaffected and will simply trigger
                # mitigation again on this user's next connection.
                logger.exception("event_type=mitigation_apply_failed", username=event.username, level=outcome.level)

        if event.outcome.value == "accepted":
            window_start = event.occurred_at.replace(second=0, microsecond=0)
            bucket = rollups[(event.username, event.node_id, window_start)]
            bucket["tcp" if event.protocol.value == "tcp" else "udp"] += 1
            bucket["ips"].add(event.destination_ip)
            bucket["ports"].add(event.destination_port)
            country = self._geoip.country_for(event.destination_ip)
            if country:
                bucket["countries"][country] += 1

    async def _flush_rollups(self, session: AsyncSession, rollups: dict) -> None:
        for (username, node_id, window_start), bucket in rollups.items():
            top_country = bucket["countries"].most_common(1)
            session.add(
                ConnectionRollup(
                    username=username,
                    node_id=node_id,
                    window_start=window_start,
                    new_connections_tcp=bucket["tcp"],
                    new_connections_udp=bucket["udp"],
                    distinct_destination_ips=len(bucket["ips"]),
                    distinct_destination_ports=len(bucket["ports"]),
                    top_destination_country=top_country[0][0] if top_country else None,
                )
            )


async def expiry_sweep_forever(
    mitigation: MitigationService, sessionmaker: async_sessionmaker[AsyncSession], interval_seconds: int = 30
) -> None:
    """Reinstates users whose level-3 (temporary) suspension has run out
    (levels 4/5 have no expiry and are never touched here — see
    services/mitigation.py), and refreshes the mg_users_by_status gauge on
    the same cadence since both need a fresh DB read anyway."""
    from sqlalchemy import func, select

    from marzban_guard.db.models import GuardUser, UserStatus
    from marzban_guard.metrics import users_by_status

    while True:
        try:
            async with sessionmaker() as session:
                expired = await user_repo.expired_suspensions(session, datetime.utcnow())
                for user in expired:
                    await mitigation.reinstate_expired(session, user)
                if expired:
                    await session.commit()

                counts = await session.execute(
                    select(GuardUser.status, func.count(GuardUser.username)).group_by(GuardUser.status)
                )
                seen = {status: 0 for status in UserStatus}
                for status, count in counts:
                    seen[status] = count
                for status, count in seen.items():
                    users_by_status.labels(status=status.value).set(count)
        except Exception:
            logger.exception("event_type=expiry_sweep_failed")
        await asyncio.sleep(interval_seconds)
