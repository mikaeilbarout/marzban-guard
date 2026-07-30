# Architecture

Read [`DATA_SOURCES.md`](DATA_SOURCES.md) first — it explains what signal is
actually available; this document explains what's built on top of it.

## End-to-end flow

```
 Xray/Marzban node                    Central service
┌────────────────────┐               ┌─────────────────────────────────────────┐
│ Xray access log     │               │  FastAPI (api)                         │
│        │            │  HTTPS POST   │  POST /api/v1/ingest/events            │
│        ▼            │  (batched)    │        │                              │
│ xray_log_collector  │──────────────▶│        ▼  XADD (pipelined)             │
│  (tail + parse +    │               │  Redis Stream "mg:events"              │
│   batch + retry)    │               │        │                              │
└────────────────────┘               │        ▼  XREADGROUP (consumer group)  │
                                       │  worker: EventConsumer                 │
                                       │   ├─ RateLimiter (Redis counters)      │
                                       │   ├─ detectors.run_all()               │
                                       │   ├─ ScoringEngine.process_event()     │
                                       │   ├─ MitigationService.apply()         │
                                       │   └─ batched ConnectionRollup upsert   │
                                       │        │                              │
                                       │        ▼                              │
                                       │  Postgres (guard_users, abuse_events,  │
                                       │  mitigation_actions, blacklist_entries,│
                                       │  connection_rollups, traffic_samples)  │
                                       │                                        │
                                       │  worker: TrafficPoller ──▶ Marzban API │
                                       │  worker: expiry_sweep_forever          │
                                       │                                        │
                                       │  api: /api/v1/admin/* (dashboard)      │
                                       │  api, worker: /metrics (Prometheus)    │
                                       └─────────────────────────────────────────┘
```

Ingestion (`api/routes/ingest.py`) and processing (`workers/event_consumer.py`)
are deliberately decoupled by the Redis Stream: the HTTP endpoint just validates
and `XADD`s (cheap, can't be slowed down by Postgres), while one or more worker
processes pull batches via a consumer group — so a crashed worker's in-flight
batch is redelivered (`XREADGROUP` + `XACK`), and you can scale workers
horizontally independent of API replicas.

## Storage: why so little is per-connection

At "thousands of users" scale, writing one Postgres row per raw connection would
dominate everything. So:

- **Raw connection data lives only in Redis**, in O(1)-per-op structures with
  TTLs (`services/rate_limiter.py`) — sliding-window counters (2 fixed buckets,
  weighted-average estimate) for rates, and TTL'd sets (hard-capped in size) for
  destination-IP/port fanout tracking. Nothing here grows without bound, even
  under sustained abuse from one user (see `max_tracked_destinations`).

- **Postgres only ever gets three kinds of writes**:
  1. `abuse_events` — one row per detector trigger (not per connection). A clean
     connection writes nothing at all.
  2. `connection_rollups` — one row per (user, node, minute), written once per
     worker batch as a single batched `session.add_all`-style flush, aggregating
     however many raw connections happened in that window.
  3. `traffic_samples` — one row per user per traffic-poll cycle (default 60s),
     also a single batched insert per cycle.

This is the concrete answer to the "batch writes where appropriate" and "avoid
unbounded storage growth" requirements: aggregate before you persist, and never
let a single user's activity grow a data structure without a cap.

## Scoring algorithm

`services/scoring.py`. Each user has one `risk_score` (float, stored on
`guard_users`), updated only when at least one detector triggers on a
connection event:

1. **Decay**: the previous score is decayed exponentially based on elapsed time
   since it was last touched, with a configurable half-life
   (`scoring.decay_half_life_seconds`). This isn't a ticking background job —
   it's recomputed lazily from `(stored_score, elapsed_time)` whenever the row
   is next touched, or on read via `effective_score()` for dashboards.
2. **New points**: every triggered detector's `score` is summed.
3. **Repeat-offender bonus**: if the user's *decayed* score is still nonzero
   **and** at least `scoring.repeat_offense_min_gap_seconds` has passed since
   their last flagged event, an extra `repeated_suspicious_behavior` bonus is
   added. That gap check is load-bearing: without it, one sustained burst (e.g.
   a single 80-connection port scan processed a few milliseconds apart) would
   retrigger the same detector dozens of times and compound the bonus every
   single time, rocketing one ordinary incident straight to a level-5
   blacklist. The gap makes "repeated" mean "happened again later", not
   "is still happening right now" — see `tests/unit/test_scoring.py`'s
   `test_burst_of_triggers_within_the_same_incident_does_not_compound` for the
   regression test that caught this during development.
4. The resulting total maps to a mitigation level via
   `scoring.thresholds.level_1..level_5` (highest threshold met wins).

## Mitigation state machine

`services/mitigation.py`. Levels only ever **escalate** automatically:

| Level | Action | Reversible how |
|---|---|---|
| 1 | Log only | n/a |
| 2 | + notify admin (rate-limited by `notify_cooldown_seconds`) | n/a |
| 3 | + temporary suspend (Marzban `status=disabled`) | Auto-reinstated by `expiry_sweep_forever` once `status_expires_at` passes |
| 4 | + disable | **Manual only** — `POST /api/v1/admin/users/{u}/override` |
| 5 | + permanent blacklist (+ `blacklist_entries` row) | **Manual only** — `POST /api/v1/admin/blacklist/{id}/review` |

A falling score never automatically downgrades a level-4/5 status — that
requires an admin to look at it, per the spec's "requires manual review" intent.
`security.mitigation.auto_block.enabled: false` turns levels 3-5 into a dry-run
(logs + notifies "would have escalated", never calls Marzban) — useful for
tuning thresholds against real traffic before trusting the system to act.

## Detector plugin framework

`detectors/base.py` + `detectors/registry.py`. Every detector is a small, pure,
synchronous function of `(event, stats, config) -> DetectorResult` — no Redis or
DB access inside a detector, since all the state it needs (`ConnectionStats`) was
already gathered by `RateLimiter` beforehand. That's what makes detectors:
- trivial to unit test (construct an event/stats pair, assert on the result), and
- trivial to add (subclass `BaseDetector`, add one line to `_DETECTOR_CLASSES`).

Shipped detectors: `ConnectionRateDetector`, `PortScanDetector` (concentrated
port probing on few hosts), `DestinationFanoutDetector` (broad IP/port fanout
regardless of concentration — deliberately separate from port-scan so a P2P
client touching many peers on many ports doesn't get misclassified as scanning),
`SpamDetector` (heuristic SMTP-fanout), `FailedConnectionDetector`.

## Observability

- `/healthz` — liveness only (process is up). Never checks dependencies, so a
  slow Postgres doesn't get the pod killed and restarted for no reason.
- `/readyz` — readiness: actually pings Postgres and Redis.
- `/metrics` — on **both** the API and the worker. They're separate processes
  with separate `prometheus_client` registries, so the worker runs its own
  metrics HTTP server (`worker.metrics_port`, default 9100) — see
  `main_worker.py`. Forgetting this would mean every detector-trigger and
  mitigation-action counter (incremented in the worker) silently never showed
  up in Prometheus, since only the API process would have been scraped.
- `docker/grafana/dashboards/overview.json` — a starter dashboard wired to both
  scrape targets via the provisioned Prometheus datasource.

## Security notes

- Ingestion and admin APIs are both gated by a static bearer token
  (`security.py`), compared with `hmac.compare_digest` to avoid timing attacks.
  An unset key fails closed (503), not open.
- The Redis stream is trimmed to an approximate max length on every write
  (`maxlen=200_000, approximate=True`) — if consumers fall behind, the stream
  self-bounds instead of growing Redis memory without limit.
- The node-side collector caps its own in-memory buffer
  (`MG_MAX_BUFFERED_EVENTS`, default 50,000) and drops the oldest events (with a
  logged warning) rather than growing without bound if the central API is
  unreachable for an extended period.
- Destination-IP/port fanout tracking is hard-capped
  (`scan_detection.max_tracked_destinations`) per user per window — the same
  memory-exhaustion protection, applied to the Redis side.
