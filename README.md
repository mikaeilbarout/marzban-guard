# marzban-guard

A production-grade abuse detection & mitigation system for VPN services built on
[Marzban](https://github.com/Gozargah/Marzban) + Xray-core. It watches connection
behavior per user, scores it against a pluggable set of detectors (port scanning,
connection-rate abuse, destination fanout, device/concurrent-connection limits,
spam relaying, failed-connection bursts), and automatically escalates through logging → admin notification → temporary
suspension → disable → permanent blacklist — all through the same Marzban admin API
your shop site already uses to provision accounts.

This is a **separate system** from your customer-facing shop/dashboard. It only ever
*restricts* an existing Marzban account; it never creates, renews, or deletes one. The
two systems share no database and don't call each other's internal APIs — the only
connection is an optional one-way callback (`shop_integration.*`) so the shop's own
ban flag/customer notice stays in sync whenever marzban-guard changes an account's
status. See `docs/ARCHITECTURE.md#shop-integration-keeping-the-storefront-in-sync`.

See:
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how the pieces fit together, the
  scoring algorithm, storage model, and design trade-offs.
- [`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md) — **read this first** — an honest
  account of what Xray's access log and Marzban's admin API actually give you, and
  what they don't (this shapes what detection is and isn't possible).
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — step-by-step production deployment,
  including installing the node-side collector via SSH.

## Components

| Component | Runs where | What it does |
|---|---|---|
| `api` (FastAPI) | Central server | Ingests events, serves the admin dashboard API, `/metrics`, health checks |
| `worker` | Central server | Consumes events, runs detectors, scores, mitigates, polls traffic |
| `xray_log_collector.py` | **Each Xray/Marzban node** | Tails Xray's access log, ships connection events to the API |
| Postgres | Central server | Users, abuse events, mitigation actions, blacklist, connection/traffic history |
| Redis | Central server | Event stream (ingestion buffer), sliding-window rate counters, fanout tracking |
| Prometheus + Grafana | Central server (optional) | Metrics and dashboards |

## Quickstart (local / staging)

```bash
cp .env.example .env            # fill in real secrets
cp config/config.example.yaml config/config.yaml   # adjust limits/thresholds
docker compose up -d postgres redis
docker compose run --rm migrate
docker compose up -d api worker prometheus grafana
```

Then install the collector on each Xray node — see
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Running tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cp config/config.example.yaml config/config.yaml
export MARZBAN_GUARD_CONFIG=config/config.example.yaml \
       POSTGRES_PASSWORD=test MARZBAN_ADMIN_USERNAME=test MARZBAN_ADMIN_PASSWORD=test \
       INGEST_API_KEY=test ADMIN_API_KEY=test
.venv/bin/python -m pytest
```

Tests run against SQLite + fakeredis (no external services needed) — see
`tests/conftest.py`. docker-compose.yml is what actually runs against real
Postgres/Redis.

## GeoIP (optional)

Connection rollups include a "top destination country" field, populated from a
local MaxMind GeoLite2-Country database. It's optional — without it, that field is
just blank. Get a free copy from
[MaxMind's GeoLite2 signup](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data),
place it at the path configured in `geoip.db_path`, and set `geoip.enabled: true`.

## Extending: adding a new detector

1. Subclass `BaseDetector` in a new file under `src/marzban_guard/detectors/`.
2. Add it to `_DETECTOR_CLASSES` in `src/marzban_guard/detectors/registry.py`.

That's it — the scoring engine, admin API, and dashboards all pick it up
automatically since they only ever see `DetectorResult` objects, not
detector-specific code.

## License

Internal tool — no license file included; add one if you intend to open-source it.
