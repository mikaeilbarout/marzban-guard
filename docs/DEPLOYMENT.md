# Deployment guide

Two separate things get deployed:
1. **The central service** (Postgres, Redis, `api`, `worker`, Prometheus, Grafana)
   — one docker-compose stack, one place.
2. **The collector** — a single Python file installed via SSH on **every**
   Marzban/Xray node you want abuse detection on.

## 1. Central service

```bash
git clone <this repo>
cd marzban-guard
cp .env.example .env
cp config/config.example.yaml config/config.yaml
```

Edit `.env`:
- `POSTGRES_PASSWORD` — anything random.
- `MARZBAN_ADMIN_USERNAME` / `MARZBAN_ADMIN_PASSWORD` — a Marzban admin account
  marzban-guard can use to call `PUT /api/user/{username}` and `GET /api/users`.
  A dedicated admin account (not your personal one) is recommended so its access
  can be revoked independently.
- `INGEST_API_KEY` — generate with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`.
  This same value goes into every node's collector config (step 2).
- `ADMIN_API_KEY` — same idea, for the admin dashboard API.
- Optionally `ADMIN_TELEGRAM_BOT_TOKEN` / `ADMIN_TELEGRAM_CHAT_ID` and/or
  `MARZBAN_GUARD_WEBHOOK_URL` for level-2+ alerts.

Edit `config/config.yaml`:
- `marzban.base_url` — your Marzban panel's URL.
- Tune `security.*` — see [`ARCHITECTURE.md`](ARCHITECTURE.md#scoring-algorithm)
  for what each knob does. The defaults are reasonable starting points, not
  guarantees for your traffic pattern — consider running with
  `security.mitigation.auto_block.enabled: false` (dry-run) for the first while
  to see what would have triggered before trusting it to act.

Bring it up:

```bash
docker compose up -d postgres redis
docker compose run --rm migrate     # applies migrations/versions/0001_initial.py
docker compose up -d api worker prometheus grafana
```

Verify:

```bash
curl http://localhost:8000/healthz
curl http://localhost:8000/readyz
curl -H "Authorization: Bearer $ADMIN_API_KEY" http://localhost:8000/api/v1/admin/stats
```

Grafana is at `http://localhost:3000` (default login `admin` /
`$GRAFANA_ADMIN_PASSWORD` from `.env`, defaulting to `change_me` — change it), with
the "marzban-guard overview" dashboard pre-provisioned.

### GeoIP (optional)

Download a free `GeoLite2-Country.mmdb` (see README) and mount it into the
`geoip_data` volume at `/data/GeoLite2-Country.mmdb`, e.g.:

```bash
docker compose cp GeoLite2-Country.mmdb api:/data/GeoLite2-Country.mmdb
```

Restart `api` and `worker` afterward. Without it, `geoip.enabled` should be set
to `false` (or just leave it — lookups fail soft and log a warning once).

### Shop integration (optional)

If you run a customer-facing shop (e.g. Freemiga) in front of the same
Marzban panel, set `SHOP_BASE_URL` and `SHOP_WEBHOOK_SECRET` in `.env` so
the shop's own ban flag/customer notice stays in sync whenever
marzban-guard suspends, disables, blacklists, or reinstates an account —
see [`ARCHITECTURE.md#shop-integration`](ARCHITECTURE.md#shop-integration-keeping-the-storefront-in-sync).
`SHOP_WEBHOOK_SECRET` must match the shop's own
`MARZBAN_GUARD_WEBHOOK_SECRET`. Leave `SHOP_BASE_URL` empty (the default)
to skip this entirely — marzban-guard still enforces restrictions
directly against Marzban either way.

## 2. Node-side collector (repeat for every Xray/Marzban node)

The collector is stdlib-only Python — no pip install, no venv required.

**Find your Xray access log path first.** For a standard Marzban node install,
check the Xray config Marzban generates (commonly under the node's data
directory, referenced by the `log.access` field in `xray_config.json`), or run
`docker exec <marzban-node-container> cat /var/lib/marzban-node/xray_config.json`
(path varies by install) and look for the `"log"` section.

**Verify the log format before trusting this in production**:

```bash
tail -f /path/to/xray-access.log
```

Compare a real line against `LOG_LINE_RE` in `collector/xray_log_collector.py` —
Xray-core's exact wording has changed across versions. If it doesn't match,
adjust the regex (it's one constant, well-commented) before deploying further.

**Install:**

```bash
# On the node, as root:
mkdir -p /opt/marzban-guard /etc/marzban-guard /var/lib/marzban-guard
scp collector/xray_log_collector.py root@node:/opt/marzban-guard/
scp collector/systemd/marzban-guard-collector.service root@node:/etc/systemd/system/
scp collector/collector.env.example root@node:/etc/marzban-guard/collector.env

# Edit /etc/marzban-guard/collector.env on the node:
#   - MG_INGEST_URL      -> https://<your central service host>
#   - MG_INGEST_API_KEY  -> same value as INGEST_API_KEY in the central .env
#   - MG_NODE_ID         -> a short unique name for this node, e.g. "node-1"
#   - MG_XRAY_ACCESS_LOG_PATH -> the path you verified above

chmod 600 /etc/marzban-guard/collector.env

useradd --system --no-create-home --shell /usr/sbin/nologin marzban-guard || true
chown -R marzban-guard:marzban-guard /var/lib/marzban-guard

systemctl daemon-reload
systemctl enable --now marzban-guard-collector
systemctl status marzban-guard-collector
journalctl -u marzban-guard-collector -f
```

You should see `event_type=collector_starting` in the journal, and — once
traffic flows — events start appearing via
`GET /api/v1/admin/users/active` on the central service (or just watch
`mg_connection_events_processed_total` climb at `/metrics`).

### Firewall / network note

The collector only makes **outbound** HTTPS calls to the central service's
`/api/v1/ingest/events` — no inbound port needs to be opened on the VPN node for
this system. Put the central service behind your own TLS termination (nginx,
Caddy, Cloudflare, etc.) the same way you would any other internal API — this
repo doesn't include a reverse proxy config, since that's typically shared
infrastructure with whatever else you already run.

## 3. Rolling out safely

1. Deploy the central service and **at least one** collector with
   `security.mitigation.auto_block.enabled: false` in `config.yaml`.
2. Watch the Grafana dashboard and `/api/v1/admin/users/most-suspicious` for a
   few days. Adjust `security.*` thresholds based on what your actual traffic
   looks like — the shipped defaults are starting points, not calibrated to any
   specific deployment.
3. Flip `auto_block.enabled: true` once you're confident the thresholds aren't
   flagging legitimate heavy users. Restart `worker` to pick up the change
   (config is loaded once per process and cached — see `config.get_config()`).
4. Roll the collector out to remaining nodes the same way.
