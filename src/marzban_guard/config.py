"""
Loads config/config.yaml (path overridable via MARZBAN_GUARD_CONFIG) into
typed, validated Pydantic models. ${ENV_VAR} placeholders anywhere in the
YAML are substituted from the process environment before parsing — this is
how secrets (DB password, Marzban admin creds, API keys) stay out of the
committed YAML. An unresolved placeholder becomes an empty string rather
than a hard error, since some of them (Telegram alerts, webhook) are
genuinely optional.

Call get_config() to obtain the singleton — it's loaded once per process
and cached.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

_DURATION_RE = re.compile(r"^(\d+)\s*(s|m|h|d)$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: str | int) -> int:
    """Parses a config duration like "1h", "30m", "45s" into seconds. Plain
    integers are passed through unchanged (already-seconds)."""
    if isinstance(value, int):
        return value
    match = _DURATION_RE.match(value.strip())
    if not match:
        raise ValueError(f"Invalid duration string: {value!r} (expected e.g. '1h', '30m', '45s')")
    amount, unit = match.groups()
    return int(amount) * _DURATION_UNITS[unit]


def _interpolate_env(raw: str) -> str:
    return _ENV_VAR_RE.sub(lambda m: os.environ.get(m.group(1), ""), raw)


class ServiceConfig(BaseModel):
    environment: str = "production"
    log_level: str = "INFO"


class DatabaseConfig(BaseModel):
    url: str
    pool_size: int = 10
    max_overflow: int = 20


class RedisConfig(BaseModel):
    url: str = "redis://localhost:6379/0"
    stream_name: str = "mg:events"
    consumer_group: str = "mg-workers"
    key_ttl_seconds: int = 3600


class MarzbanConfig(BaseModel):
    base_url: str
    admin_username: str
    admin_password: str
    request_timeout_seconds: int = 15


class GeoIPConfig(BaseModel):
    enabled: bool = True
    db_path: str = "/data/GeoLite2-Country.mmdb"


class ScanDetectionConfig(BaseModel):
    enabled: bool = True
    window_seconds: int = 60
    port_threshold: int = 80
    ip_threshold: int = 50
    # A true port scan is many distinct ports concentrated on a FEW hosts —
    # this distinguishes that from a P2P/torrent client naturally touching
    # many different ports across many different peer IPs, which trips
    # port_threshold too but isn't scanning anything.
    port_scan_max_distinct_ips: int = 5
    # Hard cap on how many distinct destination IPs/ports are tracked per
    # user per window — protects Redis memory from a single user's fanout
    # growing unbounded (requirement: "protect against memory exhaustion").
    # Hitting the cap is itself a strong abuse signal, so counts saturate
    # rather than silently stop being useful.
    max_tracked_destinations: int = 2000


class ConcurrencyEstimateConfig(BaseModel):
    # Xray's access log has no "connection closed" event, so true
    # concurrency isn't directly observable — this is a short rolling
    # window used as a practical proxy (see docs/DATA_SOURCES.md).
    window_seconds: int = 10


class DeviceLimitConfig(BaseModel):
    """Distinct-device enforcement — approximated by counting distinct
    client IPs seen for a user within a rolling window, since neither
    Xray's access log nor Marzban's admin API expose a real device
    fingerprint (see docs/DATA_SOURCES.md). This under-counts when several
    real devices share one IP (carrier-grade NAT, a home router), and can
    over-count a single device whose IP rotates mid-session — tune
    max_devices and window_minutes with that in mind, and treat it as "how
    many distinct network paths are using this account right now", not a
    literal device count."""

    enabled: bool = True
    max_devices: int = 2
    # How long a client IP keeps "counting" as a currently-active device
    # after its last connection — long enough that normal reconnects
    # (network switch, app backgrounding) don't look like a new device,
    # short enough that someone who's genuinely stopped using a device
    # drops out of the count reasonably soon.
    window_minutes: int = 15


class SpamDetectionConfig(BaseModel):
    """Heuristic, not deep packet inspection: flags a user relaying to an
    unusually large number of distinct mail-server IPs on mail ports in a
    short window — the classic signature of a spam bot / open relay abuse.
    Reuses scan_detection's window/cap rather than adding a third set of
    knobs for what is, mechanically, the same kind of fanout tracking."""

    enabled: bool = True
    ports: list[int] = Field(default_factory=lambda: [25, 465, 587])
    distinct_ip_threshold: int = 30


class ScoringWeights(BaseModel):
    high_connection_rate: int = 40
    port_scan: int = 60
    too_many_destination_ips: int = 35
    too_many_destination_ports: int = 35
    repeated_suspicious_behavior: int = 80
    failed_connection_burst: int = 30
    # Matches thresholds.level_3 by default so exceeding the device cap
    # alone is enough to trigger a temporary suspension immediately,
    # without waiting on other signals or a repeat offense.
    device_limit_exceeded: int = 80


class ScoringThresholds(BaseModel):
    level_1: int = 20
    level_2: int = 50
    level_3: int = 80
    level_4: int = 120
    level_5: int = 160


class ScoringConfig(BaseModel):
    weights: ScoringWeights = Field(default_factory=ScoringWeights)
    decay_half_life_seconds: int = 1800
    # Minimum gap since this user's last flagged event before a new
    # trigger counts as a genuinely SEPARATE repeat offense (and earns the
    # repeated_suspicious_behavior bonus). Without this, one sustained
    # burst — e.g. a single port scan spanning 80 connections processed a
    # few milliseconds apart — would retrigger the same detector dozens of
    # times and compound the bonus every single time, rocketing an
    # ordinary single incident straight to a level-5 blacklist. This
    # keeps "repeated" meaning "happened again later", not "is still
    # happening right now".
    repeat_offense_min_gap_seconds: int = 60
    thresholds: ScoringThresholds = Field(default_factory=ScoringThresholds)


class AutoBlockConfig(BaseModel):
    # Master switch for levels 3-5 actually restricting access via the
    # Marzban API. False = dry-run / monitor-only: scoring, logging, and
    # admin notifications all still happen, nothing gets suspended.
    enabled: bool = True
    # How long a level-3 (temporary suspend) action lasts before the
    # worker's expiry sweep auto-reinstates the user. Levels 4/5 ignore
    # this entirely — they require manual admin review, see
    # level_4_requires_manual_reenable below and the blacklist_entries table.
    duration: str = "1h"

    @property
    def duration_seconds(self) -> int:
        return parse_duration(self.duration)


class MitigationConfig(BaseModel):
    level_4_requires_manual_reenable: bool = True
    auto_block: AutoBlockConfig = Field(default_factory=AutoBlockConfig)
    # Minimum gap between repeated "notify admin" alerts for the same user
    # while their score stays in the level-2 band, so a sustained abuse
    # burst sends one alert, not one per connection.
    notify_cooldown_seconds: int = 900


class PerUserOverride(BaseModel):
    connection_limit_per_minute: int | None = None
    connection_limit_per_hour: int | None = None
    concurrent_limit: int | None = None
    max_devices: int | None = None


class SecurityConfig(BaseModel):
    connection_limit_per_minute: int = 150
    connection_limit_per_hour: int = 5000
    concurrent_limit: int = 100
    # Rejected/failed connection attempts per minute before
    # FailedConnectionDetector fires — repeated failures are the signature
    # of a misconfigured/automated client hammering a dead target, or
    # credential/endpoint probing. Only meaningful if the node's Xray log
    # level is turned up enough to emit "rejected" lines — see
    # docs/DATA_SOURCES.md.
    failed_connection_threshold_per_minute: int = 50
    scan_detection: ScanDetectionConfig = Field(default_factory=ScanDetectionConfig)
    concurrency_estimate: ConcurrencyEstimateConfig = Field(default_factory=ConcurrencyEstimateConfig)
    device_limit: DeviceLimitConfig = Field(default_factory=DeviceLimitConfig)
    spam_detection: SpamDetectionConfig = Field(default_factory=SpamDetectionConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    mitigation: MitigationConfig = Field(default_factory=MitigationConfig)
    per_user_overrides: dict[str, PerUserOverride] = Field(default_factory=dict)

    def limits_for(self, username: str) -> EffectiveLimits:
        override = self.per_user_overrides.get(username)
        return EffectiveLimits(
            connection_limit_per_minute=(override.connection_limit_per_minute if override else None)
            or self.connection_limit_per_minute,
            connection_limit_per_hour=(override.connection_limit_per_hour if override else None)
            or self.connection_limit_per_hour,
            concurrent_limit=(override.concurrent_limit if override else None) or self.concurrent_limit,
            max_devices=(override.max_devices if override else None) or self.device_limit.max_devices,
        )


class EffectiveLimits(BaseModel):
    connection_limit_per_minute: int
    connection_limit_per_hour: int
    concurrent_limit: int
    max_devices: int


class NotificationsConfig(BaseModel):
    admin_telegram_bot_token: str = ""
    admin_telegram_chat_id: str = ""
    webhook_url: str = ""


class IngestConfig(BaseModel):
    api_key: str = ""


class AdminApiConfig(BaseModel):
    api_key: str = ""


class ShopIntegrationConfig(BaseModel):
    """marzban-guard never touches the shop's database directly — this is
    a best-effort callback so the shop's own ban flag (and its
    customer-facing dashboard/Telegram notice) stays in sync with a
    restriction already enforced directly against Marzban. Leave
    base_url empty to disable it entirely; nothing about mitigation
    itself depends on this succeeding. Distinct from
    notifications.webhook_url, which is an admin alert (Slack/Discord
    style), not this shop-state callback."""

    base_url: str = ""
    webhook_secret: str = ""
    request_timeout_seconds: int = 10


class WorkerConfig(BaseModel):
    # How many EventConsumer instances to run concurrently in-process
    # (each with its own consumer_id in the same Redis consumer group) —
    # cheap horizontal scaling within one worker process before you need
    # to run multiple worker containers.
    consumer_concurrency: int = 2
    expiry_sweep_interval_seconds: int = 30
    traffic_poll_interval_seconds: int = 60
    # A message read via XREADGROUP but never XACKed (worker crashed or
    # threw mid-batch) sits in the consumer group's pending-entries list
    # FOREVER — Redis never redelivers it on its own, no matter how many
    # times you call XREADGROUP with ">". This is how long an entry must
    # have been idle (unclaimed/unacked) before EventConsumer reclaims it
    # via XAUTOCLAIM and retries it. Too short risks reclaiming a batch a
    # sibling consumer is still legitimately (slowly) processing.
    claim_min_idle_seconds: int = 60
    # The worker is a separate process from the API, so its
    # prometheus_client counters live in a separate registry — it needs
    # its own /metrics HTTP server for Prometheus to scrape (see
    # main_worker.py). Set to 0 to disable.
    metrics_port: int = 9100
    # Label attached to every TrafficSampleRow — the traffic poller talks
    # to one Marzban panel (which may itself front several Xray nodes), so
    # this is a fixed identifier for "the panel", not a specific node.
    marzban_node_id: str = "marzban"


class AppConfig(BaseModel):
    service: ServiceConfig = Field(default_factory=ServiceConfig)
    database: DatabaseConfig
    redis: RedisConfig = Field(default_factory=RedisConfig)
    marzban: MarzbanConfig
    geoip: GeoIPConfig = Field(default_factory=GeoIPConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    ingest: IngestConfig = Field(default_factory=IngestConfig)
    admin_api: AdminApiConfig = Field(default_factory=AdminApiConfig)
    worker: WorkerConfig = Field(default_factory=WorkerConfig)
    shop_integration: ShopIntegrationConfig = Field(default_factory=ShopIntegrationConfig)


def _config_path() -> Path:
    return Path(os.environ.get("MARZBAN_GUARD_CONFIG", "config/config.yaml"))


def load_config(path: Path | None = None) -> AppConfig:
    """Reads + validates the YAML config file. Not cached — use get_config()
    in application code; this is exposed separately so tests can load a
    fixture config without touching the process-wide cache."""
    path = path or _config_path()
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found at {path}. Copy config/config.example.yaml to "
            f"{path} (or set MARZBAN_GUARD_CONFIG) and fill it in."
        )
    raw = path.read_text()
    interpolated = _interpolate_env(raw)
    data = yaml.safe_load(interpolated) or {}
    return AppConfig.model_validate(data)


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    return load_config()
