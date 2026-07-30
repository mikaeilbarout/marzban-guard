"""
GeoIP country lookups for destination IPs (MaxMind GeoLite2-Country),
opened once per process. Optional and fail-soft by design: if
geoip.enabled is false, or the .mmdb file isn't present at geoip.db_path,
country_for() just returns None — a missing GeoIP database should never
block connection processing, only make "top destination country" blank in
the dashboard. See README for where to get a free GeoLite2-Country.mmdb.
"""
from __future__ import annotations

from functools import lru_cache

import geoip2.database
import geoip2.errors

from marzban_guard.config import GeoIPConfig, get_config
from marzban_guard.logging import get_logger

logger = get_logger("geoip")


class GeoIPLookup:
    def __init__(self, cfg: GeoIPConfig):
        self._reader: geoip2.database.Reader | None = None
        if cfg.enabled:
            try:
                self._reader = geoip2.database.Reader(cfg.db_path)
            except (FileNotFoundError, OSError):
                logger.warning("event_type=geoip_db_not_found", path=cfg.db_path)

    def country_for(self, ip: str) -> str | None:
        if not self._reader:
            return None
        try:
            return self._reader.country(ip).country.iso_code
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None


@lru_cache(maxsize=1)
def get_geoip_lookup() -> GeoIPLookup:
    return GeoIPLookup(get_config().geoip)
