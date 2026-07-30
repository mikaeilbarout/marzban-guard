from __future__ import annotations

from marzban_guard.config import SecurityConfig
from marzban_guard.detectors.base import BaseDetector, DetectorResult
from marzban_guard.schemas.events import ConnectionEvent
from marzban_guard.services.rate_limiter import ConnectionStats


class SpamDetector(BaseDetector):
    """Heuristic spam-relay detector: flags a user connecting to an
    unusually large number of distinct IPs on mail ports (25/465/587 by
    default) in a short window — the standard signature of a spam bot or
    open-relay abuse.

    This is connection-metadata-only (source/destination IP:port,
    protocol) — it cannot see message content, SMTP envelope data, or
    payloads, so it can't distinguish "spamming 40 different mail
    providers" from, in principle, a legitimate mail client with a very
    unusual number of recipients. In practice normal mail clients talk to
    one or two SMTP servers, so this fires almost exclusively on abuse —
    but treat it as one signal among several (SOCKS abuse, proxy
    chaining, and payload-level malware detection all require deep packet
    inspection that is out of scope for connection-metadata monitoring —
    see docs/DATA_SOURCES.md)."""

    name = "spam"

    def evaluate(self, event: ConnectionEvent, stats: ConnectionStats, cfg: SecurityConfig) -> DetectorResult:
        spam_cfg = cfg.spam_detection
        if not spam_cfg.enabled:
            return DetectorResult.clean(self.name)

        if stats.distinct_smtp_destination_ips < spam_cfg.distinct_ip_threshold:
            return DetectorResult.clean(self.name)

        return DetectorResult(
            detector=self.name,
            triggered=True,
            # Reuses the "repeated_suspicious_behavior" weight's sibling —
            # spam relaying is scored at the same severity as a port scan,
            # since a live open relay is comparably damaging to IP
            # reputation for the whole VPN pool.
            score=cfg.scoring.weights.port_scan,
            reason=(
                f"{stats.distinct_smtp_destination_ips} distinct mail-server IPs contacted "
                f"on ports {spam_cfg.ports}"
            ),
            details={
                "distinct_smtp_destination_ips": stats.distinct_smtp_destination_ips,
                "ports": spam_cfg.ports,
            },
        )
