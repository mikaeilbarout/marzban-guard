# What this system can actually see (and what it can't)

Read this before tuning thresholds or promising capabilities to anyone. Every
claim below is scoped to what Xray's access log and Marzban's admin API
*actually* expose — not what would be nice to have.

## Xray's access log (`log.access`) — the primary signal

When Xray's log level is at least `info` (Marzban's default), it logs one line per
accepted or rejected proxy connection:

```
2024/01/15 10:23:45 from 10.20.0.5:53211 accepted tcp:8.8.8.8:443 [inbound -> outbound] email: someusername
```

This gives, per connection attempt:
- **who**: the `email` tag, which Marzban sets to the account's username
- **from**: client IP:port (the VPN client's real endpoint as seen by the node)
- **to**: destination IP:port
- **protocol**: tcp/udp
- **outcome**: accepted (always logged) or rejected (only if the node's log level
  captures it — see below)
- **when**: a node-local, timezone-naive timestamp

This is genuinely enough to build: new-connection-rate limiting, port-scan
detection, destination-IP/port fanout detection, and heuristic spam-relay
detection (`collector/xray_log_collector.py`, `detectors/*.py`).

### What it does NOT give you

- **No connection-close event.** Xray logs the *accept*, never a *close*. There is
  no way to derive an exact "currently open connections" count or a real
  per-connection session duration from this log alone. `ConcurrencyEstimateConfig`
  and `RateLimiter`'s `concurrent_estimate` are a **short rolling-window proxy**
  (connections opened in the last N seconds), not a live gauge of open sockets.
  Don't present it to anyone as exact.

- **No byte counts.** Upload/download volume isn't in this log line at all. All
  traffic-volume and "is this user currently online" data comes from a *separate*
  source: polling Marzban's own per-user accounting via
  `workers/traffic_poller.py`. That, in turn, only exposes one **cumulative**
  `used_traffic` counter per user (not a directional upload/download split) —
  see `TrafficSampleRow`'s docstring in `db/models.py`.

- **No payload visibility.** Nothing here does deep packet inspection. "SOCKS
  abuse", "proxy chaining", and "malware-like traffic patterns" from the original
  requirements are — as connection-metadata-only signals — mostly indistinguishable
  from ordinary heavy use, and are **not implemented as dedicated detectors**.
  `SpamDetector` is the one heuristic in this codebase that gets close (distinct
  mail-server IPs on mail ports), and even it can't see message content. If you
  need real payload-level detection, that requires a different tool entirely
  (e.g. a TLS-terminating proxy with content inspection, which is a fundamentally
  different privacy/architecture trade-off for a VPN service).

- **"Rejected" lines are conditional.** Whether Xray logs rejected connections at
  all — needed for `FailedConnectionDetector` — depends on the node's configured
  log level. Verify this on your actual node before relying on that detector;
  if rejected connections never appear in your log file, that detector will simply
  never fire (a false negative, not a crash).

- **The exact log line format varies across Xray-core versions.** The regex in
  `collector/xray_log_collector.py` (`LOG_LINE_RE`) matches the commonly-documented
  format. **Tail your actual node's log file and compare a real line to that regex
  before trusting this in production** — mismatches fail silently (a line that
  doesn't match is just skipped, logged at INFO, not raised as an error).

## Marzban's admin API — the secondary signal

Used for two things only:
1. **Mitigation**: `PUT /api/user/{username}` to flip `status` active/disabled.
   This is the entire enforcement mechanism — marzban-guard has no lower-level
   access to the node's firewall, iptables, or Xray's runtime config.
2. **Traffic/online polling**: `GET /api/users` (paginated), giving each user's
   cumulative `used_traffic` and an `online_at` timestamp (last time they had
   traffic) — `_is_online()` in `workers/traffic_poller.py` treats "seen in the
   last 5 minutes" as "online", since Marzban doesn't expose a live boolean.

marzban-guard never calls the *create*, *renew*, or *delete* user endpoints —
that's the shop site's job, not this system's.

## "Device" limiting is really "distinct client IP" limiting

`DeviceLimitDetector` / `security.device_limit` counts distinct **client** IPs
per user in a rolling window as a stand-in for "number of devices using this
account". There is no real device fingerprint (no client cert, no app-level
device ID) available from either the Xray access log or Marzban's admin API —
only the source IP:port the node saw the connection arrive from. Concretely:

- Multiple real devices behind one carrier-grade NAT or home router share one
  public IP and will **undercount** as a single "device".
- One real device on a network that rotates IPs mid-session (some mobile
  carriers, some residential ISPs) can **overcount** as multiple "devices".

This is a reasonable, honest proxy for the common case (someone sharing
account credentials with friends/family on genuinely different networks), but
it is not a cryptographically or biometrically verified device count — set
`max_devices` with that margin of error in mind, and treat a triggered
mitigation as "unusually many distinct network paths used this account
recently", not a courtroom-grade claim about device count.

## GeoIP

Destination-country enrichment (`services/geoip.py`) uses a local MaxMind
GeoLite2-Country database, looked up per destination IP. It's best-effort:
missing database file, private/reserved IP ranges, or an unmapped address all
just resolve to "no country" rather than erroring.

## Bottom line for tuning thresholds

Every detector in this system reasons over **connection metadata aggregated in
short time windows** — nothing more. That's a real, useful signal for the
abuse patterns it's built for (rate abuse, scanning, fanout, spam relaying), but
it is not a general-purpose intrusion detection system, and claims beyond what's
described above should not be made to customers or auditors without additional
engineering (e.g. deep packet inspection, which is a different privacy posture
for a VPN product and a decision worth making deliberately, not by accident).
