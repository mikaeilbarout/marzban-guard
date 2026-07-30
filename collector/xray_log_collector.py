#!/usr/bin/env python3
"""
Runs ON the Marzban/Xray node (not in this repo's Docker Compose stack —
see docs/DEPLOYMENT.md for the systemd install). Tails Xray's access log,
parses each accepted/rejected-connection line into the same
ConnectionEvent shape the central service expects, batches them, and POSTs
to POST /api/v1/ingest/events.

Deliberately stdlib-only (no pip install, no venv) so it's a one-file
`scp` + systemd unit away from running on a bare VPN node — see
docs/DEPLOYMENT.md. If you'd rather manage a venv there, nothing stops
you; it's just not required.

IMPORTANT — verify the log format before trusting this in production. The
regex below matches the commonly-documented Xray access-log line shape:

    2024/01/15 10:23:45 from 10.20.0.5:53211 accepted tcp:8.8.8.8:443 \
        [inbound -> outbound] email: someusername

but the exact wording/spacing has changed across Xray-core versions, and
Marzban's default log.access / xray template controls whether it's
enabled at all (loglevel must be at least "info", i.e. NOT "none"/"error").
Tail the actual file on your node and compare a real line to LOG_LINE_RE
before relying on this in production. See docs/DATA_SOURCES.md.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

logging.basicConfig(
    level=os.environ.get("MG_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("xray_log_collector")

LOG_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+"
    r"from\s+(?P<client_ip>[^\s:]+|\[[0-9a-fA-F:]+\]):(?P<client_port>\d+)\s+"
    r"(?P<outcome>accepted|rejected)\s+"
    r"(?P<protocol>tcp|udp):(?P<dest_ip>[^\s:]+|\[[0-9a-fA-F:]+\]):(?P<dest_port>\d+)"
    r".*?email:\s*(?P<email>\S+)"
)


@dataclass
class CollectorConfig:
    ingest_url: str
    api_key: str
    node_id: str
    log_path: str
    state_file: str
    batch_size: int = 200
    batch_interval_seconds: float = 2.0
    max_buffered_events: int = 50_000
    email_strip_suffix_at: str = ""  # e.g. "." if Marzban's email tag is "username.uuid"
    poll_interval_seconds: float = 0.5
    request_timeout_seconds: float = 10.0

    @classmethod
    def from_env(cls) -> CollectorConfig:
        required = ["MG_INGEST_URL", "MG_INGEST_API_KEY", "MG_NODE_ID", "MG_XRAY_ACCESS_LOG_PATH"]
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise SystemExit(f"Missing required environment variables: {', '.join(missing)}")
        return cls(
            ingest_url=os.environ["MG_INGEST_URL"].rstrip("/"),
            api_key=os.environ["MG_INGEST_API_KEY"],
            node_id=os.environ["MG_NODE_ID"],
            log_path=os.environ["MG_XRAY_ACCESS_LOG_PATH"],
            state_file=os.environ.get("MG_STATE_FILE", "/var/lib/marzban-guard/collector.state"),
            batch_size=int(os.environ.get("MG_BATCH_SIZE", "200")),
            batch_interval_seconds=float(os.environ.get("MG_BATCH_INTERVAL_SECONDS", "2")),
            max_buffered_events=int(os.environ.get("MG_MAX_BUFFERED_EVENTS", "50000")),
            email_strip_suffix_at=os.environ.get("MG_EMAIL_STRIP_SUFFIX_AT", ""),
        )


@dataclass
class TailState:
    inode: int | None = None
    offset: int = 0


class LogTailer:
    """Polling-based `tail -F` equivalent: follows the file by byte
    offset, and transparently reopens from the start if the inode changes
    (log rotation) or the file shrinks (truncation) — no inotify/watchdog
    dependency required."""

    def __init__(self, path: str, state_file: str, poll_interval: float):
        self._path = path
        self._state_file = state_file
        self._poll_interval = poll_interval
        self._state = self._load_state()
        self._fh = None

    def _load_state(self) -> TailState:
        try:
            with open(self._state_file) as f:
                data = json.load(f)
                return TailState(inode=data.get("inode"), offset=data.get("offset", 0))
        except (FileNotFoundError, json.JSONDecodeError):
            return TailState()

    def save_state(self) -> None:
        os.makedirs(os.path.dirname(self._state_file), exist_ok=True)
        tmp = f"{self._state_file}.tmp"
        with open(tmp, "w") as f:
            json.dump({"inode": self._state.inode, "offset": self._state.offset}, f)
        os.replace(tmp, self._state_file)

    def _ensure_open(self) -> bool:
        try:
            st = os.stat(self._path)
        except FileNotFoundError:
            return False
        current_inode = st.st_ino

        # `logrotate`'s copytruncate strategy (common for daemons that
        # can't be told to reopen their log file) truncates the file IN
        # PLACE — same inode, size suddenly smaller than our saved offset.
        # Inode-only rotation detection misses this entirely: seeking to
        # a stale offset past the new (small) end of file would silently
        # skip everything written after the truncation until the file
        # grows past that stale offset again, at which point reads would
        # resume at the wrong byte boundary. Treat "smaller than expected"
        # as a truncation regardless of inode.
        truncated = current_inode == self._state.inode and st.st_size < self._state.offset

        if self._fh is None or current_inode != self._state.inode or truncated:
            if self._fh:
                self._fh.close()
            self._fh = open(self._path, errors="replace")
            if current_inode == self._state.inode and not truncated:
                self._fh.seek(self._state.offset)
            else:
                logger.info(
                    "event_type=log_rotated_or_first_open inode=%s truncated=%s", current_inode, truncated
                )
                self._state = TailState(inode=current_inode, offset=0)
        return True

    def poll_lines(self) -> list[str]:
        if not self._ensure_open():
            return []
        lines = self._fh.readlines()
        self._state.offset = self._fh.tell()
        return lines

    def sleep(self) -> None:
        time.sleep(self._poll_interval)


def parse_line(line: str, node_id: str, email_strip_suffix_at: str) -> dict | None:
    match = LOG_LINE_RE.match(line.strip())
    if not match:
        return None

    email = match.group("email")
    if email_strip_suffix_at and email_strip_suffix_at in email:
        email = email.split(email_strip_suffix_at, 1)[0]

    # Xray's own timestamp has no timezone and is local to the node — we
    # trust it as UTC-naive and let the central service treat it as such.
    # If your node's clock isn't UTC, set MG_NODE_TZ_IS_UTC=false and fix
    # the node's clock instead of trying to convert here.
    return {
        "username": email,
        "node_id": node_id,
        "client_ip": match.group("client_ip").strip("[]"),
        "destination_ip": match.group("dest_ip").strip("[]"),
        "destination_port": int(match.group("dest_port")),
        "protocol": match.group("protocol"),
        "outcome": match.group("outcome"),
        "occurred_at": match.group("timestamp").replace("/", "-", 2).replace(" ", "T"),
    }


class EventBuffer:
    def __init__(self, max_events: int):
        self._events: list[dict] = []
        self._max_events = max_events

    def add(self, event: dict) -> None:
        if len(self._events) >= self._max_events:
            dropped = self._events.pop(0)
            logger.warning("event_type=buffer_overflow_dropping_oldest dropped_username=%s", dropped.get("username"))
        self._events.append(event)

    def drain(self) -> list[dict]:
        events, self._events = self._events, []
        return events

    def __len__(self) -> int:
        return len(self._events)


def post_batch(cfg: CollectorConfig, events: list[dict]) -> bool:
    if not events:
        return True
    payload = json.dumps({"node_id": cfg.node_id, "events": events}).encode()
    request = urllib.request.Request(
        f"{cfg.ingest_url}/api/v1/ingest/events",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {cfg.api_key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=cfg.request_timeout_seconds) as resp:
            if resp.status >= 300:
                logger.warning("event_type=ingest_post_bad_status status=%s", resp.status)
                return False
            return True
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        logger.warning("event_type=ingest_post_failed error=%s", exc)
        return False


def run(cfg: CollectorConfig) -> None:
    tailer = LogTailer(cfg.log_path, cfg.state_file, cfg.poll_interval_seconds)
    buffer = EventBuffer(cfg.max_buffered_events)
    last_flush = time.monotonic()

    logger.info(
        "event_type=collector_starting log_path=%s node_id=%s ingest_url=%s",
        cfg.log_path, cfg.node_id, cfg.ingest_url,
    )

    while True:
        try:
            for line in tailer.poll_lines():
                event = parse_line(line, cfg.node_id, cfg.email_strip_suffix_at)
                if event:
                    buffer.add(event)

            should_flush = len(buffer) >= cfg.batch_size or (
                len(buffer) > 0 and time.monotonic() - last_flush >= cfg.batch_interval_seconds
            )
            if should_flush:
                events = buffer.drain()
                if post_batch(cfg, events):
                    tailer.save_state()
                else:
                    # Put them back so a transient outage doesn't lose events —
                    # bounded by EventBuffer's max_events, which will start
                    # dropping the oldest ones if the outage runs long enough.
                    for event in events:
                        buffer.add(event)
                last_flush = time.monotonic()
        except Exception:
            # Never let an unexpected error (a transient OS error reading
            # the log file, etc.) kill the whole collector — systemd's
            # Restart=always would bring it back anyway, but restarting
            # loses nothing here (state is only saved after a successful
            # flush) and just adds needless restart delay/log noise.
            logger.exception("event_type=collector_iteration_failed")

        tailer.sleep()


if __name__ == "__main__":
    run(CollectorConfig.from_env())
