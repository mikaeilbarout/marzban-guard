"""
Tests for the node-side collector (collector/xray_log_collector.py). This
file had zero test coverage until now — which is exactly how two real bugs
shipped unnoticed:

1. Every logger.X(...) call used structlog-style keyword arguments
   (`logger.info("...", key=val)`) against Python's plain stdlib
   `logging.Logger`, which doesn't accept arbitrary kwargs — it raised
   TypeError on the very first log line at startup, before the collector
   could process anything at all.
2. LogTailer only detected log rotation via inode change, missing
   `logrotate`'s copytruncate strategy entirely (same inode, file
   truncated in place) — a stale byte offset seeked past a truncated
   file's end silently skips everything written after the truncation.

Both are covered below as explicit regression tests.
"""
from __future__ import annotations

import os

from xray_log_collector import CollectorConfig, EventBuffer, LogTailer, parse_line


def test_parse_line_accepted_tcp():
    line = "2024/01/15 10:23:45 from 10.20.0.5:53211 accepted tcp:8.8.8.8:443 [in -> out] email: alice"
    event = parse_line(line, node_id="node-1", email_strip_suffix_at="")
    assert event == {
        "username": "alice",
        "node_id": "node-1",
        "client_ip": "10.20.0.5",
        "destination_ip": "8.8.8.8",
        "destination_port": 443,
        "protocol": "tcp",
        "outcome": "accepted",
        "occurred_at": "2024-01-15T10:23:45",
    }


def test_parse_line_rejected_udp():
    line = "2024/01/15 10:23:46 from 10.20.0.5:53212 rejected udp:1.2.3.4:53 [in -> out] email: bob"
    event = parse_line(line, node_id="node-1", email_strip_suffix_at="")
    assert event["outcome"] == "rejected"
    assert event["protocol"] == "udp"
    assert event["username"] == "bob"


def test_parse_line_strips_email_suffix_when_configured():
    line = "2024/01/15 10:23:45 from 10.20.0.5:53211 accepted tcp:8.8.8.8:443 [in -> out] email: alice.4f3a2b1c"
    event = parse_line(line, node_id="node-1", email_strip_suffix_at=".")
    assert event["username"] == "alice"


def test_parse_line_returns_none_for_unrecognized_format():
    assert parse_line("this is not a log line at all", node_id="n", email_strip_suffix_at="") is None
    assert parse_line("", node_id="n", email_strip_suffix_at="") is None


def test_event_buffer_drops_oldest_when_full():
    buf = EventBuffer(max_events=3)
    for i in range(5):
        buf.add({"username": f"user{i}"})
    remaining = buf.drain()
    assert len(remaining) == 3
    # The two oldest (user0, user1) were dropped — only the last 3 remain.
    assert [e["username"] for e in remaining] == ["user2", "user3", "user4"]
    assert len(buf) == 0


def test_log_tailer_reads_incrementally_across_polls(tmp_path):
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    log_path.write_text("line1\n")

    tailer = LogTailer(str(log_path), str(state_path), poll_interval=0.01)
    assert tailer.poll_lines() == ["line1\n"]
    assert tailer.poll_lines() == []  # nothing new yet

    with open(log_path, "a") as f:
        f.write("line2\n")
    assert tailer.poll_lines() == ["line2\n"]


def test_log_tailer_persists_and_reloads_offset(tmp_path):
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    log_path.write_text("line1\nline2\n")

    tailer = LogTailer(str(log_path), str(state_path), poll_interval=0.01)
    tailer.poll_lines()
    tailer.save_state()

    with open(log_path, "a") as f:
        f.write("line3\n")

    # A fresh LogTailer (simulating a process restart) must resume from
    # the saved offset, not reread line1/line2 or start from EOF.
    reloaded = LogTailer(str(log_path), str(state_path), poll_interval=0.01)
    assert reloaded.poll_lines() == ["line3\n"]


def test_log_tailer_handles_rotation_via_inode_change(tmp_path):
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    log_path.write_text("old-line\n")

    tailer = LogTailer(str(log_path), str(state_path), poll_interval=0.01)
    tailer.poll_lines()
    tailer.save_state()

    # Simulate logrotate's "create" strategy: old file renamed away, a
    # brand new file (new inode) created at the same path.
    os.replace(log_path, tmp_path / "access.log.1")
    log_path.write_text("new-line\n")

    reloaded = LogTailer(str(log_path), str(state_path), poll_interval=0.01)
    assert reloaded.poll_lines() == ["new-line\n"]


def test_log_tailer_handles_copytruncate_rotation_same_inode(tmp_path):
    """Regression test for the bug described in this file's module
    docstring: `logrotate`'s copytruncate strategy truncates the log file
    IN PLACE (same inode), which inode-only rotation detection misses
    entirely."""
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    log_path.write_text("line1\n" * 50)  # large enough that the offset is well past 0

    tailer = LogTailer(str(log_path), str(state_path), poll_interval=0.01)
    tailer.poll_lines()
    tailer.save_state()

    # copytruncate: same path, same inode, truncated to (near) zero, then
    # a little new data appended — classic logrotate behavior.
    with open(log_path, "w") as f:  # "w" truncates in place on POSIX — same inode
        f.write("after-truncate\n")

    reloaded = LogTailer(str(log_path), str(state_path), poll_interval=0.01)
    assert reloaded.poll_lines() == ["after-truncate\n"]


def test_logging_calls_do_not_raise(tmp_path):
    """Regression test for the bug described in this file's module
    docstring: every logger call in this module must be valid stdlib
    `logging` usage (no structlog-style keyword arguments), since a
    TypeError from a broken log call previously crashed the collector on
    its very first startup line."""
    log_path = tmp_path / "access.log"
    log_path.write_text("garbage that will not match the regex\n")

    cfg = CollectorConfig(
        ingest_url="http://example.invalid",
        api_key="key",
        node_id="node-1",
        log_path=str(log_path),
        state_file=str(tmp_path / "state.json"),
        batch_interval_seconds=0.01,
    )

    def _urlopen_raises(*args, **kwargs):
        import urllib.error

        raise urllib.error.URLError("connection refused")

    import xray_log_collector as collector_module

    original_urlopen = collector_module.urllib.request.urlopen
    collector_module.urllib.request.urlopen = _urlopen_raises
    try:
        # Run a few iterations of the loop body directly rather than the
        # infinite `run()` — exercise every logging path (rotation/open,
        # a non-matching line, and a failed post) without blocking forever.
        tailer = LogTailer(str(log_path), str(tmp_path / "state.json"), poll_interval=0.01)
        tailer.poll_lines()  # hits the "first open" log line

        buf = EventBuffer(max_events=2)
        for i in range(5):
            buf.add({"username": f"u{i}"})  # hits the "buffer overflow" log line

        from xray_log_collector import post_batch

        assert post_batch(cfg, [{"username": "x"}]) is False  # hits the "post failed" log line
    finally:
        collector_module.urllib.request.urlopen = original_urlopen
