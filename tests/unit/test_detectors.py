from __future__ import annotations

from marzban_guard.config import get_config
from marzban_guard.detectors.connection_rate import ConnectionRateDetector
from marzban_guard.detectors.destination_fanout import DestinationFanoutDetector
from marzban_guard.detectors.device_limit import DeviceLimitDetector
from marzban_guard.detectors.failed_connections import FailedConnectionDetector
from marzban_guard.detectors.port_scan import PortScanDetector
from marzban_guard.detectors.registry import run_all
from marzban_guard.detectors.spam import SpamDetector
from marzban_guard.services.rate_limiter import ConnectionStats
from tests.conftest import make_event


def _stats(**overrides) -> ConnectionStats:
    defaults = dict(
        username="alice",
        new_connections_last_minute=1,
        new_connections_last_hour=1,
        concurrent_estimate=1,
        rejected_last_minute=0,
        distinct_destination_ips=1,
        distinct_destination_ports=1,
        destination_ip_cap_hit=False,
        destination_port_cap_hit=False,
        distinct_smtp_destination_ips=0,
        distinct_client_devices=1,
    )
    defaults.update(overrides)
    return ConnectionStats(**defaults)


def test_connection_rate_detector_clean_below_limits():
    cfg = get_config().security
    result = ConnectionRateDetector().evaluate(make_event(), _stats(), cfg)
    assert result.triggered is False


def test_connection_rate_detector_triggers_over_per_minute_limit():
    cfg = get_config().security
    over_limit = cfg.connection_limit_per_minute + 1
    result = ConnectionRateDetector().evaluate(make_event(), _stats(new_connections_last_minute=over_limit), cfg)
    assert result.triggered is True
    assert result.score == cfg.scoring.weights.high_connection_rate


def test_port_scan_detector_requires_concentration():
    cfg = get_config().security
    # Many ports, but spread across many IPs too — NOT a concentrated scan.
    spread = ConnectionStats(
        **{
            **_stats().__dict__,
            "distinct_destination_ports": cfg.scan_detection.port_threshold + 10,
            "distinct_destination_ips": 500,
        }
    )
    assert PortScanDetector().evaluate(make_event(), spread, cfg).triggered is False

    concentrated = ConnectionStats(
        **{
            **_stats().__dict__,
            "distinct_destination_ports": cfg.scan_detection.port_threshold + 10,
            "distinct_destination_ips": 2,
        }
    )
    result = PortScanDetector().evaluate(make_event(), concentrated, cfg)
    assert result.triggered is True
    assert result.score == cfg.scoring.weights.port_scan


def test_destination_fanout_detector_scores_ips_and_ports_independently():
    cfg = get_config().security
    stats = ConnectionStats(
        **{
            **_stats().__dict__,
            "distinct_destination_ips": cfg.scan_detection.ip_threshold + 1,
            "distinct_destination_ports": cfg.scan_detection.port_threshold + 1,
        }
    )
    result = DestinationFanoutDetector().evaluate(make_event(), stats, cfg)
    assert result.triggered is True
    expected = cfg.scoring.weights.too_many_destination_ips + cfg.scoring.weights.too_many_destination_ports
    assert result.score == expected


def test_spam_detector_triggers_on_smtp_fanout():
    cfg = get_config().security
    stats = ConnectionStats(
        **{**_stats().__dict__, "distinct_smtp_destination_ips": cfg.spam_detection.distinct_ip_threshold + 5}
    )
    result = SpamDetector().evaluate(make_event(destination_port=25), stats, cfg)
    assert result.triggered is True


def test_failed_connection_detector_triggers_on_burst():
    cfg = get_config().security
    stats = _stats(rejected_last_minute=cfg.failed_connection_threshold_per_minute + 1)
    result = FailedConnectionDetector().evaluate(make_event(outcome="rejected"), stats, cfg)
    assert result.triggered is True


def test_device_limit_detector_clean_at_or_below_limit():
    cfg = get_config().security
    stats = _stats(distinct_client_devices=cfg.device_limit.max_devices)
    assert DeviceLimitDetector().evaluate(make_event(), stats, cfg).triggered is False


def test_device_limit_detector_triggers_over_limit():
    cfg = get_config().security
    stats = _stats(distinct_client_devices=cfg.device_limit.max_devices + 1)
    result = DeviceLimitDetector().evaluate(make_event(username="alice"), stats, cfg)
    assert result.triggered is True
    assert result.score == cfg.scoring.weights.device_limit_exceeded


def test_device_limit_detector_respects_per_user_override(monkeypatch):
    cfg = get_config().security
    from marzban_guard.config import PerUserOverride

    monkeypatch.setitem(cfg.per_user_overrides, "vip", PerUserOverride(max_devices=5))
    stats = _stats(distinct_client_devices=cfg.device_limit.max_devices + 1)
    result = DeviceLimitDetector().evaluate(make_event(username="vip"), stats, cfg)
    assert result.triggered is False


def test_run_all_returns_only_triggered_detectors():
    cfg = get_config().security
    clean_stats = _stats()
    assert run_all(make_event(), clean_stats, cfg) == []

    over_limit = _stats(new_connections_last_minute=cfg.connection_limit_per_minute + 1)
    triggered = run_all(make_event(), over_limit, cfg)
    assert len(triggered) == 1
    assert triggered[0].detector == "connection_rate"
