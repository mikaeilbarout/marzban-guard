from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from marzban_guard.config import get_config
from marzban_guard.detectors.base import DetectorResult
from marzban_guard.services.scoring import ScoringEngine, decay, level_for_score
from tests.conftest import make_event


def test_decay_returns_previous_score_with_no_elapsed_time():
    assert decay(100, 0, 1800) == 100


def test_decay_halves_at_exactly_one_half_life():
    assert decay(100, 1800, 1800) == pytest.approx(50)


def test_decay_never_goes_negative():
    assert decay(-5, 100, 1800) == 0


def test_level_for_score_matches_configured_thresholds():
    cfg = get_config().security
    assert level_for_score(0, cfg) == 0
    assert level_for_score(cfg.scoring.thresholds.level_1, cfg) == 1
    assert level_for_score(cfg.scoring.thresholds.level_5 + 1000, cfg) == 5


async def test_process_event_with_no_triggers_writes_nothing(db_session):
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    outcome = await engine.process_event(db_session, make_event(), [])
    assert outcome is None


async def test_process_event_persists_abuse_event_and_updates_score(db_session):
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    result = DetectorResult(detector="connection_rate", triggered=True, score=40, reason="too fast")

    outcome = await engine.process_event(db_session, make_event(username="dave"), [result])

    assert outcome is not None
    assert outcome.score == pytest.approx(40)
    assert outcome.user.risk_score == pytest.approx(40)
    assert outcome.repeat_bonus_applied is False


async def test_repeated_offense_after_a_real_gap_adds_compounding_bonus(db_session):
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    result = DetectorResult(detector="connection_rate", triggered=True, score=40, reason="too fast")

    now = datetime.utcnow()
    first = await engine.process_event(db_session, make_event(username="erin", occurred_at=now), [result])
    assert first.repeat_bonus_applied is False

    later = now + timedelta(seconds=cfg.scoring.repeat_offense_min_gap_seconds + 1)
    second = await engine.process_event(db_session, make_event(username="erin", occurred_at=later), [result])
    assert second.repeat_bonus_applied is True
    expected = 40 + 40 + cfg.scoring.weights.repeated_suspicious_behavior
    assert second.score == pytest.approx(expected, rel=0.01)


async def test_burst_of_triggers_within_the_same_incident_does_not_compound(db_session):
    """Regression test: a single sustained burst (e.g. one port scan spanning
    dozens of connections a few milliseconds apart) must NOT retrigger the
    repeat-offender bonus on every single one of those connections — that
    would rocket one ordinary incident straight to a level-5 blacklist."""
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    result = DetectorResult(detector="port_scan", triggered=True, score=60, reason="scanning")

    now = datetime.utcnow()
    outcome = None
    for i in range(10):
        outcome = await engine.process_event(
            db_session, make_event(username="mallory", occurred_at=now + timedelta(milliseconds=i)), [result]
        )
        assert outcome.repeat_bonus_applied is False

    # 10 triggers of the same detector, no compounding bonus — just the
    # ten scores summed (decay is negligible over milliseconds).
    assert outcome.score == pytest.approx(60 * 10, rel=0.01)


def _device_limit_result(distinct_client_devices: int, max_devices: int, weight: float) -> DetectorResult:
    return DetectorResult(
        detector="device_limit",
        triggered=True,
        score=weight,  # ScoringEngine recomputes this from details, not from here
        reason=f"{distinct_client_devices} distinct client IPs (limit {max_devices})",
        details={"distinct_client_devices": distinct_client_devices, "max_devices": max_devices},
    )


async def test_device_limit_scores_only_the_new_devices_over_the_limit(db_session):
    """The behavior this delta logic exists for: limit=3, a 4th device
    connecting scores one weight's worth, a 5th on top of that scores
    another — matching the user-specified rule directly, rather than a
    flat score per trigger."""
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    weight = cfg.scoring.weights.device_limit_exceeded

    now = datetime.utcnow()
    first = await engine.process_event(
        db_session, make_event(username="oscar", occurred_at=now), [_device_limit_result(4, 3, weight)]
    )
    assert first is not None
    assert first.score == pytest.approx(weight)  # 1 device over the limit of 3

    soon = now + timedelta(seconds=1)
    second = await engine.process_event(
        db_session, make_event(username="oscar", occurred_at=soon), [_device_limit_result(5, 3, weight)]
    )
    assert second is not None
    assert second.score == pytest.approx(weight * 2, rel=0.01)  # decayed 80 + a fresh 80 for the 5th device


async def test_device_limit_reconnect_of_the_same_devices_scores_nothing_further(db_session):
    """A device_limit trigger reporting the SAME device count as last time
    — the same set of devices simply reconnecting, not a new one joining —
    must not add fresh score. Nothing else triggered this event either, so
    there's nothing left to score at all."""
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    weight = cfg.scoring.weights.device_limit_exceeded

    now = datetime.utcnow()
    first = await engine.process_event(
        db_session, make_event(username="peggy", occurred_at=now), [_device_limit_result(4, 3, weight)]
    )
    assert first.score == pytest.approx(weight)

    soon = now + timedelta(seconds=1)
    second = await engine.process_event(
        db_session, make_event(username="peggy", occurred_at=soon), [_device_limit_result(4, 3, weight)]
    )
    assert second is None


async def test_device_limit_first_violation_scores_for_every_device_already_over(db_session):
    """If the very first observed violation already has 2 devices over the
    limit (e.g. limit=3, 5 devices show up at once), it scores for both —
    the baseline for "already counted" is the limit itself, not zero."""
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    weight = cfg.scoring.weights.device_limit_exceeded

    outcome = await engine.process_event(
        db_session, make_event(username="steve"), [_device_limit_result(5, 3, weight)]
    )
    assert outcome is not None
    assert outcome.score == pytest.approx(weight * 2)


async def test_device_limit_delta_does_not_suppress_other_detectors(db_session):
    """device_limit firing alongside a real abuse signal (port_scan) is
    unaffected by the delta logic — port_scan scores normally even when
    device_limit's own contribution this round is zero."""
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    weight = cfg.scoring.weights.device_limit_exceeded
    scan_result = DetectorResult(detector="port_scan", triggered=True, score=60, reason="scanning")

    now = datetime.utcnow()
    first = await engine.process_event(
        db_session, make_event(username="quinn", occurred_at=now), [_device_limit_result(4, 3, weight)]
    )
    assert first.score == pytest.approx(weight)

    soon = now + timedelta(seconds=1)
    second = await engine.process_event(
        db_session,
        make_event(username="quinn", occurred_at=soon),
        [_device_limit_result(4, 3, weight), scan_result],
    )
    assert second is not None
    assert [r.detector for r in second.triggered] == ["port_scan"]


async def test_score_decays_between_events_far_apart_in_time(db_session):
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    result = DetectorResult(detector="connection_rate", triggered=True, score=40, reason="too fast")

    now = datetime.utcnow()
    first = await engine.process_event(db_session, make_event(username="frank", occurred_at=now), [result])
    assert first.score == pytest.approx(40)

    # Two half-lives later (comfortably past repeat_offense_min_gap_seconds
    # too) — score should have decayed to ~1/4, then 40 new points plus the
    # repeat bonus get added on top.
    half_life = cfg.scoring.decay_half_life_seconds
    later = now + timedelta(seconds=half_life * 2)
    second = await engine.process_event(db_session, make_event(username="frank", occurred_at=later), [result])
    decayed = 40 * (0.5 ** 2)
    expected = decayed + 40 + cfg.scoring.weights.repeated_suspicious_behavior
    assert second.score == pytest.approx(expected, rel=0.01)
