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


async def test_device_limit_does_not_rescore_within_cooldown(db_session):
    """device_limit is a STATE signal, not a rate signal — unlike
    test_burst_of_triggers_within_the_same_incident_does_not_compound
    (port_scan legitimately sums every trigger, burst or not), retriggering
    on every connection while still over the device limit must not add
    fresh points each time — it's the same ongoing violation, not new
    evidence."""
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    result = DetectorResult(detector="device_limit", triggered=True, score=80, reason="over device limit")

    now = datetime.utcnow()
    first = await engine.process_event(db_session, make_event(username="oscar", occurred_at=now), [result])
    assert first is not None
    assert first.score == pytest.approx(80)

    # Moments later, well inside score_cooldown_seconds — same ongoing
    # violation, already counted. Nothing else triggered this event either,
    # so there's nothing left to score at all.
    soon = now + timedelta(seconds=1)
    second = await engine.process_event(db_session, make_event(username="oscar", occurred_at=soon), [result])
    assert second is None


async def test_device_limit_rescores_after_cooldown_elapses(db_session):
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    result = DetectorResult(detector="device_limit", triggered=True, score=80, reason="over device limit")

    now = datetime.utcnow()
    first = await engine.process_event(db_session, make_event(username="peggy", occurred_at=now), [result])
    assert first.score == pytest.approx(80)

    later = now + timedelta(seconds=cfg.device_limit.score_cooldown_seconds + 1)
    second = await engine.process_event(db_session, make_event(username="peggy", occurred_at=later), [result])
    assert second is not None
    assert second.score > first.score  # decayed remainder plus a fresh 80


async def test_device_limit_cooldown_does_not_suppress_other_detectors(db_session):
    """device_limit firing alongside a real abuse signal (port_scan) within
    the cooldown window still scores — the cooldown only ever drops
    device_limit's own contribution, never anything else in the same
    event."""
    cfg = get_config().security
    engine = ScoringEngine(cfg)
    device_result = DetectorResult(detector="device_limit", triggered=True, score=80, reason="over device limit")
    scan_result = DetectorResult(detector="port_scan", triggered=True, score=60, reason="scanning")

    now = datetime.utcnow()
    first = await engine.process_event(db_session, make_event(username="quinn", occurred_at=now), [device_result])
    assert first.score == pytest.approx(80)

    soon = now + timedelta(seconds=1)
    second = await engine.process_event(
        db_session, make_event(username="quinn", occurred_at=soon), [device_result, scan_result]
    )
    assert second is not None
    assert [r.detector for r in second.triggered] == ["port_scan"]


async def test_device_limit_score_cooldown_seconds_zero_disables_gate(db_session):
    cfg = get_config().security.model_copy(deep=True)
    cfg.device_limit.score_cooldown_seconds = 0
    engine = ScoringEngine(cfg)
    result = DetectorResult(detector="device_limit", triggered=True, score=80, reason="over device limit")

    now = datetime.utcnow()
    await engine.process_event(db_session, make_event(username="rhea", occurred_at=now), [result])

    soon = now + timedelta(seconds=1)
    second = await engine.process_event(db_session, make_event(username="rhea", occurred_at=soon), [result])
    assert second is not None
    assert second.score == pytest.approx(160, rel=0.01)  # old behavior: scores every event


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
