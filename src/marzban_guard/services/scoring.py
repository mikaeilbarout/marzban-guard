"""
Combines whatever detectors triggered on one connection event into a
single risk-score update for that user, with two properties the spec
calls for explicitly:

  - Decay: an old infraction stops counting against a user who's since
    behaved. Modeled as continuous exponential decay with a configurable
    half-life (security.scoring.decay_half_life_seconds), applied lazily
    — there's no ticking background job walking every user's score down;
    it's simply recomputed from (last stored score, time elapsed) the
    next time that user's row is touched, or on read via effective_score().

  - Repeat-offender compounding: if a user still has a nonzero decayed
    score from earlier (i.e. they were already flagged recently) and
    ANY detector fires again, an extra "repeated_suspicious_behavior"
    bonus is added on top of the new detector scores — a second offense
    shortly after the first costs more than the sum of its parts.

Deliberately does NOT write anything to Postgres for a clean connection
(no triggered detectors) — see docs/ARCHITECTURE.md#storage for why that
write-amplification would be wasteful at "thousands of users" scale.

device_limit is the one detector this file treats specially: it's a
STATE signal ("how many devices over the limit right now"), not a RATE
signal like connection_rate/port_scan/spam where retriggering on every
single connection genuinely means more evidence. Scored plainly, an
account that stays over its device limit would earn fresh points on
every connection it makes even though nothing about the violation
actually changed — so the penalty would track how often the account
reconnects, not how many devices are actually over. Instead,
device_limit only ever scores the INCREMENT: how many MORE devices are
over the limit than the last time device_limit was scored for this
user (limit=3, a 4th device connecting scores one weight's worth, a 5th
on top of that scores another — but a 4th device simply reconnecting
scores nothing further). See _apply_device_limit_delta below.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, replace
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from marzban_guard.config import SecurityConfig
from marzban_guard.db.models import GuardUser
from marzban_guard.detectors.base import DetectorResult
from marzban_guard.repositories import event_repo, user_repo
from marzban_guard.schemas.events import ConnectionEvent


@dataclass(frozen=True)
class ScoringOutcome:
    user: GuardUser
    score: float
    level: int
    triggered: list[DetectorResult]
    repeat_bonus_applied: bool


def decay(previous_score: float, elapsed_seconds: float, half_life_seconds: int) -> float:
    if previous_score <= 0 or elapsed_seconds <= 0:
        return max(previous_score, 0.0)
    if half_life_seconds <= 0:
        return previous_score
    return previous_score * math.pow(0.5, elapsed_seconds / half_life_seconds)


def effective_score(user: GuardUser, now: datetime, half_life_seconds: int) -> float:
    """Read-time helper for dashboards: what a user's score actually is
    *right now*, without needing a fresh event to trigger the recompute
    that process_event() does."""
    reference = user.updated_at or now
    elapsed = (now - reference).total_seconds()
    return decay(user.risk_score, elapsed, half_life_seconds)


def level_for_score(score: float, cfg: SecurityConfig) -> int:
    t = cfg.scoring.thresholds
    if score >= t.level_5:
        return 5
    if score >= t.level_4:
        return 4
    if score >= t.level_3:
        return 3
    if score >= t.level_2:
        return 2
    if score >= t.level_1:
        return 1
    return 0


class ScoringEngine:
    def __init__(self, cfg: SecurityConfig):
        self._cfg = cfg

    async def _apply_device_limit_delta(
        self, session: AsyncSession, username: str, triggered: list[DetectorResult]
    ) -> list[DetectorResult]:
        """Rewrites a device_limit result's score to just the INCREMENT
        over what's already been scored — see the module docstring. Every
        other detector passes through untouched; this only ever adjusts
        (or drops) device_limit's own contribution."""
        adjusted = []
        for result in triggered:
            if result.detector != "device_limit":
                adjusted.append(result)
                continue

            current_count = result.details.get("distinct_client_devices", 0)
            limit = result.details.get("max_devices", 0)
            current_over = max(0, current_count - limit)

            last = await event_repo.last_for_detector(session, username, "device_limit")
            last_count = last.details.get("distinct_client_devices", limit) if last else limit
            last_over = max(0, last_count - limit)

            delta_over = current_over - last_over
            if delta_over <= 0:
                continue  # no new device beyond what's already been counted

            weight = self._cfg.scoring.weights.device_limit_exceeded
            adjusted.append(replace(result, score=delta_over * weight))
        return adjusted

    async def process_event(
        self,
        session: AsyncSession,
        event: ConnectionEvent,
        triggered: list[DetectorResult],
    ) -> ScoringOutcome | None:
        if not triggered:
            return None

        now = event.occurred_at
        triggered = await self._apply_device_limit_delta(session, event.username, triggered)
        if not triggered:
            return None

        user = await user_repo.get_or_create(session, event.username)

        previous_effective = effective_score(user, now, self._cfg.scoring.decay_half_life_seconds)
        new_points = sum(r.score for r in triggered)

        # "Repeated" means happened again after a real gap — not "still
        # triggering on connection #47 of the same ongoing burst". See
        # ScoringConfig.repeat_offense_min_gap_seconds.
        gap_since_last = (
            (now - user.last_abuse_event_at).total_seconds() if user.last_abuse_event_at else None
        )
        min_gap = self._cfg.scoring.repeat_offense_min_gap_seconds
        is_separate_incident = gap_since_last is not None and gap_since_last >= min_gap
        repeat_bonus_applied = previous_effective > 0 and is_separate_incident
        repeat_bonus = self._cfg.scoring.weights.repeated_suspicious_behavior if repeat_bonus_applied else 0.0

        total = previous_effective + new_points + repeat_bonus
        user.last_abuse_event_at = now

        for result in triggered:
            await event_repo.add(session, event.username, result.detector, result.score, result.details)
        if repeat_bonus_applied:
            await event_repo.add(
                session,
                event.username,
                "repeated_suspicious_behavior",
                repeat_bonus,
                {"previous_effective_score": previous_effective},
            )

        user.risk_score = total
        await user_repo.touch_last_seen(session, user, event.node_id, now)

        level = level_for_score(total, self._cfg)
        return ScoringOutcome(
            user=user, score=total, level=level, triggered=triggered, repeat_bonus_applied=repeat_bonus_applied
        )
