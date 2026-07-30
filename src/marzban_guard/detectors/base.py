"""
Every detector is a small, pure, synchronous function of
(event, stats, config) -> DetectorResult. No Redis or DB access inside a
detector — all the state it needs has already been gathered into
ConnectionStats by RateLimiter (services/rate_limiter.py) before the
scoring engine runs. This is what makes adding a detector cheap (subclass
+ one line in registry.py) and what makes them trivially unit-testable
(construct an event/stats pair, assert on the result — no mocking).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from marzban_guard.config import SecurityConfig
from marzban_guard.schemas.events import ConnectionEvent
from marzban_guard.services.rate_limiter import ConnectionStats


@dataclass(frozen=True)
class DetectorResult:
    detector: str
    triggered: bool
    score: float = 0.0
    reason: str = ""
    details: dict = field(default_factory=dict)

    @staticmethod
    def clean(detector: str) -> DetectorResult:
        return DetectorResult(detector=detector, triggered=False)


class BaseDetector(ABC):
    name: str = "base"

    @abstractmethod
    def evaluate(self, event: ConnectionEvent, stats: ConnectionStats, cfg: SecurityConfig) -> DetectorResult:
        """Returns a DetectorResult. `triggered=False` (score 0) is the
        expected result for the overwhelming majority of calls — only
        return a nonzero score when this detector's specific condition is
        actually met."""
        raise NotImplementedError
