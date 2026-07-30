"""
The plugin registry. To add a new detector: subclass BaseDetector in its
own module under detectors/, then add one line to _DETECTOR_CLASSES below
— nothing else in the system needs to know it exists. run_all() is the
only entry point the rest of the codebase calls.
"""
from __future__ import annotations

from marzban_guard.config import SecurityConfig
from marzban_guard.detectors.base import BaseDetector, DetectorResult
from marzban_guard.detectors.connection_rate import ConnectionRateDetector
from marzban_guard.detectors.destination_fanout import DestinationFanoutDetector
from marzban_guard.detectors.failed_connections import FailedConnectionDetector
from marzban_guard.detectors.port_scan import PortScanDetector
from marzban_guard.detectors.spam import SpamDetector
from marzban_guard.schemas.events import ConnectionEvent
from marzban_guard.services.rate_limiter import ConnectionStats

_DETECTOR_CLASSES: list[type[BaseDetector]] = [
    ConnectionRateDetector,
    PortScanDetector,
    DestinationFanoutDetector,
    SpamDetector,
    FailedConnectionDetector,
]


def get_detectors() -> list[BaseDetector]:
    return [cls() for cls in _DETECTOR_CLASSES]


def run_all(
    event: ConnectionEvent,
    stats: ConnectionStats,
    cfg: SecurityConfig,
    detectors: list[BaseDetector] | None = None,
) -> list[DetectorResult]:
    """Runs every registered detector against one event and returns only
    the ones that triggered — callers (ScoringEngine) don't need to filter
    clean results out themselves."""
    detectors = detectors if detectors is not None else get_detectors()
    return [result for d in detectors if (result := d.evaluate(event, stats, cfg)).triggered]
