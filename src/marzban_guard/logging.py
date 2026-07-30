"""
Structured (JSON) logging via structlog. Every log line carries an "event"
field and, where relevant, username/detector/action so log lines are
grep/jq-able and feed cleanly into a log aggregator (Loki, ELK, etc).

Three tiers are used by convention throughout the codebase (not separate
loggers — just log level + an "event_type" field):
  - normal:  logger.info("event_type=connection_processed", ...)
  - warning: logger.warning("event_type=abuse_suspected", ...)
  - abuse:   logger.warning("event_type=abuse_detected", score=..., ...)
  - action:  logger.warning("event_type=mitigation_action", level=..., ...)
"""
from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(log_level: str = "INFO") -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper(), logging.INFO),
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
