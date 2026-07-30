"""MitigationService tests focused on the shop_notifier callback — the
rest of the escalation logic is already covered end-to-end by
tests/integration/test_ingest_flow.py."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from marzban_guard.config import get_config
from marzban_guard.db.models import GuardUser, UserStatus
from marzban_guard.detectors.base import DetectorResult
from marzban_guard.services.mitigation import MitigationService
from marzban_guard.services.scoring import ScoringOutcome

pytestmark = pytest.mark.asyncio


def _service():
    cfg = get_config().security
    marzban = AsyncMock()
    notifier = AsyncMock()
    shop_notifier = AsyncMock()
    service = MitigationService(marzban, notifier, cfg.mitigation, shop_notifier)
    return service, marzban, shop_notifier


async def test_escalation_notifies_shop_as_banned(db_session):
    service, marzban, shop_notifier = _service()
    user = GuardUser(username="alice", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    result = DetectorResult(detector="port_scan", triggered=True, score=200, reason="scanning")
    outcome = ScoringOutcome(user=user, score=200, level=3, triggered=[result], repeat_bonus_applied=False)

    await service.apply(db_session, outcome)

    shop_notifier.notify_status.assert_awaited_once_with("alice", banned=True, reason="port_scan: scanning")
    marzban.set_user_status.assert_awaited_once_with("alice", active=False)


async def test_reinstate_notifies_shop_as_unbanned(db_session):
    service, marzban, shop_notifier = _service()
    user = GuardUser(username="bob", status=UserStatus.suspended)
    db_session.add(user)
    await db_session.flush()

    await service.reinstate_expired(db_session, user)

    shop_notifier.notify_status.assert_awaited_once_with("bob", banned=False, reason="")
    marzban.set_user_status.assert_awaited_once_with("bob", active=True)


async def test_manual_override_to_active_notifies_shop_as_unbanned(db_session):
    service, marzban, shop_notifier = _service()
    user = GuardUser(username="carol", status=UserStatus.disabled)
    db_session.add(user)
    await db_session.flush()

    await service.manual_override(db_session, user, UserStatus.active, "admin cleared", "admin1")

    shop_notifier.notify_status.assert_awaited_once_with("carol", banned=False, reason="")


async def test_manual_override_to_disabled_notifies_shop_as_banned(db_session):
    service, marzban, shop_notifier = _service()
    user = GuardUser(username="dave", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    await service.manual_override(db_session, user, UserStatus.disabled, "manual ban", "admin1")

    shop_notifier.notify_status.assert_awaited_once_with("dave", banned=True, reason="manual ban")


async def test_shop_notifier_not_called_when_level_too_low_to_escalate(db_session):
    """Level 1/2 never change status, so there's nothing for the shop to
    sync yet — the callback only fires on an actual status change."""
    service, _marzban, shop_notifier = _service()
    user = GuardUser(username="erin", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    result = DetectorResult(detector="connection_rate", triggered=True, score=30, reason="a bit fast")
    outcome = ScoringOutcome(user=user, score=30, level=1, triggered=[result], repeat_bonus_applied=False)

    await service.apply(db_session, outcome)

    shop_notifier.notify_status.assert_not_awaited()
