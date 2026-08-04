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


def _service(auto_block_enabled: bool | None = None, auto_block_min_level: int | None = None):
    cfg = get_config().security
    if auto_block_enabled is not None or auto_block_min_level is not None:
        # get_config() is a process-wide @lru_cache singleton — copy
        # before overriding so a test tweaking auto_block fields can't
        # leak that change into every other test sharing the same object.
        cfg = cfg.model_copy(deep=True)
        if auto_block_enabled is not None:
            cfg.mitigation.auto_block.enabled = auto_block_enabled
        if auto_block_min_level is not None:
            cfg.mitigation.auto_block.min_level = auto_block_min_level
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


async def test_device_limit_only_escalation_warns_instead_of_suspending(db_session):
    """The specific behavior this test locks in: an escalation whose sole
    trigger is device_limit must never reach Marzban or the shop's ban
    webhook — only the dedicated warning callback, and the account stays
    untouched (active)."""
    service, marzban, shop_notifier = _service()
    user = GuardUser(username="frank", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    result = DetectorResult(
        detector="device_limit", triggered=True, score=80, reason="3 distinct client IPs in the last 15 min (limit 2)"
    )
    outcome = ScoringOutcome(user=user, score=80, level=3, triggered=[result], repeat_bonus_applied=False)

    await service.apply(db_session, outcome)

    marzban.set_user_status.assert_not_awaited()
    shop_notifier.notify_status.assert_not_awaited()
    shop_notifier.notify_device_limit_warning.assert_awaited_once_with("frank", f"device_limit: {result.reason}")
    assert user.status == UserStatus.active


async def test_device_limit_combined_with_another_detector_still_escalates(db_session):
    """device_limit firing ALONGSIDE a real abuse signal (port scan here)
    in the same event is not softened — that combination is a genuine
    abuse pattern, not routine over-the-limit roaming."""
    service, marzban, shop_notifier = _service()
    user = GuardUser(username="grace", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    device_result = DetectorResult(detector="device_limit", triggered=True, score=80, reason="over device limit")
    scan_result = DetectorResult(detector="port_scan", triggered=True, score=60, reason="scanning")
    outcome = ScoringOutcome(
        user=user, score=140, level=4, triggered=[device_result, scan_result], repeat_bonus_applied=False
    )

    await service.apply(db_session, outcome)

    marzban.set_user_status.assert_awaited_once_with("grace", active=False)
    shop_notifier.notify_status.assert_awaited_once_with(
        "grace", banned=True, reason="device_limit: over device limit; port_scan: scanning"
    )
    shop_notifier.notify_device_limit_warning.assert_not_awaited()


async def test_device_limit_warning_respects_cooldown(db_session):
    """A user stuck over their device limit across many connections should
    get one warning, not one per connection."""
    service, _marzban, shop_notifier = _service()
    user = GuardUser(username="henry", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    result = DetectorResult(detector="device_limit", triggered=True, score=80, reason="over device limit")
    outcome = ScoringOutcome(user=user, score=80, level=3, triggered=[result], repeat_bonus_applied=False)

    await service.apply(db_session, outcome)
    await service.apply(db_session, outcome)

    shop_notifier.notify_device_limit_warning.assert_awaited_once()


async def test_admin_alert_spells_out_account_score_action_and_reason(db_session):
    """The admin alert must never be a bare score — it has to say whose
    account, what the score/level was, what action was actually taken,
    and why, so the admin doesn't have to go look it up."""
    service, *_ = _service(auto_block_enabled=True)
    user = GuardUser(username="ivan", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    result = DetectorResult(detector="port_scan", triggered=True, score=200, reason="80 ports on 2 hosts")
    outcome = ScoringOutcome(user=user, score=200, level=5, triggered=[result], repeat_bonus_applied=False)

    await service.apply(db_session, outcome)

    message = service._notifier.notify.call_args[0][0]
    assert "ivan" in message
    assert "200" in message
    assert "level 5" in message
    assert "BLACKLISTED" in message
    assert "80 ports on 2 hosts" in message


async def test_dry_run_admin_alert_says_dry_run(db_session):
    service, *_ = _service(auto_block_enabled=False)
    user = GuardUser(username="judy", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    result = DetectorResult(detector="port_scan", triggered=True, score=200, reason="scanning")
    outcome = ScoringOutcome(user=user, score=200, level=5, triggered=[result], repeat_bonus_applied=False)

    await service.apply(db_session, outcome)

    message = service._notifier.notify.call_args[0][0]
    assert "DRY-RUN" in message


async def test_real_deactivation_alert_bypasses_notify_cooldown(db_session):
    """A routine level-2 ping can be throttled — an account actually going
    dark must never be swallowed by the same cooldown, or the admin could
    miss a real suspension entirely."""
    service, *_ = _service(auto_block_enabled=True)
    user = GuardUser(username="karl", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    # First, a routine level-2 flag — starts the cooldown clock.
    flag_result = DetectorResult(detector="connection_rate", triggered=True, score=50, reason="a bit fast")
    flag_outcome = ScoringOutcome(user=user, score=50, level=2, triggered=[flag_result], repeat_bonus_applied=False)
    await service.apply(db_session, flag_outcome)
    assert service._notifier.notify.await_count == 1

    # Moments later (well inside notify_cooldown_seconds), a real
    # escalation happens — this must still alert, not get throttled.
    scan_result = DetectorResult(detector="port_scan", triggered=True, score=200, reason="scanning")
    scan_outcome = ScoringOutcome(user=user, score=250, level=5, triggered=[scan_result], repeat_bonus_applied=False)
    await service.apply(db_session, scan_outcome)

    assert service._notifier.notify.await_count == 2
    message = service._notifier.notify.call_args[0][0]
    assert "BLACKLISTED" in message


async def test_levels_below_min_level_notify_without_acting(db_session):
    """auto_block.min_level=5: levels 3 and 4 must only inform the admin —
    the account stays untouched, nothing reaches Marzban or the shop."""
    service, marzban, shop_notifier = _service(auto_block_enabled=True, auto_block_min_level=5)
    user = GuardUser(username="nina", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    level3_result = DetectorResult(detector="port_scan", triggered=True, score=90, reason="scanning a bit")
    level3_outcome = ScoringOutcome(user=user, score=90, level=3, triggered=[level3_result], repeat_bonus_applied=False)
    await service.apply(db_session, level3_outcome)

    marzban.set_user_status.assert_not_awaited()
    shop_notifier.notify_status.assert_not_awaited()
    assert user.status == UserStatus.active
    assert service._notifier.notify.await_count == 1
    message = service._notifier.notify.call_args[0][0]
    assert "nina" in message
    assert "level 3" in message
    assert "Flagged" in message

    # A second flag (level 4) moments later is a routine "still elevated"
    # ping like any other — subject to the normal notify_cooldown_seconds,
    # not a bypass, since the account still isn't actually being touched.
    level4_result = DetectorResult(detector="port_scan", triggered=True, score=130, reason="scanning more")
    level4_outcome = ScoringOutcome(
        user=user, score=130, level=4, triggered=[level4_result], repeat_bonus_applied=False
    )
    await service.apply(db_session, level4_outcome)

    marzban.set_user_status.assert_not_awaited()
    assert user.status == UserStatus.active
    assert service._notifier.notify.await_count == 1  # throttled by notify_cooldown_seconds


async def test_min_level_still_auto_blocks_once_reached(db_session):
    """The other half of min_level: once the score actually reaches
    min_level, it acts for real — and that alert bypasses the cooldown
    like any real deactivation, even right after a throttled level-4 flag."""
    service, marzban, shop_notifier = _service(auto_block_enabled=True, auto_block_min_level=5)
    user = GuardUser(username="nina", status=UserStatus.active)
    db_session.add(user)
    await db_session.flush()

    level4_result = DetectorResult(detector="port_scan", triggered=True, score=130, reason="scanning more")
    level4_outcome = ScoringOutcome(
        user=user, score=130, level=4, triggered=[level4_result], repeat_bonus_applied=False
    )
    await service.apply(db_session, level4_outcome)
    assert service._notifier.notify.await_count == 1

    level5_result = DetectorResult(detector="port_scan", triggered=True, score=200, reason="scanning a lot")
    level5_outcome = ScoringOutcome(
        user=user, score=200, level=5, triggered=[level5_result], repeat_bonus_applied=False
    )
    await service.apply(db_session, level5_outcome)

    marzban.set_user_status.assert_awaited_once_with("nina", active=False)
    shop_notifier.notify_status.assert_awaited_once_with("nina", banned=True, reason="port_scan: scanning a lot")
    assert user.status == UserStatus.blacklisted
    assert service._notifier.notify.await_count == 2  # bypassed the cooldown despite the recent level-4 flag
    message = service._notifier.notify.call_args[0][0]
    assert "BLACKLISTED" in message
