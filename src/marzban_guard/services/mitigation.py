"""
Turns a ScoringEngine outcome into real action. Mitigation only ever
escalates automatically — de-escalating (unsuspending, clearing a
disable/blacklist) requires either the level-3 auto-expiry sweep
(workers/event_consumer.py) for temporary suspensions, or an explicit
admin call (api/routes/admin.py) for levels 4/5. This mirrors the spec's
intent that level 4/5 "require manual review" and keeps a falling score
from silently un-suspending someone before an admin has looked at it.

Levels:
  1  log only (no external call)
  2  + notify admin (rate-limited by notify_cooldown_seconds)
  3  + temporarily suspend (Marzban status=disabled, auto-reinstated later)
  4  + disable (Marzban status=disabled, stays until an admin re-enables)
  5  + permanent blacklist (disable + a blacklist_entries row pending review)

security.mitigation.auto_block.enabled is the master dry-run switch: when
false, levels 3-5 are logged as "would have escalated" and admin is still
notified, but nothing is actually sent to Marzban — useful for tuning
thresholds against real traffic before trusting the system to act.

Every status change that actually reaches Marzban also fires a best-effort
callback to the shop site via ShopNotifier (see services/shop_notifier.py)
— this is the only thing keeping the shop's own ban flag/customer notice
in sync with a restriction marzban-guard enforces independently.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from marzban_guard.config import MitigationConfig
from marzban_guard.db.models import GuardUser, UserStatus
from marzban_guard.logging import get_logger
from marzban_guard.repositories import action_repo, user_repo
from marzban_guard.services.marzban_client import MarzbanClient
from marzban_guard.services.notifier import Notifier
from marzban_guard.services.scoring import ScoringOutcome
from marzban_guard.services.shop_notifier import ShopNotifier

logger = get_logger("mitigation")

_STATUS_SEVERITY = {
    UserStatus.active: 0,
    UserStatus.suspended: 3,
    UserStatus.disabled: 4,
    UserStatus.blacklisted: 5,
}

_LEVEL_STATUS: dict[int, UserStatus] = {
    3: UserStatus.suspended,
    4: UserStatus.disabled,
    5: UserStatus.blacklisted,
}

_ACTION_NAME = {
    UserStatus.suspended: "suspend",
    UserStatus.disabled: "disable",
    UserStatus.blacklisted: "blacklist",
}


class MitigationService:
    def __init__(
        self, marzban: MarzbanClient, notifier: Notifier, cfg: MitigationConfig, shop_notifier: ShopNotifier
    ):
        self._marzban = marzban
        self._notifier = notifier
        self._cfg = cfg
        self._shop_notifier = shop_notifier

    async def apply(self, session: AsyncSession, outcome: ScoringOutcome) -> None:
        if outcome.level <= 0:
            return

        user = outcome.user
        level = outcome.level
        now = datetime.utcnow()
        reason = "; ".join(f"{r.detector}: {r.reason}" for r in outcome.triggered) or "score threshold reached"

        if level == 1:
            await action_repo.add(session, user.username, level, "log", reason)
            logger.info("event_type=abuse_logged", username=user.username, score=outcome.score, level=level)
            return

        target_status = _LEVEL_STATUS.get(level)  # None for level 2 — notify-only, no status change
        is_escalation = target_status is not None and _STATUS_SEVERITY[target_status] > _STATUS_SEVERITY[user.status]

        if is_escalation:
            if self._cfg.auto_block.enabled:
                await self._escalate(session, user, level, target_status, reason, now)
            else:
                logger.warning(
                    "event_type=mitigation_dry_run",
                    username=user.username,
                    would_be_status=target_status.value,
                    score=outcome.score,
                    level=level,
                )
                await action_repo.add(session, user.username, level, "dry_run", reason)

        if await self._should_notify(session, user.username, now):
            await action_repo.add(session, user.username, level, "notify_admin", reason)
            await self._notifier.notify(
                f"🚨 marzban-guard: {user.username} — risk score {outcome.score:.0f} (level {level})\n{reason}"
            )

    async def _escalate(
        self, session: AsyncSession, user: GuardUser, level: int, target_status: UserStatus, reason: str, now: datetime
    ) -> None:
        await self._marzban.set_user_status(user.username, active=False)

        expires_at = None
        if target_status == UserStatus.suspended:
            expires_at = now + timedelta(seconds=self._cfg.auto_block.duration_seconds)

        await user_repo.set_status(session, user, target_status, reason, expires_at)

        action_name = _ACTION_NAME[target_status]
        await action_repo.add(session, user.username, level, action_name, reason, expires_at=expires_at)
        if target_status == UserStatus.blacklisted:
            await action_repo.add_blacklist_entry(session, user.username, reason)

        await self._shop_notifier.notify_status(user.username, banned=True, reason=reason)

        logger.warning(
            "event_type=mitigation_action",
            username=user.username,
            action=action_name,
            level=level,
            expires_at=expires_at.isoformat() if expires_at else None,
        )

    async def _should_notify(self, session: AsyncSession, username: str, now: datetime) -> bool:
        last = await action_repo.last_action(session, username, "notify_admin")
        if not last:
            return True
        return (now - last.created_at).total_seconds() >= self._cfg.notify_cooldown_seconds

    async def reinstate_expired(self, session: AsyncSession, user: GuardUser) -> None:
        """Called by the worker's periodic expiry sweep once
        status_expires_at has passed for a level-3 (temporary) suspension.
        Levels 4/5 have no expiry and never reach this path."""
        await self._marzban.set_user_status(user.username, active=True)
        await user_repo.set_status(session, user, UserStatus.active, "temporary suspension expired", None)
        await action_repo.add(session, user.username, 0, "reinstate", "temporary suspension expired")
        await self._shop_notifier.notify_status(user.username, banned=False, reason="")
        logger.info("event_type=mitigation_action", username=user.username, action="reinstate")

    async def manual_override(
        self, session: AsyncSession, user: GuardUser, new_status: UserStatus, reason: str, actor: str
    ) -> None:
        """Admin-initiated status change (api/routes/admin.py) — the only
        way to clear a level-4/5 status, and also usable to manually
        escalate/suspend someone ahead of the automatic scoring."""
        active = new_status == UserStatus.active
        await self._marzban.set_user_status(user.username, active=active)
        await user_repo.set_status(session, user, new_status, reason, None)
        action = "reinstate" if active else _ACTION_NAME.get(new_status, "manual_status_change")
        await action_repo.add(session, user.username, 0, action, reason, actor=actor)
        await self._shop_notifier.notify_status(user.username, banned=not active, reason=reason if not active else "")
        logger.info("event_type=mitigation_action", username=user.username, action=action, actor=actor)
