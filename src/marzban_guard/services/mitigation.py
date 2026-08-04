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

auto_block.min_level raises the bar for which of those levels actually
acts: with enabled=true and min_level=5 (say), levels 3/4 only notify —
the account stays untouched — and level 5 is the first one to actually
reach Marzban. Default min_level=3 keeps every level from 3 up acting,
i.e. the original behavior.

Every admin Telegram/webhook alert (see Notifier) spells out account,
score, the specific action taken this round (suspended/disabled/
blacklisted/dry-run/device-limit-warned/flagged-only), and the detector
reason(s) — never just a bare score. A real status change (an actual
suspend/disable/blacklist reaching Marzban) always sends that alert,
bypassing notify_cooldown_seconds entirely — the cooldown only throttles
repeat pings for a user who's merely still elevated, never the moment an
account actually goes dark.

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

        # action_summary is what the admin alert below actually says
        # happened this round — every branch sets it, so the message
        # never has to be guessed from level/reason alone.
        # real_deactivation forces that alert out regardless of
        # notify_cooldown_seconds: a routine "still elevated" ping can
        # wait, but the admin must never miss an account actually going
        # dark — see the docstring on _should_notify.
        action_summary = None
        real_deactivation = False

        # device_limit-only escalations are a policy-allowance signal, not
        # a malicious-pattern one — see MitigationConfig.device_limit_warn_only's
        # docstring. If any OTHER detector triggered alongside it this
        # round, that's a real abuse signal and this stays a normal
        # escalation.
        device_limit_only = bool(outcome.triggered) and all(r.detector == "device_limit" for r in outcome.triggered)
        if is_escalation and self._cfg.device_limit_warn_only and device_limit_only:
            await self._warn_device_limit(session, user, reason, now)
            action_summary = "⚠️ Customer warned — account untouched (device-limit-only trigger)"
            is_escalation = False  # already handled — don't also fall through to the normal path below

        if is_escalation:
            if not self._cfg.auto_block.enabled:
                logger.warning(
                    "event_type=mitigation_dry_run",
                    username=user.username,
                    would_be_status=target_status.value,
                    score=outcome.score,
                    level=level,
                )
                await action_repo.add(session, user.username, level, "dry_run", reason)
                action_summary = f"🟡 DRY-RUN — would have been {target_status.value} (auto_block is off)"
            elif level >= self._cfg.auto_block.min_level:
                await self._escalate(session, user, level, target_status, reason, now)
                real_deactivation = True
                if target_status == UserStatus.suspended:
                    action_summary = f"🔴 SUSPENDED — auto-reinstated in {self._cfg.auto_block.duration}"
                elif target_status == UserStatus.disabled:
                    action_summary = "🔴 DISABLED — stays off until an admin manually re-enables it"
                else:
                    action_summary = "🔴 BLACKLISTED — permanent, pending manual review"
            else:
                # Below auto_block.min_level: policy says "tell me, don't
                # act yet" — account stays untouched, this round is just a
                # (cooldown-throttled, like any routine flag) heads-up.
                await action_repo.add(session, user.username, level, "flagged", reason)
                action_summary = (
                    f"🟡 Flagged — level {level} reached, no action taken "
                    f"(auto-block only applies from level {self._cfg.auto_block.min_level}+)"
                )
        elif action_summary is None:
            action_summary = "ℹ️ Flagged only — no status change at this level"

        should_notify = real_deactivation or await self._should_notify(session, user.username, now)
        if should_notify:
            await action_repo.add(session, user.username, level, "notify_admin", reason)
            await self._notifier.notify(
                f"🚨 marzban-guard alert\n"
                f"Account: {user.username}\n"
                f"Score: {outcome.score:.0f} (level {level})\n"
                f"Action: {action_summary}\n"
                f"Reason: {reason}"
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

    async def _warn_device_limit(self, session: AsyncSession, user: GuardUser, reason: str, now: datetime) -> None:
        """The soft alternative to _escalate() for a device_limit-only
        trigger: no Marzban call, no local status change — just a
        cooldown-limited notice to the shop so the account holder finds
        out, without their access being touched at all."""
        last = await action_repo.last_action(session, user.username, "device_limit_warn")
        if last and (now - last.created_at).total_seconds() < self._cfg.device_limit_warn_cooldown_seconds:
            return
        await action_repo.add(session, user.username, 0, "device_limit_warn", reason)
        await self._shop_notifier.notify_device_limit_warning(user.username, reason)
        logger.info("event_type=device_limit_warned", username=user.username)

    async def _should_notify(self, session: AsyncSession, username: str, now: datetime) -> bool:
        """Throttles routine "still elevated" pings (level 2, dry-run, or
        a device-limit warning) to at most one per notify_cooldown_seconds
        per user — without this, a user stuck above a threshold would
        generate one Telegram message per connection. Only consulted for
        those routine cases; apply() bypasses this entirely for an actual
        suspend/disable/blacklist (real_deactivation), since that's
        exactly the kind of event the cooldown must never be allowed to
        swallow."""
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
