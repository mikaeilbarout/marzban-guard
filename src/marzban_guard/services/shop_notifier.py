"""
Best-effort callback to the shop site (e.g. Freemiga) whenever
MitigationService changes an account's restriction status, so the shop's
own ban flag — and whatever customer-facing dashboard/Telegram notice it
already has for that — stays in sync with a restriction marzban-guard
enforced directly against Marzban. marzban-guard never reads or writes
the shop's database itself; this is the one place it calls out to it,
and only after the real action (the Marzban API call) already succeeded.

A failure here must never affect mitigation itself — by the time this
runs, Marzban has already been told what to do and the local guard_users
row already updated. See services/mitigation.py for the call sites.
"""
from __future__ import annotations

import httpx

from marzban_guard.config import ShopIntegrationConfig
from marzban_guard.logging import get_logger

logger = get_logger("shop_notifier")


class ShopNotifier:
    def __init__(self, cfg: ShopIntegrationConfig):
        self._cfg = cfg

    async def notify_status(self, username: str, banned: bool, reason: str) -> None:
        if not self._cfg.base_url:
            return
        try:
            async with httpx.AsyncClient(timeout=self._cfg.request_timeout_seconds) as client:
                resp = await client.post(
                    f"{self._cfg.base_url}/api/integrations/marzban-guard/status",
                    json={"username": username, "banned": banned, "reason": reason},
                    headers={"Authorization": f"Bearer {self._cfg.webhook_secret}"},
                )
                if resp.status_code >= 300:
                    logger.warning(
                        "event_type=shop_notify_failed", username=username, status=resp.status_code
                    )
        except Exception:
            logger.exception("event_type=shop_notify_error", username=username)
