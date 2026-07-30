"""Best-effort admin alerting — Telegram DM and/or a generic webhook
(Slack/Discord-compatible incoming-webhook JSON shape). A notification
failure must never block a mitigation action from being applied; every
call here swallows and logs its own exceptions."""
from __future__ import annotations

import httpx

from marzban_guard.config import NotificationsConfig
from marzban_guard.logging import get_logger

logger = get_logger("notifier")


class Notifier:
    def __init__(self, cfg: NotificationsConfig):
        self._cfg = cfg

    async def notify(self, text: str) -> None:
        if self._cfg.admin_telegram_bot_token and self._cfg.admin_telegram_chat_id:
            await self._send_telegram(text)
        if self._cfg.webhook_url:
            await self._send_webhook(text)

    async def _send_telegram(self, text: str) -> None:
        url = f"https://api.telegram.org/bot{self._cfg.admin_telegram_bot_token}/sendMessage"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json={"chat_id": self._cfg.admin_telegram_chat_id, "text": text})
                if resp.status_code != 200:
                    logger.warning("telegram_notify_failed", status=resp.status_code, body=resp.text)
        except Exception:
            logger.exception("telegram_notify_error")

    async def _send_webhook(self, text: str) -> None:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self._cfg.webhook_url, json={"text": text})
                if resp.status_code >= 300:
                    logger.warning("webhook_notify_failed", status=resp.status_code, body=resp.text)
        except Exception:
            logger.exception("webhook_notify_error")
