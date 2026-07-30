"""
Thin async client for the subset of the Marzban admin API marzban-guard
needs to actually enforce mitigation: flip a user active/disabled, and
read back per-user traffic/online state for the traffic poller. This is
deliberately narrow — provisioning (create/renew/delete) is the shop
site's job, not this system's; marzban-guard only ever *restricts* access
on an existing account, it never creates or deletes one.
"""
from __future__ import annotations

import time

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from marzban_guard.config import MarzbanConfig
from marzban_guard.logging import get_logger

logger = get_logger("marzban_client")

_RETRYABLE = (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError)


class MarzbanClientError(Exception):
    pass


class MarzbanClient:
    def __init__(self, cfg: MarzbanConfig):
        self._cfg = cfg
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    async def _get_token(self) -> str:
        now = time.time()
        if self._token and now < self._token_expires_at:
            return self._token

        async with httpx.AsyncClient(timeout=self._cfg.request_timeout_seconds) as client:
            resp = await client.post(
                f"{self._cfg.base_url}/api/admin/token",
                data={"username": self._cfg.admin_username, "password": self._cfg.admin_password},
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data["access_token"]
            self._token_expires_at = now + 60 * 60 * 20  # refresh a bit before Marzban's ~24h expiry
            return self._token

    @retry(
        retry=retry_if_exception_type(_RETRYABLE),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
        reraise=True,
    )
    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        token = await self._get_token()
        async with httpx.AsyncClient(timeout=self._cfg.request_timeout_seconds) as client:
            resp = await client.request(
                method, f"{self._cfg.base_url}{path}", headers={"Authorization": f"Bearer {token}"}, **kwargs
            )
        if resp.status_code == 401:
            # Token might have been invalidated server-side — refresh once and retry.
            self._token = None
            token = await self._get_token()
            async with httpx.AsyncClient(timeout=self._cfg.request_timeout_seconds) as client:
                resp = await client.request(
                    method, f"{self._cfg.base_url}{path}", headers={"Authorization": f"Bearer {token}"}, **kwargs
                )
        return resp

    async def set_user_status(self, username: str, active: bool) -> None:
        """Used for suspend (temporary) and disable (level 4) — both are
        just Marzban's "disabled" status; what differs is whether
        marzban-guard's own state machine plans to auto-reinstate it
        later (see workers/event_consumer.py's expiry sweep)."""
        resp = await self._request(
            "PUT", f"/api/user/{username}", json={"status": "active" if active else "disabled"}
        )
        if resp.status_code == 404:
            logger.warning("marzban_user_not_found", username=username)
            return
        resp.raise_for_status()

    async def get_user(self, username: str) -> dict | None:
        resp = await self._request("GET", f"/api/user/{username}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    async def list_users(self, offset: int = 0, limit: int = 200) -> dict:
        """Paginated — the traffic poller walks all pages each cycle. See
        workers/traffic_poller.py."""
        resp = await self._request("GET", "/api/users", params={"offset": offset, "limit": limit})
        resp.raise_for_status()
        return resp.json()
