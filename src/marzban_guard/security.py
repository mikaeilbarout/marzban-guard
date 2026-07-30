"""Bearer-token auth for the two API surfaces: the node collector
(ingest.api_key) and the admin dashboard (admin_api.api_key). Constant-time
comparison so a valid key can't be brute-forced via response-timing
differences. Both keys are required config — an unset key fails closed
(503, not "auth disabled")."""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from marzban_guard.config import get_config


def _check_bearer(authorization: str, expected: str) -> None:
    if not expected:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "API key not configured for this endpoint")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")


async def require_ingest_api_key(authorization: str = Header(default="")) -> None:
    _check_bearer(authorization, get_config().ingest.api_key)


async def require_admin_api_key(authorization: str = Header(default="")) -> None:
    _check_bearer(authorization, get_config().admin_api.api_key)
