"""
Regression coverage for SecurityConfig.limits_for(). This caught a real
bug: the original implementation picked between a per-user override and
the global default with `override_value or default`, which treats 0 as
falsy — an explicit override of 0 (e.g. "block this user's new
connections/devices entirely" without a full ban) silently fell through
to the global default instead of being honored.
"""
from __future__ import annotations

from marzban_guard.config import PerUserOverride, get_config


def test_limits_for_uses_global_defaults_with_no_override():
    cfg = get_config().security
    limits = cfg.limits_for("nobody-has-an-override")
    assert limits.connection_limit_per_minute == cfg.connection_limit_per_minute
    assert limits.connection_limit_per_hour == cfg.connection_limit_per_hour
    assert limits.concurrent_limit == cfg.concurrent_limit
    assert limits.max_devices == cfg.device_limit.max_devices


def test_limits_for_honors_nonzero_override(monkeypatch):
    cfg = get_config().security
    monkeypatch.setitem(cfg.per_user_overrides, "vip", PerUserOverride(max_devices=10))
    assert cfg.limits_for("vip").max_devices == 10


def test_limits_for_honors_explicit_zero_override(monkeypatch):
    """The regression case: 0 is a legitimate override value, distinct
    from None ("no override configured"), for every one of these fields."""
    cfg = get_config().security
    monkeypatch.setitem(
        cfg.per_user_overrides,
        "blocked",
        PerUserOverride(connection_limit_per_minute=0, connection_limit_per_hour=0, concurrent_limit=0, max_devices=0),
    )
    limits = cfg.limits_for("blocked")
    assert limits.connection_limit_per_minute == 0
    assert limits.connection_limit_per_hour == 0
    assert limits.concurrent_limit == 0
    assert limits.max_devices == 0


def test_limits_for_partial_override_falls_back_per_field(monkeypatch):
    """An override that only sets one field must not affect the others —
    each field falls back to the global default independently."""
    cfg = get_config().security
    monkeypatch.setitem(cfg.per_user_overrides, "partial", PerUserOverride(max_devices=7))
    limits = cfg.limits_for("partial")
    assert limits.max_devices == 7
    assert limits.connection_limit_per_minute == cfg.connection_limit_per_minute
    assert limits.connection_limit_per_hour == cfg.connection_limit_per_hour
    assert limits.concurrent_limit == cfg.concurrent_limit
