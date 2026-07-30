"""
Async SQLAlchemy engine/session setup. One engine per process, shared by
the API and the worker — each created via get_engine()/get_sessionmaker()
so tests can point them at a throwaway SQLite DB instead (see
tests/conftest.py) without touching application code.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from marzban_guard.config import get_config


class Base(DeclarativeBase):
    pass


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    cfg = get_config().database
    return create_async_engine(
        cfg.url,
        pool_size=cfg.pool_size,
        max_overflow=cfg.max_overflow,
        pool_pre_ping=True,
    )


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False)


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency — one session per request, committed/rolled back
    by the caller (repositories don't commit internally, see
    repositories/README below each repo docstring)."""
    async with get_sessionmaker()() as session:
        yield session
