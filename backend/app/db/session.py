"""
CAS-SE Database Session and Engine

Provides the async SQLAlchemy engine and session factory.
The organization points DATABASE_URL at their own PostgreSQL instance.
CAS-SE tables (cas_*) are added via Alembic migrations without touching
the organization's existing schema.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

# Resolve relative SQLite paths against project repository root
resolved_db_url = settings.database_url
if resolved_db_url.startswith("sqlite+aiosqlite:///"):
    sqlite_rel = resolved_db_url[len("sqlite+aiosqlite:///"):]
    if not os.path.isabs(sqlite_rel) and not sqlite_rel.startswith(":memory:"):
        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        resolved_db_path = (repo_root / sqlite_rel).resolve()
        resolved_db_url = f"sqlite+aiosqlite:///{resolved_db_path.as_posix()}"

engine_kwargs: dict[str, object] = {"echo": settings.debug}
if not resolved_db_url.startswith("sqlite"):
    engine_kwargs.update(
        {
            "pool_pre_ping": True,
            "pool_size": 10,
            "max_overflow": 20,
        }
    )

engine = create_async_engine(
    resolved_db_url,
    **engine_kwargs,
)

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------
AsyncSessionFactory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)
async_session_factory = AsyncSessionFactory


# ---------------------------------------------------------------------------
# Declarative Base
# ---------------------------------------------------------------------------
class CASBase(DeclarativeBase):
    """
    Shared declarative base for all CAS-SE ORM models.

    All CAS-SE tables use the `cas_` prefix to namespace them within
    the organization's existing database and avoid schema conflicts.
    """

    pass


# ---------------------------------------------------------------------------
# Dependency injection helper (FastAPI)
# ---------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession]:
    """FastAPI dependency: yields a database session per request."""
    async with AsyncSessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
