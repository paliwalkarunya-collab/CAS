"""
CAS-SE Database Session and Engine

Provides the async SQLAlchemy engine and session factory.
The organization points DATABASE_URL at their own PostgreSQL instance.
CAS-SE tables (cas_*) are added via Alembic migrations without touching
the organization's existing schema.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
engine_kwargs: dict[str, object] = {"echo": settings.debug}
if not settings.database_url.startswith("sqlite"):
    engine_kwargs.update(
        {
            "pool_pre_ping": True,
            "pool_size": 10,
            "max_overflow": 20,
        }
    )

engine = create_async_engine(
    settings.database_url,
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
