"""Tests for Schema Overlay Isolation and Migration Non-Interference."""

from __future__ import annotations

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, inspect, select
from sqlalchemy.ext.asyncio import create_async_engine

from app.models.models import CASBase


@pytest.mark.asyncio
async def test_schema_overlay_isolation() -> None:
    """Verify that CAS-SE overlay tables coexist with an organization's existing tables

    without touching, altering, or dropping them.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    # 1. Simulate the organization's existing pre-existing schema
    org_metadata = MetaData()
    org_employees = Table(
        "org_employees",
        org_metadata,
        Column("id", Integer, primary_key=True),
        Column("name", String(100), nullable=False),
        Column("department", String(100), nullable=False),
    )

    async with engine.begin() as conn:
        await conn.run_sync(org_metadata.create_all)
        # Seed an organization record
        await conn.execute(
            org_employees.insert().values(id=1, name="John Doe", department="Radiology")
        )

    # Verify organization table exists and has data
    async with engine.connect() as conn:
        res = await conn.execute(select(org_employees))
        rows = res.fetchall()
        assert len(rows) == 1
        assert rows[0][1] == "John Doe"

    # 2. Apply CAS-SE schema overlay
    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    # 3. Inspect database tables: ensure both org tables and cas_* tables coexist
    def _inspect_tables(connection):
        insp = inspect(connection)
        return set(insp.get_table_names())

    async with engine.connect() as conn:
        table_names = await conn.run_sync(_inspect_tables)
        # Org table is preserved
        assert "org_employees" in table_names

        # All 11 CAS-SE tables exist with cas_ prefix
        expected_cas_tables = {
            "cas_users",
            "cas_refresh_tokens",
            "cas_policies",
            "cas_policy_versions",
            "cas_data_envelopes",
            "cas_protected_indexes",
            "cas_access_audit",
            "cas_ml_jobs",
            "cas_job_approvals",
            "cas_anomaly_alerts",
            "cas_key_versions",
        }
        for cas_table in expected_cas_tables:
            assert cas_table in table_names

        # Org employee data is completely unaffected
        res = await conn.execute(select(org_employees))
        assert len(res.fetchall()) == 1

    # 4. Simulate dropping/removing only CAS-SE tables
    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.drop_all)

    # 5. Org table remains completely intact!
    async with engine.connect() as conn:
        table_names_after = await conn.run_sync(_inspect_tables)
        assert "org_employees" in table_names_after
        for cas_table in expected_cas_tables:
            assert cas_table not in table_names_after

        res = await conn.execute(select(org_employees))
        assert len(res.fetchall()) == 1

    await engine.dispose()


@pytest.mark.asyncio
async def test_fresh_database_initialization_includes_key_check_value() -> None:
    """Verify that direct fresh database initialization creates key_check_value column."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    def _check_columns(connection) -> list[str]:
        insp = inspect(connection)
        cols = insp.get_columns("cas_key_versions")
        return [c["name"] for c in cols]

    async with engine.connect() as conn:
        columns = await conn.run_sync(_check_columns)
        assert "key_check_value" in columns

    await engine.dispose()


def test_alembic_migration_003_upgrades_and_downgrades_safely(tmp_path) -> None:
    """Verify Alembic migration 003 adds key_check_value to existing schema and rolls back safely.

    Uses an isolated temporary SQLite database without modifying existing databases or .env.
    """
    import os
    import sqlite3
    from pathlib import Path

    from alembic.config import Config

    from alembic import command

    repo_root = Path(__file__).resolve().parent.parent.parent
    db_path = tmp_path / "alembic_test.db"

    # Ensure clean environment for isolated test
    orig_db_url = os.environ.pop("DATABASE_URL", None)
    try:
        cfg = Config(str(repo_root / "backend" / "alembic.ini"))
        cfg.set_main_option("script_location", str(repo_root / "backend" / "alembic"))
        cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path.as_posix()}")

        # 1. Upgrade to 002 (prior schema)
        command.upgrade(cfg, "002_protected_scopes")
        con = sqlite3.connect(db_path)
        cols_002 = [r[1] for r in con.cursor().execute("PRAGMA table_info(cas_key_versions)").fetchall()]
        con.close()
        assert "key_check_value" not in cols_002

        # 2. Upgrade to 003 (head)
        command.upgrade(cfg, "head")
        con = sqlite3.connect(db_path)
        cols_003 = [r[1] for r in con.cursor().execute("PRAGMA table_info(cas_key_versions)").fetchall()]
        con.close()
        assert "key_check_value" in cols_003

        # 3. Downgrade back to 002
        command.downgrade(cfg, "002_protected_scopes")
        con = sqlite3.connect(db_path)
        cols_downgraded = [r[1] for r in con.cursor().execute("PRAGMA table_info(cas_key_versions)").fetchall()]
        con.close()
        assert "key_check_value" not in cols_downgraded
    finally:
        if orig_db_url is not None:
            os.environ["DATABASE_URL"] = orig_db_url

