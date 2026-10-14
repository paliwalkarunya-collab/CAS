"""CAS-SE Rich Demo Seed Data Script -- Phase 8.

Populates the database with:
  1. Demonstration accounts for all 5 integration roles (plus frontend quick-login personas).
  2. Default base OPA Rego policy in `cas_policies`.
  3. Sample encrypted envelopes with blind HMAC search indexes.
  4. Scoped ML training jobs (approved and in-progress).
  5. Initial hash-chained audit events.

Usage:
  python scripts/seed_demo_data.py
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add backend to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.core.config import get_settings
from app.models.models import (
    CASBase,
    CASDataEnvelope,
    CASMLJob,
    CASPolicy,
    CASPolicyVersion,
    CASProtectedIndex,
    CASUser,
)
from app.services.audit import append_audit_event
from app.services.crypto import (
    build_aad,
    compute_hmac_token,
    encrypt_payload,
    generate_dek,
    normalize_index_value,
    wrap_dek,
)
from app.services.identity_service import hash_password
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

settings = get_settings()

DEMO_USERS = [
    {
        "username": "admin",
        "email": "admin@cas-se.local",
        "password": "Pass123!",
        "role": "admin",
    },
    {
        "username": "uploader",
        "email": "uploader@cas-se.local",
        "password": "Pass123!",
        "role": "uploader",
    },
    {
        "username": "trainer",
        "email": "trainer@cas-se.local",
        "password": "Pass123!",
        "role": "trainer",
    },
    {
        "username": "researcher",
        "email": "researcher@cas-se.local",
        "password": "Pass123!",
        "role": "researcher",
    },
    {
        "username": "auditor",
        "email": "auditor@cas-se.local",
        "password": "Pass123!",
        "role": "auditor",
    },
    # Frontend quick-login demo accounts
    {
        "username": "admin_demo",
        "email": "admin_demo@cas-se.local",
        "password": "Pass123!",
        "role": "admin",
    },
    {
        "username": "trainer_demo",
        "email": "trainer_demo@cas-se.local",
        "password": "Pass123!",
        "role": "trainer",
    },
    {
        "username": "researcher_demo",
        "email": "researcher_demo@cas-se.local",
        "password": "Pass123!",
        "role": "researcher",
    },
    {
        "username": "auditor_demo",
        "email": "auditor_demo@cas-se.local",
        "password": "Pass123!",
        "role": "auditor",
    },
]

DEFAULT_REGO = """package cas_se.access

# Default deny (fail-closed)
default allow := false

# 1. Admin operations
allow if {
    input.actor_role == "admin"
}

# 2. Uploader can ingest records
allow if {
    input.actor_role == "uploader"
    input.operation == "upload"
}

# 3. Trainer can access feature_only view for active approved job
allow if {
    input.actor_role == "trainer"
    input.requested_view == "feature_only"
    input.job_status == "approved"
    input.job_expired == false
}

# 4. Researcher can access raw_image if explicitly approved
allow if {
    input.actor_role == "researcher"
    input.requested_view == "raw_image"
    input.job_status == "approved"
    input.job_expired == false
}
"""


async def seed_data(session: AsyncSession) -> dict[str, uuid.UUID]:
    user_ids: dict[str, uuid.UUID] = {}

    # 1. Seed Users
    for user_info in DEMO_USERS:
        stmt = select(CASUser).where(CASUser.username == user_info["username"])
        result = await session.execute(stmt)
        existing_user = result.scalar_one_or_none()

        if existing_user is None:
            new_user = CASUser(
                id=uuid.uuid4(),
                username=user_info["username"],
                email=user_info["email"],
                hashed_password=hash_password(user_info["password"]),
                role=user_info["role"],
                is_active=True,
            )
            session.add(new_user)
            await session.flush()
            user_ids[user_info["username"]] = new_user.id
            print(f"[+] Created user: {user_info['username']} ({user_info['role']})")
        else:
            user_ids[user_info["username"]] = existing_user.id

    # 2. Seed Default OPA Policy
    pol_stmt = select(CASPolicy).where(CASPolicy.name == "cas_se_default_policy")
    pol_res = await session.execute(pol_stmt)
    if pol_res.scalar_one_or_none() is None:
        policy = CASPolicy(
            id=uuid.uuid4(),
            name="cas_se_default_policy",
            description="Default fail-closed ABAC policy for CAS-SE middleware",
            rego_policy=DEFAULT_REGO,
            is_active=True,
        )
        session.add(policy)
        await session.flush()

        policy_ver = CASPolicyVersion(
            id=uuid.uuid4(),
            policy_id=policy.id,
            version_number=1,
            rego_snapshot=DEFAULT_REGO,
            snapshot_hash=hashlib.sha256(DEFAULT_REGO.encode()).hexdigest(),
        )
        session.add(policy_ver)
        await session.flush()
        print("[+] Created default OPA policy: cas_se_default_policy (v1)")

    # 3. Seed Sample Encrypted Envelopes
    env_stmt = select(CASDataEnvelope).limit(1)
    if (await session.execute(env_stmt)).scalar_one_or_none() is None:
        kek_bytes = b"k" * 32
        for i in range(1, 4):
            env_id = uuid.uuid4()
            raw_data = f"Simulated medical imaging payload record {i}".encode()
            dek = generate_dek()
            aad = build_aad(str(env_id), None, "restricted", 1)
            enc = encrypt_payload(raw_data, dek, aad)
            wrapped = wrap_dek(dek, kek_bytes, 1)

            env = CASDataEnvelope(
                id=env_id,
                object_uri=f"envelopes/demo_{i}.enc",
                nonce_hex=enc.nonce.hex(),
                wrapped_dek=wrapped.wrapped_dek_b64,
                kek_version=1,
                ciphertext_hash=enc.ciphertext_sha256,
                sensitivity_label="restricted",
                uploaded_by=user_ids.get("uploader"),
            )
            session.add(env)
            await session.flush()

            # Seed HMAC equality search indexes
            idx_dataset = CASProtectedIndex(
                id=uuid.uuid4(),
                envelope_id=env_id,
                field_name="dataset_id",
                hmac_token=compute_hmac_token(
                    normalize_index_value("fashion_mnist"),
                    settings.index_hmac_key_bytes,
                ),
                token_version=1,
            )
            idx_subject = CASProtectedIndex(
                id=uuid.uuid4(),
                envelope_id=env_id,
                field_name="subject_id",
                hmac_token=compute_hmac_token(
                    normalize_index_value(f"patient-{100 + i}"),
                    settings.index_hmac_key_bytes,
                ),
                token_version=1,
            )
            session.add_all([idx_dataset, idx_subject])

            # Audit event for upload
            await append_audit_event(
                session,
                event_type="upload",
                actor_id=user_ids.get("uploader"),
                actor_role="uploader",
                envelope_id=env_id,
                decision="allow",
                reason=f"Ingested sample envelope {i}",
            )
        print("[+] Seeded 3 encrypted envelopes with blind HMAC search indexes")

    # 4. Seed Sample ML Job
    job_stmt = select(CASMLJob).limit(1)
    if (await session.execute(job_stmt)).scalar_one_or_none() is None:
        trainer_id = user_ids.get("trainer")
        job = CASMLJob(
            id=uuid.uuid4(),
            requester_id=trainer_id or uuid.uuid4(),
            purpose="Train Fashion-MNIST feature-vector classifier",
            dataset_scope=json.dumps(["fashion_mnist"]),
            requested_view="feature_only",
            status="approved",
            expires_at=datetime.now(UTC) + timedelta(days=7),
            created_at=datetime.now(UTC),
        )
        session.add(job)
        await session.flush()
        print(f"[+] Seeded approved ML job: {job.id}")

    await session.commit()
    return user_ids


async def main() -> None:
    db_url = os.environ.get("DATABASE_URL", settings.database_url)
    engine_kwargs: dict[str, object] = {"echo": False}
    if not db_url.startswith("sqlite"):
        engine_kwargs["pool_pre_ping"] = True

    engine = create_async_engine(db_url, **engine_kwargs)  # type: ignore[arg-type]
    session_factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )

    print(f"Connecting to database: {db_url}")
    # Ensure tables exist
    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    async with session_factory() as session:
        await seed_data(session)

    await engine.dispose()
    print("Demo seed complete! Rich demonstration dataset is ready.")


if __name__ == "__main__":
    asyncio.run(main())
