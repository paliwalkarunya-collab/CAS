"""
CAS-SE Policy Management API -- Phase 6

CRUD for access control policies and immutable policy versioning.
"""

from __future__ import annotations

import hashlib
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user, require_roles
from app.db.session import get_db
from app.models.models import CASPolicy, CASPolicyVersion, CASUser
from app.services.audit import append_audit_event

router = APIRouter()

# Schemas (centralised in app.schemas per PRD §10.3)
from app.schemas.policies import (  # noqa: E402
    CreatePolicyRequest,
    PolicyResponse,
)


@router.get("", response_model=list[PolicyResponse])
async def list_policies(
    _: CASUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[PolicyResponse]:
    """List all registered access policies."""
    result = await db.execute(select(CASPolicy).order_by(CASPolicy.name.asc()))
    policies = result.scalars().all()

    response: list[PolicyResponse] = []
    for p in policies:
        v_res = await db.execute(
            select(CASPolicyVersion.version_number)
            .where(CASPolicyVersion.policy_id == p.id)
            .order_by(CASPolicyVersion.version_number.desc())
            .limit(1)
        )
        latest_ver = v_res.scalar_one_or_none() or 1
        response.append(
            PolicyResponse(
                policy_id=p.id,
                name=p.name,
                description=p.description,
                is_active=p.is_active,
                rego_policy=p.rego_policy,
                latest_version=latest_ver,
                created_at=p.created_at.isoformat(),
                updated_at=p.updated_at.isoformat(),
            )
        )
    return response


@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(
    body: CreatePolicyRequest,
    current_user: CASUser = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> PolicyResponse:
    """Create a new access policy with initial version 1."""
    # Check duplicate
    existing = await db.execute(select(CASPolicy).where(CASPolicy.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Policy {body.name!r} already exists")

    policy_id = uuid.uuid4()
    policy = CASPolicy(
        id=policy_id,
        name=body.name,
        description=body.description,
        rego_policy=body.rego_policy,
        is_active=True,
        created_by=current_user.id,
    )
    db.add(policy)
    await db.flush()

    # Create immutable version 1
    rego_hash = hashlib.sha256(body.rego_policy.encode("utf-8")).hexdigest()
    version = CASPolicyVersion(
        id=uuid.uuid4(),
        policy_id=policy_id,
        version_number=1,
        rego_snapshot=body.rego_policy,
        snapshot_hash=rego_hash,
    )
    db.add(version)
    await db.flush()

    await append_audit_event(
        db=db,
        event_type="policy_create",
        actor_id=current_user.id,
        actor_role=current_user.role,
        policy_id=policy_id,
        policy_version=1,
        decision="allow",
        reason=f"Created policy {body.name}",
    )
    await db.commit()

    return PolicyResponse(
        policy_id=policy.id,
        name=policy.name,
        description=policy.description,
        is_active=policy.is_active,
        rego_policy=policy.rego_policy,
        latest_version=1,
        created_at=policy.created_at.isoformat(),
        updated_at=policy.updated_at.isoformat(),
    )


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: uuid.UUID,
    _: object = Depends(require_roles("admin", "auditor")),
    db: AsyncSession = Depends(get_db),
) -> PolicyResponse:
    """Get policy details and latest version number."""
    result = await db.execute(select(CASPolicy).where(CASPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    v_res = await db.execute(
        select(CASPolicyVersion.version_number)
        .where(CASPolicyVersion.policy_id == policy.id)
        .order_by(CASPolicyVersion.version_number.desc())
        .limit(1)
    )
    latest_ver = v_res.scalar_one_or_none() or 1

    return PolicyResponse(
        policy_id=policy.id,
        name=policy.name,
        description=policy.description,
        is_active=policy.is_active,
        rego_policy=policy.rego_policy,
        latest_version=latest_ver,
        created_at=policy.created_at.isoformat(),
        updated_at=policy.updated_at.isoformat(),
    )
