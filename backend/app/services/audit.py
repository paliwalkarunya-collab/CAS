"""
CAS-SE Audit Service -- Phase 6

Hash-chained, tamper-evident audit trail using HMAC-SHA-256.

Chain structure:
  event_hmac_n = HMAC(audit_key, canonical(fields_n) || prev_event_hmac_{n-1})

Invariants:
  - All audit events are append-only -- never modified or deleted.
  - Canonical field serialization prevents format-manipulation attacks.
  - No secrets, keys, DEKs, or raw data in audit event fields.
  - Anomaly detection reads audit data -- it never grants access automatically.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.models import CASAccessAudit
from app.services.crypto import compute_audit_hmac

settings = get_settings()

# Valid audit event types (from ORM Enum)
AUDIT_EVENT_TYPES = {
    "login",
    "logout",
    "upload",
    "search",
    "access_request",
    "access_allow",
    "access_deny",
    "decryption",
    "job_create",
    "job_approve",
    "job_reject",
    "job_cancel",
    "policy_create",
    "policy_update",
    "key_rotate",
    "anomaly_alert",
    "audit_verify",
}


def _canonicalize(fields: dict[str, Any]) -> dict[str, Any]:
    """
    Produce a canonical representation of audit fields for HMAC computation.

    - All values converted to strings.
    - None values become empty strings.
    - Keys sorted alphabetically.
    - No secrets, keys, or raw data should ever appear in fields.
    """
    return {k: (str(v) if v is not None else "") for k, v in sorted(fields.items())}


def _format_occurred_at(dt: datetime) -> str:
    """Format datetime to canonical UTC ISO-8601 string with timezone offset."""
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return dt.isoformat()


async def append_audit_event(
    db: AsyncSession,
    event_type: str,
    actor_id: uuid.UUID | None = None,
    actor_role: str | None = None,
    envelope_id: uuid.UUID | None = None,
    decision: str | None = None,
    reason: str | None = None,
    policy_id: uuid.UUID | None = None,
    policy_version: int | None = None,
    job_id: uuid.UUID | None = None,
    extra: dict[str, Any] | None = None,
) -> CASAccessAudit:
    """
    Append a new event to the audit chain.

    Computes the chain HMAC by:
      1. Loading the previous event's HMAC.
      2. Canonicalizing the current event's fields.
      3. Computing HMAC over canonical fields + previous HMAC.

    :raises ValueError: If event_type is not a valid audit event type.
    """
    if event_type not in AUDIT_EVENT_TYPES:
        raise ValueError(f"Invalid audit event type: {event_type!r}")

    now = datetime.now(UTC)
    event_id = uuid.uuid4()

    # Canonical fields for HMAC (no secrets, no raw data)
    canonical_fields = _canonicalize(
        {
            "event_id": str(event_id),
            "event_type": event_type,
            "actor_id": str(actor_id) if actor_id else "",
            "actor_role": actor_role or "",
            "envelope_id": str(envelope_id) if envelope_id else "",
            "decision": decision or "",
            "reason": reason or "",
            "policy_id": str(policy_id) if policy_id else "",
            "policy_version": str(policy_version) if policy_version is not None else "",
            "job_id": str(job_id) if job_id else "",
            "occurred_at": _format_occurred_at(now),
        }
    )

    # Get previous event HMAC for chain
    prev_result = await db.execute(
        select(CASAccessAudit.event_hmac).order_by(CASAccessAudit.occurred_at.desc()).limit(1)
    )
    prev_hmac_row = prev_result.scalar_one_or_none()

    # Compute chain HMAC
    event_hmac = compute_audit_hmac(
        canonical_fields=canonical_fields,
        prev_hmac=prev_hmac_row,
        audit_key=settings.audit_integrity_key_bytes,
    )

    audit_event = CASAccessAudit(
        id=event_id,
        event_type=event_type,
        actor_id=actor_id,
        actor_role=actor_role,
        envelope_id=envelope_id,
        decision=decision,
        reason=reason,
        policy_id=policy_id,
        policy_version=policy_version,
        job_id=job_id,
        event_hmac=event_hmac,
        prev_event_hmac=prev_hmac_row,
        extra=json.dumps(extra) if extra else None,
        occurred_at=now,
    )
    db.add(audit_event)
    await db.flush()
    return audit_event


async def verify_chain(db: AsyncSession) -> tuple[bool, str]:
    """
    Verify the integrity of the entire audit chain.

    :returns: (is_valid, message) -- message describes the first broken link if invalid.
    """
    result = await db.execute(select(CASAccessAudit).order_by(CASAccessAudit.occurred_at.asc()))
    events = list(result.scalars().all())

    if not events:
        return True, "Audit chain is empty -- no events to verify"

    # Re-order events along the hash-chain pointers to ensure strict sequence
    by_prev: dict[str | None, CASAccessAudit] = {e.prev_event_hmac: e for e in events}
    ordered_events: list[CASAccessAudit] = []
    curr_prev: str | None = None
    while curr_prev in by_prev and len(ordered_events) < len(events):
        ev = by_prev[curr_prev]
        ordered_events.append(ev)
        curr_prev = ev.event_hmac

    if len(ordered_events) == len(events):
        events = ordered_events

    prev_hmac: str | None = None
    for i, event in enumerate(events):
        canonical_fields = _canonicalize(
            {
                "event_id": str(event.id),
                "event_type": event.event_type,
                "actor_id": str(event.actor_id) if event.actor_id else "",
                "actor_role": event.actor_role or "",
                "envelope_id": str(event.envelope_id) if event.envelope_id else "",
                "decision": event.decision or "",
                "reason": event.reason or "",
                "policy_id": str(event.policy_id) if event.policy_id else "",
                "policy_version": str(event.policy_version)
                if event.policy_version is not None
                else "",
                "job_id": str(event.job_id) if event.job_id else "",
                "occurred_at": _format_occurred_at(event.occurred_at),
            }
        )

        computed_hmac = compute_audit_hmac(
            canonical_fields=canonical_fields,
            prev_hmac=prev_hmac,
            audit_key=settings.audit_integrity_key_bytes,
        )

        import hmac as hmac_lib

        if not hmac_lib.compare_digest(computed_hmac, event.event_hmac):
            return False, (
                f"Audit chain broken at event {i} "
                f"(id={event.id}, type={event.event_type}, time={event.occurred_at})"
            )

        prev_hmac = event.event_hmac

    return True, f"Audit chain intact -- {len(events)} events verified"
