"""
CAS-SE OPA Integration Client -- Phase 4

Evaluates context-aware access decisions via Open Policy Agent (OPA).

Security invariants:
  - OPA unavailability always results in DENY for sensitive operations.
  - No caching of policy decisions -- every request is evaluated fresh.
  - Policy input never includes raw keys, DEKs, HMAC tokens, or credentials.
  - Decision expiry is enforced by the caller.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.config import get_settings

logger = logging.getLogger("cas_se.policy")
settings = get_settings()


@dataclass
class PolicyDecision:
    """Structured result of an OPA policy evaluation."""

    decision: str  # deny | metadata_only | masked_image | feature_only | raw_image
    reason: str  # Human-readable explanation for logging/audit
    policy_id: str | None  # Policy ID evaluated
    policy_version: int | None
    allowed_view: str | None
    decision_expiry: str | None  # ISO8601 expiry timestamp


DENY_DECISION = PolicyDecision(
    decision="deny",
    reason="Access denied",
    policy_id=None,
    policy_version=None,
    allowed_view=None,
    decision_expiry=None,
)


async def evaluate_access_policy(
    identity: dict[str, Any],
    resource: dict[str, Any],
    context: dict[str, Any],
) -> PolicyDecision:
    """
    Evaluate an access request against the CAS-SE OPA policy.

    :param identity: Authenticated user context (user_id, role -- NO secrets).
    :param resource: Resource context (envelope_id, sensitivity_label, dataset_id).
    :param context: Request context (purpose, requested_view, job details, policy_version).
    :returns: PolicyDecision -- always returns a decision (never raises on OPA timeout).

    OPA unavailability -> DENY (fail-closed).
    """
    opa_input = {
        "input": {
            "identity": identity,
            "resource": resource,
            "context": context,
        }
    }

    try:
        async with httpx.AsyncClient(timeout=settings.opa_timeout_seconds) as client:
            response = await client.post(
                f"{settings.opa_url}/v1/data/{settings.opa_policy_path}",
                json=opa_input,
            )

        if response.status_code != 200:
            logger.warning(
                "OPA returned non-200 status %d -- defaulting to DENY",
                response.status_code,
            )
            return _deny("OPA policy evaluation returned non-200 status")

        result = response.json().get("result", {})

        if not result.get("allow", False):
            return _deny(result.get("reason", "Policy denied access"))

        return PolicyDecision(
            decision=result.get("decision", "deny"),
            reason=result.get("reason", ""),
            policy_id=result.get("policy_id"),
            policy_version=result.get("policy_version"),
            allowed_view=result.get("allowed_view"),
            decision_expiry=result.get("decision_expiry"),
        )

    except httpx.TimeoutException:
        logger.error("OPA timeout after %.1fs -- defaulting to DENY", settings.opa_timeout_seconds)
        return _deny("OPA policy engine unavailable (timeout) -- access denied")

    except Exception as exc:
        logger.error("OPA evaluation error: %s -- defaulting to DENY", exc)
        return _deny("OPA policy evaluation failed -- access denied")


def _deny(reason: str) -> PolicyDecision:
    return PolicyDecision(
        decision="deny",
        reason=reason,
        policy_id=None,
        policy_version=None,
        allowed_view=None,
        decision_expiry=None,
    )
