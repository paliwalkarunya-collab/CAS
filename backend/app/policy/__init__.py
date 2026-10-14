"""Policy package init."""

from .opa_client import PolicyDecision, evaluate_access_policy

__all__ = ["PolicyDecision", "evaluate_access_policy"]
