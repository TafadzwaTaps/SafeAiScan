"""
access.py — SaaS permission engine (FIXED & CONSISTENT)
Single source of truth for plans + access control
"""

from fastapi import HTTPException
from plans import PLAN_LIMITS

FEATURE_GATES = {
    "/api/scan-repo": "repo_scan",
    "/api/repo/tree": "repo_scan",
}
# ------------------------------------------------------------
# CORE PLAN ACCESS
# ------------------------------------------------------------

def get_limits(plan: str) -> dict:
    """Always safe fallback to free plan"""
    return PLAN_LIMITS.get((plan or "free").lower(), PLAN_LIMITS["free"])


def has_feature(user: dict, feature: str) -> bool:
    """Check feature access based on user's plan"""
    plan = (user or {}).get("plan", "free").lower()
    return bool(get_limits(plan)["features"].get(feature, False))


def enforce_feature(user: dict, feature: str):
    """Hard block if feature not allowed"""
    if not has_feature(user, feature):
        raise HTTPException(
            status_code=403,
            detail={
                "success": False,
                "error": f"This feature requires a higher plan: {feature}"
            }
        )


# ------------------------------------------------------------
# PLAN CAPABILITIES
# ------------------------------------------------------------

def get_ai_depth(user: dict) -> str:
    plan = (user or {}).get("plan", "free").lower()
    return get_limits(plan)["ai_depth"]


def get_daily_limit(user: dict) -> int:
    plan = (user or {}).get("plan", "free").lower()
    return get_limits(plan)["daily_scans"]


def get_history_limit(user: dict) -> int:
    plan = (user or {}).get("plan", "free").lower()
    return get_limits(plan)["history_limit"]


# ------------------------------------------------------------
# USAGE LIMIT ENFORCEMENT (FIXED)
# ------------------------------------------------------------

def within_limit(user: dict, count: int) -> bool:
    """Correct enforcement: user + current usage count"""
    return count <= get_daily_limit(user)
