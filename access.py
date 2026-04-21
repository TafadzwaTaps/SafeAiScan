"""
access.py — permission layer (CLEAN + FIXED)
"""

from fastapi import HTTPException
from plans import PLAN_LIMITS, get_plan_limits


def has_feature(user: dict, feature: str) -> bool:
    plan = (user or {}).get("plan", "free").lower()
    return get_plan_limits(plan)["features"].get(feature, False)


def enforce_feature(user: dict, feature: str):
    if not has_feature(user, feature):
        raise HTTPException(
            status_code=403,
            detail={
                "success": False,
                "error": f"{feature} requires higher plan"
            }
        )


def get_ai_depth(user: dict) -> str:
    plan = (user or {}).get("plan", "free").lower()
    return get_plan_limits(plan)["ai_depth"]


def get_daily_limit(user: dict) -> int:
    plan = (user or {}).get("plan", "free").lower()
    return get_plan_limits(plan)["daily_scans"]


def within_limit(user: dict, count: int) -> bool:
    plan = (user or {}).get("plan", "free").lower()
    return count <= get_daily_limit(user)