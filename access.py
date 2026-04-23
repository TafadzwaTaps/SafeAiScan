from fastapi import HTTPException
from config import DEV_MODE

# FIX: import from plans.py so limits are defined in ONE place
from plans import get_plan_limits

PLAN_FEATURES = {
    "free":       {"scan", "basic_ai"},
    "pro":        {"scan", "basic_ai", "repo_scan", "advanced_ai"},
    "enterprise": {"scan", "basic_ai", "repo_scan", "advanced_ai", "team"},
}


def enforce_feature(user, feature: str):
    """
    Blocks access unless feature exists in plan.
    DEV_MODE bypasses everything for testing.
    """
    if DEV_MODE:
        return  # unlock all features in dev

    plan = user.get("plan", "free").lower()

    if feature not in PLAN_FEATURES.get(plan, set()):
        raise HTTPException(
            status_code=403,
            detail={"success": False, "error": f"{feature} requires higher plan"}
        )


def has_feature(user, feature: str) -> bool:
    if DEV_MODE:
        return True
    plan = user.get("plan", "free").lower()
    return feature in PLAN_FEATURES.get(plan, set())


def get_ai_depth(user) -> str:
    if DEV_MODE:
        return "full"
    plan = user.get("plan", "free").lower()
    # FIX: delegate to plans.py — single source of truth
    return get_plan_limits(plan).get("ai_depth", "basic")


def get_daily_limit(user) -> int:
    if DEV_MODE:
        return 999999
    plan = user.get("plan", "free").lower()
    # FIX: was hardcoded to 5/100/1000 here AND differently in plans.py (10/100/1000)
    # Now always reads from plans.py so there's one place to change limits
    return get_plan_limits(plan).get("daily_scans", 10)


def within_limit(user, usage_count: int) -> bool:
    if DEV_MODE:
        return True
    return usage_count <= get_daily_limit(user)
