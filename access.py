from fastapi import HTTPException
from config import DEV_MODE

# Example plan feature map (keep your existing one)
PLAN_FEATURES = {
    "free": {"scan", "basic_ai"},
    "pro": {"scan", "basic_ai", "repo_scan", "advanced_ai"},
    "enterprise": {"scan", "basic_ai", "repo_scan", "advanced_ai", "team"},
}

def enforce_feature(user, feature: str):
    """
    Blocks access unless feature exists in plan.
    DEV_MODE bypasses everything for testing.
    """
    if DEV_MODE:
        return  # 🔓 unlock all features in dev

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


def get_ai_depth(user):
    if DEV_MODE:
        return "full"

    plan = user.get("plan", "free").lower()
    return {
        "free": "basic",
        "pro": "full",
        "enterprise": "full"
    }.get(plan, "basic")


def get_daily_limit(user):
    if DEV_MODE:
        return 10_000

    plan = user.get("plan", "free").lower()
    return {
        "free": 5,
        "pro": 100,
        "enterprise": 1000
    }.get(plan, 5)


def within_limit(user, usage_count: int) -> bool:
    if DEV_MODE:
        return True

    return usage_count <= get_daily_limit(user)